// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Network diagnostics tools for dreamingwrt-toolkit (RoceOS parity set).
 * Every command is a one-shot: it reads a JSON request object, performs one
 * measurement, and returns exactly one toolkit_success()/toolkit_error()
 * envelope. No resident state, no procd entry.
 *
 * Security invariants enforced here (do NOT relax without review):
 *   - Every shell-out target is screened by net_target_ok(): it rejects the
 *     shell metacharacters and a leading '-' (argv option injection), so a
 *     hostile "host" can neither inject a command nor a flag.
 *   - HTTP tools (http-request/headers/website-check) resolve the target and
 *     refuse loopback/RFC1918/link-local/ULA/multicast addresses unless the
 *     caller explicitly opts in, and re-check on every redirect hop. TLS peer
 *     verification is ON by default; disabling it needs an explicit flag and
 *     is echoed back so the UI can warn.
 *   - The three phone-home tools (public-ip geo / ip-geo / mac-lookup) are
 *     gated behind [toolkit] external_lookup and disclosed by the frontend.
 */
#include "toolkit_internal.h"
#include "jmx_utils.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- shared helpers -------------------------------------------------- */

static const char *net_bin(const char *name, char *path, size_t path_len)
{
    static const char *dirs[] = { "/usr/sbin", "/usr/bin", "/sbin", "/bin", NULL };
    for (int i = 0; dirs[i]; i++) {
        snprintf(path, path_len, "%s/%s", dirs[i], name);
        if (access(path, X_OK) == 0) return path;
    }
    path[0] = 0;
    return NULL;
}

/* Unified screen for any value handed to execv() as a host/target argument.
 * Accepts host names, IPv4 and IPv6 literals; rejects shell metacharacters,
 * whitespace, control bytes and a leading '-' (which execv would treat as an
 * option). This is the metachar filter the parity mandate requires on every
 * shell-out tool. */
static int net_target_ok(const char *s, size_t max_len)
{
    size_t len = s ? strlen(s) : 0;
    if (!len || len > max_len || s[0] == '-' || s[0] == '.' || s[len - 1] == '.')
        return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '-' && c != ':')
            return 0;
    }
    return 1;
}

struct net_buf { char *data; size_t len; size_t cap; };

static size_t net_curl_write(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    struct net_buf *b = opaque;
    size_t bytes = size * nmemb, cap;
    char *next;
    if (!b || bytes > 1024 * 1024 || b->len > 1024 * 1024 - bytes) return 0;
    if (b->len + bytes + 1 > b->cap) {
        cap = b->cap ? b->cap : 4096;
        while (cap < b->len + bytes + 1) cap *= 2;
        next = realloc(b->data, cap);
        if (!next) return 0;
        b->data = next; b->cap = cap;
    }
    memcpy(b->data + b->len, ptr, bytes); b->len += bytes; b->data[b->len] = 0;
    return bytes;
}
/* ---- SSRF address classification ------------------------------------- */

/* ip is in host byte order. Blocks loopback, RFC1918, CGNAT, link-local
 * (incl. the 169.254.169.254 metadata address), the 0.0.0.0/8 "this host"
 * block and everything multicast/reserved from 224.0.0.0 up. */
static int net_v4_blocked(uint32_t ip)
{
    uint8_t a = (ip >> 24) & 0xff, b = (ip >> 16) & 0xff;
    if (a == 127 || a == 10 || a == 0) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 169 && b == 254) return 1;
    if (a == 100 && b >= 64 && b <= 127) return 1;
    if (a >= 224) return 1;
    return 0;
}

static int net_sa_is_blocked(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return net_v4_blocked(ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr));
    if (sa->sa_family == AF_INET6) {
        const struct in6_addr *a6 = &((const struct sockaddr_in6 *)sa)->sin6_addr;
        const uint8_t *p = a6->s6_addr;
        if (IN6_IS_ADDR_LOOPBACK(a6) || IN6_IS_ADDR_LINKLOCAL(a6) ||
            IN6_IS_ADDR_MULTICAST(a6) || IN6_IS_ADDR_UNSPECIFIED(a6) ||
            IN6_IS_ADDR_SITELOCAL(a6)) return 1;
        if ((p[0] & 0xfe) == 0xfc) return 1;              /* ULA fc00::/7 */
        if (IN6_IS_ADDR_V4MAPPED(a6))
            return net_v4_blocked(((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                                  ((uint32_t)p[14] << 8) | p[15]);
        return 0;
    }
    return 1;
}

/* Resolve host and confirm every returned address is public (unless the caller
 * opted in to private targets). On success *out receives the resolved list for
 * the caller to pin the connection to; caller frees with freeaddrinfo(). */
static int net_host_public(const char *host, int allow_private, struct addrinfo **out)
{
    struct addrinfo hints, *res = NULL, *it;
    *out = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    if (!allow_private)
        for (it = res; it; it = it->ai_next)
            if (net_sa_is_blocked(it->ai_addr)) { freeaddrinfo(res); return -2; }
    *out = res;
    return 0;
}

/* [toolkit] external_lookup gate. Default is ENABLED (the product decision is
 * "allow external lookups, but disclose and let admins turn it off"); an
 * explicit false-y option in /etc/config/dreamingwrt disables it. */
static int net_external_lookup_enabled(void)
{
    FILE *fp = fopen("/etc/config/dreamingwrt", "r");
    char line[256];
    int in_toolkit = 0, enabled = 1;
    if (!fp) return 1;
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (!strncmp(s, "config ", 7)) in_toolkit = strstr(s, "toolkit") != NULL;
        else if (in_toolkit && strstr(s, "external_lookup")) {
            if (strstr(s, "'0'") || strstr(s, "\"0\"") || strstr(s, "off") ||
                strstr(s, "false") || strstr(s, "'no'")) enabled = 0;
            else enabled = 1;
            break;
        }
    }
    fclose(fp);
    return enabled;
}
/* ---- port scan / port check ------------------------------------------ */

static const char *net_service_name(int port)
{
    switch (port) {
    case 20: case 21: return "ftp";
    case 22: return "ssh";
    case 23: return "telnet";
    case 25: return "smtp";
    case 53: return "dns";
    case 67: case 68: return "dhcp";
    case 80: return "http";
    case 110: return "pop3";
    case 123: return "ntp";
    case 143: return "imap";
    case 161: return "snmp";
    case 443: return "https";
    case 445: return "smb";
    case 465: case 587: return "smtps";
    case 993: return "imaps";
    case 995: return "pop3s";
    case 1194: return "openvpn";
    case 1723: return "pptp";
    case 3306: return "mysql";
    case 3389: return "rdp";
    case 5201: return "iperf3";
    case 5432: return "postgres";
    case 6379: return "redis";
    case 8080: return "http-alt";
    case 8443: return "https-alt";
    case 51820: return "wireguard";
    default: return "";
    }
}

/* Parse "80,443,8000-8100" into a de-duplicated, ascending port array. Caps at
 * max entries (hard ceiling 1000) so a "1-65535" request cannot exhaust us. */
static int net_parse_ports(const char *spec, int *ports, int max)
{
    int count = 0;
    const char *p = spec;
    char seen[65536 / 8];
    memset(seen, 0, sizeof(seen));
    if (!spec || !spec[0]) return 0;
    while (*p && count < max) {
        int lo = 0, hi = 0, n = 0;
        while (*p == ' ' || *p == ',') p++;
        if (sscanf(p, "%d-%d%n", &lo, &hi, &n) < 2) {
            if (sscanf(p, "%d%n", &lo, &n) < 1) break;
            hi = lo;
        }
        p += n;
        if (lo < 1) lo = 1;
        if (hi > 65535) hi = 65535;
        for (int v = lo; v <= hi && count < max; v++)
            if (!(seen[v >> 3] & (1 << (v & 7)))) {
                seen[v >> 3] |= 1 << (v & 7);
                ports[count++] = v;
            }
    }
    return count;
}
static int net_resolve_first(const char *host, struct sockaddr_storage *ss,
                             socklen_t *len, char ipstr[INET6_ADDRSTRLEN])
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ipstr[0] = 0;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *len = res->ai_addrlen;
    if (res->ai_family == AF_INET)
        inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ipstr, INET6_ADDRSTRLEN);
    else if (res->ai_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    freeaddrinfo(res);
    return 0;
}

static void net_ss_set_port(struct sockaddr_storage *ss, int port)
{
    if (ss->ss_family == AF_INET) ((struct sockaddr_in *)ss)->sin_port = htons(port);
    else ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
}

/* One non-blocking connect wave over up to `n` ports. Fills state[i]:
 * 0 open, 1 closed (refused), 2 filtered (timeout / unreachable). */
static void net_scan_wave(const struct sockaddr_storage *base, socklen_t slen,
                          const int *ports, int n, int timeout_ms, int *state)
{
    struct pollfd pfd[128];
    int fd[128], idx[128], nf = 0;
    for (int i = 0; i < n; i++) {
        struct sockaddr_storage ss = *base;
        int s = socket(base->ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        state[i] = 2;
        if (s < 0) continue;
        net_ss_set_port(&ss, ports[i]);
        if (connect(s, (struct sockaddr *)&ss, slen) == 0) { state[i] = 0; close(s); continue; }
        if (errno != EINPROGRESS) { state[i] = (errno == ECONNREFUSED) ? 1 : 2; close(s); continue; }
        fd[nf] = s; idx[nf] = i; pfd[nf].fd = s; pfd[nf].events = POLLOUT; pfd[nf].revents = 0; nf++;
    }
    if (nf) poll(pfd, nf, timeout_ms);
    for (int k = 0; k < nf; k++) {
        int err = 0; socklen_t el = sizeof(err);
        if (pfd[k].revents & (POLLOUT | POLLERR | POLLHUP)) {
            if (getsockopt(fd[k], SOL_SOCKET, SO_ERROR, &err, &el) == 0)
                state[idx[k]] = (err == 0) ? 0 : (err == ECONNREFUSED) ? 1 : 2;
        }
        close(fd[k]);
    }
}
static struct json_object *net_port_scan(struct json_object *payload, int single)
{
    const char *host = toolkit_json_str(payload, "host", toolkit_json_str(payload, "target", ""));
    int timeout_ms = toolkit_json_int(payload, "timeout_ms", 1200);
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    char ip[INET6_ADDRSTRLEN];
    int *ports, *state, total, open_count = 0, closed = 0, filtered = 0;
    struct json_object *data, *arr;
    if (!net_target_ok(host, 253)) return toolkit_error("invalid_host", "host is missing or contains illegal characters");
    if (timeout_ms < 200) timeout_ms = 200;
    if (timeout_ms > 5000) timeout_ms = 5000;
    ports = malloc(sizeof(int) * 1000);
    state = malloc(sizeof(int) * 1000);
    if (!ports || !state) { free(ports); free(state); return toolkit_error("out_of_memory", "port buffer allocation failed"); }
    if (single) {
        int port = toolkit_json_int(payload, "port", 0);
        if (port < 1 || port > 65535) { free(ports); free(state); return toolkit_error("invalid_port", "port must be 1-65535"); }
        ports[0] = port; total = 1;
    } else {
        total = net_parse_ports(toolkit_json_str(payload, "ports", "1-1000"), ports, 1000);
        if (!total) { free(ports); free(state); return toolkit_error("invalid_ports", "ports specification is empty or invalid"); }
    }
    if (net_resolve_first(host, &ss, &slen, ip) != 0) { free(ports); free(state); return toolkit_error("resolve_failed", "host could not be resolved"); }
    for (int off = 0; off < total; off += 128)
        net_scan_wave(&ss, slen, ports + off, total - off < 128 ? total - off : 128, timeout_ms, state + off);
    data = json_object_new_object();
    arr = json_object_new_array();
    for (int i = 0; i < total; i++) {
        if (state[i] == 1) closed++;
        else if (state[i] == 2) filtered++;
        else open_count++;
        if (state[i] == 0 || single) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "port", json_object_new_int(ports[i]));
            json_object_object_add(o, "state", json_object_new_string(state[i] == 0 ? "open" : state[i] == 1 ? "closed" : "filtered"));
            json_object_object_add(o, "service", json_object_new_string(net_service_name(ports[i])));
            json_object_array_add(arr, o);
        }
    }
    json_object_object_add(data, "host", json_object_new_string(host));
    json_object_object_add(data, "ip", json_object_new_string(ip));
    json_object_object_add(data, "ports_scanned", json_object_new_int(total));
    json_object_object_add(data, "open_count", json_object_new_int(open_count));
    json_object_object_add(data, "closed_count", json_object_new_int(closed));
    json_object_object_add(data, "filtered_count", json_object_new_int(filtered));
    json_object_object_add(data, single ? "results" : "open_ports", arr);
    free(ports); free(state);
    return toolkit_success(data, single ? "dreamingwrt-toolkit.port_check" : "dreamingwrt-toolkit.port_scan");
}
/* ---- tcp / udp connectivity test ------------------------------------- */

static struct json_object *net_tcp_udp_test(struct json_object *payload)
{
    const char *host = toolkit_json_str(payload, "host", "");
    const char *proto = toolkit_json_str(payload, "protocol", "tcp");
    const char *data_in = toolkit_json_str(payload, "payload", "");
    int port = toolkit_json_int(payload, "port", 0);
    int timeout_ms = toolkit_json_int(payload, "timeout_ms", 3000);
    int is_udp = !strcmp(proto, "udp");
    struct sockaddr_storage ss; socklen_t slen = 0; char ip[INET6_ADDRSTRLEN];
    struct json_object *data;
    int fd, connected = 0, replied = 0; long rx = 0;
    char buf[4096];
    if (!net_target_ok(host, 253)) return toolkit_error("invalid_host", "host is missing or contains illegal characters");
    if (port < 1 || port > 65535) return toolkit_error("invalid_port", "port must be 1-65535");
    if (strcmp(proto, "tcp") && strcmp(proto, "udp")) return toolkit_error("invalid_protocol", "protocol must be tcp or udp");
    if (strlen(data_in) > 1024) return toolkit_error("payload_too_large", "payload exceeds 1024 bytes");
    if (timeout_ms < 200) timeout_ms = 200;
    if (timeout_ms > 15000) timeout_ms = 15000;
    if (net_resolve_first(host, &ss, &slen, ip) != 0) return toolkit_error("resolve_failed", "host could not be resolved");
    net_ss_set_port(&ss, port);
    fd = socket(ss.ss_family, (is_udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return toolkit_error("socket_failed", strerror(errno));
    if (!is_udp) {
        struct pollfd p = { fd, POLLOUT, 0 };
        if (connect(fd, (struct sockaddr *)&ss, slen) == 0) connected = 1;
        else if (errno == EINPROGRESS && poll(&p, 1, timeout_ms) > 0) {
            int err = 0; socklen_t el = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) connected = 1;
        }
        if (connected && data_in[0]) { ssize_t w = send(fd, data_in, strlen(data_in), MSG_NOSIGNAL); (void)w; }
        if (connected) {
            struct pollfd r = { fd, POLLIN, 0 };
            if (poll(&r, 1, timeout_ms) > 0) { ssize_t g = recv(fd, buf, sizeof(buf) - 1, 0); if (g > 0) { rx = g; replied = 1; } }
        }
    } else {
        struct pollfd r = { fd, POLLIN, 0 };
        if (sendto(fd, data_in, strlen(data_in), 0, (struct sockaddr *)&ss, slen) >= 0) {
            connected = 1;
            if (poll(&r, 1, timeout_ms) > 0) { ssize_t g = recv(fd, buf, sizeof(buf) - 1, 0); if (g >= 0) { rx = g; replied = 1; } }
        }
    }
    close(fd);
    data = json_object_new_object();
    json_object_object_add(data, "host", json_object_new_string(host));
    json_object_object_add(data, "ip", json_object_new_string(ip));
    json_object_object_add(data, "port", json_object_new_int(port));
    json_object_object_add(data, "protocol", json_object_new_string(proto));
    json_object_object_add(data, is_udp ? "sent" : "connected", json_object_new_boolean(connected));
    json_object_object_add(data, "replied", json_object_new_boolean(replied));
    json_object_object_add(data, "bytes_received", json_object_new_int64(rx));
    if (is_udp) json_object_object_add(data, "note", json_object_new_string("UDP is connectionless: no reply does not prove the port is closed"));
    return toolkit_success(data, "dreamingwrt-toolkit.tcp_udp");
}
/* ---- ssl-check (OpenSSL) ---------------------------------------------- */

/* Resolve + connect a blocking TCP socket with a bounded connect time. Returns
 * a connected fd (left in blocking mode with send/recv timeouts) or -1. */
static int net_tcp_connect(const char *host, int port, int timeout_ms, char ip[INET6_ADDRSTRLEN])
{
    struct sockaddr_storage ss; socklen_t slen = 0;
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    struct pollfd p;
    int fd, flags;
    if (net_resolve_first(host, &ss, &slen, ip) != 0) return -1;
    net_ss_set_port(&ss, port);
    fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (connect(fd, (struct sockaddr *)&ss, slen) != 0) {
        if (errno != EINPROGRESS) { close(fd); return -1; }
        p.fd = fd; p.events = POLLOUT; p.revents = 0;
        if (poll(&p, 1, timeout_ms) <= 0) { close(fd); return -1; }
        int err = 0; socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) { close(fd); return -1; }
    }
    fcntl(fd, F_SETFL, flags);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

static void net_asn1_time_str(const ASN1_TIME *t, char *out, size_t len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *p = NULL; long n;
    out[0] = 0;
    if (!bio) return;
    if (t && ASN1_TIME_print(bio, t)) { n = BIO_get_mem_data(bio, &p); if (n > 0 && (size_t)n < len) { memcpy(out, p, n); out[n] = 0; } }
    BIO_free(bio);
}
static struct json_object *net_cert_to_json(X509 *cert)
{
    struct json_object *o = json_object_new_object(), *sans = json_object_new_array();
    char line[512]; int pday = 0, psec = 0;
    GENERAL_NAMES *gens; ASN1_INTEGER *sn; BIGNUM *bn;
    X509_NAME_oneline(X509_get_subject_name(cert), line, sizeof(line));
    json_object_object_add(o, "subject", json_object_new_string(line));
    X509_NAME_oneline(X509_get_issuer_name(cert), line, sizeof(line));
    json_object_object_add(o, "issuer", json_object_new_string(line));
    net_asn1_time_str(X509_get0_notBefore(cert), line, sizeof(line));
    json_object_object_add(o, "not_before", json_object_new_string(line));
    net_asn1_time_str(X509_get0_notAfter(cert), line, sizeof(line));
    json_object_object_add(o, "not_after", json_object_new_string(line));
    if (ASN1_TIME_diff(&pday, &psec, NULL, X509_get0_notAfter(cert)))
        json_object_object_add(o, "days_remaining", json_object_new_int(pday));
    sn = X509_get_serialNumber(cert);
    bn = sn ? ASN1_INTEGER_to_BN(sn, NULL) : NULL;
    if (bn) { char *hex = BN_bn2hex(bn); if (hex) { json_object_object_add(o, "serial", json_object_new_string(hex)); OPENSSL_free(hex); } BN_free(bn); }
    json_object_object_add(o, "signature_algorithm", json_object_new_string(OBJ_nid2ln(X509_get_signature_nid(cert))));
    gens = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (gens) {
        for (int i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
            GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
            if (g->type == GEN_DNS) {
                const unsigned char *d = ASN1_STRING_get0_data(g->d.dNSName);
                if (d) json_object_array_add(sans, json_object_new_string((const char *)d));
            }
        }
        GENERAL_NAMES_free(gens);
    }
    json_object_object_add(o, "subject_alt_names", sans);
    return o;
}
static struct json_object *net_ssl_check(struct json_object *payload)
{
    const char *host = toolkit_json_str(payload, "host", "");
    const char *sni = toolkit_json_str(payload, "servername", host);
    int port = toolkit_json_int(payload, "port", 443);
    int timeout_ms = toolkit_json_int(payload, "timeout_ms", 8000);
    char ip[INET6_ADDRSTRLEN];
    int fd; long vr;
    SSL_CTX *ctx; SSL *ssl; X509 *leaf; STACK_OF(X509) *chain;
    struct json_object *data, *chain_arr;
    if (!net_target_ok(host, 253)) return toolkit_error("invalid_host", "host is missing or contains illegal characters");
    if (!net_target_ok(sni, 253)) return toolkit_error("invalid_servername", "servername contains illegal characters");
    if (port < 1 || port > 65535) return toolkit_error("invalid_port", "port must be 1-65535");
    if (timeout_ms < 500) timeout_ms = 500;
    if (timeout_ms > 20000) timeout_ms = 20000;
    fd = net_tcp_connect(host, port, timeout_ms, ip);
    if (fd < 0) return toolkit_error("connect_failed", "TLS host could not be reached");
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return toolkit_error("tls_init_failed", "SSL_CTX_new failed"); }
    SSL_CTX_set_default_verify_paths(ctx);
    /* VERIFY_NONE keeps the handshake alive for an untrusted cert so we can
     * still report its fields; validity is judged separately below and never
     * silently trusted. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, sni);
    SSL_set1_host(ssl, sni);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return toolkit_error("tls_handshake_failed", ERR_reason_error_string(ERR_get_error()) ? ERR_reason_error_string(ERR_get_error()) : "handshake failed");
    }
    data = json_object_new_object();
    json_object_object_add(data, "host", json_object_new_string(host));
    json_object_object_add(data, "ip", json_object_new_string(ip));
    json_object_object_add(data, "port", json_object_new_int(port));
    json_object_object_add(data, "tls_version", json_object_new_string(SSL_get_version(ssl)));
    json_object_object_add(data, "cipher", json_object_new_string(SSL_get_cipher(ssl)));
    vr = SSL_get_verify_result(ssl);
    json_object_object_add(data, "valid", json_object_new_boolean(vr == X509_V_OK));
    json_object_object_add(data, "verify_result", json_object_new_string(X509_verify_cert_error_string(vr)));
    leaf = SSL_get_peer_certificate(ssl);
    if (leaf) { json_object_object_add(data, "certificate", net_cert_to_json(leaf)); X509_free(leaf); }
    chain_arr = json_object_new_array();
    chain = SSL_get_peer_cert_chain(ssl);
    for (int i = 1; chain && i < sk_X509_num(chain); i++) {
        char sub[512]; X509_NAME_oneline(X509_get_subject_name(sk_X509_value(chain, i)), sub, sizeof(sub));
        json_object_array_add(chain_arr, json_object_new_string(sub));
    }
    json_object_object_add(data, "chain", chain_arr);
    SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
    return toolkit_success(data, "dreamingwrt-toolkit.ssl_check");
}
/* ---- local-ports (ss with /proc fallback) ---------------------------- */

static void net_ss_process(const char *field, char *name, size_t nlen, int *pid)
{
    const char *q = field ? strstr(field, "((\"") : NULL, *e; const char *pp;
    name[0] = 0; *pid = 0;
    if (q) { q += 3; e = strchr(q, '"'); if (e && (size_t)(e - q) < nlen) { memcpy(name, q, e - q); name[e - q] = 0; } }
    pp = field ? strstr(field, "pid=") : NULL;
    if (pp) *pid = atoi(pp + 4);
}

static int net_proc_ports_fallback(struct json_object *arr)
{
    static const struct { const char *path; const char *proto; int listen_only; } src[] = {
        { "/proc/net/tcp", "tcp", 1 }, { "/proc/net/tcp6", "tcp6", 1 },
        { "/proc/net/udp", "udp", 0 }, { "/proc/net/udp6", "udp6", 0 }, { NULL, NULL, 0 } };
    char line[512]; int found = 0;
    for (int i = 0; src[i].path; i++) {
        FILE *fp = fopen(src[i].path, "r");
        if (!fp) continue;
        if (!fgets(line, sizeof(line), fp)) { fclose(fp); continue; }   /* header */
        while (fgets(line, sizeof(line), fp)) {
            unsigned lport = 0, st = 0; char la[128];
            if (sscanf(line, "%*d: %127[0-9A-Fa-f]:%x %*s %x", la, &lport, &st) < 3) continue;
            if (src[i].listen_only && st != 0x0A) continue;
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "protocol", json_object_new_string(src[i].proto));
            json_object_object_add(o, "port", json_object_new_int((int)lport));
            json_object_object_add(o, "state", json_object_new_string(src[i].listen_only ? "LISTEN" : "UNCONN"));
            json_object_array_add(arr, o); found++;
        }
        fclose(fp);
    }
    return found;
}

static struct json_object *net_local_ports(void)
{
    char ss[128], out[65536] = ""; int ec = 0;
    struct json_object *data = json_object_new_object(), *arr = json_object_new_array();
    const char *source = "proc";
    if (net_bin("ss", ss, sizeof(ss))) {
        char *argv[] = { ss, "-H", "-tuln", "-p", NULL };
        if (toolkit_exec_wait(argv, 4000, out, sizeof(out), &ec) == 0 && out[0]) {
            char *save = NULL, *line = strtok_r(out, "\n", &save);
            source = "ss";
            while (line) {
                char *f[8] = {0}; int nf = 0; char *t, *s2 = NULL;
                for (t = strtok_r(line, " \t", &s2); t && nf < 8; t = strtok_r(NULL, " \t", &s2)) f[nf++] = t;
                if (nf >= 5) {
                    char name[64]; int pid = 0; const char *colon = strrchr(f[4], ':');
                    net_ss_process(nf >= 7 ? f[6] : NULL, name, sizeof(name), &pid);
                    struct json_object *o = json_object_new_object();
                    json_object_object_add(o, "protocol", json_object_new_string(f[0]));
                    json_object_object_add(o, "state", json_object_new_string(f[1]));
                    json_object_object_add(o, "local_address", json_object_new_string(f[4]));
                    json_object_object_add(o, "port", json_object_new_int(colon ? atoi(colon + 1) : 0));
                    json_object_object_add(o, "process", json_object_new_string(name));
                    json_object_object_add(o, "pid", json_object_new_int(pid));
                    json_object_array_add(arr, o);
                }
                line = strtok_r(NULL, "\n", &save);
            }
        }
    }
    if (!json_object_array_length(arr)) { net_proc_ports_fallback(arr); source = "proc"; }
    json_object_object_add(data, "source", json_object_new_string(source));
    json_object_object_add(data, "count", json_object_new_int(json_object_array_length(arr)));
    json_object_object_add(data, "sockets", arr);
    return toolkit_success(data, "dreamingwrt-toolkit.local_ports");
}
/* ---- local-info ------------------------------------------------------- */

static const char *net_iface_type(const char *n)
{
    if (!strcmp(n, "lo")) return "loopback";
    if (!strncmp(n, "eth", 3) || !strncmp(n, "en", 2) || !strncmp(n, "lan", 3)) return "wired";
    if (!strncmp(n, "wl", 2) || !strncmp(n, "ra", 2) || !strncmp(n, "ath", 3)) return "wifi";
    if (!strncmp(n, "ppp", 3)) return "ppp";
    if (!strncmp(n, "docker", 6) || !strncmp(n, "br-", 3) || !strncmp(n, "veth", 4) ||
        !strncmp(n, "virbr", 5) || !strncmp(n, "tun", 3) || !strncmp(n, "tap", 3)) return "virtual";
    if (!strncmp(n, "br", 2)) return "bridge";
    return "other";
}

struct net_iface_map {
    struct json_object *arr;
    char names[64][IFNAMSIZ];
    struct json_object *objs[64];
    int n;
};

/* Return the interface object for `name`, creating it (and appending it to the
 * array, which owns it) on first sight. Grouping by name folds the several
 * getifaddrs() rows per interface into one object. */
static struct json_object *net_iface_get(struct net_iface_map *m, const char *name)
{
    struct json_object *o;
    char path[128], val[64] = "";
    for (int i = 0; i < m->n; i++)
        if (!strcmp(m->names[i], name)) return m->objs[i];
    if (m->n >= 64) return NULL;
    o = json_object_new_object();
    json_object_object_add(o, "name", json_object_new_string(name));
    json_object_object_add(o, "type", json_object_new_string(net_iface_type(name)));
    json_object_object_add(o, "addresses", json_object_new_array());
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", name);
    if (af_read_file_value(path, val, sizeof(val)) == 0) {
        str_trim(val);
        if (val[0]) json_object_object_add(o, "mac", json_object_new_string(val));
    }
    json_object_array_add(m->arr, o);
    snprintf(m->names[m->n], IFNAMSIZ, "%s", name);
    m->objs[m->n] = o;
    m->n++;
    return o;
}

static void net_collect_default_gw(struct json_object *data, int v6)
{
    char ipb[128], out[2048] = ""; int ec = 0;
    if (!net_bin("ip", ipb, sizeof(ipb))) return;
    {
        char *argv[] = { ipb, v6 ? "-6" : "-4", "route", "show", "default", NULL };
        const char *key = v6 ? "gateway_v6" : "gateway_v4";
        char *via, *dev;
        if (toolkit_exec_wait(argv, 2000, out, sizeof(out), &ec) != 0 || !out[0]) return;
        via = strstr(out, "via "); dev = strstr(out, "dev ");
        if (via) { char g[128]; if (sscanf(via + 4, "%127s", g) == 1) json_object_object_add(data, key, json_object_new_string(g)); }
        if (dev && !json_object_object_get_ex(data, "wan_ifname", NULL)) { char d[64]; if (sscanf(dev + 4, "%63s", d) == 1) json_object_object_add(data, "wan_ifname", json_object_new_string(d)); }
    }
}
static struct json_object *net_local_info(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *ifarr = json_object_new_array();
    struct json_object *dns = json_object_new_array();
    struct net_iface_map map;
    struct ifaddrs *ifa, *it;
    FILE *fp;
    char line[256];

    memset(&map, 0, sizeof(map));
    map.arr = ifarr;

    if (getifaddrs(&ifa) == 0) {
        for (it = ifa; it; it = it->ifa_next) {
            struct json_object *io;
            char buf[INET6_ADDRSTRLEN] = "";
            if (!it->ifa_addr) continue;
            io = net_iface_get(&map, it->ifa_name);
            if (!io) continue;
            if (!json_object_object_get_ex(io, "up", NULL)) {
                json_object_object_add(io, "up", json_object_new_boolean((it->ifa_flags & IFF_UP) ? 1 : 0));
                json_object_object_add(io, "running", json_object_new_boolean((it->ifa_flags & IFF_RUNNING) ? 1 : 0));
            }
            if (it->ifa_addr->sa_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in *)it->ifa_addr)->sin_addr, buf, sizeof(buf));
            else if (it->ifa_addr->sa_family == AF_INET6)
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)it->ifa_addr)->sin6_addr, buf, sizeof(buf));
            if (buf[0]) {
                struct json_object *ao, *addrs = NULL;
                ao = json_object_new_object();
                json_object_object_add(ao, "family",
                    json_object_new_string(it->ifa_addr->sa_family == AF_INET ? "ipv4" : "ipv6"));
                json_object_object_add(ao, "address", json_object_new_string(buf));
                json_object_object_get_ex(io, "addresses", &addrs);
                if (addrs) json_object_array_add(addrs, ao);
                else json_object_put(ao);
            }
        }
        freeifaddrs(ifa);
    }
    json_object_object_add(data, "interfaces", ifarr);

    fp = fopen("/etc/resolv.conf", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char srv[128];
            char *s = line;
            while (*s == ' ' || *s == '\t') s++;
            if (!strncmp(s, "nameserver", 10) && sscanf(s + 10, "%127s", srv) == 1)
                json_object_array_add(dns, json_object_new_string(srv));
        }
        fclose(fp);
    }
    json_object_object_add(data, "dns_servers", dns);

    net_collect_default_gw(data, 0);
    net_collect_default_gw(data, 1);

    return toolkit_success(data, "dreamingwrt-toolkit.local_info");
}
/* ---- arp-scan (passive neighbour table) ------------------------------- */

static struct json_object *net_arp_scan(struct json_object *payload)
{
    const char *iface = toolkit_json_str(payload, "interface", NULL);
    char ipb[128], *out, *save = NULL, *ln;
    size_t cap = 256 * 1024;
    struct json_object *data, *arr;
    int ec = 0, count = 0;
    char *argv[7];
    int ai = 0;

    if (iface && iface[0] && !toolkit_ifname_ok(iface))
        return toolkit_error("invalid_interface", "interface name is not valid");
    if (!net_bin("ip", ipb, sizeof(ipb)))
        return toolkit_error("capability_unavailable", "the 'ip' utility is not available");

    out = malloc(cap);
    if (!out) return toolkit_error("internal_error", "out of memory");
    out[0] = 0;

    argv[ai++] = ipb;
    argv[ai++] = "neigh";
    argv[ai++] = "show";
    if (iface && iface[0]) { argv[ai++] = "dev"; argv[ai++] = (char *)iface; }
    argv[ai] = NULL;
    if (toolkit_exec_wait(argv, 8000, out, cap, &ec) != 0) {
        free(out);
        return toolkit_error("exec_failed", "failed to read the neighbour table");
    }

    data = json_object_new_object();
    arr = json_object_new_array();
    for (ln = strtok_r(out, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        char ip[64] = "", dev[IFNAMSIZ] = "", mac[32] = "", state[24] = "";
        char *p;
        if (sscanf(ln, "%63s", ip) != 1 || !ip[0]) continue;
        if ((p = strstr(ln, "dev ")) != NULL) sscanf(p + 4, "%15s", dev);
        if ((p = strstr(ln, "lladdr ")) != NULL) sscanf(p + 7, "%31s", mac);
        /* state is the trailing keyword (REACHABLE/STALE/DELAY/...) */
        {
            char *tok, *s2 = NULL, *last = NULL;
            char tmp[256];
            snprintf(tmp, sizeof(tmp), "%s", ln);
            for (tok = strtok_r(tmp, " \t", &s2); tok; tok = strtok_r(NULL, " \t", &s2)) last = tok;
            if (last) snprintf(state, sizeof(state), "%s", last);
        }
        if (!mac[0] && (!strcmp(state, "FAILED") || !strcmp(state, "INCOMPLETE")))
            continue;                       /* no usable neighbour */
        {
            struct json_object *e = json_object_new_object();
            json_object_object_add(e, "ip", json_object_new_string(ip));
            if (mac[0]) json_object_object_add(e, "mac", json_object_new_string(mac));
            if (dev[0]) json_object_object_add(e, "interface", json_object_new_string(dev));
            if (state[0]) json_object_object_add(e, "state", json_object_new_string(state));
            json_object_array_add(arr, e);
            count++;
        }
    }
    free(out);
    json_object_object_add(data, "neighbors", arr);
    json_object_object_add(data, "count", json_object_new_int(count));
    json_object_object_add(data, "method", json_object_new_string("ip-neigh"));
    return toolkit_success(data, "dreamingwrt-toolkit.arp_scan");
}
/* ---- mtu-detect (DF binary search) ------------------------------------ */

/* One DF-set ping of a given payload size. Returns 1 if it passed (the packet
 * was delivered without fragmentation), 0 otherwise. */
static int net_ping_df(const char *pingb, const char *ip, int v6, int payload)
{
    char sizebuf[16], out[1024] = "";
    int ec = -1;
    char *argv[] = { (char *)pingb, v6 ? "-6" : "-4", "-M", "do", "-s", sizebuf,
                     "-c", "1", "-W", "1", (char *)ip, NULL };
    snprintf(sizebuf, sizeof(sizebuf), "%d", payload);
    if (toolkit_exec_wait(argv, 4000, out, sizeof(out), &ec) != 0) return 0;
    return ec == 0;
}

static struct json_object *net_mtu_detect(struct json_object *payload)
{
    const char *host = toolkit_json_str(payload, "host", NULL);
    struct sockaddr_storage ss;
    socklen_t slen;
    char ip[INET6_ADDRSTRLEN] = "", pingb[128];
    int v6, overhead, lo_mtu, hi_mtu, best, lo, hi;
    struct json_object *data;

    if (!host || !host[0])
        return toolkit_error("invalid_argument", "host is required");
    if (!net_target_ok(host, 255))
        return toolkit_error("invalid_argument", "host contains invalid characters");
    if (!net_bin("ping", pingb, sizeof(pingb)))
        return toolkit_error("capability_unavailable", "the 'ping' utility is not available");
    if (net_resolve_first(host, &ss, &slen, ip) != 0 || !ip[0])
        return toolkit_error("resolve_failed", "could not resolve host");

    v6 = (ss.ss_family == AF_INET6);
    overhead = v6 ? 48 : 28;              /* IPv6+ICMPv6 vs IPv4+ICMP headers */
    lo_mtu = v6 ? 1280 : 576;
    hi_mtu = 1500;

    /* Confirm the floor is reachable with DF set. If not, we cannot tell a
     * fragmentation boundary from an unreachable host or a ping without DF
     * support, so report rather than invent an MTU. */
    if (!net_ping_df(pingb, ip, v6, lo_mtu - overhead))
        return toolkit_error("mtu_probe_failed",
                             "host did not answer a DF-set ping at the minimum size");

    best = lo_mtu;
    lo = lo_mtu + 1;
    hi = hi_mtu;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (net_ping_df(pingb, ip, v6, mid - overhead)) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }

    data = json_object_new_object();
    json_object_object_add(data, "host", json_object_new_string(host));
    json_object_object_add(data, "resolved_ip", json_object_new_string(ip));
    json_object_object_add(data, "family", json_object_new_string(v6 ? "ipv6" : "ipv4"));
    json_object_object_add(data, "mtu", json_object_new_int(best));
    json_object_object_add(data, "max_payload", json_object_new_int(best - overhead));
    json_object_object_add(data, "overhead", json_object_new_int(overhead));
    return toolkit_success(data, "dreamingwrt-toolkit.mtu_detect");
}
/* ---- latency-monitor (synchronous batch) ------------------------------ */

static struct json_object *net_latency_monitor(struct json_object *payload)
{
    const char *host = toolkit_json_str(payload, "host", NULL);
    int count = toolkit_json_int(payload, "count", 10);
    double interval = 1.0;
    struct sockaddr_storage ss;
    socklen_t slen;
    char ip[INET6_ADDRSTRLEN] = "", pingb[128], cbuf[16], ibuf[32];
    char *out, *save = NULL, *ln;
    size_t cap = 128 * 1024;
    struct json_object *iv, *data, *arr;
    int ec = 0, recv = 0, v6, tmo;
    double vmin = 0, vmax = 0, sum = 0, prev = -1, jsum = 0;
    int jn = 0;

    if (!host || !host[0])
        return toolkit_error("invalid_argument", "host is required");
    if (!net_target_ok(host, 255))
        return toolkit_error("invalid_argument", "host contains invalid characters");
    if (json_object_object_get_ex(payload, "interval", &iv))
        interval = json_object_get_double(iv);
    if (count < 1) count = 1;
    if (count > 100) count = 100;
    if (interval < 0.2) interval = 0.2;
    if (interval > 10) interval = 10;
    if (!net_bin("ping", pingb, sizeof(pingb)))
        return toolkit_error("capability_unavailable", "the 'ping' utility is not available");
    if (net_resolve_first(host, &ss, &slen, ip) != 0 || !ip[0])
        return toolkit_error("resolve_failed", "could not resolve host");
    v6 = (ss.ss_family == AF_INET6);

    out = malloc(cap);
    if (!out) return toolkit_error("internal_error", "out of memory");
    out[0] = 0;
    snprintf(cbuf, sizeof(cbuf), "%d", count);
    snprintf(ibuf, sizeof(ibuf), "%.2f", interval);
    tmo = (int)(count * interval * 1000) + 6000;
    if (tmo > 190000) tmo = 190000;
    {
        char *argv[] = { pingb, v6 ? "-6" : "-4", "-c", cbuf, "-i", ibuf,
                         "-W", "2", ip, NULL };
        toolkit_exec_wait(argv, tmo, out, cap, &ec);   /* loss is expected; ignore rc */
    }

    data = json_object_new_object();
    arr = json_object_new_array();
    for (ln = strtok_r(out, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        char *t = strstr(ln, "time=");
        double v;
        if (!t) continue;
        v = strtod(t + 5, NULL);
        if (v <= 0) continue;
        json_object_array_add(arr, json_object_new_double(v));
        if (recv == 0 || v < vmin) vmin = v;
        if (recv == 0 || v > vmax) vmax = v;
        sum += v;
        if (prev >= 0) { double d = v - prev; jsum += (d < 0 ? -d : d); jn++; }
        prev = v;
        recv++;
    }
    free(out);

    json_object_object_add(data, "host", json_object_new_string(host));
    json_object_object_add(data, "resolved_ip", json_object_new_string(ip));
    json_object_object_add(data, "sent", json_object_new_int(count));
    json_object_object_add(data, "received", json_object_new_int(recv));
    json_object_object_add(data, "loss_percent",
        json_object_new_double(count ? (double)(count - recv) * 100.0 / count : 0));
    json_object_object_add(data, "min_ms", json_object_new_double(recv ? vmin : 0));
    json_object_object_add(data, "max_ms", json_object_new_double(recv ? vmax : 0));
    json_object_object_add(data, "avg_ms", json_object_new_double(recv ? sum / recv : 0));
    json_object_object_add(data, "jitter_ms", json_object_new_double(jn ? jsum / jn : 0));
    json_object_object_add(data, "samples", arr);
    return toolkit_success(data, "dreamingwrt-toolkit.latency_monitor");
}
/* ---- whois (native TCP:43) -------------------------------------------- */

/* One whois exchange: connect to <server>:43, send "<query>\r\n", read the
 * whole reply until the server closes. *out is a malloc'd NUL-terminated
 * string (caller frees). Returns 0 on success. */
static int net_whois_read(const char *server, const char *query, char **out)
{
    char ip[INET6_ADDRSTRLEN];
    char req[300], *buf;
    size_t cap = 64 * 1024, len = 0;
    int fd;
    ssize_t n;

    *out = NULL;
    fd = net_tcp_connect(server, 43, 6000, ip);
    if (fd < 0) return -1;
    snprintf(req, sizeof(req), "%s\r\n", query);
    if (write(fd, req, strlen(req)) < 0) { close(fd); return -1; }

    buf = malloc(cap);
    if (!buf) { close(fd); return -1; }
    while ((n = read(fd, buf + len, cap - len - 1)) > 0) {
        len += (size_t)n;
        if (len + 1 >= cap) {
            char *nb;
            if (cap >= 1024 * 1024) break;
            cap *= 2;
            nb = realloc(buf, cap);
            if (!nb) break;
            buf = nb;
        }
    }
    close(fd);
    buf[len] = 0;
    *out = buf;
    return 0;
}

/* If `line` begins (case-insensitively) with `key` then a colon, return a
 * pointer to the trimmed value; else NULL. */
static const char *net_kv(const char *line, const char *key)
{
    size_t kl = strlen(key);
    if (strncasecmp(line, key, kl) != 0) return NULL;
    {
        const char *p = line + kl;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != ':') return NULL;
        p++;
        while (*p == ' ' || *p == '\t') p++;
        return p;
    }
}

static void net_kv_set(struct json_object *o, const char *field, const char *val)
{
    char tmp[256];
    if (json_object_object_get_ex(o, field, NULL)) return;   /* keep first */
    snprintf(tmp, sizeof(tmp), "%s", val);
    str_trim(tmp);
    if (tmp[0]) json_object_object_add(o, field, json_object_new_string(tmp));
}
static struct json_object *net_whois(struct json_object *payload)
{
    const char *domain = toolkit_json_str(payload, "domain", NULL);
    const char *server = toolkit_json_str(payload, "server", NULL);
    char refserver[256] = "";
    char *iana_text = NULL, *text = NULL;
    struct json_object *data, *ns, *status;
    char *save = NULL, *ln;

    if (!domain || !domain[0]) domain = toolkit_json_str(payload, "query", NULL);
    if (!domain || !domain[0])
        return toolkit_error("invalid_argument", "domain is required");
    if (!net_target_ok(domain, 253))
        return toolkit_error("invalid_argument", "domain contains invalid characters");

    /* An explicit server override must be a public host (no SSRF into the LAN);
     * otherwise we discover the authoritative server from IANA's referral. */
    if (server && server[0]) {
        struct addrinfo *ai = NULL;
        if (!net_target_ok(server, 253))
            return toolkit_error("invalid_argument", "server contains invalid characters");
        if (net_host_public(server, 0, &ai) != 0)
            return toolkit_error("blocked_target", "whois server is not a public host");
        freeaddrinfo(ai);
        snprintf(refserver, sizeof(refserver), "%s", server);
    } else {
        if (net_whois_read("whois.iana.org", domain, &iana_text) == 0 && iana_text) {
            for (ln = strtok_r(iana_text, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
                const char *v = net_kv(ln, "refer");
                if (!v) v = net_kv(ln, "whois");
                if (v) { snprintf(refserver, sizeof(refserver), "%s", v); str_trim(refserver); break; }
            }
        }
    }

    if (refserver[0]) {
        if (net_whois_read(refserver, domain, &text) != 0) { free(text); text = NULL; }
    }
    if (!text) {
        /* Fall back to the IANA answer itself (works for many TLDs / IPs). */
        text = iana_text;
        iana_text = NULL;
        snprintf(refserver, sizeof(refserver), "%s", "whois.iana.org");
    }
    if (!text) {
        free(iana_text);
        return toolkit_error("whois_failed", "no whois server answered");
    }
    /* WHOIS_PARSE_MARKER */
    data = json_object_new_object();
    ns = json_object_new_array();
    status = json_object_new_array();
    json_object_object_add(data, "domain", json_object_new_string(domain));
    json_object_object_add(data, "whois_server", json_object_new_string(refserver));

    save = NULL;
    for (ln = strtok_r(text, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        const char *v;
        while (*ln == ' ' || *ln == '\t') ln++;
        if ((v = net_kv(ln, "Registrar")) || (v = net_kv(ln, "registrar")))
            net_kv_set(data, "registrar", v);
        if ((v = net_kv(ln, "Creation Date")) || (v = net_kv(ln, "created")) ||
            (v = net_kv(ln, "Registered on")))
            net_kv_set(data, "creation_date", v);
        if ((v = net_kv(ln, "Registry Expiry Date")) || (v = net_kv(ln, "Expiry Date")) ||
            (v = net_kv(ln, "paid-till")) || (v = net_kv(ln, "Expiration Date")))
            net_kv_set(data, "expiry_date", v);
        if ((v = net_kv(ln, "Updated Date")) || (v = net_kv(ln, "last-update")) ||
            (v = net_kv(ln, "changed")))
            net_kv_set(data, "updated_date", v);
        if ((v = net_kv(ln, "Name Server")) || (v = net_kv(ln, "nserver"))) {
            char t[256]; snprintf(t, sizeof(t), "%s", v); str_trim(t);
            if (t[0]) json_object_array_add(ns, json_object_new_string(t));
        }
        if ((v = net_kv(ln, "Domain Status")) || (v = net_kv(ln, "status"))) {
            char t[256]; snprintf(t, sizeof(t), "%s", v); str_trim(t);
            if (t[0]) json_object_array_add(status, json_object_new_string(t));
        }
        if ((v = net_kv(ln, "DNSSEC")))
            net_kv_set(data, "dnssec", v);
    }
    json_object_object_add(data, "name_servers", ns);
    json_object_object_add(data, "status", status);
    json_object_object_add(data, "raw", json_object_new_string(text));
    free(text);
    free(iana_text);
    return toolkit_success(data, "dreamingwrt-toolkit.whois");
}
/* ---- dns-query (dig with native A/AAAA fallback) ---------------------- */

static int net_dns_type_ok(const char *t)
{
    static const char *ok[] = { "A", "AAAA", "CNAME", "MX", "TXT", "NS",
                                "SOA", "PTR", "SRV", "CAA", NULL };
    for (int i = 0; ok[i]; i++) if (!strcasecmp(t, ok[i])) return 1;
    return 0;
}

/* Native fallback when dig is absent: resolve A/AAAA via getaddrinfo. Returns
 * the number of records appended, or -1 if the type is not supported here. */
static int net_dns_native(const char *name, const char *type, struct json_object *arr)
{
    struct addrinfo hints, *res = NULL, *it;
    int fam, added = 0;
    if (!strcasecmp(type, "A")) fam = AF_INET;
    else if (!strcasecmp(type, "AAAA")) fam = AF_INET6;
    else return -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = fam;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &res) != 0 || !res) return 0;
    for (it = res; it; it = it->ai_next) {
        char ipb[INET6_ADDRSTRLEN] = "";
        void *ap = it->ai_family == AF_INET
            ? (void *)&((struct sockaddr_in *)it->ai_addr)->sin_addr
            : (void *)&((struct sockaddr_in6 *)it->ai_addr)->sin6_addr;
        if (!inet_ntop(it->ai_family, ap, ipb, sizeof(ipb))) continue;
        {
            struct json_object *r = json_object_new_object();
            json_object_object_add(r, "name", json_object_new_string(name));
            json_object_object_add(r, "type", json_object_new_string(type));
            json_object_object_add(r, "data", json_object_new_string(ipb));
            json_object_array_add(arr, r);
            added++;
        }
    }
    freeaddrinfo(res);
    return added;
}
static struct json_object *net_dns_query(struct json_object *payload)
{
    const char *name = toolkit_json_str(payload, "name", NULL);
    const char *type = toolkit_json_str(payload, "type", "A");
    const char *server = toolkit_json_str(payload, "server", NULL);
    char digb[128], atbuf[264] = "";
    struct json_object *data, *arr;

    if (!name || !name[0]) name = toolkit_json_str(payload, "domain", NULL);
    if (!name || !name[0])
        return toolkit_error("invalid_argument", "name is required");
    if (!net_target_ok(name, 253))
        return toolkit_error("invalid_argument", "name contains invalid characters");
    if (!type || !type[0]) type = "A";
    if (!net_dns_type_ok(type))
        return toolkit_error("invalid_argument", "unsupported record type");
    if (server && server[0] && !net_target_ok(server, 253))
        return toolkit_error("invalid_argument", "server contains invalid characters");

    data = json_object_new_object();
    arr = json_object_new_array();
    json_object_object_add(data, "name", json_object_new_string(name));
    json_object_object_add(data, "type", json_object_new_string(type));
    if (server && server[0]) json_object_object_add(data, "server", json_object_new_string(server));

    if (net_bin("dig", digb, sizeof(digb))) {
        char out[64 * 1024] = "", *save = NULL, *ln;
        int ec = 0, ai = 0, count = 0;
        char *argv[10];
        argv[ai++] = digb;
        argv[ai++] = "+noall";
        argv[ai++] = "+answer";
        argv[ai++] = "+tries=2";
        argv[ai++] = "+time=3";
        if (server && server[0]) { snprintf(atbuf, sizeof(atbuf), "@%s", server); argv[ai++] = atbuf; }
        argv[ai++] = (char *)name;
        argv[ai++] = (char *)type;
        argv[ai] = NULL;
        if (toolkit_exec_wait(argv, 12000, out, sizeof(out), &ec) != 0) {
            json_object_put(data); json_object_put(arr);
            return toolkit_error("exec_failed", "dig invocation failed");
        }
        for (ln = strtok_r(out, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
            char rn[256] = "", cls[16] = "", rt[16] = ""; int ttl = 0, off = 0;
            const char *d;
            if (ln[0] == ';' || !ln[0]) continue;
            if (sscanf(ln, "%255s %d %15s %15s %n", rn, &ttl, cls, rt, &off) < 4) continue;
            d = ln + off;
            {
                struct json_object *r = json_object_new_object();
                char dbuf[1024]; snprintf(dbuf, sizeof(dbuf), "%s", d); str_trim(dbuf);
                json_object_object_add(r, "name", json_object_new_string(rn));
                json_object_object_add(r, "ttl", json_object_new_int(ttl));
                json_object_object_add(r, "type", json_object_new_string(rt));
                json_object_object_add(r, "data", json_object_new_string(dbuf));
                json_object_array_add(arr, r);
                count++;
            }
        }
        json_object_object_add(data, "provider", json_object_new_string("dig"));
        json_object_object_add(data, "records", arr);
        json_object_object_add(data, "count", json_object_new_int(count));
        return toolkit_success(data, "dreamingwrt-toolkit.dns_query");
    }

    /* dig absent: native fallback covers A/AAAA only. */
    if (server && server[0]) {
        json_object_put(data); json_object_put(arr);
        return toolkit_error("capability_unavailable",
                             "custom DNS server requires 'dig', which is not installed");
    }
    {
        int added = net_dns_native(name, type, arr);
        if (added < 0) {
            json_object_put(data); json_object_put(arr);
            return toolkit_error("capability_unavailable",
                                 "record type requires 'dig', which is not installed");
        }
        json_object_object_add(data, "provider", json_object_new_string("getaddrinfo"));
        json_object_object_add(data, "records", arr);
        json_object_object_add(data, "count", json_object_new_int(added));
        return toolkit_success(data, "dreamingwrt-toolkit.dns_query");
    }
}
/* ---- http-request / headers / website-check (libcurl, SSRF-guarded) --- */

/* Vet `host` (must be public unless allow_private) and, on success, emit a
 * CURLOPT_RESOLVE entry "host:port:ip" pinning it to the vetted address so
 * curl cannot be steered elsewhere by a rebinding DNS answer between our check
 * and its connect. Returns 0 ok, -2 blocked, -1 resolve failure. */
static int net_vet_resolve(const char *host, long port, int allow_private,
                           char *resolve, size_t rlen, char *ipout, size_t iplen)
{
    struct addrinfo *ai = NULL;
    char ip[INET6_ADDRSTRLEN] = "";
    void *ap;
    int rc = net_host_public(host, allow_private, &ai);
    if (rc != 0) return rc;
    ap = ai->ai_family == AF_INET
        ? (void *)&((struct sockaddr_in *)ai->ai_addr)->sin_addr
        : (void *)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
    inet_ntop(ai->ai_family, ap, ip, sizeof(ip));
    freeaddrinfo(ai);
    if (!ip[0]) return -1;
    snprintf(resolve, rlen, "%s:%ld:%s", host, port, ip);
    if (ipout) snprintf(ipout, iplen, "%s", ip);
    return 0;
}

/* Parse response header lines ("K: V\r\n") accumulated in `raw` into a JSON
 * object keyed by lowercase header name (last value wins). */
static struct json_object *net_headers_to_json(const char *raw)
{
    struct json_object *o = json_object_new_object();
    const char *p = raw;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
        const char *colon = memchr(p, ':', linelen);
        if (colon) {
            char key[128], val[1024];
            size_t kl = (size_t)(colon - p), vi = 0, i;
            const char *v = colon + 1;
            size_t vl = linelen - kl - 1;
            if (kl < sizeof(key)) {
                for (i = 0; i < kl; i++) key[i] = (char)tolower((unsigned char)p[i]);
                key[kl] = 0;
                while (vl && (*v == ' ' || *v == '\t')) { v++; vl--; }
                while (vl && (v[vl - 1] == '\r' || v[vl - 1] == ' ')) vl--;
                for (i = 0; i < vl && vi < sizeof(val) - 1; i++) val[vi++] = v[i];
                val[vi] = 0;
                if (key[0]) json_object_object_add(o, key, json_object_new_string(val));
            }
        }
        if (!eol) break;
        p = eol + 1;
    }
    return o;
}
/* method must be a short all-caps token (no injection into the request line). */
static int net_http_method_ok(const char *m)
{
    size_t n = m ? strlen(m) : 0;
    if (!n || n > 12) return 0;
    for (size_t i = 0; i < n; i++) if (m[i] < 'A' || m[i] > 'Z') return 0;
    return 1;
}

/* Append caller-supplied request headers (object {k:v} or array ["K: V"]) to a
 * slist, rejecting CR/LF so a value cannot inject extra headers. */
static struct curl_slist *net_build_req_headers(struct json_object *payload)
{
    struct json_object *h = NULL;
    struct curl_slist *list = NULL;
    char line[1024];
    if (!json_object_object_get_ex(payload, "headers", &h)) return NULL;
    if (json_object_is_type(h, json_type_object)) {
        json_object_object_foreach(h, k, v) {
            const char *val = json_object_get_string(v);
            if (!k || !val || strpbrk(k, "\r\n") || strpbrk(val, "\r\n")) continue;
            snprintf(line, sizeof(line), "%s: %s", k, val);
            list = curl_slist_append(list, line);
        }
    } else if (json_object_is_type(h, json_type_array)) {
        int n = json_object_array_length(h);
        for (int i = 0; i < n; i++) {
            const char *s = json_object_get_string(json_object_array_get_idx(h, i));
            if (!s || strpbrk(s, "\r\n")) continue;
            snprintf(line, sizeof(line), "%s", s);
            list = curl_slist_append(list, line);
        }
    }
    return list;
}

static struct json_object *net_http_request(struct json_object *payload, int head_only)
{
    const char *url = toolkit_json_str(payload, "url", NULL);
    const char *method = toolkit_json_str(payload, "method", head_only ? "HEAD" : "GET");
    const char *body = toolkit_json_str(payload, "body", NULL);
    int allow_private = toolkit_json_bool(payload, "allow_private", 0);
    int insecure = toolkit_json_bool(payload, "insecure", 0);
    int max_redirects = toolkit_json_int(payload, "max_redirects", 10);
    int timeout_s = toolkit_json_int(payload, "timeout", 15);
    struct net_buf bodybuf = { NULL, 0, 0 }, hdrbuf = { NULL, 0, 0 };
    struct curl_slist *reqhdrs = NULL;
    struct json_object *data, *chain, *err = NULL;
    char current[2048];
    CURL *curl;
    long final_code = 0;
    int hop;

    if (!url || !url[0]) return toolkit_error("invalid_argument", "url is required");
    if (strncasecmp(url, "http://", 7) && strncasecmp(url, "https://", 8))
        return toolkit_error("invalid_argument", "url must be http or https");
    if (!net_http_method_ok(method))
        return toolkit_error("invalid_argument", "invalid HTTP method");
    if (max_redirects < 0) max_redirects = 0;
    if (max_redirects > 10) max_redirects = 10;
    if (timeout_s < 1) timeout_s = 1;
    if (timeout_s > 120) timeout_s = 120;

    curl = curl_easy_init();
    if (!curl) return toolkit_error("internal_error", "curl init failed");
    reqhdrs = net_build_req_headers(payload);
    snprintf(current, sizeof(current), "%s", url);
    data = json_object_new_object();
    chain = json_object_new_array();
    /* HTTP_LOOP_MARKER */
    for (hop = 0; ; hop++) {
        CURLU *u = curl_url();
        char *host = NULL, *scheme = NULL, *port = NULL, *redir = NULL;
        char resolve[300] = "";
        struct curl_slist *reslist = NULL;
        long code = 0;
        double ttime = 0;
        CURLcode rc;

        if (!u) { err = toolkit_error("internal_error", "url parser init failed"); break; }
        if (curl_url_set(u, CURLUPART_URL, current, 0) != CURLUE_OK) {
            curl_url_cleanup(u);
            err = toolkit_error("invalid_argument", "malformed url");
            break;
        }
        curl_url_get(u, CURLUPART_SCHEME, &scheme, 0);
        curl_url_get(u, CURLUPART_HOST, &host, 0);
        curl_url_get(u, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT);
        if (!scheme || (strcasecmp(scheme, "http") && strcasecmp(scheme, "https")) ||
            !host || !port) {
            curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
            err = toolkit_error("invalid_argument", "unsupported url scheme");
            break;
        }
        {
            long p = strtol(port, NULL, 10);
            int vr = net_vet_resolve(host, p, allow_private, resolve, sizeof(resolve), NULL, 0);
            if (vr != 0) {
                curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
                err = toolkit_error(vr == -2 ? "blocked_target" : "resolve_failed",
                                    vr == -2 ? "target resolves to a private or reserved address"
                                             : "could not resolve target host");
                break;
            }
        }
        reslist = curl_slist_append(NULL, resolve);

        bodybuf.len = 0; if (bodybuf.data) bodybuf.data[0] = 0;
        hdrbuf.len = 0; if (hdrbuf.data) hdrbuf.data[0] = 0;

        curl_easy_reset(curl);
        curl_easy_setopt(curl, CURLOPT_URL, current);
        curl_easy_setopt(curl, CURLOPT_RESOLVE, reslist);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        if (head_only) curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        if (body && !head_only) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
        }
        if (reqhdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, reqhdrs);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, net_curl_write);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &bodybuf);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, net_curl_write);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdrbuf);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)timeout_s);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout_s);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DreamingWrt-Toolkit/1.0");
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        if (insecure) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }
        rc = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &ttime);
        curl_slist_free_all(reslist);

        if (rc != CURLE_OK) {
            curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
            err = toolkit_error("request_failed", curl_easy_strerror(rc));
            break;
        }
        {
            struct json_object *hopo = json_object_new_object();
            json_object_object_add(hopo, "url", json_object_new_string(current));
            json_object_object_add(hopo, "status", json_object_new_int((int)code));
            json_object_array_add(chain, hopo);
        }
        final_code = code;
        json_object_object_add(data, "elapsed_ms", json_object_new_double(ttime * 1000.0));

        if (code >= 300 && code < 400 && hop < max_redirects) {
            curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redir);
            if (redir && redir[0]) {
                snprintf(current, sizeof(current), "%s", redir);
                curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
                continue;
            }
        }
        curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
        break;
    }
    curl_easy_cleanup(curl);
    if (reqhdrs) curl_slist_free_all(reqhdrs);
    free(bodybuf.data);
    free(hdrbuf.data);
    if (err) { json_object_put(data); json_object_put(chain); return err; }
    json_object_object_add(data, "url", json_object_new_string(url));
    json_object_object_add(data, "status", json_object_new_int((int)final_code));
    json_object_object_add(data, "redirects", chain);
    json_object_object_add(data, "insecure", json_object_new_boolean(insecure));
    json_object_object_add(data, "tls_verified", json_object_new_boolean(insecure ? 0 : 1));
    if (hdrbuf.data) json_object_object_add(data, "headers", net_headers_to_json(hdrbuf.data));
    if (!head_only && bodybuf.data) {
        json_object_object_add(data, "body", json_object_new_string(bodybuf.data));
        json_object_object_add(data, "body_size", json_object_new_int64((int64_t)bodybuf.len));
    }
    return toolkit_success(data, head_only ? "dreamingwrt-toolkit.headers"
                                           : "dreamingwrt-toolkit.http_request");
}
/* ---- website-check (batch up/down, no redirect-follow) ---------------- */

/* One SSRF-vetted request with redirects disabled. Fills *code with the HTTP
 * status and *tls_fail when the peer certificate failed verification. Returns
 * a CURLcode; CURLE_COULDNT_RESOLVE_HOST is also used to signal a blocked
 * (private/reserved) target so the caller reports it as down, not an error. */
static CURLcode net_site_probe(CURL *curl, const char *url, int allow_private,
                               int head, int insecure, long *code, int *tls_fail)
{
    CURLU *u = curl_url();
    char *host = NULL, *scheme = NULL, *port = NULL;
    char resolve[300] = "";
    struct curl_slist *reslist = NULL;
    CURLcode rc = CURLE_URL_MALFORMAT;

    *code = 0;
    *tls_fail = 0;
    if (!u) return CURLE_OUT_OF_MEMORY;
    if (curl_url_set(u, CURLUPART_URL, url, 0) != CURLUE_OK) { curl_url_cleanup(u); return CURLE_URL_MALFORMAT; }
    curl_url_get(u, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(u, CURLUPART_HOST, &host, 0);
    curl_url_get(u, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT);
    if (!scheme || (strcasecmp(scheme, "http") && strcasecmp(scheme, "https")) || !host || !port) {
        curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
        return CURLE_UNSUPPORTED_PROTOCOL;
    }
    if (net_vet_resolve(host, strtol(port, NULL, 10), allow_private, resolve, sizeof(resolve), NULL, 0) != 0) {
        curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
        return CURLE_COULDNT_RESOLVE_HOST;      /* treated as "down"/blocked */
    }
    reslist = curl_slist_append(NULL, resolve);

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_RESOLVE, reslist);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, head ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DreamingWrt-Toolkit/1.0");
    if (insecure) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, code);
    if (rc == CURLE_PEER_FAILED_VERIFICATION || rc == CURLE_SSL_CACERT ||
        rc == CURLE_SSL_CACERT_BADFILE || rc == CURLE_SSL_CERTPROBLEM)
        *tls_fail = 1;
    curl_slist_free_all(reslist);
    curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
    return rc;
}
static struct json_object *net_website_check(struct json_object *payload)
{
    struct json_object *urls = NULL, *single = NULL, *data, *arr;
    int allow_private = toolkit_json_bool(payload, "allow_private", 0);
    CURL *curl;
    int n = 0, i, up_count = 0;

    if (json_object_object_get_ex(payload, "urls", &urls) &&
        json_object_is_type(urls, json_type_array)) {
        n = json_object_array_length(urls);
    } else if (json_object_object_get_ex(payload, "url", &single)) {
        n = 1;
    }
    if (n <= 0) return toolkit_error("invalid_argument", "url or urls[] is required");
    if (n > 50) n = 50;

    curl = curl_easy_init();
    if (!curl) return toolkit_error("internal_error", "curl init failed");

    data = json_object_new_object();
    arr = json_object_new_array();
    for (i = 0; i < n; i++) {
        const char *url = urls ? json_object_get_string(json_object_array_get_idx(urls, i))
                               : json_object_get_string(single);
        long code = 0;
        int tls_fail = 0, ssl_valid = 1, up;
        CURLcode rc;
        struct json_object *e;

        if (!url || (strncasecmp(url, "http://", 7) && strncasecmp(url, "https://", 8))) {
            e = json_object_new_object();
            json_object_object_add(e, "url", json_object_new_string(url ? url : ""));
            json_object_object_add(e, "up", json_object_new_boolean(0));
            json_object_object_add(e, "error", json_object_new_string("invalid url"));
            json_object_array_add(arr, e);
            continue;
        }
        rc = net_site_probe(curl, url, allow_private, 1, 0, &code, &tls_fail);
        if (tls_fail) { ssl_valid = 0; rc = net_site_probe(curl, url, allow_private, 1, 1, &code, &tls_fail); }
        if (rc == CURLE_OK && (code == 405 || code == 403 || code == 404)) {
            rc = net_site_probe(curl, url, allow_private, 0, ssl_valid ? 0 : 1, &code, &tls_fail);
            if (tls_fail && ssl_valid) { ssl_valid = 0; rc = net_site_probe(curl, url, allow_private, 0, 1, &code, &tls_fail); }
        } else if (rc != CURLE_OK && rc != CURLE_COULDNT_RESOLVE_HOST && !tls_fail) {
            rc = net_site_probe(curl, url, allow_private, 0, ssl_valid ? 0 : 1, &code, &tls_fail);
            if (tls_fail && ssl_valid) { ssl_valid = 0; rc = net_site_probe(curl, url, allow_private, 0, 1, &code, &tls_fail); }
        }
        up = (rc == CURLE_OK && code >= 200 && code < 400);
        if (up) up_count++;

        e = json_object_new_object();
        json_object_object_add(e, "url", json_object_new_string(url));
        json_object_object_add(e, "up", json_object_new_boolean(up));
        json_object_object_add(e, "status", json_object_new_int((int)code));
        json_object_object_add(e, "sslValid", json_object_new_boolean(ssl_valid));
        if (rc != CURLE_OK)
            json_object_object_add(e, "error", json_object_new_string(curl_easy_strerror(rc)));
        json_object_array_add(arr, e);
    }
    curl_easy_cleanup(curl);
    json_object_object_add(data, "results", arr);
    json_object_object_add(data, "total", json_object_new_int(n));
    json_object_object_add(data, "up", json_object_new_int(up_count));
    json_object_object_add(data, "down", json_object_new_int(n - up_count));
    return toolkit_success(data, "dreamingwrt-toolkit.website_check");
}
/* ---- external-lookup tools (gated by [toolkit] external_lookup) -------- */

/* Simple GET against a fixed, trusted external endpoint (ip-api / macvendors).
 * The host is never caller-controlled, only the path segment is, and that is
 * validated by each caller, so no per-hop SSRF vetting is needed here. TLS
 * verification stays on. Returns the HTTP status, or -1 on transport failure;
 * *out is a malloc'd body (caller frees) or NULL. */
static long net_ext_get(const char *url, char **out)
{
    CURL *curl = curl_easy_init();
    struct net_buf buf = { NULL, 0, 0 };
    long code = -1;
    *out = NULL;
    if (!curl) return -1;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, net_curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 12L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DreamingWrt-Toolkit/1.0");
    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    *out = buf.data;
    return code;
}

/* Copy selected string/number fields from an ip-api.com JSON object into dst. */
static void net_ipapi_copy(struct json_object *src, struct json_object *dst)
{
    static const char *keys[] = { "country", "countryCode", "regionName", "city",
                                   "zip", "lat", "lon", "timezone", "isp", "org",
                                   "as", "query", "mobile", "proxy", "hosting", NULL };
    for (int i = 0; keys[i]; i++) {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(src, keys[i], &v))
            json_object_object_add(dst, keys[i], json_object_get(v));
    }
}

static struct json_object *net_public_ip(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *local = json_object_new_array();
    struct ifaddrs *ifa, *it;
    int ext = net_external_lookup_enabled();

    if (getifaddrs(&ifa) == 0) {
        for (it = ifa; it; it = it->ifa_next) {
            char ipb[INET6_ADDRSTRLEN] = "";
            if (!it->ifa_addr) continue;
            if (it->ifa_addr->sa_family != AF_INET && it->ifa_addr->sa_family != AF_INET6) continue;
            if (net_sa_is_blocked(it->ifa_addr)) continue;   /* only globally-routable */
            if (it->ifa_addr->sa_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in *)it->ifa_addr)->sin_addr, ipb, sizeof(ipb));
            else
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)it->ifa_addr)->sin6_addr, ipb, sizeof(ipb));
            if (ipb[0]) {
                struct json_object *o = json_object_new_object();
                json_object_object_add(o, "interface", json_object_new_string(it->ifa_name));
                json_object_object_add(o, "family",
                    json_object_new_string(it->ifa_addr->sa_family == AF_INET ? "ipv4" : "ipv6"));
                json_object_object_add(o, "address", json_object_new_string(ipb));
                json_object_array_add(local, o);
            }
        }
        freeifaddrs(ifa);
    }
    json_object_object_add(data, "local_public_addresses", local);
    json_object_object_add(data, "external_lookup", json_object_new_boolean(ext));

    if (ext) {
        char *body = NULL;
        long code = net_ext_get("http://ip-api.com/json/?lang=zh-CN&fields=status,message,"
                                "country,countryCode,regionName,city,zip,lat,lon,timezone,"
                                "isp,org,as,query,mobile,proxy,hosting", &body);
        if (code == 200 && body) {
            struct json_object *j = json_tokener_parse(body), *q = NULL;
            if (j) {
                if (json_object_object_get_ex(j, "query", &q))
                    json_object_object_add(data, "public_ip", json_object_get(q));
                net_ipapi_copy(j, data);
                json_object_put(j);
            }
        }
        free(body);
    } else {
        json_object_object_add(data, "note",
            json_object_new_string("公网 IP 探测需要外部查询（当前已关闭 external_lookup）"));
    }
    return toolkit_success(data, "dreamingwrt-toolkit.public_ip");
}
static struct json_object *net_ip_geo(struct json_object *payload)
{
    const char *q = toolkit_json_str(payload, "ip", NULL);
    char url[512];
    char *body = NULL;
    long code;
    struct json_object *data, *j, *st = NULL;

    if (!net_external_lookup_enabled())
        return toolkit_error("external_lookup_disabled",
                             "external lookups are disabled by [toolkit] external_lookup");
    if (!q || !q[0]) q = toolkit_json_str(payload, "host", NULL);
    if (!q || !q[0]) q = toolkit_json_str(payload, "query", NULL);
    if (!q || !q[0])
        return toolkit_error("invalid_argument", "ip is required");
    if (!net_target_ok(q, 253))
        return toolkit_error("invalid_argument", "ip/host contains invalid characters");

    snprintf(url, sizeof(url),
             "http://ip-api.com/json/%s?lang=zh-CN&fields=status,message,country,"
             "countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,"
             "query,mobile,proxy,hosting", q);
    code = net_ext_get(url, &body);
    if (code != 200 || !body) {
        free(body);
        return toolkit_error("lookup_failed", "geolocation provider did not answer");
    }
    j = json_tokener_parse(body);
    free(body);
    if (!j) return toolkit_error("lookup_failed", "malformed provider response");
    if (json_object_object_get_ex(j, "status", &st) &&
        strcmp(json_object_get_string(st), "success") != 0) {
        struct json_object *m = NULL;
        const char *msg = json_object_object_get_ex(j, "message", &m) ? json_object_get_string(m) : "lookup failed";
        struct json_object *e = toolkit_error("lookup_failed", msg);
        json_object_put(j);
        return e;
    }
    data = json_object_new_object();
    net_ipapi_copy(j, data);
    {
        struct json_object *rev = NULL;
        if (json_object_object_get_ex(j, "reverse", &rev))
            json_object_object_add(data, "reverse", json_object_get(rev));
    }
    json_object_put(j);
    return toolkit_success(data, "dreamingwrt-toolkit.ip_geo");
}

static struct json_object *net_mac_lookup(struct json_object *payload)
{
    const char *mac = toolkit_json_str(payload, "mac", NULL);
    unsigned char raw[6];
    char oui[16], url[128], *body = NULL;
    long code;
    struct json_object *data;

    if (!net_external_lookup_enabled())
        return toolkit_error("external_lookup_disabled",
                             "external lookups are disabled by [toolkit] external_lookup");
    if (!mac || !mac[0] || toolkit_mac_parse(mac, raw) != 0)
        return toolkit_error("invalid_argument", "a valid MAC address is required");
    snprintf(oui, sizeof(oui), "%02X:%02X:%02X", raw[0], raw[1], raw[2]);
    snprintf(url, sizeof(url), "https://api.macvendors.com/%s", oui);

    code = net_ext_get(url, &body);
    data = json_object_new_object();
    json_object_object_add(data, "mac", json_object_new_string(mac));
    json_object_object_add(data, "oui", json_object_new_string(oui));
    if (code == 200 && body && body[0]) {
        char v[256]; snprintf(v, sizeof(v), "%s", body); str_trim(v);
        json_object_object_add(data, "vendor", json_object_new_string(v));
        json_object_object_add(data, "found", json_object_new_boolean(1));
    } else if (code == 404) {
        json_object_object_add(data, "found", json_object_new_boolean(0));
    } else {
        free(body);
        json_object_put(data);
        return toolkit_error("lookup_failed", "vendor lookup provider did not answer");
    }
    free(body);
    return toolkit_success(data, "dreamingwrt-toolkit.mac_lookup");
}
/* ---- speedtest (async job, Cloudflare via libcurl) -------------------- */

/* Download sink: count bytes, store nothing (the payload is tens of MB). */
static size_t net_curl_discard(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    (void)ptr;
    if (opaque) *(uint64_t *)opaque += (uint64_t)(size * nmemb);
    return size * nmemb;
}

struct net_upsrc { size_t remaining; };

/* Upload source: feed `remaining` bytes of a static filler. */
static size_t net_upload_read(char *buffer, size_t size, size_t nitems, void *opaque)
{
    struct net_upsrc *u = opaque;
    size_t want = size * nitems;
    if (u->remaining < want) want = u->remaining;
    if (want) { memset(buffer, 'x', want); u->remaining -= want; }
    return want;
}

static int net_job_write(const char *path, struct json_object *o)
{
    char tmp[600]; const char *raw; int fd;
    snprintf(tmp, sizeof(tmp), "%s.tmp-%ld", path, (long)getpid());
    raw = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || !raw || write(fd, raw, strlen(raw)) != (ssize_t)strlen(raw)) {
        if (fd >= 0) close(fd);
        unlink(tmp);
        return -1;
    }
    if (close(fd) != 0 || rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static struct json_object *net_job_read(const char *path)
{
    struct stat st; char *raw; struct json_object *o;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > 1024 * 1024) {
        if (fd >= 0) close(fd);
        return NULL;
    }
    raw = malloc((size_t)st.st_size + 1);
    if (!raw) { close(fd); return NULL; }
    if (read(fd, raw, (size_t)st.st_size) != st.st_size) { free(raw); close(fd); return NULL; }
    close(fd);
    raw[st.st_size] = 0;
    o = json_tokener_parse(raw);
    free(raw);
    return o;
}

static int net_speed_id_ok(const char *id)
{
    return id && !strncmp(id, "speed-", 6) && toolkit_token_ok(id, 80) && !strchr(id, '/');
}

static int net_pid_is_toolkit(pid_t pid)
{
    char path[64], comm[64] = "";
    FILE *fp;
    if (pid <= 1 || kill(pid, 0) != 0) return 0;
    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    fp = fopen(path, "r");
    if (!fp) return 0;
    if (!fgets(comm, sizeof(comm), fp)) comm[0] = 0;
    fclose(fp);
    comm[strcspn(comm, "\r\n")] = 0;
    return strstr(comm, "toolkit") != NULL;   /* our own one-shot binary */
}
static void net_speed_progress(const char *path, const char *phase, const char *state,
                               double latency, double jitter, double dl, double ul, int done)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "phase", json_object_new_string(phase));
    json_object_object_add(o, "state", json_object_new_string(state));
    if (latency > 0) json_object_object_add(o, "latency_ms", json_object_new_double(latency));
    if (jitter >= 0 && latency > 0) json_object_object_add(o, "jitter_ms", json_object_new_double(jitter));
    if (dl > 0) json_object_object_add(o, "download_mbps", json_object_new_double(dl));
    if (ul > 0) json_object_object_add(o, "upload_mbps", json_object_new_double(ul));
    json_object_object_add(o, "done", json_object_new_boolean(done));
    json_object_object_add(o, "updated_at", json_object_new_int64(toolkit_now_s()));
    net_job_write(path, o);
    json_object_put(o);
}

/* Runs in the forked child. Measures latency/jitter, download and upload speed
 * against Cloudflare's speedtest endpoints, writing an updated snapshot to
 * result_path after each phase so a polling client sees incremental progress. */
static void net_speed_measure(const char *result_path)
{
    double latency = 0, jitter = 0, dl_mbps = 0, ul_mbps = 0;
    double samples[3]; int got = 0, i;

    for (i = 0; i < 3; i++) {
        CURL *c = curl_easy_init();
        uint64_t sink = 0; double ct = 0;
        if (!c) continue;
        curl_easy_setopt(c, CURLOPT_URL, "https://speed.cloudflare.com/cdn-cgi/trace");
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, net_curl_discard);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(c, CURLOPT_USERAGENT, "DreamingWrt-Toolkit/1.0");
        if (curl_easy_perform(c) == CURLE_OK) {
            curl_easy_getinfo(c, CURLINFO_CONNECT_TIME, &ct);
            if (ct > 0) samples[got++] = ct * 1000.0;
        }
        curl_easy_cleanup(c);
    }
    if (got) {
        double sum = 0, jsum = 0; int jn = 0;
        for (i = 0; i < got; i++) { sum += samples[i]; if (i) { double d = samples[i] - samples[i - 1]; jsum += d < 0 ? -d : d; jn++; } }
        latency = sum / got;
        jitter = jn ? jsum / jn : 0;
    }
    net_speed_progress(result_path, "latency", "running", latency, jitter, 0, 0, 0);

    {
        CURL *c = curl_easy_init();
        uint64_t sink = 0; curl_off_t spd = 0;
        if (c) {
            curl_easy_setopt(c, CURLOPT_URL, "https://speed.cloudflare.com/__down?bytes=26214400");
            curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, net_curl_discard);
            curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
            curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
            curl_easy_setopt(c, CURLOPT_TIMEOUT, 40L);
            curl_easy_setopt(c, CURLOPT_USERAGENT, "DreamingWrt-Toolkit/1.0");
            if (curl_easy_perform(c) == CURLE_OK) {
                curl_easy_getinfo(c, CURLINFO_SPEED_DOWNLOAD_T, &spd);
                dl_mbps = (double)spd * 8.0 / 1e6;
            }
            curl_easy_cleanup(c);
        }
    }
    net_speed_progress(result_path, "download", "running", latency, jitter, dl_mbps, 0, 0);
    /* SPEED_UPLOAD_MARKER */
    {
        CURL *c = curl_easy_init();
        struct net_upsrc up = { 10 * 1024 * 1024 };
        uint64_t sink = 0; curl_off_t spd = 0;
        if (c) {
            curl_easy_setopt(c, CURLOPT_URL, "https://speed.cloudflare.com/__up");
            curl_easy_setopt(c, CURLOPT_POST, 1L);
            curl_easy_setopt(c, CURLOPT_READFUNCTION, net_upload_read);
            curl_easy_setopt(c, CURLOPT_READDATA, &up);
            curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)up.remaining);
            curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, net_curl_discard);
            curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
            curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
            curl_easy_setopt(c, CURLOPT_TIMEOUT, 40L);
            curl_easy_setopt(c, CURLOPT_USERAGENT, "DreamingWrt-Toolkit/1.0");
            if (curl_easy_perform(c) == CURLE_OK) {
                curl_easy_getinfo(c, CURLINFO_SPEED_UPLOAD_T, &spd);
                ul_mbps = (double)spd * 8.0 / 1e6;
            }
            curl_easy_cleanup(c);
        }
    }
    net_speed_progress(result_path, "done", "completed", latency, jitter, dl_mbps, ul_mbps, 1);
}
static struct json_object *net_speedtest_start(struct json_object *payload)
{
    char id[96], meta_path[512], result_path[512];
    const char *actor = toolkit_json_str(payload, "actor", "");
    struct json_object *meta;
    pid_t pid;

    if (toolkit_runtime_dir_ready() != 0)
        return toolkit_error("runtime_storage_unavailable", "toolkit runtime directory is unavailable");
    snprintf(id, sizeof(id), "speed-%lld-%ld", (long long)toolkit_now_s(), (long)getpid());
    snprintf(meta_path, sizeof(meta_path), "%s/%s.json", TOOLKIT_RUNTIME_DIR, id);
    snprintf(result_path, sizeof(result_path), "%s/%s.result.json", TOOLKIT_RUNTIME_DIR, id);

    /* Seed a snapshot so an immediate status poll sees the running job. */
    net_speed_progress(result_path, "init", "running", 0, -1, 0, 0, 0);

    pid = fork();
    if (pid < 0) { unlink(result_path); return toolkit_error("speedtest_start_failed", strerror(errno)); }
    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDWR);
        setsid();
        if (nullfd >= 0) { dup2(nullfd, STDIN_FILENO); dup2(nullfd, STDOUT_FILENO); dup2(nullfd, STDERR_FILENO); if (nullfd > 2) close(nullfd); }
        net_speed_measure(result_path);
        _exit(0);
    }

    meta = json_object_new_object();
    json_object_object_add(meta, "id", json_object_new_string(id));
    json_object_object_add(meta, "pid", json_object_new_int(pid));
    json_object_object_add(meta, "actor", json_object_new_string(actor));
    json_object_object_add(meta, "started_at", json_object_new_int64(toolkit_now_s()));
    if (net_job_write(meta_path, meta) != 0) {
        kill(pid, SIGTERM); json_object_put(meta); unlink(result_path);
        return toolkit_error("speedtest_start_failed", "could not persist task metadata");
    }
    json_object_object_add(meta, "state", json_object_new_string("running"));
    json_object_object_add(meta, "provider", json_object_new_string("cloudflare"));
    return toolkit_success(meta, "dreamingwrt-toolkit.speedtest");
}

static struct json_object *net_speedtest_status(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", "");
    char meta_path[512], result_path[512];
    struct json_object *meta, *result;
    int done = 0, running;
    pid_t pid;

    if (!net_speed_id_ok(id)) return toolkit_error("invalid_speedtest_id", "speedtest id is invalid");
    snprintf(meta_path, sizeof(meta_path), "%s/%s.json", TOOLKIT_RUNTIME_DIR, id);
    snprintf(result_path, sizeof(result_path), "%s/%s.result.json", TOOLKIT_RUNTIME_DIR, id);
    meta = net_job_read(meta_path);
    if (!meta) return toolkit_error("speedtest_not_found", "speedtest task was not found");

    pid = (pid_t)toolkit_json_int(meta, "pid", 0);
    running = net_pid_is_toolkit(pid);
    result = net_job_read(result_path);
    if (result) {
        done = toolkit_json_bool(result, "done", 0);
        json_object_object_add(meta, "result", result);
    }
    json_object_object_add(meta, "state",
        json_object_new_string(done ? "completed" : (running ? "running" : "completed")));
    return toolkit_success(meta, "dreamingwrt-toolkit.speedtest");
}

static struct json_object *net_speedtest_stop(struct json_object *payload)
{
    const char *id = toolkit_json_str(payload, "id", "");
    char meta_path[512], result_path[512];
    struct json_object *meta;
    pid_t pid;

    if (!net_speed_id_ok(id)) return toolkit_error("invalid_speedtest_id", "speedtest id is invalid");
    snprintf(meta_path, sizeof(meta_path), "%s/%s.json", TOOLKIT_RUNTIME_DIR, id);
    snprintf(result_path, sizeof(result_path), "%s/%s.result.json", TOOLKIT_RUNTIME_DIR, id);
    meta = net_job_read(meta_path);
    if (!meta) return toolkit_error("speedtest_not_found", "speedtest task was not found");
    pid = (pid_t)toolkit_json_int(meta, "pid", 0);
    if (net_pid_is_toolkit(pid)) kill(-pid, SIGTERM);
    json_object_object_add(meta, "state", json_object_new_string("stopped"));
    json_object_object_add(meta, "stopped_at", json_object_new_int64(toolkit_now_s()));
    net_job_write(meta_path, meta);
    (void)result_path;
    return toolkit_success(meta, "dreamingwrt-toolkit.speedtest");
}
/* ---- mdns (multicast DNS service discovery) --------------------------- */

/* Service types look like "_http._tcp" — underscores and dots are legal, so
 * net_target_ok (which forbids '_' and a leading '.') is the wrong screen.
 * This accepts the RFC 6763 service-type charset and nothing that execv would
 * treat as an option or a shell would treat as a metacharacter. */
static int net_service_type_ok(const char *s)
{
    size_t len = s ? strlen(s) : 0;
    if (!len || len > 128 || s[0] == '-')
        return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '-' && c != '_')
            return 0;
    }
    return 1;
}

static struct json_object *net_mdns(struct json_object *payload)
{
    const char *type = toolkit_json_str(payload, "service_type",
                                        toolkit_json_str(payload, "type", ""));
    int timeout_ms = toolkit_json_int(payload, "timeout_ms", 5000);
    char browseb[128], *out, *save = NULL, *ln;
    size_t cap = 256 * 1024;
    struct json_object *data, *arr;
    int ec = 0, count = 0, ai = 0;
    char *argv[8];

    if (type[0] && !net_service_type_ok(type))
        return toolkit_error("invalid_service_type", "service type contains illegal characters");
    if (timeout_ms < 1000) timeout_ms = 1000;
    if (timeout_ms > 15000) timeout_ms = 15000;

    /* Our own mDNS component (dreamingwrt-mdns-advert) only advertises and
     * exposes no browse interface, so on-demand discovery shells out to
     * avahi-browse. A native multicast query is a documented future step. */
    if (!net_bin("avahi-browse", browseb, sizeof(browseb)))
        return toolkit_error("capability_unavailable", "avahi-browse is not available for mDNS discovery");

    out = malloc(cap);
    if (!out) return toolkit_error("out_of_memory", "discovery buffer allocation failed");
    out[0] = 0;

    argv[ai++] = browseb;
    argv[ai++] = "-t";                       /* terminate once the cache settles */
    argv[ai++] = "-r";                       /* resolve hostnames and addresses */
    argv[ai++] = "-p";                       /* parseable, one record per line */
    if (type[0]) argv[ai++] = (char *)type;
    else argv[ai++] = "-a";                  /* all service types */
    argv[ai] = NULL;

    if (toolkit_exec_wait(argv, timeout_ms, out, cap, &ec) != 0) {
        free(out);
        return toolkit_error("exec_failed", "failed to run avahi-browse");
    }

    data = json_object_new_object();
    arr = json_object_new_array();
    /* Resolved records start with '='; fields are ';'-separated:
     * =;iface;proto;name;type;domain;host;address;port;txt */
    for (ln = strtok_r(out, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        char *f[10];
        int nf = 0;
        char *p = ln;
        if (ln[0] != '=') continue;
        while (nf < 10) {
            f[nf++] = p;
            if (nf == 10) break;             /* field 10 keeps the txt remainder */
            p = strchr(p, ';');
            if (!p) break;
            *p++ = 0;
        }
        if (nf < 9) continue;                /* malformed / unresolved row */
        {
            struct json_object *e = json_object_new_object();
            json_object_object_add(e, "interface", json_object_new_string(f[1]));
            json_object_object_add(e, "protocol", json_object_new_string(f[2]));
            json_object_object_add(e, "name", json_object_new_string(f[3]));
            json_object_object_add(e, "type", json_object_new_string(f[4]));
            json_object_object_add(e, "domain", json_object_new_string(f[5]));
            json_object_object_add(e, "host", json_object_new_string(f[6]));
            json_object_object_add(e, "address", json_object_new_string(f[7]));
            json_object_object_add(e, "port", json_object_new_int(atoi(f[8])));
            if (nf >= 10 && f[9][0]) json_object_object_add(e, "txt", json_object_new_string(f[9]));
            json_object_array_add(arr, e);
            count++;
        }
    }
    free(out);

    if (!count && ec != 0) {
        json_object_put(arr);
        json_object_put(data);
        return toolkit_error("mdns_unavailable", "the mDNS (Avahi) daemon is unavailable");
    }

    json_object_object_add(data, "services", arr);
    json_object_object_add(data, "count", json_object_new_int(count));
    json_object_object_add(data, "method", json_object_new_string("avahi-browse"));
    return toolkit_success(data, "dreamingwrt-toolkit.mdns");
}
/* ---- dispatch --------------------------------------------------------- */

/* Returns the response for a network command, or NULL when `command` is not one
 * of ours (so the main dispatcher can fall through to unknown_command). */
struct json_object *toolkit_net_dispatch(const char *command, struct json_object *payload)
{
    if (!strcmp(command, "port-scan")) return net_port_scan(payload, 0);
    if (!strcmp(command, "port-check")) return net_port_scan(payload, 1);
    if (!strcmp(command, "tcp-udp-test")) return net_tcp_udp_test(payload);
    if (!strcmp(command, "ssl-check")) return net_ssl_check(payload);
    if (!strcmp(command, "local-ports")) return net_local_ports();
    if (!strcmp(command, "local-info")) return net_local_info();
    if (!strcmp(command, "arp-scan")) return net_arp_scan(payload);
    if (!strcmp(command, "mtu-detect")) return net_mtu_detect(payload);
    if (!strcmp(command, "latency-monitor")) return net_latency_monitor(payload);
    if (!strcmp(command, "whois")) return net_whois(payload);
    if (!strcmp(command, "dns-query")) return net_dns_query(payload);
    if (!strcmp(command, "http-request")) return net_http_request(payload, 0);
    if (!strcmp(command, "headers")) return net_http_request(payload, 1);
    if (!strcmp(command, "website-check")) return net_website_check(payload);
    if (!strcmp(command, "public-ip")) return net_public_ip();
    if (!strcmp(command, "ip-geo")) return net_ip_geo(payload);
    if (!strcmp(command, "mac-lookup")) return net_mac_lookup(payload);
    if (!strcmp(command, "mdns")) return net_mdns(payload);
    if (!strcmp(command, "speedtest-start")) return net_speedtest_start(payload);
    if (!strcmp(command, "speedtest-status")) return net_speedtest_status(payload);
    if (!strcmp(command, "speedtest-stop")) return net_speedtest_stop(payload);
    return NULL;
}
