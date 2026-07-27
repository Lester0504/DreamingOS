// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
/* DreamingWrt client identity collectors: mDNS, SSDP, DHCP lease evidence. */
#include "jmx_identity_collector.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libubox/uloop.h>

#include "jmx.h"
#include "jmx_db.h"
#include "jmx_user.h"

#define JMX_ID_BUF 2048

static struct uloop_fd g_mdns_fd = { .fd = -1 };
static struct uloop_fd g_ssdp_fd = { .fd = -1 };
static struct uloop_fd g_dhcp_fd = { .fd = -1 };

static void trim_crlf(char *s)
{
    size_t n;
    if (!s) return;
    while (*s && isspace((unsigned char)*s)) memmove(s, s + 1, strlen(s));
    n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int make_mcast_socket(const char *group, int port)
{
    int fd, on = 1;
    struct sockaddr_in addr;
    struct ip_mreq mreq;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(group);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    set_nonblock(fd);
    return fd;
}

/* Pending signal buffer: signals received before IP→MAC mapping existed.
 * Stored as a ring buffer; replayed after ARP table populates mappings. */
#define PENDING_SIG_MAX 128
typedef struct {
    char ip[64];
    char source[32];
    char key[64];
    char value[256];
    int confidence;
    int used;
} pending_signal_t;
static pending_signal_t g_pending_sigs[PENDING_SIG_MAX];
static int g_pending_head = 0;

static void store_pending_signal(const char *ip, const char *source, const char *key, const char *value, int confidence)
{
    if (!ip || !source || !key || !value) return;
    pending_signal_t *p = &g_pending_sigs[g_pending_head % PENDING_SIG_MAX];
    snprintf(p->ip, sizeof(p->ip), "%s", ip);
    snprintf(p->source, sizeof(p->source), "%s", source);
    snprintf(p->key, sizeof(p->key), "%s", key);
    snprintf(p->value, sizeof(p->value), "%s", value);
    p->confidence = confidence;
    p->used = 1;
    g_pending_head++;
}

static void flush_pending_ip_signals(void)
{
    int i, flushed = 0;
    for (i = 0; i < PENDING_SIG_MAX && i < g_pending_head; i++) {
        pending_signal_t *p = &g_pending_sigs[i];
        if (!p->used || !p->ip[0]) continue;
        int rc = jmx_db_observe_signal_by_ip(p->ip, p->source, p->key, p->value, p->confidence, "");
        if (rc == 0) { flushed++; p->used = 0; }
    }
    if (flushed > 0) LOG_INFO("identity: flushed pending signals");
}


static void observe_ip(const char *ip, const char *source, const char *key, const char *value, int conf, const char *raw)
{
    if (!ip || !ip[0] || !value || !value[0]) return;
    int rc = jmx_db_observe_signal_by_ip(ip, source, key, value, conf, raw ? raw : "");
    if (rc != 0) {
        /* IP→MAC mapping not yet known; buffer for later replay after ARP scan */
        store_pending_signal(ip, source, key, value, conf);
    }
}

static void scan_printable_tokens(const unsigned char *buf, int len, const char *ip, const char *source)
{
    char tok[256];
    int n = 0, i;
    for (i = 0; i <= len; i++) {
        int c = (i < len) ? buf[i] : 0;
        if (i < len && c >= 32 && c <= 126 && n < (int)sizeof(tok) - 1) {
            tok[n++] = (char)c;
            continue;
        }
        if (n >= 3) {
            tok[n] = '\0';
            if (strstr(tok, "model=")) observe_ip(ip, source, "model", strchr(tok, '=') + 1, 90, tok);
            else if (strstr(tok, "_device-info._tcp")) observe_ip(ip, source, "service", "_device-info._tcp", 85, tok);
            else if (strstr(tok, "_airplay._tcp")) observe_ip(ip, source, "service", "_airplay._tcp", 75, tok);
            else if (strstr(tok, "_homekit._tcp")) observe_ip(ip, source, "service", "_homekit._tcp", 75, tok);
            else if (strstr(tok, "_googlecast._tcp")) observe_ip(ip, source, "service", "_googlecast._tcp", 75, tok);
            else if (strstr(tok, "_printer._tcp")) observe_ip(ip, source, "service", "_printer._tcp", 75, tok);
        }
        n = 0;
    }
}

static void mdns_cb(struct uloop_fd *u, unsigned int events)
{
    unsigned char buf[JMX_ID_BUF];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    char ip[INET_ADDRSTRLEN];
    int n;
    (void)events;
    while ((n = recvfrom(u->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen)) > 0) {
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        scan_printable_tokens(buf, n, ip, "mdns");
    }
}

static char *header_value(char *msg, const char *name)
{
    size_t nl = strlen(name);
    char *p = msg;
    while (p && *p) {
        char *e = strstr(p, "\r\n");
        if (e) *e = '\0';
        if (!strncasecmp(p, name, nl) && p[nl] == ':') {
            char *v = p + nl + 1;
            trim_crlf(v);
            return v;
        }
        if (!e) break;
        *e = '\r';
        p = e + 2;
    }
    return NULL;
}


static int is_private_ipv4(const char *ip)
{
    unsigned int a,b,c,d;
    if (!ip || sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a == 10) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 169 && b == 254) return 1;
    return 0;
}

static int parse_http_url(const char *url, char *host, size_t host_len, int *port, char *path, size_t path_len)
{
    const char *p, *slash, *colon;
    size_t hl;
    if (!url || strncasecmp(url, "http://", 7)) return -1;
    p = url + 7;
    slash = strchr(p, '/');
    if (!slash) return -1;
    colon = memchr(p, ':', slash - p);
    if (colon) {
        hl = (size_t)(colon - p);
        *port = atoi(colon + 1);
    } else {
        hl = (size_t)(slash - p);
        *port = 80;
    }
    if (hl == 0 || hl >= host_len || *port <= 0 || *port > 65535) return -1;
    memcpy(host, p, hl); host[hl] = '\0';
    snprintf(path, path_len, "%s", slash);
    return 0;
}

static int http_fetch_small(const char *host, int port, const char *path, char *out, size_t out_len)
{
    int fd, n, total = 0;
    struct sockaddr_in sa;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    char req[512];
    if (!is_private_ipv4(host) || !out || out_len < 2) return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: jmxd/identity\r\nConnection: close\r\n\r\n", path, host);
    if (send(fd, req, strlen(req), 0) < 0) { close(fd); return -1; }
    while (total < (int)out_len - 1 && (n = recv(fd, out + total, out_len - 1 - total, 0)) > 0)
        total += n;
    close(fd);
    out[total] = '\0';
    return total > 0 ? total : -1;
}

static int xml_text(const char *xml, const char *tag, char *out, size_t out_len)
{
    char open[64], close_tag[64];
    const char *a, *b;
    size_t n;
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    a = strcasestr(xml, open);
    if (!a) return -1;
    a += strlen(open);
    b = strcasestr(a, close_tag);
    if (!b) return -1;
    n = (size_t)(b - a);
    if (n >= out_len) n = out_len - 1;
    memcpy(out, a, n); out[n] = '\0';
    trim_crlf(out);
    return out[0] ? 0 : -1;
}

static void fetch_ssdp_location_xml(const char *src_ip, const char *location)
{
    char host[64], path[256], xml[8192], val[256];
    int port = 80;
    if (parse_http_url(location, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return;
    if (strcmp(host, src_ip) && !is_private_ipv4(host))
        return;
    if (http_fetch_small(host, port, path, xml, sizeof(xml)) <= 0)
        return;
    if (xml_text(xml, "friendlyName", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "friendlyName", val, 85, location);
    if (xml_text(xml, "manufacturer", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "manufacturer", val, 85, location);
    if (xml_text(xml, "modelName", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "modelName", val, 88, location);
    if (xml_text(xml, "modelNumber", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "modelNumber", val, 80, location);
    if (xml_text(xml, "deviceType", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "deviceType", val, 80, location);
}

static void ssdp_cb(struct uloop_fd *u, unsigned int events)
{
    char buf[JMX_ID_BUF];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    char ip[INET_ADDRSTRLEN];
    int n;
    (void)events;
    while ((n = recvfrom(u->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &flen)) > 0) {
        char raw[JMX_ID_BUF];
        char *v;
        buf[n] = '\0';
        memcpy(raw, buf, n + 1);
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        if ((v = header_value(buf, "SERVER"))) observe_ip(ip, "ssdp", "server", v, 65, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "USN"))) observe_ip(ip, "ssdp", "usn", v, 65, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "ST"))) observe_ip(ip, "ssdp", "st", v, 60, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "NT"))) observe_ip(ip, "ssdp", "nt", v, 60, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "LOCATION"))) { observe_ip(ip, "ssdp", "location", v, 70, raw); fetch_ssdp_location_xml(ip, v); }
    }
}

static void collect_dhcp_leases(void)
{
    FILE *f = fopen("/tmp/dhcp.leases", "r");
    char line[512];
    if (!f) f = fopen("/tmp/hosts/dhcp.leases", "r");
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char ts[32], mac[32], ip[64], host[128];
        if (sscanf(line, "%31s %31s %63s %127s", ts, mac, ip, host) == 4) {
            if (strcmp(host, "*"))
                jmx_db_observe_signal(mac, "dhcp", "hostname", host, 70, line);
            jmx_db_observe_signal(mac, "dhcp", "lease_ip", ip, 60, line);
        }
    }
    fclose(f);
}


struct dhcp_fixed_hdr {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
} __attribute__((packed));

static int make_dhcp_packet_socket(void)
{
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) return -1;
    set_nonblock(fd);
    return fd;
}

static void mac_to_text(const uint8_t *m, char *out, size_t out_len)
{
    snprintf(out, out_len, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void option_bytes_csv(const uint8_t *p, int len, char *out, size_t out_len)
{
    int i, off = 0;
    if (!out || out_len == 0) return;
    out[0] = '\0';
    for (i = 0; i < len; i++) {
        int n = snprintf(out + off, out_len - off, "%s%u", i ? "," : "", p[i]);
        if (n < 0 || off + n >= (int)out_len) break;
        off += n;
    }
}

static void dhcp_cb(struct uloop_fd *u, unsigned int events)
{
    uint8_t buf[2048];
    int n;
    (void)events;
    while ((n = recv(u->fd, buf, sizeof(buf), 0)) > 0) {
        struct iphdr *ip;
        struct udphdr *udp;
        struct dhcp_fixed_hdr *dh;
        uint8_t *opt;
        int ip_hl, udp_len, opt_len, i;
        char mac[32];
        if (n < (int)(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcp_fixed_hdr) + 4)) continue;
        ip = (struct iphdr *)buf;
        if (ip->version != 4 || ip->protocol != IPPROTO_UDP) continue;
        ip_hl = ip->ihl * 4;
        if (ip_hl < (int)sizeof(struct iphdr) || n < ip_hl + (int)sizeof(struct udphdr)) continue;
        udp = (struct udphdr *)(buf + ip_hl);
        if (!(ntohs(udp->source) == 67 || ntohs(udp->source) == 68 || ntohs(udp->dest) == 67 || ntohs(udp->dest) == 68)) continue;
        udp_len = ntohs(udp->len) - (int)sizeof(struct udphdr);
        if (udp_len < (int)sizeof(struct dhcp_fixed_hdr) + 4) continue;
        dh = (struct dhcp_fixed_hdr *)(buf + ip_hl + sizeof(struct udphdr));
        if (dh->hlen < 6) continue;
        opt = (uint8_t *)dh + sizeof(struct dhcp_fixed_hdr);
        if (!(opt[0] == 0x63 && opt[1] == 0x82 && opt[2] == 0x53 && opt[3] == 0x63)) continue;
        mac_to_text(dh->chaddr, mac, sizeof(mac));
        opt += 4;
        opt_len = udp_len - (int)sizeof(struct dhcp_fixed_hdr) - 4;
        for (i = 0; i < opt_len;) {
            uint8_t code = opt[i++];
            uint8_t len;
            char val[512];
            if (code == 0) continue;
            if (code == 255) break;
            if (i >= opt_len) break;
            len = opt[i++];
            if (i + len > opt_len) break;
            val[0] = '\0';
            if (code == 12 || code == 60 || code == 61 || code == 77) {
                int copy = len < sizeof(val) - 1 ? len : sizeof(val) - 1;
                memcpy(val, opt + i, copy); val[copy] = '\0';
                for (int k = 0; val[k]; k++) if ((unsigned char)val[k] < 32) val[k] = '.';
                if (code == 12) jmx_db_observe_signal(mac, "dhcp-packet", "hostname", val, 80, "dhcp-option-12");
                else if (code == 60) jmx_db_observe_signal(mac, "dhcp-packet", "vendor_class", val, 85, "dhcp-option-60");
                else if (code == 61) jmx_db_observe_signal(mac, "dhcp-packet", "client_id", val, 70, "dhcp-option-61");
                else if (code == 77) jmx_db_observe_signal(mac, "dhcp-packet", "user_class", val, 75, "dhcp-option-77");
            } else if (code == 55) {
                option_bytes_csv(opt + i, len, val, sizeof(val));
                jmx_db_observe_signal(mac, "dhcp-packet", "option55", val, 90, "dhcp-option-55");
            }
            i += len;
        }
    }
}

int jmx_identity_collector_init(void)
{
    g_mdns_fd.fd = make_mcast_socket("224.0.0.251", 5353);
    if (g_mdns_fd.fd >= 0) {
        g_mdns_fd.cb = mdns_cb;
        uloop_fd_add(&g_mdns_fd, ULOOP_READ);
        LOG_INFO("identity collector: mDNS listener ready\n");
    } else {
        LOG_WARN("identity collector: mDNS listener failed: %s\n", strerror(errno));
    }

    g_ssdp_fd.fd = make_mcast_socket("239.255.255.250", 1900);
    if (g_ssdp_fd.fd >= 0) {
        g_ssdp_fd.cb = ssdp_cb;
        uloop_fd_add(&g_ssdp_fd, ULOOP_READ);
        LOG_INFO("identity collector: SSDP listener ready\n");
    } else {
        LOG_WARN("identity collector: SSDP listener failed: %s\n", strerror(errno));
    }
    g_dhcp_fd.fd = make_dhcp_packet_socket();
    if (g_dhcp_fd.fd >= 0) {
        g_dhcp_fd.cb = dhcp_cb;
        uloop_fd_add(&g_dhcp_fd, ULOOP_READ);
        LOG_INFO("identity collector: DHCP packet listener ready\n");
    } else {
        LOG_WARN("identity collector: DHCP packet listener failed: %s\n", strerror(errno));
    }
    collect_dhcp_leases();
    return 0;
}

static void collect_arp_entries(void)
{
    FILE *f = fopen("/proc/net/arp", "r");
    char line[256];
    if (!f) return;
    /* skip header */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return; }
    while (fgets(line, sizeof(line), f)) {
        char ip[64] = {0}, hw[8] = {0}, flags[16] = {0}, mac[32] = {0}, mask[16] = {0}, dev[32] = {0};
        if (sscanf(line, "%63s %7s %15s %31s %15s %31s", ip, hw, flags, mac, mask, dev) < 4) continue;
        /* skip incomplete entries (flags 0x0) */
        unsigned int fl = 0;
        sscanf(flags, "%x", &fl);
        if (!(fl & 0x2)) continue;  /* ATF_COM = complete */
        if (!strcmp(mac, "00:00:00:00:00:00")) continue;
        /* normalize MAC to lowercase */
        char mac_l[32] = {0};
        size_t i;
        for (i = 0; mac[i] && i < sizeof(mac_l) - 1; i++)
            mac_l[i] = (char)tolower((unsigned char)mac[i]);

        /* 1) Add to in-memory client list so client_detail sees it */
        client_node_t *node = add_client_node(mac_l);
        if (node) {
            if (!node->ip[0] || strcmp(node->ip, "0.0.0.0") == 0)
                snprintf(node->ip, sizeof(node->ip), "%s", ip);
            node->online = 1;
        }

        /* 2) Observe ARP signal in DB (creates client + signal) */
        jmx_db_observe_signal(mac_l, "arp", "ip", ip, 40, line);

        /* 3) Cache IP→MAC for ssdp/mdns signal resolution */
        observe_ip(ip, "arp", "mac", mac_l, 40, line);
    }
    fclose(f);
}

void jmx_identity_collector_tick(void)
{
    collect_dhcp_leases();
    collect_arp_entries();
    flush_pending_ip_signals();
}

void jmx_identity_collector_close(void)
{
    if (g_mdns_fd.fd >= 0) { uloop_fd_delete(&g_mdns_fd); close(g_mdns_fd.fd); g_mdns_fd.fd = -1; }
    if (g_ssdp_fd.fd >= 0) { uloop_fd_delete(&g_ssdp_fd); close(g_ssdp_fd.fd); g_ssdp_fd.fd = -1; }
    if (g_dhcp_fd.fd >= 0) { uloop_fd_delete(&g_dhcp_fd); close(g_dhcp_fd.fd); g_dhcp_fd.fd = -1; }
}
