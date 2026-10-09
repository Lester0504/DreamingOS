// SPDX-License-Identifier: GPL-2.0-or-later
/* Client connection close/clear and protocol control, with the raw-netlink
 * conntrack delete primitives they drive. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include "../jmx_app_api.h"
#include "api_client_connections.h"
#include "api_json.h"
#include "api_ubus.h"

/* Helpers owned by the monolith that this closure still calls. Declared here
 * so the module need not pull <uci.h> (webd_normalize_mac_text lives in
 * api_policy_write_internal.h) or duplicate the profile/ARP helpers. */
int webd_normalize_mac_text(const char *in, char *out, size_t out_len);
const char *webd_first_nonempty4(const char *a, const char *b,
                                 const char *c, const char *d);
const char *webd_first_nonempty6(const char *a, const char *b,
                                 const char *c, const char *d,
                                 const char *e, const char *f);
int webd_ipv4_from_arp_by_mac(const char *norm_mac, char *out, size_t out_len);
int webd_ipv6_is_link_local(const char *addr);

int app_run_conntrack_delete(const char *direction, const char *ip)
{
    pid_t pid;
    int status;

    if (!direction || !ip || !ip[0])
        return -1;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);

        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("conntrack", "conntrack", "-D", direction, ip, (char *)NULL);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

struct app_ct_tuple {
    int family;
    int l4proto;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } src;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } dst;
    uint16_t sport;
    uint16_t dport;
    uint16_t icmp_id;
    uint8_t icmp_type;
    uint8_t icmp_code;
    int has_ports;
    int has_icmp;
};

static int app_ct_parse_proto_num(const char *proto)
{
    if (!proto || !proto[0])
        return 0;
    if (!strcasecmp(proto, "tcp"))
        return IPPROTO_TCP;
    if (!strcasecmp(proto, "udp"))
        return IPPROTO_UDP;
    if (!strcasecmp(proto, "icmp"))
        return IPPROTO_ICMP;
    if (!strcasecmp(proto, "icmpv6") || !strcasecmp(proto, "ipv6-icmp"))
        return IPPROTO_ICMPV6;
    return atoi(proto);
}

static int app_ct_line_token(const char *line, const char *key,
                             int occurrence, char *out, size_t out_len)
{
    char *copy;
    char *save = NULL;
    char *tok;
    size_t key_len;
    int seen = 0;

    if (!out || out_len == 0 || !line || !key || !key[0] || occurrence <= 0)
        return -1;
    out[0] = '\0';
    key_len = strlen(key);
    copy = strdup(line);
    if (!copy)
        return -1;
    for (tok = strtok_r(copy, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save)) {
        if (!strncmp(tok, key, key_len)) {
            seen++;
            if (seen == occurrence) {
                snprintf(out, out_len, "%s", tok + key_len);
                free(copy);
                return out[0] ? 0 : -1;
            }
        }
    }
    free(copy);
    return -1;
}

static int app_ct_line_parse_tuple(const char *line, struct app_ct_tuple *t)
{
    char l3[16] = {0};
    char proto[16] = {0};
    char src[128] = {0};
    char dst[128] = {0};
    char sport[32] = {0};
    char dport[32] = {0};
    char icmp_id[32] = {0};
    char icmp_type[32] = {0};
    char icmp_code[32] = {0};
    int l3num = 0;

    if (!line || !t)
        return -1;
    memset(t, 0, sizeof(*t));
    if (sscanf(line, "%15s %d %15s", l3, &l3num, proto) != 3)
        return -1;
    if (!strcasecmp(l3, "ipv4"))
        t->family = AF_INET;
    else if (!strcasecmp(l3, "ipv6"))
        t->family = AF_INET6;
    else
        return -1;
    t->l4proto = app_ct_parse_proto_num(proto);
    if (t->l4proto <= 0)
        return -1;
    if (app_ct_line_token(line, "src=", 1, src, sizeof(src)) != 0 ||
        app_ct_line_token(line, "dst=", 1, dst, sizeof(dst)) != 0)
        return -1;
    if (t->family == AF_INET) {
        if (inet_pton(AF_INET, src, &t->src.v4) != 1 ||
            inet_pton(AF_INET, dst, &t->dst.v4) != 1)
            return -1;
    } else {
        if (inet_pton(AF_INET6, src, &t->src.v6) != 1 ||
            inet_pton(AF_INET6, dst, &t->dst.v6) != 1)
            return -1;
    }
    if (t->l4proto == IPPROTO_TCP || t->l4proto == IPPROTO_UDP) {
        if (app_ct_line_token(line, "sport=", 1, sport, sizeof(sport)) != 0 ||
            app_ct_line_token(line, "dport=", 1, dport, sizeof(dport)) != 0)
            return -1;
        t->sport = (uint16_t)atoi(sport);
        t->dport = (uint16_t)atoi(dport);
        t->has_ports = 1;
    } else if (t->l4proto == IPPROTO_ICMP || t->l4proto == IPPROTO_ICMPV6) {
        if (app_ct_line_token(line, "type=", 1, icmp_type, sizeof(icmp_type)) == 0)
            t->icmp_type = (uint8_t)atoi(icmp_type);
        if (app_ct_line_token(line, "code=", 1, icmp_code, sizeof(icmp_code)) == 0)
            t->icmp_code = (uint8_t)atoi(icmp_code);
        if (app_ct_line_token(line, "id=", 1, icmp_id, sizeof(icmp_id)) == 0)
            t->icmp_id = (uint16_t)atoi(icmp_id);
        t->has_icmp = 1;
    }
    return 0;
}

static int app_ct_line_has_ip(const char *line, const char *ip)
{
    char src[128] = {0};
    char dst[128] = {0};
    char rsrc[128] = {0};
    char rdst[128] = {0};

    if (!line || !ip || !ip[0])
        return 0;
    return (app_ct_line_token(line, "src=", 1, src, sizeof(src)) == 0 && !strcmp(src, ip)) ||
           (app_ct_line_token(line, "dst=", 1, dst, sizeof(dst)) == 0 && !strcmp(dst, ip)) ||
           (app_ct_line_token(line, "src=", 2, rsrc, sizeof(rsrc)) == 0 && !strcmp(rsrc, ip)) ||
           (app_ct_line_token(line, "dst=", 2, rdst, sizeof(rdst)) == 0 && !strcmp(rdst, ip));
}

static int app_nl_addattr(struct nlmsghdr *nlh, size_t max_len, int type,
                          const void *data, size_t len)
{
    size_t alen = NLA_HDRLEN + len;
    size_t new_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(alen);
    struct nlattr *nla;

    if (new_len > max_len)
        return -1;
    nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    nla->nla_type = (uint16_t)type;
    nla->nla_len = (uint16_t)alen;
    if (len > 0 && data)
        memcpy((char *)nla + NLA_HDRLEN, data, len);
    nlh->nlmsg_len = (uint32_t)new_len;
    return 0;
}

static int app_ct_add_tuple_attr(struct nlmsghdr *nlh, size_t max_len,
                                 const struct app_ct_tuple *t)
{
    struct nlattr *tuple;
    struct nlattr *ip;
    struct nlattr *proto;
    uint8_t proto_num;

    tuple = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    if (app_nl_addattr(nlh, max_len, CTA_TUPLE_ORIG | NLA_F_NESTED, NULL, 0) != 0)
        return -1;
    ip = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    if (app_nl_addattr(nlh, max_len, CTA_TUPLE_IP | NLA_F_NESTED, NULL, 0) != 0)
        return -1;
    if (t->family == AF_INET) {
        if (app_nl_addattr(nlh, max_len, CTA_IP_V4_SRC, &t->src.v4, sizeof(t->src.v4)) != 0 ||
            app_nl_addattr(nlh, max_len, CTA_IP_V4_DST, &t->dst.v4, sizeof(t->dst.v4)) != 0)
            return -1;
    } else {
        if (app_nl_addattr(nlh, max_len, CTA_IP_V6_SRC, &t->src.v6, sizeof(t->src.v6)) != 0 ||
            app_nl_addattr(nlh, max_len, CTA_IP_V6_DST, &t->dst.v6, sizeof(t->dst.v6)) != 0)
            return -1;
    }
    ip->nla_len = (uint16_t)((char *)nlh + nlh->nlmsg_len - (char *)ip);
    proto = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    if (app_nl_addattr(nlh, max_len, CTA_TUPLE_PROTO | NLA_F_NESTED, NULL, 0) != 0)
        return -1;
    proto_num = (uint8_t)t->l4proto;
    if (app_nl_addattr(nlh, max_len, CTA_PROTO_NUM, &proto_num, sizeof(proto_num)) != 0)
        return -1;
    if (t->has_ports) {
        uint16_t sport = htons(t->sport);
        uint16_t dport = htons(t->dport);

        if (app_nl_addattr(nlh, max_len, CTA_PROTO_SRC_PORT, &sport, sizeof(sport)) != 0 ||
            app_nl_addattr(nlh, max_len, CTA_PROTO_DST_PORT, &dport, sizeof(dport)) != 0)
            return -1;
    } else if (t->has_icmp) {
        uint16_t id = htons(t->icmp_id);

        if (t->l4proto == IPPROTO_ICMP) {
            if (app_nl_addattr(nlh, max_len, CTA_PROTO_ICMP_TYPE, &t->icmp_type, sizeof(t->icmp_type)) != 0 ||
                app_nl_addattr(nlh, max_len, CTA_PROTO_ICMP_CODE, &t->icmp_code, sizeof(t->icmp_code)) != 0 ||
                app_nl_addattr(nlh, max_len, CTA_PROTO_ICMP_ID, &id, sizeof(id)) != 0)
                return -1;
        } else {
            if (app_nl_addattr(nlh, max_len, CTA_PROTO_ICMPV6_TYPE, &t->icmp_type, sizeof(t->icmp_type)) != 0 ||
                app_nl_addattr(nlh, max_len, CTA_PROTO_ICMPV6_CODE, &t->icmp_code, sizeof(t->icmp_code)) != 0 ||
                app_nl_addattr(nlh, max_len, CTA_PROTO_ICMPV6_ID, &id, sizeof(id)) != 0)
                return -1;
        }
    }
    proto->nla_len = (uint16_t)((char *)nlh + nlh->nlmsg_len - (char *)proto);
    tuple->nla_len = (uint16_t)((char *)nlh + nlh->nlmsg_len - (char *)tuple);
    return 0;
}

static int app_ct_netlink_delete_tuple(const struct app_ct_tuple *t)
{
    unsigned char buf[512];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct nfgenmsg *nfg;
    struct sockaddr_nl sa;
    int fd;
    int rc;

    if (!t)
        return -1;
    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*nfg));
    nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = (uint32_t)time(NULL);
    nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
    nfg->nfgen_family = (uint8_t)t->family;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;
    if (app_ct_add_tuple_attr(nlh, sizeof(buf), t) != 0)
        return -1;
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    rc = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0) {
        close(fd);
        return -1;
    }
    rc = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    if (rc < 0)
        return -1;
    nlh = (struct nlmsghdr *)buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

        return err->error == 0 ? 0 : -1;
    }
    return 0;
}

static int app_conntrack_builtin_delete_ip(const char *ip)
{
    FILE *fp;
    char line[4096];
    int deleted = 0;
    int matched = 0;

    if (!ip || !ip[0])
        return -1;
    fp = fopen("/proc/net/nf_conntrack", "r");
    if (!fp)
        fp = fopen("/proc/net/ip_conntrack", "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        struct app_ct_tuple t;

        if (!app_ct_line_has_ip(line, ip))
            continue;
        matched++;
        if (app_ct_line_parse_tuple(line, &t) != 0)
            continue;
        if (app_ct_netlink_delete_tuple(&t) == 0)
            deleted++;
    }
    fclose(fp);
    if (deleted > 0)
        return deleted;
    return matched > 0 ? 0 : -1;
}

static int app_conntrack_executor_available(void)
{
    if (access("/proc/net/nf_conntrack", R_OK) == 0 ||
        access("/proc/net/ip_conntrack", R_OK) == 0)
        return 1;
    return access("/usr/sbin/conntrack", X_OK) == 0 ||
           access("/sbin/conntrack", X_OK) == 0 ||
           access("/usr/bin/conntrack", X_OK) == 0 ||
           access("/bin/conntrack", X_OK) == 0;
}

static int app_conntrack_cli_available(void)
{
    return access("/usr/sbin/conntrack", X_OK) == 0 ||
           access("/sbin/conntrack", X_OK) == 0 ||
           access("/usr/bin/conntrack", X_OK) == 0 ||
           access("/bin/conntrack", X_OK) == 0;
}

struct webd_ct_close_target {
    char mac[32];
    char proto[16];
    char local_ip[128];
    char remote_ip[128];
    int local_port;
    int remote_port;
    char signature[512];
    char id[560];
};

static void webd_ct_copy_lower_proto(const char *in, char *out, size_t out_len)
{
    size_t i;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in || !in[0])
        return;
    if (!strcasecmp(in, "quic")) {
        snprintf(out, out_len, "udp");
        return;
    }
    for (i = 0; in[i] && i + 1 < out_len; i++)
        out[i] = (char)tolower((unsigned char)in[i]);
    out[i] = '\0';
}

static int webd_ct_parse_pipe_signature(const char *sig, char *proto, size_t proto_len,
                                        char *src, size_t src_len, int *sport,
                                        char *dst, size_t dst_len, int *dport)
{
    char copy[512];
    char *save = NULL;
    char *tok;
    char *parts[5] = {0};
    int n = 0;

    if (!sig || !strchr(sig, '|'))
        return -1;
    snprintf(copy, sizeof(copy), "%s", sig);
    for (tok = strtok_r(copy, "|", &save); tok && n < 5; tok = strtok_r(NULL, "|", &save))
        parts[n++] = tok;
    if (n != 5)
        return -1;
    if (proto && proto_len) webd_ct_copy_lower_proto(parts[0], proto, proto_len);
    if (src && src_len) snprintf(src, src_len, "%s", parts[1] ? parts[1] : "");
    if (sport) *sport = parts[2] ? atoi(parts[2]) : 0;
    if (dst && dst_len) snprintf(dst, dst_len, "%s", parts[3] ? parts[3] : "");
    if (dport) *dport = parts[4] ? atoi(parts[4]) : 0;
    return 0;
}

static int webd_ct_parse_ipv4_id(const char *id, char *proto, size_t proto_len,
                                 char *src, size_t src_len, int *sport,
                                 char *dst, size_t dst_len, int *dport)
{
    char p[16] = {0};
    char s[128] = {0};
    char d[128] = {0};
    int sp = 0;
    int dp = 0;

    if (!id || strncmp(id, "ct:", 3))
        return -1;
    if (sscanf(id, "ct:%15[^:]:%127[^:]:%d:%127[^:]:%d", p, s, &sp, d, &dp) != 5)
        return -1;
    if (proto && proto_len) webd_ct_copy_lower_proto(p, proto, proto_len);
    if (src && src_len) snprintf(src, src_len, "%s", s);
    if (sport) *sport = sp;
    if (dst && dst_len) snprintf(dst, dst_len, "%s", d);
    if (dport) *dport = dp;
    return 0;
}

static int webd_ct_json_port(struct json_object *body, const char *a, const char *b,
                             const char *c, const char *d)
{
    const char *s = webd_first_nonempty4(app_nc_json_str(body, a, ""),
                                         app_nc_json_str(body, b, ""),
                                         app_nc_json_str(body, c, ""),
                                         app_nc_json_str(body, d, ""));

    return s[0] ? atoi(s) : 0;
}

static void webd_ct_resolve_client_ips(const char *norm_mac,
                                       char *ip4, size_t ip4_len,
                                       char *ip6, size_t ip6_len)
{
    struct json_object *params;
    struct json_object *cg;
    struct json_object *cd = NULL;
    struct json_object *co = NULL;

    if (ip4 && ip4_len)
        ip4[0] = '\0';
    if (ip6 && ip6_len)
        ip6[0] = '\0';
    if (!norm_mac || !norm_mac[0])
        return;
    params = json_object_new_object();
    json_object_object_add(params, "mac", json_object_new_string(norm_mac));
    cg = app_ubus_invoke("client_get", params);
    json_object_put(params);
    if (cg) {
        json_object_object_get_ex(cg, "data", &cd);
        if (cd)
            json_object_object_get_ex(cd, "client", &co);
        if (co) {
            const char *ip = app_nc_json_str(co, "ip", "");
            const char *ipv6 = webd_first_nonempty4(app_nc_json_str(co, "ipv6_global", ""),
                                                    app_nc_json_str(co, "global_ipv6", ""),
                                                    app_nc_json_str(co, "ipv6", ""),
                                                    app_nc_json_str(co, "ip6", ""));
            if (ip4 && ip4_len && ip[0])
                snprintf(ip4, ip4_len, "%s", ip);
            if (ip6 && ip6_len && ipv6[0] && !webd_ipv6_is_link_local(ipv6))
                snprintf(ip6, ip6_len, "%s", ipv6);
        }
        json_object_put(cg);
    }
    if (ip4 && ip4_len && !ip4[0])
        (void)webd_ipv4_from_arp_by_mac(norm_mac, ip4, ip4_len);
}

static int webd_ct_token_int(const char *line, const char *key, int occurrence)
{
    char buf[32] = {0};

    if (app_ct_line_token(line, key, occurrence, buf, sizeof(buf)) != 0)
        return -1;
    return atoi(buf);
}

static int webd_ct_ip_eq(const char *a, const char *b)
{
    return a && b && a[0] && b[0] && !strcmp(a, b);
}

static int webd_ct_ip_any(const char *line, const char *ip)
{
    return !ip || !ip[0] || app_ct_line_has_ip(line, ip);
}

static int webd_ct_tuple_side_matches(const char *src, const char *dst, int sport, int dport,
                                      const struct webd_ct_close_target *target)
{
    int local_src_ok;
    int remote_dst_ok;
    int sport_ok;
    int dport_ok;
    int local_dst_ok;
    int remote_src_ok;
    int dport_local_ok;
    int sport_remote_ok;

    if (!target)
        return 0;
    local_src_ok = !target->local_ip[0] || webd_ct_ip_eq(src, target->local_ip);
    remote_dst_ok = !target->remote_ip[0] || webd_ct_ip_eq(dst, target->remote_ip);
    sport_ok = target->local_port <= 0 || sport == target->local_port;
    dport_ok = target->remote_port <= 0 || dport == target->remote_port;
    if (local_src_ok && remote_dst_ok && sport_ok && dport_ok)
        return 1;

    local_dst_ok = !target->local_ip[0] || webd_ct_ip_eq(dst, target->local_ip);
    remote_src_ok = !target->remote_ip[0] || webd_ct_ip_eq(src, target->remote_ip);
    dport_local_ok = target->local_port <= 0 || dport == target->local_port;
    sport_remote_ok = target->remote_port <= 0 || sport == target->remote_port;
    return local_dst_ok && remote_src_ok && dport_local_ok && sport_remote_ok;
}

static int webd_ct_line_matches_close_target(const char *line,
                                             const struct webd_ct_close_target *target)
{
    struct app_ct_tuple tuple;
    int want_proto;
    char src1[128] = {0}, dst1[128] = {0};
    char src2[128] = {0}, dst2[128] = {0};
    int sport1;
    int dport1;
    int sport2;
    int dport2;

    if (!line || !target)
        return 0;
    if (app_ct_line_parse_tuple(line, &tuple) != 0)
        return 0;
    want_proto = app_ct_parse_proto_num(target->proto);
    if (want_proto > 0 && tuple.l4proto != want_proto)
        return 0;
    if (!webd_ct_ip_any(line, target->local_ip) ||
        !webd_ct_ip_any(line, target->remote_ip))
        return 0;

    if (target->local_port <= 0 && target->remote_port <= 0)
        return target->local_ip[0] || target->remote_ip[0];

    app_ct_line_token(line, "src=", 1, src1, sizeof(src1));
    app_ct_line_token(line, "dst=", 1, dst1, sizeof(dst1));
    app_ct_line_token(line, "src=", 2, src2, sizeof(src2));
    app_ct_line_token(line, "dst=", 2, dst2, sizeof(dst2));
    sport1 = webd_ct_token_int(line, "sport=", 1);
    dport1 = webd_ct_token_int(line, "dport=", 1);
    sport2 = webd_ct_token_int(line, "sport=", 2);
    dport2 = webd_ct_token_int(line, "dport=", 2);

    if (sport1 >= 0 && dport1 >= 0 &&
        webd_ct_tuple_side_matches(src1, dst1, sport1, dport1, target))
        return 1;
    if (sport2 >= 0 && dport2 >= 0 &&
        webd_ct_tuple_side_matches(src2, dst2, sport2, dport2, target))
        return 1;

    if (target->local_port > 0 &&
        sport1 != target->local_port && dport1 != target->local_port &&
        sport2 != target->local_port && dport2 != target->local_port)
        return 0;
    if (target->remote_port > 0 &&
        sport1 != target->remote_port && dport1 != target->remote_port &&
        sport2 != target->remote_port && dport2 != target->remote_port)
        return 0;
    return 1;
}

static int webd_conntrack_close_target(const struct webd_ct_close_target *target,
                                       int *matched_out, int *deleted_out)
{
    FILE *fp;
    char line[4096];
    int matched = 0;
    int deleted = 0;

    if (matched_out) *matched_out = 0;
    if (deleted_out) *deleted_out = 0;
    fp = fopen("/proc/net/nf_conntrack", "r");
    if (!fp)
        fp = fopen("/proc/net/ip_conntrack", "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        struct app_ct_tuple tuple;

        if (!webd_ct_line_matches_close_target(line, target))
            continue;
        matched++;
        if (app_ct_line_parse_tuple(line, &tuple) != 0)
            continue;
        if (app_ct_netlink_delete_tuple(&tuple) == 0)
            deleted++;
    }
    fclose(fp);
    if (matched_out) *matched_out = matched;
    if (deleted_out) *deleted_out = deleted;
    return 0;
}

static struct json_object *webd_client_connections_close_response(struct json_object *body,
                                                                  int *status)
{
    struct webd_ct_close_target target;
    struct json_object *resp = json_object_new_object();
    struct json_object *data = json_object_new_object();
    const char *mac_in = app_nc_json_str(body, "mac",
        app_nc_json_str(body, "client_mac", app_nc_json_str(body, "device_mac", "")));
    const char *proto_in = webd_first_nonempty4(app_nc_json_str(body, "proto", ""),
                                                app_nc_json_str(body, "protocol", ""),
                                                app_nc_json_str(body, "app_proto", ""),
                                                "");
    const char *local_ip = webd_first_nonempty6(app_nc_json_str(body, "src_ip", ""),
                                                app_nc_json_str(body, "source_ip", ""),
                                                app_nc_json_str(body, "client_ip", ""),
                                                app_nc_json_str(body, "ip", ""),
                                                app_nc_json_str(body, "ipv4", ""),
                                                "");
    const char *remote_ip = webd_first_nonempty6(app_nc_json_str(body, "dst_ip", ""),
                                                 app_nc_json_str(body, "destination_ip", ""),
                                                 app_nc_json_str(body, "remote_ip", ""),
                                                 app_nc_json_str(body, "server_ip", ""),
                                                 app_nc_json_str(body, "external_ip", ""),
                                                 app_nc_json_str(body, "wan_ip", ""));
    const char *signature = app_nc_json_str(body, "signature",
        app_nc_json_str(body, "ct_signature", ""));
    const char *id = app_nc_json_str(body, "id",
        app_nc_json_str(body, "ct_id", ""));
    char sig_proto[16] = {0}, sig_src[128] = {0}, sig_dst[128] = {0};
    int sig_sport = 0, sig_dport = 0;
    char resolved4[64] = {0};
    char resolved6[128] = {0};
    int matched = 0;
    int deleted = 0;
    int rc;

    memset(&target, 0, sizeof(target));
    if (status)
        *status = 200;
    if (mac_in[0]) {
        if (webd_normalize_mac_text(mac_in, target.mac, sizeof(target.mac)) != 0) {
            if (status) *status = 400;
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("bad_request"));
            json_object_object_add(resp, "message", json_object_new_string("invalid mac"));
            json_object_put(data);
            return resp;
        }
    }
    webd_ct_copy_lower_proto(proto_in, target.proto, sizeof(target.proto));
    if (local_ip[0] && strcmp(local_ip, "--"))
        snprintf(target.local_ip, sizeof(target.local_ip), "%s", local_ip);
    if (remote_ip[0] && strcmp(remote_ip, "--"))
        snprintf(target.remote_ip, sizeof(target.remote_ip), "%s", remote_ip);
    target.local_port = webd_ct_json_port(body, "src_port", "source_port", "sport", "local_port");
    target.remote_port = webd_ct_json_port(body, "dst_port", "destination_port", "dport", "remote_port");
    if (signature[0])
        snprintf(target.signature, sizeof(target.signature), "%s", signature);
    if (id[0])
        snprintf(target.id, sizeof(target.id), "%s", id);

    if (webd_ct_parse_ipv4_id(id, sig_proto, sizeof(sig_proto),
                              sig_src, sizeof(sig_src), &sig_sport,
                              sig_dst, sizeof(sig_dst), &sig_dport) != 0) {
        (void)webd_ct_parse_pipe_signature(signature, sig_proto, sizeof(sig_proto),
                                           sig_src, sizeof(sig_src), &sig_sport,
                                           sig_dst, sizeof(sig_dst), &sig_dport);
    }
    if (!target.proto[0] && sig_proto[0])
        snprintf(target.proto, sizeof(target.proto), "%s", sig_proto);
    if (!target.local_ip[0] && sig_src[0])
        snprintf(target.local_ip, sizeof(target.local_ip), "%s", sig_src);
    if (!target.remote_ip[0] && sig_dst[0])
        snprintf(target.remote_ip, sizeof(target.remote_ip), "%s", sig_dst);
    if (target.local_port <= 0 && sig_sport > 0)
        target.local_port = sig_sport;
    if (target.remote_port <= 0 && sig_dport > 0)
        target.remote_port = sig_dport;

    if (!target.local_ip[0] && target.mac[0]) {
        webd_ct_resolve_client_ips(target.mac, resolved4, sizeof(resolved4),
                                   resolved6, sizeof(resolved6));
        if (target.remote_ip[0] && strchr(target.remote_ip, ':') && resolved6[0])
            snprintf(target.local_ip, sizeof(target.local_ip), "%s", resolved6);
        else if (resolved4[0])
            snprintf(target.local_ip, sizeof(target.local_ip), "%s", resolved4);
        else if (resolved6[0])
            snprintf(target.local_ip, sizeof(target.local_ip), "%s", resolved6);
    }
    if (!target.signature[0] && (target.proto[0] || target.local_ip[0] ||
                                 target.remote_ip[0] || target.local_port > 0 ||
                                 target.remote_port > 0)) {
        snprintf(target.signature, sizeof(target.signature), "%s|%s|%d|%s|%d",
                 target.proto, target.local_ip, target.local_port,
                 target.remote_ip, target.remote_port);
    }

    if (!target.proto[0] || !target.local_ip[0] || !target.remote_ip[0] ||
        ((app_ct_parse_proto_num(target.proto) == IPPROTO_TCP ||
          app_ct_parse_proto_num(target.proto) == IPPROTO_UDP) &&
         (target.local_port <= 0 || target.remote_port <= 0))) {
        if (status) *status = 400;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("bad_request"));
        json_object_object_add(resp, "message", json_object_new_string(
            "client_connections/close requires proto, client/source ip, remote ip and ports for tcp/udp"));
        json_object_object_add(data, "mac", json_object_new_string(target.mac));
        json_object_object_add(data, "signature", json_object_new_string(target.signature));
        json_object_object_add(data, "proto", json_object_new_string(target.proto));
        json_object_object_add(data, "src_ip", json_object_new_string(target.local_ip));
        json_object_object_add(data, "dst_ip", json_object_new_string(target.remote_ip));
        json_object_object_add(data, "src_port", json_object_new_int(target.local_port));
        json_object_object_add(data, "dst_port", json_object_new_int(target.remote_port));
        json_object_object_add(resp, "data", data);
        return resp;
    }

    rc = webd_conntrack_close_target(&target, &matched, &deleted);
    if (rc != 0) {
        if (status) *status = 503;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("conntrack_unavailable"));
        json_object_object_add(resp, "message", json_object_new_string("conntrack table is not readable"));
        json_object_object_add(data, "mac", json_object_new_string(target.mac));
        json_object_object_add(data, "signature", json_object_new_string(target.signature));
        json_object_object_add(data, "source", json_object_new_string("nf_conntrack"));
        json_object_object_add(resp, "data", data);
        return resp;
    }

    json_object_object_add(data, "closed", json_object_new_boolean(deleted > 0));
    json_object_object_add(data, "already_gone", json_object_new_boolean(matched == 0));
    json_object_object_add(data, "matched", json_object_new_int(matched));
    json_object_object_add(data, "deleted", json_object_new_int(deleted));
    json_object_object_add(data, "method", json_object_new_string("conntrack_delete"));
    json_object_object_add(data, "executor", json_object_new_string("nfnetlink_conntrack_delete"));
    json_object_object_add(data, "signature", json_object_new_string(target.signature));
    json_object_object_add(data, "id", json_object_new_string(target.id));
    json_object_object_add(data, "proto", json_object_new_string(target.proto));
    json_object_object_add(data, "src_ip", json_object_new_string(target.local_ip));
    json_object_object_add(data, "dst_ip", json_object_new_string(target.remote_ip));
    json_object_object_add(data, "src_port", json_object_new_int(target.local_port));
    json_object_object_add(data, "dst_port", json_object_new_int(target.remote_port));
    json_object_object_add(data, "source", json_object_new_string("nf_conntrack"));
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "data", data);
    jmx_app_audit_log("app", "", "client.connections.close", "medium",
                      target.mac, target.local_ip, target.signature);
    return resp;
}

static struct json_object *webd_client_connections_clear_response(struct json_object *body,
                                                                  int *status)
{
    char norm_mac[32] = {0};
    char ip_buf[64] = {0};
    char ipv6_buf[128] = {0};
    const char *mac_in = app_nc_json_str(body, "mac",
        app_nc_json_str(body, "client_mac", app_nc_json_str(body, "device_mac", "")));
    struct json_object *resp = json_object_new_object();
    struct json_object *data = json_object_new_object();
    int src_rc = -1;
    int dst_rc = -1;
    int src6_rc = -1;
    int dst6_rc = -1;
    int builtin4 = -1;
    int builtin6 = -1;
    int cleared;
    const char *executor = "conntrack";

    if (status)
        *status = 200;
    if (webd_normalize_mac_text(mac_in, norm_mac, sizeof(norm_mac)) != 0) {
        if (status)
            *status = 400;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("missing_mac"));
        json_object_object_add(resp, "message", json_object_new_string("client_connections/clear requires mac"));
        json_object_put(data);
        return resp;
    }

    {
        const char *body_ip = webd_first_nonempty4(app_nc_json_str(body, "ip", ""),
                                                  app_nc_json_str(body, "ipv4", ""),
                                                  app_nc_json_str(body, "client_ip", ""),
                                                  app_nc_json_str(body, "address", ""));
        const char *body_ip6 = webd_first_nonempty4(app_nc_json_str(body, "ipv6_global", ""),
                                                    app_nc_json_str(body, "global_ipv6", ""),
                                                    app_nc_json_str(body, "ipv6", ""),
                                                    app_nc_json_str(body, "ip6", ""));

        if (body_ip[0])
            snprintf(ip_buf, sizeof(ip_buf), "%s", body_ip);
        if (body_ip6[0] && !webd_ipv6_is_link_local(body_ip6))
            snprintf(ipv6_buf, sizeof(ipv6_buf), "%s", body_ip6);
    }

    if (!ip_buf[0] || !ipv6_buf[0]) {
        struct json_object *params = json_object_new_object();
        struct json_object *cg;
        struct json_object *cd = NULL;
        struct json_object *co = NULL;

        json_object_object_add(params, "mac", json_object_new_string(norm_mac));
        cg = app_ubus_invoke("client_get", params);
        json_object_put(params);
        if (cg) {
            json_object_object_get_ex(cg, "data", &cd);
            if (cd)
                json_object_object_get_ex(cd, "client", &co);
            if (co) {
                const char *ip = app_nc_json_str(co, "ip", "");
                const char *ip6 = webd_first_nonempty4(app_nc_json_str(co, "ipv6_global", ""),
                                                       app_nc_json_str(co, "global_ipv6", ""),
                                                       app_nc_json_str(co, "ipv6", ""),
                                                       app_nc_json_str(co, "ip6", ""));
                if (!ip_buf[0] && ip[0])
                    snprintf(ip_buf, sizeof(ip_buf), "%s", ip);
                if (!ipv6_buf[0] && ip6[0] && !webd_ipv6_is_link_local(ip6))
                    snprintf(ipv6_buf, sizeof(ipv6_buf), "%s", ip6);
            }
            json_object_put(cg);
        }
    }
    if (!ip_buf[0])
        (void)webd_ipv4_from_arp_by_mac(norm_mac, ip_buf, sizeof(ip_buf));

    if (!ip_buf[0] && !ipv6_buf[0]) {
        if (status)
            *status = 400;
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("client_ip_unavailable"));
        json_object_object_add(resp, "message", json_object_new_string("client is not online or has no usable IP"));
        json_object_object_add(data, "mac", json_object_new_string(norm_mac));
        json_object_object_add(resp, "data", data);
        return resp;
    }
    if (!app_conntrack_executor_available()) {
        if (status)
            *status = 503;
        json_object_object_add(data, "mac", json_object_new_string(norm_mac));
        json_object_object_add(data, "ip", json_object_new_string(ip_buf));
        json_object_object_add(data, "ipv6", json_object_new_string(ipv6_buf));
        json_object_object_add(data, "cleared", json_object_new_boolean(0));
        json_object_object_add(data, "source", json_object_new_string("conntrack"));
        json_object_object_add(data, "executor", json_object_new_string("conntrack"));
        json_object_object_add(data, "reason", json_object_new_string("conntrack_command_unavailable"));
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("executor_unavailable"));
        json_object_object_add(resp, "message", json_object_new_string("conntrack command is not installed"));
        json_object_object_add(resp, "data", data);
        return resp;
    }

    if (app_conntrack_cli_available()) {
        executor = "conntrack_cli";
        if (ip_buf[0]) {
            src_rc = app_run_conntrack_delete("-s", ip_buf);
            dst_rc = app_run_conntrack_delete("-d", ip_buf);
        }
        if (ipv6_buf[0]) {
            src6_rc = app_run_conntrack_delete("-s", ipv6_buf);
            dst6_rc = app_run_conntrack_delete("-d", ipv6_buf);
        }
        cleared = (src_rc == 0 || dst_rc == 0 || src6_rc == 0 || dst6_rc == 0);
    } else {
        executor = "nfnetlink_builtin";
        if (ip_buf[0])
            builtin4 = app_conntrack_builtin_delete_ip(ip_buf);
        if (ipv6_buf[0])
            builtin6 = app_conntrack_builtin_delete_ip(ipv6_buf);
        cleared = (builtin4 > 0 || builtin6 > 0);
    }

    json_object_object_add(data, "mac", json_object_new_string(norm_mac));
    json_object_object_add(data, "ip", json_object_new_string(ip_buf));
    json_object_object_add(data, "ipv6", json_object_new_string(ipv6_buf));
    json_object_object_add(data, "cleared", json_object_new_boolean(cleared));
    json_object_object_add(data, "cleared_count", json_object_new_int(
        (builtin4 > 0 ? builtin4 : 0) + (builtin6 > 0 ? builtin6 : 0)));
    json_object_object_add(data, "src_rc", json_object_new_int(src_rc));
    json_object_object_add(data, "dst_rc", json_object_new_int(dst_rc));
    json_object_object_add(data, "src6_rc", json_object_new_int(src6_rc));
    json_object_object_add(data, "dst6_rc", json_object_new_int(dst6_rc));
    json_object_object_add(data, "builtin4_deleted", json_object_new_int(builtin4));
    json_object_object_add(data, "builtin6_deleted", json_object_new_int(builtin6));
    json_object_object_add(data, "source", json_object_new_string("conntrack"));
    json_object_object_add(data, "executor", json_object_new_string(executor));
    json_object_object_add(data, "reason", json_object_new_string(cleared ? "conntrack_entries_deleted" : "conntrack_entries_not_found"));
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "data", data);
    jmx_app_audit_log("app", "", "client.connections.clear", "medium",
                      norm_mac, ip_buf, ipv6_buf);
    return resp;
}

static struct json_object *webd_client_protocol_control_response(struct json_object *body,
                                                                 int *status)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *cap = json_object_new_object();
    struct json_object *supported_actions = json_object_new_array();
    const char *mac = app_nc_json_str(body, "mac",
        app_nc_json_str(body, "client_mac", app_nc_json_str(body, "device_mac", "")));
    const char *protocol = webd_first_nonempty4(app_nc_json_str(body, "protocol", ""),
                                                app_nc_json_str(body, "protocol_name", ""),
                                                app_nc_json_str(body, "app", ""),
                                                app_nc_json_str(body, "name", ""));

    if (status)
        *status = 501;
    json_object_array_add(supported_actions, json_object_new_string("block"));
    json_object_array_add(supported_actions, json_object_new_string("allow"));
    json_object_array_add(supported_actions, json_object_new_string("rate_limit"));
    json_object_object_add(cap, "protocol_control", json_object_new_boolean(0));
    json_object_object_add(cap, "protocol_control_preview", json_object_new_boolean(0));
    json_object_object_add(cap, "supported_actions", supported_actions);
    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "error", json_object_new_string("not_implemented"));
    json_object_object_add(resp, "message", json_object_new_string(
        "client protocol control write path is not available yet; use network_control/app_rules once protocol rule schema is defined"));
    webd_obj_add_str(resp, "mac", mac);
    webd_obj_add_str(resp, "protocol", protocol);
    json_object_object_add(resp, "capabilities", cap);
    webd_obj_add_str(resp, "source", "webd.client_protocol_control");
    return resp;
}



static struct json_object *client_connections_clear(struct jmx_api_ctx *ctx)
{
    return webd_client_connections_clear_response(ctx->body, &ctx->status);
}

static struct json_object *client_connections_close(struct jmx_api_ctx *ctx)
{
    return webd_client_connections_close_response(ctx->body, &ctx->status);
}

static struct json_object *client_protocol_control(struct jmx_api_ctx *ctx)
{
    return webd_client_protocol_control_response(ctx->body, &ctx->status);
}

const struct jmx_api_route client_connections_api_routes[] = {
    JMX_API_ROUTE(593, "/api/v1/client_connections/clear", "POST,PUT", JMX_API_EXACT, client_connections_clear),
    JMX_API_ROUTE(594, "/api/v1/client_connections/close", "POST,PUT", JMX_API_EXACT, client_connections_close),
    JMX_API_ROUTE(595, "/api/v1/client_protocol_control", "POST,PUT", JMX_API_EXACT, client_protocol_control),
    JMX_API_ROUTE_END,
};
