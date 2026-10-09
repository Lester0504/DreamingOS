/*
 * Behavioural fixture for two projections added while unifying the connection
 * count and fixing the topology zero paths.
 *
 * These are pure functions over text/JSON, so they are extracted verbatim from
 * jmx_dreamingwrt_api.c rather than mocked: the point is to test the shipped
 * logic, not a paraphrase of it. Keep the copies in sync -- the runner asserts
 * the source still contains them.
 *
 *   dw_conntrack_line_category()          conntrack line -> transport bucket
 *   dw_unifi_add_aggregate_rate_contract() WAN rate contracts -> gateway verdict
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <json-c/json.h>

/* ---- helpers copied from the core (same semantics, same defaults) ---- */

static const char *dw_json_get_string(struct json_object *obj, const char *key,
                                      const char *def)
{
    struct json_object *v = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    if (!json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v);
}

static int64_t dw_json_get_int64(struct json_object *obj, const char *key,
                                 int64_t def)
{
    struct json_object *v = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    return json_object_get_int64(v);
}

static int dw_json_get_bool(struct json_object *obj, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

/* ---- BEGIN copy: connection category projection ---- */

typedef enum {
    DW_CONN_CAT_WEB = 0,
    DW_CONN_CAT_DNS,
    DW_CONN_CAT_MAIL,
    DW_CONN_CAT_TRANSFER,
    DW_CONN_CAT_VPN,
    DW_CONN_CAT_ICMP,
    DW_CONN_CAT_OTHER_TCP,
    DW_CONN_CAT_OTHER_UDP,
    DW_CONN_CAT_OTHER,
    DW_CONN_CAT__COUNT
} dw_conn_cat_t;

typedef struct {
    const char *key;
    const char *name;
} dw_conn_cat_meta_t;

static const dw_conn_cat_meta_t dw_conn_cat_meta[DW_CONN_CAT__COUNT] = {
    { "web",       "网页浏览" },
    { "dns",       "域名解析" },
    { "mail",      "邮件" },
    { "transfer",  "文件传输" },
    { "vpn",       "VPN/隧道" },
    { "icmp",      "ICMP" },
    { "other_tcp", "其他 TCP" },
    { "other_udp", "其他 UDP" },
    { "other",     "其他协议" },
};

static int dw_conntrack_line_remote_port(const char *line)
{
    const char *p;

    if (!line)
        return 0;
    p = strstr(line, "dport=");
    if (!p)
        return 0;
    return atoi(p + 6);
}

static dw_conn_cat_t dw_conntrack_line_category(const char *line)
{
    int tcp, udp;
    int port;

    if (!line)
        return DW_CONN_CAT_OTHER;
    if (strstr(line, "icmp") || strstr(line, "icmpv6"))
        return DW_CONN_CAT_ICMP;

    tcp = strstr(line, "tcp") != NULL;
    udp = strstr(line, "udp") != NULL;
    port = dw_conntrack_line_remote_port(line);

    switch (port) {
    case 80: case 443: case 8080: case 8443: case 8000:
        return DW_CONN_CAT_WEB;
    case 53: case 853: case 5353:
        return DW_CONN_CAT_DNS;
    case 25: case 465: case 587: case 110: case 143: case 993: case 995:
        return DW_CONN_CAT_MAIL;
    case 20: case 21: case 989: case 990: case 445: case 873:
        return DW_CONN_CAT_TRANSFER;
    case 500: case 1194: case 1701: case 1723: case 4500: case 51820:
        return DW_CONN_CAT_VPN;
    default:
        break;
    }
    if (tcp)
        return DW_CONN_CAT_OTHER_TCP;
    if (udp)
        return DW_CONN_CAT_OTHER_UDP;
    return DW_CONN_CAT_OTHER;
}

/* ---- END copy ---- */

/* ---- BEGIN copy: aggregate rate contract ---- */

static void dw_unifi_add_aggregate_rate_contract(struct json_object *obj,
                                                 struct json_object *wans,
                                                 int64_t summed_rate)
{
    const char *zero_reason = "";
    int64_t oldest_updated_at = 0;
    int64_t worst_age_ms = -1;
    int contributors = 0;
    int all_valid = 1;
    int any_degraded = 0;
    int any_carried = 0;
    int i, n;

    if (!obj || !wans || !json_object_is_type(wans, json_type_array))
        return;
    n = (int)json_object_array_length(wans);
    for (i = 0; i < n; i++) {
        struct json_object *w = json_object_array_get_idx(wans, i);
        const char *wan_zero;
        int64_t updated_at;
        int64_t age_ms;

        if (!w)
            continue;
        contributors++;
        if (!dw_json_get_bool(w, "sample_valid", 1))
            all_valid = 0;
        if (dw_json_get_bool(w, "degraded", 0))
            any_degraded = 1;
        if (dw_json_get_bool(w, "rate_carried_forward", 0))
            any_carried = 1;
        updated_at = dw_json_get_int64(w, "updated_at", 0);
        if (updated_at > 0 && (oldest_updated_at == 0 || updated_at < oldest_updated_at))
            oldest_updated_at = updated_at;
        age_ms = dw_json_get_int64(w, "sample_age_ms", -1);
        if (age_ms > worst_age_ms)
            worst_age_ms = age_ms;
        wan_zero = dw_json_get_string(w, "zero_reason", "");
        if (wan_zero[0] && (!zero_reason[0] || !strcmp(zero_reason, "idle")))
            zero_reason = wan_zero;
    }
    if (!contributors)
        return;

    json_object_object_add(obj, "rate_source", json_object_new_string("wan_sum"));
    json_object_object_add(obj, "sample_valid", json_object_new_boolean(all_valid));
    json_object_object_add(obj, "degraded", json_object_new_boolean(any_degraded));
    json_object_object_add(obj, "rate_carried_forward", json_object_new_boolean(any_carried));
    json_object_object_add(obj, "updated_at", json_object_new_int64(oldest_updated_at));
    json_object_object_add(obj, "sample_age_ms", json_object_new_int64(worst_age_ms));
    if (summed_rate > 0)
        json_object_object_add(obj, "zero_reason", json_object_new_string(""));
    else
        json_object_object_add(obj, "zero_reason",
                               json_object_new_string(zero_reason[0] ? zero_reason :
                                                      "no_contributing_wan_sample"));
}

/* ---- END copy ---- */

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        printf("FAIL %s\n", what);
    } else {
        printf("ok   %s\n", what);
    }
}

static void check_cat(const char *line, dw_conn_cat_t want, const char *what)
{
    dw_conn_cat_t got = dw_conntrack_line_category(line);

    if (got != want) {
        failures++;
        printf("FAIL %s: got %s want %s\n", what,
               dw_conn_cat_meta[got].key, dw_conn_cat_meta[want].key);
    } else {
        printf("ok   %s -> %s\n", what, dw_conn_cat_meta[got].key);
    }
}

static struct json_object *wan_row(int valid, int degraded, int carried,
                                   const char *zero_reason,
                                   int64_t updated_at, int64_t age_ms)
{
    struct json_object *w = json_object_new_object();

    json_object_object_add(w, "sample_valid", json_object_new_boolean(valid));
    json_object_object_add(w, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(w, "rate_carried_forward", json_object_new_boolean(carried));
    json_object_object_add(w, "zero_reason", json_object_new_string(zero_reason));
    json_object_object_add(w, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(w, "sample_age_ms", json_object_new_int64(age_ms));
    return w;
}

int main(void)
{
    /* Real /proc/net/nf_conntrack shapes observed on 30.1. */
    check_cat("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.30.50 dst=1.1.1.1 sport=51000 dport=443 packets=10 bytes=1000 src=1.1.1.1 dst=203.0.113.9 sport=443 dport=51000 [ASSURED] mark=65536001 use=1",
              DW_CONN_CAT_WEB, "tcp/443 is web");
    check_cat("ipv4     2 udp     17 29 src=192.168.30.50 dst=1.1.1.1 sport=51001 dport=443 packets=4 bytes=400 mark=65536003 use=1",
              DW_CONN_CAT_WEB, "udp/443 (QUIC) is web");
    check_cat("ipv4     2 udp     17 29 src=192.168.30.50 dst=192.168.30.1 sport=51002 dport=53 packets=2 bytes=140 use=1",
              DW_CONN_CAT_DNS, "udp/53 is dns");
    check_cat("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.30.50 dst=203.0.113.7 sport=51003 dport=993 packets=9 bytes=900 use=1",
              DW_CONN_CAT_MAIL, "tcp/993 is mail");
    check_cat("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.30.50 dst=203.0.113.8 sport=51004 dport=445 packets=9 bytes=900 use=1",
              DW_CONN_CAT_TRANSFER, "tcp/445 is transfer");
    check_cat("ipv4     2 udp     17 180 src=192.168.30.50 dst=203.0.113.9 sport=51005 dport=51820 packets=9 bytes=900 use=1",
              DW_CONN_CAT_VPN, "udp/51820 is vpn");
    check_cat("ipv4     2 icmp     1 29 src=192.168.30.50 dst=1.1.1.1 type=8 code=0 id=1 packets=1 bytes=84 use=1",
              DW_CONN_CAT_ICMP, "icmp is icmp");

    /*
     * The defect this replaced: a high port was rendered as an application name
     * ("tcp/30185"). It must land in a transport bucket, never invent a service,
     * and never be guessed as P2P.
     */
    check_cat("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.30.50 dst=203.0.113.10 sport=51006 dport=30185 packets=9 bytes=900 use=1",
              DW_CONN_CAT_OTHER_TCP, "tcp high port is other_tcp, not p2p");
    check_cat("ipv4     2 udp     17 29 src=192.168.30.50 dst=203.0.113.11 sport=51007 dport=6882 packets=9 bytes=900 use=1",
              DW_CONN_CAT_OTHER_UDP, "udp/6882 is other_udp, not p2p");

    /*
     * The remote port is the first dport. A line whose reply tuple carries an
     * ephemeral dport must still classify on the server port, or every flow
     * would bucket by the client's random port.
     */
    check_cat("ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=93.184.216.34 sport=44321 dport=80 packets=5 bytes=500 src=93.184.216.34 dst=203.0.113.9 sport=80 dport=44321 [ASSURED] use=1",
              DW_CONN_CAT_WEB, "classifies on first dport, not the reply's");

    /* Every bucket has a key and a display name: no empty column downstream. */
    {
        int i, all = 1;

        for (i = 0; i < DW_CONN_CAT__COUNT; i++)
            if (!dw_conn_cat_meta[i].key || !dw_conn_cat_meta[i].key[0] ||
                !dw_conn_cat_meta[i].name || !dw_conn_cat_meta[i].name[0])
                all = 0;
        check(all, "every category has a key and a name");
    }

    /*
     * Aggregate rate contract. The reported symptom was WAN and gateway both 0
     * while clients showed traffic, so the cases that matter are: all WANs
     * stale, some stale, genuinely idle, and carried forward.
     */
    {
        struct json_object *wans = json_object_new_array();
        struct json_object *gw = json_object_new_object();

        json_object_array_add(wans, wan_row(0, 1, 0, "no_fresh_sample", 1000, 21000));
        json_object_array_add(wans, wan_row(0, 1, 0, "no_fresh_sample", 1002, 19000));
        dw_unifi_add_aggregate_rate_contract(gw, wans, 0);

        check(!strcmp(dw_json_get_string(gw, "zero_reason", ""), "no_fresh_sample"),
              "all WANs stale -> gateway says no_fresh_sample, not idle");
        check(dw_json_get_bool(gw, "degraded", 0) == 1, "all stale -> degraded");
        check(dw_json_get_bool(gw, "sample_valid", 1) == 0, "all stale -> not valid");
        check(dw_json_get_int64(gw, "updated_at", -1) == 1000,
              "updated_at is the oldest contributor");
        check(dw_json_get_int64(gw, "sample_age_ms", -1) == 21000,
              "sample_age_ms is the worst contributor");
        json_object_put(gw);
        json_object_put(wans);
    }
    {
        /* Genuinely idle lines must still report idle, not a fake data gap. */
        struct json_object *wans = json_object_new_array();
        struct json_object *gw = json_object_new_object();

        json_object_array_add(wans, wan_row(1, 0, 0, "idle", 2000, 1000));
        json_object_array_add(wans, wan_row(1, 0, 0, "idle", 2001, 900));
        dw_unifi_add_aggregate_rate_contract(gw, wans, 0);

        check(!strcmp(dw_json_get_string(gw, "zero_reason", ""), "idle"),
              "all idle -> gateway says idle");
        check(dw_json_get_bool(gw, "sample_valid", 0) == 1, "all idle -> still valid");
        check(dw_json_get_bool(gw, "degraded", 1) == 0, "all idle -> not degraded");
        json_object_put(gw);
        json_object_put(wans);
    }
    {
        /*
         * Mixed: one line idle, one line unsampled. A zero sum here is caused by
         * the missing sample, so that reason must win -- reporting "idle" would
         * be the exact conflation this contract removes.
         */
        struct json_object *wans = json_object_new_array();
        struct json_object *gw = json_object_new_object();

        json_object_array_add(wans, wan_row(1, 0, 0, "idle", 3000, 500));
        json_object_array_add(wans, wan_row(0, 1, 0, "stale_beyond_carry_window", 2900, 90000));
        dw_unifi_add_aggregate_rate_contract(gw, wans, 0);

        check(!strcmp(dw_json_get_string(gw, "zero_reason", ""),
                      "stale_beyond_carry_window"),
              "missing-data reason outranks idle");
        check(dw_json_get_bool(gw, "sample_valid", 1) == 0,
              "one invalid contributor -> aggregate not valid");
        json_object_put(gw);
        json_object_put(wans);
    }
    {
        /* Non-zero sum needs no excuse, and carry-forward propagates. */
        struct json_object *wans = json_object_new_array();
        struct json_object *gw = json_object_new_object();

        json_object_array_add(wans, wan_row(0, 1, 1, "carried_forward_stale_sample", 4000, 20000));
        json_object_array_add(wans, wan_row(1, 0, 0, "", 4001, 1000));
        dw_unifi_add_aggregate_rate_contract(gw, wans, 12345);

        check(!strcmp(dw_json_get_string(gw, "zero_reason", "x"), ""),
              "non-zero sum -> empty zero_reason");
        check(dw_json_get_bool(gw, "rate_carried_forward", 0) == 1,
              "any carried contributor -> aggregate carried_forward");
        json_object_put(gw);
        json_object_put(wans);
    }
    {
        /* No WANs: write nothing rather than claim a verdict. */
        struct json_object *wans = json_object_new_array();
        struct json_object *gw = json_object_new_object();

        dw_unifi_add_aggregate_rate_contract(gw, wans, 0);
        check(json_object_object_length(gw) == 0,
              "no contributors -> no contract fields invented");
        json_object_put(gw);
        json_object_put(wans);
    }

    printf("\nfailures: %d\n", failures);
    return failures ? 1 : 0;
}
