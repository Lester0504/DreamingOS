/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "client_connections_snapshot.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

char *get_app_name_by_id(int id)
{
    (void)id;
    return "";
}

static void test_ipv4_mark_and_stable_id(void)
{
    static const char *before =
        "ipv4 2 tcp 6 7424 ESTABLISHED "
        "src=192.168.30.2 dst=54.248.179.9 sport=46106 dport=443 "
        "packets=10 bytes=1000 "
        "src=192.168.30.1 dst=192.168.30.2 sport=12345 dport=46106 "
        "packets=20 bytes=2000 [ASSURED] mark=65536003 zone=0 use=2";
    static const char *after =
        "ipv4 2 tcp 6 7410 ESTABLISHED "
        "src=192.168.30.2 dst=54.248.179.9 sport=46106 dport=443 "
        "packets=100 bytes=9000 "
        "src=192.168.30.1 dst=192.168.30.2 sport=12345 dport=46106 "
        "packets=200 bytes=12000 [ASSURED] mark=65536002 zone=0 use=2";
    char id_before[DW_CC_ID_LEN];
    char id_after[DW_CC_ID_LEN];
    int family = 0, wan = 0;
    uint64_t up = 0, down = 0;

    assert(dw_cc_test_parse_conntrack(before, id_before, sizeof(id_before),
                                      &family, &wan, &up, &down) == 0);
    assert(family == 4);
    assert(wan == 3);
    assert(up == 1000 && down == 2000);
    assert(strlen(id_before) == 35 && !strncmp(id_before, "ct:", 3));

    assert(dw_cc_test_parse_conntrack(after, id_after, sizeof(id_after),
                                      &family, &wan, &up, &down) == 0);
    assert(wan == 2);
    assert(up == 9000 && down == 12000);
    assert(!strcmp(id_before, id_after));
}

static void test_ipv6_canonical_id(void)
{
    static const char *expanded =
        "ipv6 10 tcp 6 2 TIME_WAIT "
        "src=fd00:0030:0001:0000:be24:11ff:fe1c:9fec "
        "dst=2408:8678:be00:0007:0000:0000:2a3f:322b "
        "sport=53217 dport=80 packets=0 bytes=0 "
        "src=2408:8678:be00:0007:0000:0000:2a3f:322b "
        "dst=2409:8a10:0010:68c0:0000:0000:0000:0001 "
        "sport=80 dport=53217 packets=0 bytes=0 [ASSURED] "
        "mark=65536004 zone=0 use=2";
    static const char *compressed =
        "ipv6 10 tcp 6 1 TIME_WAIT "
        "src=fd00:30:1::be24:11ff:fe1c:9fec "
        "dst=2408:8678:be00:7::2a3f:322b "
        "sport=53217 dport=80 packets=0 bytes=0 "
        "src=2408:8678:be00:7::2a3f:322b "
        "dst=2409:8a10:10:68c0::1 "
        "sport=80 dport=53217 packets=0 bytes=0 [ASSURED] "
        "mark=65536004 zone=0 use=2";
    char a[DW_CC_ID_LEN], b[DW_CC_ID_LEN];
    int family = 0, wan = 0;

    assert(dw_cc_test_parse_conntrack(expanded, a, sizeof(a), &family, &wan,
                                      NULL, NULL) == 0);
    assert(family == 6 && wan == 4);
    assert(dw_cc_test_parse_conntrack(compressed, b, sizeof(b), NULL, NULL,
                                      NULL, NULL) == 0);
    assert(!strcmp(a, b));
}

static void test_invalid_line(void)
{
    assert(dw_cc_test_parse_conntrack("not conntrack", NULL, 0, NULL, NULL,
                                      NULL, NULL) != 0);
}

static void test_ct_appid_ipv4_tcp_exact_and_wan(void)
{
    static const char *ct_line =
        "4 0 6 192.168.30.2 52770 124.163.205.212 443 "
        "100000146 80000004 2 80000004 10002";
    char src[DW_CC_ADDR_LEN], dst[DW_CC_ADDR_LEN];
    int family = 0, zone = -1, proto = 0, sport = 0, dport = 0;
    int app_id = 0, wan_id = 0;
    unsigned int status = 0;

    assert(dw_cc_test_parse_ct_appid(ct_line, &family, &zone, &proto,
                                     src, sizeof(src), &sport,
                                     dst, sizeof(dst), &dport, &app_id,
                                     &status, &wan_id) == 0);
    assert(family == 4 && zone == 0 && proto == 6);
    assert(!strcmp(src, "192.168.30.2"));
    assert(!strcmp(dst, "124.163.205.212"));
    assert(sport == 52770 && dport == 443);
    assert(app_id == 100000146 && status == 0x80000004U && wan_id == 2);
}

static void test_ct_appid_ipv6_udp_and_zone_exactness(void)
{
    static const char *ct_line =
        "6 7 17 fd00:30:1::2 5353 2404:6800:4008::200e 443 "
        "100000322 80000004 4 80000004 10004";
    assert(dw_cc_test_ct_tuple_matches(
               6, 7, 17, "fd00:30:1::2", 5353,
               "2404:6800:4008::200e", 443,
               6, 7, 17, "fd00:0030:0001:0000::2", 5353,
               "2404:6800:4008:0000:0000:0000:0000:200e", 443) == 1);
    assert(dw_cc_test_ct_tuple_matches(
               6, 7, 17, "fd00:30:1::2", 5353,
               "2404:6800:4008::200e", 443,
               6, 8, 17, "fd00:30:1::2", 5353,
               "2404:6800:4008::200e", 443) == 0);
    assert(dw_cc_test_parse_ct_appid(ct_line, NULL, NULL, &((int){0}),
                                     NULL, 0, NULL, NULL, 0, NULL, NULL,
                                     NULL, NULL) == 0);
}

static void test_ct_appid_reliability_and_fallback_priority(void)
{
    static const char *conntrack_line =
        "ipv4 2 tcp 6 7424 ESTABLISHED "
        "src=192.168.30.2 dst=54.248.179.9 sport=46106 dport=443 "
        "packets=10 bytes=1000 "
        "src=192.168.30.1 dst=192.168.30.2 sport=12345 dport=46106 "
        "packets=20 bytes=2000 [ASSURED] mark=65536003 zone=0 use=2";
    static const char *reliable =
        "4 0 6 192.168.30.2 46106 54.248.179.9 443 "
        "100000146 80000004 2 80000004 10002";
    static const char *ignored =
        "4 0 6 192.168.30.2 46106 54.248.179.9 443 "
        "100000999 80000005 2 80000004 10002";
    int app_id = 0, wan_id = 0;

    assert(dw_cc_test_resolve_app(conntrack_line, reliable, 777,
                                  &app_id, &wan_id) == 1);
    assert(app_id == 100000146 && wan_id == 2);
    assert(dw_cc_test_resolve_app(conntrack_line, ignored, 777,
                                  &app_id, &wan_id) == 1);
    assert(app_id == 777 && wan_id == 2);
}

static void test_ct_appid_rejects_malformed_and_family_mismatch(void)
{
    static const char *bad = "4 0 6 192.168.30.2 1 2001:db8::1 443 "
                             "100000146 80000004 2 80000004 10002";
    assert(dw_cc_test_parse_ct_appid(bad, NULL, NULL, NULL, NULL, 0,
                                     NULL, NULL, 0, NULL, NULL, NULL,
                                     NULL) != 0);
}

static void test_service_category_fallback_is_generic_and_honest(void)
{
    char app_name[64], category_key[64];

    assert(dw_cc_test_service_category("tcp", 443, app_name,
                                       sizeof(app_name), category_key,
                                       sizeof(category_key)) == 1);
    assert(!strcmp(app_name, "TLS/HTTPS 服务"));
    assert(!strcmp(category_key, "service_https"));
    assert(dw_cc_test_service_category("udp", 443, app_name,
                                       sizeof(app_name), category_key,
                                       sizeof(category_key)) == 1);
    assert(!strcmp(app_name, "QUIC/HTTP3 服务"));
    assert(!strcmp(category_key, "service_quic"));
    assert(dw_cc_test_service_category("tcp", 30131, app_name,
                                       sizeof(app_name), category_key,
                                       sizeof(category_key)) == 0);
    assert(!app_name[0]);
    assert(!strcmp(category_key, "unknown_application"));
}

int main(void)
{
    test_ipv4_mark_and_stable_id();
    test_ipv6_canonical_id();
    test_invalid_line();
    test_ct_appid_ipv4_tcp_exact_and_wan();
    test_ct_appid_ipv6_udp_and_zone_exactness();
    test_ct_appid_reliability_and_fallback_priority();
    test_ct_appid_rejects_malformed_and_family_mismatch();
    test_service_category_fallback_is_generic_and_honest();
    puts("client_connections_snapshot parser tests: ok");
    return 0;
}
