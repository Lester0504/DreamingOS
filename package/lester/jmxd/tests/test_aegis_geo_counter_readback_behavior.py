#!/usr/bin/env python3
"""Compile the production Geo readback parser and verify nft counter attribution.

The rule comment written by geo_write_rule_line() is
`aegis_geo:<rule_id>:<direction>:<COUNTRY>`, so packets/bytes must land on an
exact rule/direction/country. This test uses the real `nft -j list table` shape
(comment on the rule object, counter inside the expr array) and asserts that
nothing is inferred from rule ordering.
"""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "aegisxd" / "aegisxd_geo.c"
BEGIN = "/* GEO_READBACK_STREAM_BEGIN"
END = "/* GEO_READBACK_STREAM_END */"


def production_parser() -> str:
    source = SOURCE.read_text(encoding="utf-8")
    begin = source.index(BEGIN)
    end = source.index(END, begin) + len(END)
    return source[begin:end]


HARNESS = r'''
static int parse_stream(const char *json, struct geo_runtime_counts *counts)
{
    struct geo_readback_parser parser;
    size_t offset;
    int rc = 0;

    geo_readback_parser_init(&parser);
    for (offset = 0; offset < strlen(json); offset++) {
        rc = geo_readback_parser_feed(&parser,
                (const unsigned char *)json + offset, 1);
        if (rc != 0)
            return rc;
    }
    return geo_readback_parser_finish(&parser, counts);
}

static const struct geo_rule_counter *find_rule(const struct geo_runtime_counts *counts,
                                                const char *rule_id)
{
    int i;

    for (i = 0; i < counts->rule_counter_count; i++)
        if (!strcmp(counts->rule_counters[i].rule_id, rule_id))
            return &counts->rule_counters[i];
    return NULL;
}

static const struct geo_country_counter *find_country(const struct geo_runtime_counts *counts,
                                                      const char *country)
{
    int i;

    for (i = 0; i < counts->country_counter_count; i++)
        if (!strcmp(counts->country_counters[i].country, country))
            return &counts->country_counters[i];
    return NULL;
}

/* Real `nft -j list table inet dreamingwrt_aegis_geo` layout: the comment lives
 * on the rule object and the counter is one element of the expr array.
 */
static const char owned_stream[] =
    "{\"nftables\":["
    "{\"metainfo\":{\"json_schema_version\":1}},"
    "{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\",\"handle\":9}},"
    "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
      "\"chain\":\"geo_input\",\"handle\":3,"
      "\"comment\":\"aegis_geo:rule-a:inbound:CN\","
      "\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"payload\":"
        "{\"protocol\":\"ip\",\"field\":\"saddr\"}},\"right\":\"@geo_cn_v4\"}},"
        "{\"counter\":{\"packets\":11,\"bytes\":1100}},{\"drop\":null}]}},"
    "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
      "\"chain\":\"geo_input\",\"handle\":4,"
      "\"comment\":\"aegis_geo:rule-a:inbound:CN\","
      "\"expr\":[{\"counter\":{\"packets\":4,\"bytes\":400}},{\"drop\":null}]}},"
    "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
      "\"chain\":\"geo_output\",\"handle\":5,"
      "\"comment\":\"aegis_geo:rule-a:outbound:US\","
      "\"expr\":[{\"counter\":{\"packets\":7,\"bytes\":700}},{\"accept\":null}]}},"
    "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
      "\"chain\":\"geo_forward\",\"handle\":6,"
      "\"comment\":\"aegis_geo:rule-b:inbound:US\","
      "\"expr\":[{\"counter\":{\"packets\":2,\"bytes\":200}},{\"drop\":null}]}},"
    /* Owned table, but a foreign comment: must not be attributed. */
    "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
      "\"chain\":\"geo_forward\",\"handle\":7,\"comment\":\"someone_else\","
      "\"expr\":[{\"counter\":{\"packets\":999,\"bytes\":99900}}]}},"
    /* Owned comment without any counter expression. */
    "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
      "\"chain\":\"geo_forward\",\"handle\":8,"
      "\"comment\":\"aegis_geo:rule-c:inbound:JP\",\"expr\":[{\"drop\":null}]}},"
    /* Different table entirely: ignored. */
    "{\"rule\":{\"family\":\"inet\",\"table\":\"other_table\","
      "\"chain\":\"x\",\"comment\":\"aegis_geo:rule-z:inbound:DE\","
      "\"expr\":[{\"counter\":{\"packets\":5,\"bytes\":500}}]}}"
    "]}";

static int test_owned_attribution(void)
{
    struct geo_runtime_counts counts;
    const struct geo_rule_counter *rule_a, *rule_b, *rule_c;
    const struct geo_country_counter *cn, *us, *jp;

    if (parse_stream(owned_stream, &counts) != 0)
        return 1;
    /* Six rule entries belong to the owned table; the other_table rule is not
     * counted at all.
     */
    if (!counts.table_found || counts.rule_count != 6)
        return 2;
    if (counts.owned_rule_lines != 5 || counts.foreign_rule_lines != 1 ||
        counts.rule_lines_without_counter != 1 || counts.rule_counter_bucket_overflow)
        return 3;

    /* 11 + 4 inbound, 2 inbound for rule-b, 7 outbound. Foreign 999 excluded. */
    if (counts.counter_totals.inbound_packets != 17 ||
        counts.counter_totals.inbound_bytes != 1700 ||
        counts.counter_totals.outbound_packets != 7 ||
        counts.counter_totals.outbound_bytes != 700 ||
        counts.counter_totals.rule_lines != 5 ||
        counts.counter_totals.counter_lines != 4)
        return 4;

    rule_a = find_rule(&counts, "rule-a");
    rule_b = find_rule(&counts, "rule-b");
    rule_c = find_rule(&counts, "rule-c");
    if (!rule_a || !rule_b || !rule_c || counts.rule_counter_count != 3)
        return 5;
    if (rule_a->totals.inbound_packets != 15 || rule_a->totals.inbound_bytes != 1500 ||
        rule_a->totals.outbound_packets != 7 || rule_a->totals.outbound_bytes != 700 ||
        rule_a->totals.rule_lines != 3 || rule_a->totals.counter_lines != 3)
        return 6;
    if (rule_b->totals.inbound_packets != 2 || rule_b->totals.outbound_packets != 0)
        return 7;
    /* rule-c has no counter: a rule line, but zero counter lines. */
    if (rule_c->totals.rule_lines != 1 || rule_c->totals.counter_lines != 0 ||
        rule_c->totals.inbound_packets != 0 || rule_c->totals.inbound_bytes != 0)
        return 8;

    cn = find_country(&counts, "CN");
    us = find_country(&counts, "US");
    jp = find_country(&counts, "JP");
    if (!cn || !us || !jp || counts.country_counter_count != 3)
        return 9;
    if (cn->totals.inbound_packets != 15 || cn->totals.inbound_bytes != 1500 ||
        cn->totals.outbound_packets != 0)
        return 10;
    /* US receives rule-a outbound and rule-b inbound. */
    if (us->totals.outbound_packets != 7 || us->totals.inbound_packets != 2 ||
        us->totals.counter_lines != 2)
        return 11;
    if (jp->totals.counter_lines != 0 || jp->totals.rule_lines != 1)
        return 12;
    return 0;
}

static int test_malformed_comments(void)
{
    static const char *ignored[] = {
        "aegis_geo:rule-a:sideways:CN",
        "aegis_geo:rule-a:inbound:cn",
        "aegis_geo:rule-a:inbound:CHN",
        "aegis_geo:rule-a:inbound:C1",
        "aegis_geo:rule-a:inbound:",
        "aegis_geo:rule-a:inbound",
        "aegis_geo::inbound:CN",
        "aegis_geo:rule-a",
        "aegis_geo:",
        "prefix_aegis_geo:rule-a:inbound:CN",
    };
    size_t i;

    for (i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++) {
        struct geo_runtime_counts counts;
        char json[768];

        snprintf(json, sizeof(json),
                 "{\"nftables\":["
                 "{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
                 "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
                 "\"chain\":\"geo_input\",\"comment\":\"%s\","
                 "\"expr\":[{\"counter\":{\"packets\":5,\"bytes\":500}}]}}]}",
                 ignored[i]);
        if (parse_stream(json, &counts) != 0)
            return 20 + (int)i;
        if (counts.owned_rule_lines != 0 || counts.foreign_rule_lines != 1 ||
            counts.rule_counter_count != 0 || counts.country_counter_count != 0 ||
            counts.counter_totals.inbound_packets != 0)
            return 40 + (int)i;
    }
    return 0;
}

static int test_rejects_broken_counters(void)
{
    static const char *bad[] = {
        /* Fractional, negative and exponent counters are not the nft contract. */
        "{\"counter\":{\"packets\":1.5,\"bytes\":10}}",
        "{\"counter\":{\"packets\":-1,\"bytes\":10}}",
        "{\"counter\":{\"packets\":1e3,\"bytes\":10}}",
        /* Duplicate keys must not silently take the last value. */
        "{\"counter\":{\"packets\":1,\"packets\":2,\"bytes\":10}}",
        /* Two counter expressions on one rule is ambiguous. */
        "{\"counter\":{\"packets\":1,\"bytes\":10}},{\"counter\":{\"packets\":2,\"bytes\":20}}",
        /* Overflowing uint64 must fail instead of wrapping. */
        "{\"counter\":{\"packets\":18446744073709551616,\"bytes\":10}}",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct geo_runtime_counts counts;
        char json[768];

        snprintf(json, sizeof(json),
                 "{\"nftables\":["
                 "{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
                 "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
                 "\"chain\":\"geo_input\",\"comment\":\"aegis_geo:r:inbound:CN\","
                 "\"expr\":[%s]}}]}",
                 bad[i]);
        if (parse_stream(json, &counts) == 0)
            return 60 + (int)i;
    }
    return 0;
}

static int test_missing_counter_is_not_zero_traffic(void)
{
    struct geo_runtime_counts counts;
    static const char json[] =
        "{\"nftables\":["
        "{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
        "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
          "\"chain\":\"geo_input\",\"comment\":\"aegis_geo:r:inbound:CN\","
          "\"expr\":[{\"counter\":null},{\"drop\":null}]}}]}";

    if (parse_stream(json, &counts) != 0)
        return 80;
    if (counts.owned_rule_lines != 1 || counts.rule_lines_without_counter != 1 ||
        counts.counter_totals.counter_lines != 0 ||
        counts.counter_totals.rule_lines != 1)
        return 81;
    return 0;
}

static int test_large_counters(void)
{
    struct geo_runtime_counts counts;
    const struct geo_country_counter *cn;
    static const char json[] =
        "{\"nftables\":["
        "{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
        "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
          "\"chain\":\"geo_input\",\"comment\":\"aegis_geo:r:inbound:CN\","
          "\"expr\":[{\"counter\":{\"packets\":9223372036854775807,"
          "\"bytes\":18446744073709551615}}]}}]}";

    if (parse_stream(json, &counts) != 0)
        return 90;
    cn = find_country(&counts, "CN");
    if (!cn || cn->totals.inbound_packets != 9223372036854775807ULL ||
        cn->totals.inbound_bytes != 18446744073709551615ULL)
        return 91;
    return 0;
}

int main(void)
{
    int rc;

    if ((rc = test_owned_attribution()) != 0)
        return rc;
    if ((rc = test_malformed_comments()) != 0)
        return rc;
    if ((rc = test_rejects_broken_counters()) != 0)
        return rc;
    if ((rc = test_missing_counter_is_not_zero_traffic()) != 0)
        return rc;
    if ((rc = test_large_counters()) != 0)
        return rc;
    puts("ok: Geo nft counter readback attributes packets/bytes by rule and country");
    return 0;
}
'''


def main() -> None:
    source = textwrap.dedent(
        f"""
        #include <ctype.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <string.h>
        #include <limits.h>

        #define GEO_NFT_TABLE "dreamingwrt_aegis_geo"
        #define GEO_JSON_MAX_DEPTH 128U
        #define GEO_JSON_TOKEN_BYTES 256U
        #define GEO_JSON_MAX_TOKENS 16000000ULL
        #define GEO_READBACK_MAX_ELEMENTS 1000000LL
        #define GEO_READBACK_MAX_SETS 498
        #define GEO_READBACK_MAX_RULES 63744
        #define GEO_MAX_RULES 64
        #define GEO_MAX_COUNTRIES 249

        struct geo_runtime_set {{
            char name[16];
            int64_t element_count;
        }};

        struct geo_counter_totals {{
            uint64_t inbound_packets;
            uint64_t inbound_bytes;
            uint64_t outbound_packets;
            uint64_t outbound_bytes;
            int rule_lines;
            int counter_lines;
        }};

        struct geo_rule_counter {{
            char rule_id[65];
            struct geo_counter_totals totals;
        }};

        struct geo_country_counter {{
            char country[3];
            struct geo_counter_totals totals;
        }};

        struct geo_runtime_counts {{
            int table_found;
            int set_count;
            int rule_count;
            int64_t element_count;
            struct geo_runtime_set sets[GEO_READBACK_MAX_SETS];
            struct geo_counter_totals counter_totals;
            struct geo_rule_counter rule_counters[GEO_MAX_RULES];
            int rule_counter_count;
            struct geo_country_counter country_counters[GEO_MAX_COUNTRIES];
            int country_counter_count;
            int owned_rule_lines;
            int foreign_rule_lines;
            int rule_lines_without_counter;
            int rule_counter_bucket_overflow;
        }};

        {production_parser()}
        {HARNESS}
        """
    )
    with tempfile.TemporaryDirectory(prefix="aegis-geo-counters-") as tmp:
        c_file = pathlib.Path(tmp) / "counters.c"
        binary = pathlib.Path(tmp) / "counters"
        c_file.write_text(source, encoding="utf-8")
        subprocess.run(
            ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(c_file), "-o", str(binary)],
            check=True,
        )
        completed = subprocess.run([str(binary)], check=True, text=True,
                                   capture_output=True)
        print(completed.stdout, end="")


if __name__ == "__main__":
    main()
