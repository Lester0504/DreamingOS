#!/usr/bin/env python3
"""Compile and exercise the production Geo nft streaming JSON parser."""

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
static int feed_bytes(struct geo_readback_parser *parser, const char *text,
                      size_t length, size_t seed)
{
    size_t offset = 0;

    while (offset < length) {
        size_t chunk = ((offset * 1103515245U + seed) % 97U) + 1U;
        if (chunk > length - offset)
            chunk = length - offset;
        if (geo_readback_parser_feed(parser,
                (const unsigned char *)text + offset, chunk) != 0)
            return -1;
        offset += chunk;
    }
    return 0;
}

static int expect_json(const char *json, int valid, int sets, int rules,
                       int64_t elements)
{
    struct geo_readback_parser parser;
    struct geo_runtime_counts counts;
    int rc = 0;

    geo_readback_parser_init(&parser);
    for (size_t offset = 0; offset < strlen(json); offset++) {
        rc = geo_readback_parser_feed(&parser,
            (const unsigned char *)json + offset, 1);
        if (rc != 0)
            break;
    }
    if (rc == 0)
        rc = geo_readback_parser_finish(&parser, &counts);
    if (!valid)
        return rc == 0 ? -1 : 0;
    if (rc != 0 || counts.table_found != 1 || counts.set_count != sets ||
        counts.rule_count != rules || counts.element_count != elements)
        return -1;
    return 0;
}

static int test_large_stream(void)
{
    static const char prefix[] =
        "{\"metadata\":{\"escaped\":\"chunk\\n\\u4e2d\\u56fd\\uD83D\\uDE80\"},"
        "\"nftables\":["
        "{\"metainfo\":{\"json_schema_version\":1}},"
        "{\"table\":{\"name\":\"dreamingwrt_aegis_geo\",\"family\":\"inet\"}},"
        "{\"set\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
        "\"name\":\"geo_cn_v6\",\"elem\":[";
    static const char item[] =
        "{\"prefix\":{\"addr\":\"2001:db8:1234:5678::\",\"len\":64},"
        "\"comment\":\"escaped\\\"value\"}";
    static const char suffix[] =
        "]}},"
        "{\"set\":{\"family\":\"inet\",\"table\":\"other_table\","
        "\"name\":\"ignored\",\"elem\":[1,2,3]}},"
        "{\"rule\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
        "\"chain\":\"geo_forward\",\"expr\":[{\"counter\":null}]}},"
        "{\"rule\":{\"family\":\"inet\",\"table\":\"other_table\"}}]}";
    const int64_t wanted = 664323;
    struct geo_readback_parser parser;
    struct geo_runtime_counts counts;
    int64_t i;
    uint64_t bytes = 0;

    geo_readback_parser_init(&parser);
    if (feed_bytes(&parser, prefix, sizeof(prefix) - 1, 3U) != 0)
        return -1;
    bytes += sizeof(prefix) - 1;
    for (i = 0; i < wanted; i++) {
        if (i && geo_readback_parser_feed(&parser,
                (const unsigned char *)",", 1) != 0)
            return -1;
        if (feed_bytes(&parser, item, sizeof(item) - 1, (size_t)i + 7U) != 0)
            return -1;
        bytes += sizeof(item) - 1 + (i != 0);
    }
    if (feed_bytes(&parser, suffix, sizeof(suffix) - 1, 11U) != 0 ||
        geo_readback_parser_finish(&parser, &counts) != 0)
        return -1;
    bytes += sizeof(suffix) - 1;
    if (bytes <= 16ULL * 1024ULL * 1024ULL || counts.table_found != 1 ||
        counts.set_count != 1 || counts.rule_count != 1 ||
        counts.element_count != wanted)
        return -1;
    printf("large_bytes=%llu elements=%lld parser_bytes=%zu\n",
           (unsigned long long)bytes, (long long)counts.element_count,
           sizeof(parser));
    return 0;
}

int main(void)
{
    static const char *bad[] = {
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}}",
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},]}",
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\\q\"}}]}",
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
          "{\"set\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\",\"name\":\"x\",\"elem\":1}}]}",
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
          "{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}}]}",
        "{\"nftables\":[]}{\"nftables\":[]}",
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
          "{\"element\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
          "\"elem\":[1,{\"a\":[2,3]}]}}]}",
        "{\"metadata\":{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
          "\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"other\"}}]}",
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"family\":\"inet\","
          "\"name\":\"dreamingwrt_aegis_geo\"}}]}",
    };
    size_t i;

    if (test_large_stream() != 0)
        return 1;
    if (expect_json(
        "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\"dreamingwrt_aegis_geo\"}},"
        "{\"set\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
        "\"name\":\"geo_cn_v4\",\"elem\":[1,{\"a\":[2,3]}]}},"
        "{\"rule\":{\"table\":\"dreamingwrt_aegis_geo\",\"family\":\"inet\"}}]}",
        1, 1, 1, 2) != 0)
        return 2;
    if (expect_json(
        "{\"nft\\u0061bles\":[{\"ta\\u0062le\":{\"fa\\u006dily\":\"in\\u0065t\","
        "\"na\\u006de\":\"dreamingwrt_aegis_ge\\u006f\"}},"
        "{\"s\\u0065t\":{\"family\":\"inet\",\"table\":\"dreamingwrt_aegis_geo\","
        "\"name\":\"geo_us_v4\",\"el\\u0065m\":[\"1.1.1.0/24\"]}}]}",
        1, 1, 0, 1) != 0)
        return 3;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        if (expect_json(bad[i], 0, 0, 0, 0) != 0)
            return 10 + (int)i;
    {
        static const unsigned char bad_utf8[] =
            "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"name\":\""
            "dreamingwrt_aegis_geo\"}}],\"bad\":\"\xc0\x80\"}";
        struct geo_readback_parser parser;
        geo_readback_parser_init(&parser);
        if (geo_readback_parser_feed(&parser, bad_utf8, sizeof(bad_utf8) - 1) == 0)
            return 20;
    }
    {
        struct geo_readback_parser parser;
        geo_readback_parser_init(&parser);
        parser.token_count = GEO_JSON_MAX_TOKENS;
        if (geo_readback_parser_feed(&parser, (const unsigned char *)"{", 1) == 0)
            return 21;
    }
    {
        struct geo_readback_parser parser;
        static const char start[] = "{\"padding\":";
        char quote = '"', value = 'a';
        size_t i;

        geo_readback_parser_init(&parser);
        if (geo_readback_parser_feed(&parser, (const unsigned char *)start,
                                     sizeof(start) - 1) != 0 ||
            geo_readback_parser_feed(&parser, (const unsigned char *)&quote, 1) != 0)
            return 22;
        for (i = 0; i < GEO_JSON_TOKEN_BYTES + 32; i++)
            if (geo_readback_parser_feed(&parser, (const unsigned char *)&value, 1) != 0)
                return 22;
        if (geo_readback_parser_feed(&parser, (const unsigned char *)&quote, 1) == 0)
            return 22;
    }
    {
        struct geo_readback_parser parser;
        static const char start[] = "{\"padding\":";
        char bracket = '[';
        size_t i;

        geo_readback_parser_init(&parser);
        if (geo_readback_parser_feed(&parser, (const unsigned char *)start,
                                     sizeof(start) - 1) != 0)
            return 23;
        for (i = 0; i < GEO_JSON_MAX_DEPTH; i++) {
            int rc = geo_readback_parser_feed(&parser,
                    (const unsigned char *)&bracket, 1);
            if (i + 1 < GEO_JSON_MAX_DEPTH && rc != 0)
                return 23;
            if (i + 1 == GEO_JSON_MAX_DEPTH && rc == 0)
                return 23;
        }
    }
    puts("ok: strict large streaming Geo nft readback");
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

        struct geo_runtime_set {{
            char name[16];
            int64_t element_count;
        }};

        struct geo_runtime_counts {{
            int table_found;
            int set_count;
            int rule_count;
            int64_t element_count;
            struct geo_runtime_set sets[GEO_READBACK_MAX_SETS];
        }};

        {production_parser()}
        {HARNESS}
        """
    )
    with tempfile.TemporaryDirectory(prefix="aegis-geo-readback-") as tmp:
        c_file = pathlib.Path(tmp) / "readback.c"
        binary = pathlib.Path(tmp) / "readback"
        c_file.write_text(source, encoding="utf-8")
        subprocess.run(
            ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(c_file), "-o", str(binary)],
            check=True,
        )
        completed = subprocess.run([str(binary)], check=True, text=True, capture_output=True)
        print(completed.stdout, end="")


if __name__ == "__main__":
    main()
