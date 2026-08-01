#!/usr/bin/env python3
"""U-15 IPv6 counters must use fixed nft argv and honest readback."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
START = SOURCE.index("#define IPV6_MAX_INTERFACES")
END = SOURCE.index(" * VPN status: enumerate VPN instances", START)
FAMILY = SOURCE[START:END]


def test_ipv6_nft_uses_bounded_argv_and_readback() -> None:
    for forbidden in ("system(", "popen(", "pclose(", '"/bin/sh"'):
        assert forbidden not in FAMILY, forbidden
    for required in (
        '#define IPV6_NFT_PATH "/usr/sbin/nft"',
        "dw_tool_capture(argv, result)",
        "dw_ipv6_nft_delete_table();",
        "!dw_ipv6_device_ok(iface->device)",
        "if_nametoindex(device) != 0",
        "dw_ipv6_counter_name(",
        "id_len + suffix_len >= out_len",
        '"add", "counter", "inet"',
        '"add", "rule", "inet"',
        '"list", "counter", "inet"',
        "strtoull(p, &end, 10)",
        "dw_read_nft_counter(cname_in, &iface->down_bytes)",
        "if (!iface->valid)",
        "continue;",
        "g_ipv6_counters_installed = 0;",
        '"ipv6_counters_unavailable"',
    ):
        assert required in FAMILY, required
    assert "snprintf(cname_" not in FAMILY


if __name__ == "__main__":
    test_ipv6_nft_uses_bounded_argv_and_readback()
    print("ok: U-15 IPv6 nft counters use fixed argv and honest readback")
