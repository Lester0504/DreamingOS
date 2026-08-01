#!/usr/bin/env python3
"""U-15 regex nft management must use bounded argv and owned handles."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_regex.c").read_text(encoding="utf-8")


def test_regex_nft_has_no_shell_pipeline() -> None:
    for forbidden in ("system(", "popen(", "pclose(", '"/bin/sh"',
                      "grep -E", "sed '", "while read h"):
        assert forbidden not in SOURCE, forbidden
    for required in (
        '#include "jmx_exec.h"',
        '#define JMX_REGEX_NFT_PATH     "/usr/sbin/nft"',
        "jmx_exec_wait(",
        "jmx_exec_capture(",
        "!result->timed_out",
        "!result->truncated",
        "result->term_signal == 0",
        "result->exit_code == 0",
        "JMX_REGEX_NFT_MAX_HANDLES",
        "regex_nft_line_handle(",
        "strtoull(tag, &parse_end, 10)",
        "if (remove_nftables_rule() != 0)",
        "if (setup_nftables_rule() != 0)",
        "dreamingwrt-regex-forward",
        "dreamingwrt-regex-output-mark",
        "dreamingwrt-regex-output-queue",
        '"delete", "rule", "inet"',
    ):
        assert required in SOURCE, required
    setup = SOURCE.split("static int setup_nftables_rule(void)", 1)[1]
    setup = setup.split("static int remove_nftables_rule(void)", 1)[0]
    assert setup.index("regex_nft_wait(queue_argv)") < setup.index("regex_nft_wait(mark_argv)")


if __name__ == "__main__":
    test_regex_nft_has_no_shell_pipeline()
    print("ok: U-15 regex nft rules use bounded argv and owned handles")
