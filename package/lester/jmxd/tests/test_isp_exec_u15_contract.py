#!/usr/bin/env python3
"""U-15 ISP detection must not interpolate WAN data into a root shell."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_isp.c").read_text(encoding="utf-8")


def test_isp_detection_uses_bounded_fixed_argv() -> None:
    for forbidden in ("system(", "popen(", "pclose(", '"/bin/sh"', "jsonfilter"):
        assert forbidden not in SOURCE, forbidden
    for required in (
        '#include "jmx_exec.h"',
        '{ "/bin/ubus", "call", object, "status", NULL }',
        '"/usr/bin/curl", "-4", "-fsS"',
        "JMX_ISP_EXEC_TIMEOUT_MS",
        "JMX_ISP_IFSTATUS_OUTPUT_MAX",
        "jmx_exec_capture(",
        "!result->timed_out",
        "!result->truncated",
        "result->term_signal == 0",
        "result->exit_code == 0",
        "json_tokener_parse_ex(",
        '"l3_device"',
        "jmx_isp_ifname_ok(json_object_get_string(value))",
    ):
        assert required in SOURCE, required


if __name__ == "__main__":
    test_isp_detection_uses_bounded_fixed_argv()
    print("ok: U-15 ISP detection uses bounded fixed argv and strict JSON")
