#!/usr/bin/env python3
"""vendor_limit=0 must mean "no vendors", not "unlimited".

`GET /api/v1/fingerprint_index` returns vendors[] (1129 rows, ~596 KB on 30.1)
alongside devices[]. A caller that only consumes devices[] previously had no way
to opt out: vendor_limit was initialised to 0 and the emit loop only clamped when
`vendor_limit > 0`, so an explicit 0 was indistinguishable from an absent
parameter and the full list came back. The Android icon picker debounces on every
keystroke, so that difference is ~0.6 MB per keypress versus 66 KB.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_function_text
API = webd_dispatch_text()


def _fingerprint_index_body() -> str:
    """Source text of webd_fingerprint_index_response() only."""
    return webd_function_text("api_fingerprint.c", "webd_fingerprint_index_response")


def test_absent_and_zero_are_distinguishable() -> None:
    body = _fingerprint_index_body()
    assert "int vendor_limit_set = 0;" in body, (
        "a separate 'was it supplied' flag is required; reusing vendor_limit==0 "
        "as the sentinel is the defect itself")
    assert "if (vendor_limit_set && (int)json_object_array_length(vendors) >= vendor_limit)" in body, (
        "vendors[] clamp must trigger on vendor_limit_set, otherwise 0 reverts "
        "to meaning unlimited")
    assert "if (vendor_limit > 0 && (int)json_object_array_length(vendors)" not in body, (
        "the old '> 0' guard is back; vendor_limit=0 would return every vendor")
    assert "webd_fingerprint_parse_vendor_limit(vendor_limit_s, &vendor_limit)" in body
    assert "vendor_limit = atoi(vendor_limit_s)" not in body, (
        'atoi() cannot distinguish "0" from "abc"')


def test_echoed_vendor_limit_is_not_a_misleading_zero() -> None:
    body = _fingerprint_index_body()
    assert "vendor_limit_set ? vendor_limit : -1" in body, (
        "with no vendor_limit supplied the response must not echo 0, which now "
        "reads as 'zero requested' while a full vendors[] is returned")
    assert '"vendor_limit_applied"' in body


def test_limit_semantics_for_devices_are_untouched() -> None:
    """The devices[] limit keeps its own defaulting; only vendors[] changed."""
    body = _fingerprint_index_body()
    assert "if (limit <= 0)" in body and "limit = 48;" in body
    assert "if (limit > 120)" in body


def test_strict_parser_compiled_behaviour() -> None:
    """Compile the real parser and check every boundary case."""
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler, "a C compiler is required for this contract"

    match = re.search(
        r"static int webd_fingerprint_parse_vendor_limit\(const char \*text, int \*out\)\n\{.*?\n\}\n",
        API, re.S)
    assert match, "parser helper not found; was it renamed?"

    harness = (
        "#include <errno.h>\n"
        "#include <limits.h>\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        + match.group(0)
        + "struct expectation { const char *text; int ok; int value; };\n"
        "int main(void)\n"
        "{\n"
        "    struct expectation cases[] = {\n"
        "        { \"0\", 1, 0 },\n"
        "        { \"1\", 1, 1 },\n"
        "        { \"1129\", 1, 1129 },\n"
        "        { \" 7\", 1, 7 },\n"
        "        { \"\", 0, 0 },\n"
        "        { \"abc\", 0, 0 },\n"
        "        { \"0x10\", 0, 0 },\n"
        "        { \"12ab\", 0, 0 },\n"
        "        { \"-1\", 0, 0 },\n"
        "        { \"99999999999999\", 0, 0 },\n"
        "    };\n"
        "    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {\n"
        "        int value = -12345;\n"
        "        int ok = webd_fingerprint_parse_vendor_limit(cases[i].text, &value);\n"
        "        if (ok != cases[i].ok || (ok && value != cases[i].value)) {\n"
        "            fprintf(stderr, \"case %u (%s): ok=%d value=%d\\n\",\n"
        "                    i, cases[i].text, ok, value);\n"
        "            return 1;\n"
        "        }\n"
        "    }\n"
        "    if (webd_fingerprint_parse_vendor_limit(NULL, NULL)) {\n"
        "        fputs(\"NULL must not parse\\n\", stderr);\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n")

    with tempfile.TemporaryDirectory(prefix="fp-vendor-limit-") as raw:
        temporary = Path(raw)
        source = temporary / "contract.c"
        binary = temporary / "contract"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} fingerprint_index vendor_limit contracts")
