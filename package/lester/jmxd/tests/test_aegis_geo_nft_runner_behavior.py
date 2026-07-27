#!/usr/bin/env python3
"""Exercise the bounded nft runner used by Geo check/apply/snapshot operations."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import textwrap


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "aegisxd" / "aegisxd_geo.c"


def section(source: str, start: str, end: str, include_end: bool = False) -> str:
    left = source.index(start)
    right = source.index(end, left)
    return source[left : right + (len(end) if include_end else 0)]


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    capture_marker = source.index("/* GEO_READBACK_CAPTURE_BEGIN */")
    child_left = source.index("static uint64_t geo_monotonic_ms(void)", capture_marker)
    child_right = source.index("static int geo_capture_readback(", child_left)
    child_helpers = source[child_left:child_right]
    runner = section(
        source,
        "/* GEO_NFT_RUNNER_BEGIN */",
        "/* GEO_NFT_RUNNER_END */",
        include_end=True,
    )

    with tempfile.TemporaryDirectory(prefix="aegis-geo-runner-") as td:
        tmp = pathlib.Path(td)
        log = tmp / "nft.log"
        output = tmp / "snapshot.nft"
        fake = tmp / "nft"
        harness = tmp / "runner.c"
        binary = tmp / "runner"

        fake.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                mode="$1"
                case "$mode" in
                  ok) printf 'new-artifact\\n'; sleep 0.1; exit 0 ;;
                  fail) printf 'must-not-replace\\n'; printf 'nonzero\\n' >&2; exit 7 ;;
                  hang) sleep 3; exit 0 ;;
                  stdout-overflow) dd if=/dev/zero bs=2048 count=1 2>/dev/null; exit 0 ;;
                  stderr-overflow) dd if=/dev/zero bs=2048 count=1 1>&2 2>/dev/null; exit 0 ;;
                  log-first) printf 'first-long-message\\n' >&2; exit 9 ;;
                  log-second) printf 'x\\n' >&2; exit 9 ;;
                  *) exit 64 ;;
                esac
                """
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)

        harness.write_text(
            textwrap.dedent(
                f"""
                #define _DEFAULT_SOURCE 1
                #include <errno.h>
                #include <fcntl.h>
                #include <poll.h>
                #include <signal.h>
                #include <stdint.h>
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include <time.h>
                #include <unistd.h>
                #include <sys/types.h>
                #include <sys/wait.h>

                #define AEGISXD_MAX_PATH 4096
                #define GEO_NFT_TIMEOUT_MS 1500ULL
                #define GEO_NFT_FILE_MAX_BYTES 1024ULL
                #define GEO_NFT_LOG_MAX_BYTES 1024ULL
                #define GEO_NFT_LOG "{log}"

                {child_helpers}
                {runner}

                int main(int argc, char **argv)
                {{
                    char *args[3];
                    const char *output_path;
                    int rc;

                    if (argc != 4) return 64;
                    args[0] = argv[1];
                    args[1] = argv[2];
                    args[2] = NULL;
                    output_path = !strcmp(argv[3], "-") ? NULL : argv[3];
                    rc = geo_nft_run(args, output_path);
                    printf("rc=%d\\n", rc);
                    return 0;
                }}
                """
            ),
            encoding="utf-8",
        )
        subprocess.run(
            ["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(harness), "-o", str(binary)],
            check=True,
        )

        def run(mode: str, out: pathlib.Path | None = output) -> int:
            completed = subprocess.run(
                [str(binary), str(fake), mode, str(out) if out else "-"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return int(completed.stdout.strip().split("=")[-1])

        for _ in range(5):
            ok_rc = run("ok")
            assert ok_rc == 0, f"delayed successful exit returned {ok_rc}; log={log.read_bytes()!r}"
        assert output.read_text(encoding="utf-8") == "new-artifact\n"

        output.write_text("known-good\n", encoding="utf-8")
        assert run("fail") == 7
        assert output.read_text(encoding="utf-8") == "known-good\n"

        assert run("hang") == -1
        assert output.read_text(encoding="utf-8") == "known-good\n"
        assert run("stdout-overflow") == -1
        assert output.read_text(encoding="utf-8") == "known-good\n"
        assert run("stderr-overflow", None) == -1

        assert run("log-first", None) == 9
        assert "first-long-message" in log.read_text(encoding="utf-8")
        assert run("log-second", None) == 9
        assert log.read_text(encoding="utf-8") == "x\n"

    print("ok: bounded Geo nft runner timeout, caps, status, truncation, and atomic output")


if __name__ == "__main__":
    main()
