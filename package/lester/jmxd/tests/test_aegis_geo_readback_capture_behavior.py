#!/usr/bin/env python3
"""Exercise the production Geo readback subprocess/pipe resource guards."""

from __future__ import annotations

import errno
import os
import pathlib
import signal
import subprocess
import tempfile
import textwrap
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "aegisxd" / "aegisxd_geo.c"


def marked(source: str, begin: str, end: str) -> str:
    left = source.index(begin)
    right = source.index(end, left) + len(end)
    return source[left:right]


def process_gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.ESRCH
    return False


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    parser = marked(source, "/* GEO_READBACK_STREAM_BEGIN", "/* GEO_READBACK_STREAM_END */")
    capture = marked(source, "/* GEO_READBACK_CAPTURE_BEGIN", "/* GEO_READBACK_CAPTURE_END */")
    harness = textwrap.dedent(
        f"""
        #define _DEFAULT_SOURCE 1
        #include <ctype.h>
        #include <errno.h>
        #include <fcntl.h>
        #include <limits.h>
        #include <poll.h>
        #include <signal.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <time.h>
        #include <unistd.h>
        #include <sys/resource.h>
        #include <sys/types.h>
        #include <sys/wait.h>

        #define GEO_NFT_TABLE "dreamingwrt_aegis_geo"
        #define GEO_READBACK_MAX_BYTES (32ULL * 1024ULL * 1024ULL)
        #define GEO_NFT_LOG_MAX_BYTES (1ULL * 1024ULL * 1024ULL)
        #define GEO_READBACK_TIMEOUT_MS 5000ULL
        #define GEO_READBACK_CHUNK_BYTES 127U
        #define GEO_JSON_MAX_DEPTH 128U
        #define GEO_JSON_TOKEN_BYTES 256U
        #define GEO_JSON_MAX_TOKENS 16000000ULL
        #define GEO_READBACK_MAX_ELEMENTS 1000000LL
        #define GEO_READBACK_MAX_SETS 498
        #define GEO_READBACK_MAX_RULES 63744
        #define GEO_LEGACY_READBACK_PATH "{tempfile.gettempdir()}/aegis-geo-capture-legacy.json"
        #define GEO_NFT_LOG "{tempfile.gettempdir()}/aegis-geo-capture.log"

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

        static const char *geo_nft_binary(void)
        {{
            const char *path = getenv("FAKE_NFT");
            return path ? path : "";
        }}

        {parser}
        {capture}

        int main(int argc, char **argv)
        {{
            struct geo_runtime_counts counts;
            int rc;
            if (argc != 2) return 64;
            rc = geo_capture_readback(&counts);
            printf("mode=%s rc=%d sets=%d rules=%d elements=%lld\\n", argv[1], rc,
                   counts.set_count, counts.rule_count, (long long)counts.element_count);
            if (!strcmp(argv[1], "ok")) {{
                if (rc != 0 || counts.table_found != 1 || counts.set_count != 1 ||
                    counts.rule_count != 1 || counts.element_count != 3)
                    return 1;
            }} else if (!strcmp(argv[1], "large")) {{
                if (rc != 0 || counts.table_found != 1 || counts.set_count != 1 ||
                    counts.rule_count != 1 || counts.element_count != 500000)
                    return 1;
            }} else if (rc == 0) {{
                return 2;
            }}
            return 0;
        }}
        """
    )
    fake_nft = r'''#!/usr/bin/env python3
import os
import signal
import sys
import time

with open(os.environ["PID_FILE"], "w", encoding="ascii") as fp:
    fp.write(str(os.getpid()))
mode = os.environ["FAKE_MODE"]
written = 0
def emit(data):
    global written
    os.write(sys.stdout.fileno(), data)
    written += len(data)

if mode == "ok":
    sys.stdout.write('{"nftables":['
        '{"table":{"family":"inet","name":"dreamingwrt_aegis_geo"}},'
        '{"set":{"family":"inet","table":"dreamingwrt_aegis_geo","name":"x","elem":[1,2,3]}},'
        '{"rule":{"family":"inet","table":"dreamingwrt_aegis_geo"}}]}')
elif mode == "overflow":
    chunk = b" " * 1048576
    for _ in range(40):
        os.write(sys.stdout.fileno(), chunk)
    time.sleep(5)
elif mode == "timeout":
    sys.stdout.write('{"nftables":[')
    sys.stdout.flush()
    time.sleep(5)
elif mode == "large":
    emit(b'{"nftables":['
        b'{"table":{"family":"inet","name":"dreamingwrt_aegis_geo"}},'
        b'{"set":{"family":"inet","table":"dreamingwrt_aegis_geo",'
        b'"name":"geo_cn_v4","elem":[')
    item = b'{"prefix":{"addr":"2001:db8:1234:5678::","len":64}}'
    batch = b",".join([item] * 4096)
    left = 500000
    first = True
    while left:
        count = min(left, 4096)
        payload = batch if count == 4096 else b",".join([item] * count)
        if not first:
            emit(b",")
        emit(payload)
        first = False
        left -= count
    emit(b']}},'
        b'{"rule":{"family":"inet","table":"dreamingwrt_aegis_geo"}}]}')
    with open(os.environ["PID_FILE"] + ".bytes", "w", encoding="ascii") as fp:
        fp.write(str(written))
elif mode == "close_then_hang":
    emit(b'{"nftables":['
        b'{"table":{"family":"inet","name":"dreamingwrt_aegis_geo"}}]}')
    os.close(sys.stdout.fileno())
    time.sleep(10)
else:
    sys.exit(65)
'''

    with tempfile.TemporaryDirectory(prefix="aegis-geo-capture-") as tmp:
        tmp_path = pathlib.Path(tmp)
        c_file = tmp_path / "capture.c"
        binary = tmp_path / "capture"
        fake = tmp_path / "nft"
        c_file.write_text(harness, encoding="utf-8")
        fake.write_text(fake_nft, encoding="utf-8")
        fake.chmod(0o755)
        subprocess.run(
            ["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", str(c_file), "-o", str(binary)],
            check=True,
        )
        for mode in ("ok", "large", "overflow", "timeout", "close_then_hang"):
            pid_file = tmp_path / f"{mode}.pid"
            env = os.environ.copy()
            env.update(FAKE_NFT=str(fake), FAKE_MODE=mode, PID_FILE=str(pid_file))
            legacy = pathlib.Path(tempfile.gettempdir()) / "aegis-geo-capture-legacy.json"
            legacy.write_text("must be removed", encoding="ascii")
            completed = subprocess.run(
                [str(binary), mode], env=env, check=False, text=True, capture_output=True, timeout=8
            )
            assert completed.returncode == 0, (
                f"{mode} harness failed rc={completed.returncode}: "
                f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
            )
            print(completed.stdout, end="")
            if mode == "large":
                byte_count = int((pathlib.Path(str(pid_file) + ".bytes")).read_text())
                assert byte_count > 16 * 1024 * 1024, byte_count
                print(f"large_bytes={byte_count}\n", end="")
            pid = int(pid_file.read_text(encoding="ascii"))
            for _ in range(20):
                if process_gone(pid):
                    break
                time.sleep(0.01)
            assert process_gone(pid), f"{mode} child {pid} was not reaped"
            assert not legacy.exists(), "legacy full readback file was retained"
    print("ok: Geo nft readback >16 MiB stream, byte limit, timeout, and child cleanup")


if __name__ == "__main__":
    main()
