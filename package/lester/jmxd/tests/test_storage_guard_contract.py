#!/usr/bin/env python3
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = r'''
#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>
#include "jmx_storage_guard.h"

int main(void) {
    struct jmx_storage_guard_state s;
    const unsigned long long gib = 1024ULL * 1024ULL * 1024ULL;

    assert(jmx_storage_guard_evaluate(10 * gib, 4 * gib, &s) ==
           JMX_STORAGE_PRESSURE_OK);
    assert(jmx_storage_guard_evaluate(10 * gib, 1500ULL * 1024ULL * 1024ULL, &s) ==
           JMX_STORAGE_PRESSURE_WARNING);
    assert(jmx_storage_guard_evaluate(10 * gib, 500ULL * 1024ULL * 1024ULL, &s) ==
           JMX_STORAGE_PRESSURE_CRITICAL);
    assert(jmx_storage_guard_evaluate(100 * gib, 400ULL * 1024ULL * 1024ULL, &s) ==
           JMX_STORAGE_PRESSURE_CRITICAL);
    assert(jmx_storage_guard_evaluate(100 * gib, 100ULL * 1024ULL * 1024ULL, &s) ==
           JMX_STORAGE_PRESSURE_CRITICAL);
    assert(jmx_storage_guard_evaluate(gib, 400ULL * 1024ULL * 1024ULL, &s) ==
           JMX_STORAGE_PRESSURE_OK);
    assert(jmx_storage_guard_evaluate(0, 0, &s) ==
           JMX_STORAGE_PRESSURE_UNKNOWN);
    assert(jmx_storage_guard_check("/", &s) == 0);
    assert(s.total_bytes > 0);
    assert(jmx_storage_guard_check("/tmp/dreamingwrt-guard-missing/child", &s) == 0);
    assert(s.total_bytes > 0);
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "guard_test.c"
        exe = Path(tmp) / "guard_test"
        src.write_text(source)
        subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            f"-I{ROOT / 'src'}", str(src),
            str(ROOT / "src/jmx_storage_guard.c"), "-o", str(exe),
        ], check=True)
        subprocess.run([str(exe)], check=True)
    print("ok: shared storage guard thresholds and live statvfs")


if __name__ == "__main__":
    main()
