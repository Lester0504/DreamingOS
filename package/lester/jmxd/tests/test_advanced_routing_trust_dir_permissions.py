#!/usr/bin/env python3
"""Permission tests for the advanced-routing trusted-directory walk.

Regression cover for the P0 in
``Acceptance-to-Backend-core-trust-dir-regression.md``: requiring the full
``NC_ADV_DIR_IS_TRUSTED`` predicate on *every* ancestor made a group-writable
``/etc`` (0775, which is what OpenWrt ships) fail the walk, and because
``jmx_netconfig_db_init()`` refused to start on that failure, every netconfig
read endpoint answered empty.

These cases cannot run against the real ``/``: a build machine has a clean
parent chain and a test cannot chmod ``/etc``. The implementation therefore
exposes ``NC_ADV_TRUST_ROOT``, which production leaves as ``"/"`` and this
harness points at a temporary tree so ancestor permissions are ours to set.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")

# The trust predicates are extracted from the source, never restated here.
# An earlier version of this test defined NC_ADV_DIR_IS_TRUSTED and
# NC_ADV_ANCESTOR_IS_TRUSTED in the harness, which meant reverting the fix in
# the real file left the test green -- it was measuring its own copy. Only
# NC_ADV_TRUSTED_UID is overridden, because the tests run unprivileged and the
# temporary tree is owned by the caller rather than root.
_PRED_START = SOURCE.index("#ifndef NC_ADV_TRUSTED_UID")
_PRED_END = SOURCE.index("#ifndef NC_ADV_FAULT_POINT", _PRED_START)
PREDICATES = SOURCE[_PRED_START:_PRED_END]

_IMPL_START = SOURCE.index("static int nc_adv_open_trusted_dir(const char *path)")
_IMPL_END = SOURCE.index("static int nc_adv_stat_regular_at(", _IMPL_START)
IMPLEMENTATION = SOURCE[_IMPL_START:_IMPL_END]

for _required in ("NC_ADV_DIR_IS_TRUSTED", "NC_ADV_ANCESTOR_IS_TRUSTED"):
    if _required not in PREDICATES:
        raise SystemExit(
            "harness could not find " + _required + " in the source; the "
            "extraction window moved and this test would stop testing anything"
        )

CC = os.environ.get("CC", "cc")

HARNESS_TEMPLATE = """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define NC_ADV_TRUST_ROOT "__TRUST_ROOT__"
#define NC_ADV_TRUSTED_UID ((uid_t)getuid())

__PREDICATES__

__IMPLEMENTATION__

int main(int argc, char **argv)
{
    int fd;
    if (argc < 2)
        return 2;
    fd = nc_adv_open_trusted_dir(argv[1]);
    if (fd < 0) {
        printf("denied\\n");
        return 1;
    }
    close(fd);
    printf("allowed\\n");
    return 0;
}
"""


def c_string(value: Path) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def build_harness(base: Path, trust_root: Path) -> Path:
    harness = base / "trust_harness.c"
    binary = base / "trust_harness"
    source = HARNESS_TEMPLATE.replace("__TRUST_ROOT__", c_string(trust_root))
    source = source.replace("__PREDICATES__", PREDICATES)
    source = source.replace("__IMPLEMENTATION__", IMPLEMENTATION)
    harness.write_text(source, encoding="utf-8")
    subprocess.run(
        [CC, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O1",
         str(harness), "-o", str(binary)],
        check=True,
    )
    return binary


def walk(binary: Path, path: str) -> str:
    result = subprocess.run([str(binary), path], capture_output=True, text=True)
    return result.stdout.strip()


def main() -> None:
    failures = []

    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        trust_root = base / "root"
        # Mirrors /etc/config: the ancestor is the one that goes group-writable.
        etc = trust_root / "etc"
        config = etc / "config"
        config.mkdir(parents=True)
        trust_root.chmod(0o755)
        binary = build_harness(base, trust_root)

        # 1. Clean chain is allowed.
        etc.chmod(0o755)
        config.chmod(0o755)
        if walk(binary, "/etc/config") != "allowed":
            failures.append("clean parent chain should be allowed")

        # 2. The regression itself: a group-writable ancestor must not deny.
        etc.chmod(0o775)
        if walk(binary, "/etc/config") != "allowed":
            failures.append(
                "group-writable ancestor (0775 /etc) must not deny the walk; "
                "this is the P0 that emptied every netconfig reader"
            )

        # 3. World-writable ancestor is tolerated too, because only the final
        #    directory decides. Symlink substitution stays blocked by O_NOFOLLOW.
        etc.chmod(0o777)
        if walk(binary, "/etc/config") != "allowed":
            failures.append("world-writable ancestor must not deny the walk")

        # 4. Strictness on the TARGET must survive. The handoff explicitly
        #    forbids weakening this half while fixing the ancestor half.
        etc.chmod(0o755)
        config.chmod(0o775)
        if walk(binary, "/etc/config") != "denied":
            failures.append("group-writable TARGET must still be denied")

        config.chmod(0o777)
        if walk(binary, "/etc/config") != "denied":
            failures.append("world-writable TARGET must still be denied")

        config.chmod(0o755)

        # 5. Traversal hygiene: relative paths, dot segments, symlinked targets.
        if walk(binary, "etc/config") != "denied":
            failures.append("relative path must be denied")
        if walk(binary, "/etc/../etc/config") != "denied":
            failures.append("dot-dot segment must be denied")

        link = etc / "linked"
        link.symlink_to(config)
        if walk(binary, "/etc/linked") != "denied":
            failures.append("symlinked final component must be denied (O_NOFOLLOW)")

        if walk(binary, "/etc/does_not_exist") != "denied":
            failures.append("missing directory must be denied")

    if failures:
        for item in failures:
            print("FAIL: " + item)
        raise SystemExit(1)
    print("advanced-routing trusted-directory permission contract: PASS")


if __name__ == "__main__":
    main()
