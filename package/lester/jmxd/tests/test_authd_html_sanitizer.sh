#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKAGE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OPENWRT_ROOT=${OPENWRT_ROOT:-$(CDPATH= cd -- "$PACKAGE_ROOT/../../../.." && pwd)}
TARGET_DIR=${TARGET_DIR:-}
TOOLCHAIN_DIR=${TOOLCHAIN_DIR:-}

if [ -z "$TARGET_DIR" ]; then
    for candidate in "$OPENWRT_ROOT"/staging_dir/target-*_glibc; do
        [ -d "$candidate" ] || continue
        [ -z "$TARGET_DIR" ] || {
            echo "multiple glibc target staging directories found; set TARGET_DIR" >&2
            exit 2
        }
        TARGET_DIR=$candidate
    done
fi
if [ -z "$TOOLCHAIN_DIR" ]; then
    for candidate in "$OPENWRT_ROOT"/staging_dir/toolchain-*_glibc; do
        [ -d "$candidate" ] || continue
        [ -z "$TOOLCHAIN_DIR" ] || {
            echo "multiple glibc toolchains found; set TOOLCHAIN_DIR" >&2
            exit 2
        }
        TOOLCHAIN_DIR=$candidate
    done
fi

[ -n "$TARGET_DIR" ] || { echo "glibc target staging directory not found" >&2; exit 2; }
[ -n "$TOOLCHAIN_DIR" ] || { echo "glibc toolchain not found" >&2; exit 2; }
export STAGING_DIR=${STAGING_DIR:-"$OPENWRT_ROOT/staging_dir"}
CC=${CC:-$(find "$TOOLCHAIN_DIR/bin" -maxdepth 1 -name '*-openwrt-linux-gcc' -print -quit)}
[ -x "$CC" ] || { echo "target compiler not found" >&2; exit 2; }

OUTPUT=${OUTPUT:-/tmp/authd_html_sanitize_harness}
ICONV_DIR="$TARGET_DIR/usr/lib/libiconv-full"

"$CC" -Wall -Wextra \
    -I"$PACKAGE_ROOT/src" \
    -I"$TARGET_DIR/usr/include" \
    -I"$TARGET_DIR/usr/include/libxml2" \
    -I"$ICONV_DIR/include" \
    -o "$OUTPUT" \
    "$SCRIPT_DIR/authd_html_sanitize_harness.c" \
    "$PACKAGE_ROOT/src/authd/authd_html.c" \
    -L"$TARGET_DIR/usr/lib" \
    -L"$ICONV_DIR/lib" \
    -Wl,-rpath-link,"$TARGET_DIR/usr/lib" \
    -Wl,-rpath-link,"$ICONV_DIR/lib" \
    -lxml2 -liconv -lm

LD_LIBRARY_PATH="$ICONV_DIR/lib:$TARGET_DIR/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$OUTPUT"
