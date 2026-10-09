#!/bin/sh
# Local integration helpers only. All output is outside the source tree.
set -eu
SRC=$(CDPATH= cd -- "$(dirname "$0")/../src" && pwd)
TESTS=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
OUT=${1:?Usage: build_community_test.sh /tmp/task-output}
case "$OUT" in /tmp/*) ;; *) exit 2;; esac
mkdir -p "$OUT"
python3 - "$SRC" "$OUT" <<'PY'
from pathlib import Path
import sys
src,out=map(Path,sys.argv[1:]);s=(src/'webd/api/api_realtime.c').read_text()
framing=s[s.index('static int webd_read_exact('):s.index('static int webd_ws_topics_any(')]
preamble='#include <unistd.h>\n#include <errno.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <openssl/evp.h>\n#include <json-c/json.h>\n#include "api_util.h"\n#define WEBD_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"\n#define WEBD_WS_MAX_PAYLOAD 8192\n'
(out/'framing.c').write_text(preamble+framing)
PY
FLAGS="$(pkg-config --cflags json-c sqlite3 openssl libcurl)"
LIBS="$(pkg-config --libs json-c sqlite3 openssl libcurl)"
cc -DSUPPORT_TEST -DCOMMUNITY_TEST -std=c11 $FLAGS "$TESTS/test_community_cli.c" "$SRC/webd/webd_community.c" "$SRC/webd/webd_support.c" $LIBS -o "$OUT/community-cli"
cc -DSUPPORT_TEST -std=c11 $FLAGS "$TESTS/test_support_cli.c" "$SRC/webd/webd_support.c" $LIBS -o "$OUT/support-cli"
cc -DSUPPORT_TEST -std=c11 -DCOMMUNITY_STATE_DIR="\"$OUT\"" -DSUPPORT_IDENTITY_DIR="\"$OUT\"" $FLAGS -I"$SRC/webd/api" "$TESTS/test_community_ws.c" "$SRC/webd/webd_community.c" "$SRC/webd/webd_support.c" "$SRC/webd/webd_http.c" "$SRC/webd/api/api_util.c" "$SRC/webd/api/api_request.c" "$OUT/framing.c" $LIBS -lz -o "$OUT/community-ws"
