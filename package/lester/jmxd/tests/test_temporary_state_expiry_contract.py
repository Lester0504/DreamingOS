#!/usr/bin/env python3
"""
Contract tests for temporary state expiry cleanup (Acceptance-to-Backend-P2-temporary-state-expiry-cleanup.md).

Verifies that:
1. Gateway Shadow pairing uses rejection sampling for random code
2. Gateway Shadow pairing cleans up expired pending sessions
3. AI OAuth status checks expires_at for pending state
4. AI OAuth poll deletes expired pending file
5. Setup session has absolute max lifetime
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GS = (ROOT / "src/jmx_gateway_shadow_pairing.c").read_text(encoding="utf-8")
OAUTH = (ROOT / "src/webd/ai_oauth.c").read_text(encoding="utf-8")

import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
WEB = webd_dispatch_text()


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


# ---- Gateway Shadow pairing ----
gs_start = between(GS, "static struct json_object *gs_start_new", "static struct json_object *gs_finalize")
assert "4200000000U" in gs_start or "4000000000U" in gs_start, \
    "must use rejection sampling threshold"
assert "random_code >= 4200000000U" in gs_start or "random_code >= 4000000000U" in gs_start, \
    "must reject values above threshold"
assert "RAND_bytes" in gs_start, \
    "must re-seed on rejection"
assert "gs_load_session" in gs_start, \
    "must load existing session before creating new one"
assert "old_session.expires_at < gs_now()" in gs_start, \
    "must check if existing session is expired"
assert "unlink" in gs_start, \
    "must unlink old code file on expiry"

# ---- AI OAuth status ----
oauth_status = between(OAUTH, "struct json_object *webd_ai_oauth_status", "struct json_object *webd_ai_oauth_start")
assert "pending_expires" in oauth_status, \
    "must check pending expiry in status"
assert "now_seconds()" in oauth_status, \
    "must compare against current time"
assert "pending_state" in oauth_status, \
    "must report pending_state for expired"
assert "expired" in oauth_status, \
    "must return expired state"
assert "unlink" in oauth_status, \
    "must delete expired pending file"

# ---- AI OAuth poll ----
oauth_poll = between(OAUTH, "struct json_object *webd_ai_oauth_poll", "struct json_object *webd_ai_oauth_disconnect")
assert "expires_at" in oauth_poll, \
    "must check expires_at in poll"
assert "expired_token" in oauth_poll, \
    "must return expired_token error"
assert "unlink" in oauth_poll, \
    "must delete pending file on expiry"

# ---- Setup session absolute max ----
assert "WEBD_SETUP_ABSOLUTE_MAX_S" in WEB, \
    "must define WEBD_SETUP_ABSOLUTE_MAX_S"
assert "7200" in WEB, \
    "absolute max must be 2 hours (7200 seconds)"
setup_verify = between(WEB, "static int webd_setup_session_verify", "static int webd_setup_session_actor")
assert "created_at" in setup_verify, \
    "must select created_at from setup_sessions"
assert "WEBD_SETUP_ABSOLUTE_MAX_S" in setup_verify, \
    "must check absolute max in verify"
assert "webd_setup_session_clear()" in setup_verify, \
    "must clear session when absolute max exceeded"

print("ok: temporary state expiry cleanup contract tests passed")
