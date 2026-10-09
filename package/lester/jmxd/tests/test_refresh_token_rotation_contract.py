#!/usr/bin/env python3
"""
Contract tests for refresh token rotation (Acceptance-to-Backend-P1-refresh-token-rotation-and-session-gc.md).

Verifies that:
1. auth_tokens schema has refresh_consumed_at and replaced_by columns
2. App refresh path does atomic consume+replace
3. Web refresh path uses webd_session_idle_refresh_rotate
4. Reuse detection revokes entire device family
5. GC function exists in webd_session_idle
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text

WEB = webd_dispatch_text()
IDLE_C = (ROOT / "src/webd/webd_session_idle.c").read_text(encoding="utf-8")
IDLE_H = (ROOT / "src/webd/webd_session_idle.h").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


# ---- Schema migration ----
assert "refresh_consumed_at INTEGER NOT NULL DEFAULT 0" in WEB, \
    "auth_tokens must have refresh_consumed_at column"
assert "replaced_by TEXT NOT NULL DEFAULT ''" in WEB, \
    "auth_tokens must have replaced_by column"
assert 'app_db_add_column_if_missing(\n            "auth_tokens", "refresh_consumed_at"' in WEB, \
    "schema migration must add refresh_consumed_at"
assert 'app_db_add_column_if_missing(\n            "auth_tokens", "replaced_by"' in WEB, \
    "schema migration must add replaced_by"

# ---- App refresh rotation ----
app_refresh = between(WEB, "static struct json_object *jmx_app_refresh_ex",
                       "struct json_object *jmx_app_refresh(struct")
assert "BEGIN IMMEDIATE" in app_refresh, \
    "app refresh must use BEGIN IMMEDIATE for atomic rotation"
assert "refresh_consumed_at>0" in app_refresh, \
    "reuse detection must check refresh_consumed_at"
assert "refresh_token_reused" in app_refresh, \
    "reuse must return refresh_token_reused error"
assert "replaced_by" in app_refresh, \
    "consumed token must record replaced_by"
assert "revoked=1, refresh_consumed_at=?2, replaced_by=?3" in app_refresh, \
    "old refresh must be marked consumed with replaced_by"
assert 'json_object_object_add(resp, "refresh_token"' in app_refresh, \
    "app refresh must return new refresh_token"
assert 'json_object_object_add(resp, "refresh_expires_at"' in app_refresh, \
    "app refresh must return refresh_expires_at"
assert "OPENSSL_cleanse(new_refresh_tok" in app_refresh, \
    "new refresh token must be cleansed after use"

# ---- Web refresh rotation ----
web_refresh = between(WEB, "idle_rc = webd_session_idle_refresh_rotate",
                       "OPENSSL_cleanse(new_refresh_tok")
assert "webd_session_idle_refresh_rotate" in web_refresh, \
    "web refresh must use webd_session_idle_refresh_rotate"
assert "new_refresh_tok" in web_refresh, \
    "web refresh must generate new refresh token"
assert 'json_object_object_add(web, "refresh_token"' in web_refresh, \
    "web refresh must return new refresh_token"
assert 'json_object_object_add(web, "refresh_expires_at"' in web_refresh, \
    "web refresh must return refresh_expires_at"

# ---- webd_session_idle module ----
assert "webd_session_idle_refresh_rotate" in IDLE_H, \
    "header must export webd_session_idle_refresh_rotate"
assert "webd_session_idle_gc" in IDLE_H, \
    "header must export webd_session_idle_gc"
assert "WEBD_SESSION_IDLE_REUSED" in IDLE_H or "refresh_token_reused" in IDLE_C, \
    "must have reuse detection"
assert "webd_session_idle_refresh_rotate" in IDLE_C, \
    "implementation must have webd_session_idle_refresh_rotate"
assert "BEGIN IMMEDIATE" in IDLE_C, \
    "refresh rotation must use BEGIN IMMEDIATE"
assert "revoked<>0" in IDLE_C or "revoked=1" in IDLE_C, \
    "reuse detection must check revoked state"
assert "webd_session_idle_gc" in IDLE_C, \
    "implementation must have GC function"
assert "expires_at<=?" in IDLE_C or "expires_at<=?1" in IDLE_C, \
    "GC must filter on expires_at"

print("ok: refresh token rotation contract tests passed")
