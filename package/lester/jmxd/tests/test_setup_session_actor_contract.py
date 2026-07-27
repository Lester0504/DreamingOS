#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def between(start: str, end: str) -> str:
    first = API.index(start)
    return API[first:API.index(end, first)]


def function(name: str) -> str:
    start = API.index(name)
    brace = API.index("{", start)
    depth = 0
    for index in range(brace, len(API)):
        if API[index] == "{":
            depth += 1
        elif API[index] == "}":
            depth -= 1
            if depth == 0:
                return API[start:index + 1]
    raise AssertionError(f"unterminated function: {name}")


class SetupSessionActorContract(unittest.TestCase):
    def test_token_is_hashed_ip_bound_and_single_session(self):
        block = between("static int webd_setup_session_clear",
                        "static int webd_user_create")
        for marker in (
            "webd_token_sha256(generated, token_hash)",
            "BEGIN IMMEDIATE",
            "FROM setup_sessions WHERE id=1 AND expires_at>?1",
            "!strcmp(client_ip, stored_ip)",
            "ct_str_equal(supplied_hash, stored_hash)",
            "OPENSSL_cleanse(generated, sizeof(generated))",
            "setup:%.32s",
            "step_rc != SQLITE_DONE",
            "return -1",
        ):
            self.assertIn(marker, block)
        self.assertNotIn("g_webd_setup_session_token", API)
        schema = between('"CREATE TABLE IF NOT EXISTS setup_sessions ("',
                         '"CREATE TABLE IF NOT EXISTS port_view_preferences ("')
        self.assertIn("token_hash TEXT NOT NULL", schema)
        self.assertNotIn(" token TEXT", schema)
        self.assertIn("twofa_secret_hash TEXT NOT NULL", schema)
        self.assertNotIn("twofa_secret TEXT", schema)

    def test_cookie_is_http_only_strict_and_parsed_separately(self):
        self.assertIn('#define WEBD_SETUP_SESSION_COOKIE "dwrt_setup"', API)
        cookie = between("static void webd_setup_session_cookie",
                         "static int webd_user_create")
        self.assertIn("HttpOnly; SameSite=Strict", cookie)
        parser = function("static int parse_http_request")
        self.assertIn("WEBD_SETUP_SESSION_COOKIE", parser)
        self.assertIn("out->setup_session", parser)
        self.assertIn("char setup_session[WEBD_SETUP_SESSION_TOKEN_LEN + 1]", API)

    def test_public_setup_writes_require_the_actor_session(self):
        dispatch = between("int setup_public_write =", "/* ── All remaining routes")
        self.assertIn("webd_setup_session_active()", dispatch)
        self.assertIn("another setup session is already active", dispatch)
        self.assertIn("setup_verify = setup_active >= 0 ? webd_setup_session_verify", dispatch)
        self.assertIn("cross_site_setup_write_rejected", dispatch)
        self.assertIn("webd_setup_session_claim(req.client_ip", dispatch)
        self.assertLess(dispatch.index("webd_setup_session_claim(req.client_ip"),
                        dispatch.index('app_ubus_or_error("setup_start"'))
        self.assertIn("webd_setup_session_clear()", dispatch)
        self.assertIn("setup_active < 0", dispatch)
        self.assertIn('"setup_session_store_unavailable"', dispatch)
        self.assertIn("response_status = 503", dispatch)
        self.assertIn("setup_active < 0 || setup_verify < 0", dispatch)

    def test_setup_writes_run_in_bounded_workers(self):
        child_safe = function("static int app_api_child_safe_route")
        self.assertIn('!strncmp(path, "/api/setup/", 11)', child_safe)
        for route in (
            "/api/v1/auth/pair/cancel",
            "/api/system/dhcp",
            "/api/system/static",
            "/api/system/pppoe",
            "/api/v1/device/config/lan",
        ):
            self.assertIn(f'!strcmp(path, "{route}")', child_safe)

    def test_forwarded_ip_is_accepted_only_from_loopback_proxy(self):
        parser = function("static int parse_http_request")
        self.assertNotIn("parse_forwarded_ip", parser)
        handler = function("static void handle_client")
        self.assertLess(handler.index("fill_peer_ip(fd, &req)"),
                        handler.index("apply_trusted_forwarded_ip(buf, &req)"))
        trusted = function("static void apply_trusted_forwarded_ip")
        self.assertIn("webd_peer_is_loopback(req->client_ip)", trusted)
        forwarded = function(
            "static void parse_forwarded_ip(const char *raw, const char *hdr_end, "
            "char *out, size_t out_len)\n{")
        self.assertIn("inet_pton(AF_INET, candidate", forwarded)
        self.assertIn("inet_pton(AF_INET6, candidate", forwarded)

    def test_setup_oauth_start_and_poll_share_the_same_actor(self):
        dispatch = between("int setup_public_write =", "/* ── All remaining routes")
        self.assertIn('"/api/setup/oauth/start"', dispatch)
        self.assertIn('"/api/setup/oauth/poll"', dispatch)
        self.assertIn("setup_session_ok = webd_setup_session_actor", dispatch)
        self.assertIn("req.setup_session, req.client_ip", dispatch)
        self.assertIn("webd_ai_oauth_start(body_json, setup_actor", dispatch)
        self.assertIn("webd_ai_oauth_poll(body_json, setup_actor", dispatch)
        self.assertNotIn('app_setup_not_implemented_response("setup.oauth.start")',
                         dispatch)

    def test_public_pair_cancel_uses_the_same_setup_session(self):
        cancel = between("/* ── Pair cancel (setup no-auth",
                         "/* ── Login (no auth)")
        self.assertIn("setup_verify = setup_active >= 0 ? webd_setup_session_verify", cancel)
        self.assertIn("setup_session_required", cancel)
        self.assertIn("setup_session_store_unavailable", cancel)
        self.assertIn("setup_active < 0 || setup_verify < 0", cancel)
        self.assertIn("http_send_json(fd, 503", cancel)
        self.assertIn("http_send_json_cookie", cancel)

    def test_setup_twofa_is_bound_to_actor_and_first_admin(self):
        owner = function("static int webd_setup_owner_username")
        self.assertIn("role IN ('owner','admin')", owner)
        self.assertIn("ORDER BY created_at ASC,username ASC LIMIT 1", owner)
        prepare = function("static struct json_object *app_setup_twofa_prepare_response")
        enable = function("static struct json_object *app_setup_twofa_enable_response")
        self.assertIn("webd_twofa_prepare(username)", prepare)
        self.assertIn("webd_setup_twofa_challenge_store", prepare)
        self.assertIn("webd_setup_twofa_challenge_verify", enable)
        self.assertIn("webd_twofa_enable(username, body)", enable)
        self.assertIn("webd_setup_twofa_challenge_clear", enable)
        self.assertNotIn('app_nc_json_str(body, "username"', prepare + enable)
        dispatch = between("int setup_public_write =", "/* ── All remaining routes")
        self.assertIn('"/api/setup/security/2fa/prepare"', dispatch)
        self.assertIn('"/api/setup/security/2fa/enable"', dispatch)

    def test_setup_finish_overrides_actor_and_requires_readback(self):
        finish = function("static struct json_object *app_setup_finish_response")
        for marker in (
            'json_object_object_del(request, "completed_by")',
            'json_object_object_del(request, "actor")',
            'json_object_object_del(request, "version")',
            'json_object_new_string(setup_actor)',
            'app_ubus_or_error("setup_finish", request)',
            'app_ubus_or_error("setup_status", NULL)',
            '"setup_finish_readback_mismatch"',
            '"finish_readback_verified"',
        ):
            self.assertIn(marker, finish)
        dispatch = between("int setup_public_write =", "/* ── All remaining routes")
        self.assertIn("resp = app_setup_finish_response", dispatch)
        self.assertIn("finish_ok", dispatch)
        self.assertIn("webd_setup_session_clear()", dispatch)

    def test_authenticated_finish_uses_authenticated_actor(self):
        dispatch = between("/* ── Authenticated first-run/setup management ──",
                           "/* ── Session ──")
        self.assertIn('"/api/v1/setup/finish"', dispatch)
        self.assertIn('"web:%s"', dispatch)
        self.assertIn('"app:%s"', dispatch)
        self.assertIn("app_setup_finish_response(body_json, finish_actor", dispatch)
        self.assertNotIn('app_ubus_or_error("setup_finish", body_json)', dispatch)


if __name__ == "__main__":
    unittest.main()
