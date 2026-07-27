#!/usr/bin/env python3
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/webd/ai_oauth.c").read_text()
HEADER = (ROOT / "src/webd/ai_oauth.h").read_text()
LIVE = (ROOT / "tests/test_ai_openai_oauth_live.c").read_text()


class AiOauthContract(unittest.TestCase):
    def test_catalog_covers_all_requested_providers_without_false_support(self):
        for provider in ("gemini", "kimi", "anthropic", "openai", "grok", "antigravity"):
            self.assertRegex(SOURCE, rf'\{{\s*"{provider}"')
        self.assertIn('{ "gemini", 1,', SOURCE)
        self.assertIn('{ "kimi", 1,', SOURCE)
        self.assertIn('{ "anthropic", 1,', SOURCE)
        for provider in ("grok", "antigravity"):
            self.assertIn(f'{{ "{provider}", 0,', SOURCE)
        self.assertIn('{ "openai", 1, "chatgpt_authorization_code_pkce_s256"', SOURCE)
        self.assertIn('"enterprise_wif"', SOURCE)
        self.assertNotIn('no_public_third_party_oauth_for_openai_model_api', SOURCE)
        self.assertIn('no_public_third_party_oauth_for_xai_model_api', SOURCE)
        self.assertIn('not_independent_model_api', SOURCE)

    def test_official_gemini_and_kimi_metadata(self):
        for endpoint in (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/device/code",
            "https://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com/revoke",
            "https://generativelanguage.googleapis.com/v1",
            "https://auth.kimi.com/api/oauth/device_authorization",
            "https://auth.kimi.com/api/oauth/token",
            "https://api.kimi.com/coding/v1",
            "17e5f671-d194-4dfb-9706-5516cb48c098",
        ):
            self.assertIn(endpoint, SOURCE)
        self.assertIn("https://www.googleapis.com/auth/cloud-platform", SOURCE)
        self.assertIn('"pkce_s256"', SOURCE)
        self.assertIn('"device_flow_supported"', SOURCE)

    def test_openai_chatgpt_oauth_matches_sub2api_codex_contract(self):
        for marker in (
            '"app_EMoamEEZ73f0CkXaXp7hrann"',
            '"https://auth.openai.com/oauth/authorize"',
            '"https://auth.openai.com/oauth/token"',
            '"http://localhost:1455/auth/callback"',
            '"openid profile email offline_access"',
            '"openid profile email"',
            '"https://chatgpt.com/backend-api/codex"',
            'id_token_add_organizations=true',
            'codex_cli_simplified_flow=true',
            'code_challenge_method=S256',
            'OPENAI_OAUTH_USER_AGENT "codex-cli/0.91.0"',
        ):
            self.assertIn(marker, SOURCE)
        self.assertIn('verifier = random_hex(64)', SOURCE)
        self.assertIn('state = random_hex(32)', SOURCE)
        self.assertIn('openai_code_exchange(', SOURCE)
        self.assertIn('openai_refresh_exchange(', SOURCE)
        self.assertIn('"manual_callback_url_to_poll"', SOURCE)
        self.assertIn('"callback_url_parse_required"', SOURCE)
        self.assertIn('"custom_redirect_uri_supported"', SOURCE)
        self.assertIn('secure_equal(redirect_uri, OPENAI_REDIRECT_URI)', SOURCE)
        self.assertIn('openai_callback_url_parse(', SOURCE)
        self.assertIn('CURLUPART_QUERY', SOURCE)
        self.assertIn('curl_easy_unescape', SOURCE)
        self.assertIn('"invalid_oauth_callback"', SOURCE)

    def test_openai_callback_is_actor_bound_state_checked_and_one_time(self):
        poll = SOURCE[SOURCE.index("struct json_object *webd_ai_oauth_poll"):SOURCE.index("struct json_object *webd_ai_oauth_refresh")]
        self.assertIn('secure_equal(json_string(pending, "actor"), actor)', poll)
        self.assertIn('secure_equal(returned_state, expected_state)', poll)
        self.assertIn('state_path(inflight_path, sizeof(inflight_path), provider, "in-flight")', poll)
        self.assertIn('rename(pending_path, inflight_path)', poll)
        self.assertIn('"oauth_callback_already_claimed"', poll)
        self.assertIn('unlink(inflight_path)', poll)
        disconnect = SOURCE[SOURCE.index("struct json_object *webd_ai_oauth_disconnect"):SOURCE.index("int webd_ai_oauth_access_token")]
        self.assertIn('provider, "in-flight"', disconnect)
        self.assertIn('removed != 3', disconnect)

    def test_openai_account_routing_is_internal_and_never_returned(self):
        self.assertIn('"https://api.openai.com/auth"', SOURCE)
        self.assertIn('"chatgpt_account_id"', SOURCE)
        self.assertIn('json_string(state, "chatgpt_account_id")', SOURCE)
        poll = SOURCE[SOURCE.index("struct json_object *webd_ai_oauth_poll"):SOURCE.index("struct json_object *webd_ai_oauth_refresh")]
        self.assertNotIn('json_object_object_add(out, "access_token"', poll)
        self.assertNotIn('json_object_object_add(out, "refresh_token"', poll)
        self.assertNotIn('json_object_object_add(out, "chatgpt_account_id"', poll)

    def test_tokens_and_pending_state_are_authenticated_encrypted(self):
        self.assertIn('"/etc/dreamingwrt/ai-oauth"', HEADER)
        self.assertIn("EVP_aes_256_gcm()", SOURCE)
        self.assertIn("EVP_CTRL_GCM_GET_TAG", SOURCE)
        self.assertIn("EVP_CTRL_GCM_SET_TAG", SOURCE)
        self.assertIn('snprintf(aad, sizeof(aad), "%s:%s", provider, kind)', SOURCE)
        self.assertIn('encrypted_save(provider, "token"', SOURCE)
        self.assertIn('encrypted_save(provider, "pending"', SOURCE)
        self.assertNotIn("plaintext_fallback", SOURCE)

    def test_root_only_storage_and_atomic_write(self):
        self.assertIn("chmod(WEBD_AI_OAUTH_STATE_DIR, 0700)", SOURCE)
        self.assertIn("fchmod(fd, 0600)", SOURCE)
        self.assertIn("st.st_uid != 0", SOURCE)
        self.assertIn("O_NOFOLLOW", SOURCE)
        self.assertIn("rename(tmp, path)", SOURCE)
        self.assertNotIn('chmod("/etc/dreamingwrt", 0700)', SOURCE)
        self.assertIn('CURLOPT_PROTOCOLS_STR, "https"', SOURCE)
        self.assertIn("#ifndef WEBD_AI_OAUTH_STATE_DIR", HEADER)

    def test_openai_live_harness_covers_real_start_state_and_cleanup(self):
        for marker in (
            "webd_ai_oauth_catalog()",
            "webd_ai_oauth_start(request, \"contract-admin\"",
            "pending_file_is_encrypted()",
            "webd_ai_oauth_status(\"openai\"",
            "oauth_actor_mismatch",
            "oauth_state_mismatch",
            "webd_ai_oauth_disconnect(\"openai\"",
            "response_has_secret",
        ):
            self.assertIn(marker, LIVE)

    def test_webd_surface_is_complete_and_does_not_return_secrets(self):
        for name in ("catalog", "status", "start", "poll", "refresh", "disconnect", "access_token"):
            self.assertIn(f"webd_ai_oauth_{name}", HEADER)
            self.assertIn(f"webd_ai_oauth_{name}", SOURCE)
        start = SOURCE[SOURCE.index("struct json_object *webd_ai_oauth_start"):SOURCE.index("struct json_object *webd_ai_oauth_poll")]
        poll = SOURCE[SOURCE.index("struct json_object *webd_ai_oauth_poll"):SOURCE.index("struct json_object *webd_ai_oauth_refresh")]
        self.assertIn('json_object_object_del(response, "device_code")', start)
        self.assertNotIn('json_object_object_add(out, "access_token"', poll)
        self.assertNotIn('json_object_object_add(out, "refresh_token"', poll)

    def test_device_poll_and_refresh_grants_are_implemented(self):
        self.assertIn('urn:ietf:params:oauth:grant-type:device_code', SOURCE)
        self.assertIn('"refresh_token"', SOURCE)
        self.assertIn('"authorization_pending"', SOURCE)
        self.assertIn('"slow_down"', SOURCE)
        self.assertIn('"poll_too_fast"', SOURCE)

    def test_gemini_authorization_code_uses_pkce_and_state(self):
        self.assertIn('"authorization_code_pkce_s256"', SOURCE)
        self.assertIn('code_challenge_method=S256', SOURCE)
        self.assertIn('gemini_code_exchange(', SOURCE)
        self.assertIn('secure_equal(returned_state, expected_state)', SOURCE)
        self.assertIn('"code_verifier"', SOURCE)

    def test_anthropic_wif_uses_official_jwt_bearer_exchange(self):
        self.assertIn('urn:ietf:params:oauth:grant-type:jwt-bearer', SOURCE)
        for field in ("assertion", "federation_rule_id", "organization_id",
                      "service_account_id", "workspace_id"):
            self.assertIn(f'"{field}"', SOURCE)
        self.assertIn('"https://api.anthropic.com/v1/oauth/token"', SOURCE)
        self.assertIn('"/etc/dreamingwrt/credentials/"', SOURCE)
        self.assertIn('O_NOFOLLOW', SOURCE)
        self.assertIn('st.st_uid != 0', SOURCE)


if __name__ == "__main__":
    unittest.main()
