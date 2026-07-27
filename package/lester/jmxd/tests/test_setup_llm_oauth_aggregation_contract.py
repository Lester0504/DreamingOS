#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")
OAUTH = (ROOT / "src/webd/ai_oauth.c").read_text(encoding="utf-8")
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def function(source: str, name: str, next_marker: str) -> str:
    start = source.index(name)
    end = source.index(next_marker, start)
    return source[start:end]


def provider_contract(source: str, start: str, end: str):
    block = source[source.index(start):source.index(end, source.index(start))]
    pattern = re.compile(r'\{\s*"([^"]+)",\s*([01]),\s*"([^"]+)"')
    return [(provider, int(supported), mode)
            for provider, supported, mode in pattern.findall(block)]


class SetupLlmOauthAggregationContract(unittest.TestCase):
    def test_setup_oauth_catalog_matches_webd_catalog_capability(self):
        setup = provider_contract(
            SETUP, "nc_setup_oauth_providers[]", "struct nc_setup_oauth_credential")
        webd = provider_contract(
            OAUTH, "static const struct oauth_provider providers[]", "struct http_buffer")
        self.assertEqual(setup, webd)
        self.assertEqual(
            setup,
            [
                ("gemini", 1, "authorization_code_pkce_s256"),
                ("kimi", 1, "device_oauth"),
                ("anthropic", 1, "enterprise_wif"),
                ("openai", 1, "chatgpt_authorization_code_pkce_s256"),
                ("grok", 0, "api_key_only"),
                ("antigravity", 0, "not_independent_model_api"),
            ],
        )

    def test_runtime_and_provider_availability_come_from_real_state(self):
        llm = function(
            SETUP, "static struct json_object *nc_setup_llm_json(void)",
            "static struct json_object *nc_setup_app_pairing_json")
        self.assertIn(
            'nc_setup_proc_executable_running("dreamingwrt-webd")', llm)
        self.assertIn(
            "nc_setup_unix_listener_active(NC_SETUP_AI_RUNTIME_SOCKET)", llm)
        self.assertIn(
            "int runtime_available = webd_available", llm)
        self.assertIn(
            "int local_rpc_available = webd_available &&", llm)
        self.assertIn(
            "provider_available = runtime_available && configured", llm)
        self.assertIn('"provider_reachable", json_object_new_null()', llm)
        self.assertIn('"provider_test_required"', llm)
        self.assertNotIn("provider_integration_pending", llm)
        self.assertNotIn(
            '"runtime_available", json_object_new_boolean(0)', llm)
        self.assertNotIn(
            '"provider_available", json_object_new_boolean(0)', llm)
        self.assertNotIn("nc_setup_cmd_success(", llm)

    def test_api_key_and_oauth_configuration_are_evaluated_separately(self):
        llm = function(
            SETUP, "static struct json_object *nc_setup_llm_json(void)",
            "static struct json_object *nc_setup_app_pairing_json")
        for marker in (
            'auth_mode_supported = !strcmp(auth_mode, "api_key") ||',
            '!strcmp(auth_mode, "oauth")',
            "credential_configured = oauth_credential.connected",
            "credential_configured = api_key_set",
            "if (nc_setup_oauth_provider_find(provider))",
            "nc_setup_oauth_catalog_json(webd_available, provider,",
            'blocked_reason = "auth_mode_unsupported"',
            '"local_rpc_available"',
            '"ai_runtime_socket_unavailable"',
        ):
            self.assertIn(marker, llm)
        self.assertIn("enabled && provider_supported &&", llm)
        self.assertIn("auth_mode_supported && model[0] && credential_configured", llm)

    def test_oauth_connected_requires_authenticated_root_only_state(self):
        token = function(
            SETUP, "static struct json_object *nc_setup_oauth_token_load",
            "static void nc_setup_oauth_credential_status")
        for marker in (
            "O_NOFOLLOW",
            "nc_setup_root_private_dir_ok(NC_SETUP_AI_OAUTH_DIR)",
            "fstat(fd, &st)",
            "st.st_uid != 0",
            "(st.st_mode & 077) != 0",
            "EVP_aes_256_gcm()",
            "EVP_CTRL_GCM_SET_TAG",
            "EVP_DecryptFinal_ex",
            'nc_json_str_def(token, "access_token", "")',
            '"oauth_state_authentication_failed"',
        ):
            self.assertIn(marker, token)
        status = function(
            SETUP, "static void nc_setup_oauth_credential_status",
            "static struct json_object *nc_setup_oauth_catalog_json")
        self.assertIn("nc_setup_oauth_provider_find(provider)", status)
        self.assertIn("!catalog_provider->supported", status)
        self.assertIn("status->connected = 1", status)
        self.assertIn("status->expired =", status)
        self.assertNotIn('json_object_object_add(', token)

    def test_catalog_implementation_and_service_availability_are_distinct(self):
        catalog = function(
            SETUP, "static struct json_object *nc_setup_oauth_catalog_json",
            "static struct json_object *nc_setup_llm_json")
        self.assertIn('"implemented", json_object_new_boolean(1)', catalog)
        self.assertIn('"available",', catalog)
        self.assertIn("json_object_new_boolean(service_available)", catalog)
        self.assertIn('"dreamingwrt_webd_not_running"', catalog)
        for endpoint in (
            "/api/v1/ai/oauth/providers",
            "/api/v1/setup/oauth/providers",
            "/api/v1/ai/oauth/status",
            "/api/v1/setup/oauth/start",
            "/api/v1/ai/oauth/poll",
            "/api/v1/ai/oauth/refresh",
            "/api/v1/ai/oauth/disconnect",
        ):
            self.assertIn(endpoint, catalog)

    def test_assist_mode_reuses_the_same_aggregation(self):
        assist = SETUP[SETUP.index("struct json_object *jmx_setup_assist_mode") :]
        self.assertIn("llm = nc_setup_llm_json()", assist)
        self.assertIn('nc_json_bool_def(llm, "configured", 0)', assist)
        self.assertIn('nc_json_bool_def(llm, "provider_available", 0)', assist)
        self.assertIn('nc_json_bool_def(llm, "runtime_available", 0)', assist)
        self.assertNotIn("provider_integration_pending", assist)

    def test_setup_rest_routes_keep_webd_oauth_as_the_action_authority(self):
        self.assertIn(
            '"/api/v1/setup/llm/status") && !strcmp(req.method, "GET")', API)
        self.assertIn('app_setup_status_slice_response("llm")', API)
        self.assertIn(
            '"/api/v1/setup/oauth/providers") && !strcmp(req.method, "GET")', API)
        self.assertIn("webd_ai_oauth_catalog()", API)
        self.assertIn(
            '"/api/v1/setup/oauth/start") && !strcmp(req.method, "POST")', API)
        self.assertIn("webd_ai_oauth_start(body_json, device_id, &status)", API)


if __name__ == "__main__":
    unittest.main()
