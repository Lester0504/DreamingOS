#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (ROOT / "src/webd/ai_runtime.c").read_text()
API = (ROOT / "src/webd/jmx_app_api.c").read_text()
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text()
MAKEFILE = (ROOT / "src/Makefile").read_text()


class AiOauthRuntimeContract(unittest.TestCase):
    def test_webd_routes_and_link_target_are_registered(self):
        self.assertIn("webd/ai_oauth.o", MAKEFILE)
        for route in ("providers", "status", "start", "poll", "refresh", "disconnect"):
            self.assertIn(f'"/api/v1/ai/oauth/{route}"', API)
        self.assertIn('!strncmp(path, "/api/v1/ai/oauth/", 17)', API)
        self.assertIn('{ "/api/v1/ai/oauth/refresh",   "POST", JMX_RISK_MEDIUM }', PERMS)
        self.assertIn('json_object_object_add(data, "oauth", oauth)', RUNTIME)
        self.assertIn('"refresh_endpoint"', RUNTIME)
        self.assertIn('"/api/v1/ai/oauth/refresh"', RUNTIME)
        self.assertIn('resp = webd_ai_oauth_start(body_json, device_id, &status)', API)

    def test_runtime_uses_oauth_token_without_exposing_refresh_token(self):
        self.assertIn('snprintf(cfg->auth_mode', RUNTIME)
        self.assertIn('webd_ai_oauth_access_token(cfg->provider', RUNTIME)
        self.assertIn('"Authorization: Bearer %s" : "x-api-key: %s"', RUNTIME)
        self.assertNotIn('refresh_token', RUNTIME[RUNTIME.index("static int ai_config_load"):RUNTIME.index("static int ai_url_ok")])

    def test_gemini_has_native_rest_stream_and_auth_shapes(self):
        for marker in (
            "generateContent",
            "streamGenerateContent?alt=sse",
            '"systemInstruction"',
            '"generationConfig"',
            '"functionDeclarations"',
            '"functionCall"',
            '"functionResponse"',
            '"x-goog-user-project: %s"',
            '"x-goog-api-key: %s"',
            'ai_is_gemini(&cfg) ||',
            '?\n                                      "models" : "data"',
        ):
            self.assertIn(marker, RUNTIME)

    def test_kimi_code_is_openai_compatible_with_official_base(self):
        self.assertIn('"https://api.kimi.com/coding/v1"', RUNTIME)
        self.assertIn('!strcasecmp(cfg->provider, "kimi")', RUNTIME)
        self.assertIn('"/chat/completions"', RUNTIME)

    def test_openai_oauth_and_api_key_are_distinct_upstreams(self):
        self.assertIn('#define AI_OPENAI_CHATGPT_BASE "https://chatgpt.com/backend-api/codex"', RUNTIME)
        self.assertIn('!strcasecmp(cfg->provider, "openai") &&', RUNTIME)
        self.assertIn('!strcmp(cfg->auth_mode, "oauth")', RUNTIME)
        self.assertIn('base = AI_OPENAI_CHATGPT_BASE', RUNTIME)
        self.assertIn('base = "https://api.openai.com/v1"', RUNTIME)
        self.assertIn('ai_is_openai_chatgpt_oauth(cfg) ||', RUNTIME)

    def test_openai_oauth_runtime_uses_codex_headers_and_body(self):
        for marker in (
            '"OpenAI-Beta: responses=experimental"',
            '"Originator: " AI_OPENAI_CODEX_ORIGINATOR',
            '"chatgpt-account-id: %s"',
            'AI_OPENAI_CODEX_USER_AGENT',
            'json_object_new_boolean(0)',
            'json_object_new_boolean(1)',
            'ai_openai_codex_input(',
            'ai_sse_capture_write',
            '"%s/models?client_version=0.144.1"',
            'ai_is_openai_chatgpt_oauth(&cfg) ? "slug" : "id"',
        ):
            self.assertIn(marker, RUNTIME)
        oauth_input = RUNTIME[RUNTIME.index("static struct json_object *ai_openai_codex_input"):RUNTIME.index("static struct json_object *ai_core_data")]
        self.assertIn('"instructions"', RUNTIME)
        self.assertIn('if (!role[0])', oauth_input)
        self.assertIn('json_object_array_add(input, json_object_get(item))', oauth_input)
        self.assertIn('function_call/function_call_output', oauth_input)
        self.assertNotIn('access_token', oauth_input)
        self.assertNotIn('refresh_token', RUNTIME[RUNTIME.index("static int ai_config_load"):RUNTIME.index("static int ai_url_ok")])


if __name__ == "__main__":
    unittest.main()
