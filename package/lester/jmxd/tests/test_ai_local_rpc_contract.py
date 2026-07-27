#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = (ROOT / "src/ai_local_rpc_protocol.h").read_text()
SERVER = (ROOT / "src/webd/ai_local_rpc.c").read_text()
API = (ROOT / "src/webd/jmx_app_api.c").read_text()
CLI = (ROOT / "src/ctl/jmctl.c").read_text()
MAKEFILE = (ROOT / "src/Makefile").read_text()


class AiLocalRpcContract(unittest.TestCase):
    def test_socket_is_root_only_and_peer_credentials_are_checked(self):
        self.assertIn('"/var/run/dreamingwrt-ai.sock"', PROTOCOL)
        self.assertIn("chmod(DREAMINGWRT_AI_LOCAL_SOCKET, 0600)", SERVER)
        self.assertIn("SO_PEERCRED", SERVER)
        self.assertRegex(SERVER, r"peer->uid\s*!=\s*0")

    def test_cli_does_not_call_core_ai_chat_or_read_api_key(self):
        llm = CLI[CLI.index("static int cmd_llm"):CLI.index("static int split_args")]
        self.assertNotIn('"ai_chat"', llm)
        self.assertNotIn('json_get_string_def(cfg_data, "api_key"', llm)
        self.assertNotIn('json_get_string_def(cfg_data, "access_token"', llm)
        self.assertNotIn('json_get_string_def(cfg_data, "refresh_token"', llm)
        self.assertIn("jmctl_ai_local_invoke(opts, req)", llm)

    def test_server_owns_provider_runtime_and_actor_identity(self):
        self.assertIn("webd_ai_runtime_chat(request, actor, &http_status)", SERVER)
        self.assertIn('"jmctl:uid=%lu:pid=%ld"', SERVER)
        for untrusted in ('"actor"', '"role"', '"provider"'):
            self.assertIn(f"json_object_object_del(request, {untrusted})", SERVER)

    def test_requests_are_framed_and_bounded(self):
        self.assertRegex(PROTOCOL, r"REQUEST_MAX\s+\(128U \* 1024U\)")
        self.assertRegex(PROTOCOL, r"RESPONSE_MAX\s+\(1024U \* 1024U\)")
        self.assertGreaterEqual(SERVER.count("ntohl("), 1)
        self.assertGreaterEqual(SERVER.count("htonl("), 1)
        self.assertGreaterEqual(CLI.count("ntohl("), 1)
        self.assertGreaterEqual(CLI.count("htonl("), 1)

    def test_webd_lifecycle_registers_and_removes_socket(self):
        self.assertIn("webd_ai_local_rpc_init(&ai_local_hooks)", API)
        self.assertIn("webd_ai_local_rpc_done()", API)
        self.assertIn("webd_child_track(pid, 0)", API)
        self.assertIn("webd/ai_local_rpc.o", MAKEFILE)

    def test_cli_default_timeout_covers_provider_and_tool_rounds(self):
        match = re.search(r"DEFAULT_TIMEOUT_MS\s+(\d+)", PROTOCOL)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(int(match.group(1)), 180000)
        self.assertIn("opts->timeout_set", CLI)

    def test_cli_accepts_oauth_without_reading_tokens(self):
        llm = CLI[CLI.index("static int cmd_llm"):CLI.index("static int split_args")]
        self.assertIn('json_get_string_def(cfg_data, "auth_mode", "api_key")', llm)
        self.assertIn('strcmp(auth_mode, "oauth")', llm)
        self.assertNotIn('"access_token"', llm)
        self.assertNotIn('"refresh_token"', llm)


if __name__ == "__main__":
    unittest.main()
