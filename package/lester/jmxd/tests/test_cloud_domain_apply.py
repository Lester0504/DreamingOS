#!/usr/bin/env python3
"""Real UCI + filesystem transaction, only private paths and a reload callback."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_cloud_router_id_runtime import probe_flags

ROOT = Path(__file__).resolve().parents[1]


class DomainApply(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="domain-apply-build-")
        cls.binary = Path(cls.build.name) / "apply"
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-D_GNU_SOURCE",
                        "-Wall", "-Wextra", "-Werror",
                        str(ROOT / "tests/cloud_domain_apply_fixture.c"),
                        str(ROOT / "src/webd/api/api_cloud_domain.c"),
                        "-o", str(cls.binary), *probe_flags(), "-Wl,--disable-new-dtags"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="domain-apply-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = self.base / "config"
        self.config.mkdir()
        self.hosts = self.base / "hosts"
        self.hosts.write_text("127.0.0.1 localhost\n192.168.1.20 private.home\n")
        (self.config / "system").write_text("config system\n option console_domain 'box.dev.example'\n")
        (self.config / "network").write_text("config interface 'lan'\n option ipaddr '192.168.1.3'\n list ip6addr 'fd00::3/64'\n")
        (self.config / "relay").write_text("config relay 'cert'\n option enabled '0'\n")
        (self.config / "dhcp").write_text("config dnsmasq 'main'\n list address '/untouched.example/192.168.2.1'\n list addnhosts '/etc/custom.hosts'\n")

    def run_case(self, action="apply", mode="gateway", reload="ok", rp="box.dev.example"):
        result = subprocess.run([str(self.binary), str(self.config), str(self.hosts),
                                 str(self.base / "absent.crt"), rp, mode, action, reload,
                                 str(self.base)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_managed_mapping_preserves_user_files_and_backs_up(self):
        old_hosts = self.hosts.read_bytes()
        old_config = (self.config / "dhcp").read_bytes()
        result = self.run_case()
        self.assertTrue(result["result"]["configured"])
        self.assertEqual(result["reload_calls"], 1)
        self.assertEqual(self.hosts.read_bytes(), old_hosts)
        text = (self.config / "dhcp").read_text()
        self.assertIn("/untouched.example/192.168.2.1", text)
        self.assertIn("/etc/custom.hosts", text)
        self.assertIn(str(self.base / "managed.hosts"), text)
        self.assertIn("192.168.1.3 box.dev.example", (self.base / "managed.hosts").read_text())
        self.assertIn("fd00::3 box.dev.example", (self.base / "managed.hosts").read_text())
        self.assertEqual((Path(result["result"]["backup"]) / "dhcp").read_bytes(), old_config)
        second = self.run_case()
        self.assertTrue(second["result"]["configured"])
        self.assertEqual((self.config / "dhcp").read_text().count(str(self.base / "managed.hosts")), 1)

    def test_reload_failure_restores_both_files(self):
        old = (self.config / "dhcp").read_bytes()
        (self.base / "managed.hosts").write_text("old managed content\n")
        result = self.run_case(reload="fail-once")
        self.assertFalse(result["result"]["configured"])
        self.assertTrue(result["result"]["rolled_back"])
        self.assertEqual(result["reload_calls"], 2)
        self.assertEqual((self.config / "dhcp").read_bytes(), old)
        self.assertEqual((self.base / "managed.hosts").read_text(), "old managed content\n")

    def test_rollback_reload_failure_is_reported(self):
        result = self.run_case(reload="fail-always")
        self.assertFalse(result["result"]["rolled_back"])
        self.assertEqual(result["result"]["rollback_error"], "dns_rollback_failed")
        self.assertFalse((self.base / "managed.hosts").exists())

    def test_unconfigured_domain_has_no_publishable_records(self):
        (self.config / "system").write_text("config system 'main'\n")
        old = (self.config / "dhcp").read_bytes()
        result = self.run_case()
        self.assertEqual(result["plan"]["reason"], "local_domain_unconfigured")
        self.assertEqual(result["plan"]["records"], [])
        self.assertFalse(result["plan"]["can_apply"])
        self.assertEqual((self.config / "dhcp").read_bytes(), old)
        self.assertFalse((self.base / "managed.hosts").exists())

    def test_side_router_and_unknown_mode_do_not_write(self):
        old = (self.config / "dhcp").read_bytes()
        for mode, error in (("side-router", "external_dns_action_required"), ("unknown", "work_mode_unavailable")):
            result = self.run_case(mode=mode)
            self.assertFalse(result["plan"]["can_apply"])
            self.assertEqual(result["result"]["error"], error)
            self.assertEqual(len(result["plan"]["records"]), 2)
        self.assertEqual((self.config / "dhcp").read_bytes(), old)
        self.assertFalse((self.base / "managed.hosts").exists())

    def test_revision_changes_and_rp_migration_is_refused(self):
        first = self.run_case(action="plan")["plan"]["revision"]
        with (self.config / "dhcp").open("a") as f:
            f.write(" option cachesize '1000'\n")
        self.assertNotEqual(first, self.run_case(action="plan")["plan"]["revision"])
        result = self.run_case(rp="other.dev.example")
        self.assertEqual(result["result"]["error"], "identity_migration_required")
        self.assertFalse((self.base / "managed.hosts").exists())

    def test_disabled_dns_instance_does_not_write_mapping(self):
        (self.config / "dhcp").write_text("config dnsmasq 'main'\n option port '0'\n")
        result = self.run_case()
        self.assertEqual(result["result"]["error"], "dns_service_unavailable")
        self.assertFalse((self.base / "managed.hosts").exists())

    def test_loopback_and_duplicate_addresses_are_not_published(self):
        (self.config / "network").write_text("config interface 'lan'\n list ipaddr '127.0.0.1'\n list ipaddr '192.168.1.3'\n list ipaddr '192.168.1.3/24'\n list ip6addr '::1'\n list ip6addr 'fe80::1'\n list ip6addr 'fd00::3/64'\n")
        result = self.run_case()
        self.assertEqual([r["address"] for r in result["plan"]["records"]], ["192.168.1.3", "fd00::3"])

    def test_preexisting_uci_delta_is_not_committed(self):
        delta = self.base / "delta"
        delta.mkdir()
        pending = delta / "dhcp"
        pending.write_text("dhcp.main.cachesize='1000'\n")
        old = (self.config / "dhcp").read_bytes()
        result = self.run_case()
        self.assertEqual(result["result"]["error"], "dns_pending_changes")
        self.assertEqual((self.config / "dhcp").read_bytes(), old)
        self.assertTrue(pending.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
