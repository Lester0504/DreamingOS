#!/usr/bin/env python3
"""Run the real C snapshot with private UCI/hosts/certificate fixtures."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

from test_cloud_router_id_runtime import probe_flags


ROOT = Path(__file__).resolve().parents[1]


class LocalDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="cloud-domain-build-")
        cls.binary = Path(cls.build.name) / "snapshot"
        flags = probe_flags()
        if sys.platform.startswith("linux"):
            # libuci's libubox dependency also needs the staging rpath. Do not
            # put target libraries in the compiler's LD_LIBRARY_PATH.
            flags.append("-Wl,--disable-new-dtags")
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=c11", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Werror",
            *shlex.split(os.environ.get("CLOUD_DOMAIN_CFLAGS", "")),
            str(ROOT / "tests/cloud_domain_fixture.c"),
            str(ROOT / "src/webd/api/api_cloud_domain.c"),
            "-o", str(cls.binary), *flags,
        ], check=True)
        cls.pem = Path(cls.build.name) / "fixture.crt"
        subprocess.run([
            os.environ.get("OPENSSL", "openssl"), "req", "-x509", "-newkey",
            "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=not-the-domain",
            "-addext", "subjectAltName=DNS:box.dev.example",
            "-keyout", str(Path(cls.build.name) / "fixture.key"),
            "-out", str(cls.pem),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloud-domain-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = self.base / "config"
        self.config.mkdir()
        self.hosts = self.base / "hosts"
        self.hosts.write_text(
            "127.0.0.1 localhost\n"
            "192.168.1.1 other.dev.example\n"
            "192.168.1.2 box.dev.example.evil\n"
            "192.168.1.3 alias BOX.DEV.EXAMPLE. # exact alias\n"
            "fd00::3 box.dev.example\n"
            "not-an-ip box.dev.example\n"
        )
        self.certificate = self.base / "console.crt"
        self.certificate.write_bytes(self.pem.read_bytes())
        self.write("system", "config system\n option console_domain 'BOX.DEV.EXAMPLE.'\n")
        self.write("network", "config interface 'lan'\n option ipaddr '192.168.1.3'\n"
                   " list ip6addr 'fd00::3/64'\n")
        self.write("dhcp", "config dnsmasq 'main'\n")
        self.write("relay", "config relay 'service'\n option enabled '0'\n"
                   "config relay 'cert'\n option enabled '1'\n"
                   f" option fullchain_path '{self.certificate}'\n")

    def write(self, name, contents):
        (self.config / name).write_text(contents)

    def snapshot(self, rp="box.dev.example"):
        result = subprocess.run([
            str(self.binary), str(self.config), str(self.hosts),
            str(self.certificate), rp,
        ], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def sources(self, data):
        return data["local_dns"]["instances"][0]["host_sources"]

    def test_exact_host_ipv4_ipv6_and_no_side_effects(self):
        before = {str(p): p.read_bytes() for p in self.base.rglob("*") if p.is_file()}
        d = self.snapshot()
        self.assertEqual(d["domain"], "box.dev.example")
        self.assertTrue(d["passkey"]["matches_domain"])
        self.assertEqual(d["configured_lan_addresses"], ["192.168.1.3", "fd00::3/64"])
        self.assertIsNone(d["runtime_lan_addresses"])
        self.assertEqual(self.sources(d)[0]["entries"], [
            {"address": "192.168.1.3", "family": 4},
            {"address": "fd00::3", "family": 6},
        ])
        self.assertFalse(d["local_dns"]["client_verified"])
        self.assertFalse(d["local_dns"]["runtime_verified"])
        self.assertEqual(d["local_dns"]["state"], "unverified")
        self.assertEqual(before, {
            str(p): p.read_bytes() for p in self.base.rglob("*") if p.is_file()
        })

    def test_self_signed_is_not_browser_trust_and_relay_is_independent(self):
        d = self.snapshot()["certificate"]
        self.assertEqual(d["state"], "time_valid")
        self.assertTrue(d["hostname_matches"])
        self.assertIsNone(d["browser_trusted"])
        self.assertIsNone(d["served_by_listener"])
        self.assertTrue(d["renewal_enabled"])
        self.assertTrue(d["renewal_targets_console"])
        self.assertGreater(d["not_after"], d["not_before"])

    def test_wrong_rp_and_certificate_name_are_visible(self):
        self.write("system", "config system\n option console_domain 'else.dev.example'\n")
        d = self.snapshot()
        self.assertFalse(d["passkey"]["matches_domain"])
        self.assertEqual(d["certificate"]["state"], "hostname_mismatch")
        self.assertEqual(self.sources(d)[0]["entries"], [])

    def test_nohosts_and_addnhosts_list_with_missing_file(self):
        extra = self.base / "managed.hosts"
        extra.write_text("192.168.2.9 box.dev.example\n")
        self.write("dhcp", "config dnsmasq 'main'\n option nohosts '1'\n"
                   f" list addnhosts '{extra}'\n"
                   f" list addnhosts '{self.base}/missing'\n")
        d = self.snapshot()
        self.assertFalse(d["local_dns"]["instances"][0]["reads_system_hosts"])
        self.assertEqual(len(self.sources(d)), 2)
        self.assertEqual(self.sources(d)[0]["entries"][0]["address"], "192.168.2.9")
        self.assertEqual(self.sources(d)[1]["state"], "unavailable")

    def test_second_instance_and_string_addnhosts_are_not_lost(self):
        self.write("dhcp", "config dnsmasq 'main'\n option nohosts '1'\n"
                   "config dnsmasq 'secondary'\n option port '0'\n option nohosts '1'\n"
                   f" option addnhosts '{self.hosts}'\n")
        d = self.snapshot()["local_dns"]["instances"]
        self.assertEqual(len(d), 2)
        self.assertEqual(d[0]["host_sources"], [])
        self.assertEqual(d[1]["configured_port"], "0")
        self.assertEqual(len(d[1]["host_sources"][0]["entries"]), 2)

    def test_missing_configuration_is_unknown_not_false_success(self):
        for p in self.config.iterdir():
            p.unlink()
        self.certificate.unlink()
        d = self.snapshot("")
        self.assertIsNone(d["domain"])
        self.assertIsNone(d["passkey"]["rp_id"])
        self.assertIsNone(d["passkey"]["matches_domain"])
        self.assertEqual(d["certificate"]["state"], "missing")
        self.assertIsNone(d["certificate"]["renewal_enabled"])
        self.assertEqual(d["local_dns"]["instances"], [])
        self.assertEqual(d["unavailable_config_packages"], ["system", "network", "dhcp", "relay"])

    def test_invalid_hostname_and_malformed_certificate(self):
        for name in ("*.dev.example", "-bad.dev.example", "a..example", "a" * 64 + ".example"):
            with self.subTest(name=name):
                self.write("system", f"config system\n option console_domain '{name}'\n")
                self.certificate.write_text("not a certificate")
                d = self.snapshot()
                self.assertEqual(d["domain_state"], "invalid")
                self.assertIsNone(d["domain"])
                self.assertEqual(d["certificate"]["state"], "malformed")

    def test_file_limits_and_fifo_do_not_block(self):
        self.hosts.write_text("x" * (256 * 1024 + 1))
        self.assertEqual(self.sources(self.snapshot())[0]["state"], "limit_exceeded")
        self.hosts.unlink()
        os.mkfifo(self.hosts)
        self.assertEqual(self.sources(self.snapshot())[0]["state"], "unsupported_source")
        self.certificate.unlink()
        os.mkfifo(self.certificate)
        self.assertEqual(self.snapshot()["certificate"]["state"], "unsupported_source")

    def test_long_line_and_source_budget_are_explicit(self):
        self.hosts.write_text("x" * 2048 + " box.dev.example\n")
        self.assertEqual(self.sources(self.snapshot())[0]["state"], "limit_exceeded")
        self.write("dhcp", "config dnsmasq 'main'\n" +
                   "".join(f" list addnhosts '{self.base}/hosts{i}'\n" for i in range(20)))
        d = self.snapshot()
        self.assertTrue(d["local_dns"]["truncated"])
        self.assertEqual(len(self.sources(d)), 16)

    def test_renewal_for_another_certificate_is_not_console_renewal(self):
        other = self.base / "other.crt"
        other.write_bytes(self.pem.read_bytes())
        self.write("relay", "config relay 'cert'\n option enabled '1'\n"
                   f" option fullchain_path '{other}'\n")
        self.assertFalse(self.snapshot()["certificate"]["renewal_targets_console"])
        other.unlink()
        other.symlink_to(self.certificate)
        self.assertTrue(self.snapshot()["certificate"]["renewal_targets_console"])

    def test_existing_managed_dns_rule_is_read_without_applying_it(self):
        rule = "/box.dev.example/192.168.1.3"
        self.write("system", "config system\n option console_domain 'box.dev.example'\n"
                   f" option console_domain_address '{rule}'\n")
        self.write("dhcp", "config dnsmasq 'main'\n"
                   f" list address '{rule}'\n"
                   "config dnsmasq 'other'\n"
                   " list address '/else.dev.example/192.168.1.4'\n")
        d = self.snapshot()["local_dns"]
        self.assertEqual(d["managed_address_rule"], rule)
        self.assertTrue(d["instances"][0]["managed_rule_present"])
        self.assertFalse(d["instances"][1]["managed_rule_present"])
        self.assertFalse(d["runtime_verified"])
        self.assertFalse(d["client_verified"])


if __name__ == "__main__":
    unittest.main()
