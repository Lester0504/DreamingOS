#!/usr/bin/env python3
"""Actual UCI, pthread controller and transport lifecycle; network is a test double."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from test_cloud_router_id_runtime import probe_flags

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="cloud-browser-control-") as tmp:
    flags = probe_flags()
    flags += [f"-I{ROOT / 'src'}"]
    flags += ["-Wl,--disable-new-dtags"]
    binary = Path(tmp) / "test"
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror",
        *shlex.split(os.environ.get("CFLAGS", "")),
        f'-DCLOUD_STATE_DIR="{tmp}"', f'-DCLOUD_BROWSER_CONFIG_DIR="{tmp}"',
        str(ROOT / "tests/cloud_browser_control_fixture.c"),
        str(ROOT / "src/cloud/cloud_browser.c"),
        str(ROOT / "src/cloud/cloud_browser_services.c"),
        str(ROOT / "src/cloud/protocol/webframe.c"),
        "-o", str(binary), *flags, "-lcurl",
    ], check=True)
    cert = Path(tmp) / "service.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=nas.local", "-keyout", str(Path(tmp) / "service.key"),
                    "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env=dict(os.environ, CWC_TEST_CERT=str(cert)))
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-D_GNU_SOURCE",
        # Legacy api_cloud.c contains "/api/v1/cloud/*" inside its header comment.
        "-Wall", "-Wextra", "-Werror", "-Wno-comment", "-ffunction-sections", "-fdata-sections",
        *shlex.split(os.environ.get("CFLAGS", "")),
        str(ROOT / "tests/cloud_browser_api_fixture.c"),
        "-o", str(binary), *flags, "-Wl,--gc-sections",
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
