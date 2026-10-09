#!/usr/bin/env python3
"""Route authorization, operation/session binding and actual forked job lifecycle."""
import os
from pathlib import Path
import subprocess
import tempfile
from test_cloud_router_id_runtime import probe_flags

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="cloud-domain-api-") as tmp:
    binary = Path(tmp) / "fixture"
    defines = [f'-D{name}="{tmp}/{suffix}"' for name, suffix in (
        ("DOMAIN_DHCP", "dhcp"), ("DOMAIN_HOSTS", "hosts"),
        ("DOMAIN_BACKUPS", "backups"), ("DOMAIN_JOBS", "jobs"), ("DOMAIN_LOCK", "lock"))]
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror", "-Wno-comment", "-ffunction-sections", "-fdata-sections",
        *defines, f"-I{ROOT / 'src'}", str(ROOT / "tests/cloud_domain_api_fixture.c"),
        str(ROOT / "src/webd/api/api_cloud_domain.c"), "-o", str(binary),
        *probe_flags(), "-lcurl", "-Wl,--gc-sections", "-Wl,--disable-new-dtags"], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
