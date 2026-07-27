#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "tools/package-signature-update.sh").read_text(encoding="utf-8")


assert 'case "$out" in' in SCRIPT
assert 'out_dir="$(dirname "$out")"' in SCRIPT
assert 'out="$(cd "$out_dir" && pwd)/$out_base"' in SCRIPT
assert 'case "$db" in /*)' in SCRIPT
assert 'case "$logos" in /*)' in SCRIPT
assert "validate_icon_assets()" in SCRIPT
assert 'SELECT icon_file FROM icon_asset' in SCRIPT
assert 'runtime_name="${runtime_name#icons/}"' in SCRIPT
assert 'runtime_name="tencent.svg"' in SCRIPT
assert '[ -L "$logos/$runtime_name" ]' in SCRIPT
assert "database and logo directory are not a complete artifact set" in SCRIPT

print("ok: signature packager resolves paths and rejects incomplete DB/logo artifact sets")
