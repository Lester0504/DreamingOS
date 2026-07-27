#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/otad/otad_inventory.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


apk = between(SOURCE, "static void scan_apk_manifests", "static void scan_path_recursive")
scan = between(SOURCE, "struct json_object *otad_inventory_scan", "struct json_object *otad_unknowns_json")

assert 'manifest_dir = "/lib/apk/packages"' in apk
assert 'strcmp(de->d_name + name_len - 5, ".list")' in apk
assert 'scan_package_list_file(pkg, path, "apk_manifest", 1, stats)' in apk
assert 'index_package_file(pkg, path, "apk_manifest", stats)' in apk
assert 'snprintf(absolute, sizeof(absolute), "/%s", start)' in SOURCE
assert 'path_has_prefix(path, "/lib/apk")' in SOURCE
assert 'path_has_prefix(path, "/etc/apk")' in SOURCE
assert 'SELECT owner_pkg,source FROM inventory_files' in SOURCE
assert 'S_ISLNK(st.st_mode)' in SOURCE
assert 'char *resolved = realpath(path, NULL)' in SOURCE
assert 'free(resolved)' in SOURCE
assert '"package_symlink"' in SOURCE
assert '"manual_override"' in SOURCE
assert '"manual_review"' in SOURCE
assert '"report_only"' in SOURCE
assert 'otad_inventory_action_count("manual_review", 1)' in FIRMWARE
assert 'otad_inventory_action_count("report_only", 0)' in FIRMWARE
assert '"inventory_reports"' in FIRMWARE
assert 'SELECT COUNT(*) FROM inventory_unknowns WHERE suggested_action=?1' in FIRMWARE
assert 'int include_apk = otad_json_bool(body, "include_apk", 1)' in scan
assert scan.index("scan_apk_manifests(&stats)") < scan.index("scan_metadata_roots(")
assert '"include_apk"' in scan

print("ok: otad APK ownership inventory contract")
