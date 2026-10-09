#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/otad/otad_inventory.c").read_text(encoding="utf-8")
PROVIDER = (ROOT / "src/otad/otad_persist_source.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "src/Makefile").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin)
    return text[begin:finish]


def main() -> None:
    assert 'OTAD_PERSIST_NEW_DIR "/usr/share/dreamingos/persist.d"' in SOURCE
    assert 'OTAD_PERSIST_LEGACY_DIR "/usr/share/dreamingwrt/persist.d"' in SOURCE
    assert 'OTAD_PERSIST_RUNTIME_DIR "/etc/dreamingwrt/persist.d"' in SOURCE
    otad_objects = MAKEFILE.split("OTAD_OBJS :=", 1)[1].splitlines()[0]
    assert "jmx_path_provider.o" in otad_objects
    assert "otad/otad_persist_source.o" in otad_objects
    assert "otad/otad_inventory_transaction.o" in otad_objects

    assert "jmx_path_select_immutable_file_set" in PROVIDER
    assert "immutable_persist_list_read_failed" in PROVIDER
    assert "runtime_persist_list_read_failed" in PROVIDER
    assert "O_NOFOLLOW" in PROVIDER

    scan = between(SOURCE, "struct json_object *otad_inventory_scan(",
                   "struct json_object *otad_unknowns_json")
    preflight = scan.index("otad_persist_sources_load(")
    transaction = scan.index("otad_inventory_run_transaction(")
    assert preflight < transaction
    preflight_failure = scan[preflight:transaction]
    assert '"persist_source_preflight_failed"' in preflight_failure
    assert '"inventory_unchanged"' in preflight_failure
    assert "inventory_scan_transaction_work" in scan
    assert 'otad_json_add_string(resp, "error", transaction_error)' in scan
    assert '"persist_source_new_only"' in scan
    assert '"persist_source_legacy_only"' in scan
    assert '"persist_source_identical_new"' in scan
    assert '"persist_source_runtime_files"' in scan

    for call in ("otad_inventory_clear_unknowns()",
                 "otad_inventory_replace_file(",
                 "otad_inventory_add_unknown("):
        assert f"if ({call}" in SOURCE, f"unchecked inventory write: {call}"

    print("ok: otad persist source selection and atomic inventory contract")


if __name__ == "__main__":
    main()
