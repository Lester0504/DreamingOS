#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def main() -> None:
    required = (
        "DW_STORAGE_TMP_SCAN_MAX_ENTRIES 4096",
        "DW_STORAGE_TMP_SCAN_MAX_DEPTH   2",
        "DW_STORAGE_TMP_TOP_FILES        8",
        "DW_STORAGE_TMP_WARN_BYTES",
        "DW_STORAGE_TMP_CRITICAL_BYTES",
        "dw_storage_tmp_scan_dir",
        "st.st_dev != scan->device",
        "S_ISREG(st.st_mode)",
        "S_ISDIR(st.st_mode)",
        "lstat(path, &st)",
        'json_object_object_add(data, "tmp_files", summary)',
        '"tmp_file_size_warning"',
        '"tmp_file_size_critical"',
        '"largest_files"',
        '"truncated"',
    )
    for marker in required:
        assert marker in SOURCE, f"missing tmp storage health marker: {marker}"
    scan = SOURCE[SOURCE.index("static void dw_storage_tmp_scan_dir"):
                  SOURCE.index("static void dw_storage_add_tmp_files")]
    assert "stat(" not in scan.replace("lstat(", "")
    assert "unlink(" not in scan
    assert "remove(" not in scan
    assert "system(" not in scan
    print("storage tmp-file bounded health contract: ok")


if __name__ == "__main__":
    main()
