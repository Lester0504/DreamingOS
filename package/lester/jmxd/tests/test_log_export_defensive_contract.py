#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOGD = (ROOT / "src/logd/logd_event.c").read_text()
LOGD_H = (ROOT / "src/logd/logd_internal.h").read_text()
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text()
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text()


def main():
    combined = LOGD + LOGD_H + CORE + WEBD
    assert "/tmp/dreamingwrt/log_exports" not in combined
    assert "/tmp/dreamingwrt/log_export_" not in combined
    assert '"/run/dreamingwrt/log_exports"' in combined

    for source in (LOGD, CORE):
        assert "O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC" in source
        assert "st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))" in source
        assert "fflush(fp) != 0" in source
        assert "fsync(fileno(fp)) != 0" in source
        assert "fclose(fp) != 0" in source
        assert "unlinkat(dirfd, id, 0)" in source
        assert "download_url" in source

    assert 'json_object_object_add(resp, "path"' not in LOGD
    assert 'json_object_object_add(data, "path"' not in CORE
    assert "neutralize = s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@';" in LOGD
    assert "neutralize = s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@';" in CORE
    assert "*p == '\"' || *p == ',' || *p == '\\n' || *p == '\\r'" in LOGD
    assert "*p == '\"' || *p == ',' || *p == '\\r' || *p == '\\n'" in CORE

    assert "openat(dirfd, id, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)" in WEBD
    assert "fstat(f, &st) != 0 || !S_ISREG(st.st_mode)" in WEBD
    assert "st.st_uid != 0 || st.st_nlink != 1" in WEBD
    print("ok: log exports use safe opaque files and propagate write failures")


if __name__ == "__main__":
    main()
