#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOG_C = (ROOT / "src" / "jmx_log.c").read_text()
JMX_H = (ROOT / "src" / "jmx.h").read_text()
MAIN_C = (ROOT / "src" / "jmx_main.c").read_text()
ROUTE_C = (ROOT / "src" / "jmx_route.c").read_text()


def main() -> None:
    assert 'kobject_create_and_add("dreamingwrt", module_root)' in LOG_C
    assert "THIS_MODULE->mkobj.kobj.parent" in LOG_C
    assert "__ATTR(debug, 0644, debug_show, debug_store)" in LOG_C
    assert "kstrtoint(buf, 0, &level)" in LOG_C
    assert "level < 0 || level > jmx_debug_max" in LOG_C
    assert "return -EINVAL;" in LOG_C
    assert "static int jmx_debug;" in LOG_C
    assert "WRITE_ONCE(jmx_debug, 0);" in LOG_C
    assert "return READ_ONCE(jmx_debug);" in LOG_C
    assert "sysfs_remove_file(dreamingwrt_kobj" in LOG_C
    assert "kobject_put(dreamingwrt_kobj);" in LOG_C

    # The sysctl alias exposes the same bounded 0..3 level.
    debug_table = LOG_C.split('.procname\t= "debug"', 1)[1].split("},", 1)[0]
    assert ".data\t\t= &jmx_debug" in debug_table
    assert "proc_dointvec_minmax" in debug_table
    assert "SYSCTL_ZERO" in debug_table
    assert "&jmx_debug_max" in debug_table

    assert "(level) == 3 && jmx_debug_at_least(3)" in JMX_H
    assert "if (jmx_debug_at_least(3))" in MAIN_C
    assert 'pr_info_ratelimited("jmx DBG:' in MAIN_C
    for marker in ("jmx_v2_MATCH:", "jmx_v3_MATCH:", "jmx_v3_SHADOW:", "jmx_fallback:"):
        line = next(line for line in MAIN_C.splitlines() if marker in line)
        assert "JMX_DEBUG_RATELIMITED(2" in line
    assert 'JMX_DEBUG_RATELIMITED(1,' in ROUTE_C
    assert '"jmx_route: wan health changed' in ROUTE_C
    assert '"jmx_route: bind appid=' in MAIN_C
    print("ok: runtime debug sysfs contract passed")


if __name__ == "__main__":
    main()
