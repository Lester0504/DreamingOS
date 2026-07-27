#!/usr/bin/env python3
"""Route configuration must use config.db after one-time UCI migration."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_uses_config_db_only() -> None:
    runtime = (ROOT / "src/routed/jmx_route.c").read_text(encoding="utf-8")
    migration = (ROOT / "src/routed/jmx_route_db.c").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert '#include "jmx_route_db.h"' in runtime
    assert "jmx_route_db_config_get(&data)" in runtime
    assert "jmx_route_db_replace_begin" in runtime
    assert "jmx_route_db_replace_commit" in runtime
    assert "jmx_route_db_replace_rollback" in runtime
    assert 'uci_load(ctx, "jmx_route"' not in runtime
    assert 'uci_load(context, "jmx_route"' in migration
    assert "JMX_ROUTE_UCI_MIGRATION" in migration
    assert "./files/jmx_route.config" not in makefile
    assert not (ROOT / "files/jmx_route.config").exists()


def test_apply_is_transactional_and_clears_stale_wans() -> None:
    runtime = (ROOT / "src/routed/jmx_route.c").read_text(encoding="utf-8")

    begin = runtime.index("struct json_object *jmx_api_route_config_set")
    end = runtime.index("struct json_object *jmx_api_route_status", begin)
    setter = runtime[begin:end]
    apply_begin = runtime.index("static int jmx_route_sync_json(struct json_object *config)\n{")
    apply_end = runtime.index("int jmx_route_sync_config", apply_begin)
    apply = runtime[apply_begin:apply_end]

    assert setter.index("jmx_route_db_replace_begin") < setter.index("jmx_route_sync_json(readback)")
    assert setter.index("jmx_route_sync_json(readback)") < setter.index("jmx_route_db_replace_commit")
    assert "jmx_route_db_replace_rollback(tx)" in setter
    assert "jmx_route_sync_json(previous)" in setter
    assert "for (i = 1; i <= JMX_ROUTE_MAX_WAN_IFACES; i++)" in apply
    assert "jmx_route_nl_wan_unregister(fd, (uint8_t)i)" in apply
    assert "route_sync_network_wans" in apply
    assert "route_kernel_state_counts" in apply
    assert '"--", (char *)url' in runtime
    assert "jmx_route_cleanup_system_route(table_id);" in runtime
    assert "jmx_route_cleanup_untracked_system_routes" not in runtime


if __name__ == "__main__":
    test_runtime_uses_config_db_only()
    test_apply_is_transactional_and_clears_stale_wans()
    print("ok: route config.db authority and transactional runtime apply")
