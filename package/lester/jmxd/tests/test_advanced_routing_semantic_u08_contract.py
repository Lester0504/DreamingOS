#!/usr/bin/env python3
"""Contract for U-08 advanced-routing semantic validation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")


def function_source(signature: str) -> str:
    start = SOURCE.index(signature)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def main() -> None:
    validate = function_source("static int nc_adv_validate_config(")
    setter = function_source("int jmx_advanced_routing_set(")
    generate = function_source("static int nc_adv_generate_runtime(")
    draft = function_source("static int nc_adv_generate_draft_config(")
    object_emit = function_source("static int nc_adv_emit_obj_nft(")

    for helper in (
        "nc_adv_ip_cidr_ok",
        "nc_adv_ifname_ok",
        "nc_adv_route_type_ok",
        "nc_adv_proto_ok",
        "nc_fw_port_expr_ok",
        "nc_adv_object_value_ok",
        "NC_ADV_MAX_ITEMS",
    ):
        assert helper in validate
    assert 'strcmp(action, "route_table")' in validate
    assert 'strcmp(nc_json_str_def(o, "schedule", "always"), "always")' in validate
    assert 'strcmp(type, "ip_group")' in validate
    assert setter.index("nc_adv_validate_config(cfg, 0)") < setter.index(
        "jmx_netconfig_db_init()"
    ) < setter.index('nc_exec("BEGIN IMMEDIATE")')
    assert 'if (rc == 0 && nc_exec("COMMIT") == 0)' in setter
    assert 'nc_exec("ROLLBACK")' in setter

    assert 'SELECT COUNT(*) FROM cross_l3_service WHERE enabled=1' in generate
    assert 'nc_adv_table_id_by_name(table, &table_id)' in generate
    assert 'snprintf(table_text, sizeof(table_text), "%d", table_id)' in generate
    assert 'if(!has) { sqlite3_finalize(st); return -1; }' in generate
    assert '(src && src[0] && src_count == 0)' in generate
    assert 'nc_adv_object_value_ok(v)' in object_emit
    assert 'nc_fw_uci_value(fp, "option table", table_text)' in draft
    assert 'fprintf(fp, "config %s' in draft
    assert 'option comment \'%s\'' not in draft

    print("ok: U-08 advanced routing validates legacy generator semantics")


if __name__ == "__main__":
    main()
