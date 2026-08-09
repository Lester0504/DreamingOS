#!/usr/bin/env python3
"""Contract for U-08 advanced-routing semantic validation."""

from pathlib import Path
import re


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
    # The property: a rule that declares an IP-group source but resolves to zero
    # members must fail the publish rather than emit a rule matching everything.
    #
    # This used to match the literal '(src && src[0] && src_count == 0)'. The
    # condition legitimately gained a 'src_dev_count == 0' guard when
    # interface/zone sources were added (an interface rule carries its source on
    # iifname and does not consult source_object), so the literal stopped
    # matching and the gate silently stopped checking. Assert the property
    # instead of the exact spelling.
    unresolved = re.search(
        r'src\s*&&\s*src\[0\]\s*&&\s*src_count\s*==\s*0', generate)
    assert unresolved, (
        "the unresolved-IP-group-source check is gone; a rule with a source "
        "that resolves to no members would match every address"
    )
    # The object-source check must only apply when the source is not an
    # interface/zone, otherwise interface rules would be rejected outright.
    guarded = re.search(
        r'src_dev_count\s*==\s*0\s*&&\s*src\s*&&\s*src\[0\]\s*&&\s*src_count\s*==\s*0',
        generate)
    assert guarded, (
        "the object-source check must be guarded by src_dev_count == 0 so "
        "interface/zone sources are not judged by source_object"
    )
    assert 'nc_adv_object_value_ok(v)' in object_emit
    assert 'nc_fw_uci_value(fp, "option table", table_text)' in draft
    assert 'fprintf(fp, "config %s' in draft
    assert 'option comment \'%s\'' not in draft

    print("ok: U-08 advanced routing validates legacy generator semantics")


if __name__ == "__main__":
    main()
