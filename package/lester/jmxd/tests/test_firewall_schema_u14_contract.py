#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text()


def function_body(signature: str) -> str:
    start = SOURCE.index(signature)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[brace + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


def main():
    validate = function_body("int jmx_firewall_service_validate(")
    setter = function_body("int jmx_firewall_service_set(")

    assert "json_object_is_type(cfg, json_type_object)" in validate
    assert 'json_object_is_type(o, json_type_object)' in validate
    assert '"zones", "rules", "forwards", "nat_rules", "ipsets"' in validate
    assert "json_object_is_type(arr, json_type_array)" in validate
    assert "NC_FIREWALL_GROUP_MAX" in validate
    assert "NC_FIREWALL_TOTAL_MAX" in validate
    assert "priorities[NC_FIREWALL_GROUP_MAX]" in validate
    assert "qsort(priorities" in validate
    assert "for(j=i+1" not in validate.replace(" ", "")

    validate_call = setter.index("jmx_firewall_service_validate(cfg)")
    database_init = setter.index("jmx_netconfig_db_init()")
    begin = setter.index('nc_exec("BEGIN IMMEDIATE")')
    first_delete = setter.index('nc_exec("DELETE FROM firewall_')
    assert validate_call < database_init < begin < first_delete
    assert 'if(nc_exec("BEGIN IMMEDIATE")!=0)return -1;' in setter
    assert 'if (nc_exec("COMMIT") != 0)' in setter

    # Regression: {"rules":"wrong-type"} is rejected by the array gate before
    # the setter can start its transaction or execute DELETE FROM firewall_rule.
    rules_lookup = validate.index('json_object_object_get_ex(cfg, groups[i], &arr)')
    array_gate = validate.index('json_object_is_type(arr, json_type_array)', rules_lookup)
    assert rules_lookup < array_gate
    print("ok: U-14 firewall schema fails closed before database mutation")


if __name__ == "__main__":
    main()
