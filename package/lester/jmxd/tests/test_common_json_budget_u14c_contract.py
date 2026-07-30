#!/usr/bin/env python3
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def body(start: str, end: str) -> str:
    begin = SOURCE.index(start)
    finish = SOURCE.index(end, begin)
    return SOURCE[begin:finish]


def function(signature: str) -> str:
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


def test_parser_is_strict_bounded_and_preserves_empty_request() -> None:
    parser = function("static struct json_object *dw_parse_payload(")
    for token in (
        "DW_JSON_TEXT_MAX_BYTES",
        "json_tokener_new_ex(DW_JSON_MAX_DEPTH + 1)",
        "json_tokener_set_flags(tok, JSON_TOKENER_STRICT)",
        "json_tokener_get_error(tok)",
        "json_tokener_get_parse_end(tok) != text_len",
        "dw_json_budget_walk(*in, 1, &budget, &reason)",
        'reason = "json_root_must_be_object"',
        'reason = "json_data_must_be_object"',
    ):
        assert token in parser
    assert "if (!msg)" in parser
    empty_branch = parser[parser.index("if (!msg)"):parser.index("if ((size_t)blob_len(msg)")]
    assert "json_object_new_object()" in empty_branch
    assert "return *in" in empty_branch
    assert "if (!*in)\n        *in = json_object_new_object()" not in parser


def test_walker_has_all_required_complexity_budgets() -> None:
    limits = body("#define DW_JSON_TEXT_MAX_BYTES", "static void dw_payload_parse_error_set")
    for token in (
        "DW_JSON_MAX_DEPTH",
        "DW_JSON_MAX_NODES",
        "DW_JSON_MAX_OBJECT_MEMBERS",
        "DW_JSON_MAX_ARRAY_ITEMS",
        "DW_JSON_MAX_STRING_BYTES",
        "DW_JSON_MAX_TOTAL_STRING_BYTES",
        "budget->nodes",
        "budget->object_members",
        "budget->array_items",
        "budget->string_bytes",
        "strlen(key)",
        "json_object_get_string_len(value)",
    ):
        assert token in limits


def test_parse_failures_are_distinct_and_write_handlers_fail_before_mutation() -> None:
    parser = function("static struct json_object *dw_parse_payload(")
    guard = function("static int dw_parse_write_payload(")
    for reason in (
        "json_text_too_large",
        "json_format_failed",
        "json_parser_unavailable",
        "json_parse_failed",
        "json_depth_exceeded",
        "json_root_must_be_object",
        "json_data_must_be_object",
    ):
        assert reason in parser or reason in guard
    assert '"invalid_request"' in guard
    assert '"reason"' in guard
    assert '"field"' in guard

    guarded_calls = {
        "dw_handle_file_service_write": "jmx_samba_share_delete",
        "dw_handle_system_power_schedule_write": "jmx_system_power_schedule_delete",
        "dw_handle_system_power_action": "jmx_system_power_immediate_action",
        "dw_handle_flow_control_set": "jmx_flow_control_set(payload)",
        "dw_handle_flow_control_apply": "jmx_flow_control_apply(payload)",
        "dw_handle_multicast_service_set": "jmx_multicast_service_set(payload)",
        "dw_handle_multicast_service_apply": "jmx_multicast_service_apply(dry_run)",
        "dw_handle_system_kernel_restore_defaults": "jmx_system_kernel_restore_defaults(payload)",
        "dw_handle_system_cpu_interrupt_set": "jmx_system_cpu_interrupt_set(payload, data)",
        "dw_handle_system_ssh_idle_timeout_set": "jmx_system_ssh_idle_timeout_set(payload, data)",
        "dw_handle_system_startup_service_action": "jmx_system_startup_service_action(payload)",
        "dw_handle_system_crontab_apply": "jmx_crontab_apply_text(text, data)",
        "dw_handle_system_rc_local_apply": "jmx_system_rc_local_apply(content, confirm, data)",
        "dw_handle_system_time_sync_browser": "jmx_system_time_sync_browser(ts, data)",
        "dw_handle_system_admin_avatar_set": "jmx_admin_avatar_set(payload, out)",
        "dw_handle_system_admin_rename": "jmx_admin_rename(payload, out)",
        "dw_handle_system_admin_password_set": "jmx_admin_password_set(payload, out)",
        "dw_handle_system_flash_factory_reset": "jmx_flash_factory_reset(payload)",
        "dw_handle_system_flash_preserve_config_set": "jmx_flash_preserve_config_set(payload)",
        "dw_handle_system_mount_save_point": "jmx_api_system_mount_save_point(payload)",
        "dw_handle_system_mount_delete_point": "jmx_api_system_mount_delete_point(payload)",
        "dw_handle_system_mount_unmount": "jmx_api_system_mount_execute(payload)",
        "dw_handle_system_mount_generate_config": "jmx_api_system_mount_generate_config(payload)",
        "dw_handle_docker_container_action": "jmx_docker_container_create(payload, data)",
        "dw_handle_docker_image_action": "jmx_docker_image_pull(payload, data)",
        "dw_handle_docker_job_cancel": "jmx_docker_job_cancel(",
        "dw_handle_docker_network_action": "jmx_docker_network_create(payload, data)",
        "dw_handle_docker_volume_action": "jmx_docker_volume_create(payload, data)",
        "dw_handle_docker_service_action": "jmx_docker_service_action(action, data)",
        "dw_handle_ai_tool_call": "jmx_ai_tool_call(payload)",
        "dw_handle_ai_history_save": "jmx_ai_history_save(payload)",
        "dw_handle_ai_history_delete": "jmx_ai_history_delete(id)",
    }
    for handler, mutation in guarded_calls.items():
        code = function(f"static int {handler}(")
        assert "dw_parse_write_payload(" in code, handler
        assert code.index("dw_parse_write_payload(") < code.index(mutation), handler


def test_production_walker_host_fixture() -> None:
    cc = shutil.which("cc") or shutil.which("clang")
    pkg_config = shutil.which("pkg-config")
    if not cc or not pkg_config:
        return
    flags = subprocess.run(
        [pkg_config, "--cflags", "--libs", "json-c"],
        check=False,
        capture_output=True,
        text=True,
    )
    if flags.returncode != 0:
        return

    production = body("#define DW_JSON_TEXT_MAX_BYTES", "static void dw_payload_parse_error_set")
    fixture = f'''\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
{production}
static void expect_result(struct json_object *value, struct dw_json_budget budget,
                          int wanted, const char *wanted_reason) {{
    const char *reason = "";
    int rc = dw_json_budget_walk(value, 1, &budget, &reason);
    if (rc != wanted || (wanted_reason && strcmp(reason, wanted_reason))) {{
        fprintf(stderr, "rc=%d reason=%s wanted=%d/%s\\n", rc, reason,
                wanted, wanted_reason ? wanted_reason : "");
        exit(1);
    }}
}}
int main(void) {{
    struct dw_json_budget zero = {{0}};
    struct json_object *valid = json_tokener_parse("{{\\\"data\\\":{{\\\"name\\\":\\\"ok\\\",\\\"items\\\":[1,2]}}}}");
    struct json_object *scalar = json_object_new_int(1);
    struct json_object *object = json_object_new_object();
    struct json_object *array = json_object_new_array();
    struct json_object *string = json_object_new_string("abc");
    struct json_object *deep = json_object_new_array();
    struct json_object *cursor = deep;
    struct json_object *long_string;
    struct dw_json_budget budget;
    char *long_text = malloc(DW_JSON_MAX_STRING_BYTES + 2);
    unsigned int i;
    if (!long_text) return 2;
    memset(long_text, 'x', DW_JSON_MAX_STRING_BYTES + 1);
    long_text[DW_JSON_MAX_STRING_BYTES + 1] = '\\0';
    long_string = json_object_new_string_len(long_text, DW_JSON_MAX_STRING_BYTES + 1);
    free(long_text);
    if (!long_string) return 2;
    for (i = 0; i < DW_JSON_MAX_DEPTH; i++) {{
        struct json_object *next = json_object_new_array();
        json_object_array_add(cursor, next);
        cursor = next;
    }}
    expect_result(valid, zero, 0, NULL);
    expect_result(deep, zero, -1, "json_depth_exceeded");
    expect_result(long_string, zero, -1, "json_string_too_long");
    budget = zero; budget.nodes = DW_JSON_MAX_NODES;
    expect_result(scalar, budget, -1, "json_node_budget_exceeded");
    json_object_object_add(object, "k", json_object_new_int(1));
    budget = zero; budget.object_members = DW_JSON_MAX_OBJECT_MEMBERS;
    expect_result(object, budget, -1, "json_object_member_budget_exceeded");
    json_object_array_add(array, json_object_new_int(1));
    budget = zero; budget.array_items = DW_JSON_MAX_ARRAY_ITEMS;
    expect_result(array, budget, -1, "json_array_item_budget_exceeded");
    budget = zero; budget.string_bytes = DW_JSON_MAX_TOTAL_STRING_BYTES - 2;
    expect_result(string, budget, -1, "json_string_budget_exceeded");
    budget = zero;
    expect_result(string, budget, 0, NULL);
    json_object_put(valid); json_object_put(scalar); json_object_put(object);
    json_object_put(array); json_object_put(string); json_object_put(deep);
    json_object_put(long_string);
    puts("ok: production JSON walker budgets execute fail-closed");
    return 0;
}}
'''
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "fixture.c"
        binary = Path(tmp) / "fixture"
        source.write_text(fixture, encoding="utf-8")
        command = [cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)]
        command.extend(shlex.split(flags.stdout))
        subprocess.run(command, check=True, capture_output=True, text=True)
        run = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        assert "execute fail-closed" in run.stdout


if __name__ == "__main__":
    test_parser_is_strict_bounded_and_preserves_empty_request()
    test_walker_has_all_required_complexity_budgets()
    test_parse_failures_are_distinct_and_write_handlers_fail_before_mutation()
    test_production_walker_host_fixture()
    print("ok: U-14C common JSON parser contract")
