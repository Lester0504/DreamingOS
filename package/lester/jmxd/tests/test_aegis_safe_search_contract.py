#!/usr/bin/env python3
"""Static production contracts for AegisX Safe Search Phase 2a."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CONTENT = (ROOT / "src/aegisxd/aegisxd_content.c").read_text(encoding="utf-8")
DATAPLANE = (ROOT / "src/aegisxd/aegisxd_dataplane.c").read_text(encoding="utf-8")
STATUS = (ROOT / "src/aegisxd/aegisxd_status.c").read_text(encoding="utf-8")


def function_body(text: str, symbol: str) -> str:
    match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL)
    assert match, f"missing production function: {symbol}"
    pos = match.end()
    start = pos
    depth = 1
    quote = ""
    line_comment = False
    block_comment = False
    while pos < len(text) and depth:
        char = text[pos]
        nxt = text[pos + 1] if pos + 1 < len(text) else ""
        if line_comment:
            line_comment = char != "\n"
            pos += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                pos += 2
            else:
                pos += 1
            continue
        if quote:
            if char == "\\":
                pos += 2
                continue
            if char == quote:
                quote = ""
            pos += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            pos += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            pos += 2
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        pos += 1
    assert depth == 0, f"could not delimit production function: {symbol}"
    return text[start : pos - 1]


def require_all(text: str, values: tuple[str, ...], scope: str) -> None:
    missing = [value for value in values if value not in text]
    assert not missing, f"{scope} missing: {missing}"


def test_safe_search_validation_is_strict_and_canonical() -> None:
    parse = function_body(CONTENT, "content_safe_search_parse")
    require_all(
        parse,
        (
            "json_type_object",
            "json_type_boolean",
            '"google"',
            '"bing"',
            '"youtube"',
            '"invalid_safe_search"',
            '"invalid_safe_search_field"',
            '"invalid_safe_search_value"',
        ),
        "strict Safe Search validation",
    )
    assert "json_object_object_foreach" in parse, "unknown Safe Search keys must be rejected"
    canonical = function_body(CONTENT, "content_canonical_object")
    assert "content_safe_search_parse" in canonical
    for provider in ("google", "bing", "youtube"):
        assert re.search(
            rf'json_object_object_add\(copy,\s*"{provider}",\s*json_object_new_boolean\(safe_values\.{provider}\)\)',
            canonical,
        ), f"missing canonical false-default for {provider}"
    assert "safe_search_not_supported" not in CONTENT


def test_only_active_global_policies_are_merged_with_or() -> None:
    load = function_body(CONTENT, "aegisxd_content_filter_load")
    require_all(
        load,
        (
            "safe_search_json",
            "enabled=1",
            "mode<>'off'",
            "ORDER BY id",
            "f->safe_search.google|=parsed.google",
            "f->safe_search.bing|=parsed.bing",
            "f->safe_search.youtube|=parsed.youtube",
        ),
        "active policy OR merge",
    )
    effective = function_body(CONTENT, "content_safe_search_effective")
    require_all(effective, ("enabled=1", "mode<>'off'", "|="), "readback OR merge")
    canonical = function_body(CONTENT, "content_canonical_object")
    require_all(
        canonical,
        ('"all"', '"content_scope_not_supported"', '"content_schedule_not_supported"'),
        "Phase 2a scope/schedule boundaries",
    )


def test_dnsmasq_artifact_uses_fixed_addresses_and_required_hosts() -> None:
    required = (
        '"forcesafesearch.google.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"google.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"www.google.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"strict.bing.com", "204.79.197.220", ""',
        '"www.bing.com", "204.79.197.220", ""',
        '"restrict.youtube.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"www.youtube.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"m.youtube.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"youtubei.googleapis.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"youtube.googleapis.com", "216.239.38.120", "2001:4860:4802:32::"',
        '"www.youtube-nocookie.com", "216.239.38.120", "2001:4860:4802:32::"',
    )
    require_all(CONTENT, required, "fixed Safe Search host map")
    render = function_body(CONTENT, "aegisxd_content_filter_write_explicit_blocks")
    require_all(
        render,
        (
            "content_safe_search_hosts",
            "content_safe_search_provider_enabled",
            'fprintf(fp,"address=/%s/%s\\n",host->host,host->ipv4)',
            "host->ipv6[0]",
        ),
        "Safe Search dnsmasq renderer",
    )
    assert "cname=" not in render.lower()


def test_safe_search_reuses_atomic_dns_writer_and_guarded_apply() -> None:
    writer = function_body(DATAPLANE, "aegisxd_plan_write_dnsmasq")
    require_all(
        writer,
        ("aegisxd_plan_writer_open", "aegisxd_content_filter_load", "aegisxd_content_filter_write_explicit_blocks", "aegisxd_plan_writer_finish"),
        "existing atomic DNS artifact",
    )
    finish = function_body(DATAPLANE, "aegisxd_plan_writer_finish")
    require_all(finish, ("fflush", "rename", "unlink"), "atomic artifact commit")
    apply = function_body(DATAPLANE, "aegisxd_apply")
    require_all(
        apply,
        (
            '"dns_filter"',
            "aegisxd_file_copy_atomic",
            "AEGISXD_DNSMASQ_RELOAD_CMD",
            '"dnsmasq_reload_failed"',
            '"active_state_write_failed"',
            "dns_previous",
            "aegisxd_apply_write_state",
        ),
        "guarded apply/readback/rollback",
    )
    state = function_body(DATAPLANE, "aegisxd_apply_state_json")
    assert 'scope && !strcmp(scope, "dns_filter")' in state
    compile_plan = function_body(DATAPLANE, "aegisxd_compile_plan")
    assert "aegisxd_plan_write_dnsmasq" in compile_plan
    assert "/etc/init.d/dnsmasq" not in CONTENT


def test_empty_artifact_disables_through_existing_path() -> None:
    request = function_body(CONTENT, "content_apply_requested")
    require_all(
        request,
        ('"dns_filter"', '"dnsmasq_rules_empty"', '"disable"', "aegisxd_apply(req)"),
        "empty artifact disable",
    )
    disable = function_body(DATAPLANE, "aegisxd_apply_disable")
    require_all(
        disable,
        (
            "unlink",
            "AEGISXD_DNSMASQ_RELOAD_CMD",
            "active.json",
            '"active_state_remove_failed"',
            '"rollback_ok"',
        ),
        "guarded disable",
    )


def test_capabilities_runtime_and_compile_metadata_are_stable() -> None:
    capabilities = function_body(CONTENT, "content_capabilities")
    require_all(
        capabilities,
        (
            '"safe_search_supported", json_object_new_boolean(1)',
            '"device_scope_supported", json_object_new_boolean(0)',
            '"network_scope_supported", json_object_new_boolean(0)',
            '"schedule_supported", json_object_new_boolean(0)',
        ),
        "content capability boundaries",
    )
    require_all(
        STATUS,
        (
            '"content_filter_safe_search_supported", json_object_new_boolean(1)',
            '"content_filter_schedule_supported", json_object_new_boolean(0)',
            '"content_filter_device_scope_supported", json_object_new_boolean(0)',
            '"content_filter_network_scope_supported", json_object_new_boolean(0)',
        ),
        "global Aegis capability boundaries",
    )
    compile_plan = function_body(DATAPLANE, "aegisxd_compile_plan")
    require_all(
        compile_plan,
        (
            '"safe_search_active_policies"',
            '"safe_search_providers"',
            '"safe_search_rules"',
            '"logical_or"',
            '"dnsmasq_domain_blocklist"',
        ),
        "compile plan Safe Search metadata",
    )
    runtime = function_body(CONTENT, "aegisxd_content_runtime_json")
    require_all(
        runtime,
        ("active.json", '"configured"', '"active"', '"installed"', '"readback_source"'),
        "installed Safe Search readback",
    )


if __name__ == "__main__":
    test_safe_search_validation_is_strict_and_canonical()
    test_only_active_global_policies_are_merged_with_or()
    test_dnsmasq_artifact_uses_fixed_addresses_and_required_hosts()
    test_safe_search_reuses_atomic_dns_writer_and_guarded_apply()
    test_empty_artifact_disables_through_existing_path()
    test_capabilities_runtime_and_compile_metadata_are_stable()
    print("ok: 6 Aegis Safe Search Phase 2a contracts")
