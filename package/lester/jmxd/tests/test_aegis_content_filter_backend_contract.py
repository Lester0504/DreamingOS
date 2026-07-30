#!/usr/bin/env python3
"""Production static contracts for AegisX content filtering Phase 1 + Safe Search Phase 2a.

The suite inspects the installed production implementation boundary: config.db
authority, real ubus handlers, authenticated REST/RBAC routes, validation, and
the existing DNS/dnsmasq apply path.  It intentionally provides no mock
storage or fake dataplane.  An incomplete production implementation is
expected to fail with the missing contract named by the assertion.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
AEGIS_DIR = ROOT / "src/aegisxd"
DB_PATH = AEGIS_DIR / "aegisxd_db.c"
UBUS_PATH = AEGIS_DIR / "aegisxd_ubus.c"
DATAPLANE_PATH = AEGIS_DIR / "aegisxd_dataplane.c"
INTERNAL_PATH = AEGIS_DIR / "aegisxd_internal.h"
WEBD_PATH = ROOT / "src/webd/jmx_app_api.c"
PERMS_PATH = ROOT / "src/webd/jmx_app_perms.c"


def read_required(path: Path) -> str:
    assert path.is_file(), f"required production file is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def source_bundle(directory: Path) -> str:
    paths = sorted(
        path for path in directory.glob("*")
        if path.is_file() and path.suffix in {".c", ".h"}
    )
    assert paths, f"required production source directory is missing or empty: {directory.relative_to(ROOT)}"
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


DB = read_required(DB_PATH)
UBUS = read_required(UBUS_PATH)
DATAPLANE = read_required(DATAPLANE_PATH)
INTERNAL = read_required(INTERNAL_PATH)
WEBD = read_required(WEBD_PATH)
PERMS = read_required(PERMS_PATH)
AEGIS = source_bundle(AEGIS_DIR)


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} is missing contract evidence: {missing}"


def require_one(text: str, needles: tuple[str, ...], scope: str) -> str:
    for needle in needles:
        if needle in text:
            return needle
    raise AssertionError(f"{scope} needs one of these production evidences: {needles}")


def c_string_literals(text: str) -> str:
    return "".join(
        match.group(1).replace(r'\"', '"')
        for match in re.finditer(r'"((?:\\.|[^"\\])*)"', text)
    )


def create_table_body(names: tuple[str, ...]) -> tuple[str, str]:
    schema = c_string_literals(DB)
    for name in names:
        match = re.search(
            rf"CREATE TABLE IF NOT EXISTS {re.escape(name)}\s*\((.*?)\)(?=CREATE|INSERT|ALTER|$)",
            schema,
            re.DOTALL,
        )
        if match:
            return name, match.group(1)
    raise AssertionError(f"config.db authority table is missing; expected one of {names}")


def function_body(text: str, symbol: str) -> str:
    start_match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL)
    assert start_match, f"production function body is missing: {symbol}"
    start = start_match.end()
    depth = 1
    pos = start
    quote = ""
    line_comment = False
    block_comment = False
    while pos < len(text) and depth:
        char = text[pos]
        next_char = text[pos + 1] if pos + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            pos += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
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
        if char == "/" and next_char == "/":
            line_comment = True
            pos += 2
            continue
        if char == "/" and next_char == "*":
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
    return text[start:pos - 1]


def function_body_any(text: str, symbols: tuple[str, ...], scope: str) -> str:
    for symbol in symbols:
        if re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL):
            return function_body(text, symbol)
    raise AssertionError(f"{scope} needs one of these production functions: {symbols}")


def ubus_handler_any(methods: tuple[str, ...], scope: str) -> tuple[str, str]:
    for method in methods:
        match = re.search(
            rf'UBUS_METHOD(?:_NOARG)?\(\s*"{re.escape(method)}"\s*,\s*([A-Za-z0-9_]+)',
            UBUS,
        )
        if match:
            return method, match.group(1)
    raise AssertionError(f"{scope} needs one of these ubus methods: {methods}")


def route_window(path: str, radius: int = 1500) -> str:
    pos = WEBD.find(f'"{path}"')
    assert pos >= 0, f"authenticated REST route is missing: {path}"
    return WEBD[max(0, pos - radius):min(len(WEBD), pos + radius)]


def test_config_db_is_authoritative_for_policies_and_domain_overrides() -> None:
    require_all(
        INTERNAL,
        ('AEGISXD_CONFIG_DIR "/etc/dreamingwrt"',
         'AEGISXD_CONFIG_DB_PATH AEGISXD_CONFIG_DIR "/config.db"'),
        "config.db production path",
    )
    policy_name, policy = create_table_body(("aegis_content_policies", "aegis_content_policy"))
    override_name, override = create_table_body(("aegis_domain_overrides",))

    require_all(policy, (" id ", " name ", " enabled ", " mode "), policy_name)
    require_all(
        policy,
        (" scope_json ", " ad_block ", " categories_json ", " schedule_json "),
        f"{policy_name} Phase 1 policy fields",
    )
    require_all(policy, (" created_at ", " updated_at "), policy_name)

    require_all(override, (" domain ",), override_name)
    require_one(override, (" policy_id ", " profile_id "), f"{override_name} policy ownership")
    require_one(override, (" action ", " type "), f"{override_name} allow/block action")
    require_one(override, (" normalized_domain ", "UNIQUE"), f"{override_name} normalized uniqueness")
    require_all(override, (" created_at ", " updated_at "), override_name)

    require_all(
        AEGIS,
        ("g_aegisxd_config_db", "aegisxd_config_prepare", policy_name, override_name),
        "content-filter config.db reads and writes",
    )


def test_ubus_get_list_set_delete_and_override_handlers_are_production() -> None:
    contracts = {
        "content policy get": ("content_policy_get",),
        "content policy list": ("content_policy_list", "list_content_policies"),
        "content policy set": ("set_content_policy", "content_policy_set"),
        "content policy delete": ("delete_content_policy", "content_policy_delete"),
        "domain override list": ("domain_overrides", "domain_overrides_list", "list_domain_overrides"),
        "domain override add": ("add_domain_override", "domain_override_add"),
        "domain override delete": ("remove_domain_override", "domain_override_delete"),
    }
    for scope, methods in contracts.items():
        method, handler = ubus_handler_any(methods, scope)
        assert handler != "aegisxd_handle_safe_disabled", (
            f"{method} must not use the safe_not_implemented handler"
        )
        body = function_body(UBUS, handler)
        assert "safe_not_implemented" not in body
        assert "aegisxd_handle_safe_disabled" not in body
        assert "aegisxd_send_json" in body, f"{method} must return its production result"
        require_one(
            body,
            ("aegisxd_content_", "aegisxd_domain_override"),
            f"{method} production control-plane call",
        )


def test_authenticated_rest_has_read_write_and_delete_routes_with_rbac() -> None:
    auth_pos = WEBD.find("jmx_app_validate_token_ex(req.auth_token")
    assert auth_pos >= 0, "webd authenticated route gate is missing"
    for path in (
        "/api/v1/aegis/content-policy",
        "/api/v1/aegis/domain-overrides",
    ):
        assert WEBD.find(f'"{path}"', auth_pos) > auth_pos, f"{path} must be behind bearer authentication"

    policy = route_window("/api/v1/aegis/content-policy")
    require_all(policy, ('req.method, "GET"', 'req.method, "POST"'), "content-policy collection REST")
    require_one(policy, ('req.method, "PUT"', 'req.method, "PATCH"'), "content-policy update REST")
    require_all(
        WEBD,
        ('"content_policy_get"', '"content_policy_list"', '"set_content_policy"'),
        "content-policy REST to ubus forwarding",
    )
    assert '"/api/v1/aegis/content-policy/"' in WEBD
    policy_item = route_window("/api/v1/aegis/content-policy/")
    require_all(policy_item, ('req.method, "GET"', 'req.method, "DELETE"'), "content-policy item REST")
    require_one(
        policy_item,
        ('"delete_content_policy"', '"content_policy_delete"'),
        "content-policy delete forwarding",
    )

    overrides = route_window("/api/v1/aegis/domain-overrides")
    require_all(overrides, ('req.method, "GET"', 'req.method, "POST"'), "domain-overrides REST")
    require_one(overrides, ('req.method, "PUT"', 'req.method, "PATCH"'), "domain-overrides update REST")
    require_one(
        overrides,
        ('"domain_overrides"', '"domain_overrides_list"', '"list_domain_overrides"'),
        "domain-overrides list forwarding",
    )
    require_all(WEBD, ('"add_domain_override"', '"remove_domain_override"'), "domain override writes")
    assert (
        '"/api/v1/aegis/domain-overrides/"' in WEBD
        or '"/api/v1/aegis/domain-overrides/delete"' in WEBD
    ), "domain override authenticated DELETE route is missing"

    require_all(
        PERMS,
        (
            '{ "/api/v1/aegis/content-policy",        "GET",',
            '{ "/api/v1/aegis/content-policy",        "POST,PUT,PATCH",',
            '{ "/api/v1/aegis/content-policy/",       "GET",',
            '{ "/api/v1/aegis/domain-overrides",      "GET",',
            '{ "/api/v1/aegis/domain-overrides",      "POST,PUT",',
        ),
        "explicit Aegis content-filter REST RBAC",
    )
    assert re.search(
        r'\{\s*"/api/v1/aegis/content-policy/"\s*,\s*"[^"]*DELETE[^"]*"\s*,\s*JMX_RISK_MEDIUM\s*\}',
        PERMS,
    ), "content-policy DELETE must have explicit medium-risk RBAC"
    assert re.search(
        r'\{\s*"/api/v1/aegis/domain-overrides(?:/|/delete)"\s*,\s*"[^"]*DELETE[^"]*"\s*,\s*JMX_RISK_MEDIUM\s*\}',
        PERMS,
    ), "domain override DELETE must have explicit medium-risk RBAC"
    assert "JMX_RISK_LOW" in PERMS and "JMX_RISK_MEDIUM" in PERMS


def test_content_filter_mode_is_strictly_off_enhanced_or_basic() -> None:
    validate = function_body_any(
        AEGIS,
        ("content_mode_ok", "aegisxd_content_filter_mode_valid", "aegisxd_content_mode_valid"),
        "strict content-filter mode validator",
    )
    require_all(validate, ('"off"', '"enhanced"', '"basic"'), "content-filter mode enum")
    compared = set(re.findall(
        r'(?:strcmp|strcasecmp)\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*"([a-z_]+)"',
        validate,
    ))
    assert compared == {"off", "enhanced", "basic"}, (
        f"content-filter mode validator must accept exactly off/enhanced/basic; found {sorted(compared)}"
    )
    assert '"monitor"' not in validate and '"protect"' not in validate
    require_one(
        AEGIS,
        ("invalid_content_policy_mode", "invalid_content_filter_mode", "content_filter_mode_invalid"),
        "invalid content-filter mode error",
    )


def test_scope_schedule_and_safe_search_boundaries_are_explicit() -> None:
    canonical = function_body_any(
        AEGIS,
        ("content_canonical_object", "aegisxd_content_canonical_object"),
        "content-policy validator",
    )
    require_all(canonical, ('"all"', '"always"'), "supported scope and schedule")
    require_all(
        canonical,
        (
            '"devices"',
            '"networks"',
            '"content_scope_not_supported"',
            '"content_schedule_not_supported"',
            "content_safe_search_parse",
        ),
        "scope/schedule blockers and Safe Search parser",
    )
    require_all(canonical, ('"ad_block"', '"categories"'), "Phase 1 filter controls")

    capabilities = function_body_any(
        AEGIS,
        ("content_capabilities", "aegisxd_content_capabilities"),
        "content-filter capabilities",
    )
    require_all(
        capabilities,
        (
            '"all_scope_supported"',
            '"device_scope_supported"',
            '"network_scope_supported"',
            '"schedule_supported"',
            '"safe_search_supported"',
            '"ad_block_supported"',
        ),
        "content capability flags",
    )
    assert re.search(
        r'"all_scope_supported"\s*,\s*json_object_new_boolean\(\s*1\s*\)',
        capabilities,
    ), "scope=all must be advertised as supported"
    for capability in (
        "device_scope_supported",
        "network_scope_supported",
        "schedule_supported",
    ):
        assert re.search(
            rf'"{capability}"\s*,\s*json_object_new_boolean\(\s*0\s*\)',
            capabilities,
        ), f"{capability} must remain false until its dataplane is implemented"
    assert re.search(
        r'"safe_search_supported"\s*,\s*json_object_new_boolean\(\s*1\s*\)',
        capabilities,
    ), "Safe Search must be advertised after its guarded DNS dataplane is implemented"

    validate = function_body_any(
        AEGIS,
        ("aegisxd_content_policy_validate_json",),
        "content-policy preview validation",
    )
    require_all(validate, ('"blockers"', '"dry_run"', '"dataplane_changed"'), "validation preview")
    assert re.search(
        r'"dataplane_changed"\s*,\s*json_object_new_boolean\(\s*0\s*\)',
        validate,
    ), "validation preview must not claim a dataplane mutation"


def test_domain_overrides_are_normalized_and_allow_block_conflicts_fail() -> None:
    normalize = function_body_any(
        AEGIS,
        ("content_domain_normalize", "aegisxd_domain_normalize", "aegisxd_content_domain_normalize"),
        "domain normalization",
    )
    require_one(normalize, ("tolower", "g_ascii_strdown"), "lower-case domain normalization")
    require_one(normalize, ("trailing", "n - 1", "len - 1", "length - 1"), "trailing-dot normalization")
    require_one(AEGIS, ("invalid_domain", "domain_invalid"), "invalid domain rejection")

    validate = function_body_any(
        AEGIS,
        (
            "aegisxd_domain_override_set_json",
            "aegisxd_domain_override_validate",
            "aegisxd_content_domain_override_validate",
        ),
        "domain override validator",
    )
    require_all(validate, ('"allow"', '"block"'), "domain override action enum")
    require_all(
        AEGIS,
        ("aegis_domain_overrides", "domain_override_conflict"),
        "allow/block conflict query and error",
    )
    assert re.search(
        r"SELECT[^;\"]*(?:action|type)[^;\"]*FROM\s+aegis_domain_overrides|"
        r"SELECT[^;\"]*FROM\s+aegis_domain_overrides[^;\"]*(?:action|type)",
        c_string_literals(AEGIS),
        re.IGNORECASE,
    ), "conflict validation must read the authoritative override table"


def test_mutations_require_confirm_support_dry_run_and_rollback() -> None:
    preview = function_body_any(
        AEGIS,
        ("aegisxd_content_policy_validate_json",),
        "content-filter preview validator",
    )
    require_all(
        preview,
        ('"dry_run"', '"confirm_required"', '"changed"', '"dataplane_changed"'),
        "content-filter validation preview",
    )
    assert "BEGIN IMMEDIATE" not in preview, "preview must not open a write transaction"

    mutations = (
        ("aegisxd_content_policy_set_json", "content policy set"),
        ("aegisxd_content_policy_delete_json", "content policy delete"),
        ("aegisxd_domain_override_set_json", "domain override set"),
        ("aegisxd_domain_override_delete_json", "domain override delete"),
    )
    for symbol, scope in mutations:
        mutate = function_body(AEGIS, symbol)
        require_all(mutate, ("confirm", "BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"), scope)
        require_one(mutate, ("content_apply_requested", "aegisxd_apply("), f"{scope} dataplane apply")
        require_one(mutate, ("rollback_ok", "previous configuration remains authoritative"), f"{scope} rollback")

    require_one(
        AEGIS,
        ("content_policy_apply_failed", "runtime_apply_failed", "content_filter_apply_failed"),
        "observable runtime apply failure",
    )


def test_dnsmasq_production_apply_is_reused_not_replaced_by_db_only_success() -> None:
    require_all(
        DATAPLANE,
        (
            "AEGISXD_DNSMASQ_ACTIVE_FILE",
            "aegisxd_apply_find_dnsmasq_dir",
            "aegisxd_plan_write_dnsmasq",
            "AEGISXD_DNSMASQ_RELOAD_CMD",
            "dnsmasq_reload_failed",
        ),
        "existing Aegis DNS/dnsmasq production apply",
    )
    render = function_body(DATAPLANE, "aegisxd_plan_write_dnsmasq")
    require_all(
        render,
        (
            "aegisxd_content_filter_load",
            "aegisxd_content_filter_domain_blocked",
            "aegisxd_content_filter_write_explicit_blocks",
        ),
        "policy-backed dnsmasq artifact render",
    )
    loader = function_body(AEGIS, "aegisxd_content_filter_load")
    require_all(loader, ("aegis_content_policies", "aegis_domain_overrides"), "policy/override filter load")
    require_all(loader, ('"allow"', '"block"'), "allow/block filter semantics")

    apply = function_body_any(
        AEGIS,
        ("content_apply_requested", "aegisxd_content_filter_apply", "aegisxd_content_dns_apply"),
        "content-filter production apply",
    )
    require_one(apply, ("aegisxd_apply(", "aegisxd_dns_filter_apply("), "reuse guarded DNS apply")
    assert "/etc/init.d/dnsmasq" not in apply, (
        "content filtering must reuse the production DNS apply instead of adding another restart path"
    )
    assert "system(" not in apply and "popen(" not in apply
    require_all(apply, ('"confirm"', '"dns_filter"'), "guarded DNS-filter apply request")
    require_one(apply, ('"apply"', '"disable"'), "real dataplane operation selection")


def test_runtime_readback_reports_installed_state_not_requested_state() -> None:
    runtime = function_body_any(
        AEGIS,
        ("aegisxd_content_filter_runtime_json", "aegisxd_content_runtime_json"),
        "content-filter runtime readback",
    )
    require_all(runtime, ('"managed"', '"active"', '"apply_state"'), "content-filter runtime state")
    require_one(runtime, ('"revision"', '"generation"'), "runtime/config correlation")
    require_one(runtime, ("active.json", "active_file"), "installed dataplane artifact readback")
    require_one(runtime, ("access(", "stat(", "fopen("), "filesystem runtime evidence")
    assert not re.search(
        r'"(?:active|runtime_active)"\s*,\s*json_object_new_boolean\(\s*1\s*\)',
        runtime,
    ), (
        "runtime active must be derived from installed state, not hard-coded true"
    )


if __name__ == "__main__":
    test_config_db_is_authoritative_for_policies_and_domain_overrides()
    test_ubus_get_list_set_delete_and_override_handlers_are_production()
    test_authenticated_rest_has_read_write_and_delete_routes_with_rbac()
    test_content_filter_mode_is_strictly_off_enhanced_or_basic()
    test_scope_schedule_and_safe_search_boundaries_are_explicit()
    test_domain_overrides_are_normalized_and_allow_block_conflicts_fail()
    test_mutations_require_confirm_support_dry_run_and_rollback()
    test_dnsmasq_production_apply_is_reused_not_replaced_by_db_only_success()
    test_runtime_readback_reports_installed_state_not_requested_state()
    print("ok: AegisX content-filter authority, API, validation, apply, rollback, and readback contracts")
