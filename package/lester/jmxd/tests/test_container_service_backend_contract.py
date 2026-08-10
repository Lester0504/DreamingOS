#!/usr/bin/env python3
"""Static production contract for the container-service backend.

The suite intentionally inspects production sources instead of supplying a
mock Docker/LXC implementation.  Unsupported operations are valid only when
their capability and REST behavior are both explicitly disabled.  Long-lived
operations must use a queryable task lifecycle rather than holding an HTTP or
ubus request open while the runtime command completes.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
NETCONFIG_PATH = SRC / "jmx_netconfig_db.c"
UBUS_PATH = SRC / "jmx_dreamingwrt_api.c"
WEBD_PATH = SRC / "webd/jmx_app_api.c"
PERMS_PATH = SRC / "webd/jmx_app_perms.c"


def read_required(path: Path) -> str:
    assert path.is_file(), f"required production file is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


NETCONFIG = read_required(NETCONFIG_PATH)
UBUS = read_required(UBUS_PATH)
WEBD = read_required(WEBD_PATH)
PERMS = read_required(PERMS_PATH)


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} is missing contract evidence: {missing}"


def require_one(text: str, needles: tuple[str, ...], scope: str) -> str:
    for needle in needles:
        if needle in text:
            return needle
    raise AssertionError(f"{scope} needs one of these production evidences: {needles}")


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
            line_comment = char != "\n"
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


def route_window(path: str, radius: int = 4200) -> str:
    pos = WEBD.find(f'"{path}"')
    assert pos >= 0, f"authenticated REST route is missing: {path}"
    return WEBD[max(0, pos - radius):min(len(WEBD), pos + radius)]


def route_section(start_path: str, end_path: str) -> str:
    start = WEBD.find(f'"{start_path}"')
    end = WEBD.find(f'"{end_path}"', start + 1)
    assert start >= 0, f"authenticated REST route is missing: {start_path}"
    assert end > start, f"could not delimit REST route block {start_path} before {end_path}"
    return WEBD[start:end]


def test_capabilities_are_stable_per_operation_and_match_runtime_availability() -> None:
    summary = function_body(NETCONFIG, "jmx_container_service_get")
    docker = function_body(NETCONFIG, "jmx_container_docker_get")
    lxc = function_body(NETCONFIG, "jmx_container_lxc_get")

    require_all(summary, ('"contract_version"', '"capabilities"'), "container-service stable envelope")
    for capability in (
        "container_start", "container_stop", "container_restart", "container_pause",
        "container_unpause", "container_rename", "container_restart_policy",
        "container_logs", "container_stats", "container_create", "container_remove",
        "image_read", "network_read", "volume_read", "service_read", "config_read",
    ):
        assert f'"{capability}"' in docker, f"Docker needs stable capability: {capability}"
    require_one(docker, ('"capability_reasons"', '"blockers"'), "Docker capability blockers")
    require_all(lxc, ('"actions"', '"missing_commands"'), "LXC action capability and blockers")
    assert "nc_cmd_exists" in lxc, "LXC capabilities must derive from installed commands"


def test_docker_container_minimum_lifecycle_has_real_handlers_and_routes() -> None:
    command_symbols = (
        "jmx_docker_container_start", "jmx_docker_container_stop",
        "jmx_docker_container_restart", "jmx_docker_container_pause",
        "jmx_docker_container_unpause", "jmx_docker_container_rename",
        "jmx_docker_container_restart_policy",
        "jmx_docker_container_remove",
    )
    for symbol in command_symbols:
        body = function_body(NETCONFIG, symbol)
        require_one(body, ("nc_exec_argv_json", "nc_container_task_submit"), f"{symbol} runtime operation")
    for symbol in ("jmx_docker_container_logs", "jmx_docker_container_stats"):
        body = function_body(NETCONFIG, symbol)
        require_one(body, ("nc_exec_argv_capture", "nc_container_task_submit"), f"{symbol} bounded runtime readback")

    route = route_section(
        "/api/v1/container_service/docker/container/",
        "/api/v1/container_service/docker/image/",
    )
    require_all(
        route,
        (
            '"start"', '"stop"', '"restart"', '"pause"', '"unpause"',
            '"rename"', '"restart-policy"', '"logs"', '"stats"',
            '"docker_container_action"', '"docker_container_logs"',
            '"docker_container_stats"', 'req.method, "DELETE"',
        ),
        "Docker container REST lifecycle",
    )


def test_docker_image_network_volume_service_and_config_routes_are_complete() -> None:
    routes = {
        "/api/v1/container_service/docker/image/": ("docker_image_action", "pull", "remove"),
        "/api/v1/container_service/docker/network/": ("docker_network_action", "create", "remove"),
        "/api/v1/container_service/docker/volume/": ("docker_volume_action", "create", "remove"),
        "/api/v1/container_service/docker/service/": ("docker_service_status", "docker_service_action"),
        "/api/v1/container_service/docker/config": ("docker_config_get", "docker_config_set"),
    }
    for path, evidence in routes.items():
        require_all(route_window(path), evidence, f"container resource REST {path}")

    require_all(
        UBUS,
        (
            '"docker_image_action"', '"docker_network_action"', '"docker_volume_action"',
            '"docker_service_status"', '"docker_service_action"',
            '"docker_config_get"', '"docker_config_set"',
        ),
        "container resource ubus methods",
    )


def test_ids_names_and_all_command_parameters_are_strictly_validated() -> None:
    # nc_docker_id_valid() was refactor residue and is gone; every container
    # entry point validates through nc_docker_resource_id_valid(), which is
    # strictly tighter (first character must be alphanumeric, and ':' '@' '+'
    # are rejected). Anchor on the validator that is actually called.
    id_validator = function_body(NETCONFIG, "nc_docker_resource_id_valid")
    name_validator = function_body(NETCONFIG, "nc_docker_name_valid")
    require_one(id_validator, ("strlen", "strnlen"), "bounded Docker ID validation")
    require_one(name_validator, ("strlen", "strnlen"), "bounded Docker name validation")
    assert "c == '/'" not in id_validator, "container IDs must not accept image-reference path separators"
    image_id_validator = function_body(NETCONFIG, "nc_docker_image_id_valid")
    require_all(image_id_validator, ("strlen", "c == ':'", "c == '/'"),
                "bounded Docker image reference validation")
    image_remove = function_body(NETCONFIG, "jmx_docker_image_remove")
    require_all(image_remove, ("nc_docker_image_id_valid", "nc_docker_confirmation_required",
                               "nc_exec_argv_json"), "safe Docker image removal")
    for symbol in ("jmx_docker_container_start", "jmx_docker_container_stop",
                   "jmx_docker_container_restart", "jmx_docker_container_pause",
                   "jmx_docker_container_unpause", "jmx_docker_container_remove"):
        require_one(function_body(NETCONFIG, symbol), ('"invalid_id"', "nc_docker_invalid"),
                    f"{symbol} stable invalid-ID response")

    create = function_body(NETCONFIG, "jmx_docker_container_create")
    require_all(create, ("nc_docker_confirmation_required", "nc_docker_create_normalize",
                         "nc_container_job_submit", '"container_create"'),
                "validated asynchronous container create path")
    require_all(NETCONFIG, ("nc_docker_driver_valid",), "strict Docker command parameter validators")
    for symbol in ("jmx_docker_container_stop", "jmx_docker_container_restart"):
        body = function_body(NETCONFIG, symbol)
        require_one(body, ("NC_CONTAINER_TIMEOUT_MAX", "nc_container_timeout_valid", "nc_docker_bounded_int"),
                    f"{symbol} bounded timeout")


def test_destructive_operations_require_explicit_confirmation() -> None:
    destructive = (
        "jmx_docker_container_remove", "jmx_docker_image_remove",
        "jmx_docker_image_prune", "jmx_docker_network_remove",
        "jmx_docker_network_prune", "jmx_docker_volume_remove",
        "jmx_docker_volume_prune", "jmx_docker_config_set",
    )
    missing = []
    for symbol in destructive:
        body = function_body(NETCONFIG, symbol)
        if not any(token in body for token in ("confirm", "confirmed", "confirmation_required", "nc_docker_capability_disabled")):
            missing.append(symbol)
    assert not missing, f"destructive functions lack explicit confirmation: {missing}"

    route = route_window("/api/v1/container_service/docker/container/")
    require_one(route, ("app_require_confirm", "confirmation_required"), "REST destructive confirmation gate")


def test_rest_is_authenticated_and_container_writes_have_explicit_rbac() -> None:
    auth_gate = WEBD.find("jmx_app_validate_token_ex(req.auth_token")
    container_routes = WEBD.find('"/api/v1/container_service"')
    assert auth_gate >= 0 and container_routes > auth_gate, "all container-service routes must follow bearer authentication"
    require_all(
        WEBD,
        ("jmx_perm_route_risk(req.method, req.path)", "jmx_perm_check(role, risk)"),
        "container REST role enforcement",
    )
    assert '"/api/v1/container_service"' in PERMS, (
        "container-service must have an explicit route-risk entry; default risk is not sufficient RBAC"
    )
    perms_window = PERMS[PERMS.find('"/api/v1/container_service"') - 1000:]
    require_all(perms_window, ("POST", "PUT", "DELETE", "JMX_RISK_"), "container write RBAC methods")


def test_every_mutation_family_has_audit_hook() -> None:
    actions = (
        "docker.container.start", "docker.container.stop", "docker.container.restart",
        "docker.container.pause", "docker.container.unpause", "docker.container.rename",
        "docker.container.restart_policy", "docker.container.create", "docker.container.remove",
        "docker.image.pull", "docker.image.remove", "docker.network.create",
        "docker.network.remove", "docker.volume.create", "docker.volume.remove",
        "docker.service", "docker.config.set",
    )
    missing = [action for action in actions if f'"{action}"' not in WEBD]
    assert not missing, f"container mutations lack audit hooks: {missing}"
    assert "jmx_app_audit_log" in route_window("/api/v1/container_service/docker/container/"), (
        "container mutation routes must call the authenticated audit hook"
    )


def test_long_operations_are_async_or_explicitly_disabled_end_to_end() -> None:
    long_operations = {
        "image_pull": ("jmx_docker_image_pull", '"pull"'),
        "container_create": ("jmx_docker_container_create", '"create"'),
    }
    capability_source = function_body(NETCONFIG, "jmx_container_docker_get")
    for capability, (symbol, action_literal) in long_operations.items():
        operation = function_body(NETCONFIG, symbol)
        route = route_window("/api/v1/container_service/docker/image/" if capability == "image_pull" else "/api/v1/container_service/docker/container/")
        ubus_handler = function_body(
            UBUS,
            "dw_handle_docker_image_action" if capability == "image_pull" else "dw_handle_docker_container_action",
        )
        async_evidence = any(
            token in operation + route + ubus_handler + NETCONFIG
            for token in ("task_id", "job_id", "task_submit", "worker_submit", "fork(", "posix_spawn")
        )
        disabled_evidence = (
            f'"{capability}"' in capability_source
            and f'"{capability}", json_object_new_boolean(0)' in capability_source
            and action_literal in route
            and any(token in route + ubus_handler for token in ("capability_disabled", "not_supported", "unsupported"))
        )
        assert async_evidence or disabled_evidence, (
            f"{capability} must return a queryable asynchronous task, or advertise and enforce capability=false; "
            "a synchronous docker command behind REST/ubus is forbidden"
        )


def test_image_pull_has_persistent_queryable_job_lifecycle() -> None:
    pull = function_body(NETCONFIG, "jmx_docker_image_pull")
    get_job = function_body(NETCONFIG, "jmx_docker_job_get")
    list_jobs = function_body(NETCONFIG, "jmx_docker_jobs_list")
    cancel = function_body(NETCONFIG, "jmx_docker_job_cancel")
    job_row = function_body(NETCONFIG, "nc_container_job_row")
    require_all(pull, ('nc_container_job_submit', '"image_pull"',
                       'registry_credentials_unsupported'),
                "asynchronous Docker image pull")
    require_all(function_body(NETCONFIG, "nc_container_job_spawn"),
                ('fork()', '"--container-job-worker"'), "shared Docker job spawn")
    require_all(NETCONFIG, (
        '"/etc/dreamingwrt/dreamingwrt.db"', '"CREATE TABLE IF NOT EXISTS container_job',
        '"docker", "image", "pull", "--quiet"', 'NC_CONTAINER_OUTPUT_MAX',
        'jmx_docker_job_worker', 'nc_exec_argv_capture_ex',
    ), "Docker job worker and runtime storage")
    require_all(function_body(NETCONFIG, "jmx_docker_job_worker"),
                ('nc_exec_argv_capture_ex', '&result, 0'),
                "Docker pull stays in the cancellable worker process group")
    require_all(get_job, ('nc_container_job_row', '"container_job_not_found"'),
                "Docker job status")
    require_all(job_row, ('"container-job.v1"', '"output_truncated"'),
                "Docker job response contract")
    require_all(list_jobs, ('"items"', 'NC_CONTAINER_JOB_RETENTION_SEC',
                            'NC_CONTAINER_JOB_MAX_ROWS'), "Docker job list and retention")
    require_all(cancel, ('"cancelled"', 'nc_container_job_worker_matches',
                         'SIGTERM', 'SIGKILL'), "Docker job cancellation")
    require_all(function_body(NETCONFIG, "nc_container_job_worker_matches"),
                ('NC_CONTAINER_JOB_WORKER_COMM', '"/proc/%ld/comm"',
                 '"/proc/%ld/cmdline"', '"--container-job-worker"'),
                "Docker job worker identity check")
    require_all(UBUS, ('"docker_jobs_list"', '"docker_job_get"',
                       '"docker_job_cancel"'), "Docker job ubus")
    require_all(WEBD, ('"/api/v1/container_service/docker/jobs"',
                       '"docker_jobs_list"', '"docker_job_get"',
                       '"docker_job_cancel"', '"docker.job.cancel"'),
                "Docker job REST and audit")
    require_all(PERMS, ('"/api/v1/container_service/docker/jobs"',
                        '"/api/v1/container_service/docker/jobs/"'),
                "Docker job RBAC")


def test_container_create_reuses_persistent_job_with_strict_schema_and_fixed_argv() -> None:
    create = function_body(NETCONFIG, "jmx_docker_container_create")
    normalize = function_body(NETCONFIG, "nc_docker_create_normalize")
    submit = function_body(NETCONFIG, "nc_container_job_submit")
    worker = function_body(NETCONFIG, "jmx_docker_job_worker")
    db_open = function_body(NETCONFIG, "nc_container_job_db_open")
    job_row = function_body(NETCONFIG, "nc_container_job_row")
    ubus_create = function_body(UBUS, "dw_handle_docker_container_action")
    capability = function_body(NETCONFIG, "jmx_container_docker_get")

    require_all(create, ('nc_docker_confirmation_required', 'nc_cmd_exists("docker")',
                         'nc_docker_create_normalize', 'nc_container_job_submit'),
                "container create submission gates")
    require_all(normalize, ('"image"', '"name"', '"hostname"', '"restart_policy"',
                            '"network"', '"command"', '"labels"',
                            '"unsupported_container_create_field"',
                            '"host_network_unsupported"', 'JSON_C_TO_STRING_PLAIN'),
                "container create allowlist and canonical JSON")
    allowlist = function_body(NETCONFIG, "nc_docker_create_field_supported")
    for forbidden in ("env", "mount", "device", "cap_add", "privileged", "ports",
                      "registry_auth", "password"):
        assert f'"{forbidden}"' not in allowlist, f"container create must not allow {forbidden}"
    require_all(submit, ('"BEGIN IMMEDIATE"', 'NC_CONTAINER_JOB_ACTIVE_MAX',
                         'request_json', '"container_create"', 'nc_container_job_spawn'),
                "shared persistent atomic job submission")
    require_all(db_open, ('"ALTER TABLE container_job ADD COLUMN', '"request_json"',
                          '"result_id"', '"result_name"', '"output_truncated"',
                          '"PRAGMA table_info(container_job)"'),
                "idempotent compatible container_job migration")
    require_all(worker, ('strcmp(kind, "container_create")', 'json_tokener_parse(request_json)',
                         'nc_docker_create_normalize', 'strcmp(canonical, request_json)',
                         'NC_CREATE_ARG("docker")', 'NC_CREATE_ARG("create")',
                         'nc_exec_argv_capture_ex(argv', '&result, 0',
                         'result_id', 'result_name'),
                "container create worker revalidation and fixed argv")
    assert "system(" not in worker and "popen(" not in worker and '"/bin/sh"' not in worker
    require_all(job_row, ('"result"', '"container_id"', '"container_name"'),
                "container create structured result")
    require_all(ubus_create, ('!strcmp(action, "create")',
                              'jmx_docker_container_create(payload, data)'),
                "ubus container create dispatch")
    require_all(capability, ('"container_create", json_object_new_boolean(can_act)',
                             '"docker_command_not_found"'),
                "Docker-derived container create capability")


def test_lxc_missing_commands_disable_actions_and_routes() -> None:
    lxc = function_body(NETCONFIG, "jmx_container_lxc_get")
    require_all(lxc, ("nc_cmd_exists", '"missing_commands"', '"actions"'), "LXC command-derived capability")
    require_one(lxc, ("capability_reasons", "blockers", "missing_commands"), "LXC unavailable reason")

    handler = function_body(UBUS, "dw_handle_lxc_container_action")
    route = route_window("/api/v1/container_service/lxc/container/")
    assert any(token in handler + route for token in ("lxc_actions_supported", "missing_command", "capability_disabled")), (
        "LXC action ubus/REST must reject operations when required commands are absent"
    )


def test_lxc_write_executors_are_fail_closed_below_rest_and_ubus() -> None:
    helper = function_body(NETCONFIG, "nc_lxc_write_disabled")
    require_all(
        helper,
        ('"capability_disabled"', '"persisted"', '"applied"'),
        "LXC canonical write rejection",
    )
    symbols = (
        "jmx_lxc_container_start", "jmx_lxc_container_stop",
        "jmx_lxc_container_restart", "jmx_lxc_container_destroy",
        "jmx_lxc_container_create", "jmx_lxc_container_clone",
        "jmx_lxc_container_snapshot", "jmx_lxc_container_snapshot_restore",
        "jmx_lxc_container_config_set", "jmx_lxc_config_set",
    )
    forbidden = (
        "nc_exec_shell_json", "system(", "popen(", "fopen(", "fwrite(",
        "lxc-start", "lxc-stop", "lxc-create", "lxc-destroy", "lxc-copy",
        "lxc-snapshot", "uci set", "uci commit",
    )
    for symbol in symbols:
        body = function_body(NETCONFIG, symbol)
        assert "nc_lxc_write_disabled" in body, (
            f"{symbol} must use the canonical fail-closed helper"
        )
        assert not any(token in body for token in forbidden), (
            f"{symbol} must not retain a command or direct-file write path"
        )
    assert "nc_lxc_exec" not in NETCONFIG, (
        "the synchronous 300-second LXC shell executor must be removed"
    )


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    failures = []
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failures.append(f"{test.__name__}: {exc}")
    if failures:
        raise SystemExit("container-service contract failures:\n- " + "\n- ".join(failures))
    print("ok: container capabilities, Docker lifecycle/resources, validation, confirm, RBAC, audit, async tasks, and LXC degradation")
