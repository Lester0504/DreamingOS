#!/usr/bin/env python3
"""U-15 source contract for controlled asynchronous factory reset.

Factory reset is destructive and intentionally outlives the HTTP/ubus request.
The API may acknowledge only a verified dispatch; the detached worker must then
run trusted fixed-argv executables and persist any post-dispatch failure.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
MAIN_SOURCE = (ROOT / "src/main.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    """Return one C function definition, including nested blocks."""
    match = re.search(rf"\b{re.escape(name)}\s*\([^;]*?\)\s*\{{", SOURCE, re.S)
    if not match:
        raise AssertionError(f"missing function: {name}")
    brace = SOURCE.index("{", match.start())
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[match.start():index + 1]
    raise AssertionError(f"unterminated function: {name}")


def definitions(prefixes: tuple[str, ...]) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*?\)\s*\{", SOURCE, re.S
    ):
        name = match.group(1)
        if name.startswith(prefixes):
            found[name] = function(name)
    return found


def string_literals(text: str) -> list[str]:
    """Return C string literal bodies; operators in C expressions are allowed."""
    return re.findall(r'"(?:\\.|[^"\\])*"', text, re.S)


HANDLER = function("jmx_flash_factory_reset")
HELPERS = definitions(("nc_factory_reset_", "jmx_factory_reset_"))
FAMILY = HANDLER + "\n" + "\n".join(HELPERS[name] for name in sorted(HELPERS))


def named_helper(*needles: str) -> tuple[str, str]:
    matches = sorted(
        name for name in HELPERS
        if all(needle in name.lower() for needle in needles)
    )
    if not matches:
        raise AssertionError(
            "missing factory-reset helper containing: " + ", ".join(needles)
        )
    name = matches[0]
    return name, HELPERS[name]


def test_confirm_is_present_strict_boolean_and_true() -> None:
    assert re.search(
        r'json_object_object_get_ex\s*\([^;]*?"confirm"\s*,', FAMILY, re.S
    ), "factory reset must require an explicit confirm member"
    assert "json_object_is_type" in FAMILY and "json_type_boolean" in FAMILY, \
        "confirm must be a JSON boolean, not a truthy string or integer"
    assert "json_object_get_boolean" in FAMILY
    assert re.search(
        r"if\s*\([^)]*!\s*json_object_get_boolean\s*\(", FAMILY, re.S
    ) or re.search(
        r"json_object_get_boolean\s*\([^;]+;[\s\S]{0,240}"
        r"if\s*\([^)]*!\s*[A-Za-z_][A-Za-z0-9_]*", FAMILY
    ), "confirm=false must be rejected"
    assert "API_CODE_ERROR" in FAMILY, \
        "missing/invalid/false confirmation must return an API error"


def test_family_has_no_shell_or_background_command_boundary() -> None:
    for token in ("nc_run_quiet(", "system(", "popen(", "pclose("):
        assert token not in FAMILY, \
            f"factory-reset family still uses a shell command boundary: {token}"
    assert not re.search(r'exec(?:l|v|ve|vp)?\s*\(\s*"/bin/sh"', FAMILY)
    assert '"/bin/sh"' not in FAMILY and '"-c"' not in FAMILY
    for literal in string_literals(FAMILY):
        assert "&&" not in literal, "factory reset must not chain commands with &&"
        assert not re.search(r"(?:^|[^&])&(?:[^&]|$)", literal), \
            "factory reset must not use shell background '&'"


def test_only_trusted_absolute_fixed_argv_is_executed() -> None:
    for path in ('"/sbin/factoryreset"', '"/sbin/reboot"'):
        assert path in FAMILY, f"missing trusted absolute executable path: {path}"
    assert '"-y"' in FAMILY, "factoryreset must receive the non-interactive -y flag"
    assert re.search(
        r'(?:char|const\s+char)\s*\*\s*(?:const\s+)?[A-Za-z0-9_]*argv\s*\[',
        FAMILY,
    ), "factory reset needs explicit argv vectors"
    assert re.search(r"\b(?:execve|fexecve|execveat)\s*\(", FAMILY), \
        "detached execution must use fixed argv plus an explicit clean environment"
    assert not re.search(r'"(?:firstboot|factoryreset|reboot)(?:\s|$)', FAMILY), \
        "bare command strings are forbidden"


def test_both_executables_are_root_owned_immutable_and_inode_bound() -> None:
    validation_names = sorted(
        name for name in HELPERS
        if any(word in name.lower() for word in ("trusted", "validate", "executable"))
    )
    validation_text = "\n".join(HELPERS[name] for name in validation_names)
    if not validation_text:
        shared_calls = re.findall(
            r"\b((?:jmx|nc)_[A-Za-z0-9_]*(?:trusted|executable)[A-Za-z0-9_]*)\s*\(",
            FAMILY,
        )
        shared_defs = []
        for name in sorted(set(shared_calls)):
            try:
                shared_defs.append(function(name))
            except AssertionError:
                pass
        validation_text = "\n".join(shared_defs)
    assert validation_text, \
        "factory reset must validate both executables or reuse a shared trusted-executable helper"
    assert "O_NOFOLLOW" in validation_text and "fstat(" in validation_text
    assert "S_ISREG" in validation_text and re.search(r"st_uid\s*!=\s*0|st_uid\s*==\s*0", validation_text)
    assert re.search(r"S_IWGRP|S_IWOTH|022", validation_text), \
        "group/world-writable executables must be rejected"
    assert re.search(r"S_IXUSR|0111|S_IXGRP|S_IXOTH", validation_text), \
        "trusted executable must have an execution bit"
    assert "st_dev" in validation_text and "st_ino" in validation_text, \
        "device/inode identity must be captured and revalidated or fd-bound"
    calls = sum(FAMILY.count(f"{name}(") for name in validation_names)
    assert calls >= 2 or "fexecve(" in FAMILY or "execveat(" in FAMILY, \
        "factoryreset and reboot must both cross the trusted-executable boundary"


def test_dispatch_handshake_precedes_success_response() -> None:
    dispatch_name, dispatch = named_helper("dispatch")
    assert "pipe2(" in dispatch or "pipe(" in dispatch
    assert "socketpair(" in dispatch, "release gate must be a socketpair"
    assert "O_CLOEXEC" in dispatch or "SOCK_CLOEXEC" in dispatch
    assert dispatch.count("fork(") >= 2, "worker must use a double fork"
    assert "setsid(" in dispatch
    assert "poll(" in dispatch and "read(" in dispatch and "waitpid(" in dispatch, \
        "parent must verify dispatcher/detached-worker handshake"
    assert re.search(r"release_(?:gate|fd)|gate_(?:fd|pair)", dispatch), \
        "dispatch must retain a release gate until the API path accepts it"
    assert f"{dispatch_name}(" in HANDLER
    dispatch_call = HANDLER.find(f"{dispatch_name}(")
    success = HANDLER.find("API_CODE_SUCCESS")
    assert dispatch_call >= 0 and success > dispatch_call, \
        "API success must be constructed only after dispatch handshake"
    assert re.search(
        rf"if\s*\([^)]*{re.escape(dispatch_name)}\s*\([^;]+(?:!=\s*0|<\s*0)",
        HANDLER,
        re.S,
    ), "dispatch failure must be explicitly rejected"


def test_worker_is_delayed_fd_clean_and_environment_clean() -> None:
    _, dispatch = named_helper("dispatch")
    _, worker = named_helper("worker")
    delayed_family = dispatch + "\n" + worker
    assert re.search(r"sleep\s*\(\s*[A-Za-z_0-9]+\s*\)", delayed_family) or (
        "nanosleep(" in delayed_family
        and re.search(r"tv_sec\s*=\s*[1-9][0-9]*", delayed_family)
    ) or (
        re.search(r"#define\s+NC_FACTORY_RESET_[A-Z0-9_]*DELAY[A-Z0-9_]*\s+[1-9][0-9]*", SOURCE)
        and "sleep(" in delayed_family
    ), "detached reset must wait at least one second after release"
    assert "_SC_OPEN_MAX" in dispatch or "close_range(" in dispatch, \
        "detached worker must close inherited descriptors"
    assert re.search(r"for\s*\([^;]*fd\s*=\s*3", dispatch) or "close_range(" in dispatch
    assert re.search(r"(?:clean_)?envp\s*\[", FAMILY), \
        "worker must pass a small explicit clean environment"
    assert "execv(" not in FAMILY and "execvp(" not in FAMILY, \
        "execv/execvp would inherit or search the caller environment"


def test_factoryreset_y_is_checked_then_reboot_is_dispatched_once() -> None:
    _, worker = named_helper("worker")
    exec_helpers = "\n".join(
        body for name, body in HELPERS.items()
        if name != "nc_factory_reset_worker"
        and any(part in name.lower() for part in ("exec_wait", "wait_fd"))
    )
    worker_family = worker + "\n" + exec_helpers
    assert '"/sbin/factoryreset"' in worker and '"-y"' in worker
    assert '"-r"' not in worker_family, \
        "factoryreset -r already reboots; the selected -y contract uses one explicit reboot"
    assert worker.count('"/sbin/reboot"') == 1, \
        "the -y path must issue exactly one explicit reboot"
    assert "waitpid(" in worker_family, \
        "worker must wait for factoryreset before deciding whether to reboot"
    for token in ("WIFEXITED", "WEXITSTATUS", "WIFSIGNALED"):
        assert token in worker_family, f"factoryreset result handling omits {token}"
    reset_pos = worker.find('"/sbin/factoryreset"')
    reboot_pos = worker.find('"/sbin/reboot"')
    assert 0 <= reset_pos < reboot_pos, "reboot must follow successful factoryreset -y"


def test_factory_reset_is_single_flight_and_worker_is_fresh_exec() -> None:
    _, dispatch = named_helper("dispatch")
    lock_helpers = "\n".join(
        body for name, body in HELPERS.items() if "lock" in name.lower()
    )
    assert "flock(" in lock_helpers and "LOCK_EX" in lock_helpers and "LOCK_NB" in lock_helpers, \
        "factory reset must reject concurrent/retried destructive dispatches"
    assert "lock_fd" in dispatch or "lockfd" in dispatch, \
        "the single-flight lock must survive until the detached worker starts"
    assert '"--factory-reset-worker"' in dispatch
    assert "fexecve(" in dispatch, \
        "the detached worker must exec a fresh single-threaded image before complex work"
    assert re.search(r"factory_reset_in_progress", HANDLER), \
        "a duplicate request needs an explicit busy result"
    assert '"--factory-reset-worker"' in MAIN_SOURCE
    assert "jmx_flash_factory_reset_worker_main" in MAIN_SOURCE, \
        "the fresh executable image must enter the dedicated reset worker before core startup"


def test_detached_failures_are_persisted_root_only_and_atomically() -> None:
    _, persist = named_helper("status", "write")
    assert any(path in FAMILY for path in (
        "/etc/dreamingwrt/", "/var/lib/dreamingwrt/", "/overlay/upper/etc/dreamingwrt/"
    )), "failure status needs a persistent root-owned path"
    for field in ('"stage"', '"reason"', '"timestamp"'):
        assert field in persist, f"persistent failure status omits {field}"
    assert re.search(r"0600|S_IRUSR\s*\|\s*S_IWUSR", persist), \
        "failure status must be root-only"
    nofollow = "O_NOFOLLOW" in persist
    atomic = (
        re.search(r"openat?\s*\([^;]*O_EXCL", persist, re.S)
        and "fsync(" in persist
        and ("rename(" in persist or "renameat(" in persist)
    )
    assert nofollow or atomic, \
        "status publication must resist symlink races through O_NOFOLLOW or atomic replace"
    assert "fchmod(" in persist or "chmod(" in persist, \
        "status mode must be enforced even under an unexpected umask"
    _, worker = named_helper("worker")
    for stage in ("factoryreset", "reboot"):
        assert stage in worker, f"worker does not identify the {stage} failure stage"
    assert persist.split("(", 1)[0].split()[-1] in worker or "status_write(" in worker, \
        "detached worker must persist post-dispatch execution failures"


def test_api_reports_dispatch_truth_not_reset_completion() -> None:
    for field in ('"accepted"', '"dispatched"'):
        assert field in HANDLER, f"success response omits dispatch field {field}"
    assert re.search(r'"ok"[^;]*json_object_new_boolean\(0\)', FAMILY)
    assert re.search(r'"ok"[^;]*json_object_new_boolean\(1\)', FAMILY)
    assert "API_CODE_ERROR" in FAMILY and "API_CODE_SUCCESS" in FAMILY
    assert not re.search(r'"(?:completed|reset_completed)"', HANDLER), \
        "API cannot claim a detached destructive action has completed"
    assert re.search(r'"(?:state|status)"[^;]*"(?:accepted|dispatched)"', HANDLER), \
        "successful response must explicitly describe dispatch acceptance"


if __name__ == "__main__":
    test_confirm_is_present_strict_boolean_and_true()
    test_family_has_no_shell_or_background_command_boundary()
    test_only_trusted_absolute_fixed_argv_is_executed()
    test_both_executables_are_root_owned_immutable_and_inode_bound()
    test_dispatch_handshake_precedes_success_response()
    test_worker_is_delayed_fd_clean_and_environment_clean()
    test_factoryreset_y_is_checked_then_reboot_is_dispatched_once()
    test_factory_reset_is_single_flight_and_worker_is_fresh_exec()
    test_detached_failures_are_persisted_root_only_and_atomically()
    test_api_reports_dispatch_truth_not_reset_completion()
    print("ok: U-15 factory reset is confirmed, trusted, dispatched, and auditable")
