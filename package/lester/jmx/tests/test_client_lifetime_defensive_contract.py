#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLIENT = (ROOT / "src/jmx_client.c").read_text()
HEADER = (ROOT / "src/jmx_client.h").read_text()
FS = (ROOT / "src/jmx_client_fs.c").read_text()
MAIN = (ROOT / "src/jmx_main.c").read_text()
V2 = (ROOT / "src/jmx_v2_nl_handler.c").read_text()


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.DOTALL)
    assert match, f"function {name} not found"
    start = match.end() - 1
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1:index]
    raise AssertionError(f"unterminated function {name}")


def test_client_object_has_owner_and_explicit_get_put() -> None:
    assert "refcount_t refs;" in HEADER
    assert "bool dying;" in HEADER
    add = function_body(CLIENT, "nf_client_add")
    assert "refcount_set(&node->refs, 1)" in add
    assert "refcount_dec_and_test(&client->refs)" in function_body(CLIENT, "af_client_put")


def test_expiry_detaches_before_blocking_cleanup_and_owner_put() -> None:
    expire = function_body(CLIENT, "check_client_expire")
    detach = expire.index("list_del_init")
    unlock = expire.index("AF_CLIENT_UNLOCK_W", detach)
    timer = expire.index("stop_client_timer", unlock)
    proc = expire.index("remove_client_proc_dir", timer)
    put = expire.index("af_client_put", proc)
    assert detach < unlock < timer < proc < put
    assert "kfree(node)" not in expire


def test_removal_shuts_timer_down_without_rearm_window() -> None:
    stop = function_body(CLIENT, "stop_client_timer")
    assert "jmx_timer_shutdown_sync(&client->client_timer)" in stop
    assert "jmx_timer_delete_sync(&client->client_timer)" not in stop


def test_proc_entry_and_open_fd_each_hold_lifetime() -> None:
    create = function_body(FS, "create_client_proc_dir")
    remove = function_body(FS, "remove_client_proc_dir")
    opened = function_body(FS, "single_client_visit_open")
    release = function_body(FS, "single_client_visit_release")
    assert "refcount_inc(&client->refs)" in create
    assert "proc_ref_held = true" in create
    assert remove.index("proc_remove") < remove.index("af_client_put")
    assert "af_client_get_if_live(client)" in opened
    assert "af_client_put(client)" in release


def test_unlocked_gateway_and_v2_paths_use_held_references() -> None:
    gateway = function_body(MAIN, "jmx_hook_gateway_handle")
    assert "af_client_get_by_ip" in gateway
    assert "af_client_get_by_ipv6" in gateway
    assert "af_client_put(client)" in gateway
    assert "AF_CLIENT_LOCK_R" not in gateway
    assert "af_client_get_by_ip" in V2
    assert "af_client_put(cli)" in V2


def test_bypass_failure_unlocks_conn_lock_and_releases_client() -> None:
    bypass = function_body(MAIN, "jmx_hook_bypass_handle")
    failure = bypass[bypass.index("conn = af_conn_find_and_add"):]
    assert failure.index("spin_unlock(&af_conn_lock)") < failure.index("goto bypass_out")
    assert "af_client_put(client)" in bypass


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("ok: client lifetime defensive contract passed")
