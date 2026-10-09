#!/usr/bin/env python3
"""Contracts that prevent a WebD worker slot from becoming a path black hole."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_module_text
WEB = webd_dispatch_text()
API_UBUS = webd_module_text("api_ubus.c")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_affinity_is_used_only_for_an_idle_worker() -> None:
    dispatch = between(
        WEB,
        "static int webd_persistent_dispatch(int fd, const char *header, size_t header_len)\n{",
        "/*\n * Dispatch backlog.",
    )
    assert "g_persistent_workers[preferred].inflight == 0" in dispatch
    assert "g_persistent_workers[preferred].inflight <" not in dispatch


def test_repeated_flowd_status_reads_use_the_fast_lane() -> None:
    fast_lane = between(
        WEB,
        "static int webd_persistent_fast_lane(const char *header, size_t header_len)\n{",
        "static int webd_persistent_dispatch",
    )
    assert '"/api/v1/flowd/status"' in fast_lane
    assert '"/api/v1/system/status"' in fast_lane


def test_parent_watchdog_replaces_a_worker_without_an_ack() -> None:
    watchdog = between(
        WEB,
        "static void webd_persistent_workers_watchdog(void)\n{",
        "static void webd_persistent_worker_ufd_cb",
    )
    assert "WEBD_PERSISTENT_WORKER_HARD_DEADLINE_MS" in watchdog
    assert "kill(g_persistent_workers[i].pid, SIGKILL);" in watchdog
    assert "webd_persistent_worker_detach(i);" in watchdog
    assert "#define WEBD_PERSISTENT_WORKER_HARD_DEADLINE_MS 90000" in WEB
    reap = between(
        WEB,
        "static void webd_child_reap_timer_cb(struct uloop_timeout *t)\n{",
        "static void webd_child_kill_tracked",
    )
    assert "webd_persistent_workers_watchdog();" in reap


def test_wan_fetches_share_one_timed_join_deadline() -> None:
    join = between(
        WEB,
        "static struct json_object *webd_wan_fetch_join(",
        "static int webd_str_eq_nonempty",
    )
    assert "pthread_timedjoin_np" in join
    assert "task->abandoned = 1" in join
    assert "thread = task->thread" in join
    assert "kind = task->kind" in join
    assert join.index("kind = task->kind") < join.index("task->abandoned = 1")
    assert "pthread_detach(thread)" in join
    assert "pthread_join(task->thread, NULL)" not in join
    assert "webd_wan_fetch_kind_name(kind)" in join
    assert "_exit(124)" not in join
    assert "partial_sources" in join
    response = between(
        WEB,
        "static struct json_object *webd_network_wans_response(int *status)\n{",
        "static struct json_object *webd_route_status_response",
    )
    assert "struct timespec fetch_deadline" in response
    assert "webd_timespec_add_ms(&fetch_deadline, WEBD_WAN_FETCH_DEADLINE_MS);" in response
    assert response.count("&fetch_deadline, partial_sources)") >= 5
    assert '"partial_sources"' in response
    assert '"wan_runtime_sources_partial"' in response

    start = between(
        WEB,
        "static struct webd_wan_fetch_task *webd_wan_fetch_start(",
        "static struct json_object *webd_wan_fetch_join(",
    )
    assert "task->finished = 1;" in start
    assert "webd_wan_fetch_thread(task);" not in start


def test_lookup_and_invoke_are_bounded_by_one_budget() -> None:
    invoke = between(
        API_UBUS,
        "struct json_object *app_ubus_invoke_object_diag(const char *object,",
        "struct json_object *app_ubus_invoke_object_timeout",
    )
    guard = between(
        API_UBUS,
        "struct app_ubus_deadline_guard {",
        "/* Optional per-call failure diagnosis",
    )
    assert "pthread_cond_timedwait" in guard
    assert "shutdown(fd, SHUT_RDWR);" in guard
    assert "_exit(124);" in guard
    assert "if (!completed)" in guard
    assert "g_listen_fd.fd < 0" not in guard
    assert "webd_timespec_remaining_ms(&guard.deadline)" in invoke
    assert invoke.count("app_ubus_request_build_lock_until(&guard.deadline)") >= 2
    assert "ubus_lookup_id(uctx, object, &id)" in invoke
    assert "ubus_invoke_async(uctx, id, method" in invoke
    async_invoke = invoke.index("ubus_invoke_async(uctx, id, method")
    invoke_unlock = invoke.index(
        "pthread_mutex_unlock(&g_app_ubus_request_build_lock);", async_invoke
    )
    complete = invoke.index("ubus_complete_request(uctx, &req, remaining_ms)")
    assert async_invoke < invoke_unlock < complete
    assert "app_ubus_deadline_guard_start" in invoke
    assert "app_ubus_deadline_guard_finish" in invoke
    assert "app_ubus_deadline_init(&call_deadline, timeout_ms)" in invoke
    assert "app_ubus_context_get_until(&call_deadline)" in invoke


if __name__ == "__main__":
    test_affinity_is_used_only_for_an_idle_worker()
    test_repeated_flowd_status_reads_use_the_fast_lane()
    test_parent_watchdog_replaces_a_worker_without_an_ack()
    test_wan_fetches_share_one_timed_join_deadline()
    test_lookup_and_invoke_are_bounded_by_one_budget()
