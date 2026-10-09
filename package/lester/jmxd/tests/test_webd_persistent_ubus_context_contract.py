#!/usr/bin/env python3
"""Static ownership contract for WebD's bounded reusable UBus contexts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_module_text
WEB = webd_dispatch_text()
JMX_APP = webd_module_text("jmx_app_api.c")
API_UBUS = webd_module_text("api_ubus.c")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_persistent_workers_drop_inherited_ubus_before_serving() -> None:
    worker = between(
        WEB,
        "static void webd_persistent_worker_prepare_child(int control_fd)\n{",
        "static void webd_persistent_worker_loop",
    )
    assert "app_ubus_context_drop_in_child();" in worker
    drop = between(
        API_UBUS,
        "void app_ubus_context_drop_in_child(void)\n{",
        "void app_ubus_context_close",
    )
    assert "close(g_app_ubus_thread_context->sock.fd);" in drop
    assert "ubus_free" not in drop

    ws_child = between(
        WEB,
        "if (pid == 0) {\n        memset(g_app_children, 0, sizeof(g_app_children));",
        "if (pid > 0) {",
    )
    assert "app_ubus_context_drop_in_child();" in ws_child


def test_long_lived_children_do_not_pin_worker_control_sockets() -> None:
    helper = between(
        WEB,
        "static void webd_persistent_controls_close_in_child(int keep_fd)\n{",
        "static void webd_persistent_worker_prepare_child",
    )
    assert "close(g_persistent_workers[i].control_fd);" in helper
    assert "g_persistent_workers[i].control_fd != keep_fd" in helper
    assert "memset(g_persistent_workers, 0, sizeof(g_persistent_workers));" in helper
    assert "g_persistent_workers[i].control_fd = -1;" in helper

    ws_child = between(
        WEB,
        "if (pid == 0) {\n        memset(g_app_children, 0, sizeof(g_app_children));",
        "if (pid > 0) {",
    )
    assert "webd_persistent_controls_close_in_child(-1);" in ws_child

    ai_child = between(
        WEB,
        "static void webd_ai_local_worker_prepare(void)\n{",
        "static int webd_ai_local_worker_track",
    )
    assert "webd_persistent_controls_close_in_child(-1);" in ai_child


def test_fork_cannot_inherit_the_request_build_lock_owned_by_another_thread() -> None:
    helper = between(
        API_UBUS,
        "static void app_ubus_atfork_prepare(void)\n{",
        "void app_ubus_context_drop(void)",
    )
    assert "pthread_mutex_lock(&g_app_ubus_request_build_lock);" in helper
    assert "pthread_mutex_unlock(&g_app_ubus_request_build_lock);" in helper
    assert "pthread_atfork(app_ubus_atfork_prepare, app_ubus_atfork_unlock," in helper
    assert "pthread_mutex_timedlock(&g_app_ubus_request_build_lock," in helper
    init = between(
        JMX_APP,
        "int jmx_app_api_init(const char *bind_addr, int port)\n{",
        "void jmx_app_api_done(void)",
    )
    assert "pthread_once(&g_app_ubus_atfork_once, app_ubus_atfork_register);" in init


def test_context_is_owned_per_thread_and_only_frame_building_is_serialized() -> None:
    helper = between(
        API_UBUS,
        "static __thread struct ubus_context *g_app_ubus_thread_context;",
        "static void ubus_invoke_cb",
    )
    assert "static struct ubus_context *app_ubus_context_get_until(" in helper
    assert "g_app_ubus_thread_context = ubus_connect(NULL);" in helper
    assert "app_ubus_request_build_lock_until(deadline)" in helper
    assert "void app_ubus_context_drop(void)" in helper
    assert "ubus_free(uctx);" in helper
    assert "app_ubus_deadline_init(&cleanup_deadline," in helper
    assert "app_ubus_request_build_lock_until(&cleanup_deadline)" in helper
    assert "g_app_ubus_request_build_lock" in helper
    drop = between(
        API_UBUS,
        "void app_ubus_context_drop(void)\n{",
        "/* Only call from a freshly forked child.",
    )
    free_call = drop.index("ubus_free(uctx);")
    assert drop.rfind(
        "app_ubus_request_build_lock_until(&cleanup_deadline)", 0, free_call
    ) >= 0
    assert drop.index(
        "pthread_mutex_unlock(&g_app_ubus_request_build_lock);", free_call
    ) > free_call

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
    assert "uctx = app_ubus_context_get_until(&call_deadline);" in invoke
    assert "ubus_lookup_id(uctx, object, &id)" in invoke
    assert "webd_timespec_remaining_ms(&guard.deadline)" in invoke
    assert "app_ubus_deadline_guard_start" in invoke
    assert "app_ubus_deadline_guard_finish" in invoke
    assert "pthread_cond_timedwait" in guard
    assert "shutdown(fd, SHUT_RDWR);" in guard
    assert "_exit(124);" in guard
    assert "pthread_mutex_lock(&g_app_ubus_invoke_lock);" not in invoke
    lookup = invoke.index("ubus_lookup_id(uctx, object, &id)")
    lookup_lock = invoke.rfind(
        "app_ubus_request_build_lock_until(&guard.deadline)", 0, lookup
    )
    lookup_unlock = invoke.index(
        "pthread_mutex_unlock(&g_app_ubus_request_build_lock);", lookup
    )
    async_invoke = invoke.index("ubus_invoke_async(uctx, id, method, b.head, &req)")
    invoke_lock = invoke.rfind(
        "app_ubus_request_build_lock_until(&guard.deadline)", 0, async_invoke
    )
    invoke_unlock = invoke.index(
        "pthread_mutex_unlock(&g_app_ubus_request_build_lock);", async_invoke
    )
    complete = invoke.index("ubus_complete_request(uctx, &req, remaining_ms)")
    assert lookup_lock < lookup < lookup_unlock
    assert invoke_lock < async_invoke < invoke_unlock < complete
    assert "ubus_invoke(uctx, id, method" not in invoke

    insights_thread = between(
        WEB,
        "static void *webd_insights_fetch_thread(void *opaque)\n{",
        "static struct webd_insights_fetch_task *webd_insights_fetch_start",
    )
    assert "app_ubus_context_drop();" in insights_thread

    wan_thread = between(
        WEB,
        "static void *webd_wan_fetch_thread(void *opaque)\n{",
        "static struct webd_wan_fetch_task *webd_wan_fetch_start",
    )
    assert "app_ubus_context_drop();" in wan_thread


def test_context_is_dropped_after_transport_failure_and_on_shutdown() -> None:
    availability = between(
        API_UBUS,
        "int app_ubus_object_available(const char *object)\n{",
        "struct json_object *app_ubus_or_error",
    )
    assert "app_ubus_deadline_guard_start" in availability
    assert "app_ubus_deadline_guard_finish" in availability
    assert "app_ubus_context_get_until(&call_deadline)" in availability
    assert "ubus_lookup_id(uctx, object, &id)" in availability
    lookup = availability.index("ubus_lookup_id(uctx, object, &id)")
    assert availability.rfind(
        "app_ubus_request_build_lock_until(&guard.deadline)", 0, lookup
    ) >= 0
    assert availability.index(
        "pthread_mutex_unlock(&g_app_ubus_request_build_lock);", lookup
    ) > lookup

    done_offset = JMX_APP.index("void jmx_app_api_done(void)\n{")
    assert "app_ubus_context_close();" in JMX_APP[done_offset:]


if __name__ == "__main__":
    test_persistent_workers_drop_inherited_ubus_before_serving()
    test_long_lived_children_do_not_pin_worker_control_sockets()
    test_fork_cannot_inherit_the_request_build_lock_owned_by_another_thread()
    test_context_is_owned_per_thread_and_only_frame_building_is_serialized()
    test_context_is_dropped_after_transport_failure_and_on_shutdown()
