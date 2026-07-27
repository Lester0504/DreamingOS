// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "jmx.h"
#include "jmx_core_watchdog.h"

jmx_status_t g_jmx_status;
int current_log_level = LOG_LEVEL_ERROR;

int uloop_timeout_set(struct uloop_timeout *timeout, int milliseconds)
{
    (void)timeout;
    (void)milliseconds;
    return 0;
}

int uloop_timeout_cancel(struct uloop_timeout *timeout)
{
    (void)timeout;
    return 0;
}

static struct json_object *required(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;

    assert(object != NULL);
    assert(json_object_object_get_ex(object, key, &value));
    assert(value != NULL);
    return value;
}

static void assert_watchdog(struct json_object *root, const char *state,
                            int healthy, int handler_stuck)
{
    struct json_object *watchdog = required(root, "watchdog");

    assert(!strcmp(json_object_get_string(required(watchdog, "state")), state));
    assert(json_object_get_boolean(required(watchdog, "healthy")) == healthy);
    assert(json_object_get_boolean(required(watchdog, "handler_stuck")) ==
           handler_stuck);
    assert(!json_object_get_boolean(required(watchdog, "loop_stalled")));
}

int main(void)
{
    struct json_object *root;
    uint64_t call_id;

    assert(jmx_core_watchdog_start() == 0);
    root = json_object_new_object();
    jmx_core_watchdog_append_status(root);
    assert_watchdog(root, "ok", 1, 0);
    json_object_put(root);

    call_id = jmx_core_ubus_dispatch_enter("dreamingwrt", "fixture_slow");
    usleep(80 * 1000);
    root = json_object_new_object();
    jmx_core_watchdog_append_status(root);
    assert_watchdog(root, "handler_stuck", 0, 1);
    json_object_put(root);

    jmx_core_ubus_dispatch_leave(call_id, 0);
    root = json_object_new_object();
    jmx_core_watchdog_append_status(root);
    assert_watchdog(root, "ok", 1, 0);
    assert(!strcmp(json_object_get_string(required(root, "last_handler")),
                   "fixture_slow"));
    json_object_put(root);
    jmx_core_watchdog_stop();
    puts("ok: core watchdog runtime stuck/recovery fields are consistent");
    return 0;
}
