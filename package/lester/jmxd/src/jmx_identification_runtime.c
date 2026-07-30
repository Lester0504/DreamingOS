// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_identification_runtime.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>

#define JMX_IDENTITY_STATE_MAX_BYTES (64U * 1024U)
#define JMX_IDENTITY_STATE_MAX_AGE_SEC 15

static int read_int_file(const char *path, int *value)
{
    FILE *fp;
    char buf[32];

    *value = -1;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *value = atoi(buf) ? 1 : 0;
    return 0;
}

static struct json_object *read_runtime_state(void)
{
    FILE *fp;
    char *buf;
    long size;
    size_t n;
    struct json_object *state = NULL;

    fp = fopen(JMX_IDENTITY_RUNTIME_STATE_PATH, "rb");
    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) <= 0 ||
        size > (long)JMX_IDENTITY_STATE_MAX_BYTES || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = calloc(1, (size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    n = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    if (n == (size_t)size)
        state = json_tokener_parse(buf);
    free(buf);
    if (state && !json_object_is_type(state, json_type_object)) {
        json_object_put(state);
        state = NULL;
    }
    return state;
}

static int state_json_bool(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    return o && json_object_object_get_ex(o, key, &v) && v &&
           json_object_get_boolean(v);
}

static int64_t json_i64(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    return o && json_object_object_get_ex(o, key, &v) && v ?
           json_object_get_int64(v) : 0;
}

static const char *json_str(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    const char *s;

    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return "";
    s = json_object_get_string(v);
    return s ? s : "";
}

static void set_reason(struct jmx_identification_runtime *out, const char *reason)
{
    snprintf(out->reason, sizeof(out->reason), "%s", reason ? reason : "");
}

int jmx_identification_runtime_probe(const char *configured_mode,
                                     int configured_record,
                                     struct jmx_identification_runtime *out)
{
    struct json_object *state;
    time_t now = time(NULL);
    int expected_device;

    if (!configured_mode || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->kernel_record_enabled = -1;
    if (read_int_file(JMX_RECORD_ENABLE_PATH, &out->kernel_record_enabled) == 0)
        out->kernel_readback_available = 1;
    out->traffic_dataplane_matches = out->kernel_readback_available &&
        out->kernel_record_enabled == (configured_record ? 1 : 0);

    state = read_runtime_state();
    if (state) {
        out->identityd_readback_available = 1;
        out->identityd_pid = json_i64(state, "pid");
        out->updated_at = json_i64(state, "updated_at");
        out->last_tick_at = json_i64(state, "last_tick_at");
        out->tick_count = json_i64(state, "tick_count");
        out->listeners_ready = (int)json_i64(state, "listeners_ready");
        out->collector_requested = state_json_bool(state, "collector_requested");
        out->collector_ready = state_json_bool(state, "collector_ready");
        out->collector_active = state_json_bool(state, "collector_active");
        snprintf(out->runtime_mode, sizeof(out->runtime_mode), "%s",
                 json_str(state, "mode"));
        out->identityd_mode_matches = !strcmp(out->runtime_mode, configured_mode);
        out->identityd_process_running = out->identityd_pid > 1 &&
            (kill((pid_t)out->identityd_pid, 0) == 0 || errno == EPERM);
        out->identityd_state_fresh = out->updated_at > 0 && now >= out->updated_at &&
            now - out->updated_at <= JMX_IDENTITY_STATE_MAX_AGE_SEC;
        json_object_put(state);
    }

    expected_device = !strcmp(configured_mode, "device_and_traffic");
    out->device_dataplane_matches = out->identityd_readback_available &&
        out->identityd_process_running && out->identityd_state_fresh &&
        out->identityd_mode_matches &&
        (expected_device ?
            (out->collector_requested && out->collector_ready && out->collector_active) :
            (!out->collector_requested && !out->collector_active));
    out->applied = out->traffic_dataplane_matches && out->device_dataplane_matches;

    if (out->applied)
        set_reason(out, "");
    else if (!out->kernel_readback_available)
        set_reason(out, "kernel_record_readback_missing");
    else if (!out->traffic_dataplane_matches)
        set_reason(out, "kernel_record_mode_mismatch");
    else if (!out->identityd_readback_available)
        set_reason(out, "identityd_readback_missing");
    else if (!out->identityd_process_running)
        set_reason(out, "identityd_process_not_running");
    else if (!out->identityd_state_fresh)
        set_reason(out, "identityd_state_stale");
    else if (!out->identityd_mode_matches)
        set_reason(out, "identityd_mode_mismatch");
    else if (expected_device && !out->collector_ready)
        set_reason(out, "identity_collector_not_ready");
    else if (expected_device && !out->collector_active)
        set_reason(out, "identity_collector_not_active");
    else if (!expected_device && out->collector_active)
        set_reason(out, "identity_collector_unexpected_active");
    else
        set_reason(out, "identification_dataplane_mismatch");
    return 0;
}
