// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DreamingWrt core observer-only watchdog and telemetry.
 *
 * Rules:
 * - fixed-size state only; no heap allocation in watchdog thread;
 * - watchdog thread never calls ubus, shell, SQLite, json-c or daemon control;
 * - no automatic restart; core_status is the only public side effect;
 * - main-loop lag is measured by an ordinary uloop timeout heartbeat.
 */
#include "jmx_core_watchdog.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libubox/uloop.h>
#include "jmx.h"

#define JMX_WD_NAME_LEN 96

typedef struct {
    int enabled;
    int running;
    int stop_requested;
    int observer_only;
    int last_observed_unhealthy;
    int loop_stalled;
    int handler_stuck;
    int thread_create_errno;
    uint64_t observer_iterations;
    int64_t last_check_mono_ms;
    int64_t last_check_wall_s;
} jmx_watchdog_observer_t;

typedef struct {
    uint64_t heartbeat_seq;
    int started;
    int64_t started_mono_ms;
    int64_t last_heartbeat_mono_ms;
    int64_t last_heartbeat_wall_s;
    int64_t next_due_mono_ms;
    int64_t last_interval_ms;
    int64_t last_lag_ms;
    int64_t max_lag_ms;
    uint64_t lag_count;
} jmx_loop_telemetry_t;

typedef struct {
    uint64_t next_call_id;
    uint64_t total_calls;
    uint64_t slow_count;
    int active;
    uint64_t active_call_id;
    char active_object[JMX_WD_NAME_LEN];
    char active_method[JMX_WD_NAME_LEN];
    int64_t active_started_mono_ms;
    int64_t active_started_wall_s;

    char last_object[JMX_WD_NAME_LEN];
    char last_method[JMX_WD_NAME_LEN];
    int64_t last_started_wall_s;
    int64_t last_duration_ms;
    int last_status_code;

    char slowest_object[JMX_WD_NAME_LEN];
    char slowest_method[JMX_WD_NAME_LEN];
    int64_t slowest_started_wall_s;
    int64_t slowest_duration_ms;
    int slowest_status_code;
} jmx_ubus_telemetry_t;

typedef struct {
    jmx_watchdog_observer_t watchdog;
    jmx_loop_telemetry_t loop;
    jmx_ubus_telemetry_t ubus;
} jmx_core_watchdog_state_t;

static pthread_mutex_t g_wd_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_wd_thread;
static int g_wd_thread_started;
static struct uloop_timeout g_loop_heartbeat_tm;
static jmx_core_watchdog_state_t g_wd = {
    .watchdog = {
        .observer_only = 1,
    },
};

static int64_t jmx_wd_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void jmx_wd_copy_name(char *dst, size_t len, const char *src)
{
    if (!dst || len == 0)
        return;
    snprintf(dst, len, "%s", (src && src[0]) ? src : "unknown");
}

static void jmx_core_loop_heartbeat_cb(struct uloop_timeout *t)
{
    int64_t now = jmx_wd_monotonic_ms();
    int64_t wall = (int64_t)time(NULL);
    int64_t lag = 0;

    pthread_mutex_lock(&g_wd_lock);
    if (!g_wd.loop.started) {
        g_wd.loop.started = 1;
        g_wd.loop.started_mono_ms = now;
    }
    if (g_wd.loop.next_due_mono_ms > 0 && now > g_wd.loop.next_due_mono_ms)
        lag = now - g_wd.loop.next_due_mono_ms;
    if (lag > 0) {
        g_wd.loop.last_lag_ms = lag;
        if (lag > g_wd.loop.max_lag_ms)
            g_wd.loop.max_lag_ms = lag;
        if (lag >= JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS)
            g_wd.loop.lag_count++;
    } else {
        g_wd.loop.last_lag_ms = 0;
    }
    if (g_wd.loop.last_heartbeat_mono_ms > 0 && now >= g_wd.loop.last_heartbeat_mono_ms)
        g_wd.loop.last_interval_ms = now - g_wd.loop.last_heartbeat_mono_ms;
    g_wd.loop.heartbeat_seq++;
    g_wd.loop.last_heartbeat_mono_ms = now;
    g_wd.loop.last_heartbeat_wall_s = wall;
    g_wd.loop.next_due_mono_ms = now + JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS;
    pthread_mutex_unlock(&g_wd_lock);

    uloop_timeout_set(t, (int)JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS);
}

static void jmx_wd_emit(const char *line, int len)
{
    if (len > 0)
        (void)!write(STDERR_FILENO, line, (size_t)len);
}

/*
 * Hard-recovery threshold in ms; read once from the environment so it can be
 * tuned or disabled per deployment. Default-on at JMX_CORE_HARD_RECOVER_DEFAULT_MS;
 * an explicit 0 (or negative) restores pure observer mode.
 */
static int64_t jmx_wd_hard_recover_ms(void)
{
    const char *v = getenv("DREAMINGWRT_CORE_WATCHDOG_HARD_RECOVER_MS");
    return v ? (int64_t)atoll(v) : JMX_CORE_HARD_RECOVER_DEFAULT_MS;
}

static void *jmx_core_watchdog_thread(void *arg)
{
    int prev_unhealthy = 0;
    int64_t hard_recover_ms = jmx_wd_hard_recover_ms();
    int64_t started_mono_ms = jmx_wd_monotonic_ms();

    (void)arg;

    for (;;) {
        int64_t now = jmx_wd_monotonic_ms();
        int stop;
        int unhealthy = 0, loop_stalled = 0, handler_stuck = 0;
        int64_t heartbeat_age = 0, active_elapsed = 0;
        char obj[JMX_WD_NAME_LEN] = "", meth[JMX_WD_NAME_LEN] = "";

        pthread_mutex_lock(&g_wd_lock);
        stop = g_wd.watchdog.stop_requested;
        if (!stop) {
            heartbeat_age = g_wd.loop.last_heartbeat_mono_ms > 0 ?
                now - g_wd.loop.last_heartbeat_mono_ms : -1;
            active_elapsed = (g_wd.ubus.active &&
                                      g_wd.ubus.active_started_mono_ms > 0 &&
                                      now >= g_wd.ubus.active_started_mono_ms) ?
                now - g_wd.ubus.active_started_mono_ms : 0;

            g_wd.watchdog.observer_iterations++;
            g_wd.watchdog.last_check_mono_ms = now;
            g_wd.watchdog.last_check_wall_s = (int64_t)time(NULL);
            loop_stalled = heartbeat_age < 0 ||
                heartbeat_age >= JMX_CORE_LOOP_STALL_THRESHOLD_MS;
            handler_stuck = active_elapsed >= JMX_CORE_UBUS_STUCK_THRESHOLD_MS;
            g_wd.watchdog.loop_stalled = loop_stalled;
            g_wd.watchdog.handler_stuck = handler_stuck;
            g_wd.watchdog.last_observed_unhealthy = loop_stalled || handler_stuck;
            unhealthy = loop_stalled || handler_stuck;
            snprintf(obj, sizeof(obj), "%s", g_wd.ubus.active_object);
            snprintf(meth, sizeof(meth), "%s", g_wd.ubus.active_method);
        }
        pthread_mutex_unlock(&g_wd_lock);

        if (stop)
            break;

        /*
         * Surface stalls on their onset/clear edges. The observer thread runs
         * independently of the (possibly spinning) main loop, so this stderr
         * line — captured by procd — is the only post-mortem signal available
         * when the control plane is wedged and ubus can no longer answer.
         * Raw write() with a stack buffer keeps this heap-free and ubus-free.
         */
        if (unhealthy && !prev_unhealthy) {
            char line[288];
            int n = snprintf(line, sizeof(line),
                "jmx_core_watchdog: CONTROL-PLANE STALL onset loop_stalled=%d handler_stuck=%d heartbeat_age_ms=%lld active=%s.%s active_ms=%lld\n",
                loop_stalled, handler_stuck, (long long)heartbeat_age,
                obj[0] ? obj : "-", meth[0] ? meth : "-", (long long)active_elapsed);
            jmx_wd_emit(line, n < (int)sizeof(line) ? n : (int)sizeof(line) - 1);
        } else if (!unhealthy && prev_unhealthy) {
            static const char cleared[] = "jmx_core_watchdog: control-plane stall cleared\n";
            jmx_wd_emit(cleared, (int)sizeof(cleared) - 1);
        }
        prev_unhealthy = unhealthy;

        /*
         * Hard recovery: a stall past the threshold means the main loop is not
         * coming back on its own (livelock/deadlock), so abort() and let the
         * supervisor respawn a fresh core. A min-uptime grace protects a slow
         * first boot; abort() from this observer thread terminates the whole
         * process even while the main thread spins. Gated by hard_recover_ms>0.
         */
        if (hard_recover_ms > 0 && unhealthy &&
            (now - started_mono_ms) >= JMX_CORE_HARD_RECOVER_MIN_UPTIME_MS) {
            int64_t stuck_ms = handler_stuck ? active_elapsed :
                (heartbeat_age > 0 ? heartbeat_age : 0);
            if (stuck_ms >= hard_recover_ms) {
                char line[288];
                int n = snprintf(line, sizeof(line),
                    "jmx_core_watchdog: HARD RECOVERY abort after %lld ms stall active=%s.%s; supervisor will respawn\n",
                    (long long)stuck_ms, obj[0] ? obj : "-", meth[0] ? meth : "-");
                jmx_wd_emit(line, n < (int)sizeof(line) ? n : (int)sizeof(line) - 1);
                abort();
            }
        }

        usleep(1000 * 1000);
    }

    pthread_mutex_lock(&g_wd_lock);
    g_wd.watchdog.running = 0;
    pthread_mutex_unlock(&g_wd_lock);
    return NULL;
}

int jmx_core_watchdog_start(void)
{
    int rc = 0;
    int64_t now = jmx_wd_monotonic_ms();

    pthread_mutex_lock(&g_wd_lock);
    if (g_wd.watchdog.enabled) {
        pthread_mutex_unlock(&g_wd_lock);
        return 0;
    }
    memset(&g_wd, 0, sizeof(g_wd));
    g_wd.watchdog.enabled = 1;
    g_wd.watchdog.running = 1;
    g_wd.watchdog.observer_only = 1;
    g_wd.loop.started = 1;
    g_wd.loop.started_mono_ms = now;
    g_wd.loop.last_heartbeat_mono_ms = now;
    g_wd.loop.last_heartbeat_wall_s = (int64_t)time(NULL);
    g_wd.loop.next_due_mono_ms = now + JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS;
    g_wd.ubus.next_call_id = 1;
    pthread_mutex_unlock(&g_wd_lock);

    memset(&g_loop_heartbeat_tm, 0, sizeof(g_loop_heartbeat_tm));
    g_loop_heartbeat_tm.cb = jmx_core_loop_heartbeat_cb;
    uloop_timeout_set(&g_loop_heartbeat_tm, (int)JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS);

    rc = pthread_create(&g_wd_thread, NULL, jmx_core_watchdog_thread, NULL);
    pthread_mutex_lock(&g_wd_lock);
    if (rc != 0) {
        g_wd.watchdog.running = 0;
        g_wd.watchdog.thread_create_errno = rc;
        g_wd_thread_started = 0;
    } else {
        g_wd_thread_started = 1;
    }
    pthread_mutex_unlock(&g_wd_lock);
    if (rc != 0)
        LOG_WARN("core watchdog observer thread start failed errno=%d\n", rc);
    return rc == 0 ? 0 : -1;
}

void jmx_core_watchdog_stop(void)
{
    int join = 0;

    uloop_timeout_cancel(&g_loop_heartbeat_tm);
    pthread_mutex_lock(&g_wd_lock);
    g_wd.watchdog.stop_requested = 1;
    join = g_wd_thread_started;
    pthread_mutex_unlock(&g_wd_lock);

    if (join)
        pthread_join(g_wd_thread, NULL);

    pthread_mutex_lock(&g_wd_lock);
    g_wd_thread_started = 0;
    g_wd.watchdog.running = 0;
    pthread_mutex_unlock(&g_wd_lock);
}

uint64_t jmx_core_ubus_dispatch_enter(const char *object_name,
                                      const char *method_name)
{
    uint64_t id;
    int64_t now = jmx_wd_monotonic_ms();

    pthread_mutex_lock(&g_wd_lock);
    id = g_wd.ubus.next_call_id++;
    if (!g_wd.ubus.next_call_id)
        g_wd.ubus.next_call_id = 1;
    g_wd.ubus.total_calls++;
    g_wd.ubus.active = 1;
    g_wd.ubus.active_call_id = id;
    g_wd.ubus.active_started_mono_ms = now;
    g_wd.ubus.active_started_wall_s = (int64_t)time(NULL);
    jmx_wd_copy_name(g_wd.ubus.active_object, sizeof(g_wd.ubus.active_object), object_name);
    jmx_wd_copy_name(g_wd.ubus.active_method, sizeof(g_wd.ubus.active_method), method_name);
    pthread_mutex_unlock(&g_wd_lock);
    return id;
}

void jmx_core_ubus_dispatch_update(uint64_t call_id, const char *object_name,
                                   const char *method_name)
{
    pthread_mutex_lock(&g_wd_lock);
    if (g_wd.ubus.active && g_wd.ubus.active_call_id == call_id) {
        jmx_wd_copy_name(g_wd.ubus.active_object, sizeof(g_wd.ubus.active_object), object_name);
        jmx_wd_copy_name(g_wd.ubus.active_method, sizeof(g_wd.ubus.active_method), method_name);
    }
    pthread_mutex_unlock(&g_wd_lock);
}

void jmx_core_ubus_dispatch_update_current(const char *object_name,
                                           const char *method_name)
{
    pthread_mutex_lock(&g_wd_lock);
    if (g_wd.ubus.active) {
        jmx_wd_copy_name(g_wd.ubus.active_object, sizeof(g_wd.ubus.active_object), object_name);
        jmx_wd_copy_name(g_wd.ubus.active_method, sizeof(g_wd.ubus.active_method), method_name);
    }
    pthread_mutex_unlock(&g_wd_lock);
}

void jmx_core_ubus_dispatch_leave(uint64_t call_id, int status_code)
{
    int64_t now = jmx_wd_monotonic_ms();
    int64_t duration = 0;

    pthread_mutex_lock(&g_wd_lock);
    if (g_wd.ubus.active && g_wd.ubus.active_call_id == call_id) {
        if (g_wd.ubus.active_started_mono_ms > 0 && now >= g_wd.ubus.active_started_mono_ms)
            duration = now - g_wd.ubus.active_started_mono_ms;
        jmx_wd_copy_name(g_wd.ubus.last_object, sizeof(g_wd.ubus.last_object),
                         g_wd.ubus.active_object);
        jmx_wd_copy_name(g_wd.ubus.last_method, sizeof(g_wd.ubus.last_method),
                         g_wd.ubus.active_method);
        g_wd.ubus.last_started_wall_s = g_wd.ubus.active_started_wall_s;
        g_wd.ubus.last_duration_ms = duration;
        g_wd.ubus.last_status_code = status_code;
        if (duration >= JMX_CORE_UBUS_SLOW_THRESHOLD_MS)
            g_wd.ubus.slow_count++;
        if (duration > g_wd.ubus.slowest_duration_ms) {
            jmx_wd_copy_name(g_wd.ubus.slowest_object, sizeof(g_wd.ubus.slowest_object),
                             g_wd.ubus.active_object);
            jmx_wd_copy_name(g_wd.ubus.slowest_method, sizeof(g_wd.ubus.slowest_method),
                             g_wd.ubus.active_method);
            g_wd.ubus.slowest_started_wall_s = g_wd.ubus.active_started_wall_s;
            g_wd.ubus.slowest_duration_ms = duration;
            g_wd.ubus.slowest_status_code = status_code;
        }
        g_wd.ubus.active = 0;
        g_wd.ubus.active_call_id = 0;
        g_wd.ubus.active_started_mono_ms = 0;
        g_wd.ubus.active_started_wall_s = 0;
        g_wd.ubus.active_object[0] = '\0';
        g_wd.ubus.active_method[0] = '\0';
    }
    pthread_mutex_unlock(&g_wd_lock);
}

static void jmx_json_add_i64(struct json_object *obj, const char *key, int64_t value)
{
    json_object_object_add(obj, key, json_object_new_int64(value));
}

static const char *jmx_wd_state_name(const jmx_core_watchdog_state_t *s,
                                     int loop_stalled,
                                     int handler_stuck)
{
    if (!s->watchdog.enabled)
        return "disabled";
    if (!s->watchdog.running)
        return "stopped";
    if (loop_stalled)
        return "loop_stalled";
    if (handler_stuck)
        return "handler_stuck";
    return "ok";
}

void jmx_core_watchdog_append_status(struct json_object *data)
{
    jmx_core_watchdog_state_t snap;
    int64_t now = jmx_wd_monotonic_ms();
    int64_t heartbeat_age_ms;
    int64_t active_elapsed_ms = 0;
    int loop_stalled;
    int handler_stuck;
    struct json_object *watchdog;
    struct json_object *loop;
    struct json_object *ubus;
    struct json_object *thresholds;
    const char *state;

    if (!data)
        return;

    pthread_mutex_lock(&g_wd_lock);
    snap = g_wd;
    pthread_mutex_unlock(&g_wd_lock);

    heartbeat_age_ms = snap.loop.last_heartbeat_mono_ms > 0 && now >= snap.loop.last_heartbeat_mono_ms ?
        now - snap.loop.last_heartbeat_mono_ms : -1;
    if (snap.ubus.active && snap.ubus.active_started_mono_ms > 0 && now >= snap.ubus.active_started_mono_ms)
        active_elapsed_ms = now - snap.ubus.active_started_mono_ms;
    loop_stalled = heartbeat_age_ms < 0 ||
                   heartbeat_age_ms >= JMX_CORE_LOOP_STALL_THRESHOLD_MS;
    handler_stuck = snap.ubus.active &&
                    active_elapsed_ms >= JMX_CORE_UBUS_STUCK_THRESHOLD_MS;
    state = jmx_wd_state_name(&snap, loop_stalled, handler_stuck);

    int64_t hard_recover_ms = jmx_wd_hard_recover_ms();

    thresholds = json_object_new_object();
    jmx_json_add_i64(thresholds, "ubus_slow_ms", JMX_CORE_UBUS_SLOW_THRESHOLD_MS);
    jmx_json_add_i64(thresholds, "ubus_stuck_ms", JMX_CORE_UBUS_STUCK_THRESHOLD_MS);
    jmx_json_add_i64(thresholds, "loop_heartbeat_interval_ms", JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS);
    jmx_json_add_i64(thresholds, "loop_stall_ms", JMX_CORE_LOOP_STALL_THRESHOLD_MS);
    jmx_json_add_i64(thresholds, "hard_recover_ms", hard_recover_ms > 0 ? hard_recover_ms : 0);

    watchdog = json_object_new_object();
    json_object_object_add(watchdog, "contract_version",
                           json_object_new_string(JMX_CORE_WATCHDOG_CONTRACT_VERSION));
    json_object_object_add(watchdog, "enabled", json_object_new_boolean(snap.watchdog.enabled));
    json_object_object_add(watchdog, "running", json_object_new_boolean(snap.watchdog.running));
    json_object_object_add(watchdog, "observer_only", json_object_new_boolean(hard_recover_ms <= 0));
    json_object_object_add(watchdog, "auto_restart", json_object_new_boolean(hard_recover_ms > 0));
    json_object_object_add(watchdog, "state", json_object_new_string(state));
    json_object_object_add(watchdog, "healthy", json_object_new_boolean(!strcmp(state, "ok")));
    json_object_object_add(watchdog, "loop_stalled",
                           json_object_new_boolean(loop_stalled));
    json_object_object_add(watchdog, "handler_stuck",
                           json_object_new_boolean(handler_stuck));
    json_object_object_add(watchdog, "last_observed_unhealthy",
                           json_object_new_boolean(snap.watchdog.last_observed_unhealthy));
    jmx_json_add_i64(watchdog, "observer_iterations", (int64_t)snap.watchdog.observer_iterations);
    jmx_json_add_i64(watchdog, "last_check_wall_s", snap.watchdog.last_check_wall_s);
    jmx_json_add_i64(watchdog, "last_check_mono_ms", snap.watchdog.last_check_mono_ms);
    json_object_object_add(watchdog, "thread_create_errno",
                           json_object_new_int(snap.watchdog.thread_create_errno));
    json_object_object_add(watchdog, "thresholds", thresholds);

    loop = json_object_new_object();
    json_object_object_add(loop, "heartbeat_running", json_object_new_boolean(snap.loop.started));
    jmx_json_add_i64(loop, "heartbeat_seq", (int64_t)snap.loop.heartbeat_seq);
    jmx_json_add_i64(loop, "last_heartbeat_wall_s", snap.loop.last_heartbeat_wall_s);
    jmx_json_add_i64(loop, "last_heartbeat_mono_ms", snap.loop.last_heartbeat_mono_ms);
    jmx_json_add_i64(loop, "heartbeat_age_ms", heartbeat_age_ms);
    jmx_json_add_i64(loop, "heartbeat_interval_ms", JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS);
    jmx_json_add_i64(loop, "last_interval_ms", snap.loop.last_interval_ms);
    jmx_json_add_i64(loop, "last_lag_ms", snap.loop.last_lag_ms);
    jmx_json_add_i64(loop, "max_lag_ms", snap.loop.max_lag_ms);
    jmx_json_add_i64(loop, "lag_count", (int64_t)snap.loop.lag_count);
    jmx_json_add_i64(loop, "stall_threshold_ms", JMX_CORE_LOOP_STALL_THRESHOLD_MS);
    json_object_object_add(loop, "stalled", json_object_new_boolean(loop_stalled));

    ubus = json_object_new_object();
    jmx_json_add_i64(ubus, "total_calls", (int64_t)snap.ubus.total_calls);
    jmx_json_add_i64(ubus, "slow_count", (int64_t)snap.ubus.slow_count);
    jmx_json_add_i64(ubus, "slow_threshold_ms", JMX_CORE_UBUS_SLOW_THRESHOLD_MS);
    jmx_json_add_i64(ubus, "stuck_threshold_ms", JMX_CORE_UBUS_STUCK_THRESHOLD_MS);
    json_object_object_add(ubus, "active", json_object_new_boolean(snap.ubus.active));
    json_object_object_add(ubus, "current_handler",
                           json_object_new_string(snap.ubus.active_method));
    json_object_object_add(ubus, "current_object",
                           json_object_new_string(snap.ubus.active_object));
    jmx_json_add_i64(ubus, "current_call_id", (int64_t)snap.ubus.active_call_id);
    jmx_json_add_i64(ubus, "current_started_wall_s", snap.ubus.active_started_wall_s);
    jmx_json_add_i64(ubus, "current_elapsed_ms", active_elapsed_ms);
    json_object_object_add(ubus, "last_handler", json_object_new_string(snap.ubus.last_method));
    json_object_object_add(ubus, "last_object", json_object_new_string(snap.ubus.last_object));
    jmx_json_add_i64(ubus, "last_started_wall_s", snap.ubus.last_started_wall_s);
    jmx_json_add_i64(ubus, "last_duration_ms", snap.ubus.last_duration_ms);
    json_object_object_add(ubus, "last_status_code", json_object_new_int(snap.ubus.last_status_code));
    json_object_object_add(ubus, "slowest_handler", json_object_new_string(snap.ubus.slowest_method));
    json_object_object_add(ubus, "slowest_object", json_object_new_string(snap.ubus.slowest_object));
    jmx_json_add_i64(ubus, "slowest_started_wall_s", snap.ubus.slowest_started_wall_s);
    jmx_json_add_i64(ubus, "slowest_duration_ms", snap.ubus.slowest_duration_ms);
    json_object_object_add(ubus, "slowest_status_code", json_object_new_int(snap.ubus.slowest_status_code));

    json_object_object_add(data, "watchdog", watchdog);
    json_object_object_add(data, "main_loop", loop);
    json_object_object_add(data, "ubus_dispatch", ubus);

    json_object_object_add(data, "active_handler", json_object_new_string(snap.ubus.active_method));
    json_object_object_add(data, "current_handler", json_object_new_string(snap.ubus.active_method));
    json_object_object_add(data, "last_handler", json_object_new_string(snap.ubus.last_method));
    json_object_object_add(data, "slowest_handler", json_object_new_string(snap.ubus.slowest_method));
    jmx_json_add_i64(data, "last_handler_duration_ms", snap.ubus.last_duration_ms);
    jmx_json_add_i64(data, "slowest_handler_duration_ms", snap.ubus.slowest_duration_ms);
    jmx_json_add_i64(data, "slow_handler_count", (int64_t)snap.ubus.slow_count);
    jmx_json_add_i64(data, "loop_lag_ms", snap.loop.last_lag_ms);
    jmx_json_add_i64(data, "loop_max_lag_ms", snap.loop.max_lag_ms);
    jmx_json_add_i64(data, "loop_heartbeat_age_ms", heartbeat_age_ms);
}
