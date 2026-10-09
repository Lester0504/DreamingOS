// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_runtime_sampler.h"
#include "flowd_runtime_sample_store.h"
#include "flowd_wan_runtime.h"
#include "flowd_internal.h"

#include <net/if.h>

#define FLOWD_RUNTIME_SAMPLE_INITIAL_MS 1000
#define FLOWD_RUNTIME_SAMPLE_TICK_MS 60000
#define FLOWD_RUNTIME_SAMPLE_MAX_WANS 64
#define FLOWD_RUNTIME_ONCE_ARG "--runtime-sample-once"
#define FLOWD_RUNTIME_SYSFS_ROOT "/sys/class/net"

struct flowd_runtime_source_slot {
    char wan[FLOWD_MAX_TEXT];
    char ifname[IFNAMSIZ];
};

static struct uloop_timeout g_runtime_sampler_timer;
static struct uloop_process g_runtime_sampler_process;
static const char *g_runtime_sampler_argv0;
static int g_runtime_sampler_initialized;
static int g_runtime_sampler_started;
static int g_runtime_sampler_running;

static void flowd_runtime_sampler_kill(pid_t pid)
{
    int i;

    if (pid <= 0)
        return;
    kill(pid, SIGTERM);
    for (i = 0; i < 20; i++) {
        pid_t result = waitpid(pid, NULL, WNOHANG);

        if (result == pid || (result < 0 && errno == ECHILD))
            return;
        usleep(50000);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
}

static int flowd_runtime_sample_once(void)
{
    struct flowd_runtime_source_slot slots[FLOWD_RUNTIME_SAMPLE_MAX_WANS];
    struct flowd_runtime_wan_source sources[FLOWD_RUNTIME_SAMPLE_MAX_WANS];
    struct flowd_settings settings;
    struct json_object *result = NULL;
    sqlite3_stmt *st = NULL;
    size_t count = 0;
    size_t written = 0;
    int rc = -1;

    if (flowd_db_open_worker() != 0)
        return -1;
    memset(slots, 0, sizeof(slots));
    memset(sources, 0, sizeof(sources));
    st = flowd_config_prepare(
        "SELECT wan FROM flowd_wan_capacity WHERE enabled=1 ORDER BY wan LIMIT 64");
    if (!st)
        goto done;
    while (sqlite3_step(st) == SQLITE_ROW && count < FLOWD_RUNTIME_SAMPLE_MAX_WANS) {
        const char *wan = flowd_sqlite_text(st, 0, "");

        if (!wan[0] || !flowd_text_ok(wan, sizeof(slots[count].wan) - 1) ||
            flowd_wan_resolve_ifname(wan, slots[count].ifname,
                                     sizeof(slots[count].ifname)) != 0)
            continue;
        snprintf(slots[count].wan, sizeof(slots[count].wan), "%s", wan);
        sources[count].wan = slots[count].wan;
        sources[count].ifname = slots[count].ifname;
        count++;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (count == 0 || flowd_mkdir_p("/etc/dreamingwrt", 0755) != 0 ||
        flowd_runtime_sample_store(FLOWD_RUNTIME_SYSFS_ROOT,
                                   FLOWD_DEFAULT_FLOW_DB_PATH, sources, count,
                                   flowd_now_s(), &written) != 0 || written == 0)
        goto done;
    if (flowd_settings_load(&settings) == 0 && settings.enabled &&
        !strcmp(settings.apply_mode, "managed")) {
        result = flowd_tc_apply(&settings);
        if (!result || !flowd_json_bool(result, "ok", 0)) {
            fprintf(stderr, "[dreamingwrt-flowd] runtime reconcile failed: %s\n",
                    result ? flowd_json_str(result, "runtime_reason", "tc_apply_failed") :
                             "tc_apply_unavailable");
            goto done;
        }
    }
    rc = 0;

done:
    if (st)
        sqlite3_finalize(st);
    if (result)
        json_object_put(result);
    flowd_db_close();
    return rc;
}

int flowd_runtime_sampler_command(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], FLOWD_RUNTIME_ONCE_ARG))
        return flowd_runtime_sample_once() == 0 ? 0 : 1;
    return -1;
}

static void flowd_runtime_sampler_done(struct uloop_process *process, int status)
{
    (void)process;
    (void)status;
    g_runtime_sampler_running = 0;
    if (g_runtime_sampler_started)
        uloop_timeout_set(&g_runtime_sampler_timer, FLOWD_RUNTIME_SAMPLE_TICK_MS);
}

static void flowd_runtime_sampler_tick(struct uloop_timeout *timeout)
{
    pid_t pid;

    (void)timeout;
    if (g_runtime_sampler_running || !g_runtime_sampler_started)
        return;
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[dreamingwrt-flowd] runtime sampler fork failed: %s\n",
                strerror(errno));
        uloop_timeout_set(&g_runtime_sampler_timer, FLOWD_RUNTIME_SAMPLE_TICK_MS);
        return;
    }
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        execlp(g_runtime_sampler_argv0 ? g_runtime_sampler_argv0 : "dreamingwrt-flowd",
               g_runtime_sampler_argv0 ? g_runtime_sampler_argv0 : "dreamingwrt-flowd",
               FLOWD_RUNTIME_ONCE_ARG, NULL);
        _exit(127);
    }
    memset(&g_runtime_sampler_process, 0, sizeof(g_runtime_sampler_process));
    g_runtime_sampler_process.pid = pid;
    g_runtime_sampler_process.cb = flowd_runtime_sampler_done;
    if (uloop_process_add(&g_runtime_sampler_process) != 0) {
        flowd_runtime_sampler_kill(pid);
        uloop_timeout_set(&g_runtime_sampler_timer, FLOWD_RUNTIME_SAMPLE_TICK_MS);
        return;
    }
    g_runtime_sampler_running = 1;
}

int flowd_runtime_sampler_init(const char *argv0)
{
    if (g_runtime_sampler_initialized)
        return 0;
    memset(&g_runtime_sampler_timer, 0, sizeof(g_runtime_sampler_timer));
    g_runtime_sampler_timer.cb = flowd_runtime_sampler_tick;
    g_runtime_sampler_argv0 = argv0 && argv0[0] ? argv0 : "dreamingwrt-flowd";
    g_runtime_sampler_initialized = 1;
    return 0;
}

int flowd_runtime_sampler_start(void)
{
    if (!g_runtime_sampler_initialized || g_runtime_sampler_started)
        return g_runtime_sampler_initialized ? 0 : -1;
    g_runtime_sampler_started = 1;
    uloop_timeout_set(&g_runtime_sampler_timer, FLOWD_RUNTIME_SAMPLE_INITIAL_MS);
    return 0;
}

void flowd_runtime_sampler_stop(void)
{
    if (!g_runtime_sampler_initialized)
        return;
    g_runtime_sampler_started = 0;
    uloop_timeout_cancel(&g_runtime_sampler_timer);
    if (g_runtime_sampler_running) {
        uloop_process_delete(&g_runtime_sampler_process);
        flowd_runtime_sampler_kill(g_runtime_sampler_process.pid);
        g_runtime_sampler_running = 0;
    }
    g_runtime_sampler_initialized = 0;
}
