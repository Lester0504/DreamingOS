// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DreamingWrt client identity collection daemon.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <libubox/uloop.h>
#include <sqlite3.h>

#include "jmx.h"
#include "jmx_huginn.h"
#include "jmx_identity_collector.h"

int current_log_level = LOG_LEVEL_WARN;

static struct uloop_timeout identity_tick_timer;
static int identity_collector_active;
static int identity_collector_requested;
static char identity_mode[32] = "unavailable";
static time_t identity_next_collect_at;
static time_t identity_last_tick_at;
static uint64_t identity_tick_count;

#define IDENTITY_CONFIG_DB "/etc/dreamingwrt/config.db"
#define IDENTITY_RUNTIME_DIR "/run/dreamingwrt"
#define IDENTITY_RUNTIME_STATE IDENTITY_RUNTIME_DIR "/identityd-state.json"

static int identity_mode_load(char *mode, size_t mode_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!mode || mode_len == 0)
        return -1;
    mode[0] = '\0';
    if (sqlite3_open_v2(IDENTITY_CONFIG_DB, &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK)
        goto out;
    sqlite3_busy_timeout(db, 1000);
    if (sqlite3_prepare_v2(db,
        "SELECT identify_mode FROM firewall_global WHERE id=1", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto out;
    snprintf(mode, mode_len, "%s",
             sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
    if (!strcmp(mode, "traffic"))
        snprintf(mode, mode_len, "%s", "device_and_traffic");
    if (strcmp(mode, "disabled") && strcmp(mode, "device_and_traffic") &&
        strcmp(mode, "traffic_only"))
        goto out;
    rc = 0;
out:
    if (st)
        sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return rc;
}

static void identity_runtime_write(void)
{
    char tmp[256];
    char payload[1024];
    int fd;
    int len;

    if (mkdir(IDENTITY_RUNTIME_DIR, 0755) != 0 && errno != EEXIST)
        return;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", IDENTITY_RUNTIME_STATE, (long)getpid());
    len = snprintf(payload, sizeof(payload),
        "{\"ok\":true,\"service\":\"dreamingwrt-identityd\",\"pid\":%ld,"
        "\"mode\":\"%s\",\"collector_requested\":%s,"
        "\"collector_ready\":%s,\"collector_active\":%s,"
        "\"device_identification_active\":%s,\"listeners_ready\":%d,"
        "\"tick_count\":%llu,\"last_tick_at\":%lld,\"updated_at\":%lld}\n",
        (long)getpid(), identity_mode,
        identity_collector_requested ? "true" : "false",
        jmx_identity_collector_ready() ? "true" : "false",
        identity_collector_active ? "true" : "false",
        identity_collector_active ? "true" : "false",
        jmx_identity_collector_listener_count(),
        (unsigned long long)identity_tick_count,
        (long long)identity_last_tick_at, (long long)time(NULL));
    if (len <= 0 || (size_t)len >= sizeof(payload))
        return;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return;
    if (write(fd, payload, (size_t)len) != len || fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return;
    }
    close(fd);
    if (rename(tmp, IDENTITY_RUNTIME_STATE) != 0)
        unlink(tmp);
}

static void identity_mode_reconcile(void)
{
    char mode[32] = "unavailable";
    int should_collect;
    int old_active = identity_collector_active;

    if (identity_mode_load(mode, sizeof(mode)) != 0)
        snprintf(mode, sizeof(mode), "%s", "unavailable");
    should_collect = !strcmp(mode, "device_and_traffic");
    identity_collector_requested = should_collect;
    if (should_collect && !identity_collector_active) {
        identity_collector_active = jmx_identity_collector_init() == 0 &&
                                    jmx_identity_collector_ready();
        identity_next_collect_at = identity_collector_active ? time(NULL) + 10 : 0;
    } else if (!should_collect && identity_collector_active) {
        jmx_identity_collector_close();
        identity_collector_active = 0;
        identity_next_collect_at = 0;
    }
    if (strcmp(identity_mode, mode) || old_active != identity_collector_active)
        snprintf(identity_mode, sizeof(identity_mode), "%s", mode);
    identity_runtime_write();
}

static void identity_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

static void identity_handle_sigusr2(int signo)
{
    (void)signo;
    if (current_log_level < LOG_LEVEL_DEBUG)
        current_log_level++;
    else
        current_log_level = LOG_LEVEL_WARN;
}

static void identity_tick_cb(struct uloop_timeout *t)
{
    time_t now = time(NULL);

    identity_mode_reconcile();
    if (identity_collector_active && now >= identity_next_collect_at) {
        jmx_identity_collector_tick();
        identity_tick_count++;
        identity_last_tick_at = now;
        identity_next_collect_at = now + 10;
        identity_runtime_write();
    }
    uloop_timeout_set(t, 2000);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    huginn_init();
    uloop_init();
    signal(SIGINT, identity_handle_signal);
    signal(SIGTERM, identity_handle_signal);
    signal(SIGUSR2, identity_handle_sigusr2);

    identity_tick_timer.cb = identity_tick_cb;
    uloop_timeout_set(&identity_tick_timer, 1000);
    uloop_run();

    uloop_timeout_cancel(&identity_tick_timer);
    if (identity_collector_active)
        jmx_identity_collector_close();
    identity_collector_active = 0;
    identity_runtime_write();
    huginn_close();
    uloop_done();
    return 0;
}
