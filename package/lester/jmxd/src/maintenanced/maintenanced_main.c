// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt maintenance scheduler daemon. */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#define MAINTENANCED_INTERVAL_MS 1000
#define MAINTENANCED_INITIAL_DELAY_MS 5000
#define MAINTENANCED_BACKOFF_MAX_MS 10000
#define MAINTENANCED_HEALTH_TICKS 30
#define MAINTENANCED_CLIENT_TICKS 60
#define MAINTENANCED_FULL_TICKS 3600
#define MAINTENANCED_SYSTEM_EVENT_TICKS 300
/* Retention must not depend on a daemon surviving for a full day.  Core's
 * internal flow sampler writes outside the audit_flows ingest path, so prune
 * often enough to bound short-lived samples across normal deployments. */
#define MAINTENANCED_PRUNE_TICKS 600
#define MAINTENANCED_CLIENT_CONTROL_TICKS 30
#define MAINTENANCED_POWER_TICKS 5

static struct ubus_context *maintenance_ubus;
static struct blob_buf maintenance_blob;
static struct uloop_timeout maintenance_timer;
static unsigned int maintenance_tick_count;
static time_t maintenance_last_warn;
static int maintenance_pending_health_status;
static int maintenance_pending_client_sync;
static int maintenance_pending_full;
static int maintenance_pending_system_status_event;
/* Run one bounded retention prune after every start, then every 10 minutes. */
static int maintenance_pending_db_prune = 1;
static int maintenance_pending_client_control;
static int maintenance_pending_power_schedule = 1;
static unsigned int maintenance_consecutive_failures;
static const char *maintenance_last_failure_msg;

static void maintenance_warn_throttled(const char *msg, int rc, int next_delay_ms)
{
    time_t now = time(NULL);

    /*
     * A single timeout that the next tick recovers from is not an error.
     *
     * rc=7 is UBUS_STATUS_TIMEOUT, and the common cause is entirely benign:
     * core was restarting, so its ubus object was briefly absent. Every
     * occurrence observed on 30.1 landed within a minute of a core restart,
     * always with failures=1, and never recurred while core stayed up. Everything
     * these daemons print goes to stderr, which the supervisor files under
     * daemon.err, so that self-healing blip was being reported at error severity
     * and read as a recurring production fault.
     *
     * Staying quiet on the first failure keeps the transient out of the error
     * log while preserving the signal that matters: a fault that does not
     * recover still reports, because consecutive_failures keeps climbing.
     */
    if (maintenance_consecutive_failures <= 1)
        return;
    if (now - maintenance_last_warn < 30)
        return;
    maintenance_last_warn = now;
    fprintf(stderr,
            "[dreamingwrt-maintenanced] %s rc=%d failures=%u next_delay_ms=%d pending={health:%d,client:%d,full:%d,system:%d,prune:%d,control:%d,power:%d}\n",
            msg, rc, maintenance_consecutive_failures, next_delay_ms,
            maintenance_pending_health_status, maintenance_pending_client_sync,
            maintenance_pending_full, maintenance_pending_system_status_event,
            maintenance_pending_db_prune, maintenance_pending_client_control,
            maintenance_pending_power_schedule);
}

static void maintenance_ubus_close(void)
{
    if (maintenance_ubus) {
        ubus_free(maintenance_ubus);
        maintenance_ubus = NULL;
    }
}

static int maintenance_ubus_ensure(void)
{
    if (maintenance_ubus)
        return 0;
    maintenance_ubus = ubus_connect(NULL);
    return maintenance_ubus ? 0 : -1;
}

static int maintenance_invoke_tick(int health_status, int client_sync,
                                   int full_maintenance, int system_status_event,
                                   int db_prune, int client_control,
                                   int power_schedule)
{
    uint32_t id = 0;
    int rc;

    if (maintenance_ubus_ensure() != 0) {
        maintenance_last_failure_msg = "ubus connect failed";
        return -1;
    }

    rc = ubus_lookup_id(maintenance_ubus, "dreamingwrt", &id);
    if (rc != UBUS_STATUS_OK) {
        maintenance_last_failure_msg = "dreamingwrt ubus object not ready";
        maintenance_ubus_close();
        return rc;
    }

    blob_buf_init(&maintenance_blob, 0);
    blobmsg_add_u32(&maintenance_blob, "health_status", health_status ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "client_sync", client_sync ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "daily_archive", full_maintenance ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "lan_ip", full_maintenance ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "expired_clients", full_maintenance ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "dump_clients", full_maintenance ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "history_cleanup", full_maintenance ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "system_status_event", system_status_event ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "db_prune", db_prune ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "client_control_schedule", client_control ? 1 : 0);
    blobmsg_add_u32(&maintenance_blob, "power_schedule", power_schedule ? 1 : 0);
    rc = ubus_invoke(maintenance_ubus, id, "_maintenance_tick", maintenance_blob.head,
                     NULL, NULL, 30000);
    blob_buf_free(&maintenance_blob);

    if (rc != UBUS_STATUS_OK) {
        maintenance_last_failure_msg = "_maintenance_tick invoke failed";
        maintenance_ubus_close();
        return rc;
    }
    maintenance_last_failure_msg = NULL;
    return 0;
}

static int maintenance_next_delay_ms(int rc)
{
    int delay = MAINTENANCED_INTERVAL_MS;

    if (rc == 0) {
        maintenance_consecutive_failures = 0;
        return delay;
    }

    maintenance_consecutive_failures++;
    delay = MAINTENANCED_INTERVAL_MS * (int)(maintenance_consecutive_failures + 1);
    if (delay > MAINTENANCED_BACKOFF_MAX_MS)
        delay = MAINTENANCED_BACKOFF_MAX_MS;
    maintenance_warn_throttled(maintenance_last_failure_msg ? maintenance_last_failure_msg : "_maintenance_tick invoke failed",
                               rc, delay);
    return delay;
}

static void maintenance_tick_cb(struct uloop_timeout *t)
{
    int full_maintenance;
    int system_status_event;
    int health_status;
    int client_sync;
    int db_prune;
    int client_control;
    int power_schedule;
    int rc = 0;
    int next_delay_ms;

    maintenance_tick_count++;
    health_status = (maintenance_tick_count % MAINTENANCED_HEALTH_TICKS) == 0;
    client_sync = (maintenance_tick_count % MAINTENANCED_CLIENT_TICKS) == 0;
    full_maintenance = (maintenance_tick_count % MAINTENANCED_FULL_TICKS) == 0;
    system_status_event = (maintenance_tick_count % MAINTENANCED_SYSTEM_EVENT_TICKS) == 0;
    db_prune = (maintenance_tick_count % MAINTENANCED_PRUNE_TICKS) == 0;
    client_control = (maintenance_tick_count % MAINTENANCED_CLIENT_CONTROL_TICKS) == 0;
    power_schedule = (maintenance_tick_count % MAINTENANCED_POWER_TICKS) == 0;
    if (health_status)
        maintenance_pending_health_status = 1;
    if (client_sync)
        maintenance_pending_client_sync = 1;
    if (full_maintenance)
        maintenance_pending_full = 1;
    if (system_status_event)
        maintenance_pending_system_status_event = 1;
    if (db_prune)
        maintenance_pending_db_prune = 1;
    if (client_control)
        maintenance_pending_client_control = 1;
    if (power_schedule)
        maintenance_pending_power_schedule = 1;

    if (maintenance_pending_health_status || maintenance_pending_client_sync ||
        maintenance_pending_full || maintenance_pending_system_status_event ||
        maintenance_pending_db_prune || maintenance_pending_client_control ||
        maintenance_pending_power_schedule) {
        health_status = maintenance_pending_health_status;
        client_sync = maintenance_pending_client_sync;
        full_maintenance = maintenance_pending_full;
        system_status_event = maintenance_pending_system_status_event;
        db_prune = maintenance_pending_db_prune;
        client_control = maintenance_pending_client_control;
        power_schedule = maintenance_pending_power_schedule;

        rc = maintenance_invoke_tick(health_status, client_sync, full_maintenance,
                                     system_status_event, db_prune, client_control,
                                     power_schedule);
        if (rc == 0) {
            if (health_status)
                maintenance_pending_health_status = 0;
            if (client_sync)
                maintenance_pending_client_sync = 0;
            if (full_maintenance)
                maintenance_pending_full = 0;
            if (system_status_event)
                maintenance_pending_system_status_event = 0;
            if (db_prune)
                maintenance_pending_db_prune = 0;
            if (client_control)
                maintenance_pending_client_control = 0;
            if (power_schedule)
                maintenance_pending_power_schedule = 0;
        }
    }
    next_delay_ms = maintenance_next_delay_ms(rc);

    if (maintenance_tick_count >= 86400)
        maintenance_tick_count = 0;
    uloop_timeout_set(t, next_delay_ms);
}

static void maintenance_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    signal(SIGINT, maintenance_handle_signal);
    signal(SIGTERM, maintenance_handle_signal);

    uloop_init();
    maintenance_timer.cb = maintenance_tick_cb;
    uloop_timeout_set(&maintenance_timer, MAINTENANCED_INITIAL_DELAY_MS);
    uloop_run();

    uloop_timeout_cancel(&maintenance_timer);
    maintenance_ubus_close();
    uloop_done();
    return 0;
}
