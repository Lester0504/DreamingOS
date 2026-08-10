// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt metrics scheduler daemon. */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#define METRICSD_INTERVAL_MS 2000
#define METRICSD_BACKOFF_MAX_MS 10000
#define METRICSD_FAST_TIMEOUT_MS 3000
#define METRICSD_SLOW_TIMEOUT_MS 8000
#define METRICSD_SLOW_BACKOFF_MAX_S 30
#define METRICSD_HEALTH_TICKS 5
#define METRICSD_FLUSH_TICKS 150
#define METRICSD_PROFILE_TICKS 300
#define METRICSD_AUDIT_FLOW_TICKS 30
#define METRICSD_TOPOLOGY_HISTORY_TICKS 15

static struct ubus_context *metrics_ubus;
static struct blob_buf metrics_blob;
static struct uloop_timeout metrics_timer;
static unsigned int metrics_tick_count;
static int metrics_pending_flush_health;
static int metrics_pending_refresh_profiles;
static time_t metrics_last_warn;
static time_t metrics_last_slow_warn;
static unsigned int metrics_consecutive_failures;
static unsigned int metrics_slow_consecutive_failures;
static time_t metrics_slow_retry_after;
static const char *metrics_last_failure_msg;
static time_t metrics_last_tick_at;
static time_t metrics_started_at;
static time_t metrics_last_stall_warn;

/*
 * Stall self-check. A collector that stops ticking used to surface only as blank
 * pages in the UI, 23 hours after the fact, because a live process sitting in
 * epoll_wait with an open ubus socket looks healthy from the outside. The tick
 * stamps metrics_last_tick_at; this timer runs on its own uloop timeout, so it
 * still fires if the tick timer is the thing that died, and reports the gap.
 */
#define METRICSD_STALL_CHECK_MS 30000
#define METRICSD_STALL_AFTER_TICKS 5

static struct uloop_timeout metrics_stall_timer;

static void metrics_stall_check_cb(struct uloop_timeout *t)
{
    time_t now = time(NULL);
    time_t reference;
    long gap;
    long threshold = (long)((METRICSD_INTERVAL_MS / 1000) * METRICSD_STALL_AFTER_TICKS);

    uloop_timeout_set(t, METRICSD_STALL_CHECK_MS);

    reference = metrics_last_tick_at ? metrics_last_tick_at : metrics_started_at;
    if (!reference)
        return;
    gap = (long)(now - reference);
    if (gap < threshold)
        return;
    if (now - metrics_last_stall_warn < 300)
        return;
    metrics_last_stall_warn = now;
    fprintf(stderr,
            "[dreamingwrt-metricsd] tick stalled: no tick for %lds (threshold %lds, ticks=%u)\n",
            gap, threshold, metrics_tick_count);
}

static void metrics_warn_throttled_at(const char *msg, int rc, unsigned int failures,
                                      int next_delay_ms, time_t *last_warn)
{
    time_t now = time(NULL);

    /*
     * Skip the first failure. rc=7 is UBUS_STATUS_TIMEOUT and its usual cause
     * here is core restarting, so its ubus object is briefly gone; the next tick
     * succeeds. stderr from these daemons is filed under daemon.err by the
     * supervisor, which turned a self-healing blip into a recurring
     * error-severity report. A fault that does not recover still gets logged,
     * because failures keeps climbing past 1.
     */
    if (failures <= 1)
        return;
    if (now - *last_warn < 30)
        return;
    *last_warn = now;
    fprintf(stderr, "[dreamingwrt-metricsd] %s rc=%d failures=%u next_delay_ms=%d\n",
            msg, rc, failures, next_delay_ms);
}

static void metrics_warn_throttled(const char *msg, int rc, int next_delay_ms)
{
    metrics_warn_throttled_at(msg, rc, metrics_consecutive_failures,
                              next_delay_ms, &metrics_last_warn);
}

static void metrics_ubus_close(void)
{
    if (metrics_ubus) {
        ubus_free(metrics_ubus);
        metrics_ubus = NULL;
    }
}

static int metrics_ubus_ensure(void)
{
    if (metrics_ubus)
        return 0;
    metrics_ubus = ubus_connect(NULL);
    return metrics_ubus ? 0 : -1;
}

static int metrics_invoke_tick(int wan_health, int ipv6_load, int interface_traffic,
                               int audit_flow_sample, int flush_health, int refresh_profiles,
                               int topology_history,
                               int timeout_ms, const char *failure_msg)
{
    uint32_t id = 0;
    int rc;

    if (metrics_ubus_ensure() != 0) {
        metrics_last_failure_msg = "ubus connect failed";
        return -1;
    }

    rc = ubus_lookup_id(metrics_ubus, "dreamingwrt", &id);
    if (rc != UBUS_STATUS_OK) {
        metrics_last_failure_msg = "dreamingwrt ubus object not ready";
        metrics_ubus_close();
        return rc;
    }

    blob_buf_init(&metrics_blob, 0);
    blobmsg_add_u32(&metrics_blob, "wan_health", wan_health ? 1 : 0);
    blobmsg_add_u32(&metrics_blob, "ipv6_load", ipv6_load ? 1 : 0);
    blobmsg_add_u32(&metrics_blob, "interface_traffic", interface_traffic ? 1 : 0);
    blobmsg_add_u32(&metrics_blob, "audit_flow_sample", audit_flow_sample ? 1 : 0);
    blobmsg_add_u32(&metrics_blob, "flush_health", flush_health ? 1 : 0);
    blobmsg_add_u32(&metrics_blob, "wan_profiles", refresh_profiles ? 1 : 0);
    blobmsg_add_u32(&metrics_blob, "topology_history", topology_history ? 1 : 0);
    rc = ubus_invoke(metrics_ubus, id, "_metrics_tick", metrics_blob.head,
                     NULL, NULL, timeout_ms);
    blob_buf_free(&metrics_blob);

    if (rc != UBUS_STATUS_OK) {
        metrics_last_failure_msg = failure_msg ? failure_msg : "_metrics_tick invoke failed";
        metrics_ubus_close();
        return rc;
    }
    metrics_last_failure_msg = NULL;
    return 0;
}

static void metrics_record_slow_result(int rc)
{
    int delay_s;

    if (rc == 0) {
        metrics_slow_consecutive_failures = 0;
        metrics_slow_retry_after = 0;
        return;
    }

    metrics_slow_consecutive_failures++;
    delay_s = 4 * (int)metrics_slow_consecutive_failures;
    if (delay_s > METRICSD_SLOW_BACKOFF_MAX_S)
        delay_s = METRICSD_SLOW_BACKOFF_MAX_S;
    metrics_slow_retry_after = time(NULL) + delay_s;
    metrics_warn_throttled_at(metrics_last_failure_msg ?
                              metrics_last_failure_msg : "slow _metrics_tick invoke failed",
                              rc, metrics_slow_consecutive_failures,
                              delay_s * 1000, &metrics_last_slow_warn);
}

static int metrics_next_delay_ms(int rc)
{
    int delay = METRICSD_INTERVAL_MS;

    if (rc == 0) {
        metrics_consecutive_failures = 0;
        return delay;
    }

    metrics_consecutive_failures++;
    delay = METRICSD_INTERVAL_MS * (int)(metrics_consecutive_failures + 1);
    if (delay > METRICSD_BACKOFF_MAX_MS)
        delay = METRICSD_BACKOFF_MAX_MS;
    /*
     * Clamp both ends. A delay of 0 would spin the loop, and a negative one --
     * reachable if metrics_consecutive_failures ever grew enough to overflow the
     * int multiply above -- is passed to uloop as a timeout it can never fire,
     * which is indistinguishable from a dead scheduler.
     */
    if (delay < METRICSD_INTERVAL_MS)
        delay = METRICSD_BACKOFF_MAX_MS;
    metrics_warn_throttled(metrics_last_failure_msg ? metrics_last_failure_msg : "_metrics_tick invoke failed",
                           rc, delay);
    return delay;
}

static void metrics_tick_cb(struct uloop_timeout *t)
{
    int flush_health;
    int refresh_profiles;
    int wan_health;
    int ipv6_load;
    int audit_flow_sample;
    int topology_history;
    int slow_due;
    int rc;
    int slow_rc;
    int next_delay_ms;
    time_t now;

    /*
     * Re-arm first, unconditionally. Everything below this point can fail, and
     * the old ordering put the only uloop_timeout_set() call at the very end of
     * the function, so any future early return silently retired the collector
     * for the lifetime of the process -- with no log line and no ubus symptom,
     * because the socket stays connected and the process stays in epoll_wait.
     * Arming up front costs a fixed cadence during backoff (the delay computed
     * at the end still applies from the next tick onward) and removes the class
     * of bug entirely.
     */
    uloop_timeout_set(t, METRICSD_INTERVAL_MS);
    metrics_last_tick_at = time(NULL);

    metrics_tick_count++;
    wan_health = (metrics_tick_count % METRICSD_HEALTH_TICKS) == 0;
    ipv6_load = wan_health;
    audit_flow_sample = (metrics_tick_count % METRICSD_AUDIT_FLOW_TICKS) == 0;
    topology_history = (metrics_tick_count % METRICSD_TOPOLOGY_HISTORY_TICKS) == 0;
    if ((metrics_tick_count % METRICSD_FLUSH_TICKS) == 0)
        metrics_pending_flush_health = 1;
    if ((metrics_tick_count % METRICSD_PROFILE_TICKS) == 0)
        metrics_pending_refresh_profiles = 1;

    flush_health = metrics_pending_flush_health;
    refresh_profiles = metrics_pending_refresh_profiles;
    if (flush_health || refresh_profiles) {
        wan_health = 1;
        ipv6_load = 1;
    }
    slow_due = wan_health || ipv6_load || audit_flow_sample || flush_health ||
               refresh_profiles || topology_history;

    rc = metrics_invoke_tick(0, 0, 1, 0, 0, 0, 0,
                             METRICSD_FAST_TIMEOUT_MS,
                             "fast _metrics_tick invoke failed");
    if (rc == 0 && slow_due) {
        now = time(NULL);
        if (!metrics_slow_retry_after || now >= metrics_slow_retry_after) {
            slow_rc = metrics_invoke_tick(wan_health, ipv6_load, 0, audit_flow_sample,
                                          flush_health, refresh_profiles,
                                          topology_history,
                                          METRICSD_SLOW_TIMEOUT_MS,
                                          "slow _metrics_tick invoke failed");
            metrics_record_slow_result(slow_rc);
            if (slow_rc == 0) {
                if (flush_health)
                    metrics_pending_flush_health = 0;
                if (refresh_profiles)
                    metrics_pending_refresh_profiles = 0;
            }
        }
    }
    next_delay_ms = metrics_next_delay_ms(rc);

    if (metrics_tick_count >= 86400)
        metrics_tick_count = 0;
    uloop_timeout_set(t, next_delay_ms);
}

static void metrics_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    signal(SIGINT, metrics_handle_signal);
    signal(SIGTERM, metrics_handle_signal);

    uloop_init();
    metrics_started_at = time(NULL);
    metrics_timer.cb = metrics_tick_cb;
    uloop_timeout_set(&metrics_timer, 1000);
    metrics_stall_timer.cb = metrics_stall_check_cb;
    uloop_timeout_set(&metrics_stall_timer, METRICSD_STALL_CHECK_MS);
    uloop_run();

    uloop_timeout_cancel(&metrics_timer);
    uloop_timeout_cancel(&metrics_stall_timer);
    metrics_ubus_close();
    uloop_done();
    return 0;
}
