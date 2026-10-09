// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define APD_RRM_FORWARD_STANDALONE_TEST 1
#define APD_RRM_FORWARD_MARKER_PATH "./marker"
#define APD_RRM_FORWARD_STATE_PATH "./state"
#define APD_RRM_FORWARD_INITIAL_MS 1
#define APD_RRM_FORWARD_INTERVAL_MS 2
#define APD_RRM_FORWARD_RETRY_MS 3
#define APD_RRM_FORWARD_MAX_FAILURES 3

struct uloop_timeout {
    void (*cb)(struct uloop_timeout *);
};
struct apd_command_result {
    char *text;
    size_t length;
    char *stderr_text;
    size_t stderr_length;
    int exit_status;
    int timed_out;
    int output_limited;
    int stderr_limited;
    const char *path;
};

static int flags[3];
static int writes[3];
static int fail_write = -1;
static int fail_restore = -1;
static int fail_read_after_first_write = -1;
static int hostapd_ready = 1;
static int wrong_identity = -1;
static int timer_ms;
static int timer_pending;
static const char *const expected_bssids[] = {
    "44:df:65:2e:de:26", "44:df:65:2e:de:25", "46:df:65:2e:de:27"
};

static int fixture_index(const char *interface)
{
    if (!strcmp(interface, "ath0")) return 0;
    if (!strcmp(interface, "ath1")) return 1;
    if (!strcmp(interface, "ath2")) return 2;
    return -1;
}

static int apd_readonly_command_bounded(const char *path, char *const argv[],
    int timeout_ms, size_t limit, struct apd_command_result *result)
{
    int index;
    char text[256];

    (void)timeout_ms;
    (void)limit;
    memset(result, 0, sizeof(*result));
    if (!strcmp(path, "/bin/sh")) {
        index = fixture_index(argv[2]);
        if (index < 0)
            return -1;
        if (!strcmp(argv[3], "g_fwd_act_app")) {
            if (index == fail_read_after_first_write && writes[0] == 1)
                return -1;
            snprintf(text, sizeof(text), "%s\tg_fwd_act_app:%d\n",
                     argv[2], flags[index]);
        } else if (!strcmp(argv[3], "fwd_act_app") && argv[4]) {
            int value = !strcmp(argv[4], "1") ? 1 :
                        !strcmp(argv[4], "0") ? 0 : -1;

            if (value < 0 || index == fail_write ||
                (value == 0 && index == fail_restore))
                return -1;
            flags[index] = value;
            writes[index]++;
            text[0] = '\0';
        } else {
            return -1;
        }
    } else if (!strcmp(path, "/usr/sbin/hostapd_cli")) {
        index = fixture_index(argv[4]);
        if (index < 0 || !hostapd_ready)
            return -1;
        snprintf(text, sizeof(text),
                 "state=ENABLED\nbssid[0]=%s\nssid[0]=%s\n",
                 index == wrong_identity ? "00:00:00:00:00:01" :
                     expected_bssids[index],
                 index == wrong_identity ? "Other" : "Xiaomi_DE23");
    } else {
        return -1;
    }
    result->text = strdup(text);
    result->stderr_text = strdup("");
    if (!result->text || !result->stderr_text)
        return -1;
    result->length = strlen(result->text);
    result->exit_status = 0;
    return 0;
}

static void apd_command_result_free(struct apd_command_result *result)
{
    free(result->text);
    free(result->stderr_text);
    memset(result, 0, sizeof(*result));
}

static int uloop_timeout_set(struct uloop_timeout *timer, int milliseconds)
{
    (void)timer;
    timer_ms = milliseconds;
    timer_pending = 1;
    return 0;
}

static int uloop_timeout_cancel(struct uloop_timeout *timer)
{
    (void)timer;
    timer_pending = 0;
    return 0;
}

#include "../src/apd/apd_rrm_forward.c"

#define CHECK(label, expression) do { \
    if (!(expression)) { fprintf(stderr, "FAIL %s\n", label); return 1; } \
} while (0)

static int write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    int ok;

    if (!file)
        return -1;
    ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok ? 0 : -1;
}

static void marker(const char *bssid1)
{
    char value[256];

    snprintf(value, sizeof(value),
        "version=1\nssid=Xiaomi_DE23\nath0=%s\nath1=%s\nath2=%s\n",
        expected_bssids[0], bssid1 ? bssid1 : expected_bssids[1],
        expected_bssids[2]);
    if (write_text(APD_RRM_FORWARD_MARKER_PATH, value) != 0)
        abort();
}

static void reset(int first, int second, int third)
{
    unlink(APD_RRM_FORWARD_MARKER_PATH);
    unlink(APD_RRM_FORWARD_STATE_PATH);
    flags[0] = first;
    flags[1] = second;
    flags[2] = third;
    memset(writes, 0, sizeof(writes));
    fail_write = wrong_identity = -1;
    fail_restore = fail_read_after_first_write = -1;
    hostapd_ready = 1;
    timer_pending = 0;
    apd_rrm_forward_failures = apd_rrm_forward_restoring = 0;
}

static void tick(void)
{
    timer_pending = 0;
    apd_rrm_forward_timer.cb(&apd_rrm_forward_timer);
}

int main(void)
{
    struct apd_rrm_forward_state state;

    reset(0, 0, 0);
    CHECK("no marker inert",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_INERT &&
          flags[0] == 0 && flags[1] == 0 && flags[2] == 0);

    marker(NULL);
    CHECK("enable exact BSS set",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_OK &&
          flags[0] == 1 && flags[1] == 1 && flags[2] == 1);
    CHECK("state persisted first", apd_rrm_forward_state_read(&state) == 0 &&
          state.original[0] == 0 && state.original[1] == 0 &&
          state.original[2] == 0);
    memset(writes, 0, sizeof(writes));
    CHECK("reconcile idempotent",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_OK &&
          !writes[0] && !writes[1] && !writes[2]);

    unlink(APD_RRM_FORWARD_MARKER_PATH);
    CHECK("marker removal restores",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_INERT &&
          flags[0] == 0 && flags[1] == 0 && flags[2] == 0 &&
          access(APD_RRM_FORWARD_STATE_PATH, F_OK) != 0);

    reset(1, 0, 1);
    marker(NULL);
    CHECK("preserve mixed originals",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_OK &&
          flags[0] == 1 && flags[1] == 1 && flags[2] == 1);
    CHECK("normal stop restores", apd_rrm_forward_restore() == 0 &&
          flags[0] == 1 && flags[1] == 0 && flags[2] == 1);

    reset(0, 0, 0);
    marker(NULL);
    fail_write = 1;
    CHECK("partial write rolls back",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_FAILED &&
          flags[0] == 0 && flags[1] == 0 && flags[2] == 0 &&
          access(APD_RRM_FORWARD_STATE_PATH, F_OK) != 0);

    reset(0, 0, 0);
    marker(NULL);
    hostapd_ready = 0;
    CHECK("hostapd readiness retries",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_RETRY &&
          !writes[0] && !writes[1] && !writes[2] &&
          access(APD_RRM_FORWARD_STATE_PATH, F_OK) != 0);

    reset(0, 0, 0);
    marker(NULL);
    wrong_identity = 2;
    CHECK("identity mismatch refuses",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_FAILED &&
          !writes[0] && !writes[1] && !writes[2]);

    reset(0, 0, 0);
    marker(NULL);
    CHECK("first process enables",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_OK);
    flags[1] = 0;
    CHECK("restart reuses saved originals",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_OK &&
          flags[1] == 1 && apd_rrm_forward_state_read(&state) == 0 &&
          state.original[1] == 0);

    marker("44:df:65:2e:de:24");
    CHECK("marker identity change restores and stops",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_FAILED &&
          flags[0] == 0 && flags[1] == 0 && flags[2] == 0 &&
          access(APD_RRM_FORWARD_STATE_PATH, F_OK) != 0);

    reset(0, 0, 0);
    marker(NULL);
    fail_read_after_first_write = 1;
    CHECK("partial read failure rolls back",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_FAILED &&
          flags[0] == 0 && flags[1] == 0 && flags[2] == 0);

    reset(0, 0, 0);
    CHECK("unmarked startup has no timer",
          apd_rrm_forward_start() == 0 && !timer_pending);
    marker(NULL);
    CHECK("startup schedules timer",
          apd_rrm_forward_start() == 0 &&
          timer_pending && timer_ms == APD_RRM_FORWARD_INITIAL_MS);
    tick();
    CHECK("successful timer repeats",
          flags[0] == 1 && timer_pending &&
          timer_ms == APD_RRM_FORWARD_INTERVAL_MS);
    wrong_identity = 1;
    tick();
    CHECK("identity change never writes replacement BSS",
          flags[0] == 0 && flags[1] == 1 && flags[2] == 0 &&
          writes[1] == 1 && apd_rrm_forward_restoring && timer_pending &&
          access(APD_RRM_FORWARD_STATE_PATH, F_OK) == 0);
    wrong_identity = -1;
    tick();
    CHECK("restore retry finishes without reenable",
          flags[0] == 0 && flags[1] == 0 && flags[2] == 0 &&
          !timer_pending && access(APD_RRM_FORWARD_STATE_PATH, F_OK) != 0);

    reset(0, 0, 0);
    marker(NULL);
    CHECK("second timer startup", apd_rrm_forward_start() == 0);
    tick();
    flags[1] = 0;
    fail_write = 1;
    fail_restore = 0;
    tick();
    CHECK("failed rollback retries",
          apd_rrm_forward_restoring && timer_pending &&
          flags[0] == 1 && flags[1] == 0 && flags[2] == 0);
    tick();
    tick();
    tick();
    CHECK("bounded retry retains journal",
          !timer_pending && access(APD_RRM_FORWARD_STATE_PATH, F_OK) == 0);
    fail_restore = fail_write = -1;
    apd_rrm_forward_stop();
    CHECK("stop retries pending recovery",
          flags[0] == 0 && !timer_pending &&
          access(APD_RRM_FORWARD_STATE_PATH, F_OK) != 0);

    reset(0, 0, 0);
    marker(NULL);
    CHECK("corrupt state created", write_text(APD_RRM_FORWARD_STATE_PATH,
          "version=1\nssid=Xiaomi_DE23\n") == 0);
    CHECK("corrupt state fails closed",
          apd_rrm_forward_reconcile() == APD_RRM_FORWARD_FAILED &&
          !writes[0] && !writes[1] && !writes[2] &&
          apd_rrm_forward_restore() != 0);
    reset(0, 0, 0);
    unlink(APD_RRM_FORWARD_MARKER_PATH);
    puts("ok: QSDK RRM forwarding exact identity, durable ownership, rollback and restart recovery");
    return 0;
}
