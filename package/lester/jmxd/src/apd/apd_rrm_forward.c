// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_rrm_forward.h"

#ifndef APD_RRM_FORWARD_STANDALONE_TEST
#include "apd_internal.h"
#include "apd_readonly_command.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef APD_RRM_FORWARD_MARKER_PATH
#define APD_RRM_FORWARD_MARKER_PATH "/etc/dreamingwrt/rrm-forward.conf"
#endif
#ifndef APD_RRM_FORWARD_STATE_PATH
#define APD_RRM_FORWARD_STATE_PATH "/var/run/dreamingwrt-apd/rrm-forward.state"
#endif
#ifndef APD_RRM_FORWARD_CFG80211TOOL
#define APD_RRM_FORWARD_CFG80211TOOL "/usr/sbin/cfg80211tool"
#endif
#ifndef APD_RRM_FORWARD_SHELL
#define APD_RRM_FORWARD_SHELL "/bin/sh"
#endif
#ifndef APD_RRM_FORWARD_HOSTAPD_CLI
#define APD_RRM_FORWARD_HOSTAPD_CLI "/usr/sbin/hostapd_cli"
#endif
#ifndef APD_RRM_FORWARD_INITIAL_MS
#define APD_RRM_FORWARD_INITIAL_MS 2000
#endif
#ifndef APD_RRM_FORWARD_INTERVAL_MS
#define APD_RRM_FORWARD_INTERVAL_MS 30000
#endif
#ifndef APD_RRM_FORWARD_RETRY_MS
#define APD_RRM_FORWARD_RETRY_MS 2000
#endif
#ifndef APD_RRM_FORWARD_MAX_FAILURES
#define APD_RRM_FORWARD_MAX_FAILURES 15
#endif
#ifndef APD_RRM_FORWARD_COMMAND_TIMEOUT_MS
#define APD_RRM_FORWARD_COMMAND_TIMEOUT_MS 1500
#endif

#define APD_RRM_FORWARD_BSS_COUNT 3
#define APD_RRM_FORWARD_SSID "Xiaomi_DE23"

struct apd_rrm_forward_config {
    char bssid[APD_RRM_FORWARD_BSS_COUNT][18];
};

struct apd_rrm_forward_state {
    struct apd_rrm_forward_config config;
    int original[APD_RRM_FORWARD_BSS_COUNT];
};

static const char *const apd_rrm_forward_interfaces[] = {
    "ath0", "ath1", "ath2"
};
static const char *const apd_rrm_forward_ctrl_dirs[] = {
    "/var/run/hostapd-wifi0", "/var/run/hostapd-wifi1",
    "/var/run/hostapd-wifi2"
};

static struct uloop_timeout apd_rrm_forward_timer;
static int apd_rrm_forward_failures;
static int apd_rrm_forward_restoring;

static int apd_rrm_forward_bssid_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (value[i] != ':')
                return 0;
        } else if (!isdigit((unsigned char)value[i]) &&
                   !(value[i] >= 'a' && value[i] <= 'f')) {
            return 0;
        }
    }
    return 1;
}

static int apd_rrm_forward_read_line(FILE *file, const char *expected,
                                     char *value, size_t value_size)
{
    char line[128];
    size_t prefix = strlen(expected);
    size_t length;

    if (!fgets(line, sizeof(line), file))
        return -1;
    length = strlen(line);
    if (!length || line[length - 1] != '\n' || strncmp(line, expected, prefix))
        return -1;
    line[--length] = '\0';
    if (length < prefix || length - prefix + 1 > value_size)
        return -1;
    memcpy(value, line + prefix, length - prefix + 1);
    return 0;
}

static int apd_rrm_forward_config_read(struct apd_rrm_forward_config *config)
{
    static const char *const prefixes[] = { "ath0=", "ath1=", "ath2=" };
    FILE *file;
    char value[64];
    size_t i;
    int rc = -1;

    if (!config)
        return -1;
    file = fopen(APD_RRM_FORWARD_MARKER_PATH, "r");
    if (!file)
        return errno == ENOENT ? 1 : -1;
    if (apd_rrm_forward_read_line(file, "version=", value, sizeof(value)) != 0 ||
        strcmp(value, "1") ||
        apd_rrm_forward_read_line(file, "ssid=", value, sizeof(value)) != 0 ||
        strcmp(value, APD_RRM_FORWARD_SSID))
        goto done;
    for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++) {
        if (apd_rrm_forward_read_line(file, prefixes[i], config->bssid[i],
                                      sizeof(config->bssid[i])) != 0 ||
            !apd_rrm_forward_bssid_valid(config->bssid[i]))
            goto done;
    }
    if (fgetc(file) != EOF)
        goto done;
    rc = 0;
done:
    fclose(file);
    return rc;
}

static int apd_rrm_forward_state_read(struct apd_rrm_forward_state *state)
{
    static const char *const bssid_prefixes[] = {
        "ath0_bssid=", "ath1_bssid=", "ath2_bssid="
    };
    static const char *const value_prefixes[] = {
        "ath0_original=", "ath1_original=", "ath2_original="
    };
    FILE *file;
    char value[64];
    size_t i;
    int rc = -1;

    if (!state)
        return -1;
    file = fopen(APD_RRM_FORWARD_STATE_PATH, "r");
    if (!file)
        return errno == ENOENT ? 1 : -1;
    if (apd_rrm_forward_read_line(file, "version=", value, sizeof(value)) != 0 ||
        strcmp(value, "1") ||
        apd_rrm_forward_read_line(file, "ssid=", value, sizeof(value)) != 0 ||
        strcmp(value, APD_RRM_FORWARD_SSID))
        goto done;
    for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++) {
        if (apd_rrm_forward_read_line(file, bssid_prefixes[i],
                state->config.bssid[i], sizeof(state->config.bssid[i])) != 0 ||
            !apd_rrm_forward_bssid_valid(state->config.bssid[i]) ||
            apd_rrm_forward_read_line(file, value_prefixes[i], value,
                                      sizeof(value)) != 0 ||
            (strcmp(value, "0") && strcmp(value, "1")))
            goto done;
        state->original[i] = value[0] - '0';
    }
    if (fgetc(file) != EOF)
        goto done;
    rc = 0;
done:
    fclose(file);
    return rc;
}

static int apd_rrm_forward_state_write(const struct apd_rrm_forward_state *state)
{
    char temporary[PATH_MAX];
    FILE *file = NULL;
    int fd = -1;
    int rc = -1;
    int written;
    size_t i;

    if (!state)
        return -1;
    written = snprintf(temporary, sizeof(temporary), "%s.new.%ld",
                       APD_RRM_FORWARD_STATE_PATH, (long)getpid());
    if (written < 0 || (size_t)written >= sizeof(temporary))
        return -1;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    file = fdopen(fd, "w");
    if (!file)
        goto done;
    fd = -1;
    if (fprintf(file, "version=1\nssid=%s\n", APD_RRM_FORWARD_SSID) < 0)
        goto done;
    for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++)
        if (fprintf(file, "%s_bssid=%s\n%s_original=%d\n",
                    apd_rrm_forward_interfaces[i], state->config.bssid[i],
                    apd_rrm_forward_interfaces[i], state->original[i]) < 0)
            goto done;
    if (fflush(file) != 0 || fsync(fileno(file)) != 0)
        goto done;
    if (fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;
    if (rename(temporary, APD_RRM_FORWARD_STATE_PATH) != 0)
        goto done;
    rc = 0;
done:
    if (file)
        fclose(file);
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(temporary);
    return rc;
}

static int apd_rrm_forward_command(const char *path, char *const argv[],
                                   struct apd_command_result *result)
{
    return apd_readonly_command_bounded(path, argv,
        APD_RRM_FORWARD_COMMAND_TIMEOUT_MS, 4096, result);
}

static int apd_rrm_forward_flag_read(size_t index, int *value)
{
    struct apd_command_result result;
    char *argv[] = { "sh", APD_RRM_FORWARD_CFG80211TOOL,
                     (char *)apd_rrm_forward_interfaces[index],
                     "g_fwd_act_app", NULL };
    char interface[16];
    char extra;
    int parsed;
    int rc = -1;

    memset(&result, 0, sizeof(result));
    if (apd_rrm_forward_command(APD_RRM_FORWARD_SHELL, argv, &result) != 0)
        goto done;
    parsed = sscanf(result.text ? result.text : "", "%15s g_fwd_act_app:%d %c",
                    interface, value, &extra);
    if (parsed == 2 && !strcmp(interface, apd_rrm_forward_interfaces[index]) &&
        (*value == 0 || *value == 1))
        rc = 0;
done:
    apd_command_result_free(&result);
    return rc;
}

static int apd_rrm_forward_flag_write(size_t index, int value)
{
    struct apd_command_result result;
    char setting[2] = { value ? '1' : '0', '\0' };
    char *argv[] = { "sh", APD_RRM_FORWARD_CFG80211TOOL,
                     (char *)apd_rrm_forward_interfaces[index],
                     "fwd_act_app", setting, NULL };
    int readback = -1;
    int rc;

    memset(&result, 0, sizeof(result));
    rc = apd_rrm_forward_command(APD_RRM_FORWARD_SHELL, argv, &result);
    apd_command_result_free(&result);
    if (rc != 0 || apd_rrm_forward_flag_read(index, &readback) != 0)
        return -1;
    return readback == value ? 0 : -1;
}

/* Returns 0 for an exact match, 1 while hostapd is not ready, and -1 for
 * an explicit identity mismatch. */
static int apd_rrm_forward_identity(size_t index, const char *bssid)
{
    struct apd_command_result result;
    char *argv[] = { "hostapd_cli", "-p",
                     (char *)apd_rrm_forward_ctrl_dirs[index], "-i",
                     (char *)apd_rrm_forward_interfaces[index], "status", NULL };
    char *line;
    char *save = NULL;
    int state = 0, ssid = 0, address = 0;

    memset(&result, 0, sizeof(result));
    if (apd_rrm_forward_command(APD_RRM_FORWARD_HOSTAPD_CLI, argv, &result) != 0) {
        apd_command_result_free(&result);
        return 1;
    }
    for (line = result.text ? strtok_r(result.text, "\n", &save) : NULL; line;
         line = strtok_r(NULL, "\n", &save)) {
        if (!strcmp(line, "state=ENABLED"))
            state = 1;
        else if (!strcmp(line, "ssid[0]=" APD_RRM_FORWARD_SSID))
            ssid = 1;
        else if (!strncmp(line, "bssid[0]=", 9))
            address = !strcmp(line + 9, bssid);
    }
    apd_command_result_free(&result);
    if (!ssid || !address)
        return -1;
    return state ? 0 : 1;
}

static int apd_rrm_forward_config_equal(
    const struct apd_rrm_forward_config *left,
    const struct apd_rrm_forward_config *right)
{
    size_t i;

    for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++)
        if (strcmp(left->bssid[i], right->bssid[i]))
            return 0;
    return 1;
}

static int apd_rrm_forward_restore_state(
    const struct apd_rrm_forward_state *state)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++) {
        int current = -1;

        /* An interface may now belong to a different BSS after reconfiguration.
         * Retain the journal instead of writing an unrelated network. */
        if (apd_rrm_forward_identity(i, state->config.bssid[i]) != 0 ||
            apd_rrm_forward_flag_read(i, &current) != 0 ||
            (current != state->original[i] &&
             apd_rrm_forward_flag_write(i, state->original[i]) != 0))
            failed = 1;
    }
    if (!failed && unlink(APD_RRM_FORWARD_STATE_PATH) != 0 && errno != ENOENT)
        failed = 1;
    return failed ? -1 : 0;
}

int apd_rrm_forward_restore(void)
{
    struct apd_rrm_forward_state state;
    int rc = apd_rrm_forward_state_read(&state);

    if (rc == 1)
        return 0;
    if (rc != 0)
        return -1;
    return apd_rrm_forward_restore_state(&state);
}

enum apd_rrm_forward_result {
    APD_RRM_FORWARD_OK,
    APD_RRM_FORWARD_INERT,
    APD_RRM_FORWARD_RETRY,
    APD_RRM_FORWARD_FAILED,
};

static enum apd_rrm_forward_result apd_rrm_forward_reconcile(void)
{
    struct apd_rrm_forward_config config;
    struct apd_rrm_forward_state state;
    int config_rc = apd_rrm_forward_config_read(&config);
    int state_rc = apd_rrm_forward_state_read(&state);
    size_t i;

    if (config_rc == 1) {
        if (state_rc == 0 && apd_rrm_forward_restore_state(&state) != 0)
            return APD_RRM_FORWARD_RETRY;
        return state_rc < 0 ? APD_RRM_FORWARD_FAILED : APD_RRM_FORWARD_INERT;
    }
    if (config_rc != 0) {
        if (state_rc == 0)
            apd_rrm_forward_restore_state(&state);
        return APD_RRM_FORWARD_FAILED;
    }
    if (state_rc < 0)
        return APD_RRM_FORWARD_FAILED;
    if (state_rc == 0 && !apd_rrm_forward_config_equal(&config, &state.config)) {
        apd_rrm_forward_restore_state(&state);
        return APD_RRM_FORWARD_FAILED;
    }
    for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++) {
        int identity = apd_rrm_forward_identity(i, config.bssid[i]);

        if (identity > 0) {
            if (state_rc == 0)
                apd_rrm_forward_restore_state(&state);
            return APD_RRM_FORWARD_RETRY;
        }
        if (identity < 0) {
            if (state_rc == 0)
                apd_rrm_forward_restore_state(&state);
            return APD_RRM_FORWARD_FAILED;
        }
    }
    if (state_rc == 1) {
        memset(&state, 0, sizeof(state));
        state.config = config;
        for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++)
            if (apd_rrm_forward_flag_read(i, &state.original[i]) != 0)
                return APD_RRM_FORWARD_RETRY;
        if (apd_rrm_forward_state_write(&state) != 0)
            return APD_RRM_FORWARD_FAILED;
    }
    for (i = 0; i < APD_RRM_FORWARD_BSS_COUNT; i++) {
        int current = -1;

        if (apd_rrm_forward_flag_read(i, &current) != 0) {
            apd_rrm_forward_restore_state(&state);
            return APD_RRM_FORWARD_FAILED;
        }
        if (current != 1 && apd_rrm_forward_flag_write(i, 1) != 0) {
            apd_rrm_forward_restore_state(&state);
            return APD_RRM_FORWARD_FAILED;
        }
    }
    return APD_RRM_FORWARD_OK;
}

static void apd_rrm_forward_timer_cb(struct uloop_timeout *timeout)
{
    enum apd_rrm_forward_result result;

    (void)timeout;
    if (apd_rrm_forward_restoring) {
        if (apd_rrm_forward_restore() == 0) {
            apd_rrm_forward_restoring = 0;
            return;
        }
        if (++apd_rrm_forward_failures < APD_RRM_FORWARD_MAX_FAILURES)
            uloop_timeout_set(&apd_rrm_forward_timer, APD_RRM_FORWARD_RETRY_MS);
        else
            fprintf(stderr, "[dreamingwrt-apd] QSDK RRM restore pending; journal retained\n");
        return;
    }
    result = apd_rrm_forward_reconcile();
    if (result == APD_RRM_FORWARD_OK) {
        apd_rrm_forward_failures = 0;
        uloop_timeout_set(&apd_rrm_forward_timer,
                          APD_RRM_FORWARD_INTERVAL_MS);
        return;
    }
    if (result == APD_RRM_FORWARD_RETRY &&
        ++apd_rrm_forward_failures < APD_RRM_FORWARD_MAX_FAILURES) {
        uloop_timeout_set(&apd_rrm_forward_timer, APD_RRM_FORWARD_RETRY_MS);
        return;
    }
    if (result != APD_RRM_FORWARD_INERT && apd_rrm_forward_restore() != 0) {
        apd_rrm_forward_restoring = 1;
        apd_rrm_forward_failures = 0;
        uloop_timeout_set(&apd_rrm_forward_timer, APD_RRM_FORWARD_RETRY_MS);
    }
    fprintf(stderr, "[dreamingwrt-apd] QSDK RRM forwarding stopped result=%d\n",
            result);
}

int apd_rrm_forward_start(void)
{
    apd_rrm_forward_failures = 0;
    apd_rrm_forward_restoring = 0;
    if (access(APD_RRM_FORWARD_MARKER_PATH, F_OK) != 0 &&
        access(APD_RRM_FORWARD_STATE_PATH, F_OK) != 0)
        return 0;
    apd_rrm_forward_timer.cb = apd_rrm_forward_timer_cb;
    return uloop_timeout_set(&apd_rrm_forward_timer,
                             APD_RRM_FORWARD_INITIAL_MS);
}

void apd_rrm_forward_stop(void)
{
    uloop_timeout_cancel(&apd_rrm_forward_timer);
    if (apd_rrm_forward_restore() != 0)
        fprintf(stderr, "[dreamingwrt-apd] QSDK RRM forwarding restore failed\n");
}
