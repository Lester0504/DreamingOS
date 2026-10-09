// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * 6 GHz transmit-ceiling mode control for apd.
 *
 * The mt7996 driver clamps every channel to its EEPROM calibrated target
 * (min(max_reg_power, eeprom_target) in __mt7996_init_txpower). mt76 patch
 * 042 adds an opt-in module parameter, txpower_from_regdb, that drops the
 * clamp so the regulatory ceiling stands on its own -- which drives the PA
 * above its factory calibration and is only safe on hardware qualified for
 * 6 GHz standard power.
 *
 * This file exposes that knob to the controller through apd, behind four
 * gates that must ALL pass before the regulatory mode can be selected:
 *
 *   1. board is on the hardware allowlist (W1700K only, today),
 *   2. the running mt7996e exposes the parameter (patched driver present),
 *   3. the active regdb exposes the qualified 35 dBm ceiling,
 *   4. the caller passes confirm=true.
 *
 * apd never selects the regulatory mode on its own. There is no default or
 * migration. An explicitly confirmed selection is persisted outside the
 * volatile module parameter and replayed only after all of the same runtime
 * gates pass again. Startup never cycles existing wireless interfaces.
 * A cold-start apply may roll back once, but is not automatically repeated.
 */
#ifndef APD_TXPOWER_MODE_STANDALONE_TEST
#include "apd_internal.h"
#endif
#include "apd_readonly_command.h"
#include "apd_txpower_mode.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef APD_TXPOWER_BOOT_CONFIG_PATH
#define APD_TXPOWER_BOOT_CONFIG_PATH "/etc/modules.conf"
#endif

enum apd_txpower_restore_result {
    APD_TXPOWER_RESTORE_RETRY = -1,
    APD_TXPOWER_RESTORE_OK = 0,
    APD_TXPOWER_RESTORE_DEFERRED = 1,
    APD_TXPOWER_RESTORE_FAILED = 2,
};

#ifndef APD_TXPOWER_MODE_STANDALONE_TEST
#define APD_TXPOWER_RESTORE_INITIAL_MS 5000
#define APD_TXPOWER_RESTORE_RETRY_MS 10000
#define APD_TXPOWER_RESTORE_MAX_ATTEMPTS 12

static struct uloop_timeout apd_txpower_restore_timer;
static int apd_txpower_restore_pending;
static int apd_txpower_restore_attempts;
static char apd_txpower_restore_reason[APD_TXPOWER_REASON_MAX + 1];
#endif

/*
 * Hardware allowlist. Only boards explicitly qualified for 6 GHz standard
 * power may drop the EEPROM ceiling. Match is a prefix test against the
 * ubus/board_name token (e.g. "gemtek,w1700k-ubi"), so a layout variant of
 * the same board still matches while an unrelated board never does.
 */
static const char *const apd_txpower_allowed_boards[] = {
    "gemtek,w1700k",
    NULL,
};

static const char *apd_txpower_find_iw(void)
{
    static const char *const paths[] = {
        "/usr/sbin/iw", "/usr/bin/iw", "/sbin/iw", NULL
    };
    size_t i;

    for (i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return NULL;
}

static int apd_txpower_board_allowed(const char *board_name)
{
    size_t i;

    if (!board_name || !board_name[0])
        return 0;
    for (i = 0; apd_txpower_allowed_boards[i]; i++) {
        size_t len = strlen(apd_txpower_allowed_boards[i]);

        if (strncmp(board_name, apd_txpower_allowed_boards[i], len) == 0)
            return 1;
    }
    return 0;
}

/* Reads the volatile knob. present=0 means the patched driver is not loaded. */
static int apd_txpower_param_read(int *value, int *present)
{
    char buf[8] = { 0 };
    ssize_t n;
    int fd;

    if (present)
        *present = 0;
    if (value)
        *value = 0;

    fd = open(APD_TXPOWER_PARAM_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (present)
        *present = 1;
    do {
        n = read(fd, buf, sizeof(buf) - 1);
    } while (n < 0 && errno == EINTR);
    close(fd);
    if (n <= 0)
        return -1;
    if (value)
        *value = (buf[0] == '1' || buf[0] == 'Y' || buf[0] == 'y');
    return 0;
}

static int apd_txpower_param_write(int on)
{
    const char *text = on ? "1\n" : "0\n";
    ssize_t n;
    int fd;

    fd = open(APD_TXPOWER_PARAM_PATH, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    do {
        n = write(fd, text, 2);
    } while (n < 0 && errno == EINTR);
    close(fd);
    return n == 2 ? 0 : -1;
}

static int apd_txpower_persist_read(char mode[APD_TXPOWER_MODE_MAX + 1])
{
    char buf[APD_TXPOWER_MODE_MAX + 4] = { 0 };
    ssize_t n;
    int fd;
    char *p;

    if (!mode)
        return -1;
    mode[0] = '\0';
    fd = open(APD_TXPOWER_PERSIST_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? 1 : -1;
    do {
        n = read(fd, buf, sizeof(buf) - 1);
    } while (n < 0 && errno == EINTR);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    n = (ssize_t)strcspn(p, " \t\r\n");
    if (n <= 0 || n > APD_TXPOWER_MODE_MAX)
        return -1;
    memcpy(mode, p, (size_t)n);
    mode[n] = '\0';
    if (strcmp(mode, APD_TXPOWER_MODE_CALIBRATED) &&
        strcmp(mode, APD_TXPOWER_MODE_REGULATORY))
        return -1;
    return 0;
}

static int apd_txpower_atomic_text(const char *path, const char *text,
                                  mode_t permissions)
{
    char tmp[PATH_MAX];
    char parent[PATH_MAX];
    char *slash;
    int fd;
    int dirfd;
    ssize_t n;
    size_t len;
    size_t written = 0;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp) ||
        snprintf(parent, sizeof(parent), "%s", path) >= (int)sizeof(parent))
        return -1;
    slash = strrchr(parent, '/');
    if (!slash)
        snprintf(parent, sizeof(parent), ".");
    else if (slash == parent)
        slash[1] = '\0';
    else
        *slash = '\0';
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, permissions);
    if (fd < 0)
        return -1;
    len = strlen(text);
    while (written < len) {
        do {
            n = write(fd, text + written, len - written);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            break;
        written += (size_t)n;
    }
    if (written != len || fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    if (close(fd) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return -1;
    fd = fsync(dirfd);
    close(dirfd);
    return fd;
}

static int apd_txpower_persist_write(const char *mode)
{
    char text[APD_TXPOWER_MODE_MAX + 2];

    if (!mode || (strcmp(mode, APD_TXPOWER_MODE_CALIBRATED) &&
                  strcmp(mode, APD_TXPOWER_MODE_REGULATORY)))
        return -1;
    snprintf(text, sizeof(text), "%s\n", mode);
    return apd_txpower_atomic_text(APD_TXPOWER_PERSIST_PATH, text, 0600);
}

/*
 * OpenWrt kmodloader reads /etc/modules.conf, including when invoked as
 * modprobe; that modprobe does not consume command-line module parameters.
 * Own one marked option line and leave every unrelated option untouched.
 */
static int apd_txpower_boot_config(const char *mode, int apply)
{
    static const char *const lines[] = {
        "options mt7996e txpower_from_regdb=0 # dreamingwrt-apd\n",
        "options mt7996e txpower_from_regdb=1 # dreamingwrt-apd\n"
    };
    const char *wanted = lines[!strcmp(mode, APD_TXPOWER_MODE_REGULATORY)];
    FILE *input = fopen(APD_TXPOWER_BOOT_CONFIG_PATH, "r");
    FILE *output;
    char *line = NULL;
    char *text = NULL;
    size_t capacity = 0, size = 0;
    ssize_t length;
    int found = 0, matching = 0, last = '\n', rc = -1;

    if (!input && errno != ENOENT)
        return -1;
    output = open_memstream(&text, &size);
    if (!output) {
        if (input)
            fclose(input);
        return -1;
    }
    while (input && (length = getline(&line, &capacity, input)) >= 0) {
        char command[32], module[64];
        char *option, *comment;

        if (!strcmp(line, lines[0]) || !strcmp(line, lines[1])) {
            found++;
            matching += !strcmp(line, wanted);
            continue;
        }
        comment = strchr(line, '#');
        option = strstr(line, "txpower_from_regdb=");
        if (sscanf(line, "%31s %63s", command, module) == 2 &&
            !strcmp(command, "options") && !strcmp(module, "mt7996e") &&
            option && (!comment || option < comment))
            goto out;
        if (fputs(line, output) == EOF)
            goto out;
        if (length)
            last = line[length - 1];
    }
    if (input && ferror(input))
        goto out;
    if (last != '\n' && fputc('\n', output) == EOF)
        goto out;
    if (fputs(wanted, output) == EOF)
        goto out;
    if (fclose(output) != 0) {
        output = NULL;
        goto out;
    }
    output = NULL;
    rc = !apply || (found == 1 && matching == 1) ? 0 :
         apd_txpower_atomic_text(APD_TXPOWER_BOOT_CONFIG_PATH, text, 0644);
out:
    if (input)
        fclose(input);
    if (output)
        fclose(output);
    free(line);
    free(text);
    return rc;
}

static int apd_txpower_persist_selection(const char *mode, const char *previous)
{
    if (apd_txpower_boot_config(mode, 1) != 0)
        return -1;
    if (strcmp(previous, mode) && apd_txpower_persist_write(mode) != 0) {
        if (previous[0])
            apd_txpower_persist_write(previous);
        else
            unlink(APD_TXPOWER_PERSIST_PATH);
        apd_txpower_boot_config(!strcmp(previous, APD_TXPOWER_MODE_REGULATORY) ?
                               APD_TXPOWER_MODE_REGULATORY :
                               APD_TXPOWER_MODE_CALIBRATED, 1);
        return -1;
    }
    return 0;
}

static const char *apd_txpower_find_wifi(void)
{
    static const char *const paths[] = {
        "/sbin/wifi", "/usr/sbin/wifi", "/usr/bin/wifi", NULL
    };
    size_t i;

    for (i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return NULL;
}

static const char *apd_txpower_find_uci(void)
{
    static const char *const paths[] = {
        "/sbin/uci", "/usr/sbin/uci", "/usr/bin/uci", NULL
    };
    size_t i;

    for (i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return NULL;
}

/* Find the UCI wifi-device section whose declared band is 6 GHz. */
static int apd_txpower_find_6ghz_radio(const char *uci_path,
                                       char radio[APD_TXPOWER_RADIO_MAX + 1])
{
    char *const argv[] = { (char *)uci_path, "-q", "show", "wireless", NULL };
    struct apd_command_result result = { 0 };
    char *line;
    int found = -1;

    radio[0] = '\0';
    if (!uci_path || apd_readonly_command(uci_path, argv, &result) != 0 ||
        !result.text)
        goto out;
    for (line = strtok(result.text, "\n"); line;
         line = strtok(NULL, "\n")) {
        char *prefix;
        char *band;
        char *dot;
        size_t len;

        prefix = strstr(line, "wireless.");
        band = strstr(line, ".band='6g'");
        if (!prefix || !band || band <= prefix + 9)
            continue;
        dot = band;
        len = (size_t)(dot - (prefix + 9));
        if (!len || len > APD_TXPOWER_RADIO_MAX)
            continue;
        memcpy(radio, prefix + 9, len);
        radio[len] = '\0';
        found = 0;
        break;
    }
out:
    apd_command_result_free(&result);
    return found;
}

static int apd_txpower_wifi_action(const char *wifi, const char *action,
                                   const char *radio)
{
    char *const argv[] = { (char *)wifi, (char *)action, (char *)radio, NULL };
    struct apd_command_result result = { 0 };
    int rc;

    if (!wifi || !action || (radio && !radio[0]))
        return -1;
    rc = apd_readonly_command_bounded(wifi, argv, 15000,
                                      256U * 1024U, &result);
    apd_command_result_free(&result);
    return rc;
}

static int apd_txpower_single_phy(void)
{
    DIR *dir = opendir("/sys/class/ieee80211");
    struct dirent *entry;
    int count = 0;

    if (!dir)
        return 0;
    while ((entry = readdir(dir)))
        if (!strncmp(entry->d_name, "phy", 3))
            count++;
    closedir(dir);
    return count == 1;
}

/* Parses the first "country XX:" token from `iw reg get`. */
static int apd_txpower_current_country(const char *iw, char cc[3])
{
    char *const argv[] = { (char *)iw, "reg", "get", NULL };
    struct apd_command_result result = { 0 };
    const char *p;
    int rc;

    cc[0] = cc[1] = cc[2] = '\0';
    if (!iw)
        return -1;
    rc = apd_readonly_command(iw, argv, &result);
    if (rc != 0 || !result.text) {
        apd_command_result_free(&result);
        return -1;
    }
    p = strstr(result.text, "country ");
    if (p && isalpha((unsigned char)p[8]) && isalpha((unsigned char)p[9])) {
        cc[0] = p[8];
        cc[1] = p[9];
    }
    apd_command_result_free(&result);
    return cc[0] ? 0 : -1;
}

/* Highest 6 GHz EIRP ceiling from `iw reg get`, in tenths of a dBm. */
static int apd_txpower_reg_ceiling_x10(const char *iw)
{
    char *const argv[] = { (char *)iw, "reg", "get", NULL };
    struct apd_command_result result = { 0 };
    int best = -1;
    char *line;

    if (!iw)
        return -1;
    if (apd_readonly_command(iw, argv, &result) != 0 || !result.text) {
        apd_command_result_free(&result);
        return -1;
    }

    for (line = strtok(result.text, "\n"); line;
         line = strtok(NULL, "\n")) {
        char tuple[64];
        char *range_open = strchr(line, '(');
        char *range_dash;
        char *range_at;
        char *range_close;
        char *power_open;
        char *power_close;
        char *number;
        char *end;
        double start;
        double stop;
        double power;
        size_t len;

        if (!range_open)
            continue;
        start = strtod(range_open + 1, &end);
        if (end == range_open + 1)
            continue;
        range_dash = strstr(end, " - ");
        if (!range_dash)
            continue;
        stop = strtod(range_dash + 3, &end);
        if (end == range_dash + 3 || stop < 5925.0 || start > 7125.0)
            continue;

        range_at = strchr(end, '@');
        range_close = range_at ? strchr(range_at, ')') : NULL;
        power_open = range_close ? strchr(range_close + 1, '(') : NULL;
        power_close = power_open ? strchr(power_open + 1, ')') : NULL;
        if (!power_open || !power_close)
            continue;
        len = (size_t)(power_close - power_open - 1);
        if (!len || len >= sizeof(tuple))
            continue;
        memcpy(tuple, power_open + 1, len);
        tuple[len] = '\0';

        /* `iw` prints EIRP as either `(30)` or `(N/A, 30)`. */
        number = strrchr(tuple, ',');
        number = number ? number + 1 : tuple;
        while (isspace((unsigned char)*number))
            number++;
        power = strtod(number, &end);
        if (end == number || power <= 0.0 || power > 100.0)
            continue;
        if ((int)(power * 10.0 + 0.5) > best)
            best = (int)(power * 10.0 + 0.5);
    }

    apd_command_result_free(&result);
    return best;
}

static int apd_txpower_reg_set(const char *iw, const char *cc)
{
    char *const argv[] = { (char *)iw, "reg", "set", (char *)cc, NULL };
    struct apd_command_result result = { 0 };

    if (!iw || !cc || !cc[0])
        return -1;
    if (apd_readonly_command(iw, argv, &result) != 0) {
        apd_command_result_free(&result);
        return -1;
    }
    apd_command_result_free(&result);
    return 0;
}

/*
 * __mt7996_init_txpower only re-runs on a real regulatory change, so setting
 * the current country to itself is a no-op. Cycle through the world domain
 * and back to force the driver to recompute chan->max_power with the new
 * knob value. The caller must quiesce the complete shared PHY first.
 * Always try to restore the country captured before the transaction,
 * including when the first write fails or this is the rollback attempt.
 */
static int apd_txpower_reapply(const char *iw, const char country[3])
{
    char actual[3];
    int world_rc;
    int restore_rc;

    if (!iw || !country || !country[0])
        return -1;
    world_rc = apd_txpower_reg_set(iw, "00");
    usleep(400 * 1000);
    restore_rc = apd_txpower_reg_set(iw, country);
    usleep(400 * 1000);
    return world_rc == 0 && restore_rc == 0 &&
           apd_txpower_current_country(iw, actual) == 0 &&
           !strcmp(actual, country) ? 0 : -1;
}

static int apd_txpower_collect_active(const char *iw,
                                      struct apd_txpower_mode_state *out)
{
    char *const argv[] = { (char *)iw, "dev", NULL };
    struct apd_command_result result = { 0 };
    char ifname[APD_TXPOWER_IFACE_NAME_MAX + 1] = { 0 };
    int is_ap = 0;
    int in_mld_links = 0;
    int frequency = 0;
    int txpower = -1;
    char *line;

    /* Keep the list bounded, but never treat a truncated list as proof. */
    #define APD_TXPOWER_RECORD_ACTIVE(_name, _power) do { \
        if (out->active_6ghz_interface_count < \
                APD_TXPOWER_ACTIVE_IFACE_MAX) { \
            int _i = out->active_6ghz_interface_count++; \
            snprintf(out->active_6ghz_interfaces[_i], \
                     sizeof(out->active_6ghz_interfaces[_i]), "%s", \
                     (_name)); \
            out->active_6ghz_txpower_dbm_x10[_i] = (_power); \
        } else { \
            out->active_6ghz_interface_overflow = 1; \
        } \
    } while (0)

    if (!iw || !out)
        return -1;
    if (apd_readonly_command(iw, argv, &result) != 0 || !result.text)
        goto out;
    out->wireless_inventory_ok = 1;
    for (line = strtok(result.text, "\n"); line;
         line = strtok(NULL, "\n")) {
        char *value = line;
        int channel;
        int width;
        int parsed_frequency;
        double parsed_power;

        while (*value == ' ' || *value == '\t')
            value++;
        if (!strncmp(value, "Interface ", 10)) {
            out->wireless_interfaces_present = 1;
            if (!in_mld_links && is_ap && frequency >= 5925 &&
                frequency <= 7125 &&
                txpower >= 0)
                APD_TXPOWER_RECORD_ACTIVE(ifname, txpower);
            snprintf(ifname, sizeof(ifname), "%s", value + 10);
            is_ap = 0;
            in_mld_links = 0;
            frequency = 0;
            txpower = -1;
            continue;
        }
        if (!strncmp(value, "type ", 5)) {
            is_ap = !strcmp(value + 5, "AP");
            continue;
        }
        if (!strcmp(value, "MLD with links:")) {
            in_mld_links = 1;
            continue;
        }
        if (in_mld_links && !strncmp(value, "- link ID ", 10)) {
            frequency = 0;
            txpower = -1;
            continue;
        }
        if (!strncmp(value, "channel ", 8) &&
            sscanf(value, "channel %d (%d MHz), width: %d MHz",
                   &channel, &parsed_frequency, &width) >= 2)
            frequency = parsed_frequency;
        else if (!strncmp(value, "txpower ", 8) &&
                 sscanf(value + 8, "%lf dBm", &parsed_power) == 1) {
            txpower = (int)(parsed_power * 10.0 + 0.5);
            if (in_mld_links && is_ap && frequency >= 5925 &&
                frequency <= 7125)
                APD_TXPOWER_RECORD_ACTIVE(ifname, txpower);
        }
    }
    if (!in_mld_links && is_ap && frequency >= 5925 &&
        frequency <= 7125 && txpower >= 0)
        APD_TXPOWER_RECORD_ACTIVE(ifname, txpower);
out:
    apd_command_result_free(&result);
    if (out->active_6ghz_interface_count <= 0 ||
        out->active_6ghz_interface_overflow)
        return -1;
    out->active_6ghz_readback_ok = 1;
    #undef APD_TXPOWER_RECORD_ACTIVE
    return 0;
}

enum apd_txpower_apply_result {
    APD_TXPOWER_APPLY_OK,
    APD_TXPOWER_APPLY_STOP_FAILED,
    APD_TXPOWER_APPLY_PARAM_FAILED,
    APD_TXPOWER_APPLY_REG_FAILED,
    APD_TXPOWER_APPLY_START_FAILED,
};

static int apd_txpower_apply_quiesced(const char *iw, const char country[3],
                                      int regulatory)
{
    const char *wifi = apd_txpower_find_wifi();
    struct apd_txpower_mode_state inventory;
    int rc = APD_TXPOWER_APPLY_STOP_FAILED;
    int attempt;

    if (!wifi)
        return rc;
    /* All UCI radios share this PHY. A radio2-only restart removes MLO
     * links owned by the other radios without bringing them back. */
    if (apd_txpower_wifi_action(wifi, "down", NULL) == 0) {
        for (attempt = 0; attempt < 8; attempt++) {
            memset(&inventory, 0, sizeof(inventory));
            apd_txpower_collect_active(iw, &inventory);
            if (inventory.wireless_inventory_ok &&
                !inventory.wireless_interfaces_present) {
                rc = APD_TXPOWER_APPLY_OK;
                break;
            }
            usleep(250 * 1000);
        }
    }
    if (rc == APD_TXPOWER_APPLY_OK &&
        apd_txpower_param_write(regulatory) != 0)
        rc = APD_TXPOWER_APPLY_PARAM_FAILED;
    if (rc == APD_TXPOWER_APPLY_OK &&
        apd_txpower_reapply(iw, country) != 0)
        rc = APD_TXPOWER_APPLY_REG_FAILED;
    /* Even a partial stop must be followed by an attempt to restore Wi-Fi. */
    if (apd_txpower_wifi_action(wifi, "up", NULL) != 0 &&
        rc == APD_TXPOWER_APPLY_OK)
        rc = APD_TXPOWER_APPLY_START_FAILED;
    return rc;
}

static int apd_txpower_collect_after_apply(struct apd_txpower_mode_state *out)
{
    int attempt;
    int rc = -1;

    for (attempt = 0; attempt < 10; attempt++) {
        rc = apd_txpower_mode_state_collect(out);
        if (rc == 0 && out->active_6ghz_readback_ok)
            break;
        usleep(250 * 1000);
    }
    return rc;
}

static int apd_txpower_active_min_x10(const struct apd_txpower_mode_state *state)
{
    int best = -1;
    int i;

    if (!state)
        return -1;
    for (i = 0; i < state->active_6ghz_interface_count; i++) {
        int value = state->active_6ghz_txpower_dbm_x10[i];

        if (best < 0 || value < best)
            best = value;
    }
    return best;
}

static int apd_txpower_active_max_x10(const struct apd_txpower_mode_state *state)
{
    int best = -1;
    int i;

    if (!state)
        return -1;
    for (i = 0; i < state->active_6ghz_interface_count; i++)
        if (state->active_6ghz_txpower_dbm_x10[i] > best)
            best = state->active_6ghz_txpower_dbm_x10[i];
    return best;
}

static int apd_txpower_active_matches(
    const struct apd_txpower_mode_state *expected,
    const struct apd_txpower_mode_state *actual)
{
    int i;

    if (!expected || !actual || !expected->active_6ghz_readback_ok ||
        !actual->active_6ghz_readback_ok ||
        expected->active_6ghz_interface_overflow ||
        actual->active_6ghz_interface_overflow ||
        expected->active_6ghz_interface_count !=
            actual->active_6ghz_interface_count)
        return 0;
    for (i = 0; i < expected->active_6ghz_interface_count; i++) {
        int j;
        int found = 0;

        for (j = 0; j < actual->active_6ghz_interface_count; j++) {
            if (strcmp(expected->active_6ghz_interfaces[i],
                       actual->active_6ghz_interfaces[j]) == 0) {
                if (expected->active_6ghz_txpower_dbm_x10[i] !=
                    actual->active_6ghz_txpower_dbm_x10[j])
                    return 0;
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    return 1;
}

static int apd_txpower_calibrated_state_ok(
    const struct apd_txpower_mode_state *state)
{
    int max_power;

    if (!state || strcmp(state->mode, APD_TXPOWER_MODE_CALIBRATED) != 0 ||
        !state->active_6ghz_readback_ok ||
        state->active_6ghz_interface_overflow ||
        state->active_6ghz_interface_count <= 0)
        return 0;
    max_power = apd_txpower_active_max_x10(state);
    /* Compare the live AP against the post-reapply calibrated ceiling. */
    return state->ceiling_dbm_x10 >= 0 && max_power >= 0 &&
           state->ceiling_dbm_x10 < APD_TXPOWER_REQUIRED_REG_CEILING_X10 &&
           max_power <= state->ceiling_dbm_x10;
}

static int apd_txpower_regulatory_state_ok(
    const struct apd_txpower_mode_state *state)
{
    int max_power;

    if (!state || strcmp(state->mode, APD_TXPOWER_MODE_REGULATORY) ||
        state->ceiling_dbm_x10 < APD_TXPOWER_REQUIRED_REG_CEILING_X10 ||
        !state->active_6ghz_readback_ok ||
        state->active_6ghz_interface_overflow)
        return 0;
    max_power = apd_txpower_active_max_x10(state);
    return max_power >= 0 && max_power <= state->ceiling_dbm_x10;
}

/*
 * Restore calibrated operation through the same whole-PHY transaction.
 * Never bounce the regulatory domain while any wireless interface remains.
 */
static int apd_txpower_restore_calibrated(
    const char *iw, const char *radio, const char country[3],
    const struct apd_txpower_mode_state *expected,
    struct apd_txpower_mode_state *out)
{
    int apply_rc;
    int collect_rc;

    if (!iw || !radio || !radio[0] || !out)
        return -1;
    apply_rc = apd_txpower_apply_quiesced(iw, country, 0);

    memset(out, 0, sizeof(*out));
    out->ceiling_dbm_x10 = -1;
    out->regulatory_ceiling_dbm_x10 = -1;
    collect_rc = apd_txpower_collect_after_apply(out);
    snprintf(out->radio, sizeof(out->radio), "%s", radio);
    out->radio_reload_performed = 1;
    out->radio_reload_ok = apply_rc == APD_TXPOWER_APPLY_OK;
    out->rollback_performed = 1;
    out->rollback_ok = apply_rc == APD_TXPOWER_APPLY_OK &&
                        collect_rc == 0 && apd_txpower_calibrated_state_ok(out);
    if (out->rollback_ok && expected &&
        !strcmp(expected->mode, APD_TXPOWER_MODE_CALIBRATED) &&
        expected->active_6ghz_readback_ok)
        out->rollback_ok = apd_txpower_active_matches(expected, out);
    return out->rollback_ok ? 0 : -1;
}

/* Best-effort: highest 6 GHz per-channel ceiling iw reports, in x10 dBm. */
static int apd_txpower_ceiling_x10(const char *iw)
{
    DIR *dir;
    struct dirent *ent;
    int best = -1;

    if (!iw)
        return -1;
    dir = opendir("/sys/class/ieee80211");
    if (!dir)
        return -1;
    while ((ent = readdir(dir))) {
        char *const argv[] = { (char *)iw, "phy", ent->d_name, "info", NULL };
        struct apd_command_result result = { 0 };
        char *line;

        if (strncmp(ent->d_name, "phy", 3) != 0)
            continue;
        if (apd_readonly_command(iw, argv, &result) != 0 || !result.text) {
            apd_command_result_free(&result);
            continue;
        }
        for (line = strtok(result.text, "\n"); line;
             line = strtok(NULL, "\n")) {
            char *mhz = strstr(line, " MHz");
            char *dbm = strstr(line, " dBm)");
            long freq;
            double power;
            char *q;

            if (!mhz || !dbm)
                continue;
            /* Frequency token sits just before " MHz". */
            q = mhz;
            while (q > line && q[-1] != '*' && q[-1] != ' ')
                q--;
            freq = strtol(q, NULL, 10);
            if (freq < 5925 || freq > 7125)
                continue;
            /* Power token sits just before " dBm)". */
            q = dbm;
            while (q > line && q[-1] != '(' && q[-1] != ' ')
                q--;
            power = strtod(q, NULL);
            if (power > 0.0) {
                int x10 = (int)(power * 10.0 + 0.5);

                if (x10 > best)
                    best = x10;
            }
        }
        apd_command_result_free(&result);
    }
    closedir(dir);
    return best;
}

int apd_txpower_mode_state_collect(struct apd_txpower_mode_state *out)
{
    struct apd_device_model model;
    const char *iw = apd_txpower_find_iw();
    int value = 0;
    int present = 0;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->ceiling_dbm_x10 = -1;
    out->regulatory_ceiling_dbm_x10 = -1;

    memset(&model, 0, sizeof(model));
    apd_backend_device_model_collect(&model);
    snprintf(out->board_name, sizeof(out->board_name), "%s", model.board_name);
    out->board_allowed = apd_txpower_board_allowed(model.board_name);

    apd_txpower_param_read(&value, &present);
    out->param_present = present;
    snprintf(out->mode, sizeof(out->mode), "%s",
             value ? APD_TXPOWER_MODE_REGULATORY : APD_TXPOWER_MODE_CALIBRATED);
    if (apd_txpower_persist_read(out->persisted_mode) != 0)
        out->persisted_mode[0] = '\0';
#ifndef APD_TXPOWER_MODE_STANDALONE_TEST
    out->restore_pending = apd_txpower_restore_pending;
    out->restore_attempts = apd_txpower_restore_attempts;
    snprintf(out->restore_reason, sizeof(out->restore_reason), "%s",
             apd_txpower_restore_reason);
#endif

    out->regulatory_ceiling_dbm_x10 = apd_txpower_reg_ceiling_x10(iw);
    out->regdb_ready = out->regulatory_ceiling_dbm_x10 >=
                       APD_TXPOWER_REQUIRED_REG_CEILING_X10;
    out->supported = out->board_allowed && out->param_present &&
                     out->regdb_ready;
    if (!out->board_allowed)
        snprintf(out->reason, sizeof(out->reason), "%s",
                 "board_not_standard_power_capable");
    else if (!out->param_present)
        snprintf(out->reason, sizeof(out->reason), "%s",
                 "driver_txpower_param_absent");
    else if (out->regulatory_ceiling_dbm_x10 < 0)
        snprintf(out->reason, sizeof(out->reason), "%s",
                 "regdb_ceiling_unavailable");
    else if (!out->regdb_ready)
        snprintf(out->reason, sizeof(out->reason), "%s",
                 "regdb_ceiling_insufficient");

    out->ceiling_dbm_x10 = apd_txpower_ceiling_x10(iw);
    if (iw)
        apd_txpower_collect_active(iw, out);
    return 0;
}

static void apd_txpower_add_state(struct json_object *root,
                                  const struct apd_txpower_mode_state *state)
{
    json_object_object_add(root, "mode", json_object_new_string(state->mode));
    json_object_object_add(root, "active_mode",
                           json_object_new_string(state->mode));
    if (state->persisted_mode[0])
        json_object_object_add(root, "persisted_mode",
                               json_object_new_string(state->persisted_mode));
    json_object_object_add(root, "restore_pending",
                           json_object_new_boolean(state->restore_pending));
    json_object_object_add(root, "restore_attempts",
                           json_object_new_int(state->restore_attempts));
    if (state->restore_reason[0])
        json_object_object_add(root, "restore_reason",
                               json_object_new_string(state->restore_reason));
    json_object_object_add(root, "supported",
                           json_object_new_boolean(state->supported));
    json_object_object_add(root, "board_allowed",
                           json_object_new_boolean(state->board_allowed));
    json_object_object_add(root, "param_present",
                           json_object_new_boolean(state->param_present));
    json_object_object_add(root, "regdb_ready",
                           json_object_new_boolean(state->regdb_ready));
    json_object_object_add(root, "board_name",
                           json_object_new_string(state->board_name));
    if (state->reason[0])
        json_object_object_add(root, "reason",
                               json_object_new_string(state->reason));
    if (state->ceiling_dbm_x10 >= 0)
        json_object_object_add(root, "ceiling_6ghz_dbm",
            json_object_new_double(state->ceiling_dbm_x10 / 10.0));
    if (state->regulatory_ceiling_dbm_x10 >= 0)
        json_object_object_add(root, "regulatory_ceiling_6ghz_dbm",
            json_object_new_double(
                state->regulatory_ceiling_dbm_x10 / 10.0));
    json_object_object_add(root, "active_6ghz_readback_ok",
                           json_object_new_boolean(state->active_6ghz_readback_ok));
    json_object_object_add(root, "active_6ghz_interface_overflow",
                           json_object_new_boolean(
                               state->active_6ghz_interface_overflow));
    if (state->active_6ghz_interface_count > 0) {
        struct json_object *interfaces = json_object_new_array();
        int i;

        for (i = 0; i < state->active_6ghz_interface_count; i++) {
            struct json_object *entry = json_object_new_object();

            json_object_object_add(entry, "interface",
                                   json_object_new_string(
                                       state->active_6ghz_interfaces[i]));
            json_object_object_add(entry, "txpower_dbm",
                                   json_object_new_double(
                                       state->active_6ghz_txpower_dbm_x10[i] /
                                       10.0));
            json_object_array_add(interfaces, entry);
        }
        json_object_object_add(root, "active_6ghz_interfaces", interfaces);
        json_object_object_add(root, "active_6ghz_txpower_min_dbm",
                               json_object_new_double(
                                   apd_txpower_active_min_x10(state) / 10.0));
        json_object_object_add(root, "active_6ghz_txpower_max_dbm",
                               json_object_new_double(
                                   apd_txpower_active_max_x10(state) / 10.0));
        json_object_object_add(root, "active_6ghz_txpower_dbm",
                               json_object_new_double(
                                   apd_txpower_active_min_x10(state) / 10.0));
    }
    if (state->radio[0])
        json_object_object_add(root, "radio",
                               json_object_new_string(state->radio));
    json_object_object_add(root, "radio_reload_performed",
                           json_object_new_boolean(state->radio_reload_performed));
    json_object_object_add(root, "radio_reload_ok",
                           json_object_new_boolean(state->radio_reload_ok));
    json_object_object_add(root, "radio_reload_scope",
                           json_object_new_string(state->radio_reload_performed ?
                                                  "shared_phy" : "none"));
    json_object_object_add(root, "rollback_performed",
                           json_object_new_boolean(state->rollback_performed));
    json_object_object_add(root, "rollback_ok",
                           json_object_new_boolean(state->rollback_ok));
    json_object_object_add(root, "required_regulatory_ceiling_6ghz_dbm",
        json_object_new_double(
            APD_TXPOWER_REQUIRED_REG_CEILING_X10 / 10.0));
}

struct json_object *apd_txpower_mode_json(void)
{
    struct apd_txpower_mode_state state;
    struct json_object *root = json_object_new_object();

    apd_txpower_mode_state_collect(&state);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "operation",
                           json_object_new_string("txpower_mode"));
    apd_txpower_add_state(root, &state);
    return root;
}

static struct json_object *apd_txpower_fail(const char *reason,
                                            const struct apd_txpower_mode_state *state)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("capability_disabled"));
    json_object_object_add(root, "operation",
                           json_object_new_string("txpower_mode_set"));
    json_object_object_add(root, "reason", json_object_new_string(reason));
    json_object_object_add(root, "applied", json_object_new_boolean(0));
    if (state)
        apd_txpower_add_state(root, state);
    return root;
}

struct json_object *apd_txpower_mode_set_json(const char *mode, int confirmed)
{
    struct apd_txpower_mode_state state;
    struct json_object *root;
    const char *iw;
    const char *uci = apd_txpower_find_uci();
    char radio[APD_TXPOWER_RADIO_MAX + 1];
    char country[3];
    struct apd_txpower_mode_state baseline;
    int apply_rc;
    int rollback_rc;
    int want_regulatory;
    int already_applied = 0;

    if (!mode || !mode[0])
        return apd_txpower_fail("mode_required", NULL);
    if (!strcmp(mode, APD_TXPOWER_MODE_REGULATORY))
        want_regulatory = 1;
    else if (!strcmp(mode, APD_TXPOWER_MODE_CALIBRATED))
        want_regulatory = 0;
    else
        return apd_txpower_fail("unknown_mode", NULL);

    apd_txpower_mode_state_collect(&state);
    baseline = state;

    iw = apd_txpower_find_iw();
    if (!iw)
        return apd_txpower_fail("iw_unavailable", &state);
    if (!uci || apd_txpower_find_6ghz_radio(uci, radio) != 0)
        return apd_txpower_fail("six_ghz_radio_not_found", &state);
    snprintf(state.radio, sizeof(state.radio), "%s", radio);

    /* Gate 1: hardware allowlist. Refused even to read-flip on other boards. */
    if (!state.board_allowed)
        return apd_txpower_fail("board_not_standard_power_capable", &state);
    /* Gate 2: patched driver present. */
    if (!state.param_present)
        return apd_txpower_fail("driver_txpower_param_absent", &state);
    /* Gate 3: do not claim high-power support with a 30 dBm regdb. */
    if (want_regulatory && state.regulatory_ceiling_dbm_x10 < 0)
        return apd_txpower_fail("regdb_ceiling_unavailable", &state);
    if (want_regulatory && !state.regdb_ready)
        return apd_txpower_fail("regdb_ceiling_insufficient", &state);
    /* Gate 4: explicit confirmation, only for the destructive direction. */
    if (want_regulatory && !confirmed)
        return apd_txpower_fail("confirmation_required", &state);
    if (!state.wireless_inventory_ok)
        return apd_txpower_fail("wireless_inventory_unavailable", &state);
    if (apd_txpower_boot_config(mode, 0) != 0)
        return apd_txpower_fail("boot_module_config_conflict", &state);

    if (want_regulatory ? apd_txpower_regulatory_state_ok(&state) :
                          apd_txpower_calibrated_state_ok(&state)) {
        already_applied = 1;
        goto persist;
    }
    /* Both directions restart every radio sharing the PHY. */
    if (!confirmed)
        return apd_txpower_fail("confirmation_required", &state);
    if (!apd_txpower_single_phy())
        return apd_txpower_fail("shared_phy_scope_unavailable", &state);
    if (apd_txpower_current_country(iw, country) != 0)
        return apd_txpower_fail("operating_country_unavailable", &state);

    state.radio_reload_performed = 1;
    apply_rc = apd_txpower_apply_quiesced(iw, country, want_regulatory);
    state.radio_reload_ok = apply_rc == APD_TXPOWER_APPLY_OK;
    if (apply_rc != APD_TXPOWER_APPLY_OK) {
        const char *reason = "radio_reload_failed";

        if (apply_rc == APD_TXPOWER_APPLY_PARAM_FAILED)
            reason = "param_write_failed";
        else if (apply_rc == APD_TXPOWER_APPLY_REG_FAILED)
            reason = want_regulatory ? "regulatory_reapply_failed" :
                                       "calibrated_reapply_failed";
        else if (apply_rc == APD_TXPOWER_APPLY_STOP_FAILED)
            reason = "wireless_quiesce_failed";
        rollback_rc = apd_txpower_restore_calibrated(
            iw, radio, country, &baseline, &state);
        return apd_txpower_fail(rollback_rc == 0 ?
                                reason :
                                "calibrated_interface_not_restored", &state);
    }

    /* Read back the real state rather than trusting the write. */
    apd_txpower_collect_after_apply(&state);
    snprintf(state.radio, sizeof(state.radio), "%s", radio);
    state.radio_reload_performed = 1;
    state.radio_reload_ok = 1;

    if (want_regulatory && !apd_txpower_regulatory_state_ok(&state)) {
        /* Never leave a partial high-power request active after failed proof. */
        rollback_rc = apd_txpower_restore_calibrated(
            iw, radio, country, &baseline, &state);
        return apd_txpower_fail(rollback_rc == 0 ?
                                "active_interface_txpower_not_applied" :
                                "calibrated_interface_not_restored", &state);
    }
    if (!want_regulatory && !apd_txpower_calibrated_state_ok(&state)) {
        rollback_rc = apd_txpower_restore_calibrated(
            iw, radio, country, &baseline, &state);
        return apd_txpower_fail(rollback_rc == 0 ?
                                "calibrated_mode_not_applied" :
                                "calibrated_interface_not_restored", &state);
    }

persist:
    /* The sysfs knob is volatile. Persist only after the live readback has
     * proved the requested mode, and fail closed if the durable write fails. */
    if (apd_txpower_persist_selection(mode, state.persisted_mode) != 0) {
        if (already_applied)
            return apd_txpower_fail("persistence_write_failed", &state);
        rollback_rc = apd_txpower_restore_calibrated(
            iw, radio, country, &baseline, &state);
        return apd_txpower_fail(rollback_rc == 0 ?
                                "persistence_write_failed" :
                                "calibrated_interface_not_restored", &state);
    }
    snprintf(state.persisted_mode, sizeof(state.persisted_mode), "%s", mode);

    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "operation",
                           json_object_new_string("txpower_mode_set"));
    json_object_object_add(root, "requested_mode",
                           json_object_new_string(mode));
    json_object_object_add(root, "applied", json_object_new_boolean(1));
    json_object_object_add(root, "already_applied",
                           json_object_new_boolean(already_applied));
    json_object_object_add(root, "boot_mode_persisted",
                           json_object_new_boolean(1));
    apd_txpower_add_state(root, &state);
    return root;
}

int apd_txpower_mode_restore_persisted(void)
{
    char mode[APD_TXPOWER_MODE_MAX + 1];
    struct apd_txpower_mode_state state;
    struct json_object *result;
    struct json_object *ok = NULL;
    int rc;

    rc = apd_txpower_persist_read(mode);
    if (rc == 1)
        return 0; /* No operator selection yet: keep the driver default. */
    if (rc != 0)
        return -1;
    if (!strcmp(mode, APD_TXPOWER_MODE_CALIBRATED)) {
        /* Calibrated is the driver default; do not needlessly cycle Wi-Fi. */
        return 0;
    }

    if (apd_txpower_mode_state_collect(&state) != 0)
        return APD_TXPOWER_RESTORE_RETRY;
    if (!state.board_allowed)
        return APD_TXPOWER_RESTORE_FAILED;
    if (!state.param_present || !state.regdb_ready ||
        !state.wireless_inventory_ok)
        return APD_TXPOWER_RESTORE_RETRY;
    /* Restoring a ceiling is not a request to force every MLO link to it. */
    if (!strcmp(state.mode, mode) &&
        state.ceiling_dbm_x10 >= APD_TXPOWER_REQUIRED_REG_CEILING_X10)
        return APD_TXPOWER_RESTORE_OK;
    /* A per-radio down/up also tears down shared MLO links. An APD restart
     * must not replay that operation against an already-created interface. */
    if (state.wireless_interfaces_present)
        return APD_TXPOWER_RESTORE_DEFERRED;

    result = apd_txpower_mode_set_json(APD_TXPOWER_MODE_REGULATORY, 1);
    if (!result)
        return APD_TXPOWER_RESTORE_FAILED;
    if (json_object_object_get_ex(result, "ok", &ok) &&
        json_object_get_boolean(ok)) {
        json_object_put(result);
        return 0;
    }
    json_object_put(result);

    /* set_json already attempted rollback. Retrying here would alternate
     * apply/rollback radio cycles; leave the persisted intent for the user. */
    return APD_TXPOWER_RESTORE_FAILED;
}

#ifndef APD_TXPOWER_MODE_STANDALONE_TEST
static void apd_txpower_restore_timer_cb(struct uloop_timeout *timeout)
{
    int rc;

    (void)timeout;
    apd_txpower_restore_attempts++;
    rc = apd_txpower_mode_restore_persisted();
    if (rc == APD_TXPOWER_RESTORE_OK) {
        apd_txpower_restore_pending = 0;
        apd_txpower_restore_reason[0] = '\0';
        return;
    }
    if (rc == APD_TXPOWER_RESTORE_DEFERRED ||
        rc == APD_TXPOWER_RESTORE_FAILED) {
        apd_txpower_restore_pending = 0;
        snprintf(apd_txpower_restore_reason, sizeof(apd_txpower_restore_reason),
                 "%s", rc == APD_TXPOWER_RESTORE_DEFERRED ?
                 "active_wireless_requires_explicit_apply" : "restore_failed");
        return;
    }

    snprintf(apd_txpower_restore_reason, sizeof(apd_txpower_restore_reason),
             "%s", "wireless_not_ready");
    if (apd_txpower_restore_attempts < APD_TXPOWER_RESTORE_MAX_ATTEMPTS)
        uloop_timeout_set(&apd_txpower_restore_timer,
                          APD_TXPOWER_RESTORE_RETRY_MS);
    else {
        apd_txpower_restore_pending = 0;
        snprintf(apd_txpower_restore_reason, sizeof(apd_txpower_restore_reason),
                 "%s", "retry_exhausted");
    }
}

int apd_txpower_mode_restore_start(void)
{
    char mode[APD_TXPOWER_MODE_MAX + 1];
    int rc = apd_txpower_persist_read(mode);

    apd_txpower_restore_attempts = 0;
    apd_txpower_restore_reason[0] = '\0';
    if (rc == 1 || (rc == 0 && !strcmp(mode, APD_TXPOWER_MODE_CALIBRATED))) {
        apd_txpower_restore_pending = 0;
        return 0;
    }
    if (rc != 0) {
        apd_txpower_restore_pending = 0;
        snprintf(apd_txpower_restore_reason, sizeof(apd_txpower_restore_reason),
                 "%s", "persisted_mode_invalid");
        return -1;
    }

    apd_txpower_restore_pending = 1;
    snprintf(apd_txpower_restore_reason, sizeof(apd_txpower_restore_reason),
             "%s", "waiting_for_wireless");
    apd_txpower_restore_timer.cb = apd_txpower_restore_timer_cb;
    uloop_timeout_set(&apd_txpower_restore_timer,
                      APD_TXPOWER_RESTORE_INITIAL_MS);
    return 0;
}

void apd_txpower_mode_restore_stop(void)
{
    uloop_timeout_cancel(&apd_txpower_restore_timer);
}
#else
int apd_txpower_mode_restore_start(void) { return 0; }
void apd_txpower_mode_restore_stop(void) {}
#endif
