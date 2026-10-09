// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef APD_HOSTAPD_STANDALONE_TEST
#include "apd_internal.h"
#include "apd_readonly_command.h"
#include "jmx_strbuf.h"
#else
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#ifdef APD_ROAMING_STANDALONE_TEST
#include "apd_config_executor.h"
#endif
#if defined(APD_SURVEY_STANDALONE_TEST) || \
    defined(APD_NEIGHBOR_SCAN_STANDALONE_TEST)
#include "apd_readonly_command.h"
#endif
#endif

#include <ctype.h>
#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <stddef.h>
#include <pwd.h>
#include <signal.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>

/*
 * Parser for the QCA vendor channel listing. Header-only dependency: the
 * implementation lives in its own translation unit so the catalogue fallback
 * stays testable apart from the collectors in this file.
 */
#include "apd_vendor_chanlist.h"
#include "apd_iw_topology.h"
#include "ap_radio_id.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef APD_IEEE80211_PATH
#define APD_IEEE80211_PATH "/sys/class/ieee80211"
#endif
#ifndef APD_UCI_CONFIG_DIR
#define APD_UCI_CONFIG_DIR "/etc/config"
#endif
#ifndef APD_HOSTAPD_RUN_DIR
#define APD_HOSTAPD_RUN_DIR "/var/run/hostapd"
#endif
/*
 * QCA/QSDK builds (QWRT on the BE10000) do not put per-interface control
 * sockets in APD_HOSTAPD_RUN_DIR. That directory holds only the `global`
 * socket, and each radio gets its own `ctrl_interface=/var/run/hostapd-wifiN`
 * directory holding the VAP sockets (ath0, ath01, ...). Scanning only the main
 * directory therefore found a global socket and no per-interface ones, and
 * concluded `per_interface_control_unavailable` on a device where every socket
 * was present. The sibling directories are matched by this prefix under the
 * same parent as the main run directory.
 */
#ifndef APD_HOSTAPD_RUN_DIR_PARENT
#define APD_HOSTAPD_RUN_DIR_PARENT "/var/run"
#endif
#ifndef APD_HOSTAPD_VENDOR_DIR_PREFIX
#define APD_HOSTAPD_VENDOR_DIR_PREFIX "hostapd-"
#endif
/* Bounds the sibling-directory scan; QSDK ships at most a handful of radios. */
#ifndef APD_HOSTAPD_VENDOR_DIR_LIMIT
#define APD_HOSTAPD_VENDOR_DIR_LIMIT 8
#endif
#ifndef APD_HOSTAPD_CONF_PREFIX
#define APD_HOSTAPD_CONF_PREFIX APD_HOSTAPD_RUN_DIR_PARENT "/hostapd-"
#endif
#ifndef APD_IW_PATH
#define APD_IW_PATH ""
#endif
#ifndef APD_WLANCONFIG_PATH
#define APD_WLANCONFIG_PATH ""
#endif
#ifndef APD_APSTATS_PATH
#define APD_APSTATS_PATH ""
#endif
#ifndef APD_HOSTAPD_LOCAL_DIR
#define APD_HOSTAPD_LOCAL_DIR "/var/run/dreamingwrt-apd"
#endif
#ifndef APD_HOSTAPD_EXPECTED_UID
#define APD_HOSTAPD_EXPECTED_UID ((uid_t)0)
#endif
#ifndef APD_HOSTAPD_SERVICE_USER
#define APD_HOSTAPD_SERVICE_USER "network"
#endif
#ifndef APD_HOSTAPD_SERVICE_UID
#define APD_HOSTAPD_SERVICE_UID ((uid_t)-1)
#endif
#ifndef APD_HOSTAPD_SERVICE_GID
#define APD_HOSTAPD_SERVICE_GID ((gid_t)-1)
#endif
#ifndef APD_HOSTAPD_TIMEOUT_MS
#define APD_HOSTAPD_TIMEOUT_MS 750
#endif
#ifndef APD_HOSTAPD_COLLECTION_TIMEOUT_MS
#define APD_HOSTAPD_COLLECTION_TIMEOUT_MS 5000
#endif
#ifndef APD_HOSTAPD_RESPONSE_LIMIT
#define APD_HOSTAPD_RESPONSE_LIMIT (32U * 1024U)
#endif
#ifndef APD_HOSTAPD_BSS_LIMIT
#define APD_HOSTAPD_BSS_LIMIT 32U
#endif
/*
 * Size of the control-directory paths held while scanning.
 *
 * These buffers only ever feed apd_hostapd_socket_path(), which writes
 * "<dir>/<name>" into a sockaddr_un sun_path, so a directory longer than
 * sun_path is unusable no matter how much room we reserve for it. PATH_MAX
 * per entry is what overflowed the collector's stack: BSS_LIMIT plus the
 * vendor directories came to roughly 166KB in a single frame, against the
 * 128KB default thread stack musl gives the transport worker, so the
 * function faulted in its prologue as soon as a radio was present.
 */
#define APD_HOSTAPD_DIR_LEN sizeof(((struct sockaddr_un *)0)->sun_path)
#ifndef APD_HOSTAPD_STATION_LIMIT
#define APD_HOSTAPD_STATION_LIMIT 256U
#endif
#ifndef APD_UBUS_TIMEOUT_MS
#define APD_UBUS_TIMEOUT_MS 2500
#endif
#ifndef APD_HOSTAPD_STATIONS_PER_BSS_LIMIT
#define APD_HOSTAPD_STATIONS_PER_BSS_LIMIT 128U
#endif
#ifndef APD_HOSTAPD_SOCKET_SCAN_LIMIT
#define APD_HOSTAPD_SOCKET_SCAN_LIMIT 128U
#endif
#ifndef APD_NET_CLASS_PATH
#define APD_NET_CLASS_PATH "/sys/class/net"
#endif
#ifndef APD_NEIGHBOR_SCAN_TIMEOUT_MS
#define APD_NEIGHBOR_SCAN_TIMEOUT_MS 30000
#endif
#ifndef APD_NEIGHBOR_SCAN_OUTPUT_LIMIT
#define APD_NEIGHBOR_SCAN_OUTPUT_LIMIT (1024U * 1024U)
#endif
#ifndef APD_NEIGHBOR_SCAN_ITEM_LIMIT
#define APD_NEIGHBOR_SCAN_ITEM_LIMIT 128U
#endif
#ifndef APD_NEIGHBOR_SCAN_FRAME_LIMIT
/* Must leave headroom under AP_CONTROL_FRAME_MAX/2 (32 KiB wire budget)
 * for the radio job finish/reconcile envelope. */
#define APD_NEIGHBOR_SCAN_FRAME_LIMIT (24U * 1024U)
#endif
#ifndef APD_NEIGHBOR_IF_NAMETOINDEX
#define APD_NEIGHBOR_IF_NAMETOINDEX(name) if_nametoindex(name)
#endif

#ifndef APD_HOSTAPD_STANDALONE_TEST
struct apd_netifd_result {
    struct json_object *json;
};
#endif

#ifndef APD_SURVEY_STANDALONE_TEST
static int64_t apd_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int apd_hostapd_control_dir_available(void);
#endif

#if !defined(APD_HOSTAPD_STANDALONE_TEST) || \
    defined(APD_SURVEY_STANDALONE_TEST) || \
    defined(APD_NEIGHBOR_SCAN_STANDALONE_TEST)
#define APD_SURVEY_REASON_LEN 63U
/*
 * Locating the `iw` binary is an access() probe with nothing hostapd-specific in
 * it, so it lives under the widest guard that any of its callers use. It used to
 * sit inside "#ifndef APD_HOSTAPD_STANDALONE_TEST" while its callers are in the
 * neighbor-scan/survey vendor-fallback block that IS compiled in for those
 * fixtures, so both standalone builds saw a call with no declaration:
 * "call to undeclared function 'apd_find_iw'". Note the guard below admits the
 * survey fixture too, which defines APD_SURVEY_STANDALONE_TEST but not
 * APD_NEIGHBOR_SCAN_STANDALONE_TEST -- placing this any deeper fixes only the
 * neighbor-scan build and leaves the survey build broken.
 */
static const char *apd_find_iw(void)
{
    static const char *const paths[] = {
        "/usr/sbin/iw", "/usr/bin/iw", "/sbin/iw", NULL
    };
    size_t i;

    if (APD_IW_PATH[0] && access(APD_IW_PATH, X_OK) == 0)
        return APD_IW_PATH;
    for (i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return NULL;
}


struct apd_survey_sample {
    int has_frequency;
    int frequency_mhz;
    int in_use;
    int has_noise;
    int noise_dbm;
    int has_active_time;
    uint64_t active_time_ms;
    int has_busy_time;
    uint64_t busy_time_ms;
    int has_receive_time;
    uint64_t receive_time_ms;
    /*
     * `channel BSS receive time` is airtime spent receiving frames of *this*
     * BSS. mac80211 prints it right after `channel receive time`, so
     * (busy - bss_receive) is the airtime other networks and non-Wi-Fi energy
     * occupied -- the only honest OBSS figure available without vendor
     * counters. Kept separate from receive_time_ms: that one counts every
     * frame the radio decoded, self-BSS included.
     */
    int has_bss_receive_time;
    uint64_t bss_receive_time_ms;
    int has_transmit_time;
    uint64_t transmit_time_ms;
    int malformed;
    int complete;
    char reason[APD_SURVEY_REASON_LEN + 1];
};

static char *apd_survey_trim(char *line)
{
    char *end;

    while (*line == ' ' || *line == '\t')
        line++;
    end = line + strlen(line);
    while (end > line && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return line;
}

static int apd_survey_safe_interface_name(const char *name)
{
    size_t i;
    size_t length;

    if (!name)
        return 0;
    length = strlen(name);
    if (!length || length >= IFNAMSIZ || name[0] == '.')
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)name[i];

        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static int apd_survey_parse_signed(const char *value, long minimum,
                                   long maximum, long *out,
                                   const char **end_out)
{
    char *end = NULL;
    long parsed;

    if (!value || !out)
        return -1;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno == ERANGE || end == value || parsed < minimum || parsed > maximum)
        return -1;
    *out = parsed;
    if (end_out)
        *end_out = end;
    return 0;
}

static int apd_survey_parse_u64_ms(const char *line, const char *prefix,
                                   uint64_t *out)
{
    const char *value;
    char *end = NULL;
    unsigned long long parsed;

    if (!line || !prefix || !out || strncmp(line, prefix, strlen(prefix)) != 0)
        return 0;
    value = line + strlen(prefix);
    while (*value == ' ' || *value == '\t')
        value++;
    if (*value == '-')
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno == ERANGE || end == value || parsed > (unsigned long long)INT64_MAX)
        return -1;
    while (*end == ' ' || *end == '\t')
        end++;
    if (strcmp(end, "ms") != 0)
        return -1;
    *out = (uint64_t)parsed;
    return 1;
}

static int apd_survey_parse_frequency(const char *line, int *frequency_mhz,
                                      int *in_use)
{
    const char *value;
    const char *end;
    long parsed;

    if (!line || strncmp(line, "frequency:", 10) != 0)
        return 0;
    value = line + 10;
    while (*value == ' ' || *value == '\t')
        value++;
    if (apd_survey_parse_signed(value, 1, 100000, &parsed, &end) != 0)
        return -1;
    while (*end == ' ' || *end == '\t')
        end++;
    if (strncmp(end, "MHz", 3) != 0)
        return -1;
    end += 3;
    while (*end == ' ' || *end == '\t')
        end++;
    if (*end && strcmp(end, "[in use]") != 0)
        return -1;
    *frequency_mhz = (int)parsed;
    *in_use = strcmp(end, "[in use]") == 0;
    return 1;
}

static int apd_survey_parse_noise(const char *line, int *noise_dbm)
{
    const char *value;
    const char *end;
    long parsed;

    if (!line || strncmp(line, "noise:", 6) != 0)
        return 0;
    value = line + 6;
    while (*value == ' ' || *value == '\t')
        value++;
    if (apd_survey_parse_signed(value, -255, 255, &parsed, &end) != 0)
        return -1;
    while (*end == ' ' || *end == '\t')
        end++;
    if (strcmp(end, "dBm") != 0)
        return -1;
    *noise_dbm = (int)parsed;
    return 1;
}

static void apd_survey_consider(const struct apd_survey_sample *candidate,
                                int target_frequency,
                                struct apd_survey_sample *selected,
                                int *found)
{
    if (!candidate->has_frequency || candidate->frequency_mhz != target_frequency)
        return;
    if (!*found || (candidate->in_use && !selected->in_use)) {
        *selected = *candidate;
        *found = 1;
    }
}

static void apd_survey_finish(struct apd_survey_sample *sample, int found)
{
    if (!found) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_current_frequency_missing");
        return;
    }
    if (sample->malformed) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_value_invalid");
        return;
    }
    if (!sample->has_active_time) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_active_time_missing");
        return;
    }
    if (!sample->has_busy_time) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_busy_time_missing");
        return;
    }
    if (sample->busy_time_ms > sample->active_time_ms) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_busy_exceeds_active");
        return;
    }
    sample->complete = 1;
}

static int apd_survey_parse(const char *text, int target_frequency,
                            struct apd_survey_sample *sample)
{
    struct apd_survey_sample current = { 0 };
    struct apd_survey_sample selected = { 0 };
    char *copy;
    char *line;
    char *saveptr = NULL;
    int found = 0;

    if (!sample || target_frequency <= 0)
        return -1;
    memset(sample, 0, sizeof(*sample));
    copy = strdup(text ? text : "");
    if (!copy) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_allocation_failed");
        return -1;
    }
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_survey_trim(line);
        uint64_t counter = 0;
        int frequency_mhz = 0;
        int in_use = 0;
        int parsed;

        parsed = apd_survey_parse_frequency(value, &frequency_mhz, &in_use);
        if (parsed != 0) {
            apd_survey_consider(&current, target_frequency, &selected, &found);
            memset(&current, 0, sizeof(current));
            if (parsed < 0) {
                current.malformed = 1;
            } else {
                current.has_frequency = 1;
                current.frequency_mhz = frequency_mhz;
                current.in_use = in_use;
            }
            continue;
        }
        if (!current.has_frequency)
            continue;
        parsed = apd_survey_parse_noise(value, &current.noise_dbm);
        if (parsed != 0) {
            current.has_noise = parsed > 0;
            current.malformed |= parsed < 0;
            continue;
        }
        parsed = apd_survey_parse_u64_ms(value, "channel active time:",
                                         &counter);
        if (parsed != 0) {
            current.active_time_ms = counter;
            current.has_active_time = parsed > 0;
            current.malformed |= parsed < 0;
            continue;
        }
        parsed = apd_survey_parse_u64_ms(value, "channel busy time:",
                                         &counter);
        if (parsed != 0) {
            current.busy_time_ms = counter;
            current.has_busy_time = parsed > 0;
            current.malformed |= parsed < 0;
            continue;
        }
        parsed = apd_survey_parse_u64_ms(value, "channel receive time:",
                                         &counter);
        if (parsed != 0) {
            current.receive_time_ms = counter;
            current.has_receive_time = parsed > 0;
            current.malformed |= parsed < 0;
            continue;
        }
        parsed = apd_survey_parse_u64_ms(value, "channel BSS receive time:",
                                         &counter);
        if (parsed != 0) {
            current.bss_receive_time_ms = counter;
            current.has_bss_receive_time = parsed > 0;
            current.malformed |= parsed < 0;
            continue;
        }
        parsed = apd_survey_parse_u64_ms(value, "channel transmit time:",
                                         &counter);
        if (parsed != 0) {
            current.transmit_time_ms = counter;
            current.has_transmit_time = parsed > 0;
            current.malformed |= parsed < 0;
        }
    }
    apd_survey_consider(&current, target_frequency, &selected, &found);
    free(copy);
    *sample = selected;
    apd_survey_finish(sample, found);
    return found ? 0 : -1;
}

#if !defined(APD_NEIGHBOR_SCAN_STANDALONE_TEST) || \
    defined(APD_SURVEY_STANDALONE_TEST)
static int apd_survey_utilization(const struct apd_survey_sample *sample,
                                  double *utilization_pct)
{
    if (!sample || !utilization_pct || !sample->has_active_time ||
        !sample->has_busy_time || sample->active_time_ms == 0 ||
        sample->busy_time_ms > sample->active_time_ms)
        return -1;
    *utilization_pct = (double)sample->busy_time_ms * 100.0 /
                       (double)sample->active_time_ms;
    return 0;
}

/*
 * Airtime split between this BSS and everything else on the channel.
 *
 * mac80211 reports `channel BSS receive time` alongside busy/active, so the
 * OBSS share is (busy - bss_receive) / active: busy airtime that this BSS did
 * not receive is by definition other networks plus non-Wi-Fi energy. Vendor
 * `apstats` builds report the same two figures directly; this derivation is
 * what makes them available on a plain mac80211 AP, where the wireless page
 * used to print "driver did not report OBSS".
 *
 * Fail-closed: no BSS-receive counter, no numbers. Nothing is inferred from
 * neighbour scans or signal strength.
 */
static int apd_survey_bss_split(const struct apd_survey_sample *sample,
                                double *obss_pct, double *self_pct)
{
    uint64_t obss_ms;

    if (!sample || !sample->has_active_time || !sample->has_busy_time ||
        !sample->has_bss_receive_time || sample->active_time_ms == 0 ||
        sample->busy_time_ms > sample->active_time_ms ||
        sample->bss_receive_time_ms > sample->busy_time_ms)
        return -1;
    obss_ms = sample->busy_time_ms - sample->bss_receive_time_ms;
    if (obss_pct)
        *obss_pct = (double)obss_ms * 100.0 / (double)sample->active_time_ms;
    if (self_pct)
        *self_pct = (double)sample->bss_receive_time_ms * 100.0 /
                    (double)sample->active_time_ms;
    return 0;
}

static int apd_survey_collect_raw(const char *path, const char *interface,
                                  int target_frequency,
                                  struct apd_survey_sample *sample)
{
    struct apd_command_result result = { 0 };
    int rc;

    if (!sample)
        return -1;
    memset(sample, 0, sizeof(*sample));
    if (!path || !path[0]) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_binary_unavailable");
        return -1;
    }
    if (target_frequency <= 0) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_current_frequency_unavailable");
        return -1;
    }
    if (!interface || !interface[0]) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_ap_interface_unavailable");
        return -1;
    }
    if (!apd_survey_safe_interface_name(interface)) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_interface_invalid");
        return -1;
    }
    {
        char *const argv[] = {
            (char *)path, "dev", (char *)interface, "survey", "dump", NULL
        };

        rc = apd_readonly_command(path, argv, &result);
    }
    if (rc != 0) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 result.timed_out ? "iw_survey_timeout" :
                                    "iw_survey_failed_or_unsupported");
        apd_command_result_free(&result);
        return -1;
    }
    if (!result.text || !result.length) {
        snprintf(sample->reason, sizeof(sample->reason), "%s",
                 "iw_survey_unsupported");
        apd_command_result_free(&result);
        return -1;
    }
    rc = apd_survey_parse(result.text, target_frequency, sample);
    apd_command_result_free(&result);
    return rc == 0 && sample->complete ? 0 : -1;
}

#endif

/* The channel-catalog block below is compiled for both the neighbor-scan
 * and the survey standalone fixtures, so both need json-c declarations;
 * guarding the include on neighbor-scan alone left the survey fixture
 * compiling that block with implicit declarations. */
#if defined(APD_NEIGHBOR_SCAN_STANDALONE_TEST) || \
    defined(APD_SURVEY_STANDALONE_TEST)
#include <json-c/json.h>
#endif

#if !defined(APD_HOSTAPD_STANDALONE_TEST) || \
    defined(APD_NEIGHBOR_SCAN_STANDALONE_TEST)
#define APD_NEIGHBOR_REASON_LEN 95U
#define APD_NEIGHBOR_SSID_LEN 32U

struct apd_neighbor_target {
    char radio_id[32];
    char wiphy_name[64];
    char interface[IFNAMSIZ];
    unsigned int wiphy_index;
    unsigned int radio_index;
    int has_radio_index;
    unsigned int ifindex;
    int frequency_mhz;
    int preferred;
};

struct apd_neighbor_item {
    char bssid[18];
    unsigned char ssid[APD_NEIGHBOR_SSID_LEN];
    size_t ssid_len;
    int has_ssid;
    int ssid_valid;
    int locally_administered;
    int has_frequency;
    int frequency_mhz;
    int has_signal;
    double signal_dbm;
    int has_age;
    uint64_t age_ms;
    int has_width;
    int width_mhz;
    char width_mode[16];
    int standard_rank;
    int privacy;
    int rsn;
    int wpa;
    int auth_psk;
    int auth_sae;
    int auth_owe;
    int auth_eap;
    int malformed;
};

struct apd_neighbor_parse_result {
    struct apd_neighbor_item *items;
    size_t count;
    size_t capacity;
    size_t malformed_count;
};

static int apd_neighbor_read_uint_file(const char *path, unsigned int *out)
{
    char buffer[32];
    char *end = NULL;
    unsigned long value;
    ssize_t length;
    int fd;

    if (!path || !out || (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
        return -1;
    do {
        length = read(fd, buffer, sizeof(buffer) - 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    if (length <= 0 || (size_t)length >= sizeof(buffer))
        return -1;
    buffer[length] = '\0';
    errno = 0;
    value = strtoul(buffer, &end, 10);
    while (end && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
        end++;
    if (errno == ERANGE || !end || end == buffer || *end || value > UINT_MAX)
        return -1;
    *out = (unsigned int)value;
    return 0;
}

static int apd_neighbor_radio_id(const char *radio_id,
                                 unsigned int *wiphy_index,
                                 unsigned int *radio_index,
                                 int *has_radio_index)
{
    return dreamingwrt_ap_radio_id_parse(radio_id, wiphy_index, radio_index,
                                         has_radio_index);
}

static int apd_neighbor_wiphy_name(unsigned int index, char *out, size_t out_size)
{
    DIR *directory = opendir(APD_IEEE80211_PATH);
    struct dirent *entry;
    int found = 0;

    if (!directory || !out || out_size == 0)
        return -1;
    while ((entry = readdir(directory)) != NULL) {
        char path[PATH_MAX];
        size_t name_len;
        unsigned int observed;

        if (entry->d_name[0] == '.' ||
            snprintf(path, sizeof(path), "%s/%s/index", APD_IEEE80211_PATH,
                     entry->d_name) >= (int)sizeof(path) ||
            apd_neighbor_read_uint_file(path, &observed) != 0 || observed != index)
            continue;
        name_len = strlen(entry->d_name);
        if (found || name_len >= out_size) {
            found = -1;
            break;
        }
        memcpy(out, entry->d_name, name_len + 1);
        found = 1;
    }
    closedir(directory);
    return found == 1 ? 0 : -1;
}

static int apd_neighbor_interface_runtime_valid(const char *interface,
                                                unsigned int wiphy_index,
                                                unsigned int parsed_ifindex)
{
    char path[PATH_MAX];
    char state[24];
    unsigned int actual_wiphy;
    unsigned int actual_ifindex;
    ssize_t length;
    int fd;

    if (!apd_survey_safe_interface_name(interface) ||
        (actual_ifindex = APD_NEIGHBOR_IF_NAMETOINDEX(interface)) == 0 ||
        actual_ifindex != parsed_ifindex)
        return 0;
    if (snprintf(path, sizeof(path), "%s/%s/phy80211/index", APD_NET_CLASS_PATH,
                 interface) >= (int)sizeof(path) ||
        apd_neighbor_read_uint_file(path, &actual_wiphy) != 0 ||
        actual_wiphy != wiphy_index)
        return 0;
    if (snprintf(path, sizeof(path), "%s/%s/operstate", APD_NET_CLASS_PATH,
                 interface) >= (int)sizeof(path) ||
        (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
        return 0;
    do {
        length = read(fd, state, sizeof(state) - 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    if (length <= 0 || (size_t)length >= sizeof(state))
        return 0;
    state[length] = '\0';
    while (length > 0 && isspace((unsigned char)state[length - 1]))
        state[--length] = '\0';
    return !strcmp(state, "up") || !strcmp(state, "unknown");
}

static void apd_neighbor_target_consider(struct apd_neighbor_target *best,
                                         int *found, unsigned int wiphy_index,
                                         int has_radio_index,
                                         int interface_radio_match,
                                         const char *interface,
                                         unsigned int ifindex, int frequency,
                                         int type_ap, int has_ssid)
{
    int preferred;
    int best_preferred;

    if (!type_ap || frequency <= 0 ||
        (has_radio_index && !interface_radio_match) ||
        !interface || !interface[0] ||
        !apd_neighbor_interface_runtime_valid(interface, wiphy_index, ifindex))
        return;
    /* QWRT/QSDK "wifiN" radio nodes reject scan triggers with EPERM
     * (verified on BE10000 2026-07-26); broadcasting VAPs can scan. */
    preferred = strncmp(interface, "wifi", 4) != 0 && has_ssid;
    best_preferred = *found ? best->preferred : 0;
    if (*found && (preferred < best_preferred ||
        (preferred == best_preferred && ifindex >= best->ifindex)))
        return;
    snprintf(best->interface, sizeof(best->interface), "%s", interface);
    best->ifindex = ifindex;
    best->frequency_mhz = frequency;
    best->preferred = preferred;
    *found = 1;
}

/* QSDK exposes several type-801 radio netdevs under one wiphy and prints the
 * radio anchors after the ordinary VAPs in `iw dev`. Resolve wifiN's current
 * frequency in a first pass so the second pass can select an ordinary VAP on
 * the same band even though QSDK prints no `Radios:` line. */
static int apd_neighbor_logical_frequency(const char *text,
                                          unsigned int wiphy_index,
                                          unsigned int radio_index,
                                          int *frequency_out)
{
    char expected[IFNAMSIZ];
    char *copy;
    char *line;
    char *saveptr = NULL;
    unsigned int current_index = UINT_MAX;
    int matching = 0;
    int frequency = 0;

    if (!frequency_out ||
        snprintf(expected, sizeof(expected), "wifi%u", radio_index) >=
            (int)sizeof(expected))
        return -1;
    copy = strdup(text ? text : "");
    if (!copy)
        return -1;
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_survey_trim(line);

        if (!strncmp(value, "phy#", 4)) {
            current_index = (unsigned int)strtoul(value + 4, NULL, 10);
            matching = 0;
            continue;
        }
        if (current_index != wiphy_index)
            continue;
        if (!strncmp(value, "Interface ", 10)) {
            matching = !strcmp(value + 10, expected);
            continue;
        }
        if (matching && !strncmp(value, "channel ", 8)) {
            int channel = 0;

            if (sscanf(value, "channel %d (%d MHz)", &channel,
                       &frequency) == 2 && frequency > 0)
                break;
        }
    }
    free(copy);
    if (frequency <= 0)
        return -1;
    *frequency_out = frequency;
    return 0;
}

static int apd_neighbor_target_from_iw(const char *text, const char *radio_id,
                                       struct apd_neighbor_target *target,
                                       char reason[APD_NEIGHBOR_REASON_LEN + 1])
{
    char *copy;
    char *line;
    char *saveptr = NULL;
    char interface[IFNAMSIZ] = { 0 };
    unsigned int requested_index = 0;
    unsigned int requested_radio = 0;
    int has_requested_radio = 0;
    unsigned int current_index = UINT_MAX;
    unsigned int ifindex = 0;
    int frequency = 0;
    int type_ap = 0;
    int has_ssid = 0;
    int interface_radio_match = 0;
    int aggregate_mld = 0;
    int requested_frequency = 0;
    int found = 0;

    memset(target, 0, sizeof(*target));
    if (apd_neighbor_radio_id(radio_id, &requested_index, &requested_radio,
                              &has_requested_radio) != 0) {
        snprintf(reason, APD_NEIGHBOR_REASON_LEN + 1, "%s", "radio_id_invalid");
        return -1;
    }
    target->wiphy_index = requested_index;
    target->radio_index = requested_radio;
    target->has_radio_index = has_requested_radio;
    if (has_requested_radio)
        (void)apd_neighbor_logical_frequency(text, requested_index,
                                             requested_radio,
                                             &requested_frequency);
    snprintf(target->radio_id, sizeof(target->radio_id), "%s", radio_id);
    if (apd_neighbor_wiphy_name(requested_index, target->wiphy_name,
                                sizeof(target->wiphy_name)) != 0) {
        snprintf(reason, APD_NEIGHBOR_REASON_LEN + 1, "%s",
                 "radio_sysfs_mapping_unavailable");
        return -1;
    }
    copy = strdup(text ? text : "");
    if (!copy) {
        snprintf(reason, APD_NEIGHBOR_REASON_LEN + 1, "%s", "allocation_failed");
        return -1;
    }
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_survey_trim(line);

        if (!strncmp(value, "phy#", 4)) {
            apd_neighbor_target_consider(target, &found, requested_index,
                                         has_requested_radio,
                                         interface_radio_match,
                                         interface, ifindex, frequency,
                                         type_ap && !aggregate_mld, has_ssid);
            interface[0] = '\0';
            ifindex = 0;
            frequency = 0;
            type_ap = 0;
            has_ssid = 0;
            interface_radio_match = 0;
            aggregate_mld = 0;
            current_index = (unsigned int)strtoul(value + 4, NULL, 10);
            continue;
        }
        if (current_index != requested_index)
            continue;
        if (!strncmp(value, "Interface ", 10)) {
            apd_neighbor_target_consider(target, &found, requested_index,
                                         has_requested_radio,
                                         interface_radio_match,
                                         interface, ifindex, frequency,
                                         type_ap && !aggregate_mld, has_ssid);
            snprintf(interface, sizeof(interface), "%s", value + 10);
            ifindex = 0;
            frequency = 0;
            type_ap = 0;
            has_ssid = 0;
            aggregate_mld = 0;
            if (has_requested_radio) {
                char expected[IFNAMSIZ];

                interface_radio_match =
                    snprintf(expected, sizeof(expected), "wifi%u",
                             requested_radio) < (int)sizeof(expected) &&
                    !strcmp(interface, expected);
            } else {
                interface_radio_match = 0;
            }
        } else if (!strncmp(value, "ifindex ", 8)) {
            unsigned long parsed = strtoul(value + 8, NULL, 10);
            if (parsed <= UINT_MAX)
                ifindex = (unsigned int)parsed;
        } else if (!strncmp(value, "type ", 5)) {
            type_ap = !strcmp(value + 5, "AP");
        } else if (!strncmp(value, "ssid ", 5)) {
            has_ssid = 1;
        } else if (!strncmp(value, "channel ", 8)) {
            int channel = 0;
            int parsed_frequency = 0;
            if (!aggregate_mld &&
                sscanf(value, "channel %d (%d MHz)", &channel,
                       &parsed_frequency) == 2 && parsed_frequency > 0) {
                frequency = parsed_frequency;
                if (has_requested_radio && requested_frequency > 0 &&
                    frequency == requested_frequency)
                    interface_radio_match = 1;
            }
        } else if (!strcmp(value, "MLD with links:") ||
                   (!strncmp(value, "link ", 5) && strchr(value, ':'))) {
            aggregate_mld = 1;
            frequency = 0;
        } else if (!strncmp(value, "Radios:", 7)) {
            const char *cursor = value + 7;

            while (*cursor) {
                char *end = NULL;
                unsigned long parsed;

                while (*cursor && isspace((unsigned char)*cursor))
                    cursor++;
                if (!*cursor)
                    break;
                errno = 0;
                parsed = strtoul(cursor, &end, 10);
                if (errno == ERANGE || !end || end == cursor ||
                    parsed > UINT_MAX)
                    break;
                if ((unsigned int)parsed == requested_radio)
                    interface_radio_match = 1;
                cursor = end;
            }
        }
    }
    apd_neighbor_target_consider(target, &found, requested_index,
                                 has_requested_radio,
                                 interface_radio_match, interface,
                                 ifindex, frequency,
                                 type_ap && !aggregate_mld, has_ssid);
    free(copy);
    if (!found) {
        snprintf(reason, APD_NEIGHBOR_REASON_LEN + 1, "%s",
                 "radio_not_scannable");
        return -1;
    }
    reason[0] = '\0';
    return 0;
}

static int apd_neighbor_hex(unsigned char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int apd_neighbor_ssid_decode(const char *text, unsigned char *out,
                                    size_t *out_len)
{
    size_t length = 0;

    for (size_t i = 0; text && text[i]; i++) {
        unsigned char byte = (unsigned char)text[i];

        if (byte == '\\') {
            int high;
            int low;

            if (text[i + 1] == '\\') {
                byte = '\\';
                i++;
            } else if (text[i + 1] == 'x' &&
                       (high = apd_neighbor_hex((unsigned char)text[i + 2])) >= 0 &&
                       (low = apd_neighbor_hex((unsigned char)text[i + 3])) >= 0) {
                byte = (unsigned char)((high << 4) | low);
                i += 3;
            } else {
                return -1;
            }
        }
        if (length >= APD_NEIGHBOR_SSID_LEN)
            return -1;
        out[length++] = byte;
    }
    *out_len = length;
    return 0;
}

/* The ap-control wire's strict JSON parser rejects any raw non-ASCII
 * byte (verified against staging json-c on 2026-07-26: ["楼"] as raw
 * UTF-8 is refused, ASCII passes). Until the wire contract grows UTF-8
 * support, the human-readable "ssid" field is only populated for
 * printable-ASCII names; ssid_hex always carries the exact bytes. */
static int apd_neighbor_ssid_wire_safe(const unsigned char *bytes,
                                       size_t length)
{
    for (size_t i = 0; i < length; i++) {
        if (bytes[i] < 0x20 || bytes[i] > 0x7e)
            return 0;
    }
    return 1;
}

static int apd_neighbor_mac(const char *text, char out[18],
                            int *locally_administered)
{
    static const char hex[] = "0123456789abcdef";
    unsigned int bytes[6];
    char tail;
    size_t i;

    if (!text || sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &bytes[0],
                        &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5],
                        &tail) != 6 || (bytes[0] & 1))
        return -1;
    for (i = 0; i < 6; i++) {
        out[i * 3] = hex[(bytes[i] >> 4) & 0x0f];
        out[i * 3 + 1] = hex[bytes[i] & 0x0f];
        if (i < 5)
            out[i * 3 + 2] = ':';
    }
    out[17] = '\0';
    *locally_administered = !!(bytes[0] & 2);
    return 0;
}

static int apd_neighbor_channel(int frequency)
{
    if (frequency == 2484) return 14;
    if (frequency >= 2412 && frequency <= 2472 && (frequency - 2407) % 5 == 0)
        return (frequency - 2407) / 5;
    if (frequency >= 5000 && frequency < 5925 && frequency % 5 == 0)
        return (frequency - 5000) / 5;
    if (frequency == 5935) return 2;
    if (frequency >= 5955 && frequency <= 7115 && (frequency - 5950) % 5 == 0)
        return (frequency - 5950) / 5;
    return 0;
}

static void apd_neighbor_standard(struct apd_neighbor_item *item, int rank)
{
    if (rank > item->standard_rank)
        item->standard_rank = rank;
}

/* iw >= 5.16 prints the scan frequency with a kHz fraction ("freq: 2412.0")
 * because nl80211 gained NL80211_ATTR_WIPHY_FREQ_OFFSET.  The integer MHz is
 * the value the channel mapping needs, so accept and drop a well-formed
 * fraction.  Any other trailing text is unparsed evidence and still marks the
 * BSS block malformed rather than being silently ignored. */
static int apd_neighbor_freq_tail_valid(const char *end)
{
    if (!end)
        return 0;
    if (!*end)
        return 1;
    if (*end != '.' || !isdigit((unsigned char)end[1]))
        return 0;
    for (end++; isdigit((unsigned char)*end); end++)
        ;
    return !*end;
}

static int apd_neighbor_store(struct apd_neighbor_parse_result *result,
                              const struct apd_neighbor_item *item)
{
    struct apd_neighbor_item *expanded;

    for (size_t i = 0; i < result->count; i++) {
        if (strcmp(result->items[i].bssid, item->bssid))
            continue;
        if ((!item->has_age && result->items[i].has_age) ||
            (item->has_age && result->items[i].has_age &&
             item->age_ms > result->items[i].age_ms) ||
            (item->has_age == result->items[i].has_age && item->has_signal &&
             result->items[i].has_signal &&
             item->signal_dbm <= result->items[i].signal_dbm))
            return 0;
        result->items[i] = *item;
        return 0;
    }
    if (result->count == result->capacity) {
        size_t capacity = result->capacity ? result->capacity * 2 : 32;
        if (capacity > 4096)
            return -1;
        expanded = realloc(result->items, capacity * sizeof(*expanded));
        if (!expanded)
            return -1;
        result->items = expanded;
        result->capacity = capacity;
    }
    result->items[result->count++] = *item;
    return 0;
}

static int apd_neighbor_parse(const char *text,
                              struct apd_neighbor_parse_result *result)
{
    struct apd_neighbor_item current = { 0 };
    char *copy = strdup(text ? text : "");
    char *line;
    char *saveptr = NULL;
    int have_block = 0;
    enum { APD_SCAN_CTX_NONE, APD_SCAN_CTX_RSN, APD_SCAN_CTX_WPA,
           APD_SCAN_CTX_HT, APD_SCAN_CTX_VHT, APD_SCAN_CTX_HE,
           APD_SCAN_CTX_EHT } context = APD_SCAN_CTX_NONE;

    memset(result, 0, sizeof(*result));
    if (!copy)
        return -1;
#define APD_NEIGHBOR_FINISH() do { \
    if (have_block) { \
        if (!current.bssid[0] || current.malformed) result->malformed_count++; \
        else if (apd_neighbor_store(result, &current) != 0) { free(copy); return -1; } \
    } \
} while (0)
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_survey_trim(line);
        int indented = line[0] == ' ' || line[0] == '\t';

        /* Only a column-0 "BSS <mac>" line opens a scan entry.  iw indents
         * information elements, and two of them ("BSS Load:", "BSS Color:")
         * share that prefix: treating them as headers ended the real entry
         * early -- losing every HT/VHT/HE/EHT line that follows, hence null
         * width and standard -- and counted each one as a malformed BSS,
         * which reported the whole scan as truncated. */
        if (!indented && !strncmp(value, "BSS ", 4)) {
            char address[32];
            const char *begin = value + 4;
            size_t length = strcspn(begin, " (");

            APD_NEIGHBOR_FINISH();
            memset(&current, 0, sizeof(current));
            have_block = 1;
            context = APD_SCAN_CTX_NONE;
            if (length >= sizeof(address)) {
                current.malformed = 1;
                continue;
            }
            memcpy(address, begin, length);
            address[length] = '\0';
            if (apd_neighbor_mac(address, current.bssid,
                                 &current.locally_administered) != 0)
                current.malformed = 1;
            continue;
        }
        if (!have_block)
            continue;
        if (!strncmp(value, "freq:", 5)) {
            long parsed;
            const char *end = NULL;
            const char *number = value + 5;
            while (*number == ' ' || *number == '\t') number++;
            if (apd_survey_parse_signed(number, 1, 100000, &parsed, &end) == 0 &&
                apd_neighbor_freq_tail_valid(end)) {
                current.frequency_mhz = (int)parsed;
                current.has_frequency = 1;
            } else current.malformed = 1;
        } else if (!strncmp(value, "signal:", 7)) {
            char *end = NULL;
            double parsed;
            const char *number = value + 7;
            while (*number == ' ' || *number == '\t') number++;
            errno = 0;
            parsed = strtod(number, &end);
            while (end && (*end == ' ' || *end == '\t')) end++;
            if (errno != ERANGE && end != number && end && !strcmp(end, "dBm") &&
                parsed >= -255.0 && parsed <= 100.0) {
                current.signal_dbm = parsed;
                current.has_signal = 1;
            } else current.malformed = 1;
        } else if (!strncmp(value, "last seen:", 10) && strstr(value, "ms ago")) {
            const char *number = value + 10;
            char *end = NULL;
            unsigned long long parsed;
            while (*number == ' ' || *number == '\t') number++;
            errno = 0;
            parsed = strtoull(number, &end, 10);
            while (end && (*end == ' ' || *end == '\t')) end++;
            if (errno != ERANGE && end != number && end && !strcmp(end, "ms ago")) {
                current.age_ms = (uint64_t)parsed;
                current.has_age = 1;
            } else current.malformed = 1;
        } else if (!strncmp(value, "SSID:", 5)) {
            const char *ssid = value + 5;
            while (*ssid == ' ' || *ssid == '\t') ssid++;
            current.has_ssid = 1;
            if (apd_neighbor_ssid_decode(ssid, current.ssid, &current.ssid_len) == 0) {
                current.ssid_valid = apd_neighbor_ssid_wire_safe(
                    current.ssid, current.ssid_len);
            } else current.malformed = 1;
        } else if (!strncmp(value, "capability:", 11)) {
            current.privacy = strstr(value, "Privacy") != NULL;
        } else if (!strcmp(value, "RSN:") || !strncmp(value, "RSN:", 4)) {
            current.rsn = 1; context = APD_SCAN_CTX_RSN;
        } else if (!strcmp(value, "WPA:") || !strncmp(value, "WPA:", 4)) {
            current.wpa = 1; context = APD_SCAN_CTX_WPA;
        } else if (!strncmp(value, "HT capabilities:", 16) ||
                   !strncmp(value, "HT operation:", 13)) {
            apd_neighbor_standard(&current, 1); context = APD_SCAN_CTX_HT;
        } else if (!strncmp(value, "VHT capabilities:", 17) ||
                   !strncmp(value, "VHT operation:", 14)) {
            apd_neighbor_standard(&current, 2); context = APD_SCAN_CTX_VHT;
        } else if (!strncmp(value, "HE capabilities:", 16) ||
                   !strncmp(value, "HE operation:", 13)) {
            apd_neighbor_standard(&current, 3); context = APD_SCAN_CTX_HE;
        } else if (!strncmp(value, "EHT capabilities:", 17) ||
                   !strncmp(value, "EHT operation:", 14)) {
            apd_neighbor_standard(&current, 4); context = APD_SCAN_CTX_EHT;
        } else if ((context == APD_SCAN_CTX_RSN || context == APD_SCAN_CTX_WPA) &&
                   strstr(value, "Authentication suites:")) {
            const char *auth = strchr(value, ':');
            auth = auth ? auth + 1 : "";
            current.auth_psk |= strstr(auth, "PSK") != NULL;
            current.auth_sae |= strstr(auth, "SAE") != NULL;
            current.auth_owe |= strstr(auth, "OWE") != NULL;
            current.auth_eap |= strstr(auth, "802.1X") != NULL ||
                                strstr(auth, "EAP") != NULL;
        } else if (context == APD_SCAN_CTX_HT &&
                   strstr(value, "secondary channel offset:")) {
            current.has_width = 1;
            current.width_mhz = strstr(value, "no secondary") ? 20 : 40;
            snprintf(current.width_mode, sizeof(current.width_mode), "%s",
                     current.width_mhz == 20 ? "20" : "40");
        } else if ((context == APD_SCAN_CTX_VHT || context == APD_SCAN_CTX_HE ||
                    context == APD_SCAN_CTX_EHT) && strstr(value, "channel width:")) {
            const char *units = strstr(value, "MHz");
            const char *start = units;
            long parsed;
            if (units) {
                while (start > value && isspace((unsigned char)start[-1])) start--;
                while (start > value && isdigit((unsigned char)start[-1])) start--;
                parsed = strtol(start, NULL, 10);
                if (parsed == 20 || parsed == 40 || parsed == 80 ||
                    parsed == 160 || parsed == 320) {
                    current.has_width = 1;
                    current.width_mhz = (int)parsed;
                    snprintf(current.width_mode, sizeof(current.width_mode), "%ld",
                             parsed);
                }
            }
        }
    }
    APD_NEIGHBOR_FINISH();
#undef APD_NEIGHBOR_FINISH
    free(copy);
    return 0;
}

static int apd_neighbor_compare(const void *left, const void *right)
{
    const struct apd_neighbor_item *a = left;
    const struct apd_neighbor_item *b = right;

    if (a->has_signal != b->has_signal)
        return b->has_signal - a->has_signal;
    if (a->has_signal && a->signal_dbm != b->signal_dbm)
        return a->signal_dbm < b->signal_dbm ? 1 : -1;
    return strcmp(a->bssid, b->bssid);
}

static void apd_neighbor_nullable_string(struct json_object *object,
                                         const char *name, const char *value)
{
    json_object_object_add(object, name, value ? json_object_new_string(value) :
                           json_object_new_null());
}

static const char *apd_neighbor_standard_name(int rank)
{
    switch (rank) {
    case 4: return "802.11be";
    case 3: return "802.11ax";
    case 2: return "802.11ac";
    case 1: return "802.11n";
    default: return NULL;
    }
}

static const char *apd_neighbor_security(const struct apd_neighbor_item *item)
{
    if (item->auth_owe) return "owe";
    if (item->auth_sae && item->auth_psk) return "wpa2-wpa3-personal";
    if (item->auth_sae) return "wpa3-personal";
    if (item->auth_eap) return "enterprise";
    if (item->auth_psk && item->rsn) return "wpa2-personal";
    if (item->auth_psk && item->wpa) return "wpa-personal";
    if (item->privacy && !item->rsn && !item->wpa) return "wep";
    if (!item->privacy && !item->rsn && !item->wpa) return "open";
    return "unknown";
}

static struct json_object *apd_neighbor_item_json(const struct apd_neighbor_item *item)
{
    static const char hex[] = "0123456789abcdef";
    struct json_object *object = json_object_new_object();
    struct json_object *missing = json_object_new_array();
    char ssid_hex[APD_NEIGHBOR_SSID_LEN * 2 + 1];
    int complete = !item->malformed && item->has_frequency && item->has_signal;
    int channel = item->has_frequency ? apd_neighbor_channel(item->frequency_mhz) : 0;

    for (size_t i = 0; i < item->ssid_len; i++) {
        ssid_hex[i * 2] = hex[item->ssid[i] >> 4];
        ssid_hex[i * 2 + 1] = hex[item->ssid[i] & 15];
    }
    ssid_hex[item->ssid_len * 2] = '\0';
    json_object_object_add(object, "bssid", json_object_new_string(item->bssid));
    json_object_object_add(object, "locally_administered",
                           json_object_new_boolean(item->locally_administered));
    if (item->has_ssid && item->ssid_valid)
        json_object_object_add(object, "ssid",
            json_object_new_string_len((const char *)item->ssid, item->ssid_len));
    else
        json_object_object_add(object, "ssid", json_object_new_null());
    json_object_object_add(object, "ssid_hex", json_object_new_string(ssid_hex));
    json_object_object_add(object, "ssid_hidden",
                           json_object_new_boolean(item->has_ssid && item->ssid_len == 0));
    if (item->has_signal)
        json_object_object_add(object, "rssi_dbm",
                               json_object_new_double(item->signal_dbm));
    else {
        json_object_object_add(object, "rssi_dbm", json_object_new_null());
        json_object_array_add(missing, json_object_new_string("rssi_dbm"));
    }
    if (item->has_age)
        json_object_object_add(object, "age_ms",
                               json_object_new_int64((int64_t)item->age_ms));
    else
        json_object_object_add(object, "age_ms", json_object_new_null());
    if (item->has_frequency)
        json_object_object_add(object, "frequency_mhz",
                               json_object_new_int(item->frequency_mhz));
    else {
        json_object_object_add(object, "frequency_mhz", json_object_new_null());
        json_object_array_add(missing, json_object_new_string("frequency_mhz"));
    }
    if (channel)
        json_object_object_add(object, "channel", json_object_new_int(channel));
    else
        json_object_object_add(object, "channel", json_object_new_null());
    if (item->has_width)
        json_object_object_add(object, "width_mhz", json_object_new_int(item->width_mhz));
    else
        json_object_object_add(object, "width_mhz", json_object_new_null());
    apd_neighbor_nullable_string(object, "width_mode",
                                 item->has_width ? item->width_mode : NULL);
    apd_neighbor_nullable_string(object, "standard",
                                 apd_neighbor_standard_name(item->standard_rank));
    json_object_object_add(object, "security",
                           json_object_new_string(apd_neighbor_security(item)));
    json_object_object_add(object, "vendor", json_object_new_null());
    json_object_object_add(object, "vendor_reason", json_object_new_string(
        item->locally_administered ? "locally_administered_bssid" :
                                     "controller_enrichment_pending"));
    json_object_object_add(object, "complete", json_object_new_boolean(complete));
    json_object_object_add(object, "missing_fields", missing);
    return object;
}

static size_t apd_neighbor_json_size(struct json_object *object)
{
    const char *text = json_object_to_json_string_ext(object,
                                                       JSON_C_TO_STRING_PLAIN);
    return text ? strlen(text) : SIZE_MAX;
}

static size_t apd_neighbor_update_frame_bytes(struct json_object *root)
{
    size_t previous = SIZE_MAX;
    size_t current = apd_neighbor_json_size(root);

    for (int i = 0; i < 8 && current != previous; i++) {
        previous = current;
        json_object_object_del(root, "frame_bytes");
        json_object_object_add(root, "frame_bytes",
            json_object_new_int64(current == SIZE_MAX ? INT64_MAX :
                                  (int64_t)current));
        current = apd_neighbor_json_size(root);
    }
    return current;
}

/* iw reports nl80211 failures on stderr as
 * "command failed: <strerror> (-<errno>)"; the parenthesised errno is the
 * stable machine token across locales and iw versions.  Returns 0 when no
 * errno token is present. */
static int apd_neighbor_scan_stderr_errno(const char *stderr_text)
{
    const char *cursor = stderr_text;

    while (cursor && (cursor = strstr(cursor, "(-")) != NULL) {
        char *end = NULL;
        long value = strtol(cursor + 2, &end, 10);

        if (end && *end == ')' && value > 0 && value < 4096)
            return (int)value;
        cursor += 2;
    }
    return 0;
}

/* The errno that iw prints is a Linux kernel ABI number, not a value from
 * the compiling host's <errno.h>.  On the OpenWrt target the two happen to
 * agree, but comparing the wire number against host constants silently
 * misclassifies every failure when the file is compiled anywhere the
 * numbering differs (macOS: EOPNOTSUPP is 102, ENETDOWN is 50).  Pin the
 * Linux values so the mapping is decided by the evidence iw produced. */
#define APD_NL80211_EPERM 1
#define APD_NL80211_ENODEV 19
#define APD_NL80211_EINVAL 22
#define APD_NL80211_EBUSY 16
#define APD_NL80211_EACCES 13
#define APD_NL80211_EOPNOTSUPP 95
#define APD_NL80211_ENETDOWN 100

/* Split the former catch-all "iw_neighbor_scan_failed_or_unsupported" into
 * diagnosable reasons.  "not supported" is only claimed on proven
 * EOPNOTSUPP/ENOTSUP evidence; everything unproven stays a command
 * failure with the exit status preserved so field triage does not have to
 * guess.  No sampling data is invented on any of these paths. */
static const char *apd_neighbor_scan_failure_reason(
    const struct apd_command_result *scan, char *out, size_t out_len)
{
    const char *stderr_text = scan && scan->stderr_text ? scan->stderr_text : "";
    int err = apd_neighbor_scan_stderr_errno(stderr_text);
    const char *reason = NULL;

    if (err == 0) {
        /* Textual fallback for iw builds that omit the errno suffix. */
        if (strstr(stderr_text, "not supported"))
            err = APD_NL80211_EOPNOTSUPP;
        else if (strstr(stderr_text, "busy"))
            err = APD_NL80211_EBUSY;
        else if (strstr(stderr_text, "Network is down"))
            err = APD_NL80211_ENETDOWN;
        else if (strstr(stderr_text, "not permitted") ||
                 strstr(stderr_text, "Permission denied"))
            err = APD_NL80211_EPERM;
        else if (strstr(stderr_text, "Invalid argument"))
            err = APD_NL80211_EINVAL;
        else if (strstr(stderr_text, "No such device"))
            err = APD_NL80211_ENODEV;
    }
    switch (err) {
    case APD_NL80211_EOPNOTSUPP:
        reason = "iw_neighbor_scan_not_supported";
        break;
    case APD_NL80211_EBUSY:
        reason = "iw_neighbor_scan_interface_busy";
        break;
    case APD_NL80211_ENETDOWN:
        reason = "iw_neighbor_scan_interface_down";
        break;
    case APD_NL80211_EPERM:
    case APD_NL80211_EACCES:
        reason = "iw_neighbor_scan_permission_denied";
        break;
    case APD_NL80211_EINVAL:
        reason = "iw_neighbor_scan_driver_rejected";
        break;
    case APD_NL80211_ENODEV:
        reason = "iw_neighbor_scan_interface_missing";
        break;
    default:
        break;
    }
    if (reason) {
        snprintf(out, out_len, "%s", reason);
        return out;
    }
    snprintf(out, out_len, "iw_neighbor_scan_command_failed_exit_%d",
             scan ? scan->exit_status : -1);
    return out;
}

/* Keep the raw evidence with the local result object and the AP log so a
 * failed scan can be triaged without re-running hardware commands.  Only
 * the bounded reason token travels to the AC as the job error code. */
static void apd_neighbor_scan_log_failure(const char *radio_id,
                                          const char *reason,
                                          const struct apd_command_result *scan)
{
    char excerpt[161];
    size_t j = 0;
    const char *stderr_text = scan && scan->stderr_text ? scan->stderr_text : "";

    for (size_t i = 0; stderr_text[i] && j + 1 < sizeof(excerpt); i++) {
        unsigned char c = (unsigned char)stderr_text[i];

        excerpt[j++] = (char)(c >= 0x20 && c < 0x7f ? c : ' ');
    }
    excerpt[j] = '\0';
    fprintf(stderr,
            "[dreamingwrt-apd] neighbor scan failed radio=%s reason=%s "
            "exit=%d stderr=\"%s\"%s\n",
            radio_id ? radio_id : "", reason ? reason : "",
            scan ? scan->exit_status : -1, excerpt,
            scan && scan->stderr_limited ? " (stderr truncated)" : "");
}

static void apd_neighbor_attach_failure_evidence(
    struct json_object *root, const struct apd_command_result *scan)
{
    struct json_object *evidence = json_object_new_object();
    char excerpt[161];
    size_t j = 0;
    const char *stderr_text = scan && scan->stderr_text ? scan->stderr_text : "";

    for (size_t i = 0; stderr_text[i] && j + 1 < sizeof(excerpt); i++) {
        unsigned char c = (unsigned char)stderr_text[i];

        excerpt[j++] = (char)(c >= 0x20 && c < 0x7f ? c : ' ');
    }
    excerpt[j] = '\0';
    json_object_object_add(evidence, "exit_status",
                           json_object_new_int(scan ? scan->exit_status : -1));
    json_object_object_add(evidence, "stderr_excerpt",
                           json_object_new_string(excerpt));
    json_object_object_add(evidence, "stderr_truncated",
        json_object_new_boolean(scan && (scan->stderr_limited ||
                                         strlen(stderr_text) >
                                             sizeof(excerpt) - 1)));
    json_object_object_add(root, "error_evidence", evidence);
}

static struct json_object *apd_neighbor_result_new(const char *radio_id,
                                                   const char *error_code)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(error_code == NULL));
    json_object_object_add(root, "source", json_object_new_string("iw_passive_scan"));
    json_object_object_add(root, "scanner_radio_id",
                           json_object_new_string(radio_id ? radio_id : ""));
    json_object_object_add(root, "complete", json_object_new_boolean(0));
    json_object_object_add(root, "truncated", json_object_new_boolean(0));
    json_object_object_add(root, "error_code",
                           json_object_new_string(error_code ? error_code : ""));
    json_object_object_add(root, "items", json_object_new_array());
    return root;
}

static int apd_neighbor_scan_collect(const char *path, const char *radio_id,
                                     struct json_object **out)
{
    struct apd_command_result inventory = { 0 };
    struct apd_command_result scan = { 0 };
    struct apd_neighbor_target target;
    struct apd_neighbor_parse_result parsed;
    struct json_object *root = NULL;
    struct json_object *items;
    char reason[APD_NEIGHBOR_REASON_LEN + 1] = { 0 };
    int64_t started_at = (int64_t)time(NULL);
    size_t returned = 0;
    int truncated = 0;
    int dumped = 0;
    int rc = -1;

    if (!out)
        return -1;
    *out = NULL;
    if (!path || !path[0]) {
        *out = apd_neighbor_result_new(radio_id, "iw_binary_unavailable");
        return -1;
    }
    {
        char *const argv[] = { (char *)path, "dev", NULL };
        if (apd_readonly_command(path, argv, &inventory) != 0) {
            *out = apd_neighbor_result_new(radio_id,
                inventory.timed_out ? "iw_dev_timeout" :
                inventory.output_limited ? "iw_dev_output_limited" :
                                           "iw_dev_failed");
            goto done;
        }
    }
    if (apd_neighbor_target_from_iw(inventory.text, radio_id, &target, reason) != 0) {
        *out = apd_neighbor_result_new(radio_id, reason);
        goto done;
    }
    {
        /* iw parses scan flags before the ssid|passive terminator; with
         * "passive" first it prints usage to stdout and exits 1. */
        char *const argv[] = {
            (char *)path, "dev", target.interface, "scan",
            "ap-force", "flush", "passive", NULL
        };
        if (apd_readonly_command_bounded(path, argv, APD_NEIGHBOR_SCAN_TIMEOUT_MS,
                                         APD_NEIGHBOR_SCAN_OUTPUT_LIMIT,
                                         &scan) != 0 && !scan.output_limited) {
            char failure[APD_NEIGHBOR_REASON_LEN + 1];
            const char *code = scan.timed_out ? "iw_neighbor_scan_timeout" :
                apd_neighbor_scan_failure_reason(&scan, failure,
                                                 sizeof(failure));

            /* EBUSY means the driver refused to leave its operating channel --
             * a DFS or wide-channel AP cannot go off-channel while beaconing,
             * so the trigger will keep failing for as long as that radio is up.
             * The driver still maintains a scan table fed by beacons received
             * on the operating channel, and `scan dump` returns it without
             * touching the radio.  Those entries are measured, so read them
             * instead of reporting the band as having no neighbours at all.
             * Only EBUSY falls back: every other failure stays a failure. */
            if (strcmp(code, "iw_neighbor_scan_interface_busy") != 0) {
                *out = apd_neighbor_result_new(radio_id, code);
                apd_neighbor_attach_failure_evidence(*out, &scan);
                apd_neighbor_scan_log_failure(radio_id, code, &scan);
                goto done;
            }
            apd_neighbor_scan_log_failure(radio_id, code, &scan);
            apd_command_result_free(&scan);
            memset(&scan, 0, sizeof(scan));
            {
                char *const dump_argv[] = {
                    (char *)path, "dev", target.interface, "scan", "dump", NULL
                };
                if (apd_readonly_command_bounded(path, dump_argv,
                                                 APD_NEIGHBOR_SCAN_TIMEOUT_MS,
                                                 APD_NEIGHBOR_SCAN_OUTPUT_LIMIT,
                                                 &scan) != 0 &&
                    !scan.output_limited) {
                    *out = apd_neighbor_result_new(radio_id, code);
                    apd_neighbor_attach_failure_evidence(*out, &scan);
                    goto done;
                }
                dumped = 1;
            }
        }
    }
    if (apd_neighbor_parse(scan.text, &parsed) != 0) {
        *out = apd_neighbor_result_new(radio_id, "iw_neighbor_scan_parse_failed");
        goto done;
    }
    qsort(parsed.items, parsed.count, sizeof(*parsed.items), apd_neighbor_compare);
    root = apd_neighbor_result_new(radio_id, NULL);
    items = NULL;
    json_object_object_get_ex(root, "items", &items);
    if (dumped) {
        /* Name the producer honestly: these rows come from the driver's cached
         * scan table, not from a scan this call triggered. */
        json_object_object_del(root, "source");
        json_object_object_add(root, "source",
                               json_object_new_string("iw_scan_dump_cache"));
    }
    json_object_object_add(root, "scanner_wiphy_name",
                           json_object_new_string(target.wiphy_name));
    json_object_object_add(root, "scanner_interface",
                           json_object_new_string(target.interface));
    json_object_object_add(root, "scanner_ifindex",
                           json_object_new_int64(target.ifindex));
    json_object_object_add(root, "scanner_frequency_mhz",
                           json_object_new_int(target.frequency_mhz));
    json_object_object_add(root, "sample_started_at",
                           json_object_new_int64(started_at));
    json_object_object_add(root, "sample_finished_at",
                           json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(root, "discovered_count",
                           json_object_new_int64((int64_t)parsed.count));
    json_object_object_add(root, "malformed_count",
                           json_object_new_int64((int64_t)parsed.malformed_count));
    for (size_t i = 0; i < parsed.count && returned < APD_NEIGHBOR_SCAN_ITEM_LIMIT;
         i++) {
        struct json_object *item = apd_neighbor_item_json(&parsed.items[i]);

        json_object_array_add(items, item);
        if (apd_neighbor_json_size(root) > APD_NEIGHBOR_SCAN_FRAME_LIMIT) {
            json_object_array_del_idx(items, returned, 1);
            truncated = 1;
            break;
        }
        returned++;
    }
    if (returned < parsed.count || scan.output_limited)
        truncated = 1;
    if (parsed.malformed_count)
        snprintf(reason, sizeof(reason), "%s", "scan_output_parse_partial");
    else if (scan.output_limited)
        snprintf(reason, sizeof(reason), "%s", "scan_output_limited");
    else if (truncated)
        snprintf(reason, sizeof(reason), "%s", "scan_result_limited");
    json_object_object_del(root, "complete");
    json_object_object_add(root, "complete",
        json_object_new_boolean(!truncated && parsed.malformed_count == 0));
    json_object_object_del(root, "truncated");
    json_object_object_add(root, "truncated", json_object_new_boolean(truncated));
    json_object_object_del(root, "error_code");
    json_object_object_add(root, "error_code",
                           json_object_new_string(reason[0] ? reason : ""));
    json_object_object_add(root, "returned_count",
                           json_object_new_int64((int64_t)returned));
    json_object_object_add(root, "frame_bytes",
                           json_object_new_int64(0));
    while (apd_neighbor_update_frame_bytes(root) > APD_NEIGHBOR_SCAN_FRAME_LIMIT &&
           returned > 0) {
        json_object_array_del_idx(items, returned - 1, 1);
        returned--;
        truncated = 1;
        if (!parsed.malformed_count && !scan.output_limited)
            snprintf(reason, sizeof(reason), "%s", "scan_result_limited");
        json_object_object_del(root, "complete");
        json_object_object_add(root, "complete", json_object_new_boolean(0));
        json_object_object_del(root, "truncated");
        json_object_object_add(root, "truncated", json_object_new_boolean(1));
        json_object_object_del(root, "error_code");
        json_object_object_add(root, "error_code", json_object_new_string(reason));
        json_object_object_del(root, "returned_count");
        json_object_object_add(root, "returned_count",
                               json_object_new_int64((int64_t)returned));
    }
    apd_neighbor_update_frame_bytes(root);
    free(parsed.items);
    *out = root;
    rc = 0;
done:
    apd_command_result_free(&inventory);
    apd_command_result_free(&scan);
    return rc;
}

#if !defined(APD_NEIGHBOR_SCAN_STANDALONE_TEST) || \
    defined(APD_SURVEY_STANDALONE_TEST)
/* QCA/Atheros vendor drivers answer `iw ... survey dump` with an empty body and
 * `iw ... station dump` with zero stations even while clients are associated;
 * `wlanconfig`/`apstats` carry the same data there. These collectors are the
 * fallback path only: the caller tries the nl80211 tool first and drops here
 * when it yielded no data, so a driver where `iw` works keeps using `iw`.
 * The decision is driven by "did we get data", never by "does the binary
 * exist", because on 31.31 `iw` is present and `iw dev` works while its
 * station and survey subcommands return nothing. */
#define APD_VENDOR_STATION_LIMIT 128U

struct apd_vendor_station {
    char mac[18];
    char mode[40];
    int aid;
    int channel;
    int rssi;
    int min_rssi;
    int max_rssi;
    int idle_ms;
    unsigned int tx_rate_kbps;
    unsigned int rx_rate_kbps;
    int tx_nss;
    int rx_nss;
    int has_rssi;
    int has_min_rssi;
    int has_max_rssi;
    int has_tx_rate;
    int has_rx_rate;
    int has_tx_nss;
    int has_rx_nss;
    int has_channel;
    int has_idle;
};

struct apd_vendor_station_set {
    struct apd_vendor_station items[APD_VENDOR_STATION_LIMIT];
    size_t count;
    int truncated;
    char reason[APD_SURVEY_REASON_LEN + 1];
};

static const char *apd_find_wlanconfig(void)
{
    static const char *const paths[] = {
        "/usr/sbin/wlanconfig", "/usr/bin/wlanconfig", "/sbin/wlanconfig", NULL
    };
    size_t i;

    if (APD_WLANCONFIG_PATH[0] && access(APD_WLANCONFIG_PATH, X_OK) == 0)
        return APD_WLANCONFIG_PATH;
    for (i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return NULL;
}

/* `wlanconfig` prints rates as `433M`, `292M`, occasionally `1.5G` or a bare
 * `54`. Normalise to kbps so the JSON contract stays a single integer unit
 * instead of leaking a vendor-formatted string to the frontend. */
static int apd_vendor_parse_rate_kbps(const char *token, unsigned int *out)
{
    double value = 0.0;
    char *end = NULL;

    if (!token || !token[0] || !out)
        return -1;
    errno = 0;
    value = strtod(token, &end);
    if (errno != 0 || end == token || value < 0.0 || value > 1.0e7)
        return -1;
    if (end && (*end == 'M' || *end == 'm'))
        value *= 1000.0;
    else if (end && (*end == 'G' || *end == 'g'))
        value *= 1000000.0;
    else if (end && (*end == 'K' || *end == 'k'))
        ;
    else if (end && *end && *end != ' ' && *end != '\t')
        return -1;
    else
        value *= 1000.0;
    if (value <= 0.0 || value > 1.0e9)
        return -1;
    *out = (unsigned int)(value + 0.5);
    return 0;
}

static int apd_vendor_parse_int_token(const char *token, long minimum,
                                      long maximum, int *out)
{
    long parsed = 0;
    char *end = NULL;

    if (!token || !token[0] || !out)
        return -1;
    errno = 0;
    parsed = strtol(token, &end, 10);
    if (errno != 0 || end == token || parsed < minimum || parsed > maximum)
        return -1;
    if (end && *end && *end != ' ' && *end != '\t')
        return -1;
    *out = (int)parsed;
    return 0;
}

static int apd_vendor_valid_mac(const char *value)
{
    size_t i;

    if (!value)
        return 0;
    for (i = 0; i < 17; i++) {
        if ((i % 3) == 2) {
            if (value[i] != ':')
                return 0;
            continue;
        }
        if (!isxdigit((unsigned char)value[i]))
            return 0;
    }
    return value[17] == '\0';
}

/* Column layout of `wlanconfig <if> list`:
 * ADDR AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE ... MODE RXNSS TXNSS PSMODE
 * Fields after IDLE vary between driver builds, so MODE is located by content
 * (the token starts with IEEE80211_MODE_) and the two NSS values are read from
 * the positions immediately following it. They are not the trailing tokens:
 * PSMODE follows TXNSS on real hardware. */
static void apd_vendor_parse_station_line(const char *line,
                                          struct apd_vendor_station_set *set)
{
    struct apd_vendor_station station;
    char buffer[512];
    char *tokens[48];
    size_t token_count = 0;
    char *cursor = NULL;
    char *saved = NULL;
    size_t mode_index = 0;
    int have_mode = 0;

    if (!line || !set || set->count >= APD_VENDOR_STATION_LIMIT)
        return;
    if (snprintf(buffer, sizeof(buffer), "%s", line) >= (int)sizeof(buffer))
        return;
    cursor = strtok_r(buffer, " \t", &saved);
    while (cursor && token_count < (sizeof(tokens) / sizeof(tokens[0]))) {
        tokens[token_count++] = cursor;
        cursor = strtok_r(NULL, " \t", &saved);
    }
    if (token_count < 6 || !apd_vendor_valid_mac(tokens[0]))
        return;

    memset(&station, 0, sizeof(station));
    snprintf(station.mac, sizeof(station.mac), "%s", tokens[0]);
    if (apd_vendor_parse_int_token(tokens[1], 0, 4096, &station.aid) != 0)
        station.aid = 0;
    if (apd_vendor_parse_int_token(tokens[2], 1, 200, &station.channel) == 0)
        station.has_channel = 1;
    if (apd_vendor_parse_rate_kbps(tokens[3], &station.tx_rate_kbps) == 0)
        station.has_tx_rate = 1;
    if (apd_vendor_parse_rate_kbps(tokens[4], &station.rx_rate_kbps) == 0)
        station.has_rx_rate = 1;
    if (apd_vendor_parse_int_token(tokens[5], -127, 127, &station.rssi) == 0)
        station.has_rssi = 1;
    if (token_count > 6 &&
        apd_vendor_parse_int_token(tokens[6], -127, 127, &station.min_rssi) == 0)
        station.has_min_rssi = 1;
    if (token_count > 7 &&
        apd_vendor_parse_int_token(tokens[7], -127, 127, &station.max_rssi) == 0)
        station.has_max_rssi = 1;
    if (token_count > 8 &&
        apd_vendor_parse_int_token(tokens[8], 0, 1000000, &station.idle_ms) == 0)
        station.has_idle = 1;

    for (size_t i = 9; i < token_count; i++) {
        if (!strncmp(tokens[i], "IEEE80211_MODE_", 15)) {
            snprintf(station.mode, sizeof(station.mode), "%s", tokens[i]);
            mode_index = i;
            have_mode = 1;
            break;
        }
    }
    /*
     * RXNSS/TXNSS are the two columns immediately after MODE.
     *
     * They are located relative to MODE rather than from the end of the line,
     * because MODE is not the last field on real hardware: ath11 emits
     * `MODE RXNSS TXNSS PSMODE`, so the final two tokens are TXNSS and PSMODE.
     * PSMODE is 0 for a station that is not power-saving, 0 falls outside the
     * 1..8 range a spatial-stream count may take, and the paired check below
     * then discarded both values together -- which is why MIMO read as "--" on
     * a driver that was reporting it correctly all along.
     *
     * Locating by offset from MODE is also what this function's own header
     * comment promises: fields after IDLE vary between driver builds, so they
     * are found by content and not by counting from either end.
     */
    if (have_mode && token_count > mode_index + 2) {
        int rx_nss = 0;
        int tx_nss = 0;

        if (apd_vendor_parse_int_token(tokens[mode_index + 1], 1, 8,
                                      &rx_nss) == 0 &&
            apd_vendor_parse_int_token(tokens[mode_index + 2], 1, 8,
                                      &tx_nss) == 0) {
            station.rx_nss = rx_nss;
            station.tx_nss = tx_nss;
            station.has_rx_nss = 1;
            station.has_tx_nss = 1;
        }
    }
    set->items[set->count++] = station;
}

static int apd_vendor_station_collect(const char *path, const char *interface,
                                      struct apd_vendor_station_set *set)
{
    struct apd_command_result result = { 0 };
    char *line = NULL;
    char *saved = NULL;

    if (!set)
        return -1;
    memset(set, 0, sizeof(*set));
    if (!path || !path[0]) {
        snprintf(set->reason, sizeof(set->reason), "%s",
                 "wlanconfig_binary_unavailable");
        return -1;
    }
    if (!interface || !interface[0]) {
        snprintf(set->reason, sizeof(set->reason), "%s",
                 "wlanconfig_interface_unavailable");
        return -1;
    }
    if (!apd_survey_safe_interface_name(interface)) {
        snprintf(set->reason, sizeof(set->reason), "%s",
                 "wlanconfig_interface_invalid");
        return -1;
    }
    {
        char *const argv[] = {
            (char *)path, (char *)interface, "list", NULL
        };

        if (apd_readonly_command(path, argv, &result) != 0) {
            snprintf(set->reason, sizeof(set->reason), "%s",
                     result.timed_out ? "wlanconfig_timeout" :
                                        "wlanconfig_failed_or_unsupported");
            apd_command_result_free(&result);
            return -1;
        }
    }
    if (!result.text || !result.length) {
        snprintf(set->reason, sizeof(set->reason), "%s",
                 "wlanconfig_no_output");
        apd_command_result_free(&result);
        return -1;
    }
    if (result.output_limited)
        set->truncated = 1;
    line = strtok_r(result.text, "\n", &saved);
    while (line) {
        char *trimmed = apd_survey_trim(line);

        if (trimmed && trimmed[0] && strncmp(trimmed, "ADDR", 4) != 0) {
            if (set->count >= APD_VENDOR_STATION_LIMIT) {
                set->truncated = 1;
                break;
            }
            apd_vendor_parse_station_line(trimmed, set);
        }
        line = strtok_r(NULL, "\n", &saved);
    }
    apd_command_result_free(&result);
    if (!set->count) {
        snprintf(set->reason, sizeof(set->reason), "%s",
                 "wlanconfig_no_stations");
        return -1;
    }
    return 0;
}

/* Airtime counters from the QCA `apstats` tool.
 *
 * Same shape as the station fallback above and for the same reason: on these
 * drivers `iw ... survey dump` returns an empty body, so channel airtime has to
 * come from the vendor tool. Radio level (`apstats -r -i wifiN`) is the level
 * that matches one wiphy; AP level would sum every radio on the box.
 *
 * Two properties of the real output drive the parsing:
 *   - Metrics the firmware refuses to compute print the literal `<DISABLED>`
 *     (`Channel Utilization`, `Throughput`, `PER over configured period`).
 *     Those must surface as unavailable, never as 0, because a 0 reads as a
 *     measurement. `Total PER (%) = 0` on the same AP is a real measured zero
 *     and is reported as 0.
 *   - Labels carry their unit inline (`Average Tx Rate (kbps)`), and the
 *     per-AC blocks repeat indented sub-keys under a parent label, so matching
 *     is done on the full label up to `=` rather than a prefix. */
#define APD_AIRTIME_LABEL_LEN 64U

struct apd_airtime_stats {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_failures;
    uint64_t tx_dropped;
    uint64_t retries;
    uint64_t rx_phy_errors;
    uint64_t rx_crc_errors;
    int total_per_pct;
    int self_bss_util_pct;
    int obss_util_pct;
    int noise_floor_dbm;
    int has_tx_packets;
    int has_tx_bytes;
    int has_rx_packets;
    int has_rx_bytes;
    int has_tx_failures;
    int has_tx_dropped;
    int has_retries;
    int has_rx_phy_errors;
    int has_rx_crc_errors;
    int has_total_per;
    int has_self_bss_util;
    int has_obss_util;
    int has_noise_floor;
    /* Distinguishes "the firmware disabled this counter" from "this build of
     * apstats never printed the label", so the reason can say which. */
    int channel_util_disabled;
    int throughput_disabled;
    char reason[APD_SURVEY_REASON_LEN + 1];
};

static const char *apd_find_apstats(void)
{
    static const char *const paths[] = {
        "/usr/sbin/apstats", "/usr/bin/apstats", "/sbin/apstats", NULL
    };
    size_t i;

    if (APD_APSTATS_PATH[0] && access(APD_APSTATS_PATH, X_OK) == 0)
        return APD_APSTATS_PATH;
    for (i = 0; paths[i]; i++) {
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    }
    return NULL;
}

/* Splits `Label (unit)   = value` into label and value. Returns -1 when the
 * line carries no `=`, which covers the banners and per-AC section headers. */
static int apd_airtime_split_line(char *line, char **label_out, char **value_out)
{
    char *separator;
    char *label;
    char *value;

    if (!line || !label_out || !value_out)
        return -1;
    separator = strchr(line, '=');
    if (!separator)
        return -1;
    *separator = '\0';
    label = apd_survey_trim(line);
    value = apd_survey_trim(separator + 1);
    if (!label || !label[0] || !value || !value[0])
        return -1;
    *label_out = label;
    *value_out = value;
    return 0;
}

static int apd_airtime_parse_u64(const char *value, uint64_t *out)
{
    unsigned long long parsed;
    char *end = NULL;

    if (!value || !value[0] || !out)
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value)
        return -1;
    while (end && (*end == ' ' || *end == '\t'))
        end++;
    if (end && *end)
        return -1;
    *out = (uint64_t)parsed;
    return 0;
}

static int apd_airtime_parse_int(const char *value, long minimum, long maximum,
                                 int *out)
{
    long parsed;
    char *end = NULL;

    if (!value || !value[0] || !out)
        return -1;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || parsed < minimum || parsed > maximum)
        return -1;
    while (end && (*end == ' ' || *end == '\t'))
        end++;
    if (end && *end)
        return -1;
    *out = (int)parsed;
    return 0;
}

/* `<DISABLED>` is the firmware saying it does not compute the counter. */
static int apd_airtime_value_disabled(const char *value)
{
    return value && !strcmp(value, "<DISABLED>");
}

static void apd_airtime_apply_u64(const char *value, uint64_t *slot, int *has)
{
    uint64_t parsed = 0;

    if (apd_airtime_parse_u64(value, &parsed) != 0)
        return;
    *slot = parsed;
    *has = 1;
}

static void apd_airtime_apply_int(const char *value, long minimum, long maximum,
                                  int *slot, int *has)
{
    int parsed = 0;

    if (apd_airtime_parse_int(value, minimum, maximum, &parsed) != 0)
        return;
    *slot = parsed;
    *has = 1;
}

static void apd_airtime_parse_line(char *line, struct apd_airtime_stats *stats)
{
    char *label = NULL;
    char *value = NULL;

    if (!stats || apd_airtime_split_line(line, &label, &value) != 0)
        return;
    /* Indented per-AC rows ("Best effort", "Voice", ...) repeat under a parent
     * label such as "Tx Data Packets per AC:". Exact full-label matching below
     * already makes a sub-row name match nothing, so this guard is redundant
     * today -- it is kept because it is what stops a future prefix or
     * substring match from silently letting an AC row overwrite a radio total.
     * The caller strips leading space, so the rows are rejected by name. */
    if (!strcmp(label, "Best effort") || !strcmp(label, "Background") ||
        !strcmp(label, "Video") || !strcmp(label, "Voice"))
        return;

    if (!strcmp(label, "Channel Utilization (0-255)") ||
        !strcmp(label, "Resource Utilization (0-255)")) {
        if (apd_airtime_value_disabled(value))
            stats->channel_util_disabled = 1;
        return;
    }
    if (!strcmp(label, "Throughput (kbps)")) {
        if (apd_airtime_value_disabled(value))
            stats->throughput_disabled = 1;
        return;
    }
    if (!strcmp(label, "Tx Data Packets"))
        apd_airtime_apply_u64(value, &stats->tx_packets, &stats->has_tx_packets);
    else if (!strcmp(label, "Tx Data Bytes"))
        apd_airtime_apply_u64(value, &stats->tx_bytes, &stats->has_tx_bytes);
    else if (!strcmp(label, "Rx Data Packets"))
        apd_airtime_apply_u64(value, &stats->rx_packets, &stats->has_rx_packets);
    else if (!strcmp(label, "Rx Data Bytes"))
        apd_airtime_apply_u64(value, &stats->rx_bytes, &stats->has_rx_bytes);
    else if (!strcmp(label, "Tx failures"))
        apd_airtime_apply_u64(value, &stats->tx_failures,
                              &stats->has_tx_failures);
    else if (!strcmp(label, "Tx Dropped"))
        apd_airtime_apply_u64(value, &stats->tx_dropped,
                              &stats->has_tx_dropped);
    else if (!strcmp(label, "Retries"))
        apd_airtime_apply_u64(value, &stats->retries, &stats->has_retries);
    else if (!strcmp(label, "Rx PHY errors"))
        apd_airtime_apply_u64(value, &stats->rx_phy_errors,
                              &stats->has_rx_phy_errors);
    else if (!strcmp(label, "Rx CRC errors"))
        apd_airtime_apply_u64(value, &stats->rx_crc_errors,
                              &stats->has_rx_crc_errors);
    else if (!strcmp(label, "Total PER (%)"))
        apd_airtime_apply_int(value, 0, 100, &stats->total_per_pct,
                              &stats->has_total_per);
    else if (!strcmp(label, "Self BSS chan util"))
        apd_airtime_apply_int(value, 0, 100, &stats->self_bss_util_pct,
                              &stats->has_self_bss_util);
    else if (!strcmp(label, "OBSS chan util"))
        apd_airtime_apply_int(value, 0, 100, &stats->obss_util_pct,
                              &stats->has_obss_util);
    else if (!strcmp(label,
                     "lithium_cycle_cnt: Chan NF (BDF averaged NF_dBm)"))
        apd_airtime_apply_int(value, -127, 0, &stats->noise_floor_dbm,
                              &stats->has_noise_floor);
}

/* Resolves the radio netdev (`wifiN`) that owns a wiphy index. `apstats -r`
 * wants that name, not a VAP: sysfs marks it with ARPHRD type 801 while VAPs
 * are plain type 1, so it is identified by content rather than by an assumed
 * `wifi%u` spelling. */
#define APD_ARPHRD_IEEE80211_RADIO 801

/*
 * Distinguishes the ways this lookup can come up empty. The caller turns these
 * into reason codes, and the difference matters: a wiphy that owns netdevs but
 * none of ARPHRD type 801 is an MLD pseudo-PHY, which aggregates the real
 * radios and has no radio netdev of its own. That is normal hardware topology,
 * not a failed probe, and reporting it as "unresolved" reads as a defect.
 *
 * Observed on 31.31 (Xiaomi BE10000 / QWRT): phy_index 0 owns `MLD1` and
 * `mld-wifi0`, both type 1, while phy_index 1..3 each own exactly one type-801
 * netdev (`wifi0`/`wifi1`/`wifi2`).
 */
enum apd_radio_netdev_status {
    APD_RADIO_NETDEV_OK = 0,
    APD_RADIO_NETDEV_SYSFS_UNREADABLE,
    APD_RADIO_NETDEV_NO_NETDEV_FOR_WIPHY,
    APD_RADIO_NETDEV_AGGREGATE_ONLY,
    APD_RADIO_NETDEV_AMBIGUOUS,
    APD_RADIO_NETDEV_LOGICAL_NOT_FOUND,
};

static const char *apd_radio_netdev_reason(enum apd_radio_netdev_status status)
{
    switch (status) {
    case APD_RADIO_NETDEV_OK:
        return NULL;
    case APD_RADIO_NETDEV_SYSFS_UNREADABLE:
        return "apstats_sysfs_net_class_unreadable";
    case APD_RADIO_NETDEV_NO_NETDEV_FOR_WIPHY:
        return "apstats_no_netdev_for_wiphy";
    case APD_RADIO_NETDEV_AGGREGATE_ONLY:
        return "mld_pseudo_phy_has_no_radio_netdev";
    case APD_RADIO_NETDEV_AMBIGUOUS:
        return "apstats_multiple_radio_netdevs_for_wiphy";
    case APD_RADIO_NETDEV_LOGICAL_NOT_FOUND:
        return "apstats_logical_radio_netdev_missing";
    }
    return "apstats_radio_netdev_unresolved";
}

static enum apd_radio_netdev_status apd_airtime_radio_netdev(
        unsigned int wiphy_index, unsigned int radio_index,
        int has_radio_index, char *out, size_t out_size)
{
    DIR *directory = opendir(APD_NET_CLASS_PATH);
    struct dirent *entry;
    char expected[IFNAMSIZ] = { 0 };
    int found = 0;
    int owned_netdevs = 0;
    int radio_netdevs = 0;

    if (!directory)
        return APD_RADIO_NETDEV_SYSFS_UNREADABLE;
    if (!out || out_size == 0) {
        closedir(directory);
        return APD_RADIO_NETDEV_SYSFS_UNREADABLE;
    }
    if (has_radio_index &&
        snprintf(expected, sizeof(expected), "wifi%u", radio_index) >=
            (int)sizeof(expected)) {
        closedir(directory);
        return APD_RADIO_NETDEV_LOGICAL_NOT_FOUND;
    }
    while ((entry = readdir(directory)) != NULL) {
        char path[PATH_MAX];
        unsigned int observed = 0;
        unsigned int type = 0;
        size_t name_len = strlen(entry->d_name);

        if (entry->d_name[0] == '.' || name_len >= out_size)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s/phy80211/index",
                     APD_NET_CLASS_PATH, entry->d_name) >= (int)sizeof(path) ||
            apd_neighbor_read_uint_file(path, &observed) != 0 ||
            observed != wiphy_index)
            continue;
        /*
         * Counted before the type filter so the caller can tell "this wiphy has
         * no interfaces at all" from "it has interfaces, just no radio netdev".
         */
        owned_netdevs++;
        if (snprintf(path, sizeof(path), "%s/%s/type", APD_NET_CLASS_PATH,
                     entry->d_name) >= (int)sizeof(path) ||
            apd_neighbor_read_uint_file(path, &type) != 0 ||
            type != APD_ARPHRD_IEEE80211_RADIO)
            continue;
        radio_netdevs++;
        if (has_radio_index && strcmp(entry->d_name, expected))
            continue;
        if (found) {
            found = -1;
            break;
        }
        memcpy(out, entry->d_name, name_len + 1);
        found = 1;
    }
    closedir(directory);
    if (found == 1)
        return APD_RADIO_NETDEV_OK;
    if (found == -1)
        return APD_RADIO_NETDEV_AMBIGUOUS;
    if (has_radio_index && radio_netdevs > 0)
        return APD_RADIO_NETDEV_LOGICAL_NOT_FOUND;
    if (owned_netdevs > 0)
        return APD_RADIO_NETDEV_AGGREGATE_ONLY;
    return APD_RADIO_NETDEV_NO_NETDEV_FOR_WIPHY;
}

static int apd_airtime_collect(const char *path, const char *radio_netdev,
                               struct apd_airtime_stats *stats)
{
    struct apd_command_result result = { 0 };
    char *line = NULL;
    char *saved = NULL;
    int parsed_any;

    if (!stats)
        return -1;
    memset(stats, 0, sizeof(*stats));
    if (!path || !path[0]) {
        snprintf(stats->reason, sizeof(stats->reason), "%s",
                 "apstats_binary_unavailable");
        return -1;
    }
    if (!radio_netdev || !radio_netdev[0]) {
        snprintf(stats->reason, sizeof(stats->reason), "%s",
                 "apstats_radio_netdev_unavailable");
        return -1;
    }
    if (!apd_survey_safe_interface_name(radio_netdev)) {
        snprintf(stats->reason, sizeof(stats->reason), "%s",
                 "apstats_radio_netdev_invalid");
        return -1;
    }
    {
        char *const argv[] = {
            (char *)path, "-r", "-i", (char *)radio_netdev, NULL
        };

        if (apd_readonly_command(path, argv, &result) != 0) {
            snprintf(stats->reason, sizeof(stats->reason), "%s",
                     result.timed_out ? "apstats_timeout" :
                                        "apstats_failed_or_unsupported");
            apd_command_result_free(&result);
            return -1;
        }
    }
    if (!result.text || !result.length) {
        snprintf(stats->reason, sizeof(stats->reason), "%s",
                 "apstats_no_output");
        apd_command_result_free(&result);
        return -1;
    }
    line = strtok_r(result.text, "\n", &saved);
    while (line) {
        char *trimmed = apd_survey_trim(line);

        if (trimmed && trimmed[0])
            apd_airtime_parse_line(trimmed, stats);
        line = strtok_r(NULL, "\n", &saved);
    }
    apd_command_result_free(&result);
    /* The verdict is whether any counter was actually read, not whether the
     * binary ran: a truncated or unexpected build yields zero fields and must
     * report unavailable instead of a page of zeros. */
    parsed_any = stats->has_tx_packets || stats->has_rx_packets ||
                 stats->has_tx_failures || stats->has_retries ||
                 stats->has_total_per || stats->has_rx_phy_errors;
    if (!parsed_any) {
        snprintf(stats->reason, sizeof(stats->reason), "%s",
                 "apstats_no_counters_parsed");
        return -1;
    }
    return 0;
}

/* Cumulative TX retry counters for one radio, summed over its VAPs.
 *
 * The radio level (`apstats -r -i wifiN`) prints `Tx Data Packets` and
 * `Tx failures` but no `Retries` at all -- verified on 31.31 (Xiaomi BE10000 /
 * QWRT). `Retries` only exists per VAP (`apstats -v -i athN`), so the only
 * honest cumulative retry numerator for a radio is the sum over every VAP that
 * belongs to its wiphy. Both counters are monotonic since interface bring-up,
 * which is what makes them differenceable into history buckets.
 *
 * A partial sum is worse than no answer: it would drop the traffic of whichever
 * VAP failed to report and understate the retry rate, so any VAP that cannot be
 * read makes the whole radio unsupported.
 *
 * `tx_failures` is deliberately not accepted as a substitute. A failure is a
 * frame that exhausted its retries; a retry is an extra attempt. Substituting
 * one for the other would fabricate a curve, which the handoff prohibits.
 */
#define APD_TX_RETRY_MAX_VAPS 32U

struct apd_tx_retry_stats {
    uint64_t tx_total;
    uint64_t tx_retries;
    unsigned int vap_count;
    int available;
    char reason[APD_SURVEY_REASON_LEN + 1];
};

static int apd_hostapd_uid_trusted(uid_t uid);

/* Maps a QSDK VAP to its owning wifiN using the generated hostapd config.
 * This is stronger evidence than interface spelling: ath0/ath01/... are not
 * numerically aligned with their radios, while ctrl_interface is. */
static int apd_tx_retry_vap_radio_index(const char *vap,
                                        unsigned int *radio_index)
{
    static const char ctrl_prefix[] = "ctrl_interface=";
    char path[PATH_MAX];
    char buffer[4096];
    struct stat st;
    ssize_t length;
    char *line;
    char *saveptr = NULL;
    int fd;

    if (!radio_index || !apd_survey_safe_interface_name(vap) ||
        snprintf(path, sizeof(path), "%s%s.conf", APD_HOSTAPD_CONF_PREFIX,
                 vap) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        !apd_hostapd_uid_trusted(st.st_uid) ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(fd);
        return -1;
    }
    do {
        length = read(fd, buffer, sizeof(buffer) - 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    if (length <= 0 || length >= (ssize_t)sizeof(buffer) - 1)
        return -1;
    buffer[length] = '\0';
    for (line = strtok_r(buffer, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        const char *value;
        const char *name;
        char directory[PATH_MAX];
        char *end = NULL;
        unsigned long parsed;
        size_t value_len;

        while (*line == ' ' || *line == '\t')
            line++;
        if (strncmp(line, ctrl_prefix, sizeof(ctrl_prefix) - 1))
            continue;
        value = line + sizeof(ctrl_prefix) - 1;
        value_len = strcspn(value, " \t\r");
        if (!value_len || value_len >= sizeof(directory))
            return -1;
        memcpy(directory, value, value_len);
        directory[value_len] = '\0';
        if (lstat(directory, &st) != 0 || !S_ISDIR(st.st_mode) ||
            !apd_hostapd_uid_trusted(st.st_uid) ||
            (st.st_mode & (S_IWGRP | S_IWOTH)))
            return -1;
        name = strrchr(directory, '/');
        name = name ? name + 1 : directory;
        if (strncmp(name, "hostapd-wifi", 12) || !name[12] ||
            (name[12] == '0' && name[13]))
            return -1;
        errno = 0;
        parsed = strtoul(name + 12, &end, 10);
        if (errno == ERANGE || !end || end == name + 12 || *end ||
            parsed > UINT_MAX)
            return -1;
        *radio_index = (unsigned int)parsed;
        return 0;
    }
    return -1;
}

static int apd_tx_retry_aggregate_interface(const char *interface)
{
    return interface &&
           (!strncmp(interface, "MLD", 3) ||
            !strncmp(interface, "mld-", 4));
}

/* Reads `Tx Data Packets` and `Retries` for a single VAP. Both must be present:
 * a VAP that reports only one of them cannot contribute a ratio. */
static int apd_tx_retry_collect_vap(const char *path, const char *vap,
                                    uint64_t *tx_total, uint64_t *tx_retries,
                                    char *reason, size_t reason_size)
{
    struct apd_command_result result = { 0 };
    struct apd_airtime_stats stats;
    char *line = NULL;
    char *saved = NULL;

    memset(&stats, 0, sizeof(stats));
    if (!path || !path[0] || !vap || !vap[0] || !tx_total || !tx_retries) {
        snprintf(reason, reason_size, "%s", "apstats_binary_unavailable");
        return -1;
    }
    if (!apd_survey_safe_interface_name(vap)) {
        snprintf(reason, reason_size, "%s", "apstats_vap_name_invalid");
        return -1;
    }
    {
        char *const argv[] = {
            (char *)path, "-v", "-i", (char *)vap, NULL
        };

        if (apd_readonly_command(path, argv, &result) != 0) {
            snprintf(reason, reason_size, "%s",
                     result.timed_out ? "apstats_vap_timeout" :
                                        "apstats_vap_failed_or_unsupported");
            apd_command_result_free(&result);
            return -1;
        }
    }
    if (!result.text || !result.length) {
        snprintf(reason, reason_size, "%s", "apstats_vap_no_output");
        apd_command_result_free(&result);
        return -1;
    }
    line = strtok_r(result.text, "\n", &saved);
    while (line) {
        char *trimmed = apd_survey_trim(line);

        if (trimmed && trimmed[0])
            apd_airtime_parse_line(trimmed, &stats);
        line = strtok_r(NULL, "\n", &saved);
    }
    apd_command_result_free(&result);
    if (!stats.has_retries) {
        snprintf(reason, reason_size, "%s", "apstats_vap_retries_absent");
        return -1;
    }
    if (!stats.has_tx_packets) {
        snprintf(reason, reason_size, "%s", "apstats_vap_tx_packets_absent");
        return -1;
    }
    *tx_total = stats.tx_packets;
    *tx_retries = stats.retries;
    return 0;
}

/* Sums the VAP counters for one wiphy. The radio netdev itself (ARPHRD type
 * 801) is skipped: it is not a VAP and `apstats -v` does not apply to it. */
static int apd_tx_retry_collect(const char *path, unsigned int wiphy_index,
                                unsigned int radio_index, int has_radio_index,
                                struct apd_tx_retry_stats *out)
{
    DIR *directory;
    struct dirent *entry;
    uint64_t total = 0;
    uint64_t retries = 0;
    unsigned int counted = 0;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!path || !path[0]) {
        snprintf(out->reason, sizeof(out->reason), "%s",
                 "apstats_binary_unavailable");
        return -1;
    }
    directory = opendir(APD_NET_CLASS_PATH);
    if (!directory) {
        snprintf(out->reason, sizeof(out->reason), "%s",
                 "apstats_sysfs_net_class_unreadable");
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        char path_buf[PATH_MAX];
        char vap[IFNAMSIZ] = { 0 };
        uint64_t vap_total = 0;
        uint64_t vap_retries = 0;
        unsigned int observed = 0;
        unsigned int type = 0;
        size_t name_len = strlen(entry->d_name);

        if (entry->d_name[0] == '.' || name_len >= sizeof(vap))
            continue;
        if (snprintf(path_buf, sizeof(path_buf), "%s/%s/phy80211/index",
                     APD_NET_CLASS_PATH, entry->d_name) >= (int)sizeof(path_buf) ||
            apd_neighbor_read_uint_file(path_buf, &observed) != 0 ||
            observed != wiphy_index)
            continue;
        if (snprintf(path_buf, sizeof(path_buf), "%s/%s/type",
                     APD_NET_CLASS_PATH, entry->d_name) >= (int)sizeof(path_buf) ||
            apd_neighbor_read_uint_file(path_buf, &type) != 0) {
            closedir(directory);
            snprintf(out->reason, sizeof(out->reason), "%s",
                     "apstats_sysfs_net_class_unreadable");
            return -1;
        }
        if (type == APD_ARPHRD_IEEE80211_RADIO)
            continue;
        if (has_radio_index) {
            unsigned int owner = 0;

            if (apd_tx_retry_vap_radio_index(entry->d_name, &owner) != 0) {
                if (apd_tx_retry_aggregate_interface(entry->d_name))
                    continue;
                closedir(directory);
                snprintf(out->reason, sizeof(out->reason), "%s",
                         "apstats_vap_radio_mapping_unavailable");
                return -1;
            }
            if (owner != radio_index)
                continue;
        }
        if (counted >= APD_TX_RETRY_MAX_VAPS) {
            closedir(directory);
            snprintf(out->reason, sizeof(out->reason), "%s",
                     "apstats_vap_count_exceeds_limit");
            return -1;
        }
        memcpy(vap, entry->d_name, name_len + 1);
        if (apd_tx_retry_collect_vap(path, vap, &vap_total, &vap_retries,
                                     out->reason, sizeof(out->reason)) != 0) {
            closedir(directory);
            return -1;
        }
        /* Saturation would silently turn a sum into a smaller number, which the
         * AC would read as a counter wrap and rebaseline forever. */
        if (total > UINT64_MAX - vap_total ||
            retries > UINT64_MAX - vap_retries) {
            closedir(directory);
            snprintf(out->reason, sizeof(out->reason), "%s",
                     "apstats_vap_sum_overflow");
            return -1;
        }
        total += vap_total;
        retries += vap_retries;
        counted++;
    }
    closedir(directory);
    if (counted == 0) {
        snprintf(out->reason, sizeof(out->reason), "%s",
                 has_radio_index ? "apstats_no_vap_for_logical_radio" :
                                   "apstats_no_vap_for_wiphy");
        return -1;
    }
    if (retries > total) {
        snprintf(out->reason, sizeof(out->reason), "%s",
                 "apstats_vap_retries_exceed_tx_total");
        return -1;
    }
    out->tx_total = total;
    out->tx_retries = retries;
    out->vap_count = counted;
    out->available = 1;
    return 0;
}

/* Adds the cumulative retry pair to an existing `air_stats` object. The AC
 * ingest only differences counters carrying
 * `tx_retry_counter_semantics == "cumulative"`, so the flag is the contract:
 * emitting the numbers without it is a no-op on the controller side. */
static void apd_tx_retry_decorate(struct json_object *air,
                                  const struct apd_tx_retry_stats *stats)
{
    if (!air)
        return;
    if (!stats || !stats->available) {
        json_object_object_add(air, "tx_retry_available",
                               json_object_new_boolean(0));
        json_object_object_add(air, "tx_retry_source", json_object_new_null());
        json_object_object_add(air, "tx_retry_counter_semantics",
                               json_object_new_null());
        json_object_object_add(air, "tx_retry_reason",
            (stats && stats->reason[0]) ?
            json_object_new_string(stats->reason) :
            json_object_new_string("apstats_vap_retry_unavailable"));
        json_object_object_add(air, "tx_retry_vap_count",
                               json_object_new_int(0));
        return;
    }
    json_object_object_add(air, "tx_retry_available",
                           json_object_new_boolean(1));
    json_object_object_add(air, "tx_retry_source",
        json_object_new_string("apstats_vap_aggregate"));
    json_object_object_add(air, "tx_retry_counter_semantics",
                           json_object_new_string("cumulative"));
    json_object_object_add(air, "tx_retry_reason", json_object_new_null());
    json_object_object_add(air, "tx_retry_vap_count",
                           json_object_new_int((int)stats->vap_count));
    json_object_object_add(air, "tx_total",
                           json_object_new_int64((int64_t)stats->tx_total));
    json_object_object_add(air, "tx_retries",
                           json_object_new_int64((int64_t)stats->tx_retries));
}

/* Retry rate as a percentage of offered frames. `Retries` is VAP level, so at
 * radio level this derives from Tx failures over Tx packets, which is what the
 * frontend's retry-rate metric reads. Returns -1 when the inputs are missing or the
 * denominator is zero, so the caller emits null rather than 0. */
static int apd_airtime_retry_pct(const struct apd_airtime_stats *stats,
                                 double *out)
{
    uint64_t failures;

    if (!stats || !out || !stats->has_tx_packets || stats->tx_packets == 0)
        return -1;
    if (!stats->has_retries && !stats->has_tx_failures)
        return -1;
    failures = stats->has_retries ? stats->retries : stats->tx_failures;
    if (failures > stats->tx_packets)
        return -1;
    *out = (double)failures * 100.0 / (double)stats->tx_packets;
    return 0;
}

/* Channel utilization from the two chan-util counters apstats does report.
 * `Channel Utilization (0-255)` is `<DISABLED>` on real hardware, but
 * `Self BSS chan util` + `OBSS chan util` are live percentages. */
static int apd_airtime_utilization_pct(const struct apd_airtime_stats *stats,
                                       double *out)
{
    int total;

    if (!stats || !out || !stats->has_self_bss_util || !stats->has_obss_util)
        return -1;
    total = stats->self_bss_util_pct + stats->obss_util_pct;
    if (total < 0)
        return -1;
    if (total > 100)
        total = 100;
    *out = (double)total;
    return 0;
}

static void apd_airtime_add_u64(struct json_object *object, const char *name,
                                int present, uint64_t value)
{
    json_object_object_add(object, name,
                           present ? json_object_new_int64((int64_t)value) :
                                     json_object_new_null());
}

/* Emits the `air_stats` block plus the derived airtime metrics. Every absent
 * counter is null with a reason; nothing is defaulted to 0. */
static struct json_object *apd_airtime_json(const struct apd_airtime_stats *stats,
                                            int available,
                                            const char *radio_netdev)
{
    struct json_object *air = json_object_new_object();
    double value = 0.0;

    if (!air)
        return NULL;
    json_object_object_add(air, "source", available ?
        json_object_new_string("apstats_radio") : json_object_new_null());
    json_object_object_add(air, "available", json_object_new_boolean(available));
    json_object_object_add(air, "interface", radio_netdev && radio_netdev[0] ?
        json_object_new_string(radio_netdev) : json_object_new_null());
    json_object_object_add(air, "reason",
        (!available && stats && stats->reason[0]) ?
        json_object_new_string(stats->reason) : json_object_new_null());
    if (!available || !stats) {
        static const char *const fields[] = {
            "tx_packets", "tx_bytes", "rx_packets", "rx_bytes", "tx_failures",
            "dropped", "retries", "rx_phy_errors", "rx_crc_errors",
            "total_per_pct", "retry_rate_pct", "utilization_pct",
            "self_bss_util_pct", "obss_util_pct", "noise_floor_dbm", NULL
        };
        size_t i;

        for (i = 0; fields[i]; i++)
            json_object_object_add(air, fields[i], json_object_new_null());
        return air;
    }
    apd_airtime_add_u64(air, "tx_packets", stats->has_tx_packets,
                        stats->tx_packets);
    apd_airtime_add_u64(air, "tx_bytes", stats->has_tx_bytes, stats->tx_bytes);
    apd_airtime_add_u64(air, "rx_packets", stats->has_rx_packets,
                        stats->rx_packets);
    apd_airtime_add_u64(air, "rx_bytes", stats->has_rx_bytes, stats->rx_bytes);
    apd_airtime_add_u64(air, "tx_failures", stats->has_tx_failures,
                        stats->tx_failures);
    apd_airtime_add_u64(air, "dropped", stats->has_tx_dropped,
                        stats->tx_dropped);
    apd_airtime_add_u64(air, "retries", stats->has_retries, stats->retries);
    apd_airtime_add_u64(air, "rx_phy_errors", stats->has_rx_phy_errors,
                        stats->rx_phy_errors);
    apd_airtime_add_u64(air, "rx_crc_errors", stats->has_rx_crc_errors,
                        stats->rx_crc_errors);
    /* A measured 0 is reported as 0; only an unread counter becomes null. */
    json_object_object_add(air, "total_per_pct", stats->has_total_per ?
        json_object_new_int(stats->total_per_pct) : json_object_new_null());
    json_object_object_add(air, "self_bss_util_pct", stats->has_self_bss_util ?
        json_object_new_int(stats->self_bss_util_pct) : json_object_new_null());
    json_object_object_add(air, "obss_util_pct", stats->has_obss_util ?
        json_object_new_int(stats->obss_util_pct) : json_object_new_null());
    json_object_object_add(air, "noise_floor_dbm", stats->has_noise_floor ?
        json_object_new_int(stats->noise_floor_dbm) : json_object_new_null());
    if (apd_airtime_retry_pct(stats, &value) == 0)
        json_object_object_add(air, "retry_rate_pct",
                               json_object_new_double(value));
    else
        json_object_object_add(air, "retry_rate_pct", json_object_new_null());
    if (apd_airtime_utilization_pct(stats, &value) == 0)
        json_object_object_add(air, "utilization_pct",
                               json_object_new_double(value));
    else
        json_object_object_add(air, "utilization_pct", json_object_new_null());
    /* Names which counters the firmware itself refuses to compute, so the UI
     * can say "not measured" instead of implying the collector failed. */
    json_object_object_add(air, "firmware_disabled_channel_utilization",
                           json_object_new_boolean(stats->channel_util_disabled));
    json_object_object_add(air, "firmware_disabled_throughput",
                           json_object_new_boolean(stats->throughput_disabled));
    return air;
}

static int apd_survey_scan_collect(const char *path, const char *radio_id,
                                   struct json_object **out)
{
    struct apd_command_result inventory = { 0 };
    /* Zeroed up front: the early `goto result` paths run before the radio
     * mapping is resolved, and the station emitter reads target.interface. */
    struct apd_neighbor_target target = { 0 };
    struct apd_survey_sample raw;
    struct json_object *root = NULL;
    struct json_object *items = NULL;
    struct json_object *sample = NULL;
    const char *reason = "iw_survey_failed_or_unsupported";
    char target_reason[APD_NEIGHBOR_REASON_LEN + 1] = { 0 };
    double utilization_pct = 0.0;
    int complete = 0;
    int rc = -1;
    const char *station_source = "";
    const char *station_reason = "";
    struct apd_vendor_station_set vendor_stations = { 0 };
    struct json_object *stations = NULL;
    int have_vendor_stations = 0;
    struct apd_airtime_stats airtime;
    char airtime_netdev[IFNAMSIZ] = { 0 };
    int have_airtime = 0;
    int airtime_attempted = 0;
    struct apd_tx_retry_stats tx_retry;

    if (!out)
        return -1;
    *out = NULL;
    root = json_object_new_object();
    items = json_object_new_array();
    if (!root || !items)
        goto done;
    json_object_object_add(root, "source", json_object_new_string("iw_survey"));
    json_object_object_add(root, "scanner_radio_id",
                           json_object_new_string(radio_id ? radio_id : ""));
    json_object_object_add(root, "truncated", json_object_new_boolean(0));
    if (!path) {
        reason = "iw_binary_unavailable";
        goto result;
    }
    {
        char *const argv[] = { (char *)path, "dev", NULL };

        if (apd_readonly_command(path, argv, &inventory) != 0) {
            reason = inventory.timed_out ? "iw_dev_timeout" :
                     inventory.output_limited ? "iw_dev_output_limited" :
                                                "iw_dev_failed";
            goto result;
        }
    }
    if (apd_neighbor_target_from_iw(inventory.text, radio_id, &target,
                                    target_reason) != 0) {
        reason = target_reason[0] ? target_reason : "radio_mapping_unavailable";
        goto result;
    }
    memset(&raw, 0, sizeof(raw));
    /* Station inventory is collected independently of the survey sample: on QCA
     * drivers `survey dump` is empty while stations are still readable through
     * `wlanconfig`, so a survey failure must not suppress station data. */
    memset(&vendor_stations, 0, sizeof(vendor_stations));
    if (apd_vendor_station_collect(apd_find_wlanconfig(), target.interface,
                                   &vendor_stations) == 0) {
        have_vendor_stations = 1;
        station_source = "wlanconfig_list";
    } else {
        station_reason = vendor_stations.reason[0] ? vendor_stations.reason :
                                                    "wlanconfig_unavailable";
    }
    /* Airtime counters follow the same rule as stations: the survey sample
     * below stays the main source, and this vendor path only supplies what an
     * empty `survey dump` cannot. Collected before the survey bails out so a
     * missing survey does not also suppress airtime. */
    memset(&airtime, 0, sizeof(airtime));
    airtime_attempted = 1;
    {
        enum apd_radio_netdev_status netdev_status =
            apd_airtime_radio_netdev(target.wiphy_index, target.radio_index,
                                     target.has_radio_index, airtime_netdev,
                                     sizeof(airtime_netdev));

        if (netdev_status != APD_RADIO_NETDEV_OK)
            snprintf(airtime.reason, sizeof(airtime.reason), "%s",
                     apd_radio_netdev_reason(netdev_status));
        else if (apd_airtime_collect(apd_find_apstats(), airtime_netdev,
                                     &airtime) == 0)
            have_airtime = 1;
    }
    /* Independent of the radio-level block above: the radio level has no
     * `Retries` counter at all, so a working radio sample says nothing about
     * whether retry history is available, and a failed one must not suppress it. */
    (void)apd_tx_retry_collect(apd_find_apstats(), target.wiphy_index,
                               target.radio_index, target.has_radio_index,
                               &tx_retry);
    if (apd_survey_collect_raw(path, target.interface, target.frequency_mhz,
                               &raw) != 0 || !raw.complete) {
        reason = raw.reason[0] ? raw.reason : reason;
        goto result;
    }
    sample = json_object_new_object();
    if (!sample)
        goto result;
    json_object_object_add(sample, "source", json_object_new_string("iw_survey"));
    json_object_object_add(sample, "sample_time",
                           json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(sample, "complete", json_object_new_boolean(1));
    json_object_object_add(sample, "stale", json_object_new_boolean(0));
    json_object_object_add(sample, "reason", json_object_new_null());
    json_object_object_add(sample, "radio_id", json_object_new_string(radio_id));
    json_object_object_add(sample, "wiphy_name",
                           json_object_new_string(target.wiphy_name));
    json_object_object_add(sample, "interface",
                           json_object_new_string(target.interface));
    json_object_object_add(sample, "ifindex",
                           json_object_new_int64(target.ifindex));
    json_object_object_add(sample, "frequency_mhz",
                           json_object_new_int(raw.frequency_mhz));
    json_object_object_add(sample, "in_use",
                           json_object_new_boolean(raw.in_use));
    json_object_object_add(sample, "noise_dbm", raw.has_noise ?
        json_object_new_int(raw.noise_dbm) : json_object_new_null());
    json_object_object_add(sample, "channel_active_time_ms",
        raw.has_active_time ? json_object_new_int64((int64_t)raw.active_time_ms) :
                              json_object_new_null());
    json_object_object_add(sample, "channel_busy_time_ms",
        raw.has_busy_time ? json_object_new_int64((int64_t)raw.busy_time_ms) :
                            json_object_new_null());
    json_object_object_add(sample, "channel_receive_time_ms",
        raw.has_receive_time ? json_object_new_int64((int64_t)raw.receive_time_ms) :
                               json_object_new_null());
    json_object_object_add(sample, "channel_bss_receive_time_ms",
        raw.has_bss_receive_time ?
            json_object_new_int64((int64_t)raw.bss_receive_time_ms) :
            json_object_new_null());
    json_object_object_add(sample, "channel_transmit_time_ms",
        raw.has_transmit_time ? json_object_new_int64((int64_t)raw.transmit_time_ms) :
                                json_object_new_null());
    if (apd_survey_utilization(&raw, &utilization_pct) == 0)
        json_object_object_add(sample, "utilization_pct",
                               json_object_new_double(utilization_pct));
    else
        json_object_object_add(sample, "utilization_pct", json_object_new_null());
    /*
     * Self-BSS / OBSS split travels on the sample's own air_stats, which is
     * where the aggregator already looks for the vendor `apstats` figures. A
     * mac80211 AP has no apstats, so without this the wireless page reported
     * "driver did not report OBSS interference" while `iw survey dump` was
     * printing the counters it needs.
     */
    {
        double obss_pct = 0.0;
        double self_pct = 0.0;
        int split = apd_survey_bss_split(&raw, &obss_pct, &self_pct) == 0;
        struct json_object *air = json_object_new_object();

        if (air) {
            json_object_object_add(air, "source",
                json_object_new_string("iw_survey"));
            json_object_object_add(air, "interface",
                json_object_new_string(target.interface));
            json_object_object_add(air, "available",
                                   json_object_new_boolean(split));
            json_object_object_add(air, "obss_util_pct", split ?
                json_object_new_double(obss_pct) : json_object_new_null());
            json_object_object_add(air, "self_bss_util_pct", split ?
                json_object_new_double(self_pct) : json_object_new_null());
            json_object_object_add(air, "noise_floor_dbm", raw.has_noise ?
                json_object_new_int(raw.noise_dbm) : json_object_new_null());
            json_object_object_add(air, "reason", split ? json_object_new_null() :
                json_object_new_string(raw.has_bss_receive_time ?
                    "iw_survey_bss_receive_time_inconsistent" :
                    "iw_survey_bss_receive_time_missing"));
            json_object_object_add(sample, "air_stats", air);
        }
    }
    json_object_array_add(items, sample);
    sample = NULL;
    complete = 1;
    rc = 0;
result:
    if (have_vendor_stations) {
        stations = json_object_new_array();
        if (stations) {
            for (size_t i = 0; i < vendor_stations.count; i++) {
                const struct apd_vendor_station *st = &vendor_stations.items[i];
                struct json_object *entry = json_object_new_object();

                if (!entry)
                    break;
                json_object_object_add(entry, "mac",
                                       json_object_new_string(st->mac));
                json_object_object_add(entry, "source",
                                       json_object_new_string("wlanconfig_list"));
                json_object_object_add(entry, "interface",
                                       json_object_new_string(target.interface));
                json_object_object_add(entry, "radio_id",
                    json_object_new_string(radio_id ? radio_id : ""));
                json_object_object_add(entry, "aid",
                                       json_object_new_int(st->aid));
                json_object_object_add(entry, "channel", st->has_channel ?
                    json_object_new_int(st->channel) : json_object_new_null());
                json_object_object_add(entry, "rssi_dbm", st->has_rssi ?
                    json_object_new_int(st->rssi) : json_object_new_null());
                json_object_object_add(entry, "min_rssi_dbm", st->has_min_rssi ?
                    json_object_new_int(st->min_rssi) : json_object_new_null());
                json_object_object_add(entry, "max_rssi_dbm", st->has_max_rssi ?
                    json_object_new_int(st->max_rssi) : json_object_new_null());
                json_object_object_add(entry, "tx_rate_kbps", st->has_tx_rate ?
                    json_object_new_int64((int64_t)st->tx_rate_kbps) :
                    json_object_new_null());
                json_object_object_add(entry, "rx_rate_kbps", st->has_rx_rate ?
                    json_object_new_int64((int64_t)st->rx_rate_kbps) :
                    json_object_new_null());
                json_object_object_add(entry, "tx_nss", st->has_tx_nss ?
                    json_object_new_int(st->tx_nss) : json_object_new_null());
                json_object_object_add(entry, "rx_nss", st->has_rx_nss ?
                    json_object_new_int(st->rx_nss) : json_object_new_null());
                json_object_object_add(entry, "idle_ms", st->has_idle ?
                    json_object_new_int(st->idle_ms) : json_object_new_null());
                json_object_object_add(entry, "wifi_standard", st->mode[0] ?
                    json_object_new_string(st->mode) : json_object_new_null());
                json_object_array_add(stations, entry);
            }
            json_object_object_add(root, "stations", stations);
            stations = NULL;
        }
    } else {
        json_object_object_add(root, "stations", json_object_new_array());
    }
    json_object_object_add(root, "station_count",
        json_object_new_int((int)(have_vendor_stations ?
                                  vendor_stations.count : 0)));
    json_object_object_add(root, "station_truncated",
        json_object_new_boolean(have_vendor_stations &&
                                vendor_stations.truncated));
    /* Report the source that actually produced data, not the one we tried
     * first. An unqualified "iw station dump" here is what misled acceptance. */
    json_object_object_add(root, "station_source", station_source[0] ?
        json_object_new_string(station_source) : json_object_new_null());
    json_object_object_add(root, "station_reason", station_reason[0] ?
        json_object_new_string(station_reason) : json_object_new_null());
    /* Airtime block travels beside the survey items so the aggregator can read
     * it per radio. `air_stats` is the key the wireless page already consumes. */
    if (airtime_attempted) {
        struct json_object *air = apd_airtime_json(&airtime, have_airtime,
                                                  airtime_netdev);

        if (air) {
            apd_tx_retry_decorate(air, &tx_retry);
            json_object_object_add(root, "air_stats", air);
        }
        json_object_object_add(root, "airtime_source", have_airtime ?
            json_object_new_string("apstats_radio") : json_object_new_null());
        json_object_object_add(root, "airtime_reason",
            (!have_airtime && airtime.reason[0]) ?
            json_object_new_string(airtime.reason) : json_object_new_null());
    }
    json_object_object_add(root, "ok", json_object_new_boolean(complete));
    json_object_object_add(root, "complete", json_object_new_boolean(complete));
    json_object_object_add(root, "error_code",
                           json_object_new_string(complete ? "" : reason));
    json_object_object_add(root, "items", items);
    items = NULL;
    *out = root;
    root = NULL;
done:
    apd_command_result_free(&inventory);
    json_object_put(sample);
    json_object_put(stations);
    json_object_put(items);
    json_object_put(root);
    return rc;
}
#endif
#endif
#endif

#ifndef APD_HOSTAPD_STANDALONE_TEST
static void apd_json_nullable_string(struct json_object *obj, const char *name,
                                     const char *value)
{
    json_object_object_add(obj, name, value ? json_object_new_string(value) :
                           json_object_new_null());
}

static struct json_object *apd_source_state(const char *source,
                                            const char *scope,
                                            int available, int complete,
                                            const char *reason,
                                            int64_t observed_at)
{
    struct json_object *state = json_object_new_object();

    json_object_object_add(state, "source", json_object_new_string(source));
    json_object_object_add(state, "scope", json_object_new_string(scope));
    json_object_object_add(state, "available",
                           json_object_new_boolean(available));
    json_object_object_add(state, "complete",
                           json_object_new_boolean(complete));
    json_object_object_add(state, "stale", json_object_new_boolean(0));
    apd_json_nullable_string(state, "reason", reason);
    json_object_object_add(state, "observed_at",
                           json_object_new_int64(observed_at));
    return state;
}

static int apd_openwrt_phy_count(int *inventory_available)
{
    DIR *dir = opendir(APD_IEEE80211_PATH);
    struct dirent *entry;
    int count = 0;

    if (inventory_available)
        *inventory_available = dir != NULL;
    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.')
            count++;
    }
    closedir(dir);
    return count;
}

static const char *apd_uci_string(struct uci_context *ctx,
                                  struct uci_section *section,
                                  const char *name)
{
    const char *value = uci_lookup_option_string(ctx, section, name);

    return value && value[0] ? value : NULL;
}

static int apd_text_boolean(const char *value, int fallback)
{
    if (!value)
        return fallback;
    if (!strcmp(value, "1") || !strcasecmp(value, "true") ||
        !strcasecmp(value, "yes") || !strcasecmp(value, "on"))
        return 1;
    if (!strcmp(value, "0") || !strcasecmp(value, "false") ||
        !strcasecmp(value, "no") || !strcasecmp(value, "off"))
        return 0;
    return fallback;
}

static void apd_add_desired_string(struct json_object *obj,
                                   struct uci_context *ctx,
                                   struct uci_section *section,
                                   const char *json_name,
                                   const char *uci_name)
{
    const char *value = apd_uci_string(ctx, section, uci_name);

    if (value)
        json_object_object_add(obj, json_name, json_object_new_string(value));
}

static int apd_collect_uci(struct json_object **radios_out,
                           struct json_object **ssids_out,
                           struct json_object **source_out,
                           int64_t observed_at)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *package = NULL;
    struct json_object *radios = json_object_new_array();
    struct json_object *ssids = json_object_new_array();
    struct uci_element *element;
    int available = 0;

    if (!ctx || !radios || !ssids)
        goto fail;
    uci_set_confdir(ctx, APD_UCI_CONFIG_DIR);
    if (uci_load(ctx, "wireless", &package) != UCI_OK || !package) {
        *source_out = apd_source_state("uci_wireless", "desired", 0, 0,
                                       "wireless_config_unavailable", observed_at);
        goto done;
    }
    available = 1;
    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        const char *type = section->type;
        struct json_object *item;

        if (strcmp(type, "wifi-device") && strcmp(type, "wifi-iface"))
            continue;
        item = json_object_new_object();
        json_object_object_add(item, "id",
                               json_object_new_string(section->e.name));
        json_object_object_add(item, "source",
                               json_object_new_string("uci_wireless"));
        json_object_object_add(item, "complete", json_object_new_boolean(1));
        json_object_object_add(item, "stale", json_object_new_boolean(0));
        json_object_object_add(item, "reason", json_object_new_null());
        json_object_object_add(item, "observed_at",
                               json_object_new_int64(observed_at));
        if (!strcmp(type, "wifi-device")) {
            const char *disabled = apd_uci_string(ctx, section, "disabled");
            apd_add_desired_string(item, ctx, section, "driver", "type");
            apd_add_desired_string(item, ctx, section, "phy", "phy");
            apd_add_desired_string(item, ctx, section, "band", "band");
            apd_add_desired_string(item, ctx, section, "hwmode", "hwmode");
            apd_add_desired_string(item, ctx, section, "channel", "channel");
            apd_add_desired_string(item, ctx, section, "width_mode", "htmode");
            apd_add_desired_string(item, ctx, section, "country", "country");
            json_object_object_add(item, "enabled", json_object_new_boolean(
                                   !apd_text_boolean(disabled, 0)));
            json_object_array_add(radios, item);
        } else {
            const char *disabled = apd_uci_string(ctx, section, "disabled");
            struct uci_option *devices = uci_lookup_option(ctx, section, "device");
            struct json_object *radio_ids = json_object_new_array();

            if (devices && devices->type == UCI_TYPE_LIST) {
                struct uci_element *entry;

                uci_foreach_element(&devices->v.list, entry)
                    json_object_array_add(radio_ids, json_object_new_string(entry->name));
            } else if (devices && devices->type == UCI_TYPE_STRING) {
                json_object_array_add(radio_ids, json_object_new_string(devices->v.string));
            }
            if (json_object_array_length(radio_ids))
                json_object_object_add(item, "radio_id",
                    json_object_get(json_object_array_get_idx(radio_ids, 0)));
            json_object_object_add(item, "radio_ids", radio_ids);
            apd_add_desired_string(item, ctx, section, "radio_id", "device");
            apd_add_desired_string(item, ctx, section, "interface", "ifname");
            apd_add_desired_string(item, ctx, section, "broadcast_name", "ssid");
            apd_add_desired_string(item, ctx, section, "mode", "mode");
            apd_add_desired_string(item, ctx, section, "network", "network");
            apd_add_desired_string(item, ctx, section, "security_mode", "encryption");
            apd_add_desired_string(item, ctx, section, "ieee80211w", "ieee80211w");
            apd_add_desired_string(item, ctx, section, "dreamingwrt_mlo_members",
                                   "dreamingwrt_mlo_members");
            json_object_object_add(item, "mlo", json_object_new_boolean(
                apd_text_boolean(apd_uci_string(ctx, section, "mlo"), 0)));
            {
                const char *key = apd_uci_string(ctx, section, "key");

                json_object_object_add(item, "password_present",
                    json_object_new_boolean(key && key[0]));
            }
            json_object_object_add(item, "enabled", json_object_new_boolean(
                                   !apd_text_boolean(disabled, 0)));
            json_object_object_add(item, "hidden", json_object_new_boolean(
                apd_text_boolean(apd_uci_string(ctx, section, "hidden"), 0)));
            json_object_object_add(item, "isolate", json_object_new_boolean(
                apd_text_boolean(apd_uci_string(ctx, section, "isolate"), 0)));
            json_object_array_add(ssids, item);
        }
    }
    *source_out = apd_source_state("uci_wireless", "desired", 1, 1,
                                   NULL, observed_at);

done:
    if (package)
        uci_unload(ctx, package);
    uci_free_context(ctx);
    *radios_out = radios;
    *ssids_out = ssids;
    return available ? 0 : -1;

fail:
    if (package && ctx)
        uci_unload(ctx, package);
    if (ctx)
        uci_free_context(ctx);
    if (radios)
        json_object_put(radios);
    if (ssids)
        json_object_put(ssids);
    *radios_out = json_object_new_array();
    *ssids_out = json_object_new_array();
    *source_out = apd_source_state("uci_wireless", "desired", 0, 0,
                                   "collector_allocation_failed", observed_at);
    return -1;
}

static void apd_netifd_callback(struct ubus_request *request, int type,
                                struct blob_attr *message)
{
    struct apd_netifd_result *result = request->priv;
    char *text;

    (void)type;
    if (!result || !message)
        return;
    text = blobmsg_format_json(message, true);
    if (!text)
        return;
    result->json = json_tokener_parse(text);
    free(text);
}

static int apd_device_text_copy(char *out, size_t out_size, const char *value)
{
    const unsigned char *bytes = (const unsigned char *)value;
    size_t begin = 0;
    size_t end;

    if (!out || out_size == 0 || !value)
        return -1;
    end = strlen(value);
    while (begin < end && isspace(bytes[begin]))
        begin++;
    while (end > begin && isspace(bytes[end - 1]))
        end--;
    if (end == begin || end - begin >= out_size)
        return -1;
    for (size_t i = begin; i < end; i++)
        if (bytes[i] < 0x20 && bytes[i] != '\t')
            return -1;
    memcpy(out, value + begin, end - begin);
    out[end - begin] = '\0';
    return 0;
}

static int apd_device_file_read(const char *path, char *out, size_t out_size)
{
    unsigned char buffer[APD_DEVICE_MODEL_MAX + 2];
    ssize_t length;
    int fd;

    if (!path || !out || out_size == 0 ||
        (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
        return -1;
    do {
        length = read(fd, buffer, sizeof(buffer) - 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    if (length <= 0 || (size_t)length >= sizeof(buffer))
        return -1;
    while (length > 0 && (buffer[length - 1] == '\0' ||
                          isspace(buffer[length - 1])))
        length--;
    if (length <= 0 || (size_t)length >= out_size ||
        memchr(buffer, '\0', (size_t)length))
        return -1;
    buffer[length] = '\0';
    return apd_device_text_copy(out, out_size, (const char *)buffer);
}

int apd_backend_device_model_collect(struct apd_device_model *out)
{
    static const char *const dt_paths[] = {
        "/proc/device-tree/model",
        "/sys/firmware/devicetree/base/model",
        NULL
    };
    struct apd_netifd_result result = { 0 };
    struct ubus_context *ctx = NULL;
    struct json_object *value = NULL;
    uint32_t object_id;
    size_t i;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    snprintf(out->model_source, sizeof(out->model_source), "%s", "unavailable");
    snprintf(out->reason, sizeof(out->reason), "%s",
             "reliable_model_source_unavailable");

    ctx = ubus_connect(APD_UBUS_SOCKET_PATH);
    if (ctx && ubus_lookup_id(ctx, "system", &object_id) == UBUS_STATUS_OK &&
        ubus_invoke(ctx, object_id, "board", NULL, apd_netifd_callback,
                    &result, APD_UBUS_TIMEOUT_MS) == UBUS_STATUS_OK &&
        result.json && json_object_is_type(result.json, json_type_object)) {
        if (json_object_object_get_ex(result.json, "model", &value) && value &&
            json_object_is_type(value, json_type_string))
            apd_device_text_copy(out->model, sizeof(out->model),
                                 json_object_get_string(value));
        if (json_object_object_get_ex(result.json, "board_name", &value) && value &&
            json_object_is_type(value, json_type_string))
            apd_device_text_copy(out->board_name, sizeof(out->board_name),
                                 json_object_get_string(value));
        if (out->model[0])
            snprintf(out->model_source, sizeof(out->model_source), "%s",
                     "ubus_system_board");
    }
    if (ctx)
        ubus_free(ctx);
    if (result.json)
        json_object_put(result.json);

    if (!out->model[0] &&
        apd_device_file_read("/tmp/sysinfo/model", out->model,
                             sizeof(out->model)) == 0)
        snprintf(out->model_source, sizeof(out->model_source), "%s",
                 "tmp_sysinfo_model");
    if (!out->board_name[0])
        apd_device_file_read("/tmp/sysinfo/board_name", out->board_name,
                             sizeof(out->board_name));
    if (!out->model[0]) {
        for (i = 0; dt_paths[i]; i++) {
            if (apd_device_file_read(dt_paths[i], out->model,
                                     sizeof(out->model)) == 0) {
                snprintf(out->model_source, sizeof(out->model_source), "%s",
                         "device_tree_model");
                break;
            }
        }
    }
    out->model_available = out->model[0] != '\0';
    if (out->model_available)
        out->reason[0] = '\0';
    return out->model_available ? 0 : -1;
}

static struct json_object *apd_collect_netifd(int phy_count,
                                              int64_t observed_at,
                                              int *complete_out)
{
    struct ubus_context *ctx = ubus_connect(APD_UBUS_SOCKET_PATH);
    struct apd_netifd_result result = { 0 };
    struct json_object *state;
    uint32_t object_id;
    int rc;
    int count = 0;
    int complete = 0;
    const char *reason = NULL;

    if (!ctx) {
        state = apd_source_state("ubus_network_wireless", "runtime", 0, 0,
                                 "ubus_unavailable", observed_at);
        goto done;
    }
    rc = ubus_lookup_id(ctx, "network.wireless", &object_id);
    if (rc != UBUS_STATUS_OK) {
        state = apd_source_state("ubus_network_wireless", "runtime", 0, 0,
                                 "network_wireless_object_unavailable",
                                 observed_at);
        goto close;
    }
    rc = ubus_invoke(ctx, object_id, "status", NULL, apd_netifd_callback,
                     &result, APD_UBUS_TIMEOUT_MS);
    if (rc != UBUS_STATUS_OK) {
        state = apd_source_state("ubus_network_wireless", "runtime", 1, 0,
                                 "network_wireless_status_failed", observed_at);
        json_object_object_add(state, "ubus_status", json_object_new_int(rc));
        goto close;
    }
    if (result.json && json_object_is_type(result.json, json_type_object))
        count = json_object_object_length(result.json);
    complete = phy_count == 0 || count > 0;
    if (phy_count == 0)
        reason = "no_phy_detected";
    else if (!count)
        reason = "empty_runtime_status";
    state = apd_source_state("ubus_network_wireless", "runtime", 1,
                             complete, reason, observed_at);
    json_object_object_add(state, "radio_entries", json_object_new_int(count));

close:
    ubus_free(ctx);
done:
    if (result.json)
        json_object_put(result.json);
    if (complete_out)
        *complete_out = complete;
    return state;
}
#endif

#ifndef APD_SURVEY_STANDALONE_TEST
#include <openssl/evp.h>

#define APD_HOSTAPD_IFACE_LEN 63U
#define APD_HOSTAPD_SSID_LEN 127U
#define APD_HOSTAPD_STATE_LEN 31U
#define APD_HOSTAPD_REASON_LEN 63U
#define APD_HOSTAPD_MAC_LEN 17U

enum apd_hostapd_request_result {
    APD_HOSTAPD_REQUEST_OK = 0,
    APD_HOSTAPD_REQUEST_FAILED = -1,
    APD_HOSTAPD_REQUEST_TIMEOUT = -2,
    APD_HOSTAPD_REQUEST_TOO_LARGE = -3,
    APD_HOSTAPD_REQUEST_TOTAL_TIMEOUT = -4,
    /*
     * A zero-length reply. QSDK's hostapd ends a station walk this way instead
     * of answering "FAIL", so for STA-FIRST / STA-NEXT this is the normal end
     * of the list rather than an error. Kept distinct from _FAILED because
     * recvmsg() returning 0 and returning -1 mean opposite things here.
     */
    APD_HOSTAPD_REQUEST_EMPTY = -5,
};

struct apd_hostapd_station_observation {
    char interface[APD_HOSTAPD_IFACE_LEN + 1];
    char mac[APD_HOSTAPD_MAC_LEN + 1];
    int has_signal;
    int signal_dbm;
    int has_rx_bytes;
    uint64_t rx_bytes;
    int has_tx_bytes;
    uint64_t tx_bytes;
    int has_rx_packets;
    uint64_t rx_packets;
    int has_tx_packets;
    uint64_t tx_packets;
    int has_connected_time;
    uint64_t connected_time_seconds;
    int has_inactive_time;
    uint64_t inactive_time_ms;
    int has_flags;
    int authenticated;
    int associated;
    int authorized;
    int has_extended_capabilities;
    int station_btm_capable;
    char station_btm_reason[APD_HOSTAPD_REASON_LEN + 1];
    int has_mld_address;
    char mld_address[APD_HOSTAPD_MAC_LEN + 1];
    int has_link_id;
    int link_id;
    int mlo_relation_complete;
};

#define APD_HOSTAPD_NEIGHBOR_LIMIT 64U
#ifndef APD_QCA_HAPD_SUPP_PATH
#define APD_QCA_HAPD_SUPP_PATH "/usr/sbin/qca-hapd-supp"
#endif
#ifndef APD_QCA_HAPD_PID_PATH
#define APD_QCA_HAPD_PID_PATH APD_HOSTAPD_RUN_DIR_PARENT "/hostapd-global.pid"
#endif
#ifndef APD_QCA_HAPD_PROC_ROOT
#define APD_QCA_HAPD_PROC_ROOT "/proc"
#endif
#ifndef APD_QCA_HAPD_SAFE_SIZE
#define APD_QCA_HAPD_SAFE_SIZE 5183011
#endif
#ifndef APD_QCA_HAPD_SAFE_SHA256
#define APD_QCA_HAPD_SAFE_SHA256 \
    "0efdc9f4670325eaa5807b693665c04420eaf230d17f003952bddfe08601b403"
#endif

static int apd_hostapd_reassoc_backend_safe(void)
{
    struct stat disk, running;
    FILE *binary, *pid_file;
    EVP_MD_CTX *context = NULL;
    unsigned char buffer[4096], digest[EVP_MAX_MD_SIZE];
    char path[PATH_MAX], hex[65], extra;
    unsigned int digest_length, i;
    size_t length;
    long pid;
    int safe = 0;

    binary = fopen(APD_QCA_HAPD_SUPP_PATH, "rb");
    if (!binary)
        return errno == ENOENT;
    if (fstat(fileno(binary), &disk) != 0 || !S_ISREG(disk.st_mode) ||
        disk.st_size != APD_QCA_HAPD_SAFE_SIZE)
        goto out;
    pid_file = fopen(APD_QCA_HAPD_PID_PATH, "r");
    if (!pid_file)
        goto out;
    i = fscanf(pid_file, "%ld %c", &pid, &extra) == 1 &&
        pid > 1 && pid <= INT_MAX;
    fclose(pid_file);
    if (!i)
        goto out;
    snprintf(path, sizeof(path), APD_QCA_HAPD_PROC_ROOT "/%ld/exe", pid);
    /* An on-disk patch cannot qualify an old, still-running hostapd. */
    if (stat(path, &running) != 0 || running.st_dev != disk.st_dev ||
        running.st_ino != disk.st_ino)
        goto out;
    context = EVP_MD_CTX_new();
    if (!context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto out;
    while ((length = fread(buffer, 1, sizeof(buffer), binary)) > 0)
        if (EVP_DigestUpdate(context, buffer, length) != 1)
            goto out;
    if (ferror(binary) ||
        EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
        digest_length != 32)
        goto out;
    for (i = 0; i < digest_length; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    safe = !strcmp(hex, APD_QCA_HAPD_SAFE_SHA256);
out:
    EVP_MD_CTX_free(context);
    fclose(binary);
    return safe;
}

struct apd_hostapd_neighbor {
    char bssid[18];
    char ssid_hex[65];
    char report[27];
};

struct apd_hostapd_bss_observation {
    char interface[APD_HOSTAPD_IFACE_LEN + 1];
    char control_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char bssid[APD_HOSTAPD_MAC_LEN + 1];
    char ssid[APD_HOSTAPD_SSID_LEN + 1];
    char state[APD_HOSTAPD_STATE_LEN + 1];
    int has_bssid;
    int has_ssid;
    int has_frequency;
    int frequency_mhz;
    int has_channel;
    int channel;
    int has_reported_station_count;
    int reported_station_count;
    int has_mld_address;
    char mld_address[APD_HOSTAPD_MAC_LEN + 1];
    int has_link_id;
    int link_id;
    int mlo_relation_complete;
    size_t station_offset;
    size_t station_count;
    int hostapd_ctrl_reachable;
    int ft_configured;
    int ft_supported;
    int ft_over_ds;
    int neighbor_report_80211k;
    int neighbor_database_configured;
    int neighbors_complete;
    size_t neighbor_count;
    struct apd_hostapd_neighbor neighbors[APD_HOSTAPD_NEIGHBOR_LIMIT];
    int bss_transition_80211v;
    int client_deauth;
    int reassoc_block;
    char ft_reason[APD_HOSTAPD_REASON_LEN + 1];
    char neighbor_report_reason[APD_HOSTAPD_REASON_LEN + 1];
    char bss_transition_reason[APD_HOSTAPD_REASON_LEN + 1];
    char client_deauth_reason[APD_HOSTAPD_REASON_LEN + 1];
    int complete;
    char reason[APD_HOSTAPD_REASON_LEN + 1];
};

struct apd_hostapd_observation {
    int directory_available;
    int available;
    int complete;
    int global_control;
    int reassoc_backend_safe;
    size_t interface_controls;
    size_t bss_count;
    size_t station_count;
    int socket_scan_limited;
    int bss_limited;
    int station_limited;
    char reason[APD_HOSTAPD_REASON_LEN + 1];
    struct apd_hostapd_bss_observation bss[APD_HOSTAPD_BSS_LIMIT];
    struct apd_hostapd_station_observation stations[APD_HOSTAPD_STATION_LIMIT];
};

static void apd_hostapd_set_reason(char *target, size_t target_len,
                                   const char *reason)
{
    if (!target || !target_len || target[0] || !reason)
        return;
    snprintf(target, target_len, "%s", reason);
}

static int apd_hostapd_safe_name(const char *name)
{
    size_t i;
    size_t length;

    if (!name)
        return 0;
    length = strlen(name);
    if (!length || length > APD_HOSTAPD_IFACE_LEN || name[0] == '.')
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)name[i];

        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == '@'))
            return 0;
    }
    return strcmp(name, "global") != 0;
}

static int apd_hostapd_copy_text(char *target, size_t target_len,
                                 const char *value)
{
    size_t i;
    size_t length;

    if (!target || !target_len || !value)
        return -1;
    length = strlen(value);
    if (!length || length >= target_len)
        return -1;
    for (i = 0; i < length;) {
        const unsigned char *bytes = (const unsigned char *)value;
        unsigned char c = bytes[i];
        size_t continuation;
        uint32_t codepoint;

        if (c < 0x20 || c == 0x7f)
            return -1;
        if (c < 0x80) {
            i++;
            continue;
        }
        if (c >= 0xc2 && c <= 0xdf) {
            continuation = 1;
            codepoint = c & 0x1f;
        } else if (c >= 0xe0 && c <= 0xef) {
            continuation = 2;
            codepoint = c & 0x0f;
        } else if (c >= 0xf0 && c <= 0xf4) {
            continuation = 3;
            codepoint = c & 0x07;
        } else {
            return -1;
        }
        if (i + continuation >= length)
            return -1;
        for (size_t j = 1; j <= continuation; j++) {
            if ((bytes[i + j] & 0xc0) != 0x80)
                return -1;
            codepoint = (codepoint << 6) | (bytes[i + j] & 0x3f);
        }
        if ((continuation == 2 && codepoint < 0x800) ||
            (continuation == 3 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
            return -1;
        i += continuation + 1;
    }
    memcpy(target, value, length + 1);
    return 0;
}

static int apd_hostapd_parse_mac(const char *value,
                                 char out[APD_HOSTAPD_MAC_LEN + 1])
{
    size_t i;

    if (!value || strlen(value) != APD_HOSTAPD_MAC_LEN)
        return -1;
    for (i = 0; i < APD_HOSTAPD_MAC_LEN; i++) {
        unsigned char c = (unsigned char)value[i];

        if ((i + 1) % 3 == 0) {
            if (c != ':')
                return -1;
            out[i] = ':';
        } else {
            if (!isxdigit(c))
                return -1;
            out[i] = (char)tolower(c);
        }
    }
    out[APD_HOSTAPD_MAC_LEN] = '\0';
    return 0;
}

static int apd_hostapd_parse_i64(const char *value, int64_t minimum,
                                 int64_t maximum, int64_t *out)
{
    char *end = NULL;
    long long parsed;

    if (!value || !value[0] || isspace((unsigned char)value[0]))
        return -1;
    errno = 0;
    parsed = strtoll(value, &end, 10);
    if (errno || !end || *end || parsed < minimum || parsed > maximum)
        return -1;
    *out = (int64_t)parsed;
    return 0;
}

static int apd_hostapd_parse_u64(const char *value, uint64_t *out)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!value || !value[0] || isspace((unsigned char)value[0]) ||
        value[0] == '-')
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno || !end || *end || parsed > (unsigned long long)INT64_MAX)
        return -1;
    *out = (uint64_t)parsed;
    return 0;
}

static int apd_hostapd_socket_path(const char *directory, const char *name,
                                   char *path, size_t path_len)
{
    int written;

    if (!directory || !name || !path || !path_len)
        return -1;
    written = snprintf(path, path_len, "%s/%s", directory, name);
    return written < 0 || (size_t)written >= path_len ? -1 : 0;
}

static int apd_hostapd_uid_trusted(uid_t uid)
{
    struct passwd account;
    struct passwd *result = NULL;
    char buffer[1024];

    if (uid == APD_HOSTAPD_EXPECTED_UID ||
        (APD_HOSTAPD_SERVICE_UID != (uid_t)-1 &&
         uid == APD_HOSTAPD_SERVICE_UID))
        return 1;
    return getpwnam_r(APD_HOSTAPD_SERVICE_USER, &account, buffer,
                      sizeof(buffer), &result) == 0 &&
           result && result->pw_uid == uid;
}

static int apd_hostapd_service_gid(gid_t *gid)
{
    struct passwd account;
    struct passwd *result = NULL;
    char buffer[1024];

    if (!gid)
        return -1;
    if (APD_HOSTAPD_SERVICE_GID != (gid_t)-1) {
        *gid = APD_HOSTAPD_SERVICE_GID;
        return 0;
    }
    if (getpwnam_r(APD_HOSTAPD_SERVICE_USER, &account, buffer,
                   sizeof(buffer), &result) != 0 || !result)
        return -1;
    *gid = result->pw_gid;
    return 0;
}

static int apd_hostapd_control_dir_available(void)
{
    struct stat st;

    return lstat(APD_HOSTAPD_RUN_DIR, &st) == 0 && S_ISDIR(st.st_mode) &&
           apd_hostapd_uid_trusted(st.st_uid) &&
           !(st.st_mode & (S_IWGRP | S_IWOTH));
}

/* Control paths may be owned by root or OpenWrt's named hostapd service user.
 * Arbitrary UIDs and group/world-writable directories remain rejected. */
static int apd_hostapd_dir_trusted(const char *path)
{
    struct stat st;

    return path && lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           apd_hostapd_uid_trusted(st.st_uid) &&
           !(st.st_mode & (S_IWGRP | S_IWOTH));
}

/* Read the per-BSS runtime configuration generated by hostapd/netifd.  The
 * control directory is configuration evidence, not a guessed QSDK layout.
 * Only a root-owned, non-writable, regular file and a trusted control
 * directory are accepted. */
static int apd_hostapd_conf_control_dir(const char *interface,
                                        char *out, size_t out_len,
                                        struct apd_hostapd_bss_observation *bss)
{
    char path[PATH_MAX];
    char buffer[4096];
    struct stat st;
    ssize_t length;
    char *line;
    char *saveptr = NULL;
    int fd;

    if (!apd_hostapd_safe_name(interface) || !out || out_len == 0 ||
        snprintf(path, sizeof(path), "%s%s.conf", APD_HOSTAPD_CONF_PREFIX,
                 interface) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        !apd_hostapd_uid_trusted(st.st_uid) ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(fd);
        return -1;
    }
    length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0 || length >= (ssize_t)sizeof(buffer) - 1)
        return -1;
    buffer[length] = '\0';
    for (line = strtok_r(buffer, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        static const char ctrl_prefix[] = "ctrl_interface=";
        const char *value;
        size_t value_len;

        while (*line == ' ' || *line == '\t')
            line++;
        if (!strncmp(line, "ieee80211r=", 11)) {
            if (bss && !strcmp(line + 11, "1"))
                bss->ft_configured = 1;
            if (bss && !bss->ft_reason[0])
                snprintf(bss->ft_reason, sizeof(bss->ft_reason),
                         "hostapd_ft_%s",
                         bss->ft_configured ? "configured" : "not_configured");
            continue;
        }
        if (!strncmp(line, "ft_over_ds=", 11)) {
            if (bss && !strcmp(line + 11, "1"))
                bss->ft_over_ds = 1;
            if (bss && !bss->ft_reason[0])
                snprintf(bss->ft_reason, sizeof(bss->ft_reason),
                         "hostapd_ft_over_ds_%s",
                         bss->ft_over_ds ? "enabled" : "disabled");
            continue;
        }
        if (!strncmp(line, "ieee80211k=", 11)) {
            if (bss && !strcmp(line + 11, "1"))
                bss->neighbor_report_80211k = 1;
            if (bss && !bss->neighbor_report_reason[0])
                snprintf(bss->neighbor_report_reason,
                         sizeof(bss->neighbor_report_reason),
                         "hostapd_config_%s",
                         bss->neighbor_report_80211k ?
                         "enabled" : "disabled");
            continue;
        }
        if (!strncmp(line, "ieee80211v=", 11) ||
            !strncmp(line, "bss_transition=", 15)) {
            if (bss && (!strcmp(line + 11, "1") ||
                        !strcmp(line + 15, "1")))
                bss->bss_transition_80211v = 1;
            if (bss && !bss->bss_transition_reason[0])
                snprintf(bss->bss_transition_reason,
                         sizeof(bss->bss_transition_reason),
                         "hostapd_config_%s",
                         bss->bss_transition_80211v ?
                         "enabled" : "disabled");
            continue;
        }
        if (!strncmp(line, "rrm_neighbor_report=", 20)) {
            if (bss && !strcmp(line + 20, "1"))
                bss->neighbor_database_configured = 1;
            if (bss && !bss->neighbor_report_reason[0])
                snprintf(bss->neighbor_report_reason,
                         sizeof(bss->neighbor_report_reason),
                         "hostapd_config_%s",
                         bss->neighbor_database_configured ?
                         "enabled" : "disabled");
            continue;
        }
        if (!strncmp(line, "mobility_domain=", 16)) {
            /* mobility_domain is present, FT is configured. */
            if (bss)
                bss->ft_configured = 1;
            if (bss && !bss->ft_reason[0])
                snprintf(bss->ft_reason, sizeof(bss->ft_reason),
                         "hostapd_ft_configured_via_mobility_domain");
            continue;
        }
        if (strncmp(line, ctrl_prefix, sizeof(ctrl_prefix) - 1))
            continue;
        value = line + sizeof(ctrl_prefix) - 1;
        value_len = strcspn(value, " \t\r");
        if (!value_len || value_len >= out_len)
            return -1;
        memcpy(out, value, value_len);
        out[value_len] = '\0';
        if (!apd_hostapd_dir_trusted(out))
            return -1;
    }
    if (bss) {
        snprintf(bss->ft_reason, sizeof(bss->ft_reason), "%s",
                 bss->ft_configured ? "hostapd_ft_configured" :
                                      "hostapd_ft_not_configured");
    }
    return out[0] ? 0 : -1;
}

/*
 * Collects the QSDK per-radio control directories (`/var/run/hostapd-wifiN`).
 * Only names starting with the vendor prefix and holding a trusted directory
 * are accepted, and the count is bounded. Returns the number appended.
 */
static size_t apd_hostapd_vendor_dirs(char (*out)[APD_HOSTAPD_DIR_LEN],
                                      size_t out_limit)
{
    DIR *parent = opendir(APD_HOSTAPD_RUN_DIR_PARENT);
    struct dirent *entry;
    size_t found = 0;
    size_t prefix_len = strlen(APD_HOSTAPD_VENDOR_DIR_PREFIX);

    if (!parent || !out || out_limit == 0) {
        if (parent)
            closedir(parent);
        return 0;
    }
    while ((entry = readdir(parent)) != NULL && found < out_limit) {
        char path[PATH_MAX];

        if (entry->d_name[0] == '.')
            continue;
        if (strncmp(entry->d_name, APD_HOSTAPD_VENDOR_DIR_PREFIX, prefix_len))
            continue;
        /* The suffix must be a plain interface-ish token; this rejects
         * `hostapd-global.pid` and similar non-directory siblings early. */
        if (!entry->d_name[prefix_len] ||
            !apd_hostapd_safe_name(entry->d_name + prefix_len))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", APD_HOSTAPD_RUN_DIR_PARENT,
                     entry->d_name) >= (int)sizeof(path))
            continue;
        if (!apd_hostapd_dir_trusted(path))
            continue;
        /* Skip anything that cannot round-trip through sun_path rather than
         * storing a truncated directory we would fail to dial later. */
        if ((size_t)snprintf(out[found], APD_HOSTAPD_DIR_LEN, "%s", path) >=
            APD_HOSTAPD_DIR_LEN)
            continue;
        found++;
    }
    closedir(parent);
    return found;
}

static int apd_hostapd_local_dir_prepare(void)
{
    struct stat st;
    gid_t service_gid;

    if (apd_hostapd_service_gid(&service_gid) != 0)
        return -1;

    if (lstat(APD_HOSTAPD_LOCAL_DIR, &st) != 0) {
        if (errno != ENOENT || mkdir(APD_HOSTAPD_LOCAL_DIR, 0750) != 0)
            return -1;
        if (lstat(APD_HOSTAPD_LOCAL_DIR, &st) != 0)
            return -1;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() ||
        (st.st_mode & S_IRWXO))
        return -1;
    if (st.st_gid != service_gid && chown(APD_HOSTAPD_LOCAL_DIR, (uid_t)-1,
                                          service_gid) != 0)
        return -1;
    if ((st.st_mode & 0777) != 0750 && chmod(APD_HOSTAPD_LOCAL_DIR, 0750) != 0)
        return -1;
    if (lstat(APD_HOSTAPD_LOCAL_DIR, &st) != 0)
        return -1;
    return S_ISDIR(st.st_mode) && st.st_uid == getuid() &&
           st.st_gid == service_gid && (st.st_mode & 0777) == 0750 ? 0 : -1;
}

static void apd_hostapd_clear(void *data, size_t length)
{
    volatile unsigned char *bytes = data;

    while (bytes && length--)
        *bytes++ = 0;
}

/*
 * Which step of the control-socket exchange failed.
 *
 * Every failure path in apd_hostapd_request() used to collapse into one
 * APD_HOSTAPD_REQUEST_FAILED, which the caller then rendered as the single
 * reason "hostapd_station_query_failed". On a QSDK AP that string appeared on
 * 15 BSSes while 29 stations had in fact been collected, so a reader could
 * neither tell what went wrong nor that most of the data was good. Recording
 * the stage lets the reason name the actual cause.
 */
enum apd_hostapd_stage {
    APD_HOSTAPD_STAGE_NONE = 0,
    APD_HOSTAPD_STAGE_ARGUMENTS,
    APD_HOSTAPD_STAGE_SOCKET,
    APD_HOSTAPD_STAGE_CLOEXEC,
    APD_HOSTAPD_STAGE_LOCAL_PATH,
    APD_HOSTAPD_STAGE_BIND,
    APD_HOSTAPD_STAGE_LOCAL_VERIFY,
    APD_HOSTAPD_STAGE_CHMOD,
    APD_HOSTAPD_STAGE_CONNECT,
    APD_HOSTAPD_STAGE_SEND,
    APD_HOSTAPD_STAGE_POLL,
    APD_HOSTAPD_STAGE_RECV,
    APD_HOSTAPD_STAGE_RESPONSE_EMBEDDED_NUL,
};

static const char *apd_hostapd_stage_reason(enum apd_hostapd_stage stage,
                                            const char *operation)
{
    int station = operation && strcmp(operation, "status") != 0;

    switch (stage) {
    case APD_HOSTAPD_STAGE_NONE:
        break;
    case APD_HOSTAPD_STAGE_ARGUMENTS:
        return "hostapd_request_arguments_invalid";
    case APD_HOSTAPD_STAGE_SOCKET:
        return "hostapd_local_socket_create_failed";
    case APD_HOSTAPD_STAGE_CLOEXEC:
        return "hostapd_local_socket_cloexec_failed";
    case APD_HOSTAPD_STAGE_LOCAL_PATH:
        return "hostapd_local_socket_path_too_long";
    case APD_HOSTAPD_STAGE_BIND:
        return "hostapd_local_socket_bind_failed";
    case APD_HOSTAPD_STAGE_LOCAL_VERIFY:
        return "hostapd_local_socket_untrusted";
    case APD_HOSTAPD_STAGE_CHMOD:
        return "hostapd_local_socket_chmod_failed";
    case APD_HOSTAPD_STAGE_CONNECT:
        return "hostapd_control_socket_connect_failed";
    case APD_HOSTAPD_STAGE_SEND:
        return "hostapd_control_socket_send_failed";
    case APD_HOSTAPD_STAGE_POLL:
        return "hostapd_control_socket_poll_failed";
    case APD_HOSTAPD_STAGE_RECV:
        return station ? "hostapd_station_response_read_failed" :
                         "hostapd_status_response_read_failed";
    case APD_HOSTAPD_STAGE_RESPONSE_EMBEDDED_NUL:
        return station ? "hostapd_station_response_malformed" :
                         "hostapd_status_response_malformed";
    }
    return NULL;
}

static int apd_hostapd_request(const char *remote_path, const char *command,
                               char *response, size_t response_capacity,
                               size_t *response_len,
                               int64_t collection_deadline,
                               enum apd_hostapd_stage *stage_out)
{
    struct sockaddr_un local = { .sun_family = AF_UNIX };
    struct sockaddr_un remote = { .sun_family = AF_UNIX };
    struct stat local_st = { 0 };
    struct stat cleanup_st;
    struct pollfd pfd;
    struct iovec iov;
    struct msghdr msg;
    int fd = -1;
    int64_t deadline;
    int rc = APD_HOSTAPD_REQUEST_FAILED;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    int bound = 0;
    int local_verified = 0;
    gid_t service_gid;
    int written;
    ssize_t received;
    size_t command_len;

    if (stage_out)
        *stage_out = APD_HOSTAPD_STAGE_NONE;
    if (!remote_path || !command || !response || response_capacity < 2 ||
        !response_len || strlen(remote_path) >= sizeof(remote.sun_path)) {
        if (stage_out)
            *stage_out = APD_HOSTAPD_STAGE_ARGUMENTS;
        return APD_HOSTAPD_REQUEST_FAILED;
    }
    if (apd_hostapd_service_gid(&service_gid) != 0 ||
        apd_hostapd_local_dir_prepare() != 0) {
        if (stage_out)
            *stage_out = APD_HOSTAPD_STAGE_LOCAL_VERIFY;
        return APD_HOSTAPD_REQUEST_FAILED;
    }
    command_len = strlen(command);
    if (!command_len || command_len > 512U ||
        strchr(command, '\n') || strchr(command, '\r')) {
        if (stage_out)
            *stage_out = APD_HOSTAPD_STAGE_ARGUMENTS;
        return APD_HOSTAPD_REQUEST_FAILED;
    }
    memcpy(remote.sun_path, remote_path, strlen(remote_path) + 1);
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        if (stage_out)
            *stage_out = APD_HOSTAPD_STAGE_SOCKET;
        return APD_HOSTAPD_REQUEST_FAILED;
    }
    stage = APD_HOSTAPD_STAGE_CLOEXEC;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
        goto done;
    written = snprintf(local.sun_path, sizeof(local.sun_path),
                       "%s/dreamingwrt-apd-%ld-%d", APD_HOSTAPD_LOCAL_DIR,
                       (long)getpid(), fd);
    stage = APD_HOSTAPD_STAGE_LOCAL_PATH;
    if (written < 0 || (size_t)written >= sizeof(local.sun_path))
        goto done;
    stage = APD_HOSTAPD_STAGE_BIND;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0)
        goto done;
    bound = 1;
    stage = APD_HOSTAPD_STAGE_LOCAL_VERIFY;
    if (lstat(local.sun_path, &local_st) != 0 || !S_ISSOCK(local_st.st_mode) ||
        local_st.st_uid != getuid())
        goto done;
    local_verified = 1;
    stage = APD_HOSTAPD_STAGE_CHMOD;
    if (chown(local.sun_path, (uid_t)-1, service_gid) != 0 ||
        chmod(local.sun_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) != 0 ||
        lstat(local.sun_path, &local_st) != 0 || !S_ISSOCK(local_st.st_mode) ||
        local_st.st_uid != getuid() || local_st.st_gid != service_gid ||
        (local_st.st_mode & 0777) != 0660)
        goto done;
    stage = APD_HOSTAPD_STAGE_CONNECT;
    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) != 0)
        goto done;
    stage = APD_HOSTAPD_STAGE_SEND;
    if (send(fd, command, command_len, MSG_NOSIGNAL) != (ssize_t)command_len)
        goto done;
    deadline = apd_monotonic_ms() + APD_HOSTAPD_TIMEOUT_MS;
    if (collection_deadline > 0 && collection_deadline < deadline)
        deadline = collection_deadline;
    pfd.fd = fd;
    pfd.events = POLLIN;
    for (;;) {
        int64_t remaining = deadline - apd_monotonic_ms();
        int poll_rc;

        if (remaining <= 0) {
            rc = collection_deadline > 0 &&
                 apd_monotonic_ms() >= collection_deadline ?
                 APD_HOSTAPD_REQUEST_TOTAL_TIMEOUT : APD_HOSTAPD_REQUEST_TIMEOUT;
            goto done;
        }
        poll_rc = poll(&pfd, 1, (int)remaining);
        if (poll_rc < 0 && errno == EINTR)
            continue;
        if (poll_rc == 0) {
            rc = collection_deadline > 0 &&
                 apd_monotonic_ms() >= collection_deadline ?
                 APD_HOSTAPD_REQUEST_TOTAL_TIMEOUT : APD_HOSTAPD_REQUEST_TIMEOUT;
            goto done;
        }
        if (poll_rc < 0 || !(pfd.revents & POLLIN)) {
            stage = APD_HOSTAPD_STAGE_POLL;
            goto done;
        }
        break;
    }
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = response;
    iov.iov_len = response_capacity - 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    received = recvmsg(fd, &msg, 0);
    if (received == 0) {
        /*
         * An empty datagram is a real reply, not a read error. Whether it means
         * "end of list" or "unexpected" depends on the command, so that call is
         * left to the caller.
         */
        rc = APD_HOSTAPD_REQUEST_EMPTY;
        *response_len = 0;
        response[0] = '\0';
        goto done;
    }
    if (received < 0) {
        stage = APD_HOSTAPD_STAGE_RECV;
        goto done;
    }
    if ((msg.msg_flags & MSG_TRUNC) || (size_t)received > APD_HOSTAPD_RESPONSE_LIMIT) {
        rc = APD_HOSTAPD_REQUEST_TOO_LARGE;
        goto done;
    }
    if (memchr(response, '\0', (size_t)received) != NULL) {
        stage = APD_HOSTAPD_STAGE_RESPONSE_EMBEDDED_NUL;
        goto done;
    }
    response[received] = '\0';
    *response_len = (size_t)received;
    rc = APD_HOSTAPD_REQUEST_OK;
    stage = APD_HOSTAPD_STAGE_NONE;

done:
    if (stage_out && rc != APD_HOSTAPD_REQUEST_OK)
        *stage_out = stage;
    if (fd >= 0)
        close(fd);
    if (bound && local_verified && lstat(local.sun_path, &cleanup_st) == 0 &&
        cleanup_st.st_dev == local_st.st_dev &&
        cleanup_st.st_ino == local_st.st_ino &&
        S_ISSOCK(cleanup_st.st_mode) && cleanup_st.st_uid == getuid())
        unlink(local.sun_path);
    return rc;
}

/*
 * Liveness probe for a control socket. These are SOCK_DGRAM, so `connect()`
 * succeeds against an abandoned inode and proves nothing; only a reply proves a
 * listener. `PING` is hostapd's own no-op command, so this reads state without
 * changing it. A timeout counts as dead: the socket exists but nothing answers.
 */
static int apd_hostapd_socket_alive(const char *directory, const char *name)
{
    char remote_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char response[64];
    size_t response_len = 0;

    if (apd_hostapd_socket_path(directory, name, remote_path,
                                sizeof(remote_path)) != 0)
        return 0;
    return apd_hostapd_request(remote_path, "PING", response, sizeof(response),
                               &response_len, 0, NULL) ==
               APD_HOSTAPD_REQUEST_OK &&
           response_len > 0;
}

static char *apd_hostapd_next_line(char **cursor)
{
    char *line;
    char *end;

    if (!cursor || !*cursor || !**cursor)
        return NULL;
    line = *cursor;
    end = strchr(line, '\n');
    if (end) {
        *end = '\0';
        *cursor = end + 1;
    } else {
        *cursor = line + strlen(line);
    }
    if (end && end > line && end[-1] == '\r')
        end[-1] = '\0';
    return line;
}

static int apd_hostapd_parse_status(char *response,
                                    struct apd_hostapd_bss_observation *bss)
{
    char *cursor = response;
    char *line;
    int recognized = 0;

    while ((line = apd_hostapd_next_line(&cursor)) != NULL) {
        char *separator = strchr(line, '=');
        const char *key;
        const char *value;
        int64_t number;

        if (!separator || separator == line)
            continue;
        *separator = '\0';
        key = line;
        value = separator + 1;
        if (!strcmp(key, "state")) {
            if (apd_hostapd_copy_text(bss->state, sizeof(bss->state), value) != 0)
                return -1;
            recognized++;
        } else if (!strcmp(key, "bssid") || !strcmp(key, "bssid[0]")) {
            if (apd_hostapd_parse_mac(value, bss->bssid) != 0)
                return -1;
            bss->has_bssid = 1;
            recognized++;
        } else if (!strcmp(key, "ssid[0]") || !strcmp(key, "ssid")) {
            if (apd_hostapd_copy_text(bss->ssid, sizeof(bss->ssid), value) != 0)
                return -1;
            bss->has_ssid = 1;
            recognized++;
        } else if (!strcmp(key, "freq")) {
            if (apd_hostapd_parse_i64(value, 1, 100000, &number) != 0)
                return -1;
            bss->frequency_mhz = (int)number;
            bss->has_frequency = 1;
            recognized++;
        } else if (!strcmp(key, "channel")) {
            if (apd_hostapd_parse_i64(value, 1, 10000, &number) != 0)
                return -1;
            bss->channel = (int)number;
            bss->has_channel = 1;
            recognized++;
        } else if (!strcmp(key, "num_sta") || !strcmp(key, "num_sta[0]")) {
            if (apd_hostapd_parse_i64(value, 0, 1000000, &number) != 0)
                return -1;
            bss->reported_station_count = (int)number;
            bss->has_reported_station_count = 1;
            recognized++;
        } else if (!strcmp(key, "mld_addr")) {
            if (apd_hostapd_parse_mac(value, bss->mld_address) != 0)
                return -1;
            bss->has_mld_address = 1;
            recognized++;
        } else if (!strcmp(key, "mld_link_id") || !strcmp(key, "link_id")) {
            if (apd_hostapd_parse_i64(value, 0, 255, &number) != 0)
                return -1;
            bss->link_id = (int)number;
            bss->has_link_id = 1;
            recognized++;
        }
    }
    bss->mlo_relation_complete = bss->has_mld_address && bss->has_link_id;
    return recognized > 0 && bss->state[0] ? 0 : -1;
}

static int apd_hostapd_parse_station(char *response,
                                     const char *interface,
                                     struct apd_hostapd_station_observation *station)
{
    char *cursor = response;
    char *line = apd_hostapd_next_line(&cursor);

    if (!line || apd_hostapd_parse_mac(line, station->mac) != 0 ||
        apd_hostapd_copy_text(station->interface, sizeof(station->interface),
                              interface) != 0)
        return -1;
    while ((line = apd_hostapd_next_line(&cursor)) != NULL) {
        char *separator = strchr(line, '=');
        const char *key;
        const char *value;
        int64_t signed_number;
        uint64_t number;

        if (!separator || separator == line)
            continue;
        *separator = '\0';
        key = line;
        value = separator + 1;
        if (!strcmp(key, "flags")) {
            station->has_flags = 1;
            station->authenticated = strstr(value, "[AUTH]") != NULL;
            station->associated = strstr(value, "[ASSOC]") != NULL;
            station->authorized = strstr(value, "[AUTHORIZED]") != NULL;
        } else if (!strcmp(key, "extended_capabilities") ||
                   !strcmp(key, "ext_capab")) {
            size_t length = strlen(value);

            station->has_extended_capabilities = 1;
            station->station_btm_capable = length >= 6 &&
                isxdigit((unsigned char)value[4]) &&
                isxdigit((unsigned char)value[5]) &&
                (strtoul((char[]){ value[4], value[5], '\0' }, NULL, 16) & 0x08);
            snprintf(station->station_btm_reason,
                     sizeof(station->station_btm_reason), "%s",
                     station->station_btm_capable ?
                         "station_extended_capabilities_btm_supported" :
                         "station_extended_capabilities_btm_not_supported");
        } else if (!strcmp(key, "signal")) {
            if (apd_hostapd_parse_i64(value, -200, 100, &signed_number) != 0)
                return -1;
            station->signal_dbm = (int)signed_number;
            station->has_signal = 1;
        } else if (!strcmp(key, "rx_bytes")) {
            if (apd_hostapd_parse_u64(value, &number) != 0)
                return -1;
            station->rx_bytes = number;
            station->has_rx_bytes = 1;
        } else if (!strcmp(key, "tx_bytes")) {
            if (apd_hostapd_parse_u64(value, &number) != 0)
                return -1;
            station->tx_bytes = number;
            station->has_tx_bytes = 1;
        } else if (!strcmp(key, "rx_packets")) {
            if (apd_hostapd_parse_u64(value, &number) != 0)
                return -1;
            station->rx_packets = number;
            station->has_rx_packets = 1;
        } else if (!strcmp(key, "tx_packets")) {
            if (apd_hostapd_parse_u64(value, &number) != 0)
                return -1;
            station->tx_packets = number;
            station->has_tx_packets = 1;
        } else if (!strcmp(key, "connected_time")) {
            if (apd_hostapd_parse_u64(value, &number) != 0)
                return -1;
            station->connected_time_seconds = number;
            station->has_connected_time = 1;
        } else if (!strcmp(key, "inactive_msec")) {
            if (apd_hostapd_parse_u64(value, &number) != 0)
                return -1;
            station->inactive_time_ms = number;
            station->has_inactive_time = 1;
        } else if (!strcmp(key, "mld_addr")) {
            if (apd_hostapd_parse_mac(value, station->mld_address) != 0)
                return -1;
            station->has_mld_address = 1;
        } else if (!strcmp(key, "link_id")) {
            if (apd_hostapd_parse_i64(value, 0, 255, &signed_number) != 0)
                return -1;
            station->link_id = (int)signed_number;
            station->has_link_id = 1;
        }
    }
    station->mlo_relation_complete = station->has_mld_address &&
                                     station->has_link_id;
    if (!station->has_extended_capabilities)
        snprintf(station->station_btm_reason,
                 sizeof(station->station_btm_reason),
                 "station_extended_capabilities_not_reported");
    return 0;
}

static int apd_hostapd_is_fail(const char *response)
{
    return response && (!strcmp(response, "FAIL\n") || !strcmp(response, "FAIL"));
}

static int apd_hostapd_is_unknown_command(const char *response)
{
    return response && !strncmp(response, "UNKNOWN COMMAND", 15);
}

static int apd_hostapd_probe_command(const char *remote_path,
                                     const char *command,
                                     char *response, size_t response_capacity,
                                     int64_t collection_deadline,
                                     const char **reason)
{
    size_t response_len = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    int rc;

    rc = apd_hostapd_request(remote_path, command, response,
                             response_capacity, &response_len,
                             collection_deadline, &stage);
    if (rc != APD_HOSTAPD_REQUEST_OK) {
        if (reason)
            *reason = "hostapd_capability_probe_failed";
        return 0;
    }
    if (apd_hostapd_is_unknown_command(response)) {
        if (reason)
            *reason = "hostapd_command_unsupported";
        return 0;
    }
    if (reason)
        *reason = "hostapd_command_supported";
    return 1;
}

static const char *apd_hostapd_request_reason(int rc, const char *operation,
                                             enum apd_hostapd_stage stage)
{
    if (rc == APD_HOSTAPD_REQUEST_TOTAL_TIMEOUT)
        return "hostapd_collection_timeout";
    if (rc == APD_HOSTAPD_REQUEST_TIMEOUT)
        return !strcmp(operation, "status") ? "hostapd_status_timeout" :
                                               "hostapd_station_timeout";
    if (rc == APD_HOSTAPD_REQUEST_TOO_LARGE)
        return !strcmp(operation, "status") ? "hostapd_status_response_too_large" :
                                               "hostapd_station_response_too_large";
    /*
     * Only STATUS reaches here with an empty reply; the station walk treats it
     * as end-of-list before asking for a reason.
     */
    if (rc == APD_HOSTAPD_REQUEST_EMPTY)
        return !strcmp(operation, "status") ? "hostapd_status_response_empty" :
                                              "hostapd_station_response_empty";
    /*
     * Prefer the stage-specific cause. The generic strings below remain only as
     * a last resort for a failure that recorded no stage at all, so a caller
     * never sees "query_failed" when the real cause is known.
     */
    {
        const char *staged = apd_hostapd_stage_reason(stage, operation);

        if (staged)
            return staged;
    }
    return !strcmp(operation, "status") ? "hostapd_status_query_failed" :
                                           "hostapd_station_query_failed";
}

/* SHOW_NEIGHBOR may include optional subelements and a trailing "stat".
 * Keep the fixed report body; a truncated/malformed table is never complete. */
static int apd_hostapd_neighbors_parse(char *response,
                                      struct apd_hostapd_bss_observation *bss)
{
    char *line, *save = NULL;

    bss->neighbor_count = 0;
    bss->neighbors_complete = 0;
    if (apd_hostapd_is_fail(response) || apd_hostapd_is_unknown_command(response))
        return -1;
    for (line = strtok_r(response, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        struct apd_hostapd_neighbor item = {0};
        char mac[18], report[511];
        size_t i, length;
        int consumed = 0;

        if (bss->neighbor_count >= APD_HOSTAPD_NEIGHBOR_LIMIT ||
            sscanf(line, "%17s ssid=%64[0-9a-fA-F] nr=%510[0-9a-fA-F]%n",
                   mac, item.ssid_hex, report, &consumed) != 3 ||
            !consumed || (line[consumed] && line[consumed] != ' ') ||
            apd_hostapd_parse_mac(mac, item.bssid) != 0)
            return -1;
        length = strlen(report);
        if (length < 26 || length % 2 || strlen(item.ssid_hex) % 2)
            return -1;
        for (i = 0; i < 12; i++)
            if (tolower((unsigned char)report[i]) != item.bssid[i + i / 2])
                return -1;
        for (i = 0; i < 26; i++)
            item.report[i] = (char)tolower((unsigned char)report[i]);
        for (i = 0; item.ssid_hex[i]; i++)
            item.ssid_hex[i] = (char)tolower((unsigned char)item.ssid_hex[i]);
        bss->neighbors[bss->neighbor_count++] = item;
    }
    bss->neighbors_complete = 1;
    return 0;
}

#if !defined(APD_HOSTAPD_STANDALONE_TEST) || defined(APD_ROAMING_STANDALONE_TEST)
static struct json_object *apd_hostapd_neighbors_json(
    const struct apd_hostapd_bss_observation *bss)
{
    struct json_object *rows = json_object_new_array();
    size_t i;

    for (i = 0; i < bss->neighbor_count; i++) {
        const struct apd_hostapd_neighbor *raw = &bss->neighbors[i];
        struct json_object *row = json_object_new_object();

        json_object_object_add(row, "bssid", json_object_new_string(raw->bssid));
        json_object_object_add(row, "ssid_hex", json_object_new_string(raw->ssid_hex));
        json_object_object_add(row, "report", json_object_new_string(raw->report));
        json_object_array_add(rows, row);
    }
    return rows;
}
#endif

static int apd_hostapd_collect_bss(const char *remote_path,
                                   struct apd_hostapd_observation *result,
                                   struct apd_hostapd_bss_observation *bss,
                                   char *response, size_t response_capacity,
                                   int64_t collection_deadline)
{
    char command[64];
    char previous_mac[APD_HOSTAPD_MAC_LEN + 1] = { 0 };
    const char *probe_reason = NULL;
    size_t response_len = 0;
    int rc;
    int partial_mlo = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;

    rc = apd_hostapd_request(remote_path, "STATUS", response,
                             response_capacity, &response_len,
                             collection_deadline, &stage);
    if (rc != APD_HOSTAPD_REQUEST_OK) {
        apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                               apd_hostapd_request_reason(rc, "status", stage));
        return -1;
    }
    if (apd_hostapd_is_unknown_command(response)) {
        apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                               "hostapd_status_query_unsupported");
        return -1;
    }
    if (apd_hostapd_is_fail(response) ||
        apd_hostapd_parse_status(response, bss) != 0) {
        apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                               "hostapd_status_malformed");
        return -1;
    }
    bss->hostapd_ctrl_reachable = 1;
    snprintf(bss->control_path, sizeof(bss->control_path), "%s", remote_path);

    bss->neighbor_report_80211k = apd_hostapd_probe_command(
        remote_path, "REQ_BEACON ", response, response_capacity,
        collection_deadline, &probe_reason);
    snprintf(bss->neighbor_report_reason,
             sizeof(bss->neighbor_report_reason), "%s", probe_reason);
    if (bss->neighbor_report_80211k && apd_hostapd_probe_command(
            remote_path, "SHOW_NEIGHBOR", response, response_capacity,
            collection_deadline, &probe_reason)) {
        bss->neighbor_database_configured = !apd_hostapd_is_fail(response);
        if (bss->neighbor_database_configured)
            apd_hostapd_neighbors_parse(response, bss);
        snprintf(bss->neighbor_report_reason,
                 sizeof(bss->neighbor_report_reason), "%s",
                 bss->neighbor_database_configured ?
                     "hostapd_neighbor_database_available" :
                     "hostapd_command_supported_neighbor_database_unavailable");
    }

    bss->bss_transition_80211v = apd_hostapd_probe_command(
        remote_path, "BSS_TM_REQ ", response, response_capacity,
        collection_deadline, &probe_reason);
    snprintf(bss->bss_transition_reason,
             sizeof(bss->bss_transition_reason), "%s", probe_reason);

    bss->client_deauth = apd_hostapd_probe_command(
        remote_path, "DEAUTHENTICATE ", response, response_capacity,
        collection_deadline, &probe_reason);
    snprintf(bss->client_deauth_reason,
             sizeof(bss->client_deauth_reason), "%s", probe_reason);
    bss->reassoc_block = 0;
    if (result->reassoc_backend_safe &&
        !bss->has_mld_address && !bss->has_link_id) {
        rc = apd_hostapd_request(
            remote_path, "DENY_ACL SHOW", response, response_capacity, &response_len,
            collection_deadline, &stage);
        bss->reassoc_block = (rc == APD_HOSTAPD_REQUEST_OK ||
                              rc == APD_HOSTAPD_REQUEST_EMPTY) &&
            !apd_hostapd_is_fail(response) &&
            !apd_hostapd_is_unknown_command(response);
    }
    if ((bss->has_mld_address || bss->has_link_id) &&
        !bss->mlo_relation_complete) {
        apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                               "hostapd_mlo_relation_partial");
        partial_mlo = 1;
    }
    bss->station_offset = result->station_count;
    for (;;) {
        struct apd_hostapd_station_observation station = { 0 };

        if (bss->station_count >= APD_HOSTAPD_STATIONS_PER_BSS_LIMIT ||
            result->station_count >= APD_HOSTAPD_STATION_LIMIT) {
            result->station_limited = 1;
            apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                                   "hostapd_station_limit_reached");
            return -1;
        }
        if (!previous_mac[0]) {
            snprintf(command, sizeof(command), "STA-FIRST");
        } else if (snprintf(command, sizeof(command), "STA-NEXT %s",
                            previous_mac) >= (int)sizeof(command)) {
            apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                                   "hostapd_station_cursor_invalid");
            return -1;
        }
        response_len = 0;
        rc = apd_hostapd_request(remote_path, command, response,
                                 response_capacity, &response_len,
                                 collection_deadline, &stage);
        /*
         * Two spellings of "no more stations".
         *
         * Mainline hostapd answers "FAIL"; the QSDK build on this AP replies
         * with a zero-length datagram instead. Verified on 31.31, where every
         * VAP ended its walk this way - ath01 after 21 stations, ath02 on the
         * very first STA-FIRST. Treating the empty reply as a read failure made
         * all 14 BSSes report incomplete even though 29 stations had been read,
         * so the end-of-list case is handled here alongside FAIL.
         */
        if (rc == APD_HOSTAPD_REQUEST_EMPTY)
            goto end_of_list;
        if (rc != APD_HOSTAPD_REQUEST_OK) {
            apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                                   apd_hostapd_request_reason(rc, "station",
                                                              stage));
            return -1;
        }
        if (apd_hostapd_is_unknown_command(response)) {
            apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                                   "hostapd_station_query_unsupported");
            return -1;
        }
        if (apd_hostapd_is_fail(response)) {
end_of_list:
            if (bss->has_reported_station_count &&
                bss->reported_station_count != (int)bss->station_count) {
                apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                                       "hostapd_station_count_mismatch");
                return -1;
            }
            bss->complete = !partial_mlo;
            return partial_mlo ? -1 : 0;
        }
        if (apd_hostapd_parse_station(response, bss->interface, &station) != 0 ||
            !strcmp(previous_mac, station.mac)) {
            apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                                   "hostapd_station_malformed");
            return -1;
        }
        if ((station.has_mld_address || station.has_link_id) &&
            !station.mlo_relation_complete) {
            apd_hostapd_set_reason(bss->reason, sizeof(bss->reason),
                                   "hostapd_mlo_relation_partial");
            partial_mlo = 1;
        }
        result->stations[result->station_count++] = station;
        bss->station_count++;
        snprintf(previous_mac, sizeof(previous_mac), "%s", station.mac);
    }
}

static int apd_hostapd_collect_raw(int phy_count,
                                   struct apd_hostapd_observation *result)
{
    DIR *dir;
    struct dirent *entry;
    struct stat dir_st;
    char names[APD_HOSTAPD_BSS_LIMIT][APD_HOSTAPD_IFACE_LEN + 1];
    /* Directory each socket in `names` lives in, so a VAP found in a vendor
     * per-radio directory is reconnected there rather than in the main one. */
    char dirs[APD_HOSTAPD_BSS_LIMIT][APD_HOSTAPD_DIR_LEN];
    char scan_dirs[APD_HOSTAPD_VENDOR_DIR_LIMIT + 1][APD_HOSTAPD_DIR_LEN];
    size_t scan_dir_count = 0;
    char *response;
    size_t scanned = 0;
    size_t name_count = 0;
    size_t i;
    int64_t collection_deadline;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (phy_count == 0) {
        result->directory_available = apd_hostapd_control_dir_available();
        result->complete = 1;
        apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                               "no_phy_detected");
        return 0;
    }
    if (lstat(APD_HOSTAPD_RUN_DIR, &dir_st) != 0) {
        apd_hostapd_set_reason(result->reason, sizeof(result->reason),
            phy_count == 0 ? "no_phy_detected" : "control_directory_unavailable");
        return -1;
    }
    if (!S_ISDIR(dir_st.st_mode) ||
        !apd_hostapd_uid_trusted(dir_st.st_uid) ||
        (dir_st.st_mode & (S_IWGRP | S_IWOTH))) {
        apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                               "control_directory_untrusted");
        return -1;
    }
    if (apd_hostapd_local_dir_prepare() != 0) {
        apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                               "local_control_directory_untrusted");
        return -1;
    }
    result->reassoc_backend_safe = apd_hostapd_reassoc_backend_safe();
    /* Main run directory first, then the vendor per-radio directories. On
     * mainline OpenWrt the vendor scan finds nothing and behavior is unchanged;
     * on QSDK it is where every per-interface socket actually lives. */
    snprintf(scan_dirs[0], APD_HOSTAPD_DIR_LEN, "%s", APD_HOSTAPD_RUN_DIR);
    scan_dir_count = 1;
    scan_dir_count += apd_hostapd_vendor_dirs(&scan_dirs[1],
                                              APD_HOSTAPD_VENDOR_DIR_LIMIT);
    for (i = 0; i < scan_dir_count; i++) {
        const char *scan_dir = scan_dirs[i];

        dir = opendir(scan_dir);
        if (!dir) {
            /* The main directory failing is fatal; a vendor directory that
             * vanished between listing and opening is not. */
            if (i == 0) {
                apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                                       "control_directory_unavailable");
                return -1;
            }
            continue;
        }
        if (i == 0)
            result->directory_available = 1;
        while ((entry = readdir(dir)) != NULL) {
            char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
            struct stat st;
            size_t name_len;

            if (entry->d_name[0] == '.')
                continue;
            if (++scanned > APD_HOSTAPD_SOCKET_SCAN_LIMIT) {
                result->socket_scan_limited = 1;
                break;
            }
            if (apd_hostapd_socket_path(scan_dir, entry->d_name,
                                        path, sizeof(path)) != 0 ||
                lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) ||
                !apd_hostapd_uid_trusted(st.st_uid))
                continue;
            if (!strcmp(entry->d_name, "global")) {
                result->global_control = 1;
                continue;
            }
            if (!apd_hostapd_safe_name(entry->d_name))
                continue;
            name_len = strlen(entry->d_name);
            if (name_len >= sizeof(names[0]))
                continue;
            /* The same VAP name can appear in more than one directory; count
             * and dial it once. */
            {
                size_t seen;
                int duplicate = 0;

                for (seen = 0; seen < name_count; seen++) {
                    if (!strcmp(names[seen], entry->d_name)) {
                        duplicate = 1;
                        break;
                    }
                }
                if (duplicate)
                    continue;
            }
            result->interface_controls++;
            if (name_count >= APD_HOSTAPD_BSS_LIMIT) {
                result->bss_limited = 1;
                continue;
            }
            memcpy(names[name_count], entry->d_name, name_len + 1);
            /* scan_dirs[] and dirs[] rows have identical extent, so this always
             * fits. Copying rather than formatting keeps the compiler from
             * treating scan_dir as a pointer into the flat scan_dirs array,
             * where the apparent source bound is every remaining row at once. */
            memcpy(dirs[name_count], scan_dir, APD_HOSTAPD_DIR_LEN);
            dirs[name_count][APD_HOSTAPD_DIR_LEN - 1] = '\0';
            name_count++;
        }
        closedir(dir);
        if (result->socket_scan_limited)
            break;
    }
    result->available = result->interface_controls > 0;
    if (!name_count) {
        if (phy_count == 0) {
            result->complete = 1;
            apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                                   "no_phy_detected");
        } else if (result->global_control) {
            /*
             * A `global` socket alone used to be read as "hostapd is running
             * but exposes no per-interface control". That inference is wrong
             * when hostapd has exited and left the socket behind: lstat only
             * proves the inode exists, not that anything is listening. Connect
             * to it, and if nothing accepts, report the stale socket for what
             * it is instead of an unavailable control interface.
             */
            apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                apd_hostapd_socket_alive(APD_HOSTAPD_RUN_DIR, "global") ?
                    "per_interface_control_unavailable" :
                    "hostapd_control_socket_stale");
        } else {
            apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                                   "control_sockets_unavailable");
        }
        return result->complete ? 0 : -1;
    }
    /* names[] and dirs[] are parallel, so they are ordered together. qsort on
     * names alone would leave each socket pointing at another's directory. */
    for (i = 1; i < name_count; i++) {
        char name_key[APD_HOSTAPD_IFACE_LEN + 1];
        char dir_key[APD_HOSTAPD_DIR_LEN];
        size_t j = i;

        memcpy(name_key, names[i], sizeof(name_key));
        memcpy(dir_key, dirs[i], sizeof(dir_key));
        while (j > 0 && strcmp(names[j - 1], name_key) > 0) {
            memcpy(names[j], names[j - 1], sizeof(names[0]));
            memcpy(dirs[j], dirs[j - 1], sizeof(dirs[0]));
            j--;
        }
        memcpy(names[j], name_key, sizeof(name_key));
        memcpy(dirs[j], dir_key, sizeof(dir_key));
    }
    collection_deadline = apd_monotonic_ms() + APD_HOSTAPD_COLLECTION_TIMEOUT_MS;
    response = calloc(1, APD_HOSTAPD_RESPONSE_LIMIT + 2U);
    if (!response) {
        apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                               "hostapd_collector_allocation_failed");
        return -1;
    }
    for (i = 0; i < name_count; i++) {
        char remote_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
        char configured_dir[APD_HOSTAPD_DIR_LEN];
        const char *control_dir = dirs[i];
        struct apd_hostapd_bss_observation *bss = &result->bss[result->bss_count];

        if (apd_hostapd_copy_text(bss->interface, sizeof(bss->interface),
                                  names[i]) != 0) {
            apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                                   "hostapd_interface_name_invalid");
            continue;
        }
        result->bss_count++;
        /* Prefer the runtime hostapd configuration as the authoritative
         * control location. The directory scan remains a fail-closed fallback
         * for platforms that do not expose a per-BSS generated conf file. */
        configured_dir[0] = '\0';
        if (apd_hostapd_conf_control_dir(names[i], configured_dir,
                                         sizeof(configured_dir), bss) == 0)
            control_dir = configured_dir;
        if (apd_hostapd_socket_path(control_dir, names[i], remote_path,
                                    sizeof(remote_path)) != 0 ||
            apd_hostapd_collect_bss(remote_path, result, bss, response,
                                    APD_HOSTAPD_RESPONSE_LIMIT + 2U,
                                    collection_deadline) != 0)
            apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                                   bss->reason[0] ? bss->reason :
                                                    "hostapd_control_partial");
    }
    apd_hostapd_clear(response, APD_HOSTAPD_RESPONSE_LIMIT + 2U);
    free(response);
    if (result->socket_scan_limited)
        apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                               "hostapd_socket_scan_limit_reached");
    if (result->bss_limited)
        apd_hostapd_set_reason(result->reason, sizeof(result->reason),
                               "hostapd_bss_limit_reached");
    result->complete = !result->reason[0] &&
                       result->bss_count == result->interface_controls;
    return result->complete ? 0 : -1;
}
#endif

#ifndef APD_HOSTAPD_STANDALONE_TEST
static void apd_hostapd_json_u64(struct json_object *obj, const char *name,
                                 int present, uint64_t value)
{
    if (present)
        json_object_object_add(obj, name,
                               json_object_new_int64((int64_t)value));
}

/*
 * Emits one `wlanconfig`-derived station using the same field names the
 * hostapd path emits, so the aggregator and the wireless page do not need to
 * know which collector produced the row. `source` still reports the truth.
 *
 * Signal is carried as `signal_dbm` because that is the key consumers read;
 * wlanconfig's RSSI is already combined over chains in dBm (the tool says so
 * in its own header), so no conversion is applied.
 */
static void apd_vendor_station_emit(struct json_object *stations,
                                    const struct apd_vendor_station *st,
                                    const char *interface,
                                    int64_t observed_at)
{
    struct json_object *item;

    if (!stations || !st)
        return;
    item = json_object_new_object();
    if (!item)
        return;
    json_object_object_add(item, "mac", json_object_new_string(st->mac));
    json_object_object_add(item, "interface",
                           json_object_new_string(interface ? interface : ""));
    if (st->has_rssi)
        json_object_object_add(item, "signal_dbm",
                               json_object_new_int(st->rssi));
    if (st->has_min_rssi)
        json_object_object_add(item, "min_signal_dbm",
                               json_object_new_int(st->min_rssi));
    if (st->has_max_rssi)
        json_object_object_add(item, "max_signal_dbm",
                               json_object_new_int(st->max_rssi));
    if (st->has_tx_rate)
        json_object_object_add(item, "tx_rate_kbps",
                               json_object_new_int64((int64_t)st->tx_rate_kbps));
    if (st->has_rx_rate)
        json_object_object_add(item, "rx_rate_kbps",
                               json_object_new_int64((int64_t)st->rx_rate_kbps));
    if (st->has_tx_nss)
        json_object_object_add(item, "tx_nss", json_object_new_int(st->tx_nss));
    if (st->has_rx_nss)
        json_object_object_add(item, "rx_nss", json_object_new_int(st->rx_nss));
    if (st->has_idle)
        json_object_object_add(item, "inactive_time_ms",
                               json_object_new_int64((int64_t)st->idle_ms));
    if (st->mode[0])
        json_object_object_add(item, "wifi_standard",
                               json_object_new_string(st->mode));
    if (st->aid > 0)
        json_object_object_add(item, "aid", json_object_new_int(st->aid));
    /*
     * wlanconfig lists only associated stations, so association is implied.
     * Authorization is not reported by this tool and is left absent rather
     * than guessed.
     */
    json_object_object_add(item, "associated", json_object_new_boolean(1));
    json_object_object_add(item, "mlo_evidence", json_object_new_boolean(0));
    json_object_object_add(item, "mlo_relation_complete",
                           json_object_new_boolean(0));
    json_object_object_add(item, "mlo_relation_state",
                           json_object_new_string("unavailable"));
    apd_json_nullable_string(item, "mlo_reason", "not_reported_by_wlanconfig");
    json_object_object_add(item, "source",
                           json_object_new_string("wlanconfig_list"));
    json_object_object_add(item, "stale", json_object_new_boolean(0));
    json_object_object_add(item, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_array_add(stations, item);
}

/*
 * Spatial-stream counts for one station, looked up by MAC in a vendor set.
 *
 * hostapd's station reply has no NSS columns, so a radio's MIMO width stayed
 * unreportable on APs where hostapd otherwise works fine. `wlanconfig` has
 * RXNSS/TXNSS and costs almost nothing to call, so the hostapd rows are
 * enriched rather than replaced: hostapd stays the source of the traffic and
 * MLO fields it alone reports, and this only adds what it never had.
 */
/* ---- Phase 2: 802.11k beacon reports -----------------------------------
 *
 * The controller cannot score a roaming candidate without knowing how well the
 * *station* hears it.  The AP's own view is useless for this: a candidate AP
 * never sees a client associated elsewhere, and the serving AP's RSSI says
 * nothing about the target.  802.11k beacon reports are the only source that
 * answers the actual question, because the station does the measuring.
 *
 * Flow: REQ_BEACON asks the station to measure; the answer arrives
 * asynchronously as a BEACON-RESP-RX event on an ATTACHed control socket. */

#endif
#if !defined(APD_HOSTAPD_STANDALONE_TEST) || defined(APD_ROAMING_STANDALONE_TEST)

#define APD_BEACON_REPORT_FIXED_LEN 26   /* rrm_measurement_beacon_report */
#define APD_BEACON_REPORT_HEX_LEN (APD_BEACON_REPORT_FIXED_LEN * 2U)
#define APD_BEACON_RCPI_UNAVAILABLE 255

struct apd_beacon_report {
    char bssid[18];
    int op_class;
    int channel;
    int rcpi_dbm;
    int rsni_db;
    int have_rcpi;
    int have_rsni;
};

static int apd_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decode the hex body hostapd prints after BEACON-RESP-RX.
 *
 * hostapd has already skipped the 3-byte measurement report header, so the
 * payload starts at struct rrm_measurement_beacon_report:
 *
 *   op_class(1) channel(1) start_time(8) duration(2) report_info(1)
 *   rcpi(1) rsni(1) bssid(6) antenna_id(1) parent_tsf(4)  = 26 bytes
 *
 * RCPI is defined in 0.5 dBm steps from -110 dBm (IEEE 802.11 Table 9-176),
 * so dBm = rcpi/2 - 110.  255 means the station could not measure, which is
 * NOT the same as a very weak signal and must never be scored as one.
 *
 * Returns 0 on success. */
static int apd_beacon_report_decode(const char *hex,
                                    struct apd_beacon_report *out)
{
    unsigned char raw[APD_BEACON_REPORT_FIXED_LEN];
    size_t hex_len;
    size_t i;

    if (!hex || !out)
        return -1;
    hex_len = strspn(hex, "0123456789abcdefABCDEF");
    if (hex_len < APD_BEACON_REPORT_HEX_LEN || (hex_len & 1))
        return -1;
    for (i = hex_len; hex[i]; i++) {
        if (!isspace((unsigned char)hex[i]))
            return -1;
    }
    /* Valid reports may append subelements, including a reported frame body.
     * Check their boundaries without mistaking them for a malformed body. */
    for (i = APD_BEACON_REPORT_HEX_LEN; i < hex_len;) {
        size_t bytes;

        if (hex_len - i < 4)
            return -1;
        bytes = (size_t)((apd_hex_nibble(hex[i + 2]) << 4) |
                         apd_hex_nibble(hex[i + 3]));
        i += 4 + bytes * 2;
        if (i > hex_len)
            return -1;
    }
    memset(out, 0, sizeof(*out));
    for (i = 0; i < APD_BEACON_REPORT_FIXED_LEN; i++) {
        int hi = apd_hex_nibble(hex[i * 2]);
        int lo = hi < 0 ? -1 : apd_hex_nibble(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0)
            return -1;      /* truncated or non-hex: refuse, do not guess */
        raw[i] = (unsigned char)((hi << 4) | lo);
    }
    out->op_class = raw[0];
    out->channel = raw[1];
    if (raw[13] <= 220) {
        out->rcpi_dbm = (int)raw[13] / 2 - 110;
        out->have_rcpi = 1;
    }
    if (raw[14] != APD_BEACON_RCPI_UNAVAILABLE) {
        /* RSNI is in 0.5 dB steps offset by -10 dB. */
        out->rsni_db = (int)raw[14] / 2 - 10;
        out->have_rsni = 1;
    }
    snprintf(out->bssid, sizeof(out->bssid),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             raw[15], raw[16], raw[17], raw[18], raw[19], raw[20]);
    /* A report naming no BSS measured nothing useful. */
    if (!strcmp(out->bssid, "00:00:00:00:00:00"))
        return -1;
    return 0;
}

/* Ask one station to measure one candidate channel.
 *
 * The request body is the Beacon Request element:
 *   op_class(1) channel(1) rand_interval(2 LE) duration(2 LE) mode(1) bssid(6)
 *
 * Prefer active scanning, then passive measurement, then the station's
 * existing scan table. Some clients advertise only table reporting.
 * hostapd checks the station's RRM capabilities before sending a request.
 * Only an explicit FAIL permits trying another mode; a timeout is ambiguous.
 * A wildcard BSSID asks for every BSS on the candidate channel.
 *
 * Returns the measurement token (>=0) that later BEACON-RESP-RX events carry,
 * or -1. */
static int apd_roaming_monitor_attach(const char *ctrl_path);
static int apd_phase4_station_associated(const char *ctrl_path,
                                         const char *sta_mac);
static void apd_beacon_request_record(const char *ctrl_path,
    const char *station_mac, int token, int mode);
static int apd_beacon_request_wait_previous(const char *ctrl_path,
    const char *station_mac);

static int apd_phase2_request_beacon(const char *ctrl_path, const char *sta_mac,
                                     int op_class, int channel, int duration_tu,
                                     const char *bssid, const char *ssid)
{
    static const int modes[] = { 1, 0, 2 };
    char command[256];
    char normalized[18];
    char normalized_bssid[18];
    const char *request_bssid;
    char bssid_hex[13] = "ffffffffffff";
    char response[128];
    size_t response_len = 0;
    size_t attempt;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    int rc;

    if (!ctrl_path || apd_hostapd_parse_mac(sta_mac, normalized) != 0)
        return -1;
    if (op_class <= 0 || op_class > 255 || channel <= 0 || channel > 255)
        return -1;
    if (bssid && bssid[0]) {
        size_t i;

        if (apd_hostapd_parse_mac(bssid, normalized_bssid) != 0)
            return -1;
        for (i = 0; i < 12; i++)
            bssid_hex[i] = normalized_bssid[i + i / 2];
        request_bssid = bssid_hex;
    } else {
        request_bssid = "ffffffffffff";
    }
    if (duration_tu <= 0 || duration_tu > 65535)
        duration_tu = 50;
    if (!apd_phase4_station_associated(ctrl_path, normalized) ||
        apd_roaming_monitor_attach(ctrl_path) != 0)
        return -1;
    if (apd_beacon_request_wait_previous(ctrl_path, normalized) != 0)
        return -1;
    for (attempt = 0; attempt < sizeof(modes) / sizeof(modes[0]); attempt++) {
        int64_t token;
        char *end;

        rc = snprintf(command, sizeof(command),
                      "REQ_BEACON %s %02x%02x0000%02x%02x%02x"
                      "%s",
                      normalized, op_class & 0xff, channel & 0xff,
                      duration_tu & 0xff, (duration_tu >> 8) & 0xff,
                      modes[attempt], request_bssid);
        if (rc < 0 || (size_t)rc >= sizeof(command))
            return -1;
        if (ssid && ssid[0]) {
            size_t i, length = strlen(ssid);

            if (length > 32)
                return -1;
            rc += snprintf(command + rc, sizeof(command) - (size_t)rc,
                           "00%02x", (unsigned)length);
            for (i = 0; i < length; i++)
                rc += snprintf(command + rc, sizeof(command) - (size_t)rc,
                               "%02x", (unsigned char)ssid[i]);
        }
        /* Reporting Detail 0 requests the fixed measurement, not a full beacon. */
        snprintf(command + rc, sizeof(command) - (size_t)rc, "020100");
        rc = apd_hostapd_request(ctrl_path, command, response, sizeof(response),
                                 &response_len, 0, &stage);
        if (rc != APD_HOSTAPD_REQUEST_OK)
            return -1;
        end = response + strlen(response);
        while (end > response && isspace((unsigned char)end[-1]))
            *--end = '\0';
        if (!strcmp(response, "FAIL"))
            continue;
        if (apd_hostapd_parse_i64(response, 0, 255, &token) != 0)
            return -1;
        apd_beacon_request_record(ctrl_path, normalized, (int)token,
                                  modes[attempt]);
        return (int)token;
    }
    return -1;
}

/* Beacon reports arrive asynchronously, but this backend is a synchronous
 * periodic collector with no event loop.  Rather than drag uloop in here, keep
 * the monitor socket ATTACHed across collections and drain it without blocking
 * at each pass: hostapd queues events into the socket buffer meanwhile, so
 * nothing is lost between polls, and the collector keeps its current shape. */

#define APD_BEACON_MONITORS_MAX APD_HOSTAPD_BSS_LIMIT
#define APD_BEACON_CACHE_MAX 128
#define APD_BEACON_MEASUREMENT_TTL_S 120
#define APD_PROBE_OBSERVATION_MAX 256
#define APD_PROBE_OBSERVATION_TTL_S 120
/* Cap how many probe observations are serialized into the telemetry snapshot.
 * The whole snapshot must encode under AP_CONTROL_FRAME_MAX (64 KiB); a busy AP
 * with many BSSes accumulates up to APD_PROBE_OBSERVATION_MAX entries (~268 B
 * each), which overflowed the wire frame and made every telemetry push fail at
 * stage=frame (the AP then went permanently stale on the controller). Keep the
 * newest entries only -- steering scores from recent probes -- so the frame
 * always fits. 64 * ~268 B ~= 17 KiB, well under budget beside a ~32 KiB base. */
#define APD_PROBE_OBSERVATION_EMIT_MAX 64
#define APD_PROBE_EVENT_PREFIX "RX-PROBE-REQUEST "
#ifndef APD_BEACON_SERIAL_TIMEOUT_MS
#define APD_BEACON_SERIAL_TIMEOUT_MS 3000
#endif

struct apd_beacon_monitor {
    int fd;
    char ctrl_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char local_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    dev_t device;
    ino_t inode;
};

struct apd_probe_observation {
    char station_mac[18];
    char interface[APD_HOSTAPD_IFACE_LEN + 1];
    char bssid[18];
    int rssi_dbm;
    int mac_randomized;
    int64_t observed_at;
};

struct apd_beacon_measurement {
    char station_mac[18];
    char bssid[18];
    int op_class;
    int channel;
    int rcpi_dbm;
    int rsni_db;
    int have_rsni;
    int measurement_mode;
    int64_t observed_at;
};

static struct apd_beacon_monitor g_apd_beacon_monitors[APD_BEACON_MONITORS_MAX];
static struct apd_beacon_measurement g_apd_beacon_cache[APD_BEACON_CACHE_MAX];
static size_t g_apd_beacon_cache_len;
static struct apd_probe_observation g_apd_probe_observations[APD_PROBE_OBSERVATION_MAX];
static size_t g_apd_probe_observations_len;
static pthread_mutex_t g_apd_roaming_lock = PTHREAD_MUTEX_INITIALIZER;

struct apd_beacon_request {
    char station_mac[18];
    char interface[APD_HOSTAPD_IFACE_LEN + 1];
    int token;
    int mode;
    int awaiting_response;
    int64_t deadline_ms;
};

static struct apd_beacon_request g_apd_beacon_requests[APD_BEACON_CACHE_MAX];
static size_t g_apd_beacon_requests_next;

static void apd_beacon_request_record(const char *ctrl_path,
    const char *station_mac, int token, int mode)
{
    const char *interface = strrchr(ctrl_path, '/') + 1;
    struct apd_beacon_request *slot = NULL;
    size_t i;

    for (i = 0; i < APD_BEACON_CACHE_MAX; i++) {
        if (!strcmp(g_apd_beacon_requests[i].station_mac, station_mac) &&
            !strcmp(g_apd_beacon_requests[i].interface, interface) &&
            g_apd_beacon_requests[i].token == token) {
            slot = &g_apd_beacon_requests[i];
            break;
        }
    }
    if (!slot) {
        slot = &g_apd_beacon_requests[g_apd_beacon_requests_next];
        g_apd_beacon_requests_next =
            (g_apd_beacon_requests_next + 1) % APD_BEACON_CACHE_MAX;
    }
    snprintf(slot->station_mac, sizeof(slot->station_mac), "%s", station_mac);
    snprintf(slot->interface, sizeof(slot->interface), "%s", interface);
    slot->token = token;
    slot->mode = mode;
    slot->awaiting_response = 1;
    slot->deadline_ms = apd_monotonic_ms() + APD_BEACON_SERIAL_TIMEOUT_MS;
}

static int apd_beacon_request_mode(const char *interface,
    const char *station_mac, unsigned token)
{
    size_t i;

    for (i = 0; i < APD_BEACON_CACHE_MAX; i++)
        if (!strcmp(g_apd_beacon_requests[i].station_mac, station_mac) &&
            !strcmp(g_apd_beacon_requests[i].interface, interface) &&
            g_apd_beacon_requests[i].token == (int)token)
            return g_apd_beacon_requests[i].mode;
    return -1;
}

struct apd_btm_response {
    char station_mac[18];
    char interface[APD_HOSTAPD_IFACE_LEN + 1];
    char target_bssid[18];
    int status_code;
    int64_t observed_at;
};

static struct apd_btm_response g_apd_btm_responses[APD_BEACON_CACHE_MAX];
static size_t g_apd_btm_responses_len;

static void apd_btm_response_consume(const char *line, const char *interface,
                                     int64_t now)
{
    char mac[18], normalized[18], target[18] = {0};
    const char *value;
    struct apd_btm_response *slot = NULL;
    unsigned status;
    size_t i, oldest = 0;

    if (sscanf(line, "BSS-TM-RESP %17s", mac) != 1 ||
        apd_hostapd_parse_mac(mac, normalized) != 0 ||
        !(value = strstr(line, " status_code=")) ||
        sscanf(value, " status_code=%u", &status) != 1 || status > 255)
        return;
    value = strstr(line, " target_bssid=");
    if (value && sscanf(value, " target_bssid=%17s", mac) == 1)
        apd_hostapd_parse_mac(mac, target);
    for (i = 0; i < g_apd_btm_responses_len; i++) {
        struct apd_btm_response *entry = &g_apd_btm_responses[i];

        if (!strcmp(entry->station_mac, normalized) &&
            !strcmp(entry->interface, interface)) {
            slot = entry;
            break;
        }
        if (entry->observed_at < g_apd_btm_responses[oldest].observed_at)
            oldest = i;
    }
    if (!slot)
        slot = &g_apd_btm_responses[g_apd_btm_responses_len <
            APD_BEACON_CACHE_MAX ? g_apd_btm_responses_len++ : oldest];
    snprintf(slot->station_mac, sizeof(slot->station_mac), "%s", normalized);
    snprintf(slot->interface, sizeof(slot->interface), "%s", interface);
    snprintf(slot->target_bssid, sizeof(slot->target_bssid), "%s", target);
    slot->status_code = (int)status;
    slot->observed_at = now;
}

/* ---- Item 6: hostapd auth-failure capture (event stream, not snapshot diff) --
 *
 * A station that fails authentication never enters the station dump, so the AC
 * snapshot-diff producer can never see it.  hostapd emits the failure on the
 * ATTACHed monitor socket this backend already drains every collection pass:
 *   AP-STA-POSSIBLE-PSK-MISMATCH <mac>   (WPA2/WPA3-PSK wrong key)
 *   CTRL-EVENT-EAP-FAILURE ... <mac>     (802.1X/EAP reject)
 * Both were confirmed present in the shipped wpad on a live AP.  Attribution is
 * fail-closed: an event with no parseable station MAC is dropped, never guessed. */
struct apd_auth_failure {
    char station_mac[18];
    char interface[APD_HOSTAPD_IFACE_LEN + 1];
    char reason[24];
    int count;
    int64_t observed_at;
};

static struct apd_auth_failure g_apd_auth_failures[APD_BEACON_CACHE_MAX];
static size_t g_apd_auth_failures_len;

/* First whitespace-separated token that parses as a MAC.  hostapd puts the STA
 * address in different positions per event, so scan rather than fix an offset. */
static int apd_auth_failure_first_mac(const char *rest, char out[18])
{
    char tok[64];
    int consumed = 0;

    if (!rest)
        return -1;
    while (sscanf(rest, "%63s%n", tok, &consumed) == 1 && consumed > 0) {
        if (apd_hostapd_parse_mac(tok, out) == 0)
            return 0;
        rest += consumed;
        consumed = 0;
    }
    return -1;
}

static void apd_auth_failure_consume(const char *rest, const char *interface,
                                     const char *reason, int64_t now)
{
    char normalized[18];
    struct apd_auth_failure *slot = NULL;
    size_t i, oldest = 0;

    if (!rest || !interface || !interface[0] || !reason ||
        apd_auth_failure_first_mac(rest, normalized) != 0)
        return;
    for (i = 0; i < g_apd_auth_failures_len; i++) {
        struct apd_auth_failure *entry = &g_apd_auth_failures[i];

        if (!strcmp(entry->station_mac, normalized) &&
            !strcmp(entry->interface, interface) &&
            !strcmp(entry->reason, reason)) {
            slot = entry;
            break;
        }
        if (entry->observed_at < g_apd_auth_failures[oldest].observed_at)
            oldest = i;
    }
    if (!slot) {
        slot = &g_apd_auth_failures[g_apd_auth_failures_len <
            APD_BEACON_CACHE_MAX ? g_apd_auth_failures_len++ : oldest];
        memset(slot, 0, sizeof(*slot));
    }
    snprintf(slot->station_mac, sizeof(slot->station_mac), "%s", normalized);
    snprintf(slot->interface, sizeof(slot->interface), "%s", interface);
    snprintf(slot->reason, sizeof(slot->reason), "%s", reason);
    if (slot->count < 1000000)
        slot->count++;
    slot->observed_at = now;
}

/*
 * Item 6 (WPA3-SAE coverage): a wrong SAE password fails at SAE confirm during
 * 802.11 authentication, BEFORE the 4-way handshake, so hostapd emits NO
 * wpa_ctrl string (unlike PSK, which emits AP-STA-POSSIBLE-PSK-MISMATCH). The
 * only signal is a ubus notify "key-mismatch" on the per-BSS object
 * hostapd.<iface>; that same notify also fires for PSK 4-way MIC failures, so
 * it unifies PSK+SAE. We subscribe to every hostapd.<iface> object and feed
 * key-mismatch into the same auth-failure cache the wpa_ctrl path uses (reason
 * "key_mismatch"). The existing PSK/EAP string branch is left untouched, so PSK
 * detection cannot regress if this subscription ever drops; a PSK failure that
 * arrives via both paths is deduped downstream (AC ingest keys on
 * ap_id+event+station_mac+interface+observed_at, reason is not in the key).
 *
 * This callback runs on the uloop thread (ubus_add_uloop), the same thread as
 * the ubus `snapshot` handler that already writes g_apd_auth_failures[] via
 * apd_openwrt_snapshot()->apd_collect_hostapd()->drain()->consume(); identical
 * thread-safety profile, and only on real auth failures (never per-frame).
 */
#ifdef APD_HAS_UBUS_AUTOSUB
enum {
    APD_KEYMISMATCH_ADDRESS,
    APD_KEYMISMATCH_IFNAME,
    __APD_KEYMISMATCH_MAX
};

static const struct blobmsg_policy
apd_keymismatch_policy[__APD_KEYMISMATCH_MAX] = {
    [APD_KEYMISMATCH_ADDRESS] = { .name = "address",
                                  .type = BLOBMSG_TYPE_STRING },
    [APD_KEYMISMATCH_IFNAME]  = { .name = "ifname",
                                  .type = BLOBMSG_TYPE_STRING },
};

static struct ubus_subscriber apd_hostapd_subscriber;

static int apd_hostapd_notify_cb(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_KEYMISMATCH_MAX];
    const char *address;
    const char *ifname;

    (void)ctx;
    (void)obj;
    (void)req;
    if (!method || strcmp(method, "key-mismatch") != 0 || !msg)
        return 0;
    blobmsg_parse(apd_keymismatch_policy, __APD_KEYMISMATCH_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (!tb[APD_KEYMISMATCH_ADDRESS] || !tb[APD_KEYMISMATCH_IFNAME])
        return 0;
    address = blobmsg_get_string(tb[APD_KEYMISMATCH_ADDRESS]);
    ifname = blobmsg_get_string(tb[APD_KEYMISMATCH_IFNAME]);
    if (!address || !ifname || !ifname[0])
        return 0;
    apd_auth_failure_consume(address, ifname, "key_mismatch",
                             (int64_t)time(NULL));
    return 0;
}

static bool apd_hostapd_new_obj_cb(struct ubus_context *ctx,
                                   struct ubus_subscriber *sub,
                                   const char *path)
{
    (void)ctx;
    (void)sub;
    /* Per-BSS objects are "hostapd.<iface>" (e.g. hostapd.phy0.0-ap0) and the
     * MLD object "hostapd.ap-mld0"; the bare "hostapd"/"hostapd-auth" control
     * objects do not emit key-mismatch, so match only the dotted namespace. */
    return path && strncmp(path, "hostapd.", 8) == 0;
}

int apd_hostapd_keymismatch_subscribe_start(struct ubus_context *ctx)
{
    if (!ctx)
        return -1;
    apd_hostapd_subscriber.cb = apd_hostapd_notify_cb;
    apd_hostapd_subscriber.new_obj_cb = apd_hostapd_new_obj_cb;
    /* Setting new_obj_cb makes ubus_register_subscriber() subscribe to all
     * matching objects that already exist AND auto-subscribe on
     * ubus.object.add, so a hostapd restart re-arms the subscription with no
     * extra wiring. */
    return ubus_register_subscriber(ctx, &apd_hostapd_subscriber);
}
#else /* !APD_HAS_UBUS_AUTOSUB */
int apd_hostapd_keymismatch_subscribe_start(struct ubus_context *ctx)
{
    /* This libubus predates ubus_subscriber.new_obj_cb (auto-subscribe to
     * existing/added objects); the SAE key-mismatch subscriber cannot be
     * armed here, so it degrades to unavailable (PSK/EAP string path is
     * unaffected). */
    (void)ctx;
    return -1;
}
#endif /* APD_HAS_UBUS_AUTOSUB */

static void apd_probe_observation_store(const char *station_mac,
                                        const char *interface, int rssi_dbm,
                                        int64_t now)
{
    struct apd_probe_observation *slot = NULL;
    unsigned int first_octet = 0;
    size_t i, oldest = 0;

    if (!station_mac || !interface || !station_mac[0] || !interface[0] ||
        rssi_dbm < -200 || rssi_dbm > 100)
        return;
    if (sscanf(station_mac, "%2x", &first_octet) != 1 || first_octet > 255)
        return;
    for (i = 0; i < g_apd_probe_observations_len; i++) {
        if (!strcasecmp(g_apd_probe_observations[i].station_mac, station_mac) &&
            !strcmp(g_apd_probe_observations[i].interface, interface)) {
            slot = &g_apd_probe_observations[i];
            break;
        }
        if (g_apd_probe_observations[i].observed_at <
            g_apd_probe_observations[oldest].observed_at)
            oldest = i;
    }
    if (!slot)
        slot = &g_apd_probe_observations[g_apd_probe_observations_len <
            APD_PROBE_OBSERVATION_MAX ? g_apd_probe_observations_len++ : oldest];
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->station_mac, sizeof(slot->station_mac), "%s", station_mac);
    snprintf(slot->interface, sizeof(slot->interface), "%s", interface);
    slot->rssi_dbm = rssi_dbm;
    slot->mac_randomized = (first_octet & 0x02) != 0;
    slot->observed_at = now;
}

static void apd_probe_observation_consume(const char *line,
                                          const char *interface, int64_t now)
{
    char station_mac[18];
    char normalized[18];
    const char *sa;
    const char *signal;
    char *end;
    long rssi;

    if (!line || strncmp(line, APD_PROBE_EVENT_PREFIX,
                         sizeof(APD_PROBE_EVENT_PREFIX) - 1))
        return;
    sa = strstr(line, "sa=");
    signal = strstr(line, " signal=");
    if (!sa || !signal || sscanf(sa, "sa=%17s", station_mac) != 1 ||
        apd_hostapd_parse_mac(station_mac, normalized) != 0)
        return;
    errno = 0;
    rssi = strtol(signal + 8, &end, 10);
    if (errno || end == signal + 8 || (*end && !isspace((unsigned char)*end)) ||
        rssi < -200 || rssi > 100)
        return;
    apd_probe_observation_store(normalized, interface, (int)rssi, now);
}

/* Newest measurement per (station, BSSID) wins; the cache is small and bounded
 * because only the most recent reading per pair can inform a decision. */
static void apd_beacon_cache_store(const char *station_mac,
                                   const struct apd_beacon_report *report,
                                   int64_t now, int measurement_mode)
{
    struct apd_beacon_measurement *slot = NULL;
    size_t i;

    if (!station_mac || !report || !report->have_rcpi)
        return;
    for (i = 0; i < g_apd_beacon_cache_len; i++) {
        if (!strcasecmp(g_apd_beacon_cache[i].station_mac, station_mac) &&
            !strcasecmp(g_apd_beacon_cache[i].bssid, report->bssid)) {
            slot = &g_apd_beacon_cache[i];
            break;
        }
    }
    if (!slot) {
        if (g_apd_beacon_cache_len < APD_BEACON_CACHE_MAX) {
            slot = &g_apd_beacon_cache[g_apd_beacon_cache_len++];
        } else {
            /* Full: evict the oldest rather than dropping the new reading --
             * a stale entry is worth less than a fresh one. */
            size_t oldest = 0;

            for (i = 1; i < g_apd_beacon_cache_len; i++)
                if (g_apd_beacon_cache[i].observed_at <
                    g_apd_beacon_cache[oldest].observed_at)
                    oldest = i;
            slot = &g_apd_beacon_cache[oldest];
        }
    }
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->station_mac, sizeof(slot->station_mac), "%s", station_mac);
    snprintf(slot->bssid, sizeof(slot->bssid), "%s", report->bssid);
    slot->op_class = report->op_class;
    slot->channel = report->channel;
    slot->rcpi_dbm = report->rcpi_dbm;
    slot->rsni_db = report->rsni_db;
    slot->have_rsni = report->have_rsni;
    slot->measurement_mode = measurement_mode;
    slot->observed_at = now;
}

/* Parse one control-interface event line.
 *
 * Format (src/ap/rrm.c):  <prio>BEACON-RESP-RX <mac> <token> <rep_mode> <hex>
 * The priority prefix is optional depending on hostapd version, so skip it
 * only when present rather than assuming a fixed offset. */
static void apd_beacon_monitor_consume(const char *line, const char *interface,
                                       int64_t now)
{
    struct apd_beacon_report report;
    char station_mac[18];
    char normalized_station_mac[18];
    const char *pos = line;
    const char *hex;
    unsigned token, rep_mode;
    int consumed = 0;
    size_t i;

    if (!line)
        return;
    if (*pos == '<') {
        pos = strchr(pos, '>');
        if (!pos)
            return;
        pos++;
    }
    if (!strncmp(pos, "AP-STA-POSSIBLE-PSK-MISMATCH ", 29)) {
        apd_auth_failure_consume(pos + 29, interface, "psk_mismatch", now);
        return;
    }
    if (!strncmp(pos, "CTRL-EVENT-EAP-FAILURE", 22)) {
        apd_auth_failure_consume(pos + 22, interface, "eap_failure", now);
        return;
    }
    if (!strncmp(pos, "BSS-TM-RESP ", 12)) {
        apd_btm_response_consume(pos, interface, now);
        return;
    }
    if (!strncmp(pos, APD_PROBE_EVENT_PREFIX,
                 sizeof(APD_PROBE_EVENT_PREFIX) - 1)) {
        apd_probe_observation_consume(pos, interface, now);
        return;
    }
    if (strncmp(pos, "BEACON-RESP-RX ", 15))
        return;
    pos += 15;
    if (sscanf(pos, "%17s %u %2x %n", station_mac, &token, &rep_mode,
               &consumed) < 3 || consumed <= 0)
        return;
    if (token > 255 ||
        apd_hostapd_parse_mac(station_mac, normalized_station_mac) != 0)
        return;
    for (i = 0; i < APD_BEACON_CACHE_MAX; i++) {
        struct apd_beacon_request *request = &g_apd_beacon_requests[i];

        if (request->token == (int)token &&
            !strcmp(request->interface, interface) &&
            !strcmp(request->station_mac, normalized_station_mac))
            request->awaiting_response = 0;
    }
    /* rep_mode is a bitmask of refusal/incapable/late bits; any non-zero value
     * means the station did not actually perform the measurement, so the body
     * that follows is not a usable reading. */
    if (rep_mode != 0)
        return;
    hex = pos + consumed;
    if (apd_beacon_report_decode(hex, &report) != 0)
        return;
    apd_beacon_cache_store(normalized_station_mac, &report, now,
        apd_beacon_request_mode(interface, normalized_station_mac, token));
}

/* Find or create an ATTACHed monitor for one control socket. Probe request
 * delivery is opt-in on hostapd, while BTM and beacon responses continue to
 * use the same monitor connection. */
static struct apd_beacon_monitor *apd_beacon_monitor_get(const char *ctrl_path)
{
    struct sockaddr_un local = { .sun_family = AF_UNIX };
    struct sockaddr_un remote = { .sun_family = AF_UNIX };
    struct apd_beacon_monitor *mon = NULL;
    struct stat st;
    struct stat remote_st;
    gid_t service_gid;
    char response[32];
    ssize_t received;
    struct pollfd pfd;
    size_t i;
    int fd = -1;
    int written;

    if (!ctrl_path || strlen(ctrl_path) >= sizeof(remote.sun_path) ||
        apd_hostapd_local_dir_prepare() != 0 ||
        apd_hostapd_service_gid(&service_gid) != 0 ||
        lstat(ctrl_path, &remote_st) != 0 || !S_ISSOCK(remote_st.st_mode))
        return NULL;
    for (i = 0; i < APD_BEACON_MONITORS_MAX; i++) {
        struct apd_beacon_monitor *entry = &g_apd_beacon_monitors[i];

        if (entry->ctrl_path[0] && !strcmp(entry->ctrl_path, ctrl_path)) {
            if (entry->device == remote_st.st_dev &&
                entry->inode == remote_st.st_ino)
                return entry;
            close(entry->fd);
            unlink(entry->local_path);
            memset(entry, 0, sizeof(*entry));
        }
        if (!mon && !entry->ctrl_path[0])
            mon = entry;
    }
    if (!mon)
        return NULL;

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(fd, F_SETFL, O_NONBLOCK) != 0)
        goto fail;
    written = snprintf(local.sun_path, sizeof(local.sun_path),
                       "%s/dreamingwrt-apd-mon-%ld-%d", APD_HOSTAPD_LOCAL_DIR,
                       (long)getpid(), fd);
    if (written < 0 || (size_t)written >= sizeof(local.sun_path))
        goto fail;
    unlink(local.sun_path);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0)
        goto fail;
    if (lstat(local.sun_path, &st) != 0 || !S_ISSOCK(st.st_mode) ||
        st.st_uid != getuid() ||
        chown(local.sun_path, (uid_t)-1, service_gid) != 0 ||
        chmod(local.sun_path, 0660) != 0 ||
        lstat(local.sun_path, &st) != 0 || st.st_gid != service_gid ||
        (st.st_mode & 0777) != 0660)
        goto fail_unlink;
    memcpy(remote.sun_path, ctrl_path, strlen(ctrl_path) + 1);
    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) != 0)
        goto fail_unlink;
    if (send(fd, "ATTACH probe_rx_events=1", 24, MSG_NOSIGNAL) != 24)
        goto fail_unlink;
    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, APD_HOSTAPD_TIMEOUT_MS) != 1)
        goto fail_unlink;
    received = recv(fd, response, sizeof(response) - 1, 0);
    if (received <= 0)
        goto fail_unlink;
    response[received] = '\0';
    if (strncmp(response, "OK", 2))
        goto fail_unlink;
    mon->fd = fd;
    snprintf(mon->ctrl_path, sizeof(mon->ctrl_path), "%s", ctrl_path);
    snprintf(mon->local_path, sizeof(mon->local_path), "%s", local.sun_path);
    mon->device = remote_st.st_dev;
    mon->inode = remote_st.st_ino;
    return mon;

fail_unlink:
    unlink(local.sun_path);
fail:
    close(fd);
    return NULL;
}

static int apd_roaming_monitor_attach(const char *ctrl_path)
{
    return apd_beacon_monitor_get(ctrl_path) ? 0 : -1;
}

/* Drain whatever the monitor has queued.  Bounded so a flood cannot stall a
 * collection pass; anything left over is read on the next one. */
static void apd_beacon_monitor_drain(struct apd_beacon_monitor *mon,
                                     int64_t now)
{
    char buf[1024];
    int i;

    if (!mon || !mon->ctrl_path[0])
        return;
    for (i = 0; i < 64; i++) {
        ssize_t received = recv(mon->fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);

        if (received <= 0)
            break;
        buf[received] = '\0';
        apd_beacon_monitor_consume(buf, strrchr(mon->ctrl_path, '/') + 1, now);
    }
}

/* A station may accept only one measurement at a time. Wait on its matching
 * response, not the hostapd command ACK; refused/empty replies also finish it. */
static int apd_beacon_request_wait_previous(const char *ctrl_path,
    const char *station_mac)
{
    struct apd_beacon_monitor *mon = apd_beacon_monitor_get(ctrl_path);
    const char *interface = strrchr(ctrl_path, '/') + 1;
    size_t i;

    if (!mon)
        return -1;
    apd_beacon_monitor_drain(mon, (int64_t)time(NULL));
    for (i = 0; i < APD_BEACON_CACHE_MAX; i++) {
        struct apd_beacon_request *request = &g_apd_beacon_requests[i];

        if (!request->awaiting_response ||
            strcmp(request->interface, interface) ||
            strcmp(request->station_mac, station_mac))
            continue;
        if (request->deadline_ms <= apd_monotonic_ms()) {
            request->awaiting_response = 0;
            continue;
        }
        while (request->awaiting_response) {
            struct pollfd pfd = { .fd = mon->fd, .events = POLLIN };
            int64_t remaining = request->deadline_ms - apd_monotonic_ms();
            int ready;

            if (remaining <= 0) {
                request->awaiting_response = 0;
                return -1;
            }
            ready = poll(&pfd, 1, (int)remaining);
            if (ready < 0 && errno == EINTR)
                continue;
            if (ready <= 0 || !(pfd.revents & POLLIN)) {
                request->awaiting_response = 0;
                return -1;
            }
            apd_beacon_monitor_drain(mon, (int64_t)time(NULL));
        }
    }
    return 0;
}

/* Expire reports by reception time. A table report is explicitly cached:
 * receiving it now does not establish when the station measured that BSS. */
static struct json_object *apd_beacon_reports_json(int64_t now)
{
    struct json_object *arr = json_object_new_array();
    size_t i;

    for (i = 0; i < g_apd_beacon_cache_len; i++) {
        const struct apd_beacon_measurement *m = &g_apd_beacon_cache[i];
        struct json_object *item;

        if (!m->station_mac[0] ||
            m->observed_at < now - APD_BEACON_MEASUREMENT_TTL_S)
            continue;
        item = json_object_new_object();
        json_object_object_add(item, "station_mac",
                               json_object_new_string(m->station_mac));
        json_object_object_add(item, "bssid",
                               json_object_new_string(m->bssid));
        json_object_object_add(item, "op_class",
                               json_object_new_int(m->op_class));
        json_object_object_add(item, "channel",
                               json_object_new_int(m->channel));
        json_object_object_add(item, "rcpi_dbm",
                               json_object_new_int(m->rcpi_dbm));
        if (m->have_rsni)
            json_object_object_add(item, "rsni_db",
                                   json_object_new_int(m->rsni_db));
        json_object_object_add(item, "observed_at",
                               json_object_new_int64(m->observed_at));
        json_object_object_add(item, "measurement_mode",
                               json_object_new_string(
                                   m->measurement_mode == 0 ? "passive" :
                                   m->measurement_mode == 1 ? "active" :
                                   m->measurement_mode == 2 ? "table" : "unknown"));
        json_object_object_add(item, "cached",
                               json_object_new_boolean(m->measurement_mode == 2));
        json_object_object_add(item, "source",
                               json_object_new_string(m->measurement_mode == 2 ?
                                   "ieee80211k_beacon_table" : "ieee80211k_beacon_report"));
        json_object_array_add(arr, item);
    }
    return arr;
}

static struct json_object *apd_btm_responses_json(int64_t now)
{
    struct json_object *array = json_object_new_array();
    size_t i;

    for (i = 0; i < g_apd_btm_responses_len; i++) {
        const struct apd_btm_response *entry = &g_apd_btm_responses[i];
        struct json_object *item;

        if (entry->observed_at < now - 300)
            continue;
        item = json_object_new_object();
        json_object_object_add(item, "station_mac",
                               json_object_new_string(entry->station_mac));
        json_object_object_add(item, "interface",
                               json_object_new_string(entry->interface));
        json_object_object_add(item, "target_bssid",
                               json_object_new_string(entry->target_bssid));
        json_object_object_add(item, "status_code",
                               json_object_new_int(entry->status_code));
        json_object_object_add(item, "observed_at",
                               json_object_new_int64(entry->observed_at));
        json_object_array_add(array, item);
    }
    return array;
}

/* Item 6: recent auth failures, same TTL/shape as btm_responses. */
static struct json_object *apd_auth_failures_json(int64_t now)
{
    struct json_object *array = json_object_new_array();
    size_t i;

    for (i = 0; i < g_apd_auth_failures_len; i++) {
        const struct apd_auth_failure *entry = &g_apd_auth_failures[i];
        struct json_object *item;

        if (entry->observed_at < now - 300)
            continue;
        item = json_object_new_object();
        json_object_object_add(item, "station_mac",
                               json_object_new_string(entry->station_mac));
        json_object_object_add(item, "interface",
                               json_object_new_string(entry->interface));
        json_object_object_add(item, "reason",
                               json_object_new_string(entry->reason));
        json_object_object_add(item, "count",
                               json_object_new_int(entry->count));
        json_object_object_add(item, "observed_at",
                               json_object_new_int64(entry->observed_at));
        json_object_object_add(item, "source",
                               json_object_new_string("hostapd_control_event"));
        json_object_array_add(array, item);
    }
    return array;
}

static struct json_object *apd_probe_observations_json(
    int64_t now, const struct apd_hostapd_observation *observation)
{
    struct json_object *array = json_object_new_array();
    struct {
        struct apd_probe_observation *entry;
        const struct apd_hostapd_bss_observation *source_bss;
    } eligible[APD_PROBE_OBSERVATION_MAX];
    size_t eligible_len = 0;
    size_t i;
    size_t emit;

    /* First pass: keep only fresh, BSS-attributable observations. */
    for (i = 0; i < g_apd_probe_observations_len; i++) {
        struct apd_probe_observation *entry = &g_apd_probe_observations[i];
        const struct apd_hostapd_bss_observation *source_bss = NULL;
        size_t bss_index;

        if (!entry->station_mac[0] ||
            entry->observed_at < now - APD_PROBE_OBSERVATION_TTL_S)
            continue;
        for (bss_index = 0; observation &&
             bss_index < observation->bss_count; bss_index++) {
            const struct apd_hostapd_bss_observation *bss =
                &observation->bss[bss_index];

            if (!strcmp(bss->interface, entry->interface) && bss->has_bssid) {
                source_bss = bss;
                break;
            }
        }
        if (!source_bss ||
            (entry->bssid[0] && strcasecmp(entry->bssid, source_bss->bssid)))
            continue;
        if (!entry->bssid[0])
            snprintf(entry->bssid, sizeof(entry->bssid), "%s",
                     source_bss->bssid);
        eligible[eligible_len].entry = entry;
        eligible[eligible_len].source_bss = source_bss;
        eligible_len++;
    }

    /* Newest first, then cap: the telemetry frame must fit AP_CONTROL_FRAME_MAX,
     * and steering only needs recent probes. Selection sort keeps it simple and
     * bounded (eligible_len <= APD_PROBE_OBSERVATION_MAX). */
    for (i = 0; i < eligible_len; i++) {
        size_t best = i, j;

        for (j = i + 1; j < eligible_len; j++)
            if (eligible[j].entry->observed_at >
                eligible[best].entry->observed_at)
                best = j;
        if (best != i) {
            struct apd_probe_observation *swap_entry = eligible[i].entry;
            const struct apd_hostapd_bss_observation *swap_bss =
                eligible[i].source_bss;

            eligible[i] = eligible[best];
            eligible[best].entry = swap_entry;
            eligible[best].source_bss = swap_bss;
        }
    }

    emit = eligible_len < APD_PROBE_OBSERVATION_EMIT_MAX ?
        eligible_len : APD_PROBE_OBSERVATION_EMIT_MAX;
    for (i = 0; i < emit; i++) {
        struct apd_probe_observation *entry = eligible[i].entry;
        const struct apd_hostapd_bss_observation *source_bss =
            eligible[i].source_bss;
        struct json_object *item;

        item = json_object_new_object();
        json_object_object_add(item, "station_mac",
                               json_object_new_string(entry->station_mac));
        json_object_object_add(item, "interface",
                               json_object_new_string(entry->interface));
        json_object_object_add(item, "bssid",
            json_object_new_string(entry->bssid));
        if (source_bss->has_frequency)
            json_object_object_add(item, "frequency_mhz",
                json_object_new_int(source_bss->frequency_mhz));
        if (source_bss->has_channel)
            json_object_object_add(item, "channel",
                json_object_new_int(source_bss->channel));
        json_object_object_add(item, "rssi_dbm",
                               json_object_new_int(entry->rssi_dbm));
        json_object_object_add(item, "mac_randomized",
                               json_object_new_boolean(entry->mac_randomized));
        json_object_object_add(item, "observed_at",
                               json_object_new_int64(entry->observed_at));
        json_object_object_add(item, "frame_type",
                               json_object_new_string("probe_request"));
        json_object_object_add(item, "source",
                               json_object_new_string("hostapd_control_event"));
        json_object_object_add(item, "direction",
                               json_object_new_string("uplink"));
        json_object_array_add(array, item);
    }
    return array;
}

#endif
#ifndef APD_HOSTAPD_STANDALONE_TEST

static void apd_vendor_station_attach_nss(struct json_object *item,
                                          const struct apd_vendor_station_set *set,
                                          const char *mac)
{
    size_t i;

    if (!item || !set || !mac || !mac[0])
        return;
    for (i = 0; i < set->count; i++) {
        const struct apd_vendor_station *st = &set->items[i];

        if (strcasecmp(st->mac, mac))
            continue;
        if (st->has_rx_nss)
            json_object_object_add(item, "rx_nss",
                                   json_object_new_int(st->rx_nss));
        if (st->has_tx_nss)
            json_object_object_add(item, "tx_nss",
                                   json_object_new_int(st->tx_nss));
        if (st->has_rx_nss || st->has_tx_nss)
            json_object_object_add(item, "spatial_stream_source",
                                   json_object_new_string("wlanconfig_list"));
        return;
    }
}

static struct json_object *apd_collect_hostapd(int phy_count,
                                               struct json_object **stations_out,
                                               int64_t observed_at,
                                               int *complete_out)
{
    struct apd_hostapd_observation *observation = calloc(1, sizeof(*observation));
    struct json_object *stations = json_object_new_array();
    struct json_object *bss_array = json_object_new_array();
    struct json_object *state;
    size_t i;
    size_t vendor_station_total = 0;
    int vendor_truncated = 0;
    /*
     * One vendor query per VAP, reused across that VAP's stations. The
     * hostapd station list is grouped by interface, so caching the last
     * interface queried keeps this at one `wlanconfig` call per VAP.
     */
    struct apd_vendor_station_set *nss_set = NULL;
    char nss_interface[IFNAMSIZ] = { 0 };
    const char *nss_tool = NULL;
    int nss_valid = 0;

    if (!observation || !stations || !bss_array) {
        free(observation);
        if (stations)
            json_object_put(stations);
        if (bss_array)
            json_object_put(bss_array);
        *stations_out = json_object_new_array();
        state = apd_source_state("hostapd_control", "runtime", 0, 0,
                                 "hostapd_collector_allocation_failed",
                                 observed_at);
        if (complete_out)
            *complete_out = 0;
        return state;
    }
    apd_hostapd_collect_raw(phy_count, observation);
    for (i = 0; i < observation->bss_count; i++) {
        const struct apd_hostapd_bss_observation *raw = &observation->bss[i];
        struct json_object *item = json_object_new_object();

        json_object_object_add(item, "interface",
                               json_object_new_string(raw->interface));
        if (raw->has_bssid)
            json_object_object_add(item, "bssid", json_object_new_string(raw->bssid));
        if (raw->has_ssid)
            json_object_object_add(item, "broadcast_name",
                                   json_object_new_string(raw->ssid));
        if (raw->state[0])
            json_object_object_add(item, "state", json_object_new_string(raw->state));
        if (raw->has_frequency)
            json_object_object_add(item, "frequency_mhz",
                                   json_object_new_int(raw->frequency_mhz));
        if (raw->has_channel)
            json_object_object_add(item, "channel", json_object_new_int(raw->channel));
        json_object_object_add(item, "hostapd_ctrl_reachable",
                               json_object_new_boolean(raw->hostapd_ctrl_reachable));
        apd_json_nullable_string(item, "hostapd_ctrl_source",
                                 raw->control_path[0] ? raw->control_path : NULL);
        /* Reuse the action-time monitor and collect delayed station replies. */
        if (raw->hostapd_ctrl_reachable && raw->control_path[0]) {
            struct apd_beacon_monitor *mon;

            pthread_mutex_lock(&g_apd_roaming_lock);
            mon = apd_beacon_monitor_get(raw->control_path);
            if (mon)
                apd_beacon_monitor_drain(mon, (int64_t)time(NULL));
            pthread_mutex_unlock(&g_apd_roaming_lock);
        }
        json_object_object_add(item, "ft_configured",
                               json_object_new_boolean(raw->ft_configured));
        json_object_object_add(item, "ft_supported",
                               json_object_new_boolean(raw->ft_supported));
        json_object_object_add(item, "ft_over_ds",
                               json_object_new_boolean(raw->ft_over_ds));
        apd_json_nullable_string(item, "ft_reason",
                                 raw->ft_reason[0] ? raw->ft_reason :
                                     "hostapd_ft_configuration_unavailable");
        json_object_object_add(item, "neighbor_report_80211k",
                               json_object_new_boolean(raw->neighbor_report_80211k));
        json_object_object_add(item, "neighbor_database_configured",
                               json_object_new_boolean(raw->neighbor_database_configured));
        json_object_object_add(item, "neighbors_complete",
                               json_object_new_boolean(raw->neighbors_complete));
        json_object_object_add(item, "neighbors", apd_hostapd_neighbors_json(raw));
        apd_json_nullable_string(item, "neighbor_report_reason",
                                 raw->neighbor_report_reason[0] ?
                                     raw->neighbor_report_reason :
                                     "hostapd_capability_probe_failed");
        json_object_object_add(item, "bss_transition_80211v",
                               json_object_new_boolean(raw->bss_transition_80211v));
        apd_json_nullable_string(item, "bss_transition_reason",
                                 raw->bss_transition_reason[0] ?
                                     raw->bss_transition_reason :
                                     "hostapd_capability_probe_failed");
        json_object_object_add(item, "client_deauth",
                               json_object_new_boolean(raw->client_deauth));
        json_object_object_add(item, "reassoc_block",
                               json_object_new_boolean(raw->reassoc_block));
        json_object_object_add(item, "reassoc_block_reason", json_object_new_string(
            !observation->reassoc_backend_safe ? "native_acl_backend_quarantined" :
            raw->has_mld_address || raw->has_link_id ? "mlo_reassociation_block_unsupported" :
            raw->reassoc_block ? "hostapd_acl_available" : "hostapd_acl_unavailable"));
        apd_json_nullable_string(item, "client_deauth_reason",
                                 raw->client_deauth_reason[0] ?
                                     raw->client_deauth_reason :
                                     "hostapd_capability_probe_failed");
        if (raw->has_reported_station_count)
            json_object_object_add(item, "reported_station_count",
                                   json_object_new_int(raw->reported_station_count));
        json_object_object_add(item, "station_count",
                               json_object_new_int((int)raw->station_count));
        json_object_object_add(item, "complete", json_object_new_boolean(raw->complete));
        /*
         * A BSS that failed partway still carries every station it did read.
         * `complete` alone cannot express that, and a reader treating it as
         * "no usable data" discards a full station list - observed on 31.31,
         * where 15 BSSes reported incomplete while 29 stations had been
         * collected. This says explicitly whether the rows below are usable.
         */
        json_object_object_add(item, "stations_usable",
            json_object_new_boolean(raw->station_count > 0));
        json_object_object_add(item, "station_coverage",
            json_object_new_string(raw->complete ? "complete" :
                raw->station_count > 0 ? "partial" : "none"));
        apd_json_nullable_string(item, "reason", raw->reason[0] ? raw->reason : NULL);
        if (raw->has_mld_address) {
            json_object_object_add(item, "mld_address",
                                   json_object_new_string(raw->mld_address));
        }
        if (raw->has_link_id)
            json_object_object_add(item, "link_id", json_object_new_int(raw->link_id));
        json_object_object_add(item, "mlo_evidence",
            json_object_new_boolean(raw->has_mld_address || raw->has_link_id));
        json_object_object_add(item, "mlo_relation_complete",
                               json_object_new_boolean(raw->mlo_relation_complete));
        json_object_object_add(item, "mlo_relation_state", json_object_new_string(
            raw->mlo_relation_complete ? "complete" :
            (raw->has_mld_address || raw->has_link_id) ? "partial" : "unavailable"));
        apd_json_nullable_string(item, "mlo_reason",
            raw->mlo_relation_complete ? NULL :
            (raw->has_mld_address || raw->has_link_id) ?
                "hostapd_mlo_relation_partial" : "not_reported_by_hostapd");
        json_object_array_add(bss_array, item);
    }
    for (i = 0; i < observation->station_count; i++) {
        const struct apd_hostapd_station_observation *raw = &observation->stations[i];
        struct json_object *item = json_object_new_object();

        json_object_object_add(item, "mac", json_object_new_string(raw->mac));
        json_object_object_add(item, "interface",
                               json_object_new_string(raw->interface));
        /* Refresh the vendor set when the interface changes. */
        if (raw->interface[0] && strcmp(nss_interface, raw->interface)) {
            if (!nss_tool)
                nss_tool = apd_find_wlanconfig();
            if (nss_tool && !nss_set)
                nss_set = calloc(1, sizeof(*nss_set));
            snprintf(nss_interface, sizeof(nss_interface), "%s", raw->interface);
            nss_valid = 0;
            if (nss_tool && nss_set) {
                memset(nss_set, 0, sizeof(*nss_set));
                nss_valid = apd_vendor_station_collect(nss_tool, raw->interface,
                                                       nss_set) == 0;
            }
        }
        if (nss_valid)
            apd_vendor_station_attach_nss(item, nss_set, raw->mac);
        if (raw->has_signal)
            json_object_object_add(item, "signal_dbm",
                                   json_object_new_int(raw->signal_dbm));
        apd_hostapd_json_u64(item, "rx_bytes", raw->has_rx_bytes, raw->rx_bytes);
        apd_hostapd_json_u64(item, "tx_bytes", raw->has_tx_bytes, raw->tx_bytes);
        apd_hostapd_json_u64(item, "rx_packets", raw->has_rx_packets,
                             raw->rx_packets);
        apd_hostapd_json_u64(item, "tx_packets", raw->has_tx_packets,
                             raw->tx_packets);
        apd_hostapd_json_u64(item, "connected_time_seconds",
                             raw->has_connected_time,
                             raw->connected_time_seconds);
        apd_hostapd_json_u64(item, "inactive_time_ms", raw->has_inactive_time,
                             raw->inactive_time_ms);
        if (raw->has_flags) {
            json_object_object_add(item, "authenticated",
                                   json_object_new_boolean(raw->authenticated));
            json_object_object_add(item, "associated",
                                   json_object_new_boolean(raw->associated));
            json_object_object_add(item, "authorized",
                                   json_object_new_boolean(raw->authorized));
        }
        json_object_object_add(item, "station_btm_capable",
                               json_object_new_boolean(
                                   raw->station_btm_capable));
        apd_json_nullable_string(item, "station_btm_reason",
                                 raw->station_btm_reason);
        json_object_object_add(item, "mlo_evidence",
            json_object_new_boolean(raw->has_mld_address || raw->has_link_id));
        json_object_object_add(item, "mlo_relation_complete",
                               json_object_new_boolean(raw->mlo_relation_complete));
        json_object_object_add(item, "mlo_relation_state", json_object_new_string(
            raw->mlo_relation_complete ? "complete" :
            (raw->has_mld_address || raw->has_link_id) ? "partial" : "unavailable"));
        if (raw->has_mld_address)
            json_object_object_add(item, "mld_address",
                                   json_object_new_string(raw->mld_address));
        if (raw->has_link_id)
            json_object_object_add(item, "link_id", json_object_new_int(raw->link_id));
        apd_json_nullable_string(item, "mlo_reason",
            raw->mlo_relation_complete ? NULL :
            (raw->has_mld_address || raw->has_link_id) ?
                "hostapd_mlo_relation_partial" : "not_reported_by_hostapd");
        json_object_object_add(item, "source",
                               json_object_new_string("hostapd_control"));
        json_object_object_add(item, "stale", json_object_new_boolean(0));
        json_object_object_add(item, "observed_at",
                               json_object_new_int64(observed_at));
        json_object_array_add(stations, item);
    }
    /*
     * Vendor fallback for the station detail.
     *
     * On QCA/ath APs the per-VAP hostapd control sockets are absent (only
     * `global` exists), so the STATUS query yields per-BSS counts while the
     * station query fails; the snapshot then reported 30 associated clients
     * with an empty station array, leaving signal and spatial streams null on
     * a page that had the data available all along. `wlanconfig <vap> list`
     * carries it, and was already used by the on-demand survey path only.
     *
     * Driven by "did hostapd produce rows for this BSS", never by "does the
     * binary exist", so an AP where hostapd works keeps using hostapd and this
     * costs one `wlanconfig` call per affected VAP.
     */
    if (observation->bss_count && !observation->station_count) {
        const char *wlanconfig = apd_find_wlanconfig();
        struct apd_vendor_station_set *vendor;


        vendor = wlanconfig ? calloc(1, sizeof(*vendor)) : NULL;
        for (i = 0; vendor && i < observation->bss_count; i++) {
            const struct apd_hostapd_bss_observation *raw = &observation->bss[i];
            size_t s;

            if (!raw->interface[0])
                continue;
            memset(vendor, 0, sizeof(*vendor));
            if (apd_vendor_station_collect(wlanconfig, raw->interface,
                                           vendor) != 0)
                continue;
            for (s = 0; s < vendor->count; s++) {
                apd_vendor_station_emit(stations, &vendor->items[s],
                                        raw->interface, observed_at);
                vendor_station_total++;
            }
            if (vendor->truncated)
                vendor_truncated = 1;
        }
        free(vendor);
    }
    state = apd_source_state("hostapd_control", "runtime",
                             observation->available,
                             observation->complete,
                             observation->reason[0] ? observation->reason : NULL,
                             observed_at);
    json_object_object_add(state, "global_control",
                           json_object_new_boolean(observation->global_control));
    json_object_object_add(state, "interface_controls",
                           json_object_new_int((int)observation->interface_controls));
    json_object_object_add(state, "bss_count",
                           json_object_new_int((int)observation->bss_count));
    json_object_object_add(state, "station_count",
                           json_object_new_int((int)observation->station_count));
    /*
     * Two separate facts, kept separate: how many rows the station array holds,
     * and which collector produced them. `station_count` above stays hostapd's
     * own tally so an existing reader sees no change in meaning.
     */
    json_object_object_add(state, "station_detail_count",
        json_object_new_int((int)(observation->station_count +
                                 vendor_station_total)));
    json_object_object_add(state, "station_detail_source",
        json_object_new_string(observation->station_count ? "hostapd_control" :
                               vendor_station_total ? "wlanconfig_list" :
                                                      "unavailable"));
    if (vendor_truncated)
        json_object_object_add(state, "station_detail_truncated",
                               json_object_new_boolean(1));
    json_object_object_add(state, "bss", bss_array);
    /* Per-candidate signal as measured by the station itself -- the one thing
     * neither the serving AP nor the candidate AP can observe on its own. */
    pthread_mutex_lock(&g_apd_roaming_lock);
    json_object_object_add(state, "beacon_reports",
                           apd_beacon_reports_json((int64_t)time(NULL)));
    json_object_object_add(state, "probe_observations",
                           apd_probe_observations_json((int64_t)time(NULL),
                                                       observation));
    json_object_object_add(state, "btm_responses",
                           apd_btm_responses_json((int64_t)time(NULL)));
    json_object_object_add(state, "auth_failures",
                           apd_auth_failures_json((int64_t)time(NULL)));
    pthread_mutex_unlock(&g_apd_roaming_lock);
    json_object_object_add(state, "runtime_actions",
                           json_object_new_boolean(1));
    json_object_object_add(state, "limits", json_object_new_object());
    {
        struct json_object *limits;

        json_object_object_get_ex(state, "limits", &limits);
        json_object_object_add(limits, "bss", json_object_new_int(APD_HOSTAPD_BSS_LIMIT));
        json_object_object_add(limits, "stations",
                               json_object_new_int(APD_HOSTAPD_STATION_LIMIT));
        json_object_object_add(limits, "stations_per_bss",
                               json_object_new_int(APD_HOSTAPD_STATIONS_PER_BSS_LIMIT));
        json_object_object_add(limits, "response_bytes",
                               json_object_new_int(APD_HOSTAPD_RESPONSE_LIMIT));
        json_object_object_add(limits, "query_timeout_ms",
                               json_object_new_int(APD_HOSTAPD_TIMEOUT_MS));
        json_object_object_add(limits, "collection_timeout_ms",
                               json_object_new_int(APD_HOSTAPD_COLLECTION_TIMEOUT_MS));
    }
    *stations_out = stations;
    if (complete_out)
        *complete_out = observation->complete;
    free(nss_set);
    free(observation);
    return state;
}

static int apd_parse_iw_dev(const char *text, struct json_object *radios,
                            struct json_object *ssids, int64_t observed_at)
{
    return apd_iw_topology_parse(text, radios, ssids, observed_at);
}

static void apd_survey_json_nullable_int(struct json_object *object,
                                         const char *name, int present, int value)
{
    json_object_object_add(object, name, present ? json_object_new_int(value) :
                           json_object_new_null());
}

static void apd_survey_json_nullable_u64(struct json_object *object,
                                         const char *name, int present,
                                         uint64_t value)
{
    json_object_object_add(object, name,
                           present ? json_object_new_int64((int64_t)value) :
                                     json_object_new_null());
}

static struct json_object *apd_survey_json(const char *path,
                                           const char *interface,
                                           int target_frequency,
                                           int64_t sample_time,
                                           unsigned int wiphy_index,
                                           int have_wiphy_index,
                                           unsigned int radio_index,
                                           int has_radio_index)
{
    struct apd_survey_sample sample;
    struct json_object *survey = json_object_new_object();
    double utilization_pct = 0.0;
    int complete;

    if (!survey)
        return NULL;
    memset(&sample, 0, sizeof(sample));
    apd_survey_collect_raw(path, interface, target_frequency, &sample);
    complete = sample.complete;
    json_object_object_add(survey, "source",
                           json_object_new_string("iw_survey"));
    json_object_object_add(survey, "sample_time",
                           json_object_new_int64(sample_time));
    json_object_object_add(survey, "complete",
                           json_object_new_boolean(complete));
    json_object_object_add(survey, "stale", json_object_new_boolean(0));
    apd_json_nullable_string(survey, "reason",
                             sample.reason[0] ? sample.reason : NULL);
    if (apd_survey_safe_interface_name(interface))
        json_object_object_add(survey, "interface",
                               json_object_new_string(interface));
    apd_survey_json_nullable_int(survey, "frequency_mhz",
                                 sample.has_frequency, sample.frequency_mhz);
    json_object_object_add(survey, "in_use",
                           sample.has_frequency ?
                           json_object_new_boolean(sample.in_use) :
                           json_object_new_null());
    apd_survey_json_nullable_int(survey, "noise_dbm", sample.has_noise,
                                 sample.noise_dbm);
    apd_survey_json_nullable_u64(survey, "channel_active_time_ms",
                                 sample.has_active_time, sample.active_time_ms);
    apd_survey_json_nullable_u64(survey, "channel_busy_time_ms",
                                 sample.has_busy_time, sample.busy_time_ms);
    apd_survey_json_nullable_u64(survey, "channel_receive_time_ms",
                                 sample.has_receive_time,
                                 sample.receive_time_ms);
    apd_survey_json_nullable_u64(survey, "channel_transmit_time_ms",
                                 sample.has_transmit_time,
                                 sample.transmit_time_ms);
    if (apd_survey_utilization(&sample, &utilization_pct) == 0)
        json_object_object_add(survey, "utilization_pct",
                               json_object_new_double(utilization_pct));
    else
        json_object_object_add(survey, "utilization_pct",
                               json_object_new_null());
    /* Vendor airtime fallback. The survey above stays the main source: this
     * only takes over when the survey produced no sample, and it never
     * overwrites a survey-derived value. */
    if (have_wiphy_index) {
        struct apd_airtime_stats stats;
        struct apd_tx_retry_stats tx_retry;
        char radio_netdev[IFNAMSIZ] = { 0 };
        int available = 0;
        double vendor_pct = 0.0;

        memset(&stats, 0, sizeof(stats));
        {
            enum apd_radio_netdev_status netdev_status =
                apd_airtime_radio_netdev(wiphy_index, radio_index,
                                         has_radio_index, radio_netdev,
                                         sizeof(radio_netdev));

            if (netdev_status != APD_RADIO_NETDEV_OK)
                snprintf(stats.reason, sizeof(stats.reason), "%s",
                         apd_radio_netdev_reason(netdev_status));
            else if (apd_airtime_collect(apd_find_apstats(), radio_netdev,
                                         &stats) == 0)
                available = 1;
        }
        /* This is the block the controller differences into retry history, so
         * the VAP sum is attached here regardless of the radio-level outcome. */
        (void)apd_tx_retry_collect(apd_find_apstats(), wiphy_index,
                                   radio_index, has_radio_index, &tx_retry);
        {
            struct json_object *air = apd_airtime_json(&stats, available,
                                                       radio_netdev);

            if (air) {
                apd_tx_retry_decorate(air, &tx_retry);
                json_object_object_add(survey, "air_stats", air);
            }
        }
        if (available && !sample.complete &&
            apd_airtime_utilization_pct(&stats, &vendor_pct) == 0) {
            json_object_object_del(survey, "utilization_pct");
            json_object_object_add(survey, "utilization_pct",
                                   json_object_new_double(vendor_pct));
            json_object_object_del(survey, "source");
            json_object_object_add(survey, "source",
                                   json_object_new_string("apstats_radio"));
        }
        if (available && !sample.has_noise && stats.has_noise_floor) {
            json_object_object_del(survey, "noise_dbm");
            json_object_object_add(survey, "noise_dbm",
                json_object_new_int(stats.noise_floor_dbm));
            json_object_object_add(survey, "noise_source",
                json_object_new_string("apstats_radio"));
        }
    }
    return survey;
}

static void apd_collect_radio_surveys(const char *path,
                                      struct json_object *radios,
                                      int64_t sample_time,
                                      int *survey_count_out,
                                      int *complete_count_out)
{
    int survey_count = 0;
    int complete_count = 0;
    size_t i;

    for (i = 0; i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        struct json_object *interfaces = NULL;
        struct json_object *frequency = NULL;
        struct json_object *survey;
        const char *interface_name = NULL;
        const char *invalid_interface_name = NULL;
        int target_frequency = 0;
        size_t j;
        struct json_object *radio_id = NULL;
        unsigned int wiphy_index = 0;
        unsigned int radio_index = 0;
        int has_radio_index = 0;
        int have_wiphy_index = 0;

        /* Radio ids are `phyN`; the airtime fallback needs that index to find
         * the matching radio netdev in sysfs. */
        if (json_object_object_get_ex(radio, "id", &radio_id) &&
            json_object_is_type(radio_id, json_type_string) &&
            apd_neighbor_radio_id(json_object_get_string(radio_id),
                                  &wiphy_index, &radio_index,
                                  &has_radio_index) == 0)
            have_wiphy_index = 1;

        if (!json_object_object_get_ex(radio, "interfaces", &interfaces) ||
            !json_object_object_get_ex(radio, "frequency_mhz", &frequency) ||
            !json_object_is_type(frequency, json_type_int)) {
            survey = apd_survey_json(path, NULL, 0, sample_time, wiphy_index,
                                     have_wiphy_index, radio_index,
                                     has_radio_index);
            json_object_object_add(radio, "survey", survey);
            survey_count++;
            continue;
        }
        target_frequency = json_object_get_int(frequency);
        for (j = 0; j < json_object_array_length(interfaces); j++) {
            struct json_object *interface = json_object_array_get_idx(interfaces, j);
            struct json_object *type = NULL;
            struct json_object *name = NULL;

            if (!json_object_object_get_ex(interface, "type", &type) ||
                !json_object_is_type(type, json_type_string) ||
                strcmp(json_object_get_string(type), "AP") != 0 ||
                !json_object_object_get_ex(interface, "interface", &name) ||
                !json_object_is_type(name, json_type_string))
                continue;
            if (apd_survey_safe_interface_name(json_object_get_string(name))) {
                interface_name = json_object_get_string(name);
                break;
            }
            invalid_interface_name = json_object_get_string(name);
        }
        if (!interface_name) {
            survey = apd_survey_json(path, invalid_interface_name,
                                     target_frequency, sample_time,
                                     wiphy_index, have_wiphy_index,
                                     radio_index, has_radio_index);
        } else {
            survey = apd_survey_json(path, interface_name, target_frequency,
                                     sample_time, wiphy_index,
                                     have_wiphy_index, radio_index,
                                     has_radio_index);
        }
        if (!survey)
            continue;
        json_object_object_add(radio, "survey", survey);
        survey_count++;
        {
            struct json_object *complete = NULL;

            if (json_object_object_get_ex(survey, "complete", &complete) &&
                json_object_get_boolean(complete))
                complete_count++;
        }
    }
    if (survey_count_out)
        *survey_count_out = survey_count;
    if (complete_count_out)
        *complete_count_out = complete_count;
}

#endif /* APD_HOSTAPD_STANDALONE_TEST */

/* Compiled for production and for the neighbor-scan standalone fixture (which
 * links json-c); the hostapd-only fixture builds without json-c and must not
 * see this block.
 *
 * Deliberately NOT compiled for a survey-only fixture. This block calls the
 * neighbor-scan helpers (apd_neighbor_target_from_iw(), apd_find_wlanconfig(),
 * struct apd_neighbor_target, APD_NEIGHBOR_REASON_LEN), which are declared under
 * a guard requiring APD_NEIGHBOR_SCAN_STANDALONE_TEST. Admitting
 * APD_SURVEY_STANDALONE_TEST here pulled these callers in without their
 * dependencies, so tests/apd_survey_runtime_fixture.c failed to compile on
 * symbols it never uses: it needs only apd_survey_utilization() and
 * apd_survey_collect_raw(), both defined far above this point.
 */
#if !defined(APD_HOSTAPD_STANDALONE_TEST) || \
    defined(APD_NEIGHBOR_SCAN_STANDALONE_TEST)

/* ── Authoritative channel catalog from `iw phy` ─────────────────────────
 * Channels, disabled/no-IR/radar flags and DFS state come only from the
 * driver/regdb evidence that `iw phy` prints; nothing is inferred from
 * country-code tables.  Every radio always carries a channel_catalog
 * object; missing evidence is complete=false with a reason.  This block
 * is compiled in the standalone fixtures too, so it stays self-contained
 * (no helpers from the hostapd-only region). */

static char *apd_channel_line_trim(char *line)
{
    char *end;

    while (*line == ' ' || *line == '\t')
        line++;
    end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t' ||
                          end[-1] == '\r'))
        *--end = '\0';
    return line;
}

/*
 * `source` is a parameter rather than the literal "iw_phy" it used to be,
 * because the vendor fallback below fills the same object from
 * `wlanconfig <if> list chan`. Leaving it hardcoded would have made a catalogue
 * built from vendor output report itself as iw_phy, which is the "data source
 * lies about itself" failure the handoff for this fallback called out
 * explicitly.
 */
static struct json_object *apd_channel_catalog_new_source(const char *source,
                                                          const char *reason,
                                                          int64_t observed_at)
{
    struct json_object *catalog = json_object_new_object();

    json_object_object_add(catalog, "source",
                           json_object_new_string(source ? source : "iw_phy"));
    json_object_object_add(catalog, "scope",
                           json_object_new_string("runtime"));
    json_object_object_add(catalog, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(catalog, "complete",
                           json_object_new_boolean(reason == NULL));
    if (reason)
        json_object_object_add(catalog, "reason",
                               json_object_new_string(reason));
    json_object_object_add(catalog, "channels", json_object_new_array());
    return catalog;
}

static struct json_object *apd_channel_catalog_new(const char *reason,
                                                   int64_t observed_at)
{
    return apd_channel_catalog_new_source("iw_phy", reason, observed_at);
}

/* Channel width support is taken only from explicit iw phy capability
 * markers (HT20/HT40 lines, HE PHY "HE40/HE80/..." strings, the VHT
 * "Supported Channel Width" line and the EHT "320 MHz in 6 GHz Support"
 * line).  Bare VHT presence is deliberately not treated as 80 MHz
 * evidence: BE10000/QWRT advertises vendor VHT on 2.4 GHz where no
 * 80 MHz channel exists.  Missing markers under-claim, never over-claim;
 * the AC validate path rejects widths without evidence. */
struct apd_channel_width_evidence {
    int w20;
    int w40;
    int w80;
    int w160;
    int w320;
};

static void apd_channel_width_scan(const char *value,
                                   struct apd_channel_width_evidence *width)
{
    if (!strcmp(value, "HT20/HT40")) {
        width->w20 = 1;
        width->w40 = 1;
    } else if (!strcmp(value, "HT20")) {
        width->w20 = 1;
    } else if (!strncmp(value, "HE PHY Capabilities", 19)) {
        width->w20 = 1;
    } else if (!strncmp(value, "Supported Channel Width:", 24)) {
        if (!strstr(value, "neither") && strstr(value, "160"))
            width->w160 = 1;
    } else if (strstr(value, "320 MHz in 6 GHz Support") ||
               /* mt7996/iw 6.x prints the EHT marker unspaced
                * ("320MHz in 6GHz Supported"). Matching only the spaced
                * spelling dropped 320 MHz from every BE10000-class 6 GHz
                * radio, so an EHT320 radio could not be validated at the
                * width it was already running. */
               strstr(value, "320MHz in 6GHz Support")) {
        width->w320 = 1;
    } else {
        if (strstr(value, "HE40"))
            width->w40 = 1;
        if (strstr(value, "HE80"))
            width->w80 = 1;
        if (strstr(value, "HE160"))
            width->w160 = 1;
    }
}

static void apd_channel_catalog_finalize(
    struct json_object *catalog, struct json_object *channels,
    const struct apd_channel_width_evidence *width)
{
    struct json_object *widths;
    struct json_object *supported;
    double min_dbm = 0.0;
    double max_dbm = 0.0;
    int has_power = 0;
    size_t i;

    int has_6ghz = 0;

    if (!catalog || !channels)
        return;
    /* "320 MHz in 6 GHz Support" is a band-qualified capability that the
     * driver also decodes on the 5 GHz wiphy (identical EHT PHY caps on
     * BE10000); only count it when this wiphy actually reports 6 GHz
     * frequencies. */
    for (i = 0; i < json_object_array_length(channels); i++) {
        struct json_object *entry = json_object_array_get_idx(channels, i);
        struct json_object *field = NULL;

        if (entry &&
            json_object_object_get_ex(entry, "frequency_mhz", &field) &&
            field && json_object_get_int(field) >= 5925)
            has_6ghz = 1;
    }
    if (width->w20 || width->w40 || width->w80 || width->w160 ||
        (width->w320 && has_6ghz)) {
        widths = json_object_new_array();
        if (width->w20)
            json_object_array_add(widths, json_object_new_int(20));
        if (width->w40)
            json_object_array_add(widths, json_object_new_int(40));
        if (width->w80)
            json_object_array_add(widths, json_object_new_int(80));
        if (width->w160)
            json_object_array_add(widths, json_object_new_int(160));
        if (width->w320 && has_6ghz)
            json_object_array_add(widths, json_object_new_int(320));
        json_object_object_add(catalog, "supported_widths_mhz", widths);
    }
    supported = json_object_new_array();
    for (i = 0; i < json_object_array_length(channels); i++) {
        struct json_object *entry = json_object_array_get_idx(channels, i);
        struct json_object *field = NULL;
        double dbm;

        if (!entry)
            continue;
        if (json_object_object_get_ex(entry, "disabled", &field) &&
            json_object_get_boolean(field))
            continue;
        if (json_object_object_get_ex(entry, "max_txpower_dbm", &field) &&
            field) {
            dbm = json_object_get_double(field);
            if (!has_power || dbm < min_dbm)
                min_dbm = dbm;
            if (!has_power || dbm > max_dbm)
                max_dbm = dbm;
            has_power = 1;
        }
        if (json_object_object_get_ex(entry, "no_ir", &field) &&
            json_object_get_boolean(field))
            continue;
        if (json_object_object_get_ex(entry, "channel", &field) && field)
            json_object_array_add(supported,
                json_object_new_int(json_object_get_int(field)));
    }
    json_object_object_add(catalog, "supported_channels", supported);
    if (has_power) {
        struct json_object *range = json_object_new_object();

        json_object_object_add(range, "min",
                               json_object_new_double(min_dbm));
        json_object_object_add(range, "max",
                               json_object_new_double(max_dbm));
        json_object_object_add(catalog, "tx_power_range_dbm", range);
    }
}

/* One line of `iw phy` output, applied to the catalogue being built.
 *
 * Shared by the per-wiphy parser below and the band-scoped collector used by
 * the mac80211 backend, so both read channel flags, DFS state and width
 * markers from exactly the same evidence. A second copy of this logic is how
 * the two paths would drift into disagreeing about what a radio supports.
 */
static void apd_channel_catalog_scan_line(
    char *value, struct json_object *channels,
    struct json_object **channel,
    struct apd_channel_width_evidence *width)
{
    if (value[0] == '*' && strstr(value, " MHz [")) {
        double frequency_mhz = 0.0;
        int frequency = 0;
        int number = 0;
        double txpower = 0.0;
        int has_txpower = 0;
        const char *close_bracket;
        struct json_object *entry;

        /* iw 6.x prints a fractional frequency ("* 2412.0 MHz [1]").
         * Scanning it as %d stopped at the '.', the match count came back as
         * 1, and every channel line was discarded -- which is why a
         * BE10000-class AP reported no channel catalogue at all and the
         * controller refused every radio write with channel_catalog_missing. */
        if (sscanf(value, "* %lf MHz [%d]", &frequency_mhz, &number) != 2 ||
            (close_bracket = strchr(value, ']')) == NULL) {
            *channel = NULL;
            return;
        }
        frequency = (int)(frequency_mhz + 0.5);
        has_txpower = sscanf(close_bracket + 1, " (%lf dBm", &txpower) == 1;
        entry = json_object_new_object();
        json_object_object_add(entry, "channel", json_object_new_int(number));
        json_object_object_add(entry, "frequency_mhz",
                               json_object_new_int(frequency));
        if (has_txpower)
            json_object_object_add(entry, "max_txpower_dbm",
                                   json_object_new_double(txpower));
        json_object_object_add(entry, "disabled",
            json_object_new_boolean(strstr(value, "(disabled)") != NULL));
        json_object_object_add(entry, "no_ir",
            json_object_new_boolean(strstr(value, "no IR") != NULL));
        json_object_object_add(entry, "radar_detection",
            json_object_new_boolean(strstr(value, "radar detection") != NULL));
        json_object_array_add(channels, entry);
        *channel = entry;
        return;
    }
    if (*channel && !strncmp(value, "DFS state: ", 11)) {
        char state[32] = { 0 };

        if (sscanf(value + 11, "%31s", state) == 1)
            json_object_object_add(*channel, "dfs_state",
                                   json_object_new_string(state));
        return;
    }
    apd_channel_width_scan(value, width);
}

static void apd_channel_catalog_parse(const char *text,
                                      struct json_object *radios,
                                      const char *regdomain,
                                      int64_t observed_at)
{
    char *copy = strdup(text ? text : "");
    char *line;
    char *saveptr = NULL;
    struct json_object *catalog = NULL;
    struct json_object *channels = NULL;
    struct json_object *channel = NULL;
    struct apd_channel_width_evidence width = { 0 };
    size_t i;

    if (!copy)
        return;
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_channel_line_trim(line);

        if (!strncmp(value, "Wiphy ", 6)) {
            const char *name = value + 6;

            apd_channel_catalog_finalize(catalog, channels, &width);
            memset(&width, 0, sizeof(width));
            catalog = NULL;
            channels = NULL;
            channel = NULL;
            for (i = 0; radios && i < json_object_array_length(radios); i++) {
                struct json_object *radio = json_object_array_get_idx(radios,
                                                                      i);
                struct json_object *id = NULL;

                if (json_object_object_get_ex(radio, "id", &id) && id &&
                    !strcmp(json_object_get_string(id), name)) {
                    catalog = apd_channel_catalog_new(NULL, observed_at);
                    if (regdomain && regdomain[0])
                        json_object_object_add(catalog, "regdomain",
                            json_object_new_string(regdomain));
                    json_object_object_get_ex(catalog, "channels", &channels);
                    json_object_object_add(radio, "channel_catalog", catalog);
                    break;
                }
            }
            continue;
        }
        if (!catalog || !channels)
            continue;
        apd_channel_catalog_scan_line(value, channels, &channel, &width);
    }
    apd_channel_catalog_finalize(catalog, channels, &width);
    free(copy);
}

/*
 * Builds a channel catalogue from `wlanconfig <if> list chan` for a radio that
 * `iw phy` did not describe.
 *
 * Returns 0 when a catalogue was attached to the radio, -1 when the caller
 * should fall back to recording the original iw-phy reason. A failure here is
 * deliberately quiet: the vendor tool is absent on mac80211-only builds, and
 * that is not an error worth overwriting the real reason with.
 *
 * Width handling follows the parser's conservative rule: a channel is claimed
 * at a width only when the tool printed the matching capability token, so a
 * 2.4 GHz channel that reports vendor VHT is not promoted to 80 MHz.
 */
static int apd_channel_catalog_vendor_fallback(struct json_object *radio,
                                               const char *regdomain,
                                               int64_t observed_at,
                                               const char *iw_reason)
{
    const char *wlanconfig = apd_find_wlanconfig();
    const char *iw = apd_find_iw();
    struct apd_command_result inventory = { 0 };
    struct apd_command_result listing = { 0 };
    struct apd_neighbor_target target;
    char reason[APD_NEIGHBOR_REASON_LEN + 1] = { 0 };
    struct apd_vendor_chan_set set;
    struct json_object *catalog = NULL;
    struct json_object *channels = NULL;
    struct json_object *id = NULL;
    const char *radio_id;
    size_t i;
    int rc = -1;

    (void)iw_reason;
    if (!radio || !wlanconfig || !wlanconfig[0] || !iw || !iw[0])
        return -1;
    if (!json_object_object_get_ex(radio, "id", &id) || !id)
        return -1;
    radio_id = json_object_get_string(id);
    if (!radio_id || !radio_id[0])
        return -1;

    {
        char *const argv[] = { (char *)iw, "dev", NULL };

        if (apd_readonly_command(iw, argv, &inventory) != 0)
            goto done;
    }
    if (apd_neighbor_target_from_iw(inventory.text, radio_id, &target,
                                    reason) != 0)
        goto done;
    {
        char *const argv[] = {
            (char *)wlanconfig, target.interface, "list", "chan", NULL
        };

        if (apd_readonly_command(wlanconfig, argv, &listing) != 0)
            goto done;
    }

    memset(&set, 0, sizeof(set));
    if (apd_vendor_chanlist_parse(listing.text, &set) != 0)
        goto done;

    catalog = apd_channel_catalog_new_source("wlanconfig_list_chan", NULL,
                                             observed_at);
    if (!catalog)
        goto done;
    if (regdomain && regdomain[0])
        json_object_object_add(catalog, "regdomain",
                               json_object_new_string(regdomain));
    /*
     * The interface the catalogue was read from is recorded because, unlike the
     * iw-phy path, this data is per-VAP rather than per-wiphy. Without it a
     * reader cannot tell which of a radio's interfaces answered.
     */
    json_object_object_add(catalog, "interface",
                           json_object_new_string(target.interface));
    if (set.truncated)
        json_object_object_add(catalog, "truncated",
                               json_object_new_boolean(1));
    json_object_object_get_ex(catalog, "channels", &channels);
    if (!channels) {
        json_object_put(catalog);
        goto done;
    }
    for (i = 0; i < set.count; i++) {
        const struct apd_vendor_channel *src = &set.items[i];
        struct json_object *channel = json_object_new_object();
        struct json_object *widths;

        json_object_object_add(channel, "channel",
                               json_object_new_int(src->channel));
        json_object_object_add(channel, "frequency_mhz",
                               json_object_new_int(src->freq_mhz));
        /*
         * The vendor listing has no disabled/no-IR notion, so those flags are
         * reported false rather than omitted: the iw-phy path always emits
         * them, and a reader that treats "absent" as "unknown" would otherwise
         * see two different shapes for the same field depending on source.
         */
        json_object_object_add(channel, "disabled",
                               json_object_new_boolean(0));
        json_object_object_add(channel, "no_ir", json_object_new_boolean(0));
        json_object_object_add(channel, "radar_detection",
                               json_object_new_boolean(src->dfs ? 1 : 0));
        if (src->mode[0])
            json_object_object_add(channel, "mode",
                                   json_object_new_string(src->mode));
        widths = json_object_new_array();
        if (src->width_20)
            json_object_array_add(widths, json_object_new_int(20));
        if (src->width_40)
            json_object_array_add(widths, json_object_new_int(40));
        if (src->width_80)
            json_object_array_add(widths, json_object_new_int(80));
        if (src->width_160)
            json_object_array_add(widths, json_object_new_int(160));
        if (json_object_array_length(widths))
            json_object_object_add(channel, "supported_widths_mhz", widths);
        else
            json_object_put(widths);
        if (src->center_80)
            json_object_object_add(channel, "center_channel_80",
                                   json_object_new_int(src->center_80));
        if (src->center_160)
            json_object_object_add(channel, "center_channel_160",
                                   json_object_new_int(src->center_160));
        json_object_array_add(channels, channel);
    }
    json_object_object_add(radio, "channel_catalog", catalog);
    rc = 0;

done:
    apd_command_result_free(&listing);
    apd_command_result_free(&inventory);
    return rc;
}

static void apd_reg_domain(const char *path, char *out, size_t out_len)
{
    struct apd_command_result result = { 0 };

    out[0] = '\0';
    {
        char *const argv[] = { (char *)path, "reg", "get", NULL };

        if (apd_readonly_command(path, argv, &result) == 0 && result.text) {
            const char *country = strstr(result.text, "country ");

            if (country &&
                sscanf(country, "country %7[^:]:", out) != 1)
                out[0] = '\0';
            if (strlen(out) >= out_len)
                out[0] = '\0';
        }
    }
    apd_command_result_free(&result);
}

static void apd_collect_channel_catalogs(const char *path,
                                         struct json_object *radios,
                                         int64_t observed_at)
{
    struct apd_command_result result = { 0 };
    char regdomain[8] = { 0 };
    const char *failure = NULL;
    size_t i;

    apd_reg_domain(path, regdomain, sizeof(regdomain));
    {
        char *const argv[] = { (char *)path, "phy", NULL };

        if (apd_readonly_command(path, argv, &result) != 0)
            failure = result.timed_out ? "iw_phy_timeout" :
                      result.output_limited ? "iw_phy_output_limited" :
                                              "iw_phy_failed";
    }
    if (!failure)
        apd_channel_catalog_parse(result.text, radios, regdomain,
                                  observed_at);
    /*
     * Vendor fallback for radios `iw phy` did not describe.
     *
     * QCA driver builds answer `iw phy` without a channel list while still
     * reporting a full catalogue through `wlanconfig <if> list chan`. The old
     * code recorded "wiphy_not_in_iw_phy_output" and stopped there, which read
     * as "the driver cannot report channels" when in fact only the probe was
     * wrong.
     *
     * The interface for a radio comes from the same `iw dev` inventory the
     * survey and neighbor collectors already use, so a radio with no usable AP
     * interface falls through to the original reason rather than guessing a
     * name.
     */
    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        struct json_object *existing = NULL;
        const char *reason = failure ? failure : "wiphy_not_in_iw_phy_output";

        if (json_object_object_get_ex(radio, "channel_catalog", &existing))
            continue;
        if (apd_channel_catalog_vendor_fallback(radio, regdomain, observed_at,
                                                reason) == 0)
            continue;
        json_object_object_add(radio, "channel_catalog",
            apd_channel_catalog_new(reason, observed_at));
    }
    apd_command_result_free(&result);
}

/* ── Band-scoped catalogs for single-wiphy multi-radio hardware ───────────
 *
 * mac80211 radios on a BE10000-class board all live on one wiphy: phy0r0,
 * phy0r1 and phy0r2 report phy=phy0 and `iw phy` prints a single "Wiphy phy0"
 * with Band 1/2/4 underneath. The per-wiphy parser above matches the Wiphy
 * name against radio.id, which no such radio ever equals, so every radio came
 * back with channel_catalog absent -- and the AC's fail-closed evidence check
 * (ac_wifi_validate_evidence) then refused every channel/width/tx-power write
 * with channel_catalog_missing. That is the whole reason the射频 sheet was
 * read-only on a managed AP.
 *
 * Each band block becomes its own catalog and is attached to the radio(s)
 * whose band it is, so a 2.4 GHz radio is never told it may use channel 165.
 * Band membership comes from the frequencies the driver actually printed, not
 * from a country table.
 */
#define APD_CHANNEL_CATALOG_BANDS_MAX 8U

struct apd_channel_band_catalog {
    struct json_object *catalog;
    struct json_object *channels;
    struct apd_channel_width_evidence width;
    const char *band;
    /* Highest spatial-stream count the driver claims for this band, read from
     * the HE RX/TX "N streams:" rows. Station rows cannot supply this on
     * mac80211 (no per-station NSS in `iw station dump`), which is why the
     * wireless page reported MIMO as "not reported" on hardware that plainly
     * advertises 4x4. */
    int rx_nss;
    int tx_nss;
    int nss_direction;   /* 0 unknown, 1 RX block, 2 TX block */
};

/* "4 streams: MCS 0-11" -> 4; "5 streams: not supported" -> 0. */
static int apd_channel_stream_row(const char *value)
{
    int streams = 0;
    const char *tail;

    if (sscanf(value, "%d streams:", &streams) != 1 || streams <= 0 ||
        streams > 16)
        return 0;
    tail = strchr(value, ':');
    if (!tail || strstr(tail, "not supported"))
        return 0;
    return streams;
}

static void apd_channel_band_scan_nss(struct apd_channel_band_catalog *band,
                                      const char *value)
{
    int streams;

    if (strstr(value, "RX MCS and NSS set") || strstr(value, "RX MCS Set"))
        band->nss_direction = 1;
    else if (strstr(value, "TX MCS and NSS set") ||
             strstr(value, "TX MCS Set"))
        band->nss_direction = 2;
    streams = apd_channel_stream_row(value);
    if (!streams)
        return;
    if (band->nss_direction == 2) {
        if (streams > band->tx_nss)
            band->tx_nss = streams;
    } else if (band->nss_direction == 1) {
        if (streams > band->rx_nss)
            band->rx_nss = streams;
    }
}

static const char *apd_channel_band_code(int frequency_mhz)
{
    if (frequency_mhz >= 2400 && frequency_mhz < 2500)
        return "2g";
    if (frequency_mhz >= 4900 && frequency_mhz < 5925)
        return "5g";
    if (frequency_mhz >= 5925 && frequency_mhz < 7125)
        return "6g";
    return NULL;
}

static const char *apd_channel_band_of_catalog(struct json_object *channels)
{
    size_t i;

    for (i = 0; channels && i < json_object_array_length(channels); i++) {
        struct json_object *entry = json_object_array_get_idx(channels, i);
        struct json_object *field = NULL;
        const char *band;

        if (!entry ||
            !json_object_object_get_ex(entry, "frequency_mhz", &field) || !field)
            continue;
        band = apd_channel_band_code(json_object_get_int(field));
        if (band)
            return band;
    }
    return NULL;
}

/* Normalizes the band spellings that reach a radio object: UCI writes
 * `2g`/`5g`/`6g`, the openwrt backend's own inventory writes `2.4GHz`. */
static const char *apd_channel_band_normalize(const char *raw)
{
    if (!raw || !raw[0])
        return NULL;
    if (!strcmp(raw, "2g") || !strcmp(raw, "2.4GHz") || !strcmp(raw, "2.4g"))
        return "2g";
    if (!strcmp(raw, "5g") || !strcmp(raw, "5GHz"))
        return "5g";
    if (!strcmp(raw, "6g") || !strcmp(raw, "6GHz"))
        return "6g";
    return NULL;
}

static const char *apd_channel_radio_band(struct json_object *radio)
{
    struct json_object *field = NULL;
    const char *band = NULL;

    if (json_object_object_get_ex(radio, "band", &field) && field &&
        json_object_is_type(field, json_type_string))
        band = apd_channel_band_normalize(json_object_get_string(field));
    if (band)
        return band;
    if (json_object_object_get_ex(radio, "frequency_mhz", &field) && field)
        return apd_channel_band_code(json_object_get_int(field));
    return NULL;
}

void apd_collect_channel_catalogs_by_band(struct json_object *radios,
                                          int64_t observed_at)
{
    const char *path = apd_find_iw();
    struct apd_command_result result = { 0 };
    struct apd_channel_band_catalog bands[APD_CHANNEL_CATALOG_BANDS_MAX];
    char regdomain[8] = { 0 };
    const char *failure = NULL;
    char *copy = NULL;
    char *line;
    char *saveptr = NULL;
    size_t band_count = 0;
    size_t i;

    if (!radios)
        return;
    memset(bands, 0, sizeof(bands));
    if (!path) {
        failure = "iw_binary_unavailable";
        goto attach;
    }
    apd_reg_domain(path, regdomain, sizeof(regdomain));
    {
        char *const argv[] = { (char *)path, "phy", NULL };

        if (apd_readonly_command(path, argv, &result) != 0) {
            failure = result.timed_out ? "iw_phy_timeout" :
                      result.output_limited ? "iw_phy_output_limited" :
                                              "iw_phy_failed";
            goto attach;
        }
    }
    copy = strdup(result.text ? result.text : "");
    if (!copy) {
        failure = "iw_phy_allocation_failed";
        goto attach;
    }
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_channel_line_trim(line);
        struct apd_channel_band_catalog *current;
        struct json_object *channel = NULL;

        if (!strncmp(value, "Band ", 5) && strchr(value, ':')) {
            if (band_count >= APD_CHANNEL_CATALOG_BANDS_MAX)
                break;
            current = &bands[band_count++];
            current->catalog = apd_channel_catalog_new(NULL, observed_at);
            if (!current->catalog) {
                band_count--;
                continue;
            }
            if (regdomain[0])
                json_object_object_add(current->catalog, "regdomain",
                                       json_object_new_string(regdomain));
            json_object_object_get_ex(current->catalog, "channels",
                                      &current->channels);
            continue;
        }
        if (!band_count)
            continue;
        current = &bands[band_count - 1];
        if (!current->channels)
            continue;
        /* The per-channel object is re-resolved from the array rather than
         * carried across lines, because a "DFS state:" line always follows the
         * frequency line it belongs to. */
        if (json_object_array_length(current->channels))
            channel = json_object_array_get_idx(current->channels,
                json_object_array_length(current->channels) - 1);
        apd_channel_band_scan_nss(current, value);
        apd_channel_catalog_scan_line(value, current->channels, &channel,
                                      &current->width);
    }
    for (i = 0; i < band_count; i++) {
        apd_channel_catalog_finalize(bands[i].catalog, bands[i].channels,
                                     &bands[i].width);
        bands[i].band = apd_channel_band_of_catalog(bands[i].channels);
        if (bands[i].band)
            json_object_object_add(bands[i].catalog, "band",
                                   json_object_new_string(bands[i].band));
        if (bands[i].rx_nss > 0 && bands[i].tx_nss > 0) {
            char mimo[24];

            snprintf(mimo, sizeof(mimo), "%dx%d", bands[i].rx_nss,
                     bands[i].tx_nss);
            json_object_object_add(bands[i].catalog, "spatial_streams_rx",
                                   json_object_new_int(bands[i].rx_nss));
            json_object_object_add(bands[i].catalog, "spatial_streams_tx",
                                   json_object_new_int(bands[i].tx_nss));
            json_object_object_add(bands[i].catalog, "mimo",
                                   json_object_new_string(mimo));
        }
    }
attach:
    for (i = 0; i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        struct json_object *existing = NULL;
        const char *radio_band = apd_channel_radio_band(radio);
        size_t j;
        int attached = 0;

        if (!radio || json_object_object_get_ex(radio, "channel_catalog",
                                                &existing))
            continue;
        for (j = 0; radio_band && j < band_count; j++) {
            struct json_object *mimo = NULL;

            if (!bands[j].band || !bands[j].catalog ||
                strcmp(bands[j].band, radio_band))
                continue;
            /* Radios share a band catalogue by reference count, not by copy:
             * two 5 GHz radios on one wiphy see identical driver evidence. */
            json_object_object_add(radio, "channel_catalog",
                                   json_object_get(bands[j].catalog));
            /* Republished on the radio itself because the aggregator reads
             * MIMO at radio level; the catalogue keeps the same value with its
             * stream counts for anything that wants the detail. */
            if (json_object_object_get_ex(bands[j].catalog, "mimo", &mimo) &&
                mimo && !json_object_object_get_ex(radio, "mimo", NULL)) {
                json_object_object_add(radio, "mimo", json_object_get(mimo));
                json_object_object_add(radio, "mimo_source",
                                       json_object_new_string("iw_phy_he_nss"));
            }
            attached = 1;
            break;
        }
        if (attached)
            continue;
        json_object_object_add(radio, "channel_catalog",
            apd_channel_catalog_new(failure ? failure :
                radio_band ? "iw_phy_band_not_reported" :
                             "radio_band_unknown", observed_at));
    }
    for (i = 0; i < band_count; i++)
        json_object_put(bands[i].catalog);
    free(copy);
    apd_command_result_free(&result);
}

#endif /* channel catalog visibility */

#ifndef APD_HOSTAPD_STANDALONE_TEST

static struct json_object *apd_collect_iw(int phy_count,
                                          struct json_object **radios_out,
                                          struct json_object **ssids_out,
                                          int64_t observed_at,
                                          int *complete_out)
{
    const char *path = apd_find_iw();
    struct apd_command_result result = { 0 };
    struct json_object *radios = json_object_new_array();
    struct json_object *ssids = json_object_new_array();
    struct json_object *state;
    int complete = 0;
    int survey_count = 0;
    int survey_complete_count = 0;
    const char *reason = NULL;

    *radios_out = radios;
    *ssids_out = ssids;
    if (phy_count == 0) {
        state = apd_source_state("iw_dev", "runtime", path != NULL, 0,
                                 "no_phy_detected", observed_at);
        goto done;
    }
    if (!path) {
        state = apd_source_state("iw_dev", "runtime", 0, 0,
                                 "iw_binary_unavailable", observed_at);
        complete = 0;
        goto done;
    }
    {
        char *const argv[] = { (char *)path, "dev", NULL };
        if (apd_readonly_command(path, argv, &result) != 0) {
            reason = result.timed_out ? "iw_dev_timeout" : "iw_dev_failed";
            state = apd_source_state("iw_dev", "runtime", 1, 0,
                                     reason, observed_at);
            json_object_object_add(state, "exit_status",
                                   json_object_new_int(result.exit_status));
            complete = 0;
            goto free_result;
        }
    }
    if (apd_parse_iw_dev(result.text, radios, ssids, observed_at) != 0) {
        state = apd_source_state("iw_dev", "runtime", 1, 0,
                                 "iw_output_parse_failed", observed_at);
        goto free_result;
    }
    apd_collect_radio_surveys(path, radios, observed_at, &survey_count,
                              &survey_complete_count);
    {
        int logical_radios = 0;
        size_t i;

        for (i = 0; i < json_object_array_length(radios); i++) {
            struct json_object *radio =
                json_object_array_get_idx(radios, i);
            struct json_object *index = NULL;

            if (radio && json_object_object_get_ex(radio, "radio_index",
                                                   &index)) {
                logical_radios = 1;
                break;
            }
        }
        if (logical_radios)
            apd_collect_channel_catalogs_by_band(radios, observed_at);
        else
            apd_collect_channel_catalogs(path, radios, observed_at);
    }
    complete = json_object_array_length(radios) > 0;
    if (!json_object_array_length(radios))
        reason = "empty_runtime_inventory";
    state = apd_source_state("iw_dev", "runtime", 1, complete, reason,
                             observed_at);
    json_object_object_add(state, "radio_count",
                           json_object_new_int((int)json_object_array_length(radios)));
    json_object_object_add(state, "ssid_count",
                           json_object_new_int((int)json_object_array_length(ssids)));
    json_object_object_add(state, "passive_survey_collector",
                           json_object_new_string("iw_survey"));
    json_object_object_add(state, "survey_available",
                           json_object_new_boolean(survey_complete_count > 0));
    json_object_object_add(state, "survey_count",
                           json_object_new_int(survey_count));
    json_object_object_add(state, "survey_complete_count",
                           json_object_new_int(survey_complete_count));
free_result:
    apd_command_result_free(&result);
done:
    if (complete_out)
        *complete_out = complete;
    return state;
}

static int apd_openwrt_probe(struct json_object **out)
{
    struct json_object *probe;
    int inventory_available = 0;
    int phy_count;
    uint32_t object_id;

    if (!out)
        return -1;
    phy_count = apd_openwrt_phy_count(&inventory_available);
    probe = json_object_new_object();
    json_object_object_add(probe, "backend",
                           json_object_new_string("openwrt-netifd-hostapd-nl80211"));
    json_object_object_add(probe, "phy_count", json_object_new_int(phy_count));
    json_object_object_add(probe, "wireless_present",
                           json_object_new_boolean(inventory_available && phy_count > 0));
    json_object_object_add(probe, "snapshot_supported", json_object_new_boolean(1));
    json_object_object_add(probe, "sysfs_available",
                           json_object_new_boolean(inventory_available));
    json_object_object_add(probe, "uci_available",
                           json_object_new_boolean(access(APD_UCI_CONFIG_DIR, R_OK) == 0));
    json_object_object_add(probe, "iw_available",
                           json_object_new_boolean(apd_find_iw() != NULL));
    json_object_object_add(probe, "hostapd_control_available",
                           json_object_new_boolean(
                               apd_hostapd_control_dir_available()));
    json_object_object_add(probe, "netifd_wireless_available",
        json_object_new_boolean(g_apd_ubus &&
            ubus_lookup_id(g_apd_ubus, "network.wireless", &object_id) == UBUS_STATUS_OK));
    *out = probe;
    return 0;
}

int apd_backend_neighbor_scan(const char *radio_id, struct json_object **out)
{
    return apd_neighbor_scan_collect(apd_find_iw(), radio_id, out);
}

int apd_backend_survey_scan(const char *radio_id, struct json_object **out)
{
    return apd_survey_scan_collect(apd_find_iw(), radio_id, out);
}

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

#ifndef APD_PROC_UPTIME_PATH
#define APD_PROC_UPTIME_PATH "/proc/uptime"
#endif
#ifndef APD_OPENWRT_RELEASE_PATH
#define APD_OPENWRT_RELEASE_PATH "/etc/openwrt_release"
#endif
#ifndef APD_PROC_NET_ROUTE_PATH
#define APD_PROC_NET_ROUTE_PATH "/proc/net/route"
#endif

static void apd_system_null_with_reason(struct json_object *object,
                                        const char *key,
                                        const char *reason_key,
                                        const char *reason)
{
    json_object_object_add(object, key, json_object_new_null());
    json_object_object_add(object, reason_key,
                           json_object_new_string(reason));
}

/* Parse VAR='value' lines from /etc/openwrt_release without a shell. */
static int apd_openwrt_release_value(const char *text, const char *name,
                                     char *out, size_t out_len)
{
    const char *cursor = text;
    size_t name_len = strlen(name);

    while (cursor && *cursor) {
        const char *line_end = strchr(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - cursor) :
                                     strlen(cursor);

        if (line_len > name_len + 2 &&
            !strncmp(cursor, name, name_len) && cursor[name_len] == '=' &&
            cursor[name_len + 1] == '\'' && cursor[line_len - 1] == '\'') {
            size_t value_len = line_len - name_len - 3;

            if (value_len >= out_len)
                value_len = out_len - 1;
            memcpy(out, cursor + name_len + 2, value_len);
            out[value_len] = '\0';
            return out[0] != '\0' ? 0 : -1;
        }
        cursor = line_end ? line_end + 1 : NULL;
    }
    return -1;
}

static int apd_system_read_small_file(const char *path, char *out,
                                      size_t out_len)
{
    ssize_t length;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0 || !out || out_len < 2)
        return fd >= 0 ? (close(fd), -1) : -1;
    do {
        length = read(fd, out, out_len - 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    if (length <= 0)
        return -1;
    out[length] = '\0';
    return 0;
}

/* Interface carrying the IPv4 default route; the management path an
 * operator would use to reach this AP. */
static int apd_system_default_route_interface(char *out, size_t out_len)
{
    char text[8192];
    const char *cursor;

    if (apd_system_read_small_file(APD_PROC_NET_ROUTE_PATH, text,
                                   sizeof(text)) != 0)
        return -1;
    cursor = strchr(text, '\n');
    cursor = cursor ? cursor + 1 : NULL;
    while (cursor && *cursor) {
        char iface[IFNAMSIZ + 1] = { 0 };
        char destination[16] = { 0 };
        unsigned int flags = 0;
        const char *line_end = strchr(cursor, '\n');

        if (sscanf(cursor, "%16s %15s %*s %x", iface, destination,
                   &flags) == 3 &&
            !strcmp(destination, "00000000") && (flags & 0x1U)) {
            snprintf(out, out_len, "%s", iface);
            return 0;
        }
        cursor = line_end ? line_end + 1 : NULL;
    }
    return -1;
}

static int apd_system_interface_ipv4(const char *interface, char *out,
                                     size_t out_len)
{
    struct ifaddrs *list = NULL;
    struct ifaddrs *entry;
    int rc = -1;

    if (getifaddrs(&list) != 0)
        return -1;
    for (entry = list; entry; entry = entry->ifa_next) {
        if (!entry->ifa_name || !entry->ifa_addr ||
            entry->ifa_addr->sa_family != AF_INET ||
            strcmp(entry->ifa_name, interface) != 0)
            continue;
        if (inet_ntop(AF_INET,
                      &((struct sockaddr_in *)(void *)entry->ifa_addr)->sin_addr,
                      out, (socklen_t)out_len)) {
            rc = 0;
            break;
        }
    }
    freeifaddrs(list);
    return rc;
}

/* Read-only device facts for the UniFi AP-details contract: uptime,
 * firmware identity and the management interface address.  Every field is
 * evidence-backed; missing evidence stays null with a reason instead of a
 * fabricated value. */
static struct json_object *apd_collect_system_facts(int64_t observed_at)
{
    struct json_object *facts = json_object_new_object();
    char text[512];
    char value[256];
    char interface[IFNAMSIZ + 1] = { 0 };

    json_object_object_add(facts, "source",
                           json_object_new_string("apd_local_readonly"));
    json_object_object_add(facts, "scope", json_object_new_string("runtime"));
    json_object_object_add(facts, "observed_at",
                           json_object_new_int64(observed_at));

    if (apd_system_read_small_file(APD_PROC_UPTIME_PATH, text,
                                   sizeof(text)) == 0) {
        double uptime = -1.0;

        if (sscanf(text, "%lf", &uptime) == 1 && uptime >= 0.0) {
            json_object_object_add(facts, "uptime_seconds",
                                   json_object_new_int64((int64_t)uptime));
            json_object_object_add(facts, "uptime_source",
                                   json_object_new_string("proc_uptime"));
        } else {
            apd_system_null_with_reason(facts, "uptime_seconds",
                                        "uptime_reason",
                                        "proc_uptime_parse_failed");
        }
    } else {
        apd_system_null_with_reason(facts, "uptime_seconds", "uptime_reason",
                                    "proc_uptime_unavailable");
    }

    if (apd_system_read_small_file(APD_OPENWRT_RELEASE_PATH, text,
                                   sizeof(text)) == 0) {
        if (apd_openwrt_release_value(text, "DISTRIB_DESCRIPTION", value,
                                      sizeof(value)) == 0 ||
            apd_openwrt_release_value(text, "DISTRIB_RELEASE", value,
                                      sizeof(value)) == 0) {
            json_object_object_add(facts, "firmware_version",
                                   json_object_new_string(value));
            json_object_object_add(facts, "firmware_source",
                                   json_object_new_string("etc_openwrt_release"));
        } else {
            apd_system_null_with_reason(facts, "firmware_version",
                                        "firmware_reason",
                                        "openwrt_release_parse_failed");
        }
        if (apd_openwrt_release_value(text, "DISTRIB_REVISION", value,
                                      sizeof(value)) == 0)
            json_object_object_add(facts, "firmware_revision",
                                   json_object_new_string(value));
    } else {
        apd_system_null_with_reason(facts, "firmware_version",
                                    "firmware_reason",
                                    "openwrt_release_unavailable");
    }

    if (apd_system_default_route_interface(interface,
                                           sizeof(interface)) == 0) {
        char path[128];

        json_object_object_add(facts, "management_interface",
                               json_object_new_string(interface));
        json_object_object_add(facts, "management_source",
                               json_object_new_string("default_route_interface"));
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", interface);
        if (apd_device_file_read(path, value, sizeof(value)) == 0 &&
            strlen(value) == 17)
            json_object_object_add(facts, "mac",
                                   json_object_new_string(value));
        else
            apd_system_null_with_reason(facts, "mac", "mac_reason",
                                        "interface_mac_unavailable");
        if (apd_system_interface_ipv4(interface, value, sizeof(value)) == 0)
            json_object_object_add(facts, "ip", json_object_new_string(value));
        else
            apd_system_null_with_reason(facts, "ip", "ip_reason",
                                        "interface_ipv4_unavailable");
    } else {
        apd_system_null_with_reason(facts, "management_interface",
                                    "management_reason",
                                    "default_route_unavailable");
        apd_system_null_with_reason(facts, "mac", "mac_reason",
                                    "default_route_unavailable");
        apd_system_null_with_reason(facts, "ip", "ip_reason",
                                    "default_route_unavailable");
    }
    return facts;
}

static int apd_openwrt_snapshot(struct json_object **out)
{
    struct json_object *root;
    struct json_object *sources;
    struct json_object *desired;
    struct json_object *desired_radios = NULL;
    struct json_object *desired_ssids = NULL;
    struct json_object *radios = NULL;
    struct json_object *ssids = NULL;
    struct json_object *stations = NULL;
    struct json_object *source;
    int64_t observed_at = apd_now_s();
    int inventory_available = 0;
    int phy_count;
    int iw_complete = 0;
    int netifd_complete = 0;
    int hostapd_complete = 0;
    int complete;
    const char *reason = NULL;
    struct apd_device_model device;

    if (!out)
        return -1;
    memset(&device, 0, sizeof(device));
    apd_backend_device_model_collect(&device);
    phy_count = apd_openwrt_phy_count(&inventory_available);
    root = json_object_new_object();
    sources = json_object_new_object();
    desired = json_object_new_object();

    if (!inventory_available)
        source = apd_source_state("sysfs_ieee80211", "runtime", 0, 0,
                                  "phy_inventory_unavailable", observed_at);
    else
        source = apd_source_state("sysfs_ieee80211", "runtime", 1, 1,
                                  phy_count == 0 ? "no_phy_detected" : NULL,
                                  observed_at);
    json_object_object_add(source, "phy_count", json_object_new_int(phy_count));
    json_object_object_add(sources, "sysfs", source);

    apd_collect_uci(&desired_radios, &desired_ssids, &source, observed_at);
    json_object_object_add(sources, "uci", source);
    source = apd_collect_netifd(phy_count, observed_at, &netifd_complete);
    json_object_object_add(sources, "netifd", source);
    source = apd_collect_iw(phy_count, &radios, &ssids, observed_at, &iw_complete);
    json_object_object_add(sources, "iw", source);
    source = apd_collect_hostapd(phy_count, &stations, observed_at,
                                 &hostapd_complete);
    json_object_object_add(sources, "hostapd", source);

    if (!inventory_available) {
        complete = 0;
        reason = "phy_inventory_unavailable";
    } else if (phy_count == 0) {
        complete = 1;
        reason = "no_phy_detected";
    } else {
        complete = iw_complete && netifd_complete && hostapd_complete;
        if (!complete)
            reason = "partial_runtime_sources";
    }

    json_object_object_add(desired, "source",
                           json_object_new_string("uci_wireless"));
    json_object_object_add(desired, "scope", json_object_new_string("desired"));
    json_object_object_add(desired, "radios", desired_radios);
    json_object_object_add(desired, "ssids", desired_ssids);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(APD_CONTRACT_VERSION));
    json_object_object_add(root, "snapshot_version",
                           json_object_new_string(APD_SNAPSHOT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(APD_SERVICE_NAME));
    json_object_object_add(root, "backend",
                           json_object_new_string("openwrt-netifd-hostapd-nl80211"));
    json_object_object_add(root, "observed_at", json_object_new_int64(observed_at));
    json_object_object_add(root, "complete", json_object_new_boolean(complete));
    json_object_object_add(root, "stale", json_object_new_boolean(0));
    apd_json_nullable_string(root, "reason", reason);
    json_object_object_add(root, "wireless_present",
                           json_object_new_boolean(inventory_available && phy_count > 0));
    json_object_object_add(root, "phy_count", json_object_new_int(phy_count));
    json_object_object_add(root, "radio_count",
                           json_object_new_int((int)json_object_array_length(radios)));
    json_object_object_add(root, "ssid_count",
                           json_object_new_int((int)json_object_array_length(ssids)));
    json_object_object_add(root, "station_count",
                           json_object_new_int((int)json_object_array_length(stations)));
    json_object_object_add(root, "system",
                           apd_collect_system_facts(observed_at));
    json_object_object_add(root, "model", json_object_new_string(device.model));
    json_object_object_add(root, "board_name",
                           json_object_new_string(device.board_name));
    json_object_object_add(root, "model_source",
                           json_object_new_string(device.model_source));
    json_object_object_add(root, "model_available",
                           json_object_new_boolean(device.model_available));
    json_object_object_add(root, "model_reason",
                           json_object_new_string(device.reason));
    json_object_object_add(root, "radios", radios);
    json_object_object_add(root, "ssids", ssids);
    json_object_object_add(root, "stations", stations);
    json_object_object_add(root, "desired", desired);
    json_object_object_add(root, "sources", sources);
    *out = root;
    return 0;
}

static int apd_openwrt_validate(struct json_object *candidate,
                                struct json_object **out)
{
    if (apd_config_candidate_has_actions(candidate))
        return apd_config_hostapd_actions_validate(candidate, out);
    return apd_config_candidate_validate(candidate, out);
}

static int apd_openwrt_stage(struct json_object *candidate,
                             struct json_object **out)
{
    struct apd_config_paths paths = { "/sbin/uci", "/sbin/wifi",
                                      "/etc/config",
                                      "/tmp/dreamingwrt-apd-config-candidate" };
    return apd_config_stage(&paths, candidate, out);
}


#endif
#if !defined(APD_HOSTAPD_STANDALONE_TEST) || defined(APD_ROAMING_STANDALONE_TEST)

/* ---- Phase 3: hostapd action helpers for 11k neighbor and 11v BTM ---- */

/* Resolve the hostapd control socket path for a given BSS interface name.
 * Reads the per-BSS runtime conf to find ctrl_interface=, then builds the
 * full socket path "<ctrl_dir>/<bss_interface>".  Returns 0 on success. */
static int apd_phase3_ctrl_path(const char *identifier,
                                 char *out, size_t out_len)
{
    char ctrl_dir[APD_HOSTAPD_DIR_LEN];

    if (!identifier || !out || out_len == 0)
        return -1;
    /* Fast path: identifier is the BSS interface name. */
    if (apd_hostapd_conf_control_dir(identifier, ctrl_dir,
                                      sizeof(ctrl_dir), NULL) == 0)
        return apd_hostapd_socket_path(ctrl_dir, identifier, out, out_len);
    /* Slow path: identifier might be a BSSID.  Scan hostapd sockets
     * and match by sending STATUS.  Only runs when conf lookup fails. */
    {
        char scan_dirs[1 + APD_HOSTAPD_VENDOR_DIR_LIMIT][APD_HOSTAPD_DIR_LEN];
        const char *dirs[1 + APD_HOSTAPD_VENDOR_DIR_LIMIT];
        size_t dir_count = 0;
        DIR *d;
        struct dirent *entry;
        size_t si;

        snprintf(scan_dirs[0], APD_HOSTAPD_DIR_LEN, "%s", APD_HOSTAPD_RUN_DIR);
        dirs[0] = scan_dirs[0];
        dir_count = 1;
        {
            size_t vcount = apd_hostapd_vendor_dirs(&scan_dirs[dir_count],
                                                    APD_HOSTAPD_VENDOR_DIR_LIMIT);
            size_t vi;
            for (vi = 0; vi < vcount; vi++) {
                dirs[dir_count] = scan_dirs[dir_count];
                dir_count++;
            }
        }
        for (si = 0; si < dir_count; si++) {
            d = opendir(dirs[si]);
            if (!d)
                continue;
            while ((entry = readdir(d)) != NULL) {
                char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
                char response[1024];
                size_t response_len = 0;
                enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
                char *bssid_line;
                struct stat st;

                if (entry->d_name[0] == '.')
                    continue;
                if (!strcmp(entry->d_name, "global"))
                    continue;
                if (apd_hostapd_socket_path(dirs[si], entry->d_name,
                                            path, sizeof(path)) != 0 ||
                    lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode))
                    continue;
                if (!strcmp(entry->d_name, identifier)) {
                    closedir(d);
                    snprintf(out, out_len, "%s", path);
                    return 0;
                }
                if (apd_hostapd_request(path, "STATUS", response,
                                        sizeof(response), &response_len,
                                        0, &stage) != APD_HOSTAPD_REQUEST_OK)
                    continue;
                response[sizeof(response) - 1] = '\0';
                bssid_line = strstr(response, "bssid=");
                if (!bssid_line) {
                    bssid_line = strstr(response, "bssid[0]=");
                    if (bssid_line)
                        bssid_line += 3;
                }
                if (!bssid_line)
                    continue;
                bssid_line += 6;
                if (!strncasecmp(bssid_line, identifier, 17) &&
                    (bssid_line[17] == '\n' || bssid_line[17] == '\0' ||
                     bssid_line[17] == ' ')) {
                    closedir(d);
                    return apd_hostapd_socket_path(dirs[si], entry->d_name,
                                                   out, out_len);
                }
            }
            closedir(d);
        }
    }
    return -1;
}

/* ---- Phase 3 hostapd wire formats ------------------------------------------
 *
 * Both commands below previously used an invented syntax that hostapd does not
 * accept, and in the BTM case did so while still reporting success:
 *
 *   SET_NEIGHBOR <bssid> oc=<n> ch=<n>
 *       hostapd_ctrl_iface_set_neighbor() requires "ssid=" and "nr="; with
 *       neither it bails at "Bad or missing SSID" and show_neighbor stays FAIL.
 *
 *   BSS_TM_REQ <sta> <target_bssid> validity=<n>
 *       hostapd only reads space-prefixed key=value tokens after the STA
 *       address.  The bare BSSID was ignored, "validity=" is not the token
 *       (it is " valid_int="), and ieee802_11_parse_candidate_list() returns 0
 *       rather than an error when it finds no " neighbor=" -- so hostapd
 *       answered OK to a transition request carrying no candidates at all.
 */

/* Neighbor Report element body: BSSID(6) || BSSID Information(4, little
 * endian) || Operating Class(1) || Channel(1) || PHY Type(1). */
#define APD_NR_ELEMENT_BYTES 13
#define APD_NR_HEX_LEN (APD_NR_ELEMENT_BYTES * 2)
/* An SSID is at most 32 octets, so 64 hex characters. */
#define APD_HOSTAPD_SSID_HEX_MAX 64

static int apd_parse_mac(const char *text, unsigned char out[6])
{
    unsigned int octet[6];
    int i;

    if (!text || sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x",
                        &octet[0], &octet[1], &octet[2],
                        &octet[3], &octet[4], &octet[5]) != 6)
        return -1;
    for (i = 0; i < 6; i++) {
        if (octet[i] > 0xff)
            return -1;
        out[i] = (unsigned char)octet[i];
    }
    return 0;
}

/* BSSID Information, IEEE 802.11 Table 9-176.  Only bits we can assert from
 * what the controller told us are set; speculative capability bits are left
 * clear because a station that trusts them and finds otherwise will fall back
 * to a full scan, which is the outcome 11k exists to avoid. */
static uint32_t apd_nr_bssid_info(int phy_type, int ft_capable)
{
    uint32_t info = 0;

    info |= 3u;         /* AP Reachability: reachable */
    info |= 1u << 2;    /* Security: same as current AP */
    info |= 1u << 3;    /* Key Scope: same authenticator */
    info |= 1u << 5;    /* QoS */
    info |= 1u << 6;    /* APSD */
    info |= 1u << 7;    /* Radio Measurement */
    if (ft_capable)
        info |= 1u << 10;   /* Mobility Domain */
    info |= 1u << 11;       /* High Throughput */
    if (phy_type >= 9)      /* PHY_TYPE_VHT and newer */
        info |= 1u << 12;
    return info;
}

static int apd_nr_element_hex(const char *bssid, int op_class, int channel,
                              int phy_type, int ft_capable,
                              char out[APD_NR_HEX_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char body[APD_NR_ELEMENT_BYTES];
    uint32_t info;
    int i;

    if (op_class <= 0 || op_class > 255 || channel <= 0 || channel > 255 ||
        phy_type <= 0 || phy_type > 255 || apd_parse_mac(bssid, body) != 0)
        return -1;
    info = apd_nr_bssid_info(phy_type, ft_capable);
    body[6] = (unsigned char)(info & 0xff);
    body[7] = (unsigned char)((info >> 8) & 0xff);
    body[8] = (unsigned char)((info >> 16) & 0xff);
    body[9] = (unsigned char)((info >> 24) & 0xff);
    body[10] = (unsigned char)op_class;
    body[11] = (unsigned char)channel;
    body[12] = (unsigned char)phy_type;
    for (i = 0; i < APD_NR_ELEMENT_BYTES; i++) {
        out[i * 2] = hex[body[i] >> 4];
        out[i * 2 + 1] = hex[body[i] & 0x0f];
    }
    out[APD_NR_HEX_LEN] = '\0';
    return 0;
}

static int apd_phase3_neighbor_readback(const char *ctrl_path,
    const char *bssid, const char *ssid_hex, const char *report)
{
    struct apd_hostapd_bss_observation *table = calloc(1, sizeof(*table));
    char *response = calloc(1, APD_HOSTAPD_RESPONSE_LIMIT + 2U);
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    size_t length = 0, i;
    int rc = -1;

    if (!table || !response)
        goto done;
    if (apd_hostapd_request(ctrl_path, "SHOW_NEIGHBOR", response,
            APD_HOSTAPD_RESPONSE_LIMIT + 2U, &length, 0, &stage) !=
                APD_HOSTAPD_REQUEST_OK ||
        apd_hostapd_neighbors_parse(response, table) != 0)
        goto done;
    for (i = 0; i < table->neighbor_count; i++) {
        const struct apd_hostapd_neighbor *row = &table->neighbors[i];

        if (!strcasecmp(row->bssid, bssid) && !strcmp(row->ssid_hex, ssid_hex) &&
            !strcmp(row->report, report)) {
            rc = 0;
            break;
        }
    }
done:
    free(table);
    free(response);
    return rc;
}

/* A replay must still own the same BSS when the queued job reaches the AP. */
static int apd_phase3_neighbor_owner(const char *ctrl_path,
                                     struct json_object *options)
{
    const char *bssid = json_object_get_string(
        json_object_object_get(options, "source_bssid"));
    const char *ssid = json_object_get_string(
        json_object_object_get(options, "source_ssid"));
    const char *peer = json_object_get_string(
        json_object_object_get(options, "neighbor_bssid"));
    const char *peer_ssid = json_object_get_string(
        json_object_object_get(options, "neighbor_ssid"));
    struct apd_hostapd_bss_observation *status;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    char response[4096];
    size_t length = 0;
    int ok = 0;

    if (!bssid && !ssid)
        return 1;
    if (!bssid || !ssid || !peer || !peer_ssid ||
        !strcasecmp(bssid, peer) || strcmp(ssid, peer_ssid))
        return 0;
    status = calloc(1, sizeof(*status));
    if (!status)
        return 0;
    if (apd_hostapd_request(ctrl_path, "STATUS", response, sizeof(response),
            &length, 0, &stage) == APD_HOSTAPD_REQUEST_OK &&
        apd_hostapd_parse_status(response, status) == 0 &&
        status->has_bssid && status->has_ssid &&
        !strcmp(status->state, "ENABLED") &&
        !strcasecmp(status->bssid, bssid) && !strcmp(status->ssid, ssid))
        ok = 1;
    free(status);
    return ok;
}

/* Success requires both an explicit ACK and the fixed report body in readback. */
static int apd_phase3_set_neighbor(const char *ctrl_path,
                                    const char *bssid,
                                    const char *ssid,
                                    int op_class,
                                    int channel,
                                    int phy_type,
                                    int ft_capable)
{
    static const char hex[] = "0123456789abcdef";
    char ssid_hex[APD_HOSTAPD_SSID_HEX_MAX + 1];
    char nr_hex[APD_NR_HEX_LEN + 1];
    char command[320];
    char response[256];
    size_t response_len = 0;
    size_t ssid_len;
    size_t i;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    int rc;

    if (!ctrl_path || !bssid || !ssid || !ssid[0])
        return -1;
    ssid_len = strlen(ssid);
    if (ssid_len > APD_HOSTAPD_SSID_HEX_MAX / 2)
        return -1;
    /* Hex rather than the quoted form: hostapd's ssid_parse() terminates a
     * quoted SSID at the closing quote and an unquoted one at the next space,
     * so a hex SSID cannot be broken by spaces or quotes in the name. */
    for (i = 0; i < ssid_len; i++) {
        ssid_hex[i * 2] = hex[(unsigned char)ssid[i] >> 4];
        ssid_hex[i * 2 + 1] = hex[(unsigned char)ssid[i] & 0x0f];
    }
    ssid_hex[ssid_len * 2] = '\0';
    if (apd_nr_element_hex(bssid, op_class, channel, phy_type, ft_capable,
                           nr_hex) != 0)
        return -1;
    rc = snprintf(command, sizeof(command), "SET_NEIGHBOR %s ssid=%s nr=%s",
                  bssid, ssid_hex, nr_hex);
    if (rc < 0 || (size_t)rc >= sizeof(command))
        return -1;
    rc = apd_hostapd_request(ctrl_path, command, response,
                              sizeof(response), &response_len, 0, &stage);
    if (rc != APD_HOSTAPD_REQUEST_OK ||
        (strcmp(response, "OK") && strcmp(response, "OK\n")))
        return -1;
    return apd_phase3_neighbor_readback(ctrl_path, bssid, ssid_hex, nr_hex);
}

/* Send DEL_NEIGHBOR <bssid> to hostapd. Returns 0 on success. */
static int apd_phase3_del_neighbor(const char *ctrl_path,
                                    const char *bssid)
{
    char command[65];
    char response[256];
    size_t response_len = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    int rc;

    if (!ctrl_path || !bssid)
        return -1;
    rc = snprintf(command, sizeof(command), "DEL_NEIGHBOR %s", bssid);
    if (rc < 0 || (size_t)rc >= sizeof(command))
        return -1;
    rc = apd_hostapd_request(ctrl_path, command, response,
                              sizeof(response), &response_len, 0, &stage);
    return rc == APD_HOSTAPD_REQUEST_OK && !apd_hostapd_is_fail(response) ?
           0 : -1;
}

/* Send BSS_TM_REQ with a real candidate list to hostapd.
 *
 * Every token after the STA address must be space prefixed, because hostapd
 * matches them with os_strstr(cmd, " valid_int=") and friends. " pref=1"
 * marks the list preferred; subelement 3 assigns the target preference 255.
 *
 * Returns 0 only when a candidate was actually included and hostapd accepted
 * the request. */
static int apd_phase3_send_btm(const char *ctrl_path,
                                 const char *sta_mac,
                                 const char *target_bssid,
                                 int op_class,
                                 int channel,
                                 int phy_type,
                                 int ft_capable,
                                 int validity,
                                 const char *target_bssid_2,
                                 int op_class_2,
                                 int channel_2,
                                 int phy_type_2,
                                 int ft_capable_2,
                                 int disassoc_imminent,
                                 int disassoc_timer)
{
    char command[384];
    char response[256];
    char normalized[18];
    char normalized_target[18];
    char normalized_target_2[18] = {0};
    size_t response_len = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    uint32_t info;
    uint32_t info_2;
    int rc;

    if (!ctrl_path ||
        apd_hostapd_parse_mac(sta_mac, normalized) != 0 ||
        apd_hostapd_parse_mac(target_bssid, normalized_target) != 0)
        return -1;
    /* Refuse rather than send a transition request with an empty candidate
     * list: hostapd answers OK to that, so the caller would record a steer
     * that never gave the station anywhere to go. */
    if (op_class <= 0 || op_class > 255 || channel <= 0 || channel > 255 ||
        phy_type <= 0 || phy_type > 255 || validity < 0 || validity > 255 ||
        disassoc_imminent < 0 || disassoc_imminent > 1 ||
        disassoc_timer < 0 || disassoc_timer > 65535)
        return -1;
    if (target_bssid_2 && target_bssid_2[0] &&
        (apd_hostapd_parse_mac(target_bssid_2, normalized_target_2) != 0 ||
         op_class_2 <= 0 || op_class_2 > 255 || channel_2 <= 0 ||
         channel_2 > 255 || phy_type_2 <= 0 || phy_type_2 > 255 ||
         !strcasecmp(normalized_target, normalized_target_2)))
        return -1;
    if (!apd_phase4_station_associated(ctrl_path, normalized) ||
        apd_roaming_monitor_attach(ctrl_path) != 0)
        return -1;
    info = apd_nr_bssid_info(phy_type, ft_capable);
    rc = snprintf(command, sizeof(command),
                  "BSS_TM_REQ %s neighbor=%s,%u,%d,%d,%d,0301ff pref=1",
                  normalized, normalized_target, (unsigned int)info,
                  op_class, channel, phy_type);
    if (rc < 0 || (size_t)rc >= sizeof(command))
        return -1;
    if (validity > 0) {
        int written = snprintf(command + rc, sizeof(command) - (size_t)rc,
                               " valid_int=%d", validity);
        if (written < 0 || (size_t)written >= sizeof(command) - (size_t)rc)
            return -1;
        rc += written;
    }
    if (target_bssid_2 && target_bssid_2[0]) {
        info_2 = apd_nr_bssid_info(phy_type_2, ft_capable_2);
        rc += snprintf(command + rc, sizeof(command) - (size_t)rc,
                       " neighbor=%s,%u,%d,%d,%d,0301fe pref=1",
                       normalized_target_2, (unsigned int)info_2, op_class_2,
                       channel_2, phy_type_2);
        if (rc < 0 || (size_t)rc >= sizeof(command))
            return -1;
    }
    rc += snprintf(command + rc, sizeof(command) - (size_t)rc,
                   " disassoc_imminent=%d disassoc_timer=%d",
                   disassoc_imminent, disassoc_timer);
    if (rc < 0 || (size_t)rc >= sizeof(command))
        return -1;
    rc = apd_hostapd_request(ctrl_path, command, response,
                              sizeof(response), &response_len, 0, &stage);
    return rc == APD_HOSTAPD_REQUEST_OK && !apd_hostapd_is_fail(response) ?
           0 : -1;
}

/* Phase 4: is this station currently associated with this BSS?
 *
 * hostapd's DEAUTHENTICATE sends the frame whether or not the station is on
 * this BSS -- ap_get_sta() returning NULL only skips the local cleanup.  So a
 * misrouted request would put a deauth frame on the air for someone else's
 * client and still answer OK.  Ask hostapd first and refuse if it does not
 * know the station: the AC does its own ownership check, this is the second
 * one at the point of no return. */
static int apd_phase4_station_associated(const char *ctrl_path,
                                         const char *sta_mac)
{
    char command[128];
    char *response;
    size_t response_len = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    int rc;

    if (!ctrl_path || !sta_mac || !sta_mac[0])
        return 0;
    rc = snprintf(command, sizeof(command), "STA %s", sta_mac);
    if (rc < 0 || (size_t)rc >= sizeof(command))
        return 0;
    response = calloc(1, APD_HOSTAPD_RESPONSE_LIMIT + 2U);
    if (!response)
        return 0;
    rc = apd_hostapd_request(ctrl_path, command, response,
                             APD_HOSTAPD_RESPONSE_LIMIT + 2U,
                             &response_len, 0, &stage);
    rc = rc == APD_HOSTAPD_REQUEST_OK && !apd_hostapd_is_fail(response) &&
         strncasecmp(response, sta_mac, strlen(sta_mac)) == 0 &&
         strstr(response, "[ASSOC]") != NULL;
    apd_hostapd_clear(response, APD_HOSTAPD_RESPONSE_LIMIT + 2U);
    free(response);
    return rc;
}

/* Send DEAUTHENTICATE for one station.
 *
 * Wire format is "DEAUTHENTICATE <mac> reason=<n>": hostapd parses the address
 * with hwaddr_aton() first, then looks for the space-prefixed " reason=" token
 * (ctrl_iface_ap.c).  Anything malformed makes hostapd answer FAIL rather than
 * misfire, but the association check above runs first regardless.
 *
 * Deliberately never emits " test=", " tx=0" or " p2p=": those hostapd
 * branches either forge a frame or silently drop the station locally without
 * telling it, and both would make the audit trail lie about what happened. */
static int apd_phase4_send_deauth(const char *ctrl_path, const char *sta_mac,
                                  int reason)
{
    char command[160];
    char response[256];
    size_t response_len = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;
    int rc;

    if (!ctrl_path || !sta_mac || !sta_mac[0])
        return -1;
    if (reason <= 0 || reason > 65535)
        return -1;
    if (!apd_phase4_station_associated(ctrl_path, sta_mac))
        return -1;
    rc = snprintf(command, sizeof(command), "DEAUTHENTICATE %s reason=%d",
                  sta_mac, reason);
    if (rc < 0 || (size_t)rc >= sizeof(command))
        return -1;
    rc = apd_hostapd_request(ctrl_path, command, response, sizeof(response),
                             &response_len, 0, &stage);
    return rc == APD_HOSTAPD_REQUEST_OK && !apd_hostapd_is_fail(response) ?
           0 : -1;
}

#define APD_REASSOC_BSS_MAX 16
#ifndef APD_REASSOC_WORKER_EXE
#define APD_REASSOC_WORKER_EXE "/proc/self/exe"
#endif

struct apd_reassoc_bss {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char bssid[18];
    dev_t device;
    ino_t inode;
    int owned;
};

static volatile sig_atomic_t apd_reassoc_cancelled;

static void apd_reassoc_signal(int signo)
{
    (void)signo;
    apd_reassoc_cancelled = 1;
}

static int apd_reassoc_lock_open(const char *mac)
{
    char normalized[18], path[APD_HOSTAPD_DIR_LEN + 64];
    unsigned char bytes[6];
    struct stat st;
    int fd;

    if (apd_hostapd_parse_mac(mac, normalized) != 0 ||
        apd_parse_mac(normalized, bytes) != 0 || (bytes[0] & 1) ||
        !strcmp(normalized, "00:00:00:00:00:00") ||
        apd_hostapd_local_dir_prepare() != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/reassoc-%s.lock",
             APD_HOSTAPD_LOCAL_DIR, normalized);
    fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
                    st.st_uid != geteuid() || (st.st_mode & 0077))) {
        close(fd);
        return -1;
    }
    return fd;
}

int apd_reassoc_block_release(const char *station_mac)
{
    struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    int fd = apd_reassoc_lock_open(station_mac);
    int64_t deadline = apd_monotonic_ms() + 5000;
    int rc = 1;

    if (fd < 0)
        return 1;
    if (fcntl(fd, F_GETLK, &lock) != 0)
        goto done;
    if (lock.l_type != F_UNLCK && kill(lock.l_pid, SIGTERM) != 0)
        goto done;
    do {
        lock.l_type = F_WRLCK;
        if (fcntl(fd, F_GETLK, &lock) != 0)
            break;
        if (lock.l_type == F_UNLCK) {
            rc = 0;
            break;
        }
        poll(NULL, 0, 50);
    } while (apd_monotonic_ms() < deadline);
done:
    close(fd);
    return rc;
}

static int apd_reassoc_status(const char *path,
                              struct apd_hostapd_bss_observation *status)
{
    char response[4096];
    size_t length = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;

    memset(status, 0, sizeof(*status));
    return apd_hostapd_request(path, "STATUS", response, sizeof(response),
        &length, 0, &stage) == APD_HOSTAPD_REQUEST_OK &&
        apd_hostapd_parse_status(response, status) == 0 &&
        status->has_bssid && status->has_ssid ? 0 : -1;
}

static int apd_reassoc_band(int frequency)
{
    return frequency >= 5925 && frequency <= 7125 ? 6 :
           frequency >= 4900 && frequency < 5925 ? 5 :
           frequency >= 2400 && frequency <= 2500 ? 2 : 0;
}

static int apd_reassoc_band_rank(int frequency)
{
    return frequency >= 5925 && frequency <= 7125 ? 4 :
           frequency >= 5700 && frequency < 5925 ? 3 :
           frequency >= 4900 && frequency < 5700 ? 2 :
           frequency >= 2400 && frequency <= 2500 ? 1 : 0;
}

static int apd_reassoc_add_bss(struct apd_reassoc_bss *bsses, size_t *count,
                              const char *path, const char *bssid)
{
    struct stat st;
    size_t i;

    for (i = 0; i < *count; i++)
        if (!strcasecmp(bsses[i].bssid, bssid))
            return 0;
    if (*count == APD_REASSOC_BSS_MAX || lstat(path, &st) != 0 ||
        !S_ISSOCK(st.st_mode) || !apd_hostapd_uid_trusted(st.st_uid))
        return -1;
    snprintf(bsses[*count].path, sizeof(bsses[*count].path), "%s", path);
    snprintf(bsses[*count].bssid, sizeof(bsses[*count].bssid), "%s", bssid);
    bsses[*count].device = st.st_dev;
    bsses[*count].inode = st.st_ino;
    (*count)++;
    return 0;
}

/* Enumerate only live BSS identities, not stations or vendor driver controls.
 * The serving BSS goes last: ADD_MAC can disconnect immediately. */
static int apd_reassoc_scope(const char *source_path, const char *source_bssid,
    const char *ssid, const char *scope, const char *target,
    int target_frequency_mhz,
    struct apd_reassoc_bss *bsses, size_t *count)
{
    struct apd_hostapd_bss_observation *status = calloc(1, sizeof(*status));
    char dirs[APD_HOSTAPD_VENDOR_DIR_LIMIT + 1][APD_HOSTAPD_DIR_LEN];
    size_t directory_count, i, scanned = 0;
    int band, rc = -1;

    if (!status || apd_reassoc_status(source_path, status) != 0 ||
        strcasecmp(status->bssid, source_bssid) || strcmp(status->ssid, ssid) ||
        strcmp(status->state, "ENABLED") ||
        status->has_mld_address || status->has_link_id)
        goto done;
    band = apd_reassoc_band(status->frequency_mhz);
    if (!band)
        goto done;
    if (strcmp(scope, "bss")) {
        snprintf(dirs[0], sizeof(dirs[0]), "%s", APD_HOSTAPD_RUN_DIR);
        directory_count = 1 + apd_hostapd_vendor_dirs(
            &dirs[1], APD_HOSTAPD_VENDOR_DIR_LIMIT);
        for (i = 0; i < directory_count; i++) {
            struct dirent *entry;
            DIR *directory = opendir(dirs[i]);

            if (!directory)
                goto done;
            while ((entry = readdir(directory)) != NULL) {
                char path[sizeof(bsses[0].path)];
                struct stat st;

                if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "global"))
                    continue;
                if (++scanned > APD_HOSTAPD_SOCKET_SCAN_LIMIT) {
                    closedir(directory);
                    goto done;
                }
                if (!apd_hostapd_safe_name(entry->d_name) ||
                    apd_hostapd_socket_path(dirs[i], entry->d_name,
                        path, sizeof(path)) != 0 ||
                    lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode))
                    continue;
                if (apd_reassoc_status(path, status) != 0) {
                    closedir(directory);
                    goto done;
                }
                if (strcmp(status->ssid, ssid) ||
                    strcmp(status->state, "ENABLED") ||
                    !strcasecmp(status->bssid, source_bssid))
                    continue;
                /* The selected target must remain reachable even when its
                 * band would otherwise fall inside the lower-band deny set. */
                if (!strcasecmp(status->bssid, target))
                    continue;
                if (!apd_reassoc_band(status->frequency_mhz)) {
                    closedir(directory);
                    goto done;
                }
                if (!strcmp(scope, "band") &&
                    apd_reassoc_band(status->frequency_mhz) != band)
                    continue;
                /* "lower" follows the measured target, not the source band.
                 * This covers 2.4 -> 5 GHz, 5.2 -> 5.8 GHz and 5 -> 6 GHz
                 * without denying the selected target BSSID. */
                if (!strcmp(scope, "lower") &&
                    apd_reassoc_band_rank(status->frequency_mhz) >=
                        apd_reassoc_band_rank(target_frequency_mhz))
                    continue;
                if (status->has_mld_address || status->has_link_id) {
                    closedir(directory);
                    goto done;
                }
                if (!strcasecmp(status->bssid, target))
                    continue;
                if (apd_reassoc_add_bss(bsses, count, path, status->bssid) != 0) {
                    closedir(directory);
                    goto done;
                }
            }
            closedir(directory);
        }
    }
    if (apd_reassoc_add_bss(bsses, count, source_path, source_bssid) != 0)
        goto done;
    rc = 0;
done:
    free(status);
    return rc;
}

/* -1 is an unreadable/unsupported list, never an empty ACL. */
static int apd_reassoc_acl_contains(const char *path, const char *mac)
{
    char response[8192], *line, *save = NULL;
    size_t length = 0;
    int found = 0, rc;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;

    rc = apd_hostapd_request(path, "DENY_ACL SHOW", response, sizeof(response),
                             &length, 0, &stage);
    if ((rc != APD_HOSTAPD_REQUEST_OK && rc != APD_HOSTAPD_REQUEST_EMPTY) ||
        apd_hostapd_is_fail(response) || apd_hostapd_is_unknown_command(response) ||
        length >= sizeof(response) - 1)
        return -1;
    for (line = strtok_r(response, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char address[18], normalized[18];
        size_t size = strlen(line);

        if (!size)
            continue;
        if (size < 17 || (size > 17 && !isspace((unsigned char)line[17])))
            return -1;
        memcpy(address, line, 17);
        address[17] = '\0';
        if (apd_hostapd_parse_mac(address, normalized) != 0)
            return -1;
        if (!strcasecmp(normalized, mac))
            found = 1;
    }
    return found;
}

static int apd_reassoc_acl_write(const char *path, const char *operation,
                                 const char *mac)
{
    char command[80], response[80];
    size_t length = 0;
    enum apd_hostapd_stage stage = APD_HOSTAPD_STAGE_NONE;

    snprintf(command, sizeof(command), "DENY_ACL %s_MAC %s", operation, mac);
    return apd_hostapd_request(path, command, response, sizeof(response),
        &length, 0, &stage) == APD_HOSTAPD_REQUEST_OK &&
        (!strcmp(response, "OK") || !strcmp(response, "OK\n")) ? 0 : -1;
}

static int apd_reassoc_cleanup(struct apd_reassoc_bss *bsses, size_t count,
                               const char *mac)
{
    size_t i;
    int remaining = 0;

    for (i = 0; i < count; i++) {
        struct stat st;
        int present;

        if (!bsses[i].owned)
            continue;
        /* A replaced hostapd socket has no ownership relationship with this
         * lease. Dynamic ACLs on the old BSS died with that socket. */
        if (lstat(bsses[i].path, &st) != 0) {
            if (errno == ENOENT)
                bsses[i].owned = 0;
            else
                remaining++;
            continue;
        }
        if (st.st_dev != bsses[i].device || st.st_ino != bsses[i].inode) {
            bsses[i].owned = 0;
            continue;
        }
        present = apd_reassoc_acl_contains(bsses[i].path, mac);
        if (present == 1) {
            apd_reassoc_acl_write(bsses[i].path, "DEL", mac);
            present = apd_reassoc_acl_contains(bsses[i].path, mac);
        }
        if (present == 0)
            bsses[i].owned = 0;
        else
            remaining++;
    }
    return remaining;
}

/* This exec'd, detached process owns both writes and expiry. No APD/AC
 * callback is needed after it starts, including when its parent is killed. */
int apd_reassoc_block_worker(int fd)
{
    struct apd_reassoc_bss bsses[APD_REASSOC_BSS_MAX] = {0};
    struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    struct json_object *section = NULL, *options, *receipt;
    const char *mac = NULL, *source, *ssid, *scope, *target, *text;
    char input[8192], path[sizeof(bsses[0].path)], normalized[18];
    char *end;
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int lock_fd = -1, seconds = 0, ok = 0, owned = 0, pending = 0;
    int target_frequency_mhz = 0;
    int64_t deadline = 0, expires_at = 0, not_after;
    size_t count = 0, i;
    ssize_t length;
    const char *reason = "reassoc_block_invalid";

    if (fd < 3 || poll(&pfd, 1, 5000) != 1 ||
        (length = recv(fd, input, sizeof(input) - 1, 0)) <= 0)
        return 1;
    input[length] = '\0';
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, apd_reassoc_signal);
    signal(SIGINT, apd_reassoc_signal);
    signal(SIGHUP, apd_reassoc_signal);
    if (!apd_hostapd_reassoc_backend_safe()) {
        reason = "reassoc_block_native_backend_quarantined";
        goto reply;
    }
    section = json_tokener_parse(input);
    options = json_object_object_get(section, "options");
    mac = json_object_get_string(json_object_object_get(options, "station_mac"));
    source = json_object_get_string(json_object_object_get(options, "source_bssid"));
    ssid = json_object_get_string(json_object_object_get(options, "source_ssid"));
    scope = json_object_get_string(json_object_object_get(options, "block_scope"));
    target = json_object_get_string(json_object_object_get(options, "target_bssid"));
    text = json_object_get_string(json_object_object_get(options, "block_duration_sec"));
    if (!mac || !source || !ssid || !ssid[0] || strlen(ssid) > 32 ||
        !scope || (strcmp(scope, "bss") && strcmp(scope, "ap") &&
                   strcmp(scope, "band") && strcmp(scope, "lower")) ||
        apd_hostapd_parse_mac(source, normalized) != 0 ||
        apd_hostapd_parse_mac(target, normalized) != 0 || !text)
        goto reply;
    seconds = (int)strtol(text, &end, 10);
    if (*end || seconds < 1 || seconds > 30)
        goto reply;
    if (!strcmp(scope, "lower")) {
        text = json_object_get_string(json_object_object_get(
            options, "target_frequency_mhz"));
        if (!text)
            goto reply;
        target_frequency_mhz = (int)strtol(text, &end, 10);
        if (*end || !apd_reassoc_band_rank(target_frequency_mhz))
            goto reply;
    }
    text = json_object_get_string(json_object_object_get(options, "block_not_after"));
    if (!text)
        goto reply;
    not_after = strtoll(text, &end, 10);
    if (*end || not_after < (int64_t)time(NULL) ||
        not_after > (int64_t)time(NULL) + 60) {
        reason = "reassoc_block_expired";
        goto reply;
    }
    lock_fd = apd_reassoc_lock_open(mac);
    if (lock_fd < 0 || fcntl(lock_fd, F_SETLK, &lock) != 0) {
        reason = "reassoc_block_already_active";
        goto reply;
    }
    if (apd_phase3_ctrl_path(json_object_get_string(
            json_object_object_get(section, "section")), path, sizeof(path)) != 0 ||
        apd_reassoc_scope(path, source, ssid, scope, target,
                          target_frequency_mhz, bsses, &count) != 0 ||
        !apd_phase4_station_associated(path, mac)) {
        reason = "reassoc_block_source_or_scope_changed";
        goto reply;
    }
    for (i = 0; i < count; i++) {
        int present = apd_reassoc_acl_contains(bsses[i].path, mac);

        if (present < 0) {
            reason = "reassoc_block_acl_unavailable";
            goto reply;
        }
        bsses[i].owned = present ? 0 : 2; /* Planned, but not written yet. */
    }
    deadline = apd_monotonic_ms() + seconds * 1000;
    expires_at = (int64_t)time(NULL) + seconds;
    for (i = 0; i < count; i++) {
        if (apd_reassoc_cancelled || apd_monotonic_ms() >= deadline ||
            (int64_t)time(NULL) > not_after) {
            reason = "reassoc_block_cancelled";
            goto reply;
        }
        if (bsses[i].owned != 2)
            continue;
        /* A lost ACK may still have installed the entry. Claim before send. */
        bsses[i].owned = 1;
        owned++;
        if (apd_reassoc_acl_write(bsses[i].path, "ADD", mac) != 0 ||
            apd_reassoc_acl_contains(bsses[i].path, mac) != 1) {
            reason = "reassoc_block_install_failed";
            goto reply;
        }
    }
    if (apd_phase4_station_associated(path, mac) &&
        apd_phase4_send_deauth(path, mac, 5) != 0) {
        reason = "reassoc_block_disconnect_failed";
        goto reply;
    }
    ok = 1;
    reason = "reassoc_block_installed";
reply:
    for (i = 0; i < count; i++)
        if (bsses[i].owned == 2)
            bsses[i].owned = 0;
    if (!ok)
        pending = apd_reassoc_cleanup(bsses, count, mac);
    receipt = json_object_new_object();
    json_object_object_add(receipt, "ok", json_object_new_boolean(ok));
    json_object_object_add(receipt, "reason", json_object_new_string(reason));
    json_object_object_add(receipt, "worker_pid", json_object_new_int(getpid()));
    json_object_object_add(receipt, "bss_count", json_object_new_int((int)count));
    json_object_object_add(receipt, "owned_entries", json_object_new_int(owned));
    json_object_object_add(receipt, "duration_sec", json_object_new_int(seconds));
    json_object_object_add(receipt, "expires_at", json_object_new_int64(expires_at));
    json_object_object_add(receipt, "cleanup_pending", json_object_new_boolean(pending));
    text = json_object_to_json_string_ext(receipt, JSON_C_TO_STRING_PLAIN);
    if (send(fd, text, strlen(text), MSG_NOSIGNAL) != (ssize_t)strlen(text))
        apd_reassoc_cancelled = 1;
    close(fd);
    json_object_put(receipt);
    while (ok && !apd_reassoc_cancelled && apd_monotonic_ms() < deadline) {
        int remaining = (int)(deadline - apd_monotonic_ms());
        poll(NULL, 0, remaining > 100 ? 100 : remaining);
    }
    /* Keep ownership until every reachable original BSS confirms removal.
     * If hostapd is briefly busy, recovery continues without the controller. */
    while (apd_reassoc_cleanup(bsses, count, mac) > 0)
        poll(NULL, 0, 250);
    if (owned)
        syslog(LOG_NOTICE, "apd reassoc_block released station=%s entries=%d",
               mac, owned);
    if (lock_fd >= 0)
        close(lock_fd);
    json_object_put(section);
    return ok ? 0 : 1;
}

static int apd_reassoc_block_start(struct json_object *section,
                                   struct json_object **receipt)
{
    int pair[2], status;
    long max_fd = sysconf(_SC_OPEN_MAX);
    pid_t child, waited;
    const char *request = json_object_to_json_string_ext(
        section, JSON_C_TO_STRING_PLAIN);
    char response[2048];
    struct pollfd pfd;
    ssize_t length;

    *receipt = NULL;
    if (max_fd < 0 || socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0)
        return -1;
    fcntl(pair[0], F_SETFD, FD_CLOEXEC);
    fcntl(pair[1], F_SETFD, FD_CLOEXEC);
    child = fork();
    if (child == 0) {
        char *const argv[] = {
            (char *)APD_REASSOC_WORKER_EXE, "--reassoc-block-worker", "3", NULL
        };
        int null_fd, next;
        pid_t detached;

        if (dup2(pair[1], 3) < 0 || fcntl(3, F_SETFD, 0) != 0 ||
            setsid() < 0)
            _exit(1);
        detached = fork();
        if (detached < 0)
            _exit(1);
        if (detached > 0)
            _exit(0);
        null_fd = open("/dev/null", O_RDWR);
        if (null_fd < 0)
            _exit(1);
        for (next = 0; next < 3; next++)
            if (dup2(null_fd, next) < 0)
                _exit(1);
        for (next = 4; next < max_fd; next++)
            close(next);
        execv(argv[0], argv);
        _exit(1);
    }
    close(pair[1]);
    if (child < 0) {
        close(pair[0]);
        return -1;
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    pfd.fd = pair[0];
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        strlen(request) >= 8192 ||
        send(pair[0], request, strlen(request), MSG_NOSIGNAL) !=
            (ssize_t)strlen(request) || poll(&pfd, 1, 12000) != 1 ||
        (length = recv(pair[0], response, sizeof(response) - 1, 0)) <= 0) {
        close(pair[0]);
        return -1;
    }
    close(pair[0]);
    response[length] = '\0';
    *receipt = json_tokener_parse(response);
    return json_object_get_boolean(
        json_object_object_get(*receipt, "ok")) ? 0 : -1;
}

/* Process hostapd action sections from a config candidate.
 * Each section has "hostapd_action_type" in its options and uses the BSS
 * interface name as the section identifier.  Returns 0 if all actions
 * succeeded, -1 if any failed. */
static int apd_config_apply_hostapd_actions(struct json_object *sections,
                                           struct json_object **block_receipt)
{
    size_t i, count;
    int failures = 0;

    if (!sections || !json_object_is_type(sections, json_type_array))
        return 0;
    pthread_mutex_lock(&g_apd_roaming_lock);
    count = json_object_array_length(sections);
    for (i = 0; i < count; i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *options = NULL;
        struct json_object *action_type_obj = NULL;
        const char *action_type;
        const char *bss_iface;
        char ctrl_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

        if (!section)
            continue;
        json_object_object_get_ex(section, "options", &options);
        if (!options)
            continue;
        action_type_obj = json_object_object_get(options,
                                                  "hostapd_action_type");
        if (!action_type_obj)
            continue;
        action_type = json_object_get_string(action_type_obj);
        bss_iface = json_object_get_string(
            json_object_object_get(section, "section"));
        if (!bss_iface || !action_type)
            continue;
        if (!strcmp(action_type, "reassoc_block")) {
            if (apd_reassoc_block_start(section, block_receipt) != 0)
                failures++;
            continue;
        }
        if (apd_phase3_ctrl_path(bss_iface, ctrl_path,
                                  sizeof(ctrl_path)) != 0) {
            failures++;
            continue;
        }
        if (!strcmp(action_type, "set_neighbor")) {
            const char *bssid = json_object_get_string(
                json_object_object_get(options, "neighbor_bssid"));
            const char *ssid = json_object_get_string(
                json_object_object_get(options, "neighbor_ssid"));
            const char *opclass = json_object_get_string(
                json_object_object_get(options, "neighbor_opclass"));
            const char *channel = json_object_get_string(
                json_object_object_get(options, "neighbor_channel"));
            const char *phy = json_object_get_string(
                json_object_object_get(options, "neighbor_phy"));
            if (!bssid || !ssid || !opclass || !channel || !phy ||
                !apd_phase3_neighbor_owner(ctrl_path, options) ||
                apd_phase3_set_neighbor(ctrl_path, bssid, ssid,
                                         atoi(opclass), atoi(channel),
                                         atoi(phy), json_object_get_int(
                                             json_object_object_get(
                                                 options, "neighbor_ft"))) != 0)
                failures++;
        } else if (!strcmp(action_type, "del_neighbor")) {
            const char *bssid = json_object_get_string(
                json_object_object_get(options, "neighbor_bssid"));
            if (!bssid ||
                apd_phase3_del_neighbor(ctrl_path, bssid) != 0)
                failures++;
        } else if (!strcmp(action_type, "btm_request")) {
            const char *sta_mac = json_object_get_string(
                json_object_object_get(options, "station_mac"));
            const char *target_bssid = json_object_get_string(
                json_object_object_get(options, "target_bssid"));
            struct json_object *validity_obj =
                json_object_object_get(options, "btm_validity");
            struct json_object *opclass_obj =
                json_object_object_get(options, "target_opclass");
            struct json_object *channel_obj =
                json_object_object_get(options, "target_channel");
            struct json_object *phy_obj =
                json_object_object_get(options, "target_phy");
            const char *target_bssid_2 = json_object_get_string(
                json_object_object_get(options, "target_bssid_2"));
            struct json_object *opclass_obj_2 =
                json_object_object_get(options, "target_opclass_2");
            struct json_object *channel_obj_2 =
                json_object_object_get(options, "target_channel_2");
            struct json_object *phy_obj_2 =
                json_object_object_get(options, "target_phy_2");
            struct json_object *imminent_obj =
                json_object_object_get(options, "btm_disassoc_imminent");
            struct json_object *timer_obj =
                json_object_object_get(options, "btm_disassoc_timer");
            int validity = validity_obj ?
                json_object_get_int(validity_obj) : 0;
            int have_second = target_bssid_2 && target_bssid_2[0];
            if (!sta_mac || !target_bssid ||
                !opclass_obj || !channel_obj || !phy_obj ||
                (have_second && (!opclass_obj_2 || !channel_obj_2 || !phy_obj_2)) ||
                apd_phase3_send_btm(ctrl_path, sta_mac, target_bssid,
                                     json_object_get_int(opclass_obj),
                                     json_object_get_int(channel_obj),
                                     json_object_get_int(phy_obj),
                                     json_object_get_int(json_object_object_get(
                                         options, "target_ft")), validity,
                                     target_bssid_2,
                                     opclass_obj_2 ? json_object_get_int(opclass_obj_2) : 0,
                                     channel_obj_2 ? json_object_get_int(channel_obj_2) : 0,
                                     phy_obj_2 ? json_object_get_int(phy_obj_2) : 0,
                                     json_object_get_int(json_object_object_get(
                                         options, "target_ft_2")),
                                     imminent_obj ? json_object_get_int(imminent_obj) : 0,
                                     timer_obj ? json_object_get_int(timer_obj) : 0) != 0)
                failures++;
        } else if (!strcmp(action_type, "beacon_request")) {
            /* Phase 2: ask the station to measure a candidate channel.  The
             * answer is asynchronous, so success here means "the request was
             * accepted", never "we have a measurement". */
            const char *sta_mac = json_object_get_string(
                json_object_object_get(options, "station_mac"));
            struct json_object *opclass_obj =
                json_object_object_get(options, "measure_opclass");
            struct json_object *channel_obj =
                json_object_object_get(options, "measure_channel");
            struct json_object *duration_obj =
                json_object_object_get(options, "measure_duration_tu");
            const char *measure_bssid = json_object_get_string(
                json_object_object_get(options, "measure_bssid"));
            if (!sta_mac || !opclass_obj || !channel_obj ||
                apd_phase2_request_beacon(ctrl_path, sta_mac,
                                          json_object_get_int(opclass_obj),
                                          json_object_get_int(channel_obj),
                                          duration_obj ?
                                              json_object_get_int(duration_obj) :
                                              0,
                                          measure_bssid,
                                          json_object_get_string(
                                              json_object_object_get(
                                                  options, "measure_ssid"))) < 0) {
                failures++;
                break;
            }
        } else if (!strcmp(action_type, "deauth_request")) {
            /* Phase 4.  Every authorisation decision was made by the AC before
             * this section was ever emitted; APD's job is to refuse anything
             * malformed and to confirm the station is really here. */
            const char *sta_mac = json_object_get_string(
                json_object_object_get(options, "station_mac"));
            struct json_object *reason_obj =
                json_object_object_get(options, "deauth_reason");
            if (!sta_mac || !reason_obj ||
                apd_phase4_send_deauth(ctrl_path, sta_mac,
                                       json_object_get_int(reason_obj)) != 0)
                failures++;
        } else {
            failures++;
        }
    }
    pthread_mutex_unlock(&g_apd_roaming_lock);
    return failures > 0 ? -1 : 0;
}

/* Mirror the executor's failure shape for rejections raised here, so a caller
 * cannot tell from the result whether the executor or this split step said no. */
static int apd_openwrt_apply_fail(struct json_object **out, const char *reason)
{
    struct json_object *result = json_object_new_object();

    json_object_object_add(result, "operation", json_object_new_string("apply"));
    json_object_object_add(result, "ok", json_object_new_boolean(0));
    json_object_object_add(result, "reason", json_object_new_string(reason));
    if (out)
        *out = result;
    else
        json_object_put(result);
    return -1;
}

static int apd_openwrt_apply(struct json_object *candidate,
                             struct json_object **out)
{
    struct apd_config_paths paths = { "/sbin/uci", "/sbin/wifi",
                                      "/etc/config",
                                      "/tmp/dreamingwrt-apd-config-candidate" };
    struct json_object *sections = NULL;
    struct json_object *uci_sections = json_object_new_array();
    struct json_object *hostapd_sections = json_object_new_array();
    struct json_object *uci_candidate = NULL;
    size_t i, count;
    int rc;

    /* Separate sections into UCI config and hostapd actions. */
    json_object_object_get_ex(candidate, "sections", &sections);
    if (sections && json_object_is_type(sections, json_type_array)) {
        count = json_object_array_length(sections);
        for (i = 0; i < count; i++) {
            struct json_object *sec = json_object_array_get_idx(sections, i);
            struct json_object *opts = NULL;

            json_object_object_get_ex(sec, "options", &opts);
            if (opts && json_object_object_get(opts, "hostapd_action_type"))
                json_object_array_add(hostapd_sections, json_object_get(sec));
            else
                json_object_array_add(uci_sections, json_object_get(sec));
        }
    }

    if (json_object_array_length(uci_sections) == 0) {
        json_object_put(uci_sections);
        rc = apd_config_hostapd_actions_validate(candidate, out);
    } else {
        /* Build a UCI-only candidate for the config executor.
         *
         * The digest has to be recomputed over the subset, not copied from
         * the parent.  The executor verifies the digest against the sections
         * it is handed, so a candidate that mixes UCI options with
         * hostapd-action sections -- which every multi-AP roaming apply
         * produces, since the 11r/k/v options and the SET_NEIGHBOR actions go
         * into one array and are digested together -- would be rejected with
         * candidate_digest_mismatch before touching anything.
         *
         * Recomputing is only safe because the parent digest is verified
         * first, immediately below: the subset is thereby known to be part of
         * an authentic candidate rather than something assembled locally. */
        {
            struct json_object *parent_sections = NULL;
            struct json_object *parent_digest = NULL;
            char expected[APD_CONFIG_DIGEST_MAX];
            char subset[APD_CONFIG_DIGEST_MAX];

            parent_digest = json_object_object_get(candidate,
                                                   "candidate_digest");
            json_object_object_get_ex(candidate, "sections", &parent_sections);
            if (!parent_digest || !parent_sections ||
                apd_config_candidate_digest(parent_sections, expected,
                                            sizeof(expected)) != 0 ||
                strcmp(json_object_get_string(parent_digest), expected)) {
                json_object_put(uci_sections);
                json_object_put(hostapd_sections);
                return apd_openwrt_apply_fail(out,
                                              "candidate_digest_mismatch");
            }
            uci_candidate = json_object_new_object();
            json_object_object_add(uci_candidate, "format",
                json_object_get(json_object_object_get(candidate, "format")));
            json_object_object_add(uci_candidate, "sections", uci_sections);
            if (apd_config_candidate_digest(uci_sections, subset,
                                            sizeof(subset)) != 0) {
                json_object_put(uci_candidate);
                json_object_put(hostapd_sections);
                return apd_openwrt_apply_fail(out, "digest_failed");
            }
            json_object_object_add(uci_candidate, "candidate_digest",
                                   json_object_new_string(subset));
            rc = apd_config_apply(&paths, uci_candidate, out);
            json_object_put(uci_candidate);
        }
    }

    /* Process hostapd actions after UCI config is applied and reloaded. */
    if (rc == 0 && json_object_array_length(hostapd_sections) > 0) {
        struct json_object *block_receipt = NULL;
        int ha_rc = apd_config_apply_hostapd_actions(hostapd_sections, &block_receipt);
        int neighbors_only = 1;

        for (i = 0; i < json_object_array_length(hostapd_sections); i++) {
            struct json_object *opts = json_object_object_get(
                json_object_array_get_idx(hostapd_sections, i), "options");

            if (strcmp(json_object_get_string(json_object_object_get(
                    opts, "hostapd_action_type")), "set_neighbor"))
                neighbors_only = 0;
        }

        rc = ha_rc;
        if (out && *out) {
            struct json_object *digest =
                json_object_object_get(candidate, "candidate_digest");

            json_object_object_add(*out, "operation",
                                   json_object_new_string("hostapd_actions"));
            json_object_object_add(*out, "ok", json_object_new_boolean(rc == 0));
            json_object_object_add(*out, "match", json_object_new_boolean(rc == 0));
            json_object_object_add(*out, "candidate_digest", json_object_get(digest));
            if (rc == 0)
                json_object_object_add(*out, "readback_digest", json_object_get(digest));
            json_object_object_add(*out, "evidence_type",
                json_object_new_string(block_receipt ?
                    "hostapd_temporary_reassociation_block" : neighbors_only ?
                    "hostapd_neighbor_readback" : "hostapd_command_ack"));
            json_object_object_add(*out, "reason", json_object_new_string(
                rc != 0 ? "hostapd_action_failed" :
                neighbors_only ? "hostapd_neighbors_verified" :
                                 "hostapd_commands_accepted"));
            if (block_receipt)
                json_object_object_add(*out, "reassoc_block",
                                       json_object_get(block_receipt));
        }
        json_object_put(block_receipt);
    }
    json_object_put(hostapd_sections);
    return rc;
}
#endif
#ifndef APD_HOSTAPD_STANDALONE_TEST

static int apd_openwrt_readback(struct json_object *candidate,
                                struct json_object **out)
{
    struct apd_config_paths paths = { "/sbin/uci", "/sbin/wifi",
                                      "/etc/config",
                                      "/tmp/dreamingwrt-apd-config-candidate" };
    return apd_config_readback(&paths, candidate, out);
}

static int apd_openwrt_rollback(struct json_object *rollback_ref,
                                struct json_object **out)
{
    struct apd_config_paths paths = { "/sbin/uci", "/sbin/wifi",
                                      "/etc/config",
                                      "/tmp/dreamingwrt-apd-config-candidate" };
    return apd_config_rollback(&paths, rollback_ref, out);
}

static const struct apd_backend_ops openwrt_backend = {
    .name = "openwrt-netifd-hostapd-nl80211",
    .snapshot_supported = 1,
    .probe = apd_openwrt_probe,
    .snapshot = apd_openwrt_snapshot,
    .neighbor_scan = apd_backend_neighbor_scan,
    .validate = apd_openwrt_validate,
    .stage = apd_openwrt_stage,
    .apply = apd_openwrt_apply,
    .readback = apd_openwrt_readback,
    .rollback = apd_openwrt_rollback,
};

const struct apd_backend_ops *apd_backend_openwrt(void)
{
    return &openwrt_backend;
}
#endif
