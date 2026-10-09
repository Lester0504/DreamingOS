// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define APD_HOSTAPD_STANDALONE_TEST 1
#define APD_ROAMING_STANDALONE_TEST 1
#define FIXTURE_BASE "/tmp/apd-roaming-actions-fixture"
#define APD_HOSTAPD_RUN_DIR FIXTURE_BASE "/run"
#define APD_HOSTAPD_LOCAL_DIR FIXTURE_BASE "/local"
#define APD_HOSTAPD_RUN_DIR_PARENT FIXTURE_BASE
#define APD_HOSTAPD_EXPECTED_UID ((uid_t)getuid())
#define APD_HOSTAPD_SERVICE_UID ((uid_t)getuid())
#define APD_HOSTAPD_SERVICE_GID ((gid_t)getgid())
#define APD_HOSTAPD_TIMEOUT_MS 300
#define APD_HOSTAPD_COLLECTION_TIMEOUT_MS 1500
#define APD_BEACON_SERIAL_TIMEOUT_MS 180

#include "../src/apd/apd_backend_openwrt.c"
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define STATION "44:71:47:35:e7:b3"
#define TARGET "00:58:28:09:22:ca"
#define TARGET_2 "00:58:28:09:22:ba"
#define IPHONE "d2:76:c1:3e:34:6c"
#define REPORT "83a50000000000000000320000ae640058280922ca0000000000"
#define SELF_NEIGHBOR "44:df:65:2e:de:25 ssid=5869616f6d695f44453233 " \
                      "nr=44df652ede2587000000732409 stat\n"
#define NEIGHBOR_OPTIONS "{\"hostapd_action_type\":\"set_neighbor\"," \
    "\"neighbor_bssid\":\"" TARGET "\",\"neighbor_ssid\":\"Xiaomi_DE23\"," \
    "\"neighbor_opclass\":\"131\",\"neighbor_channel\":\"165\"," \
    "\"neighbor_phy\":\"14\",\"source_bssid\":\"44:df:65:2e:de:25\"," \
    "\"source_ssid\":\"Xiaomi_DE23\"}"

static struct {
    int btm;
    int beacon;
    int beacon_modes[3];
    int accepted_beacon_mode;
    int malformed_beacon_reply;
    int silent_beacon_reply;
    int serial_delay_ms;
    int serial_report_mode;
    int serial_empty_report;
    int serial_suppress_report;
    int serial_pending;
    int serial_overlaps;
    int serial_reports;
    int neighbor;
    int directed_beacon;
    int bad_beacon_bssid;
    int neighbor_reply_mode;
    int wrong_owner;
    char neighbor_row[800];
    int permissions;
    int bad_command;
} *counts;

static int server(int fd)
{
    struct sockaddr_un monitor;
    socklen_t monitor_len = 0;
    int64_t report_due = 0;
    char pending_report[300];

    for (;;) {
        struct sockaddr_un peer;
        socklen_t length = sizeof(peer);
        struct stat st;
        char command[600];
        char token_reply[20];
        const char *reply = "FAIL\n";
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int wait_ms = report_due ? (int)(report_due - apd_monotonic_ms()) : -1;
        ssize_t n;

        if (report_due && wait_ms < 0)
            wait_ms = 0;
        if (poll(&pfd, 1, wait_ms) < 0)
            return 1;
        if (report_due && apd_monotonic_ms() >= report_due) {
            sendto(fd, pending_report, strlen(pending_report), 0,
                   (struct sockaddr *)&monitor, monitor_len);
            report_due = 0;
            counts->serial_pending = 0;
            counts->serial_reports++;
        }
        if (!(pfd.revents & POLLIN))
            continue;
        n = recvfrom(fd, command, sizeof(command) - 1, 0,
                     (struct sockaddr *)&peer, &length);
        if (n <= 0)
            return 1;
        command[n] = '\0';
        if (lstat(peer.sun_path, &st) == 0 && (st.st_mode & 0777) == 0660 &&
            st.st_gid == getgid())
            counts->permissions++;
        else
            counts->bad_command++;
        if (!strcmp(command, "ATTACH probe_rx_events=1")) {
            monitor = peer;
            monitor_len = length;
            reply = "OK\n";
        } else if (!strcmp(command, "STA " STATION)) {
            reply = STATION "\nflags=[AUTH][ASSOC][AUTHORIZED]\n";
        } else if (!strcmp(command, "STATUS")) {
            reply = counts->wrong_owner ?
                    "state=ENABLED\nbssid[0]=44:df:65:2e:de:25\n"
                    "ssid[0]=IoT\nfreq=5180\nchannel=36\nnum_sta[0]=0\n" :
                    "state=ENABLED\nbssid[0]=44:df:65:2e:de:25\n"
                    "ssid[0]=Xiaomi_DE23\nfreq=5180\nchannel=36\nnum_sta[0]=0\n";
        } else if (!strcmp(command, "SHOW_NEIGHBOR")) {
            reply = counts->neighbor_row[0] ? counts->neighbor_row : SELF_NEIGHBOR;
        } else if (!strncmp(command, "REQ_BEACON " STATION,
                             strlen("REQ_BEACON " STATION))) {
            const char *body = command + strlen("REQ_BEACON " STATION " ");
            char requested_bssid[13];
            char expected[40];
            unsigned mode = 255;

            counts->beacon++;
            if (sscanf(body + 12, "%2x", &mode) != 1 || mode > 2)
                counts->bad_command++;
            else
                counts->beacon_modes[mode]++;
            memcpy(requested_bssid, body + 14, 12);
            requested_bssid[12] = '\0';
            snprintf(expected, sizeof(expected), "83a500003200%02x"
                     "%s", mode, requested_bssid);
            if (!memcmp(requested_bssid, "000000000000", 12))
                counts->bad_beacon_bssid++;
            else if (!strcmp(requested_bssid, "0058280922ca"))
                counts->directed_beacon++;
            if (!monitor_len || strncmp(body, expected, 26) ||
                !strstr(command, "0058280922ca000b5869616f6d695f44453233") ||
                !strstr(command, "020100"))
                counts->bad_command++;
            if (counts->silent_beacon_reply)
                continue;
            if ((int)mode == counts->accepted_beacon_mode) {
                if (counts->serial_delay_ms) {
                    char noise[160];
                    unsigned token = (unsigned)counts->beacon;

                    snprintf(token_reply, sizeof(token_reply), "%u\n", token);
                    reply = token_reply;
                    snprintf(noise, sizeof(noise),
                        "<3>BEACON-RESP-RX " STATION " %u 04", token + 100);
                    sendto(fd, noise, strlen(noise), 0,
                           (struct sockaddr *)&monitor, monitor_len);
                    snprintf(noise, sizeof(noise),
                        "<3>BEACON-RESP-RX 44:71:47:35:e7:b4 %u 04", token);
                    sendto(fd, noise, strlen(noise), 0,
                           (struct sockaddr *)&monitor, monitor_len);
                    if (counts->serial_pending) {
                        counts->serial_overlaps++;
                        snprintf(noise, sizeof(noise),
                            "<3>BEACON-RESP-RX " STATION " %u 04", token);
                        sendto(fd, noise, strlen(noise), 0,
                               (struct sockaddr *)&monitor, monitor_len);
                    } else {
                        counts->serial_pending = 1;
                        snprintf(pending_report, sizeof(pending_report),
                            "<3>BEACON-RESP-RX " STATION " %u %02x %s", token,
                            counts->serial_report_mode,
                            counts->serial_empty_report ? "" : REPORT);
                        if (!counts->serial_suppress_report)
                            report_due = apd_monotonic_ms() + counts->serial_delay_ms;
                    }
                } else {
                    reply = counts->malformed_beacon_reply ? "OK\n" : "1\n";
                    sendto(fd, "<3>BEACON-RESP-RX " STATION " 1 00 " REPORT "0103000102",
                           strlen("<3>BEACON-RESP-RX " STATION " 1 00 " REPORT "0103000102"),
                           0, (struct sockaddr *)&monitor, monitor_len);
                }
            }
        } else if (!strncmp(command, "BSS_TM_REQ " STATION,
                             strlen("BSS_TM_REQ " STATION))) {
            counts->btm++;
            if (!strstr(command, "neighbor=" TARGET ",") ||
                !strstr(command, ",131,165,14,0301ff pref=1") ||
                !strstr(command, "neighbor=" TARGET_2 ",") ||
                !strstr(command, ",115,36,9,0301fe pref=1") ||
                !strstr(command, "disassoc_imminent=1 disassoc_timer=10") ||
                !strstr(command, " valid_int=100"))
                counts->bad_command++;
            reply = counts->btm == 1 ? "OK\n" : "FAIL\n";
        } else if (!strncmp(command, "SET_NEIGHBOR ", 13)) {
            counts->neighbor++;
            if (counts->neighbor_reply_mode == 0)
                snprintf(counts->neighbor_row, sizeof(counts->neighbor_row),
                         "%s\n", command + 13);
            reply = counts->neighbor_reply_mode == 2 ? "UNKNOWN COMMAND\n" : "OK\n";
        }
        if (sendto(fd, reply, strlen(reply), 0,
                   (struct sockaddr *)&peer, length) != (ssize_t)strlen(reply))
            return 2;
    }
}

static struct json_object *candidate(const char *options)
{
    struct json_object *root = json_object_new_object();
    struct json_object *sections = json_object_new_array();
    struct json_object *section = json_object_new_object();
    char digest[APD_CONFIG_DIGEST_MAX];

    json_object_object_add(section, "section", json_object_new_string("ath1"));
    json_object_object_add(section, "options", json_tokener_parse(options));
    json_object_array_add(sections, section);
    json_object_object_add(root, "format",
                           json_object_new_string(APD_CONFIG_CANDIDATE_FORMAT));
    json_object_object_add(root, "sections", sections);
    if (apd_config_candidate_digest(sections, digest, sizeof(digest)) != 0)
        abort();
    json_object_object_add(root, "candidate_digest", json_object_new_string(digest));
    return root;
}

static struct json_object *beacon_batch(int count)
{
    struct json_object *root = candidate(
        "{\"hostapd_action_type\":\"beacon_request\","
        "\"station_mac\":\"" STATION "\",\"measure_opclass\":\"131\","
        "\"measure_channel\":\"165\",\"measure_duration_tu\":\"50\","
        "\"measure_ssid\":\"Xiaomi_DE23\"}");
    struct json_object *sections = json_object_object_get(root, "sections");
    char digest[APD_CONFIG_DIGEST_MAX];
    int i;

    for (i = 1; i < count; i++)
        json_object_array_add(sections,
            json_object_get(json_object_array_get_idx(sections, 0)));
    if (apd_config_candidate_digest(sections, digest, sizeof(digest)) != 0)
        abort();
    json_object_object_add(root, "candidate_digest", json_object_new_string(digest));
    return root;
}

struct action_call {
    struct json_object *candidate;
    struct json_object *result;
    int rc;
};

static void *apply_thread(void *data)
{
    struct action_call *call = data;

    call->rc = apd_openwrt_apply(call->candidate, &call->result);
    return NULL;
}

#define CHECK(label, expression) do { \
    if (!(expression)) { fprintf(stderr, "FAIL %s\n", label); rc = 1; goto done; } \
} while (0)

int main(void)
{
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    struct apd_beacon_report decoded;
    struct apd_hostapd_observation observation;
    struct apd_beacon_monitor *mon;
    struct json_object *request = NULL, *result = NULL, *reports = NULL;
    struct stat st;
    pid_t child = -1;
    int fd = -1, rc = 0;
    int64_t observed = (int64_t)time(NULL);
    size_t i;

    counts = mmap(NULL, sizeof(*counts), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK("shared counters", counts != MAP_FAILED);
    counts->accepted_beacon_mode = 1;
    CHECK("base", mkdir(FIXTURE_BASE, 0700) == 0);
    CHECK("run", mkdir(APD_HOSTAPD_RUN_DIR, 0700) == 0);
    CHECK("local dir", apd_hostapd_local_dir_prepare() == 0);
    CHECK("local permissions", lstat(APD_HOSTAPD_LOCAL_DIR, &st) == 0 &&
          (st.st_mode & 0777) == 0750);
    snprintf(address.sun_path, sizeof(address.sun_path),
             APD_HOSTAPD_RUN_DIR "/ath1");
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK("server bind", fd >= 0 &&
          bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    child = fork();
    CHECK("fork", child >= 0);
    if (child == 0)
        _exit(server(fd));

    CHECK("collector", apd_hostapd_collect_raw(1, &observation) == 0);
    CHECK("neighbor table collected", observation.bss_count == 1 &&
          observation.bss[0].neighbors_complete &&
          observation.bss[0].neighbor_count == 1);
    reports = apd_hostapd_neighbors_json(&observation.bss[0]);
    CHECK("neighbor table exported", json_object_array_length(reports) == 1);
    json_object_put(reports);
    reports = NULL;
    {
        char malformed[] = TARGET " ssid=5869616f6d695f44453233 nr=00zz";
        char mismatch[] = TARGET " ssid=5869616f6d695f44453233 "
                          "nr=ffffffffffff8700000083a50e";

        CHECK("bad neighbor hex is incomplete",
              apd_hostapd_neighbors_parse(malformed, &observation.bss[0]) != 0 &&
              !observation.bss[0].neighbors_complete);
        CHECK("neighbor BSSID must match report",
              apd_hostapd_neighbors_parse(mismatch, &observation.bss[0]) != 0);
    }
    CHECK("report with subelements", apd_beacon_report_decode(
          REPORT "0103000102\n", &decoded) == 0 &&
          decoded.have_rcpi && decoded.rcpi_dbm == -23 &&
          !strcmp(decoded.bssid, TARGET));
    CHECK("truncated subelement", apd_beacon_report_decode(
          REPORT "0103aa", &decoded) != 0);
    CHECK("nonhex suffix", apd_beacon_report_decode(REPORT "zz", &decoded) != 0);
    request = candidate("{\"hostapd_action_type\":\"beacon_request\","
        "\"station_mac\":\"" STATION "\",\"measure_opclass\":\"131\","
        "\"measure_channel\":\"165\",\"measure_duration_tu\":\"50\","
        "\"measure_bssid\":\"" TARGET "\",\"measure_ssid\":\"Xiaomi_DE23\"}");
    CHECK("measurement action", apd_openwrt_apply(request, &result) == 0);
    CHECK("ack receipt", json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !strcmp(json_object_get_string(json_object_object_get(result, "evidence_type")),
                  "hostapd_command_ack"));
    CHECK("directed request body", counts->bad_command == 0 &&
          counts->directed_beacon >= 1 && counts->bad_beacon_bssid == 0);
    json_object_put(result);
    result = NULL;
    mon = apd_beacon_monitor_get(address.sun_path);
    CHECK("monitor", mon != NULL);
    apd_beacon_monitor_drain(mon, observed);
    reports = apd_beacon_reports_json(observed);
    CHECK("measurement published", json_object_array_length(reports) == 1 &&
          !strcmp(json_object_get_string(json_object_object_get(
              json_object_array_get_idx(reports, 0), "measurement_mode")), "active"));
    json_object_put(reports);

    counts->accepted_beacon_mode = 0;
    CHECK("passive-only station", apd_openwrt_apply(request, &result) == 0 &&
          counts->beacon == 3 && counts->beacon_modes[0] == 1);
    json_object_put(result);
    result = NULL;
    apd_beacon_monitor_drain(mon, observed + 1);
    reports = apd_beacon_reports_json(observed + 1);
    CHECK("passive mode recorded", !strcmp(json_object_get_string(
          json_object_object_get(json_object_array_get_idx(reports, 0),
                                 "measurement_mode")), "passive"));
    json_object_put(reports);

    counts->accepted_beacon_mode = 2;
    CHECK("table-only station", apd_openwrt_apply(request, &result) == 0 &&
          counts->beacon == 6 && counts->beacon_modes[2] == 1);
    json_object_put(result);
    result = NULL;
    apd_beacon_monitor_drain(mon, observed + 2);
    reports = apd_beacon_reports_json(observed + 2);
    CHECK("cached table is not labeled active", !strcmp(json_object_get_string(
          json_object_object_get(json_object_array_get_idx(reports, 0), "source")),
          "ieee80211k_beacon_table") && json_object_get_boolean(
          json_object_object_get(json_object_array_get_idx(reports, 0), "cached")));
    json_object_put(reports);

    counts->accepted_beacon_mode = -1;
    CHECK("unsupported station fails after three modes",
          apd_openwrt_apply(request, &result) != 0 && counts->beacon == 9);
    json_object_put(result);
    result = NULL;
    counts->accepted_beacon_mode = 1;
    counts->malformed_beacon_reply = 1;
    CHECK("ambiguous reply is not retried",
          apd_openwrt_apply(request, &result) != 0 && counts->beacon == 10);
    json_object_put(result);
    result = NULL;
    counts->malformed_beacon_reply = 0;
    counts->silent_beacon_reply = 1;
    CHECK("timeout is not retried",
          apd_openwrt_apply(request, &result) != 0 && counts->beacon == 11);
    counts->silent_beacon_reply = 0;
    json_object_put(result);
    result = NULL;
    json_object_put(request);
    request = NULL;

    reports = apd_beacon_reports_json(observed + 123);
    CHECK("stale measurement removed", json_object_array_length(reports) == 0);
    json_object_put(reports);
    reports = NULL;
    apd_beacon_monitor_consume(
        "<3>RX-PROBE-REQUEST sa=" IPHONE " signal=-64",
        "ath1", observed + 3);
    apd_beacon_monitor_consume(
        "<3>RX-PROBE-REQUEST sa=" IPHONE " signal=invalid",
        "ath1", observed + 4);
    reports = apd_probe_observations_json(observed + 4, &observation);
    CHECK("attributed uplink probe", json_object_array_length(reports) == 1 &&
        !strcmp(json_object_get_string(json_object_object_get(
            json_object_array_get_idx(reports, 0), "station_mac")), IPHONE) &&
        !strcmp(json_object_get_string(json_object_object_get(
            json_object_array_get_idx(reports, 0), "bssid")),
            "44:df:65:2e:de:25") &&
        !strcmp(json_object_get_string(json_object_object_get(
            json_object_array_get_idx(reports, 0), "direction")), "uplink") &&
        json_object_get_int(json_object_object_get(
            json_object_array_get_idx(reports, 0), "rssi_dbm")) == -64 &&
        json_object_get_boolean(json_object_object_get(
            json_object_array_get_idx(reports, 0), "mac_randomized")));
    json_object_put(reports);
    reports = apd_probe_observations_json(observed + 124, &observation);
    CHECK("stale probe removed", json_object_array_length(reports) == 0);
    json_object_put(reports);
    reports = NULL;
    apd_beacon_monitor_consume(
        "<3>BSS-TM-RESP " STATION " status_code=7 bss_termination_delay=0",
        "ath1", observed + 1);
    reports = apd_btm_responses_json(observed + 2);
    CHECK("btm rejection reported", json_object_array_length(reports) == 1 &&
          json_object_get_int(json_object_object_get(
              json_object_array_get_idx(reports, 0), "status_code")) == 7);
    json_object_put(reports);
    reports = NULL;
    request = candidate("{\"hostapd_action_type\":\"btm_request\","
        "\"station_mac\":\"" STATION "\",\"target_bssid\":\"" TARGET "\","
        "\"target_opclass\":\"131\",\"target_channel\":\"165\","
        "\"target_phy\":\"14\",\"target_ft\":\"0\",\"btm_validity\":\"100\","
        "\"target_bssid_2\":\"" TARGET_2 "\",\"target_opclass_2\":\"115\","
        "\"target_channel_2\":\"36\",\"target_phy_2\":\"9\","
        "\"target_ft_2\":\"0\",\"btm_disassoc_imminent\":\"1\","
        "\"btm_disassoc_timer\":\"10\"}");
    {
        struct action_call call = { .candidate = request };
        pthread_t worker;
        int started, blocked;

        pthread_mutex_lock(&g_apd_roaming_lock);
        started = pthread_create(&worker, NULL, apply_thread, &call);
        usleep(20000);
        blocked = counts->btm == 0;
        pthread_mutex_unlock(&g_apd_roaming_lock);
        if (started == 0)
            pthread_join(worker, NULL);
        result = call.result;
        CHECK("action serializes with snapshot cache", started == 0 && blocked);
        CHECK("long btm action", call.rc == 0);
    }
    json_object_put(result);
    result = NULL;
    CHECK("hostapd rejection propagated", apd_openwrt_apply(request, &result) != 0 &&
          !json_object_get_boolean(json_object_object_get(result, "ok")));
    json_object_put(result);
    result = NULL;
    json_object_object_add(request, "candidate_digest", json_object_new_string("bad"));
    CHECK("bad digest cannot transmit", apd_openwrt_apply(request, &result) != 0 &&
          counts->btm == 2);
    CHECK("wire commands and service permissions", counts->beacon == 11 &&
          counts->permissions > 0 && counts->bad_command == 0);
    json_object_put(request);
    json_object_put(result);
    result = NULL;
    request = candidate(NEIGHBOR_OPTIONS);
    CHECK("checked neighbor write", apd_openwrt_apply(request, &result) == 0 &&
          counts->neighbor == 1);
    CHECK("neighbor proof is readback",
          !strcmp(json_object_get_string(json_object_object_get(result, "evidence_type")),
                  "hostapd_neighbor_readback"));
    json_object_put(result);
    result = NULL;
    counts->neighbor_row[0] = '\0';
    counts->neighbor_reply_mode = 1;
    CHECK("ACK without data is failure", apd_openwrt_apply(request, &result) != 0 &&
          counts->neighbor == 2);
    json_object_put(result);
    result = NULL;
    counts->neighbor_reply_mode = 2;
    CHECK("unknown reply is failure", apd_openwrt_apply(request, &result) != 0 &&
          counts->neighbor == 3);
    json_object_put(result);
    result = NULL;
    counts->wrong_owner = 1;
    CHECK("changed SSID is never written", apd_openwrt_apply(request, &result) != 0 &&
          counts->neighbor == 3);
    json_object_put(result);
    result = NULL;
    counts->wrong_owner = 0;
    counts->neighbor_reply_mode = 0;
    CHECK("lost table is repairable", apd_openwrt_apply(request, &result) == 0 &&
          counts->neighbor == 4);
    json_object_put(request);
    request = NULL;
    json_object_put(result);
    result = NULL;
    counts->serial_delay_ms = 40;
    for (i = 0; i < 3; i++) {
        int before = counts->beacon;
        int responses = counts->serial_reports;

        g_apd_beacon_cache_len = 0;
        counts->serial_report_mode = i == 1 ? 4 : 0;
        counts->serial_empty_report = i == 2;
        request = beacon_batch(3);
        CHECK("delayed batch accepted", apd_openwrt_apply(request, &result) == 0);
        CHECK("no overlapping station measurements",
              counts->beacon == before + 3 && counts->serial_overlaps == 0);
        usleep(100000);
        apd_beacon_monitor_drain(mon, (int64_t)time(NULL));
        CHECK("all batch responses received", counts->serial_reports == responses + 3);
        CHECK("refused and empty reports are not measurements",
              g_apd_beacon_cache_len == (i == 0 ? 1U : 0U));
        json_object_put(request);
        request = NULL;
        json_object_put(result);
        result = NULL;
    }
    {
        int before = counts->beacon;
        int64_t started = apd_monotonic_ms();

        counts->serial_suppress_report = 1;
        request = beacon_batch(3);
        CHECK("missing report stops remaining batch",
              apd_openwrt_apply(request, &result) != 0 &&
              counts->beacon == before + 1 && counts->serial_overlaps == 0);
        CHECK("report wait is bounded",
              apd_monotonic_ms() - started >= APD_BEACON_SERIAL_TIMEOUT_MS &&
              apd_monotonic_ms() - started < 1000);
    }
done:
    json_object_put(request);
    json_object_put(result);
    json_object_put(reports);
    if (child > 0) {
        kill(child, SIGTERM);
        waitpid(child, NULL, 0);
    }
    if (fd >= 0)
        close(fd);
    for (i = 0; i < APD_BEACON_MONITORS_MAX; i++)
        if (g_apd_beacon_monitors[i].ctrl_path[0]) {
            close(g_apd_beacon_monitors[i].fd);
            unlink(g_apd_beacon_monitors[i].local_path);
        }
    unlink(address.sun_path);
    rmdir(APD_HOSTAPD_LOCAL_DIR);
    rmdir(APD_HOSTAPD_RUN_DIR);
    rmdir(FIXTURE_BASE);
    if (counts != MAP_FAILED)
        munmap(counts, sizeof(*counts));
    if (!rc)
        puts("ok");
    return rc;
}
