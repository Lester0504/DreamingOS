// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#define APD_HOSTAPD_STANDALONE_TEST 1
#define APD_HOSTAPD_RUN_DIR "/tmp/apd-hostapd-runtime-fixture-20260722/run"
#define APD_HOSTAPD_LOCAL_DIR "/tmp/apd-hostapd-runtime-fixture-20260722/local"
/* Pinned to the fixture tree so the vendor per-radio directory scan cannot
 * reach the host's real /var/run while these scenarios execute. */
#define APD_HOSTAPD_RUN_DIR_PARENT "/tmp/apd-hostapd-runtime-fixture-20260722"
#define APD_HOSTAPD_EXPECTED_UID ((uid_t)getuid())
#define APD_HOSTAPD_TIMEOUT_MS 100
#define APD_HOSTAPD_COLLECTION_TIMEOUT_MS 500
#define APD_HOSTAPD_RESPONSE_LIMIT 512U
#define APD_HOSTAPD_BSS_LIMIT 2U
#define APD_HOSTAPD_STATION_LIMIT 4U
#define APD_HOSTAPD_STATIONS_PER_BSS_LIMIT 3U
#define APD_HOSTAPD_SOCKET_SCAN_LIMIT 16U

#include "../src/apd/apd_backend_openwrt.c"

#include <signal.h>
#include <sys/wait.h>

#define FIXTURE_BASE "/tmp/apd-hostapd-runtime-fixture-20260722"
/* QSDK-style per-radio control directory, a sibling of the run directory. */
#define FIXTURE_VENDOR_DIR_PATH FIXTURE_BASE "/hostapd-wifi0"

enum fixture_mode {
    FIXTURE_SUCCESS,
    FIXTURE_PARTIAL_MLO,
    FIXTURE_TIMEOUT,
    FIXTURE_MALFORMED,
    FIXTURE_MALFORMED_STATION,
    FIXTURE_OVERSIZED,
    FIXTURE_STATION_LIMIT,
    FIXTURE_BSS_LIMIT,
    FIXTURE_NO_SOCKET,
    FIXTURE_NO_PHY,
    FIXTURE_UNSUPPORTED,
    FIXTURE_MISSING_DIR,
    FIXTURE_UNTRUSTED_DIR,
    FIXTURE_UNTRUSTED_LOCAL_DIR,
    /* QSDK layout: `global` in the run directory, VAP sockets in per-radio
     * sibling directories (`hostapd-wifiN`). */
    FIXTURE_VENDOR_DIR,
    /* Only a `global` socket, with nothing listening on it. */
    FIXTURE_STALE_GLOBAL,
};

struct fixture_socket {
    int fd;
    const char *name;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

static int fixture_contains(const void *data, size_t data_len,
                            const char *needle)
{
    const unsigned char *bytes = data;
    size_t needle_len = strlen(needle);
    size_t i;

    if (!needle_len || needle_len > data_len)
        return 0;
    for (i = 0; i + needle_len <= data_len; i++) {
        if (!memcmp(bytes + i, needle, needle_len))
            return 1;
    }
    return 0;
}

static void fixture_cleanup_paths(struct fixture_socket *sockets,
                                  size_t socket_count)
{
    size_t i;

    for (i = 0; i < socket_count; i++) {
        if (sockets[i].fd >= 0)
            close(sockets[i].fd);
        if (sockets[i].path[0])
            unlink(sockets[i].path);
    }
    /*
     * The `global` socket is not part of the caller's socket_count (the vendor
     * scenario parks it past the end, the stale one leaves only a path), so both
     * layouts are removed by name. Leaving one behind would leak into the next
     * scenario and make it read as a live control channel.
     */
    unlink(APD_HOSTAPD_RUN_DIR "/global");
    unlink(FIXTURE_VENDOR_DIR_PATH "/wlan0");
    rmdir(APD_HOSTAPD_LOCAL_DIR);
    rmdir(APD_HOSTAPD_RUN_DIR);
    rmdir(FIXTURE_VENDOR_DIR_PATH);
    rmdir(FIXTURE_BASE);
}

static int fixture_prepare_dirs(void)
{
    struct stat st;

    mkdir(FIXTURE_BASE, 0700);
    mkdir(APD_HOSTAPD_RUN_DIR, 0700);
    mkdir(APD_HOSTAPD_LOCAL_DIR, 0700);
    if (lstat(APD_HOSTAPD_RUN_DIR, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != getuid())
        return -1;
    return 0;
}

static int fixture_open_socket_in(struct fixture_socket *control,
                                  const char *directory, const char *name)
{
    struct sockaddr_un address = { .sun_family = AF_UNIX };

    memset(control, 0, sizeof(*control));
    control->fd = -1;
    control->name = name;
    if (snprintf(control->path, sizeof(control->path), "%s/%s",
                 directory, name) >= (int)sizeof(control->path))
        return -1;
    memcpy(address.sun_path, control->path, strlen(control->path) + 1);
    control->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (control->fd < 0 ||
        bind(control->fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        return -1;
    return 0;
}

static int fixture_open_socket(struct fixture_socket *control, const char *name)
{
    return fixture_open_socket_in(control, APD_HOSTAPD_RUN_DIR, name);
}

static int fixture_reply(int fd, const struct sockaddr_un *peer,
                         socklen_t peer_len, const char *response)
{
    size_t length = strlen(response);

    return sendto(fd, response, length, 0,
                  (const struct sockaddr *)peer, peer_len) == (ssize_t)length ?
                  0 : -1;
}

static const char *fixture_status(const char *name, enum fixture_mode mode)
{
    if (mode == FIXTURE_MALFORMED)
        return "state=ENABLED\nbssid=not-a-mac\n";
    if (mode == FIXTURE_OVERSIZED)
        return NULL;
    if (mode == FIXTURE_PARTIAL_MLO)
        return "state=ENABLED\nbssid=02:00:00:00:00:01\nssid[0]=Phase1-MLO\n"
               "freq=5955\nchannel=1\nnum_sta[0]=1\nmld_addr=02:00:00:00:10:00\n"
               "psk=phase1-secret-status\nsae_password=phase1-secret-sae\n";
    if (mode == FIXTURE_STATION_LIMIT)
        return "state=ENABLED\nbssid=02:00:00:00:00:01\nssid[0]=Phase1-Limit\n"
               "freq=2412\nchannel=1\nnum_sta[0]=4\n";
    if (mode == FIXTURE_BSS_LIMIT)
        return "state=ENABLED\nbssid=02:00:00:00:00:01\nssid[0]=Phase1-BSS\n"
               "freq=2412\nchannel=1\nnum_sta[0]=0\n";
    if (!strcmp(name, "wlan0"))
        return "state=ENABLED\nbssid=02:00:00:00:00:01\nssid[0]=Phase1-2G\n"
               "freq=2437\nchannel=6\nnum_sta[0]=2\n"
               "psk=phase1-secret-status\nsae_password=phase1-secret-sae\n";
    return "state=ENABLED\nbssid=02:00:00:00:01:01\nssid[0]=Phase1-5G\n"
           "freq=5745\nchannel=149\nnum_sta[0]=1\n";
}

static const char *fixture_station(const char *name, const char *command,
                                   enum fixture_mode mode)
{
    if (mode == FIXTURE_BSS_LIMIT)
        return "FAIL\n";
    if (mode == FIXTURE_UNSUPPORTED)
        return "UNKNOWN COMMAND\n";
    if (mode == FIXTURE_MALFORMED_STATION) {
        if (!strcmp(command, "STA-FIRST"))
            return "not-a-mac\nflags=[AUTH][ASSOC]\nsignal=-50\n";
        return "FAIL\n";
    }
    if (mode == FIXTURE_PARTIAL_MLO) {
        if (!strcmp(command, "STA-FIRST"))
            return "02:00:00:00:20:01\nflags=[AUTH][ASSOC][AUTHORIZED]\n"
                   "signal=-44\nrx_bytes=100\ntx_bytes=200\nconnected_time=30\n"
                   "mld_addr=02:00:00:00:20:00\npsk=phase1-secret-station\n";
        return "FAIL\n";
    }
    if (mode == FIXTURE_STATION_LIMIT) {
        if (!strcmp(command, "STA-FIRST"))
            return "02:00:00:00:30:01\nflags=[AUTH][ASSOC]\nsignal=-50\n";
        if (strstr(command, "30:01"))
            return "02:00:00:00:30:02\nflags=[AUTH][ASSOC]\nsignal=-51\n";
        if (strstr(command, "30:02"))
            return "02:00:00:00:30:03\nflags=[AUTH][ASSOC]\nsignal=-52\n";
        if (strstr(command, "30:03"))
            return "02:00:00:00:30:04\nflags=[AUTH][ASSOC]\nsignal=-53\n";
        return "FAIL\n";
    }
    if (!strcmp(name, "wlan0")) {
        if (!strcmp(command, "STA-FIRST"))
            return "02:00:00:00:10:01\nflags=[AUTH][ASSOC][AUTHORIZED]\n"
                   "signal=-41\nrx_bytes=101\ntx_bytes=202\nrx_packets=3\ntx_packets=4\n"
                   "connected_time=60\ninactive_msec=7\n"
                   "mld_addr=02:00:00:00:10:00\nlink_id=0\n"
                   "psk=phase1-secret-station\n";
        if (strstr(command, "10:01"))
            return "02:00:00:00:10:02\nflags=[AUTH][ASSOC]\nsignal=-55\n"
                   "rx_bytes=303\ntx_bytes=404\nconnected_time=20\n";
        return "FAIL\n";
    }
    if (!strcmp(command, "STA-FIRST"))
        return "02:00:00:00:11:01\nflags=[AUTH][ASSOC][AUTHORIZED]\n"
               "signal=-61\nrx_bytes=505\ntx_bytes=606\nconnected_time=90\n";
    return "FAIL\n";
}

static int fixture_server(struct fixture_socket *sockets, size_t socket_count,
                          enum fixture_mode mode)
{
    size_t handled = 0;
    size_t idle_rounds = 0;

    while (idle_rounds < 20) {
        struct pollfd polls[4];
        size_t i;
        int ready;

        for (i = 0; i < socket_count; i++) {
            polls[i].fd = sockets[i].fd;
            polls[i].events = POLLIN;
            polls[i].revents = 0;
        }
        ready = poll(polls, socket_count, 100);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0) {
            idle_rounds++;
            continue;
        }
        idle_rounds = 0;
        for (i = 0; i < socket_count; i++) {
            struct sockaddr_un peer;
            socklen_t peer_len = sizeof(peer);
            char command[128];
            ssize_t length;
            const char *response;

            if (!(polls[i].revents & POLLIN))
                continue;
            length = recvfrom(sockets[i].fd, command, sizeof(command) - 1, 0,
                              (struct sockaddr *)&peer, &peer_len);
            if (length <= 0)
                return 2;
            command[length] = '\0';
            handled++;
            if (mode == FIXTURE_TIMEOUT)
                continue;
            if (!strcmp(command, "STATUS")) {
                response = fixture_status(sockets[i].name, mode);
                if (mode == FIXTURE_OVERSIZED) {
                    char oversized[1024];

                    memset(oversized, 'A', sizeof(oversized));
                    if (sendto(sockets[i].fd, oversized, sizeof(oversized), 0,
                               (struct sockaddr *)&peer, peer_len) !=
                        (ssize_t)sizeof(oversized))
                        return 3;
                    continue;
                }
            } else {
                response = fixture_station(sockets[i].name, command, mode);
            }
            if (!response || fixture_reply(sockets[i].fd, &peer, peer_len,
                                            response) != 0)
                return 4;
        }
    }
    return handled ? 0 : 5;
}

static int fixture_assert_result(enum fixture_mode mode,
                                 const struct apd_hostapd_observation *result)
{
    if (fixture_contains(result, sizeof(*result), "phase1-secret"))
        return 20;
    if (mode == FIXTURE_SUCCESS) {
        if (!result->available || !result->complete || result->bss_count != 2 ||
            result->station_count != 3 || strcmp(result->bss[0].interface, "wlan0") ||
            strcmp(result->bss[1].interface, "wlan1") ||
            !result->stations[0].mlo_relation_complete ||
            strcmp(result->stations[0].mld_address, "02:00:00:00:10:00") ||
            result->stations[0].link_id != 0 || result->reason[0])
            return 21;
    } else if (mode == FIXTURE_PARTIAL_MLO) {
        if (result->complete || result->station_count != 1 ||
            !result->stations[0].has_mld_address ||
            result->stations[0].has_link_id ||
            result->stations[0].mlo_relation_complete ||
            strcmp(result->reason, "hostapd_mlo_relation_partial"))
            return 22;
    } else if (mode == FIXTURE_TIMEOUT) {
        if (result->complete || strcmp(result->reason, "hostapd_status_timeout"))
            return 23;
    } else if (mode == FIXTURE_MALFORMED) {
        if (result->complete || strcmp(result->reason, "hostapd_status_malformed"))
            return 24;
    } else if (mode == FIXTURE_MALFORMED_STATION) {
        if (result->complete || result->station_count != 0 ||
            strcmp(result->reason, "hostapd_station_malformed"))
            return 30;
    } else if (mode == FIXTURE_OVERSIZED) {
        if (result->complete ||
            strcmp(result->reason, "hostapd_status_response_too_large"))
            return 25;
    } else if (mode == FIXTURE_STATION_LIMIT) {
        if (result->complete || !result->station_limited ||
            result->station_count != APD_HOSTAPD_STATIONS_PER_BSS_LIMIT ||
            strcmp(result->reason, "hostapd_station_limit_reached"))
            return 26;
    } else if (mode == FIXTURE_BSS_LIMIT) {
        if (result->complete || !result->bss_limited ||
            result->interface_controls != 3 || result->bss_count != 2 ||
            strcmp(result->reason, "hostapd_bss_limit_reached"))
            return 27;
    } else if (mode == FIXTURE_NO_SOCKET) {
        if (result->available || result->complete || result->bss_count != 0 ||
            result->station_count != 0 ||
            strcmp(result->reason, "control_sockets_unavailable"))
            return 28;
    } else if (mode == FIXTURE_NO_PHY) {
        if (!result->complete || result->available || result->bss_count != 0 ||
            result->station_count != 0 || strcmp(result->reason, "no_phy_detected"))
            return 29;
    } else if (mode == FIXTURE_UNSUPPORTED) {
        if (result->complete || result->station_count != 0 ||
            strcmp(result->reason, "hostapd_station_query_unsupported"))
            return 32;
    } else if (mode == FIXTURE_MISSING_DIR) {
        if (result->directory_available || result->available || result->complete ||
            strcmp(result->reason, "control_directory_unavailable"))
            return 33;
    } else if (mode == FIXTURE_UNTRUSTED_DIR) {
        if (result->directory_available || result->available || result->complete ||
            strcmp(result->reason, "control_directory_untrusted"))
            return 34;
    } else if (mode == FIXTURE_UNTRUSTED_LOCAL_DIR) {
        if (result->available || result->complete || result->bss_count != 0 ||
            result->station_count != 0 ||
            strcmp(result->reason, "local_control_directory_untrusted"))
            return 35;
    } else if (mode == FIXTURE_VENDOR_DIR) {
        /*
         * The QSDK case this was blind to. The VAP socket lives in
         * `hostapd-wifi0`, not in the run directory, and the old collector saw
         * only `global` there and reported per_interface_control_unavailable on
         * a device where the socket existed and answered.
         */
        if (!result->available || !result->complete ||
            result->interface_controls != 1 || result->bss_count != 1 ||
            strcmp(result->bss[0].interface, "wlan0") ||
            !result->global_control || result->reason[0])
            return 36;
    } else if (mode == FIXTURE_STALE_GLOBAL) {
        /*
         * A `global` socket nobody listens on must not be read as a live
         * control channel. lstat proves the inode, not a listener.
         */
        if (result->available || result->complete || result->bss_count != 0 ||
            !result->global_control ||
            strcmp(result->reason, "hostapd_control_socket_stale"))
            return 37;
    }
    return 0;
}

static int fixture_parse_mode(const char *value, enum fixture_mode *mode,
                              size_t *socket_count)
{
    if (!strcmp(value, "success"))
        *mode = FIXTURE_SUCCESS;
    else if (!strcmp(value, "partial-mlo")) {
        *mode = FIXTURE_PARTIAL_MLO;
        *socket_count = 1;
    } else if (!strcmp(value, "timeout")) {
        *mode = FIXTURE_TIMEOUT;
        *socket_count = 1;
    } else if (!strcmp(value, "malformed")) {
        *mode = FIXTURE_MALFORMED;
        *socket_count = 1;
    } else if (!strcmp(value, "malformed-station")) {
        *mode = FIXTURE_MALFORMED_STATION;
        *socket_count = 1;
    } else if (!strcmp(value, "oversized")) {
        *mode = FIXTURE_OVERSIZED;
        *socket_count = 1;
    } else if (!strcmp(value, "station-limit")) {
        *mode = FIXTURE_STATION_LIMIT;
        *socket_count = 1;
    } else if (!strcmp(value, "bss-limit")) {
        *mode = FIXTURE_BSS_LIMIT;
        *socket_count = 3;
    } else if (!strcmp(value, "no-socket")) {
        *mode = FIXTURE_NO_SOCKET;
        *socket_count = 0;
    } else if (!strcmp(value, "no-phy")) {
        *mode = FIXTURE_NO_PHY;
        *socket_count = 0;
    } else if (!strcmp(value, "unsupported")) {
        *mode = FIXTURE_UNSUPPORTED;
        *socket_count = 1;
    } else if (!strcmp(value, "missing-dir")) {
        *mode = FIXTURE_MISSING_DIR;
        *socket_count = 0;
    } else if (!strcmp(value, "untrusted-dir")) {
        *mode = FIXTURE_UNTRUSTED_DIR;
        *socket_count = 0;
    } else if (!strcmp(value, "untrusted-local-dir")) {
        *mode = FIXTURE_UNTRUSTED_LOCAL_DIR;
        *socket_count = 1;
    } else if (!strcmp(value, "vendor-dir")) {
        *mode = FIXTURE_VENDOR_DIR;
        *socket_count = 1;
    } else if (!strcmp(value, "stale-global")) {
        *mode = FIXTURE_STALE_GLOBAL;
        *socket_count = 0;
    } else {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static const char *const names[] = { "wlan0", "wlan1", "wlan2" };
    struct fixture_socket sockets[3] = {
        { .fd = -1 }, { .fd = -1 }, { .fd = -1 }
    };
    struct apd_hostapd_observation result;
    enum fixture_mode mode = FIXTURE_SUCCESS;
    size_t socket_count = 2;
    size_t i;
    pid_t child;
    int child_status = 0;
    int rc;

    if (argc != 2 || fixture_parse_mode(argv[1], &mode, &socket_count) != 0)
        return 64;
    fixture_cleanup_paths(sockets, 0);
    if (fixture_prepare_dirs() != 0)
        return 65;
    /*
     * Both new scenarios need a `global` socket present. In the vendor case a
     * live one, because the collector now probes it; in the stale case an inode
     * with no listener, which is what hostapd leaves behind when it exits.
     */
    if (mode == FIXTURE_VENDOR_DIR || mode == FIXTURE_STALE_GLOBAL) {
        struct fixture_socket global_socket;

        if (fixture_open_socket(&global_socket, "global") != 0) {
            fixture_cleanup_paths(sockets, socket_count);
            return 66;
        }
        /*
         * The fd is closed while the path stays: an inode with no listener.
         * That is exactly the abandoned socket hostapd leaves behind. The
         * vendor scenario never probes it (the probe only runs when no
         * per-interface socket was found), so one layout serves both.
         */
        close(global_socket.fd);
    }
    if (mode == FIXTURE_VENDOR_DIR && mkdir(FIXTURE_VENDOR_DIR_PATH, 0700) != 0 &&
        errno != EEXIST) {
        fixture_cleanup_paths(sockets, socket_count);
        return 65;
    }
    for (i = 0; i < socket_count; i++) {
        if ((mode == FIXTURE_VENDOR_DIR ?
                fixture_open_socket_in(&sockets[i], FIXTURE_VENDOR_DIR_PATH,
                                       names[i]) :
                fixture_open_socket(&sockets[i], names[i])) != 0) {
            fixture_cleanup_paths(sockets, socket_count);
            return 66;
        }
    }
    child = -1;
    if (socket_count > 0 && mode != FIXTURE_UNTRUSTED_LOCAL_DIR) {
        child = fork();
        if (child < 0) {
            fixture_cleanup_paths(sockets, socket_count);
            return 67;
        }
        if (child == 0)
            _exit(fixture_server(sockets, socket_count, mode));
        for (i = 0; i < socket_count; i++) {
            close(sockets[i].fd);
            sockets[i].fd = -1;
        }
    }
    if (mode == FIXTURE_MISSING_DIR)
        rmdir(APD_HOSTAPD_RUN_DIR);
    else if (mode == FIXTURE_UNTRUSTED_DIR)
        chmod(APD_HOSTAPD_RUN_DIR, 0777);
    else if (mode == FIXTURE_UNTRUSTED_LOCAL_DIR)
        chmod(APD_HOSTAPD_LOCAL_DIR, 0777);
    rc = apd_hostapd_collect_raw(mode == FIXTURE_NO_PHY ? 0 : 2, &result);
    (void)rc;
    if (child > 0 && (waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)) {
        fixture_cleanup_paths(sockets, socket_count);
        return 68;
    }
    rc = fixture_assert_result(mode, &result);
    if (rc == 0 && mode == FIXTURE_SUCCESS) {
        struct apd_hostapd_observation fresh;

        for (i = 0; i < socket_count; i++)
            unlink(sockets[i].path);
        apd_hostapd_collect_raw(2, &fresh);
        if (fresh.station_count != 0 || fresh.bss_count != 0 || fresh.available ||
            fresh.complete ||
            strcmp(fresh.reason, "control_sockets_unavailable"))
            rc = 31;
    }
    if (mode == FIXTURE_UNTRUSTED_DIR)
        chmod(APD_HOSTAPD_RUN_DIR, 0700);
    if (mode == FIXTURE_UNTRUSTED_LOCAL_DIR)
        chmod(APD_HOSTAPD_LOCAL_DIR, 0700);
    fixture_cleanup_paths(sockets, socket_count);
    if (rc != 0) {
        fprintf(stderr, "%s: assertion %d failed (reason=%s, bss=%zu, sta=%zu)\n",
                argv[1], rc, result.reason, result.bss_count,
                result.station_count);
        return rc;
    }
    printf("ok: %s\n", argv[1]);
    return 0;
}
