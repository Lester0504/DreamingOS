// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <limits.h>
static char fixture_executable[PATH_MAX];
#define APD_REASSOC_WORKER_EXE fixture_executable
#define APD_HOSTAPD_STANDALONE_TEST 1
#define APD_ROAMING_STANDALONE_TEST 1
#define FIXTURE_BASE "/tmp/apd-reassoc-block-fixture"
#define APD_QCA_HAPD_SUPP_PATH FIXTURE_BASE "/qca-hapd-supp"
#define APD_QCA_HAPD_PROC_ROOT FIXTURE_BASE "/proc"
#define APD_QCA_HAPD_SAFE_SIZE 3
#define APD_QCA_HAPD_SAFE_SHA256 \
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#define APD_HOSTAPD_RUN_DIR FIXTURE_BASE "/run"
#define APD_HOSTAPD_LOCAL_DIR FIXTURE_BASE "/local"
#define APD_HOSTAPD_RUN_DIR_PARENT FIXTURE_BASE
#define APD_HOSTAPD_EXPECTED_UID ((uid_t)getuid())
#define APD_HOSTAPD_SERVICE_UID ((uid_t)getuid())
#define APD_HOSTAPD_SERVICE_GID ((gid_t)getgid())
#define APD_HOSTAPD_TIMEOUT_MS 150
#include "../src/apd/apd_backend_openwrt.c"
#include <sys/mman.h>

#define STATION "44:71:47:35:e7:b3"
#define OTHER "02:11:22:33:44:55"
#define SOURCE "02:00:00:00:10:01"
#define TARGET "02:00:00:00:20:01"
#define BSS_COUNT 6

static struct {
    int denied[BSS_COUNT], added[BSS_COUNT], removed[BSS_COUNT];
    int associated, fail_add, lose_ack, unsupported, bad, deauth;
    int last_added, source_added_last;
    int other_acl, requests, mld_bss;
} *state;
static pid_t server_pid;

static void cleanup(void)
{
    char path[128];
    int i;

    apd_reassoc_block_release(STATION);
    if (server_pid > 0) {
        kill(server_pid, SIGTERM);
        waitpid(server_pid, NULL, 0);
    }
    for (i = 0; i < BSS_COUNT; i++) {
        snprintf(path, sizeof(path), APD_HOSTAPD_RUN_DIR "/ath%d", i);
        unlink(path);
    }
    unlink(APD_HOSTAPD_LOCAL_DIR "/reassoc-" STATION ".lock");
    unlink(APD_QCA_HAPD_PROC_ROOT "/123/exe");
    rmdir(APD_QCA_HAPD_PROC_ROOT "/123");
    rmdir(APD_QCA_HAPD_PROC_ROOT);
    unlink(APD_QCA_HAPD_PID_PATH);
    unlink(APD_QCA_HAPD_SUPP_PATH);
    rmdir(APD_HOSTAPD_LOCAL_DIR);
    rmdir(APD_HOSTAPD_RUN_DIR);
    rmdir(FIXTURE_BASE);
}

#define CHECK(label, expression) do { \
    if (!(expression)) { fprintf(stderr, "FAIL %s\n", label); cleanup(); return 1; } \
} while (0)

static void serve(int sockets[BSS_COUNT])
{
    const int frequency[] = { 5180, 2417, 5745, 6775, 5180, 2417 };
    struct pollfd polls[BSS_COUNT];
    int i;

    for (i = 0; i < BSS_COUNT; i++) {
        polls[i].fd = sockets[i];
        polls[i].events = POLLIN;
    }
    for (;;) {
        if (poll(polls, BSS_COUNT, -1) <= 0)
            _exit(1);
        for (i = 0; i < BSS_COUNT; i++) {
            struct sockaddr_un peer;
            socklen_t peer_len = sizeof(peer);
            char command[256], response[1024];
            const char *reply = response;
            ssize_t n;

            if (!(polls[i].revents & POLLIN))
                continue;
            n = recvfrom(sockets[i], command, sizeof(command) - 1, 0,
                         (struct sockaddr *)&peer, &peer_len);
            if (n <= 0)
                _exit(2);
            command[n] = '\0';
            state->requests++;
            snprintf(response, sizeof(response), "FAIL\n");
            if (!strcmp(command, "STATUS")) {
                snprintf(response, sizeof(response),
                    "state=ENABLED\nbssid[0]=02:00:00:00:10:%02x\n"
                    "ssid[0]=%s\nfreq=%d\nchannel=36\nnum_sta[0]=1\n",
                    i + 1, i == 4 ? "IoT" : i == 5 ? "Xiaomi_Test-MLO" :
                    "Xiaomi_DE23", frequency[i]);
                if (state->mld_bss == i)
                    strncat(response, "mld_addr=02:00:00:00:10:10\nlink_id=0\n",
                            sizeof(response) - strlen(response) - 1);
            } else if (!strcmp(command, "STA " STATION)) {
                if (i == 0 && state->associated)
                    snprintf(response, sizeof(response),
                        STATION "\nflags=[AUTH][ASSOC][AUTHORIZED]\n");
            } else if (!strcmp(command, "DENY_ACL SHOW")) {
                snprintf(response, sizeof(response), "%s%s",
                         state->denied[i] ? STATION " VLAN_ID=0\n" : "",
                         state->other_acl ? OTHER " VLAN_ID=0\n" : "");
                if (state->unsupported == i)
                    snprintf(response, sizeof(response), "UNKNOWN COMMAND\n");
            } else if (!strcmp(command, "DENY_ACL ADD_MAC " STATION)) {
                if (i >= 4)
                    state->bad++;
                state->added[i]++;
                state->last_added = i;
                if (state->fail_add != i) {
                    state->denied[i] = 1;
                    if (i == 0) {
                        state->associated = 0;
                        state->source_added_last = 1;
                    } else if (state->source_added_last) {
                        state->bad++;
                    }
                    snprintf(response, sizeof(response), "OK\n");
                }
                if (state->lose_ack == i)
                    continue;
            } else if (!strcmp(command, "DENY_ACL DEL_MAC " STATION)) {
                if (i >= 4)
                    state->bad++;
                state->removed[i]++;
                state->denied[i] = 0;
                snprintf(response, sizeof(response), "OK\n");
            } else if (!strcmp(command, "DEAUTHENTICATE " STATION " reason=5")) {
                state->deauth++;
                state->associated = 0;
                snprintf(response, sizeof(response), "OK\n");
            } else {
                state->bad++;
            }
            sendto(sockets[i], reply, strlen(reply), 0,
                   (struct sockaddr *)&peer, peer_len);
        }
    }
}

static struct json_object *candidate(const char *scope, int seconds)
{
    char json[1024], digest[APD_CONFIG_DIGEST_MAX];
    struct json_object *root, *sections;
    const char *target_frequency = !strcmp(scope, "lower") ?
        "\"target_frequency_mhz\":\"6775\"," : "";

    snprintf(json, sizeof(json),
        "{\"format\":\"" APD_CONFIG_CANDIDATE_FORMAT "\",\"sections\":["
        "{\"section\":\"ath0\",\"options\":{\"hostapd_action_type\":\"reassoc_block\","
        "\"station_mac\":\"" STATION "\",\"deauth_reason\":\"5\","
        "\"source_bssid\":\"" SOURCE "\","
        "\"source_ssid\":\"Xiaomi_DE23\",\"target_bssid\":\"" TARGET "\","
        "%s\"block_scope\":\"%s\",\"block_duration_sec\":\"%d\","
        "\"block_not_after\":\"%lld\"}}]}", target_frequency, scope,
        seconds,
        (long long)time(NULL) + 30);
    root = json_tokener_parse(json);
    sections = json_object_object_get(root, "sections");
    if (apd_config_candidate_digest(sections, digest, sizeof(digest)) != 0)
        abort();
    json_object_object_add(root, "candidate_digest", json_object_new_string(digest));
    return root;
}

static void reset(void)
{
    memset(state, 0, sizeof(*state));
    state->associated = 1;
    state->fail_add = state->lose_ack = state->unsupported = -1;
    state->mld_bss = -1;
}

static void set_option(struct json_object *request, const char *name,
                        const char *value)
{
    struct json_object *sections = json_object_object_get(request, "sections");
    struct json_object *options = json_object_object_get(
        json_object_array_get_idx(sections, 0), "options");
    char digest[APD_CONFIG_DIGEST_MAX];

    json_object_object_add(options, name, json_object_new_string(value));
    if (apd_config_candidate_digest(sections, digest, sizeof(digest)) != 0)
        abort();
    json_object_object_add(request, "candidate_digest", json_object_new_string(digest));
}

static int await_release(int preserved)
{
    int64_t deadline = apd_monotonic_ms() + 4000;

    while (apd_monotonic_ms() < deadline) {
        if (!state->denied[0] && state->denied[1] == preserved &&
            !state->denied[2] && !state->denied[3])
            return 1;
        poll(NULL, 0, 20);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *scopes[] = { "bss", "band", "ap", "lower" };
    const int expected[] = { 1, 2, 4, 3 };
    int sockets[BSS_COUNT], i, j;
    struct json_object *request, *result = NULL;

    snprintf(fixture_executable, sizeof(fixture_executable), "%s", argv[0]);
    if (argc == 3 && !strcmp(argv[1], "--reassoc-block-worker"))
        return apd_reassoc_block_worker(atoi(argv[2]));
    state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK("mmap", state != MAP_FAILED);
    mkdir(FIXTURE_BASE, 0700);
    mkdir(APD_HOSTAPD_RUN_DIR, 0700);
    CHECK("local dir", apd_hostapd_local_dir_prepare() == 0);
    for (i = 0; i < BSS_COUNT; i++) {
        struct sockaddr_un address = { .sun_family = AF_UNIX };

        snprintf(address.sun_path, sizeof(address.sun_path),
                 APD_HOSTAPD_RUN_DIR "/ath%d", i);
        unlink(address.sun_path);
        sockets[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
        CHECK("bind", sockets[i] >= 0 && bind(sockets[i],
            (struct sockaddr *)&address, sizeof(address)) == 0);
    }
    server_pid = fork();
    CHECK("server fork", server_pid >= 0);
    if (!server_pid)
        serve(sockets);
    for (i = 0; i < BSS_COUNT; i++)
        close(sockets[i]);

    reset();
    {
        int fd = open(APD_QCA_HAPD_SUPP_PATH, O_CREAT | O_EXCL | O_WRONLY, 0600);

        CHECK("native backend quarantine fixture", fd >= 0);
        close(fd);
        request = candidate("ap", 10);
        CHECK("unsafe native backend rejects before ACL writes",
              apd_openwrt_apply(request, &result) != 0 &&
              state->associated && !state->bad && !state->requests);
        CHECK("quarantine receipt states the native backend reason",
              !strcmp(json_object_get_string(json_object_object_get(
                  json_object_object_get(result, "reassoc_block"), "reason")),
                  "reassoc_block_native_backend_quarantined"));
        for (i = 0; i < BSS_COUNT; i++)
            CHECK("quarantine touches no BSS", state->added[i] == 0);
        json_object_put(result);
        result = NULL;
        json_object_put(request);
        CHECK("quarantine fixture cleanup", unlink(APD_QCA_HAPD_SUPP_PATH) == 0);
    }

    {
        FILE *file = fopen(APD_QCA_HAPD_SUPP_PATH, "w");

        CHECK("patched native fixture", file && fputs("abc", file) >= 0);
        CHECK("patched native fixture close", fclose(file) == 0);
        CHECK("native missing PID remains quarantined",
              !apd_hostapd_reassoc_backend_safe());
        file = fopen(APD_QCA_HAPD_PID_PATH, "w");
        CHECK("native PID fixture", file && fputs("123\n", file) >= 0);
        CHECK("native PID fixture close", fclose(file) == 0);
        CHECK("native exited PID remains quarantined",
              !apd_hostapd_reassoc_backend_safe());
        CHECK("fake proc root", mkdir(APD_QCA_HAPD_PROC_ROOT, 0700) == 0);
        CHECK("fake proc PID", mkdir(APD_QCA_HAPD_PROC_ROOT "/123", 0700) == 0);
        file = fopen(APD_QCA_HAPD_PROC_ROOT "/123/exe", "w");
        CHECK("old running inode fixture", file && fputs("abc", file) >= 0);
        CHECK("old running inode close", fclose(file) == 0);
        CHECK("patched disk with old process remains quarantined",
              !apd_hostapd_reassoc_backend_safe());
        CHECK("old running inode cleanup",
              unlink(APD_QCA_HAPD_PROC_ROOT "/123/exe") == 0);
        CHECK("patched running inode fixture",
              link(APD_QCA_HAPD_SUPP_PATH,
                   APD_QCA_HAPD_PROC_ROOT "/123/exe") == 0);
        CHECK("exact patched native executable qualifies",
              apd_hostapd_reassoc_backend_safe());
        reset();
        request = candidate("ap", 1);
        CHECK("patched native lease apply",
              apd_openwrt_apply(request, &result) == 0 &&
              state->denied[0] && state->denied[1] &&
              state->denied[2] && state->denied[3] && !state->bad);
        CHECK("patched native lease expires", await_release(0));
        json_object_put(result);
        result = NULL;
        json_object_put(request);
        file = fopen(APD_QCA_HAPD_SUPP_PATH, "w");
        CHECK("unknown native content fixture",
              file && fputs("abd", file) >= 0);
        CHECK("unknown native content close", fclose(file) == 0);
        reset();
        request = candidate("ap", 1);
        CHECK("unknown same-size native rejects before any socket request",
              apd_openwrt_apply(request, &result) != 0 &&
              state->associated && !state->requests && !state->bad);
        json_object_put(result);
        result = NULL;
        json_object_put(request);
        CHECK("native inode cleanup", unlink(APD_QCA_HAPD_PROC_ROOT "/123/exe") == 0);
        CHECK("native PID directory cleanup", rmdir(APD_QCA_HAPD_PROC_ROOT "/123") == 0);
        CHECK("native proc cleanup", rmdir(APD_QCA_HAPD_PROC_ROOT) == 0);
        CHECK("native PID cleanup", unlink(APD_QCA_HAPD_PID_PATH) == 0);
        CHECK("native file cleanup", unlink(APD_QCA_HAPD_SUPP_PATH) == 0);
    }

    for (j = 0; j < 2; j++) {
        reset();
        state->mld_bss = j;
        request = candidate("ap", 10);
        CHECK("MLD scope rejects before ACL writes",
              apd_openwrt_apply(request, &result) != 0 &&
              state->associated && !state->deauth && !state->bad);
        for (i = 0; i < BSS_COUNT; i++)
            CHECK("MLD rejection touches no BSS", state->added[i] == 0);
        json_object_put(result);
        result = NULL;
        json_object_put(request);
    }

    for (j = 0; j < 3; j++) {
        int count = 0;

        reset();
        request = candidate(scopes[j], 1);
        CHECK("full AC reassociation payload validation",
              apd_config_hostapd_actions_validate(request, &result) == 0);
        json_object_put(result);
        result = NULL;
        CHECK("scope apply", apd_openwrt_apply(request, &result) == 0);
        CHECK("lease evidence", !strcmp(json_object_get_string(
            json_object_object_get(result, "evidence_type")),
            "hostapd_temporary_reassociation_block"));
        for (i = 0; i < BSS_COUNT; i++)
            count += state->denied[i];
        CHECK("exact scope", count == expected[j] && state->denied[0] &&
              !state->denied[4] && !state->denied[5] &&
              state->last_added == 0 && !state->bad);
        CHECK("independent expiry", await_release(0));
        json_object_put(request);
        json_object_put(result);
        result = NULL;
    }
    reset();
    request = candidate("lower", 1);
    CHECK("lower scope preserves 5-to-6 target",
          apd_openwrt_apply(request, &result) == 0);
    CHECK("lower scope blocks source and lower bands",
          state->denied[0] && state->denied[1] && state->denied[2] &&
          !state->denied[3] && !state->denied[4] && !state->denied[5] &&
          !state->bad);
    CHECK("lower scope expiry", await_release(0));
    json_object_put(request);
    json_object_put(result);
    result = NULL;
    reset();
    request = candidate("lower", 1);
    set_option(request, "target_bssid", "02:00:00:00:10:03");
    set_option(request, "target_frequency_mhz", "5745");
    CHECK("lower scope preserves selected lower-band target",
          apd_openwrt_apply(request, &result) == 0 &&
          state->denied[0] && state->denied[1] &&
          !state->denied[2] && !state->denied[3] && !state->bad);
    CHECK("lower selected target expiry", await_release(0));
    json_object_put(request);
    json_object_put(result);
    result = NULL;
    reset();
    request = candidate("ap", 10);
    set_option(request, "neighbor_ft", "0");
    set_option(request, "target_ft", "0");
    CHECK("reassociation option limit remains bounded",
          apd_config_hostapd_actions_validate(request, &result) != 0 &&
          state->added[0] == 0 && state->associated);
    json_object_put(result);
    result = NULL;
    json_object_put(request);
    request = candidate("ap", 10);
    set_option(request, "hostapd_action_type", "btm_request");
    set_option(request, "neighbor_bssid", "02:00:00:00:30:01");
    set_option(request, "neighbor_ssid", "Xiaomi_DE23");
    set_option(request, "neighbor_opclass", "131");
    set_option(request, "neighbor_channel", "69");
    set_option(request, "neighbor_phy", "9");
    set_option(request, "neighbor_ft", "0");
    set_option(request, "target_opclass", "131");
    set_option(request, "target_channel", "69");
    CHECK("other runtime actions retain original option bound",
          apd_config_hostapd_actions_validate(request, &result) != 0);
    json_object_put(result);
    result = NULL;
    json_object_put(request);

    reset();
    state->denied[1] = 1;
    state->other_acl = 1;
    request = candidate("ap", 1);
    CHECK("preserve existing apply", apd_openwrt_apply(request, &result) == 0);
    CHECK("existing ACL never added", state->added[1] == 0);
    CHECK("existing ACL survives expiry", await_release(1) &&
          state->removed[1] == 0 && !state->bad);
    json_object_put(result);
    result = NULL;
    json_object_put(request);

    reset();
    request = candidate("ap", 1);
    set_option(request, "target_bssid", "02:00:00:00:10:02");
    CHECK("target remains reachable inside blocked scope",
          apd_openwrt_apply(request, &result) == 0 &&
          state->denied[0] && !state->denied[1] && !state->bad);
    CHECK("target-preserving scope expires", await_release(0));
    json_object_put(result);
    result = NULL;
    json_object_put(request);
    reset();
    request = candidate("ap", 10);
    set_option(request, "source_ssid", "IoT");
    CHECK("source SSID ownership", apd_openwrt_apply(request, &result) != 0 &&
          state->added[0] == 0 && state->added[4] == 0);
    json_object_put(result);
    result = NULL;
    json_object_put(request);
    request = candidate("ap", 10);
    set_option(request, "block_not_after", "1");
    CHECK("expired queue cannot disconnect", apd_openwrt_apply(request, &result) != 0 &&
          state->added[0] == 0 && state->associated);
    json_object_put(result);
    result = NULL;
    json_object_put(request);

    reset();
    state->fail_add = 2;
    request = candidate("ap", 10);
    CHECK("partial add fails", apd_openwrt_apply(request, &result) != 0);
    CHECK("partial rollback", await_release(0) && state->added[0] == 0 &&
          !state->bad);
    json_object_put(result);
    result = NULL;
    json_object_put(request);

    reset();
    state->lose_ack = 2;
    request = candidate("ap", 10);
    CHECK("lost ACK fails", apd_openwrt_apply(request, &result) != 0);
    CHECK("ambiguous add removed", await_release(0) && state->removed[2] > 0);
    json_object_put(result);
    result = NULL;
    json_object_put(request);

    reset();
    state->unsupported = 2;
    request = candidate("ap", 10);
    CHECK("unsupported ACL refuses entire scope",
          apd_openwrt_apply(request, &result) != 0 && state->added[0] == 0 &&
          state->added[1] == 0 && state->added[2] == 0);
    json_object_put(result);
    result = NULL;
    json_object_put(request);

    reset();
    request = candidate("ap", 10);
    CHECK("release fixture apply", apd_openwrt_apply(request, &result) == 0);
    json_object_put(result);
    result = NULL;
    CHECK("overlapping lease refused", apd_openwrt_apply(request, &result) != 0);
    CHECK("explicit early release", apd_reassoc_block_release(STATION) == 0 &&
          await_release(0) && !state->bad);
    json_object_put(result);
    result = NULL;
    json_object_put(request);

    reset();
    {
        int pipefd[2], reply, status;
        pid_t parent;

        CHECK("crash pipe", pipe(pipefd) == 0);
        parent = fork();
        CHECK("APD fork", parent >= 0);
        if (!parent) {
            close(pipefd[0]);
            request = candidate("ap", 2);
            reply = apd_openwrt_apply(request, &result);
            if (write(pipefd[1], &reply, sizeof(reply)) != sizeof(reply))
                _exit(2);
            for (;;)
                pause();
        }
        close(pipefd[1]);
        CHECK("APD applied", read(pipefd[0], &reply, sizeof(reply)) == sizeof(reply) &&
              reply == 0 && state->denied[0]);
        close(pipefd[0]);
        CHECK("kill APD", kill(parent, SIGKILL) == 0 &&
              waitpid(parent, &status, 0) == parent && WIFSIGNALED(status));
        CHECK("expiry survives APD SIGKILL", await_release(0) && !state->bad);
    }
    cleanup();
    puts("ok: BSS/AP/band isolation, owned ACL expiry, partial/lost ACK rollback, "
         "overlap exclusion, early release and APD SIGKILL");
    return 0;
}
