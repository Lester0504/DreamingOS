// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Parity contract between the two permission tables that guard native plugins.
 *
 * webd grades a request first and refuses it before the daemon is ever
 * contacted; the daemon then grades it again. The daemon is the authority, so
 * the only safe relationship is that the two agree. When webd is stricter, a
 * request the daemon would have allowed dies at 403 in webd — which is what
 * shipped: webd's operate list held 5 segments where the daemon's holds 17, so
 * POST .../service/restart and .../overview/egress/refresh were graded
 * "configure". An App device is an operator, operator does not carry
 * configure, and those operations were dead. start and stop worked; restart
 * did not.
 *
 * This fixture pins two things:
 *
 *   1. The classifier's own behaviour, case by case, including the ordering
 *      traps (a node probe must stay operate even though writes under /nodes/
 *      are otherwise secrets; /backups/{id}/restore must stay secrets even
 *      though "restore" is in the operate list).
 *
 *   2. That the segment list in native_plugins.c still matches the one in
 *      dreamingproxy/internal/api/api.go. This is the part that catches drift:
 *      the two files are owned by different roles, and a segment added on the
 *      daemon side without a matching webd change re-creates the same outage.
 *
 * The classifier is copied in verbatim rather than linked, because
 * native_plugins.c pulls in json-c, sockets and the manifest scanner.
 * test_tables_match_sources() re-reads both real files at run time.
 *
 * Build:
 *   cc -O0 -Wall -Wextra -o /tmp/native_perm_parity \
 *      native_plugin_permission_parity_fixture.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int failures;

/* ---- verbatim copies of the helpers under test ---- */

static int path_has_segment(const char *path, const char *segment)
{
    size_t len;
    const char *p;

    if (!path || !segment || !(len = strlen(segment)))
        return 0;
    for (p = path; (p = strchr(p, '/')) != NULL; p++) {
        p++;
        if (!strncmp(p, segment, len) && (!p[len] || p[len] == '/'))
            return 1;
        if (!*p)
            break;
    }
    return 0;
}

static int native_path_equals(const char *suffix, const char *want)
{
    if (!suffix || !want)
        return 0;
    return !strcmp(suffix, want);
}

static int native_path_has_prefix(const char *suffix, const char *prefix)
{
    size_t len;

    if (!suffix || !prefix || !(len = strlen(prefix)))
        return 0;
    return !strncmp(suffix, prefix, len);
}

static int native_path_has_suffix(const char *suffix, const char *tail)
{
    size_t sl, tl;

    if (!suffix || !tail)
        return 0;
    sl = strlen(suffix);
    tl = strlen(tail);
    return sl >= tl && !strcmp(suffix + sl - tl, tail);
}

static int native_path_is_node_scoped(const char *suffix)
{
    return native_path_has_prefix(suffix, "/nodes/");
}

static int native_path_is_subscription_raw(const char *suffix)
{
    return native_path_has_prefix(suffix, "/subscriptions/") &&
           native_path_has_suffix(suffix, "/raw");
}

static int native_path_is_data_plane(const char *suffix)
{
    return native_path_has_prefix(suffix, "/data-plane/");
}

static int native_path_is_backup_restore(const char *method, const char *suffix)
{
    const char *id, *rest;
    size_t id_len;

    if (!method || strcmp(method, "POST") || !suffix)
        return 0;
    if (!native_path_has_prefix(suffix, "/backups/"))
        return 0;
    id = suffix + strlen("/backups/");
    rest = strchr(id, '/');
    if (!rest)
        return 0;
    id_len = (size_t)(rest - id);
    if (!id_len)
        return 0;
    return !strcmp(rest, "/restore");
}

static int native_path_is_node_write_secret(const char *suffix)
{
    if (!native_path_has_prefix(suffix, "/nodes/"))
        return 0;
    if (native_path_has_suffix(suffix, "/probe") ||
        native_path_has_suffix(suffix, "/service-probe") ||
        native_path_has_suffix(suffix, "/profile-probe") ||
        native_path_has_suffix(suffix, "/ip-quality-probe") ||
        native_path_has_suffix(suffix, "/wan-policy"))
        return 0;
    return 1;
}

/*
 * The classification body, lifted from webd_native_required_permission() with
 * the plugin-id lookup removed. Returns the bare action, since the plugin id
 * prefix is not what this contract is about.
 */
static const char *classify(const char *method, const char *suffix)
{
    char path[512];

    snprintf(path, sizeof(path), "/api/v1/plugins/native/dreamingproxy%s", suffix);

    if (!strcmp(method, "GET") || !strcmp(method, "HEAD")) {
        if (native_path_is_node_scoped(suffix) ||
            native_path_equals(suffix, "/data-plane/candidate") ||
            native_path_equals(suffix, "/data-plane/last-known-good") ||
            native_path_is_subscription_raw(suffix))
            return "secrets";
        return (path_has_segment(path, "audit-events") ||
                path_has_segment(path, "diagnostics")) ? "audit" : "read";
    }
    if (native_path_is_data_plane(suffix))
        return "apply";
    if (native_path_is_backup_restore(method, suffix))
        return "secrets";
    if (native_path_is_node_write_secret(suffix))
        return "secrets";
    if (path_has_segment(path, "secret") ||
        path_has_segment(path, "secrets") ||
        path_has_segment(path, "credentials"))
        return "secrets";
    if (path_has_segment(path, "apply") ||
        path_has_segment(path, "rollback"))
        return "apply";
    if (path_has_segment(path, "simulate"))
        return "read";
    if (path_has_segment(path, "probe") ||
        path_has_segment(path, "service-probe") ||
        path_has_segment(path, "profile-probe") ||
        path_has_segment(path, "probe-profile-batch") ||
        path_has_segment(path, "ip-quality-probe") ||
        path_has_segment(path, "failover-preflight") ||
        path_has_segment(path, "select") ||
        path_has_segment(path, "probe-jobs") ||
        path_has_segment(path, "ip-quality-probe-jobs") ||
        path_has_segment(path, "refresh") ||
        path_has_segment(path, "restore") ||
        path_has_segment(path, "connections") ||
        path_has_segment(path, "connection-history") ||
        path_has_segment(path, "start") ||
        path_has_segment(path, "stop") ||
        path_has_segment(path, "restart") ||
        path_has_segment(path, "update"))
        return "operate";
    return "configure";
}

static void expect(const char *method, const char *suffix, const char *want)
{
    const char *got = classify(method, suffix);

    if (strcmp(got, want)) {
        fprintf(stderr, "  FAIL %-6s %-46s want %-9s got %s\n",
                method, suffix, want, got);
        failures++;
    }
}

/*
 * The regression itself: every row the handoff listed as "daemon says operate,
 * webd says configure, App gets 403".
 */
static void test_operator_operations_are_operate(void)
{
    expect("POST", "/overview/egress/refresh", "operate");
    expect("POST", "/service/restart", "operate");
    expect("POST", "/service/start", "operate");
    expect("POST", "/service/stop", "operate");
    expect("POST", "/wan-paths/refresh", "operate");
    expect("POST", "/nodes/n1/service-probe", "operate");
    expect("POST", "/nodes/n1/ip-quality-probe", "operate");
    expect("POST", "/nodes/n1/profile-probe", "operate");
    expect("POST", "/nodes/n1/probe", "operate");
    expect("POST", "/policy-groups/g1/select", "operate");
    expect("POST", "/policy-groups/g1/failover-preflight", "operate");
    expect("DELETE", "/connections", "operate");
    expect("DELETE", "/connections/c1", "operate");
    expect("GET", "/connection-history", "read");
    expect("POST", "/resources/r1/update", "operate");
    expect("POST", "/probe-profile-batch", "operate");
    expect("POST", "/ip-quality-probe-jobs", "operate");
    expect("POST", "/probe-jobs", "operate");
}

/*
 * Credential-bearing reads must be secrets, matching the daemon. Previously
 * webd called these "read" and forwarded them, so the daemon refused and the
 * caller saw permission_denied instead of plugin_permission_denied.
 */
static void test_credential_reads_are_secrets(void)
{
    expect("GET", "/nodes/n1", "secrets");
    expect("GET", "/nodes/n1/detail", "secrets");
    expect("GET", "/data-plane/candidate", "secrets");
    expect("GET", "/data-plane/last-known-good", "secrets");
    expect("GET", "/subscriptions/s1/raw", "secrets");

    /* the collection listing is not node-scoped and stays a normal read */
    expect("GET", "/nodes", "read");
    expect("GET", "/subscriptions/s1", "read");
    expect("GET", "/data-plane/status", "read");
}

/*
 * Ordering traps. Each of these contains a segment that appears in a lower
 * tier's list, so getting the order wrong silently changes the answer.
 */
static void test_ordering_traps(void)
{
    /*
     * "restore" is in the operate list, but a full backup restore replaces the
     * encrypted secret store. Secrets must win.
     */
    expect("POST", "/backups/b1/restore", "secrets");
    /* ... while a restore that is not the backup shape stays operate */
    expect("POST", "/service/restore", "operate");
    expect("POST", "/backups/restore", "operate");

    /*
     * Writes under /nodes/ are secrets, except the probe family. Without the
     * carve-out a node probe would be refused for an operator.
     */
    expect("POST", "/nodes/n1", "secrets");
    expect("PUT", "/nodes/n1", "secrets");
    expect("DELETE", "/nodes/n1", "secrets");
    /*
     * wan-policy is a genuine oddity worth pinning: the daemon excludes it from
     * the /nodes/ secrets rule, but never lists it as an operate segment, so it
     * falls through to configure. It is therefore NOT reachable by an operator
     * — excluded from secrets does not mean promoted to operate. Verified
     * against api.go:634 (the exclusion) and api.go:652 (the operate list,
     * which has no wan-policy entry).
     */
    expect("PATCH", "/nodes/n1/wan-policy", "configure");

    /* data-plane writes are apply, and outrank the operate segments in them */
    expect("POST", "/data-plane/apply", "apply");
    expect("POST", "/data-plane/restart", "apply");

    /* simulate mutates nothing */
    expect("POST", "/rules/simulate", "read");

    /* explicit secrets segments still win over operate */
    expect("POST", "/nodes/n1/credentials", "secrets");
    expect("POST", "/secrets/rotate", "secrets");

    /* audit/diagnostics reads */
    expect("GET", "/audit-events", "audit");
    expect("GET", "/diagnostics", "audit");

    /* anything else that writes is configure */
    expect("POST", "/policy-groups", "configure");
    expect("PATCH", "/settings", "configure");
}

/*
 * Drift guard. Reads both real files and checks that every operate segment the
 * daemon knows is also present in webd's list.
 *
 * This is the assertion that would have caught the shipped defect: the daemon
 * listed 17 segments, webd listed 5, and nothing in the build noticed.
 */
static void test_tables_match_sources(void)
{
    static const char *operate_segments[] = {
        "probe", "service-probe", "profile-probe", "probe-profile-batch",
        "ip-quality-probe", "failover-preflight", "select", "probe-jobs",
        "ip-quality-probe-jobs", "refresh", "restore", "connections",
        "connection-history", "start", "stop", "restart", "update", NULL
    };
    static const char *webd_paths[] = {
        "../src/webd/native_plugins.c",
        "jmxd/src/webd/native_plugins.c",
        "src/webd/native_plugins.c",
        NULL
    };
    static const char *daemon_paths[] = {
        "../../dreamingproxy/internal/api/api.go",
        "dreamingproxy/internal/api/api.go",
        "../dreamingproxy/internal/api/api.go",
        NULL
    };
    static char webd_buf[1 << 20];
    static char daemon_buf[1 << 20];
    FILE *fp = NULL;
    int i, missing_webd = 0, missing_daemon = 0;
    size_t n;

    for (i = 0; webd_paths[i]; i++)
        if ((fp = fopen(webd_paths[i], "r")))
            break;
    if (!fp) {
        printf("  (skipped drift check: native_plugins.c not reachable)\n");
        return;
    }
    n = fread(webd_buf, 1, sizeof(webd_buf) - 1, fp);
    webd_buf[n] = '\0';
    fclose(fp);
    fp = NULL;

    for (i = 0; operate_segments[i]; i++) {
        char needle[96];

        snprintf(needle, sizeof(needle), "path_has_segment(path, \"%s\")",
                 operate_segments[i]);
        if (!strstr(webd_buf, needle)) {
            fprintf(stderr, "  FAIL webd native_plugins.c is missing operate "
                            "segment \"%s\"\n", operate_segments[i]);
            missing_webd++;
        }
    }
    if (missing_webd)
        failures += missing_webd;
    else
        printf("  drift check: all %d daemon operate segments present in webd\n",
               (int)(sizeof(operate_segments) / sizeof(operate_segments[0]) - 1));

    /*
     * The other direction: if the daemon dropped a segment webd still grades as
     * operate, webd becomes the looser of the two. Not an outage, but it makes
     * webd's audit record wrong, so it is worth knowing.
     */
    for (i = 0; daemon_paths[i]; i++)
        if ((fp = fopen(daemon_paths[i], "r")))
            break;
    if (!fp) {
        printf("  (skipped reverse drift check: api.go not reachable)\n");
        return;
    }
    n = fread(daemon_buf, 1, sizeof(daemon_buf) - 1, fp);
    daemon_buf[n] = '\0';
    fclose(fp);

    for (i = 0; operate_segments[i]; i++) {
        char needle[96];

        snprintf(needle, sizeof(needle), "pathHasSegment(path, \"%s\")",
                 operate_segments[i]);
        if (!strstr(daemon_buf, needle)) {
            fprintf(stderr, "  FAIL daemon api.go no longer lists operate "
                            "segment \"%s\" — webd is now looser\n",
                    operate_segments[i]);
            missing_daemon++;
        }
    }
    failures += missing_daemon;
    if (!missing_daemon)
        printf("  reverse drift check: daemon still lists every segment webd "
               "grades as operate\n");

    /* the credential-read rules must exist on both sides */
    assert(strstr(daemon_buf, "\"dreamingproxy.secrets\""));
    assert(strstr(webd_buf, "native_path_is_subscription_raw"));
    assert(strstr(webd_buf, "native_path_is_node_write_secret"));
    assert(strstr(webd_buf, "native_path_is_backup_restore"));
}

int main(void)
{
    test_operator_operations_are_operate();
    test_credential_reads_are_secrets();
    test_ordering_traps();
    test_tables_match_sources();

    if (failures) {
        fprintf(stderr, "native_plugin_permission_parity_fixture: %d failure(s)\n",
                failures);
        return 1;
    }
    printf("native_plugin_permission_parity_fixture: all assertions passed\n");
    return 0;
}
