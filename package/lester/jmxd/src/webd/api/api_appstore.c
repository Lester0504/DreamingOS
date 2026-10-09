// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * App Store REST surface -- worker thin-client model.
 * Contract: todo/2026-09-23/Handoff/PM-to-Backend-appstore-remote-catalog-apk-feed-v1.md §7
 *
 *   §7.1  GET  /api/v1/appstore/catalog        (+ /apps alias)
 *         POST /api/v1/appstore/catalog/refresh (202 -> task)
 *   §7.2  GET  /api/v1/appstore/installed
 *         GET  /api/v1/appstore/apps/{id}/status
 *         GET  /api/v1/appstore/tasks/{taskId}
 *   §7.3  POST /api/v1/appstore/apps/{id}/install|update|uninstall|rollback (202 -> task)
 *         POST /api/v1/appstore/apps/{id}/install-stream  (501)
 *   §7.5  GET  /api/v1/appstore/ports/check?ports=53,3000
 *
 * There is no package manager here. All network + crypto + filesystem mutation
 * lives in a standalone C worker (/usr/bin/dwrt-appstore-worker) that this
 * module drives: webd resolves the request against the signed catalog, writes a
 * task spec, spawns the worker fully detached, and answers subsequent polls by
 * reading two on-disk authorities it never writes to itself except as spec:
 *
 *   - app_registry  /etc/dreamingwrt/appstore/registry/<id>.json  (installed truth)
 *   - task state    /etc/dreamingwrt/appstore/tasks/<taskId>.state.json (worker)
 *
 * The worker must replace its process image before a supervision tick, because
 * dreamingwrt-init SIGKILLs orphaned processes whose command line still reads
 * "dreamingwrt-webd"; the double-fork + immediate execv below guarantees that.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <uci.h>
#include <curl/curl.h>
#include "../webd_http.h"
#include "../jmx_app_api.h"

#include "api_appstore.h"
#include "api_appstore_capabilities.h"
#include "api_appstore_network.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_util.h"

#ifndef APPSTORE_ROOT
#define APPSTORE_ROOT             "/etc/dreamingwrt/appstore"
#endif
#ifndef APPSTORE_DATA_ROOT
#define APPSTORE_DATA_ROOT        "/overlay/dreamingos-appstore/data"
#endif
#define APPSTORE_CATALOG_RUNTIME  APPSTORE_ROOT "/catalog.json"
#define APPSTORE_CATALOG_PACKAGED "/usr/share/dreamingwrt/appstore/catalog.json"
#define APPSTORE_CATALOG_INDEX    APPSTORE_ROOT "/catalog.index.json"
#define APPSTORE_REGISTRY_DIR     APPSTORE_ROOT "/registry"
#define APPSTORE_TASKS_DIR        APPSTORE_ROOT "/tasks"
#define APPSTORE_TRUST            "/etc/dreamingwrt/appstore-trust/trust.json"
#define APPSTORE_WORKER_BIN       "/usr/bin/dwrt-appstore-worker"
#define APPSTORE_CA_DEFAULT       "/etc/ssl/certs/ca-certificates.crt"

/* The runtime ABI follows the compiled device, not the authoring machine. */
#if defined(__x86_64__) && defined(__GLIBC__)
#define APPSTORE_DEVICE_TARGET    "linux-x86_64-glibc"
#define APPSTORE_DEVICE_ARCH      "x86_64"
#elif defined(__aarch64__) && defined(__GLIBC__)
#define APPSTORE_DEVICE_TARGET    "linux-aarch64-glibc"
#define APPSTORE_DEVICE_ARCH      "aarch64"
#else
#define APPSTORE_DEVICE_TARGET    "unsupported"
#define APPSTORE_DEVICE_ARCH      "unsupported"
#endif
#define APPSTORE_PLATFORM_API     1

/* Distributor config shares the OTA UCI package (see api_ota_remote.c). */
#define APPSTORE_UCI_PACKAGE      "relay"
#define APPSTORE_UCI_SECTION      "appstore"
#define APPSTORE_DEFAULT_CHANNEL  "stable"

#define APPSTORE_MAX_PORTS        64
#define APPSTORE_BUSY_GRACE_S     600   /* meta-without-state is "queued" this long */

/* ---- small shared helpers ---------------------------------------------- */

/* Catalog ids are the primary key and are spliced into on-disk paths, so the
 * character set is locked down: this keeps ".." or a slash out of every path
 * built from an id. Mirrors the worker's valid_app_id(). */
static int appstore_id_valid(const char *id)
{
    size_t i, n;

    if (!id || !id[0])
        return 0;
    n = strlen(id);
    if (n > 64)
        return 0;
    for (i = 0; i < n; i++) {
        char c = id[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

/* A task id is webd_request_id() output (hex); lock it down the same way so it
 * is safe to splice into a tasks/ path. */
static int appstore_task_id_valid(const char *id)
{
    size_t i, n;

    if (!id || !id[0])
        return 0;
    n = strlen(id);
    if (n > 64)
        return 0;
    for (i = 0; i < n; i++) {
        char c = id[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return 0;
    }
    return 1;
}

/* Case-insensitive substring for the optional ?q= search. */
static int appstore_ci_contains(const char *haystack, const char *needle)
{
    size_t nlen;

    if (!needle || !needle[0])
        return 1;
    if (!haystack || !haystack[0])
        return 0;
    nlen = strlen(needle);
    for (; *haystack; haystack++) {
        if (!strncasecmp(haystack, needle, nlen))
            return 1;
    }
    return 0;
}

static void appstore_now_iso(char *buf, size_t n)
{
    time_t t = time(NULL);
    struct tm tm;

    gmtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void appstore_ensure_dirs(void)
{
    mkdir("/etc/dreamingwrt", 0755);
    mkdir(APPSTORE_ROOT, 0755);
    mkdir(APPSTORE_REGISTRY_DIR, 0755);
    mkdir(APPSTORE_TASKS_DIR, 0755);
}

/* Atomic publish: temp file carrying the pid, then rename over the target. */
static int appstore_write_atomic(const char *path, const char *s, size_t len)
{
    char tmp[320];
    int fd;

    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    if (webd_write_all(fd, s, len) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* The signed, worker-published catalog is authoritative; fall back to a
 * packaged catalog only when no refresh has ever landed. */
static struct json_object *appstore_load_catalog(void)
{
    if (access(APPSTORE_CATALOG_RUNTIME, R_OK) == 0) {
        struct json_object *o = json_object_from_file(APPSTORE_CATALOG_RUNTIME);

        if (o)
            return o;
    }
    if (access(APPSTORE_CATALOG_PACKAGED, R_OK) == 0)
        return json_object_from_file(APPSTORE_CATALOG_PACKAGED);
    return NULL;
}

/* Fetch metadata sidecar the worker writes on catalog-refresh; may be absent. */
static struct json_object *appstore_load_index(void)
{
    if (access(APPSTORE_CATALOG_INDEX, R_OK) == 0)
        return json_object_from_file(APPSTORE_CATALOG_INDEX);
    return NULL;
}

/* Borrowed pointer into the catalog; valid only while the catalog is held. */
static struct json_object *appstore_find_app(struct json_object *catalog,
                                             const char *id)
{
    struct json_object *apps = NULL;
    size_t i, n;

    if (!catalog ||
        !json_object_object_get_ex(catalog, "apps", &apps) || !apps ||
        !json_object_is_type(apps, json_type_array))
        return NULL;
    n = json_object_array_length(apps);
    for (i = 0; i < n; i++) {
        struct json_object *a = json_object_array_get_idx(apps, i);

        if (a && !strcmp(app_nc_json_str(a, "id", ""), id))
            return a;
    }
    return NULL;
}

static struct json_object *appstore_registry_load(const char *id)
{
    char path[288];

    if (!appstore_id_valid(id))
        return NULL;
    snprintf(path, sizeof(path), "%s/%s.json", APPSTORE_REGISTRY_DIR, id);
    if (access(path, R_OK) != 0)
        return NULL;
    return json_object_from_file(path);
}

/*
 * Pick the release this device should install: the highest build number whose
 * targets[] carries an entry for APPSTORE_DEVICE_TARGET. On success returns 1
 * and sets *rel_out (release object) and *tgt_out (the matching target object,
 * carrying descriptorSha256 + artifactId). Both are borrowed from the catalog.
 */
static int appstore_select_release(struct json_object *app,
                                   struct json_object **rel_out,
                                   struct json_object **tgt_out)
{
    struct json_object *releases = NULL;
    struct json_object *best = NULL, *best_tgt = NULL;
    int64_t best_build = -1;
    size_t i, n;

    *rel_out = NULL;
    *tgt_out = NULL;
    if (!app || !json_object_object_get_ex(app, "releases", &releases) ||
        !releases || !json_object_is_type(releases, json_type_array))
        return 0;
    n = json_object_array_length(releases);
    for (i = 0; i < n; i++) {
        struct json_object *rel = json_object_array_get_idx(releases, i);
        struct json_object *targets = NULL;
        size_t j, m;

        if (!rel)
            continue;
        if (!json_object_object_get_ex(rel, "targets", &targets) || !targets ||
            !json_object_is_type(targets, json_type_array))
            continue;
        m = json_object_array_length(targets);
        for (j = 0; j < m; j++) {
            struct json_object *tg = json_object_array_get_idx(targets, j);

            if (tg && !strcmp(app_nc_json_str(tg, "target", ""),
                              APPSTORE_DEVICE_TARGET)) {
                int64_t build = app_nc_json_int64(rel, "build", 0);

                if (build > best_build) {
                    best_build = build;
                    best = rel;
                    best_tgt = tg;
                }
                break;
            }
        }
    }
    if (!best)
        return 0;
    *rel_out = best;
    *tgt_out = best_tgt;
    return 1;
}

/* Distributor base URL / channel / CA out of UCI (relay.appstore.*). Returns 0
 * when dist_url is present, -1 otherwise. Mirrors api_ota_remote.c. */
struct appstore_source {
    char dist_url[512];
    char channel[64];
    char ca_path[256];
};

static int appstore_uci_source(struct appstore_source *out)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_section *section;
    const char *v;

    memset(out, 0, sizeof(*out));
    snprintf(out->channel, sizeof(out->channel), "%s", APPSTORE_DEFAULT_CHANNEL);

    ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    if (uci_load(ctx, APPSTORE_UCI_PACKAGE, &pkg) != UCI_OK || !pkg) {
        uci_free_context(ctx);
        return -1;
    }
    section = uci_lookup_section(ctx, pkg, APPSTORE_UCI_SECTION);
    if (!section) {
        uci_free_context(ctx);
        return -1;
    }
    v = uci_lookup_option_string(ctx, section, "dist_url");
    if (v)
        snprintf(out->dist_url, sizeof(out->dist_url), "%s", v);
    v = uci_lookup_option_string(ctx, section, "channel");
    if (v)
        snprintf(out->channel, sizeof(out->channel), "%s", v);
    v = uci_lookup_option_string(ctx, section, "ca_path");
    if (v)
        snprintf(out->ca_path, sizeof(out->ca_path), "%s", v);
    uci_free_context(ctx);
    return out->dist_url[0] ? 0 : -1;
}

/* ---- port scan (kept from the apk-era module; §7.5 + runtimeState) ------ */

/*
 * Scan /proc/net/{tcp,tcp6,udp,udp6} for <port>. Field 2 is "HEXADDR:HEXPORT",
 * field 4 is the socket state. For TCP a port is "in use" only when LISTENing
 * (state 0x0A); for UDP any bound socket counts.
 */
static int appstore_proc_net_has_port(const char *file, unsigned port,
                                      int listen_only)
{
    FILE *fp = fopen(file, "r");
    char line[512];
    int header = 1;

    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned local_port = 0;
        unsigned st = 0;

        if (header) {
            header = 0;
            continue;
        }
        if (sscanf(line, "%*d: %*[0-9A-Fa-f]:%x %*[0-9A-Fa-f]:%*x %x",
                   &local_port, &st) != 2)
            continue;
        if (local_port != port)
            continue;
        if (listen_only && st != 0x0AU)
            continue;
        fclose(fp);
        return 1;
    }
    fclose(fp);
    return 0;
}

static int appstore_port_in_use(unsigned port, int want_tcp, int want_udp)
{
    if (want_tcp) {
        if (appstore_proc_net_has_port("/proc/net/tcp", port, 1) ||
            appstore_proc_net_has_port("/proc/net/tcp6", port, 1))
            return 1;
    }
    if (want_udp) {
        if (appstore_proc_net_has_port("/proc/net/udp", port, 0) ||
            appstore_proc_net_has_port("/proc/net/udp6", port, 0))
            return 1;
    }
    return 0;
}

/* runtimeState is independent of installStatus: an installed app whose TCP port
 * is not LISTENing is "stopped", not uninstalled. "degraded" is reserved for a
 * failed rollback and is decided by the caller from the task state. */
static const char *appstore_runtime_state(int port)
{
    if (port <= 0 || port > 65535)
        return "stopped";
    return appstore_port_in_use((unsigned)port, 1, 0) ? "running" : "stopped";
}

/* ---- task files: spec / state / meta / app pointer --------------------- */

static void appstore_task_state_path(const char *task_id, char *b, size_t n)
{
    snprintf(b, n, "%s/%s.state.json", APPSTORE_TASKS_DIR, task_id);
}

static void appstore_task_meta_path(const char *task_id, char *b, size_t n)
{
    snprintf(b, n, "%s/%s.meta.json", APPSTORE_TASKS_DIR, task_id);
}

static void appstore_task_spec_path(const char *task_id, char *b, size_t n)
{
    snprintf(b, n, "%s/%s.spec.json", APPSTORE_TASKS_DIR, task_id);
}

/* Per-app pointer to the most recent task id, so status can find the operation
 * without scanning the tasks directory. */
static void appstore_app_current_path(const char *id, char *b, size_t n)
{
    snprintf(b, n, "%s/app-%s.current", APPSTORE_TASKS_DIR, id);
}

static int appstore_read_current_task(const char *id, char *buf, size_t len)
{
    char path[288];
    FILE *fp;
    size_t got;

    appstore_app_current_path(id, path, sizeof(path));
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    got = fread(buf, 1, len - 1, fp);
    fclose(fp);
    buf[got] = '\0';
    while (got > 0 && (buf[got - 1] == '\n' || buf[got - 1] == '\r' ||
                       buf[got - 1] == ' ')) {
        buf[--got] = '\0';
    }
    return buf[0] && appstore_task_id_valid(buf) ? 0 : -1;
}

/*
 * Build the §7.2 operation object for a task id from its meta (webd) + state
 * (worker) files. Returns NULL when the task is unknown. state==NULL but meta
 * present is reported as "queued": the worker has been spawned but has not yet
 * written its first state. Caller owns the returned object.
 */
static struct json_object *appstore_operation_obj(const char *task_id)
{
    char mp[288], sp[288];
    struct json_object *meta, *state = NULL, *op, *err = NULL;
    const char *wstate, *phase, *type;
    int terminal = 0;

    if (!task_id || !task_id[0] || !appstore_task_id_valid(task_id))
        return NULL;
    appstore_task_meta_path(task_id, mp, sizeof(mp));
    if (access(mp, R_OK) != 0)
        return NULL;
    meta = json_object_from_file(mp);
    if (!meta)
        return NULL;
    appstore_task_state_path(task_id, sp, sizeof(sp));
    if (access(sp, R_OK) == 0)
        state = json_object_from_file(sp);

    op = json_object_new_object();
    type = app_nc_json_str(meta, "type", "");
    webd_obj_add_str(op, "task_id", task_id);
    webd_obj_add_str(op, "type", type);
    webd_obj_add_str(op, "appId", app_nc_json_str(meta, "appId", ""));
    webd_obj_add_str(op, "targetReleaseId",
                     app_nc_json_str(meta, "targetReleaseId", ""));
    webd_obj_add_str(op, "startedAt", app_nc_json_str(meta, "startedAt", ""));

    if (!state) {
        webd_obj_add_str(op, "state", "queued");
        webd_obj_add_str(op, "stage", "queued");
        json_object_object_add(op, "percent", NULL);
        json_object_object_add(op, "error", NULL);
    } else {
        struct json_object *result = NULL;
        if (json_object_object_get_ex(state, "result", &result) && result)
            json_object_object_add(op, "result", json_object_get(result));
        wstate = app_nc_json_str(state, "state", "running");
        phase = app_nc_json_str(state, "phase", "");
        terminal = strcmp(wstate, "running") != 0;
        webd_obj_add_str(op, "state", wstate);
        webd_obj_add_str(op, "stage", phase);
        if (json_object_object_get_ex(state, "percent", NULL))
            json_object_object_add(op, "percent",
                json_object_new_int((int)app_nc_json_int64(state, "percent", 0)));
        else
            json_object_object_add(op, "percent", NULL);
        if (json_object_object_get_ex(state, "error", &err) && err)
            json_object_object_add(op, "error", json_object_get(err));
        else
            json_object_object_add(op, "error", NULL);
        if (terminal) {
            webd_obj_add_str(op, "finishedAt",
                             app_nc_json_str(state, "updatedAt", ""));
            webd_obj_add_str(op, "result", wstate);
        }
    }
    /* rollbackState is not threaded through the worker task state yet; report
     * null rather than inventing a value. */
    json_object_object_add(op, "rollbackState", NULL);
    if (state)
        json_object_put(state);
    json_object_put(meta);
    return op;
}

/* True while the app's most recent task is still running (or freshly queued). */
static int appstore_app_busy(const char *id)
{
    char task_id[80];
    struct json_object *op;
    const char *st;
    int busy = 0;

    if (appstore_read_current_task(id, task_id, sizeof(task_id)) != 0)
        return 0;
    op = appstore_operation_obj(task_id);
    if (!op)
        return 0;
    st = app_nc_json_str(op, "state", "");
    if (!strcmp(st, "running") || !strcmp(st, "queued"))
        busy = 1;
    json_object_put(op);
    return busy;
}

/* ---- worker spawn ------------------------------------------------------ */

/*
 * Run the installer worker fully detached: double fork so it reparents to init
 * and this request never waits on it, setsid to drop the session, then execv so
 * the process image is replaced before a supervision tick -- dreamingwrt-init
 * SIGKILLs orphans whose argv still reads "dreamingwrt-webd", and the worker's
 * own name is deliberately not a supervised-daemon name. The worker writes all
 * progress to its task state file; nothing is read back from this call.
 */
static int appstore_spawn_worker(const char *spec_path)
{
    pid_t pid = fork();

    if (pid < 0)
        return -1;
    if (pid == 0) {
        pid_t gk;
        int nul;

        setsid();
        gk = fork();
        if (gk < 0)
            _exit(127);
        if (gk > 0)
            _exit(0);

        nul = open("/dev/null", O_RDWR);
        if (nul >= 0) {
            dup2(nul, 0);
            dup2(nul, 1);
            dup2(nul, 2);
            if (nul > 2)
                close(nul);
        }
        {
            char *const av[] = { "dwrt-appstore-worker", (char *)spec_path,
                                 NULL };

            execv(APPSTORE_WORKER_BIN, av);
        }
        _exit(127);
    }
    waitpid(pid, NULL, 0); /* reap the short-lived intermediate */
    return 0;
}

/*
 * Persist a task and launch it. Writes the spec, a webd-owned meta record, and
 * the per-app "current" pointer, then spawns the worker. On success copies the
 * task id into task_out and returns 0. spec is consumed (freed) here.
 */
static int appstore_accept_task(struct jmx_api_ctx *ctx, const char *id, const char *type,
                                const char *target_release_id,
                                struct json_object *spec,
                                char *task_out, size_t task_len)
{
    char task_id[48];
    char spec_path[288], meta_path[288], cur_path[288], cur_tmp[320];
    char state_path[288];
    struct json_object *meta;
    const char *s;
    char now[40];
    int fd;

    appstore_ensure_dirs();
    webd_request_id(task_id, sizeof(task_id));
    if (!appstore_task_id_valid(task_id)) {
        json_object_put(spec);
        return -1;
    }
    appstore_now_iso(now, sizeof(now));

    /* statePath is pinned into the spec so the worker and status agree. */
    appstore_task_state_path(task_id, state_path, sizeof(state_path));
    webd_obj_add_str(spec, "taskId", task_id);
    webd_obj_add_str(spec, "statePath", state_path);
    struct json_object *log_context = json_object_new_object();
    webd_obj_add_str(log_context, "actor", ctx->device_id);
    webd_obj_add_str(log_context, "source_ip", ctx->req->client_ip);
    json_object_object_add(spec, "log_context", log_context);

    appstore_task_spec_path(task_id, spec_path, sizeof(spec_path));
    s = json_object_to_json_string_ext(spec, JSON_C_TO_STRING_PLAIN);
    if (!s || appstore_write_atomic(spec_path, s, strlen(s)) != 0) {
        json_object_put(spec);
        return -1;
    }
    json_object_put(spec);

    meta = json_object_new_object();
    webd_obj_add_str(meta, "task_id", task_id);
    webd_obj_add_str(meta, "appId", id);
    webd_obj_add_str(meta, "type", type);
    webd_obj_add_str(meta, "targetReleaseId",
                     target_release_id ? target_release_id : "");
    webd_obj_add_str(meta, "startedAt", now);
    appstore_task_meta_path(task_id, meta_path, sizeof(meta_path));
    s = json_object_to_json_string_ext(meta, JSON_C_TO_STRING_PLAIN);
    if (s)
        appstore_write_atomic(meta_path, s, strlen(s));
    json_object_put(meta);

    /* Point the app at this task before spawning, so a status poll that races
     * the worker still finds the operation. */
    appstore_app_current_path(id, cur_path, sizeof(cur_path));
    snprintf(cur_tmp, sizeof(cur_tmp), "%s.tmp.%d", cur_path, (int)getpid());
    fd = open(cur_tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        if (webd_write_all(fd, task_id, strlen(task_id)) == 0) {
            close(fd);
            if (rename(cur_tmp, cur_path) != 0)
                unlink(cur_tmp);
        } else {
            close(fd);
            unlink(cur_tmp);
        }
    }

    if (appstore_spawn_worker(spec_path) != 0)
        return -1;
    snprintf(task_out, task_len, "%s", task_id);
    return 0;
}
/* installStatus per §7.2: the registry is the source of truth; a pending
 * install with no registry record yet reads as installing/failed. */
static const char *appstore_installstatus(const char *id, struct json_object *reg)
{
    char task_id[80];
    struct json_object *op;
    const char *st, *type;
    const char *result = reg ? "installed" : "not-installed";

    if (reg)
        return result;
    if (appstore_read_current_task(id, task_id, sizeof(task_id)) != 0)
        return result;
    op = appstore_operation_obj(task_id);
    if (!op)
        return result;
    st = app_nc_json_str(op, "state", "");
    type = app_nc_json_str(op, "type", "");
    if ((!strcmp(st, "running") || !strcmp(st, "queued")) && !strcmp(type, "install"))
        result = "installing";
    else if (!strcmp(st, "failed") && !strcmp(type, "install"))
        result = "failed";
    json_object_put(op);
    return result;
}

/* §7 selectedRelease. sizeBytes lives in release.json, which the device only
 * fetches at install time, so it is null here until we persist it. */
static struct json_object *appstore_selected_release(struct json_object *rel,
                                                     struct json_object *tgt)
{
    struct json_object *o = json_object_new_object();

    webd_obj_add_str(o, "releaseId", app_nc_json_str(rel, "releaseId", ""));
    webd_obj_add_str(o, "version", app_nc_json_str(rel, "version", ""));
    json_object_object_add(o, "build",
        json_object_new_int((int)app_nc_json_int64(rel, "build", 0)));
    webd_obj_add_str(o, "target", app_nc_json_str(tgt, "target", ""));
    json_object_object_add(o, "sizeBytes", NULL);
    return o;
}
/* configSchema is only known once an app's manifest is on the device (from the
 * registry record). A not-installed app reports [] until it is fetched. */
static struct json_object *appstore_config_schema(struct json_object *reg)
{
    struct json_object *manifest = NULL, *cs = NULL;

    if (reg && json_object_object_get_ex(reg, "manifest", &manifest) && manifest &&
        json_object_object_get_ex(manifest, "configSchema", &cs) && cs &&
        json_object_is_type(cs, json_type_array))
        return json_object_get(cs);
    return json_object_new_array();
}

/* Current app-owned file is the authority; registry config is an install snapshot. */
static struct json_object *appstore_current_config(const char *id, char revision[65])
{
    char path[256]; unsigned char digest[32]; unsigned int size = 0;
    snprintf(path, sizeof(path), APPSTORE_DATA_ROOT "/%s/config.json", id);
    struct json_object *cfg = json_object_from_file(path);
    if (!cfg || !json_object_is_type(cfg, json_type_object)) {
        if (cfg) json_object_put(cfg);
        return NULL;
    }
    const char *text = json_object_to_json_string_ext(cfg, JSON_C_TO_STRING_PLAIN);
    if (!EVP_Digest(text, strlen(text), digest, &size, EVP_sha256(), NULL) || size != 32) {
        json_object_put(cfg); return NULL;
    }
    for (unsigned int i = 0; i < size; i++) snprintf(revision + i * 2, 3, "%02x", digest[i]);
    return cfg;
}

static struct json_object *appstore_configuration(struct jmx_api_ctx *ctx, const char *id)
{
    struct json_object *reg = appstore_registry_load(id);
    if (!reg) { ctx->status = 404; return webd_error("app_not_installed", "app is not installed", "id", "webd.appstore"); }
    char revision[65];
    struct json_object *cfg = appstore_current_config(id, revision);
    if (!cfg) { json_object_put(reg); ctx->status = 503; return webd_error("configuration_unavailable", "current configuration cannot be read", "", "webd.appstore"); }
    struct json_object *raw_schema = appstore_config_schema(reg);
    struct json_object *schema = json_tokener_parse(json_object_to_json_string(raw_schema)), *secrets = json_object_new_object();
    json_object_put(raw_schema);
    for (size_t i = 0; i < json_object_array_length(schema); i++) {
        struct json_object *f = json_object_array_get_idx(schema, i), *value = NULL;
        const char *key = app_nc_json_str(f, "key", "");
        if (!strcmp(app_nc_json_str(f, "type", ""), "password")) {
            json_object_object_del(f, "default");
            json_object_object_get_ex(cfg, key, &value);
            json_object_object_add(secrets, key, json_object_new_boolean(value && json_object_get_string(value)[0]));
            json_object_object_del(cfg, key);
        }
    }
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "configuration", cfg);
    json_object_object_add(data, "secretsSet", secrets);
    json_object_object_add(data, "configSchema", schema);
    webd_obj_add_str(data, "revision", revision);
    webd_obj_add_str(data, "applyMode", "restart-if-running");
    webd_obj_add_str(data, "runtimeState", appstore_runtime_state((int)app_nc_json_int64(reg, "port", 0)));
    json_object_put(reg);
    return webd_envelope(data, "webd.appstore");
}

static struct json_object *appstore_network_policy_load(const char *id, char revision[65])
{
    char path[256]; snprintf(path, sizeof(path), APPSTORE_ROOT "/network/%s.json", id);
    struct json_object *policy = access(path, F_OK) && errno == ENOENT ? appstore_network_defaults() : json_object_from_file(path);
    if (!policy || appstore_network_validate(policy)) { if (policy) json_object_put(policy); return NULL; }
    appstore_network_revision(policy, revision);
    return policy;
}

static struct json_object *appstore_network_policy_get(struct jmx_api_ctx *ctx, const char *id)
{
    struct json_object *reg = appstore_registry_load(id), *mf = NULL;
    if (!reg) { ctx->status = 404; return webd_error("app_not_installed", "app is not installed", "id", "webd.appstore"); }
    json_object_object_get_ex(reg, "manifest", &mf);
    int supported = appstore_manifest_tun(mf); json_object_put(reg);
    if (!supported) { ctx->status = 422; return webd_error("network_unsupported", "installed app does not declare tun", "", "webd.appstore"); }
    char revision[65], iface[16], zone[20];
    struct json_object *policy = appstore_network_policy_load(id, revision);
    if (!policy) { ctx->status = 503; return webd_error("network_policy_unavailable", "network policy cannot be read", "", "webd.appstore"); }
    appstore_network_identity(id, iface, zone);
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "policy", policy);
    webd_obj_add_str(data, "revision", revision);
    webd_obj_add_str(data, "interface", iface);
    webd_obj_add_str(data, "readiness", "ensure-required");
    int wan = app_nc_json_bool(policy, "toWan", 0) && app_nc_json_bool(policy, "exitNode", 0);
    webd_obj_add_str(data, "wanState", wan ? "allowed" : app_nc_json_bool(policy, "toWan", 0) ? "exit-authorization-required" : "blocked");
    ctx->status = 200; return webd_envelope(data, "webd.appstore");
}

/* Signed catalog requirements are an early hint; the worker repeats the check
 * against the signed descriptor and extracted manifest before activation. */
static int appstore_release_requirements(struct json_object *target,
                                         char missing[65], const char **reason)
{
    struct json_object *requires = NULL;
    if (target) json_object_object_get_ex(target, "requires", &requires);
    return appstore_requirements_check(requires, missing, 65, reason);
}

static void appstore_add_installability(struct json_object *data, int has_release,
                                         struct json_object *rel, struct json_object *target,
                                         const char *no_release_reason)
{
    char missing[65]; const char *reason = "";
    struct json_object *requires = NULL;
    int rc = has_release ? appstore_release_requirements(target, missing, &reason) : 0;
    int checked = target && json_object_object_get_ex(target, "requires", &requires) && requires;
    json_object_object_add(data, "requirementsChecked", json_object_new_boolean(checked));
    json_object_object_add(data, "installable", json_object_new_boolean(has_release && !rc));
    if (!has_release) webd_obj_add_str(data, "unavailableReason", no_release_reason);
    else if (rc) webd_obj_add_str(data, "unavailableReason", rc < 0 ? "requirements_invalid" : "capability_unavailable");
    else json_object_object_add(data, "unavailableReason", NULL);
    struct json_object *missing_caps = json_object_new_array();
    if (has_release && rc > 0) json_object_array_add(missing_caps, json_object_new_string(missing));
    json_object_object_add(data, "missingCapabilities", missing_caps);
    webd_obj_add_str(data, "capabilityReason", reason);
    json_object_object_add(data, "selectedRelease", has_release ? appstore_selected_release(rel, target) : NULL);
}

/* One catalog list entry (§7.1 apps[]). Borrows the catalog app object. */
static struct json_object *appstore_catalog_entry(struct json_object *app)
{
    struct json_object *rel = NULL, *tgt = NULL, *reg, *entry;
    const char *id = app_nc_json_str(app, "id", "");
    const char *icon = app_nc_json_str(app, "icon", "");
    int has_release = appstore_select_release(app, &rel, &tgt);

    reg = appstore_registry_load(id);
    entry = json_object_new_object();
    webd_obj_add_str(entry, "id", id);
    webd_obj_add_str(entry, "name", app_nc_json_str(app, "name", id));
    webd_obj_add_str(entry, "category", app_nc_json_str(app, "category", ""));
    /* Optional Lucide glyph name (signed catalog app.icon). Same charset as an
     * id, so the UI can use it as an icon-table key; anything else is dropped. */
    if (appstore_id_valid(icon))
        webd_obj_add_str(entry, "icon", icon);
    webd_obj_add_str(entry, "packageFormat", "dapp/1");
    webd_obj_add_str(entry, "version",
        has_release ? app_nc_json_str(rel, "version", "") : "");
    json_object_object_add(entry, "featured",
        json_object_new_boolean(app_nc_json_bool(app, "featured", 0)));
    json_object_object_add(entry, "homepage",
        json_object_new_boolean(app_nc_json_bool(app, "homepage", 0)));
    webd_obj_add_str(entry, "installStatus", appstore_installstatus(id, reg));
    appstore_add_installability(entry, has_release, rel, tgt, "architecture_unsupported");
    json_object_object_add(entry, "configSchema", appstore_config_schema(reg));
    if (reg)
        json_object_put(reg);
    return entry;
}
/* GET /catalog (and /apps alias). Returns the BARE dwrt-appstore-catalog/1
 * object (not enveloped), transforming the stored dreamingos-shop-catalog/1. */
static struct json_object *appstore_catalog(struct jmx_api_ctx *ctx)
{
    struct json_object *catalog, *apps = NULL, *out, *caps, *index, *device;
    struct json_object *cats, *list, *idx;
    char q[128] = "", category[64] = "", featbuf[8] = "", homebuf[8] = "";
    int want_featured, want_homepage;
    const char *query = ctx->req ? ctx->req->query : "";
    int runtime_present = (access(APPSTORE_CATALOG_RUNTIME, R_OK) == 0);
    size_t i, n;

    webd_query_get(query, "q", q, sizeof(q));
    webd_query_get(query, "category", category, sizeof(category));
    want_featured = webd_query_get(query, "featured", featbuf, sizeof(featbuf)) &&
                    (featbuf[0] == '1' || featbuf[0] == 't' || featbuf[0] == 'T');
    want_homepage = webd_query_get(query, "homepage", homebuf, sizeof(homebuf)) &&
                    (homebuf[0] == '1' || homebuf[0] == 't' || homebuf[0] == 'T');

    out = json_object_new_object();
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    webd_obj_add_str(out, "schema", "dwrt-appstore-catalog/1");

    caps = json_object_new_object();
    webd_obj_add_str(caps, "installer", "dapp-v1");
    json_object_object_add(caps, "refresh", json_object_new_boolean(1));
    json_object_object_add(caps, "update", json_object_new_boolean(1));
    json_object_object_add(caps, "rollback", json_object_new_boolean(1));
    json_object_object_add(out, "capabilities", caps);

    device = json_object_new_object();
    webd_obj_add_str(device, "arch", APPSTORE_DEVICE_ARCH);
    webd_obj_add_str(device, "target", APPSTORE_DEVICE_TARGET);
    json_object_object_add(device, "platformApi",
                           json_object_new_int(APPSTORE_PLATFORM_API));
    {
        const char *names[]={"app-service-v1","tun","app-network-policy-v1"};
        struct json_object *supported = json_object_new_array();
        struct json_object *statuses = json_object_new_object();
        for (size_t n=0;n<sizeof(names)/sizeof(names[0]);n++) {
            const char *reason="";
            int available=appstore_capability_available(names[n],&reason);
            if (available) json_object_array_add(supported,json_object_new_string(names[n]));
            struct json_object *status=json_object_new_object();
            json_object_object_add(status,"supported",json_object_new_boolean(available));
            webd_obj_add_str(status,"reason",reason);
            json_object_object_add(statuses,names[n],status);
        }
        json_object_object_add(device, "capabilities", supported);
        json_object_object_add(device, "capabilityStatus", statuses);
    }
    json_object_object_add(out, "device", device);

    catalog = appstore_load_catalog();
    idx = appstore_load_index();
    index = json_object_new_object();
    webd_obj_add_str(index, "source",
        catalog ? (runtime_present ? (idx ? "remote" : "cache") : "bundled") : "bundled");
    webd_obj_add_str(index, "channel",
        idx ? app_nc_json_str(idx, "channel", "")
            : (catalog ? app_nc_json_str(catalog, "channel", "") : ""));
    json_object_object_add(index, "revision", json_object_new_int64(
        idx ? app_nc_json_int64(idx, "revision", 0)
            : (catalog ? app_nc_json_int64(catalog, "revision", 0) : 0)));
    webd_obj_add_str(index, "fetchedAt", idx ? app_nc_json_str(idx, "fetchedAt", "") : "");
    {
        const char *expires = idx ? app_nc_json_str(idx, "expiresAt", "")
            : (catalog ? app_nc_json_str(catalog, "expiresAt", "") : "");
        int stale = 0;
        if (expires && expires[0]) {
            char now[40];
            appstore_now_iso(now, sizeof(now));
            stale = strcmp(now, expires) > 0; /* ISO-8601 Z sorts chronologically */
        }
        json_object_object_add(index, "stale",
            json_object_new_boolean(catalog ? stale : 0));
    }
    json_object_object_add(index, "lastError", NULL);
    if (idx)
        json_object_put(idx);
    json_object_object_add(out, "index", index);

    cats = json_object_new_array();
    if (catalog && json_object_object_get_ex(catalog, "categories", &list) && list &&
        json_object_is_type(list, json_type_array)) {
        n = json_object_array_length(list);
        for (i = 0; i < n; i++)
            json_object_array_add(cats,
                json_object_get(json_object_array_get_idx(list, i)));
    }
    json_object_object_add(out, "categories", cats);

    list = json_object_new_array();
    if (catalog && json_object_object_get_ex(catalog, "apps", &apps) && apps &&
        json_object_is_type(apps, json_type_array)) {
        n = json_object_array_length(apps);
        for (i = 0; i < n; i++) {
            struct json_object *app = json_object_array_get_idx(apps, i);
            const char *aid, *nm, *cat;
            if (!app)
                continue;
            aid = app_nc_json_str(app, "id", "");
            nm = app_nc_json_str(app, "name", "");
            cat = app_nc_json_str(app, "category", "");
            if (category[0] && strcmp(cat, category))
                continue;
            if (want_featured && !app_nc_json_bool(app, "featured", 0))
                continue;
            if (want_homepage && !app_nc_json_bool(app, "homepage", 0))
                continue;
            if (q[0] && !appstore_ci_contains(aid, q) && !appstore_ci_contains(nm, q))
                continue;
            json_object_array_add(list, appstore_catalog_entry(app));
        }
    }
    json_object_object_add(out, "apps", list);
    if (catalog)
        json_object_put(catalog);
    ctx->status = 200;
    return out;
}
/* GET /installed (§7.2). Truth source is the registry, so a delisted or
 * offline app still appears here. Enveloped. */
static struct json_object *appstore_installed(struct jmx_api_ctx *ctx)
{
    struct json_object *data, *apps = json_object_new_array();
    struct json_object *ids = json_object_new_array();
    DIR *d = opendir(APPSTORE_REGISTRY_DIR);
    int count = 0, catalog_available;
    struct dirent *de;

    if (d) {
        while ((de = readdir(d)) != NULL) {
            size_t nl = strlen(de->d_name);
            char id[80];
            struct json_object *reg, *e, *manifest = NULL, *launch = NULL;
            int port;

            if (nl <= 5 || strcmp(de->d_name + nl - 5, ".json"))
                continue;
            if (nl - 5 >= sizeof(id))
                continue;
            memcpy(id, de->d_name, nl - 5);
            id[nl - 5] = '\0';
            if (!appstore_id_valid(id))
                continue;
            reg = appstore_registry_load(id);
            if (!reg)
                continue;
            e = json_object_new_object();
            webd_obj_add_str(e, "id", id);
            webd_obj_add_str(e, "packageFormat", "dapp/1");
            webd_obj_add_str(e, "installStatus", "installed");
            webd_obj_add_str(e, "installedVersion", app_nc_json_str(reg, "version", ""));
            json_object_object_add(e, "installedBuild",
                json_object_new_int((int)app_nc_json_int64(reg, "build", 0)));
            webd_obj_add_str(e, "installedReleaseId",
                             app_nc_json_str(reg, "releaseId", ""));
            port = (int)app_nc_json_int64(reg, "port", 0);
            webd_obj_add_str(e, "runtimeState", appstore_runtime_state(port));
            if (json_object_object_get_ex(reg, "manifest", &manifest) && manifest &&
                json_object_object_get_ex(manifest, "launch", &launch) && launch)
                json_object_object_add(e, "launch", json_object_get(launch));
            else
                json_object_object_add(e, "launch", NULL);
            json_object_array_add(apps, e);
            json_object_array_add(ids, json_object_new_string(id));
            count++;
            json_object_put(reg);
        }
        closedir(d);
    }
    catalog_available = (access(APPSTORE_CATALOG_RUNTIME, R_OK) == 0) ||
                        (access(APPSTORE_CATALOG_PACKAGED, R_OK) == 0);
    data = json_object_new_object();
    json_object_object_add(data, "apps", apps);
    json_object_object_add(data, "installed", ids);
    json_object_object_add(data, "count", json_object_new_int(count));
    json_object_object_add(data, "catalog_available",
                           json_object_new_boolean(catalog_available));
    webd_obj_add_str(data, "truth_source", "app_registry");
    ctx->status = 200;
    return webd_envelope(data, "webd.appstore");
}
/* GET /apps/{id}/status (§7.2). Installed-but-delisted must not be a 404. */
static struct json_object *appstore_status_for(struct jmx_api_ctx *ctx,
                                               const char *id)
{
    struct json_object *reg, *catalog, *app = NULL, *data, *op;
    struct json_object *rel = NULL, *tgt = NULL, *m = NULL, *l = NULL;
    char task_id[80];
    int has_release;

    if (!appstore_id_valid(id)) {
        ctx->status = 400;
        return webd_error("invalid_app_id", "app id is not valid", "id", "webd.appstore");
    }
    reg = appstore_registry_load(id);
    catalog = appstore_load_catalog();
    if (catalog)
        app = appstore_find_app(catalog, id);
    if (!reg && !app) {
        if (catalog)
            json_object_put(catalog);
        ctx->status = 404;
        return webd_error("app_not_found", "no such app", "id", "webd.appstore");
    }
    has_release = app ? appstore_select_release(app, &rel, &tgt) : 0;

    data = json_object_new_object();
    webd_obj_add_str(data, "id", id);
    webd_obj_add_str(data, "packageFormat", "dapp/1");
    webd_obj_add_str(data, "installStatus", appstore_installstatus(id, reg));
    if (reg) {
        webd_obj_add_str(data, "installedVersion", app_nc_json_str(reg, "version", ""));
        json_object_object_add(data, "installedBuild",
            json_object_new_int((int)app_nc_json_int64(reg, "build", 0)));
        webd_obj_add_str(data, "installedReleaseId",
                         app_nc_json_str(reg, "releaseId", ""));
    } else {
        json_object_object_add(data, "installedVersion", NULL);
        json_object_object_add(data, "installedBuild", NULL);
        json_object_object_add(data, "installedReleaseId", NULL);
    }
    if (has_release) {
        int ab = (int)app_nc_json_int64(rel, "build", 0);
        int ib = reg ? (int)app_nc_json_int64(reg, "build", 0) : -1;
        webd_obj_add_str(data, "availableVersion", app_nc_json_str(rel, "version", ""));
        json_object_object_add(data, "updateAvailable",
            json_object_new_boolean(reg && ab > ib));
    } else {
        json_object_object_add(data, "availableVersion", NULL);
        json_object_object_add(data, "updateAvailable", json_object_new_boolean(0));
    }
    {
        const char *prevdir = reg ? app_nc_json_str(reg, "previousVersionDir", "") : "";
        json_object_object_add(data, "canRollback",
            json_object_new_boolean(prevdir && prevdir[0]));
        json_object_object_add(data, "previousVersion", NULL);
        json_object_object_add(data, "previousReleaseId", NULL);
    }
    webd_obj_add_str(data, "runtimeState",
        reg ? appstore_runtime_state((int)app_nc_json_int64(reg, "port", 0)) : "stopped");
    appstore_add_installability(data, has_release, rel, tgt,
                               (app && !reg) ? "architecture_unsupported" : "");
    json_object_object_add(data, "configSchema", appstore_config_schema(reg));
    if (reg && json_object_object_get_ex(reg, "manifest", &m) && m &&
        json_object_object_get_ex(m, "launch", &l) && l)
        json_object_object_add(data, "launch", json_object_get(l));
    else
        json_object_object_add(data, "launch", NULL);
    if (appstore_read_current_task(id, task_id, sizeof(task_id)) == 0 &&
        (op = appstore_operation_obj(task_id)) != NULL)
        json_object_object_add(data, "operation", op);
    else
        json_object_object_add(data, "operation", NULL);
    if (catalog)
        json_object_put(catalog);
    if (reg)
        json_object_put(reg);
    ctx->status = 200;
    return webd_envelope(data, "webd.appstore");
}
/* GET /tasks/{taskId} (§7.2). The operation object already carries appId,
 * targetReleaseId, startedAt and (when terminal) finishedAt/result. */
static struct json_object *appstore_task_get(struct jmx_api_ctx *ctx,
                                             const char *task_id)
{
    struct json_object *op;

    if (!appstore_task_id_valid(task_id)) {
        ctx->status = 404;
        return webd_error("task_not_found", "no such task", "taskId", "webd.appstore");
    }
    op = appstore_operation_obj(task_id);
    if (!op) {
        ctx->status = 404;
        return webd_error("task_not_found", "no such task", "taskId", "webd.appstore");
    }
    ctx->status = 200;
    return webd_envelope(op, "webd.appstore");
}

/* GET /ports/check?ports=53,8080 (§7.3). Enveloped. */
static struct json_object *appstore_ports_check(struct jmx_api_ctx *ctx)
{
    struct json_object *data, *arr = json_object_new_array();
    char raw[256] = "";
    const char *query = ctx->req ? ctx->req->query : "";
    char *p, *save = NULL, *tok;

    webd_query_get(query, "ports", raw, sizeof(raw));
    for (p = raw; (tok = strtok_r(p, ",", &save)) != NULL; p = NULL) {
        long v = strtol(tok, NULL, 10);
        struct json_object *e;
        if (v <= 0 || v > 65535)
            continue;
        e = json_object_new_object();
        json_object_object_add(e, "port", json_object_new_int((int)v));
        json_object_object_add(e, "inUse",
            json_object_new_boolean(appstore_port_in_use((unsigned)v, 1, 0) != 0));
        json_object_array_add(arr, e);
    }
    data = json_object_new_object();
    json_object_object_add(data, "ports", arr);
    ctx->status = 200;
    return webd_envelope(data, "webd.appstore");
}
/* POST /catalog/refresh (§7.1). Builds a catalog-refresh task from the UCI
 * source and hands it to the detached worker. Returns 202 {task_id}. */
static struct json_object *appstore_catalog_refresh(struct jmx_api_ctx *ctx)
{
    struct appstore_source source;
    struct json_object *spec, *src, *cat, *data;
    char task_id[48], rp[320];

    if (appstore_uci_source(&source) != 0) {
        ctx->status = 503;
        return webd_error("source_unreachable",
            "no app distributor configured; set dist_url in relay.appstore",
            "dist_url", "webd.appstore");
    }
    spec = json_object_new_object();
    webd_obj_add_str(spec, "schema", "dreamingos-appstore-task/1");
    webd_obj_add_str(spec, "op", "catalog-refresh");
    webd_obj_add_str(spec, "appId", "catalog"); /* worker requires a valid appId */
    webd_obj_add_str(spec, "trustPath", APPSTORE_TRUST);
    src = json_object_new_object();
    webd_obj_add_str(src, "baseUrl", source.dist_url);
    webd_obj_add_str(src, "caPath",
                     source.ca_path[0] ? source.ca_path : APPSTORE_CA_DEFAULT);
    json_object_object_add(spec, "source", src);
    cat = json_object_new_object();
    /* update-os fronts the dist-appstore API; catalog is served at
     * /v1/appstore/catalog?channel=X (+ .sig), not as a static file tree. */
    snprintf(rp, sizeof(rp), "v1/appstore/catalog?channel=%s", source.channel);
    webd_obj_add_str(cat, "path", rp);
    snprintf(rp, sizeof(rp), "v1/appstore/catalog.sig?channel=%s", source.channel);
    webd_obj_add_str(cat, "signature", rp);
    webd_obj_add_str(cat, "channel", source.channel);
    json_object_object_add(spec, "catalog", cat);
    if (appstore_accept_task(ctx, "catalog", "catalog-refresh", "", spec,
                             task_id, sizeof(task_id)) != 0) {
        ctx->status = 500;
        return webd_error("catalog_unavailable",
                          "could not accept the refresh task", "", "webd.appstore");
    }
    data = json_object_new_object();
    webd_obj_add_str(data, "task_id", task_id);
    ctx->status = 202;
    return webd_envelope(data, "webd.appstore");
}
/* 202 Accepted body: {id, task_id, operation}. */
static struct json_object *appstore_accepted(struct jmx_api_ctx *ctx,
                                             const char *id, const char *task_id)
{
    struct json_object *op = appstore_operation_obj(task_id);
    struct json_object *data = json_object_new_object();

    webd_obj_add_str(data, "id", id);
    webd_obj_add_str(data, "task_id", task_id);
    json_object_object_add(data, "operation", op ? op : NULL);
    ctx->status = 202;
    return webd_envelope(data, "webd.appstore");
}

/* 200 idempotent body: nothing to do (already in the requested state). */
static struct json_object *appstore_idempotent(struct jmx_api_ctx *ctx,
                                               const char *id)
{
    struct json_object *data = json_object_new_object();

    webd_obj_add_str(data, "id", id);
    json_object_object_add(data, "task_id", NULL);
    json_object_object_add(data, "operation", NULL);
    ctx->status = 200;
    return webd_envelope(data, "webd.appstore");
}
/* POST /apps/{id}/{install|update|uninstall|rollback} (§7.3). Resolves the
 * device-compatible release, builds a dreamingos-appstore-task/1 spec, and
 * hands it to the detached worker. All network/crypto/FS work is the worker's. */
static struct json_object *appstore_write_op(struct jmx_api_ctx *ctx,
                                             const char *id, const char *action)
{
    struct json_object *body = ctx->body;
    struct json_object *reg = NULL, *catalog = NULL, *app = NULL;
    struct json_object *rel = NULL, *tgt = NULL, *spec, *src, *artifact, *conf = NULL;
    struct appstore_source source;
    const char *sel_release_id, *artifact_id, *body_release_id;
    char task_id[48], rp[320];

    if (!appstore_id_valid(id)) {
        ctx->status = 400;
        return webd_error("invalid_app_id", "app id is not valid", "id", "webd.appstore");
    }
    if (appstore_app_busy(id)) {
        ctx->status = 409;
        return webd_error("app_busy", "another operation is in progress for this app",
                          "", "webd.appstore");
    }
    reg = appstore_registry_load(id);

    if (!strcmp(action, "network-policy")) {
        struct json_object *mf = NULL;
        if (reg) json_object_object_get_ex(reg, "manifest", &mf);
        if (!reg || !appstore_manifest_tun(mf)) {
            if (reg) json_object_put(reg); ctx->status = 422;
            return webd_error("network_unsupported", "installed app must declare tun", "", "webd.appstore");
        }
        if (body) json_object_object_get_ex(body, "policy", &conf);
        if (appstore_network_validate(conf)) {
            json_object_put(reg); ctx->status = 422;
            return webd_error("network_policy_invalid", "policy requires toHost/toLan/toWan/exitNode/snat booleans", "policy", "webd.appstore");
        }
        char revision[65]; struct json_object *current = appstore_network_policy_load(id, revision);
        if (!current) { json_object_put(reg); ctx->status = 503; return webd_error("network_policy_unavailable", "current policy cannot be read", "", "webd.appstore"); }
        json_object_put(current);
        if (strcmp(app_nc_json_str(body, "revision", ""), revision)) {
            json_object_put(reg); ctx->status = 409;
            return webd_error("network_policy_conflict", "read current network policy before saving", "revision", "webd.appstore");
        }
        spec = json_object_new_object();
        webd_obj_add_str(spec, "schema", "dreamingos-appstore-task/1");
        webd_obj_add_str(spec, "op", "network-policy"); webd_obj_add_str(spec, "appId", id);
        webd_obj_add_str(spec, "revision", revision); json_object_object_add(spec, "config", json_object_get(conf));
        int accepted = appstore_accept_task(ctx, id, action, "", spec, task_id, sizeof(task_id));
        json_object_put(reg);
        if (accepted) { ctx->status = 503; return webd_error("app_runtime_unavailable", "could not accept network task", "", "webd.appstore"); }
        return appstore_accepted(ctx, id, task_id);
    }

    if (!strcmp(action, "configure")) {
        char revision[65];
        struct json_object *current = reg ? appstore_current_config(id, revision) : NULL;
        if (!reg || !current) {
            if (reg) json_object_put(reg);
            ctx->status = reg ? 503 : 404;
            return webd_error("configuration_unavailable", "installed configuration unavailable", "", "webd.appstore");
        }
        json_object_put(current);
        if (!body || !json_object_object_get_ex(body, "configuration", &conf) || !json_object_is_type(conf, json_type_object)) {
            json_object_put(reg); ctx->status = 422;
            return webd_error("configuration_invalid", "configuration must be an object patch", "configuration", "webd.appstore");
        }
        if (strcmp(app_nc_json_str(body, "revision", ""), revision)) {
            json_object_put(reg); ctx->status = 409;
            return webd_error("configuration_conflict", "read current configuration before saving", "revision", "webd.appstore");
        }
        spec = json_object_new_object();
        webd_obj_add_str(spec, "schema", "dreamingos-appstore-task/1");
        webd_obj_add_str(spec, "op", "configure");
        webd_obj_add_str(spec, "appId", id);
        webd_obj_add_str(spec, "revision", revision);
        json_object_object_add(spec, "config", json_object_get(conf));
        int accepted = appstore_accept_task(ctx, id, action, "", spec, task_id, sizeof(task_id));
        json_object_put(reg);
        if (accepted != 0) { ctx->status = 503; return webd_error("app_runtime_unavailable", "could not accept task", "", "webd.appstore"); }
        return appstore_accepted(ctx, id, task_id);
    }

    if (!strcmp(action, "uninstall")) {
        if (!reg)
            return appstore_idempotent(ctx, id); /* already absent */
        spec = json_object_new_object();
        webd_obj_add_str(spec, "schema", "dreamingos-appstore-task/1");
        webd_obj_add_str(spec, "op", "uninstall");
        webd_obj_add_str(spec, "appId", id);
        webd_obj_add_str(spec, "trustPath", APPSTORE_TRUST);
        src = json_object_new_object();
        json_object_object_add(src, "retainData",
            json_object_new_boolean(app_nc_json_bool(body, "retainData", 1)));
        json_object_object_add(spec, "config", src);
        if (appstore_accept_task(ctx, id, "uninstall", app_nc_json_str(reg, "releaseId", ""),
                                 spec, task_id, sizeof(task_id)) != 0) {
            json_object_put(reg);
            ctx->status = 503;
            return webd_error("app_runtime_unavailable", "could not accept the task",
                              "", "webd.appstore");
        }
        json_object_put(reg);
        return appstore_accepted(ctx, id, task_id);
    }

    if (!strcmp(action, "rollback")) {
        const char *prev;
        if (!reg) {
            ctx->status = 404;
            return webd_error("app_not_found", "app is not installed", "id", "webd.appstore");
        }
        prev = app_nc_json_str(reg, "previousVersionDir", "");
        if (!prev || !prev[0]) {
            json_object_put(reg);
            ctx->status = 409;
            return webd_error("no_rollback_target", "no previous version to roll back to",
                              "", "webd.appstore");
        }
        spec = json_object_new_object();
        webd_obj_add_str(spec, "schema", "dreamingos-appstore-task/1");
        webd_obj_add_str(spec, "op", "rollback");
        webd_obj_add_str(spec, "appId", id);
        webd_obj_add_str(spec, "trustPath", APPSTORE_TRUST);
        if (appstore_accept_task(ctx, id, "rollback", "", spec, task_id, sizeof(task_id)) != 0) {
            json_object_put(reg);
            ctx->status = 503;
            return webd_error("app_runtime_unavailable", "could not accept the task",
                              "", "webd.appstore");
        }
        json_object_put(reg);
        return appstore_accepted(ctx, id, task_id);
    }
    if (strcmp(action, "install") && strcmp(action, "update")) {
        if (reg)
            json_object_put(reg);
        ctx->status = 404;
        return webd_error("app_not_found", "unknown action", "action", "webd.appstore");
    }
    catalog = appstore_load_catalog();
    if (catalog)
        app = appstore_find_app(catalog, id);
    if (!app) {
        if (reg)
            json_object_put(reg);
        if (catalog)
            json_object_put(catalog);
        ctx->status = 404;
        return webd_error("app_not_found", "no such app in catalog", "id", "webd.appstore");
    }
    if (!appstore_select_release(app, &rel, &tgt)) {
        if (reg)
            json_object_put(reg);
        json_object_put(catalog);
        ctx->status = 422;
        return webd_error("architecture_unsupported",
                          "no release matches this device", "", "webd.appstore");
    }
    {
        char missing[65]; const char *reason = "";
        int rc = appstore_release_requirements(tgt, missing, &reason);
        if (rc) {
            char message[160];
            snprintf(message, sizeof(message), "required capability unavailable: %s (%s)", missing, reason);
            if (reg) json_object_put(reg);
            json_object_put(catalog);
            ctx->status = 422;
            return webd_error(rc < 0 ? "requirements_invalid" : "capability_unavailable",
                              message, "requires.capabilities", "webd.appstore");
        }
    }
    sel_release_id = app_nc_json_str(rel, "releaseId", "");
    artifact_id = app_nc_json_str(tgt, "artifactId", "");
    if (!artifact_id[0]) {
        if (reg)
            json_object_put(reg);
        json_object_put(catalog);
        ctx->status = 422;
        return webd_error("manifest_invalid",
                          "catalog release has no artifactId", "", "webd.appstore");
    }
    body_release_id = app_nc_json_str(body, "releaseId", "");
    if (body_release_id[0] && strcmp(body_release_id, sel_release_id)) {
        if (reg)
            json_object_put(reg);
        json_object_put(catalog);
        ctx->status = 409;
        return webd_error("release_changed", "the selected release is no longer current",
                          "releaseId", "webd.appstore");
    }
    if (!strcmp(action, "install") && reg &&
        !strcmp(app_nc_json_str(reg, "releaseId", ""), sel_release_id)) {
        json_object_put(reg);
        json_object_put(catalog);
        return appstore_idempotent(ctx, id); /* same release already installed */
    }
    if (appstore_uci_source(&source) != 0) {
        if (reg)
            json_object_put(reg);
        json_object_put(catalog);
        ctx->status = 503;
        return webd_error("source_unreachable",
            "no app distributor configured; set dist_url in relay.appstore",
            "dist_url", "webd.appstore");
    }
    spec = json_object_new_object();
    webd_obj_add_str(spec, "schema", "dreamingos-appstore-task/1");
    webd_obj_add_str(spec, "op", action);
    webd_obj_add_str(spec, "appId", id);
    webd_obj_add_str(spec, "releaseId", sel_release_id);
    webd_obj_add_str(spec, "version", app_nc_json_str(rel, "version", ""));
    json_object_object_add(spec, "build",
        json_object_new_int((int)app_nc_json_int64(rel, "build", 0)));
    webd_obj_add_str(spec, "target", APPSTORE_DEVICE_TARGET);
    webd_obj_add_str(spec, "expectedSha256", app_nc_json_str(tgt, "descriptorSha256", ""));
    webd_obj_add_str(spec, "trustPath", APPSTORE_TRUST);
    src = json_object_new_object();
    webd_obj_add_str(src, "baseUrl", source.dist_url);
    webd_obj_add_str(src, "caPath",
                     source.ca_path[0] ? source.ca_path : APPSTORE_CA_DEFAULT);
    json_object_object_add(spec, "source", src);
    artifact = json_object_new_object();
    /* dist-appstore API: descriptor at artifact/{id}.release, its sig at
     * artifact/{id}.release.sig, bundle at artifact/{id}. */
    snprintf(rp, sizeof(rp), "v1/appstore/artifact/%s.release", artifact_id);
    webd_obj_add_str(artifact, "release", rp);
    snprintf(rp, sizeof(rp), "v1/appstore/artifact/%s.release.sig", artifact_id);
    webd_obj_add_str(artifact, "signature", rp);
    snprintf(rp, sizeof(rp), "v1/appstore/artifact/%s", artifact_id);
    webd_obj_add_str(artifact, "bundle", rp);
    json_object_object_add(spec, "artifact", artifact);
    if (body && json_object_object_get_ex(body, "configuration", &conf) && conf)
        json_object_object_add(spec, "config", json_object_get(conf));
    if (appstore_accept_task(ctx, id, action, sel_release_id, spec,
                             task_id, sizeof(task_id)) != 0) {
        if (reg)
            json_object_put(reg);
        json_object_put(catalog);
        ctx->status = 503;
        return webd_error("app_runtime_unavailable", "could not accept the task",
                          "", "webd.appstore");
    }
    if (reg)
        json_object_put(reg);
    json_object_put(catalog);
    return appstore_accepted(ctx, id, task_id);
}
struct appstore_web_buffer { char *data; size_t size; };
static size_t appstore_web_write(char *p, size_t size, size_t count, void *opaque)
{
    struct appstore_web_buffer *b = opaque;
    if (size && count > (2U * 1024U * 1024U - b->size) / size) return 0;
    size_t n = size * count;
    char *next = realloc(b->data, b->size + n + 1);
    if (!next) return 0;
    b->data = next;
    memcpy(b->data + b->size, p, n);
    b->size += n;
    b->data[b->size] = 0;
    return n;
}

#include "api_appstore_ws.inc"

/* Only signed installed apps opting into this exact route can use the local
 * Unix-socket bridge. Never forward browser-supplied identity headers/tokens. */
static struct json_object *appstore_web_proxy(struct jmx_api_ctx *ctx,
                                              const char *id, const char *suffix)
{
    struct json_object *reg = NULL, *mf = NULL, *launch = NULL;
    char route[160], socket_path[108], url[1200], actor[320], role[96];
    struct appstore_web_buffer output = {0};
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    long code = 0;
    char *type = NULL;
    const char *method = ctx->req->method;
    if (!appstore_id_valid(id) || !ctx->device_id || !ctx->authenticated_role ||
        strpbrk(ctx->device_id, "\r\n") || strpbrk(ctx->authenticated_role, "\r\n")) {
        ctx->status = 400;
        return webd_error("invalid_app_id", "invalid application identity", "", "webd.appstore");
    }
    if (strcmp(method, "GET") && strcmp(method, "HEAD") && strcmp(method, "POST")) {
        ctx->status = 405;
        return webd_error("method_not_allowed", "use GET, HEAD or POST", "", "webd.appstore");
    }
    reg = appstore_registry_load(id);
    if (!reg) {
        ctx->status = 404;
        return webd_error("app_not_installed", "application is not installed", "", "webd.appstore");
    }
    snprintf(route, sizeof(route), "/api/v1/appstore/apps/%s/web/", id);
    json_object_object_get_ex(reg, "manifest", &mf);
    if (mf) json_object_object_get_ex(mf, "launch", &launch);
    int allowed = launch && !strcmp(app_nc_json_str(launch, "kind", ""), "web") &&
                  !strcmp(app_nc_json_str(launch, "route", ""), route);
    json_object_put(reg);
    if (!allowed) {
        ctx->status = 409;
        return webd_error("app_launch_unavailable", "application has no authenticated web launch", "", "webd.appstore");
    }
    if (snprintf(socket_path, sizeof(socket_path), "/run/dreamingos-appstore/%s/api.sock", id) >= (int)sizeof(socket_path) ||
        snprintf(url, sizeof(url), "http://localhost/%s%s%s", suffix,
                 ctx->req->query[0] ? "?" : "", ctx->req->query) >= (int)sizeof(url) ||
        snprintf(actor, sizeof(actor), "X-DreamingOS-Actor: %s", ctx->device_id) >= (int)sizeof(actor) ||
        snprintf(role, sizeof(role), "X-DreamingOS-Role: %s", ctx->authenticated_role) >= (int)sizeof(role)) {
        ctx->status = 422;
        return webd_error("app_request_too_large", "request exceeds application gateway limits", "", "webd.appstore");
    }
    struct stat st;
    if (lstat(socket_path, &st) || !S_ISSOCK(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0077)) {
        ctx->status = 503;
        return webd_error("app_service_unavailable", "application service is stopped or unavailable", "", "webd.appstore");
    }
    if (ctx->req->websocket) return appstore_web_ws(ctx, id, suffix, socket_path, &st);
    curl = curl_easy_init();
    if (!curl) goto unavailable;
    headers = curl_slist_append(headers, actor);
    headers = curl_slist_append(headers, role);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, socket_path);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, appstore_web_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);
    if (!strcmp(method, "HEAD")) curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    if (!strcmp(method, "POST")) {
        const char *body = ctx->body ? json_object_to_json_string_ext(ctx->body, JSON_C_TO_STRING_PLAIN) : "{}";
        if (strlen(body) > 65536) { ctx->status = 422; goto unavailable; }
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }
    if (curl_easy_perform(curl) != CURLE_OK) goto unavailable;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &type);
    if (code < 200 || code > 599) goto unavailable;
    http_send_raw(ctx->fd, (int)code, type ? type : "application/octet-stream",
                  output.data ? output.data : "", output.size, "no-store");
    ctx->status = (int)code;
    free(output.data); curl_slist_free_all(headers); curl_easy_cleanup(curl);
    return NULL;
unavailable:
    free(output.data); curl_slist_free_all(headers); if (curl) curl_easy_cleanup(curl);
    if (ctx->status != 422) ctx->status = 503;
    return webd_error("app_service_unavailable", "application service did not complete the request", "", "webd.appstore");
}

/* PREFIX dispatcher for /api/v1/appstore/apps/{id}/{action}. */
static struct json_object *appstore_apps_dispatch(struct jmx_api_ctx *ctx)
{
    static const char *prefix = "/api/v1/appstore/apps/";
    const char *path = ctx->req->path;
    const char *method = ctx->req->method;
    const char *rest, *slash, *action;
    char id[80];
    size_t plen = strlen(prefix), idlen;

    if (strncmp(path, prefix, plen)) {
        ctx->status = 404;
        return webd_error("app_not_found", "not found", "", "webd.appstore");
    }
    rest = path + plen;
    slash = strchr(rest, '/');
    if (!slash) {
        ctx->status = 404;
        return webd_error("app_not_found", "missing action", "", "webd.appstore");
    }
    idlen = (size_t)(slash - rest);
    if (idlen == 0 || idlen >= sizeof(id)) {
        ctx->status = 400;
        return webd_error("invalid_app_id", "app id is not valid", "id", "webd.appstore");
    }
    memcpy(id, rest, idlen);
    id[idlen] = '\0';
    action = slash + 1;

    if (!strncmp(action, "web/", 4))
        return appstore_web_proxy(ctx, id, action + 4);

    if (!strcmp(action, "configuration")) {
        if (strcmp(method, "GET") && strcmp(method, "HEAD")) { ctx->status = 405; return webd_error("method_not_allowed", "use GET", "", "webd.appstore"); }
        return appstore_configuration(ctx, id);
    }
    if (!strcmp(action, "network-policy") && (!strcmp(method, "GET") || !strcmp(method, "HEAD")))
        return appstore_network_policy_get(ctx, id);
    if (!strcmp(action, "status")) {
        if (strcmp(method, "GET") && strcmp(method, "HEAD")) {
            ctx->status = 405;
            return webd_error("method_not_allowed", "use GET", "", "webd.appstore");
        }
        return appstore_status_for(ctx, id);
    }
    if (!strcmp(action, "install-stream")) {
        ctx->status = 501;
        return webd_error("not_implemented", "install-stream (SSE) is not implemented",
                          "", "webd.appstore");
    }
    if (!strcmp(action, "install") || !strcmp(action, "update") ||
        !strcmp(action, "uninstall") || !strcmp(action, "rollback") || !strcmp(action, "configure") || !strcmp(action, "network-policy")) {
        if (strcmp(method, "POST")) {
            ctx->status = 405;
            return webd_error("method_not_allowed", "use POST", "", "webd.appstore");
        }
        struct json_object *reply = appstore_write_op(ctx, id, action);
        char audit_action[64];
        snprintf(audit_action, sizeof(audit_action), "appstore.%s", action);
        jmx_app_audit_log_response(ctx->device_id, ctx->device_id, audit_action,
                                  "medium", id, ctx->req->client_ip, reply, ctx->status);
        return reply;
    }
    ctx->status = 404;
    return webd_error("app_not_found", "unknown action", "", "webd.appstore");
}
/* PREFIX dispatcher for /api/v1/appstore/tasks/{taskId}. */
static struct json_object *appstore_tasks_dispatch(struct jmx_api_ctx *ctx)
{
    static const char *prefix = "/api/v1/appstore/tasks/";
    const char *path = ctx->req->path;
    const char *rest;
    size_t plen = strlen(prefix);

    if (strncmp(path, prefix, plen)) {
        ctx->status = 404;
        return webd_error("task_not_found", "not found", "", "webd.appstore");
    }
    rest = path + plen;
    if (!rest[0] || strchr(rest, '/')) {
        ctx->status = 404;
        return webd_error("task_not_found", "no such task", "taskId", "webd.appstore");
    }
    return appstore_task_get(ctx, rest);
}

/*
 * Route table (registered in api_router.c g_route_tables[]).
 *
 * original_seq values reuse the five slots the pre-worker apk/opkg surface held
 * (916-920) plus two new slots (955/956) so the merged route-inventory fixture
 * stays position-stable. Runtime dispatch is first-match; the paths are
 * mutually exclusive prefixes, so table order is safe. All rows are post-auth:
 * GET reads default to LOW risk, the POST /apps/ writes hit the MEDIUM row in
 * jmx_app_perms.c, and POST /catalog/refresh falls to the MEDIUM write default.
 */
const struct jmx_api_route appstore_api_routes[] = {
    JMX_API_ROUTE(916, "/api/v1/appstore/catalog",         "GET,HEAD", JMX_API_EXACT,  appstore_catalog),
    JMX_API_ROUTE(917, "/api/v1/appstore/apps",            "GET,HEAD", JMX_API_EXACT,  appstore_catalog),
    JMX_API_ROUTE(918, "/api/v1/appstore/installed",       "GET,HEAD", JMX_API_EXACT,  appstore_installed),
    JMX_API_ROUTE(919, "/api/v1/appstore/ports/check",     "GET,HEAD", JMX_API_EXACT,  appstore_ports_check),
    JMX_API_ROUTE(955, "/api/v1/appstore/catalog/refresh", "POST",     JMX_API_EXACT,  appstore_catalog_refresh),
    JMX_API_ROUTE(956, "/api/v1/appstore/tasks/",          "GET,HEAD", JMX_API_PREFIX, appstore_tasks_dispatch),
    JMX_API_ROUTE(920, "/api/v1/appstore/apps/",           "",         JMX_API_PREFIX | JMX_API_RAW_FD, appstore_apps_dispatch),
    JMX_API_ROUTE_END,
};
