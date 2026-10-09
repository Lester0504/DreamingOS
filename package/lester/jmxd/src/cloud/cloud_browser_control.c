// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cloud_internal.h"
#include "cloud_browser.h"
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

#define JOBS_MAX 16
#define JOB_PATH CLOUD_STATE_DIR "/web-jobs.json"
#define PREFLIGHT_TTL 120

static struct {
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t thread;
    int started, stop, pending;
    struct json_object *jobs, *active, *preflight;
    char preflight_id[33], preflight_actor[257], preflight_revision[65];
    int64_t preflight_until;
} control = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .wake = PTHREAD_COND_INITIALIZER
};

static const char *string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_string))
        return "";
    const char *s = json_object_get_string(v);
    return strlen(s) == (size_t)json_object_get_string_len(v) ? s : "";
}

static int boolean(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_boolean) &&
           json_object_get_boolean(v);
}

static void text(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, value && value[0] ? json_object_new_string(value) : NULL);
}

static struct json_object *copy(struct json_object *o)
{
    return o ? json_tokener_parse(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN)) : NULL;
}

static struct json_object *reply(int status, const char *error, struct json_object *data)
{
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "ok", json_object_new_boolean(status < 400));
    json_object_object_add(r, "http_status", json_object_new_int(status));
    if (error) {
        text(r, "code", error);
        text(r, "message", error);
    }
    if (data) json_object_object_add(r, "data", data);
    return r;
}

/* No preflight token survives a restart. Jobs do, including interrupted jobs. */
static int save_jobs(void)
{
    char path[] = JOB_PATH ".XXXXXX";
    const char *json = json_object_to_json_string_ext(control.jobs, JSON_C_TO_STRING_PLAIN);
    int fd = mkstemp(path), rc = -1;
    if (fd < 0) return -1;
    size_t offset = 0, length = strlen(json);
    while (offset < length) {
        ssize_t n = write(fd, json + offset, length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        offset += (size_t)n;
    }
    if (fsync(fd) || rename(path, JOB_PATH)) goto done;
    rc = 0;
done:
    close(fd);
    if (rc) unlink(path);
    return rc;
}

static int hash_file(EVP_MD_CTX *ctx, const char *path, int required)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    struct stat st;
    unsigned char bytes[4096];
    if (EVP_DigestUpdate(ctx, path, strlen(path) + 1) != 1) {
        if (fd >= 0) close(fd);
        return -1;
    }
    if (fd < 0)
        return !required && errno == ENOENT &&
               EVP_DigestUpdate(ctx, "missing", 7) == 1 ? 0 : -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 262144) {
        close(fd);
        return -1;
    }
    ssize_t n;
    size_t total = 0;
    while ((n = read(fd, bytes, sizeof(bytes))) > 0) {
        total += (size_t)n;
        if (total > 262144 || EVP_DigestUpdate(ctx, bytes, (size_t)n) != 1) {
            close(fd);
            return -1;
        }
    }
    close(fd);
    return n < 0 ? -1 : 0;
}

static int revision(char out[65])
{
    static const char *paths[] = {
        CLOUD_BROWSER_CONFIG_DIR "/cloud_web", CLOUD_BROWSER_CONFIG_DIR "/system",
        CLOUD_BROWSER_CONFIG_DIR "/dhcp", CLOUD_BROWSER_CONFIG_DIR "/relay",
        "/etc/hosts", CLOUD_BROWSER_CERT, "/etc/dreamingwrt/passkeys/config.json"
    };
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[32];
    unsigned int n = 0;
    int rc = -1;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        if (hash_file(ctx, paths[i], i == 0)) goto done;
    struct cwc_config config;
    int enabled;
    if (!cloud_browser_load(&config, &enabled, 1)) {
        EVP_PKEY_free(config.sign_key);
        if (config.ca_path[0] && hash_file(ctx, config.ca_path, 1)) goto done;
        for (int i = 0; i < config.n_services; ++i)
            if (config.services[i].ca_path[0] &&
                hash_file(ctx, config.services[i].ca_path, 1)) goto done;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &n) != 1 || n != 32) goto done;
    for (int i = 0; i < 32; ++i) snprintf(out + 2 * i, 3, "%02x", digest[i]);
    rc = 0;
done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int set_enabled(int enabled)
{
    struct uci_context *u = uci_alloc_context();
    struct uci_package *p = NULL;
    struct uci_section *main = NULL;
    struct uci_element *e;
    int rc = -1;
    if (!u) return -1;
    uci_set_confdir(u, CLOUD_BROWSER_CONFIG_DIR);
    if (uci_load(u, "cloud_web", &p)) goto done;
    uci_foreach_element(&p->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (strcmp(s->type, "browser")) continue;
        if (main) goto done;
        main = s;
    }
    if (!main) goto done;
    struct uci_ptr ptr = {.p = p, .s = main, .option = "enabled",
                          .value = enabled ? "1" : "0"};
    if (uci_set(u, &ptr) || uci_commit(u, &p, false)) goto done;
    cloud_browser_configured(enabled);
    rc = 0;
done:
    uci_free_context(u);
    return rc;
}

static void finish(const char *state, const char *error, struct json_object *result)
{
    pthread_mutex_lock(&control.lock);
    text(control.active, "state", state);
    text(control.active, "error", error);
    json_object_object_add(control.active, "updated_at", json_object_new_int64(cloud_now_s()));
    if (result) json_object_object_add(control.active, "result", result);
    if (save_jobs()) text(control.active, "persistence_error", "job_persist_failed");
    control.pending = 0;
    pthread_mutex_unlock(&control.lock);
}

static int stopping(void)
{
    pthread_mutex_lock(&control.lock);
    int stop = control.stop;
    pthread_mutex_unlock(&control.lock);
    return stop;
}

static void wait_transport(const char *expected, struct json_object *result)
{
    char applied[65] = "";
    (void)revision(applied);
    pthread_mutex_lock(&control.lock);
    text(control.active, "await_state", expected);
    text(control.active, "applied_revision", applied);
    pthread_mutex_unlock(&control.lock);
    for (int i = 0; i < 200 && !stopping(); ++i) {
        struct json_object *status = cloud_browser_status_json();
        int done = !strcmp(string(status, "state"), expected);
        int failed = !strcmp(string(status, "state"), "error");
        if (done || failed) {
            char error[160];
            snprintf(error, sizeof(error), "%s", failed ? string(status, "last_error") : "");
            if (result) json_object_object_add(result, "transport", status);
            finish(done ? "succeeded" : "failed", error, result ? result : status);
            return;
        }
        json_object_put(status);
        usleep(100000);
    }
    struct json_object *status = cloud_browser_status_json();
    if (result) json_object_object_add(result, "transport", status);
    finish("partial", !strcmp(expected, "disabled") ? "cloud_revocation_pending" :
           "connection_pending", result ? result : status);
}

static void run_job(void)
{
    char action[16], actor[257], id[33], before[65], after[65];
    pthread_mutex_lock(&control.lock);
    snprintf(action, sizeof(action), "%s", string(control.active, "action"));
    snprintf(actor, sizeof(actor), "%s", string(control.active, "actor"));
    snprintf(id, sizeof(id), "%s", string(control.active, "job_id"));
    snprintf(before, sizeof(before), "%s", string(control.active, "revision"));
    text(control.active, "state", "running");
    (void)save_jobs();
    pthread_mutex_unlock(&control.lock);

    if (!strncmp(action, "service_", 8)) {
        if (revision(after) || strcmp(before, after)) {
            finish("failed", "revision_conflict", NULL);
            return;
        }
        pthread_mutex_lock(&control.lock);
        struct json_object *request = NULL;
        json_object_object_get_ex(control.active, "request", &request);
        request = copy(request);
        pthread_mutex_unlock(&control.lock);
        struct json_object *response = cloud_browser_services(action, request), *data = NULL;
        json_object_put(request);
        json_object_object_get_ex(response, "data", &data);
        if (!boolean(response, "ok")) {
            finish("failed", string(response, "code"), data ? json_object_get(data) : NULL);
            json_object_put(response);
            return;
        }
        data = data ? json_object_get(data) : json_object_new_object();
        int reload = boolean(data, "reload");
        json_object_object_del(data, "reload");
        (void)revision(after);
        text(data, "revision", after);
        json_object_put(response);
        struct json_object *status = cloud_browser_status_json();
        int enabled = boolean(status, "configured_enabled");
        json_object_put(status);
        if (reload && enabled) {
            cloud_browser_transport_stop();
            cloud_browser_transport_start();
            wait_transport("connected", data);
        } else {
            finish("succeeded", "", data);
        }
        return;
    }
    if (!strcmp(action, "preflight")) {
        struct cwc_config config;
        int enabled;
        if (cloud_browser_load(&config, &enabled, 1)) {
            finish("failed", "browser_config_invalid", NULL);
            return;
        }
        struct json_object *result = cloud_browser_preflight(&config);
        EVP_PKEY_free(config.sign_key);
        int valid = result && !revision(after) && !strcmp(before, after);
        int allowed = valid && boolean(result, "enable_allowed");
        json_object_object_add(result, "expires_at",
            json_object_new_int64(cloud_now_s() + PREFLIGHT_TTL));
        text(result, "revision", before);
        if (allowed) {
            pthread_mutex_lock(&control.lock);
            if (control.preflight) json_object_put(control.preflight);
            control.preflight = copy(result);
            snprintf(control.preflight_id, sizeof(control.preflight_id), "%s", id);
            snprintf(control.preflight_actor, sizeof(control.preflight_actor), "%s", actor);
            snprintf(control.preflight_revision, sizeof(control.preflight_revision), "%s", before);
            control.preflight_until = cloud_monotonic_ms() + PREFLIGHT_TTL * 1000;
            pthread_mutex_unlock(&control.lock);
        }
        finish(allowed ? "succeeded" : "failed",
               !valid ? "preflight_stale" : allowed ? "" : "preflight_failed", result);
        return;
    }
    if (!strcmp(action, "enable")) {
        struct cwc_config config;
        struct cwc_publication publication;
        int enabled;
        if (cloud_browser_load(&config, &enabled, 1)) {
            finish("failed", "browser_config_invalid", NULL);
            return;
        }
        int rc = cwc_publication_read(&config, &publication);
        EVP_PKEY_free(config.sign_key);
        pthread_mutex_lock(&control.lock);
        struct json_object *generation = NULL, *cloud_revision = NULL;
        json_object_object_get_ex(control.preflight, "generation", &generation);
        json_object_object_get_ex(control.preflight, "cloud_revision", &cloud_revision);
        int valid = !rc && control.preflight_until > cloud_monotonic_ms() &&
            json_object_get_int64(generation) == publication.generation &&
            json_object_get_int64(cloud_revision) == publication.revision;
        pthread_mutex_unlock(&control.lock);
        if (!valid || revision(after) || strcmp(before, after)) {
            finish("failed", rc ? publication.error : "preflight_stale", NULL);
            return;
        }
    }
    if (strcmp(action, "reconnect") && set_enabled(!strcmp(action, "enable"))) {
        finish("failed", "config_write_failed", NULL);
        return;
    }
    /* Only this controller joins the transport thread, never the ubus loop. */
    cloud_browser_transport_stop();
    cloud_browser_transport_start();
    wait_transport(!strcmp(action, "disable") ? "disabled" : "connected", NULL);
}

static void *worker(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&control.lock);
    while (!control.stop) {
        while (!control.stop && !control.pending) pthread_cond_wait(&control.wake, &control.lock);
        if (control.stop) break;
        pthread_mutex_unlock(&control.lock);
        run_job();
        pthread_mutex_lock(&control.lock);
    }
    pthread_mutex_unlock(&control.lock);
    return NULL;
}

void cloud_browser_control_start(void)
{
    pthread_mutex_lock(&control.lock);
    struct stat st;
    if (!stat(JOB_PATH, &st) && S_ISREG(st.st_mode) && st.st_size <= 262144)
        control.jobs = json_object_from_file(JOB_PATH);
    if (!json_object_is_type(control.jobs, json_type_array) ||
        json_object_array_length(control.jobs) > JOBS_MAX) {
        if (control.jobs) json_object_put(control.jobs);
        control.jobs = json_object_new_array();
    }
    for (size_t i = 0; i < json_object_array_length(control.jobs); ++i) {
        struct json_object *job = json_object_array_get_idx(control.jobs, i);
        if (!strcmp(string(job, "state"), "queued") || !strcmp(string(job, "state"), "running")) {
            text(job, "state", "partial");
            text(job, "error", "daemon_restarted");
        }
    }
    control.stop = control.pending = 0;
    control.started = pthread_create(&control.thread, NULL, worker, NULL) == 0;
    pthread_mutex_unlock(&control.lock);
}

void cloud_browser_control_stop(void)
{
    pthread_mutex_lock(&control.lock);
    control.stop = 1;
    pthread_cond_signal(&control.wake);
    pthread_mutex_unlock(&control.lock);
    if (control.started) pthread_join(control.thread, NULL);
    control.started = 0;
    if (control.jobs) json_object_put(control.jobs);
    if (control.preflight) json_object_put(control.preflight);
    control.jobs = control.active = control.preflight = NULL;
    control.preflight_id[0] = 0;
}

struct json_object *cloud_browser_control(const char *action, const char *actor,
                                          struct json_object *request)
{
    if (!action || !actor || !actor[0] || strlen(actor) > 256)
        return reply(422, "invalid_request", NULL);
    char current[65] = "";
    (void)revision(current);
    struct json_object *status = cloud_browser_status_json();
    if (!strcmp(action, "status")) {
        text(status, "config_revision", current);
        json_object_object_add(status, "service_crud", json_object_new_boolean(1));
        json_object_object_add(status, "effective_enabled", json_object_new_boolean(
            boolean(status, "configured_enabled") && !strcmp(string(status, "state"), "connected")));
        json_object_object_add(status, "ready", json_object_new_boolean(0));
        text(status, "readiness_reason", "public_browser_path_not_verified");
        pthread_mutex_lock(&control.lock);
        if (control.active) text(status, "last_job_id", string(control.active, "job_id"));
        pthread_mutex_unlock(&control.lock);
        return reply(200, NULL, status);
    }
    int enabled = boolean(status, "configured_enabled");
    const char *transport_state = string(status, "state");
    pthread_mutex_lock(&control.lock);
    /* A background retry can complete after the initiating HTTP job timed out. */
    if (control.active && !control.pending &&
        !strcmp(string(control.active, "state"), "partial") &&
        (!strcmp(string(control.active, "error"), "connection_pending") ||
         !strcmp(string(control.active, "error"), "cloud_revocation_pending")) &&
        !strcmp(string(control.active, "await_state"), transport_state) &&
        current[0] && !strcmp(string(control.active, "applied_revision"), current)) {
        text(control.active, "state", "succeeded");
        text(control.active, "error", "");
        struct json_object *result = NULL;
        if (!strncmp(string(control.active, "action"), "service_", 8) &&
            json_object_object_get_ex(control.active, "result", &result))
            json_object_object_add(result, "transport", copy(status));
        else
            json_object_object_add(control.active, "result", copy(status));
        json_object_object_add(control.active, "updated_at", json_object_new_int64(cloud_now_s()));
        (void)save_jobs();
    }
    json_object_put(status);
    struct json_object *response = NULL;
    if (!strcmp(action, "job")) {
        const char *id = string(request, "job_id");
        for (size_t i = 0; control.jobs && i < json_object_array_length(control.jobs); ++i) {
            struct json_object *job = json_object_array_get_idx(control.jobs, i);
            if (!strcmp(id, string(job, "job_id")) && !strcmp(actor, string(job, "actor"))) {
                struct json_object *data = copy(job);
                json_object_object_del(data, "actor");
                json_object_object_del(data, "request");
                response = reply(200, NULL, data);
                break;
            }
        }
        if (!response) response = reply(404, "not_found", NULL);
        goto done;
    }
    if (!strcmp(action, "services")) {
        response = cloud_browser_services(action, request);
        struct json_object *data = NULL;
        char after[65] = "";
        if (revision(after) || strcmp(current, after)) {
            json_object_put(response);
            response = reply(409, "revision_conflict", NULL);
        } else if (json_object_object_get_ex(response, "data", &data)) {
            text(data, "revision", current);
        }
        goto done;
    }
    int service = !strcmp(action, "service_create") || !strcmp(action, "service_update") ||
                  !strcmp(action, "service_delete") || !strcmp(action, "service_probe");
    if (strcmp(action, "preflight") && strcmp(action, "enable") &&
        strcmp(action, "disable") && strcmp(action, "reconnect") && !service) {
        response = reply(404, "not_found", NULL);
        goto done;
    }
    if (!control.started || control.stop) {
        response = reply(503, "browser_control_unavailable", NULL);
        goto done;
    }
    if (control.pending) {
        response = reply(409, "job_in_progress", NULL);
        goto done;
    }
    if (service) {
        if (revision(current) || !current[0] || strcmp(string(request, "revision"), current)) {
            response = reply(409, "revision_conflict", NULL);
            goto done;
        }
        if (!strcmp(action, "service_create")) {
            response = cloud_browser_services(action, request);
            struct json_object *data = NULL;
            if (boolean(response, "ok") && json_object_object_get_ex(response, "data", &data)) {
                control.preflight_id[0] = 0;
                json_object_object_del(data, "reload");
                (void)revision(current);
                text(data, "revision", current);
            }
            goto done;
        }
    }
    if ((!strcmp(action, "enable") || !strcmp(action, "disable")) &&
        !boolean(request, "confirm")) {
        response = reply(409, "requires_confirm", NULL);
        goto done;
    }
    if (!strcmp(action, "enable")) {
        if (!control.preflight || !control.preflight_id[0] ||
            strcmp(string(request, "preflight_id"), control.preflight_id) ||
            strcmp(actor, control.preflight_actor) ||
            cloud_monotonic_ms() >= control.preflight_until ||
            !current[0] || strcmp(current, control.preflight_revision)) {
            response = reply(409, "preflight_stale", NULL);
            goto done;
        }
        if (boolean(control.preflight, "legacy_hostname") && !boolean(request, "legacy_hostname_ack")) {
            response = reply(409, "legacy_hostname_confirmation_required", NULL);
            goto done;
        }
    }
    if (!strcmp(action, "reconnect") && !enabled) {
        response = reply(409, "browser_disabled", NULL);
        goto done;
    }
    if (!strcmp(action, "preflight") && !current[0]) {
        response = reply(409, "browser_config_invalid", NULL);
        goto done;
    }
    unsigned char random[16];
    char id[33];
    if (RAND_bytes(random, sizeof(random)) != 1) {
        response = reply(503, "random_unavailable", NULL);
        goto done;
    }
    for (int i = 0; i < 16; ++i) snprintf(id + i * 2, 3, "%02x", random[i]);
    struct json_object *job = json_object_new_object();
    text(job, "job_id", id);
    text(job, "actor", actor);
    text(job, "action", action);
    text(job, "state", "queued");
    text(job, "revision", current);
    if (service) json_object_object_add(job, "request", copy(request));
    json_object_object_add(job, "created_at", json_object_new_int64(cloud_now_s()));
    json_object_object_add(job, "updated_at", json_object_new_int64(cloud_now_s()));
    if (json_object_array_length(control.jobs) == JOBS_MAX)
        json_object_array_del_idx(control.jobs, 0, 1);
    json_object_array_add(control.jobs, job);
    if (save_jobs()) {
        text(job, "state", "failed");
        text(job, "error", "job_persist_failed");
        control.active = NULL;
        response = reply(503, "job_persist_failed", NULL);
        goto done;
    }
    control.active = job;
    control.pending = 1;
    if (!strcmp(action, "enable") || !strcmp(action, "disable") || !strcmp(action, "preflight") ||
        (service && strcmp(action, "service_probe")))
        control.preflight_id[0] = 0;
    struct json_object *data = copy(job);
    json_object_object_del(data, "actor");
    json_object_object_del(data, "request");
    response = reply(202, NULL, data);
    pthread_cond_signal(&control.wake);
done:
    pthread_mutex_unlock(&control.lock);
    return response;
}
