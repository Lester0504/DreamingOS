// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Cloud enrollment BFF (Phase 6T). The /api/v1/cloud/* surface: status,
 * identity, config, enroll, disable. The core owns the persistent truth; these
 * handlers are thin BFF adapters. Each branch body moves VERBATIM from
 * jmx_app_api.c behind an alias preamble (req/body_json/device_id as referenced;
 * resp+status always), so no second implementation remains there.
 *
 * The original five routes retain their semantics. Local-domain adds an
 * independent, authenticated readback with no relay or certificate side effects.
 *
 * Borrowed from jmx_app_api.c (declared in api_cloud_internal.h; definitions stay
 * in main), de-static'd: webd_cloud_component_response, webd_cloud_config_write.
 * Every other symbol is already exported (app_ubus_*, jmx_app_audit_log,
 * webd_error, app_nc_json_*, json-c, libc).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uci.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>

#include "api_cloud.h"
#include "api_cloud_domain.h"
#include "api_cloud_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"
#include "../webd_passkey.h"
#include "../../jmx_exec.h"

#ifndef DOMAIN_DHCP
#define DOMAIN_DHCP "/etc/config/dhcp"
#define DOMAIN_HOSTS "/etc/dreamingwrt/cloud-domain.hosts"
#define DOMAIN_BACKUPS "/etc/dreamingwrt/cloud-domain-backups"
#define DOMAIN_JOBS "/etc/dreamingwrt/cloud-domain-jobs"
#define DOMAIN_LOCK "/var/lock/dreamingwrt-cloud-domain.lock"
#endif
static const struct webd_cloud_domain_paths domain_paths = {
    DOMAIN_DHCP, DOMAIN_HOSTS, DOMAIN_BACKUPS
};
static struct json_object *cloud_domain_action(struct jmx_api_ctx *ctx);

/* ── cloud route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *cloud_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = webd_cloud_component_response("status", NULL, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *cloud_identity(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = webd_cloud_component_response("identity", NULL, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *cloud_config(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = webd_cloud_config_write(body_json, &status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "cloud.config", status == 200 ? "high" : "medium", "", "", "");

    ctx->status = status;
    return resp;
}

static struct json_object *cloud_enroll(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        struct json_object *args = json_object_new_object();
        struct json_object *force = NULL;

        /*
         * force is opt-in: re-enrolling revokes the current token immediately, so
         * an accidental call would drop a working tunnel. The component answers
         * already_enrolled instead when force is absent.
         */
        if (args && json_object_object_get_ex(body_json, "force", &force) && force)
            json_object_object_add(args, "force",
                                   json_object_new_boolean(json_object_get_boolean(force)));
        resp = webd_cloud_component_response("enroll", args, &status);
        if (args)
            json_object_put(args);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "cloud.enroll", status == 200 ? "high" : "medium", "", "", "");

    ctx->status = status;
    return resp;
}

static struct json_object *cloud_disable(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        struct json_object *confirm = NULL;

        /*
         * Disabling the relay makes every paired App lose remote access, so the
         * caller has to confirm. The impact is stated in the refusal so the UI can
         * show it without hardcoding a count it cannot see.
         */
        if (!json_object_object_get_ex(body_json, "confirm", &confirm) ||
            !confirm || !json_object_get_boolean(confirm)) {
            struct json_object *detail = NULL;

            status = 409;
            resp = webd_error("requires_confirm",
                              "disabling remote access will cut off every paired App "
                              "outside the LAN",
                              "confirm", "webd.cloud");
            if (json_object_object_get_ex(resp, "error", &detail) && detail)
                json_object_object_add(detail, "impact",
                                       json_object_new_string("remote_access_lost"));
        } else {
            struct json_object *args = json_object_new_object();

            if (args)
                json_object_object_add(args, "enabled", json_object_new_boolean(0));
            resp = webd_cloud_config_write(args, &status);
            if (args)
                json_object_put(args);
        }
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "cloud.disable", status == 200 ? "high" : "medium", "", "", "");

    ctx->status = status;
    return resp;
}

static struct json_object *cloud_local_domain(struct jmx_api_ctx *ctx)
{
    struct uci_context *uci = uci_alloc_context();
    struct json_object *data;
    char rp_id[WEBD_PASSKEY_RP_ID_MAX + 1] = "";

    if (!uci) {
        ctx->status = 503;
        return webd_error("local_domain_unavailable",
                          "local domain configuration cannot be read",
                          "", "webd.cloud");
    }
    (void)webd_passkey_rp_id(rp_id, sizeof(rp_id));
    data = webd_cloud_domain_snapshot(uci, rp_id, "/etc/hosts",
                                     "/etc/dreamingwrt/tls/console.crt");
    if (data) {
        struct json_object *plan = webd_cloud_domain_plan(data, webd_cloud_work_mode(), &domain_paths);
        json_object_object_add(plan, "can_write", json_object_new_boolean(ctx->role == JMX_ROLE_OWNER &&
            webd_identity_username(ctx->device_id)[0] && webd_cloud_local_request_allowed(ctx->req)));
        json_object_object_add(data, "apply_plan", plan);
    }
    uci_free_context(uci);
    ctx->status = data ? 200 : 503;
    return data ? webd_envelope(data, "webd.cloud") :
        webd_error("local_domain_unavailable",
                   "local domain snapshot cannot be created", "", "webd.cloud");
}


static const char *cloud_domain_string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_string)) return "";
    const char *s = json_object_get_string(v);
    return strlen(s) == (size_t)json_object_get_string_len(v) ? s : "";
}

static int cloud_domain_flag(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) &&
        json_object_is_type(v, json_type_boolean) && json_object_get_boolean(v);
}

static void cloud_domain_text(struct json_object *o, const char *key, const char *value)
{ json_object_object_add(o, key, json_object_new_string(value)); }

static struct json_object *cloud_domain_read_plan(struct uci_context *uci)
{
    char rp[254] = "";
    webd_passkey_rp_id(rp, sizeof(rp));
    struct json_object *snapshot = webd_cloud_domain_snapshot(uci, rp, "/etc/hosts", "/etc/dreamingwrt/tls/console.crt");
    if (!snapshot) return NULL;
    struct json_object *plan = webd_cloud_domain_plan(snapshot, webd_cloud_work_mode(), &domain_paths);
    json_object_put(snapshot);
    return plan;
}

static int cloud_domain_reload(void *unused)
{
    (void)unused;
    struct jmx_exec_result result = {0};
    char *argv[] = {"/etc/init.d/dnsmasq", "reload", NULL};
    int rc = jmx_exec_wait(argv[0], argv, 10000, &result);
    int ok = !rc && !result.exit_code && !result.term_signal && !result.timed_out;
    jmx_exec_result_free(&result);
    return ok ? 0 : -1;
}

static size_t cloud_domain_discard(char *ptr, size_t size, size_t n, void *data)
{ (void)ptr; (void)data; return size*n; }

static struct json_object *cloud_domain_probe(struct json_object *plan)
{
    struct json_object *result = json_object_new_object(), *records = NULL;
    struct json_object *answers = json_object_new_array();
    const char *domain = cloud_domain_string(plan, "domain");
    json_object_object_get_ex(plan, "records", &records);
    cloud_domain_text(result, "domain", domain);
    cloud_domain_text(result, "dns_server", "127.0.0.1");
    json_object_object_add(result, "client_verified", json_object_new_boolean(0));
    json_object_object_add(result, "addresses", answers);
    struct jmx_exec_result command = {0};
    char *argv[] = {"/usr/bin/nslookup", (char *)domain, "127.0.0.1", NULL};
    if (access(argv[0], X_OK)) argv[0] = "/bin/nslookup";
    int rc = domain[0] ? jmx_exec_capture(argv[0], argv, 8192, 5000, &command) : -1;
    int matches = !rc && !command.exit_code && !command.timed_out && !command.truncated;
    int in_answers = 0;
    char *copy = command.output ? strdup(command.output) : NULL, *cursor = NULL;
    for (char *line = copy ? strtok_r(copy, "\n", &cursor) : NULL; line; line = strtok_r(NULL, "\n", &cursor)) {
        while (*line == ' ' || *line == '\t') line++;
        if (!strncmp(line, "Name:", 5)) { in_answers = 1; continue; }
        if (!in_answers || strncmp(line, "Address", 7)) continue;
        char ip[46], canonical[46]; unsigned char binary[16];
        char *colon = strchr(line, ':');
        if (!colon || sscanf(colon+1, "%45s", ip) != 1) continue;
        int family = inet_pton(AF_INET, ip, binary) == 1 ? AF_INET :
                     inet_pton(AF_INET6, ip, binary) == 1 ? AF_INET6 : 0;
        if (!family || !inet_ntop(family, binary, canonical, sizeof(canonical))) continue;
        int expected = 0, duplicate = 0;
        for (size_t i = 0; records && i < json_object_array_length(records); i++)
            expected |= !strcmp(canonical, cloud_domain_string(json_object_array_get_idx(records, i), "address"));
        for (size_t i = 0; i < json_object_array_length(answers); i++)
            duplicate |= !strcmp(canonical, json_object_get_string(json_object_array_get_idx(answers, i)));
        matches &= expected;
        if (!duplicate) json_object_array_add(answers, json_object_new_string(canonical));
    }
    matches &= records && json_object_array_length(records) > 0 &&
        json_object_array_length(answers) == json_object_array_length(records);
    json_object_object_add(result, "dns_matches", json_object_new_boolean(matches));
    cloud_domain_text(result, "dns_output", command.output ? command.output : "");
    free(copy); jmx_exec_result_free(&command);
    CURL *curl = curl_easy_init();
    struct curl_slist *resolve = NULL;
    CURLcode tls = CURLE_FAILED_INIT;
    long http = 0;
    if (curl && records && json_object_array_length(records) && domain[0]) {
        const char *ip = cloud_domain_string(json_object_array_get_idx(records, 0), "address");
        char url[300], binding[340];
        snprintf(url, sizeof(url), "https://%s/", domain);
        snprintf(binding, sizeof(binding), strchr(ip, ':') ? "%s:443:[%s]" : "%s:443:%s", domain, ip);
        resolve = curl_slist_append(NULL, binding);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
        curl_easy_setopt(curl, CURLOPT_PROXY, "");
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 3000L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cloud_domain_discard);
        tls = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    }
    if (curl) curl_easy_cleanup(curl);
    curl_slist_free_all(resolve);
    json_object_object_add(result, "tls_valid", json_object_new_boolean(tls == CURLE_OK));
    cloud_domain_text(result, "tls_error", tls == CURLE_OK ? "" : curl_easy_strerror(tls));
    json_object_object_add(result, "http_status", json_object_new_int64(http));
    return result;
}

static struct json_object *cloud_domain_job_read(const char *id, const char *owner)
{
    if (strlen(id) != 32 || strspn(id, "0123456789abcdef") != 32) return NULL;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.json", DOMAIN_JOBS, id);
    struct json_object *job = json_object_from_file(path);
    if (!job || strcmp(cloud_domain_string(job, "owner"), owner)) { json_object_put(job); return NULL; }
    struct json_object *updated = NULL;
    json_object_object_get_ex(job, "updated_at", &updated);
    if ((!strcmp(cloud_domain_string(job, "state"), "queued") ||
         !strcmp(cloud_domain_string(job, "state"), "running")) &&
        time(NULL) - json_object_get_int64(updated) > 60) {
        cloud_domain_text(job, "state", "failed");
        cloud_domain_text(job, "error", "job_interrupted");
    }
    return job;
}

static int cloud_domain_job_write(const char *path, struct json_object *job)
{
    json_object_object_add(job, "updated_at", json_object_new_int64(time(NULL)));
    return webd_cloud_domain_write_atomic(path, json_object_to_json_string_ext(job, JSON_C_TO_STRING_PLAIN), 0600);
}

static struct json_object *cloud_domain_start_job(struct jmx_api_ctx *ctx,
    struct json_object *plan, int lock, int apply)
{
    unsigned char random[16]; char id[33], path[512];
    if ((mkdir(DOMAIN_JOBS, 0700) && errno != EEXIST) || RAND_bytes(random, 16) != 1) goto unavailable;
    for (size_t i = 0; i < 16; i++) snprintf(id + 2*i, 3, "%02x", random[i]);
    snprintf(path, sizeof(path), "%s/%s.json", DOMAIN_JOBS, id);
    struct json_object *job = json_object_new_object();
    cloud_domain_text(job, "job_id", id);
    cloud_domain_text(job, "owner", webd_identity_username(ctx->device_id));
    cloud_domain_text(job, "action", apply ? "local_domain_apply" : "local_domain_probe");
    cloud_domain_text(job, "state", "queued");
    if (cloud_domain_job_write(path, job)) { json_object_put(job); goto unavailable; }
    pid_t pid = fork();
    if (pid < 0) { unlink(path); json_object_put(job); goto unavailable; }
    if (!pid) {
        /* This child uses fresh UCI handles and no inherited account DB handle. */
        for (int fd = 3; fd < 1024; fd++) if (fd != lock) close(fd);
        cloud_domain_text(job, "state", "running");
        if (cloud_domain_job_write(path, job)) _exit(1);
        struct json_object *result;
        if (apply) {
            struct uci_context *uci = uci_alloc_context();
            result = uci ? webd_cloud_domain_apply(uci, plan, &domain_paths, cloud_domain_reload, NULL) : NULL;
            if (uci) uci_free_context(uci);
            if (result && cloud_domain_flag(result, "configured")) {
                struct json_object *probe = cloud_domain_probe(plan);
                cloud_domain_text(job, "state", cloud_domain_flag(probe, "dns_matches") &&
                    cloud_domain_flag(probe, "tls_valid") ? "succeeded" : "partial");
                json_object_object_add(result, "probe", probe);
            } else {
                cloud_domain_text(job, "state", "failed");
                cloud_domain_text(job, "error", result ? cloud_domain_string(result, "error") : "dns_configuration_unavailable");
            }
        } else {
            result = cloud_domain_probe(plan);
            cloud_domain_text(job, "state", cloud_domain_flag(result, "dns_matches") &&
                cloud_domain_flag(result, "tls_valid") ? "succeeded" : "failed");
        }
        json_object_object_add(job, "result", result);
        int saved = cloud_domain_job_write(path, job);
        close(lock); _exit(saved ? 1 : 0);
    }
    ctx->status = 202;
    jmx_app_audit_log(ctx->device_id, ctx->device_id, apply ? "cloud.local_dns.apply" : "cloud.local_dns.probe",
        apply ? "high" : "low", id, "", "");
    return webd_envelope(job, "webd.cloud");
unavailable:
    ctx->status = 503;
    return webd_error("job_unavailable", "DNS job could not be started", "", "webd.cloud");
}

static struct json_object *cloud_domain_action(struct jmx_api_ctx *ctx)
{
    const char *owner = webd_identity_username(ctx->device_id);
    const char *suffix = ctx->req->path + strlen("/api/v1/cloud/local-domain/");
    struct json_object *reply = NULL, *plan = NULL;
    struct uci_context *uci = NULL;
    int lock = -1;
    if (ctx->role != JMX_ROLE_OWNER || !owner[0]) {
        ctx->status = 403; return webd_error("permission_denied", "device Owner web session required", "", "webd.cloud");
    }
    if (!webd_cloud_local_request_allowed(ctx->req)) {
        ctx->status = 403; return webd_error("local_confirmation_required", "use a local device connection", "", "webd.cloud");
    }
    if (!strncmp(suffix, "jobs/", 5) && !strcmp(ctx->req->method, "GET")) {
        struct json_object *job = cloud_domain_job_read(suffix+5, owner);
        ctx->status = job ? 200 : 404;
        return job ? webd_envelope(job, "webd.cloud") : webd_error("not_found", "job not found", "", "webd.cloud");
    }
    if (strcmp(ctx->req->method, "POST") ||
        (strcmp(suffix, "apply") && strcmp(suffix, "probe") && strcmp(suffix, "reauth/begin"))) {
        ctx->status = 404; return webd_error("not_found", "operation not found", "", "webd.cloud");
    }
    ctx->status = 400;
    if (!ctx->body || !json_object_is_type(ctx->body, json_type_object))
        return webd_error("invalid_request", "JSON object required", "", "webd.cloud");
    lock = open(DOMAIN_LOCK, O_RDWR|O_CREAT|O_CLOEXEC, 0600);
    if (lock < 0 || flock(lock, LOCK_EX|LOCK_NB)) {
        if (lock >= 0) close(lock);
        ctx->status = 409; return webd_error("operation_busy", "a DNS operation is in progress", "", "webd.cloud");
    }
    uci = uci_alloc_context();
    plan = uci ? cloud_domain_read_plan(uci) : NULL;
    if (!plan || !cloud_domain_string(plan, "domain")[0]) {
        ctx->status = 503; reply = webd_error("local_domain_unavailable", "local domain unavailable", "", "webd.cloud"); goto done;
    }
    if (!strcmp(suffix, "probe")) { reply = cloud_domain_start_job(ctx, plan, lock, 0); goto done; }
    if (!cloud_domain_flag(plan, "can_apply")) {
        ctx->status = 409; reply = webd_error(cloud_domain_string(plan, "reason"), "review the local DNS plan", "", "webd.cloud"); goto done;
    }
    const char *revision = cloud_domain_string(ctx->body, "revision");
    if (!revision[0] || strcmp(revision, cloud_domain_string(plan, "revision"))) {
        ctx->status = 409; reply = webd_error("revision_conflict", "DNS configuration changed; read the plan again", "", "webd.cloud"); goto done;
    }
    char message[512], binding[65]; unsigned char digest[32];
    int n = snprintf(message, sizeof(message), "dreamingos-local-dns-apply-v1\n%s\n%s\n%s", owner, ctx->req->auth_token, revision);
    if (n < 0 || (size_t)n >= sizeof(message) || !SHA256((unsigned char *)message, (size_t)n, digest)) {
        ctx->status = 503; reply = webd_error("confirmation_unavailable", "confirmation unavailable", "", "webd.cloud"); goto done;
    }
    for (size_t i = 0; i < 32; i++) snprintf(binding+2*i, 3, "%02x", digest[i]);
    if (!strcmp(suffix, "reauth/begin")) {
        reply = webd_passkey_reauthenticate_begin(owner, binding, &ctx->status); goto done;
    }
    if (!cloud_domain_flag(ctx->body, "confirm")) {
        ctx->status = 409; reply = webd_error("requires_confirm", "confirm the displayed DNS records", "", "webd.cloud"); goto done;
    }
    struct json_object *auth = NULL;
    json_object_object_get_ex(ctx->body, "authentication", &auth);
    const char *method = cloud_domain_string(auth, "method");
    if (!strcmp(method, "password")) {
        reply = webd_cloud_confirm_password(owner, cloud_domain_string(auth, "password"), ctx->req->client_ip, &ctx->status);
        if (reply) goto done;
    } else if (!strcmp(method, "passkey")) {
        struct json_object *assertion = NULL;
        json_object_object_get_ex(auth, "assertion", &assertion);
        reply = webd_cloud_confirm_passkey(assertion, owner, binding, &ctx->status);
        if (ctx->status != 200) goto done;
        json_object_put(reply); reply = NULL;
    } else {
        ctx->status = 401; reply = webd_error("reauthentication_required", "verify with password or Passkey", "", "webd.cloud"); goto done;
    }
    reply = cloud_domain_start_job(ctx, plan, lock, 1);
done:
    if (reply && ctx->status >= 400) {
        struct json_object *code = NULL;
        if (json_object_object_get_ex(reply, "error", &code) && json_object_is_type(code, json_type_string)) {
            struct json_object *normalized = webd_error(json_object_get_string(code),
                cloud_domain_string(reply, "message"), "", "webd.cloud");
            json_object_put(reply); reply = normalized;
        }
    }
    json_object_put(plan);
    if (uci) uci_free_context(uci);
    close(lock);
    return reply;
}

/*
 * Account binding by stable code (Backend §1). The user types the account's
 * stable binding code; this device proves possession of its signing key and
 * redeems the code so the account records the binding. Binding a device to an
 * account is an outward-facing, admin-only action, so it requires an explicit
 * confirm the same way disable does. It registers only the relationship — no
 * data-plane tunnel is opened here.
 *
 * The two round trips run on a cloud-side worker; this returns immediately with
 * the job snapshot and the caller polls /api/v1/cloud/bind-status.
 */
static struct json_object *cloud_bind_code(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        struct json_object *confirm = NULL;
        struct json_object *code = NULL;
        struct json_object *name = NULL;

        if (!json_object_object_get_ex(body_json, "confirm", &confirm) ||
            !confirm || !json_object_get_boolean(confirm)) {
            struct json_object *detail = NULL;

            status = 409;
            resp = webd_error("requires_confirm",
                              "binding this device to an account records it under "
                              "that account; confirm to proceed",
                              "confirm", "webd.cloud");
            if (json_object_object_get_ex(resp, "error", &detail) && detail)
                json_object_object_add(detail, "impact",
                                       json_object_new_string("account_bound"));
        } else if (!json_object_object_get_ex(body_json, "binding_code", &code) ||
                   !code || !json_object_is_type(code, json_type_string) ||
                   !json_object_get_string_len(code) ||
                   !json_object_object_get_ex(body_json, "display_name", &name) ||
                   !name || !json_object_is_type(name, json_type_string) ||
                   !json_object_get_string_len(name)) {
            status = 422;
            resp = webd_error("invalid_request",
                              "binding_code and display_name are required",
                              "binding_code", "webd.cloud");
        } else {
            struct json_object *args = json_object_new_object();

            if (args) {
                json_object_object_add(args, "code",
                    json_object_new_string(json_object_get_string(code)));
                json_object_object_add(args, "display_name",
                    json_object_new_string(json_object_get_string(name)));
            }
            resp = webd_cloud_component_response("bind_code", args, &status);
            if (args)
                json_object_put(args);
        }
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
            "cloud.bind_code", status == 200 ? "high" : "medium", "", "", "");

    ctx->status = status;
    return resp;
}

static struct json_object *cloud_bind_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = webd_cloud_component_response("bind_status", NULL, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *cloud_browser_api(struct jmx_api_ctx *ctx)
{
    const char *suffix = ctx->req->path + strlen("/api/v1/cloud/web-access/");
    int caps = !strcmp(suffix, "capabilities");
    int write = strcmp(ctx->req->method, "GET") != 0;
    if (write && ctx->role != JMX_ROLE_OWNER) {
        ctx->status = 403;
        return webd_error("permission_denied", "device owner required", "", "webd.cloud");
    }
    struct json_object *request = json_object_new_object();
    const char *action = caps ? "status" : suffix;
    if (!strcmp(suffix, "services") || !strncmp(suffix, "services/", 9)) {
        if (strcmp(suffix, "services")) {
            const char *id = suffix + 9, *slash = strchr(id, '/');
            size_t n = slash ? (size_t)(slash - id) : strlen(id);
            if (!n || n > 63 || strspn(id, "abcdefghijklmnopqrstuvwxyz0123456789-") != n ||
                id[0] == '-' || id[n - 1] == '-' ||
                (slash && strcmp(slash, "/probe"))) goto missing;
            if (slash && !strcmp(ctx->req->method, "POST")) action = "service_probe";
            else if (!slash && !strcmp(ctx->req->method, "PATCH")) action = "service_update";
            else if (!slash && !strcmp(ctx->req->method, "DELETE")) action = "service_delete";
            else goto missing;
            json_object_object_add(request, "service_id", json_object_new_string_len(id, n));
        } else if (!strcmp(ctx->req->method, "POST")) action = "service_create";
        else if (!strcmp(ctx->req->method, "GET")) action = "services";
        else goto missing;
        if (write) {
            if (!json_object_is_type(ctx->body, json_type_object)) goto invalid;
            json_object_object_foreach(ctx->body, key, value) {
                if (!strcmp(key, "service_id") || !strcmp(key, "actor")) goto invalid;
                json_object_object_add(request, key, json_object_get(value));
            }
        }
    } else if (!strncmp(suffix, "jobs/", 5)) {
        const char *id = suffix + 5;
        if (strlen(id) != 32 || strspn(id, "0123456789abcdef") != 32) {
            json_object_put(request);
            ctx->status = 404;
            return webd_error("not_found", "job not found", "", "webd.cloud");
        }
        action = "job";
        json_object_object_add(request, "job_id", json_object_new_string(id));
    } else if (write) {
        if (!json_object_is_type(ctx->body, json_type_object)) goto invalid;
        json_object_object_foreach(ctx->body, key, value) {
            int is_confirm = !strcmp(key, "confirm") &&
                (!strcmp(suffix, "enable") || !strcmp(suffix, "disable"));
            int is_ack = !strcmp(key, "legacy_hostname_ack") && !strcmp(suffix, "enable");
            int is_id = !strcmp(key, "preflight_id") && !strcmp(suffix, "enable");
            if ((is_confirm || is_ack) && json_object_is_type(value, json_type_boolean))
                json_object_object_add(request, key, json_object_get(value));
            else if (is_id && json_object_is_type(value, json_type_string) &&
                     json_object_get_string_len(value) == 32 &&
                     strspn(json_object_get_string(value), "0123456789abcdef") == 32)
                json_object_object_add(request, key, json_object_get(value));
            else goto invalid;
        }
    }
    struct json_object *args = json_object_new_object();
    json_object_object_add(args, "action", json_object_new_string(action));
    json_object_object_add(args, "actor", json_object_new_string(ctx->device_id));
    json_object_object_add(args, "request", request);
    struct json_object *response = app_ubus_invoke_object_timeout(
        "dreamingos.cloud", "web_access", args, 3000);
    json_object_put(args);
    struct json_object *ok = NULL, *data = NULL, *status = NULL, *code = NULL;
    int valid = response && json_object_object_get_ex(response, "http_status", &status) &&
                json_object_is_type(status, json_type_int) &&
                json_object_object_get_ex(response, "ok", &ok) &&
                json_object_is_type(ok, json_type_boolean);
    if (caps) {
        data = json_object_new_object();
        int supported = valid && json_object_get_boolean(ok);
        json_object_object_add(data, "supported", json_object_new_boolean(supported));
        json_object_object_add(data, "can_write",
            json_object_new_boolean(supported && ctx->role == JMX_ROLE_OWNER));
        json_object_object_add(data, "reason", supported ?
            (ctx->role == JMX_ROLE_OWNER ? NULL : json_object_new_string("device_owner_required")) :
            json_object_new_string("cloud_component_unavailable"));
        struct json_object *component = NULL, *crud = NULL;
        if (response && json_object_object_get_ex(response, "data", &component))
            json_object_object_get_ex(component, "service_crud", &crud);
        json_object_object_add(data, "service_crud", json_object_new_boolean(
            supported && json_object_get_boolean(crud)));
        const char *flags[] = {"websocket", "sse"};
        for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
            struct json_object *value = NULL;
            json_object_object_get_ex(component, flags[i], &value);
            json_object_object_add(data, flags[i], json_object_new_boolean(supported &&
                json_object_is_type(value, json_type_boolean) && json_object_get_boolean(value)));
        }
        const char *limits[] = {"upload_max_bytes", "response_max_bytes"};
        const int defaults[] = {262144, 8388608};
        for (unsigned i = 0; i < sizeof(limits) / sizeof(limits[0]); ++i) {
            struct json_object *value = NULL;
            json_object_object_get_ex(component, limits[i], &value);
            int64_t n = json_object_get_int64(value);
            json_object_object_add(data, limits[i], json_object_new_int64(supported &&
                json_object_is_type(value, json_type_int) && n > 0 && n <= 1073741824 ?
                n : defaults[i]));
        }
        const char *details[] = {"capability_state", "features_v1", "negotiated_v1", "account_quota"};
        for (unsigned i = 0; i < sizeof(details) / sizeof(details[0]); ++i) {
            struct json_object *value = NULL;
            if (supported && json_object_object_get_ex(component, details[i], &value))
                json_object_object_add(data, details[i], json_object_get(value));
        }
        if (response) json_object_put(response);
        ctx->status = 200;
        return webd_envelope(data, "webd.cloud");
    }
    ctx->status = valid ? json_object_get_int(status) : 503;
    struct json_object *out;
    if (valid && json_object_get_boolean(ok) &&
        json_object_object_get_ex(response, "data", &data)) {
        out = webd_envelope(json_object_get(data), "webd.cloud");
    } else {
        if (response) json_object_object_get_ex(response, "code", &code);
        const char *error = code && json_object_is_type(code, json_type_string) ?
            json_object_get_string(code) : "cloud_component_unavailable";
        out = webd_error(error, error, "", "webd.cloud");
    }
    if (response) json_object_put(response);
    if (write)
        jmx_app_audit_log(ctx->device_id, ctx->device_id, ctx->req->path,
                         "high", "", "", "");
    return out;
missing:
    json_object_put(request);
    ctx->status = 404;
    return webd_error("not_found", "service route not found", "", "webd.cloud");
invalid:
    json_object_put(request);
    ctx->status = 422;
    return webd_error("invalid_request", "invalid browser control request", "", "webd.cloud");
}

const struct jmx_api_route cloud_api_routes[] = {
    JMX_API_ROUTE(683, "/api/v1/cloud/status", "GET", JMX_API_EXACT, cloud_status),
    JMX_API_ROUTE(684, "/api/v1/cloud/identity", "GET", JMX_API_EXACT, cloud_identity),
    JMX_API_ROUTE(685, "/api/v1/cloud/config", "POST,PUT", JMX_API_EXACT, cloud_config),
    JMX_API_ROUTE(686, "/api/v1/cloud/enroll", "POST", JMX_API_EXACT, cloud_enroll),
    JMX_API_ROUTE(687, "/api/v1/cloud/disable", "POST", JMX_API_EXACT, cloud_disable),
    JMX_API_ROUTE(9614, "/api/v1/cloud/local-domain", "GET", JMX_API_EXACT, cloud_local_domain),
    JMX_API_ROUTE(979, "/api/v1/cloud/bind-code", "POST", JMX_API_EXACT, cloud_bind_code),
    JMX_API_ROUTE(980, "/api/v1/cloud/bind-status", "GET", JMX_API_EXACT, cloud_bind_status),
    JMX_API_ROUTE(982, "/api/v1/cloud/web-access/capabilities", "GET", JMX_API_EXACT, cloud_browser_api),
    JMX_API_ROUTE(983, "/api/v1/cloud/web-access/status", "GET", JMX_API_EXACT, cloud_browser_api),
    JMX_API_ROUTE(984, "/api/v1/cloud/web-access/preflight", "POST", JMX_API_EXACT, cloud_browser_api),
    JMX_API_ROUTE(985, "/api/v1/cloud/web-access/enable", "POST", JMX_API_EXACT, cloud_browser_api),
    JMX_API_ROUTE(986, "/api/v1/cloud/web-access/disable", "POST", JMX_API_EXACT, cloud_browser_api),
    JMX_API_ROUTE(987, "/api/v1/cloud/web-access/reconnect", "POST", JMX_API_EXACT, cloud_browser_api),
    JMX_API_ROUTE(988, "/api/v1/cloud/web-access/jobs/", "GET", JMX_API_PREFIX, cloud_browser_api),
    JMX_API_ROUTE(990, "/api/v1/cloud/web-access/services", "GET,POST", JMX_API_EXACT, cloud_browser_api),
    JMX_API_ROUTE(991, "/api/v1/cloud/web-access/services/", "PATCH,DELETE,POST", JMX_API_PREFIX, cloud_browser_api),
    JMX_API_ROUTE(9608, "/api/v1/cloud/local-domain/", "GET,POST", JMX_API_PREFIX, cloud_domain_action),
    JMX_API_ROUTE_END,
};

/* -- Cloud relay administration helpers (Phase 7Y) ---------------------------
 * The dreamingos-cloud reply unwrapper and the relay UCI settings writer, with
 * their private validators, lifted verbatim out of jmx_app_api.c. Only the
 * cloud BFF adapters above call them (declared in api_cloud_internal.h), so
 * no route and no main-TU caller moved.
 */
/* ═══ Cloud relay administration under /api/v1/cloud ═══
 *
 * The router half of remote access lives in dreamingos-cloud, which owns the key
 * material and speaks to the relay. webd is the only authenticated surface, so
 * these routes exist to let an admin see and change that state without handing
 * out shell or ubus access.
 *
 * Division of labour: settings live in UCI so they go through the normal config
 * authority, and the tunnel credential is obtained by the daemon at runtime
 * because it is a secret the router earns rather than one an operator types.
 */
#define WEBD_CLOUD_UBUS_OBJECT "dreamingos.cloud"
#define WEBD_CLOUD_UCI_PACKAGE "relay"
#define WEBD_CLOUD_UCI_SECTION "service"

/* Defined further down with the policy-engine UCI helpers; reused here so relay
 * settings go through the same validation and delete-if-empty semantics. */
int webd_policy_uci_set_pkg_option(struct uci_context *ctx,
                                          const char *package,
                                          const char *section,
                                          const char *option,
                                          const char *value,
                                          int delete_if_empty,
                                          char *err, size_t err_len);

/*
 * Unwraps a dreamingos-cloud reply into a webd envelope.
 *
 * The component is optional, so an absent ubus object is reported as a
 * capability gap rather than a server fault: the UI needs to say "remote access
 * is not installed" instead of showing an error.
 */
struct json_object *webd_cloud_component_response(const char *method,
                                                         struct json_object *args,
                                                         int *status)
{
    struct json_object *reply;
    struct json_object *data = NULL;
    struct json_object *ok = NULL;
    struct app_ubus_call_diag diag;

    reply = app_ubus_invoke_object_diag(WEBD_CLOUD_UBUS_OBJECT, method, args,
                                       3000, &diag);
    if (!reply) {
        if (status)
            *status = 503;
        /*
         * "never deployed" and "still coming up" both used to read
         * cloud_component_unavailable, and the difference matters to whoever is
         * looking at it: the first needs an operator, the second needs a few
         * seconds. The lookup stage tells them apart, since a registered ubus
         * object means the component is there and only the call did not land.
         */
        if (diag.stage && !strcmp(diag.stage, "lookup"))
            return webd_error("cloud_component_unavailable",
                              "the dreamingos-cloud component is not running",
                              "dreamingos-cloud", "webd.cloud");
        return webd_error("cloud_component_starting",
                          "the dreamingos-cloud component is registered but did "
                          "not answer yet; retry in a few seconds",
                          "dreamingos-cloud", "webd.cloud");
    }
    if (json_object_object_get_ex(reply, "ok", &ok) && ok &&
        !json_object_get_boolean(ok)) {
        struct json_object *code = NULL;
        struct json_object *message = NULL;
        struct json_object *error;

        /*
         * The component's own code is passed through unchanged. The relay's
         * documented codes distinguish cases the UI renders differently, such as
         * statically_configured, and reinterpreting them here would erase that.
         */
        json_object_object_get_ex(reply, "code", &code);
        json_object_object_get_ex(reply, "message", &message);
        error = webd_error(code && json_object_is_type(code, json_type_string) ?
                               json_object_get_string(code) : "cloud_request_failed",
                           message && json_object_is_type(message, json_type_string) ?
                               json_object_get_string(message) :
                               "the cloud component refused the request",
                           "", "webd.cloud");
        if (json_object_object_get_ex(reply, "data", &data) && data)
            json_object_object_add(error, "data", json_object_get(data));
        json_object_put(reply);
        if (status)
            *status = 409;
        return error;
    }
    if (!json_object_object_get_ex(reply, "data", &data) || !data) {
        json_object_put(reply);
        if (status)
            *status = 502;
        return webd_error("cloud_response_malformed",
                          "the cloud component returned no data block",
                          "data", "webd.cloud");
    }
    data = json_object_get(data);
    json_object_put(reply);
    if (status)
        *status = 200;
    return webd_envelope(data, "webd.cloud");
}

/*
 * Hostname or IP literal, matching cloud_config.c's own check.
 *
 * The value ends up in DNS resolution and TLS name verification, so anything
 * that could smuggle a scheme, path, port or whitespace past those is refused at
 * the edge instead of being stored and failing later.
 */
static int webd_cloud_host_valid(const char *value)
{
    size_t length = value ? strlen(value) : 0;
    size_t i;

    if (!length || length > 253)
        return 0;
    if (value[0] == '.' || value[0] == '-')
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':')
            continue;
        return 0;
    }
    return 1;
}

static struct json_object *webd_cloud_field_error(const char *field,
                                                  const char *message)
{
    struct json_object *error = webd_error("cloud_config_invalid", message,
                                           field, "webd.cloud");
    struct json_object *detail = NULL;

    /* Field-level detail so the form can mark the offending input rather than
     * showing one generic banner. */
    if (json_object_object_get_ex(error, "error", &detail) && detail)
        json_object_object_add(detail, "field", json_object_new_string(field));
    return error;
}

/*
 * Writes the relay settings to UCI.
 *
 * Only fields present in the request are touched, so a form that submits one
 * value cannot blank the rest. auth_token is accepted for the static-registration
 * path but never echoed back anywhere.
 */
struct json_object *webd_cloud_config_write(struct json_object *body,
                                                   int *status)
{
    struct uci_context *ctx;
    struct uci_package *package = NULL;
    struct json_object *value = NULL;
    struct json_object *error = NULL;
    char err[128] = "";
    int has_enabled, has_host, has_port, has_tls, has_token, has_ca;
    int enabled = 0, tls_verify = 1;
    const char *host = NULL;
    const char *token = NULL;
    const char *ca_path = NULL;
    int port = 0;

    if (status)
        *status = 400;

    has_enabled = json_object_object_get_ex(body, "enabled", &value) && value;
    if (has_enabled)
        enabled = json_object_get_boolean(value);

    has_host = json_object_object_get_ex(body, "host", &value) && value &&
               json_object_is_type(value, json_type_string);
    if (has_host) {
        host = json_object_get_string(value);
        if (!webd_cloud_host_valid(host))
            return webd_cloud_field_error("host",
                "host must be a hostname or IP literal without scheme or path");
    }

    has_port = json_object_object_get_ex(body, "port", &value) && value;
    if (has_port) {
        port = json_object_get_int(value);
        if (port < 1 || port > 65535)
            return webd_cloud_field_error("port", "port must be 1-65535");
    }

    has_tls = json_object_object_get_ex(body, "tls_verify", &value) && value;
    if (has_tls) {
        tls_verify = json_object_get_boolean(value);
        /*
         * Turning verification off makes the tunnel trivially interceptable.
         * Allowed, because a lab relay may use a private CA, but never silently:
         * the status surface reports it and this refuses the shorthand of
         * disabling it without saying so.
         */
        if (!tls_verify) {
            struct json_object *ack = NULL;

            if (!json_object_object_get_ex(body, "accept_insecure_tls", &ack) ||
                !ack || !json_object_get_boolean(ack))
                return webd_cloud_field_error("tls_verify",
                    "disabling TLS verification requires accept_insecure_tls");
        }
    }

    has_token = json_object_object_get_ex(body, "auth_token", &value) && value &&
                json_object_is_type(value, json_type_string);
    if (has_token) {
        size_t i;

        token = json_object_get_string(value);
        /* Empty clears it; otherwise the relay's own floor applies. */
        if (token[0] && (strlen(token) < 32 || strlen(token) > 255))
            return webd_cloud_field_error("auth_token",
                "auth_token must be 32-255 characters");
        for (i = 0; token[i]; i++) {
            unsigned char c = (unsigned char)token[i];

            if (c <= 0x20 || c == 0x7f || c == '"' || c == '\\')
                return webd_cloud_field_error("auth_token",
                    "auth_token contains characters that cannot be sent to the relay");
        }
    }

    has_ca = json_object_object_get_ex(body, "ca_path", &value) && value &&
             json_object_is_type(value, json_type_string);
    if (has_ca) {
        ca_path = json_object_get_string(value);
        if (ca_path[0] && (ca_path[0] != '/' || strstr(ca_path, "..") ||
                           strlen(ca_path) > 255))
            return webd_cloud_field_error("ca_path",
                "ca_path must be an absolute path without ..");
    }

    /*
     * Enabling without any way to reach the relay would leave the component
     * spinning in a failure state; refuse with a specific code instead.
     */
    if (has_enabled && enabled && !has_host) {
        struct uci_context *probe = uci_alloc_context();
        struct uci_package *probe_pkg = NULL;
        const char *existing = NULL;

        if (probe && uci_load(probe, WEBD_CLOUD_UCI_PACKAGE, &probe_pkg) == UCI_OK &&
            probe_pkg) {
            struct uci_section *section =
                uci_lookup_section(probe, probe_pkg, WEBD_CLOUD_UCI_SECTION);

            if (section)
                existing = uci_lookup_option_string(probe, section, "host");
        }
        if (!existing || !existing[0])
            error = webd_cloud_field_error("host",
                "a relay host is required before remote access can be enabled");
        if (probe)
            uci_free_context(probe);
        if (error)
            return error;
    }

    ctx = uci_alloc_context();
    if (!ctx) {
        if (status)
            *status = 500;
        return webd_error("uci_context_failed", "uci context could not be created",
                          "", "webd.cloud");
    }
    if (uci_load(ctx, WEBD_CLOUD_UCI_PACKAGE, &package) != UCI_OK || !package) {
        uci_free_context(ctx);
        if (status)
            *status = 500;
        return webd_error("relay_config_missing",
                          "/etc/config/relay could not be loaded",
                          "/etc/config/relay", "webd.cloud");
    }

    if (has_enabled &&
        webd_policy_uci_set_pkg_option(ctx, WEBD_CLOUD_UCI_PACKAGE,
                                       WEBD_CLOUD_UCI_SECTION, "enabled",
                                       enabled ? "1" : "0", 0,
                                       err, sizeof(err)) != 0)
        goto fail;
    if (has_host &&
        webd_policy_uci_set_pkg_option(ctx, WEBD_CLOUD_UCI_PACKAGE,
                                       WEBD_CLOUD_UCI_SECTION, "host", host, 0,
                                       err, sizeof(err)) != 0)
        goto fail;
    if (has_port) {
        char text[8];

        snprintf(text, sizeof(text), "%d", port);
        if (webd_policy_uci_set_pkg_option(ctx, WEBD_CLOUD_UCI_PACKAGE,
                                           WEBD_CLOUD_UCI_SECTION, "port", text,
                                           0, err, sizeof(err)) != 0)
            goto fail;
    }
    if (has_tls &&
        webd_policy_uci_set_pkg_option(ctx, WEBD_CLOUD_UCI_PACKAGE,
                                       WEBD_CLOUD_UCI_SECTION, "tls_verify",
                                       tls_verify ? "1" : "0", 0,
                                       err, sizeof(err)) != 0)
        goto fail;
    if (has_token &&
        webd_policy_uci_set_pkg_option(ctx, WEBD_CLOUD_UCI_PACKAGE,
                                       WEBD_CLOUD_UCI_SECTION, "auth_token",
                                       token, 1, err, sizeof(err)) != 0)
        goto fail;
    if (has_ca &&
        webd_policy_uci_set_pkg_option(ctx, WEBD_CLOUD_UCI_PACKAGE,
                                       WEBD_CLOUD_UCI_SECTION, "ca_path",
                                       ca_path, 1, err, sizeof(err)) != 0)
        goto fail;

    if (uci_commit(ctx, &package, 0) != UCI_OK) {
        uci_free_context(ctx);
        if (status)
            *status = 500;
        return webd_error("relay_config_commit_failed",
                          "the relay configuration could not be committed",
                          "/etc/config/relay", "webd.cloud");
    }
    uci_free_context(ctx);

    {
        struct json_object *data = json_object_new_object();

        /*
         * The daemon reads UCI at startup, so a settings change needs a restart
         * to take effect. Said plainly rather than implied, so the UI does not
         * poll for a state change that will never come on its own.
         */
        json_object_object_add(data, "committed", json_object_new_boolean(1));
        json_object_object_add(data, "restart_required",
                               json_object_new_boolean(1));
        json_object_object_add(data, "restart_hint",
                               json_object_new_string(
                                   "dreamingwrt-init restart dreamingos-cloud"));
        if (status)
            *status = 200;
        return webd_envelope(data, "webd.cloud");
    }

fail:
    uci_free_context(ctx);
    if (status)
        *status = 500;
    return webd_error("relay_config_write_failed",
                      err[0] ? err : "the relay configuration could not be written",
                      "", "webd.cloud");
}
