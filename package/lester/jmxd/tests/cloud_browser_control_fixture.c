// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../src/cloud/cloud_browser_control.c"
#include <assert.h>
#include <stdatomic.h>

static struct cloud_identity identity;
static atomic_int probes, publishes, revokes, hold_probe, allow_probe = 1, cloud_version = 1;
static atomic_int checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); abort(); } } while (0)

const struct cloud_identity *cloud_identity(void) { return &identity; }
int64_t cloud_now_s(void) { return time(NULL); }
int64_t cloud_monotonic_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
int cloud_base64_decode_fixed(const char *s, unsigned char *out, size_t n)
{
    unsigned char raw[64];
    int count = EVP_DecodeBlock(raw, (const unsigned char *)s, strlen(s));
    if (count < 0 || n != 32 || strlen(s) != 44) return -1;
    memcpy(out, raw, n);
    return 0;
}
int cwc_host_valid(const char *s) { return s && s[0] && !strchr(s, '/'); }
int cwc_service_valid(const struct cwc_service *s)
{
    return s->public_host[0] && ((s->management && !strcmp(s->id, "web")) ||
        (!s->management && !strcmp(s->target_host, "192.168.50.20") && s->port == 8080));
}
struct json_object *cwc_service_probe(const struct cwc_service *s)
{
    (void)s;
    return json_tokener_parse(allow_probe ? "{\"reachable\":true,\"http_status\":200}" :
        "{\"reachable\":false,\"error\":\"service_unreachable\"}");
}
int cwc_publish(const struct cwc_config *c, int enabled, struct cwc_publication *r)
{
    (void)c;
    memset(r, 0, sizeof(*r));
    r->generation = 3; r->revision = 3;
    if (enabled) ++publishes; else ++revokes;
    return 0;
}
int cwc_publication_read(const struct cwc_config *c, struct cwc_publication *r)
{
    (void)c;
    memset(r, 0, sizeof(*r));
    r->generation = 1; r->revision = cloud_version;
    return 0;
}
int cwc_run(const struct cwc_config *c, const struct cwc_hooks *h)
{
    (void)c;
    ++publishes;
    h->status(h->user, "connected", "", 2, 2, 1);
    while (h->running(h->user)) usleep(1000);
    h->status(h->user, "stopped", "", 2, 2, 0);
    return 0;
}
struct json_object *cloud_browser_preflight(const struct cwc_config *c)
{
    CHECK(c->n_services == 1);
    ++probes;
    while (hold_probe) usleep(1000);
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "enable_allowed", json_object_new_boolean(allow_probe));
    json_object_object_add(r, "legacy_hostname", json_object_new_boolean(1));
    json_object_object_add(r, "generation", json_object_new_int(1));
    json_object_object_add(r, "cloud_revision", json_object_new_int(1));
    return r;
}

static void config(void)
{
    FILE *f = fopen(CLOUD_BROWSER_CONFIG_DIR "/cloud_web", "w");
    CHECK(f != NULL);
    fputs("config browser 'main'\n option enabled '0'\n option api_host 'cloud.example'\n"
          " option api_port '443'\n option tunnel_host 'tunnel.example'\n option tunnel_port '443'\n"
          " option services_key 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='\n"
          " option unrelated 'preserve-me'\n"
          "config service 'web'\n option kind 'management'\n option enabled '1'\n"
          " option public_host 'box.example'\n", f);
    fclose(f);
}
static struct json_object *call(const char *action, const char *actor, const char *body, int http)
{
    struct json_object *r = json_tokener_parse(body);
    struct json_object *out = cloud_browser_control(action, actor, r), *v = NULL, *data = NULL;
    json_object_put(r);
    CHECK(json_object_object_get_ex(out, "http_status", &v) && json_object_get_int(v) == http);
    if (json_object_object_get_ex(out, "data", &data)) data = copy(data);
    json_object_put(out);
    return data;
}
static void job_id(struct json_object *job, char id[33])
{
    snprintf(id, 33, "%s", string(job, "job_id"));
    CHECK(strlen(id) == 32);
    CHECK(!json_object_object_get_ex(job, "actor", NULL));
    json_object_put(job);
}
static struct json_object *wait_job(const char *id, const char *expected)
{
    char body[80];
    snprintf(body, sizeof(body), "{\"job_id\":\"%s\"}", id);
    for (int i = 0; i < 300; ++i) {
        struct json_object *job = call("job", "user:owner", body, 200);
        const char *state = string(job, "state");
        if (strcmp(state, "queued") && strcmp(state, "running")) {
            CHECK(!strcmp(state, expected));
            return job;
        }
        json_object_put(job);
        usleep(10000);
    }
    CHECK(0);
    return NULL;
}

static struct json_object *service_call(const char *action, const char *fields, int http)
{
    struct json_object *status = call("status", "user:owner", "{}", 200);
    char body[2048];
    snprintf(body, sizeof(body), "{\"revision\":\"%s\",%s}",
             string(status, "config_revision"), fields);
    json_object_put(status);
    return call(action, "user:owner", body, http);
}

static void test_services(void)
{
    const char *create = "\"name\":\"NAS\",\"kind\":\"http\","
        "\"target\":{\"host\":\"192.168.50.20\",\"port\":8080,\"scheme\":\"http\"}";
    CHECK(call("service_create", "user:owner", "{}", 409) == NULL);
    struct json_object *created = service_call("service_create", create, 201);
    char sid[64], fields[1024], id[33], old_revision[65];
    snprintf(sid, sizeof(sid), "%s", string(created, "service_id"));
    snprintf(old_revision, sizeof(old_revision), "%s", string(created, "revision"));
    CHECK(strlen(sid) == 32 && !boolean(created, "enabled"));
    CHECK(strstr(string(created, "public_host"), ".apps.dreamingnet.com") != NULL);
    json_object_put(created);
    struct json_object *list = call("services", "user:owner", "{}", 200), *items = NULL;
    CHECK(json_object_object_get_ex(list, "services", &items) && json_object_array_length(items) == 2);
    CHECK(!strcmp(old_revision, string(list, "revision")));
    json_object_put(list);
    FILE *cert_file = fopen(getenv("CWC_TEST_CERT"), "r");
    CHECK(cert_file != NULL);
    char pem[4097] = {0}, pin_fields[9000];
    CHECK(fread(pem, 1, sizeof(pem) - 1, cert_file) > 0);
    fclose(cert_file);
    struct json_object *pem_json = json_object_new_string(pem);
    snprintf(pin_fields, sizeof(pin_fields), "\"name\":\"Pinned NAS\",\"kind\":\"http\","
        "\"target\":{\"host\":\"192.168.50.20\",\"port\":8080,\"scheme\":\"https\","
        "\"tls_policy\":\"pin\",\"certificate_pem\":%s}",
        json_object_to_json_string_ext(pem_json, JSON_C_TO_STRING_PLAIN));
    created = service_call("service_create", pin_fields, 201);
    const char *pinned_id = string(created, "service_id");
    struct json_object *pinned_target = json_object_object_get(created, "target");
    CHECK(!strcmp(string(pinned_target, "tls_policy"), "pin"));
    CHECK(strlen(string(pinned_target, "tls_pin_sha256")) == 44);
    snprintf(pin_fields, sizeof(pin_fields), "\"service_id\":\"%s\",\"confirm\":true", pinned_id);
    json_object_put(created);
    job_id(service_call("service_delete", pin_fields, 202), id);
    json_object_put(wait_job(id, "succeeded"));
    json_object_put(pem_json);
    CHECK(service_call("service_create", "\"name\":\"Bad pin\",\"kind\":\"http\","
        "\"target\":{\"host\":\"192.168.50.20\",\"port\":8080,\"scheme\":\"https\","
        "\"tls_policy\":\"pin\",\"certificate_pem\":\"not a cert\"}", 422) == NULL);
    snprintf(fields, sizeof(fields), "\"service_id\":\"%s\"", sid);
    job_id(service_call("service_probe", fields, 202), id);
    json_object_put(wait_job(id, "succeeded"));
    allow_probe = 0;
    job_id(service_call("service_probe", fields, 202), id);
    struct json_object *job = wait_job(id, "failed");
    CHECK(!strcmp(string(job, "error"), "service_unreachable"));
    json_object_put(job);
    /* A connected transport cannot complete a probe interrupted by restart. */
    pthread_mutex_lock(&control.lock);
    text(control.active, "state", "partial");
    text(control.active, "error", "daemon_restarted");
    pthread_mutex_unlock(&control.lock);
    json_object_put(wait_job(id, "partial"));
    snprintf(fields, sizeof(fields), "\"service_id\":\"%s\",\"enabled\":true", sid);
    job_id(service_call("service_update", fields, 202), id);
    json_object_put(wait_job(id, "failed"));
    allow_probe = 1;
    job_id(service_call("service_update", fields, 202), id);
    json_object_put(wait_job(id, "succeeded"));
    snprintf(fields, sizeof(fields), "{\"revision\":\"%s\",\"service_id\":\"%s\",\"enabled\":false}",
             old_revision, sid);
    CHECK(call("service_update", "user:owner", fields, 409) == NULL);
    snprintf(fields, sizeof(fields), "\"service_id\":\"%s\",\"target\":"
        "{\"host\":\"192.168.50.20\",\"port\":8080,\"scheme\":\"http\"}", sid);
    job_id(service_call("service_update", fields, 202), id);
    job = wait_job(id, "succeeded");
    struct json_object *result = NULL;
    CHECK(json_object_object_get_ex(job, "result", &result) && !boolean(result, "enabled"));
    json_object_put(job);
    job_id(service_call("service_delete", "\"service_id\":\"web\",\"confirm\":true", 202), id);
    json_object_put(wait_job(id, "failed"));
    struct uci_context *u = uci_alloc_context();
    struct uci_package *p = NULL;
    uci_set_confdir(u, CLOUD_BROWSER_CONFIG_DIR);
    CHECK(!uci_load(u, "cloud_web", &p));
    struct uci_section *section = uci_lookup_section(u, p, sid);
    struct uci_ptr ptr = {.p = p, .s = section, .option = "target_host", .value = "invalid"};
    CHECK(!uci_set(u, &ptr) && !uci_commit(u, &p, false));
    uci_free_context(u);
    snprintf(fields, sizeof(fields), "\"service_id\":\"%s\",\"confirm\":true", sid);
    job_id(service_call("service_delete", fields, 202), id);
    json_object_put(wait_job(id, "succeeded"));
    list = call("services", "user:owner", "{}", 200);
    CHECK(json_object_object_get_ex(list, "services", &items) && json_object_array_length(items) == 1);
    json_object_put(list);
}

int main(void)
{
    strcpy(identity.relay_router_id, "router-01234567890123456789012345678901");
    memset(identity.signing_private_key, 7, 32);
    config();
    cloud_browser_start();
    usleep(20000);
    int before = publishes;
    CHECK(call("enable", "user:owner", "{\"confirm\":true}", 409) == NULL);
    CHECK(call("disable", "user:owner", "{\"confirm\":\"true\"}", 409) == NULL);
    CHECK(call("reconnect", "user:owner", "{}", 409) == NULL);
    char id[33], body[180];
    hold_probe = 1;
    job_id(call("preflight", "user:owner", "{}", 202), id);
    int64_t start = cloud_monotonic_ms();
    struct json_object *status = call("status", "user:owner", "{}", 200);
    CHECK(cloud_monotonic_ms() - start < 100);
    CHECK(!boolean(status, "configured_enabled"));
    json_object_put(status);
    CHECK(call("preflight", "user:owner", "{}", 409) == NULL);
    hold_probe = 0;
    json_object_put(wait_job(id, "succeeded"));
    CHECK(publishes == before);
    snprintf(body, sizeof(body), "{\"job_id\":\"%s\"}", id);
    CHECK(call("job", "user:other", body, 404) == NULL);
    snprintf(body, sizeof(body), "{\"confirm\":true,\"preflight_id\":\"%s\"}", id);
    CHECK(call("enable", "user:other", body, 409) == NULL);
    CHECK(call("enable", "user:owner", body, 409) == NULL);
    pthread_mutex_lock(&control.lock);
    control.preflight_until = cloud_monotonic_ms() - 1;
    pthread_mutex_unlock(&control.lock);
    snprintf(body, sizeof(body), "{\"confirm\":true,\"legacy_hostname_ack\":true,\"preflight_id\":\"%s\"}", id);
    CHECK(call("enable", "user:owner", body, 409) == NULL);
    job_id(call("preflight", "user:owner", "{}", 202), id);
    json_object_put(wait_job(id, "succeeded"));
    cloud_version = 2;
    snprintf(body, sizeof(body), "{\"confirm\":true,\"legacy_hostname_ack\":true,\"preflight_id\":\"%s\"}", id);
    job_id(call("enable", "user:owner", body, 202), id);
    json_object_put(wait_job(id, "failed"));
    CHECK(publishes == before);
    cloud_version = 1;
    job_id(call("preflight", "user:owner", "{}", 202), id);
    json_object_put(wait_job(id, "succeeded"));
    FILE *f = fopen(CLOUD_BROWSER_CONFIG_DIR "/cloud_web", "a");
    fputs("# external edit\n", f); fclose(f);
    snprintf(body, sizeof(body), "{\"confirm\":true,\"legacy_hostname_ack\":true,\"preflight_id\":\"%s\"}", id);
    CHECK(call("enable", "user:owner", body, 409) == NULL);
    job_id(call("preflight", "user:owner", "{}", 202), id);
    json_object_put(wait_job(id, "succeeded"));
    snprintf(body, sizeof(body), "{\"confirm\":true,\"legacy_hostname_ack\":true,\"preflight_id\":\"%s\"}", id);
    job_id(call("enable", "user:owner", body, 202), id);
    json_object_put(wait_job(id, "succeeded"));
    status = call("status", "user:owner", "{}", 200);
    CHECK(boolean(status, "configured_enabled"));
    CHECK(boolean(status, "effective_enabled"));
    CHECK(!boolean(status, "ready"));
    json_object_put(status);
    job_id(call("reconnect", "user:owner", "{}", 202), id);
    json_object_put(wait_job(id, "succeeded"));
    test_services();
    int previous = revokes;
    job_id(call("disable", "user:owner", "{\"confirm\":true}", 202), id);
    json_object_put(wait_job(id, "succeeded"));
    CHECK(revokes > previous);
    struct uci_context *u = uci_alloc_context();
    struct uci_package *p;
    uci_set_confdir(u, CLOUD_BROWSER_CONFIG_DIR);
    CHECK(!uci_load(u, "cloud_web", &p));
    struct uci_section *s = uci_lookup_section(u, p, "main");
    CHECK(!strcmp(uci_lookup_option_string(u, s, "enabled"), "0"));
    CHECK(!strcmp(uci_lookup_option_string(u, s, "unrelated"), "preserve-me"));
    uci_free_context(u);
    cloud_browser_stop();
    cloud_browser_start();
    json_object_put(wait_job(id, "succeeded"));
    CHECK(call("enable", "user:owner", body, 409) == NULL);
    allow_probe = 0;
    job_id(call("preflight", "user:owner", "{}", 202), id);
    json_object_put(wait_job(id, "failed"));
    cloud_browser_stop();
    printf("browser control: %d checks passed\n", checks);
    return 0;
}
