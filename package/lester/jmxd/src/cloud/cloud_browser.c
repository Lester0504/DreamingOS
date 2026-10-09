// SPDX-License-Identifier: GPL-2.0-or-later
#include "cloud_internal.h"
#include "cloud_web_client.h"
#include "cloud_browser.h"
#include "protocol/service_host.h"
#include <pthread.h>
#include <curl/curl.h>

static struct {
    pthread_mutex_t lock;
    pthread_t thread;
    int started, running, enabled, desired, services;
    uint32_t generation;
    int64_t revision;
    char state[32], reason[160];
    struct cwc_config config;
    struct cwc_publication publication;
} browser = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = "disabled"
};

static const char *browser_option(struct uci_context *u, struct uci_section *s,
                                   const char *key)
{
    const char *value = uci_lookup_option_string(u, s, key);
    return value ? value : "";
}

static int browser_string(char *out, size_t cap, const char *value)
{
    if (strlen(value) >= cap)
        return -1;
    strcpy(out, value);
    return 0;
}

static int browser_port(const char *value, uint16_t *port)
{
    char *end;
    unsigned long n = strtoul(value, &end, 10);
    if (!value[0] || *end || !n || n > 65535)
        return -1;
    *port = (uint16_t)n;
    return 0;
}

int cloud_browser_load(struct cwc_config *c, int *enabled, int full)
{
    struct uci_context *u = uci_alloc_context();
    struct uci_package *p = NULL;
    struct uci_section *main = NULL;
    struct uci_element *e;
    int rc = -1;
    *enabled = 0;
    memset(c, 0, sizeof(*c));
    if (!u)
        return -1;
    uci_set_confdir(u, CLOUD_BROWSER_CONFIG_DIR);
    if (uci_load(u, "cloud_web", &p)) {
        rc = u->err == UCI_ERR_NOTFOUND ? 0 : -1;
        goto done;
    }
    uci_foreach_element(&p->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!strcmp(s->type, "browser")) {
            if (main)
                goto done;
            main = s;
        }
    }
    if (!main)
        goto done;
    *enabled = !strcmp(browser_option(u, main, "enabled"), "1");
    if (!full && !*enabled && !browser_option(u, main, "api_host")[0]) {
        rc = 0;
        goto done;
    }
    if (browser_string(c->api_host, sizeof(c->api_host),
                       browser_option(u, main, "api_host")) ||
        !cwc_host_valid(c->api_host) ||
        browser_port(browser_option(u, main, "api_port"), &c->api_port) ||
        browser_string(c->ca_path, sizeof(c->ca_path),
                       browser_option(u, main, "ca_path")))
        goto done;
    if ((full || *enabled) && (browser_string(c->tunnel_host, sizeof(c->tunnel_host),
                       browser_option(u, main, "tunnel_host")) ||
        browser_port(browser_option(u, main, "tunnel_port"), &c->tunnel_port) ||
        cloud_base64_decode_fixed(browser_option(u, main, "services_key"),
                                    c->services_key, 32)))
        goto done;
    snprintf(c->state_path, sizeof(c->state_path), CLOUD_STATE_DIR "/web-manifest-state");
    const struct cloud_identity *identity = cloud_identity();
    if (!identity || strlen(identity->relay_router_id) != 39)
        goto done;
    strcpy(c->router_id, identity->relay_router_id);
    memcpy(c->kex_pub, identity->public_key, 32);
    c->sign_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                              identity->signing_private_key, 32);
    if (!c->sign_key)
        goto done;
    uci_foreach_element(&p->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!full && !*enabled) break;
        if (strcmp(s->type, "service") || strcmp(browser_option(u, s, "enabled"), "1"))
            continue;
        if (c->n_services == CWC_MAX_SERVICES)
            goto done;
        struct cwc_service *service = &c->services[c->n_services];
        if (browser_string(service->id, sizeof(service->id), s->e.name) ||
            browser_string(service->public_host, sizeof(service->public_host),
                           browser_option(u, s, "public_host")) ||
            browser_string(service->target_host, sizeof(service->target_host),
                           browser_option(u, s, "target_host")) ||
            browser_string(service->server_name, sizeof(service->server_name),
                           browser_option(u, s, "server_name")) ||
            browser_string(service->ca_path, sizeof(service->ca_path),
                           browser_option(u, s, "ca_path")) ||
            browser_string(service->tls_pin, sizeof(service->tls_pin),
                           browser_option(u, s, "tls_pin")))
            goto done;
        const char *kind = browser_option(u, s, "kind");
        service->management = !strcmp(kind, "management");
        service->container = !strcmp(kind, "container");
        if (!service->management && !service->container && strcmp(kind, "lan"))
            goto done;
        const char *scheme = browser_option(u, s, "scheme");
        if (!service->management) {
            if (strcmp(scheme, "http") && strcmp(scheme, "https"))
                goto done;
            service->https = !strcmp(scheme, "https");
            if (browser_port(browser_option(u, s, "port"), &service->port))
                goto done;
            if (cw_application_host(c->router_id, service->id, service->public_host,
                                     sizeof(service->public_host)))
                goto done;
        }
        if (!cwc_service_valid(service))
            goto done;
        ++c->n_services;
    }
    rc = (!full && !*enabled) || cwc_host_valid(c->tunnel_host) ? 0 : -1;
done:
    uci_free_context(u);
    if (rc) {
        EVP_PKEY_free(c->sign_key);
        c->sign_key = NULL;
    }
    return rc;
}

static int browser_running(void *user)
{
    (void)user;
    pthread_mutex_lock(&browser.lock);
    int running = browser.running;
    pthread_mutex_unlock(&browser.lock);
    return running;
}

static void browser_status(void *user, const char *state, const char *reason,
                            uint32_t generation, int64_t revision, int services)
{
    (void)user;
    pthread_mutex_lock(&browser.lock);
    snprintf(browser.state, sizeof(browser.state), "%s", state);
    snprintf(browser.reason, sizeof(browser.reason), "%s", reason);
    browser.generation = generation;
    browser.revision = revision;
    browser.services = services;
    pthread_mutex_unlock(&browser.lock);
    fprintf(stderr, "[dreamingos-cloud] browser state=%s reason=%s generation=%u revision=%lld services=%d\n",
            state, reason, generation, (long long)revision, services);
}

static void browser_publication(void *user, const struct cwc_publication *result)
{
    (void)user;
    pthread_mutex_lock(&browser.lock);
    if (result) browser.publication = *result;
    else memset(&browser.publication, 0, sizeof(browser.publication));
    pthread_mutex_unlock(&browser.lock);
}

static void *browser_thread(void *user)
{
    (void)user;
    struct cwc_hooks hooks = {.running = browser_running, .status = browser_status,
                              .publication = browser_publication};
    browser_publication(NULL, NULL);
    if (!browser.enabled) {
        browser_status(NULL, "revoking", "", 0, 0, 0);
        while (browser_running(NULL)) {
            struct cwc_publication result;
            if (!cwc_publish(&browser.config, 0, &result)) {
                browser_publication(NULL, &result);
                browser_status(NULL, "disabled", "", result.generation, result.revision, 0);
                return NULL;
            }
            if (!strcmp(result.error, "binding_required")) {
                browser_status(NULL, "disabled", "", 0, 0, 0);
                return NULL;
            }
            browser_status(NULL, "revoking", result.error, 0, 0, 0);
            int delay = result.retry_after ? result.retry_after : 5;
            for (int i = 0; i < delay * 10 && browser_running(NULL); ++i)
                usleep(100000);
        }
        return NULL;
    }
    if (cwc_run(&browser.config, &hooks))
        browser_status(NULL, "error", "browser_client_failed", 0, 0, 0);
    return NULL;
}

void cloud_browser_transport_start(void)
{
    int enabled = 0;
    int rc = cloud_browser_load(&browser.config, &enabled, 0);
    pthread_mutex_lock(&browser.lock);
    browser.enabled = browser.desired = enabled;
    pthread_mutex_unlock(&browser.lock);
    if (rc) {
        browser_status(NULL, "error", "browser_config_invalid", 0, 0, 0);
        return;
    }
    if (!enabled && !browser.config.api_host[0]) {
        browser_status(NULL, "disabled", "", 0, 0, 0);
        return;
    }
    pthread_mutex_lock(&browser.lock);
    browser.running = 1;
    pthread_mutex_unlock(&browser.lock);
    browser_status(NULL, enabled ? "connecting" : "revoking", "", 0, 0, 0);
    if (pthread_create(&browser.thread, NULL, browser_thread, NULL)) {
        browser_status(NULL, "error", "browser_thread_failed", 0, 0, 0);
        EVP_PKEY_free(browser.config.sign_key);
        browser.config.sign_key = NULL;
        return;
    }
    browser.started = 1;
}

void cloud_browser_transport_stop(void)
{
    pthread_mutex_lock(&browser.lock);
    browser.running = 0;
    pthread_mutex_unlock(&browser.lock);
    if (browser.started) {
        pthread_join(browser.thread, NULL);
        browser.started = 0;
    }
    EVP_PKEY_free(browser.config.sign_key);
    browser.config.sign_key = NULL;
}

void cloud_browser_start(void)
{
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        browser_status(NULL, "error", "browser_curl_init_failed", 0, 0, 0);
        return;
    }
    cloud_browser_transport_start();
    cloud_browser_control_start();
}

void cloud_browser_stop(void)
{
    cloud_browser_control_stop();
    cloud_browser_transport_stop();
}

void cloud_browser_configured(int enabled)
{
    pthread_mutex_lock(&browser.lock);
    browser.desired = enabled;
    pthread_mutex_unlock(&browser.lock);
}

struct json_object *cloud_browser_status_json(void)
{
    struct json_object *result = json_object_new_object();
    pthread_mutex_lock(&browser.lock);
    const char *state = browser.state;
    if (!browser.desired && browser.enabled) state = "revoking";
    if (browser.desired && !browser.enabled) state = "provisioning";
    json_object_object_add(result, "configured_enabled", json_object_new_boolean(browser.desired));
    json_object_object_add(result, "state", json_object_new_string(state));
    json_object_object_add(result, "last_error", json_object_new_string(browser.reason));
    json_object_object_add(result, "generation", json_object_new_int64(browser.generation));
    json_object_object_add(result, "revision", json_object_new_int64(browser.revision));
    json_object_object_add(result, "authorized_services", json_object_new_int(
        browser.desired ? browser.services : 0));
    struct json_object *transfer = cwc_transfer_json(&browser.publication);
    json_object_object_foreach(transfer, key, value)
        json_object_object_add(result, key, json_object_get(value));
    json_object_put(transfer);
    json_object_object_add(result, "transport", json_object_new_string("cloud-web-v1"));
    pthread_mutex_unlock(&browser.lock);
    return result;
}
