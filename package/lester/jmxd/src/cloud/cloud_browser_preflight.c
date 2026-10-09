// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "cloud_browser.h"
#include <curl/curl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#ifndef CLOUD_BROWSER_HTTPS_PORT
#define CLOUD_BROWSER_HTTPS_PORT 443
#endif

static void text(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, value && value[0] ? json_object_new_string(value) : NULL);
}

static void check(struct json_object *checks, const char *name, int ok, const char *reason)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "passed", json_object_new_boolean(ok));
    text(o, "reason", reason);
    json_object_object_add(checks, name, o);
}

static int same_address(const struct sockaddr *a, const struct sockaddr *b)
{
    if (!a || !b || a->sa_family != b->sa_family) return 0;
    if (a->sa_family == AF_INET)
        return !memcmp(&((const struct sockaddr_in *)a)->sin_addr,
                       &((const struct sockaddr_in *)b)->sin_addr, sizeof(struct in_addr));
    if (a->sa_family == AF_INET6)
        return !memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
                       &((const struct sockaddr_in6 *)b)->sin6_addr, sizeof(struct in6_addr));
    return 0;
}

static int local_dns(const char *host)
{
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *addresses = NULL;
    struct ifaddrs *interfaces = NULL;
    int ok = 0;
    if (getaddrinfo(host, NULL, &hints, &addresses) || getifaddrs(&interfaces))
        goto done;
    ok = addresses != NULL;
    for (struct addrinfo *a = addresses; a; a = a->ai_next) {
        int found = 0;
        for (struct ifaddrs *i = interfaces; i; i = i->ifa_next)
            if (same_address(a->ai_addr, i->ifa_addr)) found = 1;
        if (!found) ok = 0;
    }
done:
    if (addresses) freeaddrinfo(addresses);
    if (interfaces) freeifaddrs(interfaces);
    return ok;
}

struct probe_body {
    char text[4096];
    size_t length;
};

static size_t probe_write(char *p, size_t size, size_t count, void *user)
{
    struct probe_body *body = user;
    if (size && count > (sizeof(body->text) - 1 - body->length) / size) return 0;
    size_t n = size * count;
    memcpy(body->text + body->length, p, n);
    body->length += n;
    return n;
}

static int tls_probe(const char *host, unsigned port, const char *ca, int local)
{
    CURL *curl = curl_easy_init();
    struct curl_slist *resolve = NULL;
    char url[320], mapping[320];
    long status = 0;
    int ok = 0;
    struct probe_body body = {0};
    if (!curl) return 0;
    snprintf(url, sizeof(url), "https://%s:%u%s", host, port,
             local == 2 ? "/api/v1/passkey/can-authenticate" : local ? "/app/" : "");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (ca && ca[0]) curl_easy_setopt(curl, CURLOPT_CAINFO, ca);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 8000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (local) {
        snprintf(mapping, sizeof(mapping), "%s:%u:127.0.0.1", host, port);
        resolve = curl_slist_append(NULL, mapping);
        if (!resolve) goto done;
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
        curl_easy_setopt(curl, CURLOPT_NOBODY, local == 1 ? 1L : 0L);
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, probe_write);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    } else {
        /* TLS only: no HELLO, registration or takeover of an existing tunnel. */
        curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    }
    if (curl_easy_perform(curl) != CURLE_OK) goto done;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    ok = !local || status == 200;
    if (ok && local == 2) {
        struct json_object *root = json_tokener_parse(body.text), *rp = NULL;
        ok = root && json_object_object_get_ex(root, "rp_id", &rp) &&
             json_object_is_type(rp, json_type_string) &&
             !strcmp(json_object_get_string(rp), host);
        if (root) json_object_put(root);
    }
done:
    curl_slist_free_all(resolve);
    curl_easy_cleanup(curl);
    return ok;
}

struct json_object *cloud_browser_preflight(const struct cwc_config *config)
{
    struct json_object *result = json_object_new_object();
    struct json_object *checks = json_object_new_object();
    struct cwc_publication publication;
    int allowed = 1, web = -1;
    json_object_object_add(result, "checks", checks);
    int bound = !cwc_publication_read(config, &publication);
    check(checks, "binding", bound, bound ? "" : publication.error);
    allowed &= bound;
    for (int i = 0; i < config->n_services; ++i)
        if (config->services[i].management && !strcmp(config->services[i].id, "web"))
            web = i;
    int supported = web >= 0;
    struct json_object *services = json_object_new_object();
    for (int i = 0; i < config->n_services; ++i) {
        if (i == web) continue;
        struct json_object *probe = cwc_service_probe(&config->services[i]), *reachable = NULL;
        json_object_object_get_ex(probe, "reachable", &reachable);
        supported &= json_object_get_boolean(reachable);
        json_object_object_add(services, config->services[i].id, probe);
    }
    json_object_object_add(result, "services", services);
    check(checks, "services", supported, supported ? "" :
          web < 0 ? "management_service_required" : "service_unreachable");
    allowed &= supported;
    if (bound) {
        struct json_object *transfer = cwc_transfer_json(&publication);
        json_object_object_add(result, "transfer", transfer);
        if (publication.quota_known) {
            int64_t next = publication.account_services - publication.device_services + config->n_services;
            int quota = !publication.account_service_limit ||
                next <= publication.account_service_limit || next <= publication.account_services;
            check(checks, "account_quota", quota, quota ? "" : "service_quota_exceeded");
            allowed &= quota;
        }
        text(result, "cloud_id", publication.cloud_id);
        text(result, "canonical_host", publication.canonical_host);
        json_object_object_add(result, "generation", json_object_new_int64(publication.generation));
        json_object_object_add(result, "cloud_revision", json_object_new_int64(publication.revision));
        char expected[300];
        snprintf(expected, sizeof(expected), "%s.dev.dreamingnet.com", publication.cloud_id);
        json_object_object_add(result, "legacy_hostname",
            json_object_new_boolean(strcmp(expected, publication.canonical_host) != 0));
    }
    const char *host = web >= 0 ? config->services[web].public_host : "";
    const char *local_ca = web >= 0 ? config->services[web].ca_path : "";
    int matches = bound && host[0] && !strcmp(host, publication.canonical_host) &&
                  tls_probe(host, CLOUD_BROWSER_HTTPS_PORT, local_ca, 2);
    check(checks, "domain", matches, matches ? "" : "identity_migration_required");
    allowed &= matches;
    int dns = host[0] && local_dns(host);
    check(checks, "device_dns", dns, dns ? "" : "local_dns_unverified");
    allowed &= dns;
    int local = host[0] && tls_probe(host, CLOUD_BROWSER_HTTPS_PORT, local_ca, 1);
    check(checks, "local_https", local, local ? "" : "local_https_unavailable");
    allowed &= local;
    int tunnel = tls_probe(config->tunnel_host, config->tunnel_port, config->ca_path, 0);
    check(checks, "gateway_tls", tunnel, tunnel ? "" : "gateway_unavailable");
    allowed &= tunnel;
    json_object_object_add(result, "enable_allowed", json_object_new_boolean(allowed));
    json_object_object_add(result, "client_dns_verified", json_object_new_boolean(0));
    json_object_object_add(result, "public_route_verified", json_object_new_boolean(0));
    text(result, "quota_state", bound && publication.quota_known ? "enforced" : "unknown");
    text(result, "scope", "device_preflight");
    return result;
}
