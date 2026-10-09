// SPDX-License-Identifier: GPL-2.0-or-later
#include "cloud_internal.h"
#include "cloud_browser.h"
#include "protocol/service_host.h"
#include <openssl/pem.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>

#define SERVICE_CERT_MAX 4096

static int certificate_pin(const char *pem, struct cwc_service *out)
{
    if (strncmp(pem, "-----BEGIN CERTIFICATE-----", 27)) return -1;
    BIO *bio = BIO_new_mem_buf(pem, (int)strlen(pem));
    X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    EVP_PKEY *key = cert ? X509_get_pubkey(cert) : NULL;
    unsigned char *der = NULL, digest[32];
    unsigned int n = 0;
    int length = key ? i2d_PUBKEY(key, &der) : -1, rc = -1;
    char rest[SERVICE_CERT_MAX], hash[65];
    int extra = bio ? BIO_read(bio, rest, sizeof(rest)) : -1;
    if (extra > 0)
        for (int i = 0; i < extra; ++i)
            if (!isspace((unsigned char)rest[i])) goto done;
    if (length <= 0 || !EVP_Digest(der, length, digest, &n, EVP_sha256(), NULL) || n != 32)
        goto done;
    memcpy(out->tls_pin, "sha256//", 8);
    EVP_EncodeBlock((unsigned char *)out->tls_pin + 8, digest, 32);
    if (!EVP_Digest(pem, strlen(pem), digest, &n, EVP_sha256(), NULL) || n != 32) goto done;
    for (int i = 0; i < 32; ++i) snprintf(hash + i * 2, 3, "%02x", digest[i]);
    if (snprintf(out->ca_path, sizeof(out->ca_path), CLOUD_STATE_DIR "/web-cert-%s.pem", hash) >=
        (int)sizeof(out->ca_path)) goto done;
    rc = 0;
done:
    OPENSSL_free(der);
    EVP_PKEY_free(key);
    X509_free(cert);
    BIO_free(bio);
    return rc;
}

static int certificate_store(const char *pem, const char *path)
{
    /* Immutable public trust material; UCI selects it only after durable write. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 && errno == EEXIST) {
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return -1;
        char old[SERVICE_CERT_MAX + 1];
        struct stat st;
        int same = !fstat(fd, &st) && S_ISREG(st.st_mode) &&
            st.st_size == (off_t)strlen(pem) && read(fd, old, sizeof(old)) == st.st_size &&
            !memcmp(old, pem, strlen(pem));
        close(fd);
        return same ? 0 : -1;
    }
    if (fd < 0) return -1;
    size_t length = strlen(pem), written = 0;
    int rc = -1;
    while (written < length) {
        ssize_t n = write(fd, pem + written, length - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        written += n;
    }
    rc = fsync(fd);
done:
    if (close(fd)) rc = -1;
    if (rc) unlink(path);
    return rc;
}

static const char *service_text(struct json_object *o, const char *key, size_t max)
{
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_string))
        return NULL;
    const char *s = json_object_get_string(v);
    size_t n = (size_t)json_object_get_string_len(v);
    if (!n || n > max || strlen(s) != n) return NULL;
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char)s[i] < 32 || s[i] == 127) return NULL;
    return s;
}

static int service_fields(struct json_object *o, const char *const *fields)
{
    if (!json_object_is_type(o, json_type_object)) return 0;
    json_object_object_foreach(o, key, value) {
        (void)value;
        int i;
        for (i = 0; fields[i] && strcmp(key, fields[i]); ++i) {}
        if (!fields[i]) return 0;
    }
    return 1;
}

static struct json_object *service_reply(int status, const char *error,
                                         struct json_object *data)
{
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "ok", json_object_new_boolean(status < 400));
    json_object_object_add(r, "http_status", json_object_new_int(status));
    if (error) json_object_object_add(r, "code", json_object_new_string(error));
    if (data) json_object_object_add(r, "data", data);
    return r;
}

static const char *option(struct uci_context *u, struct uci_section *s, const char *name)
{
    const char *value = uci_lookup_option_string(u, s, name);
    return value ? value : "";
}

static int set_option(struct uci_context *u, struct uci_package *p,
                       struct uci_section *s, const char *name, const char *value)
{
    struct uci_ptr ptr = {.p = p, .s = s, .option = name, .value = value};
    return uci_set(u, &ptr);
}

static int load_service(struct uci_context *u, struct uci_section *s,
                         struct cwc_service *out)
{
    memset(out, 0, sizeof(*out));
    if (strlen(s->e.name) >= sizeof(out->id)) return -1;
    strcpy(out->id, s->e.name);
    const struct cloud_identity *identity = cloud_identity();
    if (!identity) return -1;
    if (!strcmp(option(u, s, "kind"), "management")) {
        out->management = 1;
        snprintf(out->public_host, sizeof(out->public_host), "%s", option(u, s, "public_host"));
        return cwc_service_valid(out) ? 0 : -1;
    }
    if (strcmp(option(u, s, "kind"), "lan") ||
        cw_application_host(identity->relay_router_id, out->id, out->public_host,
                            sizeof(out->public_host)))
        return -1;
    const char *host = option(u, s, "target_host"), *name = option(u, s, "server_name");
    const char *scheme = option(u, s, "scheme"), *port = option(u, s, "port");
    char *end;
    unsigned long n = strtoul(port, &end, 10);
    if (!port[0] || *end || !n || n > 65535 || strlen(host) >= sizeof(out->target_host) ||
        strlen(name) >= sizeof(out->server_name) ||
        (strcmp(scheme, "http") && strcmp(scheme, "https")))
        return -1;
    strcpy(out->target_host, host);
    strcpy(out->server_name, name);
    out->port = (uint16_t)n;
    out->https = !strcmp(scheme, "https");
    /* Per-service arbitrary CA paths are not an HTTP API. Existing local CA
     * configuration remains private and is only consumed by the transport. */
    const char *ca = option(u, s, "ca_path");
    if (strlen(ca) >= sizeof(out->ca_path)) return -1;
    strcpy(out->ca_path, ca);
    const char *pin = option(u, s, "tls_pin");
    if (strlen(pin) >= sizeof(out->tls_pin)) return -1;
    strcpy(out->tls_pin, pin);
    return cwc_service_valid(out) ? 0 : -1;
}

static struct json_object *service_json(struct uci_context *u, struct uci_section *s)
{
    struct cwc_service service;
    int valid = !load_service(u, s, &service);
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "service_id", json_object_new_string(s->e.name));
    const char *name = option(u, s, "name");
    json_object_object_add(o, "name", json_object_new_string(name[0] ? name : s->e.name));
    json_object_object_add(o, "kind", json_object_new_string(
        service.management ? "management" : "http"));
    json_object_object_add(o, "enabled", json_object_new_boolean(!strcmp(option(u, s, "enabled"), "1")));
    json_object_object_add(o, "valid", json_object_new_boolean(valid));
    json_object_object_add(o, "public_host", valid ? json_object_new_string(service.public_host) : NULL);
    json_object_object_add(o, "access_policy", json_object_new_string("owner"));
    if (!service.management) {
        struct json_object *target = json_object_new_object();
        json_object_object_add(target, "host", json_object_new_string(option(u, s, "target_host")));
        json_object_object_add(target, "scheme", json_object_new_string(option(u, s, "scheme")));
        json_object_object_add(target, "port", valid ? json_object_new_int(service.port) : NULL);
        json_object_object_add(target, "server_name", json_object_new_string(option(u, s, "server_name")));
        json_object_object_add(target, "tls_policy",
            json_object_new_string(service.tls_pin[0] ? "pin" : "verify"));
        json_object_object_add(target, "tls_pin_sha256", service.tls_pin[0] ?
            json_object_new_string(service.tls_pin + 8) : NULL);
        json_object_object_add(o, "target", target);
    }
    return o;
}

static int parse_target(struct json_object *target, struct cwc_service *out, const char **certificate)
{
    static const char *const fields[] = {
        "host", "port", "scheme", "server_name", "tls_policy", "certificate_pem", NULL};
    struct json_object *port = NULL, *v = NULL;
    const char *host = service_text(target, "host", 253);
    const char *scheme = service_text(target, "scheme", 5);
    if (!service_fields(target, fields) || !host || !scheme ||
        (strcmp(scheme, "http") && strcmp(scheme, "https")) ||
        !json_object_object_get_ex(target, "port", &port) || !json_object_is_type(port, json_type_int) ||
        json_object_get_int64(port) < 1 || json_object_get_int64(port) > 65535)
        return -1;
    snprintf(out->target_host, sizeof(out->target_host), "%s", host);
    out->port = (uint16_t)json_object_get_int(port);
    out->https = !strcmp(scheme, "https");
    out->server_name[0] = out->ca_path[0] = out->tls_pin[0] = 0;
    int pin = 0;
    if (json_object_object_get_ex(target, "server_name", &v)) {
        if (!json_object_is_type(v, json_type_string)) return -1;
        const char *name = json_object_get_string(v);
        if (strlen(name) != (size_t)json_object_get_string_len(v) ||
            (name[0] && !cwc_host_valid(name)) || strlen(name) >= sizeof(out->server_name))
            return -1;
        strcpy(out->server_name, name);
    }
    if (json_object_object_get_ex(target, "tls_policy", &v)) {
        const char *policy = service_text(target, "tls_policy", 16);
        if (!policy || (strcmp(policy, "verify") && strcmp(policy, "pin"))) return -1;
        pin = !strcmp(policy, "pin");
    }
    if (pin) {
        if (!out->https || !json_object_object_get_ex(target, "certificate_pem", &v) ||
            !json_object_is_type(v, json_type_string)) return -1;
        const char *pem = json_object_get_string(v);
        if (!pem[0] || strlen(pem) > SERVICE_CERT_MAX ||
            strlen(pem) != (size_t)json_object_get_string_len(v) || certificate_pin(pem, out))
            return -1;
        *certificate = pem;
    } else if (json_object_object_get_ex(target, "certificate_pem", &v)) return -1;
    return cwc_service_valid(out) ? 0 : -1;
}

/* The controller serializes this module with enable/disable and validates the
 * caller's config revision before a mutation. Probes run on its worker thread. */
struct json_object *cloud_browser_services(const char *action, struct json_object *request)
{
    static const char *const create_fields[] = {
        "revision", "name", "kind", "target", "enabled", "access_policy", NULL};
    static const char *const update_fields[] = {
        "revision", "service_id", "name", "target", "enabled", "access_policy", NULL};
    static const char *const delete_fields[] = {"revision", "service_id", "confirm", NULL};
    static const char *const probe_fields[] = {"revision", "service_id", NULL};
    struct uci_context *u = uci_alloc_context();
    struct uci_package *p = NULL;
    struct uci_section *section = NULL;
    struct json_object *out = NULL, *target = NULL, *value = NULL, *data = NULL;
    const char *error = "invalid_request", *name = NULL, *certificate = NULL;
    int code = 422, create = !strcmp(action, "service_create"), reload = 0;
    struct cwc_service service = {0};
    if (!u) return service_reply(503, "config_unavailable", NULL);
    uci_set_confdir(u, CLOUD_BROWSER_CONFIG_DIR);
    if (uci_load(u, "cloud_web", &p)) { code = 409; error = "browser_config_invalid"; goto done; }
    if (!strcmp(action, "services")) {
        struct json_object *list = json_object_new_array();
        struct uci_element *e;
        uci_foreach_element(&p->sections, e) {
            struct uci_section *s = uci_to_section(e);
            if (!strcmp(s->type, "service")) json_object_array_add(list, service_json(u, s));
        }
        data = json_object_new_object();
        json_object_object_add(data, "services", list);
        json_object_object_add(data, "service_limit", json_object_new_int(CWC_MAX_SERVICES));
        out = service_reply(200, NULL, data);
        goto done;
    }
    const char *const *fields = create ? create_fields :
        !strcmp(action, "service_update") ? update_fields :
        !strcmp(action, "service_delete") ? delete_fields :
        !strcmp(action, "service_probe") ? probe_fields : NULL;
    if (!fields || !service_fields(request, fields)) goto done;
    if (!create) {
        const char *id = service_text(request, "service_id", 63);
        if (!id || !cw_web_is_service_id(id)) goto done;
        section = uci_lookup_section(u, p, id);
        if (!section || strcmp(section->type, "service")) {
            code = 404; error = "not_found"; goto done;
        }
        if (!strcmp(id, "web") || !strcmp(option(u, section, "kind"), "management")) {
            code = 409; error = "built_in_service"; goto done;
        }
        if (load_service(u, section, &service) &&
            strcmp(action, "service_delete")) { error = "invalid_target"; goto done; }
    }
    if (!strcmp(action, "service_probe")) {
        data = cwc_service_probe(&service);
        struct json_object *reachable = NULL, *why = NULL;
        json_object_object_get_ex(data, "reachable", &reachable);
        json_object_object_get_ex(data, "error", &why);
        out = service_reply(json_object_get_boolean(reachable) ? 200 : 422,
                            why ? json_object_get_string(why) : NULL, data);
        goto done;
    }
    if (!strcmp(action, "service_delete")) {
        if (!json_object_object_get_ex(request, "confirm", &value) ||
            !json_object_is_type(value, json_type_boolean) || !json_object_get_boolean(value)) {
            code = 409; error = "requires_confirm"; goto done;
        }
        reload = !strcmp(option(u, section, "enabled"), "1");
        struct uci_ptr ptr = {.p = p, .s = section};
        if (uci_delete(u, &ptr) || uci_commit(u, &p, false)) goto write_failed;
        data = json_object_new_object();
        json_object_object_add(data, "service_id",
            json_object_new_string(service_text(request, "service_id", 63)));
        json_object_object_add(data, "reload", json_object_new_boolean(reload));
        out = service_reply(200, NULL, data);
        goto done;
    }
    if (json_object_object_get_ex(request, "name", &value) || create) {
        name = service_text(request, "name", 80);
        if (!name) goto done;
    }
    if (json_object_object_get_ex(request, "access_policy", &value)) {
        const char *policy = service_text(request, "access_policy", 16);
        if (!policy || strcmp(policy, "owner")) goto done;
    }
    int enabled = section && !strcmp(option(u, section, "enabled"), "1");
    int was_enabled = enabled;
    int has_enabled = json_object_object_get_ex(request, "enabled", &value);
    if (has_enabled) {
        if (!json_object_is_type(value, json_type_boolean)) goto done;
        enabled = json_object_get_boolean(value);
    }
    if (create) {
        const char *kind = service_text(request, "kind", 16);
        if (!kind || strcmp(kind, "http") || enabled) goto done;
        int count = 0;
        struct uci_element *e;
        uci_foreach_element(&p->sections, e)
            if (!strcmp(uci_to_section(e)->type, "service")) ++count;
        if (count >= CWC_MAX_SERVICES) { code = 429; error = "quota_exceeded"; goto done; }
        unsigned char random[16];
        if (RAND_bytes(random, sizeof(random)) != 1) { code = 503; error = "random_unavailable"; goto done; }
        for (int i = 0; i < 16; ++i) snprintf(service.id + i * 2, 3, "%02x", random[i]);
        if (uci_lookup_section(u, p, service.id)) { code = 409; error = "service_id_conflict"; goto done; }
        const struct cloud_identity *identity = cloud_identity();
        if (!identity || cw_application_host(identity->relay_router_id, service.id,
                service.public_host, sizeof(service.public_host))) goto done;
    }
    int has_target = json_object_object_get_ex(request, "target", &target);
    if ((create && !has_target) || (has_target && parse_target(target, &service, &certificate))) {
        error = "invalid_target"; goto done;
    }
    if (has_target) {
        if (has_enabled && enabled) { error = "target_change_requires_disabled"; goto done; }
        enabled = 0;
    }
    if (!create && !name && !has_target && !has_enabled) goto done;
    if (enabled && !was_enabled) {
        struct json_object *probe = cwc_service_probe(&service);
        struct json_object *reachable = NULL, *why = NULL;
        json_object_object_get_ex(probe, "reachable", &reachable);
        if (!json_object_get_boolean(reachable)) {
            json_object_object_get_ex(probe, "error", &why);
            out = service_reply(422, why ? json_object_get_string(why) : "service_unreachable", probe);
            goto done;
        }
        json_object_put(probe);
    }
    if (certificate && certificate_store(certificate, service.ca_path)) goto write_failed;
    if (create) {
        struct uci_ptr ptr = {.p = p, .section = service.id, .value = "service"};
        if (uci_set(u, &ptr)) goto write_failed;
        section = uci_lookup_section(u, p, service.id);
        if (!section) goto write_failed;
    }
    if (name && set_option(u, p, section, "name", name)) goto write_failed;
    if (set_option(u, p, section, "kind", "lan") ||
        set_option(u, p, section, "public_host", service.public_host) ||
        set_option(u, p, section, "enabled", enabled ? "1" : "0")) goto write_failed;
    if (has_target) {
        char port[8];
        snprintf(port, sizeof(port), "%u", service.port);
        if (set_option(u, p, section, "target_host", service.target_host) ||
            set_option(u, p, section, "server_name", service.server_name) ||
            set_option(u, p, section, "port", port) ||
            set_option(u, p, section, "scheme", service.https ? "https" : "http") ||
            set_option(u, p, section, "ca_path", service.ca_path) ||
            set_option(u, p, section, "tls_pin", service.tls_pin)) goto write_failed;
    }
    if (uci_commit(u, &p, false)) goto write_failed;
    section = uci_lookup_section(u, p, service.id);
    data = service_json(u, section);
    reload = !create && (was_enabled != enabled || (has_target && was_enabled));
    json_object_object_add(data, "reload", json_object_new_boolean(reload));
    out = service_reply(create ? 201 : 200, NULL, data);
    goto done;
write_failed:
    code = 503; error = "config_write_failed";
done:
    uci_free_context(u);
    return out ? out : service_reply(code, error, NULL);
}
