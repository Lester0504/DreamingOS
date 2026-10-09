// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "api_cloud_domain.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <uci.h>
#include <unistd.h>

#define DOMAIN_HOSTS_MAX (256U * 1024U)
#define DOMAIN_SOURCES_MAX 16
#define DOMAIN_INSTANCES_MAX 8
#define DOMAIN_ENTRIES_MAX 64

static FILE *open_regular(const char *path, size_t limit, const char **state)
{
    struct stat st;
    FILE *file;
    int fd = path && path[0] == '/' ?
        open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC) : -1;

    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        *state = "unsupported_source";
        close(fd);
        return NULL;
    }
    if (st.st_size < 0 || (uint64_t)st.st_size > limit) {
        *state = "limit_exceeded";
        close(fd);
        return NULL;
    }
    file = fdopen(fd, "r");
    if (!file)
        close(fd);
    return file;
}

static void text(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, value && value[0] ?
                           json_object_new_string(value) : NULL);
}

static void boolean(struct json_object *o, const char *key, int value)
{
    json_object_object_add(o, key, json_object_new_boolean(value));
}

static struct uci_package *load(struct uci_context *uci, const char *name,
                                struct json_object *errors)
{
    struct uci_package *package = NULL;

    if (uci_load(uci, name, &package) != UCI_OK) {
        json_object_array_add(errors, json_object_new_string(name));
        return NULL;
    }
    return package;
}

static struct uci_section *first(struct uci_package *package, const char *type)
{
    struct uci_element *e;

    if (package)
        uci_foreach_element(&package->sections, e) {
            struct uci_section *section = uci_to_section(e);
            if (!strcmp(section->type, type))
                return section;
        }
    return NULL;
}

static const char *option(struct uci_context *uci, struct uci_section *section,
                           const char *key)
{
    return section ? uci_lookup_option_string(uci, section, key) : NULL;
}

static int enabled(const char *value)
{
    return value && (!strcmp(value, "1") || !strcasecmp(value, "true") ||
                     !strcasecmp(value, "yes") || !strcasecmp(value, "on"));
}

static int normalize_host(const char *value, char out[254])
{
    size_t n = value ? strlen(value) : 0;
    size_t label = 0;

    if (n && value[n - 1] == '.')
        n--;
    if (!n || n > 253)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c == '.') {
            if (!label || value[i - 1] == '-')
                return 0;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-') ||
                (!label && c == '-') || ++label > 63)
                return 0;
        }
        out[i] = (char)tolower(c);
    }
    if (!label || value[n - 1] == '-')
        return 0;
    out[n] = '\0';
    return 1;
}

static int address_family(const char *value)
{
    unsigned char address[16];
    if (value && inet_pton(AF_INET, value, address) == 1)
        return 4;
    if (value && inet_pton(AF_INET6, value, address) == 1)
        return 6;
    return 0;
}

static struct json_object *hosts_snapshot(const char *path, const char *domain)
{
    struct json_object *o = json_object_new_object();
    struct json_object *entries = json_object_new_array();
    FILE *file = NULL;
    char line[2048];
    size_t total = 0;
    const char *state = "unavailable";

    text(o, "path", path);
    json_object_object_add(o, "entries", entries);
    /* An addn-hosts file may be arbitrary local configuration. Only exact
     * hostname matches are returned, never its other names or raw contents. */
    file = open_regular(path, DOMAIN_HOSTS_MAX, &state);
    if (!file)
        goto done;
    state = "read";
    while (fgets(line, sizeof(line), file)) {
        char *save = NULL;
        char *address;
        char *name;
        char *comment;
        int family;
        total += strlen(line);
        if (total > DOMAIN_HOSTS_MAX ||
            (!strchr(line, '\n') && !feof(file) &&
             strlen(line) == sizeof(line) - 1)) {
            state = "limit_exceeded";
            break;
        }
        comment = strchr(line, '#');
        if (comment)
            *comment = '\0';
        address = strtok_r(line, " \t\r\n", &save);
        family = address_family(address);
        if (!family)
            continue;
        while ((name = strtok_r(NULL, " \t\r\n", &save))) {
            char normalized[254];
            if (!normalize_host(name, normalized) || strcmp(normalized, domain))
                continue;
            if (json_object_array_length(entries) >= DOMAIN_ENTRIES_MAX) {
                state = "limit_exceeded";
                goto done;
            }
            struct json_object *entry = json_object_new_object();
            text(entry, "address", address);
            json_object_object_add(entry, "family", json_object_new_int(family));
            json_object_array_add(entries, entry);
            break;
        }
    }
    if (ferror(file))
        state = "read_failed";
done:
    if (file)
        fclose(file);
    text(o, "state", state);
    return o;
}

static void add_host_source(struct json_object *sources, const char *path,
                            const char *domain, int *truncated)
{
    if (json_object_array_length(sources) >= DOMAIN_SOURCES_MAX) {
        *truncated = 1;
        return;
    }
    json_object_array_add(sources, hosts_snapshot(path, domain));
}

static int has_value(struct uci_option *option, const char *value)
{
    struct uci_element *e;
    if (!option || !value || !value[0])
        return 0;
    if (option->type == UCI_TYPE_STRING)
        return !strcmp(option->v.string, value);
    if (option->type == UCI_TYPE_LIST)
        uci_foreach_element(&option->v.list, e)
            if (!strcmp(e->name, value))
                return 1;
    return 0;
}

static struct json_object *dns_snapshot(struct uci_context *uci,
                                        struct uci_package *dhcp,
                                        const char *hosts_path,
                                        const char *domain,
                                        const char *managed_rule)
{
    struct json_object *o = json_object_new_object();
    struct json_object *instances = json_object_new_array();
    struct uci_element *e;
    int truncated = 0;

    text(o, "state", "unverified");
    boolean(o, "client_verified", 0);
    boolean(o, "runtime_verified", 0);
    text(o, "configuration_source", "uci.dhcp");
    text(o, "managed_address_rule", managed_rule);
    text(o, "managed_rule_source", "uci.system.console_domain_address");
    json_object_object_add(o, "instances", instances);
    if (dhcp)
        uci_foreach_element(&dhcp->sections, e) {
            struct uci_section *section = uci_to_section(e);
            struct uci_option *additional;
            struct json_object *instance;
            struct json_object *sources;
            const char *port;
            int nohosts;

            if (strcmp(section->type, "dnsmasq"))
                continue;
            if (json_object_array_length(instances) >= DOMAIN_INSTANCES_MAX) {
                truncated = 1;
                break;
            }
            instance = json_object_new_object();
            sources = json_object_new_array();
            nohosts = enabled(option(uci, section, "nohosts"));
            text(instance, "section", section->e.name);
            boolean(instance, "reads_system_hosts", !nohosts);
            port = option(uci, section, "port");
            text(instance, "configured_port", port ? port : "53");
            json_object_object_add(instance, "managed_rule_present",
                managed_rule && managed_rule[0] ? json_object_new_boolean(
                    has_value(uci_lookup_option(uci, section, "address"), managed_rule)) : NULL);
            json_object_object_add(instance, "host_sources", sources);
            json_object_array_add(instances, instance);
            if (!nohosts)
                add_host_source(sources, hosts_path, domain, &truncated);
            additional = uci_lookup_option(uci, section, "addnhosts");
            if (additional && additional->type == UCI_TYPE_STRING)
                add_host_source(sources, additional->v.string, domain, &truncated);
            else if (additional && additional->type == UCI_TYPE_LIST) {
                struct uci_element *item;
                uci_foreach_element(&additional->v.list, item)
                    add_host_source(sources, item->name, domain, &truncated);
            }
        }
    boolean(o, "truncated", truncated);
    return o;
}

static int64_t epoch(const ASN1_TIME *value)
{
    struct tm tm = {0};
    return value && ASN1_TIME_to_tm(value, &tm) == 1 ?
        (int64_t)timegm(&tm) : 0;
}

static struct json_object *certificate_snapshot(const char *path,
                                                 const char *domain)
{
    struct json_object *o = json_object_new_object();
    FILE *file;
    X509 *cert = NULL;
    const char *state = "missing";
    int64_t before = 0, after = 0, now = (int64_t)time(NULL);

    text(o, "source", path);
    json_object_object_add(o, "browser_trusted", NULL);
    json_object_object_add(o, "served_by_listener", NULL);
    json_object_object_add(o, "hostname_matches", NULL);
    file = open_regular(path, 1024 * 1024, &state);
    if (file) {
        state = "malformed";
        cert = PEM_read_X509(file, NULL, NULL, NULL);
        fclose(file);
    }
    if (cert) {
        before = epoch(X509_get0_notBefore(cert));
        after = epoch(X509_get0_notAfter(cert));
        int matches = domain[0] && X509_check_host(cert, domain, 0,
            X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
            NULL) == 1;
        if (domain[0])
            boolean(o, "hostname_matches", matches);
        if (after <= before || !before)
            state = "malformed";
        else if (now < before)
            state = "not_yet_valid";
        else if (now >= after)
            state = "expired";
        else if (!domain[0])
            state = "domain_unconfigured";
        else
            state = matches ? "time_valid" : "hostname_mismatch";
    }
    text(o, "state", state);
    json_object_object_add(o, "not_before", before > 0 ?
                           json_object_new_int64(before) : NULL);
    json_object_object_add(o, "not_after", after > 0 ?
                           json_object_new_int64(after) : NULL);
    X509_free(cert);
    return o;
}

struct json_object *webd_cloud_domain_snapshot(struct uci_context *uci,
                                              const char *rp_id,
                                              const char *hosts_path,
                                              const char *certificate_path)
{
    struct json_object *o, *errors, *passkey, *certificate, *addresses;
    struct uci_package *system, *network, *dhcp, *relay;
    struct uci_section *lan, *cert;
    const char *value, *renewal_path;
    char domain[254] = "";
    struct stat installed, renewal;

    if (!uci || !hosts_path || !certificate_path)
        return NULL;
    o = json_object_new_object();
    errors = json_object_new_array();
    passkey = json_object_new_object();
    addresses = json_object_new_array();
    system = load(uci, "system", errors);
    network = load(uci, "network", errors);
    dhcp = load(uci, "dhcp", errors);
    relay = load(uci, "relay", errors);
    value = option(uci, first(system, "system"), "console_domain");
    if (!normalize_host(value, domain))
        domain[0] = '\0';
    text(o, "contract_version", "cloud-local-domain.v1");
    text(o, "domain", domain);
    text(o, "domain_state", domain[0] ? "configured" :
         value && value[0] ? "invalid" : "unconfigured");
    text(passkey, "rp_id", rp_id);
    json_object_object_add(passkey, "matches_domain", domain[0] && rp_id && rp_id[0] ?
                           json_object_new_boolean(!strcasecmp(domain, rp_id)) : NULL);
    json_object_object_add(o, "passkey", passkey);
    lan = network ? uci_lookup_section(uci, network, "lan") : NULL;
    const char *keys[] = { "ipaddr", "ip6addr" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        struct uci_option *a = lan ? uci_lookup_option(uci, lan, keys[i]) : NULL;
        if (a && a->type == UCI_TYPE_STRING)
            json_object_array_add(addresses, json_object_new_string(a->v.string));
        else if (a && a->type == UCI_TYPE_LIST) {
            struct uci_element *e;
            uci_foreach_element(&a->v.list, e) {
                if (json_object_array_length(addresses) >= DOMAIN_ENTRIES_MAX)
                    break;
                json_object_array_add(addresses, json_object_new_string(e->name));
            }
        }
    }
    json_object_object_add(o, "configured_lan_addresses", addresses);
    text(o, "lan_address_source", "uci.network.lan");
    json_object_object_add(o, "runtime_lan_addresses", NULL);
    json_object_object_add(o, "local_dns", dns_snapshot(uci, dhcp, hosts_path, domain,
        option(uci, first(system, "system"), "console_domain_address")));
    certificate = certificate_snapshot(certificate_path, domain);
    cert = relay ? uci_lookup_section(uci, relay, "cert") : NULL;
    json_object_object_add(certificate, "renewal_enabled", relay ?
        json_object_new_boolean(enabled(option(uci, cert, "enabled"))) : NULL);
    renewal_path = option(uci, cert, "fullchain_path");
    text(certificate, "renewal_certificate_path", renewal_path);
    json_object_object_add(certificate, "renewal_targets_console", NULL);
    if (renewal_path && stat(certificate_path, &installed) == 0 &&
        stat(renewal_path, &renewal) == 0)
        boolean(certificate, "renewal_targets_console",
                installed.st_dev == renewal.st_dev && installed.st_ino == renewal.st_ino);
    json_object_object_add(o, "certificate", certificate);
    json_object_object_add(o, "unavailable_config_packages", errors);
    if (system) uci_unload(uci, system);
    if (network) uci_unload(uci, network);
    if (dhcp) uci_unload(uci, dhcp);
    if (relay) uci_unload(uci, relay);
    return o;
}

/* Managed DNS mapping. This owns one hosts file and its addnhosts references;
 * it never regenerates /etc/hosts, changes the LAN address, RP, or TLS keys. */
#include <errno.h>
#include <stdlib.h>
#include <openssl/sha.h>

static const char *domain_string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) &&
        json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
}

static char *domain_read(const char *path, int optional)
{
    const char *state = "missing";
    FILE *f = open_regular(path, DOMAIN_HOSTS_MAX, &state);
    if (!f) return optional && errno == ENOENT ? strdup("") : NULL;
    char *data = calloc(DOMAIN_HOSTS_MAX + 1, 1);
    if (!data) { fclose(f); return NULL; }
    size_t size = fread(data, 1, DOMAIN_HOSTS_MAX, f);
    int bad = ferror(f) || memchr(data, 0, size);
    fclose(f);
    if (bad) { free(data); return NULL; }
    return data;
}

int webd_cloud_domain_write_atomic(const char *path, const char *data, unsigned mode)
{
    char temporary[1024];
    if (snprintf(temporary, sizeof(temporary), "%s.new-XXXXXX", path) >= (int)sizeof(temporary)) return -1;
    int fd = mkstemp(temporary), rc = -1;
    if (fd < 0) return -1;
    size_t length = strlen(data), offset = 0;
    if (fchmod(fd, mode)) goto done;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) goto done;
        offset += (size_t)written;
    }
    if (fsync(fd)) goto done;
    if (close(fd)) { fd = -1; goto done; }
    fd = -1;
    if (rename(temporary, path)) goto done;
    rc = 0;
done:
    if (fd >= 0) close(fd);
    if (rc) unlink(temporary);
    return rc;
}

static int domain_configuration_digest(const char *dhcp, const char *hosts, char out[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char bytes[32]; unsigned length = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, dhcp, strlen(dhcp)+1) == 1 &&
        EVP_DigestUpdate(ctx, hosts, strlen(hosts)+1) == 1 &&
        EVP_DigestFinal_ex(ctx, bytes, &length) == 1 && length == 32;
    EVP_MD_CTX_free(ctx);
    if (ok) for (size_t i = 0; i < 32; i++) snprintf(out+2*i, 3, "%02x", bytes[i]);
    return ok;
}

struct json_object *webd_cloud_domain_plan(struct json_object *snapshot,
    const char *mode, const struct webd_cloud_domain_paths *paths)
{
    struct json_object *plan = json_object_new_object(), *addresses = NULL, *passkey = NULL;
    struct json_object *records = json_object_new_array(), *local = NULL;
    const char *domain = domain_string(snapshot, "domain");
    const char *reason = NULL;
    char normalized[254];
    int domain_valid = snapshot && normalize_host(domain, normalized);
    if (!domain_valid) reason = "local_domain_unconfigured";
    json_object_object_get_ex(snapshot, "passkey", &passkey);
    if (!reason && strcmp(domain_string(passkey, "rp_id"), domain)) reason = "identity_migration_required";
    json_object_object_get_ex(snapshot, "configured_lan_addresses", &addresses);
    for (size_t i = 0; domain_valid && addresses && i < json_object_array_length(addresses); i++) {
        const char *raw = json_object_get_string(json_object_array_get_idx(addresses, i));
        char address[128]; struct in6_addr storage;
        unsigned char *binary = storage.s6_addr;
        if (!raw || strlen(raw) >= sizeof(address)) continue;
        snprintf(address, sizeof(address), "%s", raw);
        char *slash = strchr(address, '/'); if (slash) *slash = 0;
        int family = inet_pton(AF_INET, address, binary) == 1 ? AF_INET :
                     inet_pton(AF_INET6, address, binary) == 1 ? AF_INET6 : 0;
        if (!family || (family == AF_INET && (binary[0] == 0 || binary[0] == 127 || binary[0] >= 224)) ||
            (family == AF_INET6 && (IN6_IS_ADDR_UNSPECIFIED(&storage) ||
                                   IN6_IS_ADDR_LOOPBACK(&storage) ||
                                   IN6_IS_ADDR_LINKLOCAL(&storage) ||
                                   IN6_IS_ADDR_MULTICAST(&storage)))) continue;
        char canonical[INET6_ADDRSTRLEN];
        if (!inet_ntop(family, binary, canonical, sizeof(canonical))) continue;
        int duplicate = 0;
        for (size_t j = 0; j < json_object_array_length(records); j++)
            duplicate |= !strcmp(canonical, domain_string(json_object_array_get_idx(records, j), "address"));
        if (duplicate) continue;
        struct json_object *record = json_object_new_object();
        text(record, "host", domain); text(record, "address", canonical);
        text(record, "type", family == AF_INET ? "A" : "AAAA");
        json_object_array_add(records, record);
    }
    if (!reason && !json_object_array_length(records)) reason = "lan_address_unavailable";
    if (!reason && (!mode || (strcmp(mode, "gateway") && strcmp(mode, "side-router"))))
        reason = "work_mode_unavailable";
    if (!reason && !strcmp(mode, "side-router")) reason = "external_dns_action_required";
    json_object_object_get_ex(snapshot, "local_dns", &local);
    text(plan, "domain", domain); text(plan, "work_mode", mode);
    text(plan, "managed_hosts", paths->hosts);
    text(plan, "previous_managed_rule", domain_string(local, "managed_address_rule"));
    json_object_object_add(plan, "records", records);
    char *dhcp = domain_read(paths->dhcp, 0), *hosts = domain_read(paths->hosts, 1);
    if (!dhcp || !hosts) reason = "dns_configuration_unavailable";
    if (dhcp && hosts) {
        char configuration_digest[65];
        if (domain_configuration_digest(dhcp, hosts, configuration_digest))
            text(plan, "configuration_digest", configuration_digest);
        else reason = "revision_unavailable";
        const char *serialized = json_object_to_json_string_ext(plan, JSON_C_TO_STRING_PLAIN);
        EVP_MD_CTX *digest = EVP_MD_CTX_new();
        unsigned char bytes[32]; unsigned length = 0; char revision[65];
        int ok = digest && EVP_DigestInit_ex(digest, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(digest, serialized, strlen(serialized)) == 1 &&
            EVP_DigestUpdate(digest, dhcp, strlen(dhcp)+1) == 1 &&
            EVP_DigestUpdate(digest, hosts, strlen(hosts)+1) == 1 &&
            EVP_DigestFinal_ex(digest, bytes, &length) == 1 && length == 32;
        EVP_MD_CTX_free(digest);
        if (ok) {
            for (size_t i = 0; i < 32; i++) snprintf(revision + 2*i, 3, "%02x", bytes[i]);
            text(plan, "revision", revision);
        } else reason = "revision_unavailable";
    }
    free(dhcp); free(hosts);
    boolean(plan, "can_apply", !reason);
    text(plan, "reason", reason);
    return plan;
}

struct json_object *webd_cloud_domain_apply(struct uci_context *uci,
    struct json_object *plan, const struct webd_cloud_domain_paths *paths,
    int (*reload)(void *), void *reload_context)
{
    struct json_object *result = json_object_new_object(), *records = NULL, *v = NULL;
    struct uci_package *dhcp = NULL;
    char *old_config = NULL, *old_hosts = NULL;
    char backup[1024], file[1100], hosts[DOMAIN_ENTRIES_MAX * 310 + 128];
    struct stat config_stat, hosts_stat;
    int had_hosts = !stat(paths->hosts, &hosts_stat), changed = 0, ok = 0;
    unsigned old_hosts_mode = had_hosts ? hosts_stat.st_mode & 0777 : 0644;
    const char *error = "dns_configuration_unavailable";
    boolean(result, "configured", 0);
    if (!json_object_object_get_ex(plan, "can_apply", &v) || !json_object_get_boolean(v)) {
        text(result, "error", domain_string(plan, "reason")); return result;
    }
    uci->flags |= UCI_FLAG_SAVED_DELTA;
    if (stat(paths->dhcp, &config_stat) || !(old_config = domain_read(paths->dhcp, 0)) ||
        !(old_hosts = domain_read(paths->hosts, 1)) || uci_load(uci, "dhcp", &dhcp) != UCI_OK) goto done;
    if (!uci_list_empty(&dhcp->saved_delta)) { error = "dns_pending_changes"; goto done; }
    char configuration_digest[65];
    if (!domain_configuration_digest(old_config, old_hosts, configuration_digest) ||
        strcmp(configuration_digest, domain_string(plan, "configuration_digest"))) {
        error = "revision_conflict"; goto done;
    }
    if (mkdir(paths->backups, 0700) && errno != EEXIST) goto done;
    if (snprintf(backup, sizeof(backup), "%s/apply-XXXXXX", paths->backups) >= (int)sizeof(backup) || !mkdtemp(backup)) goto done;
    text(result, "backup", backup);
    snprintf(file, sizeof(file), "%s/dhcp", backup);
    if (webd_cloud_domain_write_atomic(file, old_config, 0600)) goto done;
    snprintf(file, sizeof(file), "%s/hosts", backup);
    if (webd_cloud_domain_write_atomic(file, old_hosts, 0600)) goto done;
    snprintf(file, sizeof(file), "%s/hosts-existed", backup);
    if (webd_cloud_domain_write_atomic(file, had_hosts ? "1\n" : "0\n", 0600)) goto done;
    json_object_object_get_ex(plan, "records", &records);
    size_t used = (size_t)snprintf(hosts, sizeof(hosts), "# Managed by DreamingOS local-domain; current device only.\n");
    for (size_t i = 0; records && i < json_object_array_length(records); i++) {
        struct json_object *record = json_object_array_get_idx(records, i);
        int n = snprintf(hosts + used, sizeof(hosts) - used, "%s %s\n",
            domain_string(record, "address"), domain_string(record, "host"));
        if (n < 0 || (size_t)n >= sizeof(hosts)-used) goto done;
        used += (size_t)n;
    }
    int instances = 0;
    struct uci_element *entry;
    uci_foreach_element(&dhcp->sections, entry) {
        struct uci_section *section = uci_to_section(entry);
        if (strcmp(section->type, "dnsmasq")) continue;
        const char *port = option(uci, section, "port");
        if (port && !strcmp(port, "0")) continue;
        instances++;
        const char *previous = domain_string(plan, "previous_managed_rule");
        if (previous[0] && has_value(uci_lookup_option(uci, section, "address"), previous)) {
            struct uci_ptr ptr = {.p=dhcp, .s=section, .option="address", .value=previous};
            if (uci_del_list(uci, &ptr) != UCI_OK) goto done;
        }
        if (!has_value(uci_lookup_option(uci, section, "addnhosts"), paths->hosts)) {
            struct uci_ptr ptr = {.p=dhcp, .s=section, .option="addnhosts", .value=paths->hosts};
            if (uci_add_list(uci, &ptr) != UCI_OK) goto done;
        }
    }
    if (!instances) { error = "dns_service_unavailable"; goto done; }
    changed = 1;
    if (webd_cloud_domain_write_atomic(paths->hosts, hosts, old_hosts_mode) ||
        uci_commit(uci, &dhcp, false) != UCI_OK) { error = "dns_write_failed"; goto done; }
    char *readback = domain_read(paths->hosts, 0);
    int matches = readback && !strcmp(readback, hosts);
    free(readback);
    uci_unload(uci, dhcp); dhcp = NULL;
    if (uci_load(uci, "dhcp", &dhcp) != UCI_OK) matches = 0;
    int persisted_instances = 0;
    if (dhcp) uci_foreach_element(&dhcp->sections, entry) {
        struct uci_section *section = uci_to_section(entry);
        if (strcmp(section->type, "dnsmasq")) continue;
        const char *port = option(uci, section, "port");
        if (port && !strcmp(port, "0")) continue;
        persisted_instances++;
        matches &= has_value(uci_lookup_option(uci, section, "addnhosts"), paths->hosts);
        const char *previous = domain_string(plan, "previous_managed_rule");
        if (previous[0]) matches &= !has_value(uci_lookup_option(uci, section, "address"), previous);
    }
    matches &= persisted_instances == instances;
    if (!matches) { error = "dns_readback_failed"; goto done; }
    if (!reload || reload(reload_context)) { error = "dns_reload_failed"; goto done; }
    ok = 1;
    boolean(result, "configured", 1); boolean(result, "reloaded", 1);
    boolean(result, "client_verified", 0);
    text(result, "domain", domain_string(plan, "domain"));
    json_object_object_add(result, "records", json_object_get(records));
done:
    if (!ok) {
        text(result, "error", error);
        if (changed) {
            int restored = !webd_cloud_domain_write_atomic(paths->dhcp, old_config, config_stat.st_mode & 0777);
            if (had_hosts) restored &= !webd_cloud_domain_write_atomic(paths->hosts, old_hosts, old_hosts_mode);
            else restored &= !unlink(paths->hosts) || errno == ENOENT;
            if (reload) restored &= !reload(reload_context);
            boolean(result, "rolled_back", restored);
            if (!restored) text(result, "rollback_error", "dns_rollback_failed");
        }
    }
    if (dhcp) uci_unload(uci, dhcp);
    free(old_config); free(old_hosts);
    return result;
}
