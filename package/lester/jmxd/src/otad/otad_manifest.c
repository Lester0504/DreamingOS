// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"

static int otad_json_array_nonempty(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    return o && json_object_object_get_ex(o, key, &v) && v &&
           json_object_is_type(v, json_type_array) &&
           json_object_array_length(v) > 0;
}

static void manifest_error_add(struct json_object *errors, const char *field,
                               const char *reason)
{
    struct json_object *e;

    if (!errors)
        return;
    e = json_object_new_object();
    otad_json_add_string(e, "field", field ? field : "");
    otad_json_add_string(e, "reason", reason ? reason : "invalid");
    json_object_array_add(errors, e);
}

static int manifest_type_ok(const char *s)
{
    return s && (!strcmp(s, "hotfix") || !strcmp(s, "resource"));
}

static int firmware_type_ok(const char *s)
{
    return s && (!strcmp(s, "database") || !strcmp(s, "component"));
}

static int payload_type_ok(const char *s)
{
    return s && (!strcmp(s, "full_image") || !strcmp(s, "file_delta") ||
                 !strcmp(s, "file") || !strcmp(s, "resource"));
}

int otad_hot_target_allowed(const char *firmware_type, const char *path)
{
    static const char *database_prefixes[] = {
        "/etc/dreamingwrt/signatures/", "/etc/dreamingwrt/geoip/",
        "/etc/dreamingwrt/fingerprint/", "/usr/share/dreamingwrt/signatures/",
        "/usr/share/dreamingwrt/geoip/", "/usr/share/dreamingwrt/fingerprint/",
        "/opt/dreamingwrt/signatures/",
        "/www/dreamingwrt/static/images/logo/", NULL
    };
    static const char *component_prefixes[] = {
        "/usr/bin/dreamingwrt-", "/usr/sbin/dreamingwrt-",
        "/etc/init.d/dreamingwrt-",
        "/www/dreamingwrt/", "/usr/share/dreamingwrt/web/", NULL
    };
    const char **prefixes;
    int i;

    if (!path || !otad_path_ok(path))
        return 0;
    if (!strcmp(firmware_type, "database") &&
        !strcmp(path, "/etc/dreamingwrt/dreamingwrt_signatures.db"))
        return 1;
    if (!strcmp(firmware_type, "component")) {
        if (!strcmp(path, "/usr/bin/dreamingwrt-init") ||
            !strcmp(path, "/etc/init.d/dreamingwrt-init"))
            return 0;
        if (!strcmp(path, "/usr/bin/jmctl"))
            return 1;
    }
    prefixes = !strcmp(firmware_type, "database") ? database_prefixes :
               !strcmp(firmware_type, "component") ? component_prefixes : NULL;
    if (!prefixes)
        return 0;
    for (i = 0; prefixes[i]; i++)
        if (!strncmp(path, prefixes[i], strlen(prefixes[i])))
            return 1;
    return 0;
}

int otad_component_name_ok(const char *name)
{
    static const char *components[] = {
        "core", "auditd", "rulesd", "webd", "logd", "notifyd", "healthd",
        "metricsd", "maintenanced", "routed", "identityd", "flowd", "otad",
        "aegisxd", NULL
    };
    int i;

    if (!name)
        return 0;
    for (i = 0; components[i]; i++)
        if (!strcmp(name, components[i]))
            return 1;
    return 0;
}

static int manifest_sha256_hex_ok(const char *s)
{
    size_t i;

    if (!s || strlen(s) != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    }
    return 1;
}

static int manifest_md5_hex_ok(const char *s)
{
    size_t i;

    if (!s || strlen(s) != 32)
        return 0;
    for (i = 0; i < 32; i++)
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    return 1;
}

static int manifest_package_path_ok(const char *s)
{
    const char *seg = s;
    const char *p;
    size_t len;

    if (!s || !s[0] || s[0] == '/')
        return 0;
    len = strlen(s);
    if (len >= OTAD_MAX_PATH)
        return 0;
    for (p = s; ; p++) {
        unsigned char c = (unsigned char)*p;

        if (*p == '/' || *p == '\0') {
            if (p == seg)
                return 0;
            if ((p - seg == 1 && seg[0] == '.') ||
                (p - seg == 2 && seg[0] == '.' && seg[1] == '.'))
                return 0;
            if (*p == '\0')
                break;
            seg = p + 1;
            continue;
        }
        if (c <= 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static void validate_payloads(struct json_object *manifest, const char *firmware_type,
                              struct json_object *errors)
{
    struct json_object *arr = NULL;
    struct json_object *deletions = NULL;
    size_t i, n;

    if (!json_object_object_get_ex(manifest, "payloads", &arr) || !arr ||
        !json_object_is_type(arr, json_type_array)) {
        manifest_error_add(errors, "payloads", "array_required");
        return;
    }
    n = json_object_array_length(arr);
    if (n == 0 &&
        (!json_object_object_get_ex(manifest, "deletions", &deletions) || !deletions ||
         !json_object_is_type(deletions, json_type_array) ||
         json_object_array_length(deletions) == 0)) {
        manifest_error_add(errors, "payloads", "payload_or_deletion_required");
        return;
    }
    if (n > 256) {
        manifest_error_add(errors, "payloads", "maximum_256_payloads");
        return;
    }
    for (i = 0; i < n; i++) {
        struct json_object *p = json_object_array_get_idx(arr, i);
        const char *type = otad_json_str(p, "type", "");
        const char *path = otad_json_str(p, "path", "");
        const char *sha = otad_json_str(p, "sha256", "");
        const char *md5 = otad_json_str(p, "md5", "");
        const char *target = otad_json_str(p, "target_path", "");
        const char *base_sha = otad_json_str(p, "base_sha256", "");
        int target_exists = otad_json_bool(p, "target_exists", 0);
        char field[64];

        if (!p || !json_object_is_type(p, json_type_object)) {
            snprintf(field, sizeof(field), "payloads[%zu]", i);
            manifest_error_add(errors, field, "object_required");
            continue;
        }
        if (!payload_type_ok(type)) {
            snprintf(field, sizeof(field), "payloads[%zu].type", i);
            manifest_error_add(errors, field, "unknown_payload_type");
        }
        if (!manifest_package_path_ok(path)) {
            snprintf(field, sizeof(field), "payloads[%zu].path", i);
            manifest_error_add(errors, field, "relative_package_path_required");
        }
        if (!manifest_sha256_hex_ok(sha)) {
            snprintf(field, sizeof(field), "payloads[%zu].sha256", i);
            manifest_error_add(errors, field, "sha256_hex_required");
        }
        if (!manifest_md5_hex_ok(md5)) {
            snprintf(field, sizeof(field), "payloads[%zu].md5", i);
            manifest_error_add(errors, field, "md5_hex_required");
        }
        if ((!strcmp(firmware_type, "database") || !strcmp(firmware_type, "component")) &&
            !otad_hot_target_allowed(firmware_type, target)) {
            snprintf(field, sizeof(field), "payloads[%zu].target_path", i);
            manifest_error_add(errors, field, "not_allowed_for_firmware_type");
        }
        if (target_exists && !manifest_sha256_hex_ok(base_sha)) {
            snprintf(field, sizeof(field), "payloads[%zu].base_sha256", i);
            manifest_error_add(errors, field, "sha256_hex_required_when_target_exists");
        }
        if (!target_exists && base_sha[0]) {
            snprintf(field, sizeof(field), "payloads[%zu].base_sha256", i);
            manifest_error_add(errors, field, "must_be_empty_when_target_is_new");
        }
    }
}

static void validate_deletions(struct json_object *manifest, const char *firmware_type,
                               struct json_object *errors)
{
    struct json_object *arr = NULL;
    size_t i, n;

    if (!json_object_object_get_ex(manifest, "deletions", &arr) || !arr)
        return;
    if (!json_object_is_type(arr, json_type_array)) {
        manifest_error_add(errors, "deletions", "array_required");
        return;
    }
    n = json_object_array_length(arr);
    if (n > 256) {
        manifest_error_add(errors, "deletions", "maximum_256_deletions");
        return;
    }
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        const char *target = otad_json_str(item, "target_path", "");
        const char *base_sha = otad_json_str(item, "base_sha256", "");
        struct json_object *base_size = NULL;
        char field[64];

        if (!item || !json_object_is_type(item, json_type_object)) {
            snprintf(field, sizeof(field), "deletions[%zu]", i);
            manifest_error_add(errors, field, "object_required");
            continue;
        }
        if (!otad_hot_target_allowed(firmware_type, target)) {
            snprintf(field, sizeof(field), "deletions[%zu].target_path", i);
            manifest_error_add(errors, field, "not_allowed_for_firmware_type");
        }
        if (!manifest_sha256_hex_ok(base_sha)) {
            snprintf(field, sizeof(field), "deletions[%zu].base_sha256", i);
            manifest_error_add(errors, field, "sha256_hex_required");
        }
        if (!json_object_object_get_ex(item, "base_size", &base_size) || !base_size ||
            !json_object_is_type(base_size, json_type_int) ||
            json_object_get_int64(base_size) < 0) {
            snprintf(field, sizeof(field), "deletions[%zu].base_size", i);
            manifest_error_add(errors, field, "non_negative_integer_required");
        }
    }
}

static void validate_service_actions(struct json_object *manifest, struct json_object *errors)
{
    struct json_object *arr = NULL;
    size_t i, n;

    if (!json_object_object_get_ex(manifest, "service_actions", &arr) || !arr) {
        manifest_error_add(errors, "service_actions", "array_required");
        return;
    }
    if (!json_object_is_type(arr, json_type_array)) {
        manifest_error_add(errors, "service_actions", "array_required");
        return;
    }
    n = json_object_array_length(arr);
    if (n > 32) {
        manifest_error_add(errors, "service_actions", "maximum_32_actions");
        return;
    }
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        const char *service = otad_json_str(item, "service", "");
        const char *action = otad_json_str(item, "action", "");
        const char *when = otad_json_str(item, "when", "");
        char field[64];

        if (!otad_component_name_ok(service) || strcmp(action, "restart") ||
            strcmp(when, "post_apply")) {
            snprintf(field, sizeof(field), "service_actions[%zu]", i);
            manifest_error_add(errors, field, "known_component_post_apply_restart_required");
        }
    }
}

static int service_action_has(struct json_object *manifest, const char *service)
{
    struct json_object *arr = NULL;
    size_t i, n;

    if (!json_object_object_get_ex(manifest, "service_actions", &arr) || !arr ||
        !json_object_is_type(arr, json_type_array))
        return 0;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);

        if (!strcmp(otad_json_str(item, "service", ""), service) &&
            !strcmp(otad_json_str(item, "action", ""), "restart") &&
            !strcmp(otad_json_str(item, "when", ""), "post_apply"))
            return 1;
    }
    return 0;
}

static void require_restart(struct json_object *manifest, struct json_object *errors,
                            const char *service)
{
    char field[96];

    if (service_action_has(manifest, service))
        return;
    snprintf(field, sizeof(field), "service_actions.%s", service);
    manifest_error_add(errors, field, "required_for_updated_target");
}

static void validate_target_restarts(struct json_object *manifest, const char *target,
                                     struct json_object *errors)
{
    const char *base;

    if (!target || !target[0] || !strcmp(target, "/usr/bin/jmctl"))
        return;
    if (!strncmp(target, "/www/dreamingwrt/", sizeof("/www/dreamingwrt/") - 1) ||
        !strncmp(target, "/usr/share/dreamingwrt/web/",
                 sizeof("/usr/share/dreamingwrt/web/") - 1) ||
        !strncmp(target, "/www/dreamingwrt/static/images/logo/",
                 sizeof("/www/dreamingwrt/static/images/logo/") - 1)) {
        require_restart(manifest, errors, "webd");
        return;
    }
    if (strstr(target, "/geoip/")) {
        require_restart(manifest, errors, "aegisxd");
        require_restart(manifest, errors, "webd");
        return;
    }
    if (strstr(target, "/fingerprint/")) {
        require_restart(manifest, errors, "core");
        require_restart(manifest, errors, "identityd");
        require_restart(manifest, errors, "webd");
        return;
    }
    if (strstr(target, "/signatures/") ||
        !strcmp(target, "/etc/dreamingwrt/dreamingwrt_signatures.db")) {
        require_restart(manifest, errors, "aegisxd");
        require_restart(manifest, errors, "core");
        require_restart(manifest, errors, "flowd");
        return;
    }
    if (!strncmp(target, "/usr/bin/dreamingwrt-", sizeof("/usr/bin/dreamingwrt-") - 1) ||
        !strncmp(target, "/usr/sbin/dreamingwrt-", sizeof("/usr/sbin/dreamingwrt-") - 1) ||
        !strncmp(target, "/etc/init.d/dreamingwrt-", sizeof("/etc/init.d/dreamingwrt-") - 1)) {
        base = strrchr(target, '/');
        if (base && !strncmp(base + 1, "dreamingwrt-", 12) && base[13])
            require_restart(manifest, errors, base + 13);
    }
}

static void validate_required_restarts(struct json_object *manifest,
                                       struct json_object *errors)
{
    static const char *arrays[] = { "payloads", "deletions" };
    size_t a;

    for (a = 0; a < sizeof(arrays) / sizeof(arrays[0]); a++) {
        struct json_object *arr = NULL;
        size_t i, n;

        if (!json_object_object_get_ex(manifest, arrays[a], &arr) || !arr ||
            !json_object_is_type(arr, json_type_array))
            continue;
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++)
            validate_target_restarts(manifest,
                otad_json_str(json_object_array_get_idx(arr, i), "target_path", ""),
                errors);
    }
}

static void validate_preserve_paths(struct json_object *manifest, struct json_object *errors)
{
    struct json_object *arr = NULL;
    size_t i, n;

    if (!json_object_object_get_ex(manifest, "preserve", &arr) || !arr)
        return;
    if (!json_object_is_type(arr, json_type_array)) {
        manifest_error_add(errors, "preserve", "array_required");
        return;
    }
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *p = json_object_array_get_idx(arr, i);
        const char *path = otad_json_str(p, "path", "");
        char field[64];

        if (!otad_path_ok(path)) {
            snprintf(field, sizeof(field), "preserve[%zu].path", i);
            manifest_error_add(errors, field, "absolute_safe_path_required");
        }
    }
}

static void validate_migrations(struct json_object *manifest, struct json_object *errors)
{
    struct json_object *arr = NULL;
    size_t i, n;

    if (!json_object_object_get_ex(manifest, "migrations", &arr) || !arr)
        return;
    if (!json_object_is_type(arr, json_type_array)) {
        manifest_error_add(errors, "migrations", "array_required");
        return;
    }
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *m = json_object_array_get_idx(arr, i);
        const char *script = otad_json_str(m, "script", "");
        char field[64];

        if (!m || !json_object_is_type(m, json_type_object)) {
            snprintf(field, sizeof(field), "migrations[%zu]", i);
            manifest_error_add(errors, field, "object_required");
            continue;
        }
        if (!manifest_package_path_ok(script)) {
            snprintf(field, sizeof(field), "migrations[%zu].script", i);
            manifest_error_add(errors, field, "relative_package_path_required");
        }
        if (!otad_json_bool(m, "idempotent", 0)) {
            snprintf(field, sizeof(field), "migrations[%zu].idempotent", i);
            manifest_error_add(errors, field, "must_be_true");
        }
    }
}

static struct json_object *manifest_from_body(struct json_object *body)
{
    struct json_object *manifest = NULL;
    const char *path;
    char *buf = NULL;
    size_t len = 0;

    if (!body)
        return NULL;
    if (json_object_object_get_ex(body, "manifest_version", &manifest) ||
        json_object_object_get_ex(body, "package_id", &manifest) ||
        json_object_object_get_ex(body, "package_type", &manifest))
        return json_object_get(body);
    if (json_object_object_get_ex(body, "manifest", &manifest) && manifest &&
        json_object_is_type(manifest, json_type_object))
        return json_object_get(manifest);

    path = otad_json_str(body, "path", "");
    if (!path[0])
        return NULL;
    if (otad_file_read_all(path, &buf, &len, OTAD_MAX_JSON_BYTES) != 0)
        return NULL;
    (void)len;
    manifest = json_tokener_parse(buf);
    free(buf);
    if (!manifest || !json_object_is_type(manifest, json_type_object)) {
        if (manifest)
            json_object_put(manifest);
        return NULL;
    }
    return manifest;
}

struct json_object *otad_check_manifest(struct json_object *body)
{
    struct json_object *manifest;
    struct json_object *resp = json_object_new_object();
    struct json_object *errors = json_object_new_array();
    const char *package_type;
    const char *firmware_type;
    const char *package_id;
    const char *product;
    const char *version;
    int manifest_version;
    int requires_reboot;
    int slot_required;
    size_t err_count;

    manifest = manifest_from_body(body);
    if (!manifest)
        return otad_error("invalid_manifest", "manifest object or readable manifest path is required");

    manifest_version = otad_json_int(manifest, "manifest_version", 0);
    package_id = otad_json_str(manifest, "package_id", "");
    package_type = otad_json_str(manifest, "package_type", "");
    firmware_type = otad_json_str(manifest, "firmware_type", "");
    product = otad_json_str(manifest, "product", "");
    version = otad_json_str(manifest, "to_version", "");
    requires_reboot = otad_json_bool(manifest, "requires_reboot", 0);
    slot_required = otad_json_bool(manifest, "slot_required", 0);

    if (manifest_version != 1)
        manifest_error_add(errors, "manifest_version", "unsupported");
    if (!package_id[0] || !otad_text_ok(package_id, 128))
        manifest_error_add(errors, "package_id", "required");
    if (!manifest_type_ok(package_type))
        manifest_error_add(errors, "package_type", "unknown");
    if (!firmware_type_ok(firmware_type))
        manifest_error_add(errors, "firmware_type", "unknown");
    if (strcmp(product, "DreamingWrt") != 0)
        manifest_error_add(errors, "product", "must_be_DreamingWrt");
    if (!version[0])
        manifest_error_add(errors, "to_version", "required");
    if (!otad_json_array_nonempty(manifest, "from_versions"))
        manifest_error_add(errors, "from_versions", "required_non_empty_array");
    if (!otad_json_array_nonempty(manifest, "board"))
        manifest_error_add(errors, "board", "required_non_empty_array");
    validate_payloads(manifest, firmware_type, errors);
    validate_deletions(manifest, firmware_type, errors);
    validate_preserve_paths(manifest, errors);
    validate_migrations(manifest, errors);
    validate_service_actions(manifest, errors);
    validate_required_restarts(manifest, errors);

    if (strcmp(package_type, "hotfix") && strcmp(package_type, "resource"))
        manifest_error_add(errors, "package_type", "hot_update_type_required");
    if (slot_required || requires_reboot)
        manifest_error_add(errors, "firmware_type", "hot_update_must_not_require_slot_or_reboot");

    err_count = json_object_array_length(errors);
    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "validated", json_object_new_boolean(err_count == 0));
    otad_json_add_string(resp, "package_id", package_id);
    otad_json_add_string(resp, "package_type", package_type);
    otad_json_add_string(resp, "firmware_type", firmware_type);
    otad_json_add_string(resp, "to_version", version);
    json_object_object_add(resp, "requires_reboot", json_object_new_boolean(requires_reboot));
    json_object_object_add(resp, "slot_required", json_object_new_boolean(slot_required));
    json_object_object_add(resp, "integrity_verified", json_object_new_boolean(0));
    json_object_object_add(resp, "signature_required", json_object_new_boolean(1));
    json_object_object_add(resp, "signature_verified", json_object_new_boolean(0));
    json_object_object_add(resp, "safe_to_apply_now", json_object_new_boolean(0));
    otad_json_add_string(resp, "error", "hot_update_release_trust_gate_closed");
    json_object_object_add(resp, "note", json_object_new_string(
        err_count == 0 ? "hot-update manifest structure is valid but release signature verification is unavailable"
                       : "manifest contract has validation errors and release signature verification is unavailable"));
    json_object_object_add(resp, "errors", errors);
    json_object_put(manifest);
    return resp;
}
