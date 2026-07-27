// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"

sqlite3 *g_otad_config_db;
sqlite3 *g_otad_inventory_db;
struct ubus_context *g_otad_ubus;
struct blob_buf g_otad_blob;

int64_t otad_now_s(void)
{
    return (int64_t)time(NULL);
}

const char *otad_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    if (!json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

int otad_json_int(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

int otad_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

struct json_object *otad_json_from_blob(struct blob_attr *msg)
{
    char *s;
    struct json_object *o = NULL;

    if (!msg)
        return json_object_new_object();
    s = blobmsg_format_json(msg, true);
    if (s) {
        o = json_tokener_parse(s);
        free(s);
    }
    return o ? o : json_object_new_object();
}

struct json_object *otad_payload_or_self(struct json_object *body)
{
    struct json_object *payload = NULL;

    if (body && json_object_object_get_ex(body, "payload", &payload) && payload &&
        json_object_is_type(payload, json_type_object))
        return payload;
    return body;
}

struct json_object *otad_error(const char *code, const char *message)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(code ? code : "error"));
    json_object_object_add(o, "message", json_object_new_string(message ? message : ""));
    return o;
}

int otad_text_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s)
        return 1;
    if (strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x20 && *p != '\t' && *p != '\n' && *p != '\r')
            return 0;
    }
    return 1;
}

int otad_path_ok(const char *s)
{
    size_t len;
    const unsigned char *p;

    if (!s || s[0] != '/')
        return 0;
    len = strlen(s);
    if (len == 0 || len >= OTAD_MAX_PATH)
        return 0;
    if (strstr(s, "/../") || strstr(s, "/./") || strstr(s, "//"))
        return 0;
    if ((len >= 2 && strcmp(s + len - 2, "/.") == 0) ||
        (len >= 3 && strcmp(s + len - 3, "/..") == 0))
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p <= 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

int otad_file_read_all(const char *path, char **out, size_t *out_len, size_t max_len)
{
    FILE *fp;
    struct stat st;
    char *buf;
    size_t n;

    if (!path || !out || !out_len || !otad_path_ok(path))
        return -1;
    *out = NULL;
    *out_len = 0;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > max_len)
        return -1;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    buf = calloc(1, (size_t)st.st_size + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    n = fread(buf, 1, (size_t)st.st_size, fp);
    fclose(fp);
    if (n != (size_t)st.st_size) {
        free(buf);
        return -1;
    }
    buf[n] = '\0';
    *out = buf;
    *out_len = n;
    return 0;
}

int otad_file_exists(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int otad_dir_exists(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int otad_mkdir_p(const char *path, mode_t mode)
{
    char buf[OTAD_MAX_PATH];
    char *p;

    if (!path || !path[0] || !otad_path_ok(path))
        return -1;
    snprintf(buf, sizeof(buf), "%s", path);
    for (p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST)
        return -1;
    return otad_dir_exists(path) ? 0 : -1;
}

void otad_json_add_string(struct json_object *o, const char *key, const char *value)
{
    if (!o || !key)
        return;
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

static int otad_release_document_read(const char *path,
                                      struct json_object **document_out,
                                      char *error, size_t error_len)
{
    char *text = NULL;
    size_t len = 0;
    struct json_object *document = NULL;

    if (!document_out)
        return -1;
    *document_out = NULL;
    if (otad_file_read_all(path, &text, &len, OTAD_MAX_JSON_BYTES) != 0) {
        snprintf(error, error_len, "release_metadata_read_failed:%s", path);
        return -1;
    }
    (void)len;
    document = json_tokener_parse(text);
    free(text);
    if (!document || !json_object_is_type(document, json_type_object)) {
        if (document)
            json_object_put(document);
        snprintf(error, error_len, "release_metadata_invalid:%s", path);
        return -1;
    }
    *document_out = document;
    return 0;
}

static int otad_release_identity_conflict(struct json_object *new_release,
                                          struct json_object *old_release,
                                          char *error, size_t error_len)
{
    static const char *const identity_keys[] = {
        "product", "firmware_type", "artifact_type", "schema_version",
        "dreamingwrt_version", "build_id", "linux_version",
        "architecture", "target", "board", "rootfs_format"
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(identity_keys); i++) {
        struct json_object *new_value = NULL;
        struct json_object *old_value = NULL;
        int new_has = json_object_object_get_ex(
            new_release, identity_keys[i], &new_value);
        int old_has = json_object_object_get_ex(
            old_release, identity_keys[i], &old_value);

        if (new_has && old_has && !json_object_equal(new_value, old_value)) {
            snprintf(error, error_len,
                     "release_metadata_identity_conflict:%s",
                     identity_keys[i]);
            return -1;
        }
    }
    return 0;
}

int otad_release_metadata_read(struct json_object **release_out,
                               const char **selected_path_out,
                               char *error, size_t error_len)
{
    struct json_object *new_release = NULL;
    struct json_object *old_release = NULL;
    int new_exists;
    int old_exists;

    if (!release_out)
        return -1;
    *release_out = NULL;
    if (selected_path_out)
        *selected_path_out = NULL;
    if (error && error_len)
        error[0] = '\0';
    new_exists = otad_file_exists(OTAD_RELEASE_NEW_PATH);
    old_exists = otad_file_exists(OTAD_RELEASE_PATH);
    if (!new_exists && !old_exists) {
        snprintf(error, error_len, "release_metadata_absent");
        return 1;
    }
    if (new_exists && otad_release_document_read(
            OTAD_RELEASE_NEW_PATH, &new_release, error, error_len) != 0)
        goto fail;
    if (old_exists && otad_release_document_read(
            OTAD_RELEASE_PATH, &old_release, error, error_len) != 0)
        goto fail;
    if (new_release && old_release &&
        otad_release_identity_conflict(new_release, old_release,
                                       error, error_len) != 0)
        goto fail;
    if (new_release) {
        *release_out = new_release;
        new_release = NULL;
        if (selected_path_out)
            *selected_path_out = OTAD_RELEASE_NEW_PATH;
    } else {
        *release_out = old_release;
        old_release = NULL;
        if (selected_path_out)
            *selected_path_out = OTAD_RELEASE_PATH;
    }
    if (old_release)
        json_object_put(old_release);
    return 0;

fail:
    if (new_release)
        json_object_put(new_release);
    if (old_release)
        json_object_put(old_release);
    return -1;
}

static uint64_t otad_u64_add_saturate(uint64_t a, uint64_t b)
{
    return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}

static uint64_t otad_u64_mul_saturate(uint64_t a, uint64_t b)
{
    return a && b > UINT64_MAX / a ? UINT64_MAX : a * b;
}

static int64_t otad_json_i64_saturate(uint64_t value)
{
    return value > INT64_MAX ? INT64_MAX : (int64_t)value;
}

static int otad_statvfs_existing_path(const char *path, struct statvfs *vfs,
                                      struct stat *st)
{
    char probe[OTAD_MAX_PATH];
    char *slash;

    if (!path || !vfs || !otad_path_ok(path) ||
        snprintf(probe, sizeof(probe), "%s", path) >= (int)sizeof(probe))
        return -1;
    for (;;) {
        if (statvfs(probe, vfs) == 0 && stat(probe, st) == 0)
            return 0;
        if (errno != ENOENT && errno != ENOTDIR)
            return -1;
        slash = strrchr(probe, '/');
        if (!slash)
            return -1;
        if (slash == probe) {
            probe[1] = '\0';
        } else {
            *slash = '\0';
        }
        if (!strcmp(probe, "/"))
            return statvfs(probe, vfs) == 0 && stat(probe, st) == 0 ? 0 : -1;
    }
}

int otad_space_gate_check(const char *path, const char *artifact,
                          uint64_t artifact_bytes, uint64_t artifact_inodes,
                          struct otad_space_gate *gate)
{
    struct statvfs vfs;
    struct stat st;
    uint64_t percent_margin;
    uint64_t fragment_size;

    if (!gate)
        return -1;
    memset(gate, 0, sizeof(*gate));
    gate->checked = 1;
    gate->retryable = 1;
    gate->artifact_bytes = artifact_bytes;
    gate->checked_at = otad_now_s();
    snprintf(gate->artifact, sizeof(gate->artifact), "%s",
             artifact ? artifact : "ota_artifact");
    snprintf(gate->capacity_kind, sizeof(gate->capacity_kind), "filesystem");
    snprintf(gate->path, sizeof(gate->path), "%s", path ? path : "");

    percent_margin = artifact_bytes > UINT64_MAX / OTAD_SPACE_SAFETY_PERCENT
        ? UINT64_MAX
        : artifact_bytes * OTAD_SPACE_SAFETY_PERCENT / 100U;
    gate->safety_margin_bytes = percent_margin > OTAD_SPACE_SAFETY_MIN_BYTES
        ? percent_margin : OTAD_SPACE_SAFETY_MIN_BYTES;
    gate->required_bytes = otad_u64_add_saturate(
        artifact_bytes, gate->safety_margin_bytes);
    gate->required_inodes = otad_u64_add_saturate(
        artifact_inodes, OTAD_SPACE_SAFETY_INODES);

    if (gate->required_bytes == UINT64_MAX ||
        gate->required_inodes == UINT64_MAX) {
        gate->retryable = 0;
        snprintf(gate->error, sizeof(gate->error), "space_requirement_overflow");
        snprintf(gate->reason, sizeof(gate->reason),
                 "artifact_size_plus_safety_margin_overflow");
        return -1;
    }
    if (otad_statvfs_existing_path(path, &vfs, &st) != 0) {
        snprintf(gate->error, sizeof(gate->error), "statvfs_failed");
        snprintf(gate->reason, sizeof(gate->reason),
                 "target_filesystem_capacity_unavailable");
        return -1;
    }
    gate->device = st.st_dev;
    fragment_size = vfs.f_frsize ? (uint64_t)vfs.f_frsize : (uint64_t)vfs.f_bsize;
    gate->available_bytes = otad_u64_mul_saturate((uint64_t)vfs.f_bavail,
                                                   fragment_size);
    gate->available_inodes = (uint64_t)vfs.f_favail;
    if (gate->available_bytes < gate->required_bytes) {
        snprintf(gate->error, sizeof(gate->error), "insufficient_space");
        snprintf(gate->reason, sizeof(gate->reason),
                 "available_bytes_below_artifact_plus_safety_margin");
        return -1;
    }
    if (vfs.f_files == 0 || gate->available_inodes < gate->required_inodes) {
        snprintf(gate->error, sizeof(gate->error), "insufficient_inodes");
        snprintf(gate->reason, sizeof(gate->reason), vfs.f_files == 0
                 ? "target_filesystem_inode_capacity_unavailable"
                 : "available_inodes_below_artifact_plus_safety_margin");
        return -1;
    }
    gate->ok = 1;
    gate->retryable = 0;
    snprintf(gate->reason, sizeof(gate->reason), "ok");
    return 0;
}

int otad_block_capacity_gate_check(const char *path, const char *artifact,
                                   uint64_t artifact_bytes,
                                   uint64_t capacity_bytes,
                                   struct otad_space_gate *gate)
{
    struct stat st;
    uint64_t percent_margin;

    if (!gate)
        return -1;
    memset(gate, 0, sizeof(*gate));
    gate->checked = 1;
    gate->retryable = 0;
    gate->artifact_bytes = artifact_bytes;
    gate->available_bytes = capacity_bytes;
    gate->checked_at = otad_now_s();
    snprintf(gate->artifact, sizeof(gate->artifact), "%s",
             artifact ? artifact : "ota_artifact");
    snprintf(gate->capacity_kind, sizeof(gate->capacity_kind), "block_device");
    snprintf(gate->path, sizeof(gate->path), "%s", path ? path : "");

    percent_margin = artifact_bytes > UINT64_MAX / OTAD_SPACE_SAFETY_PERCENT
        ? UINT64_MAX
        : artifact_bytes * OTAD_SPACE_SAFETY_PERCENT / 100U;
    gate->safety_margin_bytes = percent_margin > OTAD_SPACE_SAFETY_MIN_BYTES
        ? percent_margin : OTAD_SPACE_SAFETY_MIN_BYTES;
    gate->required_bytes = otad_u64_add_saturate(
        artifact_bytes, gate->safety_margin_bytes);
    if (gate->required_bytes == UINT64_MAX) {
        snprintf(gate->error, sizeof(gate->error), "space_requirement_overflow");
        snprintf(gate->reason, sizeof(gate->reason),
                 "artifact_size_plus_safety_margin_overflow");
        return -1;
    }
    if (!path || !otad_path_ok(path) || stat(path, &st) != 0 ||
        !S_ISBLK(st.st_mode)) {
        snprintf(gate->error, sizeof(gate->error), "block_capacity_unavailable");
        snprintf(gate->reason, sizeof(gate->reason),
                 "inactive_slot_block_device_unavailable");
        return -1;
    }
    gate->device = st.st_rdev;
    if (capacity_bytes < gate->required_bytes) {
        snprintf(gate->error, sizeof(gate->error), "insufficient_space");
        snprintf(gate->reason, sizeof(gate->reason),
                 "slot_capacity_below_rootfs_kernel_metadata_plus_safety_margin");
        return -1;
    }
    gate->ok = 1;
    snprintf(gate->reason, sizeof(gate->reason), "ok");
    return 0;
}

void otad_space_gate_add_json(struct json_object *o,
                              const struct otad_space_gate *gate)
{
    if (!o || !gate)
        return;
    json_object_object_add(o, "checked", json_object_new_boolean(gate->checked));
    json_object_object_add(o, "gate_open", json_object_new_boolean(gate->ok));
    otad_json_add_string(o, "error", gate->error);
    otad_json_add_string(o, "reason", gate->reason);
    json_object_object_add(o, "required_bytes",
                           json_object_new_int64(otad_json_i64_saturate(
                               gate->required_bytes)));
    json_object_object_add(o, "available_bytes",
                           json_object_new_int64(otad_json_i64_saturate(
                               gate->available_bytes)));
    otad_json_add_string(o, "path", gate->path);
    json_object_object_add(o, "retryable", json_object_new_boolean(gate->retryable));
    otad_json_add_string(o, "artifact", gate->artifact);
    otad_json_add_string(o, "capacity_kind", gate->capacity_kind);
    json_object_object_add(o, "artifact_bytes",
                           json_object_new_int64(otad_json_i64_saturate(
                               gate->artifact_bytes)));
    json_object_object_add(o, "safety_margin_bytes",
                           json_object_new_int64(otad_json_i64_saturate(
                               gate->safety_margin_bytes)));
    json_object_object_add(o, "safety_margin_percent",
                           json_object_new_int(OTAD_SPACE_SAFETY_PERCENT));
    json_object_object_add(o, "safety_margin_min_bytes",
                           json_object_new_int64(OTAD_SPACE_SAFETY_MIN_BYTES));
    json_object_object_add(o, "safety_margin_inodes",
                           json_object_new_int64(OTAD_SPACE_SAFETY_INODES));
    json_object_object_add(o, "required_inodes",
                           json_object_new_int64(otad_json_i64_saturate(
                               gate->required_inodes)));
    json_object_object_add(o, "available_inodes",
                           json_object_new_int64(otad_json_i64_saturate(
                               gate->available_inodes)));
    json_object_object_add(o, "checked_at", json_object_new_int64(gate->checked_at));
}

struct json_object *otad_space_gate_error(const struct otad_space_gate *gate,
                                          const char *message)
{
    struct json_object *o = otad_error(
        gate && gate->error[0] ? gate->error : "space_gate_failed",
        message ? message : "OTA target filesystem space gate did not pass");

    otad_space_gate_add_json(o, gate);
    return o;
}

void otad_space_gate_record(const struct otad_space_gate *gate)
{
    struct json_object *o;

    if (!gate)
        return;
    o = json_object_new_object();
    if (!o)
        return;
    otad_space_gate_add_json(o, gate);
    (void)otad_state_set("space_gate",
        json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN));
    json_object_put(o);
}

struct json_object *otad_safe_not_implemented(const char *op)
{
    struct json_object *o = otad_error("not_implemented_safe",
        "This OTA operation is intentionally disabled until slot writing is implemented.");

    json_object_object_add(o, "operation", json_object_new_string(op ? op : ""));
    json_object_object_add(o, "state", json_object_new_string("idle"));
    json_object_object_add(o, "destructive", json_object_new_boolean(0));
    return o;
}
