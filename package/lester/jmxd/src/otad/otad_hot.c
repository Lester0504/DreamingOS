// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"

#define OTAD_HOT_MAGIC "DREAMINGWRT-HOT-UPDATE-V1\n"
#define OTAD_HOT_HEADER_NAME "manifest.json\n"
#define OTAD_HOT_HEADER_BYTES (1024U * 1024U)
#define OTAD_HOT_MAX_PAYLOADS 256
#define OTAD_HOT_MAX_RESTARTS 32
#define OTAD_HOT_MAX_DELETIONS 256
#define OTAD_HOT_MAX_SPACE_GATES (OTAD_HOT_MAX_PAYLOADS + 1)

struct otad_hot_info {
    char path[OTAD_MAX_PATH];
    uint64_t size;
    struct json_object *manifest;
};

struct otad_hot_file {
    char target[OTAD_MAX_PATH];
    char staged[OTAD_MAX_PATH];
    char backup[OTAD_MAX_PATH];
    uint64_t offset;
    uint64_t size;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    char md5[33];
    char sha256[65];
    char base_sha256[65];
    uint64_t base_size;
    int target_exists;
    int had_original;
    int installed;
};

struct otad_hot_deletion {
    char target[OTAD_MAX_PATH];
    char backup[OTAD_MAX_PATH];
    char base_sha256[65];
    uint64_t base_size;
    int moved;
};

struct otad_hot_space_gates {
    struct otad_space_gate items[OTAD_HOT_MAX_SPACE_GATES];
    size_t count;
};

static struct uloop_timeout g_hot_restart_timer;
static char g_hot_restarts[OTAD_HOT_MAX_RESTARTS][64];
static size_t g_hot_restart_count;

static int hot_package_path_allowed(const char *path)
{
    static const char *prefixes[] = {
        "/tmp/dreamingwrt/ota/", "/data/dreamingwrt/ota/",
        "/opt/dreamingwrt/ota/", NULL
    };
    int i;

    if (!path || !otad_path_ok(path))
        return 0;
    for (i = 0; prefixes[i]; i++)
        if (!strncmp(path, prefixes[i], strlen(prefixes[i])))
            return 1;
    return 0;
}

static uint64_t hot_json_u64(struct json_object *o, const char *key, uint64_t def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return (uint64_t)json_object_get_int64(v);
}

static int hot_hex_ok(const char *s, size_t len)
{
    size_t i;

    if (!s || strlen(s) != len)
        return 0;
    for (i = 0; i < len; i++)
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    return 1;
}

static void hot_digest_hex(const unsigned char *digest, unsigned int len,
                           char *out, size_t out_len)
{
    unsigned int i;

    if (!out || out_len < (size_t)len * 2 + 1)
        return;
    for (i = 0; i < len; i++)
        snprintf(out + i * 2, out_len - i * 2, "%02x", digest[i]);
    out[len * 2] = '\0';
}

static int hot_hash_fd_range(int fd, uint64_t offset, uint64_t size,
                             char md5_hex[33], char sha_hex[65])
{
    EVP_MD_CTX *md5 = EVP_MD_CTX_new();
    EVP_MD_CTX *sha = EVP_MD_CTX_new();
    unsigned char buf[1024 * 1024];
    unsigned char md5_out[EVP_MAX_MD_SIZE];
    unsigned char sha_out[EVP_MAX_MD_SIZE];
    unsigned int md5_len = 0, sha_len = 0;
    uint64_t done = 0;
    int rc = -1;

    if (!md5 || !sha || EVP_DigestInit_ex(md5, EVP_md5(), NULL) != 1 ||
        EVP_DigestInit_ex(sha, EVP_sha256(), NULL) != 1)
        goto out;
    while (done < size) {
        size_t want = sizeof(buf);
        ssize_t n;

        if ((uint64_t)want > size - done)
            want = (size_t)(size - done);
        n = pread(fd, buf, want, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || EVP_DigestUpdate(md5, buf, (size_t)n) != 1 ||
            EVP_DigestUpdate(sha, buf, (size_t)n) != 1)
            goto out;
        done += (uint64_t)n;
    }
    if (EVP_DigestFinal_ex(md5, md5_out, &md5_len) != 1 ||
        EVP_DigestFinal_ex(sha, sha_out, &sha_len) != 1)
        goto out;
    hot_digest_hex(md5_out, md5_len, md5_hex, 33);
    hot_digest_hex(sha_out, sha_len, sha_hex, 65);
    rc = 0;
out:
    EVP_MD_CTX_free(md5);
    EVP_MD_CTX_free(sha);
    return rc;
}

static int hot_hash_path(const char *path, uint64_t size, char md5[33], char sha[65])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int rc;

    if (fd < 0)
        return -1;
    rc = hot_hash_fd_range(fd, 0, size, md5, sha);
    close(fd);
    return rc;
}

static void hot_info_done(struct otad_hot_info *info)
{
    if (info && info->manifest) {
        json_object_put(info->manifest);
        info->manifest = NULL;
    }
}

static int hot_header_read(const char *path, struct otad_hot_info *info,
                           char *error, size_t error_len)
{
    char *header = NULL, *p, *end;
    char length_text[16];
    unsigned long json_len;
    struct stat st;
    int fd = -1;
    size_t off = 0;

    memset(info, 0, sizeof(*info));
    if (!hot_package_path_allowed(path) || stat(path, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size < (off_t)OTAD_HOT_HEADER_BYTES) {
        snprintf(error, error_len, "hot_update_path_invalid");
        return -1;
    }
    header = malloc(OTAD_HOT_HEADER_BYTES + 1);
    if (!header) {
        snprintf(error, error_len, "out_of_memory");
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        goto invalid;
    while (off < OTAD_HOT_HEADER_BYTES) {
        ssize_t n = read(fd, header + off, OTAD_HOT_HEADER_BYTES - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        off += (size_t)n;
    }
    close(fd);
    fd = -1;
    header[off] = '\0';
    if (off != OTAD_HOT_HEADER_BYTES ||
        strncmp(header, OTAD_HOT_MAGIC, strlen(OTAD_HOT_MAGIC)))
        goto invalid;
    p = header + strlen(OTAD_HOT_MAGIC);
    if (strncmp(p, OTAD_HOT_HEADER_NAME, strlen(OTAD_HOT_HEADER_NAME)))
        goto invalid;
    p += strlen(OTAD_HOT_HEADER_NAME);
    end = strchr(p, '\n');
    if (!end || (size_t)(end - p) >= sizeof(length_text))
        goto invalid;
    memcpy(length_text, p, (size_t)(end - p));
    length_text[end - p] = '\0';
    json_len = strtoul(length_text, NULL, 10);
    p = end + 1;
    if (!json_len || json_len > OTAD_HOT_HEADER_BYTES - (size_t)(p - header))
        goto invalid;
    p[json_len] = '\0';
    info->manifest = json_tokener_parse(p);
    free(header);
    if (!info->manifest || !json_object_is_type(info->manifest, json_type_object))
        goto invalid_no_header;
    info->size = hot_json_u64(info->manifest, "firmware_size_bytes", 0);
    if (strcmp(otad_json_str(info->manifest, "artifact_type", ""), "hot_update") ||
        info->size != (uint64_t)st.st_size) {
        snprintf(error, error_len, "hot_update_size_or_contract_mismatch");
        hot_info_done(info);
        return -1;
    }
    snprintf(info->path, sizeof(info->path), "%s", path);
    return 0;

invalid:
    if (fd >= 0)
        close(fd);
    free(header);
invalid_no_header:
    snprintf(error, error_len, "hot_update_manifest_header_invalid");
    hot_info_done(info);
    return -1;
}

static int hot_payloads_parse(const struct otad_hot_info *info,
                              struct otad_hot_file **files_out, size_t *count_out,
                              char *error, size_t error_len)
{
    struct json_object *arr = NULL;
    struct otad_hot_file *files;
    const char *firmware_type;
    size_t i, count;
    uint64_t previous_end = OTAD_HOT_HEADER_BYTES;

    *files_out = NULL;
    *count_out = 0;
    firmware_type = otad_json_str(info->manifest, "firmware_type", "");
    if (strcmp(firmware_type, "database") && strcmp(firmware_type, "component")) {
        snprintf(error, error_len, "hot_update_firmware_type_invalid");
        return -1;
    }
    if (!json_object_object_get_ex(info->manifest, "payloads", &arr) || !arr ||
        !json_object_is_type(arr, json_type_array)) {
        snprintf(error, error_len, "hot_update_payloads_missing");
        return -1;
    }
    count = json_object_array_length(arr);
    if (count > OTAD_HOT_MAX_PAYLOADS) {
        snprintf(error, error_len, "hot_update_payload_count_invalid");
        return -1;
    }
    if (!count)
        return 0;
    files = calloc(count, sizeof(*files));
    if (!files) {
        snprintf(error, error_len, "out_of_memory");
        return -1;
    }
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        const char *target = otad_json_str(item, "target_path", "");
        const char *md5 = otad_json_str(item, "md5", "");
        const char *sha = otad_json_str(item, "sha256", "");
        const char *base_sha = otad_json_str(item, "base_sha256", "");
        uint64_t end;

        files[i].offset = hot_json_u64(item, "offset_bytes", UINT64_MAX);
        files[i].size = hot_json_u64(item, "size", 0);
        files[i].mode = (mode_t)(hot_json_u64(item, "mode", 0644) & 07777);
        files[i].uid = (uid_t)hot_json_u64(item, "uid", 0);
        files[i].gid = (gid_t)hot_json_u64(item, "gid", 0);
        files[i].base_size = hot_json_u64(item, "base_size", 0);
        files[i].target_exists = otad_json_bool(item, "target_exists", 0);
        end = files[i].offset + files[i].size;
        if (!otad_hot_target_allowed(firmware_type, target) ||
            files[i].offset < previous_end || !files[i].size ||
            end < files[i].offset || end > info->size ||
            !hot_hex_ok(md5, 32) || !hot_hex_ok(sha, 64) ||
            (files[i].target_exists && !hot_hex_ok(base_sha, 64)) ||
            (!files[i].target_exists && base_sha[0])) {
            snprintf(error, error_len, "hot_update_payload_contract_invalid");
            free(files);
            return -1;
        }
        {
            size_t j;
            for (j = 0; j < i; j++) {
                if (!strcmp(files[j].target, target)) {
                    snprintf(error, error_len, "hot_update_duplicate_target");
                    free(files);
                    return -1;
                }
            }
        }
        snprintf(files[i].target, sizeof(files[i].target), "%s", target);
        snprintf(files[i].md5, sizeof(files[i].md5), "%s", md5);
        snprintf(files[i].sha256, sizeof(files[i].sha256), "%s", sha);
        snprintf(files[i].base_sha256, sizeof(files[i].base_sha256), "%s", base_sha);
        previous_end = end;
    }
    *files_out = files;
    *count_out = count;
    return 0;
}

static int hot_payloads_verify(const struct otad_hot_info *info,
                               struct otad_hot_file *files, size_t count,
                               char *error, size_t error_len)
{
    int fd = open(info->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    size_t i;

    if (fd < 0) {
        snprintf(error, error_len, "hot_update_open_failed");
        return -1;
    }
    for (i = 0; i < count; i++) {
        char md5[33] = "", sha[65] = "";

        if (hot_hash_fd_range(fd, files[i].offset, files[i].size, md5, sha) != 0 ||
            strcasecmp(md5, files[i].md5) || strcasecmp(sha, files[i].sha256)) {
            snprintf(error, error_len, "hot_update_payload_integrity_mismatch");
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}

static int hot_targets_verify_base(struct otad_hot_file *files, size_t count,
                                   char *error, size_t error_len)
{
    size_t i;

    for (i = 0; i < count; i++) {
        struct stat st;
        char md5[33] = "", sha[65] = "";

        if (!files[i].target_exists) {
            if (lstat(files[i].target, &st) == 0 || errno != ENOENT) {
                snprintf(error, error_len, "hot_update_new_target_already_exists");
                return -1;
            }
            continue;
        }
        if (lstat(files[i].target, &st) != 0 || !S_ISREG(st.st_mode) ||
            (uint64_t)st.st_size != files[i].base_size ||
            hot_hash_path(files[i].target, files[i].base_size, md5, sha) != 0 ||
            strcasecmp(sha, files[i].base_sha256)) {
            snprintf(error, error_len, "hot_update_base_version_mismatch");
            return -1;
        }
    }
    return 0;
}

static int hot_deletions_parse(const struct otad_hot_info *info,
                               const struct otad_hot_file *files, size_t file_count,
                               struct otad_hot_deletion **out, size_t *count_out,
                               char *error, size_t error_len)
{
    struct json_object *arr = NULL;
    struct otad_hot_deletion *items;
    const char *firmware_type = otad_json_str(info->manifest, "firmware_type", "");
    size_t i, count;

    *out = NULL;
    *count_out = 0;
    if (!json_object_object_get_ex(info->manifest, "deletions", &arr) || !arr)
        return 0;
    if (!json_object_is_type(arr, json_type_array)) {
        snprintf(error, error_len, "hot_update_deletions_invalid");
        return -1;
    }
    count = json_object_array_length(arr);
    if (!count)
        return 0;
    if (count > OTAD_HOT_MAX_DELETIONS) {
        snprintf(error, error_len, "hot_update_deletion_count_invalid");
        return -1;
    }
    items = calloc(count, sizeof(*items));
    if (!items) {
        snprintf(error, error_len, "out_of_memory");
        return -1;
    }
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        const char *target = otad_json_str(item, "target_path", "");
        const char *base_sha = otad_json_str(item, "base_sha256", "");
        size_t j;

        items[i].base_size = hot_json_u64(item, "base_size", UINT64_MAX);
        if (!otad_hot_target_allowed(firmware_type, target) ||
            !hot_hex_ok(base_sha, 64) || items[i].base_size == UINT64_MAX) {
            snprintf(error, error_len, "hot_update_deletion_contract_invalid");
            free(items);
            return -1;
        }
        for (j = 0; j < file_count; j++) {
            if (!strcmp(files[j].target, target)) {
                snprintf(error, error_len, "hot_update_duplicate_target");
                free(items);
                return -1;
            }
        }
        for (j = 0; j < i; j++) {
            if (!strcmp(items[j].target, target)) {
                snprintf(error, error_len, "hot_update_duplicate_deletion");
                free(items);
                return -1;
            }
        }
        snprintf(items[i].target, sizeof(items[i].target), "%s", target);
        snprintf(items[i].base_sha256, sizeof(items[i].base_sha256), "%s", base_sha);
    }
    *out = items;
    *count_out = count;
    return 0;
}

static int hot_deletions_verify_base(struct otad_hot_deletion *items, size_t count,
                                     char *error, size_t error_len)
{
    size_t i;

    for (i = 0; i < count; i++) {
        struct stat st;
        char md5[33] = "", sha[65] = "";

        if (lstat(items[i].target, &st) != 0 || !S_ISREG(st.st_mode) ||
            (uint64_t)st.st_size != items[i].base_size ||
            hot_hash_path(items[i].target, items[i].base_size, md5, sha) != 0 ||
            strcasecmp(sha, items[i].base_sha256)) {
            snprintf(error, error_len, "hot_update_deletion_base_mismatch");
            return -1;
        }
    }
    return 0;
}

static struct json_object *hot_space_gates_json(
    const struct otad_hot_space_gates *gates)
{
    struct json_object *arr = json_object_new_array();
    size_t i;

    if (!gates)
        return arr;
    for (i = 0; i < gates->count; i++) {
        struct json_object *item = json_object_new_object();

        otad_space_gate_add_json(item, &gates->items[i]);
        json_object_array_add(arr, item);
    }
    return arr;
}

static const struct otad_space_gate *hot_space_gate_failed(
    const struct otad_hot_space_gates *gates)
{
    size_t i;

    if (!gates)
        return NULL;
    for (i = 0; i < gates->count; i++)
        if (!gates->items[i].ok)
            return &gates->items[i];
    return NULL;
}

static uint64_t hot_target_required_inodes(const char *target)
{
    char parent[OTAD_MAX_PATH];
    char *slash;
    struct stat st;
    uint64_t inodes = 1;

    if (!target || snprintf(parent, sizeof(parent), "%s", target) >=
            (int)sizeof(parent))
        return UINT64_MAX;
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return inodes;
    *slash = '\0';
    for (;;) {
        if (lstat(parent, &st) == 0)
            return S_ISDIR(st.st_mode) ? inodes : UINT64_MAX;
        if (errno != ENOENT)
            return UINT64_MAX;
        if (inodes == UINT64_MAX)
            return UINT64_MAX;
        inodes++;
        slash = strrchr(parent, '/');
        if (!slash)
            return UINT64_MAX;
        if (slash == parent)
            return inodes;
        *slash = '\0';
    }
}

static int hot_space_gates_check(struct otad_hot_file *files, size_t count,
                                 struct otad_hot_space_gates *gates,
                                 int record_state)
{
    size_t i;
    int failed = 0;

    if (!gates)
        return -1;
    memset(gates, 0, sizeof(*gates));
    for (i = 0; i < count; i++) {
        struct otad_space_gate probe;
        uint64_t file_inodes = hot_target_required_inodes(files[i].target);
        size_t j;

        (void)otad_space_gate_check(files[i].target, "hot_update_payloads",
                                    files[i].size, file_inodes, &probe);
        for (j = 0; j < gates->count; j++)
            if (gates->items[j].device == probe.device && probe.device != 0)
                break;
        if (j == gates->count) {
            if (gates->count >= OTAD_HOT_MAX_SPACE_GATES)
                return -1;
            gates->items[gates->count++] = probe;
        } else {
            struct otad_space_gate *gate = &gates->items[j];

            if (UINT64_MAX - gate->artifact_bytes < files[i].size ||
                gate->required_inodes == UINT64_MAX) {
                gate->ok = 0;
                gate->retryable = 0;
                snprintf(gate->error, sizeof(gate->error),
                         "space_requirement_overflow");
                snprintf(gate->reason, sizeof(gate->reason),
                         "artifact_size_plus_safety_margin_overflow");
            } else {
                uint64_t artifact_inodes = gate->required_inodes >
                    OTAD_SPACE_SAFETY_INODES
                    ? gate->required_inodes - OTAD_SPACE_SAFETY_INODES : 0;
                (void)otad_space_gate_check(gate->path,
                                            "hot_update_payloads",
                                            gate->artifact_bytes + files[i].size,
                                            artifact_inodes > UINT64_MAX - file_inodes
                                                ? UINT64_MAX
                                                : artifact_inodes + file_inodes,
                                            gate);
            }
        }
    }
    for (i = 0; i < gates->count; i++) {
        if (!gates->items[i].ok)
            failed = 1;
    }
    if (record_state) {
        if (hot_space_gate_failed(gates))
            otad_space_gate_record(hot_space_gate_failed(gates));
        else if (gates->count)
            otad_space_gate_record(&gates->items[gates->count - 1]);
    }
    return failed ? -1 : 0;
}

static void hot_release_trust_fields(struct json_object *resp,
                                     int integrity_verified)
{
    json_object_object_add(resp, "verified", json_object_new_boolean(0));
    json_object_object_add(resp, "integrity_verified",
                           json_object_new_boolean(integrity_verified));
    json_object_object_add(resp, "authenticity_verified", json_object_new_boolean(0));
    json_object_object_add(resp, "signature_required", json_object_new_boolean(1));
    json_object_object_add(resp, "signature_verified", json_object_new_boolean(0));
    json_object_object_add(resp, "target_compatible", json_object_new_boolean(0));
    json_object_object_add(resp, "policy_passed", json_object_new_boolean(0));
    json_object_object_add(resp, "safe_to_apply_now", json_object_new_boolean(0));
    otad_json_add_string(resp, "release_gate", "closed");
    /*
     * Distinct from the full firmware path on purpose. Full firmware apply is
     * implemented and now gated on real trust state. Hot update's writer is
     * still compiled out (#if 0 in hot_apply_files), so no trust configuration
     * makes this reachable, and saying "trust gate closed" would send an
     * operator to provision keys that cannot help.
     */
    otad_json_add_string(resp, "release_gate_reason",
                         "hot_update_writer_disabled_in_build");
}

static struct json_object *hot_release_trust_error(const char *message,
                                                   int integrity_verified)
{
    struct json_object *resp = otad_error("hot_update_release_trust_gate_closed",
                                          message);

    hot_release_trust_fields(resp, integrity_verified);
    return resp;
}

static struct json_object *hot_verify_internal(const char *path)
{
    struct otad_hot_info info;
    struct otad_hot_file *files = NULL;
    struct otad_hot_deletion *deletions = NULL;
    struct json_object *validation = NULL;
    struct json_object *resp;
    char error[128] = "";
    struct otad_hot_space_gates gates;
    size_t count = 0;
    size_t deletion_count = 0;

    memset(&gates, 0, sizeof(gates));
    if (hot_header_read(path, &info, error, sizeof(error)) != 0) {
        resp = hot_release_trust_error(
            "hot-update package diagnostic failed and release trust gate is closed", 0);
        otad_json_add_string(resp, "diagnostic_error", error);
        return resp;
    }
    validation = otad_check_manifest(info.manifest);
    if (!validation || !otad_json_bool(validation, "validated", 0)) {
        resp = hot_release_trust_error(
            "hot-update manifest validation failed and release trust gate is closed", 0);
        if (validation)
            json_object_object_add(resp, "validation", validation);
        hot_info_done(&info);
        return resp;
    }
    json_object_put(validation);
    if (hot_payloads_parse(&info, &files, &count, error, sizeof(error)) != 0 ||
        hot_deletions_parse(&info, files, count, &deletions, &deletion_count,
                            error, sizeof(error)) != 0 ||
        hot_space_gates_check(files, count, &gates, 0) != 0 ||
        hot_payloads_verify(&info, files, count, error, sizeof(error)) != 0 ||
        hot_targets_verify_base(files, count, error, sizeof(error)) != 0 ||
        hot_deletions_verify_base(deletions, deletion_count, error, sizeof(error)) != 0) {
        free(files);
        free(deletions);
        hot_info_done(&info);
        if (!error[0] && hot_space_gate_failed(&gates)) {
            resp = hot_release_trust_error(
                "hot-update target filesystem space diagnostic failed and release trust gate is closed",
                0);
            json_object_object_add(resp, "space_gates",
                                   hot_space_gates_json(&gates));
            otad_json_add_string(resp, "diagnostic_error",
                                 hot_space_gate_failed(&gates)->error);
            return resp;
        }
        resp = hot_release_trust_error(
            "hot-update payload integrity diagnostic failed and release trust gate is closed", 0);
        otad_json_add_string(resp, "diagnostic_error", error);
        return resp;
    }
    resp = hot_release_trust_error(
        "hot-update structure and payload integrity are valid but release signature verification is unavailable",
        1);
    json_object_object_add(resp, "validated", json_object_new_boolean(1));
    otad_json_add_string(resp, "artifact_type", "hot_update");
    otad_json_add_string(resp, "firmware_type", otad_json_str(info.manifest, "firmware_type", ""));
    otad_json_add_string(resp, "package_id", otad_json_str(info.manifest, "package_id", ""));
    otad_json_add_string(resp, "to_version", otad_json_str(info.manifest, "to_version", ""));
    json_object_object_add(resp, "firmware_size_bytes", json_object_new_int64((int64_t)info.size));
    json_object_object_add(resp, "payload_count", json_object_new_int((int)count));
    json_object_object_add(resp, "deletion_count", json_object_new_int((int)deletion_count));
    json_object_object_add(resp, "slot_required", json_object_new_boolean(0));
    json_object_object_add(resp, "space_gates", hot_space_gates_json(&gates));
    {
        struct json_object *actions = NULL;

        if (json_object_object_get_ex(info.manifest, "service_actions", &actions) && actions)
            json_object_object_add(resp, "service_actions", json_object_get(actions));
    }
    free(files);
    free(deletions);
    hot_info_done(&info);
    return resp;
}

static int hot_parent_prepare(const char *target, char *parent, size_t parent_len)
{
    char *slash;

    if (snprintf(parent, parent_len, "%s", target) >= (int)parent_len)
        return -1;
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return -1;
    *slash = '\0';
    return otad_mkdir_p(parent, 0755);
}

static int hot_copy_payload(int src, const struct otad_hot_file *file, const char *staged)
{
    unsigned char buf[1024 * 1024];
    uint64_t done = 0;
    int dst = open(staged, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);

    if (dst < 0)
        return -1;
    while (done < file->size) {
        size_t want = sizeof(buf), written = 0;
        ssize_t n;

        if ((uint64_t)want > file->size - done)
            want = (size_t)(file->size - done);
        n = pread(src, buf, want, (off_t)(file->offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            goto fail;
        while (written < (size_t)n) {
            ssize_t w = write(dst, buf + written, (size_t)n - written);
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0)
                goto fail;
            written += (size_t)w;
        }
        done += (uint64_t)n;
    }
    if (fchmod(dst, file->mode) != 0 || fchown(dst, file->uid, file->gid) != 0 ||
        fsync(dst) != 0)
        goto fail;
    if (close(dst) != 0) {
        dst = -1;
        goto fail_closed;
    }
    return 0;
fail:
    if (dst >= 0)
        close(dst);
fail_closed:
    unlink(staged);
    return -1;
}

static void hot_rollback(struct otad_hot_file *files, size_t count)
{
    size_t i = count;

    while (i-- > 0) {
        if (files[i].installed)
            unlink(files[i].target);
        if (files[i].had_original)
            rename(files[i].backup, files[i].target);
        unlink(files[i].staged);
    }
    sync();
}

static void hot_deletions_rollback(struct otad_hot_deletion *items, size_t count)
{
    size_t i = count;

    while (i-- > 0)
        if (items[i].moved)
            rename(items[i].backup, items[i].target);
}

static int hot_stage_and_install(const struct otad_hot_info *info,
                                 struct otad_hot_file *files, size_t count,
                                 struct otad_hot_deletion *deletions,
                                 size_t deletion_count,
                                 struct otad_space_gate *failed_gate,
                                 char *error, size_t error_len) __attribute__((unused));

static int hot_stage_and_install(const struct otad_hot_info *info,
                                 struct otad_hot_file *files, size_t count,
                                 struct otad_hot_deletion *deletions,
                                 size_t deletion_count,
                                 struct otad_space_gate *failed_gate,
                                 char *error, size_t error_len)
{
    (void)info;
    (void)files;
    (void)count;
    (void)deletions;
    (void)deletion_count;
    (void)failed_gate;
    snprintf(error, error_len, "hot_update_release_trust_gate_closed");
    return -1;

#if 0
    struct otad_hot_space_gates gates;
    int src = -1;
    size_t i;

    if (hot_space_gates_check(files, count, &gates, 1) != 0) {
        const struct otad_space_gate *failed = hot_space_gate_failed(&gates);

        if (failed_gate && failed)
            *failed_gate = *failed;
        snprintf(error, error_len, "%s",
                 failed && failed->error[0] ? failed->error : "space_gate_failed");
        return -1;
    }
    src = open(info->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (src < 0) {
        snprintf(error, error_len, "hot_update_open_failed");
        return -1;
    }
    for (i = 0; i < count; i++) {
        char parent[OTAD_MAX_PATH];
        char md5[33] = "", sha[65] = "";

        if (hot_parent_prepare(files[i].target, parent, sizeof(parent)) != 0 ||
            snprintf(files[i].staged, sizeof(files[i].staged), "%s.dwrt-new-%ld",
                     files[i].target, (long)getpid()) >= (int)sizeof(files[i].staged) ||
            snprintf(files[i].backup, sizeof(files[i].backup), "%s.dwrt-old-%ld",
                     files[i].target, (long)getpid()) >= (int)sizeof(files[i].backup)) {
            snprintf(error, error_len, "hot_update_target_prepare_failed");
            goto fail;
        }
        unlink(files[i].staged);
        unlink(files[i].backup);
        if (hot_copy_payload(src, &files[i], files[i].staged) != 0 ||
            hot_hash_path(files[i].staged, files[i].size, md5, sha) != 0 ||
            strcasecmp(md5, files[i].md5) || strcasecmp(sha, files[i].sha256)) {
            snprintf(error, error_len, "hot_update_staged_integrity_mismatch");
            goto fail;
        }
    }
    close(src);
    src = -1;
    for (i = 0; i < count; i++) {
        struct stat st;
        char md5[33] = "", sha[65] = "";

        if (lstat(files[i].target, &st) == 0) {
            if (!S_ISREG(st.st_mode) || rename(files[i].target, files[i].backup) != 0) {
                snprintf(error, error_len, "hot_update_original_backup_failed");
                goto fail;
            }
            files[i].had_original = 1;
        } else if (errno != ENOENT) {
            snprintf(error, error_len, "hot_update_target_stat_failed");
            goto fail;
        }
        if (rename(files[i].staged, files[i].target) != 0) {
            snprintf(error, error_len, "hot_update_atomic_replace_failed");
            goto fail;
        }
        files[i].installed = 1;
        if (hot_hash_path(files[i].target, files[i].size, md5, sha) != 0 ||
            strcasecmp(md5, files[i].md5) || strcasecmp(sha, files[i].sha256)) {
            snprintf(error, error_len, "hot_update_writeback_integrity_mismatch");
            goto fail;
        }
    }
    for (i = 0; i < deletion_count; i++) {
        struct stat st;

        if (snprintf(deletions[i].backup, sizeof(deletions[i].backup),
                     "%s.dwrt-old-%ld", deletions[i].target,
                     (long)getpid()) >= (int)sizeof(deletions[i].backup)) {
            snprintf(error, error_len, "hot_update_deletion_backup_path_invalid");
            goto fail;
        }
        unlink(deletions[i].backup);
        if (lstat(deletions[i].target, &st) != 0 || !S_ISREG(st.st_mode) ||
            rename(deletions[i].target, deletions[i].backup) != 0) {
            snprintf(error, error_len, "hot_update_deletion_backup_failed");
            goto fail;
        }
        deletions[i].moved = 1;
        if (lstat(deletions[i].target, &st) == 0 || errno != ENOENT) {
            snprintf(error, error_len, "hot_update_deletion_writeback_failed");
            goto fail;
        }
    }
    for (i = 0; i < count; i++)
        if (files[i].had_original)
            unlink(files[i].backup);
    for (i = 0; i < deletion_count; i++)
        if (deletions[i].moved)
            unlink(deletions[i].backup);
    sync();
    return 0;

fail:
    if (src >= 0)
        close(src);
    hot_deletions_rollback(deletions, deletion_count);
    hot_rollback(files, count);
    return -1;
#endif
}

static int hot_run_restart(const char *service)
{
    pid_t pid = fork();
    int status;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        execl("/usr/bin/dreamingwrt-init", "dreamingwrt-init", "restart", service, NULL);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static void hot_restart_worker(void)
{
    size_t i;

    sleep(1);
    for (i = 0; i < g_hot_restart_count; i++)
        if (strcmp(g_hot_restarts[i], "otad"))
            hot_run_restart(g_hot_restarts[i]);
    for (i = 0; i < g_hot_restart_count; i++)
        if (!strcmp(g_hot_restarts[i], "otad"))
            hot_run_restart(g_hot_restarts[i]);
    _exit(0);
}

static void hot_restart_timer_cb(struct uloop_timeout *timeout)
{
    pid_t pid;
    int status;

    (void)timeout;
    pid = fork();
    if (pid == 0) {
        pid_t worker = fork();
        if (worker == 0)
            hot_restart_worker();
        _exit(worker < 0 ? 1 : 0);
    }
    if (pid > 0)
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
}

static int hot_schedule_restarts(struct json_object *manifest) __attribute__((unused));

static int hot_schedule_restarts(struct json_object *manifest)
{
    (void)manifest;
    return -1;

#if 0
    struct json_object *arr = NULL;
    size_t i, count;

    g_hot_restart_count = 0;
    if (!json_object_object_get_ex(manifest, "service_actions", &arr) || !arr)
        return 0;
    count = json_object_array_length(arr);
    if (count > OTAD_HOT_MAX_RESTARTS)
        return -1;
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        const char *service = otad_json_str(item, "service", "");

        if (!otad_component_name_ok(service))
            return -1;
        snprintf(g_hot_restarts[g_hot_restart_count++],
                 sizeof(g_hot_restarts[0]), "%s", service);
    }
    g_hot_restart_timer.cb = hot_restart_timer_cb;
    uloop_timeout_set(&g_hot_restart_timer, 500);
    return 0;
#endif
}

static int update_magic_is_hot(const char *path)
{
    char magic[sizeof(OTAD_HOT_MAGIC)] = "";
    int fd;
    ssize_t n;

    if (!path || !hot_package_path_allowed(path))
        return 0;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return 0;
    n = read(fd, magic, strlen(OTAD_HOT_MAGIC));
    close(fd);
    return n == (ssize_t)strlen(OTAD_HOT_MAGIC) &&
           !memcmp(magic, OTAD_HOT_MAGIC, strlen(OTAD_HOT_MAGIC));
}

struct json_object *otad_update_verify(struct json_object *body)
{
    const char *path = otad_json_str(body, "path", "");

    if (update_magic_is_hot(path))
        return hot_verify_internal(path);
    return otad_firmware_verify(body);
}

struct json_object *otad_update_apply(struct json_object *body)
{
    const char *path = otad_json_str(body, "path", "");

    if (!update_magic_is_hot(path))
        return otad_firmware_apply(body);
    return hot_release_trust_error(
        "hot-update apply is disabled until release signatures can be verified", 0);
}
