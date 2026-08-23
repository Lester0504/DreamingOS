// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "otad_internal.h"
#include <sys/utsname.h>

struct otad_target_identity {
    char architecture[64];
    char target[64];
    char subtarget[64];
    char board[128];
    char model[256];
    char libc[32];
    char abi_version[32];
    int boot_schema;
};

static int trust_identity_field_set(char *out, size_t out_len,
                                    const char *value)
{
    size_t value_len;

    if (!out || !out_len || !value || !(value_len = strlen(value)) ||
        value_len >= out_len)
        return -1;
    memcpy(out, value, value_len + 1);
    return 0;
}

static int trust_key_id_ok(const char *value)
{
    const unsigned char *p;
    size_t len = value ? strlen(value) : 0;

    if (!len || len > 128 || !isalnum((unsigned char)value[0]))
        return 0;
    for (p = (const unsigned char *)value + 1; *p; p++)
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '-')
            return 0;
    return 1;
}

static int trust_base64_decode(const char *text, unsigned char **out,
                               size_t *out_len, size_t max_len)
{
    unsigned char *buf;
    size_t len;
    int decoded;
    int padding = 0;

    if (!text || !out || !out_len || !(len = strlen(text)) ||
        len % 4 || len > ((max_len + 2) / 3) * 4 + 4)
        return -1;
    buf = malloc(len / 4 * 3 + 1);
    if (!buf)
        return -1;
    decoded = EVP_DecodeBlock(buf, (const unsigned char *)text, (int)len);
    if (decoded < 0) {
        free(buf);
        return -1;
    }
    if (len && text[len - 1] == '=')
        padding++;
    if (len > 1 && text[len - 2] == '=')
        padding++;
    decoded -= padding;
    if (decoded < 0 || (size_t)decoded > max_len) {
        free(buf);
        return -1;
    }
    buf[decoded] = '\0';
    *out = buf;
    *out_len = (size_t)decoded;
    return 0;
}

static int trust_sha256_range(int fd, uint64_t offset, uint64_t size,
                              char out[65])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char buf[256 * 1024];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    uint64_t done = 0;
    unsigned int i;
    int rc = -1;

    if (fd < 0 || !size || offset > UINT64_MAX - size)
        return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto out;
    while (done < size) {
        size_t want = sizeof(buf);
        ssize_t n;

        if ((uint64_t)want > size - done)
            want = (size_t)(size - done);
        n = pread(fd, buf, want, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || EVP_DigestUpdate(ctx, buf, (size_t)n) != 1)
            goto out;
        done += (uint64_t)n;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32)
        goto out;
    for (i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 65 - i * 2, "%02x", digest[i]);
    out[64] = '\0';
    rc = 0;
out:
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int trust_sha256_bytes(const void *data, size_t len, char out[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned int i;

    if (!data || !len || !out ||
        EVP_Digest(data, len, digest, &digest_len, EVP_sha256(), NULL) != 1 ||
        digest_len != 32)
        return -1;
    for (i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 65 - i * 2, "%02x", digest[i]);
    out[64] = '\0';
    return 0;
}

static int trust_sha256_file(const char *path, char out[65])
{
    char *text = NULL;
    size_t len = 0;
    int rc;

    if (!path || otad_file_read_all(path, &text, &len, OTAD_MAX_JSON_BYTES) != 0)
        return -1;
    rc = trust_sha256_bytes(text, len, out);
    free(text);
    return rc;
}

static int trust_release_assignment(const char *text, const char *key,
                                    char *out, size_t out_len)
{
    const char *line = text;
    size_t key_len = strlen(key);

    if (!text || !key || !out || out_len == 0)
        return -1;
    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);

        if (len > key_len + 2 && !strncmp(line, key, key_len) &&
            line[key_len] == '=' &&
            (line[key_len + 1] == '\'' || line[key_len + 1] == '"')) {
            char quote = line[key_len + 1];
            size_t value_len = len - key_len - 2;

            if (!value_len || line[len - 1] != quote)
                return -1;
            value_len--;
            if (value_len >= out_len)
                return -1;
            memcpy(out, line + key_len + 2, value_len);
            out[value_len] = '\0';
            return 0;
        }
        line = end ? end + 1 : NULL;
    }
    return -1;
}

static void trust_read_first_line(const char *path, char *out, size_t out_len)
{
    char *text = NULL;
    size_t len = 0;
    char *end;

    if (!out || !out_len)
        return;
    out[0] = '\0';
    if (otad_file_read_all(path, &text, &len, 4096) != 0)
        return;
    end = strpbrk(text, "\r\n");
    if (end)
        *end = '\0';
    snprintf(out, out_len, "%s", text);
    free(text);
}

static int trust_device_identity(struct otad_target_identity *identity)
{
    struct utsname uts;
    const char *architecture;
    char *release = NULL;
    size_t release_len = 0;
    char distrib_target[128] = "";
    char sysinfo_path[OTAD_MAX_PATH];
    char *slash;

    if (!identity || uname(&uts) != 0)
        return -1;
    memset(identity, 0, sizeof(*identity));
    architecture = !strcmp(uts.machine, "amd64") ? "x86_64" : uts.machine;
    if (trust_identity_field_set(identity->architecture,
                                 sizeof(identity->architecture),
                                 architecture) != 0)
        return -1;
    if (otad_file_read_all(OTAD_OPENWRT_RELEASE_PATH, &release, &release_len,
                           64 * 1024) != 0 ||
        trust_release_assignment(release, "DISTRIB_TARGET", distrib_target,
                                 sizeof(distrib_target)) != 0) {
        free(release);
        return -1;
    }
    free(release);
    slash = strchr(distrib_target, '/');
    if (!slash || slash == distrib_target || !slash[1])
        return -1;
    *slash++ = '\0';
    if (trust_identity_field_set(identity->target, sizeof(identity->target),
                                 distrib_target) != 0 ||
        trust_identity_field_set(identity->subtarget,
                                 sizeof(identity->subtarget), slash) != 0)
        return -1;
    snprintf(sysinfo_path, sizeof(sysinfo_path), "%s/board_name", OTAD_SYSINFO_DIR);
    trust_read_first_line(sysinfo_path, identity->board, sizeof(identity->board));
    snprintf(sysinfo_path, sizeof(sysinfo_path), "%s/model", OTAD_SYSINFO_DIR);
    trust_read_first_line(sysinfo_path, identity->model, sizeof(identity->model));
    if (!identity->board[0])
        snprintf(identity->board, sizeof(identity->board), "%s", identity->subtarget);
    /*
     * OTAD_IDENTITY_LIBC exists so the verifier can be exercised on a host that
     * is neither glibc nor musl. Device builds never set it and keep the same
     * detection as before; without a value the identity stays unavailable, which
     * fails the trust check closed.
     */
#ifdef OTAD_IDENTITY_LIBC
    snprintf(identity->libc, sizeof(identity->libc), "%s", OTAD_IDENTITY_LIBC);
#elif defined(__GLIBC__)
    snprintf(identity->libc, sizeof(identity->libc), "glibc");
#elif defined(__MUSL__)
    snprintf(identity->libc, sizeof(identity->libc), "musl");
#else
    return -1;
#endif
    snprintf(identity->abi_version, sizeof(identity->abi_version), "%s",
             OTAD_RUNTIME_ABI_VERSION);
    identity->boot_schema = OTAD_BOOT_SCHEMA_VERSION;
    return 0;
}

static int trust_device_identity_digest(const struct otad_target_identity *identity,
                                        char out[65])
{
    struct json_object *o;
    const char *text;
    int rc;

    if (!identity || !out)
        return -1;
    o = json_object_new_object();
    if (!o)
        return -1;
    otad_json_add_string(o, "architecture", identity->architecture);
    otad_json_add_string(o, "target", identity->target);
    otad_json_add_string(o, "subtarget", identity->subtarget);
    otad_json_add_string(o, "board", identity->board);
    otad_json_add_string(o, "model", identity->model);
    otad_json_add_string(o, "libc", identity->libc);
    otad_json_add_string(o, "abi_version", identity->abi_version);
    json_object_object_add(o, "boot_schema", json_object_new_int(identity->boot_schema));
    text = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    rc = text ? trust_sha256_bytes(text, strlen(text), out) : -1;
    json_object_put(o);
    return rc;
}

static int trust_models_match(struct json_object *models, const char *signed_board,
                              const struct otad_target_identity *identity)
{
    size_t i;

    if (!models || !json_object_is_type(models, json_type_array) ||
        json_object_array_length(models) == 0)
        return 0;
    for (i = 0; i < json_object_array_length(models); i++) {
        const char *model = json_object_get_string(json_object_array_get_idx(models, i));

        if (!model || !model[0])
            continue;
        if (!strcmp(model, "*") || !strcmp(model, identity->board) ||
            (identity->model[0] && !strcmp(model, identity->model)))
            return 1;
        if (!strcmp(signed_board, "generic") && !strcmp(model, "generic") &&
            !strcmp(identity->target, "x86"))
            return 1;
    }
    return 0;
}

static int trust_target_match(struct json_object *target,
                              const struct otad_target_identity *identity,
                              char *reason, size_t reason_len)
{
    struct json_object *models = NULL;
    const char *board;

#define REQUIRE_TARGET_TEXT(field, actual) do { \
    const char *expected = otad_json_str(target, field, ""); \
    if (!expected[0] || strcmp(expected, (actual))) { \
        snprintf(reason, reason_len, "target_%s_mismatch", field); \
        return -1; \
    } \
} while (0)

    if (!target || !json_object_is_type(target, json_type_object)) {
        snprintf(reason, reason_len, "target_contract_missing");
        return -1;
    }
    REQUIRE_TARGET_TEXT("architecture", identity->architecture);
    REQUIRE_TARGET_TEXT("target", identity->target);
    REQUIRE_TARGET_TEXT("subtarget", identity->subtarget);
    REQUIRE_TARGET_TEXT("libc", identity->libc);
    REQUIRE_TARGET_TEXT("abi_version", identity->abi_version);
    board = otad_json_str(target, "board", "");
    if (!board[0] || (strcmp(board, "generic") && strcmp(board, identity->board))) {
        snprintf(reason, reason_len, "target_board_mismatch");
        return -1;
    }
    if (!json_object_object_get_ex(target, "models", &models) ||
        !trust_models_match(models, board, identity)) {
        snprintf(reason, reason_len, "target_model_mismatch");
        return -1;
    }
    if (otad_json_int(target, "min_boot_schema", 0) < 1 ||
        otad_json_int(target, "min_boot_schema", INT_MAX) > identity->boot_schema) {
        snprintf(reason, reason_len, "target_boot_schema_incompatible");
        return -1;
    }
    return 0;
#undef REQUIRE_TARGET_TEXT
}

static int trust_load_policy(struct json_object **policy_out, char *error,
                             size_t error_len)
{
    char *text = NULL;
    size_t len = 0;
    struct json_object *policy = NULL;

    if (!policy_out || otad_file_read_all(OTAD_TRUST_POLICY_PATH, &text, &len,
                                          OTAD_MAX_JSON_BYTES) != 0) {
        snprintf(error, error_len, "trust_policy_unavailable");
        return -1;
    }
    policy = json_tokener_parse(text);
    free(text);
    if (!policy || !json_object_is_type(policy, json_type_object) ||
        otad_json_int(policy, "schema_version", 0) != 1 ||
        otad_json_int(policy, "policy_version", 0) < 1) {
        if (policy)
            json_object_put(policy);
        snprintf(error, error_len, "trust_policy_invalid");
        return -1;
    }
    *policy_out = policy;
    return 0;
}

static int trust_key_allowed(struct json_object *policy, const char *key_id,
                             int64_t now, char *error, size_t error_len)
{
    struct json_object *keys = NULL;
    size_t i;

    if (!json_object_object_get_ex(policy, "keys", &keys) ||
        !json_object_is_type(keys, json_type_array)) {
        snprintf(error, error_len, "trust_policy_keys_invalid");
        return -1;
    }
    for (i = 0; i < json_object_array_length(keys); i++) {
        struct json_object *key = json_object_array_get_idx(keys, i);
        int64_t not_before;
        int64_t not_after;

        if (!key || strcmp(otad_json_str(key, "key_id", ""), key_id))
            continue;
        if (strcmp(otad_json_str(key, "status", ""), "active")) {
            snprintf(error, error_len, "signing_key_revoked_or_inactive");
            return -1;
        }
        not_before = json_object_get_int64(json_object_object_get(key, "not_before"));
        not_after = json_object_get_int64(json_object_object_get(key, "not_after"));
        if ((not_before > 0 && now < not_before) ||
            (not_after > 0 && now > not_after)) {
            snprintf(error, error_len, "signing_key_outside_validity");
            return -1;
        }
        return 0;
    }
    snprintf(error, error_len, "signing_key_unknown");
    return -1;
}

static int trust_verify_ed25519(const char *key_id,
                                const unsigned char *payload, size_t payload_len,
                                const unsigned char *signature, size_t signature_len,
                                char *error, size_t error_len)
{
    char key_path[OTAD_MAX_PATH];
    FILE *fp = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    int rc = -1;

    if (!trust_key_id_ok(key_id) || signature_len != 64 ||
        snprintf(key_path, sizeof(key_path), "%s/%s.pem", OTAD_TRUST_KEY_DIR,
                 key_id) >= (int)sizeof(key_path)) {
        snprintf(error, error_len, "release_signature_contract_invalid");
        return -1;
    }
    fp = fopen(key_path, "r");
    if (!fp || !(key = PEM_read_PUBKEY(fp, NULL, NULL, NULL))) {
        snprintf(error, error_len, "signing_public_key_unavailable");
        goto out;
    }
    if (EVP_PKEY_base_id(key) != EVP_PKEY_ED25519) {
        snprintf(error, error_len, "signing_public_key_algorithm_mismatch");
        goto out;
    }
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1 ||
        EVP_DigestVerify(ctx, signature, signature_len, payload, payload_len) != 1) {
        snprintf(error, error_len, "release_signature_invalid");
        goto out;
    }
    rc = 0;
out:
    if (fp)
        fclose(fp);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

static struct json_object *trust_outer_statement(struct json_object *firmware_info)
{
    const char *text;
    struct json_object *copy;

    text = json_object_to_json_string_ext(firmware_info, JSON_C_TO_STRING_PLAIN);
    copy = text ? json_tokener_parse(text) : NULL;
    if (!copy || !json_object_is_type(copy, json_type_object)) {
        if (copy)
            json_object_put(copy);
        return NULL;
    }
    json_object_object_del(copy, "release_signature");
    json_object_object_add(copy, "statement_type",
                           json_object_new_string(OTAD_RELEASE_STATEMENT_TYPE));
    return copy;
}

static struct json_object *trust_hot_statement(struct json_object *manifest)
{
    const char *text;
    struct json_object *copy;

    text = json_object_to_json_string_ext(manifest, JSON_C_TO_STRING_PLAIN);
    copy = text ? json_tokener_parse(text) : NULL;
    if (!copy || !json_object_is_type(copy, json_type_object)) {
        if (copy)
            json_object_put(copy);
        return NULL;
    }
    json_object_object_del(copy, "release_signature");
    json_object_object_add(copy, "statement_type",
                           json_object_new_string(OTAD_HOT_STATEMENT_TYPE));
    return copy;
}

static int trust_current_release_policy(struct json_object *policy,
                                        int candidate_epoch, const char *candidate_build,
                                        int *current_epoch_out,
                                        char *error, size_t error_len)
{
    struct json_object *current = NULL;
    const char *release_path = NULL;
    char release_error[OTAD_MAX_TEXT] = "";
    int release_rc;
    int current_epoch = 0;
    const char *current_build = "";
    int minimum_epoch = otad_json_int(policy, "minimum_security_epoch", 1);

    if (candidate_epoch < 1 || candidate_epoch < minimum_epoch) {
        snprintf(error, error_len, "security_epoch_below_policy");
        return -1;
    }
    release_rc = otad_release_metadata_read(&current, &release_path,
                                            release_error,
                                            sizeof(release_error));
    (void)release_path;
    if (release_rc < 0) {
        snprintf(error, error_len, "%s", release_error);
        return -1;
    }
    if (current && json_object_is_type(current, json_type_object)) {
        struct json_object *target = NULL;

        if (json_object_object_get_ex(current, "target", &target))
            current_epoch = otad_json_int(target, "security_epoch", 0);
        current_build = otad_json_str(current, "build_id", "");
    }
    if (current_epoch_out)
        *current_epoch_out = current_epoch;
    if (candidate_epoch < current_epoch &&
        !otad_json_bool(policy, "allow_security_epoch_downgrade", 0)) {
        snprintf(error, error_len, "security_epoch_downgrade_forbidden");
        if (current)
            json_object_put(current);
        return -1;
    }
    if (candidate_epoch == current_epoch && current_build[0] && candidate_build &&
        strcmp(candidate_build, current_build) < 0 &&
        !otad_json_bool(policy, "allow_build_downgrade", 0)) {
        snprintf(error, error_len, "build_downgrade_forbidden");
        if (current)
            json_object_put(current);
        return -1;
    }
    if (candidate_epoch == current_epoch && current_build[0] && candidate_build &&
        !strcmp(candidate_build, current_build) &&
        !otad_json_bool(policy, "allow_same_build", 0)) {
        snprintf(error, error_len, "same_build_reinstall_forbidden");
        if (current)
            json_object_put(current);
        return -1;
    }
    if (current)
        json_object_put(current);
    return 0;
}

int otad_release_trust_verify(int firmware_fd, uint64_t firmware_size,
                              struct json_object *firmware_info,
                              struct json_object **evidence_out,
                              char *error, size_t error_len)
{
    struct json_object *evidence = json_object_new_object();
    struct json_object *signature_object = NULL;
    struct json_object *signed_json = NULL;
    struct json_object *outer_statement = NULL;
    struct json_object *policy = NULL;
    struct json_object *target = NULL;
    struct json_object *payload_region = NULL;
    struct otad_target_identity identity;
    unsigned char *signed_payload = NULL;
    unsigned char *signature = NULL;
    size_t signed_payload_len = 0;
    size_t signature_len = 0;
    const char *key_id = "";
    char payload_sha[65] = "";
    char manifest_digest[65] = "";
    char policy_digest[65] = "";
    char identity_digest[65] = "";
    char target_reason[96] = "";
    uint64_t region_offset;
    uint64_t region_size;
    int current_epoch = 0;
    int candidate_epoch;
    int rc = -1;

    if (error && error_len)
        error[0] = '\0';
    json_object_object_add(evidence, "authenticity_verified", json_object_new_boolean(0));
    json_object_object_add(evidence, "signature_required", json_object_new_boolean(1));
    json_object_object_add(evidence, "signature_verified", json_object_new_boolean(0));
    json_object_object_add(evidence, "target_compatible", json_object_new_boolean(0));
    json_object_object_add(evidence, "policy_passed", json_object_new_boolean(0));
    if (!firmware_info || !json_object_is_type(firmware_info, json_type_object) ||
        otad_json_int(firmware_info, "schema_version", 0) != 3 ||
        strcmp(otad_json_str(firmware_info, "release_state", ""), "signed") ||
        !otad_json_bool(firmware_info, "publishable", 0)) {
        snprintf(error, error_len, "signed_release_schema_required");
        goto out;
    }
    if (trust_load_policy(&policy, error, error_len) != 0)
        goto out;
    if (trust_sha256_file(OTAD_TRUST_POLICY_PATH, policy_digest) != 0) {
        snprintf(error, error_len, "trust_policy_digest_failed");
        goto out;
    }
    json_object_object_add(evidence, "trust_policy_version",
                           json_object_new_int(otad_json_int(policy, "policy_version", 0)));
    otad_json_add_string(evidence, "trust_policy_digest", policy_digest);
    if (!json_object_object_get_ex(firmware_info, "release_signature", &signature_object) ||
        !signature_object ||
        strcmp(otad_json_str(signature_object, "algorithm", ""), "ed25519") ||
        strcmp(otad_json_str(signature_object, "signed_payload_encoding", ""), "base64") ||
        strcmp(otad_json_str(signature_object, "signature_encoding", ""), "base64")) {
        snprintf(error, error_len, "release_signature_contract_invalid");
        goto out;
    }
    key_id = otad_json_str(signature_object, "key_id", "");
    otad_json_add_string(evidence, "key_id", key_id);
    otad_json_add_string(evidence, "signing_key_id", key_id);
    if (!trust_key_id_ok(key_id) ||
        trust_key_allowed(policy, key_id, otad_now_s(), error, error_len) != 0 ||
        trust_base64_decode(otad_json_str(signature_object, "signed_payload", ""),
                            &signed_payload, &signed_payload_len,
                            OTAD_MAX_JSON_BYTES) != 0 ||
        trust_base64_decode(otad_json_str(signature_object, "signature", ""),
                            &signature, &signature_len, 128) != 0)
        goto out;
    if (trust_sha256_bytes(signed_payload, signed_payload_len,
                           manifest_digest) != 0) {
        snprintf(error, error_len, "signed_manifest_digest_failed");
        goto out;
    }
    otad_json_add_string(evidence, "manifest_digest", manifest_digest);
    if (trust_verify_ed25519(key_id, signed_payload, signed_payload_len,
                             signature, signature_len, error, error_len) != 0)
        goto out;
    signed_json = json_tokener_parse((const char *)signed_payload);
    outer_statement = trust_outer_statement(firmware_info);
    if (!signed_json || !outer_statement ||
        !json_object_equal(signed_json, outer_statement) ||
        strcmp(otad_json_str(signed_json, "statement_type", ""),
               OTAD_RELEASE_STATEMENT_TYPE)) {
        snprintf(error, error_len, "signed_statement_metadata_mismatch");
        goto out;
    }
    json_object_object_del(evidence, "signature_verified");
    json_object_object_add(evidence, "signature_verified", json_object_new_boolean(1));
    if (!json_object_object_get_ex(firmware_info, "payload_region", &payload_region)) {
        snprintf(error, error_len, "payload_region_contract_missing");
        goto out;
    }
    region_offset = (uint64_t)json_object_get_int64(
        json_object_object_get(payload_region, "offset_bytes"));
    region_size = (uint64_t)json_object_get_int64(
        json_object_object_get(payload_region, "size_bytes"));
    if (region_offset != OTAD_FIRMWARE_HEADER_BYTES ||
        region_size != firmware_size - OTAD_FIRMWARE_HEADER_BYTES ||
        strlen(otad_json_str(payload_region, "sha256", "")) != 64 ||
        trust_sha256_range(firmware_fd, region_offset, region_size, payload_sha) != 0 ||
        strcasecmp(payload_sha, otad_json_str(payload_region, "sha256", ""))) {
        snprintf(error, error_len, "signed_payload_region_sha256_mismatch");
        goto out;
    }
    if (trust_device_identity(&identity) != 0) {
        snprintf(error, error_len, "device_target_identity_unavailable");
        goto out;
    }
    if (trust_device_identity_digest(&identity, identity_digest) != 0) {
        snprintf(error, error_len, "device_identity_digest_failed");
        goto out;
    }
    otad_json_add_string(evidence, "device_identity_digest", identity_digest);
    if (!json_object_object_get_ex(firmware_info, "target", &target) ||
        trust_target_match(target, &identity, target_reason,
                           sizeof(target_reason)) != 0) {
        snprintf(error, error_len, "%s",
                 target_reason[0] ? target_reason : "target_incompatible");
        goto out;
    }
    candidate_epoch = otad_json_int(target, "security_epoch", 0);
    if (trust_current_release_policy(policy, candidate_epoch,
                                     otad_json_str(firmware_info, "build_id", ""),
                                     &current_epoch, error, error_len) != 0)
        goto out;
    json_object_object_add(evidence, "candidate_security_epoch",
                           json_object_new_int(candidate_epoch));
    json_object_object_add(evidence, "current_security_epoch",
                           json_object_new_int(current_epoch));
    json_object_object_del(evidence, "authenticity_verified");
    json_object_object_add(evidence, "authenticity_verified", json_object_new_boolean(1));
    json_object_object_del(evidence, "target_compatible");
    json_object_object_add(evidence, "target_compatible", json_object_new_boolean(1));
    json_object_object_del(evidence, "policy_passed");
    json_object_object_add(evidence, "policy_passed", json_object_new_boolean(1));
    otad_json_add_string(evidence, "signature_status", "verified");
    otad_json_add_string(evidence, "target_status", "compatible");
    rc = 0;
out:
    if (rc != 0) {
        const char *reason = error && error[0] ? error : "release_trust_verification_failed";
        if (error && error_len && !error[0])
            snprintf(error, error_len, "%s", reason);
        otad_json_add_string(evidence, "signature_status", reason);
        otad_json_add_string(evidence, "target_status", reason);
    }
    free(signed_payload);
    free(signature);
    if (signed_json)
        json_object_put(signed_json);
    if (outer_statement)
        json_object_put(outer_statement);
    if (policy)
        json_object_put(policy);
    if (evidence_out)
        *evidence_out = evidence;
    else
        json_object_put(evidence);
    return rc;
}

/*
 * Epoch policy for a hot update. Deliberately narrower than
 * trust_current_release_policy(): a hot package does not replace the slot and
 * does not rewrite build_id, so the build_id downgrade and same-build checks
 * do not apply and would reject every legitimate hot update (allow_same_build
 * is false in the shipped policy). The security epoch floor still applies -
 * that is what stops a signed but superseded package from walking the device
 * back past a security fix.
 */
static int trust_hot_epoch_policy(struct json_object *policy, int candidate_epoch,
                                  int *current_epoch_out,
                                  char *error, size_t error_len)
{
    struct json_object *current = NULL;
    const char *release_path = NULL;
    char release_error[OTAD_MAX_TEXT] = "";
    int minimum_epoch = otad_json_int(policy, "minimum_security_epoch", 1);
    int current_epoch = 0;
    int release_rc;

    if (candidate_epoch < 1 || candidate_epoch < minimum_epoch) {
        snprintf(error, error_len, "security_epoch_below_policy");
        return -1;
    }
    release_rc = otad_release_metadata_read(&current, &release_path, release_error,
                                           sizeof(release_error));
    (void)release_path;
    if (release_rc < 0) {
        snprintf(error, error_len, "%s", release_error);
        return -1;
    }
    if (current && json_object_is_type(current, json_type_object)) {
        struct json_object *target = NULL;

        if (json_object_object_get_ex(current, "target", &target))
            current_epoch = otad_json_int(target, "security_epoch", 0);
    }
    if (current_epoch_out)
        *current_epoch_out = current_epoch;
    if (candidate_epoch < current_epoch &&
        !otad_json_bool(policy, "allow_security_epoch_downgrade", 0)) {
        snprintf(error, error_len, "security_epoch_downgrade_forbidden");
        if (current)
            json_object_put(current);
        return -1;
    }
    if (current)
        json_object_put(current);
    return 0;
}

int otad_hot_release_trust_verify(struct json_object *manifest,
                                 struct json_object **evidence_out,
                                 char *error, size_t error_len)
{
    struct json_object *evidence = json_object_new_object();
    struct json_object *signature_object = NULL;
    struct json_object *signed_json = NULL;
    struct json_object *outer_statement = NULL;
    struct json_object *policy = NULL;
    struct json_object *target = NULL;
    struct otad_target_identity identity;
    unsigned char *signed_payload = NULL;
    unsigned char *signature = NULL;
    size_t signed_payload_len = 0;
    size_t signature_len = 0;
    const char *key_id = "";
    const char *manifest_arch;
    char manifest_digest[65] = "";
    char policy_digest[65] = "";
    char identity_digest[65] = "";
    char target_reason[96] = "";
    int current_epoch = 0;
    int candidate_epoch;
    int rc = -1;

    if (error && error_len)
        error[0] = '\0';
    json_object_object_add(evidence, "authenticity_verified", json_object_new_boolean(0));
    json_object_object_add(evidence, "signature_required", json_object_new_boolean(1));
    json_object_object_add(evidence, "signature_verified", json_object_new_boolean(0));
    json_object_object_add(evidence, "target_compatible", json_object_new_boolean(0));
    json_object_object_add(evidence, "policy_passed", json_object_new_boolean(0));
    otad_json_add_string(evidence, "statement_type", OTAD_HOT_STATEMENT_TYPE);
    /*
     * There is no payload_region for a hot package. Authenticity of the bytes
     * comes from the signed manifest carrying a sha256 (and md5) for every
     * payload, which hot_payloads_verify() then checks against the file. Saying
     * so in the evidence keeps the binding auditable rather than implied.
     */
    otad_json_add_string(evidence, "payload_binding", "manifest_payload_digests");
    if (!manifest || !json_object_is_type(manifest, json_type_object) ||
        strcmp(otad_json_str(manifest, "artifact_type", ""), "hot_update") ||
        otad_json_int(manifest, "manifest_version", 0) != 1 ||
        strcmp(otad_json_str(manifest, "release_state", ""), "signed") ||
        !otad_json_bool(manifest, "publishable", 0)) {
        snprintf(error, error_len, "signed_hot_update_schema_required");
        goto out;
    }
    if (trust_load_policy(&policy, error, error_len) != 0)
        goto out;
    if (trust_sha256_file(OTAD_TRUST_POLICY_PATH, policy_digest) != 0) {
        snprintf(error, error_len, "trust_policy_digest_failed");
        goto out;
    }
    json_object_object_add(evidence, "trust_policy_version",
                           json_object_new_int(otad_json_int(policy, "policy_version", 0)));
    otad_json_add_string(evidence, "trust_policy_digest", policy_digest);
    if (!json_object_object_get_ex(manifest, "release_signature", &signature_object) ||
        !signature_object ||
        strcmp(otad_json_str(signature_object, "algorithm", ""), "ed25519") ||
        strcmp(otad_json_str(signature_object, "signed_payload_encoding", ""), "base64") ||
        strcmp(otad_json_str(signature_object, "signature_encoding", ""), "base64")) {
        snprintf(error, error_len, "release_signature_contract_invalid");
        goto out;
    }
    key_id = otad_json_str(signature_object, "key_id", "");
    otad_json_add_string(evidence, "key_id", key_id);
    otad_json_add_string(evidence, "signing_key_id", key_id);
    if (!trust_key_id_ok(key_id) ||
        trust_key_allowed(policy, key_id, otad_now_s(), error, error_len) != 0 ||
        trust_base64_decode(otad_json_str(signature_object, "signed_payload", ""),
                            &signed_payload, &signed_payload_len,
                            OTAD_MAX_JSON_BYTES) != 0 ||
        trust_base64_decode(otad_json_str(signature_object, "signature", ""),
                            &signature, &signature_len, 128) != 0)
        goto out;
    if (trust_sha256_bytes(signed_payload, signed_payload_len, manifest_digest) != 0) {
        snprintf(error, error_len, "signed_manifest_digest_failed");
        goto out;
    }
    otad_json_add_string(evidence, "manifest_digest", manifest_digest);
    if (trust_verify_ed25519(key_id, signed_payload, signed_payload_len,
                             signature, signature_len, error, error_len) != 0)
        goto out;
    signed_json = json_tokener_parse((const char *)signed_payload);
    outer_statement = trust_hot_statement(manifest);
    if (!signed_json || !outer_statement ||
        !json_object_equal(signed_json, outer_statement) ||
        strcmp(otad_json_str(signed_json, "statement_type", ""),
               OTAD_HOT_STATEMENT_TYPE)) {
        snprintf(error, error_len, "signed_statement_metadata_mismatch");
        goto out;
    }
    json_object_object_del(evidence, "signature_verified");
    json_object_object_add(evidence, "signature_verified", json_object_new_boolean(1));
    if (trust_device_identity(&identity) != 0) {
        snprintf(error, error_len, "device_target_identity_unavailable");
        goto out;
    }
    if (trust_device_identity_digest(&identity, identity_digest) != 0) {
        snprintf(error, error_len, "device_identity_digest_failed");
        goto out;
    }
    otad_json_add_string(evidence, "device_identity_digest", identity_digest);
    if (!json_object_object_get_ex(manifest, "target", &target) ||
        trust_target_match(target, &identity, target_reason,
                           sizeof(target_reason)) != 0) {
        snprintf(error, error_len, "%s",
                 target_reason[0] ? target_reason : "target_incompatible");
        goto out;
    }
    /*
     * The manifest's own arch/board fields predate the signed target block and
     * are what the packaging tool prints. Rejecting a disagreement keeps the
     * two from drifting into a package that claims one thing and is signed for
     * another.
     */
    manifest_arch = otad_json_str(manifest, "arch", "");
    if (manifest_arch[0] &&
        strcmp(manifest_arch, otad_json_str(target, "architecture", ""))) {
        snprintf(error, error_len, "target_architecture_mismatch");
        goto out;
    }
    candidate_epoch = otad_json_int(target, "security_epoch", 0);
    if (trust_hot_epoch_policy(policy, candidate_epoch, &current_epoch,
                               error, error_len) != 0)
        goto out;
    json_object_object_add(evidence, "candidate_security_epoch",
                           json_object_new_int(candidate_epoch));
    json_object_object_add(evidence, "current_security_epoch",
                           json_object_new_int(current_epoch));
    json_object_object_del(evidence, "authenticity_verified");
    json_object_object_add(evidence, "authenticity_verified", json_object_new_boolean(1));
    json_object_object_del(evidence, "target_compatible");
    json_object_object_add(evidence, "target_compatible", json_object_new_boolean(1));
    json_object_object_del(evidence, "policy_passed");
    json_object_object_add(evidence, "policy_passed", json_object_new_boolean(1));
    otad_json_add_string(evidence, "signature_status", "verified");
    otad_json_add_string(evidence, "target_status", "compatible");
    rc = 0;
out:
    if (rc != 0) {
        const char *reason = error && error[0] ? error : "release_trust_verification_failed";
        if (error && error_len && !error[0])
            snprintf(error, error_len, "%s", reason);
        otad_json_add_string(evidence, "signature_status", reason);
        otad_json_add_string(evidence, "target_status", reason);
    }
    free(signed_payload);
    free(signature);
    if (signed_json)
        json_object_put(signed_json);
    if (outer_statement)
        json_object_put(outer_statement);
    if (policy)
        json_object_put(policy);
    if (evidence_out)
        *evidence_out = evidence;
    else
        json_object_put(evidence);
    return rc;
}

int otad_release_trust_binding_get(struct json_object *result_or_evidence,
                                   struct otad_trust_binding *binding,
                                   char *error, size_t error_len)
{
    struct json_object *evidence = result_or_evidence;
    struct json_object *nested = NULL;

    if (error && error_len)
        error[0] = '\0';
    if (!binding || !evidence ||
        !json_object_is_type(evidence, json_type_object))
        goto invalid;
    if (json_object_object_get_ex(evidence, "release_trust", &nested))
        evidence = nested;
    if (!evidence || !json_object_is_type(evidence, json_type_object))
        goto invalid;
    memset(binding, 0, sizeof(*binding));
    snprintf(binding->manifest_digest, sizeof(binding->manifest_digest), "%s",
             otad_json_str(evidence, "manifest_digest", ""));
    snprintf(binding->signing_key_id, sizeof(binding->signing_key_id), "%s",
             otad_json_str(evidence, "signing_key_id",
                           otad_json_str(evidence, "key_id", "")));
    binding->trust_policy_version = otad_json_int(evidence, "trust_policy_version", 0);
    snprintf(binding->trust_policy_digest, sizeof(binding->trust_policy_digest), "%s",
             otad_json_str(evidence, "trust_policy_digest", ""));
    snprintf(binding->device_identity_digest,
             sizeof(binding->device_identity_digest), "%s",
             otad_json_str(evidence, "device_identity_digest", ""));
    binding->authenticity_verified = otad_json_bool(evidence, "authenticity_verified", 0);
    binding->target_compatible = otad_json_bool(evidence, "target_compatible", 0);
    binding->policy_passed = otad_json_bool(evidence, "policy_passed", 0);
    if (strlen(binding->manifest_digest) != 64 ||
        !trust_key_id_ok(binding->signing_key_id) ||
        binding->trust_policy_version < 1 ||
        strlen(binding->trust_policy_digest) != 64 ||
        strlen(binding->device_identity_digest) != 64 ||
        !binding->authenticity_verified || !binding->target_compatible ||
        !binding->policy_passed)
        goto invalid;
    return 0;

invalid:
    if (binding)
        memset(binding, 0, sizeof(*binding));
    if (error && error_len)
        snprintf(error, error_len, "release_trust_binding_invalid");
    return -1;
}

struct json_object *otad_release_trust_status(void)
{
    struct json_object *status = json_object_new_object();
    struct json_object *policy = NULL;
    char error[96] = "";
    struct stat st;
    int ready = 0;

    if (trust_load_policy(&policy, error, sizeof(error)) == 0 &&
        stat(OTAD_TRUST_KEY_DIR, &st) == 0 && S_ISDIR(st.st_mode)) {
        struct json_object *keys = NULL;
        size_t i;

        if (json_object_object_get_ex(policy, "keys", &keys) &&
            json_object_is_type(keys, json_type_array)) {
            for (i = 0; i < json_object_array_length(keys); i++) {
                struct json_object *key = json_object_array_get_idx(keys, i);
                const char *key_id = otad_json_str(key, "key_id", "");
                char key_path[OTAD_MAX_PATH];

                if (!strcmp(otad_json_str(key, "status", ""), "active") &&
                    trust_key_id_ok(key_id) &&
                    snprintf(key_path, sizeof(key_path), "%s/%s.pem",
                             OTAD_TRUST_KEY_DIR, key_id) < (int)sizeof(key_path) &&
                    stat(key_path, &st) == 0 && S_ISREG(st.st_mode)) {
                    ready = 1;
                    break;
                }
            }
        }
        if (!ready)
            snprintf(error, sizeof(error), "no_active_release_key");
    }

    json_object_object_add(status, "ready", json_object_new_boolean(ready));
    json_object_object_add(status, "signature_algorithm",
                           json_object_new_string("ed25519"));
    json_object_object_add(status, "signed_schema_version", json_object_new_int(3));
    json_object_object_add(status, "policy_version", json_object_new_int(
        policy ? otad_json_int(policy, "policy_version", 0) : 0));
    otad_json_add_string(status, "policy_path", OTAD_TRUST_POLICY_PATH);
    otad_json_add_string(status, "key_directory", OTAD_TRUST_KEY_DIR);
    otad_json_add_string(status, "reason", ready ? "" :
                         (error[0] ? error : "trust_key_directory_unavailable"));
    if (policy)
        json_object_put(policy);
    return status;
}
