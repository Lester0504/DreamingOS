// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "otad_internal.h"
#include <zlib.h>

#define OTAD_BOOT_MOUNT "/tmp/dreamingwrt/otad-boot"
#define OTAD_SLOT_MOUNT "/tmp/dreamingwrt/otad-slot"

struct otad_payload_info {
    uint64_t offset;
    uint64_t size;
    char md5[33];
    char sha256[65];
    int gzip;
    uint64_t raw_size;
    char raw_md5[33];
    char raw_sha256[65];
};

struct otad_firmware_info {
    char version[128];
    char build_id[64];
    char linux_version[128];
    int schema_version;
    uint64_t firmware_size;
    struct otad_payload_info rootfs;
    struct otad_payload_info vmlinuz;
    struct json_object *json;
};

struct otad_staged_upload {
    int rootfd;
    int dirfd;
    int lockfd;
    int fd;
    uint64_t size;
    time_t expires_at;
    char sha256[65];
};

struct uloop_timeout g_otad_confirm_timer;

static int otad_hex_ok(const char *s, size_t n)
{
    size_t i;

    if (!s || strlen(s) != n)
        return 0;
    for (i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    return 1;
}

static uint64_t otad_json_u64(struct json_object *o, const char *key, uint64_t def)
{
    struct json_object *v = NULL;
    int64_t value;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_int))
        return def;
    value = json_object_get_int64(v);
    return value < 0 ? def : (uint64_t)value;
}

static int otad_digest_metadata_parse(struct json_object *o, uint64_t *size,
                                      char md5_out[33], char sha_out[65])
{
    const char *md5;
    const char *sha;

    if (!o || !json_object_is_type(o, json_type_object) || !size ||
        !md5_out || !sha_out)
        return -1;
    *size = otad_json_u64(o, "size_bytes", 0);
    md5 = otad_json_str(o, "md5", "");
    sha = otad_json_str(o, "sha256", "");
    if (*size == 0 || !otad_hex_ok(md5, 32) || !otad_hex_ok(sha, 64))
        return -1;
    snprintf(md5_out, 33, "%s", md5);
    snprintf(sha_out, 65, "%s", sha);
    return 0;
}

static int otad_payload_parse(struct json_object *payloads, const char *name,
                              int schema_version, int is_rootfs,
                              struct otad_payload_info *out)
{
    struct json_object *o = NULL;
    struct json_object *compressed = NULL;
    struct json_object *uncompressed = NULL;
    const char *md5;
    const char *sha;
    const char *compression;
    uint64_t compressed_size = 0;
    char compressed_md5[33] = "";
    char compressed_sha[65] = "";

    if (!payloads || !name || !out ||
        !json_object_object_get_ex(payloads, name, &o) || !o ||
        !json_object_is_type(o, json_type_object))
        return -1;
    memset(out, 0, sizeof(*out));
    out->offset = otad_json_u64(o, "offset_bytes", UINT64_MAX);
    out->size = otad_json_u64(o, "size_bytes", 0);
    md5 = otad_json_str(o, "md5", "");
    sha = otad_json_str(o, "sha256", "");
    if (out->offset == UINT64_MAX || out->size == 0 ||
        !otad_hex_ok(md5, 32) || !otad_hex_ok(sha, 64))
        return -1;
    snprintf(out->md5, sizeof(out->md5), "%s", md5);
    snprintf(out->sha256, sizeof(out->sha256), "%s", sha);

    compression = otad_json_str(o, "compression", "");
    if (!is_rootfs) {
        if (compression[0] && strcmp(compression, "none"))
            return -1;
        out->raw_size = out->size;
        snprintf(out->raw_md5, sizeof(out->raw_md5), "%s", out->md5);
        snprintf(out->raw_sha256, sizeof(out->raw_sha256), "%s", out->sha256);
        return 0;
    }
    if (schema_version == 1) {
        if (compression[0] && strcmp(compression, "none"))
            return -1;
        out->raw_size = out->size;
        snprintf(out->raw_md5, sizeof(out->raw_md5), "%s", out->md5);
        snprintf(out->raw_sha256, sizeof(out->raw_sha256), "%s", out->sha256);
        return 0;
    }
    if ((schema_version != 2 && schema_version != 3) ||
        strcmp(compression, "gzip") ||
        !json_object_object_get_ex(o, "compressed", &compressed) ||
        !json_object_object_get_ex(o, "uncompressed", &uncompressed) ||
        otad_digest_metadata_parse(compressed, &compressed_size,
                                   compressed_md5, compressed_sha) != 0 ||
        otad_digest_metadata_parse(uncompressed, &out->raw_size,
                                   out->raw_md5, out->raw_sha256) != 0 ||
        compressed_size != out->size || strcasecmp(compressed_md5, out->md5) ||
        strcasecmp(compressed_sha, out->sha256))
        return -1;
    out->gzip = 1;
    return 0;
}

static int otad_payload_range_valid(const struct otad_payload_info *payload,
                                    uint64_t firmware_size, uint64_t min_offset)
{
    if (!payload || payload->offset < min_offset ||
        payload->offset > firmware_size ||
        payload->size > firmware_size - payload->offset)
        return 0;
    return 1;
}

static int otad_firmware_header_read_fd(int fd, uint64_t expected_size,
                                        struct otad_firmware_info *out,
                                        char *error, size_t error_len)
{
    char *header = NULL;
    char *p;
    char *end;
    char len_text[16];
    unsigned long json_len;
    ssize_t got;
    size_t off = 0;
    struct stat st;
    struct json_object *payloads = NULL;

    if (error && error_len)
        error[0] = '\0';
    if (fd < 0 || !out || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < (off_t)OTAD_FIRMWARE_HEADER_BYTES ||
        (expected_size && (uint64_t)st.st_size != expected_size)) {
        snprintf(error, error_len, "firmware_descriptor_invalid");
        return -1;
    }
    memset(out, 0, sizeof(*out));
    header = malloc(OTAD_FIRMWARE_HEADER_BYTES + 1);
    if (!header) {
        snprintf(error, error_len, "out_of_memory");
        return -1;
    }
    while (off < OTAD_FIRMWARE_HEADER_BYTES) {
        got = pread(fd, header + off, OTAD_FIRMWARE_HEADER_BYTES - off,
                    (off_t)off);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        off += (size_t)got;
    }
    header[off] = '\0';
    if (off != OTAD_FIRMWARE_HEADER_BYTES ||
        strncmp(header, OTAD_FIRMWARE_MAGIC, strlen(OTAD_FIRMWARE_MAGIC)) != 0) {
        snprintf(error, error_len, "firmware_magic_mismatch");
        free(header);
        return -1;
    }
    p = header + strlen(OTAD_FIRMWARE_MAGIC);
    if (strncmp(p, OTAD_FIRMWARE_HEADER_NAME, strlen(OTAD_FIRMWARE_HEADER_NAME)) != 0) {
        snprintf(error, error_len, "firmware_info_name_missing");
        free(header);
        return -1;
    }
    p += strlen(OTAD_FIRMWARE_HEADER_NAME);
    end = strchr(p, '\n');
    if (!end || (size_t)(end - p) >= sizeof(len_text)) {
        snprintf(error, error_len, "firmware_info_length_invalid");
        free(header);
        return -1;
    }
    memcpy(len_text, p, (size_t)(end - p));
    len_text[end - p] = '\0';
    json_len = strtoul(len_text, NULL, 10);
    p = end + 1;
    if (json_len == 0 || json_len > OTAD_FIRMWARE_HEADER_BYTES - (size_t)(p - header)) {
        snprintf(error, error_len, "firmware_info_length_invalid");
        free(header);
        return -1;
    }
    p[json_len] = '\0';
    out->json = json_tokener_parse(p);
    free(header);
    if (!out->json || !json_object_is_type(out->json, json_type_object)) {
        snprintf(error, error_len, "firmware_info_json_invalid");
        if (out->json)
            json_object_put(out->json);
        out->json = NULL;
        return -1;
    }
    out->schema_version = otad_json_int(out->json, "schema_version", 0);
    if ((out->schema_version != 1 && out->schema_version != 2 &&
         out->schema_version != 3) ||
        strcmp(otad_json_str(out->json, "product", ""), "DreamingWrt") ||
        strcmp(otad_json_str(out->json, "artifact_type", ""), "ota_bin") ||
        strcmp(otad_json_str(out->json, "firmware_type", ""), "firmware") ||
        strcmp(otad_json_str(out->json, "rootfs_format", ""), "ext4")) {
        snprintf(error, error_len, "firmware_info_contract_mismatch");
        json_object_put(out->json);
        out->json = NULL;
        return -1;
    }
    out->firmware_size = otad_json_u64(out->json, "firmware_size_bytes", 0);
    if (out->firmware_size != (uint64_t)st.st_size ||
        !json_object_object_get_ex(out->json, "payloads", &payloads) ||
        otad_payload_parse(payloads, "rootfs", out->schema_version, 1,
                           &out->rootfs) != 0 ||
        otad_payload_parse(payloads, "vmlinuz", out->schema_version, 0,
                           &out->vmlinuz) != 0 ||
        !otad_payload_range_valid(&out->rootfs, out->firmware_size,
                                  OTAD_FIRMWARE_HEADER_BYTES) ||
        !otad_payload_range_valid(&out->vmlinuz, out->firmware_size,
                                  OTAD_FIRMWARE_HEADER_BYTES) ||
        out->vmlinuz.offset < out->rootfs.offset + out->rootfs.size) {
        snprintf(error, error_len, "firmware_size_or_payload_contract_mismatch");
        json_object_put(out->json);
        out->json = NULL;
        return -1;
    }
    snprintf(out->version, sizeof(out->version), "%s",
             otad_json_str(out->json, "dreamingwrt_version", ""));
    snprintf(out->build_id, sizeof(out->build_id), "%s",
             otad_json_str(out->json, "build_id", ""));
    snprintf(out->linux_version, sizeof(out->linux_version), "%s",
             otad_json_str(out->json, "linux_version", ""));
    if (!out->version[0] || !out->build_id[0] || !out->linux_version[0]) {
        snprintf(error, error_len, "firmware_version_metadata_missing");
        json_object_put(out->json);
        out->json = NULL;
        return -1;
    }
    return 0;
}

static void otad_firmware_info_done(struct otad_firmware_info *info)
{
    if (info && info->json) {
        json_object_put(info->json);
        info->json = NULL;
    }
}

static void otad_digest_hex(const unsigned char *digest, unsigned int len,
                            char *out, size_t out_len)
{
    unsigned int i;

    if (!out || out_len < (size_t)len * 2 + 1)
        return;
    for (i = 0; i < len; i++)
        snprintf(out + i * 2, out_len - i * 2, "%02x", digest[i]);
    out[len * 2] = '\0';
}

static int otad_hash_range_fd(int fd, uint64_t offset, uint64_t size,
                              char md5_hex[33], char sha_hex[65])
{
    EVP_MD_CTX *md5 = NULL;
    EVP_MD_CTX *sha = NULL;
    unsigned char buf[1024 * 1024];
    unsigned char md5_out[EVP_MAX_MD_SIZE];
    unsigned char sha_out[EVP_MAX_MD_SIZE];
    unsigned int md5_len = 0;
    unsigned int sha_len = 0;
    uint64_t done = 0;
    int rc = -1;

    md5 = EVP_MD_CTX_new();
    sha = EVP_MD_CTX_new();
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
        if (n <= 0)
            goto out;
        if (EVP_DigestUpdate(md5, buf, (size_t)n) != 1 ||
            EVP_DigestUpdate(sha, buf, (size_t)n) != 1)
            goto out;
        done += (uint64_t)n;
    }
    if (EVP_DigestFinal_ex(md5, md5_out, &md5_len) != 1 ||
        EVP_DigestFinal_ex(sha, sha_out, &sha_len) != 1)
        goto out;
    otad_digest_hex(md5_out, md5_len, md5_hex, 33);
    otad_digest_hex(sha_out, sha_len, sha_hex, 65);
    rc = 0;
out:
    EVP_MD_CTX_free(md5);
    EVP_MD_CTX_free(sha);
    return rc;
}

static int otad_verify_payload_fd(int fd, const struct otad_payload_info *payload,
                                  char *error, size_t error_len)
{
    char md5[33] = "";
    char sha[65] = "";

    if (otad_hash_range_fd(fd, payload->offset, payload->size, md5, sha) != 0) {
        snprintf(error, error_len, "payload_read_failed");
        return -1;
    }
    if (strcasecmp(md5, payload->md5)) {
        snprintf(error, error_len, "payload_md5_mismatch");
        return -1;
    }
    if (strcasecmp(sha, payload->sha256)) {
        snprintf(error, error_len, "payload_sha256_mismatch");
        return -1;
    }
    return 0;
}

static int otad_gzip_rootfs_stream(int src_fd, const struct otad_payload_info *payload,
                                   int dst_fd, int write_output,
                                   char md5_hex[33], char sha_hex[65],
                                   char *error, size_t error_len)
{
    EVP_MD_CTX *md5 = NULL;
    EVP_MD_CTX *sha = NULL;
    z_stream zs;
    unsigned char in[256 * 1024];
    unsigned char out[256 * 1024];
    unsigned char md5_out[EVP_MAX_MD_SIZE];
    unsigned char sha_out[EVP_MAX_MD_SIZE];
    unsigned int md5_len = 0;
    unsigned int sha_len = 0;
    uint64_t in_done = 0;
    uint64_t out_done = 0;
    int zrc;
    int rc = -1;

    if (!payload || !payload->gzip || (write_output && dst_fd < 0)) {
        snprintf(error, error_len, "gzip_payload_contract_invalid");
        return -1;
    }
    memset(&zs, 0, sizeof(zs));
    md5 = EVP_MD_CTX_new();
    sha = EVP_MD_CTX_new();
    if (!md5 || !sha || EVP_DigestInit_ex(md5, EVP_md5(), NULL) != 1 ||
        EVP_DigestInit_ex(sha, EVP_sha256(), NULL) != 1) {
        snprintf(error, error_len, "gzip_digest_init_failed");
        goto out;
    }
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        snprintf(error, error_len, "gzip_init_failed");
        goto out;
    }
    do {
        if (zs.avail_in == 0 && in_done < payload->size) {
            size_t want = sizeof(in);
            ssize_t n;
            if ((uint64_t)want > payload->size - in_done)
                want = (size_t)(payload->size - in_done);
            n = pread(src_fd, in, want, (off_t)(payload->offset + in_done));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                snprintf(error, error_len, "gzip_payload_read_failed");
                goto inflate_out;
            }
            in_done += (uint64_t)n;
            zs.next_in = in;
            zs.avail_in = (uInt)n;
        }
        zs.next_out = out;
        zs.avail_out = sizeof(out);
        zrc = inflate(&zs, in_done >= payload->size ? Z_FINISH : Z_NO_FLUSH);
        if (zrc != Z_OK && zrc != Z_STREAM_END && zrc != Z_BUF_ERROR) {
            snprintf(error, error_len, "gzip_decompress_failed");
            goto inflate_out;
        }
        if (zs.avail_out < sizeof(out)) {
            size_t produced = sizeof(out) - zs.avail_out;
            size_t written = 0;
            if ((uint64_t)produced > payload->raw_size - out_done) {
                snprintf(error, error_len, "rootfs_uncompressed_size_exceeded");
                goto inflate_out;
            }
            if (EVP_DigestUpdate(md5, out, produced) != 1 ||
                EVP_DigestUpdate(sha, out, produced) != 1) {
                snprintf(error, error_len, "gzip_digest_failed");
                goto inflate_out;
            }
            if (write_output) {
                while (written < produced) {
                    ssize_t w = write(dst_fd, out + written, produced - written);
                    if (w < 0 && errno == EINTR)
                        continue;
                    if (w <= 0) {
                        snprintf(error, error_len, "rootfs_slot_write_failed");
                        goto inflate_out;
                    }
                    written += (size_t)w;
                }
            }
            out_done += produced;
        }
        if (zrc == Z_STREAM_END) {
            if (in_done != payload->size || zs.avail_in != 0) {
                snprintf(error, error_len, "gzip_trailing_bytes_mismatch");
                goto inflate_out;
            }
            break;
        }
        if (zrc == Z_BUF_ERROR && in_done >= payload->size && zs.avail_in == 0) {
            snprintf(error, error_len, "gzip_truncated");
            goto inflate_out;
        }
    } while (in_done < payload->size || zs.avail_in > 0);

    if (out_done != payload->raw_size) {
        snprintf(error, error_len, "rootfs_uncompressed_size_mismatch");
        goto inflate_out;
    }
    if (EVP_DigestFinal_ex(md5, md5_out, &md5_len) != 1 ||
        EVP_DigestFinal_ex(sha, sha_out, &sha_len) != 1) {
        snprintf(error, error_len, "gzip_digest_final_failed");
        goto inflate_out;
    }
    otad_digest_hex(md5_out, md5_len, md5_hex, 33);
    otad_digest_hex(sha_out, sha_len, sha_hex, 65);
    if (strcasecmp(md5_hex, payload->raw_md5)) {
        snprintf(error, error_len, "rootfs_uncompressed_md5_mismatch");
        goto inflate_out;
    }
    if (strcasecmp(sha_hex, payload->raw_sha256)) {
        snprintf(error, error_len, "rootfs_uncompressed_sha256_mismatch");
        goto inflate_out;
    }
    if (write_output && fsync(dst_fd) != 0) {
        snprintf(error, error_len, "rootfs_slot_fsync_failed");
        goto inflate_out;
    }
    rc = 0;
inflate_out:
    inflateEnd(&zs);
out:
    EVP_MD_CTX_free(md5);
    EVP_MD_CTX_free(sha);
    return rc;
}

static int otad_partlabel_path(const char *label, char *path, size_t path_len)
{
    return otad_ab_partlabel_unique(label, path, path_len);
}

static int otad_inventory_action_count(const char *action, int blockers_only)
{
    sqlite3_stmt *st;
    int count = -1;

    st = otad_inventory_prepare(
        "SELECT COUNT(*) FROM inventory_unknowns WHERE suggested_action=?1 "
        "AND (?2=0 OR will_preserve=0)");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, action ? action : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, blockers_only ? 1 : 0);
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

static struct json_object *otad_verify_response(const struct otad_firmware_info *info,
                                                const char *current,
                                                const char *inactive,
                                                const char *inactive_dev,
                                                int blockers)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "ok", json_object_new_boolean(1));
    json_object_object_add(o, "verified", json_object_new_boolean(0));
    otad_json_add_string(o, "dreamingwrt_version", info->version);
    otad_json_add_string(o, "build_id", info->build_id);
    otad_json_add_string(o, "linux_version", info->linux_version);
    json_object_object_add(o, "firmware_size_bytes", json_object_new_int64((int64_t)info->firmware_size));
    otad_json_add_string(o, "current_slot", current);
    otad_json_add_string(o, "target_slot", inactive);
    otad_json_add_string(o, "target_device", inactive_dev);
    json_object_object_add(o, "inventory_blockers", json_object_new_int(blockers));
    {
        int reports = otad_inventory_action_count("report_only", 0);

        json_object_object_add(o, "inventory_reports",
                               json_object_new_int(reports >= 0 ? reports : 0));
    }
    json_object_object_add(o, "safe_to_apply", json_object_new_boolean(0));
    json_object_object_add(o, "signature_verified", json_object_new_boolean(0));
    otad_json_add_string(o, "signature_status", "release_trust_not_verified");
    return o;
}

static int otad_firmware_release_gate(struct json_object *resp,
                                      char *error, size_t error_len)
{
    struct json_object *field = NULL;

    if (resp) {
        json_object_object_del(resp, "verified");
        json_object_object_add(resp, "verified", json_object_new_boolean(0));
        json_object_object_del(resp, "safe_to_apply");
        json_object_object_add(resp, "safe_to_apply", json_object_new_boolean(0));
        if (!json_object_object_get_ex(resp, "authenticity_verified", &field))
            json_object_object_add(resp, "authenticity_verified",
                                   json_object_new_boolean(0));
        json_object_object_del(resp, "signature_required");
        json_object_object_add(resp, "signature_required",
                               json_object_new_boolean(1));
        if (!json_object_object_get_ex(resp, "signature_verified", &field))
            json_object_object_add(resp, "signature_verified",
                                   json_object_new_boolean(0));
        if (!json_object_object_get_ex(resp, "signature_status", &field))
            otad_json_add_string(resp, "signature_status",
                                 "release_trust_not_verified");
        if (!json_object_object_get_ex(resp, "target_compatible", &field))
            json_object_object_add(resp, "target_compatible",
                                   json_object_new_boolean(0));
        if (!json_object_object_get_ex(resp, "policy_passed", &field))
            json_object_object_add(resp, "policy_passed",
                                   json_object_new_boolean(0));
        otad_json_add_string(resp, "release_gate",
                             "firmware_release_trust_gate_closed");
        otad_json_add_string(resp, "release_gate_reason",
                             "operation_trust_binding_and_ab_topology_pending");
    }
    if (error && error_len)
        snprintf(error, error_len, "firmware_release_trust_gate_closed");
    return -1;
}

static struct json_object *otad_firmware_release_gate_error(void)
{
    struct json_object *resp = otad_error(
        "firmware_release_trust_gate_closed",
        "publisher authenticity and target compatibility must be verified before slot writes");

    (void)otad_firmware_release_gate(resp, NULL, 0);
    return resp;
}

static int otad_parse_u64(const char *value, uint64_t *out)
{
    unsigned long long parsed;
    char *end = NULL;

    if (!value || !value[0] || value[0] == '-' || !out)
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno == ERANGE || !end || *end)
        return -1;
    *out = (uint64_t)parsed;
    return 0;
}

static int otad_staging_meta_read(int dirfd, const char *upload_id,
                                  uint64_t *size, time_t *expires_at,
                                  char sha256[65], char *error,
                                  size_t error_len)
{
    enum { META_MAX = 16 * 1024 };
    char buf[META_MAX + 1];
    char *copy = NULL;
    char *save = NULL;
    char *line;
    char meta_id[OTAD_UPLOAD_ID_LEN + 1] = "";
    char upload_type[32] = "";
    char status[32] = "";
    uint64_t parsed_size = 0;
    uint64_t parsed_expires = 0;
    int have_version = 0;
    int have_id = 0;
    int have_type = 0;
    int have_status = 0;
    int have_size = 0;
    int have_expires = 0;
    int have_sha = 0;
    int fd;
    ssize_t got;
    struct stat st;

    fd = openat(dirfd, "meta.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > META_MAX) {
        if (fd >= 0)
            close(fd);
        snprintf(error, error_len, "staging_meta_invalid");
        return -1;
    }
    do {
        got = read(fd, buf, META_MAX);
    } while (got < 0 && errno == EINTR);
    close(fd);
    if (got <= 0 || got != st.st_size) {
        snprintf(error, error_len, "staging_meta_read_failed");
        return -1;
    }
    buf[got] = '\0';
    copy = strdup(buf);
    if (!copy) {
        snprintf(error, error_len, "out_of_memory");
        return -1;
    }
    for (line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');

        if (!eq)
            continue;
        *eq++ = '\0';
        if (!strcmp(line, "version")) {
            if (have_version++ || (strcmp(eq, "1") && strcmp(eq, "2")))
                goto invalid;
        } else if (!strcmp(line, "upload_id")) {
            if (have_id++ || strlen(eq) >= sizeof(meta_id))
                goto invalid;
            snprintf(meta_id, sizeof(meta_id), "%s", eq);
        } else if (!strcmp(line, "upload_type")) {
            if (have_type++ || strlen(eq) >= sizeof(upload_type))
                goto invalid;
            snprintf(upload_type, sizeof(upload_type), "%s", eq);
        } else if (!strcmp(line, "status")) {
            if (have_status++ || strlen(eq) >= sizeof(status))
                goto invalid;
            snprintf(status, sizeof(status), "%s", eq);
        } else if (!strcmp(line, "size_bytes")) {
            if (have_size++ || otad_parse_u64(eq, &parsed_size) != 0)
                goto invalid;
        } else if (!strcmp(line, "expires_at")) {
            if (have_expires++ || otad_parse_u64(eq, &parsed_expires) != 0 ||
                parsed_expires > INT64_MAX)
                goto invalid;
        } else if (!strcmp(line, "sha256")) {
            if (have_sha++ || !otad_hex_ok(eq, 64))
                goto invalid;
            snprintf(sha256, 65, "%s", eq);
        }
    }
    free(copy);
    if (have_version != 1 || have_id != 1 || have_type != 1 ||
        have_status != 1 || have_size != 1 || have_expires != 1 ||
        have_sha != 1 || strcmp(meta_id, upload_id) ||
        strcmp(upload_type, "firmware") || strcmp(status, "finalized") ||
        parsed_size < OTAD_FIRMWARE_HEADER_BYTES ||
        parsed_size > OTAD_FIRMWARE_MAX_BYTES ||
        parsed_expires < (uint64_t)otad_now_s()) {
        snprintf(error, error_len, "staging_upload_not_finalized_firmware");
        return -1;
    }
    *size = parsed_size;
    *expires_at = (time_t)parsed_expires;
    return 0;

invalid:
    free(copy);
    snprintf(error, error_len, "staging_meta_invalid");
    return -1;
}

static void otad_staged_upload_close(struct otad_staged_upload *upload)
{
    if (!upload)
        return;
    if (upload->fd >= 0)
        close(upload->fd);
    if (upload->lockfd >= 0)
        close(upload->lockfd);
    if (upload->dirfd >= 0)
        close(upload->dirfd);
    if (upload->rootfd >= 0)
        close(upload->rootfd);
    upload->rootfd = upload->dirfd = upload->lockfd = upload->fd = -1;
}

static int otad_staged_upload_open(const char *upload_id,
                                   struct otad_staged_upload *upload,
                                   char *error, size_t error_len)
{
    char md5[33] = "";
    char actual_sha[65] = "";
    struct stat st;

    if (!upload || !otad_upload_id_ok(upload_id)) {
        snprintf(error, error_len, "upload_id_invalid");
        return -1;
    }
    memset(upload, 0, sizeof(*upload));
    upload->rootfd = upload->dirfd = upload->lockfd = upload->fd = -1;
    upload->rootfd = open(OTAD_UPLOAD_STAGING_ROOT,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (upload->rootfd < 0 || fstat(upload->rootfd, &st) != 0 ||
        !S_ISDIR(st.st_mode)) {
        snprintf(error, error_len, "staging_root_unavailable");
        goto fail;
    }
    upload->dirfd = openat(upload->rootfd, upload_id,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (upload->dirfd < 0 || fstat(upload->dirfd, &st) != 0 ||
        !S_ISDIR(st.st_mode)) {
        snprintf(error, error_len, "staging_upload_not_found");
        goto fail;
    }
    upload->lockfd = openat(upload->dirfd, "lock",
                            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (upload->lockfd < 0) {
        snprintf(error, error_len, "staging_lock_missing");
        goto fail;
    }
    while (flock(upload->lockfd, LOCK_EX) != 0) {
        if (errno == EINTR)
            continue;
        snprintf(error, error_len, "staging_lock_failed");
        goto fail;
    }
    if (otad_staging_meta_read(upload->dirfd, upload_id, &upload->size,
                               &upload->expires_at, upload->sha256,
                               error, error_len) != 0)
        goto fail;
    upload->fd = openat(upload->dirfd, "data.bin",
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (upload->fd < 0 || fstat(upload->fd, &st) != 0 ||
        !S_ISREG(st.st_mode) || (uint64_t)st.st_size != upload->size) {
        snprintf(error, error_len, "staging_data_invalid");
        goto fail;
    }
    if (otad_hash_range_fd(upload->fd, 0, upload->size, md5, actual_sha) != 0 ||
        strcasecmp(actual_sha, upload->sha256)) {
        snprintf(error, error_len, "staging_sha256_mismatch");
        goto fail;
    }
    return 0;

fail:
    otad_staged_upload_close(upload);
    return -1;
}

static int otad_inactive_capacity_gate(const char *target,
                                    uint64_t target_size,
                                    const struct otad_firmware_info *info,
                                    struct otad_space_gate *gate)
{
    const char *json_text;
    uint64_t artifact_bytes;
    size_t json_len;
    int rc;

    if (!target || !info || !gate)
        return -1;
    json_text = json_object_to_json_string_ext(info->json, JSON_C_TO_STRING_PRETTY);
    json_len = json_text ? strlen(json_text) : 0;
    artifact_bytes = info->rootfs.raw_size;
    if (info->vmlinuz.size > UINT64_MAX - artifact_bytes)
        artifact_bytes = UINT64_MAX;
    else
        artifact_bytes += info->vmlinuz.size;
    if ((uint64_t)json_len > UINT64_MAX - artifact_bytes)
        artifact_bytes = UINT64_MAX;
    else
        artifact_bytes += (uint64_t)json_len;
    rc = otad_block_capacity_gate_check(target, "inactive_slot_image",
                                        artifact_bytes, target_size, gate);
    otad_space_gate_record(gate);
    return rc;
}

static int otad_current_release_version(char version[128],
                                        char *error, size_t error_len)
{
    struct json_object *release = NULL;
    const char *release_path = NULL;
    int rc;

    version[0] = '\0';
    rc = otad_release_metadata_read(&release, &release_path,
                                    error, error_len);
    (void)release_path;
    if (rc < 0)
        return -1;
    if (release && json_object_is_type(release, json_type_object))
        snprintf(version, 128, "%s",
                 otad_json_str(release, "dreamingwrt_version", ""));
    if (release)
        json_object_put(release);
    return 0;
}

int otad_operation_reverify_trust_binding(
    int fd, uint64_t expected_size, const struct otad_operation_work *work,
    char *error, size_t error_len)
{
    struct otad_firmware_info info;
    struct otad_trust_binding binding;
    struct otad_ab_topology topology;
    struct json_object *evidence = NULL;
    int rc = -1;

    memset(&info, 0, sizeof(info));
    if (!work ||
        otad_firmware_header_read_fd(fd, expected_size, &info,
                                     error, error_len) != 0)
        goto out;
    if (otad_release_trust_verify(fd, info.firmware_size, info.json,
                                  &evidence, error, error_len) != 0)
        goto out;
    if (otad_ab_topology_discover(&topology, error, error_len) != 0 ||
        otad_ab_topology_validate_release(&topology, info.json,
                                          error, error_len) != 0)
        goto out;
    if (otad_release_trust_binding_get(evidence, &binding,
                                       error, error_len) != 0)
        goto out;
    if (strcasecmp(binding.manifest_digest, work->manifest_digest) ||
        strcmp(binding.signing_key_id, work->signing_key_id) ||
        binding.trust_policy_version != work->trust_policy_version ||
        strcasecmp(binding.trust_policy_digest, work->trust_policy_digest) ||
        strcasecmp(binding.device_identity_digest, work->device_identity_digest) ||
        binding.authenticity_verified != work->authenticity_verified ||
        binding.target_compatible != work->target_compatible ||
        binding.policy_passed != work->policy_passed ||
        strcasecmp(topology.topology_digest, work->topology_digest)) {
        snprintf(error, error_len, "release_trust_binding_changed_after_preflight");
        goto out;
    }
    rc = 0;
out:
    if (evidence)
        json_object_put(evidence);
    otad_firmware_info_done(&info);
    return rc;
}

static int otad_firmware_validate_fd(int fd, uint64_t expected_size,
                                     int allow_unpreserved,
                                     struct otad_firmware_info *info,
                                     char current[2], char inactive[2],
                                     char target[OTAD_MAX_PATH], int *blockers_out,
                                     struct json_object **result_out,
                                     char *error, size_t error_len)
{
    struct json_object *scan;
    struct json_object *resp = NULL;
    struct otad_space_gate gate;
    struct json_object *gate_json = NULL;
    struct json_object *trust_evidence = NULL;
    struct otad_ab_topology topology;
    uint64_t target_size = 0;
    int target_fd = -1;
    int blockers;

    if (result_out)
        *result_out = NULL;
    {
        struct json_object *scan_args = json_object_new_object();
        json_object_object_add(scan_args, "max_depth", json_object_new_int(0));
        scan = otad_inventory_scan(scan_args);
        json_object_put(scan_args);
    }
    if (!scan || !otad_json_bool(scan, "ok", 0)) {
        if (scan)
            json_object_put(scan);
        snprintf(error, error_len, "inventory_scan_failed");
        return -1;
    }
    json_object_put(scan);
    if (otad_firmware_header_read_fd(fd, expected_size, info,
                                     error, error_len) != 0)
        return -1;
    if (otad_ab_topology_discover(&topology, error, error_len) != 0) {
        if (!error[0])
            snprintf(error, error_len, "ab_layout_unsupported");
        return -1;
    }
    snprintf(current, 2, "%s", topology.current_slot);
    snprintf(inactive, 2, "%s", topology.inactive_slot);
    snprintf(target, OTAD_MAX_PATH, "%s",
             topology.inactive_slot[0] == 'A' ? topology.root_a : topology.root_b);
    target_fd = open(target, O_RDONLY | O_CLOEXEC);
    if (target_fd < 0 || ioctl(target_fd, BLKGETSIZE64, &target_size) != 0) {
        if (target_fd >= 0)
            close(target_fd);
        snprintf(error, error_len, "inactive_slot_capacity_unavailable");
        return -1;
    }
    close(target_fd);
    if (otad_inactive_capacity_gate(target, target_size, info, &gate) != 0) {
        gate_json = json_object_new_object();
        otad_space_gate_add_json(gate_json, &gate);
        if (result_out)
            *result_out = gate_json;
        else
            json_object_put(gate_json);
        snprintf(error, error_len, "%s",
                 gate.error[0] ? gate.error : "space_gate_failed");
        return -1;
    }
    if (otad_verify_payload_fd(fd, &info->rootfs, error, error_len) != 0 ||
        (info->rootfs.gzip &&
         otad_gzip_rootfs_stream(fd, &info->rootfs, -1, 0,
                                 (char[33]){0}, (char[65]){0},
                                 error, error_len) != 0) ||
        otad_verify_payload_fd(fd, &info->vmlinuz, error, error_len) != 0)
        return -1;
    blockers = otad_inventory_action_count("manual_review", 1);
    if (blockers < 0) {
        snprintf(error, error_len, "inventory_query_failed");
        return -1;
    }
    resp = otad_verify_response(info, current, inactive, target, blockers);
    json_object_object_add(resp, "allow_unpreserved",
                           json_object_new_boolean(allow_unpreserved));
    json_object_object_add(resp, "target_capacity_bytes",
                           json_object_new_int64((int64_t)target_size));
    json_object_object_add(resp, "required_rootfs_bytes",
                           json_object_new_int64((int64_t)info->rootfs.raw_size));
    gate_json = json_object_new_object();
    otad_space_gate_add_json(gate_json, &gate);
    json_object_object_add(resp, "space_gate", gate_json);
    json_object_object_add(resp, "integrity_verified", json_object_new_boolean(1));
    if (otad_release_trust_verify(fd, info->firmware_size, info->json,
                                  &trust_evidence, error, error_len) != 0) {
        if (trust_evidence)
            json_object_object_add(resp, "release_trust", trust_evidence);
        json_object_object_add(resp, "architecture_check_supported",
                               json_object_new_boolean(1));
        (void)otad_firmware_release_gate(resp, NULL, 0);
        if (blockers_out)
            *blockers_out = blockers;
        if (result_out)
            *result_out = resp;
        else
            json_object_put(resp);
        return -1;
    }
    json_object_object_add(resp, "release_trust", trust_evidence);
    if (otad_ab_topology_validate_release(&topology, info->json,
                                          error, error_len) != 0) {
        json_object_object_add(resp, "ab_topology", otad_ab_topology_json(&topology));
        (void)otad_firmware_release_gate(resp, NULL, 0);
        if (blockers_out)
            *blockers_out = blockers;
        if (result_out)
            *result_out = resp;
        else
            json_object_put(resp);
        return -1;
    }
    json_object_object_add(resp, "ab_topology", otad_ab_topology_json(&topology));
    json_object_object_add(resp, "architecture_check_supported",
                           json_object_new_boolean(1));
    json_object_object_add(resp, "authenticity_verified",
                           json_object_new_boolean(1));
    json_object_object_add(resp, "signature_required", json_object_new_boolean(1));
    json_object_object_add(resp, "signature_verified", json_object_new_boolean(1));
    otad_json_add_string(resp, "signature_status", "verified");
    json_object_object_add(resp, "target_compatible", json_object_new_boolean(1));
    json_object_object_add(resp, "policy_passed", json_object_new_boolean(1));
    (void)otad_firmware_release_gate(resp, error, error_len);
    if (blockers_out)
        *blockers_out = blockers;
    if (result_out)
        *result_out = resp;
    else
        json_object_put(resp);
    return -1;
}

static struct json_object *otad_operation_status_by_id(const char *operation_id)
{
    struct json_object *body = json_object_new_object();
    struct json_object *resp;

    otad_json_add_string(body, "operation_id", operation_id);
    resp = otad_operation_status(body);
    json_object_put(body);
    return resp;
}

struct json_object *otad_firmware_preflight(struct json_object *body)
{
    struct json_object *path_value = NULL;
    const char *upload_id = otad_json_str(body, "upload_id", "");
    struct json_object *options = json_object_new_object();
    struct otad_staged_upload upload;
    struct otad_firmware_info info;
    struct json_object *result = NULL;
    struct otad_trust_binding trust_binding;
    struct json_object *topology_result = NULL;
    char operation_id[OTAD_OPERATION_ID_LEN + 1] = "";
    char current[2] = "";
    char inactive[2] = "";
    char target[OTAD_MAX_PATH] = "";
    char from_version[128] = "";
    char error[160] = "";
    int allow_unpreserved = otad_json_bool(body, "allow_unpreserved", 0);
    int auto_reboot = otad_json_bool(body, "auto_reboot", 1);
    int blockers = 0;

    memset(&info, 0, sizeof(info));
    if (body && json_object_object_get_ex(body, "path", &path_value)) {
        json_object_put(options);
        return otad_error("arbitrary_path_forbidden",
                          "firmware operations accept only a finalized server upload_id");
    }
    if (!otad_upload_id_ok(upload_id)) {
        json_object_put(options);
        return otad_error("upload_id_invalid",
                          "a finalized server-generated upload_id is required");
    }
    json_object_object_add(options, "allow_unpreserved",
                           json_object_new_boolean(allow_unpreserved));
    json_object_object_add(options, "auto_reboot",
                           json_object_new_boolean(auto_reboot));
    if (otad_operation_create("firmware", "preflight", upload_id, options,
                              operation_id, error, sizeof(error)) != 0) {
        json_object_put(options);
        return otad_error(error, "failed to create firmware preflight operation");
    }
    json_object_put(options);
    if (otad_staged_upload_open(upload_id, &upload, error, sizeof(error)) != 0)
        goto failed;
    if (otad_operation_set_source(operation_id, upload.size, upload.sha256) != 0) {
        snprintf(error, sizeof(error), "operation_source_persist_failed");
        goto failed_open;
    }
    {
        int validate_rc = otad_firmware_validate_fd(
            upload.fd, upload.size, allow_unpreserved, &info, current,
            inactive, target, &blockers, &result, error, sizeof(error));

        if (result &&
            otad_release_trust_binding_get(result, &trust_binding, NULL, 0) == 0) {
            (void)json_object_object_get_ex(result, "ab_topology", &topology_result);
            if (otad_current_release_version(from_version, error,
                                             sizeof(error)) != 0)
                goto failed_open;
            if (validate_rc == 0 && otad_operation_commit_preflight(operation_id,
                    from_version, info.version, info.build_id,
                    inactive, &trust_binding,
                    otad_json_str(topology_result, "topology_digest", ""),
                    result) != 0) {
                snprintf(error, sizeof(error), "operation_trust_persist_failed");
                goto failed_open;
            }
        }
        if (validate_rc != 0)
            goto failed_open;
    }
    otad_staged_upload_close(&upload);
    otad_firmware_info_done(&info);
    json_object_put(result);
    return otad_operation_status_by_id(operation_id);

failed_open:
    otad_staged_upload_close(&upload);
failed:
    (void)otad_operation_update(operation_id, "failed", 100,
                                error[0] ? error : "firmware_preflight_failed",
                                "firmware preflight did not pass", result);
    otad_firmware_info_done(&info);
    if (result)
        json_object_put(result);
    return otad_operation_status_by_id(operation_id);
}

struct json_object *otad_firmware_verify(struct json_object *body)
{
    return otad_firmware_preflight(body);
}

static int otad_run_exit_code(char *const argv[])
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int otad_run(char *const argv[])
{
    return otad_run_exit_code(argv) == 0 ? 0 : -1;
}

static int otad_write_all_fd(int fd, const unsigned char *data, size_t len)
{
    size_t written = 0;

    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        written += (size_t)n;
    }
    return 0;
}

static int otad_copy_range(int src_fd, uint64_t offset, uint64_t size, int dst_fd)
{
    unsigned char buf[1024 * 1024];
    uint64_t done = 0;

    while (done < size) {
        size_t want = sizeof(buf);
        ssize_t n;

        if ((uint64_t)want > size - done)
            want = (size_t)(size - done);
        n = pread(src_fd, buf, want, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || otad_write_all_fd(dst_fd, buf, (size_t)n) != 0)
            return -1;
        done += (uint64_t)n;
    }
    return fsync(dst_fd);
}

static int otad_hash_device_prefix(const char *dev, uint64_t size, char sha_hex[65])
{
    int fd;
    char md5[33];
    int rc;

    fd = open(dev, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    rc = otad_hash_range_fd(fd, 0, size, md5, sha_hex);
    close(fd);
    return rc;
}

static int otad_mount_label(const char *label, const char *mountpoint, char *dev, size_t dev_len)
{
    if (otad_partlabel_path(label, dev, dev_len) != 0 ||
        otad_mkdir_p(mountpoint, 0755) != 0)
        return -1;
    if (mount(dev, mountpoint, "vfat", MS_NOATIME | MS_NODEV | MS_NOSUID | MS_NOEXEC,
              NULL) != 0) {
        if (errno != EBUSY || umount(mountpoint) != 0 ||
            mount(dev, mountpoint, "vfat",
                  MS_NOATIME | MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL) != 0)
            return -1;
    }
    return 0;
}

static int otad_attempts_from_tries(const char *tries)
{
    char *end = NULL;
    long value;

    if (!tries || !tries[0])
        return -1;
    errno = 0;
    value = strtol(tries, &end, 10);
    if (errno || !end || *end || value < 0 || value > 3)
        return -1;
    return 3 - (int)value;
}

static void otad_slot_mark_pending_boot(const char *slot, int attempts)
{
    sqlite3_stmt *st;
    int64_t now;

    if (!slot || (slot[0] != 'A' && slot[0] != 'B') || slot[1] || attempts < 1)
        return;
    st = otad_config_prepare(
        "UPDATE ota_slots SET state='pending_boot',boot_attempts=?1,last_boot_at=?2,updated_at=?2 "
        "WHERE slot_name=?3 AND state IN ('pending','pending_boot') "
        "AND (boot_attempts<?1 OR state!='pending_boot')");
    if (!st)
        return;
    now = otad_now_s();
    sqlite3_bind_int(st, 1, attempts);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, slot, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static int otad_write_file(const char *path, const void *data, size_t len, mode_t mode)
{
    int fd;
    size_t off = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    while (off < len) {
        ssize_t n = write(fd, (const char *)data + off, len - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int otad_sync_unmount(const char *mountpoint)
{
    int fd;
    int sync_rc;
    int umount_rc;

    fd = open(mountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    sync_rc = fd >= 0 ? syncfs(fd) : -1;
    if (fd >= 0)
        close(fd);
    umount_rc = umount(mountpoint);
    return sync_rc == 0 && umount_rc == 0 ? 0 : -1;
}

static int otad_grubenv_set_args(char *const assignments[], size_t count)
{
    enum { MAX_ASSIGNMENTS = 8 };
    char boot_dev[OTAD_MAX_PATH];
    char env_path[OTAD_MAX_PATH];
    char *argv[MAX_ASSIGNMENTS + 4];
    size_t i;
    int command_rc;
    int storage_rc;

    if (!assignments || count == 0 || count > MAX_ASSIGNMENTS)
        return -1;

    if (otad_mount_label(OTAD_BOOT_LABEL, OTAD_BOOT_MOUNT,
                         boot_dev, sizeof(boot_dev)) != 0)
        return -1;
    if (snprintf(env_path, sizeof(env_path), "%s/boot/grub/grubenv",
                 OTAD_BOOT_MOUNT) >= (int)sizeof(env_path)) {
        umount(OTAD_BOOT_MOUNT);
        return -1;
    }
    argv[0] = "/usr/sbin/grub-editenv";
    argv[1] = env_path;
    argv[2] = "set";
    for (i = 0; i < count; i++)
        argv[i + 3] = assignments[i];
    argv[count + 3] = NULL;
    command_rc = otad_run(argv);
    storage_rc = otad_sync_unmount(OTAD_BOOT_MOUNT);
    return command_rc == 0 && storage_rc == 0 ? 0 : -1;
}

static int otad_grubenv_get(const char *key, char *value, size_t value_len)
{
    char boot_dev[OTAD_MAX_PATH];
    char env_path[OTAD_MAX_PATH];
    char line[512];
    FILE *fp;
    size_t key_len;
    int found = 0;

    if (!key || !value || value_len == 0)
        return -1;
    value[0] = '\0';
    if (otad_mount_label(OTAD_BOOT_LABEL, OTAD_BOOT_MOUNT,
                         boot_dev, sizeof(boot_dev)) != 0)
        return -1;
    snprintf(env_path, sizeof(env_path), "%s/boot/grub/grubenv", OTAD_BOOT_MOUNT);
    fp = fopen(env_path, "r");
    if (!fp) {
        umount(OTAD_BOOT_MOUNT);
        return -1;
    }
    key_len = strlen(key);
    while (fgets(line, sizeof(line), fp)) {
        char *end;

        if (strncmp(line, key, key_len) || line[key_len] != '=')
            continue;
        end = line + strlen(line);
        while (end > line && (end[-1] == '\r' || end[-1] == '\n'))
            *--end = '\0';
        snprintf(value, value_len, "%s", line + key_len + 1);
        found = 1;
        break;
    }
    if (fclose(fp) != 0 || umount(OTAD_BOOT_MOUNT) != 0)
        return -1;
    return found ? 0 : 1;
}

static const char *otad_slot_valid_key(const char *slot)
{
    if (slot && slot[0] == 'A' && slot[1] == '\0')
        return "slot_a_valid";
    if (slot && slot[0] == 'B' && slot[1] == '\0')
        return "slot_b_valid";
    return NULL;
}

static void otad_state_set_slot_valid(const char *slot, int valid)
{
    const char *key = otad_slot_valid_key(slot);

    if (key)
        (void)otad_state_set(key, valid ? "1" : "0");
}

static int otad_grubenv_slot_valid(const char *slot, int *valid)
{
    const char *key = otad_slot_valid_key(slot);
    char value[16] = "";

    if (!key || !valid || otad_grubenv_get(key, value, sizeof(value)) != 0)
        return -1;
    if (strcmp(value, "0") && strcmp(value, "1"))
        return -1;
    *valid = !strcmp(value, "1");
    return 0;
}

static int otad_grubenv_prepare_target(const char *current, const char *target)
{
    const char *target_key = otad_slot_valid_key(target);
    char target_invalid_arg[32];
    char pending_arg[] = "pending_slot=";
    char tries_arg[] = "tries_left=0";
    char *assignments[] = { target_invalid_arg, pending_arg, tries_arg };

    if (!otad_slot_valid_key(current) || !target_key || !strcmp(current, target))
        return -1;
    snprintf(target_invalid_arg, sizeof(target_invalid_arg), "%s=0", target_key);
    return otad_grubenv_set_args(assignments,
                                 sizeof(assignments) / sizeof(assignments[0]));
}

static int otad_grubenv_set_slot_valid(const char *slot, int valid)
{
    const char *key = otad_slot_valid_key(slot);
    char valid_arg[32];
    char *assignments[] = { valid_arg };

    if (!key)
        return -1;
    snprintf(valid_arg, sizeof(valid_arg), "%s=%d", key, valid ? 1 : 0);
    return otad_grubenv_set_args(assignments, 1);
}

static int otad_grubenv_set_pending(const char *slot)
{
    char pending_arg[32];
    char tries_arg[] = "tries_left=3";
    char *assignments[] = { pending_arg, tries_arg };

    if (!otad_slot_valid_key(slot))
        return -1;
    snprintf(pending_arg, sizeof(pending_arg), "pending_slot=%s", slot);
    return otad_grubenv_set_args(assignments, 2);
}

static int otad_grubenv_clear_pending(void)
{
    char pending_arg[] = "pending_slot=";
    char tries_arg[] = "tries_left=0";
    char *assignments[] = { pending_arg, tries_arg };

    return otad_grubenv_set_args(assignments, 2);
}

static int otad_grubenv_clear_target(const char *current, const char *target)
{
    const char *target_key = otad_slot_valid_key(target);
    char target_invalid_arg[32];
    char pending_arg[] = "pending_slot=";
    char tries_arg[] = "tries_left=0";
    char *assignments[] = { target_invalid_arg, pending_arg, tries_arg };

    if (!otad_slot_valid_key(current) || !target_key || !strcmp(current, target))
        return -1;
    snprintf(target_invalid_arg, sizeof(target_invalid_arg), "%s=0", target_key);
    return otad_grubenv_set_args(assignments,
                                 sizeof(assignments) / sizeof(assignments[0]));
}

static int otad_grubenv_set_boot_selection(const char *active,
                                           const char *pending,
                                           const char *tries)
{
    char active_arg[32];
    char pending_arg[32];
    char tries_arg[32];
    char last_good_arg[32];
    char *assignments[] = { active_arg, pending_arg, tries_arg, last_good_arg };

    if (!otad_slot_valid_key(active) ||
        (pending && pending[0] && !otad_slot_valid_key(pending)) ||
        !tries)
        return -1;
    snprintf(active_arg, sizeof(active_arg), "active_slot=%s", active);
    snprintf(pending_arg, sizeof(pending_arg), "pending_slot=%s",
             pending ? pending : "");
    snprintf(tries_arg, sizeof(tries_arg), "tries_left=%s", tries);
    snprintf(last_good_arg, sizeof(last_good_arg), "last_good_slot=%s", active);
    return otad_grubenv_set_args(assignments,
                                 sizeof(assignments) / sizeof(assignments[0]));
}

static int otad_grubenv_promote(const char *slot)
{
    const char *key = otad_slot_valid_key(slot);
    char active_arg[32];
    char last_good_arg[32];
    char valid_arg[32];
    char pending_arg[] = "pending_slot=";
    char tries_arg[] = "tries_left=0";
    char *assignments[] = { active_arg, pending_arg, tries_arg,
                            last_good_arg, valid_arg };

    if (!key)
        return -1;
    snprintf(active_arg, sizeof(active_arg), "active_slot=%s", slot);
    snprintf(last_good_arg, sizeof(last_good_arg), "last_good_slot=%s", slot);
    snprintf(valid_arg, sizeof(valid_arg), "%s=1", key);
    return otad_grubenv_set_args(assignments,
                                 sizeof(assignments) / sizeof(assignments[0]));
}

static int otad_slot_row_upsert(const char *slot, const struct otad_firmware_info *info,
                                const char *state, const char *error)
{
    sqlite3_stmt *st;
    int rc;

    st = otad_config_prepare(
        "INSERT INTO ota_slots(slot_name,version,build_id,state,boot_attempts,last_error,rootfs_sha256,updated_at) "
        "VALUES(?1,?2,?3,?4,0,?5,?6,?7) ON CONFLICT(slot_name) DO UPDATE SET "
        "version=excluded.version,build_id=excluded.build_id,state=excluded.state,"
        "boot_attempts=0,last_error=excluded.last_error,rootfs_sha256=excluded.rootfs_sha256,"
        "updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, slot, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, info ? info->version : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, info ? info->build_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, state ? state : "unknown", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, info ? info->rootfs.raw_sha256 : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, otad_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int otad_firmware_apply_worker(const char *operation_id,
                                      const struct otad_operation_work *work,
                                      int allow_unpreserved, int auto_reboot)
{
    struct otad_firmware_info info;
    struct otad_staged_upload upload;
    char current[2] = "";
    char inactive[2] = "";
    char target[OTAD_MAX_PATH] = "";
    char error[160] = "";
    char sha[65] = "";
    char kernel_path[OTAD_MAX_PATH];
    char release_path[OTAD_MAX_PATH];
    char label[32];
    char *fsck_argv[] = { "/usr/sbin/e2fsck", "-f", "-y", target, NULL };
    char *resize_argv[] = { "/usr/sbin/resize2fs", target, NULL };
    char *uuid_argv[] = { "/usr/sbin/tune2fs", "-U", "random", target, NULL };
	char *label_argv[] = { "/usr/sbin/tune2fs", "-L", label, target, NULL };
    int dst = -1;
    int kernel = -1;
    uint64_t target_size = 0;
    int blockers = 0;
    int target_prepared = 0;
    int mounted = 0;
    int fsck_rc;
    struct json_object *result = NULL;
    const char *json_text;
    int rc = -1;

    memset(&info, 0, sizeof(info));
    memset(&upload, 0, sizeof(upload));
    upload.rootfd = upload.dirfd = upload.lockfd = upload.fd = -1;
    if (!operation_id || !work || strcmp(work->kind, "firmware") ||
        strcmp(work->action, "apply") || strcmp(work->state, "writing")) {
        snprintf(error, sizeof(error), "operation_worker_contract_invalid");
        goto fail;
    }
    if (otad_firmware_release_gate(NULL, error, sizeof(error)) != 0)
        goto fail;
    if (otad_staged_upload_open(work->upload_id, &upload,
                                error, sizeof(error)) != 0)
        goto fail;
    if (upload.size != work->source_size ||
        strcasecmp(upload.sha256, work->source_sha256)) {
        snprintf(error, sizeof(error), "staging_source_changed_after_preflight");
        goto fail_open;
    }
    if (otad_operation_reverify_trust_binding(upload.fd, upload.size, work,
                                              error, sizeof(error)) != 0)
        goto fail_open;
    if (otad_operation_update(operation_id, "writing", 30, "", "", NULL) != 0) {
        snprintf(error, sizeof(error), "operation_progress_persist_failed");
        goto fail_open;
    }
    if (otad_firmware_validate_fd(upload.fd, upload.size, allow_unpreserved,
                                  &info, current, inactive, target, &blockers,
                                  &result, error, sizeof(error)) != 0)
        goto fail_open;
    if (strcmp(inactive, work->target_slot)) {
        snprintf(error, sizeof(error), "target_slot_changed_after_preflight");
        goto fail_open;
    }
    if (otad_grubenv_prepare_target(current, inactive) != 0) {
        snprintf(error, sizeof(error), "grubenv_target_invalidate_failed");
        goto fail_open;
    }
    target_prepared = 1;
    dst = open(target, O_WRONLY | O_CLOEXEC | O_EXCL);
    if (dst < 0 || ioctl(dst, BLKGETSIZE64, &target_size) != 0 ||
        target_size < info.rootfs.raw_size) {
        snprintf(error, sizeof(error), "inactive_slot_too_small_or_unwritable");
        goto fail;
    }
    otad_state_set("state", "writing_inactive_slot");
    (void)otad_operation_update(operation_id, "writing", 40, "", "", NULL);
    if (info.rootfs.gzip) {
        if (otad_gzip_rootfs_stream(upload.fd, &info.rootfs, dst, 1,
                                    (char[33]){0}, sha,
                                    error, sizeof(error)) != 0)
            goto fail;
    } else if (otad_copy_range(upload.fd, info.rootfs.offset,
                               info.rootfs.size, dst) != 0) {
        snprintf(error, sizeof(error), "rootfs_slot_write_failed");
        goto fail;
    }
    close(dst); dst = -1;
    if (otad_hash_device_prefix(target, info.rootfs.raw_size, sha) != 0 ||
        strcasecmp(sha, info.rootfs.raw_sha256)) {
        snprintf(error, sizeof(error), "rootfs_writeback_sha256_mismatch");
        goto fail;
    }
    (void)otad_operation_update(operation_id, "writing", 65, "", "", NULL);
    snprintf(label, sizeof(label), "DWRT_ROOT_%s", inactive);
    fsck_rc = otad_run_exit_code(fsck_argv);
    if (fsck_rc < 0 || (fsck_rc & ~(1 | 2)) != 0) {
        snprintf(error, sizeof(error), "inactive_slot_fsck_failed");
        goto fail;
    }
    if (otad_run(uuid_argv) != 0) {
        snprintf(error, sizeof(error), "inactive_slot_uuid_update_failed");
        goto fail;
    }
    if (otad_run(label_argv) != 0) {
        snprintf(error, sizeof(error), "inactive_slot_label_update_failed");
        goto fail;
    }
    if (otad_run(resize_argv) != 0) {
        snprintf(error, sizeof(error), "inactive_slot_resize_failed");
        goto fail;
    }
    fsck_rc = otad_run_exit_code(fsck_argv);
    if (fsck_rc < 0 || (fsck_rc & ~(1 | 2)) != 0) {
        snprintf(error, sizeof(error), "inactive_slot_post_resize_fsck_failed");
        goto fail;
    }
    if (otad_mkdir_p(OTAD_SLOT_MOUNT, 0755) != 0 ||
        mount(target, OTAD_SLOT_MOUNT, "ext4", MS_NOATIME, NULL) != 0) {
        snprintf(error, sizeof(error), "inactive_slot_mount_failed");
        goto fail;
    }
    mounted = 1;
    (void)otad_operation_update(operation_id, "writing", 75, "", "", NULL);
    snprintf(kernel_path, sizeof(kernel_path), "%s/boot/vmlinuz", OTAD_SLOT_MOUNT);
    snprintf(release_path, sizeof(release_path), "%s/etc/dreamingwrt-release.json", OTAD_SLOT_MOUNT);
    if (otad_mkdir_p("/tmp/dreamingwrt", 0755) != 0) {
        snprintf(error, sizeof(error), "runtime_directory_failed");
        goto fail;
    }
    {
        char boot_dir[OTAD_MAX_PATH];
        char etc_dir[OTAD_MAX_PATH];
        snprintf(boot_dir, sizeof(boot_dir), "%s/boot", OTAD_SLOT_MOUNT);
        snprintf(etc_dir, sizeof(etc_dir), "%s/etc", OTAD_SLOT_MOUNT);
        if (otad_mkdir_p(boot_dir, 0755) != 0 || otad_mkdir_p(etc_dir, 0755) != 0) {
            snprintf(error, sizeof(error), "inactive_slot_directory_prepare_failed");
            goto fail;
        }
    }
    kernel = open(kernel_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (kernel < 0 || otad_copy_range(upload.fd, info.vmlinuz.offset,
                                     info.vmlinuz.size, kernel) != 0) {
        snprintf(error, sizeof(error), "vmlinuz_slot_write_failed");
        goto fail;
    }
    close(kernel); kernel = -1;
    {
        int kfd = open(kernel_path, O_RDONLY | O_CLOEXEC);
        char md5[33];
        char ksha[65];
        if (kfd < 0 || otad_hash_range_fd(kfd, 0, info.vmlinuz.size, md5, ksha) != 0 ||
            strcasecmp(md5, info.vmlinuz.md5) || strcasecmp(ksha, info.vmlinuz.sha256)) {
            if (kfd >= 0) close(kfd);
            snprintf(error, sizeof(error), "vmlinuz_writeback_integrity_mismatch");
            goto fail;
        }
        close(kfd);
    }
    json_text = json_object_to_json_string_ext(info.json, JSON_C_TO_STRING_PRETTY);
    if (!json_text || otad_write_file(release_path, json_text, strlen(json_text), 0644) != 0) {
        snprintf(error, sizeof(error), "release_metadata_write_failed");
        goto fail;
    }
    if (otad_sync_unmount(OTAD_SLOT_MOUNT) != 0) {
        mounted = 0;
        snprintf(error, sizeof(error), "inactive_slot_sync_unmount_failed");
        goto fail;
    }
    mounted = 0;
    (void)otad_operation_update(operation_id, "writing", 88, "", "", NULL);
    if (otad_grubenv_set_slot_valid(inactive, 1) != 0) {
        snprintf(error, sizeof(error), "grubenv_slot_valid_update_failed");
        goto fail;
    }
    otad_state_set_slot_valid(inactive, 1);
    if (otad_grubenv_set_pending(inactive) != 0) {
        snprintf(error, sizeof(error), "grubenv_pending_slot_update_failed");
        goto fail;
    }
    otad_slot_row_upsert(inactive, &info, "pending", "");
    otad_state_set("active_slot", current);
    otad_state_set("pending_slot", inactive);
    otad_state_set("state", "pending_reboot");
    otad_state_set("last_error", "");
    if (!result)
        result = otad_verify_response(&info, current, inactive, target, blockers);
    json_object_object_add(result, "slot_written", json_object_new_boolean(1));
    json_object_object_add(result, "pending_reboot", json_object_new_boolean(1));
    json_object_object_add(result, "auto_reboot", json_object_new_boolean(auto_reboot));
    json_object_object_add(result, "boot_attempts", json_object_new_int(3));
    if (otad_operation_update(operation_id, "rebooting", 90, "", "", result) != 0) {
        snprintf(error, sizeof(error), "operation_reboot_state_persist_failed");
        goto fail;
    }
    (void)otad_state_set("pending_operation_id", operation_id);
    otad_staged_upload_close(&upload);
    otad_firmware_info_done(&info);
    json_object_put(result);
    result = NULL;
    if (auto_reboot) {
        char *reboot_argv[] = { "/sbin/reboot", NULL };

        sync();
        if (otad_run(reboot_argv) != 0) {
            snprintf(error, sizeof(error), "reboot_request_failed");
            if (otad_grubenv_clear_target(current, inactive) == 0) {
                otad_state_set_slot_valid(inactive, 0);
                otad_state_set("pending_slot", "");
            }
            (void)otad_operation_update(operation_id, "failed", 100, error,
                                        "inactive slot was written but reboot could not be requested",
                                        NULL);
            return -1;
        }
    }
    return 0;

fail:
    if (kernel >= 0)
        close(kernel);
    if (dst >= 0)
        close(dst);
    if (mounted) {
        sync();
        umount(OTAD_SLOT_MOUNT);
    }
    if (target_prepared) {
        (void)otad_grubenv_clear_target(current, inactive);
        otad_state_set_slot_valid(inactive, 0);
        otad_state_set("pending_slot", "");
    }
    otad_state_set("state", "failed");
    if (inactive[0])
        otad_slot_row_upsert(inactive, &info, "failed", error);
fail_open:
    otad_staged_upload_close(&upload);
    otad_firmware_info_done(&info);
    (void)otad_operation_update(operation_id, "failed", 100,
                                error[0] ? error : "ota_apply_failed",
                                "inactive slot update failed; active slot remains selected",
                                result);
    if (result)
        json_object_put(result);
    return rc;
}

static struct uloop_process g_otad_operation_process;
static char g_otad_operation_process_id[OTAD_OPERATION_ID_LEN + 1];

static void otad_operation_process_done(struct uloop_process *process, int status)
{
    struct json_object *operation;
    const char *state;

    (void)process;
    operation = otad_operation_status_by_id(g_otad_operation_process_id);
    state = otad_json_str(operation, "state", "");
    if ((!WIFEXITED(status) || WEXITSTATUS(status) != 0) &&
        (!strcmp(state, "writing") || !strcmp(state, "validating")))
        (void)otad_operation_update(g_otad_operation_process_id, "failed", 100,
                                    "operation_worker_failed",
                                    "firmware operation worker exited before reaching reboot state",
                                    NULL);
    json_object_put(operation);
    memset(&g_otad_operation_process, 0, sizeof(g_otad_operation_process));
    g_otad_operation_process_id[0] = '\0';
}

static int otad_firmware_worker_start(const char *operation_id)
{
    pid_t pid;

    if (!otad_operation_id_ok(operation_id) || g_otad_operation_process.pid > 1)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        execlp("dreamingwrt-otad", "dreamingwrt-otad",
               "--operation-worker", operation_id, NULL);
        _exit(127);
    }
    memset(&g_otad_operation_process, 0, sizeof(g_otad_operation_process));
    snprintf(g_otad_operation_process_id, sizeof(g_otad_operation_process_id),
             "%s", operation_id);
    g_otad_operation_process.pid = pid;
    g_otad_operation_process.cb = otad_operation_process_done;
    if (otad_operation_set_worker_pid(operation_id, pid) != 0 ||
        uloop_process_add(&g_otad_operation_process) != 0) {
        kill(pid, SIGTERM);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
        memset(&g_otad_operation_process, 0, sizeof(g_otad_operation_process));
        g_otad_operation_process_id[0] = '\0';
        return -1;
    }
    return 0;
}

int otad_operation_worker(const char *operation_id)
{
    struct otad_operation_work work;
    struct json_object *options = NULL;
    int allow_unpreserved;
    int auto_reboot;
    int rc;

    if (otad_operation_get_work(operation_id, &work) != 0 ||
        strcmp(work.kind, "firmware") || strcmp(work.action, "apply") ||
        strcmp(work.state, "writing"))
        return 1;
    options = json_tokener_parse(work.options_json);
    if (!options || !json_object_is_type(options, json_type_object)) {
        if (options)
            json_object_put(options);
        (void)otad_operation_update(operation_id, "failed", 100,
                                    "operation_options_invalid",
                                    "persisted operation options are invalid", NULL);
        return 1;
    }
    allow_unpreserved = otad_json_bool(options, "allow_unpreserved", 0);
    auto_reboot = otad_json_bool(options, "auto_reboot", 1);
    json_object_put(options);
    rc = otad_firmware_apply_worker(operation_id, &work,
                                    allow_unpreserved, auto_reboot);
    return rc == 0 ? 0 : 1;
}

struct json_object *otad_firmware_apply(struct json_object *body)
{
    struct json_object *path_value = NULL;
    struct json_object *upload_value = NULL;
    const char *operation_id = otad_json_str(body, "operation_id", "");
    struct otad_operation_work work;
    char active_id[OTAD_OPERATION_ID_LEN + 1] = "";
    int rc;

    if (body && (json_object_object_get_ex(body, "path", &path_value) ||
                 json_object_object_get_ex(body, "upload_id", &upload_value)))
        return otad_error("apply_requires_preflight_operation",
                          "apply accepts only the operation_id returned by preflight");
    if (!otad_operation_id_ok(operation_id))
        return otad_error("operation_id_invalid",
                          "a pending firmware preflight operation_id is required");
    if (otad_operation_get_work(operation_id, &work) != 0)
        return otad_error("operation_not_found", "operation_id does not exist");
    if (strcmp(work.kind, "firmware") || strcmp(work.action, "preflight") ||
        strcmp(work.state, "pending"))
        return otad_error("operation_not_pending_preflight",
                          "firmware apply requires a successful pending preflight");
    {
        struct json_object *resp = otad_firmware_release_gate_error();

        (void)otad_operation_update(operation_id, "failed", 100,
                                    "firmware_release_trust_gate_closed",
                                    "firmware apply is disabled until publisher authenticity and target compatibility are verified",
                                    resp);
        otad_json_add_string(resp, "operation_id", operation_id);
        return resp;
    }
    rc = otad_operation_claim_apply(operation_id);
    if (rc == -2) {
        (void)otad_operation_find_active_firmware_apply(active_id);
        {
            struct json_object *resp = otad_error("firmware_operation_in_progress",
                                                  "another firmware write or reboot is active");
            otad_json_add_string(resp, "active_operation_id", active_id);
            return resp;
        }
    }
    if (rc != 0)
        return otad_error("operation_claim_failed",
                          "preflight operation could not transition to writing");
    if (otad_firmware_worker_start(operation_id) != 0) {
        (void)otad_operation_update(operation_id, "failed", 100,
                                    "operation_worker_start_failed",
                                    "failed to start the firmware slot-writing worker", NULL);
        return otad_operation_status_by_id(operation_id);
    }
    return otad_operation_status_by_id(operation_id);
}

struct json_object *otad_confirm_boot(struct json_object *body)
{
    struct otad_ab_topology topology;
    char current[2];
    char pending[16];
    char expected_operation_id[OTAD_OPERATION_ID_LEN + 1] = "";
    char completed_operation_id[OTAD_OPERATION_ID_LEN + 1] = "";
    uint32_t core_id;
    uint32_t network_id;
    sqlite3_stmt *st;
    int operation_rc;
    char *check_argv[] = { "/usr/bin/dreamingwrt-init", "check", "--json", NULL };

    char topology_error[128] = "";

    if (otad_ab_topology_discover(&topology, topology_error,
                                  sizeof(topology_error)) != 0)
        return otad_error(topology_error[0] ? topology_error : "ab_topology_invalid",
                          "current root, A/B partitions, and DATA mount must form a valid DreamingWrt topology");
    snprintf(current, sizeof(current), "%s", topology.current_slot);
    otad_state_get("pending_slot", pending, sizeof(pending), "");
    if (!pending[0] || strcmp(current, pending))
        return otad_error("pending_slot_mismatch", "current boot is not the pending slot");
    if (!g_otad_ubus || ubus_lookup_id(g_otad_ubus, "dreamingwrt", &core_id) != UBUS_STATUS_OK)
        return otad_error("core_unhealthy", "dreamingwrt core ubus object is unavailable");
    if (ubus_lookup_id(g_otad_ubus, "network.interface", &network_id) != UBUS_STATUS_OK)
        return otad_error("network_unhealthy", "netifd network.interface ubus object is unavailable");
    if (!otad_json_bool(body, "force", 0) &&
        (access("/usr/bin/dreamingwrt-init", X_OK) != 0 || otad_run(check_argv) != 0))
        return otad_error("supervisor_unhealthy", "dreamingwrt-init health check failed");
    if (otad_grubenv_promote(current) != 0)
        return otad_error("grubenv_confirm_failed", "failed to promote pending slot to active");
    otad_state_get("pending_operation_id", expected_operation_id,
                   sizeof(expected_operation_id), "");
    operation_rc = otad_operation_complete_confirmed_boot(
        current, expected_operation_id, "", completed_operation_id);
    if (operation_rc < 0)
        return otad_error("operation_confirm_failed",
                          "boot was promoted but its firmware operation could not be completed");
    otad_state_set("active_slot", current);
    otad_state_set("pending_slot", "");
    otad_state_set("pending_operation_id", "");
    otad_state_set("state", "idle");
    otad_state_set("last_error", "");
    st = otad_config_prepare(
        "UPDATE ota_slots SET state='good',last_good_at=?1,last_error='',updated_at=?1 WHERE slot_name=?2");
    if (st) {
        sqlite3_bind_int64(st, 1, otad_now_s());
        sqlite3_bind_text(st, 2, current, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    {
        struct json_object *resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "confirmed", json_object_new_boolean(1));
        otad_json_add_string(resp, "active_slot", current);
        json_object_object_add(resp, "operation_completed",
                               json_object_new_boolean(operation_rc == 0));
        otad_json_add_string(resp, "operation_id", completed_operation_id);
        return resp;
    }
}

void otad_reconcile_boot_state(void)
{
    struct otad_ab_topology topology;
    char current[2] = "";
    char active[16] = "";
    char pending[16] = "";
    char grub_active[16] = "";
    char grub_pending[16] = "";
    char grub_tries[16] = "";
    int grub_active_rc;
    int grub_pending_rc;
    int grub_tries_rc;
    sqlite3_stmt *st;

    if (otad_ab_topology_discover(&topology, NULL, 0) != 0)
        return;
    snprintf(current, sizeof(current), "%s", topology.current_slot);
    otad_state_get("active_slot", active, sizeof(active), current);
    otad_state_get("pending_slot", pending, sizeof(pending), "");
    grub_active_rc = otad_grubenv_get("active_slot", grub_active, sizeof(grub_active));
    grub_pending_rc = otad_grubenv_get("pending_slot", grub_pending, sizeof(grub_pending));
    grub_tries_rc = otad_grubenv_get("tries_left", grub_tries, sizeof(grub_tries));

    /* GRUB remains authoritative if DATA was stale or unavailable at boot. */
    if (grub_active_rc == 0 && (grub_active[0] == 'A' || grub_active[0] == 'B') &&
        strcmp(active, grub_active)) {
        snprintf(active, sizeof(active), "%s", grub_active);
        otad_state_set("active_slot", active);
    }
    if (grub_pending_rc == 0 && grub_pending[0]) {
        if (strcmp(pending, grub_pending)) {
            snprintf(pending, sizeof(pending), "%s", grub_pending);
            otad_state_set("pending_slot", pending);
        }
        if (!strcmp(current, pending)) {
            otad_state_set("state", "pending_boot");
            if (grub_tries_rc == 0)
                otad_slot_mark_pending_boot(pending,
                                            otad_attempts_from_tries(grub_tries));
        } else {
            otad_state_set("state", "pending_reboot");
        }
    }
    if (grub_active_rc == 0 && grub_pending_rc == 0 && grub_tries_rc == 0 &&
        !strcmp(current, grub_active) && !grub_pending[0] &&
        atoi(grub_tries) == 0 && !pending[0]) {
        char good_build_id[OTAD_MAX_TEXT] = "";
        char completed_operation_id[OTAD_OPERATION_ID_LEN + 1] = "";

        st = otad_config_prepare(
            "SELECT build_id FROM ota_slots WHERE slot_name=?1 AND state='good' LIMIT 1");
        if (st) {
            sqlite3_bind_text(st, 1, current, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW)
                snprintf(good_build_id, sizeof(good_build_id), "%s",
                         sqlite3_column_text(st, 0) ?
                         (const char *)sqlite3_column_text(st, 0) : "");
            sqlite3_finalize(st);
        }
        if (good_build_id[0] &&
            otad_operation_complete_confirmed_boot(
                current, "", good_build_id, completed_operation_id) == 0)
            fprintf(stderr,
                    "[dreamingwrt-otad] reconciled confirmed operation=%s slot=%s build=%s\n",
                    completed_operation_id, current, good_build_id);
    }
    if (!active[0])
        otad_state_set("active_slot", current);
    if (!pending[0] || !strcmp(current, pending))
        return;
    if (grub_pending_rc != 0 || grub_pending[0])
        return;

    st = otad_config_prepare(
        "UPDATE ota_slots SET state='rolled_back',last_error='boot_attempts_exhausted',"
        "updated_at=?1 WHERE slot_name=?2 AND state IN ('pending','pending_boot')");
    if (st) {
        sqlite3_bind_int64(st, 1, otad_now_s());
        sqlite3_bind_text(st, 2, pending, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    otad_state_set("active_slot", current);
    otad_state_set("pending_slot", "");
    otad_state_set("state", "rolled_back");
    otad_state_set("last_error", "boot_attempts_exhausted");
    fprintf(stderr, "[dreamingwrt-otad] reconciled automatic rollback pending=%s active=%s\n",
            pending, current);
}

struct json_object *otad_firmware_rollback(struct json_object *body)
{
    struct otad_ab_topology topology;
    char current[2];
    char active[16];
    char pending[16];
    char operation_id[OTAD_OPERATION_ID_LEN + 1] = "";
    sqlite3_stmt *st;

    char topology_error[128] = "";
    char boot_state_error[128] = "";

    (void)body;
    if (otad_ab_topology_discover(&topology, topology_error,
                                  sizeof(topology_error)) != 0)
        return otad_error(topology_error[0] ? topology_error : "ab_topology_invalid",
                          "rollback requires a valid same-disk DreamingWrt A/B topology");
    if (otad_ab_boot_state_readonly_verify(&topology, boot_state_error,
                                           sizeof(boot_state_error)) != 0)
        return otad_error(boot_state_error[0] ? boot_state_error :
                          "bootloader_slot_state_not_readonly_verified",
                          "rollback is disabled until bootloader slot state is independently verified");
    if (!topology.inactive_slot_bootable_verified)
        return otad_error("inactive_slot_not_bootable",
                          "rollback requires an independently verified bootable inactive slot");
    snprintf(current, sizeof(current), "%s", topology.current_slot);
    snprintf(active, sizeof(active), "%s", topology.boot_active_slot);
    snprintf(pending, sizeof(pending), "%s", topology.boot_pending_slot);
    if (pending[0] && strcmp(pending, current)) {
        if (otad_grubenv_clear_target(current, pending) != 0)
            return otad_error("grubenv_rollback_failed", "failed to invalidate the pending boot slot");
        otad_state_set_slot_valid(pending, 0);
        st = otad_config_prepare(
            "UPDATE ota_slots SET state='rolled_back',last_error='rollback_requested',"
            "updated_at=?1 WHERE slot_name=?2");
        if (st) {
            sqlite3_bind_int64(st, 1, otad_now_s());
            sqlite3_bind_text(st, 2, pending, -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    } else if (otad_grubenv_set_boot_selection(active, "", "0") != 0) {
        return otad_error("grubenv_rollback_failed", "failed to clear pending boot slot");
    }
    if (otad_operation_find_active_firmware_apply(operation_id) == 0 &&
        operation_id[0])
        (void)otad_operation_update(operation_id, "failed", 100,
                                    "rollback_requested",
                                    "pending firmware boot was rolled back before reboot",
                                    NULL);
    otad_state_set("pending_slot", "");
    otad_state_set("pending_operation_id", "");
    otad_state_set("state", "rollback_pending_reboot");
    {
        struct json_object *resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "rolled_back", json_object_new_boolean(1));
        json_object_object_add(resp, "pending_reboot", json_object_new_boolean(1));
        otad_json_add_string(resp, "target_slot", active);
        return resp;
    }
}

static void otad_topology_missing_evidence(struct json_object *missing,
                                           const char *error)
{
    const char *value = "ab_topology_integrity";

    if (!missing || !error || !error[0])
        return;
    if (strstr(error, "partlabel")) {
        json_object_array_add(missing, json_object_new_string(OTAD_SLOT_A_LABEL));
        json_object_array_add(missing, json_object_new_string(OTAD_SLOT_B_LABEL));
        json_object_array_add(missing, json_object_new_string(OTAD_BOOT_LABEL));
        json_object_array_add(missing, json_object_new_string(OTAD_DATA_LABEL));
        return;
    }
    if (strstr(error, "partuuid"))
        value = "unique_partition_partuuid";
    else if (strstr(error, "cmdline_slot"))
        value = !strcmp(error, "cmdline_slot_root_device_mismatch") ?
            "cmdline_mount_consistency" :
            "cmdline:dreamingos.slot|dreamingwrt.slot";
    else if (strstr(error, "cmdline_root"))
        value = "cmdline:root=PARTUUID";
    else if (strstr(error, "cmdline_evidence"))
        value = "proc:cmdline";
    else if (strstr(error, "root_mount") || strstr(error, "root_device") ||
             strstr(error, "root_slot"))
        value = "mount:/";
    else if (strstr(error, "data_mount"))
        value = "mount:/data";
    else if (strstr(error, "inactive_slot"))
        value = "inactive_slot_unmounted";
    else if (strstr(error, "bootloader") || strstr(error, "boot_partition"))
        value = "bootloader:grubenv_grubcfg";
    json_object_array_add(missing, json_object_new_string(value));
}

struct json_object *otad_slot_status_json(void)
{
    struct json_object *o = json_object_new_object();
    struct json_object *probes = json_object_new_object();
    struct json_object *missing = json_object_new_array();
    struct otad_ab_topology topology;
    char current[2] = "";
    char inactive[2] = "";
    char target[OTAD_MAX_PATH] = "";
    char a[OTAD_MAX_PATH] = "";
    char b[OTAD_MAX_PATH] = "";
    char boot[OTAD_MAX_PATH] = "";
    char data[OTAD_MAX_PATH] = "";
    char active[16];
    char pending[16];
    char topology_error[128] = "";
    char boot_state_error[128] = "";
    struct otad_ab_topology verified_topology;
    int topology_verified = otad_ab_topology_readonly_probe(
        &topology, topology_error, sizeof(topology_error)) == 0;
    int boot_state_verified = 0;

    if (topology_verified &&
        otad_ab_topology_discover(&verified_topology, boot_state_error,
                                  sizeof(boot_state_error)) == 0 &&
        otad_ab_boot_state_readonly_verify(&verified_topology,
                                           boot_state_error,
                                           sizeof(boot_state_error)) == 0) {
        topology = verified_topology;
        boot_state_verified = 1;
    }
    int supported = topology_verified && boot_state_verified;
    int inactive_bootable_verified = boot_state_verified &&
        topology.inactive_slot_bootable_verified;

    if (topology_verified) {
        snprintf(current, sizeof(current), "%s", topology.current_slot);
        snprintf(inactive, sizeof(inactive), "%s", topology.inactive_slot);
        snprintf(a, sizeof(a), "%s", topology.root_a);
        snprintf(b, sizeof(b), "%s", topology.root_b);
        snprintf(boot, sizeof(boot), "%s", topology.boot);
        snprintf(data, sizeof(data), "%s", topology.data);
        snprintf(target, sizeof(target), "%s",
                 topology.inactive_slot[0] == 'A' ? topology.root_a : topology.root_b);
    }

    snprintf(active, sizeof(active), "%s",
             boot_state_verified ? topology.boot_active_slot : "");
    snprintf(pending, sizeof(pending), "%s",
             boot_state_verified ? topology.boot_pending_slot : "");
    json_object_object_add(o, "supported", json_object_new_boolean(supported));
    json_object_object_add(o, "topology_readonly_verified",
                           json_object_new_boolean(topology_verified));
    otad_json_add_string(o, "layout", topology_verified ?
                         OTAD_AB_LAYOUT_SCHEMA : "unsupported");
    otad_json_add_string(o, "current_slot", current);
    otad_json_add_string(o, "active_slot", active);
    otad_json_add_string(o, "pending_slot", pending);
    otad_json_add_string(o, "inactive_slot", inactive);
    otad_json_add_string(o, "inactive_device", target);
    otad_json_add_string(o, "inactive_slot_state",
                         topology_verified ? topology.inactive_slot_state :
                         "unknown");
    json_object_object_add(o, "inactive_slot_write_target_verified",
                           json_object_new_boolean(topology_verified));
    json_object_object_add(o, "inactive_slot_bootable_verified",
                           json_object_new_boolean(
                               inactive_bootable_verified));
    json_object_object_add(o, "boot_state_readonly_verified",
                           json_object_new_boolean(boot_state_verified));
    otad_json_add_string(o, "boot_state_reason",
                         boot_state_verified ? "" :
                         (boot_state_error[0] ? boot_state_error :
                          "ab_topology_readonly_evidence_incomplete"));
    json_object_object_add(probes, "current_slot_detected",
                           json_object_new_boolean(topology_verified));
    otad_json_add_string(probes, "root_a_device", a);
    otad_json_add_string(probes, "root_b_device", b);
    otad_json_add_string(probes, "boot_device", boot);
    otad_json_add_string(probes, "data_device", data);
    otad_json_add_string(probes, "topology_digest",
                         boot_state_verified ? topology.topology_digest : "");
    otad_json_add_string(probes, "reason", topology_error);
    if (!topology_verified)
        otad_topology_missing_evidence(missing, topology_error);
    else if (!boot_state_verified)
        otad_topology_missing_evidence(missing, boot_state_error);
    json_object_object_add(probes, "missing", missing);
    otad_json_add_string(probes, "resolver",
                         "sysfs_blkid_mountinfo_cmdline_and_readonly_grub_state");
    json_object_object_add(probes, "configuration_values_trusted",
                           json_object_new_boolean(0));
    json_object_object_add(o, "probes", probes);
    return o;
}

static void otad_confirm_timer_cb(struct uloop_timeout *timeout)
{
    struct json_object *body = json_object_new_object();
    struct json_object *resp = otad_confirm_boot(body);
    const char *error;

    (void)timeout;
    if (!otad_json_bool(resp, "ok", 0)) {
        char tries[16] = "";
        char *reboot_argv[] = { "/sbin/reboot", NULL };

        error = otad_json_str(resp, "error", "health_check_failed");
        otad_state_set("state", "pending_boot_unhealthy");
        otad_state_set("last_error", error);
        (void)otad_grubenv_get("tries_left", tries, sizeof(tries));
        fprintf(stderr, "[dreamingwrt-otad] pending boot not confirmed: %s\n",
                error);
        fprintf(stderr,
                "[dreamingwrt-otad] requesting reboot for A/B retry tries_left=%s\n",
                tries[0] ? tries : "unknown");

        /* Keep a retry armed in case the reboot helper itself cannot signal init. */
        uloop_timeout_set(&g_otad_confirm_timer, OTAD_REBOOT_RETRY_DELAY_MS);
        sync();
        if (otad_run(reboot_argv) != 0)
            fprintf(stderr, "[dreamingwrt-otad] automatic reboot request failed\n");
    } else {
        fprintf(stderr, "[dreamingwrt-otad] pending slot confirmed active\n");
    }
    json_object_put(resp);
    json_object_put(body);
}

void otad_confirm_timer_start(void)
{
    struct otad_ab_topology topology;
    char current[2] = "";
    char pending[16];

    otad_state_get("pending_slot", pending, sizeof(pending), "");
    if (pending[0] && otad_ab_topology_discover(&topology, NULL, 0) == 0) {
        snprintf(current, sizeof(current), "%s", topology.current_slot);
    }
    if (pending[0] && current[0] && !strcmp(current, pending)) {
        g_otad_confirm_timer.cb = otad_confirm_timer_cb;
        uloop_timeout_set(&g_otad_confirm_timer, OTAD_BOOT_CONFIRM_DELAY_MS);
    }
}
