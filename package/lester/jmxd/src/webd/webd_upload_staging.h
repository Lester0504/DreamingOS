// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_UPLOAD_STAGING_H
#define WEBD_UPLOAD_STAGING_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WEBD_UPLOAD_ID_LEN 36
#define WEBD_UPLOAD_SHA256_HEX_LEN 64
#define WEBD_UPLOAD_OWNER_ID_LEN 128
#define WEBD_UPLOAD_DEFAULT_ROOT "/data/persist/var/lib/dreamingwrt/upload-staging"
#define WEBD_UPLOAD_DEFAULT_TTL_SECONDS 3600
#define WEBD_UPLOAD_META_SCAN_LIMIT 512

struct webd_upload_meta {
    char upload_id[WEBD_UPLOAD_ID_LEN + 1];
    char owner_id[WEBD_UPLOAD_OWNER_ID_LEN + 1];
    char origin[24];
    char upload_type[16];
    char original_filename[256];
    char status[16];
    uint64_t size_bytes;
    uint64_t expected_size_bytes;
    uint64_t max_size_bytes;
    time_t created_at;
    time_t updated_at;
    time_t expires_at;
    char sha256[WEBD_UPLOAD_SHA256_HEX_LEN + 1];
    char error[96];
};

struct webd_upload_list {
    struct webd_upload_meta *items;
    size_t count;
};

int webd_upload_staging_set_root_for_tests(const char *root);
const char *webd_upload_staging_root(void);
int webd_upload_type_allowed(const char *upload_type);
uint64_t webd_upload_type_default_max(const char *upload_type);

int webd_upload_begin(const char *owner_id,
                      const char *origin,
                      const char *upload_type,
                      const char *original_filename,
                      uint64_t expected_size_bytes,
                      uint64_t max_size_bytes,
                      unsigned ttl_seconds,
                      struct webd_upload_meta *out,
                      char *err,
                      size_t err_len);

int webd_upload_append(const char *owner_id,
                       const char *upload_id,
                       uint64_t offset,
                       const void *chunk,
                       size_t chunk_len,
                       struct webd_upload_meta *out,
                       char *err,
                       size_t err_len);

int webd_upload_finalize(const char *owner_id,
                         const char *upload_id,
                         const char *expected_sha256_hex,
                         struct webd_upload_meta *out,
                         char *err,
                         size_t err_len);

int webd_upload_get(const char *owner_id,
                    const char *upload_id,
                    struct webd_upload_meta *out,
                    char *err,
                    size_t err_len);

int webd_upload_delete(const char *owner_id,
                       const char *upload_id,
                       char *err,
                       size_t err_len);

int webd_upload_list_all(struct webd_upload_list *out,
                         char *err,
                         size_t err_len);
int webd_upload_list_owner(const char *owner_id,
                           struct webd_upload_list *out,
                           char *err,
                           size_t err_len);
void webd_upload_list_free(struct webd_upload_list *list);

int webd_upload_cleanup_expired(time_t now,
                                size_t *deleted_count,
                                char *err,
                                size_t err_len);

int webd_upload_open_final_readonly(const char *owner_id,
                                    const char *upload_id,
                                    char *err,
                                    size_t err_len);

#ifdef __cplusplus
}
#endif

#endif
