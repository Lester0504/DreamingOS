// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AC_SECRETS_H
#define DREAMINGWRT_AC_SECRETS_H

#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#define AC_SECRET_KEY_BYTES 32U
#define AC_SECRET_ID_MAX 128U

struct ac_secrets;

enum ac_secrets_result {
    AC_SECRETS_ERROR = -1,
    AC_SECRETS_OK = 0,
    AC_SECRETS_NOT_FOUND = 1,
    AC_SECRETS_AUTH_FAILED = 2,
    AC_SECRETS_INVALID = 3,
};

/* The production key file must be a regular, non-symlink, root-owned 0600
 * file containing exactly AC_SECRET_KEY_BYTES raw bytes. */
int ac_secrets_open(sqlite3 *db, const char *key_path,
                    struct ac_secrets **out);
int ac_secrets_open_or_create(sqlite3 *db, const char *key_path,
                              struct ac_secrets **out);
void ac_secrets_close(struct ac_secrets *secrets);

int ac_secrets_schema_init(sqlite3 *db);
int ac_secrets_put(struct ac_secrets *secrets, const char *secret_id,
                   uint64_t version, const unsigned char *plaintext,
                   size_t plaintext_len);
int ac_secrets_get(struct ac_secrets *secrets, const char *secret_id,
                   uint64_t version, unsigned char **plaintext,
                   size_t *plaintext_len);
int ac_secrets_delete(struct ac_secrets *secrets, const char *secret_id);

/* Secret buffers returned by ac_secrets_get must be released here. */
void ac_secrets_clear(unsigned char *plaintext, size_t plaintext_len);
const char *ac_secrets_key_id(const struct ac_secrets *secrets);

#ifdef AC_SECRETS_TESTING
int ac_secrets_open_with_key(sqlite3 *db,
                             const unsigned char key[AC_SECRET_KEY_BYTES],
                             struct ac_secrets **out);
#endif

#endif
