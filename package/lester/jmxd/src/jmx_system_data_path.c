// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_system_data_path.h"
#include "jmx_path_provider.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef JMX_SYSTEM_SIGNATURE_HOT_PATH
#define JMX_SYSTEM_SIGNATURE_HOT_PATH "/tmp/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SYSTEM_SIGNATURE_SEALED_HOT_PATH
#define JMX_SYSTEM_SIGNATURE_SEALED_HOT_PATH "/tmp/dreamingwrt_signatures.dwsig"
#endif
#ifndef JMX_SYSTEM_SIGNATURE_SEALED_RUNTIME_PATH
#define JMX_SYSTEM_SIGNATURE_SEALED_RUNTIME_PATH "/etc/dreamingwrt/dreamingwrt_signatures.dwsig"
#endif
#ifndef JMX_SYSTEM_SIGNATURE_SEALED_NEW_PATH
#define JMX_SYSTEM_SIGNATURE_SEALED_NEW_PATH "/usr/share/dreamingos/system-db/dreamingwrt_signatures.dwsig"
#endif
#ifndef JMX_SYSTEM_SIGNATURE_SEALED_LEGACY_PATH
#define JMX_SYSTEM_SIGNATURE_SEALED_LEGACY_PATH "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.dwsig"
#endif
#ifndef JMX_SYSTEM_SIGNATURE_RUNTIME_PATH
#define JMX_SYSTEM_SIGNATURE_RUNTIME_PATH "/etc/dreamingwrt/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SYSTEM_SIGNATURE_NEW_PATH
#define JMX_SYSTEM_SIGNATURE_NEW_PATH "/usr/share/dreamingos/system-db/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SYSTEM_SIGNATURE_LEGACY_PATH
#define JMX_SYSTEM_SIGNATURE_LEGACY_PATH "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SYSTEM_FINGERPRINT_RUNTIME_PATH
#define JMX_SYSTEM_FINGERPRINT_RUNTIME_PATH "/etc/dreamingwrt/fingerprint/fingerprint.db"
#endif
#ifndef JMX_SYSTEM_FINGERPRINT_NEW_PATH
#define JMX_SYSTEM_FINGERPRINT_NEW_PATH "/usr/share/dreamingos/system-db/fingerprint.db"
#endif
#ifndef JMX_SYSTEM_FINGERPRINT_LEGACY_PATH
#define JMX_SYSTEM_FINGERPRINT_LEGACY_PATH "/usr/share/dreamingwrt/system-db/fingerprint.db"
#endif

static void resolver_error(char *error, size_t error_len, const char *value)
{
    if (error && error_len)
        snprintf(error, error_len, "%s", value ? value : "");
}

static int select_direct(const char *path, char *selected, size_t selected_len,
                         enum jmx_system_db_source value,
                         enum jmx_system_db_source *source,
                         char *error, size_t error_len)
{
    if (snprintf(selected, selected_len, "%s", path) >= (int)selected_len) {
        resolver_error(error, error_len, "selected_path_too_long");
        return -1;
    }
    *source = value;
    return 0;
}

enum direct_path_state {
    DIRECT_PATH_MISSING = 0,
    DIRECT_PATH_VALID,
    DIRECT_PATH_INVALID,
};

static enum direct_path_state direct_path_probe(const char *path,
                                                char *error,
                                                size_t error_len)
{
    struct stat status;

    if (!path || path[0] != '/') {
        resolver_error(error, error_len, "invalid_argument");
        return DIRECT_PATH_INVALID;
    }
    if (lstat(path, &status) != 0) {
        if (errno == ENOENT)
            return DIRECT_PATH_MISSING;
        resolver_error(error, error_len, "path_probe_failed");
        return DIRECT_PATH_INVALID;
    }
    if (!S_ISREG(status.st_mode)) {
        resolver_error(error, error_len, "path_not_safe_regular_file");
        return DIRECT_PATH_INVALID;
    }
    if (access(path, R_OK) != 0) {
        resolver_error(error, error_len, "path_not_readable");
        return DIRECT_PATH_INVALID;
    }
    return DIRECT_PATH_VALID;
}

const char *jmx_system_db_source_name(enum jmx_system_db_source source)
{
    switch (source) {
    case JMX_SYSTEM_DB_SOURCE_HOT_UPDATE:
        return "hot-update";
    case JMX_SYSTEM_DB_SOURCE_RUNTIME:
        return "runtime-authority";
    case JMX_SYSTEM_DB_SOURCE_FIRMWARE_NEW:
        return "firmware-new-only";
    case JMX_SYSTEM_DB_SOURCE_FIRMWARE_LEGACY:
        return "firmware-legacy-fallback";
    case JMX_SYSTEM_DB_SOURCE_FIRMWARE_IDENTICAL_NEW:
        return "firmware-new-identical-to-legacy";
    default:
        return "none";
    }
}

int jmx_system_db_resolve(enum jmx_system_db_kind kind,
                          char *selected_path, size_t selected_path_len,
                          enum jmx_system_db_source *source,
                          char *error, size_t error_len)
{
    struct jmx_system_db_paths paths;

    if (!selected_path || selected_path_len == 0 || !source) {
        resolver_error(error, error_len, "invalid_argument");
        return -1;
    }
    selected_path[0] = '\0';
    *source = JMX_SYSTEM_DB_SOURCE_NONE;
    resolver_error(error, error_len, "");
    memset(&paths, 0, sizeof(paths));
    switch (kind) {
    case JMX_SYSTEM_DB_SIGNATURE: {
        const struct jmx_system_db_paths sealed = {
            .hot = JMX_SYSTEM_SIGNATURE_SEALED_HOT_PATH,
            .runtime = JMX_SYSTEM_SIGNATURE_SEALED_RUNTIME_PATH,
            .firmware_new = JMX_SYSTEM_SIGNATURE_SEALED_NEW_PATH,
            .firmware_legacy = JMX_SYSTEM_SIGNATURE_SEALED_LEGACY_PATH,
        };
        paths.hot = JMX_SYSTEM_SIGNATURE_HOT_PATH;
        paths.runtime = JMX_SYSTEM_SIGNATURE_RUNTIME_PATH;
        paths.firmware_new = JMX_SYSTEM_SIGNATURE_NEW_PATH;
        paths.firmware_legacy = JMX_SYSTEM_SIGNATURE_LEGACY_PATH;
        return jmx_system_signature_resolve_paths(&sealed, &paths, selected_path,
                                                   selected_path_len, source,
                                                   error, error_len);
    }
    case JMX_SYSTEM_DB_FINGERPRINT:
        paths.runtime = JMX_SYSTEM_FINGERPRINT_RUNTIME_PATH;
        paths.firmware_new = JMX_SYSTEM_FINGERPRINT_NEW_PATH;
        paths.firmware_legacy = JMX_SYSTEM_FINGERPRINT_LEGACY_PATH;
        break;
    default:
        resolver_error(error, error_len, "unknown_system_db_kind");
        return -1;
    }
    return jmx_system_db_resolve_paths(&paths, selected_path,
                                       selected_path_len, source,
                                       error, error_len);
}

int jmx_system_db_resolve_paths(
    const struct jmx_system_db_paths *paths,
    char *selected_path, size_t selected_path_len,
    enum jmx_system_db_source *source,
    char *error, size_t error_len)
{
    enum jmx_path_selection selection;
    enum direct_path_state direct_state;

    if (!paths || !paths->runtime || !paths->firmware_new ||
        !paths->firmware_legacy || !selected_path || selected_path_len == 0 ||
        !source) {
        resolver_error(error, error_len, "invalid_argument");
        return -1;
    }
    selected_path[0] = '\0';
    *source = JMX_SYSTEM_DB_SOURCE_NONE;
    resolver_error(error, error_len, "");
    if (paths->hot) {
        direct_state = direct_path_probe(paths->hot, error, error_len);
        if (direct_state == DIRECT_PATH_INVALID)
            return -1;
        if (direct_state == DIRECT_PATH_VALID)
            return select_direct(paths->hot, selected_path, selected_path_len,
                                 JMX_SYSTEM_DB_SOURCE_HOT_UPDATE, source,
                                 error, error_len);
    }
    direct_state = direct_path_probe(paths->runtime, error, error_len);
    if (direct_state == DIRECT_PATH_INVALID)
        return -1;
    if (direct_state == DIRECT_PATH_VALID)
        return select_direct(paths->runtime, selected_path, selected_path_len,
                             JMX_SYSTEM_DB_SOURCE_RUNTIME, source,
                             error, error_len);
    if (jmx_path_select_immutable(paths->firmware_new, paths->firmware_legacy,
                                  selected_path, selected_path_len, &selection,
                                  error, error_len) != 0)
        return -1;
    switch (selection) {
    case JMX_PATH_SELECTION_NEW:
        *source = JMX_SYSTEM_DB_SOURCE_FIRMWARE_NEW;
        break;
    case JMX_PATH_SELECTION_LEGACY:
        *source = JMX_SYSTEM_DB_SOURCE_FIRMWARE_LEGACY;
        break;
    case JMX_PATH_SELECTION_IDENTICAL_NEW:
        *source = JMX_SYSTEM_DB_SOURCE_FIRMWARE_IDENTICAL_NEW;
        break;
    default:
        selected_path[0] = '\0';
        resolver_error(error, error_len, "invalid_path_selection");
        return -1;
    }
    return 0;
}

int jmx_system_signature_resolve_paths(
    const struct jmx_system_db_paths *sealed,
    const struct jmx_system_db_paths *plaintext,
    char *selected_path, size_t selected_path_len,
    enum jmx_system_db_source *source, char *error, size_t error_len)
{
    char sealed_error[96] = "";
    int rc = jmx_system_db_resolve_paths(sealed, selected_path,
                                          selected_path_len, source,
                                          sealed_error, sizeof(sealed_error));
    /* Stage 1: only absence permits the legacy fallback. A present container
     * is authoritative; a bad path, signature or key must never downgrade to
     * plaintext. The corpus loader verifies it after this selection. */
    if (rc != 0 && !strcmp(sealed_error, "path_not_found"))
        return jmx_system_db_resolve_paths(plaintext, selected_path,
                                           selected_path_len, source,
                                           error, error_len);
    resolver_error(error, error_len, sealed_error);
    return rc;
}

/*
 * Is a /www static asset servable, as opposed to merely present as plaintext?
 *
 * Browser assets under /www/dreamingwrt/static are installed gzip-only:
 * dreamingos-extra-appicons ships 5004 files, every one of them a .gz, zero
 * plaintext.  nginx serves that tree through
 *
 *     location ^~ /static/ {
 *             alias /www/dreamingwrt/static/;
 *             if ($http_accept_encoding !~* gzip) { return 406; }
 *             gzip_static on;
 *     }
 *
 * so a plaintext URL is served *from the .gz twin*, and a client that cannot
 * accept gzip is rejected with 406 before any file is opened.  Measured on
 * 31.251: GET /static/images/logo/09.png with Accept-Encoding: gzip answers 200,
 * image/png, Content-Encoding: gzip, 4674 B -- exactly the size of 09.png.gz on
 * disk -- while a name present in neither form answers 404.
 *
 * access(<plaintext>, R_OK) therefore asks the wrong question.  It asks whether
 * these bytes are on disk, where the caller needs to know whether nginx can
 * serve this URL.  On a gzip-only install the first is permanently false while
 * the second is true, which is why every resolver that probed the plaintext path
 * emitted no icon URL at all.  Callers must keep emitting the plaintext URL:
 * nginx appends the .gz itself and sets Content-Encoding, whereas a URL that
 * ended in .gz would be served as an opaque application/gzip download instead of
 * an image.
 */
int jmx_static_asset_servable(const char *fs_path)
{
    char gz_path[PATH_MAX];
    struct stat st;

    if (!fs_path || !fs_path[0])
        return 0;
    if (stat(fs_path, &st) == 0 && S_ISREG(st.st_mode) &&
        access(fs_path, R_OK) == 0)
        return 1;
    if (snprintf(gz_path, sizeof(gz_path), "%s.gz", fs_path) >=
        (int)sizeof(gz_path))
        return 0;
    return stat(gz_path, &st) == 0 && S_ISREG(st.st_mode) &&
           access(gz_path, R_OK) == 0;
}
