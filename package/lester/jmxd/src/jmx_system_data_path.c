// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_system_data_path.h"
#include "jmx_path_provider.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef JMX_SYSTEM_SIGNATURE_HOT_PATH
#define JMX_SYSTEM_SIGNATURE_HOT_PATH "/tmp/dreamingwrt_signatures.db"
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
    case JMX_SYSTEM_DB_SIGNATURE:
        paths.hot = JMX_SYSTEM_SIGNATURE_HOT_PATH;
        paths.runtime = JMX_SYSTEM_SIGNATURE_RUNTIME_PATH;
        paths.firmware_new = JMX_SYSTEM_SIGNATURE_NEW_PATH;
        paths.firmware_legacy = JMX_SYSTEM_SIGNATURE_LEGACY_PATH;
        break;
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
