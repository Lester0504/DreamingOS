// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_SYSTEM_DATA_PATH_H
#define DREAMINGWRT_SYSTEM_DATA_PATH_H

#include <stddef.h>

enum jmx_system_db_kind {
    JMX_SYSTEM_DB_SIGNATURE = 0,
    JMX_SYSTEM_DB_FINGERPRINT,
};

enum jmx_system_db_source {
    JMX_SYSTEM_DB_SOURCE_NONE = 0,
    JMX_SYSTEM_DB_SOURCE_HOT_UPDATE,
    JMX_SYSTEM_DB_SOURCE_RUNTIME,
    JMX_SYSTEM_DB_SOURCE_FIRMWARE_NEW,
    JMX_SYSTEM_DB_SOURCE_FIRMWARE_LEGACY,
    JMX_SYSTEM_DB_SOURCE_FIRMWARE_IDENTICAL_NEW,
};

struct jmx_system_db_paths {
    const char *hot;
    const char *runtime;
    const char *firmware_new;
    const char *firmware_legacy;
};

int jmx_system_db_resolve_paths(
    const struct jmx_system_db_paths *paths,
    char *selected_path, size_t selected_path_len,
    enum jmx_system_db_source *source,
    char *error, size_t error_len);

int jmx_system_db_resolve(enum jmx_system_db_kind kind,
                          char *selected_path, size_t selected_path_len,
                          enum jmx_system_db_source *source,
                          char *error, size_t error_len);

const char *jmx_system_db_source_name(enum jmx_system_db_source source);

#endif
