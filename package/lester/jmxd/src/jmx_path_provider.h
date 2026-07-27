// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_PATH_PROVIDER_H
#define DREAMINGWRT_PATH_PROVIDER_H

#include <stddef.h>

enum jmx_path_selection {
    JMX_PATH_SELECTION_NONE = 0,
    JMX_PATH_SELECTION_NEW,
    JMX_PATH_SELECTION_LEGACY,
    JMX_PATH_SELECTION_IDENTICAL_NEW,
};

struct jmx_immutable_file {
    char *name;
    char *selected_path;
    int selected_fd;
    enum jmx_path_selection selection;
};

struct jmx_immutable_file_set {
    struct jmx_immutable_file *items;
    size_t count;
};

/*
 * Select one immutable, read-only file during a machine-path migration.
 * Existing unsafe files and divergent new/legacy copies fail closed.
 */
int jmx_path_select_immutable(const char *new_path, const char *legacy_path,
                              char *selected_path, size_t selected_path_len,
                              enum jmx_path_selection *selection,
                              char *error, size_t error_len);

/*
 * Select the union of immutable files with a common suffix in two directories.
 * A same-name pair must be byte-identical. Unsafe directories/files and any
 * comparison race reject the complete set; callers never receive a partial set.
 */
int jmx_path_select_immutable_file_set(
    const char *new_dir, const char *legacy_dir, const char *suffix,
    struct jmx_immutable_file_set *set, char *error, size_t error_len);

void jmx_path_immutable_file_set_free(struct jmx_immutable_file_set *set);

const char *jmx_path_selection_name(enum jmx_path_selection selection);

#endif
