// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_OTAD_PERSIST_SOURCE_H
#define DREAMINGWRT_OTAD_PERSIST_SOURCE_H

#include <stddef.h>

struct otad_persist_prefixes {
    char **items;
    size_t count;
    size_t capacity;
};

struct otad_persist_source_status {
    int new_only;
    int legacy_only;
    int identical_new;
    int runtime_files;
    char error[64];
};

int otad_persist_sources_load(const char *new_dir, const char *legacy_dir,
                              const char *runtime_dir,
                              struct otad_persist_prefixes *prefixes,
                              struct otad_persist_source_status *status);

void otad_persist_prefixes_free(struct otad_persist_prefixes *prefixes);

#endif
