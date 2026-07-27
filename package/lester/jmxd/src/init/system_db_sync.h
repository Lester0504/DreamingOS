// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_SYSTEM_DB_SYNC_H
#define DREAMINGWRT_SYSTEM_DB_SYNC_H

#include <stddef.h>

#define DWRT_SYSTEM_DB_COUNT 2

struct dwrt_system_db_item_status {
    char name[32];
    char source[256];
    char source_selection[32];
    char target[256];
    char source_sha256[65];
    char target_sha256[65];
    char firmware_identity[65];
    char applied_firmware_identity[65];
    char applied_source_sha256[65];
    char action[32];
    char error[128];
    int source_valid;
    int target_valid;
    int changed;
    int source_conflict;
};

struct dwrt_system_db_status {
    struct dwrt_system_db_item_status items[DWRT_SYSTEM_DB_COUNT];
    size_t count;
    int changed;
    int errors;
    int conflicts;
};

int dwrt_system_db_sync(struct dwrt_system_db_status *status);
int dwrt_system_db_inspect(struct dwrt_system_db_status *status);

#endif
