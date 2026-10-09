// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_MIGRATION_H
#define DREAMINGWRT_STORAGE_MIGRATION_H

#include <json-c/json.h>
#include <stddef.h>

#define JMX_STORAGE_MIGRATION_CONTRACT "storage-migration.v1"

typedef int (*jmx_storage_consumer_reopen_fn)(const char *use,
                                               const char *old_path,
                                               const char *new_path,
                                               void *arg);

typedef int (*jmx_storage_consumer_freeze_fn)(const char *use, void *arg);
typedef int (*jmx_storage_consumer_unfreeze_fn)(const char *use, void *arg);

/* The supervisor owns write freezing and consumer reopen.  The module performs
 * all filesystem work only after an explicit confirm=true request and rolls
 * back when the supervisor hook reports failure. */
void jmx_storage_migration_set_consumer_reopen_hook(
    jmx_storage_consumer_reopen_fn hook, void *arg);
void jmx_storage_migration_set_consumer_freeze_hooks(
    jmx_storage_consumer_freeze_fn freeze_hook,
    jmx_storage_consumer_unfreeze_fn unfreeze_hook, void *arg);
struct json_object *jmx_storage_migration_apply(struct json_object *request);

/* Valid only while a consumer hook is executing for the serialized migration. */
const char *jmx_storage_migration_current_provider(void);

/*
 * Boot-only copy/verify. Caller must prove all consumers are stopped and the
 * target parent is on the intended mounted volume. Never deletes the source
 * or commits assignments; callers commit only after this succeeds.
 */
int jmx_storage_migration_copy_offline(const char *old_path, const char *new_path,
                                      int is_dir, int allow_new,
                                      char *reason, size_t reason_len);

#endif
