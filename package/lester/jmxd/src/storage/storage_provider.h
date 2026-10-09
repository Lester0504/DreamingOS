// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_PROVIDER_H
#define DREAMINGWRT_STORAGE_PROVIDER_H

#include <json-c/json.h>
#include <stddef.h>
#include <stdint.h>

/* Read-only external storage provider contract.  Discovery never formats or
 * mounts a block device; callers must pass a provider through a separate
 * privileged supervisor before migration can be attempted. */

#define JMX_STORAGE_PROVIDER_CONTRACT "storage-provider.v1"
#define JMX_STORAGE_PROVIDER_ID_MAX 128
#define JMX_STORAGE_PROVIDER_REASON_MAX 96
#define JMX_STORAGE_PROVIDER_PATH_MAX 4096
#define JMX_STORAGE_PROVIDER_MAX 128

enum jmx_storage_provider_use {
    JMX_STORAGE_USE_AUDIT = 0,
    JMX_STORAGE_USE_AEGIS,
    JMX_STORAGE_USE_LOG,
    JMX_STORAGE_USE_SNAPSHOTS,
};

struct jmx_storage_provider {
    char id[JMX_STORAGE_PROVIDER_ID_MAX];
    char device[JMX_STORAGE_PROVIDER_PATH_MAX];
    char label[128];
    char uuid[128];
    char filesystem[64];
    char mountpoint[JMX_STORAGE_PROVIDER_PATH_MAX];
    uint64_t capacity_bytes;
    uint64_t available_bytes;
    uint64_t used_bytes;
    int mounted;
    int writable;
    int healthy;
    int eligible;
    int safe_to_unmount;
    int duplicate_mounts;
    char reason[JMX_STORAGE_PROVIDER_REASON_MAX];
};

struct jmx_storage_provider_use_binding {
    char use[32];
    char requested_provider[JMX_STORAGE_PROVIDER_ID_MAX];
    char active_provider[JMX_STORAGE_PROVIDER_ID_MAX];
    char state[32];
    char reason[JMX_STORAGE_PROVIDER_REASON_MAX];
    char old_path[JMX_STORAGE_PROVIDER_PATH_MAX];
    char new_path[JMX_STORAGE_PROVIDER_PATH_MAX];
    char snapshot_id[128];
    int rollback_available;
};

/* Raw JSON objects are intentionally independent of ubus/WebD.  An owning
 * route can wrap them in jmx_gen_api_response_data without coupling this
 * module to an active API source file. */
struct json_object *jmx_storage_providers_json(void);
struct json_object *jmx_storage_bindings_json(void);
struct json_object *jmx_storage_provider_status_json(void);
int jmx_storage_provider_discover(struct jmx_storage_provider *providers, size_t capacity);
int jmx_storage_provider_has_room(const char *path);

const char *jmx_storage_provider_use_name(enum jmx_storage_provider_use use);

#endif
