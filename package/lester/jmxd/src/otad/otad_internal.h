// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_OTAD_INTERNAL_H
#define DREAMINGWRT_OTAD_INTERNAL_H

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/fs.h>

#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <zlib.h>
#include <sqlite3.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

#ifndef OTAD_CONFIG_DB_PATH
#define OTAD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#endif
#ifndef OTAD_INVENTORY_DB_PATH
#define OTAD_INVENTORY_DB_PATH "/etc/dreamingwrt/inventory.db"
#endif
#ifndef OTAD_RELEASE_PATH
#define OTAD_RELEASE_PATH "/etc/dreamingwrt-release.json"
#endif
#ifndef OTAD_RELEASE_NEW_PATH
#define OTAD_RELEASE_NEW_PATH "/etc/dreamingos-release.json"
#endif
#define OTAD_TRUST_POLICY_PATH "/etc/dreamingwrt/ota-trust/policy.json"
#define OTAD_TRUST_KEY_DIR "/etc/dreamingwrt/ota-trust/keys"
#define OTAD_RELEASE_STATEMENT_TYPE "dreamingwrt.full_slot_release.v1"
#define OTAD_RUNTIME_ABI_VERSION "1"
#define OTAD_BOOT_SCHEMA_VERSION 2
#define OTAD_STATE_SCHEMA_VERSION 2
#define OTAD_INVENTORY_SCHEMA_VERSION 1
#define OTAD_MAX_TEXT 512
#define OTAD_MAX_PATH 512
#define OTAD_MAX_JSON_BYTES (4U * 1024U * 1024U)
#define OTAD_MAX_UNKNOWN_RESULTS 1000
#define OTAD_SMALL_FILE_HASH_LIMIT (1024U * 1024U)
#define OTAD_FIRMWARE_HEADER_BYTES (1024U * 1024U)
#define OTAD_FIRMWARE_MAGIC "DREAMINGWRT-FIRMWARE-V1\n"
#define OTAD_FIRMWARE_HEADER_NAME "firmware_info.json\n"
#define OTAD_BOOT_CONFIRM_DELAY_MS 120000
#define OTAD_REBOOT_RETRY_DELAY_MS 30000
#define OTAD_OPERATION_ID_LEN 36
#define OTAD_UPLOAD_ID_LEN 36
#define OTAD_OPERATION_OPTIONS_MAX 1024
#define OTAD_TRUST_KEY_ID_MAX 128
#define OTAD_UPLOAD_STAGING_ROOT "/data/persist/var/lib/dreamingwrt/upload-staging"
#define OTAD_FIRMWARE_MAX_BYTES (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define OTAD_SPACE_SAFETY_MIN_BYTES (64ULL * 1024ULL * 1024ULL)
#define OTAD_SPACE_SAFETY_PERCENT 10U
#define OTAD_SPACE_SAFETY_INODES 16ULL
#define OTAD_SLOT_A_LABEL "DWRT_ROOT_A"
#define OTAD_SLOT_B_LABEL "DWRT_ROOT_B"
#define OTAD_BOOT_LABEL "DWRT_BOOT"
#define OTAD_DATA_LABEL "DWRT_DATA"
#define OTAD_AB_LAYOUT_SCHEMA "gpt-bios-esp-root_a-root_b-data-v1"

struct otad_space_gate {
    int checked;
    int ok;
    int retryable;
    uint64_t artifact_bytes;
    uint64_t safety_margin_bytes;
    uint64_t required_bytes;
    uint64_t available_bytes;
    uint64_t required_inodes;
    uint64_t available_inodes;
    dev_t device;
    int64_t checked_at;
    char artifact[64];
    char capacity_kind[32];
    char path[OTAD_MAX_PATH];
    char error[64];
    char reason[128];
};

struct otad_operation_work {
    char operation_id[OTAD_OPERATION_ID_LEN + 1];
    char kind[32];
    char action[32];
    char upload_id[OTAD_UPLOAD_ID_LEN + 1];
    char state[32];
    char options_json[OTAD_OPERATION_OPTIONS_MAX];
    uint64_t source_size;
    char source_sha256[65];
    char target_slot[2];
    char manifest_digest[65];
    char signing_key_id[OTAD_TRUST_KEY_ID_MAX + 1];
    int trust_policy_version;
    char trust_policy_digest[65];
    char device_identity_digest[65];
    char topology_digest[65];
    int authenticity_verified;
    int target_compatible;
    int policy_passed;
};

struct otad_trust_binding {
    char manifest_digest[65];
    char signing_key_id[OTAD_TRUST_KEY_ID_MAX + 1];
    int trust_policy_version;
    char trust_policy_digest[65];
    char device_identity_digest[65];
    int authenticity_verified;
    int target_compatible;
    int policy_passed;
};

struct otad_ab_topology {
    char current_slot[2];
    char inactive_slot[2];
    char root_a[OTAD_MAX_PATH];
    char root_b[OTAD_MAX_PATH];
    char boot[OTAD_MAX_PATH];
    char data[OTAD_MAX_PATH];
    char parent_disk[128];
    char root_a_partuuid[128];
    char root_b_partuuid[128];
    char boot_partuuid[128];
    char data_partuuid[128];
    char root_a_devno[32];
    char root_b_devno[32];
    char boot_devno[32];
    char data_devno[32];
    char root_a_fstype[32];
    char root_b_fstype[32];
    char inactive_slot_state[32];
    char boot_active_slot[2];
    char boot_pending_slot[2];
    char boot_last_good_slot[2];
    unsigned int boot_tries_left;
    int slot_a_valid;
    int slot_b_valid;
    int slot_a_boot_entry_verified;
    int slot_b_boot_entry_verified;
    int boot_state_verified;
    int inactive_slot_bootable_verified;
    char topology_digest[65];
    uint64_t root_a_size;
    uint64_t root_b_size;
    uint64_t boot_size;
    uint64_t data_size;
};

extern sqlite3 *g_otad_config_db;
extern sqlite3 *g_otad_inventory_db;
extern struct ubus_context *g_otad_ubus;
extern struct blob_buf g_otad_blob;
extern struct uloop_timeout g_otad_confirm_timer;

int64_t otad_now_s(void);
const char *otad_json_str(struct json_object *o, const char *key, const char *def);
int otad_json_int(struct json_object *o, const char *key, int def);
int otad_json_bool(struct json_object *o, const char *key, int def);
struct json_object *otad_json_from_blob(struct blob_attr *msg);
struct json_object *otad_payload_or_self(struct json_object *body);
struct json_object *otad_error(const char *code, const char *message);
int otad_text_ok(const char *s, size_t max_len);
int otad_path_ok(const char *s);
int otad_file_read_all(const char *path, char **out, size_t *out_len, size_t max_len);
int otad_file_exists(const char *path);
int otad_dir_exists(const char *path);
int otad_mkdir_p(const char *path, mode_t mode);
void otad_json_add_string(struct json_object *o, const char *key, const char *value);
int otad_release_metadata_read(struct json_object **release_out,
                               const char **selected_path_out,
                               char *error, size_t error_len);
int otad_space_gate_check(const char *path, const char *artifact,
                          uint64_t artifact_bytes, uint64_t artifact_inodes,
                          struct otad_space_gate *gate);
int otad_block_capacity_gate_check(const char *path, const char *artifact,
                                   uint64_t artifact_bytes,
                                   uint64_t capacity_bytes,
                                   struct otad_space_gate *gate);
void otad_space_gate_add_json(struct json_object *o,
                              const struct otad_space_gate *gate);
struct json_object *otad_space_gate_error(const struct otad_space_gate *gate,
                                          const char *message);
void otad_space_gate_record(const struct otad_space_gate *gate);

int otad_release_trust_verify(int firmware_fd, uint64_t firmware_size,
                              struct json_object *firmware_info,
                              struct json_object **evidence_out,
                              char *error, size_t error_len);
int otad_release_trust_binding_get(struct json_object *result_or_evidence,
                                   struct otad_trust_binding *binding,
                                   char *error, size_t error_len);
struct json_object *otad_release_trust_status(void);
int otad_ab_partlabel_unique(const char *label, char *path, size_t path_len);
int otad_ab_topology_readonly_probe(struct otad_ab_topology *topology,
                                    char *error, size_t error_len);
int otad_ab_topology_discover(struct otad_ab_topology *topology,
                              char *error, size_t error_len);
int otad_ab_topology_validate_release(const struct otad_ab_topology *topology,
                                      struct json_object *firmware_info,
                                      char *error, size_t error_len);
struct json_object *otad_ab_topology_json(const struct otad_ab_topology *topology);
int otad_ab_boot_state_readonly_verify(const struct otad_ab_topology *topology,
                                       char *error, size_t error_len);

sqlite3_stmt *otad_config_prepare(const char *sql);
sqlite3_stmt *otad_inventory_prepare(const char *sql);
int otad_db_init(void);
void otad_db_close(void);
/* Flush the operation trail to stable storage. Call before anything that can
 * take the machine down, such as a slot write or a reboot request. */
int otad_db_persist_now(void);
int otad_state_set(const char *key, const char *value);
int otad_state_get(const char *key, char *out, size_t out_len, const char *def);
int otad_operation_id_ok(const char *operation_id);
int otad_upload_id_ok(const char *upload_id);
int otad_operation_create(const char *kind, const char *action,
                          const char *upload_id, struct json_object *options,
                          char operation_id[OTAD_OPERATION_ID_LEN + 1],
                          char *error, size_t error_len);
int otad_operation_set_worker_pid(const char *operation_id, pid_t worker_pid);
int otad_operation_claim_apply(const char *operation_id);
int otad_operation_get_work(const char *operation_id,
                            struct otad_operation_work *work);
int otad_operation_update(const char *operation_id, const char *state,
                          int progress, const char *error_code,
                          const char *error_message,
                          struct json_object *result);
int otad_operation_set_source(const char *operation_id, uint64_t source_size,
                              const char *source_sha256);
int otad_operation_commit_preflight(const char *operation_id,
                                    const char *from_version,
                                    const char *to_version,
                                    const char *build_id,
                                    const char *target_slot,
                                    const struct otad_trust_binding *binding,
                                    const char *topology_digest,
                                    struct json_object *result);
int otad_operation_reverify_trust_binding(
    int fd, uint64_t expected_size, const struct otad_operation_work *work,
    char *error, size_t error_len);
int otad_operation_find_active_firmware_apply(
    char operation_id[OTAD_OPERATION_ID_LEN + 1]);
int otad_operation_complete_confirmed_boot(
    const char *target_slot, const char *expected_operation_id,
    const char *expected_build_id,
    char operation_id[OTAD_OPERATION_ID_LEN + 1]);
struct json_object *otad_operation_status(struct json_object *body);
void otad_operations_reconcile_workers(void);
int otad_inventory_replace_file(const char *path, const char *owner_pkg,
                                const char *class_name, const struct stat *st,
                                const char *source, const char *preserve_policy,
                                const char *reason);
int otad_inventory_clear_unknowns(void);
int otad_inventory_add_unknown(const char *path, const char *reason,
                               const char *suggested_action, const struct stat *st,
                               int will_preserve);

struct json_object *otad_status_json(void);
struct json_object *otad_check_manifest(struct json_object *body);
struct json_object *otad_inventory_scan(struct json_object *body);
struct json_object *otad_unknowns_json(struct json_object *body);
struct json_object *otad_safe_not_implemented(const char *op);
struct json_object *otad_firmware_verify(struct json_object *body);
struct json_object *otad_firmware_apply(struct json_object *body);
struct json_object *otad_firmware_preflight(struct json_object *body);
int otad_operation_worker(const char *operation_id);
struct json_object *otad_update_verify(struct json_object *body);
struct json_object *otad_update_apply(struct json_object *body);
struct json_object *otad_firmware_rollback(struct json_object *body);
struct json_object *otad_confirm_boot(struct json_object *body);
struct json_object *otad_slot_status_json(void);
void otad_confirm_timer_start(void);
void otad_reconcile_boot_state(void);
int otad_hot_target_allowed(const char *firmware_type, const char *path);
int otad_component_name_ok(const char *name);

int otad_ubus_start(void);
void otad_ubus_stop(void);

#endif
