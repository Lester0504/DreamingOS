
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#ifndef __JMX_SYSTEM_H__
#define __JMX_SYSTEM_H__

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef JMX_SYSTEM_MOUNT_CONTRACT_ONLY
#include <json-c/json.h>
#endif

#define JMX_SYSTEM_MOUNT_SOURCE_MAX 256
#define JMX_SYSTEM_MOUNT_TARGET_MAX 256
#define JMX_SYSTEM_MOUNT_FSTYPE_MAX 32
#define JMX_SYSTEM_MOUNT_OPTIONS_MAX 256
#define JMX_SYSTEM_MOUNT_ERROR_MAX 160
#define JMX_SYSTEM_MOUNT_ID_MAX 128
#define JMX_SYSTEM_MOUNT_PROBE_MAX 128
#define JMX_SYSTEM_MOUNT_READ_MAX 512

enum jmx_system_mount_rc {
    JMX_SYSTEM_MOUNT_OK = 0,
    JMX_SYSTEM_MOUNT_ERR_INVALID = -1,
    JMX_SYSTEM_MOUNT_ERR_IO = -2,
    JMX_SYSTEM_MOUNT_ERR_EXEC = -3,
    JMX_SYSTEM_MOUNT_ERR_ROLLBACK = -4
};

struct jmx_system_mount_spec {
    char source[JMX_SYSTEM_MOUNT_SOURCE_MAX];   /* /dev/..., UUID=..., LABEL=..., /dev/disk/by-* */
    char target[JMX_SYSTEM_MOUNT_TARGET_MAX];   /* protected: only safe subdirs under /mnt or /media */
    char fstype[JMX_SYSTEM_MOUNT_FSTYPE_MAX];
    char options[JMX_SYSTEM_MOUNT_OPTIONS_MAX]; /* comma-separated, shell-safe tokens */
    int enabled;
    int check_fs;
};

struct jmx_system_mount_txn_opts {
    const char *fstab_path;  /* default: /etc/config/fstab */
    const char *mount_bin;   /* default: /bin/mount */
    const char *umount_bin;  /* default: /bin/umount */
    const char *mounts_path; /* internal/tests; default: /proc/self/mounts */
    const char *mnt_root;    /* internal/tests; default: /mnt */
    const char *media_root;  /* internal/tests; default: /media */
    int dry_run;
    int execute_mount;
    int execute_umount;
};

struct jmx_system_mount_txn_result {
    int changed;
    int executed;
    int target_created;
    int rolled_back; /* true only after durable restore and successful readback */
    char backup_path[PATH_MAX]; /* durable pre-write snapshot, when an old file existed */
    char error[JMX_SYSTEM_MOUNT_ERROR_MAX];
};

struct jmx_system_mount_batch_result {
    struct jmx_system_mount_txn_result config;
    size_t mounted_count;
    size_t failed_index;
    int rollback_attempted;
    int rollback_succeeded;
    int config_rollback_succeeded;
    int mounts_rollback_succeeded;
    int directories_rollback_succeeded;
    char error[JMX_SYSTEM_MOUNT_ERROR_MAX];
};

struct jmx_system_mount_discovery_opts {
    const char *sys_class_block; /* default: /sys/class/block */
    const char *dev_root;        /* default: /dev */
    const char *by_uuid_dir;     /* default: /dev/disk/by-uuid */
    const char *by_label_dir;    /* default: /dev/disk/by-label */
    const char *mountinfo_path;  /* default: /proc/self/mountinfo */
    const char *swaps_path;      /* default: /proc/swaps */
    const char *blkid_bin;       /* default: /sbin/blkid */
    int blkid_timeout_ms;        /* default: 2000, bounded to 100..10000 */
    int trust_fixture_block_devices; /* host tests only; public wrappers never set */
};

struct jmx_system_mount_probe {
    char name[64];
    char parent[64];
    char devnode[JMX_SYSTEM_MOUNT_SOURCE_MAX];
    char uuid[JMX_SYSTEM_MOUNT_ID_MAX];
    char label[JMX_SYSTEM_MOUNT_ID_MAX];
    char partlabel[JMX_SYSTEM_MOUNT_ID_MAX];
    char parttype[JMX_SYSTEM_MOUNT_ID_MAX];
    char fstype[JMX_SYSTEM_MOUNT_FSTYPE_MAX];
    char stable_source[JMX_SYSTEM_MOUNT_SOURCE_MAX];
    char mounted_target[JMX_SYSTEM_MOUNT_TARGET_MAX];
    char excluded_reason[JMX_SYSTEM_MOUNT_ERROR_MAX];
    unsigned int major_num;
    unsigned int minor_num;
    int is_partition;
    int system_disk;
    int swap;
    int config_eligible;
    int mount_eligible;
};

struct jmx_system_mount_runtime_entry {
    char source[JMX_SYSTEM_MOUNT_SOURCE_MAX];
    char device[JMX_SYSTEM_MOUNT_SOURCE_MAX];
    char root[JMX_SYSTEM_MOUNT_TARGET_MAX];
    char target[JMX_SYSTEM_MOUNT_TARGET_MAX];
    /*
     * 绑定挂载的宿主挂载点（同 major:minor 上 root 为该条 root 前缀且最长的那条，
     * 通常是整卷挂载 `/data`）。整卷挂载自身留空。前端据此把绑定挂载折叠到宿主之下，
     * 而不是把同一个文件系统并列成十几行各自 19.5 GB 的"独立卷"。
     */
    char bind_host_target[JMX_SYSTEM_MOUNT_TARGET_MAX];
    char fstype[JMX_SYSTEM_MOUNT_FSTYPE_MAX];
    char options[JMX_SYSTEM_MOUNT_OPTIONS_MAX];
    unsigned int major_num;
    unsigned int minor_num;
    unsigned long long size_bytes;
    unsigned long long used_bytes;
    unsigned long long available_bytes;
    int used_percent;
    int bind_mount;
    int configured;
    int stat_ok;
};

struct jmx_system_mount_config_entry {
    char section[64];
    char source[JMX_SYSTEM_MOUNT_SOURCE_MAX];
    char target[JMX_SYSTEM_MOUNT_TARGET_MAX];
    char fstype[JMX_SYSTEM_MOUNT_FSTYPE_MAX];
    char options[JMX_SYSTEM_MOUNT_OPTIONS_MAX];
    int enabled;
    int check_fs;
    int mounted;
    int editable;
};

struct jmx_system_mount_read_opts {
    const char *mountinfo_path; /* default: /proc/self/mountinfo */
    const char *fstab_path;     /* default: /etc/config/fstab */
};

struct jmx_system_text_apply_opts {
    const char *path;
    const char *backup_path;
    const char *reload_bin;
    const char *reload_action;
    size_t max_bytes;
    unsigned int mode;
    int reload_timeout_ms;
    int dry_run;
};

struct jmx_system_text_apply_result {
    int changed;
    int reloaded;
    int rollback_attempted;
    int rollback_succeeded;
    int64_t applied_at;
    char backup_path[PATH_MAX];
    char error[JMX_SYSTEM_MOUNT_ERROR_MAX];
};

int jmx_system_mount_validate_source(const char *source, char *err, size_t err_len);
int jmx_system_mount_validate_target(const char *target, char *err, size_t err_len);
int jmx_system_mount_validate_fstype(const char *fstype, char *err, size_t err_len);
int jmx_system_mount_validate_options(const char *options, char *err, size_t err_len);
int jmx_system_mount_validate_spec(const struct jmx_system_mount_spec *spec,
                                   char *err, size_t err_len);
int jmx_system_mount_render_fstab_entry(const struct jmx_system_mount_spec *spec,
                                        char *out, size_t out_len,
                                        char *err, size_t err_len);
int jmx_system_mount_save_point(const struct jmx_system_mount_spec *spec,
                                const struct jmx_system_mount_txn_opts *opts,
                                struct jmx_system_mount_txn_result *result);
int jmx_system_mount_save_batch(const struct jmx_system_mount_spec *specs, size_t count,
                                const struct jmx_system_mount_txn_opts *opts,
                                struct jmx_system_mount_txn_result *result);
int jmx_system_mount_apply_batch(const struct jmx_system_mount_spec *specs, size_t count,
                                 const struct jmx_system_mount_txn_opts *opts,
                                 struct jmx_system_mount_batch_result *result);
int jmx_system_mount_delete_point(const struct jmx_system_mount_spec *spec,
                                  const struct jmx_system_mount_txn_opts *opts,
                                  struct jmx_system_mount_txn_result *result);
int jmx_system_mount_exec_mount(const struct jmx_system_mount_spec *spec,
                                const struct jmx_system_mount_txn_opts *opts,
                                struct jmx_system_mount_txn_result *result);
int jmx_system_mount_exec_umount(const struct jmx_system_mount_spec *spec,
                                 const struct jmx_system_mount_txn_opts *opts,
                                 struct jmx_system_mount_txn_result *result);
int jmx_system_mount_discover(const struct jmx_system_mount_discovery_opts *opts,
                              struct jmx_system_mount_probe *probes,
                              size_t max_probes, size_t *count_out,
                              char *err, size_t err_len);
int jmx_system_mount_runtime_capability(int require_mount_exec);
int jmx_system_mount_read(const struct jmx_system_mount_read_opts *opts,
                          struct jmx_system_mount_runtime_entry *runtime,
                          size_t runtime_max, size_t *runtime_count,
                          struct jmx_system_mount_config_entry *configured,
                          size_t configured_max, size_t *configured_count,
                          char *err, size_t err_len);
int jmx_system_crontab_validate_text(const char *text, size_t *bad_line,
                                     char *err, size_t err_len);
int jmx_system_crontab_special_times_supported(void);
int jmx_system_text_apply(const char *text,
                          const struct jmx_system_text_apply_opts *opts,
                          struct jmx_system_text_apply_result *result);

#ifndef JMX_SYSTEM_MOUNT_CONTRACT_ONLY
struct json_object *get_system_status(void);
void jmx_system_add_release_contract(struct json_object *system);
struct json_object *jmx_api_get_system_info(struct json_object *req_obj);
struct json_object *jmx_api_set_system_info(struct json_object *req_obj);
struct json_object *jmx_api_system_mount_validate(struct json_object *req_obj);
struct json_object *jmx_api_system_mount_save_point(struct json_object *req_obj);
struct json_object *jmx_api_system_mount_delete_point(struct json_object *req_obj);
struct json_object *jmx_api_system_mount_execute(struct json_object *req_obj);
struct json_object *jmx_api_system_mount_discover(struct json_object *req_obj);
struct json_object *jmx_api_system_mount_generate_config(struct json_object *req_obj);
struct json_object *jmx_api_system_mount_connected(struct json_object *req_obj);
struct json_object *jmx_system_mounts_read_json(void);
#endif

#endif
