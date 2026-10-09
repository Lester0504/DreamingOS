// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FEATURES_H
#define DREAMINGWRT_FEATURES_H

/*
 * /etc/dreamingos_features -- optional per-device component profile.
 *
 * The file is optional: when it is missing, empty, or holds only comments,
 * dwrt_features_load() reports present = 0 and every consumer must behave
 * exactly as it did before this file existed.
 *
 *   Work_mode: ap                   -> /etc/dreamingwrt/device_role
 *   Disabled:                       -> force enabled = 0 (critical ignored)
 *     flowd
 *   Enabled:                        -> force enabled = 1, optional args
 *     logd --work_dir=/mnt/nvme
 *   Disabled_function:              -> disabled_function table input
 *     WIFI_6G
 *
 * Only the keys in dwrt_features_known_arg() are accepted on component lines;
 * anything else is reported through the warn callback and skipped.
 */

#include <stddef.h>

#ifndef DWRT_FEATURES_PATH
#define DWRT_FEATURES_PATH "/etc/dreamingos_features"
#endif
#ifndef DWRT_DEVICE_PRESET_PATH
#define DWRT_DEVICE_PRESET_PATH "/usr/share/dreamingos/device-preset.features"
#endif
#define DWRT_FEATURES_MAX_BYTES (64 * 1024)
#define DWRT_FEATURES_MAX_ENTRIES 48
#define DWRT_FEATURES_MAX_ARGS 6
#define DWRT_FEATURES_MAX_FUNCTIONS 64
#define DWRT_FEATURES_NAME_MAX 64
#define DWRT_FEATURES_ARG_MAX 256
#define DWRT_FEATURES_FUNC_MAX 65
#define DWRT_FEATURES_MODE_MAX 32

enum dwrt_features_state {
    DWRT_FEATURE_UNLISTED = 0,
    DWRT_FEATURE_ENABLED = 1,
    DWRT_FEATURE_DISABLED = 2,
};

struct dwrt_features_entry {
    char name[DWRT_FEATURES_NAME_MAX];
    int state;              /* enum dwrt_features_state */
    int line;
    int argc;
    char args[DWRT_FEATURES_MAX_ARGS][DWRT_FEATURES_ARG_MAX]; /* "--key=value" */
};

struct dwrt_features {
    int present;            /* file exists and declares at least one item */
    int has_function_section;
    int warnings;
    char work_mode[DWRT_FEATURES_MODE_MAX]; /* "" when not declared */
    size_t n_entries;
    struct dwrt_features_entry entries[DWRT_FEATURES_MAX_ENTRIES];
    size_t n_functions;
    char functions[DWRT_FEATURES_MAX_FUNCTIONS][DWRT_FEATURES_FUNC_MAX];
    int preset_version;
    char data_storage[16];
    char storage_priority[128];
    int has_automount;
    int storage_automount;
};

typedef void (*dwrt_features_warn_fn)(void *ctx, int line, const char *msg);

/*
 * Parse `path` (DWRT_FEATURES_PATH when NULL). Returns 0 on success, including
 * the missing-file case (present = 0), and -1 only when the file exists but
 * cannot be read or exceeds DWRT_FEATURES_MAX_BYTES; out is still zeroed then,
 * so a caller that ignores the return value falls back to compiled defaults.
 */
int dwrt_features_load(const char *path, struct dwrt_features *out,
                       dwrt_features_warn_fn warn, void *ctx);
int dwrt_features_parse(const char *buf, size_t len, struct dwrt_features *out,
                        dwrt_features_warn_fn warn, void *ctx);

const struct dwrt_features_entry *dwrt_features_find(const struct dwrt_features *f,
                                                     const char *name);
/* Value of "--key=value" in an entry, or NULL. `key` is given without "--". */
const char *dwrt_features_entry_arg(const struct dwrt_features_entry *e,
                                    const char *key);
int dwrt_features_known_arg(const char *key);
int dwrt_features_storage_priority_ok(const char *priority);

/* Uppercase/digit/underscore, 1..64 chars: the disabled_function code shape. */
int dwrt_features_function_code_ok(const char *code);

/*
 * --work_dir= policy: absolute, no "..", no shell metacharacters, and under an
 * external-storage prefix (/mnt/<name>... or /data/persist...). /opt, /etc,
 * /tmp and /var are refused: the first two are the same overlay flash the
 * relocation exists to relieve, the last two are volatile.
 * dwrt_features_work_dir_ok() checks the string only; _usable() additionally
 * requires an existing writable directory whose realpath still passes the
 * string policy, so a /mnt/x -> /opt symlink is refused.
 */
int dwrt_features_work_dir_ok(const char *path);
int dwrt_features_work_dir_usable(const char *path, char *resolved, size_t resolved_len);

/* argv helper for daemons: finds "--key=value" and returns value, or NULL. */
const char *dwrt_args_get(int argc, char **argv, const char *key);

#endif
