// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_CONFIG_RESTORE_H
#define DREAMINGWRT_CONFIG_RESTORE_H

#include <stddef.h>
#include <stdint.h>

#include "config_migrate.h"

#ifndef DWRT_CONFIG_DB
#define DWRT_CONFIG_DB "/etc/dreamingwrt/config.db"
#endif
#ifndef DWRT_CONFIG_RESTORE_DIR
#define DWRT_CONFIG_RESTORE_DIR "/etc/dreamingwrt/restore-staging"
#endif
#ifndef DWRT_CONFIG_RESTORE_DB
#define DWRT_CONFIG_RESTORE_DB DWRT_CONFIG_RESTORE_DIR "/config.db"
#endif
#ifndef DWRT_CONFIG_RESTORE_MANIFEST
#define DWRT_CONFIG_RESTORE_MANIFEST DWRT_CONFIG_RESTORE_DIR "/manifest.json"
#endif
#ifndef DWRT_CONFIG_RESTORE_PENDING
#define DWRT_CONFIG_RESTORE_PENDING DWRT_CONFIG_RESTORE_DIR "/pending"
#endif
#ifndef DWRT_CONFIG_RESTORE_STATE
#define DWRT_CONFIG_RESTORE_STATE DWRT_CONFIG_RESTORE_DIR "/state.json"
#endif
#ifndef DWRT_CONFIG_RESTORE_BACKUP_DIR
#define DWRT_CONFIG_RESTORE_BACKUP_DIR "/etc/dreamingwrt/config-restore-backup"
#endif
#ifndef DWRT_NETWORK_CONFIG
#define DWRT_NETWORK_CONFIG "/etc/config/network"
#endif
#ifndef DWRT_DHCP_CONFIG
#define DWRT_DHCP_CONFIG "/etc/config/dhcp"
#endif
#ifndef DWRT_FIREWALL_CONFIG
#define DWRT_FIREWALL_CONFIG "/etc/config/firewall"
#endif
#ifndef DWRT_SYSTEM_CONFIG
#define DWRT_SYSTEM_CONFIG "/etc/config/system"
#endif

#define DWRT_CONFIG_RESTORE_FORMAT "dreamingwrt-config-backup-v1"
#define DWRT_CONFIG_RESTORE_CONFIRM_SECONDS 600

struct dwrt_config_restore_info {
    char phase[40];
    char operation_id[96];
    char source_sha256[65];
    char expected_lan_ip[96];
    char error[192];
    uint64_t size_bytes;
    int64_t started_at;
    int64_t deadline;
    int wan_count;
    int lan_count;
    int pending;
    int backup_available;
    int migrated;
    int migrated_from_version;
};

struct dwrt_config_restore_hooks {
    int (*stop_all)(void *opaque);
    int (*start_core)(void *opaque);
    int (*start_all)(void *opaque);
    void *opaque;
};

int dwrt_config_restore_status(struct dwrt_config_restore_info *out);
int dwrt_config_restore_arm(struct dwrt_config_restore_info *out);
int dwrt_config_restore_apply(const struct dwrt_config_restore_hooks *hooks,
                              struct dwrt_config_restore_info *out);
int dwrt_config_restore_confirm(struct dwrt_config_restore_info *out);
int dwrt_config_restore_rollback(const struct dwrt_config_restore_hooks *hooks,
                                 const char *reason,
                                 struct dwrt_config_restore_info *out);
int dwrt_config_restore_maybe_rollback(const struct dwrt_config_restore_hooks *hooks,
                                       int64_t now,
                                       struct dwrt_config_restore_info *out);
int dwrt_config_restore_is_armed(void);

#endif
