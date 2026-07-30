// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Permission layer for Mobile App API.
 */
#include <string.h>
#include "jmx_app_perms.h"

/* ── Route risk classification ── */

struct route_risk {
    const char *prefix;
    const char *methods;  /* comma-separated, "" = all */
    jmx_risk_t  risk;
};

static int method_matches(const char *method, const char *methods)
{
    if (!methods || !methods[0]) return 1;

    size_t method_len = strlen(method);
    const char *p = methods;

    while (*p) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (method_len == len && !strncmp(method, p, len)) return 1;
        p += len;
        if (*p == ',') p++;
    }

    return 0;
}

static int method_is_readonly(const char *method)
{
    return !strcmp(method, "GET") || !strcmp(method, "HEAD") || !strcmp(method, "OPTIONS");
}

static const struct route_risk g_route_risks[] = {
    /* Blocked — never from App/AI */
    { "/api/v1/system/upgrade",   "POST", JMX_RISK_BLOCKED },
    { "/api/v1/system/restore",   "POST", JMX_RISK_BLOCKED },

    /* High — owner only, requires local confirm */
    { "/api/v1/system/reboot",    "POST", JMX_RISK_HIGH },
    { "/api/v1/system/shutdown",  "POST", JMX_RISK_HIGH },
    { "/api/v1/system/power/schedules", "POST,PUT,DELETE", JMX_RISK_HIGH },
    { "/api/v1/system/power/schedules/", "POST,PUT,DELETE", JMX_RISK_HIGH },
    { "/api/v1/system/backup",    "POST", JMX_RISK_HIGH },
    { "/api/v1/system/admin/password", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/admin/rename",   "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/admin/avatar",   "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/ttyd",           "GET",      JMX_RISK_MEDIUM },
    { "/api/v1/system/ttyd/validate",  "POST",     JMX_RISK_MEDIUM },
    { "/api/v1/system/ttyd",           "PUT",      JMX_RISK_MEDIUM },
    { "/terminal",                     "GET,HEAD,POST", JMX_RISK_MEDIUM },
    { "/api/v1/auth/pair/approve",     "POST", JMX_RISK_HIGH },
    { "/api/v1/system/kernel/restore-defaults", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/advanced/cpu-interrupt",  "GET", JMX_RISK_LOW },
    { "/api/v1/system/advanced/cpu-interrupt",  "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/container_service/docker/image/", "POST,PUT,DELETE", JMX_RISK_HIGH },
    { "/api/v1/container_service/docker/jobs", "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/docker/jobs/", "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/docker/jobs/", "DELETE", JMX_RISK_HIGH },
    { "/api/v1/container_service/docker/network/", "DELETE", JMX_RISK_HIGH },
    { "/api/v1/container_service/docker/volume/", "DELETE", JMX_RISK_HIGH },
    { "/api/v1/container_service/docker/service/", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/container_service/docker/config", "POST,PUT,PATCH", JMX_RISK_HIGH },
    { "/api/v1/container_service/lxc/container/", "POST,PUT,PATCH,DELETE", JMX_RISK_HIGH },
    { "/api/v1/container_service/lxc/config", "POST,PUT,PATCH", JMX_RISK_HIGH },
    { "/api/v1/system/startup/rc-local",         "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/crontab/apply",            "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/mounts/save-point",        "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/mounts/delete-point",      "POST,PUT,DELETE", JMX_RISK_HIGH },
    { "/api/v1/system/mounts/unmount",           "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/mounts/discovery",         "GET", JMX_RISK_HIGH },
    { "/api/v1/system/mounts/generate-config",   "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/mounts/mount-connected",   "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/flash/restore_backup",     "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/flash/restore-status",     "GET", JMX_RISK_HIGH },
    { "/api/v1/system/flash/restore-confirm",    "POST", JMX_RISK_HIGH },
    { "/api/v1/system/flash/restore-rollback",   "POST", JMX_RISK_HIGH },
    { "/api/v1/system/flash/create_backup",      "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/flash/backups",            "", JMX_RISK_HIGH },
    { "/api/v1/system/flash/signature-update/validate", "POST", JMX_RISK_HIGH },
    { "/api/v1/system/flash/signature-update/apply",    "POST", JMX_RISK_HIGH },
    { "/api/v1/system/flash/signature-update/status",   "GET",  JMX_RISK_HIGH },
    { "/api/v1/system/flash/firmware",           "", JMX_RISK_HIGH },
    { "/api/v1/system/flash/upload_firmware",   "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/flash/sysupgrade",         "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/system/flash/factory_reset",      "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/setup/apply",      "POST", JMX_RISK_HIGH },
    { "/api/v1/setup/finish",     "POST", JMX_RISK_HIGH },
    { "/api/v1/setup/reset-wizard", "POST", JMX_RISK_HIGH },
    { "/api/v1/network/lans",     "POST,PUT,PATCH,DELETE", JMX_RISK_HIGH },
    { "/api/v1/network/lans/",    "DELETE", JMX_RISK_HIGH },
    { "/api/v1/network/gateway-ports/apply", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/network/gateway-shadow/apply", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/network/gateway-shadow/disable", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/network/gateway-shadow/pairing/approve", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/network/gateway-shadow/pairing/start", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/network/gateway-shadow/preflight", "POST,PUT", JMX_RISK_HIGH },
    { "/api/v1/network/gateway-shadow/save", "POST,PUT", JMX_RISK_HIGH },

    /* Medium — affects network but auto-rollbackable */
    { "/api/v1/network/wans",     "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/network/wans/",    "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/network/wans/",    "PATCH",  JMX_RISK_MEDIUM },
    { "/api/v1/network/wans/",    "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/network/work-mode","PUT",    JMX_RISK_MEDIUM },

    /* Network services writes require an administrator or owner. */
    { "/api/v1/services/dhcp",           "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/dns/wan-policy", "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/upnp/acl",       "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/upnp/mappings",  "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/upnp",           "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },

    { "/api/v1/services/dns",     "PATCH,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/services/dns/",    "POST,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/flow-control",     "PATCH,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flow-control/",    "POST",   JMX_RISK_MEDIUM },

    /* Per-client controls mutate tc/ifb runtime state and require admin. */
    { "/api/v1/client_control_rule", "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/client_protocol_control", "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },

    /* System write operations — medium unless explicitly high above */
    { "/api/v1/system/startup/service-action", "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/system/time-sync/",         "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/system/ssh/idle-timeout",   "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/container_service",          "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/docker",   "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/lxc",      "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/docker/container/", "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/docker/container/", "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/container_service/docker/container/", "DELETE", JMX_RISK_HIGH },
    { "/api/v1/container_service/docker/network/", "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/container_service/docker/volume/", "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/container_service/docker/service/", "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/docker/config", "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/lxc/container/", "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/lxc/config", "GET", JMX_RISK_LOW },
    { "/api/v1/container_service/lxc/templates", "GET", JMX_RISK_LOW },
    { "/api/v1/storage/overview",            "GET", JMX_RISK_LOW },
    { "/api/v1/storage/files",               "GET", JMX_RISK_LOW },
    { "/api/v1/storage/files/content",       "GET", JMX_RISK_LOW },
    { "/api/v1/storage/file-services",       "GET", JMX_RISK_LOW },
    { "/api/v1/storage/partitions",          "GET", JMX_RISK_LOW },
    { "/api/v1/storage/raid/scan",           "POST", JMX_RISK_MEDIUM },
    { "/api/v1/storage/raids",               "GET", JMX_RISK_LOW },
    { "/api/v1/storage/raid",                "GET", JMX_RISK_LOW },
    { "/api/v1/services/samba",              "GET", JMX_RISK_LOW },
    { "/api/v1/services/samba/shares",       "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/nfs",                "GET", JMX_RISK_LOW },
    { "/api/v1/services/nfs/exports",        "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/webdav",             "GET", JMX_RISK_LOW },
    { "/api/v1/services/ftp",                "GET", JMX_RISK_LOW },
    { "/api/v1/system/work-mode/preview",  "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/system/work-mode/apply",    "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/system/work-mode/rollback", "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/system/disabled-functions", "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/system/flash/preserve_config",   "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/system/users",          "POST,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/system/users/",         "POST,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/system/user-groups",    "POST,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/system/user-groups/",   "POST,PATCH,DELETE", JMX_RISK_MEDIUM },

    /* First-run wizard writes — staged until setup/apply. */
    { "/api/v1/setup/start",              "POST", JMX_RISK_MEDIUM },
    { "/api/v1/setup/save-device",        "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/setup/save-wan",           "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/setup/test-wan",           "POST", JMX_RISK_MEDIUM },
    { "/api/v1/setup/save-lan",           "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/setup/save-wifi",          "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/setup/support-bundle",     "POST", JMX_RISK_MEDIUM },
    { "/api/v1/setup/detect-wan/start",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/setup/detect_wan/start",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/setup/assist-mode",        "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/setup/security",           "GET", JMX_RISK_LOW },
    { "/api/v1/setup/security/ssh",       "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/setup/llm/status",         "GET", JMX_RISK_LOW },
    { "/api/v1/setup/llm",                "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/setup/oauth/providers",    "GET", JMX_RISK_LOW },
    { "/api/v1/setup/oauth/start",        "POST", JMX_RISK_MEDIUM },
    { "/api/v1/setup/app-pairing/cancel", "POST", JMX_RISK_MEDIUM },

    /* Firewall — medium risk (auto-rollbackable) */
    { "/api/v1/services/firewall",     "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/services/firewall/apply","POST", JMX_RISK_MEDIUM },
    { "/api/v1/firewall/geo-block/runtime", "GET", JMX_RISK_LOW },
    { "/api/v1/firewall/geo-block/preview", "POST", JMX_RISK_LOW },
    { "/api/v1/firewall/geo-block/apply", "POST", JMX_RISK_HIGH },
    { "/api/v1/firewall/geo-block/disable", "POST", JMX_RISK_HIGH },
    { "/api/v1/firewall/geo-block/rollback", "POST", JMX_RISK_HIGH },
    { "/api/v1/firewall/geo-block/validate", "POST", JMX_RISK_LOW },
    { "/api/v1/firewall/geo-block", "GET", JMX_RISK_LOW },
    { "/api/v1/firewall/geo-block", "POST,PUT", JMX_RISK_MEDIUM },

    /* VPN reads are observable; every write remains owner-only and fail-closed. */
    { "/api/v1/vpn",              "POST,PUT,PATCH,DELETE", JMX_RISK_HIGH },
    { "/api/v1/vpn",              "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/services/vpn",     "POST,PUT,PATCH,DELETE", JMX_RISK_HIGH },
    { "/api/v1/services/vpn/apply","POST", JMX_RISK_HIGH },
    { "/api/v1/services/vpn",     "GET,HEAD", JMX_RISK_LOW },

    /* RADIUS — medium */
    { "/api/v1/services/radius",  "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },

    /* Cellular — medium (slot/apn changes) */
    { "/api/v1/services/cellular",        "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/apply",  "POST", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/slots",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/slots/", "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/apn-profiles",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/cellular/apn-profiles/", "DELETE", JMX_RISK_MEDIUM },

    /* Wi-Fi writes change radio availability and may disconnect clients. */
    { "/api/v1/wifi/config",       "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/wifi/config/apply", "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/wifi/scan",         "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/wifi/scan/jobs",    "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/wifi/scan/jobs/",   "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/wifi/scan/jobs/",   "DELETE", JMX_RISK_MEDIUM },

    /* AC controller reads are observable; pairing-token lifecycle is admin-grade. */
    { "/api/v1/ac/status",         "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/ac/aps",            "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/ac/capabilities",   "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/ac/pairing-tokens", "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/ac/pairing-tokens", "POST,DELETE", JMX_RISK_MEDIUM },

    /* Advanced Routing — medium */
    { "/api/v1/routing",         "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/routing/apply",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/routing/tables", "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/routing/objects", "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/routing/cross-services", "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/routing/policy-rules/reorder", "POST", JMX_RISK_MEDIUM },

    /* DNS rules — medium */
    { "/api/v1/services/dns/rules",  "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/services/dns/rules/", "DELETE", JMX_RISK_MEDIUM },

    /* AI conversations — low (no network impact) */
    { "/api/v1/ai/chat",           "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/ai/chat/stream",    "POST", JMX_RISK_LOW },
    { "/api/v1/ai/attachments",    "POST", JMX_RISK_LOW },
    { "/api/v1/ai/attachments/",   "DELETE", JMX_RISK_LOW },
    { "/api/v1/ai/tool-resume",    "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/ai/responses/",     "DELETE", JMX_RISK_LOW },
    { "/api/v1/ai/provider/test",  "POST", JMX_RISK_MEDIUM },
    { "/api/v1/ai/oauth/providers", "GET", JMX_RISK_LOW },
    { "/api/v1/ai/oauth/status",    "GET", JMX_RISK_LOW },
    { "/api/v1/ai/oauth/start",     "POST", JMX_RISK_MEDIUM },
    { "/api/v1/ai/oauth/poll",      "POST", JMX_RISK_MEDIUM },
    { "/api/v1/ai/oauth/refresh",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/ai/oauth/disconnect", "POST,DELETE", JMX_RISK_HIGH },
    { "/api/v1/ai/models/sync",    "POST", JMX_RISK_MEDIUM },
    { "/api/v1/ai/logs/analyze",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/ai/conversations",  "POST,PUT,DELETE", JMX_RISK_LOW },
    { "/api/v1/ai/conversations/", "DELETE", JMX_RISK_LOW },
    { "/api/v1/ai/history",        "POST,PUT,DELETE", JMX_RISK_LOW },
    { "/api/v1/ai/history/",       "DELETE", JMX_RISK_LOW },

    /* AI control-plane writes can authorize or execute tools */
    { "/api/v1/ai/config",          "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/ai/tool-authorize",  "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/ai/tool-authorizations/", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/ai/tool-call",       "POST,PUT", JMX_RISK_MEDIUM },

    /* Auth session operations — low; device administration is medium */
    { "/api/v1/session",            "GET,DELETE", JMX_RISK_LOW },
    { "/api/v1/session/refresh",    "POST", JMX_RISK_LOW },
    { "/api/v1/auth/session",       "GET", JMX_RISK_LOW },
    { "/api/v1/auth/logout",        "POST", JMX_RISK_LOW },
    { "/api/v1/auth/pair/cancel",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/auth/2fa",           "GET", JMX_RISK_LOW },
    { "/api/v1/auth/2fa/status",    "GET", JMX_RISK_LOW },
    { "/api/v1/auth/2fa/prepare",   "POST", JMX_RISK_LOW },
    { "/api/v1/auth/2fa/enable",    "POST", JMX_RISK_MEDIUM },
    { "/api/v1/auth/2fa/disable",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/auth/security",      "GET", JMX_RISK_LOW },
    { "/api/v1/auth/security",      "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/auth/security/failures", "GET", JMX_RISK_MEDIUM },
    { "/api/v1/auth/security/failures/clear", "POST", JMX_RISK_MEDIUM },

    /* Logd — reads are low, collector/settings/event writes are admin-grade. */
    { "/api/v1/logd/status",        "GET", JMX_RISK_LOW },
    { "/api/v1/logd/settings",      "GET", JMX_RISK_LOW },
    { "/api/v1/logd/settings",      "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/logd/syslog/test",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/logd/collectors",    "GET", JMX_RISK_LOW },
    { "/api/v1/logd/collectors",    "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/logd/collect-now",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/logd/events/query",  "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/logd/events/clear",  "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/logd/events",        "GET", JMX_RISK_LOW },
    { "/api/v1/logd/events",        "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/logs/search",        "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/logs/summary",       "GET", JMX_RISK_LOW },
    { "/api/v1/logs/count",         "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/logs/filter-data",   "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/logs/export",        "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/logs/mark-read",     "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/logs/ack",           "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/logs/download",      "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/logs/settings",      "GET", JMX_RISK_LOW },
    { "/api/v1/logs/settings",      "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/logs/syslog/test",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/logs/syslog/queue",  "GET", JMX_RISK_LOW },
    { "/api/v1/logs/syslog/queue/flush", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/logs/syslog/queue/clear", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/logs/syslog/certs",  "GET", JMX_RISK_LOW },
    { "/api/v1/logs/syslog/certs",  "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/logs/syslog/certs/delete", "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/logs/syslog/presets", "GET", JMX_RISK_LOW },
    { "/api/v1/logs/syslog/presets/preview", "POST,PUT", JMX_RISK_LOW },

    /* Notifyd — reads are low; channel/route/outbox delivery writes are admin-grade. */
    { "/api/v1/notifyd/status",        "GET", JMX_RISK_LOW },
    { "/api/v1/notifyd/events",        "GET", JMX_RISK_LOW },
    { "/api/v1/notifyd/settings",      "GET", JMX_RISK_LOW },
    { "/api/v1/notifyd/settings",      "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/notifyd/channels",      "GET", JMX_RISK_LOW },
    { "/api/v1/notifyd/channels",      "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/notifyd/routes",        "GET", JMX_RISK_LOW },
    { "/api/v1/notifyd/routes",        "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/notifyd/enqueue",       "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/notifyd/test-send",     "POST", JMX_RISK_MEDIUM },
    { "/api/v1/notifyd/outbox/query",  "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/notifyd/outbox/retry",  "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/notifyd/outbox",        "GET", JMX_RISK_LOW },
    { "/api/v1/notifyd/deliver-due",   "POST", JMX_RISK_MEDIUM },

    /* User authentication reads are low; package/account/voucher writes are admin-grade. */
    { "/api/v1/authentication",                    "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/web",                "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/web",                "PUT", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/web/portal",         "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/web/portal",         "PUT", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/web/access-rules",   "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/web/access-rules",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/web/access-rules/",  "PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/online-users",       "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/accounts",           "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/accounts",           "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/accounts/bulk",      "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/accounts/import",    "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/accounts/password-policy", "PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/accounts/",          "PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/ledger",             "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/ledger",             "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/ledger/",            "PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/packages",           "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/packages",           "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/packages/",          "PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/vouchers",           "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/vouchers",           "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/vouchers/expired",   "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/vouchers/",          "PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/delegated-services", "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/delegated-services", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/delegated-services/import", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/delegated-services/", "PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/notifications",      "GET", JMX_RISK_LOW },
    { "/api/v1/authentication/notifications/preview", "POST", JMX_RISK_LOW },
    { "/api/v1/authentication/notifications/realtime", "PUT", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/notifications/expiry",   "PUT", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/notifications/expired",  "PUT", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/notifications/periodic", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/authentication/notifications/periodic/", "PUT,DELETE", JMX_RISK_MEDIUM },

    /* Aegisxd — CyberSecure-like reads are low; feed/policy execution changes are admin-grade. */
    { "/api/v1/aegis/status",                "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/feeds",                 "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/feed-status",           "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/feed_status",           "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/feed-update/status",    "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/feed_update_status",    "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/feed-import/status",    "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/feed_import_status",    "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/categories",            "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/signature-categories",  "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/signatures/categories", "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/runtime",               "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/events",                "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/events/recent",         "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/stats",                 "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/health",                "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/identification",        "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/identification",        "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/traffic-history/clear", "POST", JMX_RISK_HIGH },
    { "/api/v1/aegis/certificates/inspection-ca/generate", "POST", JMX_RISK_HIGH },
    { "/api/v1/aegis/certificates/inspection-ca/rotate",   "POST", JMX_RISK_HIGH },
    { "/api/v1/aegis/certificates/inspection-ca/revoke",   "POST", JMX_RISK_HIGH },
    { "/api/v1/aegis/certificates/inspection-ca/distributions", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/certificates/inspection-ca",          "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/aegis/app-blocks/validate",   "POST", JMX_RISK_LOW },
    { "/api/v1/aegis/app-blocks",            "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/app-blocks",            "POST", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/app-blocks/",           "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/app-blocks/",           "PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/geo",                   "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/geo/preview",           "POST", JMX_RISK_LOW },
    { "/api/v1/aegis/geo/apply",             "POST", JMX_RISK_HIGH },
    { "/api/v1/aegis/geo/disable",           "POST", JMX_RISK_HIGH },
    { "/api/v1/aegis/geo/rollback",          "POST", JMX_RISK_HIGH },
    { "/api/v1/aegis/honeypot",              "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/honeypot/events",       "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/honeypot/validate",     "POST", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/honeypot/config",       "PUT", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/honeypot/config/",      "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/feed-update/start",     "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/feed_update_start",     "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/feeds/update",          "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/feed-import/start",     "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/compile",               "POST", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/apply",                 "POST", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/settings",              "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/policies",              "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/policies",              "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/signature-policy",       "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/signature-policy",      "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/signatures/policies",   "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/signatures/policies",   "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/content-policy",        "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/content-policy",        "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/content-policy/validate","POST", JMX_RISK_LOW },
    { "/api/v1/aegis/content-policy/pcdn",   "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/content-policy/pcdn",   "PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/content-policy/pcdn/validate", "POST", JMX_RISK_LOW },
    { "/api/v1/aegis/content-policy/pcdn/sync", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/content-policy/",       "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/content-policy/",       "PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/domain-overrides",      "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/domain-overrides",      "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/domain-overrides/",     "GET", JMX_RISK_LOW },
    { "/api/v1/aegis/domain-overrides/",     "PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/domain-overrides/delete","POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/signatures/suppress",   "POST", JMX_RISK_MEDIUM },
    { "/api/v1/aegis/signatures/unsuppress", "POST", JMX_RISK_MEDIUM },

    /* Insights / Flows — query-only BFF; POST is UniFi-style search, not mutation. */
    { "/api/v1/insights/flows/summary",       "GET", JMX_RISK_LOW },
    { "/api/v1/insights/flows/filter-data",   "GET", JMX_RISK_LOW },
    { "/api/v1/insights/flows/current",       "GET,POST", JMX_RISK_LOW },
    { "/api/v1/insights/flows/history",       "GET,POST", JMX_RISK_LOW },
    { "/api/v1/insights/flows/geo",           "GET", JMX_RISK_LOW },
    { "/api/v1/insights/flows",               "GET,POST,PUT", JMX_RISK_LOW },
    { "/api/v1/insights/map/config",          "GET", JMX_RISK_LOW },
    { "/api/v1/insights/cybersecure/status",  "GET", JMX_RISK_LOW },
    { "/v2/api/site/",                         "GET,POST,PUT", JMX_RISK_LOW },

    /* A/B OTA: webd authenticates; dreamingwrt.otad owns verification and slot writes. */
    { "/api/v1/system/ota/status",             "GET", JMX_RISK_LOW },
    { "/api/v1/system/ota/verify",             "POST", JMX_RISK_HIGH },
    { "/api/v1/system/ota/apply",              "POST", JMX_RISK_HIGH },
    { "/api/v1/system/ota/rollback",           "POST", JMX_RISK_HIGH },
    { "/api/v1/system/ota/confirm-boot",       "POST", JMX_RISK_HIGH },

    /* Opaque browser staging contains firmware, signatures, or config secrets. */
    { "/api/v1/uploads",                         "", JMX_RISK_HIGH },

    /* Topology side-panel helpers — read-only UniFi-style details. */
    { "/api/v1/topology/node/ports/batch/preview", "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/topology/node/ports/batch/apply",   "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/topology/node/ports/preview",   "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/topology/node/ports/apply",     "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/network/gateway-ports/preview", "POST,PUT", JMX_RISK_LOW },
    { "/api/v1/network/gateway-ports",         "GET", JMX_RISK_LOW },
    { "/api/v1/network/gateway-shadow",        "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/network/gateway-shadow/status", "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/topology/node/ports",           "GET,POST", JMX_RISK_LOW },
    { "/api/v1/network/settings-overview",     "GET", JMX_RISK_LOW },
    { "/api/v1/network/ports/preferences",     "GET,PUT,PATCH", JMX_RISK_LOW },
    { "/api/v1/topology/capture/status",       "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/topology/capture/download",     "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/topology/capture/start",        "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/topology/capture/stop",         "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/topology/capture",              "GET,HEAD", JMX_RISK_LOW },
    { "/api/v1/topology/capture",              "POST,PUT", JMX_RISK_MEDIUM },

    /* On-demand network toolkit */
    { "/api/v1/toolkit",                       "GET", JMX_RISK_LOW },
    { "/api/v1/toolkit/router-check",          "GET,POST", JMX_RISK_LOW },
    { "/api/v1/toolkit/port-mirror",           "GET", JMX_RISK_LOW },
    { "/api/v1/toolkit/port-mirror",           "POST,PUT,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/toolkit/port-mirror/",          "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/toolkit/ddns",                  "GET", JMX_RISK_LOW },
    { "/api/v1/toolkit/ddns",                  "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/toolkit/ddns/",                 "DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/toolkit/ddns/update",           "POST", JMX_RISK_MEDIUM },
    { "/api/v1/toolkit/wake-on-lan",           "POST", JMX_RISK_LOW },
    { "/api/v1/toolkit/throughput",            "POST", JMX_RISK_LOW },
    { "/api/v1/toolkit/throughput/status",     "GET", JMX_RISK_LOW },
    { "/api/v1/toolkit/throughput/stop",       "POST", JMX_RISK_LOW },

    /* Terminal groups are persistent policy objects; writes are admin-grade. */
    { "/api/v1/policy-engine/terminal-groups",  "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/terminal-groups",  "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },

    /* Policy runtime and Policy Engine table/catalog aggregations. */
    { "/api/v1/route_status",                       "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/policy-table/preview", "GET,POST,PUT,PATCH", JMX_RISK_LOW },
    { "/api/v1/policy-engine/policy-table/",        "GET,POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/policy-engine/policy-table",         "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/policy-table",         "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/policy-engine/catalog",              "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/zones",                "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/zones",                "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/policy-engine/zones/",               "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/zones/",               "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/policy-engine/zone-matrix",          "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/objects",              "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/objects",              "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/policy-engine/objects/",             "GET", JMX_RISK_LOW },
    { "/api/v1/policy-engine/objects/",             "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM },

    /* Flowd — GeoIP/country-route reads are low; policy/source writes are network-affecting. */
    { "/api/v1/flowd/status",                 "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/settings",               "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/settings",               "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/geoip/sources",          "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/geoip/sources",          "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/geoip/sources/delete",   "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/geoip/import/status",    "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/geoip/import",           "POST", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/country-policies",       "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/country-policies",       "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/country-policies/delete","POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/country-sets/generate",  "POST", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/objects",                "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/objects",                "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/objects/delete",         "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/custom-protocols",       "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/custom-protocols",       "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/custom-protocols/delete","POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/route-groups",           "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/route-groups",           "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/route-groups/delete",    "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/wan-capacity",           "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/wan-capacity",           "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/wan-capacity/delete",    "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/wan-health",             "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/wan-health",             "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/wan-health/delete",      "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/split-rules",            "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/split-rules",            "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/split-rules/delete",     "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/domain-rules",           "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/domain-rules",           "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/domain-rules/delete",    "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/qos/settings",           "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/qos/settings",           "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/qos/classes",            "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/qos/classes",            "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/qos/classes/delete",     "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/qos/rules",              "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/qos/rules",              "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/qos/rules/delete",       "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/smart-qos/categories",   "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/smart-qos/categories",   "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/smart-qos/categories/delete","POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/quota-rules",            "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/quota-rules",            "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/quota-rules/delete",     "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/conn-limit-rules",       "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/conn-limit-rules",       "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/conn-limit-rules/delete","POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/app-rules",              "GET", JMX_RISK_LOW },
    { "/api/v1/flowd/app-rules",              "POST,PUT,PATCH", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/app-rules/delete",       "POST,PUT", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/compile",                "POST", JMX_RISK_MEDIUM },
    { "/api/v1/flowd/apply-jobs",             "GET,POST,PUT", JMX_RISK_LOW },
    { "/api/v1/flowd/runtime",                "GET,POST,PUT", JMX_RISK_LOW },

    { "/api/v1/auth/devices",       "GET", JMX_RISK_LOW },
    { "/api/v1/auth/devices/",      "PATCH,DELETE", JMX_RISK_MEDIUM },
    { "/api/v1/realtime/ws",        "GET", JMX_RISK_LOW },
    { "/api/v1/topology",           "GET", JMX_RISK_LOW },
    { "/api/v1/topology/flow",      "GET", JMX_RISK_LOW },
    { "/api/v1/topology/infrastructure", "GET", JMX_RISK_LOW },
    { "/api/v1/topology/infrastructure/history/", "GET", JMX_RISK_LOW },
    { "/api/v1/port-manager/status", "GET", JMX_RISK_LOW },
    { "/api/v1/port-manager/transactions", "GET", JMX_RISK_LOW },
    { "/api/v1/port-manager/transactions/", "GET", JMX_RISK_LOW },
    { "/api/v1/port-manager/transactions/", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/topology/port-manager/status", "GET", JMX_RISK_LOW },
    { "/api/v1/topology/port-manager/transactions", "GET", JMX_RISK_LOW },
    { "/api/v1/topology/port-manager/transactions/", "GET", JMX_RISK_LOW },
    { "/api/v1/topology/port-manager/transactions/", "POST", JMX_RISK_MEDIUM },
    { "/api/v1/setup/status",       "GET", JMX_RISK_LOW },
    { "/api/v1/setup/progress",     "GET", JMX_RISK_LOW },
    { "/api/v1/setup/detect-wan/status", "GET", JMX_RISK_LOW },
    { "/api/v1/setup/detect_wan/status", "GET", JMX_RISK_LOW },

    { "/api/v1/config/apply",     "POST",   JMX_RISK_MEDIUM },
    { "/api/v1/config/rollback",  "POST",   JMX_RISK_MEDIUM },

    /* Native plugins apply their own scoped RBAC after authentication. */
    { "/api/v1/plugins/native/dreamingproxy", "GET,HEAD,POST,PUT,PATCH,DELETE", JMX_RISK_LOW },

    /* End of explicit table; unknown writes fall back to medium below. */
    { NULL, NULL, JMX_RISK_LOW }
};

jmx_risk_t jmx_perm_route_risk(const char *method, const char *path)
{
    const struct route_risk *r;

    if (!method || !path || !method[0] || !path[0]) return JMX_RISK_BLOCKED;

    for (r = g_route_risks; r->prefix; r++) {
        if (strncmp(path, r->prefix, strlen(r->prefix)) != 0) continue;
        if (!method_matches(method, r->methods)) continue;
        return r->risk;
    }

    return method_is_readonly(method) ? JMX_RISK_LOW : JMX_RISK_MEDIUM;
}

/* ── Permission check ── */

int jmx_perm_check(jmx_role_t role, jmx_risk_t risk)
{
    if (risk == JMX_RISK_BLOCKED) return 0;

    if (role == JMX_ROLE_AI_AGENT)
        return (risk == JMX_RISK_LOW) ? 1 : 0;

    if (role == JMX_ROLE_VIEWER)
        return (risk == JMX_RISK_LOW) ? 1 : 0;

    if (risk == JMX_RISK_HIGH)
        return (role == JMX_ROLE_OWNER) ? 1 : 0;

    if (risk == JMX_RISK_MEDIUM)
        return (role == JMX_ROLE_ADMIN || role == JMX_ROLE_OWNER) ? 1 : 0;

    /* low — everyone except viewer/ai-agent checked above */
    return 1;
}

/* ── Role parsing ── */

jmx_role_t jmx_perm_parse_role(const char *s)
{
    if (!s) return JMX_ROLE_OPERATOR;
    if (!strcmp(s, "owner"))    return JMX_ROLE_OWNER;
    if (!strcmp(s, "admin"))    return JMX_ROLE_ADMIN;
    if (!strcmp(s, "user"))     return JMX_ROLE_OPERATOR;
    if (!strcmp(s, "operator")) return JMX_ROLE_OPERATOR;
    if (!strcmp(s, "viewer"))   return JMX_ROLE_VIEWER;
    if (!strcmp(s, "ai-agent")) return JMX_ROLE_AI_AGENT;
    return JMX_ROLE_OPERATOR;
}

const char *jmx_perm_risk_str(jmx_risk_t r)
{
    switch (r) {
    case JMX_RISK_LOW:     return "low";
    case JMX_RISK_MEDIUM:  return "medium";
    case JMX_RISK_HIGH:    return "high";
    case JMX_RISK_BLOCKED: return "blocked";
    }
    return "low";
}
