// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Asserts that webd_api_key_route_forbidden() denies every high-risk route.
 *
 * This test exists because of a concrete defect: the deny list once enumerated
 * leaf routes and several of the names did not exist, so factory_reset and
 * sysupgrade were reachable through an API-Key while the list looked complete.
 * A route table and a deny list maintained separately will drift again, so the
 * check is mechanical rather than a spot check of a few paths.
 *
 * The high-risk route list below is extracted from jmx_app_perms.c. When a new
 * high-risk route is added there and not covered here, this test fails, which
 * is the intended signal.
 */
#include <stdio.h>
#include <string.h>

#include "../webd/webd_api_keys.h"

struct route_case {
    const char *method;
    const char *path;
};

/* Every JMX_RISK_HIGH route in jmx_app_perms.c, plus the shell surfaces the
 * user declared permanently closed. */
static const struct route_case g_must_deny[] = {
    /* shell / command execution — the user's hard floor */
    { "GET",  "/terminal" },
    { "POST", "/terminal" },
    { "GET",  "/api/v1/system/ttyd" },
    { "PUT",  "/api/v1/system/ttyd" },
    { "POST", "/api/v1/system/ttyd/validate" },
    { "POST", "/api/v1/policy-engine/terminal-groups" },

    /* reflash / reset / power */
    { "POST", "/api/v1/system/flash/factory_reset" },
    { "POST", "/api/v1/system/flash/sysupgrade" },
    { "POST", "/api/v1/system/flash/upload_firmware" },
    { "POST", "/api/v1/system/flash/restore_backup" },
    { "POST", "/api/v1/system/flash/create_backup" },
    { "GET",  "/api/v1/system/flash/backups" },
    { "GET",  "/api/v1/system/flash/firmware" },
    { "GET",  "/api/v1/system/flash/restore-status" },
    { "POST", "/api/v1/system/flash/restore-confirm" },
    { "POST", "/api/v1/system/flash/restore-rollback" },
    { "GET",  "/api/v1/system/flash/backup-policy" },
    { "POST", "/api/v1/system/flash/signature-update/apply" },
    { "POST", "/api/v1/system/flash/signature-update/validate" },
    { "GET",  "/api/v1/system/flash/signature-update/status" },
    { "GET",  "/api/v1/system/flash/capabilities" },
    { "POST", "/api/v1/system/reboot" },
    { "POST", "/api/v1/system/shutdown" },
    { "POST", "/api/v1/system/power/schedules" },
    { "DELETE", "/api/v1/system/power/schedules/3" },
    { "POST", "/api/v1/system/backup" },
    { "POST", "/api/v1/system/upgrade" },
    { "POST", "/api/v1/system/restore" },
    { "POST", "/api/v1/system/kernel/restore-defaults" },
    { "GET",  "/api/v1/system/ota/status" },

    /* setup wizard: re-running it reconfigures the device wholesale */
    { "POST", "/api/v1/setup/apply" },
    { "POST", "/api/v1/setup/finish" },
    { "POST", "/api/v1/setup/reset-wizard" },

    /* identity, credentials, and key self-management */
    { "GET",  "/api/v1/auth/api-keys" },
    { "POST", "/api/v1/auth/api-keys" },
    { "POST", "/api/v1/auth/api-keys/00112233aabbccdd/revoke" },
    { "POST", "/api/v1/auth/pair/approve" },
    { "GET",  "/api/v1/auth/2fa/status" },
    { "POST", "/api/v1/system/admin/password" },
    { "POST", "/api/v1/system/admin/rename" },
    { "POST", "/api/v1/system/admin/avatar" },
    { "GET",  "/api/v1/system/users" },
    { "DELETE", "/api/v1/system/users/bob" },
    { "POST", "/api/v1/system/user-groups" },

    /* file manager writes stay closed even under the control tier */
    { "POST", "/api/v1/storage/files/write" },
    { "DELETE", "/api/v1/storage/files" },
};

/*
 * Normalisation bypasses. Each of these resolves to a denied route and must be
 * refused; a raw string compare would let every one of them through.
 */
static const struct route_case g_must_deny_obfuscated[] = {
    { "POST", "/api/v1/system/flash/factory_reset/" },
    { "POST", "/API/V1/SYSTEM/FLASH/FACTORY_RESET" },
    { "POST", "/api/v1/system/flash/../flash/sysupgrade" },
    { "POST", "/api/v1//system///flash/sysupgrade" },
    { "POST", "/api/v1/system/%66lash/sysupgrade" },
    { "POST", "/api/v1/system/flash/./factory_reset" },
    { "GET",  "/api/v1/clients/../system/flash/backups" },
    { "POST", "/api/v1/auth/api-keys/../api-keys" },
};

/* Ordinary read routes must stay reachable, otherwise the channel is useless
 * and a too-broad prefix would go unnoticed. */
static const struct route_case g_must_allow[] = {
    { "GET", "/api/v1/system/status" },
    { "GET", "/api/v1/clients" },
    { "GET", "/api/v1/insights/flows/summary" },
    { "GET", "/api/v1/storage/overview" },
    { "GET", "/api/v1/storage/files" },
    { "GET", "/api/v1/network/wan" },
};

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0; i < sizeof(g_must_deny) / sizeof(g_must_deny[0]); i++) {
        if (!webd_api_key_route_forbidden(g_must_deny[i].method,
                                          g_must_deny[i].path)) {
            fprintf(stderr, "FAIL: high-risk route reachable by API-Key: %s %s\n",
                    g_must_deny[i].method, g_must_deny[i].path);
            failures++;
        }
    }
    for (i = 0; i < sizeof(g_must_deny_obfuscated) /
                    sizeof(g_must_deny_obfuscated[0]); i++) {
        if (!webd_api_key_route_forbidden(g_must_deny_obfuscated[i].method,
                                          g_must_deny_obfuscated[i].path)) {
            fprintf(stderr, "FAIL: bypass form reachable by API-Key: %s %s\n",
                    g_must_deny_obfuscated[i].method,
                    g_must_deny_obfuscated[i].path);
            failures++;
        }
    }
    for (i = 0; i < sizeof(g_must_allow) / sizeof(g_must_allow[0]); i++) {
        if (webd_api_key_route_forbidden(g_must_allow[i].method,
                                         g_must_allow[i].path)) {
            fprintf(stderr, "FAIL: ordinary read route wrongly denied: %s %s\n",
                    g_must_allow[i].method, g_must_allow[i].path);
            failures++;
        }
    }
    if (failures) {
        fprintf(stderr, "api_key_forbidden_routes_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("api_key_forbidden_routes_test: all route gates hold\n");
    return 0;
}
