// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_CLOUD_DOMAIN_H
#define WEBD_API_CLOUD_DOMAIN_H

struct json_object;
struct uci_context;

/* Read only. Explicit paths/context let fixtures use a private directory.
 * rp_id must come from webd's live Passkey getter, not a second config reader. */
struct json_object *webd_cloud_domain_snapshot(struct uci_context *uci,
                                              const char *rp_id,
                                              const char *hosts_path,
                                              const char *certificate_path);

struct webd_cloud_domain_paths {
    const char *dhcp;
    const char *hosts;
    const char *backups;
};
/* Plan only the current configured domain/addresses. No caller-selected host. */
struct json_object *webd_cloud_domain_plan(struct json_object *snapshot,
    const char *mode, const struct webd_cloud_domain_paths *paths);
/* The caller serializes operations and performs reauthentication before apply.
 * Reload is injected so tests never operate the host's DNS service. */
struct json_object *webd_cloud_domain_apply(struct uci_context *uci,
    struct json_object *plan, const struct webd_cloud_domain_paths *paths,
    int (*reload)(void *), void *reload_context);
int webd_cloud_domain_write_atomic(const char *path, const char *data, unsigned mode);

#endif
