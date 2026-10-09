// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_FILE_SERVICES_H
#define DREAMINGWRT_STORAGE_FILE_SERVICES_H

#include <json-c/json.h>

struct json_object *jmx_file_services_get(void);
int jmx_file_service_bindings_watch(void);
int jmx_file_service_ftp_runtime(const char *action);
struct json_object *jmx_ftp_settings_set(struct json_object *req);
struct json_object *jmx_ftp_share_request(const char *method, const char *id, struct json_object *req);
struct json_object *jmx_file_service_accounts_request(const char *method, const char *id, struct json_object *req);
struct json_object *jmx_file_service_action(const char *service, struct json_object *req);
struct json_object *jmx_nfs_defaults_set(struct json_object *req);
struct json_object *jmx_samba_settings_set(struct json_object *req);
struct json_object *jmx_file_service_get(const char *service);

struct json_object *jmx_samba_share_upsert(const char *id,
                                            struct json_object *req);
struct json_object *jmx_samba_share_delete(const char *id,
                                            struct json_object *req);
struct json_object *jmx_nfs_export_upsert(const char *id,
                                          struct json_object *req);
struct json_object *jmx_nfs_export_delete(const char *id,
                                          struct json_object *req);

struct json_object *jmx_file_share_operation_request(const char *method, const char *id, struct json_object *req);

struct json_object *jmx_webdav_share_request(const char *method, const char *id, struct json_object *req);

#endif
