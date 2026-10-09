/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef WEBD_API_API_MAINTENANCE_INTERNAL_H
#define WEBD_API_API_MAINTENANCE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct http_req;
struct json_object;
struct uloop_timeout;

/* Entry points defined in api_maintenance.c and used from the main TU. */
struct json_object *webd_config_restore_control_response(const char *action,
                                                                int *http_status);
struct json_object *webd_config_backup_create_response(const char *owner_id,
                                                              int *http_status);
struct json_object *webd_backup_policy_get_response(int *http_status);
void webd_backup_schedule_timer_cb(struct uloop_timeout *timer);
struct json_object *webd_backup_policy_set_response(const char *owner_id,
                                                           struct json_object *body,
                                                           int *http_status);
struct json_object *webd_config_backup_list_response(const char *owner_id,
                                                            int *http_status);
int webd_network_csv_download_response(int fd, const struct http_req *req,
                                              int is_wan);
int webd_config_backup_download_response(int fd, const struct http_req *req,
                                                const char *owner_id,
                                                const char *upload_id);
int webd_storage_files_raw_response(int fd, const struct http_req *req);
struct json_object *webd_config_restore_stage_response(const char *owner_id,
                                                              struct json_object *body,
                                                              int *http_status);
struct json_object *webd_upload_begin_response(const char *owner_id,
                                                      struct json_object *body,
                                                      int *http_status);
struct json_object *webd_upload_chunk_response(const struct http_req *req,
                                                      const char *owner_id,
                                                      const char *upload_id,
                                                      int *http_status);
struct json_object *webd_upload_finalize_response(const char *owner_id,
                                                         const char *upload_id,
                                                         struct json_object *body,
                                                         int *http_status);
struct json_object *webd_signature_update_response(const char *owner_id,
                                                          struct json_object *body,
                                                          const char *action,
                                                          int *http_status);
struct json_object *webd_signature_update_status_response(int *http_status);
struct json_object *webd_firmware_verify_response(const char *owner_id,
                                                         struct json_object *body,
                                                         int *http_status);
struct json_object *webd_firmware_apply_response(const char *owner_id,
                                                        struct json_object *body,
                                                        int *http_status);
struct json_object *webd_firmware_status_response(const struct http_req *req,
                                                         const char *owner_id,
                                                         int *http_status);
struct json_object *webd_flash_capabilities_response(int *http_status);
struct json_object *webd_upload_get_response(const char *owner_id,
                                                    const char *upload_id,
                                                    int *http_status);
struct json_object *webd_upload_delete_response(const char *owner_id,
                                                       const char *upload_id,
                                                       int *http_status);
int webd_aegis_certificate_http_status(struct json_object *response);
void webd_aegis_certificate_download_response(int fd,
                                                      const struct http_req *req);

#endif /* WEBD_API_API_MAINTENANCE_INTERNAL_H */
