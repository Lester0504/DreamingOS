// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_SUPPORT_H
#define WEBD_SUPPORT_H
#include <json-c/json.h>
#include <sqlite3.h>
#ifndef SUPPORT_STATE_DIR
#define SUPPORT_STATE_DIR "/etc/dreamingwrt/support"
#endif
#define SUPPORT_DB_PATH SUPPORT_STATE_DIR "/feedback.db"
#define SUPPORT_CONFIG_PATH SUPPORT_STATE_DIR "/service.json"
#ifndef SUPPORT_IDENTITY_DIR
#define SUPPORT_IDENTITY_DIR "/etc/dreamingwrt/cloud"
#endif
struct support_config { char url[512]; char key_dir[512]; char db_path[512]; char proof_domain[64]; };
int support_config_load(struct support_config *config);
int support_config_load_file(struct support_config *config, const char *path);
int support_db_open(const char *path, sqlite3 **db);
int support_subject(sqlite3 *config_db, const char *username, char out[65]);
struct json_object *support_diagnostics(void);
struct json_object *support_handle(sqlite3 *db, const struct support_config *config,
    const char *subject, int can_write, const char *method, const char *path,
    struct json_object *query, struct json_object *body, int *status);
struct json_object *support_remote(const struct support_config *config, const char *subject,
    const char *method, const char *path, struct json_object *query, struct json_object *body, int *status);
int support_sync_step(const struct support_config *config);
#endif
