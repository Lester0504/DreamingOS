// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_COMMUNITY_H
#define WEBD_COMMUNITY_H
#include "webd_support.h"
#ifndef COMMUNITY_STATE_DIR
#define COMMUNITY_STATE_DIR "/etc/dreamingwrt/community"
#endif
#define COMMUNITY_DB_PATH COMMUNITY_STATE_DIR "/sessions.db"
#define COMMUNITY_CONFIG_PATH COMMUNITY_STATE_DIR "/service.json"
struct http_req;
int community_config_load(struct support_config *config);
int community_db_open(const char *path, sqlite3 **db);
struct json_object *community_handle(sqlite3 *db,const struct support_config *config,const char *subject,int writable,const char *method,const char *path,struct json_object *query,struct json_object *body,int *status);
void community_ws_session(int fd,const struct http_req *req,const char *device_id);
#endif
