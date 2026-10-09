// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_IPTV_H
#define DWRT_IPTV_H
#include <json-c/json.h>
#include <stddef.h>
#include <sqlite3.h>

struct iptv_error { int status; char code[64]; char field[64]; };
/* actor is resolved by the management permission gate, never by request JSON.
 * Media bearer tokens are independent, short-lived and channel-scoped. */
struct json_object *iptv_request(const char *method, const char *resource,
    struct json_object *body, const char *actor, struct iptv_error *error);
struct json_object *iptv_media_authorize(const char *token, const char *channel,
    struct iptv_error *error);
int iptv_media_read(const char *token, const char *channel, const char *name,
    char **data, size_t *length, const char **type, struct iptv_error *error);
void iptv_shutdown(void);
void iptv_tools_inspect(void);

/* Internal module boundary. No JSON input can select a DB or a filesystem path. */
const char *iptv_string(struct json_object *obj, const char *key);
int iptv_integer(struct json_object *obj, const char *key, int fallback);
struct json_object *iptv_fail(struct iptv_error *error, int status,
    const char *code, const char *field);
int iptv_id(char *out, size_t length);
sqlite3 *iptv_db(struct iptv_error *error);
struct json_object *iptv_record(sqlite3 *db, const char *kind, const char *id);
struct json_object *iptv_settings(sqlite3 *db);
struct json_object *iptv_runtime_state(const char *channel);
struct json_object *iptv_runtime_start(struct json_object *channel,
    struct json_object *settings, int manual, struct iptv_error *error);
struct json_object *iptv_runtime_stop(const char *channel, struct iptv_error *error);
struct json_object *iptv_runtime_probe(struct json_object *channel,
    struct iptv_error *error);
struct json_object *iptv_runtime_capabilities(void);
struct json_object *iptv_encoder_request(const char *method,const char *id,struct json_object *settings,struct iptv_error *error);
int iptv_encoder_validate(struct json_object *channel,struct iptv_error *error);
struct json_object *iptv_runtime_snapshot(struct json_object *channel,const char *operation,struct iptv_error *error);
int iptv_runtime_snapshot_read(const char *operation,char **data,size_t *length,struct iptv_error *error);
struct json_object *iptv_snapshot_read(sqlite3 *db,const char *channel,struct iptv_error *error);
void iptv_snapshot_remove(sqlite3 *db,const char *channel);
void iptv_runtime_hold(const char *channel);
int iptv_runtime_read(const char *channel, const char *name, char **data,
    size_t *length, const char **type, struct iptv_error *error);
/* Catalogue operations share validation and optimistic revisions. */
int iptv_valid_id(const char *id);
int iptv_revision(sqlite3 *db);
int iptv_channel_enabled(sqlite3 *db,struct json_object *channel);
struct json_object *iptv_list(sqlite3 *db,const char *kind,struct iptv_error *error);
int iptv_validate(sqlite3 *db,const char *kind,struct json_object *record,struct iptv_error *error);
struct json_object *iptv_remove(sqlite3 *db,const char *kind,const char *id,struct json_object *body,struct iptv_error *error);
struct json_object *iptv_save(sqlite3 *db,const char *kind,const char *id,struct json_object *body,int create,struct iptv_error *error);
struct json_object *iptv_catalog_request(sqlite3 *db,const char *method,const char *path,struct json_object *body,struct iptv_error *error);
struct json_object *iptv_runtime_pending(void);
int iptv_epg_start(struct iptv_error *error);
void iptv_epg_shutdown(void);
struct json_object *iptv_epg_request(sqlite3 *db,const char *method,const char *path,struct json_object *body,struct iptv_error *error);
int iptv_principal_exists(sqlite3 *db,const char *principal);
int iptv_view_ticket_valid(sqlite3 *db,const char *ticket,struct json_object *channel);
struct json_object *iptv_view_sessions(sqlite3 *db,const char *method,const char *path,struct json_object *body,struct iptv_error *error);
struct json_object *iptv_principals(sqlite3 *db,struct iptv_error *error);
struct json_object *iptv_preview_issue(sqlite3 *db,const char *id,const char *actor,struct iptv_error *error);
struct json_object *iptv_view_request(sqlite3 *db,const char *origin,const char *token,const char *path,struct json_object *body,int writing,struct iptv_error *error);
struct json_object *iptv_workbook_read(const char *base64,struct iptv_error *error);
struct json_object *iptv_workbook_write(sqlite3 *db,int template,struct iptv_error *error);
struct json_object *iptv_inputs(sqlite3 *db,struct iptv_error *error);
int iptv_access_validate(struct json_object *channel,struct iptv_error *error);
int iptv_access_available(sqlite3 *db);
int iptv_access_save(sqlite3 *db,struct json_object *channel,struct json_object *old,struct iptv_error *error);
int iptv_access_remove(sqlite3 *db,struct json_object *channel,struct iptv_error *error);
int iptv_access_resolve(sqlite3 *db,struct json_object *channel,char *out,size_t size,struct iptv_error *error);
int iptv_source_url(sqlite3 *db,struct json_object *channel,char *out,size_t size,int runtime,struct iptv_error *error);
struct json_object *iptv_jobs_request(sqlite3 *db,const char *method,const char *path,struct json_object *body,struct iptv_error *error);
int iptv_jobs_start(struct iptv_error *error);
void iptv_jobs_shutdown(void);
struct json_object *iptv_window_read(const char *directory,struct iptv_error *error);
int iptv_window_playlist(struct json_object *window,double from,int live_count,char **data,size_t *length,struct iptv_error *error);
struct json_object *iptv_runtime_window(const char *id,struct iptv_error *error);
struct json_object *iptv_runtime_capture_window(const char *id,struct iptv_error *error);
void iptv_runtime_capture_release(const char *id);
struct json_object *iptv_storage_preflight(struct json_object *settings);
int iptv_storage_root(struct json_object *settings,const char *key,const char *module,char *path,size_t size,struct iptv_error *error);
struct json_object *iptv_runtime_archive(const char *id,const char *input,const char *output,int verify,struct json_object *settings,struct iptv_error *error);
int iptv_recordings_start(struct iptv_error *error);
void iptv_recordings_shutdown(void);
struct json_object *iptv_recordings_request(sqlite3 *db,const char *method,const char *path,struct json_object *body,const char *actor,struct iptv_error *error);
int iptv_recording_open(sqlite3 *db,const char *channel,const char *name,struct iptv_error *error);
struct json_object *iptv_recording_info(const char *token,const char *channel,const char *name,struct iptv_error *error);
int iptv_recording_read(const char *token,const char *channel,const char *name,int64_t offset,size_t maximum,char **data,size_t *length,struct iptv_error *error);
#endif
