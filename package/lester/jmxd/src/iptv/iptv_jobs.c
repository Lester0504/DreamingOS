// SPDX-License-Identifier: GPL-2.0-or-later
/* Explicit one-shot network operations. One persistent worker, bounded address
 * expansion and ffprobe admission through the same media budget as playback. */
#define _GNU_SOURCE
#include "iptv.h"
#include <curl/curl.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SCAN_LIMIT 128
#define PLAYLIST_LIMIT (512 * 1024)
static pthread_t worker_thread;
static atomic_int stopping;
static int started;
static void str(struct json_object *o, const char *k, const char *v)
{ json_object_object_add(o, k, json_object_new_string(v ? v : "")); }
static void bindstr(sqlite3_stmt *s, int n, const char *v)
{ sqlite3_bind_text(s, n, v, -1, SQLITE_TRANSIENT); }
static struct json_object *read_job(sqlite3 *db, const char *id)
{
    sqlite3_stmt *s = NULL; struct json_object *o = NULL;
    if (sqlite3_prepare_v2(db, "SELECT id,kind,state,payload,result,error,created_at,updated_at,cancel FROM iptv_job WHERE id=?", -1, &s, NULL) == SQLITE_OK) {
        bindstr(s, 1, id);
        if (sqlite3_step(s) == SQLITE_ROW) {
            o = json_object_new_object();
            const char *keys[] = {"id","kind","state","payload","result","error","created_at","updated_at","cancel"};
            for (int i = 0; i < 9; i++) json_object_object_add(o, keys[i],
                i > 5 ? json_object_new_int64(sqlite3_column_int64(s, i)) :
                i == 3 || i == 4 ? json_tokener_parse((const char *)sqlite3_column_text(s, i)) :
                json_object_new_string((const char *)sqlite3_column_text(s, i)));
        }
    }
    sqlite3_finalize(s); return o;
}
static int cancelled(sqlite3 *db, const char *id)
{
    if (atomic_load(&stopping)) return 1;
    struct json_object *j = read_job(db, id);
    int yes = !j || iptv_integer(j, "cancel", 0);
    if (j) json_object_put(j); return yes;
}
static int update(sqlite3 *db, const char *id, const char *state,
                  struct json_object *result, const char *error)
{
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db, "UPDATE iptv_job SET state=?,result=?,error=?,updated_at=unixepoch() WHERE id=?", -1, &s, NULL);
    if (rc == SQLITE_OK) {
        bindstr(s, 1, state); bindstr(s, 2, result ? json_object_to_json_string(result) : "{}");
        bindstr(s, 3, error); bindstr(s, 4, id); rc = sqlite3_step(s);
    }
    sqlite3_finalize(s); return rc == SQLITE_DONE ? 0 : -1;
}
static int expand(const char *text, struct json_object *urls, int depth)
{
    if (depth > 8 || strlen(text) > 2048) return -1;
    const char *open = strchr(text, '[');
    if (!open) {
        if (strchr(text, ']') || json_object_array_length(urls) >= SCAN_LIMIT) return -1;
        json_object_array_add(urls, json_object_new_string(text)); return 0;
    }
    unsigned from, to; int consumed = 0;
    if (sscanf(open, "[%u-%u]%n", &from, &to, &consumed) != 2 || !consumed ||
        from > to || to > 65535 || to - from >= SCAN_LIMIT) return -1;
    for (unsigned n = from; n <= to; n++) {
        char value[2049];
        if (snprintf(value, sizeof(value), "%.*s%u%s", (int)(open - text), text, n, open + consumed) >= (int)sizeof(value) ||
            expand(value, urls, depth + 1)) return -1;
    }
    return 0;
}
static struct json_object *scan_preview(sqlite3 *db, struct json_object *body, struct iptv_error *e)
{
    struct json_object *urls = json_object_new_array();
    if (expand(iptv_string(body, "template"), urls, 0)) {
        json_object_put(urls); return iptv_fail(e, 400, "scan_template_invalid_or_limit", "template");
    }
    int timeout = iptv_integer(body, "timeout_seconds", 10);
    if (timeout < 2 || timeout > 30 || iptv_integer(body, "concurrency", 1) != 1) {
        json_object_put(urls); return iptv_fail(e, 400, "scan_budget_invalid", "timeout_seconds");
    }
    for (size_t i = 0; i < json_object_array_length(urls); i++) {
        struct json_object *c = json_object_new_object(); char resolved[2304];
        str(c, "source_url", json_object_get_string(json_object_array_get_idx(urls, i)));
        str(c, "mode", "managed"); str(c, "input_id", iptv_string(body, "input_id"));
        int rc = iptv_source_url(db, c, resolved, sizeof(resolved), 0, e); json_object_put(c);
        if (rc) {json_object_put(urls); return NULL;}
    }
    struct json_object *o = json_object_new_object(); json_object_object_add(o, "urls", urls);
    str(o, "input_id", iptv_string(body, "input_id")); str(o, "template", iptv_string(body, "template"));
    json_object_object_add(o, "count", json_object_new_int(json_object_array_length(urls)));
    json_object_object_add(o, "timeout_seconds", json_object_new_int(timeout));
    json_object_object_add(o, "concurrency", json_object_new_int(1)); return o;
}
struct fetch_context { sqlite3 *db; const char *id; char *text; size_t size; };
static size_t collect(char *data, size_t n, size_t size, void *opaque)
{
    struct fetch_context *c = opaque; size_t bytes = n * size;
    if (bytes > PLAYLIST_LIMIT - c->size) return 0;
    char *next = realloc(c->text, c->size + bytes + 1); if (!next) return 0;
    c->text = next; memcpy(next + c->size, data, bytes); c->size += bytes; next[c->size] = 0; return bytes;
}
static int progress(void *opaque, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d)
{
    (void)a; (void)b; (void)c; (void)d;
    struct fetch_context *f = opaque; return cancelled(f->db, f->id);
}
static void fetch_list(sqlite3 *db, const char *id, struct json_object *payload)
{
    struct fetch_context ctx = {.db = db, .id = id};
    CURL *c = curl_easy_init(); long status = 0; CURLcode code = CURLE_FAILED_INIT;
    if (c) {
        curl_easy_setopt(c, CURLOPT_URL, iptv_string(payload, "url"));
        curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
        curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L); curl_easy_setopt(c, CURLOPT_MAXREDIRS, 3L);
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L); curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L); curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, collect);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx); curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, progress); curl_easy_setopt(c, CURLOPT_XFERINFODATA, &ctx);
        curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
        code = curl_easy_perform(c); curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status); curl_easy_cleanup(c);
    }
    struct json_object *result = NULL; struct iptv_error e = {0};
    if (!code && status >= 200 && status < 300 && ctx.size && !memchr(ctx.text, 0, ctx.size)) {
        struct json_object *body = json_object_new_object();
        str(body, "text", ctx.text); str(body, "format", iptv_string(payload, "format"));
        result = iptv_catalog_request(db, "POST", "imports/preview", body, &e);
        if (result) str(result, "text", ctx.text);
        json_object_put(body);
    }
    int stop = cancelled(db, id);
    update(db, id, stop ? "cancelled" : result ? "complete" : "failed", result,
           stop ? "operation_cancelled" : result ? "" : *e.code ? e.code : "playlist_fetch_failed");
    if (result) json_object_put(result); free(ctx.text);
}
static void scan(sqlite3 *db, const char *id, struct json_object *payload)
{
    struct json_object *urls = NULL, *result = json_object_new_object(), *rows = json_object_new_array();
    json_object_object_get_ex(payload, "urls", &urls); json_object_object_add(result, "rows", rows);
    for (size_t i = 0; i < json_object_array_length(urls) && !cancelled(db, id); i++) {
        char probe_id[97]; snprintf(probe_id, sizeof(probe_id), "scan-%s-%zu", id, i);
        struct json_object *channel = json_object_new_object(), *row = json_object_new_object();
        const char *url = json_object_get_string(json_object_array_get_idx(urls, i));
        str(channel, "id", probe_id); str(channel, "mode", "managed"); str(channel, "source_url", url);
        str(channel, "input_id", iptv_string(payload, "input_id"));
        json_object_object_add(channel, "probe_seconds", json_object_new_int(iptv_integer(payload, "timeout_seconds", 10)));
        struct iptv_error e = {0}; struct json_object *state = iptv_runtime_probe(channel, &e);
        json_object_put(channel);
        json_object_object_add(row, "index", json_object_new_int(i)); str(row, "source_url", url);
        if (state) {
            json_object_put(state);
            for (;;) {
                state = iptv_runtime_state(probe_id);
                if (strcmp(iptv_string(state, "state"), "probing") || cancelled(db, id)) break;
                json_object_put(state); usleep(200000);
            }
            str(row, "state", cancelled(db, id) ? "cancelled" : !strcmp(iptv_string(state, "state"), "probe_complete") ? "found" : "failed");
            struct json_object *probe = NULL;
            if (json_object_object_get_ex(state, "probe", &probe)) json_object_object_add(row, "probe", json_object_get(probe));
            str(row, "error", iptv_string(state, "error")); json_object_put(state);
            state = iptv_runtime_stop(probe_id, &e); if (state) json_object_put(state);
        } else {str(row, "state", "failed"); str(row, "error", e.code);}
        json_object_array_add(rows, row);
        json_object_object_add(result, "completed", json_object_new_int(i + 1));
        update(db, id, "running", result, "");
    }
    int stop = cancelled(db, id);
    update(db, id, stop ? "cancelled" : "complete", result, stop ? "operation_cancelled" : "");
    json_object_put(result);
}
struct json_object *iptv_snapshot_read(sqlite3 *db,const char *channel,struct iptv_error *e)
{
    sqlite3_stmt *stmt=NULL;struct json_object *result=json_object_new_object();
    str(result,"state","absent");str(result,"mime_type","image/jpeg");
    if(sqlite3_prepare_v2(db,"SELECT path,device,inode,bytes,captured_at FROM iptv_snapshot WHERE channel=?",-1,&stmt,NULL)!=SQLITE_OK){json_object_put(result);return iptv_fail(e,503,"job_store_failed","");}
    bindstr(stmt,1,channel);
    if(sqlite3_step(stmt)==SQLITE_ROW){
        int fd=open((const char*)sqlite3_column_text(stmt,0),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat st;
        sqlite3_int64 length=sqlite3_column_int64(stmt,3);int valid=fd>=0&&!fstat(fd,&st)&&S_ISREG(st.st_mode)&&
            st.st_dev==(dev_t)sqlite3_column_int64(stmt,1)&&st.st_ino==(ino_t)sqlite3_column_int64(stmt,2)&&
            length>0&&length<=512*1024&&st.st_size==length;
        unsigned char *raw=valid?malloc((size_t)length):NULL;size_t got=0;
        if(raw)while(got<(size_t)length){ssize_t n=read(fd,raw+got,(size_t)length-got);if(n<=0)break;got+=(size_t)n;}
        if(raw&&got==(size_t)length){
            unsigned char *encoded=malloc(4*((got+2)/3)+1);
            if(encoded){EVP_EncodeBlock(encoded,raw,(int)got);str(result,"base64",(char*)encoded);free(encoded);str(result,"state","available");}
            else str(result,"state","unavailable");
        }else str(result,"state","unavailable");
        free(raw);json_object_object_add(result,"captured_at",json_object_new_int64(sqlite3_column_int64(stmt,4)));
        if(fd>=0)close(fd);
    }
    sqlite3_finalize(stmt);stmt=NULL;
    if(sqlite3_prepare_v2(db,"SELECT id FROM iptv_job WHERE kind='snapshot' AND json_extract(payload,'$.channel_id')=? ORDER BY created_at DESC,rowid DESC LIMIT 1",-1,&stmt,NULL)==SQLITE_OK){
        bindstr(stmt,1,channel);if(sqlite3_step(stmt)==SQLITE_ROW)json_object_object_add(result,"last_attempt",read_job(db,(const char*)sqlite3_column_text(stmt,0)));
    }
    sqlite3_finalize(stmt);return result;
}
void iptv_snapshot_remove(sqlite3 *db,const char *channel)
{
    sqlite3_stmt *stmt=NULL;char path[PATH_MAX]="";
    if(sqlite3_prepare_v2(db,"SELECT path FROM iptv_snapshot WHERE channel=?",-1,&stmt,NULL)==SQLITE_OK){bindstr(stmt,1,channel);if(sqlite3_step(stmt)==SQLITE_ROW)snprintf(path,sizeof(path),"%s",sqlite3_column_text(stmt,0));}
    sqlite3_finalize(stmt);stmt=NULL;
    if(sqlite3_prepare_v2(db,"DELETE FROM iptv_snapshot WHERE channel=?",-1,&stmt,NULL)==SQLITE_OK){bindstr(stmt,1,channel);if(sqlite3_step(stmt)==SQLITE_DONE&&*path)unlink(path);}
    sqlite3_finalize(stmt);
}
static int save_snapshot(sqlite3 *db,const char *channel,int revision,struct json_object *cfg,const char *data,size_t length,struct iptv_error *e)
{
    char root[PATH_MAX],serial[49],path[PATH_MAX],old[PATH_MAX]="";
    if(iptv_storage_root(cfg,"cache_path",".dreamingwrt-iptv-snapshots",root,sizeof(root),e)||iptv_id(serial,sizeof(serial)))return -1;
    if(snprintf(path,sizeof(path),"%s/%s.jpg",root,serial)>=(int)sizeof(path))return -1;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0)return iptv_fail(e,507,"storage_not_writable",""),-1;
    size_t written=0;while(written<length){ssize_t n=write(fd,data+written,length-written);if(n<=0)break;written+=(size_t)n;}
    struct stat st;int valid=written==length&&!fsync(fd)&&!fstat(fd,&st);close(fd);
    if(!valid){unlink(path);return iptv_fail(e,507,"storage_not_writable",""),-1;}
    sqlite3_stmt *stmt=NULL;
    if(sqlite3_prepare_v2(db,"SELECT path FROM iptv_snapshot WHERE channel=?",-1,&stmt,NULL)==SQLITE_OK){bindstr(stmt,1,channel);if(sqlite3_step(stmt)==SQLITE_ROW)snprintf(old,sizeof(old),"%s",sqlite3_column_text(stmt,0));}
    sqlite3_finalize(stmt);stmt=NULL;
    int rc=sqlite3_prepare_v2(db,"INSERT OR REPLACE INTO iptv_snapshot(channel,path,device,inode,bytes,captured_at) SELECT ?,?,?,?,?,unixepoch() WHERE EXISTS(SELECT 1 FROM iptv_record WHERE kind='channels' AND id=? AND revision=?)",-1,&stmt,NULL);
    if(rc==SQLITE_OK){bindstr(stmt,1,channel);bindstr(stmt,2,path);sqlite3_bind_int64(stmt,3,st.st_dev);sqlite3_bind_int64(stmt,4,st.st_ino);sqlite3_bind_int64(stmt,5,(sqlite3_int64)length);bindstr(stmt,6,channel);sqlite3_bind_int(stmt,7,revision);rc=sqlite3_step(stmt);}
    int saved=sqlite3_changes(db);
    sqlite3_finalize(stmt);
    if(rc!=SQLITE_DONE||!saved){unlink(path);return iptv_fail(e,rc==SQLITE_DONE?409:503,rc==SQLITE_DONE?"revision_conflict":"job_store_failed",""),-1;}
    if(*old)unlink(old);return 0;
}
static void snapshot(sqlite3 *db,const char *id,struct json_object *payload)
{
    const char *channel_id=iptv_string(payload,"channel_id");
    struct json_object *channel=iptv_record(db,"channels",channel_id),*cfg=iptv_settings(db),*state=NULL;
    struct iptv_error e={0};char operation[96];snprintf(operation,sizeof(operation),"snapshot-%s",id);
    if(!iptv_channel_enabled(db,channel)||!iptv_integer(cfg,"enabled",0))iptv_fail(&e,409,"channel_unavailable","");
    else if(iptv_integer(channel,"revision",0)!=iptv_integer(payload,"revision",0))iptv_fail(&e,409,"revision_conflict","");
    else state=iptv_runtime_snapshot(channel,operation,&e);
    if(state){json_object_put(state);
        for(;;){state=iptv_runtime_state(operation);if(strcmp(iptv_string(state,"state"),"probing")||cancelled(db,id))break;json_object_put(state);usleep(200000);}
        if(!cancelled(db,id)){
            char *data=NULL;size_t length=0;
            if(strcmp(iptv_string(state,"state"),"snapshot_complete"))iptv_fail(&e,409,*iptv_string(state,"error")?iptv_string(state,"error"):"snapshot_failed","");
            else if(!iptv_runtime_snapshot_read(operation,&data,&length,&e)){
                struct json_object *current=iptv_record(db,"channels",channel_id);
                if(!iptv_channel_enabled(db,current)||iptv_integer(current,"revision",0)!=iptv_integer(payload,"revision",0))iptv_fail(&e,409,"revision_conflict","");
                else save_snapshot(db,channel_id,iptv_integer(payload,"revision",0),cfg,data,length,&e);
                if(current)json_object_put(current);
            }
            free(data);
        }
        json_object_put(state);struct iptv_error ignored={0};state=iptv_runtime_stop(operation,&ignored);if(state)json_object_put(state);
    }
    int stop=cancelled(db,id);update(db,id,stop?"cancelled":e.status?"failed":"complete",NULL,stop?"operation_cancelled":e.code);
    if(channel)json_object_put(channel);if(cfg)json_object_put(cfg);
}
static void *worker(void *unused)
{
    (void)unused;
    while (!atomic_load(&stopping)) {
        usleep(200000); struct iptv_error e = {0}; sqlite3 *db = iptv_db(&e); if (!db) continue;
        sqlite3_stmt *s = NULL; char id[97] = "";
        if (sqlite3_prepare_v2(db, "SELECT id FROM iptv_job WHERE state='queued' ORDER BY created_at LIMIT 1", -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
            snprintf(id, sizeof(id), "%s", sqlite3_column_text(s, 0));
        sqlite3_finalize(s);
        struct json_object *job = *id ? read_job(db, id) : NULL, *payload = NULL;
        if (job) {
            if (cancelled(db, id)) update(db, id, "cancelled", NULL, "operation_cancelled");
            else {
                update(db, id, "running", NULL, ""); json_object_object_get_ex(job, "payload", &payload);
                if (!strcmp(iptv_string(job, "kind"), "scan")) scan(db, id, payload);
                else if (!strcmp(iptv_string(job, "kind"), "snapshot")) snapshot(db,id,payload);
                else fetch_list(db, id, payload);
            }
            json_object_put(job);
        }
        sqlite3_close(db);
    }
    return NULL;
}
int iptv_jobs_start(struct iptv_error *e)
{
    sqlite3 *db = iptv_db(e); if (!db) return -1;
    int rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS iptv_job(id TEXT PRIMARY KEY,kind TEXT NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL,result TEXT NOT NULL DEFAULT '{}',error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,cancel INTEGER NOT NULL DEFAULT 0);UPDATE iptv_job SET state='interrupted',error='service_restarted' WHERE state IN('queued','running');", NULL, NULL, NULL);
    if(rc==SQLITE_OK)rc=sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS iptv_snapshot(channel TEXT PRIMARY KEY,path TEXT NOT NULL,device INTEGER NOT NULL,inode INTEGER NOT NULL,bytes INTEGER NOT NULL,captured_at INTEGER NOT NULL)",NULL,NULL,NULL);
    sqlite3_close(db);
    if (rc != SQLITE_OK || pthread_create(&worker_thread, NULL, worker, NULL)) {
        iptv_fail(e, 503, "job_worker_unavailable", ""); return -1;
    }
    started = 1; return 0;
}
void iptv_jobs_shutdown(void)
{ atomic_store(&stopping, 1); if (started) pthread_join(worker_thread, NULL); started = 0; }

static struct json_object *import_scan(sqlite3 *db, struct json_object *job,
    struct json_object *body, int commit, struct iptv_error *e)
{
    struct json_object *selected = NULL, *result = NULL, *found = NULL, *payload = NULL;
    if (!json_object_object_get_ex(body, "rows", &selected) ||
        !json_object_is_type(selected, json_type_array) || json_object_array_length(selected) > SCAN_LIMIT)
        return iptv_fail(e, 400, "invalid_parameter", "rows");
    if (commit && iptv_integer(body, "if_revision", -1) != iptv_revision(db))
        return iptv_fail(e, 409, "revision_conflict", "if_revision");
    json_object_object_get_ex(job, "result", &result); json_object_object_get_ex(result, "rows", &found);
    json_object_object_get_ex(job, "payload", &payload);
    struct json_object *output = json_object_new_object(), *outcomes = json_object_new_array();
    json_object_object_add(output, "base_revision", json_object_new_int(iptv_revision(db)));
    int saved_count = 0;
    for (size_t i = 0; i < json_object_array_length(selected); i++) {
        struct json_object *choice = json_object_array_get_idx(selected, i), *row = json_object_new_object();
        int index = iptv_integer(choice, "index", -1); struct json_object *source = NULL;
        if (index >= 0 && (size_t)index < json_object_array_length(found)) source = json_object_array_get_idx(found, index);
        json_object_object_add(row, "index", json_object_new_int(index));
        struct iptv_error error = {0};
        struct json_object *channel = json_tokener_parse("{\"enabled\":true,\"position\":0,\"number\":0,\"mode\":\"managed\"}");
        if (!source || strcmp(iptv_string(source, "state"), "found")) iptv_fail(&error, 400, "scan_result_not_media", "index");
        str(channel, "source_url", iptv_string(source, "source_url")); str(channel, "input_id", iptv_string(payload, "input_id"));
        const char *keys[] = {"name", "category_id", "epg_id", "epg_source_id", "logo_url", NULL};
        for (int j = 0; keys[j]; j++) str(channel, keys[j], iptv_string(choice, keys[j]));
        if (!error.status) iptv_validate(db, "channels", channel, &error);
        sqlite3_stmt *stmt = NULL; int duplicate = 0;
        if (!error.status && sqlite3_prepare_v2(db, "SELECT id FROM iptv_record WHERE kind='channels' AND json_extract(body,'$.source_url')=?", -1, &stmt, NULL) == SQLITE_OK) {
            bindstr(stmt, 1, iptv_string(channel, "source_url")); duplicate = sqlite3_step(stmt) == SQLITE_ROW;
        }
        sqlite3_finalize(stmt);
        str(row, "action", duplicate ? "skip" : "create");
        if (commit && !error.status && !duplicate) {
            char id[49]; struct json_object *saved = NULL;
            if (iptv_id(id, sizeof(id))) iptv_fail(&error, 503, "entropy_unavailable", "");
            else saved = iptv_save(db, "channels", id, channel, 1, &error);
            if (saved) {saved_count++; str(row, "id", id); json_object_put(saved);}
        }
        if (error.status) {str(row, "action", "error"); str(row, "error", error.code); str(row, "field", error.field);}
        json_object_array_add(outcomes, row); json_object_put(channel);
    }
    json_object_object_add(output, "rows", outcomes);
    json_object_object_add(output, "saved", json_object_new_int(saved_count));
    json_object_object_add(output, "persisted", json_object_new_boolean(commit));
    json_object_object_add(output, "revision", json_object_new_int(iptv_revision(db))); return output;
}

struct json_object *iptv_jobs_request(sqlite3 *db, const char *method, const char *path,
                                     struct json_object *body, struct iptv_error *e)
{
    char kind[32] = "", id[97] = "", action[32] = "", extra;
    int parts = sscanf(path, "%31[^/]/%96[^/]/%31[^/]%c", kind, id, action, &extra);
    sqlite3_stmt *s = NULL;
    if (!strcmp(path, "scans/preview") && !strcmp(method, "POST")) return scan_preview(db, body, e);
    int shot=!strcmp(kind,"snapshots")&&parts==2&&iptv_valid_id(id);
    if(shot&&!strcmp(method,"GET"))return iptv_snapshot_read(db,id,e);
    if ((!strcmp(path, "scans") || !strcmp(path, "imports/fetch") || shot) && !strcmp(method, "POST")) {
        if (!shot&&!iptv_integer(body, "confirm", 0)) return iptv_fail(e, 409, "requires_confirmation", "confirm");
        const char *job_kind = shot?"snapshot":!strcmp(path, "scans") ? "scan" : "fetch";
        struct json_object *payload = NULL;
        if(shot){
            struct json_object *channel=iptv_record(db,"channels",id);
            if(!iptv_channel_enabled(db,channel))iptv_fail(e,409,"channel_unavailable","");
            else if(!strcmp(iptv_string(channel,"mode"),"external"))iptv_fail(e,409,"external_source_not_hosted","");
            else {payload=json_object_new_object();str(payload,"channel_id",id);json_object_object_add(payload,"revision",json_object_new_int(iptv_integer(channel,"revision",0)));}
            if(channel)json_object_put(channel);
        }
        else if (!strcmp(job_kind, "scan")) payload = scan_preview(db, body, e);
        else {
            const char *url = iptv_string(body, "url"), *format = iptv_string(body, "format");
            if ((strncmp(url, "http://", 7) && strncmp(url, "https://", 8)) || strlen(url) > 2048 ||
                strpbrk(url, "@?\r\n\t ") || (strcmp(format, "m3u") && strcmp(format, "txt")))
                return iptv_fail(e, 400, "invalid_parameter", "url");
            payload = json_object_new_object(); str(payload, "url", url); str(payload, "format", format);
        }
        if (!payload) return NULL;
        if (sqlite3_prepare_v2(db, "SELECT 1 FROM iptv_job WHERE state IN('queued','running') LIMIT 1", -1, &s, NULL) != SQLITE_OK) goto create_failed;
        int busy = sqlite3_step(s) == SQLITE_ROW; sqlite3_finalize(s); s = NULL;
        if (busy) {json_object_put(payload); return iptv_fail(e, 409, "network_job_busy", "");}
        char new_id[49];
        if (iptv_id(new_id, sizeof(new_id)) || sqlite3_prepare_v2(db, "INSERT INTO iptv_job(id,kind,state,payload,created_at,updated_at) VALUES(?,?,'queued',?,unixepoch(),unixepoch())", -1, &s, NULL) != SQLITE_OK) goto create_failed;
        bindstr(s, 1, new_id); bindstr(s, 2, job_kind); bindstr(s, 3, json_object_to_json_string(payload));
        int rc = sqlite3_step(s); sqlite3_finalize(s); s = NULL; json_object_put(payload);
        if (rc == SQLITE_DONE) return read_job(db, new_id);
        return iptv_fail(e, 503, "job_store_failed", "");
create_failed:
        sqlite3_finalize(s); json_object_put(payload); return iptv_fail(e, 503, "job_store_failed", "");
    }
    if (parts == 1 && !strcmp(method, "GET")) {
        struct json_object *o = json_object_new_object(), *items = json_object_new_array();
        if (sqlite3_prepare_v2(db, !strcmp(kind, "scans") ? "SELECT id FROM iptv_job WHERE kind='scan' ORDER BY created_at DESC LIMIT 100" : "SELECT id FROM iptv_job ORDER BY created_at DESC LIMIT 100", -1, &s, NULL) == SQLITE_OK)
            while (sqlite3_step(s) == SQLITE_ROW) json_object_array_add(items, read_job(db, (const char *)sqlite3_column_text(s, 0)));
        sqlite3_finalize(s); json_object_object_add(o, "items", items); return o;
    }
    if (parts < 2 || !iptv_valid_id(id)) return iptv_fail(e, 404, "resource_not_found", "");
    struct json_object *job = read_job(db, id); if (!job) return iptv_fail(e, 404, "resource_not_found", "");
    if (parts == 2 && !strcmp(method, "GET")) return job;
    if (parts == 3 && !strcmp(method, "POST") && !strcmp(iptv_string(job, "kind"), "scan") &&
        (!strcmp(action, "import") || !strcmp(action, "import-preview"))) {
        struct json_object *result = import_scan(db, job, body, !strcmp(action, "import"), e);
        json_object_put(job); return result;
    }
    int active = !strcmp(iptv_string(job, "state"), "running") || !strcmp(iptv_string(job, "state"), "queued");
    json_object_put(job);
    if (parts == 3 && !strcmp(action, "stop") && !strcmp(method, "POST")) {
        if (sqlite3_prepare_v2(db, "UPDATE iptv_job SET cancel=1 WHERE id=?", -1, &s, NULL) != SQLITE_OK) return iptv_fail(e, 503, "job_store_failed", "");
    } else if (parts == 2 && !strcmp(method, "DELETE") && !active) {
        if (sqlite3_prepare_v2(db, "DELETE FROM iptv_job WHERE id=?", -1, &s, NULL) != SQLITE_OK) return iptv_fail(e, 503, "job_store_failed", "");
    } else return iptv_fail(e, active ? 409 : 405, active ? "job_still_active" : "method_not_allowed", "");
    bindstr(s, 1, id); int rc = sqlite3_step(s); sqlite3_finalize(s);
    return rc == SQLITE_DONE ? json_tokener_parse("{\"accepted\":true}") : iptv_fail(e, 503, "job_store_failed", "");
}
