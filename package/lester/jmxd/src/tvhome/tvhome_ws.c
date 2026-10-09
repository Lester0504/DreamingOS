// SPDX-License-Identifier: GPL-2.0-or-later
/* TV sockets use webd's bounded WS worker pool; runtime leases never write flash. */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sqlite3.h>
#include "tvhome_store.h"
#include "tvhome_ws.h"
#include "webd/webd_http.h"
#include "webd/api/webd_http_req.h"
#include "webd/api/api_error.h"
#include "webd/api/api_util.h"
#include "webd/api/api_realtime_internal.h"

#ifndef TVH_RUNTIME_DB
#define TVH_RUNTIME_DB "/tmp/dreamingwrt-tvhome-ws.db"
#endif
static sqlite3 *runtime_open(int write)
{
    sqlite3 *db=NULL;
    if (sqlite3_open_v2(TVH_RUNTIME_DB,&db,write?(SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE):SQLITE_OPEN_READONLY,NULL)!=SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db,1000);
    if (write && sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS connections(pid INTEGER PRIMARY KEY,terminal_id TEXT NOT NULL,expires INTEGER NOT NULL)",NULL,NULL,NULL)!=SQLITE_OK) {
        sqlite3_close(db);return NULL;
    }
    return db;
}
int tvhome_ws_count(const char *terminal_id)
{
    sqlite3 *db=runtime_open(0); sqlite3_stmt *st=NULL; int n=0;
    if (!db) return 0;
    if (sqlite3_prepare_v2(db,"SELECT pid FROM connections WHERE expires>? AND (?='' OR terminal_id=?)",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_int64(st,1,time(NULL));
        sqlite3_bind_text(st,2,terminal_id?terminal_id:"",-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(st,3,terminal_id?terminal_id:"",-1,SQLITE_TRANSIENT);
        while (sqlite3_step(st)==SQLITE_ROW) {
            pid_t pid=(pid_t)sqlite3_column_int64(st,0);
            if (pid>1 && (kill(pid,0)==0 || errno==EPERM)) n++;
        }
        sqlite3_finalize(st);
    }
    sqlite3_close(db); return n;
}
static int lease(const char *terminal_id)
{
    sqlite3 *db=runtime_open(1);sqlite3_stmt *st=NULL;int rc=-1;
    if (!db) return -1;
    const char *sql=terminal_id?"INSERT OR REPLACE INTO connections(pid,terminal_id,expires) VALUES(?,?,?)":"DELETE FROM connections WHERE pid=?";
    if (sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_int64(st,1,getpid());
        if (terminal_id) { sqlite3_bind_text(st,2,terminal_id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,time(NULL)+15); }
        rc=sqlite3_step(st)==SQLITE_DONE?0:-1;sqlite3_finalize(st);
    }
    sqlite3_exec(db,"DELETE FROM connections WHERE expires<CAST(strftime('%s','now') AS INTEGER)",NULL,NULL,NULL);
    sqlite3_close(db);return rc;
}
static void send_error(int fd,struct tvhome_err *err)
{
    struct json_object *o=webd_error(err->code,err->message,err->field,"webd.tvhome");
    http_send_json(fd,err->http_status,o);json_object_put(o);
}
void tvhome_ws_session(int fd,const struct http_req *req)
{
    struct tvhome_err err={0};char accept[128],header[512],terminal_id[128]="";
    struct json_object *data=tvhome_bootstrap(req->auth_token,&err),*terminal=NULL,*value=NULL;
    if (!data) { send_error(fd,&err);return; }
    if (!req->websocket || webd_ws_accept_key(req->ws_key,accept,sizeof(accept))) {
        json_object_put(data);
        err.http_status=400;snprintf(err.code,sizeof(err.code),"bad_websocket_handshake");snprintf(err.message,sizeof(err.message),"WebSocket upgrade required");send_error(fd,&err);return;
    }
    json_object_object_get_ex(data,"terminal",&terminal);
    if (terminal && json_object_object_get_ex(terminal,"id",&value)) snprintf(terminal_id,sizeof(terminal_id),"%s",json_object_get_string(value));
    json_object_put(data);
    if (!*terminal_id) return;
    int size=snprintf(header,sizeof(header),"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nCache-Control: no-store\r\n\r\n",accept);
    if (webd_write_all(fd,header,(size_t)size)) return;
    struct timeval timeout={3,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    int64_t last_version=-1;time_t last_lease=0,last_rx=time(NULL),last_ping=0;
    for (;;) {
        /* Short read only: no heartbeat side effect and no online inference. */
        data=tvhome_bootstrap(req->auth_token,&err);
        if (!data) { webd_ws_send_close(fd,err.http_status==401?4001:1011,err.code);break; }
        json_object_object_get_ex(data,"config_version",&value);
        int64_t version=json_object_get_int64(value);
        if (version!=last_version) {
            struct json_object *msg=json_object_new_object();
            json_object_object_add(msg,"type",json_object_new_string(last_version<0?"hello":"reload"));
            json_object_object_add(msg,"config_version",json_object_new_int64(version));
            int rc=webd_ws_send_json(fd,msg);json_object_put(msg);
            if (rc) { json_object_put(data);break; }
            last_version=version;
        }
        json_object_put(data);
        time_t now=time(NULL);
        if (now-last_rx>45) { webd_ws_send_close(fd,1001,"heartbeat_timeout");break; }
        if (now-last_ping>=15) { if (webd_ws_send_frame(fd,9,"")) break;last_ping=now; }
        if (now-last_lease>=5) { if (lease(terminal_id)) { webd_ws_send_close(fd,1011,"runtime_unavailable");break; }last_lease=now; }
        struct pollfd p={fd,POLLIN,0};
        int ready=poll(&p,1,1000);
        if (ready<0) { if (errno==EINTR) continue;break; }
        if (ready && (p.revents&(POLLERR|POLLHUP|POLLNVAL))) break;
        if (ready && (p.revents&POLLIN)) {
            char payload[8193];int opcode=0;
            int len=webd_ws_read_frame(fd,payload,sizeof(payload),&opcode);
            if (len<0 || opcode==8) break;
            last_rx=time(NULL);
            if (opcode==9) { if (webd_ws_send_frame(fd,10,payload)) break; }
            else if (opcode==1) {
                struct json_object *msg=json_tokener_parse(payload),*kind=NULL;
                if (msg && json_object_object_get_ex(msg,"type",&kind) && !strcmp(json_object_get_string(kind),"hello")) last_version=-1;
                if (msg) json_object_put(msg);
            }
        }
    }
    lease(NULL);
}
