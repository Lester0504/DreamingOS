// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TVHOME_INTERNAL_H
#define TVHOME_INTERNAL_H
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "tvhome_store.h"
int tvhome_db_open(sqlite3 **db, struct tvhome_err *err);
int tvhome_authorize(sqlite3 *db, const char *token, char *terminal, size_t size, struct tvhome_err *err);
struct json_object *tvhome_error(struct tvhome_err *,int,const char *,const char *,const char *);
static inline struct json_object *tv_get(struct json_object *o,const char *k) {struct json_object *v=NULL;if(o)json_object_object_get_ex(o,k,&v);return v;}
static inline const char *tv_str(struct json_object *o,const char *k) {struct json_object *v=tv_get(o,k);return json_object_is_type(v,json_type_string)?json_object_get_string(v):"";}
static inline int64_t tv_num(struct json_object *o,const char *k) {return json_object_get_int64(tv_get(o,k));}
static inline int64_t tv_now(void) {struct timeval t;gettimeofday(&t,NULL);return (int64_t)t.tv_sec*1000+t.tv_usec/1000;}
static inline const char *tv_col(sqlite3_stmt *s,int n) {const char *v=(const char *)sqlite3_column_text(s,n);return v?v:"";}
static inline const char *tv_json(struct json_object *o) {return json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN);}
static inline int tv_run(sqlite3 *db,const char *sql,int n,...) {
 sqlite3_stmt *s=NULL;if(sqlite3_prepare_v2(db,sql,-1,&s,NULL)!=SQLITE_OK)return -1;
 va_list a;va_start(a,n);for(int i=1;i<=n;i++){const char *v=va_arg(a,const char *);sqlite3_bind_text(s,i,v?v:"",-1,SQLITE_TRANSIENT);}va_end(a);
 int r=sqlite3_step(s);sqlite3_finalize(s);return r==SQLITE_DONE?0:-1;
}
static inline int tv_changed(sqlite3 *db) {return tv_run(db,"UPDATE tvhome_settings SET config_version=config_version+1 WHERE id=1",0);}
static inline struct json_object *tv_db_error(sqlite3 *db,struct tvhome_err *e) {tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,503,"service_not_ready","","TV configuration transaction failed");}
static inline int tv_exists(sqlite3 *db,const char *sql,const char *id) {
 sqlite3_stmt *s=NULL;int yes=0;if(sqlite3_prepare_v2(db,sql,-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);yes=sqlite3_step(s)==SQLITE_ROW;sqlite3_finalize(s);}return yes;
}
#endif
