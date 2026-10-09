// SPDX-License-Identifier: GPL-2.0-or-later
#include "wan_sla_history.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static struct json_object *v(struct json_object *o,const char *k)
{ struct json_object *x=NULL; if(o)json_object_object_get_ex(o,k,&x);return x; }
static const char *s(struct json_object *o,const char *k)
{ const char *x=json_object_get_string(v(o,k));return x?x:""; }
static int64_t n(struct json_object *o,const char *k)
{ return json_object_get_int64(v(o,k)); }
static int exec(sqlite3 *db,const char *sql)
{ return sqlite3_exec(db,sql,NULL,NULL,NULL)==SQLITE_OK?0:-1; }
static void text(sqlite3_stmt *st,int index,const char *str)
{ sqlite3_bind_text(st,index,str,-1,SQLITE_TRANSIENT); }
static int done(sqlite3_stmt *st)
{ int rc=sqlite3_step(st)==SQLITE_DONE?0:-1;sqlite3_finalize(st);return rc; }

int wan_sla_history_open(const char *path,sqlite3 **db)
{
    *db=NULL;
    if(sqlite3_open_v2(path,db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOMUTEX,NULL)!=SQLITE_OK)goto fail;
    sqlite3_busy_timeout(*db,0);
    if(exec(*db,"PRAGMA auto_vacuum=INCREMENTAL;PRAGMA journal_mode=WAL;PRAGMA wal_autocheckpoint=128;"
        "CREATE TABLE IF NOT EXISTS flowd_wan_sla_sample(sample_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "sla_id TEXT NOT NULL,sla_revision INTEGER NOT NULL,wan_id TEXT NOT NULL,decision_id TEXT NOT NULL,"
        "ts INTEGER NOT NULL,target_index INTEGER NOT NULL,payload TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS sla_sample_time ON flowd_wan_sla_sample(sla_id,ts,sample_id);"
        "CREATE INDEX IF NOT EXISTS sla_sample_wan_time ON flowd_wan_sla_sample(wan_id,ts,sample_id);"
        "CREATE UNIQUE INDEX IF NOT EXISTS sla_sample_once ON flowd_wan_sla_sample(decision_id,target_index);"
        "CREATE TABLE IF NOT EXISTS flowd_wan_sla_state(sla_id TEXT PRIMARY KEY,ts INTEGER NOT NULL,payload TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS flowd_wan_sla_event(event_id INTEGER PRIMARY KEY AUTOINCREMENT,sla_id TEXT NOT NULL,"
        "decision_id TEXT NOT NULL,ts INTEGER NOT NULL,pinned INTEGER NOT NULL DEFAULT 0,payload TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS sla_event_time ON flowd_wan_sla_event(sla_id,event_id);"
        "CREATE UNIQUE INDEX IF NOT EXISTS sla_event_once ON flowd_wan_sla_event(decision_id,json_extract(payload,'$.event'));"
        "CREATE TABLE IF NOT EXISTS flowd_wan_sla_rollup(rollup_id INTEGER PRIMARY KEY AUTOINCREMENT,sla_id TEXT NOT NULL,"
        "revision INTEGER NOT NULL,wan_id TEXT NOT NULL,target TEXT NOT NULL,method TEXT NOT NULL,minute INTEGER NOT NULL,"
        "payload TEXT NOT NULL,UNIQUE(sla_id,revision,target,method,minute));"
        "CREATE INDEX IF NOT EXISTS sla_rollup_time ON flowd_wan_sla_rollup(sla_id,minute,rollup_id);"
        "CREATE TABLE IF NOT EXISTS flowd_wan_sla_incident(incident_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "sla_id TEXT NOT NULL,opened_at INTEGER NOT NULL,closed_at INTEGER,pinned INTEGER NOT NULL DEFAULT 0,payload TEXT NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS sla_incident_active ON flowd_wan_sla_incident(sla_id) WHERE closed_at IS NULL;"))
        goto fail;
    return 0;
fail:
    if(*db)sqlite3_close(*db);
    *db=NULL;return -1;
}

struct json_object *wan_sla_history_restore(sqlite3 *db,const char *id)
{
    sqlite3_stmt *st=NULL;
    struct json_object *out=NULL;
    if(sqlite3_prepare_v2(db,"SELECT payload FROM flowd_wan_sla_state WHERE sla_id=?1",-1,&st,NULL)!=SQLITE_OK)return NULL;
    text(st,1,id);
    if(sqlite3_step(st)==SQLITE_ROW)out=json_tokener_parse((const char *)sqlite3_column_text(st,0));
    sqlite3_finalize(st);return out;
}

static int compare(const void *a,const void *b)
{ double x=*(const double *)a,y=*(const double *)b;return (x>y)-(x<y); }

static int rollup(sqlite3 *db,struct json_object *sample)
{
    sqlite3_stmt *st=NULL;
    struct json_object *r=NULL,*rtts;
    int64_t minute=n(sample,"finished_at")/60*60,count,successes;
    double values[60],delta=0,previous=0;
    unsigned len,i;
    int rc=-1;
    if(sqlite3_prepare_v2(db,"SELECT payload FROM flowd_wan_sla_rollup WHERE sla_id=?1 AND revision=?2 AND target=?3 AND method=?4 AND minute=?5",-1,&st,NULL)!=SQLITE_OK)return -1;
    text(st,1,s(sample,"sla_id"));sqlite3_bind_int64(st,2,n(sample,"sla_revision"));
    text(st,3,s(sample,"target"));text(st,4,s(sample,"method"));sqlite3_bind_int64(st,5,minute);
    rc=sqlite3_step(st);
    if(rc==SQLITE_ROW)r=json_tokener_parse((const char *)sqlite3_column_text(st,0));
    sqlite3_finalize(st);st=NULL;
    if(rc!=SQLITE_ROW && rc!=SQLITE_DONE)return -1;
    if(!r)r=json_object_new_object();
    rtts=v(r,"rtts");
    if(!rtts){rtts=json_object_new_array();json_object_object_add(r,"rtts",rtts);}
    count=n(r,"samples")+1;successes=n(r,"successes")+(n(sample,"ok")!=0);
    if(n(sample,"ok") && json_object_array_length(rtts)<60)
        json_object_array_add(rtts,json_object_get(v(sample,"latency_ms")));
    len=(unsigned)json_object_array_length(rtts);
    for(i=0;i<len;i++){
        values[i]=json_object_get_double(json_object_array_get_idx(rtts,i));
        if(i)delta+=fabs(values[i]-previous);
        previous=values[i];
    }
    qsort(values,len,sizeof(values[0]),compare);
    json_object_object_add(r,"samples",json_object_new_int64(count));
    json_object_object_add(r,"successes",json_object_new_int64(successes));
    json_object_object_add(r,"active_loss_pct",json_object_new_double(100.0*(count-successes)/count));
    json_object_object_add(r,"availability_pct",json_object_new_double(100.0*successes/count));
    json_object_object_add(r,"latency_p50_ms",len?json_object_new_double(values[(len*50+99)/100-1]):NULL);
    json_object_object_add(r,"latency_p95_ms",len?json_object_new_double(values[(len*95+99)/100-1]):NULL);
    json_object_object_add(r,"jitter_ms",len>1?json_object_new_double(delta/(len-1)):NULL);
    json_object_object_add(r,"jitter_algorithm",json_object_new_string("per_target_mean_absolute_adjacent_rtt_delta"));
    json_object_object_add(r,"sla_id",json_object_get(v(sample,"sla_id")));
    json_object_object_add(r,"sla_revision",json_object_get(v(sample,"sla_revision")));
    json_object_object_add(r,"wan_id",json_object_get(v(sample,"wan_id")));
    json_object_object_add(r,"target",json_object_get(v(sample,"target")));
    json_object_object_add(r,"method",json_object_get(v(sample,"method")));
    json_object_object_add(r,"minute",json_object_new_int64(minute));
    rc=-1;
    if(sqlite3_prepare_v2(db,"INSERT INTO flowd_wan_sla_rollup(sla_id,revision,wan_id,target,method,minute,payload)"
        "VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(sla_id,revision,target,method,minute) DO UPDATE SET payload=excluded.payload",-1,&st,NULL)!=SQLITE_OK)goto out;
    text(st,1,s(sample,"sla_id"));sqlite3_bind_int64(st,2,n(sample,"sla_revision"));
    text(st,3,s(sample,"wan_id"));text(st,4,s(sample,"target"));text(st,5,s(sample,"method"));
    sqlite3_bind_int64(st,6,minute);text(st,7,json_object_to_json_string_ext(r,JSON_C_TO_STRING_PLAIN));
    rc=done(st);
out:
    json_object_put(r);return rc;
}

int wan_sla_history_record(sqlite3 *db,struct json_object *runtime,
                           struct json_object *samples,struct json_object *events)
{
    sqlite3_stmt *st=NULL;
    unsigned i;
    const char *id=s(runtime,"sla_id"),*decision=s(runtime,"decision_id");
    int64_t at=n(runtime,"evaluated_at");
    if(!*id || !*decision || at<=0 || exec(db,"BEGIN IMMEDIATE"))return -1;
    for(i=0;i<json_object_array_length(samples);i++) {
        struct json_object *sample=json_object_array_get_idx(samples,i);
        if(sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO flowd_wan_sla_sample(sla_id,sla_revision,wan_id,decision_id,ts,target_index,payload)"
            "VALUES(?1,?2,?3,?4,?5,?6,?7)",-1,&st,NULL)!=SQLITE_OK)goto fail;
        text(st,1,id);sqlite3_bind_int64(st,2,n(runtime,"sla_revision"));text(st,3,s(runtime,"wan_id"));text(st,4,decision);
        sqlite3_bind_int64(st,5,n(sample,"finished_at"));sqlite3_bind_int(st,6,(int)i);
        text(st,7,json_object_to_json_string_ext(sample,JSON_C_TO_STRING_PLAIN));
        if(done(st))goto fail;
        if(sqlite3_changes(db) && n(sample,"valid") && rollup(db,sample))goto fail;
    }
    if(sqlite3_prepare_v2(db,"INSERT INTO flowd_wan_sla_state(sla_id,ts,payload) VALUES(?1,?2,?3)"
        " ON CONFLICT(sla_id) DO UPDATE SET ts=excluded.ts,payload=excluded.payload WHERE excluded.ts>=flowd_wan_sla_state.ts",-1,&st,NULL)!=SQLITE_OK)goto fail;
    text(st,1,id);sqlite3_bind_int64(st,2,at);text(st,3,json_object_to_json_string_ext(runtime,JSON_C_TO_STRING_PLAIN));
    if(done(st))goto fail;
    for(i=0;i<json_object_array_length(events);i++) {
        struct json_object *event=json_object_array_get_idx(events,i);
        if(sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO flowd_wan_sla_event(sla_id,decision_id,ts,payload) VALUES(?1,?2,?3,?4)",-1,&st,NULL)!=SQLITE_OK)goto fail;
        text(st,1,id);text(st,2,decision);sqlite3_bind_int64(st,3,at);
        text(st,4,json_object_to_json_string_ext(event,JSON_C_TO_STRING_PLAIN));
        if(done(st))goto fail;
    }
    if(strcmp(s(runtime,"stable_state"),"healthy") && strcmp(s(runtime,"stable_state"),"unknown") &&
        *s(runtime,"stable_state")) {
        if(sqlite3_prepare_v2(db,"INSERT INTO flowd_wan_sla_incident(sla_id,opened_at,payload) "
            "SELECT ?1,?2,?3 WHERE NOT EXISTS(SELECT 1 FROM flowd_wan_sla_incident WHERE sla_id=?1 AND closed_at IS NULL)",-1,&st,NULL)!=SQLITE_OK)goto fail;
    } else if(!strcmp(s(runtime,"stable_state"),"healthy") && !strcmp(s(runtime,"state"),"healthy")) {
        if(sqlite3_prepare_v2(db,"UPDATE flowd_wan_sla_incident SET closed_at=?2,payload=?3 WHERE sla_id=?1 AND closed_at IS NULL",-1,&st,NULL)!=SQLITE_OK)goto fail;
    } else st=NULL;
    if(st) {
        text(st,1,id);sqlite3_bind_int64(st,2,at);text(st,3,json_object_to_json_string_ext(runtime,JSON_C_TO_STRING_PLAIN));
        if(done(st))goto fail;
    }
    if(!exec(db,"COMMIT"))return 0;
fail:
    exec(db,"ROLLBACK");return -1;
}

static int64_t scalar(sqlite3 *db,const char *sql)
{
    sqlite3_stmt *st=NULL;int64_t out=-1;
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW)out=sqlite3_column_int64(st,0);
    if(st)sqlite3_finalize(st);
    return out;
}

int wan_sla_history_prune(sqlite3 *db,int64_t now,int64_t byte_cap,int raw_cap,int rollup_cap,int event_cap)
{
    char sql[1600];
    int64_t pages,free_pages,page_size,bytes;
    if(byte_cap<0 || raw_cap<0 || rollup_cap<0 || event_cap<0)return -1;
    snprintf(sql,sizeof(sql),
        "DELETE FROM flowd_wan_sla_sample WHERE sample_id IN(SELECT sample_id FROM flowd_wan_sla_sample WHERE ts<%lld ORDER BY sample_id LIMIT 1024);"
        "DELETE FROM flowd_wan_sla_sample WHERE sample_id IN(SELECT sample_id FROM flowd_wan_sla_sample ORDER BY sample_id LIMIT min(1024,max(0,(SELECT count(*) FROM flowd_wan_sla_sample)-%d)));"
        "DELETE FROM flowd_wan_sla_rollup WHERE rollup_id IN(SELECT rollup_id FROM flowd_wan_sla_rollup WHERE minute<%lld ORDER BY rollup_id LIMIT 1024);"
        "DELETE FROM flowd_wan_sla_rollup WHERE rollup_id IN(SELECT rollup_id FROM flowd_wan_sla_rollup ORDER BY rollup_id LIMIT min(1024,max(0,(SELECT count(*) FROM flowd_wan_sla_rollup)-%d)));"
        "DELETE FROM flowd_wan_sla_event WHERE event_id IN(SELECT event_id FROM flowd_wan_sla_event WHERE pinned=0 AND ts<%lld ORDER BY event_id LIMIT 256);"
        "DELETE FROM flowd_wan_sla_event WHERE event_id IN(SELECT event_id FROM flowd_wan_sla_event WHERE pinned=0 ORDER BY event_id LIMIT min(256,max(0,(SELECT count(*) FROM flowd_wan_sla_event)-%d)));"
        "DELETE FROM flowd_wan_sla_incident WHERE incident_id IN(SELECT incident_id FROM flowd_wan_sla_incident WHERE pinned=0 AND closed_at<%lld ORDER BY incident_id LIMIT 256);",
        (long long)(now-86400),raw_cap,(long long)(now-30LL*86400),rollup_cap,
        (long long)(now-180LL*86400),event_cap,(long long)(now-180LL*86400));
    if(exec(db,sql))return -1;
    pages=scalar(db,"PRAGMA page_count");free_pages=scalar(db,"PRAGMA freelist_count");page_size=scalar(db,"PRAGMA page_size");
    if(pages<0 || free_pages<0 || page_size<0)return -1;
    bytes=(pages-free_pages)*page_size;
    {
        const char *path=sqlite3_db_filename(db,"main");
        char wal[1024];struct stat st;
        if(path && snprintf(wal,sizeof(wal),"%s-wal",path)<(int)sizeof(wal) && !stat(wal,&st))bytes+=st.st_size;
    }
    if(bytes>byte_cap) {
        if(scalar(db,"SELECT count(*) FROM flowd_wan_sla_sample")>0)
            exec(db,"DELETE FROM flowd_wan_sla_sample WHERE sample_id IN(SELECT sample_id FROM flowd_wan_sla_sample ORDER BY sample_id LIMIT 1024)");
        else if(scalar(db,"SELECT count(*) FROM flowd_wan_sla_rollup")>0)
            exec(db,"DELETE FROM flowd_wan_sla_rollup WHERE rollup_id IN(SELECT rollup_id FROM flowd_wan_sla_rollup ORDER BY rollup_id LIMIT 1024)");
        else exec(db,"DELETE FROM flowd_wan_sla_event WHERE event_id IN(SELECT event_id FROM flowd_wan_sla_event WHERE pinned=0 ORDER BY event_id LIMIT 256)");
    }
    exec(db,"PRAGMA incremental_vacuum(128)");
    sqlite3_wal_checkpoint_v2(db,NULL,SQLITE_CHECKPOINT_TRUNCATE,NULL,NULL);
    return 0;
}

struct json_object *wan_sla_history_query(const char *path,struct json_object *request)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;
    struct json_object *out=json_object_new_object(),*items=json_object_new_array();
    const char *resolution=*s(request,"resolution")?s(request,"resolution"):"raw";
    const char *table,*column,*time_column,*id=s(request,"id");
    const char *wan=s(request,"wan_id");
    int wan_dns=!strcmp(s(request,"scope"),"wan_dns");
    int64_t from=n(request,"from"),to=v(request,"to")?n(request,"to"):time(NULL);
    int64_t cursor=n(request,"cursor"),last=0,limit=v(request,"limit")?n(request,"limit"):100;
    int status=503,rc;char sql[700];
    if((!wan_dns && (!*id || strlen(id)>=96)) || from<0 || to<from || cursor<0 || limit<1 || limit>500) {status=400;goto fail;}
    if(wan_dns && (!*wan || strlen(wan)>=96 || !v(request,"from") || !v(request,"to") ||
        to-from>86400 || n(request,"events") || strcmp(resolution,"raw"))) {status=400;goto fail;}
    if(n(request,"events")) {table="flowd_wan_sla_event";column="event_id";time_column="ts";}
    else if(!strcmp(resolution,"1m")) {table="flowd_wan_sla_rollup";column="rollup_id";time_column="minute";}
    else if(!strcmp(resolution,"raw")) {table="flowd_wan_sla_sample";column="sample_id";time_column="ts";}
    else {status=400;goto fail;}
    if(sqlite3_open_v2(path,&db,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,NULL)!=SQLITE_OK)goto fail;
    sqlite3_busy_timeout(db,0);
    if(wan_dns)
        snprintf(sql,sizeof(sql),"SELECT sample_id,payload FROM flowd_wan_sla_sample "
            "WHERE wan_id=?1 AND sample_id>?2 AND ts>=?3 AND ts<=?4 "
            "AND json_extract(payload,'$.method')='dns' ORDER BY sample_id LIMIT ?5");
    else
        snprintf(sql,sizeof(sql),"SELECT %s,payload FROM %s WHERE sla_id=?1 AND %s>?2 AND %s>=?3 AND %s<=?4 ORDER BY %s LIMIT ?5",
            column,table,column,time_column,time_column,column);
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK)goto fail;
    text(st,1,wan_dns?wan:id);sqlite3_bind_int64(st,2,cursor);sqlite3_bind_int64(st,3,from);sqlite3_bind_int64(st,4,to);sqlite3_bind_int64(st,5,limit+1);
    while((rc=sqlite3_step(st))==SQLITE_ROW) {
        struct json_object *item;
        if((int64_t)json_object_array_length(items)==limit)break;
        item=json_tokener_parse((const char *)sqlite3_column_text(st,1));
        if(!item)goto fail;
        last=sqlite3_column_int64(st,0);json_object_object_del(item,"rtts");
        json_object_array_add(items,item);
    }
    if(rc!=SQLITE_DONE && rc!=SQLITE_ROW)goto fail;
    json_object_object_add(out,"next_cursor",rc==SQLITE_ROW?json_object_new_int64(last):NULL);
    json_object_object_add(out,"ok",json_object_new_boolean(1));
    json_object_object_add(out,"items",items);
    json_object_object_add(out,"resolution",json_object_new_string(resolution));
    json_object_object_add(out,"to",json_object_new_int64(to));
    if(wan_dns) {
        json_object_object_add(out,"scope",json_object_new_string("wan_dns"));
        json_object_object_add(out,"wan_id",json_object_new_string(wan));
        json_object_object_add(out,"from",json_object_new_int64(from));
        json_object_object_add(out,"coverage",json_object_new_string("retained_samples"));
        json_object_object_add(out,"retention_seconds",json_object_new_int(86400));
    }
    sqlite3_finalize(st);sqlite3_close(db);return out;
fail:
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    json_object_put(items);
    json_object_object_add(out,"ok",json_object_new_boolean(0));json_object_object_add(out,"http_status",json_object_new_int(status));
    json_object_object_add(out,"error",json_object_new_string(status==400?"invalid_history_query":"history_unavailable"));
    return out;
}
