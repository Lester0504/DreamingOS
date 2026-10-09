// SPDX-License-Identifier: GPL-2.0-or-later
/* Filterable read-only operation audit. The ledger and its logd mirror share
 * audit_record_id / request_id / task_id; never infer correlation from time. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sqlite3.h>
#include "jmx_dataset_path.h"
#include "../../event_semantics.h"
#include "api_router.h"
#include "api_context.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "webd_http_req.h"
#include "api_audit_log.h"

struct audit_filter {
    char value[8][160];
    char q[160];
    int64_t from, to;
};
static const char *audit_keys[] = {"actor","action","risk","result","device_id","api_key_id","domain","channel"};
static const char *audit_cols[] = {"actor","action","risk","result_value","app_device_id","api_key_id","business_domain","actor_channel"};

static const char *audit_text(sqlite3_stmt *st, int i)
{
    const char *s = (const char *)sqlite3_column_text(st,i);
    return s ? s : "";
}
static void audit_param(struct jmx_api_ctx *ctx, const char *key, const char *alias, char *buf, size_t len)
{
    buf[0] = '\0';
    if (ctx->req && webd_query_get(ctx->req->query,key,buf,len) && buf[0]) return;
    if (alias && ctx->req && webd_query_get(ctx->req->query,alias,buf,len) && buf[0]) return;
    snprintf(buf,len,"%s",app_nc_json_str(ctx->body,key,alias ? app_nc_json_str(ctx->body,alias,"") : ""));
}
static int audit_number(struct jmx_api_ctx *ctx, const char *key, const char *alias, int64_t *out)
{
    char buf[64], *end;
    audit_param(ctx,key,alias,buf,sizeof(buf));
    if (!buf[0]) return 0;
    errno=0; long long n=strtoll(buf,&end,10);
    if (errno || *end || n<0) return -1;
    *out=n; return 0;
}
static void audit_domain_sql(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    (void)argc;
    sqlite3_result_text(ctx,dw_event_audit_domain((const char *)sqlite3_value_text(argv[0])),-1,SQLITE_STATIC);
}
static int audit_has_column(sqlite3 *db, const char *column)
{
    sqlite3_stmt *st=NULL; int found=0;
    if (sqlite3_prepare_v2(db,"PRAGMA table_info(api_audit_log)",-1,&st,NULL)!=SQLITE_OK) return 0;
    while (sqlite3_step(st)==SQLITE_ROW) if (!strcmp(audit_text(st,1),column)) found=1;
    sqlite3_finalize(st); return found;
}
static int audit_bind(sqlite3_stmt *st, const struct audit_filter *f)
{
    int i=1;
    for (size_t k=0;k<8;k++) if (f->value[k][0]) sqlite3_bind_text(st,i++,f->value[k],-1,SQLITE_TRANSIENT);
    if (f->from) sqlite3_bind_int64(st,i++,f->from);
    if (f->to) sqlite3_bind_int64(st,i++,f->to);
    if (f->q[0]) {
        char like[164]; snprintf(like,sizeof(like),"%%%s%%",f->q);
        for (int k=0;k<7;k++) sqlite3_bind_text(st,i++,like,-1,SQLITE_TRANSIENT);
    }
    return i;
}
static int audit_enum_valid(const char *value, const char *const *allowed)
{
    if (!value[0]) return 1;
    for (size_t i=0;allowed[i];i++) if (!strcmp(value,allowed[i])) return 1;
    return 0;
}
static struct json_object *audit_log_records(struct jmx_api_ctx *ctx)
{
    static const char *const risks[]={"low","medium","high","critical","unknown",NULL};
    static const char *const results[]={"success","failed","error","denied","accepted","pending","running","cancelled","canceled","rolled_back","partial","unknown","ok","applied","dry_run","dispatched",NULL};
    static const char *const channels[]={"web","app","api_key","system","automation","unknown",NULL};
    struct audit_filter f={0};
    int64_t page=1,size=50,total=0;
    sqlite3 *db=NULL; sqlite3_stmt *st=NULL;
    struct json_object *items=NULL,*facets=NULL,*data=NULL;
    char where[1800]=" WHERE 1=1", prefix[1600],sql[4800];
    int rc,idx;
    for (size_t k=0;k<8;k++) audit_param(ctx,audit_keys[k],k==4?"app_device_id":NULL,f.value[k],sizeof(f.value[k]));
    audit_param(ctx,"q","search",f.q,sizeof(f.q));
    if (audit_number(ctx,"from","ts_from",&f.from) || audit_number(ctx,"to","ts_to",&f.to) ||
        audit_number(ctx,"page",NULL,&page) || audit_number(ctx,"page_size","limit",&size) ||
        page<1 || page>1000000 || size<1 || size>200 || (f.to && f.from>f.to) ||
        (f.value[6][0] && !dw_event_domain_find(f.value[6])) ||
        !audit_enum_valid(f.value[2],risks) || !audit_enum_valid(f.value[3],results) || !audit_enum_valid(f.value[7],channels)) {
        ctx->status=400; return webd_error("invalid_audit_filter","invalid audit filter or pagination","","webd.audit.log");
    }
    if (sqlite3_open_v2(jmx_dataset_path("apid"),&db,SQLITE_OPEN_READONLY,NULL)!=SQLITE_OK) goto unavailable;
    sqlite3_busy_timeout(db,500);
    if (sqlite3_create_function(db,"audit_domain",1,SQLITE_UTF8|SQLITE_DETERMINISTIC,NULL,audit_domain_sql,NULL,NULL)!=SQLITE_OK) goto unavailable;
    /* Old ledgers remain readable; missing metadata stays explicitly unknown. */
    snprintf(prefix,sizeof(prefix),
        "WITH records AS (SELECT *,COALESCE(NULLIF(%s,''),audit_domain(action)) AS business_domain,"
        "COALESCE(NULLIF(%s,''),CASE WHEN actor LIKE 'web:%%' THEN 'web' WHEN actor LIKE 'app:%%' THEN 'app' "
        "WHEN actor='api_key' THEN 'api_key' WHEN actor IN ('system','automation') THEN 'system' ELSE 'unknown' END) AS actor_channel,"
        "COALESCE(NULLIF(result,''),'unknown') AS result_value,%s AS trace_request_id,%s AS trace_task_id FROM api_audit_log) ",
        audit_has_column(db,"domain")?"domain":"''",audit_has_column(db,"channel")?"channel":"''",
        audit_has_column(db,"request_id")?"request_id":"''",audit_has_column(db,"task_id")?"task_id":"''");
    for (size_t k=0;k<8;k++) if (f.value[k][0]) {
        size_t len=strlen(where); snprintf(where+len,sizeof(where)-len," AND %s=?",audit_cols[k]);
    }
    if (f.from) strncat(where," AND ts>=?",sizeof(where)-strlen(where)-1);
    if (f.to) strncat(where," AND ts<=?",sizeof(where)-strlen(where)-1);
    if (f.q[0]) strncat(where," AND (actor LIKE ? OR action LIKE ? OR target LIKE ? OR source_ip LIKE ? OR failure_reason LIKE ? OR trace_task_id LIKE ? OR trace_request_id LIKE ?)",sizeof(where)-strlen(where)-1);
    /* Count, rows and facets observe the same read transaction. */
    if (sqlite3_exec(db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK) goto unavailable;
    snprintf(sql,sizeof(sql),"%s SELECT COUNT(*) FROM records%s",prefix,where);
    if (sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK) goto unavailable;
    audit_bind(st,&f);
    if (sqlite3_step(st)!=SQLITE_ROW) goto unavailable;
    total=sqlite3_column_int64(st,0); sqlite3_finalize(st);st=NULL;
    snprintf(sql,sizeof(sql),"%s SELECT id,ts,actor,app_device_id,action,risk,target,result_value,"
        "failure_reason,failure_stage,source_ip,peer_ip,ip_source,user_agent,api_key_id,before_hash,after_hash,"
        "business_domain,actor_channel,trace_request_id,trace_task_id FROM records%s ORDER BY ts DESC,id DESC LIMIT ? OFFSET ?",prefix,where);
    if (sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK) goto unavailable;
    idx=audit_bind(st,&f);sqlite3_bind_int64(st,idx++,size);sqlite3_bind_int64(st,idx,(page-1)*size);
    items=json_object_new_array();
    while ((rc=sqlite3_step(st))==SQLITE_ROW) {
        static const char *fields[]={"actor","device_id","action","risk","target","result","failure_reason","failure_stage","source_ip","peer_ip","ip_source","user_agent","api_key_id","before_hash","after_hash","domain","channel","request_id","task_id"};
        struct json_object *o=json_object_new_object();
        json_object_object_add(o,"id",json_object_new_int64(sqlite3_column_int64(st,0)));
        json_object_object_add(o,"audit_record_id",json_object_new_int64(sqlite3_column_int64(st,0)));
        json_object_object_add(o,"ts",json_object_new_int64(sqlite3_column_int64(st,1)));
        json_object_object_add(o,"type",json_object_new_string("AUDIT"));
        for(size_t k=0;k<sizeof(fields)/sizeof(fields[0]);k++) json_object_object_add(o,fields[k],json_object_new_string(audit_text(st,(int)k+2)));
        const struct dw_event_domain_definition *domain=dw_event_domain_find(audit_text(st,17));
        json_object_object_add(o,"action_label",json_object_new_string(dw_event_audit_action_label(audit_text(st,4))));
        json_object_object_add(o,"domain_label",json_object_new_string(domain?domain->label_zh:""));
        json_object_object_add(o,"changes_available",json_object_new_boolean(0));
        json_object_array_add(items,o);
    }
    if (rc!=SQLITE_DONE) goto unavailable;
    sqlite3_finalize(st);st=NULL;
    facets=json_object_new_object();
    for(size_t k=0;k<8;k++) {
        snprintf(sql,sizeof(sql),"%s SELECT %s,COUNT(*) FROM records%s GROUP BY %s ORDER BY COUNT(*) DESC,%s LIMIT 100",prefix,audit_cols[k],where,audit_cols[k],audit_cols[k]);
        if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK) goto unavailable;
        audit_bind(st,&f);struct json_object *list=json_object_new_array();json_object_object_add(facets,audit_keys[k],list);
        while((rc=sqlite3_step(st))==SQLITE_ROW) {
            const char *v=audit_text(st,0); if(!v[0])continue;
            struct json_object *o=json_object_new_object();
            json_object_object_add(o,"value",json_object_new_string(v));
            json_object_object_add(o,"count",json_object_new_int64(sqlite3_column_int64(st,1)));
            if(k==6) { const struct dw_event_domain_definition *d=dw_event_domain_find(v); if(d)json_object_object_add(o,"label",json_object_new_string(d->label_zh)); }
            json_object_array_add(list,o);
        }
        if(rc!=SQLITE_DONE)goto unavailable;
        sqlite3_finalize(st);st=NULL;
    }
    sqlite3_exec(db,"COMMIT",NULL,NULL,NULL);sqlite3_close(db);db=NULL;
    struct json_object *pagination=json_object_new_object(),*query=json_object_new_object();
    json_object_object_add(pagination,"number",json_object_new_int64(page));
    json_object_object_add(pagination,"size",json_object_new_int64(size));
    json_object_object_add(pagination,"total",json_object_new_int64(total));
    json_object_object_add(pagination,"pages",json_object_new_int64((total+size-1)/size));
    for(size_t k=0;k<8;k++)if(f.value[k][0])json_object_object_add(query,audit_keys[k],json_object_new_string(f.value[k]));
    json_object_object_add(query,"from",json_object_new_int64(f.from));json_object_object_add(query,"to",json_object_new_int64(f.to));
    json_object_object_add(query,"q",json_object_new_string(f.q));
    data=json_object_new_object();json_object_object_add(data,"items",items);json_object_object_add(data,"page",pagination);
    json_object_object_add(data,"facets",facets);json_object_object_add(data,"query",query);
    ctx->status=200;return webd_envelope(data,"webd.audit.log");
unavailable:
    if(st)sqlite3_finalize(st);if(db)sqlite3_close(db);if(items)json_object_put(items);if(facets)json_object_put(facets);
    ctx->status=503;return webd_error("audit_log_db_unavailable","audit log database unavailable","","webd.audit.log");
}
const struct jmx_api_route audit_log_api_routes[]={
    JMX_API_ROUTE(900,"/api/v1/audit","GET",JMX_API_EXACT,audit_log_records),
    JMX_API_ROUTE(901,"/api/v1/audit/records","GET",JMX_API_EXACT,audit_log_records),
    JMX_API_ROUTE_END,
};
