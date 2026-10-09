// SPDX-License-Identifier: GPL-2.0-or-later
#include "wan_sla_config.h"
#include "wan_sla_eval.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

struct json_object *wan_sla_config_load(sqlite3 *db, const char *id)
{
    static const char *names[] = {"id","name","enabled","wan","method","targets",
        "interval_s","timeout_ms","loss_threshold_pct","latency_threshold_ms",
        "fail_count","recover_count","remark","revision","created_at","updated_at"};
    sqlite3_stmt *st = NULL;
    struct json_object *out = NULL, *stored = NULL, *profile = NULL, *targets = NULL;
    unsigned i;
    if (sqlite3_prepare_v2(db, "SELECT id,name,enabled,wan,method,targets_json,interval_s,timeout_ms,"
        "loss_threshold_pct,latency_threshold_ms,fail_count,recover_count,remark,revision,created_at,updated_at,profile_json "
        "FROM flowd_wan_health WHERE id=?1", -1, &st, NULL) != SQLITE_OK) return NULL;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) goto done;
    out = json_object_new_object();
    for (i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        const char *text = (const char *)sqlite3_column_text(st,(int)i);
        struct json_object *v;
        if (i==5) {
            targets = text ? json_tokener_parse(text) : NULL;
            if (!targets || !json_object_is_type(targets,json_type_array)) goto invalid;
            v = json_object_get(targets);
        } else if (i==2) v=json_object_new_boolean(sqlite3_column_int(st,(int)i));
        else if ((i>=6 && i<=11) || i>=13) v=json_object_new_int64(sqlite3_column_int64(st,(int)i));
        else v=json_object_new_string(text ? text : "");
        json_object_object_add(out,names[i],v);
    }
    {
        const char *text=(const char *)sqlite3_column_text(st,16);
        stored=text ? json_tokener_parse(text) : NULL;
    }
    if (!stored || !json_object_is_type(stored,json_type_object)) goto invalid;
    profile=wan_sla_profile_normalize(stored,NULL,(int)json_object_array_length(targets));
    if (!profile) goto invalid;
    json_object_object_foreach(profile,key,v) {
        json_object_object_add(out,key,json_object_get(v));
    }
    goto done;
invalid:
    if(out)json_object_put(out);
    out=NULL;
done:
    if(targets)json_object_put(targets);
    if(stored)json_object_put(stored);
    if(profile)json_object_put(profile);
    sqlite3_finalize(st);
    return out;
}

void wan_sla_config_digest(struct json_object *rule, char out[17])
{
    static const char *keys[]={"id","name","enabled","wan","method","targets","interval_s","timeout_ms",
        "loss_threshold_pct","latency_threshold_ms","fail_count","recover_count","remark","revision",
        "reliability","window_s","failure_interval_s","recovery_interval_s","cooldown_s","profile_version",
        "profile","action_mode","aggregation","degraded","critical","down","expected_status","body_marker",
        "dns_servers"};
    struct json_object *canonical=json_object_new_object();
    uint64_t hash=UINT64_C(1469598103934665603);
    const unsigned char *p;
    unsigned i;
    for(i=0;i<sizeof(keys)/sizeof(keys[0]);i++) {
        struct json_object *v=NULL;
        json_object_object_get_ex(rule,keys[i],&v);
        json_object_object_add(canonical,keys[i],json_object_get(v));
    }
    p=(const unsigned char *)json_object_to_json_string_ext(canonical,JSON_C_TO_STRING_PLAIN);
    while(*p){hash^=*p++;hash*=UINT64_C(1099511628211);}
    snprintf(out,17,"%016" PRIx64,hash);
    json_object_put(canonical);
}
