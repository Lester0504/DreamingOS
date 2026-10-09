/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "../src/dns_policy/ad_dns_control.h"
#include "../src/webd/ad_analyzer.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
static struct json_object *provider(void *ctx,const char *op,struct json_object *b){return ad_dns_handle(ctx,op,b);}
int main(int argc,char **argv) {
    if(argc<7)return 2;
    sqlite3 *db=NULL;if(sqlite3_open(argv[1],&db)!=SQLITE_OK)return 2;
    sqlite3_busy_timeout(db,1500);
    const char *schema="CREATE TABLE IF NOT EXISTS aegis_content_policies(id TEXT PRIMARY KEY,name TEXT DEFAULT '',enabled INTEGER DEFAULT 1,mode TEXT DEFAULT 'basic',scope_json TEXT DEFAULT '{\"type\":\"all\"}',ad_block INTEGER DEFAULT 0,safe_search_json TEXT DEFAULT '{}',categories_json TEXT DEFAULT '[]',schedule_json TEXT DEFAULT '{\"type\":\"always\"}',revision INTEGER DEFAULT 1,apply_state TEXT DEFAULT 'pending',last_error TEXT DEFAULT '',created_at INTEGER DEFAULT 0,updated_at INTEGER DEFAULT 0);CREATE TABLE IF NOT EXISTS aegis_domain_overrides(id TEXT PRIMARY KEY,policy_id TEXT DEFAULT '',domain TEXT,action TEXT,enabled INTEGER DEFAULT 1,note TEXT DEFAULT '',apply_state TEXT DEFAULT 'pending',last_error TEXT DEFAULT '',created_at INTEGER DEFAULT 0,updated_at INTEGER DEFAULT 0,UNIQUE(policy_id,domain));";
    if(sqlite3_exec(db,schema,NULL,NULL,NULL)!=SQLITE_OK)return 3;
    struct ad_dns_environment e={db,argv[2],argv[3],time(NULL),53,NULL};if(ad_dns_init(&e))return 3;
    struct json_object *b=json_tokener_parse(argv[6]),*r=NULL;int status=200;
    if(!strcmp(argv[4],"INIT")||!strcmp(argv[4],"RESTART")||!strcmp(argv[4],"TICK")){int rc=ad_dns_reconcile(&e,strcmp(argv[4],"TICK")!=0);r=json_object_new_object();json_object_object_add(r,"ok",json_object_new_boolean(!rc));}
    else if(!strcmp(argv[4],"PROVIDER"))r=ad_dns_handle(&e,argv[5],b);
    else {char sessions[512],log[512];snprintf(sessions,sizeof(sessions),"%s/sessions.db",argv[2]);snprintf(log,sizeof(log),"%s/queries.log",argv[2]);struct ada_environment a={sessions,log,argv[3],e.now,provider,&e};struct json_object *q=argc>7?json_tokener_parse(argv[7]):json_object_new_object();if(!strcmp(argv[4],"CAPTURE")){status=ada_tick(&a,0);r=json_object_new_object();}else if(!strcmp(argv[4],"RECOVER")){status=ada_tick(&a,1);r=json_object_new_object();}else r=ada_handle(&a,"test-user",1,argv[4],argv[5],q,b,&status);json_object_put(q);}
    if(!r)return 4;json_object_object_add(r,"http_status",json_object_new_int(status));puts(json_object_to_json_string_ext(r,JSON_C_TO_STRING_PLAIN));json_object_put(b);json_object_put(r);sqlite3_close(db);return 0;
}
