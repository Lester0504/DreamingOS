    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);
    nc_log_alarm_db_init();
    int keep_days = nc_json_int_def(cfg, "keep_days", 7);
    if(keep_days < 1) keep_days = 1; if(keep_days > 365) keep_days = 365;
    sqlite3_int64 cutoff = (sqlite3_int64)nc_now_s() - (sqlite3_int64)keep_days * 86400;
    int pruned_events = 0, pruned_alarms = 0, pruned_deliveries = 0;
    sqlite3_stmt *st = NULL;
    if(nc_prepare(&st, "DELETE FROM log_event WHERE ts < ?") == 0) {
        sqlite3_bind_int64(st, 1, cutoff);
        sqlite3_step(st);
        pruned_events = sqlite3_changes(g_netconfig_db);
        sqlite3_finalize(st);
    }
    if(nc_prepare(&st, "DELETE FROM warning_active WHERE status='resolved' AND resolved_at < ?") == 0) {
        sqlite3_bind_int64(st, 1, cutoff);
        sqlite3_step(st);
        pruned_alarms = sqlite3_changes(g_netconfig_db);
        sqlite3_finalize(st);
    }
    if(nc_prepare(&st, "DELETE FROM notification_delivery WHERE status IN ('delivered','expired') AND updated_at < ?") == 0) {
        sqlite3_bind_int64(st, 1, cutoff);
        sqlite3_step(st);
        pruned_deliveries = sqlite3_changes(g_netconfig_db);
        sqlite3_finalize(st);
    }
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "pruned_events", json_object_new_int(pruned_events));
    json_object_object_add(d, "pruned_alarms", json_object_new_int(pruned_alarms));
    json_object_object_add(d, "pruned_deliveries", json_object_new_int(pruned_deliveries));
    json_object_object_add(d, "keep_days", json_object_new_int(keep_days));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

#include "jmx_release.h"

struct json_object *jmx_log_center_delivery_replay(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);
    nc_log_alarm_db_init();
    int max_retry = nc_json_int_def(cfg, "max_retry", 3);
    if(max_retry < 1) max_retry = 1; if(max_retry > 10) max_retry = 10;
    sqlite3_int64 now = (sqlite3_int64)nc_now_s();
    int replayed = 0;
    sqlite3_stmt *st = NULL;
    /* find failed/leased items eligible for retry */
    if(nc_prepare(&st, "UPDATE notification_delivery SET status='pending',next_retry_at=0,updated_at=? WHERE (status='failed' AND attempts<?) OR (status='leased' AND next_retry_at<?)")==0) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_int(st, 2, max_retry);
        sqlite3_bind_int64(st, 3, now);
        sqlite3_step(st);
        replayed = sqlite3_changes(g_netconfig_db);
        sqlite3_finalize(st);
    }
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "replayed", json_object_new_int(replayed));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_log_center_alarm_summary(struct json_object *cfg)
{
    (void)cfg;
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);
    nc_log_alarm_db_init();
    struct json_object *d = json_object_new_object();
    struct json_object *by_status = json_object_new_object();
    struct json_object *by_level = json_object_new_object();
    int total = 0;
    sqlite3_stmt *st = NULL;
    if(nc_prepare(&st, "SELECT status, COUNT(*) FROM warning_active GROUP BY status")==0) {
        while(sqlite3_step(st)==SQLITE_ROW) {
            const char *s = (const char*)sqlite3_column_text(st, 0);
            int c = sqlite3_column_int(st, 1);
            if(s) json_object_object_add(by_status, s, json_object_new_int(c));
            total += c;
        }
        sqlite3_finalize(st);
    }
    if(nc_prepare(&st, "SELECT level, COUNT(*) FROM warning_active WHERE status='active' GROUP BY level")==0) {
        while(sqlite3_step(st)==SQLITE_ROW) {
            const char *lv = (const char*)sqlite3_column_text(st, 0);
            int c = sqlite3_column_int(st, 1);
            if(lv) json_object_object_add(by_level, lv, json_object_new_int(c));
        }
        sqlite3_finalize(st);
    }
    int pending_deliveries = 0;
    if(nc_prepare(&st, "SELECT COUNT(*) FROM notification_delivery WHERE status='pending'")==0) {
        if(sqlite3_step(st)==SQLITE_ROW) pending_deliveries = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    json_object_object_add(d, "total", json_object_new_int(total));
    json_object_object_add(d, "by_status", by_status);
    json_object_object_add(d, "active_by_level", by_level);
    json_object_object_add(d, "pending_deliveries", json_object_new_int(pending_deliveries));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_log_center_alarm_update(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_alarm_db_init(); const char*action=nc_json_str_def(cfg,"action",""); struct json_object*ids=NULL; if(strcmp(action,"ack")&&strcmp(action,"resolve"))return jmx_gen_api_response_data(API_CODE_ERROR,NULL); if(!json_object_object_get_ex(cfg,"ids",&ids)||!json_object_is_type(ids,json_type_array))return jmx_gen_api_response_data(API_CODE_ERROR,NULL); sqlite3_int64 now=(sqlite3_int64)nc_now_s(); int changed=0; int n=json_object_array_length(ids); for(int i=0;i<n;i++){const char*id=json_object_get_string(json_object_array_get_idx(ids,i)); if(!id||!nc_valid_name(id))continue; sqlite3_stmt*st=NULL; const char*sql=!strcmp(action,"ack")?"UPDATE warning_active SET status='acknowledged',ack_by=?,ack_at=?,updated_at=? WHERE id=?":"UPDATE warning_active SET status='resolved',resolved_at=?,updated_at=? WHERE id=?"; if(nc_prepare(&st,sql)==0){if(!strcmp(action,"ack")){sqlite3_bind_text(st,1,nc_json_str_def(cfg,"user","admin"),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,now);sqlite3_bind_int64(st,3,now);sqlite3_bind_text(st,4,id,-1,SQLITE_TRANSIENT);}else{sqlite3_bind_int64(st,1,now);sqlite3_bind_int64(st,2,now);sqlite3_bind_text(st,3,id,-1,SQLITE_TRANSIENT);}sqlite3_step(st);sqlite3_finalize(st);changed+=sqlite3_changes(g_netconfig_db);}}
    struct json_object*d=json_object_new_object();json_object_object_add(d,"updated",json_object_new_int(changed));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

static void nc_log_delivery_db_init(void)
{
    nc_log_alarm_db_init();
    nc_exec("CREATE TABLE IF NOT EXISTS notification_channel (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,type TEXT NOT NULL,name TEXT NOT NULL,config TEXT NOT NULL DEFAULT '{}',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE TABLE IF NOT EXISTS notification_delivery (id TEXT PRIMARY KEY,alarm_id TEXT NOT NULL DEFAULT '',event_id TEXT NOT NULL DEFAULT '',channel_id TEXT NOT NULL DEFAULT '',channel_type TEXT NOT NULL DEFAULT 'console',status TEXT NOT NULL DEFAULT 'pending',title TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '',target TEXT NOT NULL DEFAULT '',attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,next_retry_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_notification_delivery_status_retry ON notification_delivery(status,next_retry_at,created_at)");
    nc_exec("INSERT OR IGNORE INTO notification_channel(id,enabled,type,name,config,created_at,updated_at) VALUES('console',1,'console','控制台','{}',strftime('%s','now'),strftime('%s','now'))");
}

static int nc_log_alarm_cooldown_sec(struct json_object *o)
{
    const char *rule_id = nc_json_str_def(o, "rule_id", "");
    if (!rule_id[0]) return nc_json_int_def(o, "cooldown_sec", 300);
    sqlite3_stmt *st = NULL; int cd = 300;
    if (nc_prepare(&st, "SELECT cooldown_sec FROM warning_rule WHERE id=?") == 0) {
        sqlite3_bind_text(st, 1, rule_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) cd = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    if (cd < 0) cd = 0; if (cd > 86400) cd = 86400;
    return cd;
}

static int nc_log_delivery_recent_exists(const char *alarm_id, const char *channel_id, sqlite3_int64 since)
{
    sqlite3_stmt *st = NULL; int exists = 0;
    if (nc_prepare(&st, "SELECT 1 FROM notification_delivery WHERE alarm_id=? AND channel_id=? AND created_at>=? LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, alarm_id ? alarm_id : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, channel_id ? channel_id : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, since);
        exists = (sqlite3_step(st) == SQLITE_ROW);
        sqlite3_finalize(st);
    }
    return exists;
}

static void nc_log_delivery_enqueue(const char*alarm_id, struct json_object *o)
{
    nc_log_delivery_db_init(); const char*channels=nc_json_str_def(o,"channel","console"); char buf[256]; snprintf(buf,sizeof(buf),"%s",channels&&channels[0]?channels:"console"); char *save=NULL,*tok=strtok_r(buf,",/; ",&save); sqlite3_int64 now=(sqlite3_int64)nc_now_s(); int cooldown=nc_log_alarm_cooldown_sec(o);
    while(tok){ while(*tok==' ')tok++; if(*tok){ if(cooldown>0 && nc_log_delivery_recent_exists(alarm_id,tok,now-cooldown)){ tok=strtok_r(NULL,",/; ",&save); continue; } char id[128]; snprintf(id,sizeof(id),"del-%08x-%lld",nc_log_hash(alarm_id)^nc_log_hash(tok),(long long)now); sqlite3_stmt*st=NULL; if(nc_prepare(&st,"INSERT OR IGNORE INTO notification_delivery(id,alarm_id,event_id,channel_id,channel_type,status,title,detail,target,created_at,updated_at,next_retry_at) VALUES(?,?,?,?,?,'pending',?,?,?,?,?,?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,alarm_id?alarm_id:"",-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,tok,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,tok,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"title",nc_json_str_def(o,"event","")),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(o,"detail",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"target",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,9,now);sqlite3_bind_int64(st,10,now);sqlite3_bind_int64(st,11,now);sqlite3_step(st);sqlite3_finalize(st);}} tok=strtok_r(NULL,",/; ",&save);}
}

struct json_object *jmx_log_center_delivery_get(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_delivery_db_init(); const char*status=nc_json_str_def(cfg,"status","pending"); int limit=nc_json_int_def(cfg,"limit",200); if(limit<=0||limit>1000)limit=200; char sql[320]; snprintf(sql,sizeof(sql),"SELECT id,alarm_id,event_id,channel_id,channel_type,status,title,detail,target,attempts,last_error,created_at,updated_at,next_retry_at FROM notification_delivery WHERE 1=1 %s ORDER BY created_at DESC LIMIT ?",status[0]?"AND status=?":""); sqlite3_stmt*st=NULL; struct json_object*a=json_object_new_array(); if(nc_prepare(&st,sql)==0){int b=1;if(status[0])sqlite3_bind_text(st,b++,status,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,b++,limit);while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"alarm_id",st,1);nc_add_text(o,"event_id",st,2);nc_add_text(o,"channel_id",st,3);nc_add_text(o,"channel_type",st,4);nc_add_text(o,"status",st,5);nc_add_text(o,"title",st,6);nc_add_text(o,"detail",st,7);nc_add_text(o,"target",st,8);json_object_object_add(o,"attempts",json_object_new_int(sqlite3_column_int(st,9)));nc_add_text(o,"last_error",st,10);json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,11)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,12)));json_object_object_add(o,"next_retry_at",json_object_new_int64(sqlite3_column_int64(st,13)));json_object_array_add(a,o);}sqlite3_finalize(st);} struct json_object*d=json_object_new_object();json_object_object_add(d,"deliveries",a);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_log_center_delivery_update(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_delivery_db_init(); const char*id=nc_json_str_def(cfg,"id",""); const char*status=nc_json_str_def(cfg,"status",""); if(!nc_valid_name(id)||(!strcmp(status,"sent")&&!strcmp(status,"failed")))return jmx_gen_api_response_data(API_CODE_ERROR,NULL); if(strcmp(status,"sent")&&strcmp(status,"failed")&&strcmp(status,"pending")&&strcmp(status,"leased"))return jmx_gen_api_response_data(API_CODE_ERROR,NULL); sqlite3_stmt*st=NULL; sqlite3_int64 now=(sqlite3_int64)nc_now_s(); if(nc_prepare(&st,"UPDATE notification_delivery SET status=?,attempts=attempts+1,last_error=?,updated_at=?,next_retry_at=? WHERE id=?")==0){sqlite3_bind_text(st,1,status,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(cfg,"last_error",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,now);sqlite3_bind_int64(st,4,!strcmp(status,"failed")?now+nc_json_int_def(cfg,"retry_after",300):0);sqlite3_bind_text(st,5,id,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);} struct json_object*d=json_object_new_object();json_object_object_add(d,"updated",json_object_new_int(sqlite3_changes(g_netconfig_db)));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

int jmx_log_center_channels_set(struct json_object *cfg)
{
    if(!cfg||jmx_netconfig_db_init()!=0)return -1; nc_log_delivery_db_init(); struct json_object*arr=NULL; if(!json_object_object_get_ex(cfg,"channels",&arr)||!json_object_is_type(arr,json_type_array))return -1;
    if (nc_txn_begin() != 0) return -1;
    nc_exec("DELETE FROM notification_channel WHERE id!='console'"); sqlite3_int64 now=(sqlite3_int64)nc_now_s(); int rc=0,n=json_object_array_length(arr);
    for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);const char*id=nc_json_str_def(o,"id","");const char*type=nc_json_str_def(o,"type","");const char*name=nc_json_str_def(o,"name",id);if(!nc_valid_name(id)||!type[0]||!name[0]||strlen(name)>64){rc=-1;break;}struct json_object*conf=NULL;json_object_object_get_ex(o,"config",&conf);const char*confstr=conf?json_object_to_json_string(conf):"{}";int enc_len=0;char*enc_conf=nc_channel_config_encrypt(confstr,&enc_len);sqlite3_stmt*st=NULL;if(nc_prepare(&st,"INSERT OR REPLACE INTO notification_channel(id,enabled,type,name,config,created_at,updated_at) VALUES(?,?,?,?,?,COALESCE((SELECT created_at FROM notification_channel WHERE id=?),?),?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,3,type,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,name,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,enc_conf?enc_conf:confstr,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,7,now);sqlite3_bind_int64(st,8,now);if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);}else rc=-1;if(enc_conf)free(enc_conf);if(rc)break;}
    nc_exec(rc==0?"COMMIT":"ROLLBACK"); return rc;
}

struct json_object *jmx_log_center_channels_get(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_delivery_db_init(); struct json_object*a=json_object_new_array(); sqlite3_stmt*st=NULL; if(nc_prepare(&st,"SELECT id,enabled,type,name,config,created_at,updated_at FROM notification_channel ORDER BY id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"type",st,2);nc_add_text(o,"name",st,3);{const char *raw_conf=(const char*)sqlite3_column_text(st,4); char *dec=nc_channel_config_decrypt(raw_conf); json_object_object_add(o,"config",nc_log_redact_channel_config(dec?dec:raw_conf)); if(dec)free(dec);}json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,5)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,6)));json_object_array_add(a,o);}sqlite3_finalize(st);} struct json_object*d=json_object_new_object();json_object_object_add(d,"channels",a);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

static struct json_object *nc_log_redact_channel_config(const char *raw)
{
    struct json_object *cfg=json_tokener_parse(raw?raw:"{}"); if(!cfg)cfg=json_object_new_object();
    const char *keys[]={"password","passwd","token","secret","apikey","api_key","access_token","bot_token","webhook_secret",NULL};
    for(int i=0;keys[i];i++){struct json_object*v=NULL;if(json_object_object_get_ex(cfg,keys[i],&v))json_object_object_add(cfg,keys[i],json_object_new_string("***"));}
    return cfg;
}

static void nc_log_delivery_row_json(struct json_object *a, sqlite3_stmt *st)
{
    struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"alarm_id",st,1);nc_add_text(o,"event_id",st,2);nc_add_text(o,"channel_id",st,3);nc_add_text(o,"channel_type",st,4);nc_add_text(o,"status",st,5);nc_add_text(o,"title",st,6);nc_add_text(o,"detail",st,7);nc_add_text(o,"target",st,8);json_object_object_add(o,"attempts",json_object_new_int(sqlite3_column_int(st,9)));nc_add_text(o,"last_error",st,10);json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,11)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,12)));json_object_object_add(o,"next_retry_at",json_object_new_int64(sqlite3_column_int64(st,13)));json_object_array_add(a,o);
}

struct json_object *jmx_log_center_delivery_claim(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_delivery_db_init(); int limit=nc_json_int_def(cfg,"limit",20); if(limit<=0||limit>100)limit=20; int lease=nc_json_int_def(cfg,"lease_sec",120); if(lease<30)lease=30; if(lease>3600)lease=3600; sqlite3_int64 now=(sqlite3_int64)nc_now_s(); sqlite3_stmt*st=NULL; struct json_object*a=json_object_new_array();
    if(nc_txn_begin()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);
    if(nc_prepare(&st,"SELECT id FROM notification_delivery WHERE (status='pending' OR (status='failed' AND next_retry_at<=?)) AND attempts<10 ORDER BY created_at LIMIT ?")==0){sqlite3_bind_int64(st,1,now);sqlite3_bind_int(st,2,limit);while(sqlite3_step(st)==SQLITE_ROW){const char*id=(const char*)sqlite3_column_text(st,0);sqlite3_stmt*up=NULL;if(id&&nc_prepare(&up,"UPDATE notification_delivery SET status='leased',updated_at=?,next_retry_at=? WHERE id=? AND (status='pending' OR status='failed')")==0){sqlite3_bind_int64(up,1,now);sqlite3_bind_int64(up,2,now+lease);sqlite3_bind_text(up,3,id,-1,SQLITE_TRANSIENT);sqlite3_step(up);sqlite3_finalize(up);}}sqlite3_finalize(st);} nc_exec("COMMIT");
    if(nc_prepare(&st,"SELECT id,alarm_id,event_id,channel_id,channel_type,status,title,detail,target,attempts,last_error,created_at,updated_at,next_retry_at FROM notification_delivery WHERE status='leased' AND updated_at=? ORDER BY created_at LIMIT ?")==0){sqlite3_bind_int64(st,1,now);sqlite3_bind_int(st,2,limit);while(sqlite3_step(st)==SQLITE_ROW)nc_log_delivery_row_json(a,st);sqlite3_finalize(st);} struct json_object*d=json_object_new_object();json_object_object_add(d,"lease_sec",json_object_new_int(lease));json_object_object_add(d,"deliveries",a);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_log_center_delivery_stats(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_delivery_db_init(); struct json_object*d=json_object_new_object(),*by=json_object_new_object(); sqlite3_stmt*st=NULL; if(nc_prepare(&st,"SELECT status,COUNT(*) FROM notification_delivery GROUP BY status")==0){while(sqlite3_step(st)==SQLITE_ROW){json_object_object_add(by,(const char*)sqlite3_column_text(st,0),json_object_new_int64(sqlite3_column_int64(st,1)));}sqlite3_finalize(st);} json_object_object_add(d,"by_status",by); if(nc_prepare(&st,"SELECT channel_id,COUNT(*) FROM notification_delivery WHERE status IN ('pending','failed','leased') GROUP BY channel_id")==0){struct json_object*bc=json_object_new_object();while(sqlite3_step(st)==SQLITE_ROW){json_object_object_add(bc,(const char*)sqlite3_column_text(st,0),json_object_new_int64(sqlite3_column_int64(st,1)));}sqlite3_finalize(st);json_object_object_add(d,"backlog_by_channel",bc);} return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

/* ── System Settings ─────────────────────────────────────────────────── */
static void nc_sys_settings_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS system_settings (id INTEGER PRIMARY KEY CHECK (id = 1),hostname TEXT NOT NULL DEFAULT '',custom_domain TEXT NOT NULL DEFAULT '',timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',language TEXT NOT NULL DEFAULT 'zh-cn',led_policy TEXT NOT NULL DEFAULT 'normal',update_channel TEXT NOT NULL DEFAULT 'stable',packet_steering INTEGER NOT NULL DEFAULT 1,irq_balance INTEGER NOT NULL DEFAULT 1,flow_offloading TEXT NOT NULL DEFAULT 'software',config_backend TEXT NOT NULL DEFAULT 'sqlite_to_uci',description TEXT NOT NULL DEFAULT '',note TEXT NOT NULL DEFAULT '',time_format TEXT NOT NULL DEFAULT '24h',date_format TEXT NOT NULL DEFAULT 'M/D/YY',show_timezone_name INTEGER NOT NULL DEFAULT 1,ntp_mode TEXT NOT NULL DEFAULT 'client',ntp_interval TEXT NOT NULL DEFAULT 'auto',ntp_server_enabled INTEGER NOT NULL DEFAULT 0,ntp_use_dhcp INTEGER NOT NULL DEFAULT 0,log_level TEXT NOT NULL DEFAULT '',kernel_log_level TEXT NOT NULL DEFAULT '',log_buffer_kb INTEGER NOT NULL DEFAULT 0,cron_log_level TEXT NOT NULL DEFAULT 'disabled',remote_log_enabled INTEGER NOT NULL DEFAULT 0,remote_log_host TEXT NOT NULL DEFAULT '',remote_log_port INTEGER NOT NULL DEFAULT 514,remote_log_protocol TEXT NOT NULL DEFAULT 'udp',log_file_path TEXT NOT NULL DEFAULT '/tmp/system.log',table_filter INTEGER NOT NULL DEFAULT 0,interface_density TEXT NOT NULL DEFAULT 'comfortable',number_format TEXT NOT NULL DEFAULT 'auto',last_time_sync_at INTEGER NOT NULL DEFAULT 0,apply_state TEXT NOT NULL DEFAULT 'pending',last_apply_at INTEGER NOT NULL DEFAULT 0,apply_error TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_add_column_if_missing("system_settings", "memory_mode", "TEXT NOT NULL DEFAULT 'auto'");
    nc_add_column_if_missing("system_settings", "memory_revision", "INTEGER NOT NULL DEFAULT 1");
    nc_add_column_if_missing("system_settings", "memory_activated_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("system_settings", "custom_domain", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("system_settings", "last_time_sync_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("system_settings", "log_level", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("system_settings", "kernel_log_level", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("system_settings", "log_buffer_kb", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("system_settings", "cron_log_level", "TEXT NOT NULL DEFAULT 'disabled'");
    nc_add_column_if_missing("system_settings", "remote_log_enabled", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("system_settings", "remote_log_host", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("system_settings", "remote_log_port", "INTEGER NOT NULL DEFAULT 514");
    nc_add_column_if_missing("system_settings", "remote_log_protocol", "TEXT NOT NULL DEFAULT 'udp'");
    nc_add_column_if_missing("system_settings", "log_file_path", "TEXT NOT NULL DEFAULT '/tmp/system.log'");
    nc_add_column_if_missing("system_settings", "table_filter", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("system_settings", "interface_density", "TEXT NOT NULL DEFAULT 'comfortable'");
    nc_add_column_if_missing("system_settings", "number_format", "TEXT NOT NULL DEFAULT 'auto'");
    nc_add_column_if_missing("system_settings", "apply_state", "TEXT NOT NULL DEFAULT 'pending'");
    nc_add_column_if_missing("system_settings", "last_apply_at", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("system_settings", "apply_error", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("system_settings", "description", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("system_settings", "note", "TEXT NOT NULL DEFAULT ''");
    nc_add_column_if_missing("system_settings", "time_format", "TEXT NOT NULL DEFAULT '24h'");
    nc_add_column_if_missing("system_settings", "date_format", "TEXT NOT NULL DEFAULT 'M/D/YY'");
    nc_add_column_if_missing("system_settings", "show_timezone_name", "INTEGER NOT NULL DEFAULT 1");
    nc_add_column_if_missing("system_settings", "ntp_mode", "TEXT NOT NULL DEFAULT 'client'");
    nc_add_column_if_missing("system_settings", "ntp_interval", "TEXT NOT NULL DEFAULT 'auto'");
    nc_add_column_if_missing("system_settings", "ntp_server_enabled", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("system_settings", "ntp_use_dhcp", "INTEGER NOT NULL DEFAULT 0");
    nc_exec("CREATE TABLE IF NOT EXISTS system_ntp_server (id TEXT PRIMARY KEY,server TEXT NOT NULL,priority INTEGER NOT NULL DEFAULT 100,enabled INTEGER NOT NULL DEFAULT 1)");
    nc_exec("CREATE TABLE IF NOT EXISTS system_cron_job (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,schedule TEXT NOT NULL,command TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE TABLE IF NOT EXISTS disabled_function (code TEXT PRIMARY KEY,reason TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT 'auto',updated_at INTEGER NOT NULL)");
    nc_exec("CREATE TABLE IF NOT EXISTS system_ui_settings (id INTEGER PRIMARY KEY CHECK (id = 1),ui_mode TEXT NOT NULL DEFAULT 'calm',sidebar_collapsed INTEGER NOT NULL DEFAULT 1,default_view TEXT NOT NULL DEFAULT 'overview',show_status_rail INTEGER NOT NULL DEFAULT 1,animation_level TEXT NOT NULL DEFAULT 'balanced',density TEXT NOT NULL DEFAULT 'comfortable',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS appearance_settings (id INTEGER PRIMARY KEY CHECK (id = 1),accent_color TEXT NOT NULL DEFAULT 'violet',glass_opacity REAL NOT NULL DEFAULT 0.06,glass_highlight REAL NOT NULL DEFAULT 0.28,glass_blur REAL NOT NULL DEFAULT 3.2,glass_saturate INTEGER NOT NULL DEFAULT 140,glass_neutral_color TEXT NOT NULL DEFAULT '10 16 25',glass_border_width REAL NOT NULL DEFAULT 1.0,glass_border_color TEXT NOT NULL DEFAULT '#25FFFFFF',glass_preserve_center INTEGER NOT NULL DEFAULT 1,menu_glass_mode TEXT NOT NULL DEFAULT 'shader',menu_glass_displacement_scale REAL NOT NULL DEFAULT 80.0,menu_glass_blur_amount REAL NOT NULL DEFAULT 0.0,menu_glass_saturation INTEGER NOT NULL DEFAULT 140,menu_glass_aberration_intensity REAL NOT NULL DEFAULT 2.0,menu_glass_corner_radius REAL NOT NULL DEFAULT 0.0,menu_glass_over_light INTEGER NOT NULL DEFAULT 0,menu_glass_highlight_angle REAL NOT NULL DEFAULT 135.0,wallpaper_enabled INTEGER NOT NULL DEFAULT 0,wallpaper_directory TEXT NOT NULL DEFAULT '/www/dreamingwrt/static/background',wallpaper_image TEXT NOT NULL DEFAULT '',wallpaper_opacity REAL NOT NULL DEFAULT 0.16,wallpaper_mode TEXT NOT NULL DEFAULT 'argon',wallpaper_interval TEXT NOT NULL DEFAULT 'medium',login_enabled INTEGER NOT NULL DEFAULT 1,login_image TEXT NOT NULL DEFAULT '',login_opacity REAL NOT NULL DEFAULT 1.0,login_mode TEXT NOT NULL DEFAULT 'argon',login_interval TEXT NOT NULL DEFAULT 'medium',theme_family TEXT NOT NULL DEFAULT 'liquid-glass',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("INSERT OR IGNORE INTO system_settings(id) VALUES(1)");
    nc_exec("INSERT OR IGNORE INTO system_ui_settings(id) VALUES(1)");
    nc_exec("INSERT OR IGNORE INTO appearance_settings(id) VALUES(1)");
    /* Old databases predate theme_family; CREATE IF NOT EXISTS never backfills a
     * column, so add it idempotently. nc_add_column_if_missing checks the column
     * first, so a duplicate is a silent no-op and the default keeps visuals stable. */
    nc_add_column_if_missing("appearance_settings", "theme_family",
                             "TEXT NOT NULL DEFAULT 'liquid-glass'");
}

struct nc_appearance_config {
    char accent_color[32];
    double glass_opacity;
    double glass_highlight;
    double glass_blur;
    int glass_saturate;
    char glass_neutral_color[32];
    double glass_border_width;
    char glass_border_color[32];
    int glass_preserve_center;
    char menu_glass_mode[16];
    double menu_glass_displacement_scale;
    double menu_glass_blur_amount;
    int menu_glass_saturation;
    double menu_glass_aberration_intensity;
    double menu_glass_corner_radius;
    int menu_glass_over_light;
    double menu_glass_highlight_angle;
    int wallpaper_enabled;
    char wallpaper_directory[256];
    char wallpaper_image[128];
    double wallpaper_opacity;
    char wallpaper_mode[32];
    char wallpaper_interval[32];
    int login_enabled;
    char login_image[128];
    double login_opacity;
    char login_mode[32];
    char login_interval[32];
    char theme_family[24];
};

static int nc_appearance_load(struct nc_appearance_config *out)
{
    sqlite3_stmt *st = NULL;

    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    snprintf(out->accent_color, sizeof(out->accent_color), "%s", "violet");
    out->glass_opacity = 0.06;
    out->glass_highlight = 0.28;
    out->glass_blur = 3.2;
    out->glass_saturate = 140;
    snprintf(out->glass_neutral_color, sizeof(out->glass_neutral_color), "%s", "10 16 25");
    out->glass_border_width = 1.0;
    snprintf(out->glass_border_color, sizeof(out->glass_border_color), "%s", "#25FFFFFF");
    out->glass_preserve_center = 1;
    snprintf(out->menu_glass_mode, sizeof(out->menu_glass_mode), "%s", "shader");
    out->menu_glass_displacement_scale = 80.0;
    out->menu_glass_blur_amount = 0.0;
    out->menu_glass_saturation = 140;
    out->menu_glass_aberration_intensity = 2.0;
    out->menu_glass_corner_radius = 0.0;
    out->menu_glass_over_light = 0;
    out->menu_glass_highlight_angle = 135.0;
    snprintf(out->wallpaper_directory, sizeof(out->wallpaper_directory), "%s",
             "/www/dreamingwrt/static/background");
    out->wallpaper_opacity = 0.16;
    snprintf(out->wallpaper_mode, sizeof(out->wallpaper_mode), "%s", "argon");
    snprintf(out->wallpaper_interval, sizeof(out->wallpaper_interval), "%s", "medium");
    out->login_enabled = 1;
    out->login_opacity = 1.0;
    snprintf(out->login_mode, sizeof(out->login_mode), "%s", "argon");
    snprintf(out->login_interval, sizeof(out->login_interval), "%s", "medium");
    snprintf(out->theme_family, sizeof(out->theme_family), "%s", "liquid-glass");

    if (!g_netconfig_db || nc_prepare(&st,
        "SELECT accent_color,glass_opacity,glass_highlight,glass_blur,glass_saturate,"
        "glass_neutral_color,glass_border_width,glass_border_color,glass_preserve_center,"
        "menu_glass_mode,menu_glass_displacement_scale,menu_glass_blur_amount,"
        "menu_glass_saturation,menu_glass_aberration_intensity,menu_glass_corner_radius,"
        "menu_glass_over_light,menu_glass_highlight_angle,wallpaper_enabled,"
        "wallpaper_directory,wallpaper_image,wallpaper_opacity,wallpaper_mode,"
        "wallpaper_interval,login_enabled,login_image,login_opacity,login_mode,"
        "login_interval,theme_family FROM appearance_settings WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
#define NC_APPEARANCE_TEXT(_field, _col) do { \
        const char *text = (const char *)sqlite3_column_text(st, (_col)); \
        snprintf(out->_field, sizeof(out->_field), "%s", text ? text : ""); \
    } while (0)
    NC_APPEARANCE_TEXT(accent_color, 0);
    out->glass_opacity = sqlite3_column_double(st, 1);
    out->glass_highlight = sqlite3_column_double(st, 2);
    out->glass_blur = sqlite3_column_double(st, 3);
    out->glass_saturate = sqlite3_column_int(st, 4);
    NC_APPEARANCE_TEXT(glass_neutral_color, 5);
    out->glass_border_width = sqlite3_column_double(st, 6);
    NC_APPEARANCE_TEXT(glass_border_color, 7);
    out->glass_preserve_center = sqlite3_column_int(st, 8);
    NC_APPEARANCE_TEXT(menu_glass_mode, 9);
    out->menu_glass_displacement_scale = sqlite3_column_double(st, 10);
    out->menu_glass_blur_amount = sqlite3_column_double(st, 11);
    out->menu_glass_saturation = sqlite3_column_int(st, 12);
    out->menu_glass_aberration_intensity = sqlite3_column_double(st, 13);
    out->menu_glass_corner_radius = sqlite3_column_double(st, 14);
    out->menu_glass_over_light = sqlite3_column_int(st, 15);
    out->menu_glass_highlight_angle = sqlite3_column_double(st, 16);
    out->wallpaper_enabled = sqlite3_column_int(st, 17);
    NC_APPEARANCE_TEXT(wallpaper_directory, 18);
    NC_APPEARANCE_TEXT(wallpaper_image, 19);
    out->wallpaper_opacity = sqlite3_column_double(st, 20);
    NC_APPEARANCE_TEXT(wallpaper_mode, 21);
    NC_APPEARANCE_TEXT(wallpaper_interval, 22);
    out->login_enabled = sqlite3_column_int(st, 23);
    NC_APPEARANCE_TEXT(login_image, 24);
    out->login_opacity = sqlite3_column_double(st, 25);
    NC_APPEARANCE_TEXT(login_mode, 26);
    NC_APPEARANCE_TEXT(login_interval, 27);
    NC_APPEARANCE_TEXT(theme_family, 28);
#undef NC_APPEARANCE_TEXT
    /* Defensive read fallback: a corrupt or pre-migration value must never leak
     * out or poison sibling fields. Coerce anything unrecognized to liquid-glass. */
    if (strcmp(out->theme_family, "liquid-glass") &&
        strcmp(out->theme_family, "frosted-glass") &&
        strcmp(out->theme_family, "traditional"))
        snprintf(out->theme_family, sizeof(out->theme_family), "%s", "liquid-glass");
    sqlite3_finalize(st);
    return 0;
}

static int nc_appearance_accent_ok(const char *value)
{
    static const char *presets[] = {
        "violet", "blue", "emerald", "rose", "amber", "indigo", "cyan", "teal", "slate", NULL
    };
    int i;

    if (!value || !value[0]) return 0;
    if (value[0] == '#' && strlen(value) == 7) {
        for (i = 1; i < 7; i++) if (!isxdigit((unsigned char)value[i])) return 0;
        return 1;
    }
    for (i = 0; presets[i]; i++) if (!strcmp(value, presets[i])) return 1;
    return 0;
}

static int nc_appearance_mode_ok(const char *value)
{
    return value && (!strcmp(value, "argon") || !strcmp(value, "fixed") ||
                     !strcmp(value, "interval"));
}

static int nc_appearance_interval_ok(const char *value)
{
    return value && (!strcmp(value, "medium") || !strcmp(value, "slow") ||
                     !strcmp(value, "relaxed") || !strcmp(value, "long"));
}

static int nc_menu_glass_mode_ok(const char *value)
{
    return value && (!strcmp(value, "shader") || !strcmp(value, "standard") ||
                     !strcmp(value, "prominent") || !strcmp(value, "polar"));
}

/* theme_family selects the UI material family and is orthogonal to menu_glass_mode
 * (mode is the liquid family's render-precision tier, only meaningful under
 * liquid-glass). This gate only widens what validates; it never touches mode. */
static int nc_appearance_theme_family_ok(const char *value)
{
    return value && (!strcmp(value, "liquid-glass") ||
                     !strcmp(value, "frosted-glass") ||
                     !strcmp(value, "traditional"));
}

static int nc_appearance_directory_ok(const char *value)
{
    static const char *roots[] = {
        "/www/dreamingwrt/static/background",
        NULL
    };
    int i;

    if (!value || !value[0] || strlen(value) >= 256 || strstr(value, "..") ||
        strchr(value, '\n') || strchr(value, '\r')) return 0;
    for (i = 0; roots[i]; i++) {
        size_t n = strlen(roots[i]);
        if (!strncmp(value, roots[i], n) && (value[n] == '\0' || value[n] == '/')) return 1;
    }
    return 0;
}

static int nc_appearance_image_ok(const char *value)
{
    const char *ext;
    if (!value || !value[0]) return 1;
    if (strlen(value) >= 128 || value[0] == '.' || strstr(value, "..") ||
        strchr(value, '/') || strchr(value, '\\') || strchr(value, '\n') || strchr(value, '\r')) return 0;
    ext = strrchr(value, '.');
    return ext && (!strcasecmp(ext, ".jpg") || !strcasecmp(ext, ".jpeg") ||
                   !strcasecmp(ext, ".png") || !strcasecmp(ext, ".gif") ||
                   !strcasecmp(ext, ".webp") || !strcasecmp(ext, ".mp4") ||
                   !strcasecmp(ext, ".webm"));
}

static int nc_json_is_number(struct json_object *value)
{
    return value && (json_object_is_type(value, json_type_int) ||
                     json_object_is_type(value, json_type_double));
}

static int nc_json_copy_string(struct json_object *value, char *out, size_t out_len)
{
    const char *text;
    if (!value || !json_object_is_type(value, json_type_string) || !out || out_len == 0)
        return -1;
    text = json_object_get_string(value);
    if (!text || strlen(text) >= out_len) return -1;
    snprintf(out, out_len, "%s", text);
    return 0;
}

static int nc_appearance_neutral_color_ok(const char *value)
{
    int r, g, b;
    char tail;

    return value && sscanf(value, "%d %d %d %c", &r, &g, &b, &tail) == 3 &&
           r >= 0 && r <= 255 && g >= 0 && g <= 255 && b >= 0 && b <= 255;
}

static int nc_appearance_border_color_ok(const char *value)
{
    size_t n;
    int i;

    if (!value || value[0] != '#') return 0;
    n = strlen(value);
    if (n != 7 && n != 9) return 0;
    for (i = 1; i < (int)n; i++) if (!isxdigit((unsigned char)value[i])) return 0;
    return 1;
}

static int nc_appearance_patch(struct json_object *dw, struct nc_appearance_config *cfg)
{
    struct json_object *wall = NULL, *material = NULL, *menu_glass = NULL, *value = NULL;
    int unified = 0;

    if (!dw || !json_object_is_type(dw, json_type_object) || !cfg) return -1;
    if (json_object_object_get_ex(dw, "accent_color", &value) &&
        nc_json_copy_string(value, cfg->accent_color, sizeof(cfg->accent_color)) != 0) return -1;
    if (json_object_object_get_ex(dw, "material_glass", &material) && material) {
        if (!json_object_is_type(material, json_type_object)) return -1;
        unified = 1;
        if (json_object_object_get_ex(material, "mode", &value) &&
            nc_json_copy_string(value, cfg->menu_glass_mode, sizeof(cfg->menu_glass_mode)) != 0) return -1;
        if (json_object_object_get_ex(material, "base_blur", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->glass_blur = json_object_get_double(value);
        }
        if (json_object_object_get_ex(material, "neutral_density", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->glass_opacity = json_object_get_double(value);
        }
        if (json_object_object_get_ex(material, "neutral_color", &value) &&
            nc_json_copy_string(value, cfg->glass_neutral_color, sizeof(cfg->glass_neutral_color)) != 0) return -1;
        if (json_object_object_get_ex(material, "saturation", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->glass_saturate = json_object_get_int(value);
            cfg->menu_glass_saturation = cfg->glass_saturate;
        }
        if (json_object_object_get_ex(material, "displacement_scale", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->menu_glass_displacement_scale = json_object_get_double(value);
        }
        if (json_object_object_get_ex(material, "aberration_intensity", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->menu_glass_aberration_intensity = json_object_get_double(value);
        }
        if (json_object_object_get_ex(material, "border_width", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->glass_border_width = json_object_get_double(value);
        }
        if (json_object_object_get_ex(material, "border_color", &value) &&
            nc_json_copy_string(value, cfg->glass_border_color, sizeof(cfg->glass_border_color)) != 0) return -1;
        if (json_object_object_get_ex(material, "highlight", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->glass_highlight = json_object_get_double(value);
        }
        if (json_object_object_get_ex(material, "highlight_angle", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->menu_glass_highlight_angle = json_object_get_double(value);
        }
        if (json_object_object_get_ex(material, "preserve_center", &value)) {
            if (!json_object_is_type(value, json_type_boolean)) return -1;
            cfg->glass_preserve_center = json_object_get_boolean(value);
        }
        if (json_object_object_get_ex(material, "theme_family", &value) &&
            nc_json_copy_string(value, cfg->theme_family, sizeof(cfg->theme_family)) != 0) return -1;
    }
    if (!unified && json_object_object_get_ex(dw, "glass_opacity", &value)) {
        if (!nc_json_is_number(value)) return -1;
        cfg->glass_opacity = json_object_get_double(value);
    }
    if (!unified && json_object_object_get_ex(dw, "glass_highlight", &value)) {
        if (!nc_json_is_number(value)) return -1;
        cfg->glass_highlight = json_object_get_double(value);
    }
    if (!unified && json_object_object_get_ex(dw, "glass_blur", &value)) {
        if (!nc_json_is_number(value)) return -1;
        cfg->glass_blur = json_object_get_double(value);
    }
    if (!unified && json_object_object_get_ex(dw, "glass_saturate", &value)) {
        if (!nc_json_is_number(value)) return -1;
        cfg->glass_saturate = json_object_get_int(value);
        cfg->menu_glass_saturation = cfg->glass_saturate;
    }
    if (!unified && json_object_object_get_ex(dw, "menu_liquid_glass", &menu_glass) && menu_glass) {
        if (!json_object_is_type(menu_glass, json_type_object)) return -1;
        if (json_object_object_get_ex(menu_glass, "mode", &value) &&
            nc_json_copy_string(value, cfg->menu_glass_mode, sizeof(cfg->menu_glass_mode)) != 0) return -1;
        if (json_object_object_get_ex(menu_glass, "displacement_scale", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->menu_glass_displacement_scale = json_object_get_double(value);
        }
        if (json_object_object_get_ex(menu_glass, "saturation", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->menu_glass_saturation = json_object_get_int(value);
            cfg->glass_saturate = cfg->menu_glass_saturation;
        }
        if (json_object_object_get_ex(menu_glass, "aberration_intensity", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->menu_glass_aberration_intensity = json_object_get_double(value);
        }
        if (json_object_object_get_ex(menu_glass, "highlight_angle", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->menu_glass_highlight_angle = json_object_get_double(value);
        }
    }
    if (json_object_object_get_ex(dw, "wallpaper", &wall) && wall) {
        if (!json_object_is_type(wall, json_type_object)) return -1;
        if (json_object_object_get_ex(wall, "enabled", &value)) {
            if (!json_object_is_type(value, json_type_boolean)) return -1;
            cfg->wallpaper_enabled = json_object_get_boolean(value);
        }
        if (json_object_object_get_ex(wall, "directory", &value) &&
            nc_json_copy_string(value, cfg->wallpaper_directory, sizeof(cfg->wallpaper_directory)) != 0) return -1;
        if (json_object_object_get_ex(wall, "image", &value) &&
            nc_json_copy_string(value, cfg->wallpaper_image, sizeof(cfg->wallpaper_image)) != 0) return -1;
        if (json_object_object_get_ex(wall, "opacity", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->wallpaper_opacity = json_object_get_double(value);
        }
        if (json_object_object_get_ex(wall, "mode", &value) &&
            nc_json_copy_string(value, cfg->wallpaper_mode, sizeof(cfg->wallpaper_mode)) != 0) return -1;
        if (json_object_object_get_ex(wall, "interval", &value) &&
            nc_json_copy_string(value, cfg->wallpaper_interval, sizeof(cfg->wallpaper_interval)) != 0) return -1;
        if (json_object_object_get_ex(wall, "login_enabled", &value)) {
            if (!json_object_is_type(value, json_type_boolean)) return -1;
            cfg->login_enabled = json_object_get_boolean(value);
        }
        if (json_object_object_get_ex(wall, "login_image", &value) &&
            nc_json_copy_string(value, cfg->login_image, sizeof(cfg->login_image)) != 0) return -1;
        if (json_object_object_get_ex(wall, "login_opacity", &value)) {
            if (!nc_json_is_number(value)) return -1;
            cfg->login_opacity = json_object_get_double(value);
        }
        if (json_object_object_get_ex(wall, "login_mode", &value) &&
            nc_json_copy_string(value, cfg->login_mode, sizeof(cfg->login_mode)) != 0) return -1;
        if (json_object_object_get_ex(wall, "login_interval", &value) &&
            nc_json_copy_string(value, cfg->login_interval, sizeof(cfg->login_interval)) != 0) return -1;
    }
    return nc_appearance_accent_ok(cfg->accent_color) &&
           isfinite(cfg->glass_opacity) &&
           cfg->glass_opacity >= 0.025 && cfg->glass_opacity <= 0.18 &&
           isfinite(cfg->glass_highlight) &&
           cfg->glass_highlight >= 0.0 && cfg->glass_highlight <= 0.65 &&
           isfinite(cfg->glass_blur) && cfg->glass_blur >= 0.0 && cfg->glass_blur <= 16.0 &&
           cfg->glass_saturate >= 70 && cfg->glass_saturate <= 220 &&
           nc_appearance_neutral_color_ok(cfg->glass_neutral_color) &&
           isfinite(cfg->glass_border_width) &&
           cfg->glass_border_width >= 0.0 && cfg->glass_border_width <= 2.0 &&
           nc_appearance_border_color_ok(cfg->glass_border_color) &&
           nc_menu_glass_mode_ok(cfg->menu_glass_mode) &&
           nc_appearance_theme_family_ok(cfg->theme_family) &&
           isfinite(cfg->menu_glass_displacement_scale) &&
           cfg->menu_glass_displacement_scale >= 0.0 && cfg->menu_glass_displacement_scale <= 180.0 &&
           cfg->menu_glass_saturation >= 70 && cfg->menu_glass_saturation <= 220 &&
           isfinite(cfg->menu_glass_aberration_intensity) &&
           cfg->menu_glass_aberration_intensity >= 0.0 && cfg->menu_glass_aberration_intensity <= 8.0 &&
           isfinite(cfg->menu_glass_highlight_angle) &&
           cfg->menu_glass_highlight_angle >= 0.0 && cfg->menu_glass_highlight_angle <= 360.0 &&
           nc_appearance_directory_ok(cfg->wallpaper_directory) &&
           nc_appearance_image_ok(cfg->wallpaper_image) &&
           isfinite(cfg->wallpaper_opacity) &&
           cfg->wallpaper_opacity >= 0.0 && cfg->wallpaper_opacity <= 1.0 &&
           nc_appearance_mode_ok(cfg->wallpaper_mode) &&
           nc_appearance_interval_ok(cfg->wallpaper_interval) &&
           nc_appearance_image_ok(cfg->login_image) &&
           isfinite(cfg->login_opacity) &&
           cfg->login_opacity >= 0.0 && cfg->login_opacity <= 1.0 &&
           nc_appearance_mode_ok(cfg->login_mode) &&
           nc_appearance_interval_ok(cfg->login_interval) ? 0 : -1;
}

static int nc_appearance_requested(struct json_object *dw)
{
    static const char *fields[] = {
        "accent_color", "glass_opacity", "glass_highlight", "glass_blur",
        "material_glass", "glass_saturate", "menu_liquid_glass", "wallpaper", NULL
    };
    struct json_object *value = NULL;
    int i;

    if (!dw || !json_object_is_type(dw, json_type_object)) return 0;
    for (i = 0; fields[i]; i++)
        if (json_object_object_get_ex(dw, fields[i], &value)) return 1;
    return 0;
}

static int nc_appearance_save(const struct nc_appearance_config *cfg,
                              sqlite3_int64 updated_at)
{
    sqlite3_stmt *st = NULL;
    int idx = 1;

    if (!cfg || nc_prepare(&st,
        "UPDATE appearance_settings SET accent_color=?,glass_opacity=?,glass_highlight=?,"
        "glass_blur=?,glass_saturate=?,glass_neutral_color=?,glass_border_width=?,"
        "glass_border_color=?,glass_preserve_center=?,menu_glass_mode=?,"
        "menu_glass_displacement_scale=?,menu_glass_blur_amount=?,menu_glass_saturation=?,"
        "menu_glass_aberration_intensity=?,menu_glass_corner_radius=?,menu_glass_over_light=?,"
        "menu_glass_highlight_angle=?,wallpaper_enabled=?,wallpaper_directory=?,"
        "wallpaper_image=?,wallpaper_opacity=?,wallpaper_mode=?,wallpaper_interval=?,"
        "login_enabled=?,login_image=?,login_opacity=?,login_mode=?,login_interval=?,"
        "theme_family=?,updated_at=? WHERE id=1") != 0)
        return -1;
#define NC_BIND_TEXT(_value) sqlite3_bind_text(st, idx++, (_value), -1, SQLITE_TRANSIENT)
#define NC_BIND_DOUBLE(_value) sqlite3_bind_double(st, idx++, (_value))
#define NC_BIND_INT(_value) sqlite3_bind_int(st, idx++, (_value))
    NC_BIND_TEXT(cfg->accent_color);
    NC_BIND_DOUBLE(cfg->glass_opacity);
    NC_BIND_DOUBLE(cfg->glass_highlight);
    NC_BIND_DOUBLE(cfg->glass_blur);
    NC_BIND_INT(cfg->glass_saturate);
    NC_BIND_TEXT(cfg->glass_neutral_color);
    NC_BIND_DOUBLE(cfg->glass_border_width);
    NC_BIND_TEXT(cfg->glass_border_color);
    NC_BIND_INT(cfg->glass_preserve_center);
    NC_BIND_TEXT(cfg->menu_glass_mode);
    NC_BIND_DOUBLE(cfg->menu_glass_displacement_scale);
    NC_BIND_DOUBLE(cfg->menu_glass_blur_amount);
    NC_BIND_INT(cfg->menu_glass_saturation);
    NC_BIND_DOUBLE(cfg->menu_glass_aberration_intensity);
    NC_BIND_DOUBLE(cfg->menu_glass_corner_radius);
    NC_BIND_INT(cfg->menu_glass_over_light);
    NC_BIND_DOUBLE(cfg->menu_glass_highlight_angle);
    NC_BIND_INT(cfg->wallpaper_enabled);
    NC_BIND_TEXT(cfg->wallpaper_directory);
    NC_BIND_TEXT(cfg->wallpaper_image);
    NC_BIND_DOUBLE(cfg->wallpaper_opacity);
    NC_BIND_TEXT(cfg->wallpaper_mode);
    NC_BIND_TEXT(cfg->wallpaper_interval);
    NC_BIND_INT(cfg->login_enabled);
    NC_BIND_TEXT(cfg->login_image);
    NC_BIND_DOUBLE(cfg->login_opacity);
    NC_BIND_TEXT(cfg->login_mode);
    NC_BIND_TEXT(cfg->login_interval);
    NC_BIND_TEXT(cfg->theme_family);
    sqlite3_bind_int64(st, idx++, updated_at);
#undef NC_BIND_TEXT
#undef NC_BIND_DOUBLE
#undef NC_BIND_INT
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return sqlite3_changes(g_netconfig_db) == 1 ? 0 : -1;
}

static void nc_appearance_to_json(const struct nc_appearance_config *cfg,
                                  struct json_object *dw, struct json_object *wall)
{
    struct json_object *material_glass;
    struct json_object *menu_glass;
    if (!cfg || !dw || !wall) return;
    json_object_object_add(dw, "accent_color", json_object_new_string(cfg->accent_color));
    json_object_object_add(dw, "glass_opacity", json_object_new_double(cfg->glass_opacity));
    json_object_object_add(dw, "glass_highlight", json_object_new_double(cfg->glass_highlight));
    json_object_object_add(dw, "glass_blur", json_object_new_double(cfg->glass_blur));
    json_object_object_add(dw, "glass_saturate", json_object_new_int(cfg->glass_saturate));
    material_glass = json_object_new_object();
    json_object_object_add(material_glass, "version", json_object_new_int(1));
    json_object_object_add(material_glass, "mode", json_object_new_string(cfg->menu_glass_mode));
    json_object_object_add(material_glass, "base_blur", json_object_new_double(cfg->glass_blur));
    json_object_object_add(material_glass, "neutral_density", json_object_new_double(cfg->glass_opacity));
    json_object_object_add(material_glass, "neutral_color", json_object_new_string(cfg->glass_neutral_color));
    json_object_object_add(material_glass, "saturation", json_object_new_int(cfg->glass_saturate));
    json_object_object_add(material_glass, "displacement_scale", json_object_new_double(cfg->menu_glass_displacement_scale));
    json_object_object_add(material_glass, "aberration_intensity", json_object_new_double(cfg->menu_glass_aberration_intensity));
    json_object_object_add(material_glass, "border_width", json_object_new_double(cfg->glass_border_width));
    json_object_object_add(material_glass, "border_color", json_object_new_string(cfg->glass_border_color));
    json_object_object_add(material_glass, "highlight", json_object_new_double(cfg->glass_highlight));
    json_object_object_add(material_glass, "highlight_angle", json_object_new_double(cfg->menu_glass_highlight_angle));
    json_object_object_add(material_glass, "preserve_center", json_object_new_boolean(cfg->glass_preserve_center));
    json_object_object_add(material_glass, "renderer", json_object_new_string("host-tiered"));
    json_object_object_add(material_glass, "theme_family", json_object_new_string(cfg->theme_family));
    json_object_object_add(material_glass, "source", json_object_new_string("config.db:appearance_settings"));
    json_object_object_add(dw, "material_glass", material_glass);
    menu_glass = json_object_new_object();
    json_object_object_add(menu_glass, "mode", json_object_new_string(cfg->menu_glass_mode));
    json_object_object_add(menu_glass, "displacement_scale", json_object_new_double(cfg->menu_glass_displacement_scale));
    json_object_object_add(menu_glass, "blur_amount", json_object_new_double(cfg->menu_glass_blur_amount));
    json_object_object_add(menu_glass, "saturation", json_object_new_int(cfg->menu_glass_saturation));
    json_object_object_add(menu_glass, "aberration_intensity", json_object_new_double(cfg->menu_glass_aberration_intensity));
    json_object_object_add(menu_glass, "corner_radius", json_object_new_double(cfg->menu_glass_corner_radius));
    json_object_object_add(menu_glass, "over_light", json_object_new_boolean(cfg->menu_glass_over_light));
    json_object_object_add(menu_glass, "highlight_angle", json_object_new_double(cfg->menu_glass_highlight_angle));
    json_object_object_add(menu_glass, "preserve_center", json_object_new_boolean(cfg->glass_preserve_center));
    json_object_object_add(menu_glass, "renderer", json_object_new_string("svg-explicit-sampling"));
    json_object_object_add(dw, "menu_liquid_glass", menu_glass);
    json_object_object_add(wall, "enabled", json_object_new_boolean(cfg->wallpaper_enabled));
    json_object_object_add(wall, "directory", json_object_new_string(cfg->wallpaper_directory));
    json_object_object_add(wall, "image", json_object_new_string(cfg->wallpaper_image));
    json_object_object_add(wall, "opacity", json_object_new_double(cfg->wallpaper_opacity));
    json_object_object_add(wall, "mode", json_object_new_string(cfg->wallpaper_mode));
    json_object_object_add(wall, "interval", json_object_new_string(cfg->wallpaper_interval));
    json_object_object_add(wall, "login_enabled", json_object_new_boolean(cfg->login_enabled));
    json_object_object_add(wall, "login_image", json_object_new_string(cfg->login_image));
    json_object_object_add(wall, "login_opacity", json_object_new_double(cfg->login_opacity));
    json_object_object_add(wall, "login_mode", json_object_new_string(cfg->login_mode));
    json_object_object_add(wall, "login_interval", json_object_new_string(cfg->login_interval));
    json_object_object_add(wall, "source", json_object_new_string("config.db:appearance_settings"));
}
static int nc_sys_safe_token(const char*s){if(!s||!*s)return 0;for(const char*p=s;*p;p++)if(!(isalnum((unsigned char)*p)||*p=='.'||*p=='-'||*p=='_'||*p=='/'||*p==':'||*p=='@'||*p==' '))return 0;return 1;}
static int nc_sys_hostname_ok(const char*s){size_t n;if(!s||!(n=strlen(s))||n>63||s[0]=='-'||s[n-1]=='-')return 0;for(const char*p=s;*p;p++)if(!((*p>='a'&&*p<='z')||isdigit((unsigned char)*p)||*p=='-'))return 0;return 1;}
static int nc_sys_custom_domain_ok(const char*s){const char*label;size_t total;if(!s)return 0;total=strlen(s);if(!total)return 1;if(total>253||s[0]=='.'||s[total-1]=='.'||!strcasecmp(s,"local")||(total>=6&&!strcasecmp(s+total-6,".local")))return 0;label=s;for(const char*p=s;;p++){if(*p=='.'||!*p){size_t n=(size_t)(p-label);if(!n||n>63||label[0]=='-'||label[n-1]=='-')return 0;if(!*p)break;label=p+1;continue;}if(!((*p>='a'&&*p<='z')||isdigit((unsigned char)*p)||*p=='-'))return 0;}return 1;}
static int nc_sys_disabled_code_ok(const char*s){if(!s||!*s||strlen(s)>64)return 0;for(const char*p=s;*p;p++)if(!(isupper((unsigned char)*p)||isdigit((unsigned char)*p)||*p=='_'))return 0;return 1;}
static char *nc_sys_read_first_line(const char*path,char*out,size_t n){FILE*fp=fopen(path,"r");if(!fp){if(n)out[0]=0;return out;}if(!fgets(out,n,fp))out[0]=0;fclose(fp);out[strcspn(out,"\r\n")]=0;return out;}

/*
 * Firmware version for system/basic.
 *
 * This used to be nc_sys_read_first_line("/etc/openwrt_release"), which returns
 * the file's first line. That line is `DISTRIB_ID='DreamingWrt'`, so the version
 * shown on the settings page was a key=value pair rather than a version, and the
 * same string fed flash.current_firmware.
 *
 * Preferred source is /etc/dreamingos-release.json, the same file
 * jmx_system_add_release_contract() reads for system/status, so the two
 * endpoints cannot disagree. /etc/openwrt_release is the fallback, and there we
 * look the key up and strip the quotes instead of trusting line order.
 *
 * Returns 1 when a version was found, 0 when not. On 0 the caller must publish
 * null rather than inventing a plausible-looking string: "DreamingWrt" reads as
 * a real answer and hides the failure.
 */
/*
 * Build timestamp from the release file, 0 when absent. `generated_at` is when
 * the release was produced, which is what flash.build_time is asking for.
 */
static int64_t nc_sys_release_build_time(void)
{
    struct json_object *release = dw_release_read(NULL);
    struct json_object *v = NULL;
    int64_t out = 0;

    if (release && json_object_is_type(release, json_type_object) &&
        json_object_object_get_ex(release, "generated_at", &v) && v &&
        json_object_is_type(v, json_type_int))
        out = json_object_get_int64(v);
    if (release)
        json_object_put(release);
    return out > 0 ? out : 0;
}

static int nc_sys_release_version(char *out, size_t n, const char **source)
{
    struct json_object *release;


    if (!out || n == 0)
        return 0;
    out[0] = 0;
    if (source)
        *source = "";

    release = dw_release_read(source);
    dw_release_display(release, out, n);
    if (release) json_object_put(release);
    if (out[0]) return 1;

    /* Fallback: DISTRIB_RELEASE='Linux7.2' -> Linux7.2 */
    {
        FILE *fp = fopen("/etc/openwrt_release", "r");
        char line[256];

        if (!fp)
            return 0;
        while (fgets(line, sizeof(line), fp)) {
            char *eq;
            char *val;
            size_t len;

            line[strcspn(line, "\r\n")] = 0;
            if (strncmp(line, "DISTRIB_RELEASE", 15))
                continue;
            eq = strchr(line, '=');
            if (!eq)
                continue;
            val = eq + 1;
            len = strlen(val);
            if (len >= 2 && (val[0] == '\'' || val[0] == '"') &&
                val[len - 1] == val[0]) {
                val[len - 1] = 0;
                val++;
            }
            if (val[0]) {
                snprintf(out, n, "%s", val);
                if (source)
                    *source = "/etc/openwrt_release";
            }
            break;
        }
        fclose(fp);
    }
    return out[0] ? 1 : 0;
}
static void nc_sys_cmd_first(const char*cmd,char*out,size_t n){FILE*fp=popen(cmd,"r");if(!fp){out[0]=0;return;}if(!fgets(out,n,fp))out[0]=0;pclose(fp);out[strcspn(out,"\r\n")]=0;}
static void nc_sys_write_disabled_file(void);
static void nc_sys_hwprobe_disabled(void)
{
    /* First call: detect missing hardware and seed DB + file */
    sqlite3_stmt *ck=NULL;
    if(nc_prepare(&ck,"SELECT COUNT(*) FROM disabled_function WHERE source='hwprobe'")==0){
        if(sqlite3_step(ck)==SQLITE_ROW && sqlite3_column_int(ck,0)>0){sqlite3_finalize(ck);return;}
        sqlite3_finalize(ck);
    }
    sqlite3_int64 now=(sqlite3_int64)nc_now_s();
    int wifi_missing = 0;
    {struct stat st; wifi_missing = (stat("/sys/class/ieee80211",&st)!=0);
     if(!wifi_missing){DIR*d=opendir("/sys/class/ieee80211");if(d){struct dirent*e;int cnt=0;while((e=readdir(d))!=NULL){if(e->d_name[0]!='.'&&strncmp(e->d_name,"phy",3)==0)cnt++;}closedir(d);if(cnt==0)wifi_missing=1;}}}
    int cellular_missing = 1; /* assume no modem unless proven */
    {DIR*d=opendir("/dev");if(d){struct dirent*e;while((e=readdir(d))!=NULL){if(!strncmp(e->d_name,"ttyUSB",6)||!strncmp(e->d_name,"cdc-wdm",7)){cellular_missing=0;break;}}closedir(d);}
     if(cellular_missing){FILE*fp=popen("mmcli -L 2>/dev/null","r");if(fp){char buf[256];if(fgets(buf,sizeof(buf),fp)&&strstr(buf,"Modem"))cellular_missing=0;pclose(fp);}}}
    static const char*codes[]={"WIFI","CELLULAR",NULL};
    int flags[]={wifi_missing,cellular_missing};
    int added=0;
    for(int i=0;codes[i];i++){
        if(!flags[i])continue;
        sqlite3_stmt*st=NULL;
        if(nc_prepare(&st,"INSERT OR IGNORE INTO disabled_function(code,source,updated_at) VALUES(?,'hwprobe',?)")==0){
            sqlite3_bind_text(st,1,codes[i],-1,SQLITE_TRANSIENT);
            sqlite3_bind_int64(st,2,now);
            if(sqlite3_step(st)==SQLITE_DONE)added++;
            sqlite3_finalize(st);
        }
    }
    if(added>0) nc_sys_write_disabled_file();
}

static void nc_sys_sync_disabled_from_legacy_file(void)
{FILE*fp=fopen("/etc/disabled_func","r");if(!fp)return;char line[128];sqlite3_int64 now=(sqlite3_int64)nc_now_s();while(fgets(line,sizeof(line),fp)){line[strcspn(line,"\r\n")]=0;if(!nc_sys_disabled_code_ok(line))continue;sqlite3_stmt*st=NULL;if(nc_prepare(&st,"INSERT OR IGNORE INTO disabled_function(code,source,updated_at) VALUES(?,'file',?)")==0){sqlite3_bind_text(st,1,line,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,now);sqlite3_step(st);sqlite3_finalize(st);}}fclose(fp);}

/*
 * /etc/dreamingos_features "Disabled_function:" is the boot-time input that
 * replaces /etc/disabled_func once it exists. It feeds rows with source='file';
 * a code removed from the section drops its 'file' row, while 'user' and
 * 'hwprobe' rows are never touched. Runtime API edits stay in the table and are
 * not written back to the hand-edited file; /etc/disabled_func keeps being
 * regenerated as a read-only projection. Resynced when the file changes or the
 * process restarts, not on every read, so an API removal of a file code holds
 * until then.
 */
static struct stat g_nc_features_stamp;
static int g_nc_features_have_stamp;

static int nc_sys_features_functions(struct dwrt_features *f)
{
    if (dwrt_features_load(DWRT_FEATURES_PATH, f, NULL, NULL) != 0)
        return 0;
    return f->has_function_section;
}

static int nc_sys_features_mode(void)
{
    static struct dwrt_features f;

    return nc_sys_features_functions(&f);
}

static void nc_sys_sync_disabled_from_features(const struct dwrt_features *f)
{
    sqlite3_int64 now = (sqlite3_int64)nc_now_s();
    sqlite3_stmt *st = NULL;
    size_t i;
    int changed = 0;

    if (nc_txn_begin() != 0)
        return;
    if (nc_prepare(&st, "SELECT code FROM disabled_function WHERE source='file'") == 0) {
        char stale[DWRT_FEATURES_MAX_FUNCTIONS][DWRT_FEATURES_FUNC_MAX];
        size_t n_stale = 0, k;

        while (sqlite3_step(st) == SQLITE_ROW && n_stale < DWRT_FEATURES_MAX_FUNCTIONS) {
            const char *code = (const char *)sqlite3_column_text(st, 0);
            int keep = 0;

            for (i = 0; code && i < f->n_functions; i++)
                keep |= !strcmp(code, f->functions[i]);
            if (code && !keep)
                snprintf(stale[n_stale++], DWRT_FEATURES_FUNC_MAX, "%s", code);
        }
        sqlite3_finalize(st);
        st = NULL;
        for (k = 0; k < n_stale; k++) {
            if (nc_prepare(&st, "DELETE FROM disabled_function WHERE code=? AND source='file'") == 0) {
                sqlite3_bind_text(st, 1, stale[k], -1, SQLITE_TRANSIENT);
                if (sqlite3_step(st) == SQLITE_DONE && nc_sqlite_changes() > 0)
                    changed = 1;
                sqlite3_finalize(st);
                st = NULL;
            }
        }
    }
    for (i = 0; i < f->n_functions; i++) {
        if (!nc_sys_disabled_code_ok(f->functions[i]))
            continue;
        if (nc_prepare(&st, "INSERT OR IGNORE INTO disabled_function(code,source,updated_at) VALUES(?,'file',?)") == 0) {
            sqlite3_bind_text(st, 1, f->functions[i], -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, now);
            if (sqlite3_step(st) == SQLITE_DONE && nc_sqlite_changes() > 0)
                changed = 1;
            sqlite3_finalize(st);
            st = NULL;
        }
    }
    nc_txn_end(0);
    if (changed)
        nc_sys_write_disabled_file();
}

static void nc_sys_sync_disabled_from_file(void)
{
    static struct dwrt_features f;
    struct stat st;

    if (!nc_sys_features_functions(&f)) {
        g_nc_features_have_stamp = 0;
        nc_sys_sync_disabled_from_legacy_file();
        return;
    }
    if (stat(DWRT_FEATURES_PATH, &st) == 0 && g_nc_features_have_stamp &&
        st.st_ino == g_nc_features_stamp.st_ino && st.st_size == g_nc_features_stamp.st_size &&
        st.st_mtime == g_nc_features_stamp.st_mtime)
        return;
    nc_sys_sync_disabled_from_features(&f);
    if (stat(DWRT_FEATURES_PATH, &st) == 0) {
        g_nc_features_stamp = st;
        g_nc_features_have_stamp = 1;
    }
}

/* Space-separated codes from the table, for the wifi capability derivation. */
static char *nc_sys_disabled_codes_text(void)
{
    size_t cap = 256, len = 0;
    char *buf = calloc(1, cap);
    sqlite3_stmt *st = NULL;

    if (!buf)
        return NULL;
    nc_exec("CREATE TABLE IF NOT EXISTS disabled_function (code TEXT PRIMARY KEY,reason TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT 'auto',updated_at INTEGER NOT NULL)");
    nc_sys_sync_disabled_from_file();
    if (nc_prepare(&st, "SELECT code FROM disabled_function ORDER BY code") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *code = (const char *)sqlite3_column_text(st, 0);
            size_t n = code ? strlen(code) : 0;

            if (!n)
                continue;
            if (len + n + 2 > cap) {
                char *nb;

                cap = (len + n + 2) * 2;
                nb = realloc(buf, cap);
                if (!nb)
                    break;
                buf = nb;
            }
            memcpy(buf + len, code, n);
            len += n;
            buf[len++] = ' ';
            buf[len] = '\0';
        }
        sqlite3_finalize(st);
    }
    return buf;
}
static void nc_sys_write_disabled_file(void)
{FILE*fp=fopen("/etc/disabled_func","w");if(!fp)return;sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT code FROM disabled_function ORDER BY code")==0){while(sqlite3_step(st)==SQLITE_ROW)fprintf(fp,"%s\n",(const char*)sqlite3_column_text(st,0));sqlite3_finalize(st);}fclose(fp);}

static int nc_sys_service_is_critical(const char *name)
{
    if (!name) return 0;
    return !strcmp(name, "network") || !strcmp(name, "firewall") || !strcmp(name, "rpcd") ||
           !strcmp(name, "uhttpd") || !strcmp(name, "dropbear") || !strcmp(name, "dnsmasq") ||
           !strcmp(name, "jmxd") || !strcmp(name, "dreamingwrt-init");
}

#define NC_SYS_SERVICE_NAME_MAX 127
#define NC_SYS_SERVICE_SCAN_MAX 1024
#define NC_SYS_SERVICE_RETURN_MAX 200
#define NC_SYS_SERVICE_LIST_BUDGET_MS 8000
#define NC_SYS_SERVICE_LIST_ITEM_TIMEOUT_MS 500
#define NC_SYS_SERVICE_ACTION_TIMEOUT_MS 15000
#define NC_SYS_SERVICE_STATUS_TIMEOUT_MS 3000
#define NC_SYS_SERVICE_SCRIPT_SCAN_MAX (128U * 1024U)

struct nc_sys_service_handle {
    int dirfd;
    int fd;
    char name[NC_SYS_SERVICE_NAME_MAX + 1];
    char path[sizeof("/etc/init.d/") + NC_SYS_SERVICE_NAME_MAX];
    struct stat dir_st;
    struct stat file_st;
};

struct nc_sys_service_name {
    char value[NC_SYS_SERVICE_NAME_MAX + 1];
};

static int64_t nc_sys_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int nc_sys_service_token_ok(const char *name)
{
    const unsigned char *p;
    size_t len;

    if (!name || !name[0])
        return 0;
    len = strlen(name);
    if (len > NC_SYS_SERVICE_NAME_MAX)
        return 0;
    for (p = (const unsigned char *)name; *p; p++) {
        if (!isalnum(*p) && *p != '_' && *p != '-')
            return 0;
    }
    return 1;
}

static void nc_sys_service_close(struct nc_sys_service_handle *handle)
{
    if (!handle)
        return;
    if (handle->fd >= 0)
        close(handle->fd);
    if (handle->dirfd >= 0)
        close(handle->dirfd);
    memset(handle, 0, sizeof(*handle));
    handle->dirfd = -1;
    handle->fd = -1;
}

static int nc_sys_service_open(const char *name,
                               struct nc_sys_service_handle *handle)
{
    int n;

    if (!handle || !nc_sys_service_token_ok(name))
        return -1;
    memset(handle, 0, sizeof(*handle));
    handle->dirfd = -1;
    handle->fd = -1;
    handle->dirfd = open("/etc/init.d",
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (handle->dirfd < 0 || fstat(handle->dirfd, &handle->dir_st) != 0 ||
        !S_ISDIR(handle->dir_st.st_mode) || handle->dir_st.st_uid != 0 ||
        (handle->dir_st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto failed;
    handle->fd = openat(handle->dirfd, name,
                        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (handle->fd < 0 || fstat(handle->fd, &handle->file_st) != 0 ||
        !S_ISREG(handle->file_st.st_mode) || handle->file_st.st_uid != 0 ||
        (handle->file_st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (handle->file_st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
        goto failed;
    snprintf(handle->name, sizeof(handle->name), "%s", name);
    n = snprintf(handle->path, sizeof(handle->path), "/etc/init.d/%s", name);
    if (n < 0 || (size_t)n >= sizeof(handle->path))
        goto failed;
    return 0;

failed:
    nc_sys_service_close(handle);
    return -1;
}

static int nc_sys_service_same_inode(const struct stat *a,
                                     const struct stat *b)
{
    return a && b && a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int nc_sys_service_revalidate(const struct nc_sys_service_handle *handle)
{
    struct stat dir_st;
    struct stat file_st;

    if (!handle || handle->dirfd < 0 || handle->fd < 0 ||
        fstat(handle->dirfd, &dir_st) != 0 ||
        fstatat(handle->dirfd, handle->name, &file_st,
                AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (!nc_sys_service_same_inode(&dir_st, &handle->dir_st) ||
        !nc_sys_service_same_inode(&file_st, &handle->file_st) ||
        !S_ISREG(file_st.st_mode) || file_st.st_uid != 0 ||
        (file_st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (file_st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0)
        return -1;
    return 0;
}

static int nc_sys_service_exec(const struct nc_sys_service_handle *handle,
                               const char *action, int timeout_ms,
                               struct jmx_exec_result *result)
{
    char *argv[3];

    if (!handle || !action || !result || timeout_ms < 1 ||
        nc_sys_service_revalidate(handle) != 0)
        return -1;
    argv[0] = (char *)handle->path;
    argv[1] = (char *)action;
    argv[2] = NULL;
    return jmx_exec_wait(handle->path, argv, timeout_ms, result);
}

static int nc_sys_service_exec_ok(int rc,
                                  const struct jmx_exec_result *result)
{
    return rc == 0 && result && !result->timed_out && !result->truncated &&
           result->term_signal == 0 && result->exit_code == 0;
}

static int nc_sys_service_action_ok(const char *action)
{
    return action && (!strcmp(action, "enable") ||
                      !strcmp(action, "disable") ||
                      !strcmp(action, "start") ||
                      !strcmp(action, "stop") ||
                      !strcmp(action, "restart") ||
                      !strcmp(action, "reload") ||
                      !strcmp(action, "status"));
}

static int nc_sys_service_enabled(const struct nc_sys_service_handle *handle,
                                  int *enabled, int *priority)
{
    DIR *dir = NULL;
    struct dirent *entry;
    int rcfd = -1;
    int found = 0;
    int found_priority = 50;

    if (!handle || !enabled || !priority)
        return -1;
    *enabled = 0;
    *priority = 50;
    rcfd = open("/etc/rc.d", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (rcfd < 0)
        return -1;
    dir = fdopendir(rcfd);
    if (!dir) {
        close(rcfd);
        return -1;
    }
    rcfd = -1;
    while ((entry = readdir(dir)) != NULL) {
        struct stat target_st;
        const char *entry_name = entry->d_name;

        if (entry_name[0] != 'S' ||
            !isdigit((unsigned char)entry_name[1]) ||
            !isdigit((unsigned char)entry_name[2]) ||
            strcmp(entry_name + 3, handle->name) != 0)
            continue;
        if (fstatat(dirfd(dir), entry_name, &target_st, 0) != 0 ||
            !nc_sys_service_same_inode(&target_st, &handle->file_st))
            continue;
        found = 1;
        found_priority = (entry_name[1] - '0') * 10 + entry_name[2] - '0';
        break;
    }
    closedir(dir);
    *enabled = found;
    *priority = found_priority;
    return 0;
}

static int nc_sys_service_running(const struct nc_sys_service_handle *handle,
                                  int timeout_ms, int *running, int *known)
{
    struct jmx_exec_result result;
    int rc;

    if (!handle || !running || !known)
        return -1;
    *running = 0;
    *known = 0;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = nc_sys_service_exec(handle, "running", timeout_ms, &result);
    if (rc == 0 && !result.timed_out && !result.truncated &&
        result.term_signal == 0 && result.exit_code >= 0 &&
        result.exit_code < 126) {
        *running = result.exit_code == 0;
        *known = 1;
    }
    jmx_exec_result_free(&result);
    return *known ? 0 : -1;
}

static int nc_sys_service_supports_reload(
    const struct nc_sys_service_handle *handle)
{
    char *text;
    ssize_t n;
    size_t capacity;
    struct stat st;
    int supported = 0;

    if (!handle || handle->fd < 0)
        return 0;
    if (fstat(handle->fd, &st) != 0 || st.st_size <= 0)
        return 0;
    capacity = (uint64_t)st.st_size < NC_SYS_SERVICE_SCRIPT_SCAN_MAX ?
               (size_t)st.st_size : NC_SYS_SERVICE_SCRIPT_SCAN_MAX;
    text = malloc(capacity + 1);
    if (!text)
        return 0;
    n = pread(handle->fd, text, capacity, 0);
    if (n > 0) {
        text[n] = '\0';
        supported = strstr(text, "reload()") != NULL ||
                    strstr(text, "reload ()") != NULL ||
                    strstr(text, "reload_service()") != NULL ||
                    strstr(text, "reload_service ()") != NULL ||
                    (strstr(text, "EXTRA_COMMANDS") != NULL &&
                     strstr(text, "reload") != NULL);
    }
    free(text);
    return supported;
}

static int nc_sys_service_name_cmp(const void *a, const void *b)
{
    const struct nc_sys_service_name *left = a;
    const struct nc_sys_service_name *right = b;

    return strcmp(left->value, right->value);
}

static int nc_sys_service_name_ok(const char *name)
{
    struct nc_sys_service_handle handle;

    if (nc_sys_service_open(name, &handle) != 0)
        return 0;
    nc_sys_service_close(&handle);
    return 1;
}

static struct json_object *nc_sys_services_json(int *truncated_out,
                                                int *degraded_out)
{
    struct nc_sys_service_name *names = NULL;
    struct json_object *services = json_object_new_array();
    DIR *dir = NULL;
    struct dirent *entry;
    size_t count = 0;
    size_t returned;
    int truncated = 0;
    int degraded = 0;
    int64_t deadline;

    if (truncated_out)
        *truncated_out = 0;
    if (degraded_out)
        *degraded_out = 0;
    if (!services)
        return NULL;
    names = calloc(NC_SYS_SERVICE_SCAN_MAX, sizeof(*names));
    dir = opendir("/etc/init.d");
    if (!names || !dir) {
        free(names);
        if (dir)
            closedir(dir);
        if (degraded_out)
            *degraded_out = 1;
        return services;
    }
    while ((entry = readdir(dir)) != NULL) {
        struct nc_sys_service_handle handle;

        if (!nc_sys_service_token_ok(entry->d_name))
            continue;
        if (count >= NC_SYS_SERVICE_SCAN_MAX) {
            truncated = 1;
            continue;
        }
        if (nc_sys_service_open(entry->d_name, &handle) != 0)
            continue;
        snprintf(names[count].value, sizeof(names[count].value), "%s",
                 entry->d_name);
        count++;
        nc_sys_service_close(&handle);
    }
    closedir(dir);
    qsort(names, count, sizeof(*names), nc_sys_service_name_cmp);
    returned = count > NC_SYS_SERVICE_RETURN_MAX ?
               NC_SYS_SERVICE_RETURN_MAX : count;
    if (count > returned)
        truncated = 1;
    deadline = nc_sys_monotonic_ms();
    if (deadline >= 0)
        deadline += NC_SYS_SERVICE_LIST_BUDGET_MS;
    for (size_t i = 0; i < returned; i++) {
        struct nc_sys_service_handle handle;
        struct json_object *item;
        int enabled = 0;
        int enabled_known = 0;
        int priority = 50;
        int running = 0;
        int running_known = 0;
        int supports_reload = 0;
        int timeout_ms = NC_SYS_SERVICE_LIST_ITEM_TIMEOUT_MS;
        int64_t now;

        if (nc_sys_service_open(names[i].value, &handle) != 0) {
            degraded = 1;
            continue;
        }
        enabled_known = nc_sys_service_enabled(&handle, &enabled, &priority) == 0;
        supports_reload = nc_sys_service_supports_reload(&handle);
        now = nc_sys_monotonic_ms();
        if (deadline < 0 || now < 0 || now >= deadline) {
            degraded = 1;
        } else {
            int64_t remaining = deadline - now;
            if (remaining < timeout_ms)
                timeout_ms = (int)remaining;
            if (timeout_ms > 0)
                (void)nc_sys_service_running(&handle, timeout_ms,
                                             &running, &running_known);
            if (!running_known)
                degraded = 1;
        }
        item = json_object_new_object();
        if (item) {
            json_object_object_add(item, "name",
                                   json_object_new_string(handle.name));
            json_object_object_add(item, "enabled",
                                   json_object_new_boolean(enabled));
            json_object_object_add(item, "enabled_known",
                                   json_object_new_boolean(enabled_known));
            json_object_object_add(item, "running",
                                   json_object_new_boolean(running));
            json_object_object_add(item, "running_known",
                                   json_object_new_boolean(running_known));
            json_object_object_add(item, "runtime_state",
                json_object_new_string(!running_known ? "unknown" :
                                       (running ? "running" : "stopped")));
            json_object_object_add(item, "priority",
                                   json_object_new_int(priority));
            json_object_object_add(item, "supports_reload",
                                   json_object_new_boolean(supports_reload));
            json_object_object_add(item, "critical",
                json_object_new_boolean(nc_sys_service_is_critical(handle.name)));
            json_object_object_add(item, "desc", json_object_new_string(
                nc_sys_service_is_critical(handle.name) ?
                "system service" : "OpenWrt service"));
            json_object_array_add(services, item);
        } else {
            degraded = 1;
        }
        nc_sys_service_close(&handle);
    }
    free(names);
    if (truncated_out)
        *truncated_out = truncated;
    if (degraded_out)
        *degraded_out = degraded;
    return services;
}
static struct json_object *nc_sys_cron_jobs_json(void)
{struct json_object*a=json_object_new_array();sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,enabled,schedule,command,description FROM system_cron_job ORDER BY id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"schedule",st,2);nc_add_text(o,"command",st,3);nc_add_text(o,"desc",st,4);json_object_array_add(a,o);}sqlite3_finalize(st);}FILE*fp=fopen("/etc/crontabs/root","r");if(fp){char line[512];int i=0;while(fgets(line,sizeof(line),fp)){line[strcspn(line,"\r\n")]=0;if(!line[0])continue;if(line[0]=='#'){struct json_object*o=json_object_new_object();char id[32];snprintf(id,sizeof(id),"root-%d",++i);json_object_object_add(o,"id",json_object_new_string(id));json_object_object_add(o,"enabled",json_object_new_boolean(1));json_object_object_add(o,"schedule",json_object_new_string("#"));json_object_object_add(o,"command",json_object_new_string(line));json_object_object_add(o,"desc",json_object_new_string("system crontab"));json_object_array_add(a,o);}else{struct json_object*o=json_object_new_object();char id[32];snprintf(id,sizeof(id),"root-%d",++i);json_object_object_add(o,"id",json_object_new_string(id));json_object_object_add(o,"enabled",json_object_new_boolean(1));json_object_object_add(o,"schedule",json_object_new_string(line));json_object_object_add(o,"command",json_object_new_string(line));json_object_object_add(o,"desc",json_object_new_string("system crontab"));json_object_array_add(a,o);}}fclose(fp);}return a;}
static struct json_object *nc_sys_disabled_json(void)
{struct json_object*a=json_object_new_array();sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT code FROM disabled_function ORDER BY code")==0){while(sqlite3_step(st)==SQLITE_ROW)json_object_array_add(a,json_object_new_string((const char*)sqlite3_column_text(st,0)));sqlite3_finalize(st);}return a;}

/* ═══ Advanced section: device truth for conntrack / ALG / kernel switches ═══
 *
 * Everything below reads the running kernel rather than the intent stored in
 * system_settings. Returning a stored value that disagrees with the device is
 * worse than returning nothing, because the page then states the opposite of
 * what the router is doing.
 */

/* Reads a single-line sysctl-style file. Returns 0 on success. */
static int nc_adv_read_line(const char *path, char *out, size_t out_len)
{
    FILE *fp;

    if (!path || !out || out_len < 2) return -1;
    out[0] = 0;
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(out, out_len, fp)) {
        fclose(fp);
        out[0] = 0;
        return -1;
    }
    fclose(fp);
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}

static int nc_adv_path_writable(const char *path)
{
    struct stat st;

    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    return (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0;
}

/*
 * conntrack timeout knobs exposed on the advanced page.
 *
 * The UI field name is deliberately kept (nf_tcp_syn_sent and friends) so the
 * existing controls bind to real data instead of hardcoded defaults.
 */
typedef struct {
    const char *field;   /* API/UI field name */
    const char *path;    /* procfs source */
    long long min;
    long long max;
} nc_adv_conntrack_knob_t;

static const nc_adv_conntrack_knob_t nc_adv_conntrack_knobs[] = {
    { "nf_tcp_syn_sent",    "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent",    1, 86400 },
    { "nf_tcp_syn_recv",    "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv",    1, 86400 },
    { "nf_tcp_established", "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", 60, 604800 },
    { "nf_tcp_fin_wait",    "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_fin_wait",    1, 86400 },
    { "nf_tcp_close_wait",  "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait",  1, 86400 },
    { "nf_tcp_last_ack",    "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_last_ack",    1, 86400 },
    { "nf_tcp_time_wait",   "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait",   1, 86400 },
    { "nf_tcp_close",       "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close",       1, 86400 },
    { "nf_udp_timeout",     "/proc/sys/net/netfilter/nf_conntrack_udp_timeout",             1, 86400 },
    { "nf_udp_stream",      "/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream",      1, 86400 },
    { "nf_icmp_timeout",    "/proc/sys/net/netfilter/nf_conntrack_icmp_timeout",            1, 86400 },
};

static const nc_adv_conntrack_knob_t *nc_adv_conntrack_find(const char *field)
{
    size_t i;

    if (!field || !*field) return NULL;
    for (i = 0; i < sizeof(nc_adv_conntrack_knobs) / sizeof(nc_adv_conntrack_knobs[0]); i++) {
        if (!strcmp(field, nc_adv_conntrack_knobs[i].field))
            return &nc_adv_conntrack_knobs[i];
    }
    return NULL;
}

/* ALG helper modules. "loaded" is the module, "ports" its port parameter. */
typedef struct {
    const char *field;
    const char *ports_field;
    const char *module;
} nc_adv_alg_helper_t;

static const nc_adv_alg_helper_t nc_adv_alg_helpers[] = {
    { "alg_ftp",   "alg_ftp_ports",  "nf_conntrack_ftp"   },
    { "alg_tftp",  "alg_tftp_ports", "nf_conntrack_tftp"  },
    { "alg_sip",   "alg_sip_ports",  "nf_conntrack_sip"   },
    /* h323 has no ports parameter in this kernel; ports_field stays NULL. */
    { "alg_h323",  NULL,             "nf_conntrack_h323"  },
};

/* True when the conntrack helper module is loaded. */
static int nc_adv_alg_loaded(const char *module)
{
    char path[256];
    struct stat st;

    snprintf(path, sizeof(path), "/sys/module/%s", module);
    return stat(path, &st) == 0;
}

/* Reads the helper's ports parameter, e.g. "21" for ftp. */
static int nc_adv_alg_ports(const char *module, char *out, size_t out_len)
{
    char path[256];

    snprintf(path, sizeof(path), "/sys/module/%s/parameters/ports", module);
    return nc_adv_read_line(path, out, out_len);
}

/*
 * irqbalance: report whether it is actually running, not what the DB wants.
 *
 * 30.1 has no /etc/init.d/irqbalance at all while the DB said enabled, so the
 * page claimed IRQ balancing was on when nothing was balancing anything.
 * BusyBox ps hides daemons, so this walks /proc instead of shelling out.
 */
static int nc_adv_process_running(const char *needle)
{
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    int found = 0;

    if (!dir) return 0;
    while (!found && (entry = readdir(dir)) != NULL) {
        char path[320];
        char buf[1024];
        FILE *fp;
        size_t n;
        size_t i;
        const char *p = entry->d_name;

        while (*p && isdigit((unsigned char)*p)) p++;
        if (*p || p == entry->d_name) continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        fp = fopen(path, "r");
        if (!fp) continue;
        n = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);
        if (n == 0) continue;
        buf[n] = 0;
        /* cmdline is NUL separated; flatten so strstr can see the whole line. */
        for (i = 0; i < n; i++) {
            if (buf[i] == 0) buf[i] = ' ';
        }
        if (strstr(buf, needle)) found = 1;
    }
    closedir(dir);
    return found;
}

/* Query only live flowtables, without materialising every rule and set. */
static int nc_adv_nft_flowtable_count(int *count_out)
{
    const char *nft = NULL;
    char *argv[] = { NULL, "list", "flowtables", NULL };
    struct jmx_exec_result result;
    int rc, n = 0;
    char *p;

    if (access("/usr/sbin/nft", X_OK) == 0)
        nft = "/usr/sbin/nft";
    else if (access("/sbin/nft", X_OK) == 0)
        nft = "/sbin/nft";
    else if (access("/usr/bin/nft", X_OK) == 0)
        nft = "/usr/bin/nft";
    else if (access("/bin/nft", X_OK) == 0)
        nft = "/bin/nft";
    if (count_out)
        *count_out = 0;
    if (!nft)
        return -1;
    argv[0] = (char *)nft;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = jmx_exec_capture(nft, argv, 256 * 1024, 10000, &result);
    if (rc != 0 || result.timed_out || result.truncated ||
        result.term_signal != 0 || result.exit_code != 0 || !result.output) {
        jmx_exec_result_free(&result);
        return -1;
    }
    for (p = result.output; (p = strstr(p, "flowtable")) != NULL; p += 9)
        n++;
    jmx_exec_result_free(&result);
    if (count_out)
        *count_out = n;
    return 0;
}

/* Counts live flowtables that explicitly request hardware offload. */
static int nc_adv_nft_flowtable_offload_count(int *count_out)
{
    const char *nft = NULL;
    char *argv[] = { NULL, "list", "ruleset", NULL };
    struct jmx_exec_result result;
    int rc, n = 0;
    char *p;

    if (access("/usr/sbin/nft", X_OK) == 0)
        nft = "/usr/sbin/nft";
    else if (access("/sbin/nft", X_OK) == 0)
        nft = "/sbin/nft";
    else if (access("/usr/bin/nft", X_OK) == 0)
        nft = "/usr/bin/nft";
    else if (access("/bin/nft", X_OK) == 0)
        nft = "/bin/nft";
    if (count_out)
        *count_out = 0;
    if (!nft)
        return -1;
    argv[0] = (char *)nft;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = jmx_exec_capture(nft, argv, 256 * 1024, 10000, &result);
    if (rc != 0 || result.timed_out || result.truncated ||
        result.term_signal != 0 || result.exit_code != 0 || !result.output) {
        jmx_exec_result_free(&result);
        return -1;
    }
    for (p = result.output; (p = strstr(p, "flags offload")) != NULL;
         p += strlen("flags offload"))
        n++;
    jmx_exec_result_free(&result);
    if (count_out)
        *count_out = n;
    return 0;
}

/* Each read owns its libuci context; no shared CLI process or cached state. */
static int nc_adv_uci_read_int(const char *key, int *value_out)
{
    struct uci_context *ctx;
    struct uci_ptr ptr;
    char tuple[256];
    const char *text;
    char *end;
    long value;
    int rc = -1;

    if (value_out)
        *value_out = 0;
    if (!key || !key[0] || !value_out || strlen(key) >= sizeof(tuple))
        return -1;
    ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    memcpy(tuple, key, strlen(key) + 1);
    memset(&ptr, 0, sizeof(ptr));
    if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK ||
        !(ptr.flags & UCI_LOOKUP_COMPLETE) || !ptr.o || ptr.o->type != UCI_TYPE_STRING)
        goto out;
    text = ptr.o->v.string;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || end == text)
        goto out;
    while (*end && isspace((unsigned char)*end))
        end++;
    if (*end)
        goto out;
    *value_out = (int)value;
    rc = 0;
out:
    uci_free_context(ctx);
    return rc;
}

static void nc_sys_fstab_quote(FILE *stream, const char *value)
{
    fputc('\'', stream);
    for (const char *p = value; *p; p++) {
        if (*p == '\'')
            fputs("'\\''", stream);
        else
            fputc(*p, stream);
    }
    fputc('\'', stream);
}

static void nc_sys_fstab_json(struct json_object *mounts)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    struct json_object *config = json_object_new_array();
    int auto_mount = 1, auto_swap = 1, check_fs = 0, have_global = 0;

    if (ctx && uci_load(ctx, "fstab", &pkg) == UCI_OK) {
        uci_foreach_element(&pkg->sections, e) {
            struct uci_section *section = uci_to_section(e);
            const char *value;
            struct uci_element *oe;
            if (!have_global && !strcmp(section->type, "global")) {
                have_global = 1;
                value = uci_lookup_option_string(ctx, section, "anon_swap");
                if (value) auto_swap = atoi(value);
                value = uci_lookup_option_string(ctx, section, "auto_swap");
                if (value) auto_swap = atoi(value);
                value = uci_lookup_option_string(ctx, section, "auto_mount");
                if (value) auto_mount = atoi(value);
                value = uci_lookup_option_string(ctx, section, "check_fs");
                if (value) check_fs = atoi(value);
            }
            /* Match the existing `uci show fstab | grep ^fstab.cfg` view.
             * Anonymous sections are rendered as @type[index] by uci show. */
            if (section->anonymous || strncmp(section->e.name, "cfg", 3))
                continue;
            struct json_object *item = json_object_new_object();
            char key[512];
            snprintf(key, sizeof(key), "fstab.%s", section->e.name);
            json_object_object_add(item, "uci_section", json_object_new_string(key));
            json_object_object_add(item, "uci_value", json_object_new_string(section->type));
            json_object_array_add(config, item);
            uci_foreach_element(&section->options, oe) {
                struct uci_option *option = uci_to_option(oe);
                char *text = NULL;
                size_t length = 0;
                FILE *stream = open_memstream(&text, &length);
                if (!stream)
                    continue;
                if (option->type == UCI_TYPE_STRING) {
                    nc_sys_fstab_quote(stream, option->v.string);
                } else if (option->type == UCI_TYPE_LIST) {
                    struct uci_element *le;
                    int first = 1;
                    uci_foreach_element(&option->v.list, le) {
                        if (!first) fputc(' ', stream);
                        nc_sys_fstab_quote(stream, le->name);
                        first = 0;
                    }
                }
                if (fclose(stream) != 0) {
                    free(text);
                    continue;
                }
                snprintf(key, sizeof(key), "fstab.%s.%s", section->e.name, option->e.name);
                item = json_object_new_object();
                json_object_object_add(item, "uci_section", json_object_new_string(key));
                json_object_object_add(item, "uci_value", json_object_new_string(text ? text : ""));
                json_object_array_add(config, item);
                free(text);
            }
        }
    }
    if (ctx)
        uci_free_context(ctx);
    json_object_object_add(mounts, "auto_mount", json_object_new_boolean(auto_mount));
    json_object_object_add(mounts, "auto_swap", json_object_new_boolean(auto_swap));
    json_object_object_add(mounts, "check_fs", json_object_new_boolean(check_fs));
    json_object_object_add(mounts, "fstab_config", config);
}

static int nc_adv_uci_int(const char *key, int def)
{
    int value;

    return nc_adv_uci_read_int(key, &value) == 0 ? value : def;
}

char *nc_sys_read_file_text(const char *path, size_t max_bytes)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    char *buf = (char *)calloc(1, max_bytes + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t n = fread(buf, 1, max_bytes, fp);
    fclose(fp);
    if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = 0;
    return buf;
}

static int nc_sys_file_exists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

static int nc_sys_file_is_one(const char *path)
{
    return path && nc_read_int_file(path, -1) == 1;
}

static int nc_sys_cmdline_has_crashkernel(void)
{
    char *cmdline = nc_sys_read_file_text("/proc/cmdline", 8192);
    char *p;
    int configured = 0;

    if (!cmdline)
        return 0;
    for (p = strtok(cmdline, " \t\r\n"); p; p = strtok(NULL, " \t\r\n")) {
        if (!strncmp(p, "crashkernel=", 12) && p[12] != '\0' &&
            strcmp(p + 12, "0") && strcmp(p + 12, "none")) {
            configured = 1;
            break;
        }
    }
    free(cmdline);
    return configured;
}

static int nc_sys_dir_usable(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           access(path, R_OK | W_OK) == 0;
}

static int nc_sys_dropbear_port(void)
{
    FILE *fp = popen("uci -q get dropbear.@dropbear[0].Port 2>/dev/null", "r");
    char buf[32] = "";
    if (fp) { if (!fgets(buf, sizeof(buf), fp)) buf[0] = 0; pclose(fp); }
    buf[strcspn(buf, "\r\n")] = 0;
    int port = atoi(buf);
    return port > 0 ? port : 22;
}

static int nc_sys_dropbear_password_login(void)
{
    FILE *fp = popen("uci -q get dropbear.@dropbear[0].PasswordAuth 2>/dev/null", "r");
    char buf[16] = "";
    if (fp) { if (!fgets(buf, sizeof(buf), fp)) buf[0] = 0; pclose(fp); }
    buf[strcspn(buf, "\r\n")] = 0;
    return strcmp(buf, "off") != 0;
}

static int nc_sys_dropbear_root_password_login(void)
{
    FILE *fp = popen("uci -q get dropbear.@dropbear[0].RootPasswordAuth 2>/dev/null", "r");
    char buf[16] = "";
    if (fp) { if (!fgets(buf, sizeof(buf), fp)) buf[0] = 0; pclose(fp); }
    buf[strcspn(buf, "\r\n")] = 0;
    return strcmp(buf, "off") != 0;
}

static int nc_sys_dropbear_enabled(void)
{
    return system("/etc/init.d/dropbear enabled >/dev/null 2>&1") == 0;
}

static int nc_sys_dropbear_idle_timeout(void)
{
    FILE *fp = popen("uci -q get dropbear.@dropbear[0].IdleTimeout 2>/dev/null", "r");
    if (!fp) return 0;
    char buf[32] = "";
    if (fgets(buf, sizeof(buf), fp)) { buf[strcspn(buf, "\r\n")] = 0; }
    pclose(fp);
    int sec = atoi(buf);
    return sec > 0 ? sec / 60 : 0;  /* convert seconds to minutes */
}


#define NC_OPENSSH_CONFIG_PATH "/etc/ssh/sshd_config"
#define NC_OPENSSH_DROPIN_PATH "/etc/ssh/sshd_config.d/00-dreamingwrt.conf"
#define NC_OPENSSH_AUTH_KEYS_PATH "/root/.ssh/authorized_keys"
#define NC_DROPBEAR_AUTH_KEYS_PATH "/etc/dropbear/authorized_keys"

static int nc_sys_path_exists(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0;
}

static int nc_sys_openssh_available(void)
{
    return nc_sys_path_exists(NC_OPENSSH_CONFIG_PATH) ||
           nc_sys_path_exists("/usr/sbin/sshd") ||
           nc_sys_path_exists("/etc/init.d/sshd");
}

static const char *nc_sys_ssh_provider(void)
{
    if (system("pgrep -x sshd >/dev/null 2>&1") == 0)
        return "openssh";
    if (system("pgrep -x dropbear >/dev/null 2>&1") == 0)
        return "dropbear";
    return nc_sys_openssh_available() ? "openssh" : "dropbear";
}

static int nc_sys_openssh_enabled(void)
{
    if (nc_sys_path_exists("/etc/init.d/sshd"))
        return system("/etc/init.d/sshd enabled >/dev/null 2>&1") == 0;
    return system("pgrep -x sshd >/dev/null 2>&1") == 0;
}

struct nc_sys_openssh_state {
    int port;
    int password_login;
    int keyboard_interactive_login;
    int root_password_login;
    int idle_timeout_min;
};

static void nc_sys_openssh_state_load(struct nc_sys_openssh_state *state)
{
    /* This child only reads port/auth/idle settings. Avoid OpenSSL engine
     * initialization (slow /dev/crypto probes) and host-key checks for that
     * read; the SSH daemon keeps its normal crypto configuration. Older
     * OpenSSH versions lack -G, so retain their original -T readback. */
    static const char *commands[] = {
        "OPENSSL_CONF=/dev/null sshd -G 2>/dev/null", "sshd -T 2>/dev/null"
    };

    if (!state)
        return;
    for (size_t attempt = 0; attempt < sizeof(commands) / sizeof(commands[0]);
         attempt++) {
        FILE *fp;
        char k[128], v[512];
        int port_seen = 0;

        memset(state, 0, sizeof(*state));
        state->port = 22;
        state->password_login = 1;
        state->keyboard_interactive_login = 1;
        fp = popen(commands[attempt], "r");
        if (!fp)
            continue;
        while (fscanf(fp, "%127s %511s", k, v) == 2) {
            if (!strcasecmp(k, "port") && !port_seen) {
                int port = atoi(v);
                if (port > 0 && port <= 65535)
                    state->port = port;
                port_seen = 1;
            } else if (!strcasecmp(k, "passwordauthentication")) {
                state->password_login = strcasecmp(v, "no") != 0;
            } else if (!strcasecmp(k, "kbdinteractiveauthentication")) {
                state->keyboard_interactive_login = strcasecmp(v, "no") != 0;
            } else if (!strcasecmp(k, "permitrootlogin")) {
                state->root_password_login = !strcasecmp(v, "yes");
            } else if (!strcasecmp(k, "clientaliveinterval")) {
                int sec = atoi(v);
                state->idle_timeout_min = sec > 0 ? sec / 60 : 0;
            }
        }
        if (pclose(fp) == 0)
            break;
    }
}

static char *nc_sys_read_file_alloc(const char *path, size_t max_bytes, size_t *len_out)
{
    FILE *fp;
    char *buf;
    size_t n;

    if (len_out)
        *len_out = 0;
    fp = fopen(path, "r");
    if (!fp)
        return NULL;
    buf = calloc(1, max_bytes + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    n = fread(buf, 1, max_bytes, fp);
    fclose(fp);
    buf[n] = 0;
    if (len_out)
        *len_out = n;
    return buf;
}

static int nc_sys_auth_key_line_ok(const char *line)
{
    const char *p;

    if (!line)
        return 0;
    while (*line == ' ' || *line == '\t')
        line++;
    if (!*line || *line == '#')
        return 1;
    if (strlen(line) > 8192)
        return 0;
    for (p = line; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 && c != '\t')
            return 0;
    }
    return strstr(line, "ssh-ed25519 ") || strstr(line, "ssh-rsa ") ||
           strstr(line, "ecdsa-sha2-") || strstr(line, "sk-ssh-ed25519@") ||
           strstr(line, "sk-ecdsa-sha2-");
}

static int nc_sys_authorized_keys_count_path(const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[8192];
    int count = 0;

    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        line[strcspn(line, "\r\n")] = 0;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p || *p == '#')
            continue;
        if (nc_sys_auth_key_line_ok(p))
            count++;
    }
    fclose(fp);
    return count;
}

static int nc_sys_authorized_keys_count_text(const char *text)
{
    char *copy, *line, *save = NULL;
    int count = 0;

    if (!text)
        return 0;
    copy = strdup(text);
    if (!copy)
        return -1;
    for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *p = line;

        line[strcspn(line, "\r")] = 0;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p || *p == '#')
            continue;
        if (!nc_sys_auth_key_line_ok(p)) {
            free(copy);
            return -2;
        }
        count++;
    }
    free(copy);
    return count;
}

static struct json_object *nc_sys_authorized_keys_array(const char *path)
{
    struct json_object *arr = json_object_new_array();
    FILE *fp = fopen(path, "r");
    char line[8192];

    if (!fp)
        return arr;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0])
            json_object_array_add(arr, json_object_new_string(line));
    }
    fclose(fp);
    return arr;
}

static int nc_sys_extract_authorized_keys(struct json_object *ssh, char **out)
{
    struct json_object *v = NULL;
    const char *keys[] = {"authorized_keys_text", "authorized_keys", "keys", "public_keys", NULL};
    int i;

    if (out)
        *out = NULL;
    if (!ssh || !out)
        return 0;
    for (i = 0; keys[i]; i++) {
        if (!json_object_object_get_ex(ssh, keys[i], &v) || !v)
            continue;
        if (json_object_is_type(v, json_type_array)) {
            size_t cap = 1024, len = 0;
            char *buf = calloc(1, cap);
            int n = json_object_array_length(v);
            int j;

            if (!buf)
                return -1;
            for (j = 0; j < n; j++) {
                const char *line = json_object_get_string(json_object_array_get_idx(v, j));
                size_t need;

                if (!line)
                    line = "";
                need = strlen(line) + 2;
                if (len + need + 1 > cap) {
                    size_t ncap = cap * 2;
                    char *tmp;
                    while (len + need + 1 > ncap)
                        ncap *= 2;
                    tmp = realloc(buf, ncap);
                    if (!tmp) {
                        free(buf);
                        return -1;
                    }
                    buf = tmp;
                    cap = ncap;
                }
                memcpy(buf + len, line, strlen(line));
                len += strlen(line);
                buf[len++] = '\n';
                buf[len] = 0;
            }
            *out = buf;
            return 1;
        }
        *out = strdup(json_object_get_string(v) ? json_object_get_string(v) : "");
        return *out ? 1 : -1;
    }
    return 0;
}

static int nc_sys_write_authorized_keys_path(const char *path, const char *text)
{
    char tmp[256];
    char cmd[640];
    FILE *fp;
    char *copy, *line, *save = NULL;
    int key_count;

    if (!path || !text)
        return -1;
    copy = strdup(text);
    if (!copy)
        return -1;
    for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        line[strcspn(line, "\r")] = 0;
        if (!nc_sys_auth_key_line_ok(line)) {
            free(copy);
            return -2;
        }
    }
    free(copy);
    mkdir("/root", 0755);
    mkdir("/root/.ssh", 0700);
    chmod("/root/.ssh", 0700);
    mkdir("/etc/dropbear", 0700);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    fputs(text, fp);
    if (text[0] && text[strlen(text) - 1] != '\n')
        fputc('\n', fp);
    fclose(fp);
    chmod(tmp, 0600);
    key_count = nc_sys_authorized_keys_count_text(text);
    if (key_count < 0) {
        unlink(tmp);
        return -2;
    }
    if (key_count > 0 && nc_sys_path_exists("/usr/bin/ssh-keygen")) {
        snprintf(cmd, sizeof(cmd), "ssh-keygen -l -f '%s' >/dev/null 2>&1", tmp);
        if (system(cmd) != 0) {
            unlink(tmp);
            return -2;
        }
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    chmod(path, 0600);
    return 0;
}

static int nc_sys_sshd_has_dropin_include(const char *content)
{
    char *copy, *line, *save = NULL;
    int found = 0;

    if (!content)
        return 0;
    copy = strdup(content);
    if (!copy)
        return 0;
    for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ' || *line == '\t')
            line++;
        if (*line == '#' || strncasecmp(line, "Include", 7) ||
            !(line[7] == ' ' || line[7] == '\t'))
            continue;
        if (strstr(line, NC_OPENSSH_DROPIN_PATH) ||
            (strstr(line, "/etc/ssh/sshd_config.d/") && strstr(line, "*.conf"))) {
            found = 1;
            break;
        }
    }
    free(copy);
    return found;
}

static int nc_sys_write_text_file(const char *path, const char *text, mode_t mode)
{
    char tmp[320];
    FILE *fp;

    if (!path || !text)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    if (fputs(text, fp) == EOF || fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp);
        return -1;
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        return -1;
    }
    chmod(tmp, mode);
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    chmod(path, mode);
    return 0;
}

static int nc_sys_buf_append(char **buf, size_t *len, size_t *cap,
                             const char *text, size_t text_len)
{
    char *tmp;
    size_t ncap;

    if (!buf || !*buf || !len || !cap || !text)
        return -1;
    if (*len + text_len + 1 > *cap) {
        ncap = *cap ? *cap * 2 : 1024;
        while (*len + text_len + 1 > ncap)
            ncap *= 2;
        tmp = realloc(*buf, ncap);
        if (!tmp)
            return -1;
        *buf = tmp;
        *cap = ncap;
    }
    memcpy(*buf + *len, text, text_len);
    *len += text_len;
    (*buf)[*len] = 0;
    return 0;
}

static char *nc_sys_sshd_main_set_port(const char *content, int port)
{
    const char *cursor;
    char *out;
    size_t cap, len = 0;
    int seen_port = 0, in_match = 0;

    if (!content || port <= 0 || port > 65535)
        return NULL;
    cap = strlen(content) + 512;
    out = calloc(1, cap);
    if (!out)
        return NULL;
    cursor = content;
    while (*cursor) {
        const char *end = strchr(cursor, '\n');
        size_t line_len = end ? (size_t)(end - cursor) : strlen(cursor);
        const char *p = cursor;
        char rendered[1024];
        int starts_match;

        while ((size_t)(p - cursor) < line_len && (*p == ' ' || *p == '\t'))
            p++;
        starts_match = !in_match && (size_t)(p - cursor) + 5 < line_len && *p != '#' &&
                       !strncasecmp(p, "Match", 5) && (p[5] == ' ' || p[5] == '\t');
        if (!in_match && (size_t)(p - cursor) + 4 < line_len && *p != '#' &&
            !strncasecmp(p, "Port", 4) &&
            (p[4] == ' ' || p[4] == '\t' || p[4] == '=')) {
            if (!seen_port)
                snprintf(rendered, sizeof(rendered), "Port %d", port);
            else
                snprintf(rendered, sizeof(rendered), "# DreamingWrt disabled duplicate: %.*s",
                         (int)line_len, cursor);
            seen_port = 1;
            if (nc_sys_buf_append(&out, &len, &cap, rendered, strlen(rendered)) != 0)
                goto fail;
        } else if (starts_match && !seen_port) {
            snprintf(rendered, sizeof(rendered), "Port %d\n", port);
            seen_port = 1;
            if (nc_sys_buf_append(&out, &len, &cap, rendered, strlen(rendered)) != 0 ||
                nc_sys_buf_append(&out, &len, &cap, cursor, line_len) != 0)
                goto fail;
        } else {
            if (nc_sys_buf_append(&out, &len, &cap, cursor, line_len) != 0)
                goto fail;
        }
        if (starts_match)
            in_match = 1;
        if (end && nc_sys_buf_append(&out, &len, &cap, "\n", 1) != 0)
            goto fail;
        cursor = end ? end + 1 : cursor + line_len;
    }
    if (!seen_port) {
        char suffix[64];

        snprintf(suffix, sizeof(suffix), "%sPort %d\n",
                 len > 0 && out[len - 1] != '\n' ? "\n" : "", port);
        if (nc_sys_buf_append(&out, &len, &cap, suffix, strlen(suffix)) != 0)
            goto fail;
    }
    return out;
fail:
    free(out);
    return NULL;
}

static int nc_sys_sshd_config_apply(int port, int password_login, int root_password_login,
                                    int idle_timeout_min, int set_port,
                                    int *changed_out)
{
    char dropin[1024];
    char *main_content = NULL, *old_dropin = NULL, *new_main = NULL;
    int had_dropin, main_changed = 0, dropin_changed = 0, rc = -1;
    size_t main_len = 0;

    if (port <= 0 || port > 65535)
        return -1;
    if (changed_out)
        *changed_out = 0;
    main_content = nc_sys_read_file_alloc(NC_OPENSSH_CONFIG_PATH, 1 << 20, &main_len);
    if (!main_content)
        goto out;
    had_dropin = nc_sys_path_exists(NC_OPENSSH_DROPIN_PATH);
    if (had_dropin) {
        old_dropin = nc_sys_read_file_alloc(NC_OPENSSH_DROPIN_PATH, 1 << 16, NULL);
        if (!old_dropin)
            goto out;
    }
    mkdir("/etc/ssh", 0755);
    mkdir("/etc/ssh/sshd_config.d", 0755);
    snprintf(dropin, sizeof(dropin),
             "# Managed by DreamingWrt. Changes may be overwritten.\n"
             "PasswordAuthentication %s\n"
             "KbdInteractiveAuthentication %s\n"
             "PermitRootLogin %s\n"
             "PubkeyAuthentication yes\n"
             "AuthorizedKeysFile .ssh/authorized_keys\n"
             "ClientAliveInterval %d\n"
             "ClientAliveCountMax %d\n",
             password_login ? "yes" : "no", password_login ? "yes" : "no",
             root_password_login ? "yes" : "prohibit-password",
             idle_timeout_min > 0 ? idle_timeout_min * 60 : 0,
             idle_timeout_min > 0 ? 1 : 3);
    if (!old_dropin || strcmp(old_dropin, dropin)) {
        if (nc_sys_write_text_file(NC_OPENSSH_DROPIN_PATH, dropin, 0644) != 0)
            goto out;
        dropin_changed = 1;
    }
    if (!nc_sys_sshd_has_dropin_include(main_content)) {
        const char *include_line = "Include /etc/ssh/sshd_config.d/00-dreamingwrt.conf\n";
        size_t need = strlen(include_line) + main_len + 1;

        new_main = calloc(1, need);
        if (!new_main)
            goto rollback;
        snprintf(new_main, need, "%s%s", include_line, main_content);
        if (nc_sys_write_text_file(NC_OPENSSH_CONFIG_PATH, new_main, 0644) != 0)
            goto rollback;
        main_changed = 1;
    }
    if (set_port) {
        char *port_main = nc_sys_sshd_main_set_port(main_changed ? new_main : main_content, port);

        if (!port_main)
            goto rollback;
        if (strcmp(port_main, main_changed ? new_main : main_content)) {
            if (nc_sys_write_text_file(NC_OPENSSH_CONFIG_PATH, port_main, 0644) != 0) {
                free(port_main);
                goto rollback;
            }
            main_changed = 1;
        }
        free(port_main);
    }
    if ((main_changed || dropin_changed) &&
        system("sshd -t -f /etc/ssh/sshd_config >/dev/null 2>&1") != 0)
        goto rollback;
    if (changed_out)
        *changed_out = main_changed || dropin_changed;
    rc = 0;
    goto out;

rollback:
    if (main_changed)
        (void)nc_sys_write_text_file(NC_OPENSSH_CONFIG_PATH, main_content, 0644);
    if (had_dropin && dropin_changed)
        (void)nc_sys_write_text_file(NC_OPENSSH_DROPIN_PATH, old_dropin ? old_dropin : "", 0644);
    else if (!had_dropin && dropin_changed)
        unlink(NC_OPENSSH_DROPIN_PATH);
out:
    free(new_main);
    free(old_dropin);
    free(main_content);
    return rc;
}

static int nc_sys_restart_ssh_provider(const char *provider)
{
    if (provider && !strcmp(provider, "openssh"))
        return system("/etc/init.d/sshd restart >/dev/null 2>&1");
    return system("/etc/init.d/dropbear restart >/dev/null 2>&1");
}

static int nc_sys_reload_ssh_provider(const char *provider)
{
    int rc;

    if (provider && !strcmp(provider, "openssh")) {
        rc = system("/etc/init.d/sshd reload >/dev/null 2>&1");
        if (rc != 0)
            rc = nc_sys_restart_ssh_provider(provider);
        return rc;
    }
    return nc_sys_restart_ssh_provider(provider);
}

struct nc_sys_ssh_snapshot {
    char provider[16];
    const char *config_path;
    const char *auth_path;
    char *config_text;
    char *dropin_text;
    char *auth_text;
    int had_config;
    int had_dropin;
    int had_auth;
    int enabled;
    int running;
};

static const char *nc_sys_ssh_init_path(const char *provider)
{
    return provider && !strcmp(provider, "openssh") ?
           "/etc/init.d/sshd" : "/etc/init.d/dropbear";
}

static int nc_sys_ssh_running(const char *provider)
{
    return system(provider && !strcmp(provider, "openssh") ?
                  "pgrep -x sshd >/dev/null 2>&1" :
                  "pgrep -x dropbear >/dev/null 2>&1") == 0;
}

static int nc_sys_ssh_enabled(const char *provider)
{
    char cmd[160];
    const char *init = nc_sys_ssh_init_path(provider);

    if (!nc_sys_path_exists(init))
        return nc_sys_ssh_running(provider);
    snprintf(cmd, sizeof(cmd), "%s enabled >/dev/null 2>&1", init);
    return system(cmd) == 0;
}

static int nc_sys_ssh_service_action(const char *provider, const char *action)
{
    char cmd[192];
    const char *init = nc_sys_ssh_init_path(provider);

    if (!action || (!strcmp(action, "enable") && !nc_sys_path_exists(init)))
        return -1;
    if (strcmp(action, "enable") && strcmp(action, "disable") &&
        strcmp(action, "start") && strcmp(action, "stop") &&
        strcmp(action, "reload") && strcmp(action, "restart"))
        return -1;
    snprintf(cmd, sizeof(cmd), "%s %s >/dev/null 2>&1", init, action);
    return system(cmd) == 0 ? 0 : -1;
}

static void nc_sys_ssh_snapshot_free(struct nc_sys_ssh_snapshot *snapshot)
{
    if (!snapshot)
        return;
    free(snapshot->config_text);
    free(snapshot->dropin_text);
    free(snapshot->auth_text);
    memset(snapshot, 0, sizeof(*snapshot));
}

static int nc_sys_ssh_snapshot_capture(const char *provider,
                                       struct nc_sys_ssh_snapshot *snapshot)
{
    if (!provider || !snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    snprintf(snapshot->provider, sizeof(snapshot->provider), "%s", provider);
    snapshot->config_path = !strcmp(provider, "openssh") ?
                            NC_OPENSSH_CONFIG_PATH : "/etc/config/dropbear";
    snapshot->auth_path = !strcmp(provider, "openssh") ?
                          NC_OPENSSH_AUTH_KEYS_PATH : NC_DROPBEAR_AUTH_KEYS_PATH;
    snapshot->had_config = nc_sys_path_exists(snapshot->config_path);
    snapshot->had_dropin = !strcmp(provider, "openssh") &&
                           nc_sys_path_exists(NC_OPENSSH_DROPIN_PATH);
    snapshot->had_auth = nc_sys_path_exists(snapshot->auth_path);
    if (snapshot->had_config) {
        snapshot->config_text = nc_sys_read_file_alloc(
            snapshot->config_path, 1 << 20, NULL);
        if (!snapshot->config_text)
            goto failed;
    }
    if (snapshot->had_dropin) {
        snapshot->dropin_text = nc_sys_read_file_alloc(
            NC_OPENSSH_DROPIN_PATH, 1 << 16, NULL);
        if (!snapshot->dropin_text)
            goto failed;
    }
    if (snapshot->had_auth) {
        snapshot->auth_text = nc_sys_read_file_alloc(
            snapshot->auth_path, 1 << 20, NULL);
        if (!snapshot->auth_text)
            goto failed;
    }
    snapshot->enabled = nc_sys_ssh_enabled(provider);
    snapshot->running = nc_sys_ssh_running(provider);
    return 0;

failed:
    nc_sys_ssh_snapshot_free(snapshot);
    return -1;
}

static int nc_sys_restore_text_file(const char *path, const char *text,
                                    int existed, mode_t mode)
{
    if (!path)
        return -1;
    if (!existed)
        return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
    return text ? nc_sys_write_text_file(path, text, mode) : -1;
}

static int nc_sys_ssh_snapshot_restore(struct nc_sys_ssh_snapshot *snapshot)
{
    int rc = 0;
    int running;

    if (!snapshot || !snapshot->provider[0])
        return -1;
    if (nc_sys_restore_text_file(snapshot->config_path, snapshot->config_text,
                                 snapshot->had_config, 0644) != 0)
        rc = -1;
    if (!strcmp(snapshot->provider, "openssh") &&
        nc_sys_restore_text_file(NC_OPENSSH_DROPIN_PATH, snapshot->dropin_text,
                                 snapshot->had_dropin, 0644) != 0)
        rc = -1;
    if (nc_sys_restore_text_file(snapshot->auth_path, snapshot->auth_text,
                                 snapshot->had_auth, 0600) != 0)
        rc = -1;
    if (!strcmp(snapshot->provider, "openssh") && snapshot->had_config &&
        system("sshd -t -f /etc/ssh/sshd_config >/dev/null 2>&1") != 0)
        rc = -1;

    if (nc_sys_ssh_service_action(snapshot->provider,
            snapshot->enabled ? "enable" : "disable") != 0)
        rc = -1;
    running = nc_sys_ssh_running(snapshot->provider);
    if (snapshot->running) {
        if (running) {
            if (nc_sys_reload_ssh_provider(snapshot->provider) != 0)
                rc = -1;
        } else if (nc_sys_ssh_service_action(snapshot->provider, "start") != 0) {
            rc = -1;
        }
    } else if (running &&
               nc_sys_ssh_service_action(snapshot->provider, "stop") != 0) {
        rc = -1;
    }
    if (nc_sys_ssh_enabled(snapshot->provider) != snapshot->enabled ||
        nc_sys_ssh_running(snapshot->provider) != snapshot->running)
        rc = -1;
    return rc;
}

static int nc_sys_ssh_apply_service_state(const char *provider,
                                          int enabled_touched,
                                          int enabled,
                                          int config_changed,
                                          int was_running)
{
    int running;

    if (enabled_touched && nc_sys_ssh_service_action(
            provider, enabled ? "enable" : "disable") != 0)
        return -1;
    running = nc_sys_ssh_running(provider);
    if (enabled_touched) {
        if (enabled) {
            if (!running && nc_sys_ssh_service_action(provider, "start") != 0)
                return -1;
            if (running && config_changed &&
                nc_sys_reload_ssh_provider(provider) != 0)
                return -1;
        } else if (running && nc_sys_ssh_service_action(provider, "stop") != 0) {
            return -1;
        }
    } else if (config_changed && was_running &&
               nc_sys_reload_ssh_provider(provider) != 0) {
        return -1;
    }
    if (enabled_touched &&
        (nc_sys_ssh_enabled(provider) != (enabled ? 1 : 0) ||
         nc_sys_ssh_running(provider) != (enabled ? 1 : 0)))
        return -1;
    if (!enabled_touched && was_running && !nc_sys_ssh_running(provider))
        return -1;
    return 0;
}

static int nc_sys_ssh_settings_apply(struct json_object *ssh)
{
    const char *provider = nc_sys_ssh_provider();
    const char *auth_path = !strcmp(provider, "openssh") ?
                            NC_OPENSSH_AUTH_KEYS_PATH : NC_DROPBEAR_AUTH_KEYS_PATH;
    struct nc_sys_openssh_state openssh_state;
    struct nc_sys_ssh_snapshot snapshot;
    struct json_object *value = NULL;
    char *keys_text = NULL;
    int keys_state;
    int port;
    int password_login;
    int root_password_login;
    int idle_timeout_min;
    int enabled;
    int enabled_touched = 0;
    int config_touched = 0;
    int config_changed = 0;
    int port_touched = 0;
    int final_key_count;
    int rc = -1;

    if (!ssh || !json_object_is_type(ssh, json_type_object))
        return -1;
    keys_state = nc_sys_extract_authorized_keys(ssh, &keys_text);
    if (keys_state < 0)
        goto done;
    if (!strcmp(provider, "openssh")) {
        nc_sys_openssh_state_load(&openssh_state);
        port = openssh_state.port;
        password_login = openssh_state.password_login;
        root_password_login = openssh_state.root_password_login;
        idle_timeout_min = openssh_state.idle_timeout_min;
    } else {
        port = nc_sys_dropbear_port();
        password_login = nc_sys_dropbear_password_login();
        root_password_login = nc_sys_dropbear_root_password_login();
        idle_timeout_min = nc_sys_dropbear_idle_timeout();
    }
    enabled = nc_sys_ssh_enabled(provider);

    if (json_object_object_get_ex(ssh, "port", &value)) {
        port = json_object_get_int(value);
        config_touched = 1;
        port_touched = 1;
    }
    if (json_object_object_get_ex(ssh, "password_login", &value)) {
        password_login = json_object_get_boolean(value);
        config_touched = 1;
    }
    if (json_object_object_get_ex(ssh, "root_password_login", &value)) {
        root_password_login = json_object_get_boolean(value);
        config_touched = 1;
    }
    if (json_object_object_get_ex(ssh, "idle_timeout_min", &value)) {
        idle_timeout_min = json_object_get_int(value);
        if (idle_timeout_min < 0)
            idle_timeout_min = 0;
        if (idle_timeout_min > 1440)
            idle_timeout_min = 1440;
        config_touched = 1;
    }
    if (json_object_object_get_ex(ssh, "key_only", &value)) {
        config_touched = 1;
        if (json_object_get_boolean(value)) {
            password_login = 0;
            root_password_login = 0;
        }
    }
    if (json_object_object_get_ex(ssh, "enabled", &value)) {
        enabled = json_object_get_boolean(value);
        enabled_touched = 1;
    }
    if (port <= 0 || port > 65535)
        goto done;
    final_key_count = keys_state == 1 ?
        nc_sys_authorized_keys_count_text(keys_text ? keys_text : "") :
        nc_sys_authorized_keys_count_path(auth_path);
    if (final_key_count < 0 ||
        ((!password_login && !root_password_login) && final_key_count <= 0))
        goto done;
    if (nc_sys_ssh_snapshot_capture(provider, &snapshot) != 0)
        goto done;

    if (keys_state == 1 &&
        nc_sys_write_authorized_keys_path(auth_path, keys_text ? keys_text : "") != 0)
        goto rollback;
    if (!strcmp(provider, "openssh")) {
        if (config_touched &&
            nc_sys_sshd_config_apply(port, password_login, root_password_login,
                                     idle_timeout_min, port_touched,
                                     &config_changed) != 0)
            goto rollback;
    } else if (config_touched) {
        char command[768];

        if (idle_timeout_min > 0) {
            snprintf(command, sizeof(command),
                "uci set dropbear.@dropbear[0].Port='%d' && "
                "uci set dropbear.@dropbear[0].PasswordAuth='%s' && "
                "uci set dropbear.@dropbear[0].RootPasswordAuth='%s' && "
                "uci set dropbear.@dropbear[0].IdleTimeout='%d' && "
                "uci commit dropbear",
                port, password_login ? "on" : "off",
                root_password_login ? "on" : "off", idle_timeout_min * 60);
        } else {
            snprintf(command, sizeof(command),
                "uci set dropbear.@dropbear[0].Port='%d' && "
                "uci set dropbear.@dropbear[0].PasswordAuth='%s' && "
                "uci set dropbear.@dropbear[0].RootPasswordAuth='%s' && "
                "{ uci -q delete dropbear.@dropbear[0].IdleTimeout || true; } && "
                "uci commit dropbear",
                port, password_login ? "on" : "off",
                root_password_login ? "on" : "off");
        }
        if (system(command) != 0)
            goto rollback;
        config_changed = 1;
    }
    if (nc_sys_ssh_apply_service_state(provider, enabled_touched, enabled,
                                       config_changed, snapshot.running) != 0)
        goto rollback;

    rc = 0;
    nc_sys_ssh_snapshot_free(&snapshot);
    goto done;

rollback:
    if (nc_sys_ssh_snapshot_restore(&snapshot) != 0)
        LOG_ERROR("SSH apply failed and rollback verification failed for provider=%s\n",
                  provider);
    nc_sys_ssh_snapshot_free(&snapshot);
done:
    free(keys_text);
    return rc;
}

static char *nc_sys_crontab_text(void)
{
    return nc_sys_read_file_text("/etc/crontabs/root", 1 << 16);
}

int jmx_crontab_apply_text(const char *text, struct json_object *out)
{
    struct jmx_system_text_apply_opts opts;
    struct jmx_system_text_apply_result result;
    char error[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    size_t bad_line = 0;
    int rc;

    if (!text || !out) return -1;
    if (jmx_system_crontab_validate_text(text, &bad_line,
                                         error, sizeof(error)) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string(error));
        json_object_object_add(out, "line", json_object_new_int64((int64_t)bad_line));
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    opts.path = "/etc/crontabs/root";
    opts.backup_path = "/etc/crontabs/root.dreamingwrt.bak";
    opts.reload_bin = "/etc/init.d/cron";
    opts.reload_action = "restart";
    opts.max_bytes = 1U << 16;
    opts.mode = 0600;
    opts.reload_timeout_ms = 10000;
    rc = jmx_system_text_apply(text, &opts, &result);
    json_object_object_add(out, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "path", json_object_new_string("/etc/crontabs/root"));
    json_object_object_add(out, "backup_path", json_object_new_string(result.backup_path));
    json_object_object_add(out, "changed", json_object_new_boolean(result.changed));
    json_object_object_add(out, "reloaded", json_object_new_boolean(result.reloaded));
    json_object_object_add(out, "rollback_attempted",
                           json_object_new_boolean(result.rollback_attempted));
    json_object_object_add(out, "rollback_succeeded",
                           json_object_new_boolean(result.rollback_succeeded));
    json_object_object_add(out, "applied_at",
                           json_object_new_int64(result.applied_at));
    json_object_object_add(out, "last_reload_at",
                           json_object_new_int64(result.reloaded ? result.applied_at : 0));
    if (result.error[0])
        json_object_object_add(out, "error", json_object_new_string(result.error));
    if (rc == 0) {
        char *saved = nc_sys_crontab_text();
        if (saved) {
            json_object_object_add(out, "text", json_object_new_string(saved));
            free(saved);
        }
    }
    return rc == 0 ? 0 : -1;
}

int jmx_system_time_sync_browser(int64_t client_ts, struct json_object *out)
{
    if (!out || client_ts <= 0) return -1;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "date -s @%lld >/dev/null 2>&1", (long long)client_ts);
    int ok = system(cmd) == 0;
    if (ok && jmx_netconfig_db_init() == 0) {
        nc_sys_settings_db_init();
        sqlite3_stmt *st = NULL;
        if (nc_prepare(&st, "UPDATE system_settings SET last_time_sync_at=?,updated_at=? WHERE id=1") == 0) {
            sqlite3_int64 n = (sqlite3_int64)nc_now_s();
            sqlite3_bind_int64(st, 1, n);
            sqlite3_bind_int64(st, 2, n);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
    json_object_object_add(out, "ok", json_object_new_boolean(ok));
    json_object_object_add(out, "source", json_object_new_string("browser"));
    json_object_object_add(out, "last_time_sync_at", json_object_new_int64(nc_now_s()));
    json_object_object_add(out, "message", json_object_new_string(ok ? "synced" : "date_set_failed"));
    return ok ? 0 : -1;
}

int jmx_system_time_sync_ntp(struct json_object *out)
{
    if (!out) return -1;
    int ok = system("ntpd -n -q -p ntp.aliyun.com -p time.cloudflare.com >/dev/null 2>&1") == 0;
    if (ok && jmx_netconfig_db_init() == 0) {
        nc_sys_settings_db_init();
        sqlite3_stmt *st = NULL;
        if (nc_prepare(&st, "UPDATE system_settings SET last_time_sync_at=?,updated_at=? WHERE id=1") == 0) {
            sqlite3_int64 n = (sqlite3_int64)nc_now_s();
            sqlite3_bind_int64(st, 1, n);
            sqlite3_bind_int64(st, 2, n);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
    json_object_object_add(out, "ok", json_object_new_boolean(ok));
    json_object_object_add(out, "source", json_object_new_string("ntp"));
    json_object_object_add(out, "last_time_sync_at", json_object_new_int64(nc_now_s()));
    json_object_object_add(out, "message", json_object_new_string(ok ? "synced" : "ntp_sync_failed"));
    return ok ? 0 : -1;
}

struct json_object *jmx_system_startup_service_action(struct json_object *req)
{
    struct nc_sys_service_handle handle;
    struct jmx_exec_result result;
    struct jmx_exec_result rollback_result;
    struct json_object *resp;
    struct json_object *services;
    const char *reason = "ok";
    int previous_enabled = 0;
    int previous_enabled_known = 0;
    int previous_priority = 50;
    int previous_running = 0;
    int previous_running_known = 0;
    int current_enabled = 0;
    int current_enabled_known = 0;
    int current_priority = 50;
    int current_running = 0;
    int current_running_known = 0;
    int supports_reload;
    int exec_rc = 0;
    int exec_ok = 1;
    int readback_ok = 0;
    int rollback_attempted = 0;
    int rollback_succeeded = 0;
    int services_truncated = 0;
    int services_degraded = 0;

    if (!req)
        return NULL;
    const char *service = nc_json_str_def(req, "service", "");
    const char *action = nc_json_str_def(req, "action", "");
    if (!nc_sys_service_name_ok(service) ||
        nc_sys_service_open(service, &handle) != 0) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_service"));
        return resp;
    }
    int is_critical = nc_sys_service_is_critical(service);
    if (is_critical && nc_json_bool_def(req, "confirm_critical", 0) == 0 &&
        (strcmp(action, "enable") == 0 || strcmp(action, "disable") == 0 ||
         strcmp(action, "start") == 0 || strcmp(action, "stop") == 0 || strcmp(action, "restart") == 0 || strcmp(action, "reload") == 0)) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("critical_confirm_required"));
        json_object_object_add(resp, "service", json_object_new_string(service));
        nc_sys_service_close(&handle);
        return resp;
    }
    if (!nc_sys_service_action_ok(action)) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("unsupported_action"));
        nc_sys_service_close(&handle);
        return resp;
    }
    previous_enabled_known = nc_sys_service_enabled(
        &handle, &previous_enabled, &previous_priority) == 0;
    previous_running_known = nc_sys_service_running(
        &handle, NC_SYS_SERVICE_STATUS_TIMEOUT_MS,
        &previous_running, &previous_running_known) == 0;
    supports_reload = nc_sys_service_supports_reload(&handle);
    if (!strcmp(action, "reload") && !supports_reload) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error",
                               json_object_new_string("unsupported_action"));
        json_object_object_add(resp, "service", json_object_new_string(service));
        nc_sys_service_close(&handle);
        return resp;
    }

    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    exec_rc = nc_sys_service_exec(
        &handle, action,
        !strcmp(action, "status") ? NC_SYS_SERVICE_STATUS_TIMEOUT_MS :
                                    NC_SYS_SERVICE_ACTION_TIMEOUT_MS,
        &result);
    exec_ok = nc_sys_service_exec_ok(exec_rc, &result);
    current_enabled_known = nc_sys_service_enabled(
        &handle, &current_enabled, &current_priority) == 0;
    current_running_known = nc_sys_service_running(
        &handle, NC_SYS_SERVICE_STATUS_TIMEOUT_MS,
        &current_running, &current_running_known) == 0;

    if (!strcmp(action, "enable"))
        readback_ok = current_enabled_known && current_enabled;
    else if (!strcmp(action, "disable"))
        readback_ok = current_enabled_known && !current_enabled;
    else if (!strcmp(action, "start") || !strcmp(action, "restart") ||
             !strcmp(action, "reload"))
        readback_ok = current_running_known && current_running;
    else if (!strcmp(action, "stop"))
        readback_ok = current_running_known && !current_running;
    else
        readback_ok = previous_enabled_known && previous_running_known &&
                      current_enabled_known && current_running_known;

    if ((!exec_ok || !readback_ok) && strcmp(action, "status")) {
        const char *rollback_action = NULL;
        int rollback_state_known = 0;
        int rollback_state = 0;

        if ((!strcmp(action, "enable") || !strcmp(action, "disable")) &&
            previous_enabled_known && current_enabled_known &&
            previous_enabled != current_enabled) {
            rollback_action = previous_enabled ? "enable" : "disable";
            rollback_state_known = 1;
            rollback_state = previous_enabled;
        } else if ((!strcmp(action, "start") || !strcmp(action, "stop") ||
                    !strcmp(action, "restart") || !strcmp(action, "reload")) &&
                   previous_running_known && current_running_known &&
                   previous_running != current_running) {
            rollback_action = previous_running ? "start" : "stop";
            rollback_state_known = 1;
            rollback_state = previous_running;
        }
        if (rollback_action) {
            int rollback_exec_rc;
            int rollback_exec_ok;

            rollback_attempted = 1;
            memset(&rollback_result, 0, sizeof(rollback_result));
            rollback_result.exit_code = -1;
            rollback_exec_rc = nc_sys_service_exec(
                &handle, rollback_action, NC_SYS_SERVICE_ACTION_TIMEOUT_MS,
                &rollback_result);
            rollback_exec_ok = nc_sys_service_exec_ok(
                rollback_exec_rc, &rollback_result);
            if (!strcmp(action, "enable") || !strcmp(action, "disable")) {
                current_enabled_known = nc_sys_service_enabled(
                    &handle, &current_enabled, &current_priority) == 0;
                rollback_succeeded = rollback_exec_ok &&
                    rollback_state_known && current_enabled_known &&
                    current_enabled == rollback_state;
            } else {
                current_running_known = nc_sys_service_running(
                    &handle, NC_SYS_SERVICE_STATUS_TIMEOUT_MS,
                    &current_running, &current_running_known) == 0;
                rollback_succeeded = rollback_exec_ok &&
                    rollback_state_known && current_running_known &&
                    current_running == rollback_state;
            }
            jmx_exec_result_free(&rollback_result);
        }
    }

    if (!exec_ok)
        reason = result.timed_out ? "command_timeout" :
                 (result.term_signal ? "command_signaled" :
                  (exec_rc != 0 || result.exit_code == 126 ||
                   result.exit_code == 127 ? "exec_failed" :
                   "command_failed"));
    else if (!readback_ok)
        reason = "readback_mismatch";
    if (rollback_attempted && !rollback_succeeded)
        reason = "rollback_failed";

    if ((!exec_ok || !readback_ok) && strcmp(action, "status"))
        dw_report_config_commit_failed("system_service", service, reason,
                                       !(rollback_attempted && !rollback_succeeded));

    services = nc_sys_services_json(&services_truncated, &services_degraded);
    resp = json_object_new_object();
    json_object_object_add(resp, "ok",
                           json_object_new_boolean(exec_ok && readback_ok));
    json_object_object_add(resp, "service", json_object_new_string(service));
    json_object_object_add(resp, "action", json_object_new_string(action));
    json_object_object_add(resp, "reason", json_object_new_string(reason));
    json_object_object_add(resp, "previous_enabled",
                           json_object_new_boolean(previous_enabled));
    json_object_object_add(resp, "previous_enabled_known",
                           json_object_new_boolean(previous_enabled_known));
    json_object_object_add(resp, "current_enabled",
                           json_object_new_boolean(current_enabled));
    json_object_object_add(resp, "current_enabled_known",
                           json_object_new_boolean(current_enabled_known));
    json_object_object_add(resp, "previous_running",
                           json_object_new_boolean(previous_running));
    json_object_object_add(resp, "previous_running_known",
                           json_object_new_boolean(previous_running_known));
    json_object_object_add(resp, "current_running",
                           json_object_new_boolean(current_running));
    json_object_object_add(resp, "current_running_known",
                           json_object_new_boolean(current_running_known));
    json_object_object_add(resp, "supports_reload",
                           json_object_new_boolean(supports_reload));
    json_object_object_add(resp, "timed_out",
                           json_object_new_boolean(result.timed_out));
    json_object_object_add(resp, "term_signal",
                           json_object_new_int(result.term_signal));
    json_object_object_add(resp, "exit_code",
                           json_object_new_int(result.exit_code));
    json_object_object_add(resp, "rollback_attempted",
                           json_object_new_boolean(rollback_attempted));
    json_object_object_add(resp, "rollback_succeeded",
                           json_object_new_boolean(rollback_succeeded));
    json_object_object_add(resp, "ts", json_object_new_int64(nc_now_s()));
    json_object_object_add(resp, "services",
                           services ? services : json_object_new_array());
    json_object_object_add(resp, "services_truncated",
                           json_object_new_boolean(services_truncated));
    json_object_object_add(resp, "services_degraded",
                           json_object_new_boolean(services_degraded));
    jmx_exec_result_free(&result);
    nc_sys_service_close(&handle);
    return resp;
}

int jmx_system_rc_local_apply(const char *content, int confirm_no_exit0, struct json_object *out)
{
    struct jmx_system_text_apply_opts opts;
    struct jmx_system_text_apply_result result;
    int rc;

    if (!out) return -1;
    if (!content) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("empty_content"));
        return -1;
    }
    const char *has_exit = strstr(content, "exit 0");
    if (!has_exit && !confirm_no_exit0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("exit0_required"));
        json_object_object_add(out, "message", json_object_new_string("rc.local must contain exit 0"));
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    opts.path = "/etc/rc.local";
    opts.backup_path = "/etc/rc.local.dreamingwrt.bak";
    opts.max_bytes = 1U << 16;
    opts.mode = 0755;
    rc = jmx_system_text_apply(content, &opts, &result);
    json_object_object_add(out, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "path", json_object_new_string("/etc/rc.local"));
    json_object_object_add(out, "backup_path", json_object_new_string(result.backup_path));
    json_object_object_add(out, "changed", json_object_new_boolean(result.changed));
    json_object_object_add(out, "rollback_attempted",
                           json_object_new_boolean(result.rollback_attempted));
    json_object_object_add(out, "rollback_succeeded",
                           json_object_new_boolean(result.rollback_succeeded));
    json_object_object_add(out, "ts", json_object_new_int64(result.applied_at));
    if (result.error[0])
        json_object_object_add(out, "error", json_object_new_string(result.error));
    if (rc == 0) {
        char *saved = nc_sys_read_file_text("/etc/rc.local", 1 << 16);
        if (saved) {
            json_object_object_add(out, "content", json_object_new_string(saved));
            free(saved);
        }
    }
    return rc == 0 ? 0 : -1;
}

static int nc_b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t nc_base64_decode(const char *in, unsigned char *out, size_t out_len)
{
    if (!in || !out) return 0;
    size_t o = 0;
    unsigned int buf = 0;
    int bits = 0;
    for (const char *p = in; *p; p++) {
        char c = *p;
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') {
            if (c == '=') break;
            continue;
        }
        int val = nc_b64_val(c);
        if (val < 0) continue;
        buf = (buf << 6) | (unsigned int)val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < out_len) out[o++] = (unsigned char)((buf >> bits) & 0xFF);
        }
    }
    return o;
}

static int nc_admin_password_complexity_ok(const char *pw)
{
    if (!pw) return 0;
    size_t len = strlen(pw);
    if (len < 8 || len > 128) return 0;
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (const char *p = pw; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (isupper(c)) has_upper = 1;
        else if (islower(c)) has_lower = 1;
        else if (isdigit(c)) has_digit = 1;
        else has_special = 1;
    }
    return (has_upper + has_lower + has_digit + has_special) >= 3;
}

/*
 * Strong-random hex, used for the PBKDF2 salt of web user password hashes.
 *
 * Returns 0 on success and -1 when strong randomness is unavailable, in which
 * case the buffer is cleared and the caller must abort. There is deliberately no
 * weak fallback: this used to drop to srand(time(NULL)) + rand() whenever
 * fopen("/dev/urandom") failed, which is reachable through fd exhaustion or an
 * early-boot /dev, and silent. A salt an attacker can predict from the account
 * creation time removes the point of salting, because password hashes can then
 * be precomputed.
 *
 * The old loop also ignored fgetc() failure: EOF is -1 and -1 & 0xf is 15, so a
 * failed read silently produced 'f' for every byte.
 */
static int nc_random_hex(char *out, int len)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char buf[64];
    int produced = 0;

    if (!out || len <= 0)
        return -1;
    out[0] = '\0';
    while (produced < len) {
        size_t want = (size_t)(len - produced + 1) / 2;
        ssize_t got;
        size_t i;

        if (want > sizeof(buf))
            want = sizeof(buf);
        got = getrandom(buf, want, 0);
        if (got <= 0) {
            if (got < 0 && errno == EINTR)
                continue;
            memset(out, 0, (size_t)len + 1);
            return -1;
        }
        for (i = 0; i < (size_t)got && produced < len; i++) {
            out[produced++] = hex[(buf[i] >> 4) & 0xf];
            if (produced < len)
                out[produced++] = hex[buf[i] & 0xf];
        }
    }
    out[len] = '\0';
    return 0;
}

static int nc_hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int nc_hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    size_t i;

    if (!hex || !out || strlen(hex) != out_len * 2)
        return -1;
    for (i = 0; i < out_len; i++) {
        int hi = nc_hex_val(hex[i * 2]);
        int lo = nc_hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static void nc_bytes_to_hex(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (!out || out_len == 0)
        return;
    if (!in || out_len < in_len * 2 + 1) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i < in_len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[in[i] & 0xf];
    }
    out[in_len * 2] = '\0';
}

static int nc_web_password_hash(const char *password, char *out, size_t out_len)
{
    char salt_hex[NC_WEBD_SALT_HEX_LEN + 1];
    unsigned char salt[NC_WEBD_SALT_HEX_LEN / 2];
    unsigned char dk[NC_WEBD_PBKDF2_DK_LEN];
    char dk_hex[NC_WEBD_PBKDF2_DK_LEN * 2 + 1];

    if (!password || !password[0] || !out || out_len == 0)
        return -1;
    /* Refuse to hash rather than salt with a predictable value. */
    if (nc_random_hex(salt_hex, NC_WEBD_SALT_HEX_LEN) != 0)
        return -1;
    if (nc_hex_to_bytes(salt_hex, salt, sizeof(salt)) != 0)
        return -1;
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                          NC_WEBD_PBKDF2_ITER, EVP_sha256(), sizeof(dk), dk) != 1)
        return -1;
    nc_bytes_to_hex(dk, sizeof(dk), dk_hex, sizeof(dk_hex));
    if (!dk_hex[0])
        return -1;
    if (snprintf(out, out_len, "pbkdf2-sha256$%d$%s$%s",
                 NC_WEBD_PBKDF2_ITER, salt_hex, dk_hex) >= (int)out_len)
        return -1;
    return 0;
}

#include "../webd/webd_owner_policy.h"
static int nc_web_users_ensure_schema(void)
{
    if (nc_exec("CREATE TABLE IF NOT EXISTS web_users ("
                "username TEXT PRIMARY KEY,"
                "password_hash TEXT NOT NULL,"
                "status TEXT NOT NULL DEFAULT 'enabled',"
                "role TEXT NOT NULL DEFAULT 'admin',"
                "permissions_json TEXT NOT NULL DEFAULT '[]',"
                "twofa_enabled INTEGER NOT NULL DEFAULT 0,"
                "twofa_secret TEXT NOT NULL DEFAULT '',"
                "twofa_bound_at INTEGER NOT NULL DEFAULT 0,"
                "twofa_last_counter INTEGER NOT NULL DEFAULT -1,"
                "avatar_url TEXT NOT NULL DEFAULT '',"
                "created_at INTEGER NOT NULL,"
                "updated_at INTEGER NOT NULL,"
                "last_login_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return -1;
    if (nc_add_column_if_missing("web_users", "avatar_url",
                                 "TEXT NOT NULL DEFAULT ''") != 0)
        return -1;
    if (webd_owner_policy_install(g_netconfig_db) != 0 ||
        webd_owner_migrate_setup(g_netconfig_db) != 0)
        return -1;
    return 0;
}

static int nc_web_user_avatar_persist(const char *username, const char *avatar_url)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!username || !username[0] || !avatar_url || !avatar_url[0] ||
        nc_web_users_ensure_schema() != 0)
        return -1;
    if (nc_prepare(&st,
        "UPDATE web_users SET avatar_url=?1,updated_at=?2 WHERE username=?3") != 0)
        return -1;
    sqlite3_bind_text(st, 1, avatar_url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, nc_now_s());
    sqlite3_bind_text(st, 3, username, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) == 0 && sqlite3_changes(g_netconfig_db) > 0)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int nc_web_user_password_set(const char *username, const char *password,
                                    int create_if_missing,
                                    struct json_object *out)
{
    sqlite3_stmt *st = NULL;
    char hash[160];
    int exists = 0;
    int rc = -1;
    int64_t now = nc_now_s();

    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(out, "web_error", json_object_new_string("config_db_open_failed"));
        return -1;
    }

    if (nc_web_users_ensure_schema() != 0) {
        json_object_object_add(out, "web_error", json_object_new_string("web_users_schema_failed"));
        return -1;
    }

    if (nc_web_password_hash(password, hash, sizeof(hash)) != 0) {
        json_object_object_add(out, "web_error", json_object_new_string("password_hash_failed"));
        return -1;
    }

    if (nc_prepare(&st, "SELECT 1 FROM web_users WHERE username=?1") == 0) {
        sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
        exists = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
        st = NULL;
    }

    if (exists) {
        if (nc_prepare(&st,
            "UPDATE web_users SET password_hash=?1,status='enabled',updated_at=?2 "
            "WHERE username=?3") == 0) {
            sqlite3_bind_text(st, 1, hash, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, now);
            sqlite3_bind_text(st, 3, username, -1, SQLITE_TRANSIENT);
            rc = nc_step_done(st);
            sqlite3_finalize(st);
        }
    } else if (create_if_missing) {
        if (nc_prepare(&st,
            "INSERT INTO web_users(username,password_hash,status,role,permissions_json,created_at,updated_at,last_login_at) "
            "VALUES(?1,?2,'enabled','admin','[]',?3,?3,0)") == 0) {
            sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, hash, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 3, now);
            rc = nc_step_done(st);
            sqlite3_finalize(st);
        }
    } else {
        json_object_object_add(out, "web_error", json_object_new_string("web_user_not_found"));
        return -1;
    }

    json_object_object_add(out, "web_user_updated", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "web_user_created",
                           json_object_new_boolean(rc == 0 && !exists && create_if_missing));
    json_object_object_add(out, "password_algorithm", json_object_new_string("pbkdf2-sha256"));
    json_object_object_add(out, "password_iterations", json_object_new_int(NC_WEBD_PBKDF2_ITER));
    if (rc != 0)
        json_object_object_add(out, "web_error", json_object_new_string("web_users_update_failed"));
    return rc;
}

static int nc_chpasswd_stdin(const char *username, const char *password)
{
    int fds[2];
    pid_t pid;
    int status = 0;

    if (!username || !password)
        return -1;
    if (pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(fds[0], STDIN_FILENO);
        close(fds[0]);
        close(fds[1]);
        execlp("chpasswd", "chpasswd", (char *)NULL);
        _exit(127);
    }
    close(fds[0]);
    dprintf(fds[1], "%s:%s\n", username, password);
    close(fds[1]);
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/*
 * Rewrite the leading "root:" field of one account file to new_name.
 *
 * Done in-process with a temporary file plus rename() rather than sed -i, so a
 * reader never observes a half-written /etc/passwd, and so a failure leaves the
 * original file untouched. backup_path, when given, receives a copy of the
 * original contents so the caller can roll the first file back if the second
 * one fails; leaving /etc/passwd and /etc/shadow disagreeing about the account
 * name locks every login out of the device.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int nc_admin_rewrite_account_file(const char *path, const char *new_name,
                                         const char *backup_path)
{
    char tmp_path[PATH_MAX];
    FILE *src = NULL, *dst = NULL, *bak = NULL;
    struct stat st;
    char line[4096];
    int rc = -1;
    int replaced = 0;

    if (!path || !new_name || !new_name[0])
        return -1;
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.jmxd-rename.tmp", path) >=
        (int)sizeof(tmp_path))
        return -1;

    src = fopen(path, "r");
    if (!src)
        return -1;
    if (fstat(fileno(src), &st) != 0)
        goto done;
    /* The temporary file must carry the original file's mode from the start:
     * /etc/shadow is 0600 and must never exist as anything looser, even
     * briefly. */
    dst = fopen(tmp_path, "w");
    if (!dst)
        goto done;
    if (fchmod(fileno(dst), st.st_mode & 07777) != 0)
        goto done;
    if (backup_path) {
        bak = fopen(backup_path, "w");
        if (!bak || fchmod(fileno(bak), st.st_mode & 07777) != 0)
            goto done;
    }

    while (fgets(line, sizeof(line), src)) {
        if (bak && fputs(line, bak) == EOF)
            goto done;
        if (!replaced && !strncmp(line, "root:", 5)) {
            if (fprintf(dst, "%s:%s", new_name, line + 5) < 0)
                goto done;
            replaced = 1;
            continue;
        }
        if (fputs(line, dst) == EOF)
            goto done;
    }
    if (ferror(src) || !replaced)
        goto done;
    if (bak) {
        if (fflush(bak) != 0 || fsync(fileno(bak)) != 0)
            goto done;
        if (fclose(bak) != 0) {
            bak = NULL;
            goto done;
        }
        bak = NULL;
    }
    if (fflush(dst) != 0 || fsync(fileno(dst)) != 0)
        goto done;
    if (fclose(dst) != 0) {
        dst = NULL;
        goto done;
    }
    dst = NULL;
    /* rename() within the same directory is atomic: readers see either the old
     * file or the new one, never a truncated mixture. */
    if (rename(tmp_path, path) != 0)
        goto done;
    rc = 0;
done:
    if (src)
        fclose(src);
    if (dst) {
        fclose(dst);
        unlink(tmp_path);
    }
    if (bak)
        fclose(bak);
    if (rc != 0)
        unlink(tmp_path);
    return rc;
}

/* Restore a file captured by nc_admin_rewrite_account_file()'s backup_path. */
static int nc_admin_restore_account_file(const char *backup_path, const char *path)
{
    FILE *src, *dst;
    struct stat st;
    char buf[4096];
    size_t n;
    int rc = -1;

    if (!backup_path || !path)
        return -1;
    src = fopen(backup_path, "r");
    if (!src)
        return -1;
    dst = fopen(path, "w");
    if (!dst) {
        fclose(src);
        return -1;
    }
    if (fstat(fileno(src), &st) == 0)
        (void)fchmod(fileno(dst), st.st_mode & 07777);
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n)
            goto done;
    }
    if (ferror(src))
        goto done;
    if (fflush(dst) != 0 || fsync(fileno(dst)) != 0)
        goto done;
    rc = 0;
done:
    fclose(src);
    if (fclose(dst) != 0)
        rc = -1;
    return rc;
}

static int nc_admin_rename_safe(const char *new_name, struct json_object *out)
{
    if (!new_name || !new_name[0]) {
        json_object_object_add(out, "error", json_object_new_string("missing_new_username"));
        return -1;
    }
    size_t len = strlen(new_name);
    if (len < 2 || len > 32) {
        json_object_object_add(out, "error", json_object_new_string("invalid_username"));
        json_object_object_add(out, "message", json_object_new_string("username must be 2-32 chars"));
        return -1;
    }
    for (const char *p = new_name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) {
            json_object_object_add(out, "error", json_object_new_string("invalid_username"));
            return -1;
        }
    }
    char cmd[512];
    int ok;
    static const char passwd_backup[] = "/etc/passwd.jmxd-rename.bak";
    static const char shadow_backup[] = "/etc/shadow.jmxd-rename.bak";

    /*
     * /etc/passwd and /etc/shadow have to agree on the account name. The
     * previous implementation ran two sed -i calls chained with &&: if the
     * second one failed, passwd had already been rewritten and the device could
     * no longer authenticate anybody. Each file is now rewritten atomically, and
     * a failure on shadow rolls passwd back.
     */
    if (nc_admin_rewrite_account_file("/etc/passwd", new_name, passwd_backup) != 0) {
        json_object_object_add(out, "error", json_object_new_string("system_rename_failed"));
        json_object_object_add(out, "message", json_object_new_string("/etc/passwd unchanged"));
        return -1;
    }
    if (nc_admin_rewrite_account_file("/etc/shadow", new_name, shadow_backup) != 0) {
        int restored = nc_admin_restore_account_file(passwd_backup, "/etc/passwd") == 0;

        json_object_object_add(out, "error", json_object_new_string("system_rename_failed"));
        json_object_object_add(out, "message",
            json_object_new_string(restored ?
                "/etc/shadow rewrite failed; /etc/passwd rolled back" :
                "/etc/shadow rewrite failed and /etc/passwd rollback also failed; "
                "restore /etc/passwd.jmxd-rename.bak before the next login"));
        json_object_object_add(out, "rolled_back", json_object_new_boolean(restored));
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "sed -i \"s/option username '.*'/option username '%s'/\" /etc/config/rpcd && uci commit rpcd && /etc/init.d/rpcd restart >/dev/null 2>&1", new_name);
    ok = system(cmd) == 0;
    if (!ok) {
        json_object_object_add(out, "error", json_object_new_string("rpcd_rename_failed"));
        return -1;
    }
    return 0;
}

static int nc_admin_avatar_ext_ok(const char *ext)
{
    if (!ext) return 0;
    return (!strcasecmp(ext, "png") || !strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg") || !strcasecmp(ext, "webp"));
}

int jmx_admin_avatar_set(struct json_object *req, struct json_object *out)
{
    if (!req || !out) return -1;
