    nc_adv_artifacts_close(artifacts, artifact_count);
    json_object_object_add(summary, "tables", json_object_new_int(tables));
    json_object_object_add(summary, "static_routes", json_object_new_int(routes));
    json_object_object_add(summary, "route_objects", json_object_new_int(objects));
    json_object_object_add(summary, "cross_services", json_object_new_int(cross));
    json_object_object_add(summary, "policy_rules", json_object_new_int(rules));
    json_object_object_add(runtime, "rt_tables_file", json_object_new_string(rt_path));
    json_object_object_add(runtime, "draft_config", json_object_new_string(draft_path));
    json_object_object_add(runtime, "script", json_object_new_string(script_path));
    json_object_object_add(runtime, "nft_file", json_object_new_string(nft_path));
    json_object_object_add(runtime, "runtime_apply", json_object_new_string(
        dry ? "dry_run" : (apply_runtime ? "attempted" : "files_only")));
    json_object_object_add(runtime, "apply_rc", json_object_new_int(apply_rc));
    json_object_object_add(runtime, "apply_log", json_object_new_string(log_path));
    json_object_object_add(d, "ok", json_object_new_boolean(response_ok));
    json_object_object_add(d, "dry_run", json_object_new_boolean(dry));
    json_object_object_add(d, "apply_state", json_object_new_string(apply_state));
    json_object_object_add(d, "reason", json_object_new_string(reason));
    json_object_object_add(d, "failed_stage", json_object_new_string(failed_stage));
    json_object_object_add(d, "artifact_generated", json_object_new_boolean(artifact_generated));
    json_object_object_add(d, "runtime_attempted", json_object_new_boolean(runtime_attempted));
    json_object_object_add(d, "runtime_applied", json_object_new_boolean(runtime_applied));
    json_object_object_add(d, "readback_verified", json_object_new_boolean(readback_verified));
    json_object_object_add(d, "applied", json_object_new_boolean(
        response_ok && readback_verified));
    json_object_object_add(d, "summary", summary);
    json_object_object_add(d, "runtime", runtime);
    json_object_object_add(d, "warnings", warnings);
    return jmx_gen_api_response_data(response_ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}
struct json_object *jmx_advanced_routing_status(void)
{
    struct json_object*resp=jmx_advanced_routing_get(); struct json_object*d=NULL; if(json_object_object_get_ex(resp,"data",&d)&&d){struct json_object*runtime=json_object_new_object();json_object_object_add(runtime,"rt_tables_file",json_object_new_string("/etc/iproute2/rt_tables.d/dreamingwrt.conf"));json_object_object_add(runtime,"draft_config",json_object_new_string("/etc/config/dreamingwrt_advanced_routing"));json_object_object_add(runtime,"ip_rules",json_object_new_array());json_object_object_add(runtime,"nft_sets",json_object_new_array());json_object_object_add(runtime,"fallback_reasons",json_object_new_array());json_object_object_add(d,"runtime",runtime);} return resp;
}

/* ── Custom Network Objects ──────────────────────────────────────────── */
static void nc_custom_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS custom_protocol (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,name TEXT NOT NULL,category TEXT NOT NULL DEFAULT '',src_addr TEXT NOT NULL DEFAULT 'any',dest_addr TEXT NOT NULL DEFAULT 'any',protocol TEXT NOT NULL DEFAULT 'tcp',src_port TEXT NOT NULL DEFAULT 'any',dest_port TEXT NOT NULL DEFAULT 'any',remark TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_custom_protocol_category ON custom_protocol(category, enabled)");
    nc_exec("CREATE TABLE IF NOT EXISTS custom_protocol_signature (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,name TEXT NOT NULL,category TEXT NOT NULL DEFAULT '',src_addr TEXT NOT NULL DEFAULT 'any',dest_addr TEXT NOT NULL DEFAULT 'any',protocol TEXT NOT NULL DEFAULT 'tcp',src_port TEXT NOT NULL DEFAULT 'any',dest_port TEXT NOT NULL DEFAULT 'any',match_layer TEXT NOT NULL DEFAULT 'l7',direction TEXT NOT NULL DEFAULT 'request',match_mode TEXT NOT NULL DEFAULT 'contains',offset INTEGER NOT NULL DEFAULT 0,length INTEGER NOT NULL DEFAULT 0,pattern TEXT NOT NULL,remark TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_custom_protocol_signature_category ON custom_protocol_signature(category, enabled)");
    nc_exec("CREATE TABLE IF NOT EXISTS custom_port_group (id TEXT PRIMARY KEY,name TEXT NOT NULL,protocol TEXT NOT NULL DEFAULT 'tcp,udp',ports TEXT NOT NULL,remark TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE TABLE IF NOT EXISTS custom_service_template (id TEXT PRIMARY KEY,name TEXT NOT NULL,protocol TEXT NOT NULL DEFAULT 'tcp',ports TEXT NOT NULL,direction TEXT NOT NULL DEFAULT 'any',remark TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE TABLE IF NOT EXISTS custom_protocol_tag (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,color TEXT NOT NULL DEFAULT '',remark TEXT NOT NULL DEFAULT '')");
    nc_exec("CREATE TABLE IF NOT EXISTS custom_protocol_tag_map (protocol_id TEXT NOT NULL,tag_id TEXT NOT NULL,object_type TEXT NOT NULL DEFAULT 'protocol',PRIMARY KEY(protocol_id, tag_id, object_type))");
    nc_exec("CREATE TABLE IF NOT EXISTS custom_config_status (id INTEGER PRIMARY KEY CHECK (id = 1),apply_state TEXT NOT NULL DEFAULT 'draft',last_apply_at INTEGER NOT NULL DEFAULT 0,pending_runtime INTEGER NOT NULL DEFAULT 1,warnings TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("INSERT OR IGNORE INTO custom_config_status(id,warnings) VALUES(1,'advanced signatures stored but JMX runtime consumer pending')");
}

static int nc_custom_id_ok(const char*s){return s&&strlen(s)<=64&&nc_valid_name(s);}
/* The rule name reaches /etc/config/dreamingwrt_custom_appfilter as a
 * single-quoted UCI value, so a quote or newline here is an injection, not just
 * an odd name. Length alone was not enough. */
static int nc_custom_name_ok(const char*s){return s&&s[0]&&strlen(s)<=64&&jmx_uci_value_ok(s);}
static int nc_custom_proto_ok(const char*s){return s&&(!strcmp(s,"tcp")||!strcmp(s,"udp")||!strcmp(s,"tcp,udp")||!strcmp(s,"icmp")||!strcmp(s,"all"));}
static int nc_custom_layer_ok(const char*s){return s&&(!strcmp(s,"l4")||!strcmp(s,"l7")||!strcmp(s,"tls")||!strcmp(s,"http"));}
static int nc_custom_mode_ok(const char*s){return s&&(!strcmp(s,"contains")||!strcmp(s,"prefix")||!strcmp(s,"regex")||!strcmp(s,"hex"));}
static int nc_custom_hex_ok(const char*s){if(!s)return 0;int n=0;for(const unsigned char*p=(const unsigned char*)s;*p;p++){if(isspace(*p))continue;if(!isxdigit(*p))return 0;n++;}return n>0&&(n%2)==0;}
static int nc_custom_port_text_ok(const char*s){if(!s||!s[0])return 0;if(!strcmp(s,"any"))return 1;for(const unsigned char*p=(const unsigned char*)s;*p;p++){if(isdigit(*p)||*p==','||*p=='-'||isspace(*p))continue;return 0;}return 1;}
static int nc_custom_validate_common(struct json_object*o,int advanced){const char*id=nc_json_str_def(o,"id","");const char*name=nc_json_str_def(o,"name","");const char*proto=nc_json_str_def(o,"protocol","tcp");if(!nc_custom_id_ok(id)||!nc_custom_name_ok(name)||!nc_custom_proto_ok(proto))return -1;if(!nc_custom_port_text_ok(nc_json_str_def(o,"src_port","any"))||!nc_custom_port_text_ok(nc_json_str_def(o,"dest_port","any")))return -1;if(advanced){const char*layer=nc_json_str_def(o,"match_layer","l7");const char*mode=nc_json_str_def(o,"match_mode","contains");const char*pat=nc_json_str_def(o,"pattern","");if(!nc_custom_layer_ok(layer)||!nc_custom_mode_ok(mode)||!pat[0]||strlen(pat)>512)return -1;if(!strcmp(mode,"hex")&&!nc_custom_hex_ok(pat))return -1;if(!jmx_uci_value_ok(pat))return -1;}if(!jmx_uci_value_ok(nc_json_str_def(o,"remark","")))return -1;return 0;}

static void nc_custom_add_protocols_json(struct json_object*arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,enabled,name,category,src_addr,dest_addr,protocol,src_port,dest_port,remark,created_at,updated_at FROM custom_protocol ORDER BY category,name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"category",st,3);nc_add_text(o,"src_addr",st,4);nc_add_text(o,"dest_addr",st,5);nc_add_text(o,"protocol",st,6);nc_add_text(o,"src_port",st,7);nc_add_text(o,"dest_port",st,8);nc_add_text(o,"remark",st,9);json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,10)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,11)));/* compute used_by: which network_control rules reference this protocol */
                struct json_object *used = json_object_new_array();
                const char *p_id = nc_json_str_def(o, "id", "");
                if(p_id[0]) {
                    sqlite3_stmt *ub = NULL;
                    if(nc_prepare(&ub, "SELECT id,type,name FROM network_control_rule WHERE remark LIKE ? OR source LIKE ?")==0) {
                        char pat[128]; snprintf(pat, sizeof(pat), "%%%s%%", p_id);
                        sqlite3_bind_text(ub, 1, pat, -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(ub, 2, pat, -1, SQLITE_TRANSIENT);
                        while(sqlite3_step(ub)==SQLITE_ROW) {
                            struct json_object *ref = json_object_new_object();
                            nc_add_text(ref, "rule_id", ub, 0);
                            nc_add_text(ref, "type", ub, 1);
                            nc_add_text(ref, "name", ub, 2);
                            json_object_array_add(used, ref);
                        }
                        sqlite3_finalize(ub);
                    }
                }
                json_object_object_add(o, "used_by", used);
                json_object_array_add(arr, o);
            }
            sqlite3_finalize(st);
        }
}
static void nc_custom_add_signatures_json(struct json_object*arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,enabled,name,category,src_addr,dest_addr,protocol,src_port,dest_port,match_layer,direction,pattern_format,pattern_text,remark,created_at,updated_at FROM custom_signature ORDER BY name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"category",st,3);nc_add_text(o,"src_addr",st,4);nc_add_text(o,"dest_addr",st,5);nc_add_text(o,"protocol",st,6);nc_add_text(o,"src_port",st,7);nc_add_text(o,"dest_port",st,8);nc_add_text(o,"match_layer",st,9);nc_add_text(o,"direction",st,10);nc_add_text(o,"pattern_format",st,11);nc_add_text(o,"pattern_text",st,12);nc_add_text(o,"remark",st,13);json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,14)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,15)));json_object_object_add(o,"used_by",json_object_new_array());json_object_array_add(arr,o);}sqlite3_finalize(st);}}
static void nc_custom_add_port_groups_json(struct json_object*arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,name,protocol,ports,remark,created_at,updated_at FROM custom_port_group ORDER BY name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);nc_add_text(o,"protocol",st,2);nc_add_text(o,"ports",st,3);nc_add_text(o,"remark",st,4);json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,5)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,6)));json_object_object_add(o,"used_by",json_object_new_array());json_object_array_add(arr,o);}sqlite3_finalize(st);}}
static void nc_custom_add_templates_json(struct json_object*arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,name,protocol,ports,direction,remark,created_at,updated_at FROM custom_service_template ORDER BY name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);nc_add_text(o,"protocol",st,2);nc_add_text(o,"ports",st,3);nc_add_text(o,"direction",st,4);nc_add_text(o,"remark",st,5);json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,6)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,7)));json_object_array_add(arr,o);}sqlite3_finalize(st);}}
static void nc_custom_add_tags_json(struct json_object*arr)
{sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT id,name,color,remark FROM custom_protocol_tag ORDER BY name")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);nc_add_text(o,"color",st,2);nc_add_text(o,"remark",st,3);json_object_array_add(arr,o);}sqlite3_finalize(st);}}

struct json_object *jmx_custom_config_get(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_custom_db_init(); struct json_object*d=json_object_new_object(),*a=NULL; json_object_object_add(d,"ts",json_object_new_int64(nc_now_s())); a=json_object_new_array();nc_custom_add_protocols_json(a);json_object_object_add(d,"protocols",a); a=json_object_new_array();nc_custom_add_signatures_json(a);json_object_object_add(d,"advanced_protocols",a); a=json_object_new_array();nc_custom_add_port_groups_json(a);json_object_object_add(d,"port_groups",a); a=json_object_new_array();nc_custom_add_templates_json(a);json_object_object_add(d,"service_templates",a); a=json_object_new_array();nc_custom_add_tags_json(a);json_object_object_add(d,"protocol_tags",a); return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

static int nc_custom_save_protocols(struct json_object*arr)
{if(!arr||!json_object_is_type(arr,json_type_array))return 0;sqlite3_stmt*st=NULL;int n=json_object_array_length(arr);for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);if(nc_custom_validate_common(o,0)!=0)return -1;const char*id=nc_json_str_def(o,"id","");sqlite3_int64 now=(sqlite3_int64)nc_now_s();if(nc_prepare(&st,"INSERT OR REPLACE INTO custom_protocol(id,enabled,name,category,src_addr,dest_addr,protocol,src_port,dest_port,remark,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,COALESCE((SELECT created_at FROM custom_protocol WHERE id=?),?),?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,3,nc_json_str_def(o,"name",id),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"category",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"src_addr","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"dest_addr","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(o,"protocol","tcp"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"src_port","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,9,nc_json_str_def(o,"dest_port","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,10,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,11,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,12,now);sqlite3_bind_int64(st,13,now);sqlite3_step(st);sqlite3_finalize(st);}}return 0;}
static int nc_custom_save_signatures(struct json_object*arr)
{if(!arr||!json_object_is_type(arr,json_type_array))return 0;sqlite3_stmt*st=NULL;int n=json_object_array_length(arr);for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);if(nc_custom_validate_common(o,1)!=0)return -1;const char*id=nc_json_str_def(o,"id","");sqlite3_int64 now=(sqlite3_int64)nc_now_s();if(nc_prepare(&st,"INSERT OR REPLACE INTO custom_protocol_signature(id,enabled,name,category,src_addr,dest_addr,protocol,src_port,dest_port,match_layer,direction,match_mode,offset,length,pattern,remark,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,COALESCE((SELECT created_at FROM custom_protocol_signature WHERE id=?),?),?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,3,nc_json_str_def(o,"name",id),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"category",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"src_addr","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"dest_addr","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(o,"protocol","tcp"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"src_port","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,9,nc_json_str_def(o,"dest_port","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,10,nc_json_str_def(o,"match_layer","l7"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,11,nc_json_str_def(o,"direction","request"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,12,nc_json_str_def(o,"match_mode","contains"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,13,nc_json_int_def(o,"offset",0));sqlite3_bind_int(st,14,nc_json_int_def(o,"length",0));sqlite3_bind_text(st,15,nc_json_str_def(o,"pattern",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,16,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,17,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,18,now);sqlite3_bind_int64(st,19,now);sqlite3_step(st);sqlite3_finalize(st);}}return 0;}
static int nc_custom_save_port_groups(struct json_object*arr)
{if(!arr||!json_object_is_type(arr,json_type_array))return 0;sqlite3_stmt*st=NULL;int n=json_object_array_length(arr);for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);const char*id=nc_json_str_def(o,"id","");if(!nc_custom_id_ok(id)||!nc_custom_name_ok(nc_json_str_def(o,"name",""))||!nc_custom_proto_ok(nc_json_str_def(o,"protocol","tcp,udp"))||!nc_custom_port_text_ok(nc_json_str_def(o,"ports","")))return -1;sqlite3_int64 now=(sqlite3_int64)nc_now_s();if(nc_prepare(&st,"INSERT OR REPLACE INTO custom_port_group(id,name,protocol,ports,remark,created_at,updated_at) VALUES(?,?,?,?,?,COALESCE((SELECT created_at FROM custom_port_group WHERE id=?),?),?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(o,"name",id),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"protocol","tcp,udp"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"ports",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,7,now);sqlite3_bind_int64(st,8,now);sqlite3_step(st);sqlite3_finalize(st);}}return 0;}
static int nc_custom_save_templates(struct json_object*arr)
{if(!arr||!json_object_is_type(arr,json_type_array))return 0;sqlite3_stmt*st=NULL;int n=json_object_array_length(arr);for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);const char*id=nc_json_str_def(o,"id","");if(!nc_custom_id_ok(id)||!nc_custom_name_ok(nc_json_str_def(o,"name",""))||!nc_custom_proto_ok(nc_json_str_def(o,"protocol","tcp"))||!nc_custom_port_text_ok(nc_json_str_def(o,"ports","")))return -1;sqlite3_int64 now=(sqlite3_int64)nc_now_s();if(nc_prepare(&st,"INSERT OR REPLACE INTO custom_service_template(id,name,protocol,ports,direction,remark,created_at,updated_at) VALUES(?,?,?,?,?,?,COALESCE((SELECT created_at FROM custom_service_template WHERE id=?),?),?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(o,"name",id),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"protocol","tcp"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"ports",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"direction","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,8,now);sqlite3_bind_int64(st,9,now);sqlite3_step(st);sqlite3_finalize(st);}}return 0;}
static int nc_custom_save_tags(struct json_object*arr)
{if(!arr||!json_object_is_type(arr,json_type_array))return 0;sqlite3_stmt*st=NULL;int n=json_object_array_length(arr);for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);const char*id=nc_json_str_def(o,"id","");if(!nc_custom_id_ok(id)||!nc_custom_name_ok(nc_json_str_def(o,"name","")))return -1;if(nc_prepare(&st,"INSERT OR REPLACE INTO custom_protocol_tag(id,name,color,remark) VALUES(?,?,?,?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(o,"name",id),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"color",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}}return 0;}

int jmx_custom_config_save(struct json_object *cfg)
{
    if(!cfg||jmx_netconfig_db_init()!=0)return -1; nc_custom_db_init(); struct json_object*v=NULL; int rc=0; if(nc_txn_begin()!=0)return -1; if(json_object_object_get_ex(cfg,"protocols",&v))rc|=nc_custom_save_protocols(v); if(json_object_object_get_ex(cfg,"advanced_protocols",&v))rc|=nc_custom_save_signatures(v); if(json_object_object_get_ex(cfg,"port_groups",&v))rc|=nc_custom_save_port_groups(v); if(json_object_object_get_ex(cfg,"service_templates",&v))rc|=nc_custom_save_templates(v); if(json_object_object_get_ex(cfg,"protocol_tags",&v))rc|=nc_custom_save_tags(v); if(rc==0)nc_exec("UPDATE custom_config_status SET apply_state='draft',pending_runtime=1,updated_at=strftime('%s','now') WHERE id=1"); nc_exec(rc==0?"COMMIT":"ROLLBACK"); return rc==0?0:-1;
}

struct json_object *jmx_custom_config_apply(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0){struct json_object*d=json_object_new_object();json_object_object_add(d,"ok",json_object_new_boolean(0));return jmx_gen_api_response_data(API_CODE_ERROR,d);}
    nc_custom_db_init();
    mkdir("/etc/dreamingwrt", 0755);
    FILE*fp=fopen("/etc/dreamingwrt/custom_objects.json","w");
    if(fp){struct json_object*resp=jmx_custom_config_get();struct json_object*d=NULL;if(json_object_object_get_ex(resp,"data",&d))fprintf(fp,"%s\n",json_object_to_json_string_ext(d,JSON_C_TO_STRING_PRETTY));json_object_put(resp);fclose(fp);}

    /* Write UCI-compatible app_rule sections from custom_protocol_signature */
    int compat_app = 0;
    sqlite3_stmt *cs = NULL;
    FILE *afp = fopen("/etc/config/dreamingwrt_custom_appfilter", "w");
    if(afp) {
        fprintf(afp, "# DreamingWrt custom app rules compat - auto generated\n");
        if(nc_prepare(&cs, "SELECT id,name,protocol,src_port,dest_port,pattern,match_layer,remark FROM custom_protocol_signature WHERE enabled=1 ORDER BY category,name")==0) {
            while(sqlite3_step(cs)==SQLITE_ROW) {
                const char *id = (const char*)sqlite3_column_text(cs,0);
                const char *name = (const char*)sqlite3_column_text(cs,1);
                const char *proto = (const char*)sqlite3_column_text(cs,2);
                const char *sp = (const char*)sqlite3_column_text(cs,3);
                const char *dp = (const char*)sqlite3_column_text(cs,4);
                const char *pattern = (const char*)sqlite3_column_text(cs,5);
                const char *layer = (const char*)sqlite3_column_text(cs,6);
                const char *remark = (const char*)sqlite3_column_text(cs,7);
                if(id && id[0]) {
                    /* name/pattern/remark are free-text user input; a quote or
                     * newline in any of them would inject extra UCI options
                     * into the generated appfilter config. */
                    char b_id[128], b_name[256], b_proto[64], b_sp[64], b_dp[64];
                    char b_pat[1024], b_layer[64], b_remark[512];
                    fprintf(afp, "config custom_apprule\n\toption id '%s'\n\toption name '%s'\n\toption protocol '%s'\n\toption src_port '%s'\n\toption dest_port '%s'\n\toption pattern '%s'\n\toption match_layer '%s'\n\toption remark '%s'\n",
                            NC_UCI_SAFE(id, b_id),
                            NC_UCI_SAFE(name, b_name),
                            proto && proto[0] ? NC_UCI_SAFE(proto, b_proto) : "tcp",
                            sp && sp[0] ? NC_UCI_SAFE(sp, b_sp) : "any",
                            dp && dp[0] ? NC_UCI_SAFE(dp, b_dp) : "any",
                            NC_UCI_SAFE(pattern, b_pat),
                            layer && layer[0] ? NC_UCI_SAFE(layer, b_layer) : "l7",
                            NC_UCI_SAFE(remark, b_remark));
                    compat_app++;
                }
            }
            sqlite3_finalize(cs);
        }
        fclose(afp);
    }

    /* Compute used_by: which network_control app_rules reference custom signatures */
    struct json_object *used = json_object_new_object();
    if(nc_prepare(&cs, "SELECT app_id FROM network_control_app_rule WHERE enabled=1")==0) {
        while(sqlite3_step(cs)==SQLITE_ROW) {
            const char *app_id = (const char*)sqlite3_column_text(cs,0);
            if(app_id) json_object_object_add(used, app_id, json_object_new_boolean(1));
        }
        sqlite3_finalize(cs);
    }
    json_object_put(used);

    nc_exec("UPDATE custom_config_status SET apply_state='partial',last_apply_at=strftime('%s','now'),pending_runtime=1,warnings='custom objects exported + compat UCI written; DPI runtime consumer still pending',updated_at=strftime('%s','now') WHERE id=1");
    struct json_object *d = json_object_new_object(), *w = json_object_new_array();
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "applied", json_object_new_boolean(1));
    json_object_object_add(d, "pending_runtime", json_object_new_boolean(1));
    json_object_object_add(d, "export", json_object_new_string("/etc/dreamingwrt/custom_objects.json"));
    json_object_object_add(d, "compat_app_rules", json_object_new_int(compat_app));
    json_object_array_add(w, json_object_new_string("custom app rules exported to UCI compat; DPI runtime consumer still pending"));
    json_object_object_add(d, "warnings", w);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_custom_config_status(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_custom_db_init(); struct json_object*d=json_object_new_object(); json_object_object_add(d,"ts",json_object_new_int64(nc_now_s())); sqlite3_stmt*st=NULL; if(nc_prepare(&st,"SELECT apply_state,last_apply_at,pending_runtime,warnings,updated_at FROM custom_config_status WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){nc_add_text(d,"apply_state",st,0);json_object_object_add(d,"last_apply_at",json_object_new_int64(sqlite3_column_int64(st,1)));json_object_object_add(d,"pending_runtime",json_object_new_boolean(sqlite3_column_int(st,2)));nc_add_text(d,"warnings",st,3);json_object_object_add(d,"updated_at",json_object_new_int64(sqlite3_column_int64(st,4)));sqlite3_finalize(st);} int p=0,a=0,pg=0,t=0; if(nc_prepare(&st,"SELECT (SELECT COUNT(*) FROM custom_protocol),(SELECT COUNT(*) FROM custom_protocol_signature),(SELECT COUNT(*) FROM custom_port_group),(SELECT COUNT(*) FROM custom_service_template)")==0&&sqlite3_step(st)==SQLITE_ROW){p=sqlite3_column_int(st,0);a=sqlite3_column_int(st,1);pg=sqlite3_column_int(st,2);t=sqlite3_column_int(st,3);sqlite3_finalize(st);} json_object_object_add(d,"protocols",json_object_new_int(p));json_object_object_add(d,"advanced_protocols",json_object_new_int(a));json_object_object_add(d,"port_groups",json_object_new_int(pg));json_object_object_add(d,"service_templates",json_object_new_int(t));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

/* ── Network Control ─────────────────────────────────────────────────── */
#define NC_AEGIS_APPFILTER_REINIT_FILE "/tmp/appfilter_rules_state"
#define NC_AEGIS_APPFILTER_RUNTIME_FILE "/proc/dreamingwrt/jmx/app_filter_rules"
/*
 * 必须与 kmod jmx 的 MAX_APP_FILTER_RULE_NUM 保持一致，否则 webd 会放进来
 * 内核拒收的规则(表现为 applied_rule_count 少于配置条数)。
 */
#define NC_AEGIS_APPFILTER_MAX_RULES 512
#define NC_AEGIS_APPFILTER_MAX_APP_IDS 1024

/*
 * Number of MAC values that already have more than one ACL rule.
 *
 * Used to decide whether the uniqueness index can be created. Returns a
 * negative value when the question cannot be answered, which is treated as
 * "assume duplicates" so the migration never fails hard.
 */
static int nc_netctl_mac_duplicate_groups(void)
{
    sqlite3_stmt *st = NULL;
    int groups = -1;

    if (nc_prepare(&st,
            "SELECT COUNT(*) FROM (SELECT mac FROM network_control_mac_rule "
            "WHERE mac<>'' GROUP BY mac HAVING COUNT(*) > 1)") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        groups = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return groups;
}

static void nc_netctl_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_global (id INTEGER PRIMARY KEY CHECK (id = 1),enabled INTEGER NOT NULL DEFAULT 1,mode TEXT NOT NULL DEFAULT 'balanced',default_action TEXT NOT NULL DEFAULT 'allow',schedule_default TEXT NOT NULL DEFAULT 'always',apply_state TEXT NOT NULL DEFAULT 'draft',last_apply_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0,appfilter_enabled INTEGER NOT NULL DEFAULT 1,macfilter_enabled INTEGER NOT NULL DEFAULT 1,record_enabled INTEGER NOT NULL DEFAULT 1,revision INTEGER NOT NULL DEFAULT 1)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_rule (id TEXT PRIMARY KEY,type TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,name TEXT NOT NULL,priority INTEGER NOT NULL DEFAULT 1000,source TEXT NOT NULL DEFAULT 'any',schedule TEXT NOT NULL DEFAULT 'always',remark TEXT NOT NULL DEFAULT '',hits INTEGER NOT NULL DEFAULT 0,last_hit INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,runtime_rule_id INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_network_control_rule_type_priority ON network_control_rule(type, enabled, priority)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_connection_limit (rule_id TEXT PRIMARY KEY,protocol TEXT NOT NULL DEFAULT 'tcp,udp',wan_port TEXT NOT NULL DEFAULT 'any',connection_limit INTEGER NOT NULL DEFAULT 600,burst INTEGER NOT NULL DEFAULT 80,action TEXT NOT NULL DEFAULT 'limit')");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_mac_rule (rule_id TEXT PRIMARY KEY,mode TEXT NOT NULL DEFAULT 'deny',mac TEXT NOT NULL,terminal_name TEXT NOT NULL DEFAULT '')");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_url_access_rule (rule_id TEXT PRIMARY KEY,mode TEXT NOT NULL DEFAULT 'blacklist',domains TEXT NOT NULL DEFAULT '',match_type TEXT NOT NULL DEFAULT 'domain',action TEXT NOT NULL DEFAULT 'block')");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_url_rewrite_rule (rule_id TEXT PRIMARY KEY,match_mode TEXT NOT NULL DEFAULT 'domain',source_url TEXT NOT NULL,dest_url TEXT NOT NULL,exclude TEXT NOT NULL DEFAULT '',ratio INTEGER NOT NULL DEFAULT 100)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_app_rule (rule_id TEXT PRIMARY KEY,app_ids TEXT NOT NULL DEFAULT '',apps TEXT NOT NULL DEFAULT '',destination TEXT NOT NULL DEFAULT 'any',action TEXT NOT NULL DEFAULT 'block',filter_quic INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_whitelist (kind TEXT NOT NULL CHECK(kind IN ('app','mac')),mac TEXT NOT NULL,created_at INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(kind,mac))");
    /*
     * MAC allowlist ("whitelist") enforcement state.
     *
     * The allowlist itself lives in network_control_whitelist(kind='mac'); this
     * table only records whether the negated-set drop rule is installed, and the
     * self-lockout guard state that goes with it. Kept separate from
     * network_control_other because every field here is about one runtime
     * transition (enable -> confirm-or-rollback), not a persistent preference.
     *
     * admin_mac/admin_ip are the origin of the session that enabled the mode.
     * The MAC is force-merged into the generated set so the operator who turned
     * the mode on cannot be cut off by their own change; admin_ip is stored for
     * the audit trail only, never matched on.
     */
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_mac_allowlist ("
            "id INTEGER PRIMARY KEY CHECK (id = 1),"
            "enabled INTEGER NOT NULL DEFAULT 0,"
            "confirmed INTEGER NOT NULL DEFAULT 0,"
            "confirm_deadline INTEGER NOT NULL DEFAULT 0,"
            "admin_mac TEXT NOT NULL DEFAULT '',"
            "admin_ip TEXT NOT NULL DEFAULT '',"
            "admin_mac_source TEXT NOT NULL DEFAULT '',"
            "last_reason TEXT NOT NULL DEFAULT '',"
            "enabled_at INTEGER NOT NULL DEFAULT 0,"
            "config_revision INTEGER NOT NULL DEFAULT 1,"
            "runtime_revision INTEGER NOT NULL DEFAULT 0,"
            "runtime_applied INTEGER NOT NULL DEFAULT 0,"
            "runtime_reason TEXT NOT NULL DEFAULT 'runtime_readback_unavailable',"
            "updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_terminal_limit (rule_id TEXT PRIMARY KEY,limit_type TEXT NOT NULL DEFAULT 'ip',line TEXT NOT NULL DEFAULT 'all',address TEXT NOT NULL,protocol TEXT NOT NULL DEFAULT 'all',speed_mode TEXT NOT NULL DEFAULT 'shared',src_port TEXT NOT NULL DEFAULT 'any',dest_port TEXT NOT NULL DEFAULT 'any',upload_mbps REAL NOT NULL DEFAULT 0,download_mbps REAL NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_other (id INTEGER PRIMARY KEY CHECK (id = 1),anti_share_enabled INTEGER NOT NULL DEFAULT 1,ttl_value INTEGER NOT NULL DEFAULT 1,dns_hijack_protect INTEGER NOT NULL DEFAULT 1,block_proxy_vpn INTEGER NOT NULL DEFAULT 0,block_unknown_quic INTEGER NOT NULL DEFAULT 0,scope TEXT NOT NULL DEFAULT 'lan',schedule TEXT NOT NULL DEFAULT 'always',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_event (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,rule_id TEXT NOT NULL DEFAULT '',type TEXT NOT NULL DEFAULT '',client TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT '',target TEXT NOT NULL DEFAULT '',action TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',bytes INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_status (id INTEGER PRIMARY KEY CHECK (id = 1),apply_state TEXT NOT NULL DEFAULT 'draft',last_apply_at INTEGER NOT NULL DEFAULT 0,warnings TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_tc_runtime (rule_id TEXT NOT NULL,direction TEXT NOT NULL CHECK(direction IN ('ingress','egress')),pref INTEGER NOT NULL,family INTEGER NOT NULL,address TEXT NOT NULL,protocol TEXT NOT NULL,src_port INTEGER NOT NULL DEFAULT 0,dest_port INTEGER NOT NULL DEFAULT 0,rate_kbit INTEGER NOT NULL,PRIMARY KEY(direction,pref))");
    nc_exec("CREATE TABLE IF NOT EXISTS network_control_tc_state (id INTEGER PRIMARY KEY CHECK(id=1),ifname TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0,clsact_owned INTEGER NOT NULL DEFAULT 0)");
    nc_exec("INSERT OR IGNORE INTO network_control_tc_state(id) VALUES(1)");
    nc_add_column_if_missing("network_control_global", "appfilter_enabled", "INTEGER NOT NULL DEFAULT 1");
    nc_add_column_if_missing("network_control_global", "macfilter_enabled", "INTEGER NOT NULL DEFAULT 1");
    nc_add_column_if_missing("network_control_global", "record_enabled", "INTEGER NOT NULL DEFAULT 1");
    nc_add_column_if_missing("network_control_global", "revision", "INTEGER NOT NULL DEFAULT 1");
    nc_add_column_if_missing("network_control_rule", "runtime_rule_id", "INTEGER NOT NULL DEFAULT 0");
    /*
     * expires: absolute unix time after which the rule stops taking effect.
     * 0 means "never expires", which keeps every pre-existing row behaving
     * exactly as before this column existed.
     */
    nc_add_column_if_missing("network_control_rule", "expires", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("network_control_app_rule", "filter_quic", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("network_control_tc_state", "clsact_owned", "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("network_control_mac_allowlist", "config_revision",
                             "INTEGER NOT NULL DEFAULT 1");
    nc_add_column_if_missing("network_control_mac_allowlist", "runtime_revision",
                             "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("network_control_mac_allowlist", "runtime_applied",
                             "INTEGER NOT NULL DEFAULT 0");
    nc_add_column_if_missing("network_control_mac_allowlist", "runtime_reason",
                             "TEXT NOT NULL DEFAULT 'runtime_readback_unavailable'");
    /*
     * One rule per MAC, matching the upstream acl_mac_black.mac UNIQUE
     * constraint. Until now duplicates were only prevented by the frontend, so
     * an API client could create several rules for one MAC and all of them
     * would render into nftables.
     *
     * Duplicates are checked first rather than letting CREATE UNIQUE INDEX
     * fail: on a table that already holds duplicates the statement errors, and
     * nc_exec() would log that as a migration failure on every startup even
     * though nothing is wrong with the schema. A device in that state gets a
     * plain index instead; the write path refuses new duplicates either way
     * via nc_netctl_mac_conflict().
     */
    /*
     * The index is partial (WHERE mac<>'') because a group-bound MAC rule stores
     * no MAC of its own; its members are resolved from terminal_group_member at
     * generation time. A full UNIQUE index would let only one group rule exist.
     *
     * The pre-existing full index is dropped first: leaving it in place would
     * keep enforcing uniqueness over the empty string on devices that already
     * created it, so the second group rule would fail to save with nothing in the
     * UI explaining why.
     */
    nc_exec("DROP INDEX IF EXISTS idx_network_control_mac_rule_mac");
    if (nc_netctl_mac_duplicate_groups() == 0)
        nc_exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_network_control_mac_rule_mac_single "
                "ON network_control_mac_rule(mac) WHERE mac<>''");
    else
        nc_exec("CREATE INDEX IF NOT EXISTS idx_network_control_mac_rule_mac_dup "
                "ON network_control_mac_rule(mac)");
    nc_exec("INSERT OR IGNORE INTO network_control_global(id) VALUES(1)");
    nc_exec("INSERT OR IGNORE INTO network_control_other(id) VALUES(1)");
    nc_exec("INSERT OR IGNORE INTO network_control_status(id,warnings) VALUES(1,'phase1 persistence only; nft/tc/url runtime pending')");
    nc_exec("INSERT OR IGNORE INTO network_control_mac_allowlist(id) VALUES(1)");
    nc_exec("UPDATE network_control_mac_allowlist SET "
            "runtime_revision=config_revision,runtime_applied=1,"
            "runtime_reason='blacklist_mode_no_allowlist_rule' "
            "WHERE id=1 AND enabled=0 AND runtime_revision=0");
}

static void nc_rulesd_add_whitelist(struct json_object *out, const char *kind);
static int nc_rulesd_save_whitelist(struct json_object *arr, const char *kind);
static int nc_rulesd_replace_whitelist(struct json_object *arr, const char *kind);

static int nc_netctl_type_ok(const char*s){return s&&(!strcmp(s,"connection_limit")||!strcmp(s,"mac")||!strcmp(s,"url_access")||!strcmp(s,"url_rewrite")||!strcmp(s,"app")||!strcmp(s,"terminal_limit"));}
static int nc_netctl_action_ok(const char*s){return s&&(!strcmp(s,"allow")||!strcmp(s,"block")||!strcmp(s,"deny")||!strcmp(s,"limit")||!strcmp(s,"redirect")||!strcmp(s,"audit")||!strcmp(s,"rate_limit"));}
static int nc_netctl_mac_ok(const char*s){if(!s||strlen(s)!=17)return 0;for(int i=0;i<17;i++){if((i+1)%3==0){if(s[i]!=':')return 0;}else if(!isxdigit((unsigned char)s[i]))return 0;}return 1;}
static void nc_netctl_mac_norm(const char*in,char*out,size_t n){snprintf(out,n,"%s",in?in:"");for(char*p=out;*p;p++)*p=tolower((unsigned char)*p);}

/*
 * "terminal_group:<id>" in network_control_rule.source binds a MAC ACL rule to
 * a terminal group instead of a single MAC. The prefix is the convention the
 * terminal-group store already uses for its reference lookups
 * (webd/terminal_groups.c tg_reference_query), so a bound rule shows up in the
 * group's in-use list and the group cannot be deleted out from under it.
 */
#define NC_NETCTL_GROUP_SOURCE_PREFIX "terminal_group:"

static int nc_netctl_group_id_ok(const char *id)
{
    size_t len;

    if (!id || !id[0])
        return 0;
    len = strlen(id);
    /* Mirrors tg_id_ok() in webd/terminal_groups.c: a value this rejects could
     * never name an existing group, and letting it through would only push the
     * failure into the ruleset generator. */
    if (len > 96 || id[0] == '-')
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)id[i];

        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

/*
 * Returns the group id when source names a terminal group, else NULL.
 */
static const char *nc_netctl_group_source_id(const char *source)
{
    const char *id;

    if (!source)
        return NULL;
    if (strncmp(source, NC_NETCTL_GROUP_SOURCE_PREFIX,
                sizeof(NC_NETCTL_GROUP_SOURCE_PREFIX) - 1) != 0)
        return NULL;
    id = source + sizeof(NC_NETCTL_GROUP_SOURCE_PREFIX) - 1;
    return nc_netctl_group_id_ok(id) ? id : NULL;
}

static int nc_netctl_group_exists(const char *group_id)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!group_id || !group_id[0])
        return 0;
    if (nc_prepare(&st, "SELECT 1 FROM terminal_group WHERE id=?1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists;
}

/*
 * Members that carry a MAC, i.e. how many nft rules a bound rule expands to.
 * -1 when the group does not exist; 0 is a real, empty group. The two are
 * reported separately because they need different wording in the UI: one is a
 * dangling reference, the other is a group the user emptied.
 */
static int nc_netctl_group_member_mac_count(const char *group_id)
{
    sqlite3_stmt *st = NULL;
    int count = -1;

    if (!nc_netctl_group_exists(group_id))
        return -1;
    if (nc_prepare(&st,
            "SELECT COUNT(DISTINCT mac) FROM terminal_group_member "
            "WHERE group_id=?1 AND mac<>''") != 0)
        return -1;
    sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

/*
 * Publishes the source binding of a MAC ACL rule. Derived from source rather
 * than stored a second time, so the reported kind can never disagree with what
 * the ruleset generator will actually do.
 */
static void nc_netctl_mac_rule_add_binding(struct json_object *o)
{
    const char *source = json_object_get_string(json_object_object_get(o, "source"));
    const char *group_id = nc_netctl_group_source_id(source);
    int members;

    json_object_object_add(o, "source_kind",
                           json_object_new_string(group_id ? "group" : "mac"));
    json_object_object_add(o, "source_ref",
                           json_object_new_string(group_id ? group_id : ""));
    if (!group_id)
        return;
    members = nc_netctl_group_member_mac_count(group_id);
    json_object_object_add(o, "group_exists", json_object_new_boolean(members >= 0));
    json_object_object_add(o, "group_member_macs", json_object_new_int(members));
    /*
     * Both states render zero nft rules, which is indistinguishable from a
     * working block unless it is said out loud.
     */
    if (members < 0)
        json_object_object_add(o, "runtime_warning",
            json_object_new_string("bound_terminal_group_missing_rule_blocks_nothing"));
    else if (members == 0)
        json_object_object_add(o, "runtime_warning",
            json_object_new_string("terminal_group_has_no_member_mac_rule_blocks_nothing"));
}

static int nc_netctl_url_https(const char*s){return s&&(!strncasecmp(s,"https://",8));}

static int nc_netctl_upsert_rule(struct json_object*o,const char*type)
{const char*id=nc_json_str_def(o,"id","");const char*name=nc_json_str_def(o,"name",id);if(!nc_valid_name(id)||!name[0]||strlen(name)>64||!nc_netctl_type_ok(type))return -1;sqlite3_stmt*st=NULL;sqlite3_int64 now=(sqlite3_int64)nc_now_s();if(nc_prepare(&st,"INSERT OR REPLACE INTO network_control_rule(id,type,enabled,name,priority,source,schedule,remark,hits,last_hit,created_at,updated_at,runtime_rule_id,expires) VALUES(?,?,?,?,?,?,?,?,COALESCE((SELECT hits FROM network_control_rule WHERE id=?),0),COALESCE((SELECT last_hit FROM network_control_rule WHERE id=?),0),COALESCE((SELECT created_at FROM network_control_rule WHERE id=?),?),?,COALESCE(NULLIF(?,0),(SELECT runtime_rule_id FROM network_control_rule WHERE id=?),0),?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,type,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,4,name,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,5,nc_json_int_def(o,"priority",1000));sqlite3_bind_text(st,6,nc_json_str_def(o,"source","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(o,"schedule","always"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,9,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,10,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,11,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,12,now);sqlite3_bind_int64(st,13,now);sqlite3_bind_int(st,14,nc_json_int_def(o,"runtime_rule_id",0));sqlite3_bind_text(st,15,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,16,(sqlite3_int64)nc_json_int64_def(o,"expires",0));sqlite3_step(st);sqlite3_finalize(st);}return 0;}

static void nc_netctl_add_rules_json(struct json_object*arr,const char*type,const char*sql)
    {sqlite3_stmt*st=NULL;if(nc_prepare(&st,sql)==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);json_object_object_add(o,"priority",json_object_new_int(sqlite3_column_int(st,3)));nc_add_text(o,"source",st,4);nc_add_text(o,"schedule",st,5);nc_add_text(o,"remark",st,6);json_object_object_add(o,"hits",json_object_new_int64(sqlite3_column_int64(st,7)));json_object_object_add(o,"last_hit",json_object_new_int64(sqlite3_column_int64(st,8)));/* expires: 0 = never. Reported so the UI can show a lapse time and so an
             * expired-but-retained rule is distinguishable from an active one. */
            json_object_object_add(o,"expires",json_object_new_int64(sqlite3_column_int64(st,9)));json_object_object_add(o,"expired",json_object_new_boolean(sqlite3_column_int64(st,9)>0&&sqlite3_column_int64(st,9)<=(sqlite3_int64)nc_now_s()));int c=10;if(!strcmp(type,"connection_limit")){nc_add_text(o,"protocol",st,c++);nc_add_text(o,"wan_port",st,c++);json_object_object_add(o,"connection_limit",json_object_new_int(sqlite3_column_int(st,c++)));json_object_object_add(o,"burst",json_object_new_int(sqlite3_column_int(st,c++)));nc_add_text(o,"action",st,c++);}else if(!strcmp(type,"mac")){nc_add_text(o,"mode",st,c++);nc_add_text(o,"mac",st,c++);nc_add_text(o,"terminal_name",st,c++);nc_netctl_mac_rule_add_binding(o);}else if(!strcmp(type,"url_access")){nc_add_text(o,"mode",st,c++);nc_add_text(o,"domains",st,c++);nc_add_text(o,"match_type",st,c++);nc_add_text(o,"action",st,c++);}else if(!strcmp(type,"url_rewrite")){nc_add_text(o,"match_mode",st,c++);nc_add_text(o,"source_url",st,c++);nc_add_text(o,"dest_url",st,c++);nc_add_text(o,"exclude",st,c++);json_object_object_add(o,"ratio",json_object_new_int(sqlite3_column_int(st,c++)));if(nc_netctl_url_https(json_object_get_string(json_object_object_get(o,"source_url"))))json_object_object_add(o,"runtime_warning",json_object_new_string("unsupported_https_rewrite"));}else if(!strcmp(type,"app")){json_object_object_add(o,"app_ids",nc_json_array_from_text((const char*)sqlite3_column_text(st,c++)));json_object_object_add(o,"apps",nc_json_array_from_text((const char*)sqlite3_column_text(st,c++)));nc_add_text(o,"destination",st,c++);nc_add_text(o,"action",st,c++);json_object_object_add(o,"filter_quic",json_object_new_boolean(sqlite3_column_int(st,c++)));}else if(!strcmp(type,"terminal_limit")){nc_add_text(o,"limit_type",st,c++);nc_add_text(o,"line",st,c++);nc_add_text(o,"address",st,c++);nc_add_text(o,"protocol",st,c++);nc_add_text(o,"speed_mode",st,c++);nc_add_text(o,"src_port",st,c++);nc_add_text(o,"dest_port",st,c++);json_object_object_add(o,"upload_mbps",json_object_new_double(sqlite3_column_double(st,c++)));json_object_object_add(o,"download_mbps",json_object_new_double(sqlite3_column_double(st,c++)));}json_object_array_add(arr,o);}sqlite3_finalize(st);}}

struct json_object *jmx_network_control_get(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_netctl_db_init(); struct json_object*d=json_object_new_object(); json_object_object_add(d,"ts",json_object_new_int64(nc_now_s())); sqlite3_stmt*st=NULL;
    if(nc_prepare(&st,"SELECT enabled,mode,default_action,schedule_default,apply_state,last_apply_at,appfilter_enabled,macfilter_enabled,record_enabled FROM network_control_global WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){struct json_object*g=json_object_new_object();json_object_object_add(g,"enabled",json_object_new_boolean(sqlite3_column_int(st,0)));json_object_object_add(g,"engine",json_object_new_string("jmx + nftables + tc"));nc_add_text(g,"mode",st,1);nc_add_text(g,"default_action",st,2);nc_add_text(g,"schedule_default",st,3);nc_add_text(g,"apply_state",st,4);json_object_object_add(g,"last_apply_at",json_object_new_int64(sqlite3_column_int64(st,5)));json_object_object_add(g,"appfilter_enabled",json_object_new_boolean(sqlite3_column_int(st,6)));json_object_object_add(g,"macfilter_enabled",json_object_new_boolean(sqlite3_column_int(st,7)));json_object_object_add(g,"record_enabled",json_object_new_boolean(sqlite3_column_int(st,8)));json_object_object_add(d,"global",g);sqlite3_finalize(st);} struct json_object*a;
    a=json_object_new_array();nc_netctl_add_rules_json(a,"connection_limit","SELECT r.id,r.enabled,r.name,r.priority,r.source,r.schedule,r.remark,r.hits,r.last_hit,r.expires,d.protocol,d.wan_port,d.connection_limit,d.burst,d.action FROM network_control_rule r JOIN network_control_connection_limit d ON d.rule_id=r.id WHERE r.type='connection_limit' ORDER BY r.priority,r.id");json_object_object_add(d,"connection_limits",a);
    a=json_object_new_array();nc_netctl_add_rules_json(a,"mac","SELECT r.id,r.enabled,r.name,r.priority,r.source,r.schedule,r.remark,r.hits,r.last_hit,r.expires,d.mode,d.mac,d.terminal_name FROM network_control_rule r JOIN network_control_mac_rule d ON d.rule_id=r.id WHERE r.type='mac' ORDER BY r.priority,r.id");json_object_object_add(d,"mac_rules",a);
    a=json_object_new_array();nc_netctl_add_rules_json(a,"url_access","SELECT r.id,r.enabled,r.name,r.priority,r.source,r.schedule,r.remark,r.hits,r.last_hit,r.expires,d.mode,d.domains,d.match_type,d.action FROM network_control_rule r JOIN network_control_url_access_rule d ON d.rule_id=r.id WHERE r.type='url_access' ORDER BY r.priority,r.id");json_object_object_add(d,"url_access_rules",a);
    a=json_object_new_array();nc_netctl_add_rules_json(a,"url_rewrite","SELECT r.id,r.enabled,r.name,r.priority,r.source,r.schedule,r.remark,r.hits,r.last_hit,r.expires,d.match_mode,d.source_url,d.dest_url,d.exclude,d.ratio FROM network_control_rule r JOIN network_control_url_rewrite_rule d ON d.rule_id=r.id WHERE r.type='url_rewrite' ORDER BY r.priority,r.id");json_object_object_add(d,"url_rewrite_rules",a);
    a=json_object_new_array();nc_netctl_add_rules_json(a,"app","SELECT r.id,r.enabled,r.name,r.priority,r.source,r.schedule,r.remark,r.hits,r.last_hit,r.expires,d.app_ids,d.apps,d.destination,d.action,d.filter_quic FROM network_control_rule r JOIN network_control_app_rule d ON d.rule_id=r.id WHERE r.type='app' ORDER BY r.priority,r.id");json_object_object_add(d,"app_rules",a);
    a=json_object_new_array();nc_netctl_add_rules_json(a,"terminal_limit","SELECT r.id,r.enabled,r.name,r.priority,r.source,r.schedule,r.remark,r.hits,r.last_hit,r.expires,d.limit_type,d.line,d.address,d.protocol,d.speed_mode,d.src_port,d.dest_port,d.upload_mbps,d.download_mbps FROM network_control_rule r JOIN network_control_terminal_limit d ON d.rule_id=r.id WHERE r.type='terminal_limit' ORDER BY r.priority,r.id");json_object_object_add(d,"terminal_limits",a);
    if(nc_prepare(&st,"SELECT anti_share_enabled,ttl_value,dns_hijack_protect,block_proxy_vpn,block_unknown_quic,scope,schedule FROM network_control_other WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"anti_share_enabled",json_object_new_boolean(sqlite3_column_int(st,0)));json_object_object_add(o,"ttl_value",json_object_new_int(sqlite3_column_int(st,1)));json_object_object_add(o,"dns_hijack_protect",json_object_new_boolean(sqlite3_column_int(st,2)));json_object_object_add(o,"block_proxy_vpn",json_object_new_boolean(sqlite3_column_int(st,3)));json_object_object_add(o,"block_unknown_quic",json_object_new_boolean(sqlite3_column_int(st,4)));nc_add_text(o,"scope",st,5);nc_add_text(o,"schedule",st,6);json_object_object_add(d,"other_control",o);sqlite3_finalize(st);} a=json_object_new_array();nc_rulesd_add_whitelist(a,"app");json_object_object_add(d,"app_whitelist",a);a=json_object_new_array();nc_rulesd_add_whitelist(a,"mac");json_object_object_add(d,"mac_whitelist",a);a=json_object_new_array(); if(nc_prepare(&st,"SELECT id,ts,rule_id,type,client,source,target,action,reason,bytes FROM network_control_event ORDER BY ts DESC LIMIT 100")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"id",json_object_new_int(sqlite3_column_int(st,0)));json_object_object_add(o,"ts",json_object_new_int64(sqlite3_column_int64(st,1)));nc_add_text(o,"rule_id",st,2);nc_add_text(o,"type",st,3);nc_add_text(o,"client",st,4);nc_add_text(o,"source",st,5);nc_add_text(o,"target",st,6);nc_add_text(o,"action",st,7);nc_add_text(o,"reason",st,8);json_object_object_add(o,"bytes",json_object_new_int64(sqlite3_column_int64(st,9)));json_object_array_add(a,o);}sqlite3_finalize(st);} json_object_object_add(d,"recent_events",a); return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

#define NC_NETCTL_SAVE_DETAIL_BEGIN(arr,type,sql) if(arr&&json_object_is_type(arr,json_type_array)){int n=json_object_array_length(arr);for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);const char*id=nc_json_str_def(o,"id","");if(nc_netctl_upsert_rule(o,type)!=0)return -1;sqlite3_stmt*st=NULL;if(nc_prepare(&st,sql)==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
#define NC_NETCTL_SAVE_DETAIL_END sqlite3_step(st);sqlite3_finalize(st);}}}

static int nc_netctl_save_connection(struct json_object*arr){NC_NETCTL_SAVE_DETAIL_BEGIN(arr,"connection_limit","INSERT OR REPLACE INTO network_control_connection_limit(rule_id,protocol,wan_port,connection_limit,burst,action) VALUES(?,?,?,?,?,?)")sqlite3_bind_text(st,2,nc_json_str_def(o,"protocol","tcp,udp"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"wan_port","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,4,nc_json_int_def(o,"connection_limit",600));sqlite3_bind_int(st,5,nc_json_int_def(o,"burst",80));if(!nc_netctl_action_ok(nc_json_str_def(o,"action","limit"))){sqlite3_finalize(st);return -1;}sqlite3_bind_text(st,6,nc_json_str_def(o,"action","limit"),-1,SQLITE_TRANSIENT);NC_NETCTL_SAVE_DETAIL_END return 0;}
/*
 * True when `mac` already belongs to an ACL rule other than `rule_id`.
 *
 * Upstream enforces one rule per MAC with a UNIQUE column. Here the uniqueness
 * has to be checked explicitly because the row is keyed by rule_id, so two rules
 * could carry the same MAC and both would render into nftables. Passing the
 * rule's own id keeps an update to an existing rule from conflicting with itself.
 */
static int nc_netctl_mac_conflict(const char *mac, const char *rule_id)
{
    sqlite3_stmt *st = NULL;
    int conflict = 0;

    if (!mac || !mac[0])
        return 0;
    if (nc_prepare(&st,
            "SELECT 1 FROM network_control_mac_rule WHERE mac=?1 AND rule_id<>?2 LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, rule_id ? rule_id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        conflict = 1;
    sqlite3_finalize(st);
    return conflict;
}

static int nc_netctl_save_mac(struct json_object*arr)
{
    int n;

    if (!arr || !json_object_is_type(arr, json_type_array))
        return 0;
    n = json_object_array_length(arr);
    for (int i = 0; i < n; i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        const char *source = nc_json_str_def(o, "source", "any");
        const char *group_id = nc_netctl_group_source_id(source);
        char mac[32];
        sqlite3_stmt *st = NULL;

        nc_netctl_mac_norm(nc_json_str_def(o, "mac", ""), mac, sizeof(mac));
        if (group_id) {
            /*
             * A group-bound rule carries no MAC of its own: the member set is
             * resolved at ruleset generation time, so adding or removing a
             * device from the group changes what the rule blocks without the
             * rule being rewritten.
             *
             * The group must already exist. Storing a dangling reference would
             * produce a rule that silently blocks nothing, which is the failure
             * mode a user is least likely to notice on a page whose whole job is
             * cutting devices off.
             */
            if (!nc_netctl_group_exists(group_id))
                return -1;
            mac[0] = '\0';
        } else {
            if (strcmp(source, "any") && !nc_netctl_mac_ok(mac))
                return -1;
            if (nc_netctl_mac_conflict(mac, nc_json_str_def(o, "id", "")))
                return -1;
        }
        if (nc_netctl_upsert_rule(o, "mac") != 0)
            return -1;
        if (nc_prepare(&st, "INSERT OR REPLACE INTO network_control_mac_rule(rule_id,mode,mac,terminal_name) VALUES(?,?,?,?)") == 0) {
            sqlite3_bind_text(st, 1, nc_json_str_def(o, "id", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str_def(o, "mode", "deny"), -1, SQLITE_TRANSIENT);
            /*
             * A group rule stores an empty mac. The uniqueness index is partial
             * (WHERE mac<>''), so any number of group-bound rules coexist while
             * single-MAC rules keep their one-rule-per-MAC guarantee.
             */
            sqlite3_bind_text(st, 3, mac, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, nc_json_str_def(o, "terminal_name", ""), -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
    return 0;
}
static int nc_netctl_save_url_access(struct json_object*arr){NC_NETCTL_SAVE_DETAIL_BEGIN(arr,"url_access","INSERT OR REPLACE INTO network_control_url_access_rule(rule_id,mode,domains,match_type,action) VALUES(?,?,?,?,?)")sqlite3_bind_text(st,2,nc_json_str_def(o,"mode","blacklist"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"domains",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"match_type","domain"),-1,SQLITE_TRANSIENT);if(!nc_netctl_action_ok(nc_json_str_def(o,"action","block"))){sqlite3_finalize(st);return -1;}sqlite3_bind_text(st,5,nc_json_str_def(o,"action","block"),-1,SQLITE_TRANSIENT);NC_NETCTL_SAVE_DETAIL_END return 0;}
static int nc_netctl_save_url_rewrite(struct json_object*arr){NC_NETCTL_SAVE_DETAIL_BEGIN(arr,"url_rewrite","INSERT OR REPLACE INTO network_control_url_rewrite_rule(rule_id,match_mode,source_url,dest_url,exclude,ratio) VALUES(?,?,?,?,?,?)")sqlite3_bind_text(st,2,nc_json_str_def(o,"match_mode","domain"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"source_url",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"dest_url",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"exclude",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,6,nc_json_int_def(o,"ratio",100));NC_NETCTL_SAVE_DETAIL_END return 0;}
static int nc_netctl_save_app(struct json_object*arr){if(!arr||!json_object_is_type(arr,json_type_array))return 0;int n=json_object_array_length(arr);for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(arr,i);if(nc_netctl_upsert_rule(o,"app")!=0)return -1;struct json_object*v=NULL;json_object_object_get_ex(o,"app_ids",&v);char*ids=nc_json_array_to_string(v,nc_json_str_def(o,"app_ids",""));json_object_object_get_ex(o,"apps",&v);char*apps=nc_json_array_to_string(v,nc_json_str_def(o,"apps",""));sqlite3_stmt*st=NULL;if(nc_prepare(&st,"INSERT OR REPLACE INTO network_control_app_rule(rule_id,app_ids,apps,destination,action,filter_quic) VALUES(?,?,?,?,?,?)")==0){sqlite3_bind_text(st,1,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,ids?ids:"",-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,apps?apps:"",-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"destination","any"),-1,SQLITE_TRANSIENT);if(!nc_netctl_action_ok(nc_json_str_def(o,"action","block"))){sqlite3_finalize(st);if(ids)free(ids);if(apps)free(apps);return -1;}sqlite3_bind_text(st,5,nc_json_str_def(o,"action","block"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,6,nc_json_int_def(o,"filter_quic",0));sqlite3_step(st);sqlite3_finalize(st);}if(ids)free(ids);if(apps)free(apps);}return 0;}
static int nc_netctl_save_terminal(struct json_object*arr){NC_NETCTL_SAVE_DETAIL_BEGIN(arr,"terminal_limit","INSERT OR REPLACE INTO network_control_terminal_limit(rule_id,limit_type,line,address,protocol,speed_mode,src_port,dest_port,upload_mbps,download_mbps) VALUES(?,?,?,?,?,?,?,?,?,?)")sqlite3_bind_text(st,2,nc_json_str_def(o,"limit_type","ip"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"line","all"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"address",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"protocol","all"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"speed_mode","shared"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(o,"src_port","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"dest_port","any"),-1,SQLITE_TRANSIENT);sqlite3_bind_double(st,9,json_object_get_double(json_object_object_get(o,"upload_mbps")));sqlite3_bind_double(st,10,json_object_get_double(json_object_object_get(o,"download_mbps")));NC_NETCTL_SAVE_DETAIL_END return 0;}

int jmx_network_control_save(struct json_object *cfg)
{
    if(!cfg||jmx_netconfig_db_init()!=0)return -1;nc_netctl_db_init();struct json_object*v=NULL;int rc=0;
    /*
     * MAC allowlist writes have a separate transaction contract: callers must
     * provide config_revision, use the dedicated mode/members methods, and
     * receive runtime apply/readback state. Accepting mac_whitelist here would
     * silently bypass all three protections through the legacy bulk-save UBus
     * method. The one-time rulesd migration calls the lower-level import helper
     * directly and is intentionally unaffected by this runtime guard.
     */
    if (json_object_object_get_ex(cfg, "mac_whitelist", &v))
        return -1;
    if(nc_txn_begin()!=0)return -1;if(json_object_object_get_ex(cfg,"global",&v)&&v){sqlite3_stmt*st=NULL;struct json_object*f=NULL;int app=json_object_object_get_ex(v,"appfilter_enabled",&f)?json_object_get_boolean(f):-1;int mac=json_object_object_get_ex(v,"macfilter_enabled",&f)?json_object_get_boolean(f):-1;int rec=json_object_object_get_ex(v,"record_enabled",&f)?json_object_get_boolean(f):-1;if(nc_prepare(&st,"UPDATE network_control_global SET enabled=?,mode=?,default_action=?,schedule_default=?,appfilter_enabled=CASE WHEN ?<0 THEN appfilter_enabled ELSE ? END,macfilter_enabled=CASE WHEN ?<0 THEN macfilter_enabled ELSE ? END,record_enabled=CASE WHEN ?<0 THEN record_enabled ELSE ? END,apply_state='draft',updated_at=? WHERE id=1")==0){sqlite3_bind_int(st,1,nc_json_bool_def(v,"enabled",1));sqlite3_bind_text(st,2,nc_json_str_def(v,"mode","balanced"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(v,"default_action","allow"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(v,"schedule_default","always"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,5,app);sqlite3_bind_int(st,6,app);sqlite3_bind_int(st,7,mac);sqlite3_bind_int(st,8,mac);sqlite3_bind_int(st,9,rec);sqlite3_bind_int(st,10,rec);sqlite3_bind_int64(st,11,(sqlite3_int64)nc_now_s());sqlite3_step(st);sqlite3_finalize(st);}}
    if(json_object_object_get_ex(cfg,"connection_limits",&v))rc|=nc_netctl_save_connection(v);if(json_object_object_get_ex(cfg,"mac_rules",&v))rc|=nc_netctl_save_mac(v);if(json_object_object_get_ex(cfg,"url_access_rules",&v))rc|=nc_netctl_save_url_access(v);if(json_object_object_get_ex(cfg,"url_rewrite_rules",&v))rc|=nc_netctl_save_url_rewrite(v);if(json_object_object_get_ex(cfg,"app_rules",&v))rc|=nc_netctl_save_app(v);if(json_object_object_get_ex(cfg,"terminal_limits",&v))rc|=nc_netctl_save_terminal(v);if(json_object_object_get_ex(cfg,"app_whitelist",&v))rc|=nc_rulesd_replace_whitelist(v,"app");if(json_object_object_get_ex(cfg,"other_control",&v)&&v){sqlite3_stmt*st=NULL;if(nc_prepare(&st,"UPDATE network_control_other SET anti_share_enabled=?,ttl_value=?,dns_hijack_protect=?,block_proxy_vpn=?,block_unknown_quic=?,scope=?,schedule=?,updated_at=? WHERE id=1")==0){sqlite3_bind_int(st,1,nc_json_bool_def(v,"anti_share_enabled",1));sqlite3_bind_int(st,2,nc_json_int_def(v,"ttl_value",1));sqlite3_bind_int(st,3,nc_json_bool_def(v,"dns_hijack_protect",1));sqlite3_bind_int(st,4,nc_json_bool_def(v,"block_proxy_vpn",0));sqlite3_bind_int(st,5,nc_json_bool_def(v,"block_unknown_quic",0));sqlite3_bind_text(st,6,nc_json_str_def(v,"scope","lan"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(v,"schedule","always"),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,8,(sqlite3_int64)nc_now_s());sqlite3_step(st);sqlite3_finalize(st);}}
    if(rc==0)rc|=nc_exec("UPDATE network_control_global SET revision=revision+1,apply_state='draft',updated_at=strftime('%s','now') WHERE id=1");
    if(rc==0)rc|=nc_exec("UPDATE network_control_status SET apply_state='draft',warnings='saved; runtime apply pending',updated_at=strftime('%s','now') WHERE id=1");
    if(nc_exec(rc==0?"COMMIT":"ROLLBACK")!=0)rc=-1;
    return rc==0?0:-1;
}

#define RULESD_UCI_MIGRATION "rulesd_uci_v1"

static void nc_rulesd_add_whitelist(struct json_object *out, const char *kind)
{
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "SELECT mac FROM network_control_whitelist WHERE kind=?1 ORDER BY mac") != 0)
        return;
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_STATIC);
    while (sqlite3_step(st) == SQLITE_ROW)
        json_object_array_add(out, json_object_new_string((const char *)sqlite3_column_text(st, 0)));
    sqlite3_finalize(st);
}

static void nc_rulesd_add_time_rules(struct json_object *out, const char *schedule)
{
    struct json_object *parsed = NULL;
    if (!schedule || !schedule[0] || !strcmp(schedule, "always")) {
        struct json_object *rule = json_object_new_object(), *days = json_object_new_array();
        for (int i = 0; i < 7; i++) json_object_array_add(days, json_object_new_int(i));
        json_object_object_add(rule, "weekdays", days);
        json_object_object_add(rule, "start_time", json_object_new_string("00:00"));
        json_object_object_add(rule, "end_time", json_object_new_string("23:59"));
        json_object_array_add(out, rule);
        return;
    }
    if (schedule && schedule[0] == '[')
        parsed = json_tokener_parse(schedule);
    if (parsed && json_object_is_type(parsed, json_type_array)) {
        int n = json_object_array_length(parsed);
        for (int i = 0; i < n; i++)
            json_object_array_add(out, json_object_get(json_object_array_get_idx(parsed, i)));
    }
    if (parsed) json_object_put(parsed);
}

static int nc_rulesd_repair_app_runtime_ids(void)
{
    struct runtime_entry { char *id; int runtime_id; };
    /* 上限提到 512 后 entries[] 约 8KB，不放栈上。 */
    struct runtime_entry *entries = calloc(NC_AEGIS_APPFILTER_MAX_RULES,
                                           sizeof(*entries));
    sqlite3_stmt *st = NULL;
    int *used = calloc(NC_AEGIS_APPFILTER_MAX_RULES + 1, sizeof(*used));
    int count = 0, step_rc, rc = -1;

    if (!entries || !used) {
        free(entries);
        free(used);
        return -1;
    }
    if (nc_prepare(&st,
        "SELECT id,runtime_rule_id FROM network_control_rule WHERE type='app' ORDER BY created_at,id") != 0) {
        free(entries);
        free(used);
        return -1;
    }
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        int runtime_id = sqlite3_column_int(st, 1);
        if (count >= NC_AEGIS_APPFILTER_MAX_RULES || !id || !id[0])
            goto done;
        entries[count].id = strdup(id);
        if (!entries[count].id)
            goto done;
        if (runtime_id > 0 && runtime_id <= NC_AEGIS_APPFILTER_MAX_RULES && !used[runtime_id]) {
            entries[count].runtime_id = runtime_id;
            used[runtime_id] = 1;
        }
        count++;
    }
    if (step_rc != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (nc_exec("SAVEPOINT repair_app_runtime_ids") != 0)
        goto done;
    for (int i = 0; i < count; i++) {
        int candidate;
        if (entries[i].runtime_id > 0)
            continue;
        for (candidate = 1; candidate <= NC_AEGIS_APPFILTER_MAX_RULES; candidate++)
            if (!used[candidate])
                break;
        if (candidate > NC_AEGIS_APPFILTER_MAX_RULES)
            goto rollback;
        if (nc_prepare(&st,
            "UPDATE network_control_rule SET runtime_rule_id=?1 WHERE id=?2 AND type='app'") != 0)
            goto rollback;
        sqlite3_bind_int(st, 1, candidate);
        sqlite3_bind_text(st, 2, entries[i].id, -1, SQLITE_TRANSIENT);
        if (nc_step_done(st) != 0 || nc_sqlite_changes() != 1) {
            sqlite3_finalize(st);
            st = NULL;
            goto rollback;
        }
        sqlite3_finalize(st);
        st = NULL;
        entries[i].runtime_id = candidate;
        used[candidate] = 1;
    }
    if (nc_exec("RELEASE repair_app_runtime_ids") != 0)
        goto done;
    rc = 0;
    goto done;

rollback:
    if (st) {
        sqlite3_finalize(st);
        st = NULL;
    }
    nc_exec("ROLLBACK TO repair_app_runtime_ids");
    nc_exec("RELEASE repair_app_runtime_ids");
done:
    if (st) sqlite3_finalize(st);
    for (int i = 0; i < count; i++)
        free(entries[i].id);
    free(entries);
    free(used);
    return rc;
}

struct json_object *jmx_rulesd_config_get(void)
{
    struct json_object *data, *rules, *whitelist, *migration;
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    nc_netctl_db_init();
    if (nc_rulesd_repair_app_runtime_ids() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    data = json_object_new_object();
    json_object_object_add(data, "source", json_object_new_string("config.db:network_control"));
    if (nc_prepare(&st, "SELECT enabled,appfilter_enabled,macfilter_enabled,record_enabled FROM network_control_global WHERE id=1") == 0 && sqlite3_step(st) == SQLITE_ROW) {
        json_object_object_add(data, "appfilter_enabled", json_object_new_int(sqlite3_column_int(st, 0) && sqlite3_column_int(st, 1)));
        json_object_object_add(data, "macfilter_enabled", json_object_new_int(sqlite3_column_int(st, 0) && sqlite3_column_int(st, 2)));
        json_object_object_add(data, "record_enabled", json_object_new_int(sqlite3_column_int(st, 3)));
        sqlite3_finalize(st); st = NULL;
    }
    rules = json_object_new_array();
    if (nc_prepare(&st, "SELECT r.id,r.runtime_rule_id,r.name,r.enabled,r.source,r.schedule,d.app_ids,d.filter_quic FROM network_control_rule r JOIN network_control_app_rule d ON d.rule_id=r.id WHERE r.type='app' ORDER BY r.priority,r.id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object(), *times = json_object_new_array();
            nc_add_text(o, "config_id", st, 0); json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 1)));
            nc_add_text(o, "name", st, 2); json_object_object_add(o, "enabled", json_object_new_int(sqlite3_column_int(st, 3)));
            { const char *source = (const char *)sqlite3_column_text(st, 4); json_object_object_add(o, "user_mac", json_object_new_string(nc_netctl_mac_ok(source) ? source : "")); json_object_object_add(o, "mode", json_object_new_int(nc_netctl_mac_ok(source) ? 2 : 1)); }
            nc_rulesd_add_time_rules(times, (const char *)sqlite3_column_text(st, 5)); json_object_object_add(o, "time_rules", times);
            json_object_object_add(o, "app_ids", nc_json_array_from_text((const char *)sqlite3_column_text(st, 6)));
            json_object_object_add(o, "filter_quic", json_object_new_int(sqlite3_column_int(st, 7))); json_object_array_add(rules, o);
        }
        sqlite3_finalize(st); st = NULL;
    }
    json_object_object_add(data, "app_rules", rules);
    rules = json_object_new_array();
    if (nc_prepare(&st, "SELECT r.id,r.runtime_rule_id,r.name,r.enabled,r.source,r.schedule,d.mac FROM network_control_rule r JOIN network_control_mac_rule d ON d.rule_id=r.id WHERE r.type='mac' ORDER BY r.priority,r.id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object(), *times = json_object_new_array(); const char *mac = (const char *)sqlite3_column_text(st, 6);
            nc_add_text(o, "config_id", st, 0); json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 1)));
            nc_add_text(o, "name", st, 2); json_object_object_add(o, "enabled", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(o, "mode", json_object_new_int(mac && mac[0] ? 2 : 1)); nc_add_text(o, "user_mac", st, 6);
            nc_rulesd_add_time_rules(times, (const char *)sqlite3_column_text(st, 5)); json_object_object_add(o, "time_rules", times); json_object_array_add(rules, o);
        }
        sqlite3_finalize(st); st = NULL;
    }
    json_object_object_add(data, "mac_rules", rules);
    whitelist = json_object_new_array(); nc_rulesd_add_whitelist(whitelist, "app"); json_object_object_add(data, "app_whitelist", whitelist);
    whitelist = json_object_new_array(); nc_rulesd_add_whitelist(whitelist, "mac"); json_object_object_add(data, "mac_whitelist", whitelist);
    migration = json_object_new_object();
    if (nc_prepare(&st, "SELECT status,source,imported_rows,imported_at,detail FROM config_migration WHERE name=?1") == 0) {
        sqlite3_bind_text(st, 1, RULESD_UCI_MIGRATION, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) { nc_add_text(migration,"status",st,0); nc_add_text(migration,"source",st,1); json_object_object_add(migration,"imported_rows",json_object_new_int(sqlite3_column_int(st,2))); json_object_object_add(migration,"imported_at",json_object_new_int64(sqlite3_column_int64(st,3))); nc_add_text(migration,"detail",st,4); }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "migration", migration);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static sqlite3_int64 nc_aegis_app_block_revision(void)
{
    sqlite3_stmt *st = NULL;
    sqlite3_int64 revision = 0;

    if (nc_prepare(&st, "SELECT revision FROM network_control_global WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW)
        revision = sqlite3_column_int64(st, 0);
    if (st) sqlite3_finalize(st);
    return revision;
}

static int nc_aegis_app_block_global_enabled(void)
{
    sqlite3_stmt *st = NULL;
    int enabled = -1;

    if (nc_prepare(&st, "SELECT enabled AND appfilter_enabled FROM network_control_global WHERE id=1") == 0 &&
        sqlite3_step(st) == SQLITE_ROW)
        enabled = sqlite3_column_int(st, 0) != 0;
    if (st) sqlite3_finalize(st);
    return enabled;
}

static int nc_aegis_app_block_rule_type(const char *id)
{
    sqlite3_stmt *st = NULL;
    int result = 0;

    if (nc_prepare(&st, "SELECT type FROM network_control_rule WHERE id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        result = !strcmp((const char *)sqlite3_column_text(st, 0), "app") ? 1 : 2;
    sqlite3_finalize(st);
    return result;
}

static int nc_aegis_app_block_rule_count(void)
{
    sqlite3_stmt *st = NULL;
    int count = -1;

    if (nc_prepare(&st, "SELECT COUNT(*) FROM network_control_rule WHERE type='app'") == 0 &&
        sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    return count;
}

static int nc_aegis_app_block_runtime_id(const char *id, int current, int *runtime_id)
{
    sqlite3_stmt *st = NULL;
    int used[NC_AEGIS_APPFILTER_MAX_RULES + 1] = {0};
    int step_rc;

    if (!id || !id[0] || !runtime_id)
        return -1;
    if (current > 0 && current <= NC_AEGIS_APPFILTER_MAX_RULES) {
        if (nc_prepare(&st,
            "SELECT COUNT(*) FROM network_control_rule WHERE type='app' AND id<>?1 AND runtime_rule_id=?2") != 0)
            return -1;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, current);
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            return -1;
        }
        if (sqlite3_column_int(st, 0) == 0) {
            sqlite3_finalize(st);
            *runtime_id = current;
            return 0;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (nc_prepare(&st,
        "SELECT runtime_rule_id FROM network_control_rule WHERE type='app' AND id<>?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        int candidate = sqlite3_column_int(st, 0);
        if (candidate > 0 && candidate <= NC_AEGIS_APPFILTER_MAX_RULES)
            used[candidate] = 1;
    }
    sqlite3_finalize(st);
    if (step_rc != SQLITE_DONE)
        return -1;
    for (int candidate = 1; candidate <= NC_AEGIS_APPFILTER_MAX_RULES; candidate++) {
        if (!used[candidate]) {
            *runtime_id = candidate;
            return 0;
        }
    }
    return -1;
}

struct nc_aegis_app_runtime_rule {
    int rule_id;
    int enabled;
    int app_count;
    int mac_count;
    uint64_t app_hash_xor;
    uint64_t app_hash_sum;
    uint64_t mac_value;
    sqlite3_int64 hits;
    sqlite3_int64 last_hit_s;
};

struct nc_aegis_app_runtime {
    int available;
    int valid;
    int count;
    struct nc_aegis_app_runtime_rule rules[NC_AEGIS_APPFILTER_MAX_RULES];
};

static int nc_aegis_app_block_time_ok(const char *value);

static int nc_aegis_app_runtime_load(struct nc_aegis_app_runtime *runtime)
{
    FILE *fp;
    char line[256];

    memset(runtime, 0, sizeof(*runtime));
    fp = fopen(NC_AEGIS_APPFILTER_RUNTIME_FILE, "r");
    if (!fp)
        return -1;
    runtime->available = 1;
    if (!fgets(line, sizeof(line), fp) ||
        strcmp(line, "rule_id enabled app_count mac_count app_hash_xor app_hash_sum mac_value hits last_hit_s\n")) {
        fclose(fp);
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        struct nc_aegis_app_runtime_rule *rule;
        unsigned long long app_hash_xor, app_hash_sum, mac_value;
        long long hits, last_hit_s;
        char trailing;

        if (runtime->count >= NC_AEGIS_APPFILTER_MAX_RULES) {
            fclose(fp);
            return -1;
        }
        rule = &runtime->rules[runtime->count];
        if (sscanf(line, "%d %d %d %d %llx %llx %llx %lld %lld %c",
                   &rule->rule_id, &rule->enabled, &rule->app_count,
                   &rule->mac_count, &app_hash_xor, &app_hash_sum, &mac_value,
                   &hits, &last_hit_s, &trailing) != 9 ||
            rule->rule_id <= 0 ||
            rule->rule_id > NC_AEGIS_APPFILTER_MAX_RULES ||
            (rule->enabled != 0 && rule->enabled != 1) ||
            rule->app_count < 0 ||
            rule->app_count > NC_AEGIS_APPFILTER_MAX_APP_IDS ||
            rule->mac_count < 0 || rule->mac_count > 1 ||
            mac_value > 0xffffffffffffULL ||
            hits < 0 || last_hit_s < 0) {
            fclose(fp);
            return -1;
        }
        for (int i = 0; i < runtime->count; i++) {
            if (runtime->rules[i].rule_id == rule->rule_id) {
                fclose(fp);
                return -1;
            }
        }
        rule->app_hash_xor = (uint64_t)app_hash_xor;
        rule->app_hash_sum = (uint64_t)app_hash_sum;
        rule->mac_value = (uint64_t)mac_value;
        rule->hits = (sqlite3_int64)hits;
        rule->last_hit_s = (sqlite3_int64)last_hit_s;
        runtime->count++;
    }
    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    runtime->valid = 1;
    return 0;
}

static const struct nc_aegis_app_runtime_rule *nc_aegis_app_runtime_find(
    const struct nc_aegis_app_runtime *runtime, int rule_id)
{
    if (!runtime || !runtime->valid)
        return NULL;
    for (int i = 0; i < runtime->count; i++)
        if (runtime->rules[i].rule_id == rule_id)
            return &runtime->rules[i];
    return NULL;
}

/*
 * struct nc_aegis_app_runtime 随 NC_AEGIS_APPFILTER_MAX_RULES 线性增长
 * (512 条约 28KB)，放在栈上会让 webd 工作线程的单个栈帧过大，所以统一堆分配。
 * 返回 NULL 时调用方可继续，nc_aegis_app_runtime_find() 对 NULL 已做处理。
 */
static struct nc_aegis_app_runtime *nc_aegis_app_runtime_alloc_load(void)
{
    struct nc_aegis_app_runtime *runtime = calloc(1, sizeof(*runtime));

    if (!runtime)
        return NULL;
    (void)nc_aegis_app_runtime_load(runtime);
    return runtime;
}

static uint64_t nc_aegis_app_mix_id(uint32_t value)
{
    uint64_t mixed = (uint64_t)value + UINT64_C(0x9e3779b97f4a7c15);

    mixed = (mixed ^ (mixed >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    mixed = (mixed ^ (mixed >> 27)) * UINT64_C(0x94d049bb133111eb);
    return mixed ^ (mixed >> 31);
}

static int nc_aegis_app_expected_fingerprint(struct json_object *app_ids,
                                             const char *source,
                                             uint64_t *app_hash_xor,
                                             uint64_t *app_hash_sum,
                                             uint64_t *mac_value,
                                             int *app_count)
{
    unsigned int bytes[6];
    uint32_t seen[NC_AEGIS_APPFILTER_MAX_APP_IDS];
    int count = 0;

    *app_hash_xor = 0;
    *app_hash_sum = 0;
    *mac_value = 0;
    if (app_count) *app_count = 0;
    if (!app_ids || !json_object_is_type(app_ids, json_type_array))
        return -1;
    for (int i = 0; i < json_object_array_length(app_ids); i++) {
        struct json_object *value = json_object_array_get_idx(app_ids, i);
        int64_t app_id;
        uint64_t mixed;
        int duplicate = 0;

        if (!value)
            return -1;
        if (json_object_is_type(value, json_type_int)) {
            app_id = json_object_get_int64(value);
        } else if (json_object_is_type(value, json_type_string)) {
            const char *text = json_object_get_string(value);
            char *end = NULL;
            long long parsed;

            errno = 0;
            parsed = strtoll(text ? text : "", &end, 10);
            if (errno || !text || !text[0] || !end || *end)
                return -1;
            app_id = parsed;
        } else {
            return -1;
        }
        if (app_id <= 0 || app_id > INT_MAX)
            return -1;
        for (int j = 0; j < count; j++)
            if (seen[j] == (uint32_t)app_id)
                duplicate = 1;
        if (duplicate)
            continue;
        if (count >= NC_AEGIS_APPFILTER_MAX_APP_IDS)
            return -1;
        seen[count++] = (uint32_t)app_id;
        mixed = nc_aegis_app_mix_id((uint32_t)app_id);
        *app_hash_xor ^= mixed;
        *app_hash_sum += mixed;
    }
    if (count == 0)
        return -1;
    if (app_count) *app_count = count;
    if (!source || !strcmp(source, "any"))
        return 0;
    if (sscanf(source, "%2x:%2x:%2x:%2x:%2x:%2x",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3],
               &bytes[4], &bytes[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        *mac_value = (*mac_value << 8) | bytes[i];
    return 0;
}

static int nc_aegis_app_schedule_active(const char *stored, int enabled)
{
    struct json_object *schedule;
    time_t now;
    struct tm current;
    int minute;
    int active = 0;

    if (!enabled)
        return 0;
    if (!stored || !stored[0] || !strcmp(stored, "always"))
        return 1;
    schedule = json_tokener_parse(stored);
    if (!schedule || !json_object_is_type(schedule, json_type_array)) {
        if (schedule) json_object_put(schedule);
        return -1;
    }
    now = time(NULL);
    if (now == (time_t)-1 || !localtime_r(&now, &current)) {
        json_object_put(schedule);
        return -1;
    }
    minute = current.tm_hour * 60 + current.tm_min;
    for (int i = 0; i < json_object_array_length(schedule) && !active; i++) {
        struct json_object *entry = json_object_array_get_idx(schedule, i);
        struct json_object *days = NULL, *start = NULL, *end = NULL;
        int day_match = 0, start_minute, end_minute;
        const char *start_text, *end_text;

        if (!entry || !json_object_is_type(entry, json_type_object) ||
            !json_object_object_get_ex(entry, "weekdays", &days) ||
            !json_object_is_type(days, json_type_array) ||
            !json_object_object_get_ex(entry, "start_time", &start) ||
            !json_object_is_type(start, json_type_string) ||
            !json_object_object_get_ex(entry, "end_time", &end) ||
            !json_object_is_type(end, json_type_string)) {
            json_object_put(schedule);
            return -1;
        }
        for (int j = 0; j < json_object_array_length(days); j++) {
            struct json_object *day = json_object_array_get_idx(days, j);
            if (!day || !json_object_is_type(day, json_type_int)) {
                json_object_put(schedule);
                return -1;
            }
            if (json_object_get_int(day) == current.tm_wday)
                day_match = 1;
        }
        if (!day_match)
            continue;
        start_text = json_object_get_string(start);
        end_text = json_object_get_string(end);
        if (!nc_aegis_app_block_time_ok(start_text) ||
            !nc_aegis_app_block_time_ok(end_text)) {
            json_object_put(schedule);
            return -1;
        }
        start_minute = (start_text[0] - '0') * 600 +
                       (start_text[1] - '0') * 60 +
                       (start_text[3] - '0') * 10 +
                       start_text[4] - '0';
        end_minute = (end_text[0] - '0') * 600 +
                     (end_text[1] - '0') * 60 +
                     (end_text[3] - '0') * 10 +
                     end_text[4] - '0';
        active = start_minute <= end_minute ?
            minute >= start_minute && minute <= end_minute :
            minute >= start_minute || minute <= end_minute;
    }
    json_object_put(schedule);
    return active;
}

static struct json_object *nc_aegis_app_block_capabilities(int appfilter_enabled)
{
    struct json_object *caps = json_object_new_object();
    struct json_object *sources = json_object_new_array();
    struct json_object *schedules = json_object_new_array();
    struct nc_aegis_app_runtime *runtime = calloc(1, sizeof(*runtime));
    int readback = runtime && nc_aegis_app_runtime_load(runtime) == 0;

    free(runtime);

    json_object_array_add(sources, json_object_new_string("any"));
    json_object_array_add(sources, json_object_new_string("mac"));
    json_object_array_add(schedules, json_object_new_string("always"));
    json_object_array_add(schedules, json_object_new_string("weekday_time_ranges"));
    json_object_object_add(caps, "supported", json_object_new_boolean(1));
    json_object_object_add(caps, "config_authority", json_object_new_string("config.db:network_control_rule+network_control_app_rule"));
    json_object_object_add(caps, "dataplane", json_object_new_string("rule_manager.lua->/dev/jmx->jmx_match_app_filter_rule"));
    json_object_object_add(caps, "source_modes", sources);
    json_object_object_add(caps, "schedule_modes", schedules);
    json_object_object_add(caps, "action_block_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "filter_quic_supported", json_object_new_boolean(0));
    json_object_object_add(caps, "max_rules", json_object_new_int(NC_AEGIS_APPFILTER_MAX_RULES));
    json_object_object_add(caps, "max_app_ids_per_rule", json_object_new_int(NC_AEGIS_APPFILTER_MAX_APP_IDS));
    json_object_object_add(caps, "preview_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "revision_lock_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "rulesd_reinit_supported", json_object_new_boolean(1));
    json_object_object_add(caps, "runtime_readback_supported",
                           json_object_new_boolean(readback));
    json_object_object_add(caps, "per_rule_hits_supported",
                           json_object_new_boolean(readback));
    json_object_object_add(caps, "appfilter_global_state_available", json_object_new_boolean(appfilter_enabled >= 0));
    json_object_object_add(caps, "appfilter_global_enabled", json_object_new_boolean(appfilter_enabled > 0));
    return caps;
}

static void nc_aegis_app_block_runtime_fields(struct json_object *out,
                                               int appfilter_enabled,
                                               int reload_requested,
                                               const char *reload_error)
{
    const char *reason;

    if (appfilter_enabled < 0)
        reason = "appfilter_global_state_unavailable";
    else if (!appfilter_enabled)
        reason = "appfilter_global_disabled";
    else if (reload_error && reload_error[0])
        reason = reload_error;
    else
        reason = "runtime_readback_unavailable_apply_pending";
    json_object_object_add(out, "runtime", json_object_new_string("apply_pending"));
    json_object_object_add(out, "applied", json_object_new_boolean(0));
    json_object_object_add(out, "degraded", json_object_new_boolean(1));
    json_object_object_add(out, "reason", json_object_new_string(reason));
    json_object_object_add(out, "runtime_readback_supported", json_object_new_boolean(0));
    json_object_object_add(out, "reload_requested", json_object_new_boolean(reload_requested));
}

static struct json_object *nc_aegis_app_block_error(const char *error,
                                                     const char *field,
                                                     sqlite3_int64 revision)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string(error ? error : "invalid_request"));
    if (field && field[0])
        json_object_object_add(data, "field", json_object_new_string(field));
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static int nc_aegis_app_block_time_ok(const char *value)
{
    int hour, minute;

    if (!value || strlen(value) != 5 || value[2] != ':' ||
        !isdigit((unsigned char)value[0]) || !isdigit((unsigned char)value[1]) ||
        !isdigit((unsigned char)value[3]) || !isdigit((unsigned char)value[4]))
        return 0;
    hour = (value[0] - '0') * 10 + value[1] - '0';
    minute = (value[3] - '0') * 10 + value[4] - '0';
    return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
}

static int nc_aegis_app_block_text_ok(const char *value, size_t max_len)
{
    const unsigned char *p = (const unsigned char *)value;

    if (!value || !value[0] || strlen(value) > max_len)
        return 0;
    for (; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

static int nc_aegis_app_block_field_ok(const char *key)
{
    static const char *allowed[] = {
        "id", "name", "enabled", "source", "app_ids", "schedule", "action",
        "filter_quic", "preview", "confirm", "revision", NULL
    };

    for (int i = 0; allowed[i]; i++)
        if (!strcmp(key, allowed[i]))
            return 1;
    return 0;
}

static int nc_aegis_app_block_schedule_normalize(struct json_object *value,
                                                  struct json_object **normalized,
                                                  char **stored)
{
    struct json_object *out;

    *normalized = NULL;
    *stored = NULL;
    if (json_object_is_type(value, json_type_string) &&
        !strcmp(json_object_get_string(value), "always")) {
        *normalized = json_object_new_string("always");
        *stored = strdup("always");
        return *normalized && *stored ? 0 : -1;
    }
    if (!json_object_is_type(value, json_type_array) ||
        json_object_array_length(value) < 1 || json_object_array_length(value) > 32)
        return -1;
    out = json_object_new_array();
    for (int i = 0; i < json_object_array_length(value); i++) {
        struct json_object *entry = json_object_array_get_idx(value, i);
        struct json_object *weekdays = NULL, *start = NULL, *end = NULL;
        struct json_object *clean_entry, *clean_days;
        int seen[7] = {0};

        if (!entry || !json_object_is_type(entry, json_type_object) ||
            !json_object_object_get_ex(entry, "weekdays", &weekdays) ||
            !json_object_is_type(weekdays, json_type_array) ||
            json_object_array_length(weekdays) < 1 ||
            !json_object_object_get_ex(entry, "start_time", &start) ||
            !json_object_is_type(start, json_type_string) ||
            !json_object_object_get_ex(entry, "end_time", &end) ||
            !json_object_is_type(end, json_type_string) ||
            !nc_aegis_app_block_time_ok(json_object_get_string(start)) ||
            !nc_aegis_app_block_time_ok(json_object_get_string(end))) {
            json_object_put(out);
            return -1;
        }
        clean_entry = json_object_new_object();
        clean_days = json_object_new_array();
        for (int j = 0; j < json_object_array_length(weekdays); j++) {
            struct json_object *day = json_object_array_get_idx(weekdays, j);
            int weekday;

            if (!json_object_is_type(day, json_type_int) ||
                (weekday = json_object_get_int(day)) < 0 || weekday > 6) {
                json_object_put(clean_entry);
                json_object_put(clean_days);
                json_object_put(out);
                return -1;
            }
            if (!seen[weekday]) {
                seen[weekday] = 1;
                json_object_array_add(clean_days, json_object_new_int(weekday));
            }
        }
        json_object_object_add(clean_entry, "weekdays", clean_days);
        json_object_object_add(clean_entry, "start_time",
                               json_object_new_string(json_object_get_string(start)));
        json_object_object_add(clean_entry, "end_time",
                               json_object_new_string(json_object_get_string(end)));
        json_object_array_add(out, clean_entry);
    }
    *stored = strdup(json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
    if (!*stored) {
        json_object_put(out);
        return -1;
    }
    *normalized = out;
    return 0;
}

static int nc_aegis_app_block_normalize(struct json_object *cfg,
                                         struct json_object **normalized,
                                         char *field, size_t field_len)
{
    static const char *required[] = {
        "id", "name", "enabled", "source", "app_ids", "schedule", "action",
        "filter_quic", NULL
    };
    struct json_object *value = NULL, *out = NULL, *ids = NULL, *schedule = NULL;
    char source[32];
    char *stored_schedule = NULL;

    *normalized = NULL;
    if (!cfg || !json_object_is_type(cfg, json_type_object)) {
        snprintf(field, field_len, "%s", "request");
        return -1;
    }
    json_object_object_foreach(cfg, key, ignored) {
        (void)ignored;
        if (!nc_aegis_app_block_field_ok(key)) {
            snprintf(field, field_len, "%s", key);
            return -1;
        }
    }
    for (int i = 0; i < 2; i++) {
        const char *key = i == 0 ? "preview" : "confirm";
        if (json_object_object_get_ex(cfg, key, &value) &&
            !json_object_is_type(value, json_type_boolean)) {
            snprintf(field, field_len, "%s", key);
            return -1;
        }
    }
    if (json_object_object_get_ex(cfg, "revision", &value) &&
        !json_object_is_type(value, json_type_int)) {
        snprintf(field, field_len, "%s", "revision");
        return -1;
    }
    for (int i = 0; required[i]; i++) {
        if (!json_object_object_get_ex(cfg, required[i], &value)) {
            snprintf(field, field_len, "%s", required[i]);
            return -1;
        }
    }
    value = json_object_object_get(cfg, "id");
    if (!json_object_is_type(value, json_type_string) ||
        strlen(json_object_get_string(value)) > 64 ||
        !nc_valid_name(json_object_get_string(value))) {
        snprintf(field, field_len, "%s", "id"); return -1;
    }
    value = json_object_object_get(cfg, "name");
    if (!json_object_is_type(value, json_type_string) ||
        !nc_aegis_app_block_text_ok(json_object_get_string(value), 64)) {
        snprintf(field, field_len, "%s", "name"); return -1;
    }
    value = json_object_object_get(cfg, "enabled");
    if (!json_object_is_type(value, json_type_boolean)) {
        snprintf(field, field_len, "%s", "enabled"); return -1;
    }
    value = json_object_object_get(cfg, "source");
    if (!json_object_is_type(value, json_type_string)) {
        snprintf(field, field_len, "%s", "source"); return -1;
    }
    nc_netctl_mac_norm(json_object_get_string(value), source, sizeof(source));
    if (strcmp(source, "any") && !nc_netctl_mac_ok(source)) {
        snprintf(field, field_len, "%s", "source"); return -1;
    }
    value = json_object_object_get(cfg, "app_ids");
    if (!json_object_is_type(value, json_type_array) ||
        json_object_array_length(value) < 1 ||
        json_object_array_length(value) > NC_AEGIS_APPFILTER_MAX_APP_IDS) {
        snprintf(field, field_len, "%s", "app_ids"); return -1;
    }
    ids = json_object_new_array();
    for (int i = 0; i < json_object_array_length(value); i++) {
        struct json_object *id = json_object_array_get_idx(value, i);
        int64_t app_id;
        int duplicate = 0;

        if (!json_object_is_type(id, json_type_int) ||
            (app_id = json_object_get_int64(id)) <= 0 || app_id > INT_MAX) {
            snprintf(field, field_len, "%s", "app_ids"); json_object_put(ids); return -1;
        }
        for (int j = 0; j < json_object_array_length(ids); j++)
            if (json_object_get_int64(json_object_array_get_idx(ids, j)) == app_id)
                duplicate = 1;
        if (!duplicate) json_object_array_add(ids, json_object_new_int64(app_id));
    }
    value = json_object_object_get(cfg, "schedule");
    if (nc_aegis_app_block_schedule_normalize(value, &schedule, &stored_schedule) != 0) {
        snprintf(field, field_len, "%s", "schedule"); json_object_put(ids); return -1;
    }
    value = json_object_object_get(cfg, "action");
    if (!json_object_is_type(value, json_type_string) ||
        strcmp(json_object_get_string(value), "block")) {
        snprintf(field, field_len, "%s", "action"); json_object_put(ids);
        json_object_put(schedule); free(stored_schedule); return -1;
    }
    value = json_object_object_get(cfg, "filter_quic");
    if (!json_object_is_type(value, json_type_boolean) || json_object_get_boolean(value)) {
        snprintf(field, field_len, "%s", "filter_quic"); json_object_put(ids);
        json_object_put(schedule); free(stored_schedule); return -1;
    }
    out = json_object_new_object();
    json_object_object_add(out, "id", json_object_new_string(nc_json_str_def(cfg, "id", "")));
    json_object_object_add(out, "name", json_object_new_string(nc_json_str_def(cfg, "name", "")));
    json_object_object_add(out, "enabled", json_object_new_boolean(nc_json_bool_def(cfg, "enabled", 0)));
    json_object_object_add(out, "source", json_object_new_string(source));
    json_object_object_add(out, "app_ids", ids);
    json_object_object_add(out, "schedule", schedule);
    json_object_object_add(out, "schedule_storage", json_object_new_string(stored_schedule));
    json_object_object_add(out, "action", json_object_new_string("block"));
    json_object_object_add(out, "filter_quic", json_object_new_boolean(nc_json_bool_def(cfg, "filter_quic", 0)));
    free(stored_schedule);
    *normalized = out;
    return 0;
}

static struct json_object *nc_aegis_app_block_schedule_json(const char *stored)
{
    struct json_object *schedule;

    if (!stored || !stored[0] || !strcmp(stored, "always"))
        return json_object_new_string("always");
    schedule = json_tokener_parse(stored);
    if (!schedule || !json_object_is_type(schedule, json_type_array)) {
        if (schedule) json_object_put(schedule);
        return json_object_new_string("invalid");
    }
    return schedule;
}

static struct json_object *nc_aegis_app_block_row(
    sqlite3_stmt *st, int appfilter_enabled,
    const struct nc_aegis_app_runtime *runtime, int *applied)
{
    struct json_object *item = json_object_new_object();
    struct json_object *app_ids;
    const struct nc_aegis_app_runtime_rule *installed;
    const char *source = (const char *)sqlite3_column_text(st, 3);
    const char *schedule = (const char *)sqlite3_column_text(st, 5);
    int configured_enabled = sqlite3_column_int(st, 2) != 0;
    int runtime_rule_id = sqlite3_column_int(st, 8);
    int expected_active = nc_aegis_app_schedule_active(schedule, configured_enabled);
    int expected_mac_count = source && nc_netctl_mac_ok(source) ? 1 : 0;
    int config_matches = 0, active = 0, rule_applied = 0;
    uint64_t app_hash_xor = 0, app_hash_sum = 0, mac_value = 0;
    int fingerprint_ok, expected_app_count = 0;

    nc_add_text(item, "id", st, 0);
    nc_add_text(item, "name", st, 1);
    json_object_object_add(item, "enabled", json_object_new_boolean(configured_enabled));
    nc_add_text(item, "source", st, 3);
    app_ids = nc_json_array_from_text((const char *)sqlite3_column_text(st, 4));
    fingerprint_ok = nc_aegis_app_expected_fingerprint(
        app_ids, source, &app_hash_xor, &app_hash_sum, &mac_value,
        &expected_app_count) == 0;
    json_object_object_add(item, "app_ids", app_ids);
    json_object_object_add(item, "schedule", nc_aegis_app_block_schedule_json(schedule));
    nc_add_text(item, "action", st, 6);
    json_object_object_add(item, "filter_quic", json_object_new_boolean(sqlite3_column_int(st, 7)));
    json_object_object_add(item, "runtime_rule_id", json_object_new_int(runtime_rule_id));
    json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(item, "configured", json_object_new_boolean(1));
    if (!runtime || !runtime->valid) {
        nc_aegis_app_block_runtime_fields(item, appfilter_enabled, 0, NULL);
        if (applied) *applied = 0;
        return item;
    }
    installed = nc_aegis_app_runtime_find(runtime, runtime_rule_id);
    if (installed) {
        config_matches = fingerprint_ok && installed->enabled &&
            installed->app_count == expected_app_count &&
            installed->mac_count == expected_mac_count &&
            installed->app_hash_xor == app_hash_xor &&
            installed->app_hash_sum == app_hash_sum &&
            installed->mac_value == mac_value;
        active = appfilter_enabled > 0 && installed->enabled;
        json_object_object_add(item, "runtime_app_count",
                               json_object_new_int(installed->app_count));
        json_object_object_add(item, "runtime_mac_count",
                               json_object_new_int(installed->mac_count));
        json_object_object_add(item, "hits",
                               json_object_new_int64(installed->hits));
        json_object_object_add(item, "last_hit_s",
                               json_object_new_int64(installed->last_hit_s));
    } else {
        json_object_object_add(item, "runtime_app_count", json_object_new_int(0));
        json_object_object_add(item, "runtime_mac_count", json_object_new_int(0));
        json_object_object_add(item, "hits", json_object_new_int64(0));
        json_object_object_add(item, "last_hit_s", json_object_new_int64(0));
    }
    if (expected_active >= 0) {
        int should_active = expected_active && appfilter_enabled > 0;
        rule_applied = should_active ? active && config_matches : !active;
    }
    json_object_object_add(item, "installed", json_object_new_boolean(installed != NULL));
    json_object_object_add(item, "active", json_object_new_boolean(active));
    json_object_object_add(item, "applied", json_object_new_boolean(rule_applied));
    json_object_object_add(item, "degraded", json_object_new_boolean(!rule_applied));
    json_object_object_add(item, "runtime_readback_supported", json_object_new_boolean(1));
    json_object_object_add(item, "runtime",
                           json_object_new_string(active ? "active" :
                           rule_applied ? "inactive" : "apply_pending"));
    json_object_object_add(item, "reason", json_object_new_string(
        expected_active < 0 ? "invalid_persisted_schedule" :
        !rule_applied && installed && !config_matches ? "kernel_rule_config_mismatch" :
        !rule_applied ? "kernel_rule_presence_mismatch" : ""));
    if (applied) *applied = rule_applied;
    return item;
}

static int nc_aegis_app_block_signal_rulesd(void)
{
    FILE *fp = fopen(NC_AEGIS_APPFILTER_REINIT_FILE, "w");
    int rc = -1;

    if (!fp) return -1;
    if (fputs("1\n", fp) >= 0 && fflush(fp) == 0 && fsync(fileno(fp)) == 0)
        rc = 0;
    if (fclose(fp) != 0) rc = -1;
    return rc;
}

struct json_object *jmx_aegis_app_blocks(struct json_object *cfg)
{
    static const char *sql =
        "SELECT r.id,r.name,r.enabled,r.source,d.app_ids,r.schedule,d.action,d.filter_quic,"
        "r.runtime_rule_id,r.created_at,r.updated_at FROM network_control_rule r "
        "JOIN network_control_app_rule d ON d.rule_id=r.id WHERE r.type='app' ORDER BY r.priority,r.id";
    struct json_object *data = json_object_new_object(), *items = json_object_new_array();
    sqlite3_stmt *st = NULL;
    const char *id = cfg ? nc_json_str_def(cfg, "id", "") : "";
    struct nc_aegis_app_runtime *runtime = NULL;
    int appfilter_enabled, total = 0, step_rc, applied_total = 0;

    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    nc_netctl_db_init();
    if (id[0] && (!nc_valid_name(id) || strlen(id) > 64)) {
        json_object_put(items); json_object_put(data);
        return nc_aegis_app_block_error("invalid_id", "id", nc_aegis_app_block_revision());
    }
    appfilter_enabled = nc_aegis_app_block_global_enabled();
    runtime = nc_aegis_app_runtime_alloc_load();
    if (nc_prepare(&st, id[0] ?
        "SELECT r.id,r.name,r.enabled,r.source,d.app_ids,r.schedule,d.action,d.filter_quic,r.runtime_rule_id,r.created_at,r.updated_at FROM network_control_rule r JOIN network_control_app_rule d ON d.rule_id=r.id WHERE r.type='app' AND r.id=?1" : sql) != 0) {
        json_object_put(items); json_object_put(data); free(runtime);
        return nc_aegis_app_block_error("database_read_failed", "", nc_aegis_app_block_revision());
    }
    if (id[0]) sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        int rule_applied = 0;
        json_object_array_add(items, nc_aegis_app_block_row(st, appfilter_enabled,
                                                            runtime,
                                                            &rule_applied));
        applied_total += rule_applied;
        total++;
    }
    sqlite3_finalize(st);
    if (step_rc != SQLITE_DONE) {
        json_object_put(items); json_object_put(data); free(runtime);
        return nc_aegis_app_block_error("database_read_failed", "", nc_aegis_app_block_revision());
    }
    if (id[0] && total == 0) {
        json_object_put(items); json_object_put(data); free(runtime);
        return nc_aegis_app_block_error("rule_not_found", "id", nc_aegis_app_block_revision());
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "items", items);
    if (id[0]) json_object_object_add(data, "item", json_object_get(json_object_array_get_idx(items, 0)));
    json_object_object_add(data, "total", json_object_new_int(total));
    json_object_object_add(data, "configured", json_object_new_boolean(total > 0));
    json_object_object_add(data, "revision", json_object_new_int64(nc_aegis_app_block_revision()));
    json_object_object_add(data, "appfilter_state_available", json_object_new_boolean(appfilter_enabled >= 0));
    json_object_object_add(data, "appfilter_enabled", json_object_new_boolean(appfilter_enabled > 0));
    if (runtime && runtime->valid) {
        int all_applied = applied_total == total;
        json_object_object_add(data, "runtime_readback_supported", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(all_applied));
        json_object_object_add(data, "degraded", json_object_new_boolean(!all_applied));
        json_object_object_add(data, "runtime",
                               json_object_new_string(total == 0 ? "inactive" :
                               all_applied ? "synchronized" : "apply_pending"));
        json_object_object_add(data, "reason",
                               json_object_new_string(all_applied ? "" :
                                                      "one_or_more_rules_not_applied"));
        json_object_object_add(data, "runtime_rule_count",
                               json_object_new_int(runtime->count));
        json_object_object_add(data, "applied_rule_count",
                               json_object_new_int(applied_total));
    } else {
        nc_aegis_app_block_runtime_fields(data, appfilter_enabled, 0, NULL);
        if (runtime && runtime->available)
            json_object_object_add(data, "reason",
                                   json_object_new_string("kernel_runtime_readback_invalid"));
    }
    free(runtime);
    json_object_object_add(data, "capabilities", nc_aegis_app_block_capabilities(appfilter_enabled));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_aegis_app_block_validate(struct json_object *cfg)
{
    struct json_object *normalized = NULL, *data;
    char field[32] = "";
    sqlite3_int64 revision;
    int appfilter_enabled, rule_type;

    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, json_object_new_object());
    nc_netctl_db_init();
    revision = nc_aegis_app_block_revision();
    if (nc_aegis_app_block_normalize(cfg, &normalized, field, sizeof(field)) != 0)
        return nc_aegis_app_block_error("validation_failed", field, revision);
    rule_type = nc_aegis_app_block_rule_type(nc_json_str_def(normalized, "id", ""));
    if (rule_type < 0) {
        json_object_put(normalized);
        return nc_aegis_app_block_error("database_read_failed", "", revision);
    }
    if (rule_type == 2) {
        json_object_put(normalized);
        return nc_aegis_app_block_error("rule_type_conflict", "id", revision);
    }
    if (rule_type == 0) {
        int count = nc_aegis_app_block_rule_count();
        if (count < 0) {
            json_object_put(normalized);
            return nc_aegis_app_block_error("database_read_failed", "", revision);
        }
        if (count >= NC_AEGIS_APPFILTER_MAX_RULES) {
            json_object_put(normalized);
            return nc_aegis_app_block_error("rule_limit_reached", "id", revision);
        }
    }
    appfilter_enabled = nc_aegis_app_block_global_enabled();
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "valid", json_object_new_boolean(1));
    json_object_object_add(data, "preview", json_object_new_boolean(1));
    json_object_object_add(data, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(data, "configured", json_object_new_boolean(rule_type == 1));
    json_object_object_add(data, "revision", json_object_new_int64(revision));
    json_object_object_add(data, "rule", normalized);
    json_object_object_del(normalized, "schedule_storage");
    nc_aegis_app_block_runtime_fields(data, appfilter_enabled, 0, NULL);
    json_object_object_add(data, "capabilities", nc_aegis_app_block_capabilities(appfilter_enabled));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_aegis_app_block_upsert(struct json_object *cfg)
{
    struct json_object *normalized = NULL, *data = NULL;
    sqlite3_stmt *st = NULL;
    char field[32] = "", conflict_type[32] = "";
    const char *id, *schedule_storage;
    char *app_ids = NULL;
    sqlite3_int64 expected_revision, current_revision, now;
    int rc = -1, appfilter_enabled, signal_ok = 0, rule_exists = 0;
    int runtime_rule_id = 0;

    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, json_object_new_object());
    nc_netctl_db_init();
    current_revision = nc_aegis_app_block_revision();
    if (nc_aegis_app_block_normalize(cfg, &normalized, field, sizeof(field)) != 0)
        return nc_aegis_app_block_error("validation_failed", field, current_revision);
    if (nc_json_bool_def(cfg, "preview", 0)) {
        json_object_put(normalized);
        return jmx_aegis_app_block_validate(cfg);
    }
    if (!nc_json_bool_def(cfg, "confirm", 0)) {
        json_object_put(normalized);
        return nc_aegis_app_block_error("confirmation_required", "confirm", current_revision);
    }
    if (!json_object_object_get_ex(cfg, "revision", &data) ||
        !json_object_is_type(data, json_type_int) ||
        (expected_revision = json_object_get_int64(data)) < 1) {
        json_object_put(normalized);
        return nc_aegis_app_block_error("revision_required", "revision", current_revision);
    }
    id = nc_json_str_def(normalized, "id", "");
    schedule_storage = nc_json_str_def(normalized, "schedule_storage", "always");
    app_ids = nc_json_array_to_string(json_object_object_get(normalized, "app_ids"), "[]");
    now = nc_now_s();
    if (!app_ids || nc_exec("BEGIN IMMEDIATE") != 0) goto done;
    current_revision = nc_aegis_app_block_revision();
    if (expected_revision != current_revision) goto conflict;
    if (nc_prepare(&st, "SELECT type,runtime_rule_id FROM network_control_rule WHERE id=?1") != 0) goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(conflict_type, sizeof(conflict_type), "%s", sqlite3_column_text(st, 0));
        if (strcmp(conflict_type, "app")) { sqlite3_finalize(st); st = NULL; goto type_conflict; }
        rule_exists = 1;
        runtime_rule_id = sqlite3_column_int(st, 1);
    }
    sqlite3_finalize(st); st = NULL;
    if (!rule_exists) {
        int count = nc_aegis_app_block_rule_count();
        if (count < 0) goto rollback;
        if (count >= NC_AEGIS_APPFILTER_MAX_RULES) goto rule_limit;
    }
    if (nc_aegis_app_block_runtime_id(id, runtime_rule_id, &runtime_rule_id) != 0)
        goto runtime_id_unavailable;
    if (nc_prepare(&st, "UPDATE network_control_global SET revision=revision+1,apply_state='draft',updated_at=?1 WHERE id=1 AND revision=?2") != 0) goto rollback;
    sqlite3_bind_int64(st, 1, now); sqlite3_bind_int64(st, 2, expected_revision);
    if (nc_step_done(st) != 0 || nc_sqlite_changes() != 1) { sqlite3_finalize(st); st = NULL; goto conflict; }
    sqlite3_finalize(st); st = NULL;
    if (nc_prepare(&st,
        "INSERT INTO network_control_rule(id,type,enabled,name,priority,source,schedule,remark,hits,last_hit,created_at,updated_at,runtime_rule_id) "
        "VALUES(?1,'app',?2,?3,1000,?4,?5,'',0,0,?6,?6,?7) "
        "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,name=excluded.name,source=excluded.source,schedule=excluded.schedule,updated_at=excluded.updated_at,runtime_rule_id=excluded.runtime_rule_id") != 0) goto rollback;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,2,nc_json_bool_def(normalized,"enabled",0));
    sqlite3_bind_text(st,3,nc_json_str_def(normalized,"name",""),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,4,nc_json_str_def(normalized,"source","any"),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,5,schedule_storage,-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,6,now);
    sqlite3_bind_int(st,7,runtime_rule_id);
    if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto rollback; }
    sqlite3_finalize(st); st = NULL;
    if (nc_prepare(&st,
        "INSERT INTO network_control_app_rule(rule_id,app_ids,apps,destination,action,filter_quic) VALUES(?1,?2,'[]','any','block',?3) "
        "ON CONFLICT(rule_id) DO UPDATE SET app_ids=excluded.app_ids,action='block',filter_quic=excluded.filter_quic") != 0) goto rollback;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,app_ids,-1,SQLITE_TRANSIENT);
    sqlite3_bind_int(st,3,nc_json_bool_def(normalized,"filter_quic",0));
    if (nc_step_done(st) != 0) { sqlite3_finalize(st); st = NULL; goto rollback; }
    sqlite3_finalize(st); st = NULL;
    if (nc_exec("UPDATE network_control_status SET apply_state='draft',warnings='Aegis app block configured; rulesd runtime readback pending',updated_at=strftime('%s','now') WHERE id=1") != 0)
        goto rollback;
    if (nc_exec("COMMIT") != 0) { nc_exec("ROLLBACK"); goto done; }
    rc = 0;
    signal_ok = nc_aegis_app_block_signal_rulesd() == 0;
    goto done;

conflict:
    if (st) { sqlite3_finalize(st); st = NULL; }
    nc_exec("ROLLBACK");
    free(app_ids); json_object_put(normalized);
    return nc_aegis_app_block_error("revision_conflict", "revision", current_revision);
type_conflict:
    nc_exec("ROLLBACK");
    free(app_ids); json_object_put(normalized);
    return nc_aegis_app_block_error("rule_type_conflict", "id", current_revision);
rule_limit:
    nc_exec("ROLLBACK");
    free(app_ids); json_object_put(normalized);
    return nc_aegis_app_block_error("rule_limit_reached", "id", current_revision);
runtime_id_unavailable:
    nc_exec("ROLLBACK");
    free(app_ids); json_object_put(normalized);
    return nc_aegis_app_block_error("runtime_rule_id_unavailable", "id", current_revision);
rollback:
    if (st) sqlite3_finalize(st);
    st = NULL; nc_exec("ROLLBACK");
done:
    if (st) sqlite3_finalize(st);
    free(app_ids);
    if (rc != 0) { json_object_put(normalized); return nc_aegis_app_block_error("database_write_failed", "", nc_aegis_app_block_revision()); }
    current_revision = nc_aegis_app_block_revision();
    appfilter_enabled = nc_aegis_app_block_global_enabled();
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "configured", json_object_new_boolean(1));
    json_object_object_add(data, "revision", json_object_new_int64(current_revision));
    json_object_object_del(normalized, "schedule_storage");
    json_object_object_add(data, "rule", normalized);
    nc_aegis_app_block_runtime_fields(data, appfilter_enabled, signal_ok,
                                      signal_ok ? NULL : "rulesd_reinit_signal_failed");
    json_object_object_add(data, "capabilities", nc_aegis_app_block_capabilities(appfilter_enabled));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_aegis_app_block_delete(struct json_object *cfg)
{
    struct json_object *value = NULL, *data;
    sqlite3_stmt *st = NULL;
    const char *id;
    sqlite3_int64 expected_revision, current_revision;
    int appfilter_enabled, signal_ok;

    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, json_object_new_object());
    nc_netctl_db_init();
    current_revision = nc_aegis_app_block_revision();
    if (!cfg || !json_object_is_type(cfg, json_type_object))
        return nc_aegis_app_block_error("validation_failed", "request", current_revision);
    json_object_object_foreach(cfg, key, ignored) {
        (void)ignored;
        if (strcmp(key, "id") && strcmp(key, "preview") && strcmp(key, "confirm") &&
            strcmp(key, "revision"))
            return nc_aegis_app_block_error("validation_failed", key, current_revision);
    }
    if ((json_object_object_get_ex(cfg, "preview", &value) &&
         !json_object_is_type(value, json_type_boolean)) ||
        (json_object_object_get_ex(cfg, "confirm", &value) &&
         !json_object_is_type(value, json_type_boolean)) ||
        (json_object_object_get_ex(cfg, "revision", &value) &&
         !json_object_is_type(value, json_type_int)))
        return nc_aegis_app_block_error("validation_failed", "request", current_revision);
    if (!json_object_object_get_ex(cfg, "id", &value) ||
        !json_object_is_type(value, json_type_string) || strlen(json_object_get_string(value)) > 64 ||
        !nc_valid_name(json_object_get_string(value)))
        return nc_aegis_app_block_error("validation_failed", "id", current_revision);
    id = json_object_get_string(value);
    if (nc_json_bool_def(cfg, "preview", 0)) {
        int rule_type = nc_aegis_app_block_rule_type(id);
        if (rule_type == 0) return nc_aegis_app_block_error("rule_not_found", "id", current_revision);
        if (rule_type < 0) return nc_aegis_app_block_error("database_read_failed", "", current_revision);
        if (rule_type == 2) return nc_aegis_app_block_error("rule_type_conflict", "id", current_revision);
        appfilter_enabled = nc_aegis_app_block_global_enabled();
        data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "preview", json_object_new_boolean(1));
        json_object_object_add(data, "confirm_required", json_object_new_boolean(1));
        json_object_object_add(data, "configured", json_object_new_boolean(1));
        json_object_object_add(data, "id", json_object_new_string(id));
        json_object_object_add(data, "revision", json_object_new_int64(current_revision));
        nc_aegis_app_block_runtime_fields(data, appfilter_enabled, 0, NULL);
        json_object_object_add(data, "capabilities", nc_aegis_app_block_capabilities(appfilter_enabled));
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
    if (!nc_json_bool_def(cfg, "confirm", 0))
        return nc_aegis_app_block_error("confirmation_required", "confirm", current_revision);
    if (!json_object_object_get_ex(cfg, "revision", &value) ||
        !json_object_is_type(value, json_type_int) ||
        (expected_revision = json_object_get_int64(value)) < 1)
        return nc_aegis_app_block_error("revision_required", "revision", current_revision);
    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return nc_aegis_app_block_error("database_write_failed", "", current_revision);
    current_revision = nc_aegis_app_block_revision();
    if (current_revision != expected_revision) goto conflict;
    if (nc_prepare(&st, "SELECT type FROM network_control_rule WHERE id=?1") != 0) goto rollback;
