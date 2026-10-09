    nc_macacl_rollback_disarm();
    if (nc_macacl_reapply() != 0) {
        return nc_macacl_transition_error(
            "mac allowlist ruleset could not be applied; the previous state was restored",
            &previous, admin_added > 0 ? norm : NULL);
    }
    if (nc_macacl_runtime_commit(state.config_revision,
                                 "runtime_applied_and_readback_verified") != 0)
        return nc_macacl_transition_error(
            "runtime applied but revision readback could not be committed; the previous state was restored",
            &previous, admin_added > 0 ? norm : NULL);
    if (nc_macacl_state_load(&state) != 0)
        return nc_macacl_error("state_unavailable",
                               "mac allowlist runtime applied but readback failed", NULL);
    if (state.enabled)
        nc_macacl_rollback_arm(state.confirm_deadline);
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "confirm_required",
                           json_object_new_boolean(state.enabled));
    if (state.enabled)
        json_object_object_add(data, "confirm_method",
                               json_object_new_string("network_control_mac_allowlist_confirm"));
    nc_macacl_add_state(data, &state, elements);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* network_control_mac_allowlist_confirm - stops the pending auto-rollback. */
struct json_object *jmx_network_control_mac_allowlist_confirm(void)
{
    struct nc_macacl_state state;
    struct json_object *data;

    if (jmx_netconfig_db_init() != 0)
        return nc_macacl_error("database_unavailable",
                               "config database is not available", NULL);
    nc_netctl_db_init();
    if (nc_macacl_state_load(&state) != 0)
        return nc_macacl_error("state_unavailable",
                               "mac allowlist state row is missing", NULL);
    if (!state.enabled)
        return nc_macacl_error("not_pending",
                               "mac allowlist mode is not enabled", &state);
    if (state.confirmed) {
        data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "already_confirmed", json_object_new_boolean(1));
        nc_macacl_add_state(data, &state, nc_macacl_reported_elements());
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
    /*
     * A confirmation that arrives after the deadline is refused rather than
     * honoured. By then the rollback has run or is about to, and accepting it
     * would re-arm deny-by-default from a stale request.
     */
    if (state.confirm_deadline <= nc_now_s())
        return nc_macacl_error("confirm_window_expired",
                               "the confirmation window has passed; the change was or is "
                               "being rolled back", &state);
    state.confirmed = 1;
    state.confirm_deadline = 0;
    snprintf(state.last_reason, sizeof(state.last_reason), "confirmed");
    if (nc_macacl_state_store(&state) != 0)
        return nc_macacl_error("state_write_failed",
                               "could not persist confirmation", &state);
    nc_macacl_rollback_disarm();
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "confirmed", json_object_new_boolean(1));
    nc_macacl_add_state(data, &state, nc_macacl_reported_elements());
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_network_control_mac_allowlist_get(void)
{
    struct json_object *data;
    struct nc_macacl_state state;

    if (jmx_netconfig_db_init() != 0)
        return nc_macacl_error("database_unavailable",
                               "config database is not available", NULL);
    nc_netctl_db_init();
    if (nc_macacl_state_load(&state) != 0)
        return nc_macacl_error("state_unavailable",
                               "mac allowlist state row is missing", NULL);
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "members", nc_macacl_members_array());
    nc_macacl_add_state(data, &state, nc_macacl_reported_elements());
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/*
 * Called once at startup. A device that lost power, or a jmxd that was killed,
 * between enable and confirm would otherwise come back with the row saying
 * "enabled, unconfirmed" and no timer left to undo it.
 *
 * The kernel ruleset does not survive a reboot, so the usual case is a state row
 * that outlived the rules it described; clearing it keeps the row honest. When
 * jmxd was merely restarted the table can still be loaded, so the rollback path
 * runs for real rather than only rewriting the row.
 */
void jmx_network_control_mac_allowlist_boot_check(void)
{
    struct nc_macacl_state state;

    if (jmx_netconfig_db_init() != 0)
        return;
    nc_netctl_db_init();
    if (nc_macacl_state_load(&state) != 0)
        return;
    if (!state.enabled) {
        if (!state.runtime_applied ||
            state.runtime_revision != state.config_revision)
            nc_macacl_rollback_arm(nc_now_s() + 1);
        return;
    }
    state.runtime_applied = 0;
    snprintf(state.runtime_reason, sizeof(state.runtime_reason),
             "boot_runtime_reapply_pending");
    if (nc_macacl_state_store(&state) != 0)
        return;
    nc_macacl_rollback_arm(nc_now_s() + 1);
}

int jmx_network_control_rules_bulk_delete(struct json_object *cfg)
{
    if(!cfg || jmx_netconfig_db_init()!=0) return -1;
    nc_netctl_db_init();
    struct json_object *ids = NULL;
    if(!json_object_object_get_ex(cfg, "ids", &ids) || !json_object_is_type(ids, json_type_array))
        return -1;
    int n = json_object_array_length(ids);
    if(n == 0) return 0;
    int deleted = 0;
    if (nc_txn_begin() != 0) return -1;
    for(int i = 0; i < n; i++) {
        const char *id = json_object_get_string(json_object_array_get_idx(ids, i));
        if(!id || !nc_valid_name(id)) continue;
        sqlite3_stmt *st = NULL;
        static const char *detail_tables[] = {
            "network_control_connection_limit", "network_control_mac_rule",
            "network_control_url_access_rule", "network_control_url_rewrite_rule",
            "network_control_app_rule", "network_control_terminal_limit", NULL
        };
        for (int t = 0; detail_tables[t]; t++) {
            char sql[160];
            snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE rule_id=?", detail_tables[t]);
            if(nc_prepare(&st, sql) == 0) {
                sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
                sqlite3_step(st);
                sqlite3_finalize(st);
                st = NULL;
            }
        }
        if(nc_prepare(&st, "DELETE FROM network_control_rule WHERE id=?") == 0) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            deleted += sqlite3_changes(g_netconfig_db);
            sqlite3_finalize(st);
        }
    }
    if(deleted > 0) {
        nc_exec("UPDATE network_control_global SET revision=revision+1,apply_state='draft',updated_at=strftime('%s','now') WHERE id=1");
    }
    nc_exec(deleted > 0 ? "COMMIT" : "ROLLBACK");
    return deleted;
}

struct json_object *jmx_network_control_status(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);nc_netctl_db_init();struct json_object*d=json_object_new_object(),*runtime=json_object_new_object(),*rules=json_object_new_array();json_object_object_add(d,"ts",json_object_new_int64(nc_now_s()));sqlite3_stmt*st=NULL;if(nc_prepare(&st,"SELECT apply_state,last_apply_at,warnings,updated_at FROM network_control_status WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){nc_add_text(d,"apply_state",st,0);json_object_object_add(d,"last_apply_at",json_object_new_int64(sqlite3_column_int64(st,1)));nc_add_text(d,"warnings",st,2);json_object_object_add(d,"updated_at",json_object_new_int64(sqlite3_column_int64(st,3)));sqlite3_finalize(st);}json_object_object_add(runtime,"jmx_mac_filter",json_object_new_string("config_db"));json_object_object_add(runtime,"jmx_app_filter",json_object_new_string("config_db"));{
        struct stat nft_st;
        if(stat("/etc/dreamingwrt/network_control.nft", &nft_st)==0 && nft_st.st_size > 0)
            json_object_object_add(runtime,"nft",json_object_new_string("ruleset_generated"));
        else
            json_object_object_add(runtime,"nft",json_object_new_string("not_generated"));
    }{
        int tc_runtime_count = 0;
        if(nc_prepare(&st,"SELECT COUNT(*) FROM network_control_tc_runtime")==0 && sqlite3_step(st)==SQLITE_ROW)
            tc_runtime_count=sqlite3_column_int(st,0);
        if(st){sqlite3_finalize(st);st=NULL;}
        json_object_object_add(runtime,"tc",json_object_new_string(tc_runtime_count>0?"structured_runtime_committed":"no_rules"));
        json_object_object_add(runtime,"tc_rule_count",json_object_new_int(tc_runtime_count));
        json_object_object_add(runtime,"tc_source",json_object_new_string("config_db"));
    }json_object_object_add(d,"runtime",runtime);if(nc_prepare(&st,"SELECT id,type FROM network_control_rule ORDER BY type,priority,id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"type",st,1);json_object_object_add(o,"installed",json_object_new_boolean(0));json_object_object_add(o,"backend",json_object_new_string("pending_runtime"));json_object_array_add(rules,o);}sqlite3_finalize(st);}json_object_object_add(d,"rules",rules);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}
struct json_object *jmx_network_control_rule_test(struct json_object *cfg)
{
    struct json_object*d=json_object_new_object();const char*rule=nc_json_str_def(cfg,"rule_id","");json_object_object_add(d,"matched",json_object_new_boolean(0));json_object_object_add(d,"rule_id",json_object_new_string(rule));json_object_object_add(d,"reason",json_object_new_string("phase1: rule_test parser/runtime matcher pending"));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

/* ── Log Center ──────────────────────────────────────────────────────── */
static void nc_log_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS log_event (id TEXT PRIMARY KEY,type TEXT NOT NULL,ts INTEGER NOT NULL,level TEXT NOT NULL DEFAULT 'info',category TEXT NOT NULL DEFAULT '',module TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT '',iface TEXT NOT NULL DEFAULT '',username TEXT NOT NULL DEFAULT '',auth_ip TEXT NOT NULL DEFAULT '',auth_type TEXT NOT NULL DEFAULT '',identity TEXT NOT NULL DEFAULT '',mac TEXT NOT NULL DEFAULT '',ip TEXT NOT NULL DEFAULT '',title TEXT NOT NULL DEFAULT '',event TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT '',target TEXT NOT NULL DEFAULT '',channel TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_log_event_type_ts ON log_event(type, ts DESC)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_log_event_level_ts ON log_event(level, ts DESC)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_log_event_search ON log_event(type, category, module, source)");
    nc_exec("CREATE TABLE IF NOT EXISTS log_syslog_config (id INTEGER PRIMARY KEY CHECK (id = 1),enabled INTEGER NOT NULL DEFAULT 0,server TEXT NOT NULL DEFAULT '',port INTEGER NOT NULL DEFAULT 514,protocol TEXT NOT NULL DEFAULT 'udp',facility TEXT NOT NULL DEFAULT 'local7',min_level TEXT NOT NULL DEFAULT 'notice',categories TEXT NOT NULL DEFAULT 'general,audit,security,wan,client,vpn',updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS log_settings (id INTEGER PRIMARY KEY CHECK (id = 1),retention_days INTEGER NOT NULL DEFAULT 30,kernel_retention_days INTEGER NOT NULL DEFAULT 7,max_size_mb INTEGER NOT NULL DEFAULT 128,auto_cleanup INTEGER NOT NULL DEFAULT 1,archive_compress INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS warning_rule (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,name TEXT NOT NULL,type TEXT NOT NULL,target TEXT NOT NULL DEFAULT '',trigger_expr TEXT NOT NULL,channels TEXT NOT NULL DEFAULT 'console',cooldown_sec INTEGER NOT NULL DEFAULT 300,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("INSERT OR IGNORE INTO log_syslog_config(id) VALUES(1)");
    nc_exec("INSERT OR IGNORE INTO log_settings(id) VALUES(1)");
}
static int nc_log_type_ok(const char*s){return s&&(!strcmp(s,"user")||!strcmp(s,"function")||!strcmp(s,"system")||!strcmp(s,"kernel")||!strcmp(s,"message")||!strcmp(s,"warning")||!strcmp(s,"syslog"));}
static int nc_log_level_ok(const char*s){return s&&(!strcmp(s,"info")||!strcmp(s,"notice")||!strcmp(s,"warning")||!strcmp(s,"error"));}
static int nc_log_format_ok(const char*s){return s&&(!strcmp(s,"csv")||!strcmp(s,"json"));}
static int nc_log_safe_token(const char*s){if(!s)return 0;for(const char*p=s;*p;p++)if(!(isalnum((unsigned char)*p)||*p=='.'||*p=='-'||*p=='_'||*p==':' ))return 0;return 1;}
#define NC_LOG_RUNTIME_DIR "/run/dreamingwrt"
#define NC_LOG_EXPORT_DIR NC_LOG_RUNTIME_DIR "/log_exports"

static int nc_log_export_open(char *id, size_t id_len, const char *fmt,
                              int *dirfd_out)
{
    struct stat st;
    struct timespec now;
    int dirfd = -1, fd = -1, attempt;

    if (!id || id_len == 0 || !fmt || !dirfd_out)
        return -1;
    *dirfd_out = -1;
    if (mkdir(NC_LOG_RUNTIME_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open(NC_LOG_RUNTIME_DIR,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto fail;
    if (mkdirat(dirfd, "log_exports", 0700) != 0 && errno != EEXIST)
        goto fail;
    close(dirfd);
    dirfd = open(NC_LOG_EXPORT_DIR,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto fail;
    clock_gettime(CLOCK_REALTIME, &now);
    for (attempt = 0; attempt < 32; attempt++) {
        if (snprintf(id, id_len, "logs-legacy-%lld-%09ld-%ld-%08lx-%d.%s",
                     (long long)now.tv_sec, now.tv_nsec, (long)getpid(),
                     (unsigned long)random(), attempt, fmt) >= (int)id_len)
            goto fail;
        fd = openat(dirfd, id,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0) {
            *dirfd_out = dirfd;
            return fd;
        }
        if (errno != EEXIST)
            break;
    }
fail:
    if (dirfd >= 0)
        close(dirfd);
    return -1;
}

static int nc_log_csv_field(FILE *fp, const char *s)
{
    const char *p;
    int quote = 0;
    int neutralize;

    if (!fp)
        return -1;
    if (!s)
        s = "";
    neutralize = s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@';
    for (p = s; *p; p++) {
        if (*p == '"' || *p == ',' || *p == '\r' || *p == '\n') {
            quote = 1;
            break;
        }
    }
    if (neutralize)
        quote = 1;
    if (!quote)
        return fputs(s, fp) == EOF ? -1 : 0;
    if (fputc('"', fp) == EOF || (neutralize && fputc('\'', fp) == EOF))
        return -1;
    for (p = s; *p; p++) {
        if (*p == '"' && fputc('"', fp) == EOF)
            return -1;
        if (fputc(*p, fp) == EOF)
            return -1;
    }
    return fputc('"', fp) == EOF ? -1 : 0;
}

static int nc_log_csv_json_field(FILE *fp, struct json_object *row,
                                 const char *key)
{
    return nc_log_csv_field(fp, nc_json_str_def(row, key, ""));
}
static sqlite3_int64 nc_log_range_start(const char*r,sqlite3_int64 now){if(!r||!*r)return 0;if(!strcmp(r,"1d"))return now-86400;if(!strcmp(r,"3d"))return now-3*86400;if(!strcmp(r,"1w"))return now-7*86400;if(!strcmp(r,"2w"))return now-14*86400;if(!strcmp(r,"1m"))return now-30*86400;return 0;}
static unsigned nc_log_hash(const char*s){unsigned h=2166136261u;if(!s)return h;while(*s){h^=(unsigned char)*s++;h*=16777619u;}return h;}
static void nc_log_event_json(struct json_object*a,sqlite3_stmt*st)
{struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"type",st,1);json_object_object_add(o,"ts",json_object_new_int64(sqlite3_column_int64(st,2)));nc_add_text(o,"level",st,3);nc_add_text(o,"category",st,4);nc_add_text(o,"module",st,5);nc_add_text(o,"source",st,6);nc_add_text(o,"iface",st,7);nc_add_text(o,"username",st,8);nc_add_text(o,"auth_ip",st,9);nc_add_text(o,"auth_type",st,10);nc_add_text(o,"identity",st,11);nc_add_text(o,"mac",st,12);nc_add_text(o,"ip",st,13);nc_add_text(o,"title",st,14);nc_add_text(o,"event",st,15);nc_add_text(o,"detail",st,16);nc_add_text(o,"state",st,17);nc_add_text(o,"target",st,18);nc_add_text(o,"channel",st,19);json_object_array_add(a,o);} 
static void nc_log_insert_simple(const char*type,const char*level,const char*source,const char*event,const char*detail)
{if(!nc_log_type_ok(type)||!nc_log_level_ok(level)||!event)return;char id[96];sqlite3_int64 now=(sqlite3_int64)nc_now_s();snprintf(id,sizeof(id),"%s-%lld-%08x",type,(long long)now,(unsigned)(nc_log_hash(event)^nc_log_hash(detail?detail:"")));sqlite3_stmt*st=NULL;if(nc_prepare(&st,"INSERT OR IGNORE INTO log_event(id,type,ts,level,source,event,detail,created_at) VALUES(?,?,?,?,?,?,?,?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,type,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,now);sqlite3_bind_text(st,4,level,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,source?source:"",-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,event,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,detail?detail:"",-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,8,now);sqlite3_step(st);sqlite3_finalize(st);}}

static void nc_log_import_snapshot(void)
{
    FILE*fp=popen("logread 2>/dev/null | tail -80","r"); char line[1024];
    if(fp){while(fgets(line,sizeof(line),fp)){line[strcspn(line,"\r\n")]=0;if(line[0])nc_log_insert_simple("system",strstr(line,"warn")||strstr(line,"WARN")?"warning":(strstr(line,"err")||strstr(line,"ERR")?"error":"info"),"logread",line,"");}pclose(fp);} 
    fp=popen("logread -k 2>/dev/null | tail -80","r");
    if(fp){while(fgets(line,sizeof(line),fp)){line[strcspn(line,"\r\n")]=0;if(line[0])nc_log_insert_simple("kernel",strstr(line,"warn")||strstr(line,"WARN")?"warning":(strstr(line,"err")||strstr(line,"ERR")?"error":"notice"),"kernel",line,"");}pclose(fp);} 
}

static struct json_object *nc_log_query_array(const char*type,const char*range,const char*level,const char*q,int limit)
{
    struct json_object*a=json_object_new_array(); if(limit<=0||limit>1000)limit=100; sqlite3_int64 start=nc_log_range_start(range,(sqlite3_int64)nc_now_s());
    char sql[512]; snprintf(sql,sizeof(sql),"SELECT id,type,ts,level,category,module,source,iface,username,auth_ip,auth_type,identity,mac,ip,title,event,detail,state,target,channel FROM log_event WHERE 1=1 %s %s %s %s ORDER BY ts DESC LIMIT ?", type&&*type?"AND type=?":"", level&&*level?"AND level=?":"", start>0?"AND ts>=?":"", q&&*q?"AND (event LIKE ? OR detail LIKE ? OR title LIKE ? OR source LIKE ? OR username LIKE ? OR ip LIKE ? OR mac LIKE ?)":"");
    sqlite3_stmt*st=NULL; if(nc_prepare(&st,sql)==0){int b=1;if(type&&*type)sqlite3_bind_text(st,b++,type,-1,SQLITE_TRANSIENT);if(level&&*level)sqlite3_bind_text(st,b++,level,-1,SQLITE_TRANSIENT);if(start>0)sqlite3_bind_int64(st,b++,start);char pat[256];if(q&&*q){snprintf(pat,sizeof(pat),"%%%s%%",q);for(int i=0;i<7;i++)sqlite3_bind_text(st,b++,pat,-1,SQLITE_TRANSIENT);}sqlite3_bind_int(st,b++,limit);while(sqlite3_step(st)==SQLITE_ROW)nc_log_event_json(a,st);sqlite3_finalize(st);} return a;
}

struct json_object *jmx_log_center_get(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_db_init(); nc_log_import_snapshot(); struct json_object*d=json_object_new_object(),*summary=json_object_new_object(),*settings=json_object_new_object(),*syslog=json_object_new_object(); sqlite3_stmt*st=NULL; sqlite3_int64 now=(sqlite3_int64)nc_now_s();
    if(nc_prepare(&st,"SELECT COUNT(*),SUM(CASE WHEN ts>=? THEN 1 ELSE 0 END),SUM(CASE WHEN state='unread' THEN 1 ELSE 0 END),SUM(CASE WHEN level IN ('warning','error') THEN 1 ELSE 0 END) FROM log_event")==0){sqlite3_bind_int64(st,1,now-86400);if(sqlite3_step(st)==SQLITE_ROW){json_object_object_add(summary,"total",json_object_new_int64(sqlite3_column_int64(st,0)));json_object_object_add(summary,"today",json_object_new_int64(sqlite3_column_int64(st,1)));json_object_object_add(summary,"unread",json_object_new_int64(sqlite3_column_int64(st,2)));json_object_object_add(summary,"warnings",json_object_new_int64(sqlite3_column_int64(st,3)));}sqlite3_finalize(st);} 
    if(nc_prepare(&st,"SELECT retention_days,kernel_retention_days,max_size_mb,auto_cleanup,archive_compress FROM log_settings WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){json_object_object_add(settings,"retention_days",json_object_new_int(sqlite3_column_int(st,0)));json_object_object_add(settings,"kernel_retention_days",json_object_new_int(sqlite3_column_int(st,1)));json_object_object_add(settings,"max_size_mb",json_object_new_int(sqlite3_column_int(st,2)));json_object_object_add(settings,"auto_cleanup",json_object_new_boolean(sqlite3_column_int(st,3)));json_object_object_add(settings,"archive_compress",json_object_new_boolean(sqlite3_column_int(st,4)));json_object_object_add(summary,"retention_days",json_object_new_int(sqlite3_column_int(st,0)));sqlite3_finalize(st);} 
    if(nc_prepare(&st,"SELECT enabled,server,port,protocol,facility,min_level,categories FROM log_syslog_config WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){json_object_object_add(syslog,"enabled",json_object_new_boolean(sqlite3_column_int(st,0)));json_object_object_add(summary,"syslog_forward",json_object_new_boolean(sqlite3_column_int(st,0)));nc_add_text(syslog,"server",st,1);json_object_object_add(syslog,"port",json_object_new_int(sqlite3_column_int(st,2)));nc_add_text(syslog,"protocol",st,3);nc_add_text(syslog,"facility",st,4);nc_add_text(syslog,"min_level",st,5);json_object_object_add(syslog,"categories",nc_json_array_from_text((const char*)sqlite3_column_text(st,6)));sqlite3_finalize(st);} 
    json_object_object_add(d,"summary",summary);json_object_object_add(d,"settings",settings);json_object_object_add(d,"user_logs",nc_log_query_array("user","1d",NULL,NULL,100));json_object_object_add(d,"function_logs",nc_log_query_array("function","1d",NULL,NULL,100));json_object_object_add(d,"system_logs",nc_log_query_array("system","1d",NULL,NULL,100));json_object_object_add(d,"kernel_logs",nc_log_query_array("kernel","1d",NULL,NULL,100));json_object_object_add(d,"notifications",nc_log_query_array("message","1w",NULL,NULL,100));json_object_object_add(d,"warnings",nc_log_query_array("warning","1w",NULL,NULL,100));json_object_object_add(syslog,"events",nc_log_query_array("syslog","1d",NULL,NULL,100));json_object_object_add(d,"syslog",syslog);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_log_center_query(struct json_object *cfg)
{if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);nc_log_db_init();const char*type=nc_json_str_def(cfg,"type","");const char*level=nc_json_str_def(cfg,"level","");if(type[0]&&!nc_log_type_ok(type))return jmx_gen_api_response_data(API_CODE_ERROR,NULL);if(level[0]&&!nc_log_level_ok(level))return jmx_gen_api_response_data(API_CODE_ERROR,NULL);struct json_object*d=json_object_new_object();json_object_object_add(d,"records",nc_log_query_array(type,nc_json_str_def(cfg,"range","1d"),level,nc_json_str_def(cfg,"query",""),nc_json_int_def(cfg,"limit",100)));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_log_center_export(struct json_object *cfg)
{
    static const char *fields[] = {
        "id", "type", "level", "source", "module", "iface", "username",
        "ip", "mac", "title", "event", "detail", "state", "target", NULL
    };
    struct json_object *records = NULL, *data = NULL;
    const char *fmt;
    char id[128], download_url[192];
    FILE *fp = NULL;
    int dirfd = -1, fd = -1, count, write_failed = 0;

    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    nc_log_db_init();
    fmt = nc_json_str_def(cfg, "format", "json");
    if (!nc_log_format_ok(fmt))
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    records = nc_log_query_array(nc_json_str_def(cfg, "type", ""),
                                 nc_json_str_def(cfg, "range", "1w"),
                                 nc_json_str_def(cfg, "level", ""),
                                 nc_json_str_def(cfg, "query", ""),
                                 nc_json_int_def(cfg, "limit", 1000));
    if (!records)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    count = json_object_array_length(records);
    fd = nc_log_export_open(id, sizeof(id), fmt, &dirfd);
    if (fd < 0 || !(fp = fdopen(fd, "w"))) {
        if (fd >= 0) close(fd);
        if (dirfd >= 0) { unlinkat(dirfd, id, 0); close(dirfd); }
        json_object_put(records);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    if (!strcmp(fmt, "json")) {
        if (fprintf(fp, "%s\n", json_object_to_json_string_ext(
                records, JSON_C_TO_STRING_PRETTY)) < 0)
            write_failed = 1;
    } else {
        if (fputs("id,type,ts,level,source,module,iface,username,ip,mac,title,event,detail,state,target\n", fp) == EOF)
            write_failed = 1;
        for (int i = 0; i < count && !write_failed; i++) {
            struct json_object *row = json_object_array_get_idx(records, i);
            struct json_object *ts = NULL;
            if (nc_log_csv_json_field(fp, row, fields[0]) != 0 || fputc(',', fp) == EOF ||
                nc_log_csv_json_field(fp, row, fields[1]) != 0 || fputc(',', fp) == EOF)
                write_failed = 1;
            json_object_object_get_ex(row, "ts", &ts);
            if (!write_failed && fprintf(fp, "%lld,", (long long)json_object_get_int64(ts)) < 0)
                write_failed = 1;
            for (int k = 2; fields[k] && !write_failed; k++) {
                if (nc_log_csv_json_field(fp, row, fields[k]) != 0 ||
                    (fields[k + 1] ? fputc(',', fp) == EOF : fputc('\n', fp) == EOF))
                    write_failed = 1;
            }
        }
    }
    if (fflush(fp) != 0)
        write_failed = 1;
    if (fsync(fileno(fp)) != 0)
        write_failed = 1;
    if (fclose(fp) != 0)
        write_failed = 1;
    json_object_put(records);
    if (write_failed) {
        unlinkat(dirfd, id, 0);
        close(dirfd);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    close(dirfd);
    data = json_object_new_object();
    snprintf(download_url, sizeof(download_url), "/api/v1/logs/download?id=%s", id);
    json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "download_url", json_object_new_string(download_url));
    json_object_object_add(data, "format", json_object_new_string(fmt));
    json_object_object_add(data, "count", json_object_new_int(count));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_log_center_clear(struct json_object *cfg)
{if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);nc_log_db_init();const char*type=nc_json_str_def(cfg,"type","");sqlite3_int64 before=json_object_get_int64(json_object_object_get(cfg,"before"));if(!nc_log_type_ok(type)||before<=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);sqlite3_stmt*st=NULL;int changed=0;if(nc_prepare(&st,"DELETE FROM log_event WHERE type=? AND ts<?")==0){sqlite3_bind_text(st,1,type,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,before);sqlite3_step(st);sqlite3_finalize(st);changed=sqlite3_changes(g_netconfig_db);}struct json_object*d=json_object_new_object();json_object_object_add(d,"cleared",json_object_new_int(changed));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_log_center_mark_read(struct json_object *cfg)
{if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);nc_log_db_init();struct json_object*ids=NULL;int changed=0;if(json_object_object_get_ex(cfg,"ids",&ids)&&json_object_is_type(ids,json_type_array)){int n=json_object_array_length(ids);for(int i=0;i<n;i++){const char*id=json_object_get_string(json_object_array_get_idx(ids,i));sqlite3_stmt*st=NULL;if(id&&nc_prepare(&st,"UPDATE log_event SET state='read' WHERE id=? AND type='message'")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);changed+=sqlite3_changes(g_netconfig_db);}}}struct json_object*d=json_object_new_object();json_object_object_add(d,"updated",json_object_new_int(changed));return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

int jmx_log_center_syslog_set(struct json_object *cfg)
{if(!cfg||jmx_netconfig_db_init()!=0)return -1;nc_log_db_init();const char*server=nc_json_str_def(cfg,"server","");const char*proto=nc_json_str_def(cfg,"protocol","udp");if(server[0]&&!nc_log_safe_token(server))return -1;if(strcmp(proto,"udp")&&strcmp(proto,"tcp")&&strcmp(proto,"tls"))return -1;struct json_object*v=NULL;json_object_object_get_ex(cfg,"categories",&v);char*cats=nc_json_array_to_string(v,nc_json_str_def(cfg,"categories","general,audit,security,wan,client,vpn"));sqlite3_stmt*st=NULL;if(nc_prepare(&st,"UPDATE log_syslog_config SET enabled=?,server=?,port=?,protocol=?,facility=?,min_level=?,categories=?,updated_at=? WHERE id=1")==0){sqlite3_bind_int(st,1,nc_json_bool_def(cfg,"enabled",0));sqlite3_bind_text(st,2,server,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,nc_json_int_def(cfg,"port",514));sqlite3_bind_text(st,4,proto,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(cfg,"facility","local7"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(cfg,"min_level","notice"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,cats?cats:"",-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,8,(sqlite3_int64)nc_now_s());sqlite3_step(st);sqlite3_finalize(st);}if(cats)free(cats);return 0;}

int jmx_log_center_settings_set(struct json_object *cfg)
{if(!cfg||jmx_netconfig_db_init()!=0)return -1;nc_log_db_init();int rd=nc_json_int_def(cfg,"retention_days",30),krd=nc_json_int_def(cfg,"kernel_retention_days",7),mb=nc_json_int_def(cfg,"max_size_mb",128);if(rd<1||rd>365||krd<1||krd>90||mb<32||mb>1024)return -1;sqlite3_stmt*st=NULL;if(nc_prepare(&st,"UPDATE log_settings SET retention_days=?,kernel_retention_days=?,max_size_mb=?,auto_cleanup=?,archive_compress=?,updated_at=? WHERE id=1")==0){sqlite3_bind_int(st,1,rd);sqlite3_bind_int(st,2,krd);sqlite3_bind_int(st,3,mb);sqlite3_bind_int(st,4,nc_json_bool_def(cfg,"auto_cleanup",1));sqlite3_bind_int(st,5,nc_json_bool_def(cfg,"archive_compress",1));sqlite3_bind_int64(st,6,(sqlite3_int64)nc_now_s());sqlite3_step(st);sqlite3_finalize(st);}if(nc_json_bool_def(cfg,"auto_cleanup",1)){char sql[256];snprintf(sql,sizeof(sql),"DELETE FROM log_event WHERE (type='kernel' AND ts < strftime('%%s','now')-%d*86400) OR (type!='kernel' AND ts < strftime('%%s','now')-%d*86400)",krd,rd);nc_exec(sql);}return 0;}

/* ── warning expression evaluator ───────────────────────────────────── */
/* Supported trigger_expr formats:
 *   "level>=error"                        - simple level threshold
 *   "level>=warning&source=logread"       - level + source match
 *   "event~error|warn"                    - event contains substring
 *   "count>=5/60s"                        - N events in last 60s window
 *   "type=user&level>=notice"             - compound
 * Operators: >= <= = ~ (contains)  Combiner: & (AND)
 */
static int nc_log_eval_simple_cond(const char *field, const char *op, const char *val, struct json_object *ev)
{
    if (!field || !op || !val || !ev) return 0;
    const char *actual = nc_json_str_def(ev, field, "");
    if (!strcmp(op, ">=")) {
        /* numeric compare for level: debug<info<notice<warning<error */
        static const char *levels[] = {"debug","info","notice","warning","error",NULL};
        int ai=0,vi=0;
        for (int i=0; levels[i]; i++) { if (!strcmp(levels[i],actual)) ai=i; if (!strcmp(levels[i],val)) vi=i; }
        return ai >= vi;
    }
    if (!strcmp(op, "<=")) {
        static const char *levels[] = {"debug","info","notice","warning","error",NULL};
        int ai=0,vi=0;
        for (int i=0; levels[i]; i++) { if (!strcmp(levels[i],actual)) ai=i; if (!strcmp(levels[i],val)) vi=i; }
        return ai <= vi;
    }
    if (!strcmp(op, "=")) return !strcmp(actual, val);
    if (!strcmp(op, "~")) return strstr(actual, val) != NULL;
    return 0;
}

static int nc_log_eval_count_cond(const char *field, const char *op, const char *val, int window_sec, struct json_object *ev)
{
    (void)op;
    if (!field || !val || window_sec <= 0) return 0;
    const char *fv = nc_json_str_def(ev, field, "");
    int threshold = atoi(val);
    if (threshold <= 0) return 0;
    sqlite3_int64 since = (sqlite3_int64)nc_now_s() - window_sec;
    sqlite3_stmt *st = NULL;
    int count = 0;
    if (nc_prepare(&st, "SELECT COUNT(*) FROM log_event WHERE ts>=?") == 0) {
        sqlite3_bind_int64(st, 1, since);
        if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return count >= threshold;
}

static int nc_log_eval_trigger_expr(const char *expr, struct json_object *ev)
{
    if (!expr || !expr[0] || !ev) return 1; /* empty expr = always match */
    char buf[512];
    strncpy(buf, expr, sizeof(buf)-1); buf[sizeof(buf)-1] = 0;
    int result = 1;
    char *save = NULL;
    char *tok = strtok_r(buf, "&", &save);
    while (tok) {
        while (*tok == ' ') tok++;
        /* check for count pattern: count>=N/60s */
        int is_count = 0;
        if (strncmp(tok, "count", 5) == 0) {
            char *slash = strchr(tok, '/');
            if (slash) {
                *slash = 0;
                int ws = atoi(slash + 1);
                char *s_suffix = strchr(slash + 1, 's');
                if (s_suffix) *s_suffix = 0;
                if (ws <= 0) ws = 60;
                /* tok is now "count>=N" */
                char *op = tok + 5;
                char *val = NULL;
                if (!strncmp(op, ">=", 2)) { val = op + 2; is_count = 1; }
                if (is_count) {
                    if (!nc_log_eval_count_cond(NULL, ">=", val, ws, ev)) { result = 0; break; }
                    tok = strtok_r(NULL, "&", &save);
                    continue;
                }
            }
        }
        /* standard pattern: field>=value or field=value or field~value */
        char *op_start = NULL;
        for (char *p = tok; *p; p++) {
            if (*p == '>' || *p == '<' || *p == '=' || *p == '~') { op_start = p; break; }
        }
        if (op_start) {
            char field[64] = "", op[4] = "", val[128] = "";
            int flen = (int)(op_start - tok);
            if (flen > 63) flen = 63;
            strncpy(field, tok, flen); field[flen] = 0;
            if (!strncmp(op_start, ">=", 2)) { strcpy(op, ">="); strncpy(val, op_start+2, 127); }
            else if (!strncmp(op_start, "<=", 2)) { strcpy(op, "<="); strncpy(val, op_start+2, 127); }
            else { op[0] = *op_start; op[1] = 0; strncpy(val, op_start+1, 127); }
            val[127] = 0;
            if (!nc_log_eval_simple_cond(field, op, val, ev)) { result = 0; break; }
        }
        tok = strtok_r(NULL, "&", &save);
    }
    return result;
}

static int nc_log_alarm_upsert_from_event(struct json_object *o);
/* ── syslog local forwarder ─────────────────────────────────────────── */
/* Writes log events to /var/log/dreamingwrt.log in syslog-like format */
static void nc_log_syslog_forward(struct json_object *ev)
{
    if (!ev) return;
    /* check if syslog is enabled */
    sqlite3_stmt *st = NULL;
    int enabled = 0;
    if (nc_prepare(&st, "SELECT enabled FROM log_syslog_config WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) enabled = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    if (!enabled) return;

    const char *type = nc_json_str_def(ev, "type", "");
    const char *level = nc_json_str_def(ev, "level", "info");
    const char *source = nc_json_str_def(ev, "source", "");
    const char *event = nc_json_str_def(ev, "event", "");
    const char *detail = nc_json_str_def(ev, "detail", "");

    /* severity mapping */
    int severity = 6; /* info */
    if (!strcmp(level, "error")) severity = 3;
    else if (!strcmp(level, "warning")) severity = 4;
    else if (!strcmp(level, "notice")) severity = 5;

    time_t now = time(NULL);
    struct tm tm_val;
    localtime_r(&now, &tm_val);
    char ts[32];
    strftime(ts, sizeof(ts), "%b %d %H:%M:%S", &tm_val);

    /* open syslog file (append) */
    FILE *fp = fopen("/var/log/dreamingwrt.log", "a");
    if (!fp) return;
    fprintf(fp, "%s dreamingwrt[%d]: <%d>[%s] %s: %s%s%s\n",
            ts, getpid(), severity, type, source, event,
            detail[0] ? " | " : "", detail);
    fclose(fp);

    /* rotate if > 2MB */
    struct stat stbuf;
    if (stat("/var/log/dreamingwrt.log", &stbuf) == 0 && stbuf.st_size > 2 * 1024 * 1024) {
        rename("/var/log/dreamingwrt.log", "/var/log/dreamingwrt.log.1");
    }
}

static void nc_log_delivery_enqueue(const char*alarm_id, struct json_object *o);
/* ── channel config encryption ─────────────────────────────────────── */
/*
 * Key file: /etc/dreamingwrt/channel_key (32 bytes random, created on first use)
 *
 * New ciphertexts use AES-256-GCM and carry a "v1:nonce:tag:cipher" prefix, the
 * same shape authd_secret_encrypt() already uses. The previous scheme was a
 * repeating-key XOR, which leaks key bytes wherever the plaintext is guessable
 * (channel configs start with a predictable JSON prefix and hold webhook URLs).
 * Rows written by that scheme are plain hex with no prefix, so they are still
 * readable below and get rewritten in the new format on the next save.
 */
static const char *nc_channel_key_path = "/etc/dreamingwrt/channel_key";
static unsigned char g_channel_key[32];
static int g_channel_key_loaded = 0;

/* Returns 0 when g_channel_key holds a usable key, -1 otherwise. Callers must
 * check: continuing without a key used to mean encrypting with a fixed one. */
static int nc_channel_key_load(void)
{
    unsigned char fresh[32];
    FILE *fp;
    size_t n;

    if (g_channel_key_loaded)
        return 0;
    fp = fopen(nc_channel_key_path, "rb");
    if (fp) {
        n = fread(g_channel_key, 1, sizeof(g_channel_key), fp);
        fclose(fp);
        if (n == sizeof(g_channel_key)) {
            g_channel_key_loaded = 1;
            return 0;
        }
        /* A short read means the file is truncated or corrupt. The old code
         * kept whatever bytes it got and left the rest uninitialised. */
        OPENSSL_cleanse(g_channel_key, sizeof(g_channel_key));
    }
    /* No strong randomness means no key. The previous rand() fallback produced
     * the same bytes on every boot, since srand() was never called. */
    if (RAND_priv_bytes(fresh, sizeof(fresh)) != 1) {
        OPENSSL_cleanse(fresh, sizeof(fresh));
        return -1;
    }
    fp = fopen(nc_channel_key_path, "wb");
    if (!fp) {
        OPENSSL_cleanse(fresh, sizeof(fresh));
        return -1;
    }
    /* Narrow the mode before the key bytes reach the disk. */
    if (fchmod(fileno(fp), 0600) != 0 ||
        fwrite(fresh, 1, sizeof(fresh), fp) != sizeof(fresh) ||
        fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(nc_channel_key_path);
        OPENSSL_cleanse(fresh, sizeof(fresh));
        return -1;
    }
    if (fclose(fp) != 0) {
        unlink(nc_channel_key_path);
        OPENSSL_cleanse(fresh, sizeof(fresh));
        return -1;
    }
    memcpy(g_channel_key, fresh, sizeof(g_channel_key));
    OPENSSL_cleanse(fresh, sizeof(fresh));
    g_channel_key_loaded = 1;
    return 0;
}

static void nc_hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/* Value of a single hex digit, or -1 if the character is not one. */
static int nc_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Returns the number of bytes decoded, or -1 on a malformed input. */
static int nc_hex_decode(const char *hex, size_t hex_len, unsigned char *out,
                         size_t out_len)
{
    size_t i;

    if ((hex_len % 2) != 0 || hex_len / 2 > out_len)
        return -1;
    for (i = 0; i < hex_len; i += 2) {
        int hi = nc_hex_nibble(hex[i]);
        int lo = nc_hex_nibble(hex[i + 1]);

        if (hi < 0 || lo < 0)
            return -1;
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}

/*
 * Legacy reader for rows written by the repeating-key XOR scheme: a bare hex
 * string with no version prefix. Kept so existing channels keep working; new
 * writes never take this path.
 */
static char *nc_channel_config_decrypt_legacy(const char *hex)
{
    size_t hex_len;
    size_t i;
    size_t len;
    char *plain;

    if (!hex || !hex[0])
        return NULL;
    hex_len = strlen(hex);
    if ((hex_len % 2) != 0)
        return NULL;
    len = hex_len / 2;
    plain = malloc(len + 1);
    if (!plain)
        return NULL;
    for (i = 0; i < len; i++) {
        int hi = nc_hex_nibble(hex[i * 2]);
        int lo = nc_hex_nibble(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            free(plain);
            return NULL;
        }
        plain[i] = (char)(((unsigned char)((hi << 4) | lo)) ^
                          g_channel_key[i % sizeof(g_channel_key)]);
    }
    plain[len] = '\0';
    return plain;
}

static char *nc_channel_config_encrypt(const char *plaintext, int *out_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[12], tag[16];
    unsigned char *cipher = NULL;
    char *nonce_hex = NULL, *tag_hex = NULL, *cipher_hex = NULL, *out = NULL;
    size_t plain_len;
    size_t out_size;
    int len = 0, total = 0;

    if (out_len)
        *out_len = 0;
    if (!plaintext || !plaintext[0])
        return NULL;
    plain_len = strlen(plaintext);
    if (plain_len > (size_t)INT_MAX - 32)
        return NULL;
    if (nc_channel_key_load() != 0 || RAND_bytes(nonce, sizeof(nonce)) != 1)
        return NULL;

    /* GCM is a stream mode, so the ciphertext is exactly plain_len bytes; the
     * slack is only there to satisfy EVP_EncryptFinal_ex's contract. */
    cipher = malloc(plain_len + EVP_MAX_BLOCK_LENGTH);
    nonce_hex = malloc(sizeof(nonce) * 2 + 1);
    tag_hex = malloc(sizeof(tag) * 2 + 1);
    cipher_hex = malloc((plain_len + EVP_MAX_BLOCK_LENGTH) * 2 + 1);
    if (!cipher || !nonce_hex || !tag_hex || !cipher_hex)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, g_channel_key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, cipher, &len, (const unsigned char *)plaintext,
                          (int)plain_len) != 1)
        goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + total, &len) != 1)
        goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag) != 1)
        goto done;

    nc_hex_encode(nonce, sizeof(nonce), nonce_hex);
    nc_hex_encode(tag, sizeof(tag), tag_hex);
    nc_hex_encode(cipher, (size_t)total, cipher_hex);
    out_size = strlen(nonce_hex) + strlen(tag_hex) + strlen(cipher_hex) + 8;
    out = malloc(out_size);
    if (!out)
        goto done;
    if (snprintf(out, out_size, "v1:%s:%s:%s", nonce_hex, tag_hex, cipher_hex) >=
        (int)out_size) {
        free(out);
        out = NULL;
        goto done;
    }
    if (out_len)
        *out_len = (int)strlen(out);
done:
    if (cipher) {
        OPENSSL_cleanse(cipher, plain_len + EVP_MAX_BLOCK_LENGTH);
        free(cipher);
    }
    free(nonce_hex);
    free(tag_hex);
    free(cipher_hex);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return out;
}

static char *nc_channel_config_decrypt(const char *stored)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[12], tag[16];
    unsigned char *cipher = NULL;
    char *plain = NULL;
    const char *p, *sep;
    size_t nonce_hex_len, tag_hex_len, cipher_hex_len, cipher_len;
    int len = 0, total = 0;

    if (!stored || !stored[0])
        return NULL;
    if (nc_channel_key_load() != 0)
        return NULL;
    if (strncmp(stored, "v1:", 3) != 0)
        return nc_channel_config_decrypt_legacy(stored);

    p = stored + 3;
    sep = strchr(p, ':');
    if (!sep)
        return NULL;
    nonce_hex_len = (size_t)(sep - p);
    if (nc_hex_decode(p, nonce_hex_len, nonce, sizeof(nonce)) != (int)sizeof(nonce))
        return NULL;
    p = sep + 1;
    sep = strchr(p, ':');
    if (!sep)
        return NULL;
    tag_hex_len = (size_t)(sep - p);
    if (nc_hex_decode(p, tag_hex_len, tag, sizeof(tag)) != (int)sizeof(tag))
        return NULL;
    p = sep + 1;
    cipher_hex_len = strlen(p);
    if (cipher_hex_len == 0 || (cipher_hex_len % 2) != 0)
        return NULL;
    cipher_len = cipher_hex_len / 2;
    cipher = malloc(cipher_len);
    if (!cipher)
        return NULL;
    if (nc_hex_decode(p, cipher_hex_len, cipher, cipher_len) != (int)cipher_len)
        goto done;
    plain = malloc(cipher_len + 1);
    if (!plain)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx ||
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, g_channel_key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, (unsigned char *)plain, &len, cipher,
                          (int)cipher_len) != 1) {
        free(plain);
        plain = NULL;
        goto done;
    }
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)sizeof(tag), tag) != 1) {
        free(plain);
        plain = NULL;
        goto done;
    }
    /* A failed tag check means the row was altered. Return nothing rather than
     * handing the caller unauthenticated plaintext. */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)plain + total, &len) != 1) {
        OPENSSL_cleanse(plain, cipher_len + 1);
        free(plain);
        plain = NULL;
        goto done;
    }
    total += len;
    plain[total] = '\0';
done:
    if (cipher)
        free(cipher);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return plain;
}

static struct json_object *nc_log_redact_channel_config(const char *raw);
static int nc_log_event_insert_obj(struct json_object *o)
{
    if(!o)return -1; const char*type=nc_json_str_def(o,"type",""); const char*level=nc_json_str_def(o,"level","info"); if(!nc_log_type_ok(type)||!nc_log_level_ok(level))return -1;
    const char*id0=nc_json_str_def(o,"id",""); char id[96]; sqlite3_int64 now=(sqlite3_int64)nc_now_s(); sqlite3_int64 ts=json_object_get_int64(json_object_object_get(o,"ts")); if(ts<=0)ts=now;
    if(id0[0])snprintf(id,sizeof(id),"%s",id0);else snprintf(id,sizeof(id),"%s-%lld-%08x",type,(long long)ts,nc_log_hash(nc_json_str_def(o,"event",nc_json_str_def(o,"title","")))^nc_log_hash(nc_json_str_def(o,"detail","")));
    if(!nc_valid_name(id))return -1;
    sqlite3_stmt*st=NULL;
    if(nc_prepare(&st,"INSERT OR REPLACE INTO log_event(id,type,ts,level,category,module,source,iface,username,auth_ip,auth_type,identity,mac,ip,title,event,detail,state,target,channel,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,COALESCE((SELECT created_at FROM log_event WHERE id=?),?))")!=0)return -1;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,type,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,ts);sqlite3_bind_text(st,4,level,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,5,nc_json_str_def(o,"category",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"module",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(o,"source",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"iface",""),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,9,nc_json_str_def(o,"username",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,10,nc_json_str_def(o,"auth_ip",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,11,nc_json_str_def(o,"auth_type",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,12,nc_json_str_def(o,"identity",""),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,13,nc_json_str_def(o,"mac",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,14,nc_json_str_def(o,"ip",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,15,nc_json_str_def(o,"title",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,16,nc_json_str_def(o,"event",""),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,17,nc_json_str_def(o,"detail",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,18,nc_json_str_def(o,"state",!strcmp(type,"message")?"unread":""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,19,nc_json_str_def(o,"target",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,20,nc_json_str_def(o,"channel",""),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,21,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,22,now);int rc=nc_step_done(st);sqlite3_finalize(st);return rc;
}

#define NC_LOGD_BRIDGE_TIMEOUT_MS 750

/*
 * Call flowd's compile+apply via ubus.
 *
 * After the QoS merge, the legacy executor is disabled and flowd is the sole
 * executor. This helper calls `dreamingwrt.flowd compile` with apply=true
 * so that changes written to flowd tables take effect on the dataplane.
 *
 * Returns 0 on success, -1 on failure. On failure, the caller should
 * roll back the database changes.
 */
static int nc_flowd_compile_apply(void)
{
    struct ubus_context *ctx = NULL;
    uint32_t id = 0;
    struct blob_buf b = {};
    int rc = -1;
    struct json_object *body = NULL;
    const char *raw = NULL;

    ctx = ubus_connect("/var/run/ubus/ubus.sock");
    if (!ctx)
        ctx = ubus_connect("/var/run/ubus.sock");
    if (!ctx)
        return -1;
    rc = ubus_lookup_id(ctx, "dreamingwrt.flowd", &id);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(ctx);
        return -1;
    }
    body = json_object_new_object();
    json_object_object_add(body, "dry_run", json_object_new_boolean(0));
    json_object_object_add(body, "apply", json_object_new_boolean(1));
    raw = json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN);
    blob_buf_init(&b, 0);
    if (!raw || !blobmsg_add_json_from_string(&b, raw)) {
        json_object_put(body);
        blob_buf_free(&b);
        ubus_free(ctx);
        return -1;
    }
    rc = ubus_invoke(ctx, id, "compile", b.head, NULL, NULL, 5000);
    blob_buf_free(&b);
    json_object_put(body);
    ubus_free(ctx);
    return rc == UBUS_STATUS_OK ? 0 : -1;
}

struct nc_logd_bridge_reply {
    struct json_object *json;
};

static void nc_logd_bridge_reply_cb(struct ubus_request *req, int type,
                                    struct blob_attr *msg)
{
    struct nc_logd_bridge_reply *reply = req ? req->priv : NULL;
    char *raw;

    (void)type;
    if (!reply || !msg)
        return;
    raw = blobmsg_format_json(msg, true);
    if (!raw)
        return;
    if (reply->json)
        json_object_put(reply->json);
    reply->json = json_tokener_parse(raw);
    free(raw);
}

static void nc_logd_bridge_set_reason(char *reason, size_t reason_len,
                                      const char *value)
{
    if (reason && reason_len > 0)
        snprintf(reason, reason_len, "%s", value ? value : "unknown");
}

static void nc_logd_bridge_add_metadata(struct json_object *detail,
                                        struct json_object *event)
{
    static const char *keys[] = { "source", "module", "iface", "target" };
    struct json_object *meta = NULL;
    const char *category = nc_json_str_def(event, "category", "");
    const char *source = nc_json_str_def(event, "source", "");
    char wan_id[128];
    size_t i;

    snprintf(wan_id, sizeof(wan_id), "%s",
             nc_json_str_def(event, "wan_id", ""));

    if (!json_object_object_get_ex(detail, "source_metadata", &meta) || !meta ||
        !json_object_is_type(meta, json_type_object)) {
        meta = json_object_new_object();
        if (!meta)
            return;
        json_object_object_add(detail, "source_metadata", meta);
    }
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *value = nc_json_str_def(event, keys[i], "");

        json_object_object_add(meta, keys[i], json_object_new_string(value));
    }
    if (!wan_id[0] && !strcmp(category, "network.wan") &&
        !strcmp(source, "routed.health"))
        snprintf(wan_id, sizeof(wan_id), "%s",
                 nc_json_str_def(event, "target", ""));
    if (wan_id[0]) {
        json_object_object_add(event, "wan_id", json_object_new_string(wan_id));
        json_object_object_add(detail, "wan_id", json_object_new_string(wan_id));
    }
    json_object_object_add(meta, "wan_id", json_object_new_string(wan_id));
    json_object_object_add(meta, "legacy_event_id",
                           json_object_new_string(nc_json_str_def(event, "id", "")));
    json_object_object_add(meta, "bridge",
                           json_object_new_string("jmx_log_center_event_add"));
}

static struct json_object *nc_logd_bridge_payload(struct json_object *event)
{
    struct json_object *copy;
    struct json_object *detail = NULL;
    struct json_object *legacy_detail = NULL;
    const char *raw;
    const char *level;

    if (!event || !json_object_is_type(event, json_type_object))
        return NULL;
    raw = json_object_to_json_string_ext(event, JSON_C_TO_STRING_PLAIN);
    copy = raw ? json_tokener_parse(raw) : NULL;
    if (!copy || !json_object_is_type(copy, json_type_object)) {
        if (copy)
            json_object_put(copy);
        return NULL;
    }

    if (json_object_object_get_ex(copy, "detail_json", &detail) && detail &&
        json_object_is_type(detail, json_type_object)) {
        detail = json_object_get(detail);
    } else if (detail && json_object_is_type(detail, json_type_string)) {
        detail = json_tokener_parse(json_object_get_string(detail));
        if (detail && !json_object_is_type(detail, json_type_object)) {
            json_object_put(detail);
            detail = NULL;
        }
    } else {
        detail = NULL;
    }
    if (!detail)
        detail = json_object_new_object();
    if (!detail) {
        json_object_put(copy);
        return NULL;
    }
    if (json_object_object_get_ex(copy, "detail", &legacy_detail) && legacy_detail &&
        json_object_is_type(legacy_detail, json_type_string)) {
        struct json_object *text = NULL;

        if (!json_object_object_get_ex(detail, "text", &text))
            json_object_object_add(detail, "text",
                                   json_object_new_string(json_object_get_string(legacy_detail)));
    }

    nc_logd_bridge_add_metadata(detail, copy);
    json_object_object_del(copy, "detail_json");
    json_object_object_add(copy, "detail_json", detail);
    level = nc_json_str_def(copy, "severity", nc_json_str_def(copy, "level", "info"));
    json_object_object_add(copy, "severity", json_object_new_string(level));
    json_object_object_add(copy, "legacy_bridge",
                           json_object_new_string("jmx_log_center_event_add"));
    return copy;
}

static int nc_logd_bridge_event(struct json_object *event,
                                char *reason, size_t reason_len)
{
    struct ubus_context *ctx = NULL;
    struct nc_logd_bridge_reply reply = {0};
    struct json_object *payload = NULL;
    struct json_object *ok_obj = NULL;
    struct json_object *error_obj = NULL;
    struct blob_buf b = {};
    const char *raw;
    uint32_t object_id = 0;
    int rc;
    int ok = 0;

    nc_logd_bridge_set_reason(reason, reason_len, "unknown");
    payload = nc_logd_bridge_payload(event);
    if (!payload) {
        nc_logd_bridge_set_reason(reason, reason_len, "payload_build_failed");
        goto out;
    }
    ctx = ubus_connect("/var/run/ubus/ubus.sock");
    if (!ctx)
        ctx = ubus_connect("/var/run/ubus.sock");
    if (!ctx) {
        nc_logd_bridge_set_reason(reason, reason_len, "ubus_connect_failed");
        goto out;
    }
    rc = ubus_lookup_id(ctx, "dreamingwrt.logd", &object_id);
    if (rc != UBUS_STATUS_OK) {
        nc_logd_bridge_set_reason(reason, reason_len, ubus_strerror(rc));
        goto out;
    }

    raw = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);
    blob_buf_init(&b, 0);
    if (!raw || !blobmsg_add_json_from_string(&b, raw)) {
        nc_logd_bridge_set_reason(reason, reason_len, "payload_encode_failed");
        blob_buf_free(&b);
        goto out;
    }
    rc = ubus_invoke(ctx, object_id, "event_add", b.head,
                     nc_logd_bridge_reply_cb, &reply,
                     NC_LOGD_BRIDGE_TIMEOUT_MS);
    blob_buf_free(&b);
    if (rc != UBUS_STATUS_OK) {
        nc_logd_bridge_set_reason(reason, reason_len, ubus_strerror(rc));
        goto out;
    }
    if (!reply.json ||
        !json_object_object_get_ex(reply.json, "ok", &ok_obj) ||
        !json_object_get_boolean(ok_obj)) {
        if (reply.json &&
            json_object_object_get_ex(reply.json, "error", &error_obj) && error_obj)
            nc_logd_bridge_set_reason(reason, reason_len,
                                      json_object_get_string(error_obj));
        else
            nc_logd_bridge_set_reason(reason, reason_len, "logd_rejected_event");
        goto out;
    }
    nc_logd_bridge_set_reason(reason, reason_len, "");
    ok = 1;

out:
    if (reply.json)
        json_object_put(reply.json);
    if (ctx)
        ubus_free(ctx);
    if (payload)
        json_object_put(payload);
    return ok ? 0 : -1;
}

static int nc_log_center_event_store(struct json_object *event,
                                     int *bridged, int *bridge_failed,
                                     char *last_bridge_error,
                                     size_t last_bridge_error_len)
{
    char reason[128] = "";

    if (nc_log_event_insert_obj(event) != 0)
        return -1;
    nc_log_alarm_upsert_from_event(event);
    nc_log_syslog_forward(event);
    if (nc_logd_bridge_event(event, reason, sizeof(reason)) == 0) {
        (*bridged)++;
    } else {
        (*bridge_failed)++;
        nc_logd_bridge_set_reason(last_bridge_error, last_bridge_error_len, reason);
        LOG_WARN("legacy log event inserted but logd bridge failed: id=%s event=%s reason=%s",
                 nc_json_str_def(event, "id", ""),
                 nc_json_str_def(event, "event", ""), reason);
    }
    return 0;
}

struct json_object *jmx_log_center_event_add(struct json_object *cfg)
{
    struct json_object *events = NULL;
    struct json_object *data;
    char last_bridge_error[128] = "";
    int inserted = 0;
    int failed = 0;
    int bridged = 0;
    int bridge_failed = 0;
    int i;

    if (jmx_netconfig_db_init() != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    nc_log_db_init();
    if (json_object_object_get_ex(cfg, "events", &events) &&
        json_object_is_type(events, json_type_array)) {
        for (i = 0; i < json_object_array_length(events); i++) {
            struct json_object *event = json_object_array_get_idx(events, i);

            if (nc_log_center_event_store(event, &bridged, &bridge_failed,
                                          last_bridge_error,
                                          sizeof(last_bridge_error)) == 0)
                inserted++;
            else
                failed++;
        }
    } else if (nc_log_center_event_store(cfg, &bridged, &bridge_failed,
                                         last_bridge_error,
                                         sizeof(last_bridge_error)) == 0) {
        inserted++;
    } else {
        failed++;
    }

    data = json_object_new_object();
    json_object_object_add(data, "inserted", json_object_new_int(inserted));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    json_object_object_add(data, "bridged", json_object_new_int(bridged));
    json_object_object_add(data, "bridge_failed", json_object_new_int(bridge_failed));
    if (bridge_failed > 0)
        json_object_object_add(data, "bridge_error",
                               json_object_new_string(last_bridge_error));
    return jmx_gen_api_response_data(failed ? API_CODE_ERROR : API_CODE_SUCCESS,
                                     data);
}

static struct json_object *nc_log_warning_rules_json(void)
{
    struct json_object*a=json_object_new_array(); sqlite3_stmt*st=NULL; if(nc_prepare(&st,"SELECT id,enabled,name,type,target,trigger_expr,channels,cooldown_sec,created_at,updated_at FROM warning_rule ORDER BY type,name,id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"name",st,2);nc_add_text(o,"type",st,3);nc_add_text(o,"target",st,4);nc_add_text(o,"trigger_expr",st,5);json_object_object_add(o,"channels",nc_json_array_from_text((const char*)sqlite3_column_text(st,6)));json_object_object_add(o,"cooldown_sec",json_object_new_int(sqlite3_column_int(st,7)));json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,8)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,9)));json_object_array_add(a,o);}sqlite3_finalize(st);} return a;
}

int jmx_log_center_warning_rules_set(struct json_object *cfg)
{
    if(!cfg||jmx_netconfig_db_init()!=0)return -1; nc_log_db_init(); struct json_object*rules=NULL; if(!json_object_object_get_ex(cfg,"rules",&rules)||!json_object_is_type(rules,json_type_array))return -1; if(nc_txn_begin()!=0)return -1; nc_exec("DELETE FROM warning_rule"); sqlite3_int64 now=(sqlite3_int64)nc_now_s(); int rc=0;
    int n=json_object_array_length(rules); for(int i=0;i<n;i++){struct json_object*o=json_object_array_get_idx(rules,i);const char*id=nc_json_str_def(o,"id","");const char*name=nc_json_str_def(o,"name","");const char*type=nc_json_str_def(o,"type","");const char*expr=nc_json_str_def(o,"trigger_expr","");if(!nc_valid_name(id)||!name[0]||strlen(name)>64||!type[0]||!expr[0]){rc=-1;break;}struct json_object*v=NULL;json_object_object_get_ex(o,"channels",&v);char*channels=nc_json_array_to_string(v,nc_json_str_def(o,"channels","console"));sqlite3_stmt*st=NULL;if(nc_prepare(&st,"INSERT INTO warning_rule(id,enabled,name,type,target,trigger_expr,channels,cooldown_sec,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,3,name,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,type,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"target",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,expr,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,channels?channels:"console",-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,8,nc_json_int_def(o,"cooldown_sec",300));sqlite3_bind_int64(st,9,now);sqlite3_bind_int64(st,10,now);if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);} if(channels)free(channels); if(rc)break;}
    nc_exec(rc==0?"COMMIT":"ROLLBACK"); return rc;
}

struct json_object *jmx_log_center_warning_rules_get(void)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_db_init(); struct json_object*d=json_object_new_object();json_object_object_add(d,"rules",nc_log_warning_rules_json());return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

static void nc_log_alarm_db_init(void)
{
    nc_log_db_init();
    nc_exec("CREATE TABLE IF NOT EXISTS warning_active (id TEXT PRIMARY KEY,rule_id TEXT NOT NULL DEFAULT '',first_ts INTEGER NOT NULL,last_ts INTEGER NOT NULL,level TEXT NOT NULL DEFAULT 'warning',type TEXT NOT NULL DEFAULT '',title TEXT NOT NULL DEFAULT '',target TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'active',channel TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '',ack_by TEXT NOT NULL DEFAULT '',ack_at INTEGER NOT NULL DEFAULT 0,resolved_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE INDEX IF NOT EXISTS idx_warning_active_status_ts ON warning_active(status,last_ts DESC)");
}

static int nc_log_alarm_upsert_from_event(struct json_object *o)
{
    const char*type=nc_json_str_def(o,"type",""); if(strcmp(type,"warning"))return 0;
    /* evaluate trigger_expr from rule if present */
    const char *rule_id = nc_json_str_def(o, "rule_id", "");
    if (rule_id[0]) {
        sqlite3_stmt *est = NULL;
        if (nc_prepare(&est, "SELECT trigger_expr FROM warning_rule WHERE id=? AND enabled=1") == 0) {
            sqlite3_bind_text(est, 1, rule_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(est) == SQLITE_ROW) {
                const char *expr = (const char *)sqlite3_column_text(est, 0);
                if (expr && expr[0] && !nc_log_eval_trigger_expr(expr, o)) {
                    sqlite3_finalize(est);
                    return 0; /* expression did not match, skip alarm */
                }
            }
            sqlite3_finalize(est);
        }
    }
    const char*title=nc_json_str_def(o,"title",nc_json_str_def(o,"event","")); const char*target=nc_json_str_def(o,"target",""); if(!title[0])return 0;
    sqlite3_int64 now=(sqlite3_int64)nc_now_s(); sqlite3_int64 ts=json_object_get_int64(json_object_object_get(o,"ts")); if(ts<=0)ts=now;
    char id[128]; const char*id0=nc_json_str_def(o,"alarm_id",""); if(id0[0])snprintf(id,sizeof(id),"%s",id0); else snprintf(id,sizeof(id),"warn-%08x",nc_log_hash(title)^nc_log_hash(target));
    const char *ev_status = nc_json_str_def(o, "status", "");
    int is_resolve = nc_json_bool_def(o, "resolved", 0) || nc_json_bool_def(o, "recovery", 0) || !strcmp(ev_status,"resolved") || !strcmp(ev_status,"ok") || !strcmp(ev_status,"recovered");
    sqlite3_stmt*st=NULL;
    if(is_resolve){
        if(nc_prepare(&st,"UPDATE warning_active SET status='resolved',last_ts=?,detail=?,resolved_at=?,updated_at=? WHERE id=?")==0){sqlite3_bind_int64(st,1,ts);sqlite3_bind_text(st,2,nc_json_str_def(o,"detail",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,now);sqlite3_bind_int64(st,4,now);sqlite3_bind_text(st,5,id,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);} 
        return 0;
    }
    if(nc_prepare(&st,"INSERT INTO warning_active(id,rule_id,first_ts,last_ts,level,type,title,target,status,channel,detail,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_ts=excluded.last_ts,level=excluded.level,type=excluded.type,title=excluded.title,target=excluded.target,status='active',channel=excluded.channel,detail=excluded.detail,updated_at=excluded.updated_at")==0){
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(o,"rule_id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,ts);sqlite3_bind_int64(st,4,ts);sqlite3_bind_text(st,5,nc_json_str_def(o,"level","warning"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"category",nc_json_str_def(o,"module","")),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,title,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,target,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,9,"active",-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,10,nc_json_str_def(o,"channel","console"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,11,nc_json_str_def(o,"detail",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,12,now);sqlite3_step(st);sqlite3_finalize(st);
    }
    nc_log_delivery_enqueue(id, o);
    return 0;
}

struct json_object *jmx_log_center_event_search(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL);
    nc_log_alarm_db_init();
    const char *q = nc_json_str_def(cfg, "query", "");
    const char *type_filter = nc_json_str_def(cfg, "type", "");
    const char *level_filter = nc_json_str_def(cfg, "level", "");
    const char *source_filter = nc_json_str_def(cfg, "source", "");
    sqlite3_int64 ts_from = (sqlite3_int64)json_object_get_int64(json_object_object_get(cfg, "ts_from"));
    sqlite3_int64 ts_to = (sqlite3_int64)json_object_get_int64(json_object_object_get(cfg, "ts_to"));
    int limit = nc_json_int_def(cfg, "limit", 100);
    if(limit < 1) limit = 1; if(limit > 500) limit = 500;

    /*
     * There is no "raw" column on log_event (see the CREATE TABLE and the
     * sibling query above), so this SELECT never prepared and the function
     * silently returned an empty result for every request, filters or not.
     * nc_prepare() logs the failure but the caller only sees count=0, which is
     * indistinguishable from "no matching events".
     */
    char sql[1024] = "SELECT id,ts,type,level,source,event,category,target,detail FROM log_event WHERE 1=1";
    /*
     * These four values come straight from the HTTP body via
     * POST /api/v1/logs/events/search and used to be pasted into the SQL text,
     * which let a caller close the quote and append their own clauses. Bind them
     * as parameters instead; the placeholders below are filled in bind order
     * after prepare, so the SQL shape is fixed no matter what the caller sends.
     * ts_from/ts_to/limit stay inline: they are numeric and range-clamped.
     */
    char q_like[256];
    if(q[0]) { strncat(sql, " AND (event LIKE ?1 OR detail LIKE ?1 OR category LIKE ?1)", sizeof(sql)-strlen(sql)-1); }
    if(type_filter[0]) { strncat(sql, " AND type=?2", sizeof(sql)-strlen(sql)-1); }
    if(level_filter[0]) { strncat(sql, " AND level=?3", sizeof(sql)-strlen(sql)-1); }
    if(source_filter[0]) { strncat(sql, " AND source=?4", sizeof(sql)-strlen(sql)-1); }
    if(ts_from > 0) { char tmp[64]; snprintf(tmp, sizeof(tmp), " AND ts>=%lld", (long long)ts_from); strncat(sql, tmp, sizeof(sql)-strlen(sql)-1); }
    if(ts_to > 0) { char tmp[64]; snprintf(tmp, sizeof(tmp), " AND ts<=%lld", (long long)ts_to); strncat(sql, tmp, sizeof(sql)-strlen(sql)-1); }
    { char tmp[64]; snprintf(tmp, sizeof(tmp), " ORDER BY ts DESC LIMIT %d", limit); strncat(sql, tmp, sizeof(sql)-strlen(sql)-1); }

    sqlite3_stmt *st = NULL;
    struct json_object *arr = json_object_new_array();
    if(nc_prepare(&st, sql)==0) {
        /*
         * Numbered placeholders keep bind indices stable even when a filter is
         * absent, so binding an unused index is harmless rather than shifting
         * the others. The % wildcards live in the bound value, not in the SQL,
         * which is what makes a query containing % or _ or a quote inert.
         */
        if(q[0]) {
            snprintf(q_like, sizeof(q_like), "%%%s%%", q);
            sqlite3_bind_text(st, 1, q_like, -1, SQLITE_TRANSIENT);
        }
        if(type_filter[0])
            sqlite3_bind_text(st, 2, type_filter, -1, SQLITE_TRANSIENT);
        if(level_filter[0])
            sqlite3_bind_text(st, 3, level_filter, -1, SQLITE_TRANSIENT);
        if(source_filter[0])
            sqlite3_bind_text(st, 4, source_filter, -1, SQLITE_TRANSIENT);
        while(sqlite3_step(st)==SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            nc_add_text(o, "id", st, 0);
            json_object_object_add(o, "ts", json_object_new_int64(sqlite3_column_int64(st, 1)));
            nc_add_text(o, "type", st, 2);
            nc_add_text(o, "level", st, 3);
            nc_add_text(o, "source", st, 4);
            nc_add_text(o, "event", st, 5);
            nc_add_text(o, "category", st, 6);
            nc_add_text(o, "target", st, 7);
            nc_add_text(o, "detail", st, 8);
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
    struct json_object *d = json_object_new_object();
    json_object_object_add(d, "events", arr);
    json_object_object_add(d, "count", json_object_new_int(json_object_array_length(arr)));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_log_center_alarm_get(struct json_object *cfg)
{
    if(jmx_netconfig_db_init()!=0)return jmx_gen_api_response_data(API_CODE_ERROR,NULL); nc_log_alarm_db_init(); const char*status=nc_json_str_def(cfg,"status",""); int limit=nc_json_int_def(cfg,"limit",200); if(limit<=0||limit>1000)limit=200; char sql[320]; snprintf(sql,sizeof(sql),"SELECT id,rule_id,first_ts,last_ts,level,type,title,target,status,channel,detail,ack_by,ack_at,resolved_at,updated_at FROM warning_active WHERE 1=1 %s ORDER BY last_ts DESC LIMIT ?",status[0]?"AND status=?":""); sqlite3_stmt*st=NULL; struct json_object*a=json_object_new_array(); if(nc_prepare(&st,sql)==0){int b=1;if(status[0])sqlite3_bind_text(st,b++,status,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,b++,limit);while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"rule_id",st,1);json_object_object_add(o,"first_ts",json_object_new_int64(sqlite3_column_int64(st,2)));json_object_object_add(o,"last_ts",json_object_new_int64(sqlite3_column_int64(st,3)));nc_add_text(o,"level",st,4);nc_add_text(o,"type",st,5);nc_add_text(o,"title",st,6);nc_add_text(o,"target",st,7);nc_add_text(o,"status",st,8);nc_add_text(o,"channel",st,9);nc_add_text(o,"detail",st,10);nc_add_text(o,"ack_by",st,11);json_object_object_add(o,"ack_at",json_object_new_int64(sqlite3_column_int64(st,12)));json_object_object_add(o,"resolved_at",json_object_new_int64(sqlite3_column_int64(st,13)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,14)));json_object_array_add(a,o);}sqlite3_finalize(st);} struct json_object*d=json_object_new_object();json_object_object_add(d,"alarms",a);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_log_center_prune(struct json_object *cfg)
{
