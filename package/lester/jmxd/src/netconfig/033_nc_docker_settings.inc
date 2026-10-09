/* Docker engine settings: config.db is authoritative; UCI is the applied image. */
#include <uci.h>
#include <sys/file.h>
#ifndef NC_DOCKER_SETTINGS_DB
#define NC_DOCKER_SETTINGS_DB g_netconfig_db_path
#endif
#ifndef NC_DOCKER_UCI_DIR
#define NC_DOCKER_UCI_DIR "/etc/config"
#endif
#ifndef NC_DOCKER_INIT
#define NC_DOCKER_INIT "/etc/init.d/dockerd"
#endif
#ifndef NC_DOCKER_SETTINGS_LOCK
#define NC_DOCKER_SETTINGS_LOCK "/var/run/dwrt-docker-settings.lock"
#endif
#ifndef NC_DOCKER_UCI_DELTA
#define NC_DOCKER_UCI_DELTA "/tmp/.uci/dockerd"
#endif

static int nc_docker_settings_service(const char *action)
{
    const char *const argv[] = {NC_DOCKER_INIT, action, NULL};
    struct nc_exec_result result = {0};
    int rc = nc_exec_argv_capture_ex(argv, 90, 1024, &result, 0);
    nc_exec_result_free(&result); return rc;
}

static int nc_docker_settings_fingerprint(char value[65])
{
    unsigned char data[65537], digest[32]; unsigned int length = 0;
    int fd = open(NC_DOCKER_UCI_DIR "/dockerd", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t used = read(fd, data, sizeof(data)); close(fd);
    if (used < 0 || used >= 65536) return -1;
    int enabled = nc_docker_settings_service("enabled");
    if (enabled != 0 && enabled != 1) return -1;
    data[used++] = enabled == 0;
    if (!EVP_Digest(data, (size_t)used, digest, &length, EVP_sha256(), NULL) || length != 32) return -1;
    for (unsigned i = 0; i < length; i++) snprintf(value + i * 2, 3, "%02x", digest[i]);
    return 0;
}

static struct uci_context *nc_docker_settings_uci(struct uci_package **package)
{
    struct stat delta;
    if (!stat(NC_DOCKER_UCI_DELTA, &delta) && delta.st_size) return NULL;
    struct uci_context *ctx = uci_alloc_context();
    FILE *fp = fopen(NC_DOCKER_UCI_DIR "/dockerd", "r");
    if (!ctx || !fp || uci_import(ctx, fp, "dockerd", package, true)) {
        if (fp) fclose(fp);
        if (ctx) uci_free_context(ctx);
        return NULL;
    }
    fclose(fp); return ctx;
}

static struct json_object *nc_docker_settings_live(void)
{
    struct uci_package *package = NULL;
    struct uci_context *ctx = nc_docker_settings_uci(&package);
    struct json_object *out = json_object_new_object(), *mirrors = json_object_new_array();
    char fingerprint[65]; struct uci_section *globals = NULL;
    if (ctx) globals = uci_lookup_section(ctx, package, "globals");
    if (!globals || nc_docker_settings_fingerprint(fingerprint)) {
        nc_docker_invalid(out, "docker_uci_unavailable_or_uncommitted"); goto done;
    }
    const char *alternate = uci_lookup_option_string(ctx, globals, "alt_config_file");
    if (alternate && *alternate) { nc_docker_invalid(out, "docker_alternate_config_active"); goto done; }
    struct uci_option *option = uci_lookup_option(ctx, globals, "registry_mirrors");
    if (option && option->type == UCI_TYPE_LIST) {
        struct uci_element *item;
        uci_foreach_element(&option->v.list, item) json_object_array_add(mirrors, json_object_new_string(item->name));
    } else if (option && option->type == UCI_TYPE_STRING && option->v.string[0]) {
        char *text = strdup(option->v.string), *save = NULL;
        for (char *p = text ? strtok_r(text, " \t", &save) : NULL; p; p = strtok_r(NULL, " \t", &save))
            json_object_array_add(mirrors, json_object_new_string(p));
        free(text);
    }
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "registry_mirrors", json_object_get(mirrors));
    json_object_object_add(out, "autostart", json_object_new_boolean(nc_docker_settings_service("enabled") == 0));
    json_object_object_add(out, "fingerprint", json_object_new_string(fingerprint));
    const char *root = uci_lookup_option_string(ctx, globals, "data_root");
    json_object_object_add(out, "data_root", json_object_new_string(root ? root : "/opt/docker/"));
done:
    json_object_put(mirrors); if (ctx) uci_free_context(ctx); return out;
}

static struct json_object *nc_docker_settings_fields(struct json_object *source)
{
    struct json_object *out = json_object_new_object();
    nc_docker_copy(out, "registry_mirrors", source, "registry_mirrors");
    nc_docker_copy(out, "autostart", source, "autostart");
    nc_docker_copy(out, "data_root", source, "data_root"); return out;
}

static int nc_docker_settings_validate(struct json_object *value, struct json_object *out)
{
    const char *const keys[] = {"registry_mirrors", "autostart", "data_root", NULL};
    struct json_object *mirrors = nc_docker_member(value, "registry_mirrors");
    if (!nc_docker_keys(value, keys) || !json_object_is_type(nc_docker_member(value, "autostart"), json_type_boolean))
        return nc_docker_create_error(out, "invalid_docker_settings", "autostart", "boolean_required_and_unknown_fields_rejected");
    if (!json_object_is_type(mirrors, json_type_array) || json_object_array_length(mirrors) > 8)
        return nc_docker_create_error(out, "invalid_docker_settings", "registry_mirrors", "array_max_8_required");
    for (size_t i = 0; i < json_object_array_length(mirrors); i++) {
        struct json_object *item = json_object_array_get_idx(mirrors, i);
        if (!nc_docker_string(item, 1024)) return nc_docker_invalid(out, "invalid_registry_mirror");
        const char *url = json_object_get_string(item);
        CURLU *parsed = curl_url(); char *scheme = NULL, *host = NULL, *part = NULL;
        int valid = parsed && !curl_url_set(parsed, CURLUPART_URL, url, 0) &&
            !curl_url_get(parsed, CURLUPART_SCHEME, &scheme, 0) &&
            !curl_url_get(parsed, CURLUPART_HOST, &host, 0) && host && *host &&
            (!strcmp(scheme, "https") || !strcmp(scheme, "http"));
        CURLUPart forbidden[] = {CURLUPART_USER, CURLUPART_PASSWORD, CURLUPART_QUERY, CURLUPART_FRAGMENT};
        for (size_t k = 0; parsed && k < sizeof(forbidden)/sizeof(forbidden[0]); k++) {
            if (!curl_url_get(parsed, forbidden[k], &part, 0)) valid = 0;
            curl_free(part); part = NULL;
        }
        for (const unsigned char *p = (const unsigned char *)url; *p; p++) if (*p <= 32 || *p == 127) valid = 0;
        for (size_t j = 0; j < i; j++) if (!strcmp(url, json_object_get_string(json_object_array_get_idx(mirrors, j)))) valid = 0;
        curl_free(scheme); curl_free(host); if (parsed) curl_url_cleanup(parsed);
        if (!valid) return nc_docker_create_error(out, "invalid_docker_settings", "registry_mirrors", "unique_http_https_urls_without_credentials_query_or_fragment_required");
    }
    return 0;
}

static int nc_docker_settings_db(sqlite3 **result)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int rc = -1;
    if (sqlite3_open_v2(NC_DOCKER_SETTINGS_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) goto done;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS docker_engine_settings("
        "id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,desired TEXT NOT NULL,"
        "applied TEXT NOT NULL,uci_fingerprint TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'idle',"
        "recovery TEXT NOT NULL DEFAULT '{}',last_result TEXT NOT NULL DEFAULT '{}');", NULL, NULL, NULL) != SQLITE_OK) goto done;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM docker_engine_settings WHERE id=1", -1, &st, NULL) != SQLITE_OK) goto done;
    int step = sqlite3_step(st); sqlite3_finalize(st); st = NULL;
    if (step == SQLITE_DONE) {
        struct json_object *live = nc_docker_settings_live(), *fields = nc_docker_settings_fields(live);
        if (!nc_json_bool_def(live, "ok", 0)) { json_object_put(live); json_object_put(fields); goto done; }
        rc = sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO docker_engine_settings(id,revision,desired,applied,uci_fingerprint) VALUES(1,1,?1,?1,?2)", -1, &st, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(st, 1, json_object_to_json_string_ext(fields, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str_def(live, "fingerprint", ""), -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
        } else rc = -1;
        json_object_put(live); json_object_put(fields);
        if (rc) goto done;
    } else if (step != SQLITE_ROW) goto done;
    if (st) sqlite3_finalize(st);
    *result = db; return 0;
done:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return -1;
}

static struct json_object *nc_docker_settings_row(sqlite3 *db)
{
    sqlite3_stmt *st = NULL; struct json_object *out = NULL;
    if (sqlite3_prepare_v2(db, "SELECT revision,desired,applied,uci_fingerprint,state,recovery,last_result FROM docker_engine_settings WHERE id=1", -1, &st, NULL) != SQLITE_OK) return NULL;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out = json_object_new_object();
        json_object_object_add(out, "revision", json_object_new_int64(sqlite3_column_int64(st, 0)));
        const char *names[] = {"config", "applied_config", "uci_fingerprint", "state", "recovery", "last_result"};
        for (int i = 1; i < 7; i++) {
            const char *text = (const char *)sqlite3_column_text(st, i);
            struct json_object *v = i == 3 || i == 4 ? json_object_new_string(text ? text : "") : json_tokener_parse(text ? text : "{}");
            json_object_object_add(out, names[i-1], v);
        }
    }
    sqlite3_finalize(st);
    if(out && !nc_docker_member(nc_docker_member(out,"config"),"data_root")){
        struct json_object *live=nc_docker_settings_live();
        nc_docker_copy(nc_docker_member(out,"config"),"data_root",live,"data_root");
        nc_docker_copy(nc_docker_member(out,"applied_config"),"data_root",live,"data_root");
        json_object_put(live);
    }
    return out;
}

struct json_object *jmx_docker_config_get(void)
{
    sqlite3 *db = NULL; struct json_object *out = NULL, *live = nc_docker_settings_live();
    if (!nc_docker_settings_db(&db)) out = nc_docker_settings_row(db);
    if (!out) out = json_object_new_object();
    int writable = db && nc_json_bool_def(live, "ok", 0);
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "config_write", json_object_new_boolean(writable));
    if (!writable) json_object_object_add(out, "reason", json_object_new_string(nc_json_str_def(live, "error", "docker_settings_storage_unavailable")));
    int changed = writable && strcmp(nc_json_str_def(live, "fingerprint", ""), nc_json_str_def(out, "uci_fingerprint", ""));
    json_object_object_add(out, "external_change", json_object_new_boolean(changed));
    json_object_object_add(out, "pending_apply", json_object_new_boolean(!json_object_equal(nc_docker_member(out,"config"),nc_docker_member(out,"applied_config"))));
    json_object_object_add(out, "authority", json_object_new_string("config.db:docker_engine_settings"));
    nc_docker_copy(out, "data_root", live, "data_root");
    json_object_object_add(out, "runtime_config", nc_docker_settings_fields(live));
    json_object_object_del(out, "uci_fingerprint"); json_object_object_del(out, "recovery");
    if (db) sqlite3_close(db);
    json_object_put(live);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, out);
}

int jmx_docker_config_set(struct json_object *cfg, struct json_object *out)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; struct json_object *row = NULL; int rc = -1, lock = -1;
    const char *const keys[] = {"confirm", "revision", "config", NULL};
    if (nc_docker_confirmation_required(cfg, out)) return -1;
    if (!nc_docker_keys(cfg, keys) || !nc_docker_integer(nc_docker_member(cfg, "revision"), 1, INT64_MAX))
        return nc_docker_invalid(out, "invalid_docker_settings_revision");
    struct json_object *value = nc_docker_member(cfg, "config");
    if (nc_docker_member(value,"data_root"))return nc_docker_invalid(out,"docker_data_root_requires_migration");
    if (nc_docker_settings_validate(value, out)) return -1;
    lock=open(NC_DOCKER_SETTINGS_LOCK,O_RDWR|O_CREAT|O_CLOEXEC,0600);
    if(lock<0||flock(lock,LOCK_EX|LOCK_NB)){nc_docker_invalid(out,"docker_settings_busy");goto done;}
    if (nc_docker_settings_db(&db) || sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) goto done;
    row = nc_docker_settings_row(db);
    if (!row || strcmp(nc_json_str_def(row, "state", ""), "idle")) { nc_docker_invalid(out, "docker_settings_recovery_or_apply_pending"); goto done; }
    if (json_object_get_int64(nc_docker_member(row,"revision")) != json_object_get_int64(nc_docker_member(cfg,"revision"))) {
        nc_docker_invalid(out, "revision_conflict"); goto done;
    }
    nc_docker_copy(value,"data_root",nc_docker_member(row,"config"),"data_root");
    if (sqlite3_prepare_v2(db, "UPDATE docker_engine_settings SET desired=?1,revision=revision+1 WHERE id=1", -1, &st, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_text(st, 1, json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto done;
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "persisted", json_object_new_boolean(1));
    json_object_object_add(out, "applied", json_object_new_boolean(0));
    json_object_object_add(out, "revision", json_object_new_int64(json_object_get_int64(nc_docker_member(cfg,"revision")) + 1));
    rc = 0;
done:
    if (st) sqlite3_finalize(st);
    if (db) { sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); sqlite3_close(db); }
    if (row) json_object_put(row);
    if (lock>=0)close(lock);
    if (rc && !nc_docker_member(out,"error")) nc_docker_invalid(out,"docker_settings_storage_failed");
    return rc;
}

static int nc_docker_settings_copy(const char *from, const char *to, int exclusive)
{
    int source = open(from, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int dest = source < 0 ? -1 : open(to, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | (exclusive ? O_EXCL : O_TRUNC), 0600);
    int rc = -1; char bytes[4096]; ssize_t n;
    if (dest < 0) goto done;
    while ((n = read(source, bytes, sizeof(bytes))) > 0) {
        ssize_t written = 0;
        while (written < n) { ssize_t step = write(dest, bytes + written, (size_t)(n - written)); if (step <= 0) goto done; written += step; }
    }
    if (n == 0 && !fsync(dest)) rc = 0;
done:
    if (source >= 0) close(source);
    if (dest >= 0 && close(dest)) rc = -1;
    return rc;
}

static int nc_docker_settings_publish(struct json_object *value)
{
    struct uci_package *package = NULL; struct uci_context *ctx = nc_docker_settings_uci(&package);
    int rc = -1; FILE *fp = NULL; const char *temporary = NC_DOCKER_UCI_DIR "/.dockerd.dwrt-new";
    if (!ctx) return -1;
    struct uci_section *globals = uci_lookup_section(ctx, package, "globals");
    if (!globals) goto done;
    struct uci_ptr ptr = {.p=package, .s=globals, .section="globals", .option="registry_mirrors"};
    ptr.o = uci_lookup_option(ctx, globals, "registry_mirrors");
    if (ptr.o && uci_delete(ctx, &ptr)) goto done;
    struct json_object *mirrors = nc_docker_member(value, "registry_mirrors");
    for (size_t i=0; i<json_object_array_length(mirrors); i++) {
        memset(&ptr,0,sizeof(ptr)); ptr.p=package;ptr.s=globals;ptr.section="globals";ptr.option="registry_mirrors";
        ptr.value=json_object_get_string(json_object_array_get_idx(mirrors,i));
        if (uci_add_list(ctx,&ptr)) goto done;
    }
    int fd=open(temporary,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd<0) goto done;
    fp=fdopen(fd,"w"); if (!fp) {close(fd);goto done;}
    if (uci_export(ctx,fp,package,false) || fflush(fp) || fsync(fileno(fp))) goto done;
    if (fclose(fp)) {fp=NULL;goto done;} fp=NULL;
    if (rename(temporary,NC_DOCKER_UCI_DIR "/dockerd")) goto done;
    rc=0;
done:
    if (fp) fclose(fp);
    if (rc) unlink(temporary);
    uci_free_context(ctx);return rc;
}

static int nc_docker_settings_record(sqlite3 *db,const char *state,struct json_object *recovery,
                                      struct json_object *result,struct json_object *applied)
{
    sqlite3_stmt *st=NULL;char fingerprint[65];int rc=-1;
    if (applied && nc_docker_settings_fingerprint(fingerprint)) return -1;
    if (sqlite3_prepare_v2(db,"UPDATE docker_engine_settings SET state=?1,recovery=?2,last_result=?3,applied=COALESCE(?4,applied),uci_fingerprint=COALESCE(?5,uci_fingerprint) WHERE id=1",-1,&st,NULL)!=SQLITE_OK)return -1;
    sqlite3_bind_text(st,1,state,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,2,recovery?json_object_to_json_string_ext(recovery,JSON_C_TO_STRING_PLAIN):"{}",-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,3,result?json_object_to_json_string_ext(result,JSON_C_TO_STRING_PLAIN):"{}",-1,SQLITE_TRANSIENT);
    if (applied) {
        sqlite3_bind_text(st,4,json_object_to_json_string_ext(applied,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(st,5,fingerprint,-1,SQLITE_TRANSIENT);
    }
    if (sqlite3_step(st)==SQLITE_DONE)rc=0;
    sqlite3_finalize(st);return rc;
}

static int nc_docker_settings_readback(struct json_object *wanted,int running)
{
    struct json_object *live=nc_docker_settings_live(),*fields=nc_docker_settings_fields(live);
    int ok=nc_json_bool_def(live,"ok",0)&&json_object_equal(wanted,fields);
    json_object_put(fields);json_object_put(live);
    if (!ok) return -1;
    if (!running) return nc_docker_settings_service("running")==1?0:-1;
    const char *const argv[]={"docker","info","--format","{{json .}}",NULL};
    for(int attempt=0;attempt<20;attempt++) {
        struct json_object *info=nc_docker_read_json(argv,0,NULL);
        struct json_object *actual=nc_docker_member(nc_docker_member(info,"RegistryConfig"),"Mirrors"),*mirrors=nc_docker_member(wanted,"registry_mirrors");
        ok=json_object_is_type(actual,json_type_array)&&json_object_array_length(actual)==json_object_array_length(mirrors);
        for(size_t i=0;ok&&i<json_object_array_length(mirrors);i++) {
            const char *a=json_object_get_string(json_object_array_get_idx(actual,i));
            const char *b=json_object_get_string(json_object_array_get_idx(mirrors,i));
            size_t an=strlen(a),bn=strlen(b);while(an&&a[an-1]=='/')an--;while(bn&&b[bn-1]=='/')bn--;
            if(an!=bn||strncmp(a,b,an))ok=0;
        }
        if(info)json_object_put(info);
        if(ok&&nc_docker_settings_service("running")==0)return 0;
        usleep(250000);
    }
    return -1;
}

static int nc_docker_settings_restore(sqlite3 *db,struct json_object *row,struct json_object *out)
{
    struct json_object *recovery=nc_docker_member(row,"recovery"),*previous=nc_docker_member(recovery,"previous");
    const char *backup=nc_json_str_def(recovery,"backup","");
    int running=nc_json_bool_def(recovery,"running",0), rc=-1;
    const char *temporary=NC_DOCKER_UCI_DIR "/.dockerd.dwrt-restore";
    if(strncmp(backup,NC_DOCKER_UCI_DIR "/.dockerd.dwrt-job-",strlen(NC_DOCKER_UCI_DIR "/.dockerd.dwrt-job-"))||!previous)
        return nc_docker_invalid(out,"docker_settings_recovery_missing");
    if(nc_docker_settings_record(db,"restoring",recovery,out,NULL))return -1;
    if(nc_docker_settings_copy(backup,temporary,0)||rename(temporary,NC_DOCKER_UCI_DIR "/dockerd"))goto done;
    if(nc_docker_settings_service(nc_json_bool_def(previous,"autostart",0)?"enable":"disable"))goto done;
    if(nc_json_bool_def(recovery,"restart",1)&&running&&nc_docker_settings_service("restart"))goto done;
    if(nc_docker_settings_readback(previous,running))goto done;
    json_object_object_add(out,"rollback",json_object_new_string("restored"));
    rc=nc_docker_settings_record(db,"idle",NULL,out,previous);
done:
    if(rc){json_object_object_add(out,"rollback",json_object_new_string("failed"));nc_docker_settings_record(db,"recovery_required",recovery,out,NULL);}
    return rc;
}

static int nc_docker_settings_execute(const char *job,struct json_object *cfg,struct json_object *out)
{
    sqlite3 *db=NULL;struct json_object *row=NULL,*live=NULL;int rc=125,lock=-1;
    lock=open(NC_DOCKER_SETTINGS_LOCK,O_RDWR|O_CREAT|O_CLOEXEC,0600);
    if(lock<0||flock(lock,LOCK_EX|LOCK_NB)){nc_docker_invalid(out,"docker_settings_busy");goto done;}
    if(nc_docker_settings_db(&db)){nc_docker_invalid(out,"docker_settings_storage_failed");goto done;}
    row=nc_docker_settings_row(db);
    if(!row){nc_docker_invalid(out,"docker_settings_storage_failed");goto done;}
    if(!strncmp(nc_json_str_def(row,"state",""),"migration_",10)){nc_docker_invalid(out,"docker_migration_recovery_required");goto done;}
    if(!strcmp(nc_json_str_def(cfg,"operation",""),"config_recover")) {
        if(!strcmp(nc_json_str_def(row,"state",""),"idle")){nc_docker_invalid(out,"docker_settings_no_recovery");goto done;}
        rc=nc_docker_settings_restore(db,row,out)?125:0;
        json_object_object_add(out,"ok",json_object_new_boolean(!rc));goto done;
    }
    struct json_object *desired=nc_docker_member(row,"config");
    if(strcmp(nc_json_str_def(row,"state",""),"idle")){nc_docker_invalid(out,"docker_settings_recovery_required");goto done;}
    if(json_object_get_int64(nc_docker_member(row,"revision"))!=json_object_get_int64(nc_docker_member(cfg,"revision"))){nc_docker_invalid(out,"revision_conflict");goto done;}
    if(nc_docker_settings_validate(desired,out))goto done;
    live=nc_docker_settings_live();
    if(!nc_json_bool_def(live,"ok",0)||strcmp(nc_json_str_def(live,"fingerprint",""),nc_json_str_def(row,"uci_fingerprint",""))) {nc_docker_invalid(out,"docker_settings_external_change");goto done;}
    int running=nc_docker_settings_service("running");
    if(running!=0&&running!=1){nc_docker_invalid(out,"docker_service_state_unknown");goto done;}
    running=running==0;
    int restart=running&&!json_object_equal(nc_docker_member(desired,"registry_mirrors"),nc_docker_member(live,"registry_mirrors"));
    if(restart&&!nc_json_bool_def(cfg,"allow_restart",0)){nc_docker_invalid(out,"docker_restart_confirmation_required");goto done;}
    char backup[256];snprintf(backup,sizeof(backup),NC_DOCKER_UCI_DIR "/.dockerd.dwrt-%s.bak",job);
    if(nc_docker_settings_copy(NC_DOCKER_UCI_DIR "/dockerd",backup,1)){nc_docker_invalid(out,"docker_settings_backup_failed");goto done;}
    struct json_object *recovery=json_object_new_object(),*previous=nc_docker_settings_fields(live);
    json_object_object_add(recovery,"backup",json_object_new_string(backup));
    json_object_object_add(recovery,"previous",json_object_get(previous));
    json_object_object_add(recovery,"running",json_object_new_boolean(running));
    json_object_object_add(recovery,"restart",json_object_new_boolean(restart));
    json_object_object_add(out,"backup",json_object_new_string(backup));
    json_object_object_add(out,"persisted",json_object_new_boolean(1));
    json_object_object_add(out,"applied",json_object_new_boolean(0));
    if(nc_docker_settings_record(db,"applying",recovery,out,NULL)){json_object_put(previous);json_object_put(recovery);goto done;}
    json_object_object_add(row,"recovery",json_object_get(recovery));
    if(nc_docker_settings_publish(desired)||nc_docker_settings_service(nc_json_bool_def(desired,"autostart",0)?"enable":"disable")||
       (restart&&nc_docker_settings_service("restart"))||nc_docker_settings_readback(desired,running)) {
        nc_docker_invalid(out,"docker_settings_apply_failed");nc_docker_settings_restore(db,row,out);
    }else {
        json_object_object_add(out,"ok",json_object_new_boolean(1));json_object_object_add(out,"applied",json_object_new_boolean(1));
        json_object_object_add(out,"restart_required",json_object_new_boolean(0));
        if(!nc_docker_settings_record(db,"idle",NULL,out,desired))rc=0;
        else {nc_docker_invalid(out,"docker_settings_record_failed");json_object_object_add(out,"applied",json_object_new_boolean(0));}
    }
    json_object_put(previous);json_object_put(recovery);
done:
    if(live)json_object_put(live);
    if(row)json_object_put(row);
    if(db)sqlite3_close(db);
    if(lock>=0)close(lock);
    return rc;
}

static int nc_docker_settings_submit(struct json_object *cfg,struct json_object *out)
{
    const char *const keys[]={"id","operation","revision","confirm","allow_restart",NULL};
    if(!nc_docker_keys(cfg,keys)||!nc_docker_integer(nc_docker_member(cfg,"revision"),1,INT64_MAX))return nc_docker_invalid(out,"invalid_docker_settings_revision");
    return nc_container_job_submit("docker_config","docker-engine",json_object_to_json_string_ext(cfg,JSON_C_TO_STRING_PLAIN),out);
}
