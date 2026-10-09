/* Multi-protocol operations reference the existing protocol records. A receipt
 * is committed WITH each resource so an interrupted response cannot duplicate
 * a successful create on retry. No second copy of share configuration. */
#include <sys/file.h>
#ifndef JMX_FILE_OPERATIONS_LOCK
#define JMX_FILE_OPERATIONS_LOCK "/var/lock/dreamingwrt-file-operations.lock"
#endif
static _Thread_local const char *fs_operation_id;
static _Thread_local int fs_operation_index;

static int fs_operations_schema(sqlite3 *db)
{
    return fs_sql_exec(db,
        "CREATE TABLE IF NOT EXISTS file_share_operation("
        "id TEXT PRIMARY KEY,request_json TEXT NOT NULL,created_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS file_share_operation_result("
        "operation_id TEXT NOT NULL REFERENCES file_share_operation(id),"
        "item_index INTEGER NOT NULL,success INTEGER NOT NULL,result_json TEXT NOT NULL,"
        "PRIMARY KEY(operation_id,item_index));");
}

static int fs_operation_result(sqlite3 *db, const char *op, int index,
                               int success, struct json_object *result)
{
    sqlite3_stmt *st = NULL;
    if (fs_prepare(db, &st, "INSERT INTO file_share_operation_result VALUES(?1,?2,?3,?4) "
        "ON CONFLICT(operation_id,item_index) DO UPDATE SET success=excluded.success,"
        "result_json=excluded.result_json WHERE file_share_operation_result.success=0") != 0) return -1;
    sqlite3_bind_text(st,1,op,-1,SQLITE_TRANSIENT);
    sqlite3_bind_int(st,2,index); sqlite3_bind_int(st,3,success);
    sqlite3_bind_text(st,4,json_object_to_json_string_ext(result,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    int rc=fs_step_done(st); sqlite3_finalize(st); return rc;
}

static int fs_operation_receipt_state(sqlite3 *db, const char *id, int64_t revision, int deleted, int applied)
{
    if (!fs_operation_id) return 0;
    struct json_object *r=json_object_new_object();
    json_object_object_add(r,"id",json_object_new_string(id));
    json_object_object_add(r,"revision",json_object_new_int64(revision));
    json_object_object_add(r,"deleted",json_object_new_boolean(deleted));
    json_object_object_add(r,"persisted",json_object_new_boolean(1));
    json_object_object_add(r,"applied",json_object_new_boolean(applied));
    int rc=fs_operation_result(db,fs_operation_id,fs_operation_index,1,r);
    json_object_put(r); return rc;
}

static int fs_operation_receipt(sqlite3 *db,const char *id,int64_t revision,int deleted)
{
    return fs_operation_receipt_state(db,id,revision,deleted,1);
}

static const char *fs_op_text(struct json_object *o,const char *key)
{
    struct json_object *v=NULL;
    return o && json_object_object_get_ex(o,key,&v) && json_object_is_type(v,json_type_string)
        ? json_object_get_string(v) : "";
}

static struct json_object *fs_operation_read(sqlite3 *db,const char *id)
{
    sqlite3_stmt *st=NULL;
    if (fs_prepare(db,&st,"SELECT request_json,created_at FROM file_share_operation WHERE id=?1")!=0) return NULL;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if (sqlite3_step(st)!=SQLITE_ROW) {sqlite3_finalize(st);return NULL;}
    struct json_object *items=json_tokener_parse(fs_sql_text(st,0,"[]"));
    int64_t created=sqlite3_column_int64(st,1); sqlite3_finalize(st);
    if (!items) return NULL;
    struct json_object *out=json_object_new_object(),*results=json_object_new_array();
    int successes=0,failures=0,unsafe=0;
    for(size_t i=0;i<json_object_array_length(items);i++) {
        struct json_object *item=json_object_array_get_idx(items,i),*r=json_object_new_object(),*value=NULL;
        json_object_object_add(r,"index",json_object_new_int(i));
        json_object_object_add(r,"protocol",json_object_new_string(fs_op_text(item,"protocol")));
        json_object_object_add(r,"action",json_object_new_string(fs_op_text(item,"action")));
        if(fs_prepare(db,&st,"SELECT success,result_json FROM file_share_operation_result WHERE operation_id=?1 AND item_index=?2")!=0) {json_object_put(r);goto fail;}
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,i);
        int step=sqlite3_step(st),success=0;
        if(step==SQLITE_ROW) {
            success=sqlite3_column_int(st,0);
            struct json_object *detail=json_tokener_parse(fs_sql_text(st,1,"{}"));
            if(success)successes++;else failures++;
            if(detail && json_object_object_get_ex(detail,"rollback_failed",&value) && json_object_get_boolean(value)) unsafe=1;
            json_object_object_add(r,"result",detail);
        } else if(step!=SQLITE_DONE){sqlite3_finalize(st);json_object_put(r);goto fail;}
        sqlite3_finalize(st);
        json_object_object_add(r,"state",json_object_new_string(step==SQLITE_ROW ? success?"success":"failed":"pending"));
        json_object_array_add(results,r);
    }
    json_object_object_add(out,"operation_id",json_object_new_string(id));
    json_object_object_add(out,"created_at",json_object_new_int64(created));
    json_object_object_add(out,"state",json_object_new_string(successes==(int)json_object_array_length(items)?"success":successes?"partial":failures?"failed":"pending"));
    json_object_object_add(out,"retry_allowed",json_object_new_boolean(!unsafe && successes!=(int)json_object_array_length(items)));
    json_object_object_add(out,"items",items);json_object_object_add(out,"results",results);
    return out;
fail:
    json_object_put(items);json_object_put(results);json_object_put(out);return NULL;
}

struct json_object *jmx_file_share_operation_request(const char *method,const char *id,struct json_object *req)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;int lock=-1;
    struct json_object *payload=fs_payload(req),*items=NULL,*current=NULL,*reply=NULL;
    int read=!strcmp(method,"GET"),retry=!strcmp(method,"RETRY");
    if(!read && !retry && strcmp(method,"POST"))return fs_error("invalid_action","operation_method_invalid");
    if(!read && !fs_confirmed(req))return fs_error("confirmation_required","confirm_true_required");
    if(!read && !retry)id=fs_op_text(payload,"request_id");
    if((!read || (id && *id)) && (!fs_id_ok(id) || strlen(id)<16))return fs_error("invalid_id","request_id_requires_16_to_64_safe_characters");
    if(fs_db_open(&db)!=0)return fs_error("storage_unavailable","config_db_open_failed");
    if(read && (!id || !*id)) {
        struct json_object *list=json_object_new_array();
        if(fs_prepare(db,&st,"SELECT id FROM file_share_operation ORDER BY created_at DESC,id LIMIT 50")!=0){json_object_put(list);goto out;}
        int step;
        while((step=sqlite3_step(st))==SQLITE_ROW) {
            struct json_object *one=fs_operation_read(db,fs_sql_text(st,0,""));
            if(!one){json_object_put(list);goto out;}
            json_object_array_add(list,one);
        }
        if(step!=SQLITE_DONE){json_object_put(list);goto out;}
        struct json_object *data=json_object_new_object();json_object_object_add(data,"items",list);reply=fs_success(data);goto out;
    }
    if(!read) {
        lock=open(JMX_FILE_OPERATIONS_LOCK,O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
        if(lock<0 || flock(lock,LOCK_EX|LOCK_NB)!=0){reply=fs_error("storage_busy","file_operation_in_progress");goto out;}
    }
    current=fs_operation_read(db,id);
    if(read || retry) {
        if(!current){reply=fs_error("not_found","file_operation_not_found");goto out;}
        if(read){reply=fs_success(current);current=NULL;goto out;}
        struct json_object *allowed=NULL;
        json_object_object_get_ex(current,"retry_allowed",&allowed);
        if(!json_object_get_boolean(allowed)){reply=fs_error("retry_not_allowed","complete_or_recovery_required");goto out;}
        json_object_object_get_ex(current,"items",&items);
    } else {
        if(!json_object_object_get_ex(payload,"items",&items) || !json_object_is_type(items,json_type_array) ||
           json_object_array_length(items)<1 || json_object_array_length(items)>4){reply=fs_error("invalid_request","one_to_four_protocol_operations_required");goto out;}
        for(size_t i=0;i<json_object_array_length(items);i++) {
            struct json_object *item=json_object_array_get_idx(items,i),*body=NULL;
            const char *protocol=fs_op_text(item,"protocol"),*action=fs_op_text(item,"action"),*key=fs_op_text(item,"id");
            if((strcmp(protocol,"samba") && strcmp(protocol,"nfs") && strcmp(protocol,"webdav") && strcmp(protocol,"ftp")) ||
               (strcmp(action,"create") && strcmp(action,"update") && strcmp(action,"delete")) ||
               !json_object_object_get_ex(item,"body",&body) || !json_object_is_type(body,json_type_object) ||
               (!strcmp(action,"create") ? *key!=0 : !fs_id_ok(key))){reply=fs_error("invalid_request","invalid_protocol_operation");goto out;}
            json_object_object_foreach(item,itemkey,itemvalue){(void)itemvalue;
                if(strcmp(itemkey,"protocol") && strcmp(itemkey,"action") && strcmp(itemkey,"id") && strcmp(itemkey,"body")) {
                    reply=fs_error("invalid_field",itemkey);goto out;
                }
            }
            /* Do not persist credentials or unknown fields in operation history. */
            json_object_object_foreach(body,k,v){(void)v;
                const char *keys=!strcmp(protocol,"samba") ? "|confirm|expected_revision|name|path|enabled|read_only|browseable|network_discovery|guest_access|allowed_users|read_only_users|note|" : !strcmp(protocol,"ftp") ? "|confirm|expected_revision|name|path|enabled|read_only|users|note|rebind|" : !strcmp(protocol,"webdav") ? "|confirm|expected_revision|name|path|enabled|read_only|listen_address|listen_port|tls|cert_file|key_file|users|note|" : "|confirm|expected_revision|path|enabled|clients|options|note|";
                char token[100];snprintf(token,sizeof token,"|%s|",k);
                if(strlen(k)>80 || !strstr(keys,token)){reply=fs_error("invalid_field",k);goto out;}
                if((!strcmp(protocol,"webdav") || !strcmp(protocol,"ftp")) && !strcmp(k,"users")){
                    if(!json_object_is_type(v,json_type_array)){reply=fs_error("invalid_acl","account_array_required");goto out;}
                    for(size_t a=0;a<json_object_array_length(v);a++){
                        struct json_object *entry=json_object_array_get_idx(v,a);
                        if(!json_object_is_type(entry,json_type_object)){reply=fs_error("invalid_acl","account_object_required");goto out;}
                        json_object_object_foreach(entry,field,value){(void)value;if(strcmp(field,"account_id") && strcmp(field,"read_only")){reply=fs_error("invalid_acl","unknown_account_field");goto out;}}
                    }
                }
            }
        }
        if(current) {
            struct json_object *old=NULL;json_object_object_get_ex(current,"items",&old);
            if(!json_object_equal(items,old)){reply=fs_error("revision_conflict","request_id_already_used_for_different_items");goto out;}
            reply=fs_success(current);current=NULL;goto out;
        }
        if(fs_prepare(db,&st,"INSERT INTO file_share_operation VALUES(?1,?2,?3)")!=0)goto out;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(st,2,json_object_to_json_string_ext(items,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
        sqlite3_bind_int64(st,3,fs_now_s());
        if(fs_step_done(st)!=0)goto out;
        sqlite3_finalize(st);st=NULL;
    }
    for(size_t i=0;i<json_object_array_length(items);i++) {
        if(fs_prepare(db,&st,"SELECT success FROM file_share_operation_result WHERE operation_id=?1 AND item_index=?2")!=0)goto out;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,i);
        int step=sqlite3_step(st),done=step==SQLITE_ROW && sqlite3_column_int(st,0);
        sqlite3_finalize(st);st=NULL;if(step!=SQLITE_ROW && step!=SQLITE_DONE)goto out;if(done)continue;
        struct json_object *item=json_object_array_get_idx(items,i),*body=NULL,*result,*data=NULL,*code=NULL;
        json_object_object_get_ex(item,"body",&body);
        struct json_object *args=json_tokener_parse(json_object_to_json_string_ext(body,JSON_C_TO_STRING_PLAIN));
        json_object_object_add(args,"confirm",json_object_new_boolean(1));
        const char *key=fs_op_text(item,"id"),*action=fs_op_text(item,"action");
        fs_operation_id=id;fs_operation_index=i;
        if(!strcmp(fs_op_text(item,"protocol"),"samba")) result=!strcmp(action,"delete")?jmx_samba_share_delete(key,args):jmx_samba_share_upsert(key,args);
        else if(!strcmp(fs_op_text(item,"protocol"),"webdav"))result=jmx_webdav_share_request(!strcmp(action,"create")?"POST":!strcmp(action,"delete")?"DELETE":"PUT",key,args);
        else if(!strcmp(fs_op_text(item,"protocol"),"ftp"))result=jmx_ftp_share_request(!strcmp(action,"create")?"POST":!strcmp(action,"delete")?"DELETE":"PUT",key,args);
        else result=!strcmp(action,"delete")?jmx_nfs_export_delete(key,args):jmx_nfs_export_upsert(key,args);
        fs_operation_id=NULL;json_object_put(args);
        json_object_object_get_ex(result,"code",&code);json_object_object_get_ex(result,"data",&data);
        int success=json_object_get_int(code)==FS_API_OK;
        if(!success && fs_operation_result(db,id,i,0,data)!=0){json_object_put(result);goto out;}
        struct json_object *unsafe=NULL;
        int halt=data && json_object_object_get_ex(data,"rollback_failed",&unsafe) && json_object_get_boolean(unsafe);
        json_object_put(result);if(halt)break;
    }
    struct json_object *final=fs_operation_read(db,id);
    if(final)reply=fs_success(final);
out:
    fs_operation_id=NULL;
    if(st)sqlite3_finalize(st);
    if(lock>=0)close(lock);
    if(current)json_object_put(current);
    if(db)sqlite3_close(db);
    return reply?reply:fs_error("storage_error","file_operation_failed");
}
