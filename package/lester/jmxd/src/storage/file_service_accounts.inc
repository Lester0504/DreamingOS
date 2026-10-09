/* Dedicated file-sharing identities. Included by file_services.c to reuse its
 * config_db transaction, command timeout and response contract. */
#include "ac/ac_secrets.h"
#include <grp.h>
#include <shadow.h>

#ifndef JMX_SHARE_SECRET_KEY_PATH
#define JMX_SHARE_SECRET_KEY_PATH "/etc/dreamingwrt/file-services.key"
#endif
#ifndef JMX_SHARE_USERADD_PATH
#define JMX_SHARE_USERADD_PATH "/usr/sbin/useradd"
#endif
#ifndef JMX_SHARE_USERDEL_PATH
#define JMX_SHARE_USERDEL_PATH "/usr/sbin/userdel"
#endif
#ifndef JMX_SHARE_SMBPASSWD_PATH
#define JMX_SHARE_SMBPASSWD_PATH "/usr/bin/smbpasswd"
#endif
#define FS_ACCOUNT_SHELL "/bin/false"
#define FS_ACCOUNT_HOME "/var/empty"

struct fs_account {
    char id[65], username[25], login[33], label[129];
    int enabled, uid, gid;
    int64_t revision, secret_version;
};

static int fs_accounts_schema(sqlite3 *db)
{
    return fs_sql_exec(db,
        "CREATE TABLE IF NOT EXISTS file_share_account("
        "id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,login TEXT NOT NULL UNIQUE,"
        "label TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),"
        "uid INTEGER NOT NULL,gid INTEGER NOT NULL,revision INTEGER NOT NULL,"
        "secret_version INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);");
}

static int fs_account_tools(void)
{
    return access(JMX_SHARE_USERADD_PATH,X_OK)==0 && access(JMX_SHARE_USERDEL_PATH,X_OK)==0 &&
        access(JMX_SHARE_SMBPASSWD_PATH,X_OK)==0 && access(JMX_SAMBA_PDBEDIT_PATH,X_OK)==0 &&
        access(FS_ACCOUNT_SHELL,X_OK)==0;
}

static int fs_account_name_ok(const char *s)
{
    if (!s || !*s || strlen(s)>24 || s[0]<'a' || s[0]>'z') return 0;
    for (const char *p=s;*p;p++)
        if (!(*p>='a'&&*p<='z') && !(*p>='0'&&*p<='9') && *p!='_') return 0;
    return 1;
}

static int fs_account_load(sqlite3 *db,const char *id,struct fs_account *a)
{
    sqlite3_stmt *st=NULL;int rc=-1;
    memset(a,0,sizeof(*a));
    if(fs_prepare(db,&st,"SELECT id,username,login,label,enabled,uid,gid,revision,secret_version FROM file_share_account WHERE id=?1")!=0)return -1;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    int step=sqlite3_step(st);
    if(step==SQLITE_ROW){
        snprintf(a->id,sizeof a->id,"%s",fs_sql_text(st,0,""));
        snprintf(a->username,sizeof a->username,"%s",fs_sql_text(st,1,""));
        snprintf(a->login,sizeof a->login,"%s",fs_sql_text(st,2,""));
        snprintf(a->label,sizeof a->label,"%s",fs_sql_text(st,3,""));
        a->enabled=sqlite3_column_int(st,4);a->uid=sqlite3_column_int(st,5);a->gid=sqlite3_column_int(st,6);
        a->revision=sqlite3_column_int64(st,7);a->secret_version=sqlite3_column_int64(st,8);rc=1;
    }else if(step==SQLITE_DONE)rc=0;
    sqlite3_finalize(st);return rc;
}

static int fs_account_owned(const struct fs_account *a,int check_uid)
{
    char marker[100];snprintf(marker,sizeof marker,"DreamingWrt share %s",a->id);
    struct passwd *pw=getpwnam(a->login);
    if(!pw || !pw->pw_uid || !pw->pw_gid || strcmp(pw->pw_gecos,marker) || strcmp(pw->pw_shell,FS_ACCOUNT_SHELL) ||
       strcmp(pw->pw_dir,FS_ACCOUNT_HOME) || (check_uid && (pw->pw_uid!=(uid_t)a->uid || pw->pw_gid!=(gid_t)a->gid)))return 0;
    struct spwd *sp=getspnam(a->login);
    return sp && sp->sp_pwdp && (sp->sp_pwdp[0]=='!' || sp->sp_pwdp[0]=='*');
}

/* Password input is an anonymous pipe, never argv, environment or log output. */
static int fs_account_exec(char *const argv[],const unsigned char *secret,size_t len)
{
    if(!secret){struct fs_exec_result r={0};return fs_exec_argv(argv,FS_SERVICE_TIMEOUT_MS,NULL,0,&r);}
    int input[2],output[2],rc;pid_t pid;struct fs_exec_result result={0};
    if(len>128 || pipe(input)!=0)return -1;
    if(pipe(output)!=0){close(input[0]);close(input[1]);return -1;}
    for(int i=0;i<2;i++){fcntl(input[i],F_SETFD,FD_CLOEXEC);fcntl(output[i],F_SETFD,FD_CLOEXEC);}
    if(fs_write_all(input[1],secret,len)||fs_write_all(input[1],"\n",1)||
       fs_write_all(input[1],secret,len)||fs_write_all(input[1],"\n",1)){rc=-1;goto close_all;}
    close(input[1]);input[1]=-1;
    pid=fork();
    if(pid<0){rc=-1;goto close_all;}
    if(!pid){
        dup2(input[0],STDIN_FILENO);dup2(output[1],STDOUT_FILENO);dup2(output[1],STDERR_FILENO);
        close(input[0]);close(output[0]);close(output[1]);
        clearenv();setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);setenv("LANG","C",1);setenv("LC_ALL","C",1);
        execv(argv[0],argv);_exit(127);
    }
    close(input[0]);input[0]=-1;close(output[1]);output[1]=-1;
    fcntl(output[0],F_SETFL,fcntl(output[0],F_GETFL,0)|O_NONBLOCK);
    rc=fs_wait_child(pid,output[0],FS_SERVICE_TIMEOUT_MS,NULL,0,&result);
close_all:
    for(int i=0;i<2;i++){if(input[i]>=0)close(input[i]);if(output[i]>=0)close(output[i]);}
    return rc;
}

static int fs_account_samba(const struct fs_account *a,const unsigned char *password,size_t length)
{
    char *set[]={JMX_SHARE_SMBPASSWD_PATH,"-s","-a",(char *)a->login,NULL};
    char *flag[]={JMX_SHARE_SMBPASSWD_PATH,a->enabled?"-e":"-d",(char *)a->login,NULL};
    return (password && fs_account_exec(set,password,length)!=0) ? -1 : fs_account_exec(flag,NULL,0);
}

static int fs_account_create_os(struct fs_account *a,int restore)
{
    char marker[100],uid[24],gid[24];
    snprintf(marker,sizeof marker,"DreamingWrt share %s",a->id);
    snprintf(uid,sizeof uid,"%d",a->uid);snprintf(gid,sizeof gid,"%d",a->gid);
    /* A fixed existing group avoids creating/deleting groups owned by another subsystem. */
    char *args[]={JMX_SHARE_USERADD_PATH,"-M","-N","-g",gid,"-s",FS_ACCOUNT_SHELL,
        "-d",FS_ACCOUNT_HOME,"-c",marker,restore?"-u":a->login,restore?uid:NULL,restore?a->login:NULL,NULL};
    if(getpwnam(a->login) || fs_account_exec(args,NULL,0)!=0 || !fs_account_owned(a,restore))return -1;
    struct passwd *pw=getpwnam(a->login);a->uid=pw->pw_uid;a->gid=pw->pw_gid;return 0;
}

static int fs_account_remove_os(const struct fs_account *a)
{
    if(!fs_account_owned(a,1))return -1;
    char *del[]={JMX_SHARE_USERDEL_PATH,(char *)a->login,NULL};
    return fs_account_exec(del,NULL,0)==0 && !getpwnam(a->login) ? 0 : -1;
}

static struct json_object *fs_account_references(sqlite3 *db,const char *login,int broad)
{
    struct json_object *refs=json_object_new_array();sqlite3_stmt *st=NULL;
    if(fs_prepare(db,&st,"SELECT id,name,guest_access,allowed_users_json FROM samba_share")!=0){json_object_put(refs);return NULL;}
    int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        struct json_object *users=fs_json_array_text(fs_sql_text(st,3,"[]"));
        int match=broad && !sqlite3_column_int(st,2) && json_object_array_length(users)==0;
        for(size_t i=0;login && i<json_object_array_length(users);i++)
            if(!strcmp(login,json_object_get_string(json_object_array_get_idx(users,i))))match=1;
        if(match){struct json_object *r=json_object_new_object();
            json_object_object_add(r,"protocol",json_object_new_string("samba"));
            json_object_object_add(r,"id",json_object_new_string(fs_sql_text(st,0,"")));
            json_object_object_add(r,"name",json_object_new_string(fs_sql_text(st,1,"")));json_object_array_add(refs,r);}
        json_object_put(users);
    }
    sqlite3_finalize(st);if(step!=SQLITE_DONE || (fs_dav_account_refs(db,login,refs)!=0 || fs_ftp_account_refs(db,login,refs)!=0)){json_object_put(refs);return NULL;}return refs;
}

static int fs_account_samba_present(const char *login)
{
    char output[FS_SERVICE_OUTPUT_MAX],*save=NULL,*line;struct fs_exec_result r={0};
    char *argv[]={JMX_SAMBA_PDBEDIT_PATH,"-L",NULL};
    if(fs_exec_argv(argv,3000,output,sizeof output,&r)!=0 || r.output_truncated)return -1;
    for(line=strtok_r(output,"\n",&save);line;line=strtok_r(NULL,"\n",&save))
        if(!strncmp(line,login,strlen(login)) && line[strlen(login)]==':')return 1;
    return 0;
}

static struct json_object *fs_accounts_data(sqlite3 *db)
{
    struct json_object *data=json_object_new_object(),*items=json_object_new_array(),*caps=json_object_new_object();
    struct json_object *subjects_data=json_object_new_object(),*subjects=NULL,*known=NULL;
    /* One bounded passdb query per read, rather than one subprocess per account. */
    fs_subjects_read(subjects_data);
    json_object_object_get_ex(subjects_data,"subjects",&subjects);
    json_object_object_get_ex(subjects_data,"subjects_known",&known);
    sqlite3_stmt *st=NULL;
    if(fs_prepare(db,&st,"SELECT id FROM file_share_account ORDER BY username")!=0)goto fail;
    int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        struct fs_account a;if(fs_account_load(db,fs_sql_text(st,0,""),&a)!=1)goto fail;
        struct json_object *item=json_object_new_object(),*refs=fs_account_references(db,a.login,0);
        if(!refs){json_object_put(item);goto fail;}
        json_object_object_add(item,"id",json_object_new_string(a.id));
        json_object_object_add(item,"username",json_object_new_string(a.username));
        json_object_object_add(item,"login",json_object_new_string(a.login));
        json_object_object_add(item,"label",json_object_new_string(a.label));
        json_object_object_add(item,"enabled",json_object_new_boolean(a.enabled));
        json_object_object_add(item,"revision",json_object_new_int64(a.revision));
        json_object_object_add(item,"has_password",json_object_new_boolean(a.secret_version>0));
        json_object_object_add(item,"system_uid",json_object_new_int(a.uid));
        json_object_object_add(item,"shell",json_object_new_string(FS_ACCOUNT_SHELL));
        json_object_object_add(item,"identity_ready",json_object_new_boolean(fs_account_owned(&a,1)));
        int samba_present=0;
        for(size_t i=0;i<json_object_array_length(subjects);i++){
            struct json_object *entry=json_object_array_get_idx(subjects,i),*login=NULL;
            if(json_object_object_get_ex(entry,"username",&login) && !strcmp(a.login,json_object_get_string(login)))samba_present=1;
        }
        json_object_object_add(item,"samba_account_present",json_object_get_boolean(known)?json_object_new_boolean(samba_present):NULL);
        json_object_object_add(item,"references",refs);
        json_object_array_add(items,item);
    }
    if(step!=SQLITE_DONE)goto fail;
    sqlite3_finalize(st);st=NULL;
    struct json_object *broad=fs_account_references(db,NULL,1);
    if(!broad)goto fail;
    json_object_object_add(data,"items",items);
    json_object_object_add(caps,"manage",json_object_new_boolean(fs_account_tools()));
    json_object_object_add(data,"capabilities",caps);
    json_object_object_add(data,"required_role",json_object_new_string("owner"));
    json_object_object_add(data,"source",json_object_new_string("config_db"));
    json_object_object_add(data,"model",json_object_new_string("dedicated_locked_system_identity"));
    json_object_object_add(data,"unrestricted_private_shares",broad);
    json_object_put(subjects_data);
    return data;
fail:
    if(st)sqlite3_finalize(st);
    json_object_put(subjects_data);json_object_put(data);json_object_put(items);json_object_put(caps);
    return NULL;
}

struct json_object *jmx_file_service_accounts_request(const char *method,const char *id,struct json_object *req)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct ac_secrets *secrets=NULL;
    struct json_object *payload=fs_payload(req),*response=NULL,*data=NULL,*refs=NULL;
    struct fs_snapshot dav_old={0};int dav_replaced=0,dav_running=0,dav_refs=0;
    struct fs_snapshot ftp_old={0};int ftp_replaced=0,ftp_running=0,ftp_refs=0;
    struct fs_account old={0},next={0};unsigned char *old_secret=NULL;size_t old_len=0;
    const char *password=NULL,*username=NULL,*label=NULL;int present=0,enabled=0,tx=0,creation_attempted=0,samba_touched=0,removed_os=0,was_running=0,samba_was_present=0;
    int create=!strcmp(method,"POST"),remove=!strcmp(method,"DELETE");int64_t expected=0;
    char secret_id[96];const char *error="storage_error",*reason="account_transaction_failed";
    if(fs_db_open(&db)!=0)return fs_error("storage_unavailable","config_db_open_failed");
    if(!strcmp(method,"GET")){data=fs_accounts_data(db);response=data?fs_success(data):fs_error("storage_error","account_read_failed");goto out;}
    if(!create && !remove && strcmp(method,"PUT")){response=fs_error("invalid_action","account_method_invalid");goto out;}
    if(!payload || !json_object_is_type(payload,json_type_object)){response=fs_error("invalid_request","request_object_required");goto out;}
    if(!fs_confirmed(req)){response=fs_error("confirmation_required","confirm_true_required");goto out;}
    if(!fs_account_tools()){response=fs_error("runtime_not_installed","account_tools_missing");goto out;}
    if(!create && (!fs_id_ok(id) || fs_json_positive_int64(payload,"expected_revision",&expected,&present)!=0 || !present)){
        response=fs_error("missing_expected_revision","account_revision_required");goto out;}
    json_object_object_foreach(payload,key,value){(void)value;
        if(strcmp(key,"confirm")&&strcmp(key,"expected_revision")&&strcmp(key,"username")&&strcmp(key,"label")&&strcmp(key,"enabled")&&strcmp(key,"password")){
            response=fs_error("invalid_field",key);goto out;}}
    if(fs_sql_exec(db,"BEGIN IMMEDIATE")!=0){response=fs_error("storage_busy","account_operation_in_progress");goto out;}tx=1;
    if(create){
        if(fs_json_string(payload,"username",&username,&present)!=0 || !present || !fs_account_name_ok(username)){
            response=fs_error("invalid_username","use_1_to_24_lowercase_letters_digits_underscore");goto out;}
        if(fs_random_id(db,"share","file_share_account",next.id,sizeof next.id)!=0)goto out;
        snprintf(next.username,sizeof next.username,"%s",username);snprintf(next.login,sizeof next.login,"dwshare_%s",username);
        struct group *group=getgrnam("nogroup");if(!group || group->gr_gid==0){response=fs_error("dependency_unavailable","unprivileged_nogroup_required");goto out;}next.gid=group->gr_gid;
        if(getpwnam(next.login)){response=fs_error("account_exists","dedicated_login_already_exists");goto out;}
        if(fs_prepare(db,&st,"SELECT 1 FROM file_share_account WHERE username=?1 OR login=?2")!=0)goto out;
        sqlite3_bind_text(st,1,next.username,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,next.login,-1,SQLITE_TRANSIENT);
        int duplicate=sqlite3_step(st);sqlite3_finalize(st);st=NULL;
        if(duplicate==SQLITE_ROW){response=fs_error("account_exists","dedicated_account_already_exists");goto out;}
        if(duplicate!=SQLITE_DONE)goto out;
        next.enabled=1;next.revision=1;next.secret_version=1;
        refs=fs_account_references(db,NULL,1);
        if(!refs)goto out;
        if(json_object_array_length(refs)){data=fs_error_detail("explicit_acl_required","restrict_existing_private_shares_before_creating_accounts");json_object_object_add(data,"affected_shares",refs);refs=NULL;response=fs_envelope(FS_API_ERROR,data);goto out;}
    }else{
        int found=fs_account_load(db,id,&old);if(found!=1){response=fs_error(found?"storage_error":"not_found","share_account_not_found");goto out;}
        next=old;if(old.revision!=expected){response=fs_revision_conflict("share_account_changed",expected,old.revision);goto out;}
        if(!fs_account_owned(&old,1)){response=fs_error("identity_conflict","dedicated_system_identity_changed");goto out;}
        if(fs_json_string(payload,"username",&username,&present)!=0 || (present && strcmp(username,old.username))){response=fs_error("invalid_username","account_login_is_immutable");goto out;}
        refs=fs_account_references(db,old.login,0);if(!refs)goto out;
        for(size_t i=0;i<json_object_array_length(refs);i++){
            struct json_object *protocol=NULL;json_object_object_get_ex(json_object_array_get_idx(refs,i),"protocol",&protocol);
            if(protocol && !strcmp(json_object_get_string(protocol),"webdav"))dav_refs=1;
            if(protocol && !strcmp(json_object_get_string(protocol),"ftp"))ftp_refs=1;
        }
        if(remove && json_object_array_length(refs)){data=fs_error_detail("account_in_use","remove_explicit_share_references_first");json_object_object_add(data,"references",refs);refs=NULL;response=fs_envelope(FS_API_ERROR,data);goto out;}
        next.revision++;
    }
    if(fs_json_string(payload,"label",&label,&present)!=0 || (present&&!fs_text_ok(label,128,0))){response=fs_error("invalid_label","account_label_invalid");goto out;}
    if(present)snprintf(next.label,sizeof next.label,"%s",label);
    if(fs_json_bool(payload,"enabled",&enabled,&present)!=0){response=fs_error("invalid_boolean","enabled_must_be_boolean");goto out;}if(present)next.enabled=enabled;
    if(fs_json_string(payload,"password",&password,&present)!=0 || (create && !present) ||
       (present && (!fs_text_ok(password,128,1)||strlen(password)<12))){response=fs_error("invalid_password","password_requires_12_to_128_bytes_without_line_breaks");goto out;}
    if(ac_secrets_schema_init(db)!=AC_SECRETS_OK ||
       ac_secrets_open_or_create(db,JMX_SHARE_SECRET_KEY_PATH,&secrets)!=AC_SECRETS_OK){response=fs_error("credential_store_unavailable","share_secret_store_unavailable");goto out;}
    snprintf(secret_id,sizeof secret_id,"file-share:%s",next.id);
    if(!create && ac_secrets_get(secrets,secret_id,old.secret_version,&old_secret,&old_len)!=AC_SECRETS_OK){response=fs_error("credential_store_unavailable","old_credential_required_for_rollback");goto out;}
    if(!create && password)next.secret_version++;
    samba_was_present=fs_account_samba_present(next.login);
    if(samba_was_present<0){response=fs_error("credential_probe_failed","samba_account_list_unavailable");goto out;}
    if(create && samba_was_present){response=fs_error("account_exists","samba_login_already_exists");goto out;}
    if(create){
        creation_attempted=1;
        if(fs_account_create_os(&next,0)!=0){error="identity_apply_failed";reason="dedicated_user_creation_failed";goto rollback;}
    }
    if(remove){char *del[]={JMX_SHARE_SMBPASSWD_PATH,"-x",next.login,NULL};samba_touched=1;
        if((samba_was_present && fs_account_exec(del,NULL,0)!=0) || fs_account_samba_present(next.login)!=0){error="credential_apply_failed";reason="samba_account_delete_failed";goto rollback;}
        int removed=fs_account_remove_os(&old);removed_os=getpwnam(old.login)==NULL;
        if(removed!=0){error="identity_apply_failed";reason="dedicated_user_delete_failed";goto rollback;}
    }else{
        samba_touched=1;
        if(fs_account_samba(&next,(const unsigned char *)password,password?strlen(password):0)!=0 || fs_account_samba_present(next.login)!=1){
            error="credential_apply_failed";reason="samba_credential_apply_failed";goto rollback;}
    }
    /* Reset SMB sessions when credentials or enabled state change. No SSH action. */
    if(!create && (remove || password || next.enabled!=old.enabled)){
        was_running=fs_control_running("samba");
        if(was_running){struct fs_exec_result r={0};if(fs_service_action(JMX_SAMBA_INIT_PATH,"restart",&r)!=0 || fs_samba_runtime_probe(db,&r)!=0){error="service_apply_failed";reason="samba_session_reset_failed";goto rollback;}}
    }
    if(remove){
        if(ac_secrets_delete(secrets,secret_id)!=AC_SECRETS_OK || fs_prepare(db,&st,"DELETE FROM file_share_account WHERE id=?1")!=0)goto rollback;
        sqlite3_bind_text(st,1,old.id,-1,SQLITE_TRANSIENT);
    }else{
        if(password && ac_secrets_put(secrets,secret_id,next.secret_version,(const unsigned char *)password,strlen(password))!=AC_SECRETS_OK)goto rollback;
        if(fs_prepare(db,&st,"INSERT INTO file_share_account(id,username,login,label,enabled,uid,gid,revision,secret_version,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) ON CONFLICT(id) DO UPDATE SET label=excluded.label,enabled=excluded.enabled,revision=excluded.revision,secret_version=excluded.secret_version,updated_at=excluded.updated_at")!=0)goto rollback;
        sqlite3_bind_text(st,1,next.id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,next.username,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,next.login,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,next.label,-1,SQLITE_TRANSIENT);
        sqlite3_bind_int(st,5,next.enabled);sqlite3_bind_int(st,6,next.uid);sqlite3_bind_int(st,7,next.gid);sqlite3_bind_int64(st,8,next.revision);sqlite3_bind_int64(st,9,next.secret_version);sqlite3_bind_int64(st,10,fs_now_s());
    }
    if(fs_step_done(st)!=0)goto rollback;
    sqlite3_finalize(st);st=NULL;
    if(dav_refs && (password || next.enabled!=old.enabled)){
        dav_running=fs_dav_wants_running(db);
        if(fs_dav_apply(db,&dav_old,&dav_replaced,dav_running,&reason)!=0){error="webdav_credential_apply_failed";goto rollback;}
    }
    if(ftp_refs && (password || next.enabled!=old.enabled)){
        ftp_running=fs_ftp_running();
        if(fs_ftp_apply(db,&ftp_old,&ftp_replaced,fs_ftp_wants_running(db),&reason)!=0){error="ftp_credential_apply_failed";goto rollback;}
    }
    if(fs_meta_bump(db)!=0 || fs_sql_exec(db,"COMMIT")!=0)goto rollback;tx=0;
    data=json_object_new_object();json_object_object_add(data,"id",json_object_new_string(next.id));json_object_object_add(data,"login",json_object_new_string(next.login));
    json_object_object_add(data,"revision",json_object_new_int64(next.revision));json_object_object_add(data,"persisted",json_object_new_boolean(1));json_object_object_add(data,"applied",json_object_new_boolean(1));json_object_object_add(data,"deleted",json_object_new_boolean(remove));
    json_object_object_add(data,"samba_sessions_reset",json_object_new_boolean(was_running));response=fs_success(data);goto out;
rollback: {
    if(st){sqlite3_finalize(st);st=NULL;}int restored=1;
    if(create){
        if(samba_touched){char *del[]={JMX_SHARE_SMBPASSWD_PATH,"-x",next.login,NULL};fs_account_exec(del,NULL,0);if(fs_account_samba_present(next.login)!=0)restored=0;}
        if(creation_attempted){struct passwd *pw=getpwnam(next.login);if(pw){
            next.uid=pw->pw_uid;next.gid=pw->pw_gid;
            if(fs_account_remove_os(&next)!=0)restored=0;
        }}
    }else{
        if(removed_os && fs_account_create_os(&old,1)!=0)restored=0;
        if(samba_touched){
            if(!fs_account_owned(&old,1))restored=0;
            else if(samba_was_present){if(fs_account_samba(&old,old_secret,old_len)!=0)restored=0;}
            else {char *del[]={JMX_SHARE_SMBPASSWD_PATH,"-x",old.login,NULL};
                fs_account_exec(del,NULL,0);if(fs_account_samba_present(old.login)!=0)restored=0;}
        }
        if(was_running){struct fs_exec_result r={0};if(fs_service_action(JMX_SAMBA_INIT_PATH,"restart",&r)!=0 || fs_samba_runtime_probe(db,&r)!=0)restored=0;}
    }
    if(fs_dav_restore(&dav_old,dav_replaced,dav_running)!=0)restored=0;
    if(fs_ftp_restore(&ftp_old,ftp_replaced,ftp_running)!=0)restored=0;
    int db_ok=fs_sql_exec(db,"ROLLBACK")==0;tx=0;
    data=fs_error_detail(error,reason);json_object_object_add(data,"rolled_back",json_object_new_boolean(restored&&db_ok));json_object_object_add(data,"rollback_failed",json_object_new_boolean(!restored||!db_ok));json_object_object_add(data,"db_rolled_back",json_object_new_boolean(db_ok));response=fs_envelope(FS_API_ERROR,data);
}
out:
    if(st)sqlite3_finalize(st);
    if(tx)fs_sql_exec(db,"ROLLBACK");
    if(refs)json_object_put(refs);
    fs_snapshot_free(&dav_old);fs_snapshot_free(&ftp_old);
    ac_secrets_clear(old_secret,old_len);ac_secrets_close(secrets);
    if(db)sqlite3_close(db);
    return response?response:fs_error("storage_error","share_account_operation_failed");
}
