/* Per-share WebDAV sandboxes. config_db owns specs; nginx files are projections.
 * Each worker sees one bind-mounted data directory and its own runtime files. */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#ifndef JMX_DAV_BASE
#define JMX_DAV_BASE "/etc/dreamingwrt/webdav"
#endif
#ifndef JMX_DAV_RUN
#define JMX_DAV_RUN "/var/run/dreamingwrt-webdav"
#endif
#ifndef JMX_DAV_INIT
#define JMX_DAV_INIT "/etc/init.d/dreamingwrt-webdav"
#endif
#define FS_DAV_MODULE "/usr/lib/dreamingwrt/webdav/ngx_http_dav_ext_module.so"
#ifndef JMX_DAV_TIMEOUT_MS
#define JMX_DAV_TIMEOUT_MS 30000
#endif

/* Shared by the DAV and FTP projections: never operate on a truncated path. */
static int fs_service_path_join(char *out,size_t size,const char *dir,const char *name)
{
    size_t dir_len=strlen(dir),name_len=strlen(name);
    if(size<2 || dir_len>size-2 || name_len>size-dir_len-2){
        errno=ENAMETOOLONG;return -1;
    }
    memcpy(out,dir,dir_len);out[dir_len]='/';
    memcpy(out+dir_len+1,name,name_len+1);return 0;
}

static int fs_dav_schema(sqlite3 *db)
{
    return fs_sql_exec(db,"CREATE TABLE IF NOT EXISTS webdav_share("
        "id TEXT PRIMARY KEY,spec_json TEXT NOT NULL,revision INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS webdav_service_error(id INTEGER PRIMARY KEY,error TEXT NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS webdav_service_intent(id INTEGER PRIMARY KEY,running INTEGER NOT NULL,boot TEXT NOT NULL);");
}

static int fs_dav_module_ready(void)
{
    static const char marker[]="dreamingwrt-dav-ext-nofollow-v1";
    unsigned char buffer[4096+sizeof marker];size_t carry=0,n;int found=0;
    FILE *fp=fopen(FS_DAV_MODULE,"rb");if(!fp)return 0;
    while((n=fread(buffer+carry,1,4096,fp))>0){
        size_t size=carry+n;
        if(memmem(buffer,size,marker,sizeof marker-1)){found=1;break;}
        carry=size<sizeof marker?size:sizeof marker;memmove(buffer,buffer+size-carry,carry);
    }
    fclose(fp);return found;
}

static int fs_dav_installed(void)
{
    return access("/sbin/ujail",X_OK)==0 && access("/usr/sbin/nginx",X_OK)==0 &&
        fs_dav_module_ready() && access(JMX_DAV_INIT,X_OK)==0;
}

static int fs_dav_bool(struct json_object *o,const char *key)
{
    struct json_object *v=NULL;json_object_object_get_ex(o,key,&v);return json_object_get_boolean(v);
}

static int64_t fs_dav_int(struct json_object *o,const char *key)
{
    struct json_object *v=NULL;json_object_object_get_ex(o,key,&v);return json_object_get_int64(v);
}

static const char *fs_dav_str(struct json_object *o,const char *key)
{
    struct json_object *v=NULL;json_object_object_get_ex(o,key,&v);
    return v && json_object_is_type(v,json_type_string)?json_object_get_string(v):"";
}

static int fs_dav_path_text(const char *s)
{
    return s && s[0]=='/' && fs_text_ok(s,FS_MAX_PATH,1) && !strpbrk(s,"\"\\$;{}") && !fs_path_has_dotdot(s);
}

static int fs_dav_binding(struct json_object *spec)
{
    char canonical[FS_MAX_PATH+1];struct stat st;
    const char *path=fs_dav_str(spec,"path");
    struct json_object *identity=NULL;
    if(json_object_object_get_ex(spec,"storage_binding",&identity)){
        struct json_object *now=fs_binding_identity(path);int ok=fs_binding_equal(identity,now);json_object_put(now);return ok;
    }
    return fs_share_path_ok(path,canonical,sizeof canonical) && !strcmp(path,canonical) &&
        stat(path,&st)==0 && (int64_t)st.st_dev==fs_dav_int(spec,"device") && (int64_t)st.st_ino==fs_dav_int(spec,"inode");
}

static struct json_object *fs_dav_load(sqlite3 *db,const char *id,int64_t *revision)
{
    sqlite3_stmt *st=NULL;struct json_object *spec=NULL;
    if(fs_prepare(db,&st,"SELECT spec_json,revision FROM webdav_share WHERE id=?1")!=0)return NULL;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)==SQLITE_ROW){spec=json_tokener_parse(fs_sql_text(st,0,"{}"));*revision=sqlite3_column_int64(st,1);}
    sqlite3_finalize(st);return spec;
}

static int fs_dav_worker_running(const char *id,struct json_object *spec)
{
    char path[PATH_MAX],text[80];long pid=0;
    /* ujail writes its child's host PID; nginx.pid contains namespace PID 1. */
    snprintf(path,sizeof path,JMX_DAV_RUN "/%s/data/host.pid",id);
    FILE *fp=fopen(path,"r");if(!fp)return 0;
    int parsed=fscanf(fp,"%ld",&pid)==1;fclose(fp);if(!parsed || pid<=1)return 0;
    snprintf(path,sizeof path,"/proc/%ld/comm",pid);fp=fopen(path,"r");
    if(!fp)return 0;char *got=fgets(text,sizeof text,fp);fclose(fp);if(!got || strcmp(text,"nginx\n"))return 0;
    char published[FS_MAX_PATH+1];fs_binding_target(id,published,sizeof published);
    snprintf(path,sizeof path,"/proc/%ld/root%s",pid,published);
    struct stat st;
    if(stat(path,&st)!=0){
        /* Existing sandboxes from the preceding version used the source path. */
        snprintf(path,sizeof path,"/proc/%ld/root%s",pid,fs_dav_str(spec,"path"));
        if(stat(path,&st)!=0)return 0;
    }
    struct json_object *identity=NULL;
    if(json_object_object_get_ex(spec,"storage_binding",&identity)){
        struct statfs fs;char fsid[80];
        if(statfs(path,&fs)!=0)return 0;
        snprintf(fsid,sizeof fsid,"%08x:%08x",(unsigned)fs.f_fsid.__val[0],(unsigned)fs.f_fsid.__val[1]);
        if((int64_t)st.st_ino!=fs_dav_int(identity,"inode") || strcmp(fsid,fs_dav_str(identity,"fsid")))return 0;
    }else if((int64_t)st.st_dev!=fs_dav_int(spec,"device") || (int64_t)st.st_ino!=fs_dav_int(spec,"inode"))return 0;
    snprintf(path,sizeof path,JMX_DAV_RUN "/%s/auth/host.pid",id);
    fp=fopen(path,"r");if(!fp)return 0;parsed=fscanf(fp,"%ld",&pid)==1;fclose(fp);if(!parsed || pid<=1)return 0;
    snprintf(path,sizeof path,"/proc/%ld/comm",pid);fp=fopen(path,"r");if(!fp)return 0;
    got=fgets(text,sizeof text,fp);fclose(fp);if(!got || strcmp(text,"nginx\n"))return 0;
    /* A process alone is not a ready service: require its own listening socket. */
    fp=fopen("/proc/net/tcp","r");if(!fp)return 0;
    char line[512];unsigned address,port,state;unsigned long long inode=0;
    struct in_addr wanted;inet_pton(AF_INET,fs_dav_str(spec,"listen_address"),&wanted);
    while(fgets(line,sizeof line,fp)){
        unsigned long long candidate=0;
        if(sscanf(line," %*u: %x:%x %*s %x %*s %*s %*s %*u %*u %llu",&address,&port,&state,&candidate)==4 &&
           address==wanted.s_addr && port==(unsigned)fs_dav_int(spec,"listen_port") && state==10){inode=candidate;break;}
    }
    fclose(fp);if(!inode)return 0;
    snprintf(path,sizeof path,"/proc/%ld/fd",pid);DIR *fds=opendir(path);if(!fds)return 0;
    struct dirent *entry;int found=0;char target[80],expected[80],fdpath[PATH_MAX];
    snprintf(expected,sizeof expected,"socket:[%llu]",inode);
    while((entry=readdir(fds))){
        if(fs_service_path_join(fdpath,sizeof fdpath,path,entry->d_name)!=0)continue;
        ssize_t n=readlink(fdpath,target,sizeof target-1);
        if(n>0){target[n]='\0';if(!strcmp(target,expected)){found=1;break;}}
    }
    closedir(fds);return found;
}

static int fs_dav_port_available(const char *id,struct json_object *spec)
{
    if(fs_dav_worker_running(id,spec))return 1;
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return 0;
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(fs_dav_int(spec,"listen_port"))};
    inet_pton(AF_INET,fs_dav_str(spec,"listen_address"),&address.sin_addr);
    int ok=bind(fd,(struct sockaddr *)&address,sizeof address)==0;close(fd);return ok;
}

static void fs_dav_save_error(sqlite3 *db,const char *reason,int64_t revision)
{
    sqlite3_stmt *st=NULL;
    if(fs_prepare(db,&st,"INSERT INTO webdav_service_error SELECT 1,?1,?2 WHERE EXISTS(SELECT 1 FROM file_service_meta WHERE id=1 AND revision=?3) ON CONFLICT(id) DO UPDATE SET error=excluded.error,updated_at=excluded.updated_at")!=0)return;
    sqlite3_bind_text(st,1,reason,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,fs_now_s());sqlite3_bind_int64(st,3,revision);sqlite3_step(st);sqlite3_finalize(st);
}

static int fs_dav_command(const char *action,struct fs_exec_result *result)
{
    char *argv[]={JMX_DAV_INIT,(char *)action,NULL};
    return fs_exec_argv(argv,JMX_DAV_TIMEOUT_MS,NULL,0,result);
}

static int fs_dav_any_running(sqlite3 *db)
{
    sqlite3_stmt *st=NULL;int running=0;
    if(fs_prepare(db,&st,"SELECT id,spec_json FROM webdav_share")!=0)return 0;
    while(sqlite3_step(st)==SQLITE_ROW){struct json_object *spec=json_tokener_parse(fs_sql_text(st,1,"{}"));
        if(spec && fs_dav_worker_running(fs_sql_text(st,0,""),spec))running=1;json_object_put(spec);}
    sqlite3_finalize(st);return running;
}

static int fs_dav_boot(char *boot,size_t size)
{
    FILE *fp=fopen("/proc/sys/kernel/random/boot_id","re");if(!fp)return -1;
    char *got=fgets(boot,size,fp);fclose(fp);if(!got)return -1;
    boot[strcspn(boot,"\r\n")]='\0';return 0;
}

static int fs_dav_intent_set(sqlite3 *db,int running)
{
    char boot[80];sqlite3_stmt *st=NULL;if(fs_dav_boot(boot,sizeof boot)!=0)return -1;
    if(fs_prepare(db,&st,"INSERT INTO webdav_service_intent VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET running=excluded.running,boot=excluded.boot WHERE running<>excluded.running OR boot<>excluded.boot")!=0)return -1;
    sqlite3_bind_int(st,1,running);sqlite3_bind_text(st,2,boot,-1,SQLITE_TRANSIENT);
    int rc=fs_step_done(st);sqlite3_finalize(st);return rc;
}

static int fs_dav_wants_running(sqlite3 *db)
{
    char boot[80];sqlite3_stmt *st=NULL;int wanted=-1,known=0;
    if(fs_dav_boot(boot,sizeof boot)==0 && fs_prepare(db,&st,"SELECT running,boot FROM webdav_service_intent WHERE id=1")==0 && sqlite3_step(st)==SQLITE_ROW){
        known=1;if(!strcmp(boot,fs_sql_text(st,1,"")))wanted=sqlite3_column_int(st,0);
    }
    if(st)sqlite3_finalize(st);
    if(wanted>=0)return wanted;
    struct fs_exec_result result={0};
    return fs_dav_any_running(db) || (known && fs_dav_command("enabled",&result)==0);
}

static struct json_object *fs_dav_get(sqlite3 *db)
{
    struct json_object *data=json_object_new_object(),*shares=json_object_new_array(),*caps=json_object_new_object();sqlite3_stmt *st=NULL;
    int installed=fs_dav_installed(),running=0,count=0;
    if(fs_prepare(db,&st,"SELECT id,spec_json,revision FROM webdav_share ORDER BY id")!=0)goto fail;
    int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        const char *id=fs_sql_text(st,0,"");struct json_object *spec=json_tokener_parse(fs_sql_text(st,1,"{}"));
        if(!spec)goto fail;
        int available=fs_dav_binding(spec),live=fs_dav_worker_running(id,spec);running+=live;count++;
        json_object_object_add(spec,"id",json_object_new_string(id));
        json_object_object_add(spec,"revision",json_object_new_int64(sqlite3_column_int64(st,2)));
        json_object_object_add(spec,"path_available",json_object_new_boolean(available));
        json_object_object_add(spec,"path_reason",json_object_new_string(available?"":"directory_binding_changed"));
        json_object_object_add(spec,"running",json_object_new_boolean(live));
        char url[256];snprintf(url,sizeof url,"%s://%s:%lld/",fs_dav_bool(spec,"tls")?"https":"http",fs_dav_str(spec,"listen_address"),(long long)fs_dav_int(spec,"listen_port"));
        json_object_object_add(spec,"url",live && available?json_object_new_string(url):NULL);
        json_object_array_add(shares,spec);
    }
    sqlite3_finalize(st);st=NULL;if(step!=SQLITE_DONE)goto fail;
    if(!installed && count==0 && access(JMX_DAV_INIT,X_OK)!=0){json_object_put(data);json_object_put(shares);json_object_put(caps);return fs_webdav_get_data();}
    if(fs_prepare(db,&st,"SELECT error,updated_at FROM webdav_service_error WHERE id=1")==0 && sqlite3_step(st)==SQLITE_ROW){
        json_object_object_add(data,"last_error",json_object_new_string(fs_sql_text(st,0,"")));
        json_object_object_add(data,"last_error_at",json_object_new_int64(sqlite3_column_int64(st,1)));
    }else json_object_object_add(data,"last_error",json_object_new_string(""));
    if(st)sqlite3_finalize(st);st=NULL;
    json_object_object_add(data,"service",json_object_new_string("webdav"));
    json_object_object_add(data,"installed",json_object_new_boolean(installed));
    json_object_object_add(data,"available",json_object_new_boolean(installed));
    json_object_object_add(data,"running",json_object_new_boolean(running>0));
    json_object_object_add(data,"requested_running",json_object_new_boolean(fs_dav_wants_running(db)));
    struct fs_exec_result r={0};char *argv[]={JMX_DAV_INIT,"enabled",NULL};
    json_object_object_add(data,"enabled",installed?json_object_new_boolean(fs_exec_argv(argv,3000,NULL,0,&r)==0):NULL);
    json_object_object_add(data,"source",json_object_new_string(count?"config_db":"unconfigured"));
    json_object_object_add(data,"config_source",json_object_new_string("config_db"));
    int64_t control=0;if(fs_meta_revision_lookup(db,&control)==1)json_object_object_add(data,"control_revision",json_object_new_int64(control));
    json_object_object_add(data,"isolation",json_object_new_string("per_share_ujail"));
    struct json_object *listeners=json_object_new_array();
    for(size_t i=0;i<json_object_array_length(shares);i++){
        struct json_object *share=json_object_array_get_idx(shares,i);if(!fs_dav_bool(share,"running"))continue;
        struct json_object *listener=json_object_new_object();
        json_object_object_add(listener,"address",json_object_new_string(fs_dav_str(share,"listen_address")));
        json_object_object_add(listener,"port",json_object_new_int64(fs_dav_int(share,"listen_port")));
        json_object_object_add(listener,"transport",json_object_new_string("tcp"));json_object_array_add(listeners,listener);
    }
    json_object_object_add(data,"listeners",listeners);json_object_object_add(data,"listeners_known",json_object_new_boolean(access("/proc/net/tcp",R_OK)==0));
    json_object_object_add(data,"shares",shares);
    json_object_object_add(caps,"shares",json_object_new_boolean(installed));
    json_object_object_add(caps,"actions",json_object_new_boolean(installed));
    json_object_object_add(caps,"autostart",json_object_new_boolean(installed));
    json_object_object_add(caps,"settings",json_object_new_boolean(0));
    struct json_object *reasons=json_object_new_object();
    if(!installed){
        const char *reason=access(FS_DAV_MODULE,R_OK)==0 && !fs_dav_module_ready()?"nginx_dav_ext_update_required":"webdav_sandbox_runtime_missing";
        json_object_object_add(reasons,"shares",json_object_new_string(reason));json_object_object_add(reasons,"actions",json_object_new_string(reason));
    }
    json_object_object_add(data,"capability_reasons",reasons);
    json_object_object_add(data,"capabilities",caps);fs_add_contract(data);return data;
fail:
    if(st)sqlite3_finalize(st);json_object_put(shares);json_object_put(caps);json_object_put(data);return NULL;
}

static int fs_dav_account_refs(sqlite3 *db,const char *login,struct json_object *refs)
{
    if(!login)return 0;
    sqlite3_stmt *st=NULL;
    if(fs_prepare(db,&st,"SELECT id,spec_json FROM webdav_share")!=0)return -1;
    int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        struct json_object *spec=json_tokener_parse(fs_sql_text(st,1,"{}")),*users=NULL;
        if(!spec){sqlite3_finalize(st);return -1;}
        json_object_object_get_ex(spec,"users",&users);
        for(size_t i=0;i<json_object_array_length(users);i++){
            struct fs_account a;
            if(fs_account_load(db,fs_dav_str(json_object_array_get_idx(users,i),"account_id"),&a)==1 && !strcmp(a.login,login)){
                struct json_object *r=json_object_new_object();
                json_object_object_add(r,"protocol",json_object_new_string("webdav"));
                json_object_object_add(r,"id",json_object_new_string(fs_sql_text(st,0,"")));
                json_object_object_add(r,"name",json_object_new_string(fs_dav_str(spec,"name")));
                json_object_array_add(refs,r);break;
            }
        }
        json_object_put(spec);
    }
    sqlite3_finalize(st);return step==SQLITE_DONE?0:-1;
}

static int fs_dav_auth_line(struct fs_buffer *out,const char *login,const unsigned char *secret,size_t len)
{
    unsigned char salt[16],digest[EVP_MAX_MD_SIZE],raw[36],encoded[64];unsigned int n=0;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();int rc=-1;
    if(!ctx || RAND_bytes(salt,sizeof salt)!=1 || EVP_DigestInit_ex(ctx,EVP_sha1(),NULL)!=1 ||
       EVP_DigestUpdate(ctx,secret,len)!=1 || EVP_DigestUpdate(ctx,salt,sizeof salt)!=1 ||
       EVP_DigestFinal_ex(ctx,digest,&n)!=1 || n!=20)goto out;
    memcpy(raw,digest,20);memcpy(raw+20,salt,16);EVP_EncodeBlock(encoded,raw,sizeof raw);
    if(fs_buffer_append(out,login)==0 && fs_buffer_append(out,":{SSHA}")==0 &&
       fs_buffer_append(out,(char *)encoded)==0 && fs_buffer_append(out,"\n")==0)rc=0;
out: EVP_MD_CTX_free(ctx);OPENSSL_cleanse(digest,sizeof digest);OPENSSL_cleanse(raw,sizeof raw);return rc;
}

static int fs_dav_file(const char *dir,const char *name,const char *text,mode_t mode)
{
    char path[PATH_MAX];if(fs_service_path_join(path,sizeof path,dir,name)!=0)return -1;
    if(fs_atomic_replace(path,text,strlen(text),mode)!=0)return -1;
    struct group *group=getgrnam("nogroup");return group && chown(path,0,group->gr_gid)==0?0:-1;
}

static int fs_dav_printf(struct fs_buffer *b,const char *format,...)
{
    va_list args;char *text=NULL;va_start(args,format);int n=vasprintf(&text,format,args);va_end(args);
    int rc=n<0?-1:fs_buffer_append_n(b,text,n);free(text);return rc;
}

static int fs_dav_project_one(sqlite3 *db,struct ac_secrets *secrets,const char *generation,const char *id,struct json_object *spec,struct fs_buffer *preflight)
{
    char dir[PATH_MAX],run[PATH_MAX],config[PATH_MAX],secret_id[96];
    struct fs_buffer all={0},writers={0},nginx={0},launch={0},http={0};int rc=-1;
    char destination[FS_MAX_ID+32];snprintf(destination,sizeof destination,"dav_destination_%s",id);
    for(char *p=destination;*p;p++)if(*p=='-')*p='_';
    char published[FS_MAX_PATH+1];struct json_object *identity=NULL;
    if(!json_object_object_get_ex(spec,"storage_binding",&identity)){
        identity=fs_binding_identity(fs_dav_str(spec,"path"));
        if(!identity)return -1;json_object_object_add(spec,"storage_binding",identity);
    }
    if(fs_binding_pin(id,fs_dav_str(spec,"path"),identity,published,sizeof published)!=1)return -1;
    struct json_object *acl=NULL;json_object_object_get_ex(spec,"users",&acl);
    snprintf(dir,sizeof dir,"%s/%s",generation,id);snprintf(run,sizeof run,JMX_DAV_RUN "/%s",id);
    if(mkdir(dir,0750)!=0)return -1;
    struct group *group=getgrnam("nogroup");if(!group || chown(dir,0,group->gr_gid)!=0)goto out;
    for(size_t i=0;i<json_object_array_length(acl);i++){
        struct json_object *entry=json_object_array_get_idx(acl,i);struct fs_account a;unsigned char *password=NULL;size_t len=0;
        if(fs_account_load(db,fs_dav_str(entry,"account_id"),&a)!=1 || !fs_account_owned(&a,1))goto out;
        if(!a.enabled)continue;
        snprintf(secret_id,sizeof secret_id,"file-share:%s",a.id);
        if(ac_secrets_get(secrets,secret_id,a.secret_version,&password,&len)!=AC_SECRETS_OK)goto out;
        int ok=fs_dav_auth_line(&all,a.login,password,len)==0;
        if(ok && !fs_dav_bool(entry,"read_only") && !fs_dav_bool(spec,"read_only"))ok=fs_dav_auth_line(&writers,a.login,password,len)==0;
        ac_secrets_clear(password,len);if(!ok)goto out;
    }
    if(fs_dav_file(dir,"users",all.data?all.data:"",0640)!=0 || fs_dav_file(dir,"writers",writers.data?writers.data:"",0640)!=0)goto out;
    /* Authentication/TLS never share a mount namespace with DAV file I/O. */
    for(int layer=0;layer<2;layer++){
        const char *role=layer?"auth":"data";char layer_run[PATH_MAX],filename[32];
        if(fs_service_path_join(layer_run,sizeof layer_run,run,role)!=0)goto out;
        fs_buffer_free(&nginx);fs_buffer_free(&launch);fs_buffer_free(&http);
        if(!layer && fs_dav_printf(&nginx,"load_module %s;\n",FS_DAV_MODULE)!=0)goto out;
        if(fs_dav_printf(&nginx,"daemon off;\nmaster_process off;\npid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\nhttp {\naccess_log off;\n",layer_run,layer_run)!=0)goto out;
        if(layer){
            if(fs_dav_printf(&http,"map \"$http_host|$http_destination\" $%s { default invalid; ~^[^|]+\\|$ \"\"; ~^[^|]+\\|(/.*)$ $1; ~^([^|]+)\\|https?://\\1(/.*)$ $2; }\n",destination)!=0)goto out;
        }
        if(fs_dav_printf(&http,"server {\nerror_log %s/error.log;\nclient_body_temp_path %s/client;\nproxy_temp_path %s/proxy;\nfastcgi_temp_path %s/fastcgi;\nuwsgi_temp_path %s/uwsgi;\nscgi_temp_path %s/scgi;\nclient_max_body_size 0;\n",layer_run,layer_run,layer_run,layer_run,layer_run,layer_run)!=0)goto out;
        if(layer){
            if(fs_dav_printf(&http,"listen %s:%lld%s;\n",fs_dav_str(spec,"listen_address"),(long long)fs_dav_int(spec,"listen_port"),fs_dav_bool(spec,"tls")?" ssl":"")!=0)goto out;
            if(fs_dav_bool(spec,"tls")){
                for(int k=0;k<2;k++){
                    struct fs_snapshot pem={0};
                    if(fs_snapshot_read(fs_dav_str(spec,k?"key_file":"cert_file"),&pem)!=0 || !pem.existed){fs_snapshot_free(&pem);goto out;}
                    int ok=fs_dav_file(dir,k?"tls.key":"tls.crt",pem.data,0640)==0;
                    if(pem.data)OPENSSL_cleanse(pem.data,pem.len);fs_snapshot_free(&pem);if(!ok)goto out;
                }
                if(fs_dav_printf(&http,"ssl_certificate %s/tls.crt;\nssl_certificate_key %s/tls.key;\nssl_protocols TLSv1.2 TLSv1.3;\n",dir,dir)!=0)goto out;
            }
            if(fs_dav_printf(&http,"location / {\nif ($%s = invalid) { return 400; }\nauth_basic \"DreamingWrt share\";\nauth_basic_user_file %s/users;\nlimit_except GET HEAD PROPFIND OPTIONS { auth_basic_user_file %s/writers; }\nproxy_pass http://unix:%s/data/dav.sock:;\nproxy_http_version 1.1;\nproxy_set_header Host $http_host;\nproxy_set_header Destination $%s;\nproxy_set_header Authorization \"\";\nproxy_set_header Connection \"\";\nproxy_buffering off;\nproxy_request_buffering off;\n}\n}\n",destination,dir,dir,run,destination)!=0)goto out;
        }else{
            if(fs_dav_printf(&http,"listen unix:%s/dav.sock;\nroot \"%s\";\ndisable_symlinks on;\nlocation / {\nautoindex on;\ndav_ext_methods PROPFIND OPTIONS;\ndav_methods PUT DELETE MKCOL COPY MOVE;\ndav_access user:rw group:rw;\n}\n}\n",layer_run,published)!=0)goto out;
        }
        /* Validate the exact server blocks together; nginx startup cost must
         * not grow by two processes for every published directory. */
        if(fs_buffer_append(&nginx,http.data)!=0 || fs_buffer_append(&nginx,"}\n")!=0 ||
           fs_buffer_append(preflight,http.data)!=0)goto out;
        snprintf(filename,sizeof filename,"%s.conf",role);
        if(fs_dav_file(dir,filename,nginx.data,0640)!=0)goto out;
        if(fs_service_path_join(config,sizeof config,dir,filename)!=0)goto out;
        if(fs_dav_printf(&launch,"#!/bin/sh\nexec /sbin/ujail -E -c -o -n dwrt-%s-%s -U nobody -G nogroup -r '%s' -w '%s'",role,id,config,layer_run)!=0)goto out;
        if(layer){
            if(fs_dav_printf(&launch," -r '%s/users' -r '%s/writers' -r '%s/data'",dir,dir,run)!=0)goto out;
            if(fs_dav_bool(spec,"tls") && fs_dav_printf(&launch," -r '%s/tls.crt' -r '%s/tls.key'",dir,dir)!=0)goto out;
        }else if(fs_dav_printf(&launch," -r '%s' %s '%s'",FS_DAV_MODULE,fs_dav_bool(spec,"read_only")?"-r":"-w",published)!=0)goto out;
        if(fs_dav_printf(&launch," -P '%s/host.pid' -- /usr/sbin/nginx -c '%s'\n",layer_run,config)!=0)goto out;
        snprintf(filename,sizeof filename,"%s-launch",role);
        if(fs_dav_file(dir,filename,launch.data,0700)!=0)goto out;
    }
    if(fs_dav_file(dir,"spec.json",json_object_to_json_string_ext(spec,JSON_C_TO_STRING_PLAIN),0600)!=0)goto out;
    struct stat pinned;if(stat(published,&pinned)!=0)goto out;
    char binding[PATH_MAX+100];snprintf(binding,sizeof binding,"%llu %llu %s\n",(unsigned long long)pinned.st_dev,(unsigned long long)pinned.st_ino,published);
    if(fs_dav_file(dir,"binding",binding,0600)!=0)goto out;
    rc=0;
out:fs_buffer_free(&all);fs_buffer_free(&writers);fs_buffer_free(&nginx);fs_buffer_free(&launch);fs_buffer_free(&http);return rc;
}

/* Called while holding the configuration transaction. Only remove our known
 * projection files, never traverse links or recursively remove data paths. */
static void fs_dav_prune(void)
{
    struct fs_snapshot current={0};
    if(fs_snapshot_read(JMX_DAV_BASE "/current",&current)!=0)return;
    DIR *base=opendir(JMX_DAV_BASE);struct dirent *gen;
    if(!base){fs_snapshot_free(&current);return;}
    while((gen=readdir(base))){
        if(strncmp(gen->d_name,"generation-",11))continue;
        char path[PATH_MAX];struct stat st;snprintf(path,sizeof path,JMX_DAV_BASE "/%s",gen->d_name);
        if((current.data && !strcmp(path,current.data)) || lstat(path,&st)!=0 || !S_ISDIR(st.st_mode))continue;
        DIR *dir=opendir(path);struct dirent *share;if(!dir)continue;
        while((share=readdir(dir))){
            if(strncmp(share->d_name,"dav-",4) || !fs_id_ok(share->d_name))continue;
            char child[PATH_MAX],file[PATH_MAX];if(fs_service_path_join(child,sizeof child,path,share->d_name)!=0)continue;
            if(lstat(child,&st)!=0 || !S_ISDIR(st.st_mode))continue;
            const char *names[]={"users","writers","binding","data.conf","auth.conf","data-launch","auth-launch","tls.crt","tls.key","nginx.conf","launch","spec.json"};
            for(size_t i=0;i<sizeof names/sizeof names[0];i++){if(fs_service_path_join(file,sizeof file,child,names[i])==0)unlink(file);}
            rmdir(child);
        }
        closedir(dir);char check[PATH_MAX];if(fs_service_path_join(check,sizeof check,path,"preflight.conf")==0)unlink(check);rmdir(path);
    }
    closedir(base);fs_snapshot_free(&current);
}

static void fs_dav_sweep(sqlite3 *db)
{
    char target[FS_MAX_PATH+1];if(!fs_binding_target("dav-probe",target,sizeof target))return;
    char *slash=strrchr(target,'/');if(!slash)return;*slash='\0';
    DIR *dir=opendir(target);if(!dir)return;struct dirent *entry;
    while((entry=readdir(dir))){
        if(strncmp(entry->d_name,"dav-",4) || !fs_id_ok(entry->d_name))continue;
        int64_t revision=0;struct json_object *spec=fs_dav_load(db,entry->d_name,&revision);
        if(!spec || !fs_dav_bool(spec,"enabled") || !fs_dav_binding(spec))fs_binding_unpin(entry->d_name);
        json_object_put(spec);
    }
    closedir(dir);
}

static int fs_dav_apply(sqlite3 *db,struct fs_snapshot *old,int *replaced,int start,const char **reason)
{
    fs_dav_sweep(db);
    fs_dav_prune();
    char generation[PATH_MAX]=JMX_DAV_BASE "/generation-XXXXXX";sqlite3_stmt *st=NULL;struct ac_secrets *secrets=NULL;int rc=-1;
    struct fs_buffer config={0};
    if(mkdir(JMX_DAV_BASE,0750)!=0 && errno!=EEXIST){*reason="webdav_state_directory_failed";return -1;}
    struct group *group=getgrnam("nogroup");
    if(!group || chown(JMX_DAV_BASE,0,group->gr_gid)!=0 || !mkdtemp(generation) || chmod(generation,0750)!=0 || chown(generation,0,group->gr_gid)!=0){*reason="webdav_generation_failed";return -1;}
    if(ac_secrets_open(db,JMX_SHARE_SECRET_KEY_PATH,&secrets)!=AC_SECRETS_OK){*reason="webdav_credentials_unavailable";goto out;}
    if(fs_dav_printf(&config,"load_module %s;\ndaemon off;\nmaster_process off;\npid %s/preflight.pid;\nerror_log %s/preflight.log;\nevents {}\nhttp {\naccess_log off;\n",FS_DAV_MODULE,JMX_DAV_RUN,JMX_DAV_RUN)!=0)goto out;
    if(fs_prepare(db,&st,"SELECT id,spec_json FROM webdav_share")!=0)goto out;
    int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        struct json_object *spec=json_tokener_parse(fs_sql_text(st,1,"{}"));if(!spec)goto out;
        int enabled=fs_dav_bool(spec,"enabled");
        if(enabled && !fs_dav_binding(spec)){json_object_put(spec);continue;}
        if(enabled && !fs_dav_port_available(fs_sql_text(st,0,""),spec)){json_object_put(spec);*reason="port_in_use";goto out;}
        int ok=!enabled || fs_dav_project_one(db,secrets,generation,fs_sql_text(st,0,""),spec,&config)==0;
        json_object_put(spec);if(!ok){*reason="webdav_config_generation_failed";goto out;}
    }
    if(step!=SQLITE_DONE)goto out;
    if(fs_buffer_append(&config,"}\n")!=0 || fs_dav_file(generation,"preflight.conf",config.data,0640)!=0){*reason="webdav_config_generation_failed";goto out;}
    struct fs_exec_result preflight={0};char *check[]={JMX_DAV_INIT,"check",generation,NULL};
    if(fs_exec_argv(check,JMX_DAV_TIMEOUT_MS,NULL,0,&preflight)!=0){*reason=preflight.timed_out?"webdav_preflight_timeout":"webdav_preflight_failed";goto out;}
    if(fs_snapshot_read(JMX_DAV_BASE "/current",old)!=0 || fs_atomic_replace(JMX_DAV_BASE "/current",generation,strlen(generation),0600)!=0){*reason="webdav_config_replace_failed";goto out;}
    *replaced=1;
    if(start){struct fs_exec_result r={0};
        if(fs_dav_command("restart",&r)!=0){*reason="webdav_service_failed";goto out;}
        int ready=0;
        for(int attempt=0;attempt<50;attempt++){
            sqlite3_stmt *probe=NULL;int ok=1;
            if(fs_prepare(db,&probe,"SELECT id,spec_json FROM webdav_share")!=0)goto out;
            int step;
            while((step=sqlite3_step(probe))==SQLITE_ROW){
                struct json_object *spec=json_tokener_parse(fs_sql_text(probe,1,"{}"));
                if(!spec || (fs_dav_bool(spec,"enabled") && fs_dav_binding(spec) && !fs_dav_worker_running(fs_sql_text(probe,0,""),spec)))ok=0;
                json_object_put(spec);
            }
            sqlite3_finalize(probe);if(step!=SQLITE_DONE)ok=0;
            if(ok){ready=1;break;}usleep(100000);
        }
        if(!ready){*reason="webdav_listener_not_ready";goto out;}
    }
    rc=0;
out:if(st)sqlite3_finalize(st);ac_secrets_close(secrets);fs_buffer_free(&config);return rc;
}

static void fs_dav_reconcile(sqlite3 *db)
{
    if(!fs_dav_installed())return;
    int wanted=fs_dav_wants_running(db);if(fs_dav_intent_set(db,wanted)!=0 || !wanted)return;
    sqlite3_stmt *st=NULL;int changed=0,withdraw=0;
    if(fs_prepare(db,&st,"SELECT id,spec_json FROM webdav_share")!=0)return;
    while(sqlite3_step(st)==SQLITE_ROW){
        struct json_object *spec=json_tokener_parse(fs_sql_text(st,1,"{}"));
        int desired=spec && fs_dav_bool(spec,"enabled") && fs_dav_binding(spec);
        int live=spec && fs_dav_worker_running(fs_sql_text(st,0,""),spec);
        changed|=desired!=live;withdraw|=live && !desired;json_object_put(spec);
    }
    sqlite3_finalize(st);fs_dav_sweep(db);if(!changed)return;
    struct fs_snapshot old={0};int replaced=0;const char *reason="";struct fs_exec_result result={0};
    int rc=withdraw?fs_dav_command("stop",&result):0;
    if(rc==0)rc=fs_dav_apply(db,&old,&replaced,1,&reason);
    if(rc==0)fs_sql_exec(db,"DELETE FROM webdav_service_error");
    else{int64_t revision=0;if(fs_meta_revision_lookup(db,&revision)==1)fs_dav_save_error(db,reason[0]?reason:"webdav_withdraw_failed",revision);}
    fs_snapshot_free(&old);
}

static int fs_dav_generation_running(const char *generation,int expected)
{
    if(!generation || strncmp(generation,JMX_DAV_BASE "/generation-",sizeof(JMX_DAV_BASE "/generation-")-1))return !expected;
    DIR *dir=opendir(generation);if(!dir)return 0;
    struct dirent *entry;int ok=1;
    while((entry=readdir(dir))){
        if(strncmp(entry->d_name,"dav-",4) || !fs_id_ok(entry->d_name))continue;
        char path[PATH_MAX];struct fs_snapshot file={0};snprintf(path,sizeof path,"%s/%s/spec.json",generation,entry->d_name);
        if(fs_snapshot_read(path,&file)!=0 || !file.existed){ok=0;fs_snapshot_free(&file);break;}
        struct json_object *spec=json_tokener_parse(file.data);fs_snapshot_free(&file);
        if(!spec || fs_dav_worker_running(entry->d_name,spec)!=expected)ok=0;
        json_object_put(spec);
    }
    closedir(dir);return ok;
}

static int fs_dav_restore(const struct fs_snapshot *old,int replaced,int running)
{
    if(!replaced)return 0;
    struct fs_snapshot failed={0};fs_snapshot_read(JMX_DAV_BASE "/current",&failed);
    if(fs_snapshot_restore(JMX_DAV_BASE "/current",old)!=0){fs_snapshot_free(&failed);return -1;}
    struct fs_exec_result r={0};int ok=0;
    if(fs_dav_command(running?"restart":"stop",&r)==0){
        for(int i=0;i<50;i++){
            if(fs_dav_generation_running(running?old->data:failed.data,running)){ok=1;break;}
            usleep(100000);
        }
    }
    fs_snapshot_free(&failed);return ok?0:-1;
}

static int fs_dav_access(const char *path,int writing)
{
    struct passwd *pw=getpwnam("nobody");struct group *gr=getgrnam("nogroup");if(!pw || !gr || !pw->pw_uid || !gr->gr_gid)return 0;
    pid_t pid=fork();if(pid<0)return 0;
    if(!pid){if(setgroups(0,NULL)||setgid(gr->gr_gid)||setuid(pw->pw_uid))_exit(2);_exit(access(path,R_OK|X_OK|(writing?W_OK:0))==0?0:1);}
    int status=0;while(waitpid(pid,&status,0)<0){if(errno!=EINTR)return 0;}return WIFEXITED(status)&&WEXITSTATUS(status)==0;
}

struct json_object *jmx_webdav_share_request(const char *method,const char *id,struct json_object *req)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct json_object *payload=fs_payload(req),*spec=NULL,*oldspec=NULL,*response=NULL,*value=NULL;
    struct fs_snapshot old={0};int replaced=0,tx=0,running=0,create=!strcmp(method,"POST"),remove=!strcmp(method,"DELETE"),present=0;
    int64_t revision=0,expected=0,control=0;char generated[65],canonical[FS_MAX_PATH+1];const char *reason="webdav_write_failed";
    if(!fs_confirmed(req))return fs_error("confirmation_required","confirm_true_required");
    if(!fs_dav_installed())return fs_error("runtime_not_installed","webdav_sandbox_runtime_missing");
    if(!create && !remove && strcmp(method,"PUT"))return fs_error("invalid_action","webdav_method_invalid");
    if(!create && (!fs_id_ok(id) || fs_json_positive_int64(payload,"expected_revision",&expected,&present)!=0 || !present))return fs_error("missing_expected_revision","share_revision_required");
    if(fs_db_open(&db)!=0)return fs_error("storage_unavailable","config_db_open_failed");
    if(fs_sql_exec(db,"BEGIN IMMEDIATE")!=0){response=fs_error("storage_busy","protocol_operation_in_progress");goto out;}tx=1;
    if(fs_meta_revision_lookup(db,&control)!=1)goto out;
    running=fs_dav_wants_running(db);
    if(create){
        if(fs_random_id(db,"dav","webdav_share",generated,sizeof generated)!=0)goto out;id=generated;
        spec=json_tokener_parse("{\"enabled\":true,\"read_only\":true,\"tls\":false,\"note\":\"\"}");
    }else{
        oldspec=fs_dav_load(db,id,&revision);if(!oldspec){response=fs_error("not_found","webdav_share_not_found");goto out;}
        if(revision!=expected){response=fs_revision_conflict("webdav_share_changed",expected,revision);goto out;}
        spec=json_tokener_parse(json_object_to_json_string_ext(oldspec,JSON_C_TO_STRING_PLAIN));
    }
    json_object_object_foreach(payload,k,v){
        if(!strcmp(k,"confirm") || !strcmp(k,"expected_revision") || !strcmp(k,"rebind"))continue;
        if(strcmp(k,"name") && strcmp(k,"path") && strcmp(k,"enabled") && strcmp(k,"read_only") && strcmp(k,"tls") && strcmp(k,"listen_address") && strcmp(k,"listen_port") && strcmp(k,"cert_file") && strcmp(k,"key_file") && strcmp(k,"users") && strcmp(k,"note")){response=fs_error("invalid_field",k);goto out;}
        json_object_object_add(spec,k,json_object_get(v));
    }
    if(!remove){
        const char *strings[]={"name","path","listen_address","note"};
        for(size_t i=0;i<4;i++){if(!json_object_object_get_ex(spec,strings[i],&value) || !json_object_is_type(value,json_type_string) || !fs_text_ok(json_object_get_string(value),i==1?FS_MAX_PATH:128,i!=3)){response=fs_error("invalid_field",strings[i]);goto out;}}
        for(int i=0;i<2;i++){const char *key=i?"key_file":"cert_file";
            if(json_object_object_get_ex(spec,key,&value) && (!json_object_is_type(value,json_type_string) || !fs_text_ok(json_object_get_string(value),FS_MAX_PATH,0))){response=fs_error("invalid_field",key);goto out;}}
        const char *bools[]={"enabled","read_only","tls"};
        for(size_t i=0;i<3;i++){if(!json_object_object_get_ex(spec,bools[i],&value) || !json_object_is_type(value,json_type_boolean)){response=fs_error("invalid_boolean",bools[i]);goto out;}}
        int enabled=fs_dav_bool(spec,"enabled");
        if(!fs_dav_path_text(fs_dav_str(spec,"path")) || strchr(fs_dav_str(spec,"path"),'\'') ||
           (enabled && !fs_share_path_ok(fs_dav_str(spec,"path"),canonical,sizeof canonical))){response=fs_error("invalid_path","safe_existing_directory_required");goto out;}
        if(enabled){
            if(!fs_dav_access(canonical,!fs_dav_bool(spec,"read_only"))){response=fs_error("directory_permission_denied","nobody_nogroup_requires_existing_directory_access");goto out;}
            struct stat binding;if(stat(canonical,&binding)!=0)goto out;
            int rebind=0;if(fs_json_bool(payload,"rebind",&rebind,&present)!=0){response=fs_error("invalid_boolean","rebind_must_be_boolean");goto out;}
            if(oldspec && !rebind && !strcmp(canonical,fs_dav_str(oldspec,"path")) && !fs_dav_binding(oldspec)){response=fs_error("directory_binding_changed","reselect_directory_or_disable_share");goto out;}
            json_object_object_add(spec,"path",json_object_new_string(canonical));
            json_object_object_add(spec,"device",json_object_new_int64(binding.st_dev));json_object_object_add(spec,"inode",json_object_new_int64(binding.st_ino));
            struct json_object *identity=fs_binding_identity(canonical);if(!identity){response=fs_error("directory_binding_changed","filesystem_identity_unavailable");goto out;}
            json_object_object_add(spec,"storage_binding",identity);
        }
        struct in_addr address;const char *host=fs_dav_str(spec,"listen_address");int local=0;
        if(inet_pton(AF_INET,host,&address)!=1 || !address.s_addr || IN_MULTICAST(ntohl(address.s_addr))){response=fs_error("invalid_address","explicit_local_ipv4_address_required");goto out;}
        struct ifaddrs *ifaces=NULL;if(getifaddrs(&ifaces)==0){for(struct ifaddrs *a=ifaces;a;a=a->ifa_next)if(a->ifa_addr && a->ifa_addr->sa_family==AF_INET && ((struct sockaddr_in *)a->ifa_addr)->sin_addr.s_addr==address.s_addr)local=1;freeifaddrs(ifaces);}
        if(!local){response=fs_error("invalid_address","listener_address_not_on_device");goto out;}
        if(!json_object_object_get_ex(spec,"listen_port",&value) || !json_object_is_type(value,json_type_int) || fs_dav_int(spec,"listen_port")<1024 || fs_dav_int(spec,"listen_port")>65535){response=fs_error("invalid_port","use_1024_to_65535");goto out;}
        if(fs_prepare(db,&st,"SELECT spec_json FROM webdav_share WHERE id<>?1")!=0)goto out;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);int step;
        while((step=sqlite3_step(st))==SQLITE_ROW){struct json_object *other=json_tokener_parse(fs_sql_text(st,0,"{}"));int conflict=fs_dav_int(other,"listen_port")==fs_dav_int(spec,"listen_port") && !strcmp(host,fs_dav_str(other,"listen_address"));json_object_put(other);if(conflict){response=fs_error("port_in_use","webdav_share_listener_conflict");goto out;}}
        sqlite3_finalize(st);st=NULL;if(step!=SQLITE_DONE)goto out;
        if(!json_object_object_get_ex(spec,"users",&value) || !json_object_is_type(value,json_type_array) || !json_object_array_length(value) || json_object_array_length(value)>64){response=fs_error("invalid_acl","explicit_share_accounts_required");goto out;}
        for(size_t i=0;i<json_object_array_length(value);i++){
            struct json_object *entry=json_object_array_get_idx(value,i),*ro=NULL;struct fs_account account;
            if(!json_object_is_type(entry,json_type_object)){response=fs_error("invalid_acl","account_object_required");goto out;}
            json_object_object_foreach(entry,aclkey,aclvalue){(void)aclvalue;if(strcmp(aclkey,"account_id") && strcmp(aclkey,"read_only")){response=fs_error("invalid_acl","unknown_account_field");goto out;}}
            for(size_t j=0;j<i;j++)if(!strcmp(fs_dav_str(entry,"account_id"),fs_dav_str(json_object_array_get_idx(value,j),"account_id"))){response=fs_error("invalid_acl","duplicate_account");goto out;}
            if(fs_account_load(db,fs_dav_str(entry,"account_id"),&account)!=1 || !fs_account_owned(&account,1) || !json_object_object_get_ex(entry,"read_only",&ro) || !json_object_is_type(ro,json_type_boolean)){response=fs_error("invalid_acl","dedicated_account_and_read_only_required");goto out;}
        }
        if(fs_dav_bool(spec,"tls"))for(int i=0;i<2;i++){
            const char *path=fs_dav_str(spec,i?"key_file":"cert_file");struct stat stbuf;
            if(!fs_dav_path_text(path) || strchr(path,'\'') || stat(path,&stbuf)!=0 || !S_ISREG(stbuf.st_mode) || access(path,R_OK)!=0){response=fs_error("invalid_certificate","readable_certificate_and_key_required");goto out;}
        }
    }
    if(fs_prepare(db,&st,remove?"DELETE FROM webdav_share WHERE id=?1":"INSERT INTO webdav_share VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET spec_json=excluded.spec_json,revision=excluded.revision")!=0)goto out;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if(!remove){sqlite3_bind_text(st,2,json_object_to_json_string_ext(spec,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,revision+1);}
    if(fs_step_done(st)!=0)goto out;sqlite3_finalize(st);st=NULL;
    if(fs_dav_apply(db,&old,&replaced,running,&reason)!=0 || fs_sql_exec(db,"DELETE FROM webdav_service_error")!=0 || fs_meta_bump(db)!=0 || fs_operation_receipt_state(db,id,revision+1,remove,running)!=0 || fs_sql_exec(db,"COMMIT")!=0)goto rollback;
    tx=0;struct json_object *data=json_object_new_object();
    json_object_object_add(data,"id",json_object_new_string(id));json_object_object_add(data,"revision",json_object_new_int64(revision+1));
    json_object_object_add(data,"persisted",json_object_new_boolean(1));json_object_object_add(data,"applied",json_object_new_boolean(running));json_object_object_add(data,"restart_required",json_object_new_boolean(!running));json_object_object_add(data,"deleted",json_object_new_boolean(remove));response=fs_success(data);goto out;
rollback:{
    int restored=fs_dav_restore(&old,replaced,running)==0,dbok=fs_sql_exec(db,"ROLLBACK")==0;tx=0;
    if(dbok)fs_dav_save_error(db,reason,control);
    struct json_object *data=fs_error_detail("webdav_apply_failed",reason);
    json_object_object_add(data,"rolled_back",json_object_new_boolean(restored&&dbok));json_object_object_add(data,"rollback_failed",json_object_new_boolean(!restored||!dbok));response=fs_envelope(FS_API_ERROR,data);
}
out:
    if(st)sqlite3_finalize(st);if(tx)fs_sql_exec(db,"ROLLBACK");if(db)sqlite3_close(db);
    json_object_put(spec);json_object_put(oldspec);fs_snapshot_free(&old);return response?response:fs_error("storage_error",reason);
}

static struct json_object *fs_dav_action(struct json_object *req)
{
    struct json_object *payload=fs_payload(req),*response=NULL,*data=NULL;
    struct fs_snapshot old={0};sqlite3 *db=NULL;struct fs_exec_result result={0},restore={0};
    const char *action=fs_dav_str(payload,"action"),*reason="webdav_action_failed";
    int64_t expected=0,revision=0;int present=0,tx=0,replaced=0,running=0,enabled=0,rc=-1;
    int autostart=!strcmp(action,"enable") || !strcmp(action,"disable");
    if(!fs_confirmed(req))return fs_error("confirmation_required","confirm_true_required");
    if(!autostart && strcmp(action,"start") && strcmp(action,"stop") && strcmp(action,"restart"))return fs_error("invalid_action","start_stop_restart_enable_disable_only");
    if(!fs_dav_installed())return fs_error("runtime_not_installed","webdav_sandbox_runtime_missing");
    if(fs_json_positive_int64(payload,"expected_revision",&expected,&present)!=0 || !present)return fs_error("missing_expected_revision","control_revision_required");
    if(fs_db_open(&db)!=0)return fs_error("storage_unavailable","config_db_open_failed");
    if(fs_sql_exec(db,"BEGIN IMMEDIATE")!=0){response=fs_error("storage_busy","protocol_operation_in_progress");goto out;}tx=1;
    if(fs_meta_revision_lookup(db,&revision)!=1)goto out;
    if(expected!=revision){response=fs_revision_conflict("file_service_changed",expected,revision);goto out;}
    running=fs_dav_any_running(db);rc=fs_dav_command("enabled",&result);
    if(rc!=0 && result.exit_code!=1){response=fs_error("runtime_probe_failed","autostart_state_unknown");goto out;}enabled=rc==0;
    if(!autostart && strcmp(action,"stop"))rc=fs_dav_apply(db,&old,&replaced,1,&reason);
    else{
        rc=fs_dav_command(action,&result);
        if(rc==0 && autostart){int actual=fs_dav_command("enabled",&result);rc=(actual==0 || result.exit_code==1) && ((actual==0)==!strcmp(action,"enable"))?0:-1;}
        if(rc==0 && !autostart && fs_dav_any_running(db))rc=-1;
    }
    if(rc==0 && !autostart)rc=fs_dav_intent_set(db,strcmp(action,"stop")!=0);
    if(rc==0 && fs_sql_exec(db,"DELETE FROM webdav_service_error")==0 && fs_meta_bump(db)==0 && fs_sql_exec(db,"COMMIT")==0){
        tx=0;data=fs_dav_get(db);
        if(data){json_object_object_add(data,"service_action",json_object_new_string(action));json_object_object_add(data,"applied",json_object_new_boolean(1));response=fs_success(data);}goto out;
    }
    int restored;
    if(replaced)restored=fs_dav_restore(&old,replaced,running)==0;
    else restored=fs_dav_command(autostart?(enabled?"enable":"disable"):(running?"restart":"stop"),&restore)==0;
    int dbok=fs_sql_exec(db,"ROLLBACK")==0;tx=0;
    if(dbok)fs_dav_save_error(db,reason,revision);
    data=fs_error_detail("service_action_failed",reason);
    json_object_object_add(data,"rolled_back",json_object_new_boolean(restored&&dbok));json_object_object_add(data,"rollback_failed",json_object_new_boolean(!restored||!dbok));response=fs_envelope(FS_API_ERROR,data);
out:
    if(tx)fs_sql_exec(db,"ROLLBACK");if(db)sqlite3_close(db);fs_snapshot_free(&old);
    return response?response:fs_error("storage_error",reason);
}
