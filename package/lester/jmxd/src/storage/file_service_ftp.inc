/* Managed FTP: one private listener, locked shared identities and per-user
 * chroots containing only explicitly granted bind mounts. SQLite is authority. */
#include <openssl/ssl.h>
#include <sched.h>
#include <sys/statvfs.h>
#ifndef JMX_FTP_BASE
#define JMX_FTP_BASE "/etc/dreamingwrt/ftp"
#endif
#ifndef JMX_FTP_RUN
#define JMX_FTP_RUN "/var/run/dreamingwrt-ftp"
#endif
#ifndef JMX_FTP_INIT
#define JMX_FTP_INIT "/etc/init.d/dreamingwrt-ftp"
#endif
#ifndef JMX_FTP_BINARY
#define JMX_FTP_BINARY "/usr/libexec/dreamingwrt/vsftpd"
#endif
#define FS_FTP_PAM "/etc/pam.d/dreamingwrt-ftp"
#define FS_FTP_ROUNDS 100000

static int fs_ftp_schema(sqlite3 *db)
{
    return fs_sql_exec(db,"CREATE TABLE IF NOT EXISTS ftp_settings(id INTEGER PRIMARY KEY,spec_json TEXT NOT NULL,revision INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ftp_share(id TEXT PRIMARY KEY,spec_json TEXT NOT NULL,revision INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ftp_service_intent(id INTEGER PRIMARY KEY,running INTEGER NOT NULL,boot TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ftp_service_error(id INTEGER PRIMARY KEY,error TEXT NOT NULL,updated_at INTEGER NOT NULL);");
}

static int fs_ftp_installed(void)
{
    return access(JMX_FTP_BINARY,X_OK)==0 && access(JMX_FTP_INIT,X_OK)==0 && access(FS_FTP_PAM,R_OK)==0 &&
        access("/usr/lib/security/pam_exec.so",R_OK)==0 && access("/usr/lib/security/pam_permit.so",R_OK)==0;
}

static struct json_object *fs_ftp_load(sqlite3 *db,const char *id,int64_t *revision)
{
    sqlite3_stmt *st=NULL;struct json_object *spec=NULL;*revision=0;
    if(fs_prepare(db,&st,id?"SELECT spec_json,revision FROM ftp_share WHERE id=?1":"SELECT spec_json,revision FROM ftp_settings WHERE id=1")!=0)return NULL;
    if(id)sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)==SQLITE_ROW){spec=json_tokener_parse(fs_sql_text(st,0,"{}"));*revision=sqlite3_column_int64(st,1);}
    sqlite3_finalize(st);return spec;
}

static struct json_object *fs_ftp_json(const char *dir,const char *name)
{
    char path[PATH_MAX];struct fs_snapshot snap={0};if(fs_service_path_join(path,sizeof path,dir,name)!=0)return NULL;
    struct json_object *o=NULL;
    if(fs_snapshot_read(path,&snap)==0 && snap.existed)o=json_tokener_parse(snap.data);
    fs_snapshot_free(&snap);return o;
}

static int fs_ftp_current(char *path,size_t size)
{
    struct fs_snapshot snap={0};int ok=fs_snapshot_read(JMX_FTP_BASE "/current",&snap)==0 && snap.existed &&
        snap.data && snap.len<size && !strncmp(snap.data,JMX_FTP_BASE "/generation-",sizeof(JMX_FTP_BASE "/generation-")-1) &&
        fs_id_ok(snap.data+sizeof(JMX_FTP_BASE));
    if(ok)snprintf(path,size,"%s",snap.data);fs_snapshot_free(&snap);return ok;
}

static int fs_ftp_pid(pid_t pid)
{
    char path[64],exe[PATH_MAX];snprintf(path,sizeof path,"/proc/%ld/exe",(long)pid);
    ssize_t n=readlink(path,exe,sizeof exe-1);if(n<0)return 0;exe[n]='\0';
    return !strcmp(exe,JMX_FTP_BINARY) || !strcmp(exe,JMX_FTP_BINARY " (deleted)");
}

/* Match the private executable, including old sessions and deleted inodes. */
static int fs_ftp_processes(int sig)
{
    DIR *dir=opendir("/proc");if(!dir)return -1;struct dirent *e;int count=0;
    while((e=readdir(dir))){char *end;long pid=strtol(e->d_name,&end,10);
        if(*end || pid<=1 || !fs_ftp_pid(pid))continue;
        count++;if(sig && kill(pid,sig)!=0 && errno!=ESRCH){closedir(dir);return -1;}}
    closedir(dir);return count;
}

static int fs_ftp_owns_socket(unsigned long long inode)
{
    if(!inode)return 0;
    DIR *dir=opendir("/proc");if(!dir)return 0;struct dirent *e;int found=0;
    char expected[80];snprintf(expected,sizeof expected,"socket:[%llu]",inode);
    while(!found && (e=readdir(dir))){char *end;long pid=strtol(e->d_name,&end,10);if(*end || pid<=1 || !fs_ftp_pid(pid))continue;
        char path[80];snprintf(path,sizeof path,"/proc/%ld/fd",pid);DIR *fds=opendir(path);if(!fds)continue;struct dirent *fd;
        while((fd=readdir(fds))){char file[PATH_MAX],target[128];snprintf(file,sizeof file,"%s/%s",path,fd->d_name);ssize_t n=readlink(file,target,sizeof target-1);
            if(n>0){target[n]='\0';if(!strcmp(target,expected)){found=1;break;}}}closedir(fds);
    }
    closedir(dir);return found;
}

static int fs_ftp_running(void)
{
    char generation[PATH_MAX];if(!fs_ftp_current(generation,sizeof generation))return 0;
    struct json_object *settings=fs_ftp_json(generation,"settings.json");if(!settings)return 0;
    unsigned address,port,state;unsigned long long inode=0;char line[512];
    struct in_addr wanted={0};inet_pton(AF_INET,fs_dav_str(settings,"listen_address"),&wanted);
    int want_port=fs_dav_int(settings,"listen_port");json_object_put(settings);
    FILE *fp=fopen("/proc/net/tcp","re");if(!fp)return 0;
    while(fgets(line,sizeof line,fp)){
        if(sscanf(line," %*u: %x:%x %*s %x %*s %*s %*s %*u %*u %llu",&address,&port,&state,&inode)==4 &&
           address==wanted.s_addr && port==(unsigned)want_port && state==10 && fs_ftp_owns_socket(inode)){fclose(fp);return 1;}}
    fclose(fp);return 0;
}

static int fs_ftp_owns_port(struct in_addr wanted,int candidate)
{
    FILE *fp=fopen("/proc/net/tcp","re");if(!fp)return 0;
    char line[512];unsigned address,port,state;unsigned long long inode;int found=0,owned=1;
    while(fgets(line,sizeof line,fp)){
        if(sscanf(line," %*u: %x:%x %*s %x %*s %*s %*s %*u %*u %llu",&address,&port,&state,&inode)!=4 ||
           (address!=wanted.s_addr && address!=0) || port!=(unsigned)candidate || state==6)continue;
        found=1;if(!fs_ftp_owns_socket(inode)){owned=0;break;}
    }
    fclose(fp);return found && owned;
}

static int fs_ftp_command(const char *action,struct fs_exec_result *result)
{
    char *argv[]={JMX_FTP_INIT,(char *)action,NULL};return fs_exec_argv(argv,30000,NULL,0,result);
}

static int fs_ftp_intent_set(sqlite3 *db,int running)
{
    char boot[80];sqlite3_stmt *st=NULL;if(fs_dav_boot(boot,sizeof boot)!=0)return -1;
    if(fs_prepare(db,&st,"INSERT INTO ftp_service_intent VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET running=excluded.running,boot=excluded.boot WHERE running<>excluded.running OR boot<>excluded.boot")!=0)return -1;
    sqlite3_bind_int(st,1,running);sqlite3_bind_text(st,2,boot,-1,SQLITE_TRANSIENT);int rc=fs_step_done(st);sqlite3_finalize(st);return rc;
}

static int fs_ftp_wants_running(sqlite3 *db)
{
    char boot[80];sqlite3_stmt *st=NULL;int wanted=-1;
    if(fs_dav_boot(boot,sizeof boot)==0 && fs_prepare(db,&st,"SELECT running,boot FROM ftp_service_intent WHERE id=1")==0 && sqlite3_step(st)==SQLITE_ROW && !strcmp(boot,fs_sql_text(st,1,"")))wanted=sqlite3_column_int(st,0);
    if(st)sqlite3_finalize(st);if(wanted>=0)return wanted;struct fs_exec_result r={0};
    return fs_ftp_running() || fs_ftp_command("enabled",&r)==0;
}

static void fs_ftp_error(sqlite3 *db,const char *reason,int64_t revision)
{
    sqlite3_stmt *st=NULL;
    if(fs_prepare(db,&st,"INSERT INTO ftp_service_error SELECT 1,?1,?2 WHERE EXISTS(SELECT 1 FROM file_service_meta WHERE id=1 AND revision=?3) ON CONFLICT(id) DO UPDATE SET error=excluded.error,updated_at=excluded.updated_at")!=0)return;
    sqlite3_bind_text(st,1,reason,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,fs_now_s());sqlite3_bind_int64(st,3,revision);sqlite3_step(st);sqlite3_finalize(st);
}

static int fs_ftp_account_refs(sqlite3 *db,const char *login,struct json_object *refs)
{
    if(!login)return 0;sqlite3_stmt *st=NULL;if(fs_prepare(db,&st,"SELECT id,spec_json FROM ftp_share")!=0)return -1;int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){struct json_object *s=json_tokener_parse(fs_sql_text(st,1,"{}")),*users=NULL;
        if(!s){sqlite3_finalize(st);return -1;}json_object_object_get_ex(s,"users",&users);
        for(size_t i=0;i<json_object_array_length(users);i++){struct fs_account a;
            if(fs_account_load(db,fs_dav_str(json_object_array_get_idx(users,i),"account_id"),&a)==1 && !strcmp(a.login,login)){
                struct json_object *r=json_object_new_object();json_object_object_add(r,"protocol",json_object_new_string("ftp"));json_object_object_add(r,"id",json_object_new_string(fs_sql_text(st,0,"")));json_object_object_add(r,"name",json_object_new_string(fs_dav_str(s,"name")));json_object_array_add(refs,r);break;}}
        json_object_put(s);
    }
    sqlite3_finalize(st);return step==SQLITE_DONE?0:-1;
}

static int fs_ftp_share_active(sqlite3 *db,struct json_object *spec)
{
    struct json_object *users=NULL;
    if(!fs_dav_bool(spec,"enabled") || !fs_dav_binding(spec))return 0;
    json_object_object_get_ex(spec,"users",&users);
    for(size_t i=0;i<json_object_array_length(users);i++){
        struct fs_account a;
        if(fs_account_load(db,fs_dav_str(json_object_array_get_idx(users,i),"account_id"),&a)==1 && a.enabled && fs_account_owned(&a,1))return 1;
    }
    return 0;
}

static struct json_object *fs_ftp_get(sqlite3 *db)
{
    int64_t revision=0,control=0;struct json_object *settings=fs_ftp_load(db,NULL,&revision);
    struct json_object *data=json_object_new_object(),*shares=json_object_new_array(),*caps=json_object_new_object(),*reasons=json_object_new_object();
    int installed=fs_ftp_installed(),running=fs_ftp_running();sqlite3_stmt *st=NULL;
    if(fs_prepare(db,&st,"SELECT id,spec_json,revision FROM ftp_share ORDER BY id")!=0)goto fail;int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){struct json_object *spec=json_tokener_parse(fs_sql_text(st,1,"{}"));if(!spec)goto fail;
        int available=fs_dav_binding(spec),live=running && fs_ftp_share_active(db,spec);
        json_object_object_add(spec,"id",json_object_new_string(fs_sql_text(st,0,"")));json_object_object_add(spec,"revision",json_object_new_int64(sqlite3_column_int64(st,2)));
        json_object_object_add(spec,"path_available",json_object_new_boolean(available));json_object_object_add(spec,"path_reason",json_object_new_string(available?"":"directory_binding_changed"));json_object_object_add(spec,"running",json_object_new_boolean(live));
        char url[320];snprintf(url,sizeof url,"ftp://%s:%lld/%s/",fs_dav_str(settings,"listen_address"),(long long)fs_dav_int(settings,"listen_port"),fs_dav_str(spec,"name"));
        json_object_object_add(spec,"url",live?json_object_new_string(url):NULL);json_object_object_add(spec,"tls_mode",json_object_new_string(fs_dav_bool(settings,"tls")?"explicit_required":"disabled"));json_object_array_add(shares,spec);
    }
    sqlite3_finalize(st);st=NULL;if(step!=SQLITE_DONE)goto fail;
    json_object_object_add(data,"service",json_object_new_string("ftp"));json_object_object_add(data,"installed",json_object_new_boolean(installed));json_object_object_add(data,"available",json_object_new_boolean(installed));json_object_object_add(data,"running",json_object_new_boolean(running));json_object_object_add(data,"requested_running",json_object_new_boolean(fs_ftp_wants_running(db)));
    struct fs_exec_result r={0};int enabled=fs_ftp_command("enabled",&r);json_object_object_add(data,"enabled",installed && (enabled==0 || r.exit_code==1)?json_object_new_boolean(enabled==0):NULL);
    json_object_object_add(data,"source",json_object_new_string(settings?"config_db":"unconfigured"));json_object_object_add(data,"config_source",json_object_new_string("config_db"));json_object_object_add(data,"revision",json_object_new_int64(revision));
    if(fs_meta_revision_lookup(db,&control)==1)json_object_object_add(data,"control_revision",json_object_new_int64(control));
    json_object_object_add(data,"isolation",json_object_new_string("per_user_chroot_bind_mounts"));json_object_object_add(data,"anonymous_access",json_object_new_boolean(0));json_object_object_add(data,"local_login_policy",json_object_new_string("dedicated_share_accounts_only"));
    json_object_object_add(data,"settings",settings);settings=NULL;json_object_object_add(data,"shares",shares);shares=NULL;
    const char *keys[]={"settings","shares","actions","autostart","users","tls"};
    for(size_t i=0;i<6;i++){json_object_object_add(caps,keys[i],json_object_new_boolean(installed));if(!installed)json_object_object_add(reasons,keys[i],json_object_new_string("managed_ftp_runtime_missing"));}
    json_object_object_add(data,"accounts_url",json_object_new_string("/api/v1/services/file-sharing/accounts"));json_object_object_add(data,"capabilities",caps);caps=NULL;json_object_object_add(data,"capability_reasons",reasons);reasons=NULL;
    if(fs_prepare(db,&st,"SELECT error,updated_at FROM ftp_service_error WHERE id=1")==0 && sqlite3_step(st)==SQLITE_ROW){json_object_object_add(data,"last_error",json_object_new_string(fs_sql_text(st,0,"")));json_object_object_add(data,"last_error_at",json_object_new_int64(sqlite3_column_int64(st,1)));}else json_object_object_add(data,"last_error",json_object_new_string(""));
    if(st)sqlite3_finalize(st);fs_add_contract(data);return data;
fail:
    if(st)sqlite3_finalize(st);json_object_put(data);json_object_put(settings);json_object_put(shares);json_object_put(caps);json_object_put(reasons);return NULL;
}

static int fs_ftp_file(const char *dir,const char *name,const char *text,mode_t mode)
{
    char path[PATH_MAX];if(fs_service_path_join(path,sizeof path,dir,name)!=0)return -1;return fs_atomic_replace(path,text,strlen(text),mode);
}

static void fs_ftp_hex(const unsigned char *in,size_t size,char *out)
{
    for(size_t i=0;i<size;i++)sprintf(out+2*i,"%02x",in[i]);
}

static int fs_ftp_unhex(const char *in,unsigned char *out,size_t size)
{
    if(strlen(in)!=size*2)return 0;for(size_t i=0;i<size;i++){unsigned v;if(!isxdigit(in[i*2]) || !isxdigit(in[i*2+1]) || sscanf(in+i*2,"%2x",&v)!=1)return 0;out[i]=v;}return 1;
}

static int fs_ftp_auth(void)
{
    unsigned char password[513]={0},salt[16],expected[32],actual[32];size_t len=0;int ok=0;
    char generation[PATH_MAX];const char *login=getenv("PAM_USER"),*type=getenv("PAM_TYPE");struct json_object *auth=NULL,*entry=NULL;
    if(geteuid()!=0 || !login || !type || strcmp(type,"auth") || !fs_ftp_current(generation,sizeof generation))goto out;
    for(;;){ssize_t n=read(STDIN_FILENO,password+len,sizeof password-len);if(n<0){if(errno==EINTR)continue;goto out;}if(!n)break;len+=n;if(len==sizeof password)goto out;}
    if(len && !password[len-1])len--;if(len<12 || len>128 || memchr(password,0,len))goto out;
    auth=fs_ftp_json(generation,"auth.json");if(!auth || !json_object_object_get_ex(auth,login,&entry))goto out;
    struct fs_account a={0};snprintf(a.id,sizeof a.id,"%s",fs_dav_str(entry,"id"));snprintf(a.login,sizeof a.login,"%s",login);a.uid=fs_dav_int(entry,"uid");a.gid=fs_dav_int(entry,"gid");
    if(!fs_account_owned(&a,1) || !fs_ftp_unhex(fs_dav_str(entry,"salt"),salt,sizeof salt) || !fs_ftp_unhex(fs_dav_str(entry,"hash"),expected,sizeof expected))goto out;
    ok=PKCS5_PBKDF2_HMAC((char *)password,len,salt,sizeof salt,FS_FTP_ROUNDS,EVP_sha256(),sizeof actual,actual)==1 && CRYPTO_memcmp(expected,actual,sizeof actual)==0;
out:
    json_object_put(auth);OPENSSL_cleanse(password,sizeof password);OPENSSL_cleanse(actual,sizeof actual);OPENSSL_cleanse(expected,sizeof expected);return ok?0:1;
}

static int fs_ftp_dir(const char *path,mode_t mode)
{
    struct stat st;if(mkdir(path,mode)!=0 && errno!=EEXIST)return -1;
    return lstat(path,&st)==0 && S_ISDIR(st.st_mode) && st.st_uid==0 && !(st.st_mode&0022)?0:-1;
}

static int fs_ftp_cleanup(void)
{
    for(int i=0;i<30;i++){int count=fs_ftp_processes(i<20?SIGTERM:SIGKILL);if(count<0)return -1;if(!count)break;usleep(100000);}
    if(fs_ftp_processes(0)!=0)return -1;
    DIR *roots=opendir(JMX_FTP_RUN "/users");struct dirent *user;int ok=1;
    while(roots && (user=readdir(roots))){if(strncmp(user->d_name,"dwshare_",8) || !fs_account_name_ok(user->d_name+8))continue;
        char path[PATH_MAX];snprintf(path,sizeof path,JMX_FTP_RUN "/users/%s",user->d_name);DIR *dir=opendir(path);if(!dir){ok=0;continue;}struct dirent *share;
        while((share=readdir(dir))){if(!strcmp(share->d_name,".") || !strcmp(share->d_name,".."))continue;
            char target[PATH_MAX],canonical[PATH_MAX];if(fs_service_path_join(target,sizeof target,path,share->d_name)!=0){ok=0;continue;}
            /* /var/run is a symlink on OpenWrt; mountinfo names /tmp/run. */
            if(realpath(target,canonical) && fs_binding_mounted(canonical) && umount2(target,MNT_DETACH)!=0)ok=0;
            if(rmdir(target)!=0)ok=0;
        }closedir(dir);if(rmdir(path)!=0)ok=0;
    }
    if(roots)closedir(roots);
    DIR *pins=opendir(JMX_SHARE_PUBLISH_ROOT);struct dirent *pin;
    while(pins && (pin=readdir(pins)))if(!strncmp(pin->d_name,"ftp-",4) && fs_id_ok(pin->d_name))fs_binding_unpin(pin->d_name);
    if(pins)closedir(pins);unlink(JMX_FTP_RUN "/generation");return ok?0:-1;
}

static int fs_ftp_prepare(void)
{
    char generation[PATH_MAX];struct json_object *manifest=NULL;int ok=0;
    if(fs_ftp_cleanup()!=0 || !fs_ftp_current(generation,sizeof generation))return -1;
    manifest=fs_ftp_json(generation,"shares.json");if(!manifest || !json_object_is_type(manifest,json_type_array))goto out;
    if(fs_ftp_dir(JMX_FTP_RUN,0755)!=0 || fs_ftp_dir(JMX_FTP_RUN "/users",0755)!=0 || fs_ftp_dir(JMX_FTP_RUN "/empty",0555)!=0)goto out;
    for(size_t i=0;i<json_object_array_length(manifest);i++){
        struct json_object *s=json_object_array_get_idx(manifest,i),*users=NULL;
        if(!fs_dav_bool(s,"active"))continue;
        if(!fs_dav_binding(s))goto out;char source[FS_MAX_PATH+1];struct json_object *identity=NULL;
        json_object_object_get_ex(s,"storage_binding",&identity);
        if(fs_binding_pin(fs_dav_str(s,"id"),fs_dav_str(s,"path"),identity,source,sizeof source)!=1)goto out;
        json_object_object_get_ex(s,"logins",&users);
        for(size_t j=0;j<json_object_array_length(users);j++){
            struct json_object *u=json_object_array_get_idx(users,j);char root[PATH_MAX],target[PATH_MAX];
            snprintf(root,sizeof root,JMX_FTP_RUN "/users/%s",fs_dav_str(u,"login"));if(fs_ftp_dir(root,0755)!=0)goto out;
            if(fs_service_path_join(target,sizeof target,root,fs_dav_str(s,"name"))!=0 || fs_ftp_dir(target,0000)!=0 || mount(source,target,NULL,MS_BIND,NULL)!=0)goto out;
            /* Change flags on this bind only. The source mount remains untouched. */
            struct statvfs flags;if(statvfs(target,&flags)!=0)goto out;
            unsigned long mountflags=MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV;
            if(fs_dav_bool(u,"read_only") || (flags.f_flag&ST_RDONLY))mountflags|=MS_RDONLY;
            if(flags.f_flag&ST_NOEXEC)mountflags|=MS_NOEXEC;
            if(mount(NULL,target,NULL,mountflags,NULL)!=0)goto out;
        }
    }
    if(fs_ftp_file(JMX_FTP_RUN,"generation",generation,0600)!=0)goto out;ok=1;
out:json_object_put(manifest);if(!ok)fs_ftp_cleanup();return ok?0:-1;
}

int jmx_file_service_ftp_runtime(const char *action)
{
    if(!strcmp(action,"auth"))return fs_ftp_auth();
    if(geteuid()==0 && !strcmp(action,"launch")){
        char generation[PATH_MAX],config[PATH_MAX];struct fs_snapshot prepared={0};
        if(!fs_ftp_current(generation,sizeof generation) ||
           fs_snapshot_read(JMX_FTP_RUN "/generation",&prepared)!=0)return 1;
        int ready=prepared.existed && !strcmp(prepared.data,generation);fs_snapshot_free(&prepared);
        if(!ready)return 1;
        /* vsftpd enters the passwd home before the configured local_root.
         * Give only this process tree a traversable empty /var/empty; the
         * host's privileged sandbox and the locked account records stay intact. */
        if(unshare(CLONE_NEWNS)!=0 || mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)!=0 ||
           mount(JMX_FTP_RUN "/empty",FS_ACCOUNT_HOME,NULL,MS_BIND,NULL)!=0 ||
           mount(NULL,FS_ACCOUNT_HOME,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)!=0)return 1;
        if(fs_service_path_join(config,sizeof config,generation,"vsftpd.conf")!=0)return 1;
        char *argv[]={JMX_FTP_BINARY,config,NULL};execv(JMX_FTP_BINARY,argv);return 1;
    }
    if(geteuid()!=0 || (strcmp(action,"prepare") && strcmp(action,"cleanup")))return 1;
    if(fs_ftp_dir(JMX_FTP_RUN,0755)!=0)return 1;
    int lock=open(JMX_FTP_RUN "/lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if(lock<0 || flock(lock,LOCK_EX)!=0){if(lock>=0)close(lock);return 1;}
    int rc=!strcmp(action,"prepare")?fs_ftp_prepare():fs_ftp_cleanup();close(lock);return rc==0?0:1;
}

static int fs_ftp_access(const char *path,struct fs_account *a,int writing)
{
    pid_t pid=fork();if(pid<0)return 0;
    if(!pid){if(setgroups(0,NULL)||setgid(a->gid)||setuid(a->uid))_exit(2);_exit(access(path,R_OK|X_OK|(writing?W_OK:0))==0?0:1);}
    int status;while(waitpid(pid,&status,0)<0)if(errno!=EINTR)return 0;return WIFEXITED(status)&&WEXITSTATUS(status)==0;
}

static int fs_ftp_auth_entry(struct ac_secrets *secrets,struct fs_account *a,struct json_object *auth,struct json_object *cached)
{
    struct json_object *entry=NULL;
    if(json_object_object_get_ex(auth,a->login,&entry))return 0;
    if(cached && json_object_object_get_ex(cached,a->login,&entry) && fs_dav_int(entry,"secret_version")==a->secret_version &&
       fs_dav_int(entry,"uid")==a->uid && fs_dav_int(entry,"gid")==a->gid && !strcmp(fs_dav_str(entry,"id"),a->id)){
        json_object_object_add(auth,a->login,json_object_get(entry));return 0;}
    unsigned char *secret=NULL,salt[16],digest[32];size_t len=0;char id[96],hexsalt[33],hexhash[65];int ok=0;
    snprintf(id,sizeof id,"file-share:%s",a->id);
    if(ac_secrets_get(secrets,id,a->secret_version,&secret,&len)!=AC_SECRETS_OK || RAND_bytes(salt,sizeof salt)!=1 ||
       PKCS5_PBKDF2_HMAC((char *)secret,len,salt,sizeof salt,FS_FTP_ROUNDS,EVP_sha256(),sizeof digest,digest)!=1)goto out;
    fs_ftp_hex(salt,sizeof salt,hexsalt);fs_ftp_hex(digest,sizeof digest,hexhash);entry=json_object_new_object();
    json_object_object_add(entry,"id",json_object_new_string(a->id));json_object_object_add(entry,"uid",json_object_new_int(a->uid));json_object_object_add(entry,"gid",json_object_new_int(a->gid));json_object_object_add(entry,"secret_version",json_object_new_int64(a->secret_version));json_object_object_add(entry,"salt",json_object_new_string(hexsalt));json_object_object_add(entry,"hash",json_object_new_string(hexhash));json_object_object_add(auth,a->login,entry);ok=1;
out:ac_secrets_clear(secret,len);OPENSSL_cleanse(digest,sizeof digest);OPENSSL_cleanse(hexhash,sizeof hexhash);return ok?0:-1;
}

static void fs_ftp_prune(void)
{
    char current[PATH_MAX]="";fs_ftp_current(current,sizeof current);DIR *base=opendir(JMX_FTP_BASE);if(!base)return;struct dirent *e;
    while((e=readdir(base))){if(strncmp(e->d_name,"generation-",11) || !fs_id_ok(e->d_name))continue;char path[PATH_MAX];struct stat st;
        snprintf(path,sizeof path,JMX_FTP_BASE "/%s",e->d_name);if(!strcmp(current,path) || lstat(path,&st)!=0 || !S_ISDIR(st.st_mode))continue;
        char configs[PATH_MAX];if(fs_service_path_join(configs,sizeof configs,path,"users")!=0)continue;DIR *dir=opendir(configs);struct dirent *u;
        while(dir && (u=readdir(dir))){if(strncmp(u->d_name,"dwshare_",8) || !fs_account_name_ok(u->d_name+8))continue;char file[PATH_MAX];if(fs_service_path_join(file,sizeof file,configs,u->d_name)==0)unlink(file);}
        if(dir)closedir(dir);rmdir(configs);
        const char *names[]={"auth.json","shares.json","settings.json","vsftpd.conf","allowlist","tls.key","tls.crt"};
        for(size_t i=0;i<sizeof names/sizeof names[0];i++){char file[PATH_MAX];if(fs_service_path_join(file,sizeof file,path,names[i])==0)unlink(file);}rmdir(path);
    }closedir(base);
}

static int fs_ftp_project(sqlite3 *db,struct json_object *settings,char *generation,const char **reason)
{
    struct ac_secrets *secrets=NULL;struct json_object *manifest=json_object_new_array(),*auth=json_object_new_object(),*cached=NULL;
    struct fs_buffer cfg={0},allow={0};sqlite3_stmt *st=NULL;int rc=-1;char current[PATH_MAX];
    fs_ftp_prune();
    if(fs_ftp_dir(JMX_FTP_BASE,0700)!=0 || !mkdtemp(generation)){*reason="ftp_generation_failed";goto out;}
    char usersdir[PATH_MAX];snprintf(usersdir,sizeof usersdir,"%s/users",generation);if(mkdir(usersdir,0700)!=0)goto out;
    if(fs_ftp_current(current,sizeof current))cached=fs_ftp_json(current,"auth.json");
    if(fs_prepare(db,&st,"SELECT id,spec_json FROM ftp_share")!=0)goto out;int step;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        struct json_object *s=json_tokener_parse(fs_sql_text(st,1,"{}")),*users=NULL,*logins=json_object_new_array();if(!s){json_object_put(logins);goto out;}
        json_object_object_add(s,"id",json_object_new_string(fs_sql_text(st,0,"")));int active=fs_ftp_share_active(db,s);
        json_object_object_add(s,"active",json_object_new_boolean(active));json_object_object_add(s,"logins",logins);json_object_array_add(manifest,s);
        if(!active)continue;
        json_object_object_get_ex(s,"users",&users);
        for(size_t i=0;i<json_object_array_length(users);i++){
            struct json_object *u=json_object_array_get_idx(users,i);struct fs_account a;
            if(fs_account_load(db,fs_dav_str(u,"account_id"),&a)!=1 || !fs_account_owned(&a,1)){*reason="ftp_identity_conflict";goto out;}
            if(!a.enabled)continue;
            int ro=fs_dav_bool(s,"read_only") || fs_dav_bool(u,"read_only");
            if(!fs_ftp_access(fs_dav_str(s,"path"),&a,!ro)){*reason="directory_permission_denied";goto out;}
            if(!secrets && ac_secrets_open(db,JMX_SHARE_SECRET_KEY_PATH,&secrets)!=AC_SECRETS_OK){*reason="ftp_credentials_unavailable";goto out;}
            if(fs_ftp_auth_entry(secrets,&a,auth,cached)!=0){*reason="ftp_credentials_unavailable";goto out;}
            struct json_object *entry=json_object_new_object();json_object_object_add(entry,"login",json_object_new_string(a.login));json_object_object_add(entry,"read_only",json_object_new_boolean(ro));json_object_array_add(logins,entry);
        }
    }
    sqlite3_finalize(st);st=NULL;if(step!=SQLITE_DONE)goto out;
    json_object_object_foreach(auth,login,entry){(void)entry;char text[PATH_MAX+80];
        snprintf(text,sizeof text,"local_root=" JMX_FTP_RUN "/users/%s\n",login);
        if(fs_ftp_file(usersdir,login,text,0600)!=0 || fs_dav_printf(&allow,"%s\n",login)!=0)goto out;
    }
    if(fs_dav_printf(&cfg,"listen=YES\nlisten_ipv6=NO\nbackground=NO\nlisten_address=%s\nlisten_port=%lld\n"
        "anonymous_enable=NO\nlocal_enable=YES\nguest_enable=NO\nwrite_enable=YES\nlocal_umask=077\n"
        "chroot_local_user=YES\nallow_writeable_chroot=NO\nlocal_root=" JMX_FTP_RUN "/empty\n"
        "user_config_dir=%s/users\nuserlist_enable=YES\nuserlist_deny=NO\nuserlist_file=%s/allowlist\n"
        "pam_service_name=dreamingwrt-ftp\nsession_support=NO\nsecure_chroot_dir=" JMX_FTP_RUN "/empty\n"
        "nopriv_user=nobody\nchmod_enable=NO\nseccomp_sandbox=YES\n"
        "pasv_enable=YES\nport_enable=YES\ncmds_denied=PORT,EPRT\npasv_min_port=%lld\npasv_max_port=%lld\n"
        /* r11 gates getrandom() in its sandbox on transfer logging. Use the
         * existing system log (bounded by logd), with command/password logging off. */
        "xferlog_enable=YES\nsyslog_enable=YES\nlog_ftp_protocol=NO\nssl_enable=%s\n",fs_dav_str(settings,"listen_address"),(long long)fs_dav_int(settings,"listen_port"),generation,generation,
        (long long)fs_dav_int(settings,"passive_min_port"),(long long)fs_dav_int(settings,"passive_max_port"),fs_dav_bool(settings,"tls")?"YES":"NO")!=0)goto out;
    if(fs_dav_str(settings,"passive_address")[0] && fs_dav_printf(&cfg,"pasv_address=%s\n",fs_dav_str(settings,"passive_address"))!=0)goto out;
    if(fs_dav_bool(settings,"tls")){
        for(int i=0;i<2;i++){struct fs_snapshot pem={0};if(fs_snapshot_read(fs_dav_str(settings,i?"key_file":"cert_file"),&pem)!=0 || !pem.existed){fs_snapshot_free(&pem);*reason="invalid_certificate";goto out;}
            int ok=fs_ftp_file(generation,i?"tls.key":"tls.crt",pem.data,0600)==0;if(pem.data)OPENSSL_cleanse(pem.data,pem.len);fs_snapshot_free(&pem);if(!ok)goto out;}
        if(fs_dav_printf(&cfg,"ssl_sslv2=NO\nssl_sslv3=NO\nssl_tlsv1=NO\nssl_tlsv11=NO\nssl_tlsv12=YES\nssl_tlsv13=YES\nforce_local_logins_ssl=YES\nforce_local_data_ssl=YES\nrequire_ssl_reuse=YES\nrsa_cert_file=%s/tls.crt\nrsa_private_key_file=%s/tls.key\n",generation,generation)!=0)goto out;
    }
    if(fs_ftp_file(generation,"vsftpd.conf",cfg.data,0600)!=0 || fs_ftp_file(generation,"allowlist",allow.data?allow.data:"",0600)!=0 ||
       fs_ftp_file(generation,"auth.json",json_object_to_json_string_ext(auth,JSON_C_TO_STRING_PLAIN),0600)!=0 ||
       fs_ftp_file(generation,"shares.json",json_object_to_json_string_ext(manifest,JSON_C_TO_STRING_PLAIN),0600)!=0 ||
       fs_ftp_file(generation,"settings.json",json_object_to_json_string_ext(settings,JSON_C_TO_STRING_PLAIN),0600)!=0)goto out;
    rc=0;
out:if(st)sqlite3_finalize(st);ac_secrets_close(secrets);json_object_put(manifest);json_object_put(auth);json_object_put(cached);fs_buffer_free(&cfg);fs_buffer_free(&allow);return rc;
}

static int fs_ftp_port_available(struct json_object *settings)
{
    int first=fs_dav_int(settings,"passive_min_port"),last=fs_dav_int(settings,"passive_max_port");
    for(int port=first-1;port<=last;port++){
        int candidate=port==first-1?fs_dav_int(settings,"listen_port"):port;
        int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return 0;
        int reuse=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof reuse);
        struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(candidate)};inet_pton(AF_INET,fs_dav_str(settings,"listen_address"),&addr.sin_addr);
        int ok=bind(fd,(struct sockaddr *)&addr,sizeof addr)==0;close(fd);if(!ok && !fs_ftp_owns_port(addr.sin_addr,candidate))return 0;
    }
    return 1;
}

static const char *fs_ftp_validate_settings(struct json_object *s)
{
    struct json_object *v=NULL;const char *strings[]={"listen_address","passive_address","cert_file","key_file"};
    for(size_t i=0;i<4;i++)if(!json_object_object_get_ex(s,strings[i],&v) || !json_object_is_type(v,json_type_string) || !fs_text_ok(json_object_get_string(v),FS_MAX_PATH,i==0))return "invalid_field";
    if(!json_object_object_get_ex(s,"tls",&v) || !json_object_is_type(v,json_type_boolean))return "invalid_boolean";
    const char *ports[]={"listen_port","passive_min_port","passive_max_port"};
    for(size_t i=0;i<3;i++)if(!json_object_object_get_ex(s,ports[i],&v) || !json_object_is_type(v,json_type_int) || fs_dav_int(s,ports[i])<(i?1024:1) || fs_dav_int(s,ports[i])>65535)return "invalid_port";
    int first=fs_dav_int(s,"passive_min_port"),last=fs_dav_int(s,"passive_max_port"),port=fs_dav_int(s,"listen_port");
    if(last<first || last-first>=64 || (port>=first && port<=last))return "invalid_passive_range";
    struct in_addr addr;const char *host=fs_dav_str(s,"listen_address");int local=0;
    if(inet_pton(AF_INET,host,&addr)!=1 || !addr.s_addr || IN_MULTICAST(ntohl(addr.s_addr)) || addr.s_addr==INADDR_BROADCAST)return "invalid_address";
    struct ifaddrs *ifaces=NULL;if(getifaddrs(&ifaces)==0){for(struct ifaddrs *a=ifaces;a;a=a->ifa_next)if(a->ifa_addr && a->ifa_addr->sa_family==AF_INET && ((struct sockaddr_in *)a->ifa_addr)->sin_addr.s_addr==addr.s_addr)local=1;freeifaddrs(ifaces);}
    if(!local)return "listener_address_not_on_device";
    host=fs_dav_str(s,"passive_address");if(*host && (inet_pton(AF_INET,host,&addr)!=1 || !addr.s_addr || IN_MULTICAST(ntohl(addr.s_addr)) || addr.s_addr==INADDR_BROADCAST))return "invalid_passive_address";
    if(fs_dav_bool(s,"tls")){
        for(int i=0;i<2;i++){const char *path=fs_dav_str(s,i?"key_file":"cert_file");struct stat st;if(!fs_dav_path_text(path) || stat(path,&st)!=0 || !S_ISREG(st.st_mode))return "invalid_certificate";}
        SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());int ok=ctx && SSL_CTX_use_certificate_chain_file(ctx,fs_dav_str(s,"cert_file"))==1 &&
            SSL_CTX_use_PrivateKey_file(ctx,fs_dav_str(s,"key_file"),SSL_FILETYPE_PEM)==1 && SSL_CTX_check_private_key(ctx)==1;SSL_CTX_free(ctx);if(!ok)return "invalid_certificate";
    }
    return NULL;
}

static int fs_ftp_wait(int running)
{
    for(int i=0;i<100;i++){if(running?fs_ftp_running():fs_ftp_processes(0)==0)return 0;usleep(100000);}return -1;
}

static int fs_ftp_apply(sqlite3 *db,struct fs_snapshot *old,int *replaced,int start,const char **reason)
{
    int64_t rev;struct json_object *settings=fs_ftp_load(db,NULL,&rev);if(!settings){*reason="ftp_settings_required";return -1;}
    const char *invalid=fs_ftp_validate_settings(settings);if(invalid){*reason=invalid;json_object_put(settings);return -1;}
    if(!fs_ftp_port_available(settings)){*reason="port_in_use";json_object_put(settings);return -1;}
    char generation[PATH_MAX]=JMX_FTP_BASE "/generation-XXXXXX";
    int rc=fs_ftp_project(db,settings,generation,reason);json_object_put(settings);if(rc!=0)return -1;
    if(fs_snapshot_read(JMX_FTP_BASE "/current",old)!=0 || fs_atomic_replace(JMX_FTP_BASE "/current",generation,strlen(generation),0600)!=0){*reason="ftp_config_replace_failed";return -1;}*replaced=1;
    if(start){
        struct json_object *auth=fs_ftp_json(generation,"auth.json");int listen=auth && json_object_object_length(auth)>0;json_object_put(auth);
        struct fs_exec_result r={0};if(fs_ftp_command(listen?"restart":"stop",&r)!=0 || fs_ftp_wait(listen)!=0){*reason=r.timed_out?"ftp_service_timeout":"ftp_listener_not_ready";return -1;}
    }
    return 0;
}

static int fs_ftp_restore(const struct fs_snapshot *old,int replaced,int running)
{
    if(!replaced)return 0;struct fs_exec_result r={0};
    if(fs_snapshot_restore(JMX_FTP_BASE "/current",old)!=0 || fs_ftp_command(running?"restart":"stop",&r)!=0)return -1;
    return fs_ftp_wait(running);
}

static void fs_ftp_reconcile(sqlite3 *db)
{
    if(!fs_ftp_installed())return;int wanted=fs_ftp_wants_running(db);if(fs_ftp_intent_set(db,wanted)!=0 || !wanted)return;
    char generation[PATH_MAX];struct json_object *manifest=fs_ftp_current(generation,sizeof generation)?fs_ftp_json(generation,"shares.json"):NULL;
    int active=0,changed=0;
    for(size_t i=0;i<json_object_array_length(manifest);i++){
        struct json_object *s=json_object_array_get_idx(manifest,i);int desired=fs_ftp_share_active(db,s);
        if(desired)active=1;if(fs_dav_bool(s,"active")!=desired)changed=1;
    }
    if(active!=fs_ftp_running())changed=1;
    json_object_put(manifest);if(!changed)return;
    /* Withdraw sessions first. A missing/replaced disk must never be restored. */
    struct fs_exec_result r={0};struct fs_snapshot old={0};int replaced=0;const char *reason="ftp_withdraw_failed";
    int rc=fs_ftp_command("stop",&r);if(rc==0)rc=fs_ftp_apply(db,&old,&replaced,1,&reason);
    if(rc==0)fs_sql_exec(db,"DELETE FROM ftp_service_error");
    else{int64_t revision=0;if(fs_meta_revision_lookup(db,&revision)==1)fs_ftp_error(db,reason,revision);}
    fs_snapshot_free(&old);
}

struct json_object *jmx_ftp_settings_set(struct json_object *req)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct json_object *p=fs_payload(req),*s=NULL,*v=NULL,*response=NULL;
    struct fs_snapshot old={0};int replaced=0,tx=0,running=0,wanted=0;int64_t revision=0,control=0;const char *reason="ftp_settings_write_failed";
    if(!fs_confirmed(req))return fs_error("confirmation_required","confirm_true_required");
    if(!fs_ftp_installed())return fs_error("runtime_not_installed","managed_ftp_runtime_missing");
    if(!json_object_object_get_ex(p,"expected_revision",&v) || !json_object_is_type(v,json_type_int) || json_object_get_int64(v)<0)return fs_error("missing_expected_revision","ftp_settings_revision_required");
    int64_t expected=json_object_get_int64(v);
    if(fs_db_open(&db)!=0)return fs_error("storage_unavailable","config_db_open_failed");
    if(fs_sql_exec(db,"BEGIN IMMEDIATE")!=0){response=fs_error("storage_busy","protocol_operation_in_progress");goto out;}tx=1;
    if(fs_meta_revision_lookup(db,&control)!=1)goto out;
    s=fs_ftp_load(db,NULL,&revision);if(expected!=revision){response=fs_revision_conflict("ftp_settings_changed",expected,revision);goto out;}
    if(!s)s=json_tokener_parse("{\"listen_port\":21,\"passive_min_port\":50000,\"passive_max_port\":50009,\"passive_address\":\"\",\"tls\":false,\"cert_file\":\"\",\"key_file\":\"\"}");
    json_object_object_foreach(p,k,value){
        if(!strcmp(k,"confirm") || !strcmp(k,"expected_revision"))continue;
        if(strcmp(k,"listen_address") && strcmp(k,"listen_port") && strcmp(k,"passive_min_port") && strcmp(k,"passive_max_port") && strcmp(k,"passive_address") && strcmp(k,"tls") && strcmp(k,"cert_file") && strcmp(k,"key_file")){response=fs_error("invalid_field",k);goto out;}
        json_object_object_add(s,k,json_object_get(value));
    }
    const char *invalid=fs_ftp_validate_settings(s);if(invalid){response=fs_error(invalid,"ftp_settings_validation_failed");goto out;}
    if(fs_prepare(db,&st,"INSERT INTO ftp_settings VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET spec_json=excluded.spec_json,revision=excluded.revision")!=0)goto out;
    sqlite3_bind_text(st,1,json_object_to_json_string_ext(s,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,revision+1);if(fs_step_done(st)!=0)goto out;sqlite3_finalize(st);st=NULL;
    running=fs_ftp_running();wanted=fs_ftp_wants_running(db);
    if(fs_ftp_apply(db,&old,&replaced,wanted,&reason)!=0 || fs_sql_exec(db,"DELETE FROM ftp_service_error")!=0 || fs_meta_bump(db)!=0 || fs_sql_exec(db,"COMMIT")!=0)goto rollback;
    tx=0;struct json_object *data=fs_ftp_get(db);if(data){json_object_object_add(data,"persisted",json_object_new_boolean(1));json_object_object_add(data,"applied",json_object_new_boolean(wanted));json_object_object_add(data,"restart_required",json_object_new_boolean(!wanted));response=fs_success(data);}goto out;
rollback:{int restored=fs_ftp_restore(&old,replaced,running)==0,dbok=fs_sql_exec(db,"ROLLBACK")==0;tx=0;if(dbok)fs_ftp_error(db,reason,control);
    struct json_object *data=fs_error_detail("ftp_apply_failed",reason);json_object_object_add(data,"rolled_back",json_object_new_boolean(restored&&dbok));json_object_object_add(data,"rollback_failed",json_object_new_boolean(!restored||!dbok));response=fs_envelope(FS_API_ERROR,data);}
out:if(st)sqlite3_finalize(st);if(tx)fs_sql_exec(db,"ROLLBACK");if(db)sqlite3_close(db);json_object_put(s);fs_snapshot_free(&old);return response?response:fs_error("storage_error",reason);
}

struct json_object *jmx_ftp_share_request(const char *method,const char *id,struct json_object *req)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct json_object *p=fs_payload(req),*spec=NULL,*previous=NULL,*v=NULL,*response=NULL;
    struct fs_snapshot old={0};int replaced=0,tx=0,running=0,create=!strcmp(method,"POST"),remove=!strcmp(method,"DELETE"),present=0,wanted=0;
    int64_t revision=0,expected=0,control=0;char generated[65],canonical[FS_MAX_PATH+1];const char *reason="ftp_share_write_failed";
    if(!fs_confirmed(req))return fs_error("confirmation_required","confirm_true_required");
    if(!fs_ftp_installed())return fs_error("runtime_not_installed","managed_ftp_runtime_missing");
    if(!create && !remove && strcmp(method,"PUT"))return fs_error("invalid_action","ftp_method_invalid");
    if(!create && (!fs_id_ok(id) || fs_json_positive_int64(p,"expected_revision",&expected,&present)!=0 || !present))return fs_error("missing_expected_revision","share_revision_required");
    if(fs_db_open(&db)!=0)return fs_error("storage_unavailable","config_db_open_failed");
    if(fs_sql_exec(db,"BEGIN IMMEDIATE")!=0){response=fs_error("storage_busy","protocol_operation_in_progress");goto out;}tx=1;
    if(fs_meta_revision_lookup(db,&control)!=1)goto out;running=fs_ftp_running();wanted=fs_ftp_wants_running(db);
    if(create){if(fs_random_id(db,"ftp","ftp_share",generated,sizeof generated)!=0)goto out;id=generated;spec=json_tokener_parse("{\"enabled\":true,\"read_only\":true,\"note\":\"\"}");}
    else{previous=fs_ftp_load(db,id,&revision);if(!previous){response=fs_error("not_found","ftp_share_not_found");goto out;}if(expected!=revision){response=fs_revision_conflict("ftp_share_changed",expected,revision);goto out;}spec=json_tokener_parse(json_object_to_json_string_ext(previous,JSON_C_TO_STRING_PLAIN));}
    json_object_object_foreach(p,k,value){if(!strcmp(k,"confirm") || !strcmp(k,"expected_revision") || !strcmp(k,"rebind"))continue;
        if(strcmp(k,"name") && strcmp(k,"path") && strcmp(k,"enabled") && strcmp(k,"read_only") && strcmp(k,"users") && strcmp(k,"note")){response=fs_error("invalid_field",k);goto out;}json_object_object_add(spec,k,json_object_get(value));}
    if(!remove){
        if(!json_object_object_get_ex(spec,"name",&v) || !json_object_is_type(v,json_type_string) || !fs_id_ok(json_object_get_string(v))){response=fs_error("invalid_name","use_1_to_64_letters_digits_underscore_hyphen");goto out;}
        const char *bools[]={"enabled","read_only"};for(int i=0;i<2;i++)if(!json_object_object_get_ex(spec,bools[i],&v) || !json_object_is_type(v,json_type_boolean)){response=fs_error("invalid_boolean",bools[i]);goto out;}
        const char *strings[]={"path","note"};for(int i=0;i<2;i++)if(!json_object_object_get_ex(spec,strings[i],&v) || !json_object_is_type(v,json_type_string) || !fs_text_ok(json_object_get_string(v),i?256:FS_MAX_PATH,!i)){response=fs_error("invalid_field",strings[i]);goto out;}
        if(!fs_dav_path_text(fs_dav_str(spec,"path"))){response=fs_error("invalid_path","safe_directory_required");goto out;}
        if(fs_dav_bool(spec,"enabled")){
            if(!fs_share_path_ok(fs_dav_str(spec,"path"),canonical,sizeof canonical)){response=fs_error("invalid_path","safe_existing_directory_required");goto out;}
            int rebind=0;if(fs_json_bool(p,"rebind",&rebind,&present)!=0){response=fs_error("invalid_boolean","rebind_must_be_boolean");goto out;}
            if(previous && !rebind && !strcmp(canonical,fs_dav_str(previous,"path")) && !fs_dav_binding(previous)){response=fs_error("directory_binding_changed","reselect_directory_or_disable_share");goto out;}
            struct json_object *identity=fs_binding_identity(canonical);if(!identity){response=fs_error("directory_binding_changed","filesystem_identity_unavailable");goto out;}
            json_object_object_add(spec,"path",json_object_new_string(canonical));json_object_object_add(spec,"storage_binding",identity);
        }
        if(fs_prepare(db,&st,"SELECT spec_json FROM ftp_share WHERE id<>?1")!=0)goto out;sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);int step;
        while((step=sqlite3_step(st))==SQLITE_ROW){struct json_object *other=json_tokener_parse(fs_sql_text(st,0,"{}"));int same=!strcasecmp(fs_dav_str(other,"name"),fs_dav_str(spec,"name"));json_object_put(other);if(same){response=fs_error("name_in_use","ftp_directory_name_must_be_unique");goto out;}}
        sqlite3_finalize(st);st=NULL;if(step!=SQLITE_DONE)goto out;
        if(!json_object_object_get_ex(spec,"users",&v) || !json_object_is_type(v,json_type_array) || !json_object_array_length(v) || json_object_array_length(v)>FS_MAX_USERS){response=fs_error("invalid_acl","explicit_share_accounts_required");goto out;}
        for(size_t i=0;i<json_object_array_length(v);i++){
            struct json_object *u=json_object_array_get_idx(v,i),*ro=NULL;struct fs_account a;
            if(!json_object_is_type(u,json_type_object)){response=fs_error("invalid_acl","account_object_required");goto out;}
            json_object_object_foreach(u,k,field){(void)field;if(strcmp(k,"account_id") && strcmp(k,"read_only")){response=fs_error("invalid_acl","unknown_account_field");goto out;}}
            if(fs_account_load(db,fs_dav_str(u,"account_id"),&a)!=1 || !fs_account_owned(&a,1) || !json_object_object_get_ex(u,"read_only",&ro) || !json_object_is_type(ro,json_type_boolean)){response=fs_error("invalid_acl","dedicated_account_and_read_only_required");goto out;}
            for(size_t j=0;j<i;j++)if(!strcmp(fs_dav_str(u,"account_id"),fs_dav_str(json_object_array_get_idx(v,j),"account_id"))){response=fs_error("invalid_acl","duplicate_account");goto out;}
            if(a.enabled && fs_dav_bool(spec,"enabled") && !fs_ftp_access(canonical,&a,!fs_dav_bool(spec,"read_only") && !fs_dav_bool(u,"read_only"))){response=fs_error("directory_permission_denied","share_account_requires_existing_directory_access");goto out;}
        }
    }
    if(fs_prepare(db,&st,remove?"DELETE FROM ftp_share WHERE id=?1":"INSERT INTO ftp_share VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET spec_json=excluded.spec_json,revision=excluded.revision")!=0)goto out;sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if(!remove){sqlite3_bind_text(st,2,json_object_to_json_string_ext(spec,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,revision+1);}if(fs_step_done(st)!=0)goto out;sqlite3_finalize(st);st=NULL;
    if(fs_ftp_apply(db,&old,&replaced,wanted,&reason)!=0 || fs_sql_exec(db,"DELETE FROM ftp_service_error")!=0 || fs_meta_bump(db)!=0 || fs_operation_receipt_state(db,id,revision+1,remove,wanted)!=0 || fs_sql_exec(db,"COMMIT")!=0)goto rollback;
    tx=0;struct json_object *data=json_object_new_object();json_object_object_add(data,"id",json_object_new_string(id));json_object_object_add(data,"revision",json_object_new_int64(revision+1));json_object_object_add(data,"persisted",json_object_new_boolean(1));json_object_object_add(data,"applied",json_object_new_boolean(wanted));json_object_object_add(data,"restart_required",json_object_new_boolean(!wanted));json_object_object_add(data,"deleted",json_object_new_boolean(remove));response=fs_success(data);goto out;
rollback:{int restored=fs_ftp_restore(&old,replaced,running)==0,dbok=fs_sql_exec(db,"ROLLBACK")==0;tx=0;if(dbok)fs_ftp_error(db,reason,control);
    struct json_object *data=fs_error_detail("ftp_apply_failed",reason);json_object_object_add(data,"rolled_back",json_object_new_boolean(restored&&dbok));json_object_object_add(data,"rollback_failed",json_object_new_boolean(!restored||!dbok));response=fs_envelope(FS_API_ERROR,data);}
out:if(st)sqlite3_finalize(st);if(tx)fs_sql_exec(db,"ROLLBACK");if(db)sqlite3_close(db);json_object_put(spec);json_object_put(previous);fs_snapshot_free(&old);return response?response:fs_error("storage_error",reason);
}

static struct json_object *fs_ftp_action(struct json_object *req)
{
    struct json_object *payload=fs_payload(req),*response=NULL,*data=NULL;
    struct fs_snapshot old={0};sqlite3 *db=NULL;struct fs_exec_result result={0},restore={0};
    const char *action=fs_dav_str(payload,"action"),*reason="ftp_action_failed";
    int64_t expected=0,revision=0;int present=0,tx=0,replaced=0,running=0,enabled=0,rc=-1,touched=0;
    int autostart=!strcmp(action,"enable") || !strcmp(action,"disable");
    if(!fs_confirmed(req))return fs_error("confirmation_required","confirm_true_required");
    if(!autostart && strcmp(action,"start") && strcmp(action,"stop") && strcmp(action,"restart"))return fs_error("invalid_action","start_stop_restart_enable_disable_only");
    if(!fs_ftp_installed())return fs_error("runtime_not_installed","managed_ftp_runtime_missing");
    if(fs_json_positive_int64(payload,"expected_revision",&expected,&present)!=0 || !present)return fs_error("missing_expected_revision","control_revision_required");
    if(fs_db_open(&db)!=0)return fs_error("storage_unavailable","config_db_open_failed");
    if(fs_sql_exec(db,"BEGIN IMMEDIATE")!=0){response=fs_error("storage_busy","protocol_operation_in_progress");goto out;}tx=1;
    if(fs_meta_revision_lookup(db,&revision)!=1)goto out;
    if(expected!=revision){response=fs_revision_conflict("file_service_changed",expected,revision);goto out;}
    running=fs_ftp_running();int wanted=fs_ftp_wants_running(db);rc=fs_ftp_command("enabled",&result);
    if(rc!=0 && result.exit_code!=1){response=fs_error("runtime_probe_failed","autostart_state_unknown");goto out;}enabled=rc==0;
    if(!autostart && strcmp(action,"stop"))rc=fs_ftp_apply(db,&old,&replaced,1,&reason);
    else{
        touched=1;rc=fs_ftp_command(action,&result);
        if(rc==0 && autostart){int actual=fs_ftp_command("enabled",&result);rc=(actual==0 || result.exit_code==1) && ((actual==0)==!strcmp(action,"enable"))?0:-1;}
        if(rc==0 && !autostart)rc=fs_ftp_wait(0);
    }
    /* Autostart is next-boot policy; preserve this boot's explicit run intent. */
    if(rc==0)rc=fs_ftp_intent_set(db,autostart?wanted:strcmp(action,"stop")!=0);
    if(rc==0 && fs_sql_exec(db,"DELETE FROM ftp_service_error")==0 && fs_meta_bump(db)==0 && fs_sql_exec(db,"COMMIT")==0){
        tx=0;data=fs_ftp_get(db);
        if(data){json_object_object_add(data,"service_action",json_object_new_string(action));json_object_object_add(data,"applied",json_object_new_boolean(1));response=fs_success(data);}goto out;
    }
    int restored=1;
    if(replaced)restored=fs_ftp_restore(&old,replaced,running)==0;
    else if(touched){
        restored=fs_ftp_command(autostart?(enabled?"enable":"disable"):(running?"restart":"stop"),&restore)==0;
        if(restored && !autostart)restored=fs_ftp_wait(running)==0;
    }
    int dbok=fs_sql_exec(db,"ROLLBACK")==0;tx=0;
    if(dbok)fs_ftp_error(db,reason,revision);
    data=fs_error_detail("service_action_failed",reason);
    json_object_object_add(data,"rolled_back",json_object_new_boolean(restored&&dbok));json_object_object_add(data,"rollback_failed",json_object_new_boolean(!restored||!dbok));response=fs_envelope(FS_API_ERROR,data);
out:
    if(tx)fs_sql_exec(db,"ROLLBACK");if(db)sqlite3_close(db);fs_snapshot_free(&old);
    return response?response:fs_error("storage_error",reason);
}
