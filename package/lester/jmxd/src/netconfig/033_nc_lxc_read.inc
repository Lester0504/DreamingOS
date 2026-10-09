/* LXC reads share one runtime path. CLI existence never grants write capability. */
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sqlite3.h>
#ifndef NC_LXC_CONFIG_DB
#define NC_LXC_CONFIG_DB g_netconfig_db_path
#endif
#ifndef NC_LXC_SYSTEM_CONFIG
#define NC_LXC_SYSTEM_CONFIG "/etc/lxc/lxc.conf"
#endif
#ifndef NC_LXC_TEMPLATE_DIR
#define NC_LXC_TEMPLATE_DIR "/usr/share/lxc/templates"
#endif
#ifndef NC_LXC_BRIDGE_ROOT
#define NC_LXC_BRIDGE_ROOT "/sys/class/net"
#endif
#ifndef NC_LXC_PROC_ROOT
#define NC_LXC_PROC_ROOT "/proc"
#endif
#ifndef NC_LXC_CGROUP_ROOT
#define NC_LXC_CGROUP_ROOT "/sys/fs/cgroup"
#endif

static int nc_lxc_create_available(void)
{
    return nc_cmd_exists("lxc-create")&&nc_cmd_exists("lxc-info")&&nc_cmd_exists("lxc-start")&&
        access(NC_LXC_TEMPLATE_DIR "/lxc-local",X_OK)==0;
}

/* Preserve the raw config document and reject incomplete reads. */
static char *nc_lxc_read_text(const char *path,size_t limit)
{
    FILE *fp=fopen(path,"r");if(!fp)return NULL;
    char *text=calloc(1,limit+1);if(!text){fclose(fp);return NULL;}
    size_t n=fread(text,1,limit,fp);int error=ferror(fp),extra=n==limit?fgetc(fp):EOF;
    if(fclose(fp) || error || extra!=EOF){free(text);errno=extra!=EOF?EFBIG:EIO;return NULL;}
    return text;
}

static int nc_lxc_name_valid(const char *name)
{
    if (!name || !name[0] || strlen(name) > 63 || !strcmp(name,".") || !strcmp(name,"..")) return 0;
    if (!isalnum((unsigned char)name[0])) return 0;
    for (const char *p=name; *p; p++)
        if (!isalnum((unsigned char)*p) && *p!='_' && *p!='-' && *p!='.') return 0;
    return 1;
}

static void nc_lxc_string(struct json_object *o,const char *key,const char *value)
{ json_object_object_add(o,key,json_object_new_string(value ? value : "")); }
static void nc_lxc_bool(struct json_object *o,const char *key,int value)
{ json_object_object_add(o,key,json_object_new_boolean(value)); }
static int nc_lxc_error(struct json_object *o,const char *error)
{ nc_lxc_bool(o,"ok",0); nc_lxc_string(o,"error",error); return -1; }
static char *nc_lxc_trim(char *p)
{
    while (*p && isspace((unsigned char)*p)) p++;
    size_t n=strlen(p); while (n && isspace((unsigned char)p[n-1])) p[--n]=0;
    return p;
}

/* Preserve duplicate/include lines in the returned document; this is only a
 * scalar lookup, never a configuration rewriter or shell interpreter. */
static int nc_lxc_config_value(const char *text,const char *key,char *out,size_t size)
{
    char *copy=strdup(text ? text : ""), *save=NULL; int count=0;
    if (!copy) return -1;
    out[0]=0;
    for (char *line=strtok_r(copy,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        char *p=nc_lxc_trim(line),*eq=strchr(p,'=');
        if (!eq || *p=='#') continue;
        *eq=0;
        if (strcmp(nc_lxc_trim(p),key)) continue;
        p=nc_lxc_trim(eq+1);
        if (strlen(p)>=size) {free(copy);return -1;}
        snprintf(out,size,"%s",p); count++;
    }
    free(copy); return count;
}

static int nc_lxc_runtime_path(char *path,size_t size,struct json_object *out)
{
    struct nc_exec_result result={0};
    if (nc_cmd_exists("lxc-config")) {
        const char *argv[]={"lxc-config","lxc.lxcpath",NULL};
        int rc=nc_exec_argv_capture(argv,5,4096,&result);
        if (rc || result.truncated || !result.output || !result.output[0]) {
            nc_exec_result_free(&result);return nc_lxc_error(out,"lxc_path_read_failed");
        }
        snprintf(path,size,"%s",result.output);
        int invalid=strlen(result.output)>=size || strchr(result.output,'\n');
        nc_exec_result_free(&result);
        if(invalid)return nc_lxc_error(out,"lxc_multiple_paths_require_selection");
    } else {
        errno=0;
        char *text=nc_lxc_read_text(NC_LXC_SYSTEM_CONFIG,32768);
        int saved=errno;
        int count=nc_lxc_config_value(text,"lxc.lxcpath",path,size);
        free(text);
        if(!text && saved!=ENOENT)return nc_lxc_error(out,"lxc_path_read_failed");
        if(count<0 || count>1)return nc_lxc_error(out,"lxc_multiple_paths_require_selection");
        if(!count)snprintf(path,size,"/var/lib/lxc"); /* liblxc compiled default */
    }
    if(path[0]!='/' || strstr(path,"/../") || strstr(path,"/./") || strchr(path,'\r') || strchr(path,'\n'))
        return nc_lxc_error(out,"lxc_path_invalid");
    size_t n=strlen(path);while(n>1 && path[n-1]=='/')path[--n]=0;
    return 0;
}

/* Settings are a DB authority. Remembered roots keep existing objects visible
 * when the default location for newly created containers changes. */
static int nc_lxc_path(char *path,size_t size,struct json_object *out)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;int found=0;
    if(sqlite3_open_v2(NC_LXC_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK &&
       sqlite3_prepare_v2(db,"SELECT default_root FROM lxc_settings WHERE id=1",-1,&st,NULL)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW){
        const char *value=(const char *)sqlite3_column_text(st,0);
        if(value&&*value){found=1;if(snprintf(path,size,"%s",value)>=(int)size)found=-1;}
    }
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    if(found<0)return nc_lxc_error(out,"lxc_path_too_long");
    nc_lxc_string(out,"path_source",found?"config.db":"liblxc");
    return found?0:nc_lxc_runtime_path(path,size,out);
}

static void nc_lxc_root_add(struct json_object *roots,const char *path)
{
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX||strchr(path,'\n'))return;
    for(size_t i=0;i<json_object_array_length(roots);i++)if(!strcmp(path,json_object_get_string(json_object_array_get_idx(roots,i))))return;
    if(json_object_array_length(roots)<32)json_object_array_add(roots,json_object_new_string(path));
}

static struct json_object *nc_lxc_roots(void)
{
    struct json_object *roots=json_object_new_array(),*error=json_object_new_object();char path[PATH_MAX];
    if(!nc_lxc_path(path,sizeof(path),error))nc_lxc_root_add(roots,path);
    if(!nc_lxc_runtime_path(path,sizeof(path),error))nc_lxc_root_add(roots,path);
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;
    if(sqlite3_open_v2(NC_LXC_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK){
        if(sqlite3_prepare_v2(db,"SELECT path FROM lxc_roots ORDER BY path LIMIT 32",-1,&st,NULL)==SQLITE_OK)
            while(sqlite3_step(st)==SQLITE_ROW)nc_lxc_root_add(roots,(const char *)sqlite3_column_text(st,0));
        if(st)sqlite3_finalize(st);
        st=NULL;
        if(sqlite3_prepare_v2(db,"SELECT DISTINCT substr(path,1,length(path)-length(name)-8) FROM lxc_config_document LIMIT 32",-1,&st,NULL)==SQLITE_OK)
            while(sqlite3_step(st)==SQLITE_ROW)nc_lxc_root_add(roots,(const char *)sqlite3_column_text(st,0));
    }
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    json_object_put(error);return roots;
}

static int nc_lxc_object(const char *name,char *root,size_t root_size,char *config,size_t config_size,struct json_object *out)
{
    struct stat st;int found=0;const char *error="container_not_found";
    if(!nc_lxc_name_valid(name))return nc_lxc_error(out,"invalid_name");
    struct json_object *roots=nc_lxc_roots();
    for(size_t i=0;i<json_object_array_length(roots);i++){
        const char *candidate=json_object_get_string(json_object_array_get_idx(roots,i));char path[PATH_MAX];
        if(snprintf(path,sizeof(path),"%s/%s/config",candidate,name)>=(int)sizeof(path)){error="lxc_path_too_long";continue;}
        if(lstat(path,&st)){if(errno!=ENOENT)error="container_config_unreadable";continue;}
        if(!S_ISREG(st.st_mode)){error="container_config_not_regular";continue;}
        found++;
        if(snprintf(root,root_size,"%s",candidate)>=(int)root_size||snprintf(config,config_size,"%s",path)>=(int)config_size){found=0;error="lxc_path_too_long";break;}
    }
    json_object_put(roots);
    if(found!=1)return nc_lxc_error(out,found>1?"lxc_name_ambiguous":error);
    nc_lxc_string(out,"name",name);nc_lxc_string(out,"lxcpath",root);nc_lxc_string(out,"config_path",config);
    return 0;
}

static int nc_lxc_identity(const char *name,char *root,size_t root_size,
                           char *identity,size_t identity_size,struct json_object *out)
{
    char config[PATH_MAX],directory[PATH_MAX],resolved[PATH_MAX];struct stat st;
    if(nc_lxc_object(name,root,root_size,config,sizeof(config),out))return -1;
    if(!realpath(root,resolved) || strcmp(root,resolved))return nc_lxc_error(out,"lxc_root_changed");
    if(snprintf(directory,sizeof(directory),"%s/%s",root,name)>=(int)sizeof(directory) ||
       lstat(directory,&st) || !S_ISDIR(st.st_mode))return nc_lxc_error(out,"container_directory_invalid");
    snprintf(identity,identity_size,"%llu:%llu",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);
    nc_lxc_string(out,"identity",identity);
    return 0;
}

static int nc_lxc_exec_read(const char *const argv[],int seconds,size_t limit,struct nc_exec_result *r,struct json_object *out)
{
    int rc=nc_exec_argv_capture(argv,seconds,limit,r);
    json_object_object_add(out,"exit_code",json_object_new_int(rc));
    nc_lxc_bool(out,"timed_out",r->timed_out); nc_lxc_bool(out,"truncated",r->truncated);
    if(rc || r->truncated)return nc_lxc_error(out,r->timed_out ? "lxc_read_timeout" : r->truncated ? "lxc_output_truncated" : rc==127 ? "lxc_command_missing" : "lxc_read_failed");
    return 0;
}

/* Read fixed columns using header offsets, not whitespace tokenization: GROUPS
 * may be empty and an address cell can contain several comma-separated IPs. */
static int nc_lxc_parse_table(char *text,struct json_object *rows)
{
    const char *headers[]={"NAME","STATE","AUTOSTART","IPV4","IPV6","UNPRIVILEGED"};
    size_t offsets[6];char *save=NULL,*line=strtok_r(text,"\n",&save);
    if(!line || !*line)return 0;
    for(int i=0;i<6;i++) {
        char *at=strstr(line,headers[i]);
        if(!at || (i && (size_t)(at-line)<=offsets[i-1]))return -1;
        offsets[i]=(size_t)(at-line);
    }
    for(line=strtok_r(NULL,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        char fields[6][1024];size_t len=strlen(line);
        if(!*nc_lxc_trim(line))continue;
        for(int i=0;i<6;i++) {
            size_t start=offsets[i],end=i<5?offsets[i+1]:len;
            if(end>len)end=len;
            size_t n=start<len && end>start?end-start:0;
            if(n>=sizeof(fields[i]))return -1;
            memcpy(fields[i],line+(start<len?start:len),n);fields[i][n]=0;
        }
        char *name=nc_lxc_trim(fields[0]),*state=nc_lxc_trim(fields[1]);
        if(!nc_lxc_name_valid(name) || !*state)return -1;
        struct json_object *row=json_object_new_object();
        nc_lxc_string(row,"name",name);nc_lxc_string(row,"state",state);
        char *auto_value=nc_lxc_trim(fields[2]),*unpriv=nc_lxc_trim(fields[5]);
        json_object_object_add(row,"autostart",!strcmp(auto_value,"1")||!strcmp(auto_value,"YES") ? json_object_new_boolean(1) : !strcmp(auto_value,"0")||!strcmp(auto_value,"NO") ? json_object_new_boolean(0):NULL);
        json_object_object_add(row,"unprivileged",!strcmp(unpriv,"true")||!strcmp(unpriv,"YES") ? json_object_new_boolean(1) : !strcmp(unpriv,"false")||!strcmp(unpriv,"NO") ? json_object_new_boolean(0):NULL);
        for(int i=3;i<=4;i++) {char *v=nc_lxc_trim(fields[i]);nc_lxc_string(row,i==3?"ipv4":"ipv6",!strcmp(v,"-")?"":v);}
        json_object_array_add(rows,row);
        if(json_object_array_length(rows)>512)return -1;
    }
    return 0;
}

static void nc_lxc_capability(struct json_object *caps,struct json_object *reasons,const char *key,int enabled,const char *reason)
{ nc_lxc_bool(caps,key,enabled);nc_lxc_string(reasons,key,enabled ? "" : reason); }

struct json_object *jmx_container_lxc_get(void)
{
    struct json_object *d=json_object_new_object(),*caps=json_object_new_object(),*reasons=json_object_new_object();
    struct json_object *commands=json_object_new_object(),*missing=json_object_new_array(),*config=json_object_new_object();
    const char *names[]={"lxc-ls","lxc-info","lxc-config","lxc-create","lxc-start","lxc-stop","lxc-destroy","lxc-copy","lxc-snapshot","lxc-attach",NULL};
    int found=0;
    for(int i=0;names[i];i++){int yes=nc_cmd_exists(names[i]);found+=yes;nc_lxc_bool(commands,names[i],yes);if(!yes)json_object_array_add(missing,json_object_new_string(names[i]));}
    int can_list=nc_cmd_exists("lxc-ls"),can_info=nc_cmd_exists("lxc-info");
    nc_lxc_string(d,"contract_version","container-service.v1");nc_lxc_string(d,"lxc_contract_version","lxc-management.v1");
    nc_lxc_bool(d,"available",can_list);nc_lxc_bool(d,"ok",1);
    nc_lxc_string(d,"environment_state",!found?"not_installed":json_object_array_length(missing)?"degraded":"ready");
    nc_lxc_capability(caps,reasons,"read",1,"");
    nc_lxc_capability(caps,reasons,"list",can_list,"lxc_command_missing");
    nc_lxc_capability(caps,reasons,"detail",can_info,"lxc_command_missing");
    nc_lxc_capability(caps,reasons,"config_read",1,"");
    nc_lxc_capability(caps,reasons,"templates_read",1,"");
    nc_lxc_capability(caps,reasons,"stats",can_info,"lxc_command_missing");
    const char *writes[]={"actions","create","start","stop","restart","destroy","config_write","autostart","terminal","clone","snapshot_list","snapshot_create","snapshot_restore","snapshot_delete","jobs",NULL};
    for(int i=0;writes[i];i++)nc_lxc_capability(caps,reasons,writes[i],0,"lxc_control_pipeline_pending");
    nc_lxc_capability(caps,reasons,"logs",1,"");
    nc_lxc_capability(caps,reasons,"jobs",1,"");
    nc_lxc_capability(caps,reasons,"settings_write",1,"");
    nc_lxc_capability(caps,reasons,"autostart",1,"");
    nc_lxc_capability(caps,reasons,"create",nc_lxc_create_available(),"lxc_create_dependencies_missing");
    nc_lxc_capability(caps,reasons,"clone",can_info&&nc_cmd_exists("lxc-copy"),"lxc_command_missing");
    nc_lxc_capability(caps,reasons,"snapshot_list",1,"");
    const char *snap_actions[]={"snapshot_create","snapshot_restore","snapshot_delete",NULL};
    for(int i=0;snap_actions[i];i++)nc_lxc_capability(caps,reasons,snap_actions[i],can_info&&nc_cmd_exists("lxc-snapshot")&&(i!=1||nc_cmd_exists("lxc-copy")),"lxc_command_missing");
    nc_lxc_capability(caps,reasons,"terminal",can_info&&nc_cmd_exists("lxc-attach")&&nc_cmd_exists("lxc-config"),"lxc_command_missing");
    nc_lxc_string(d,"terminal_capabilities_endpoint","/api/v1/container_service/lxc/terminal/capabilities");
    const char *control[]={"start","stop","restart","destroy",NULL};
    for(int i=0;control[i];i++){
        char command[32];snprintf(command,sizeof(command),"lxc_%s",control[i]);
        command[3]='-';
        int supported=can_info&&nc_cmd_exists(!strcmp(control[i],"restart")?"lxc-stop":command);
        if(!strcmp(control[i],"restart"))supported=supported&&nc_cmd_exists("lxc-start");
        nc_lxc_capability(caps,reasons,control[i],supported,"lxc_command_missing");
    }
    nc_lxc_capability(caps,reasons,"actions",nc_json_bool_def(caps,"start",0)||nc_json_bool_def(caps,"stop",0),"lxc_command_missing");
    json_object_object_add(d,"commands",commands);json_object_object_add(d,"missing_commands",missing);
    json_object_object_add(d,"capabilities",caps);json_object_object_add(d,"capability_reasons",reasons);
    char root[PATH_MAX]="";
    int path_ok=!nc_lxc_path(root,sizeof(root),d);
    nc_lxc_string(config,"lxcpath",root);nc_lxc_string(config,"path_source",nc_json_str_def(d,"path_source","liblxc"));
    json_object_object_add(d,"config",config);json_object_object_add(d,"uci_config",json_object_get(config));
    struct utsname system;if(!uname(&system))nc_lxc_string(d,"architecture",system.machine);
    struct json_object *env=json_object_new_object();
    nc_lxc_bool(env,"user_namespace",access("/proc/self/ns/user",F_OK)==0);nc_lxc_bool(env,"pid_namespace",access("/proc/self/ns/pid",F_OK)==0);nc_lxc_bool(env,"network_namespace",access("/proc/self/ns/net",F_OK)==0);
    char *controllers=nc_lxc_read_text("/sys/fs/cgroup/cgroup.controllers",4096);
    nc_lxc_capability(caps,reasons,"config_write",controllers&&strstr(controllers,"memory")&&strstr(controllers,"cpu"),"lxc_cgroup_v2_unavailable");
    if(!nc_json_bool_def(caps,"config_write",0))nc_lxc_capability(caps,reasons,"create",0,"lxc_cgroup_v2_unavailable");
    nc_lxc_string(env,"cgroup_version",controllers?"v2":"unknown");nc_lxc_string(env,"cgroup_controllers",controllers);free(controllers);json_object_object_add(d,"environment",env);
    struct json_object *storage=json_object_new_object();struct statvfs fs;
    nc_lxc_string(storage,"path",root);
    int space=path_ok && !statvfs(root,&fs);nc_lxc_bool(storage,"available",space);
    json_object_object_add(storage,"total_bytes",space?json_object_new_int64((int64_t)fs.f_blocks*fs.f_frsize):NULL);
    json_object_object_add(storage,"available_bytes",space?json_object_new_int64((int64_t)fs.f_bavail*fs.f_frsize):NULL);
    if(!space)nc_lxc_string(storage,"reason","lxc_storage_unavailable");json_object_object_add(d,"storage",storage);
    if(can_list && path_ok) {
        struct json_object *roots=nc_lxc_roots(),*rows=json_object_new_array(),*failures=json_object_new_array();
        for(size_t index=0;index<json_object_array_length(roots);index++){
            const char *location=json_object_get_string(json_object_array_get_idx(roots,index));
            struct nc_exec_result result={0};struct json_object *part=json_object_new_array(),*error=json_object_new_object();struct stat directory;
            const char *argv[]={"lxc-ls","-P",location,"-f","--fancy-format","NAME,STATE,AUTOSTART,IPV4,IPV6,UNPRIVILEGED",NULL};
            int failed=stat(location,&directory)||!S_ISDIR(directory.st_mode);
            if(failed)nc_lxc_error(error,"lxc_storage_unavailable");
            else if(nc_lxc_exec_read(argv,8,65536,&result,error))failed=1;
            else if(result.output&&nc_lxc_parse_table(result.output,part)){nc_lxc_error(error,"lxc_list_format_invalid");failed=1;}
            if(failed){
                nc_lxc_string(error,"path",location);json_object_array_add(failures,error);
                nc_lxc_error(d,nc_json_str_def(error,"error","lxc_read_failed"));
                json_object_object_add(d,"exit_code",json_object_new_int(result.rc));
            }else{
                json_object_put(error);
                for(size_t i=0;i<json_object_array_length(part);i++){
                    struct json_object *row=json_object_array_get_idx(part,i);char path[PATH_MAX],identity[80];struct stat st;
                    const char *name=json_object_get_string(json_object_object_get(row,"name"));
                    nc_lxc_string(row,"lxcpath",location);
                    if(snprintf(path,sizeof(path),"%s/%s",location,name)<(int)sizeof(path)&&!lstat(path,&st)&&S_ISDIR(st.st_mode)){
                        snprintf(identity,sizeof(identity),"%llu:%llu",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);nc_lxc_string(row,"identity",identity);
                    }
                    json_object_array_add(rows,json_object_get(row));
                }
            }
            nc_exec_result_free(&result);json_object_put(part);
        }
        int partial=json_object_array_length(failures)>0;
        if(partial)nc_lxc_string(d,"environment_state","error");
        nc_lxc_bool(d,"partial",partial);json_object_object_add(d,"root_errors",failures);json_object_object_add(d,"roots",roots);
        if(partial&&!json_object_array_length(rows)){json_object_put(rows);json_object_object_add(d,"containers",NULL);json_object_object_add(d,"container_count",NULL);}
        else{json_object_object_add(d,"containers",rows);json_object_object_add(d,"container_count",json_object_new_int(json_object_array_length(rows)));}
    } else {json_object_object_add(d,"containers",NULL);json_object_object_add(d,"container_count",NULL);if(!path_ok)nc_lxc_string(d,"environment_state","error");}
    nc_lxc_string(d,"source","lxc-cli");json_object_object_add(d,"ts",json_object_new_int64(nc_now_s()));
    /* Diagnostics remain readable even when inventory fails; inner ok is binding. */
    return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}

struct json_object *jmx_lxc_container_config_get(const char *name)
{
    struct json_object *d=json_object_new_object();char root[PATH_MAX],path[PATH_MAX];
    if(nc_lxc_object(name,root,sizeof(root),path,sizeof(path),d))return jmx_gen_api_response_data(API_CODE_ERROR,d);
    struct stat st;char *text=NULL;
    if(stat(path,&st) || st.st_size>32768)nc_lxc_error(d,"lxc_config_unreadable_or_too_large");
    else if(!(text=nc_lxc_read_text(path,32769)))nc_lxc_error(d,"lxc_config_read_failed");
    else {nc_lxc_bool(d,"ok",1);nc_lxc_string(d,"config",text);char identity[80];nc_lxc_identity(name,root,sizeof(root),identity,sizeof(identity),d);nc_lxc_string(d,"ownership","external");nc_lxc_string(d,"write_reason","lxc_config_authority_pending");}
    free(text);return jmx_gen_api_response_data(nc_json_bool_def(d,"ok",0)?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

struct json_object *jmx_lxc_config_get(void)
{
    struct json_object *d=json_object_new_object(),*c=json_object_new_object();char root[PATH_MAX]="";
    int rc=nc_lxc_path(root,sizeof(root),d);nc_lxc_string(c,"lxcpath",root);nc_lxc_string(c,"path_source","liblxc");
    nc_lxc_string(c,"default_template","");json_object_object_add(d,"revision",json_object_new_int64(0));
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;
    if(sqlite3_open_v2(NC_LXC_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK &&
       sqlite3_prepare_v2(db,"SELECT default_template,revision FROM lxc_settings WHERE id=1",-1,&st,NULL)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW){
        nc_lxc_string(c,"path_source","config.db");nc_lxc_string(c,"default_template",(const char *)sqlite3_column_text(st,0));
        json_object_object_add(d,"revision",json_object_new_int64(sqlite3_column_int64(st,1)));
    }
    if(st)sqlite3_finalize(st);
    st=NULL;
    struct json_object *ref=json_object_new_object();nc_lxc_string(ref,"root_id","");nc_lxc_string(ref,"path",root);struct stat fs;
    if(!stat(root,&fs)){json_object_object_add(ref,"device",json_object_new_int64(fs.st_dev));json_object_object_add(ref,"inode",json_object_new_int64(fs.st_ino));}
    if(db&&sqlite3_prepare_v2(db,"SELECT device,inode FROM lxc_roots WHERE path=?1 AND inode<>0",-1,&st,NULL)==SQLITE_OK){
        sqlite3_bind_text(st,1,root,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW){json_object_object_add(ref,"device",json_object_new_int64(sqlite3_column_int64(st,0)));json_object_object_add(ref,"inode",json_object_new_int64(sqlite3_column_int64(st,1)));}
    }
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    json_object_object_add(c,"storage_ref",ref);json_object_object_add(d,"roots",nc_lxc_roots());nc_lxc_bool(d,"new_containers_only",1);nc_lxc_bool(d,"migrated",0);
    struct json_object *bridges=json_object_new_array();DIR *interfaces=opendir(NC_LXC_BRIDGE_ROOT);struct dirent *entry;
    if(interfaces){while((entry=readdir(interfaces))){
        char path[PATH_MAX];struct stat bridge;
        if(entry->d_name[0]=='.'||snprintf(path,sizeof(path),"%s/%s/bridge",NC_LXC_BRIDGE_ROOT,entry->d_name)>=(int)sizeof(path))continue;
        if(!stat(path,&bridge)&&S_ISDIR(bridge.st_mode))json_object_array_add(bridges,json_object_new_string(entry->d_name));
    }closedir(interfaces);}
    json_object_object_add(d,"bridges",bridges);
    json_object_object_add(d,"config",c);nc_lxc_bool(d,"ok",!rc);
    return jmx_gen_api_response_data(rc?API_CODE_ERROR:API_CODE_SUCCESS,d);
}

/* Supported distribution records come from the upstream HTTPS catalogue. */
#include <curl/curl.h>
#define NC_LXC_IMAGE_ORIGIN "https://images.linuxcontainers.org"
struct nc_lxc_catalog_buffer {char *text;size_t used;};
static size_t nc_lxc_catalog_collect(char *data,size_t size,size_t count,void *arg)
{
    struct nc_lxc_catalog_buffer *b=arg;size_t n=size*count;
    if(n>131072-b->used)return 0;
    char *next=realloc(b->text,b->used+n+1);if(!next)return 0;
    b->text=next;memcpy(next+b->used,data,n);b->used+=n;next[b->used]=0;return n;
}
static char *nc_lxc_catalog_fetch(struct json_object *out)
{
    CURL *curl=curl_easy_init();struct nc_lxc_catalog_buffer b={0};long status=0;
    if(!curl){nc_lxc_error(out,"template_source_unavailable");return NULL;}
    curl_easy_setopt(curl,CURLOPT_URL,NC_LXC_IMAGE_ORIGIN "/meta/1.0/index-user");
    curl_easy_setopt(curl,CURLOPT_USERAGENT,"lxc/7.0.0 compat:5");
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl,CURLOPT_PROTOCOLS_STR,"https");
#else
    curl_easy_setopt(curl,CURLOPT_PROTOCOLS,(long)CURLPROTO_HTTPS);
#endif
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,2L);
    curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,4L);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,12L);curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,nc_lxc_catalog_collect);curl_easy_setopt(curl,CURLOPT_WRITEDATA,&b);
    CURLcode result=curl_easy_perform(curl);curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);curl_easy_cleanup(curl);
    json_object_object_add(out,"source_http_status",json_object_new_int64(status));
    if(result!=CURLE_OK||status!=200||!b.used){free(b.text);nc_lxc_error(out,result==CURLE_OPERATION_TIMEDOUT?"template_source_timeout":"template_source_unavailable");return NULL;}
    return b.text;
}
static const char *nc_lxc_image_arch(void)
{
    struct utsname u;if(uname(&u))return "unsupported";
    return !strcmp(u.machine,"x86_64")?"amd64":!strcmp(u.machine,"aarch64")?"arm64":"unsupported";
}
static int nc_lxc_catalog_parse(char *text,struct json_object *rows)
{
    char *save=NULL;int accepted=0;
    for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
        char *fields[6],*p=line;int good=1;
        for(int i=0;i<6;i++){fields[i]=p;char *semi=strchr(p,';');if(i<5){if(!semi){good=0;break;}*semi=0;p=semi+1;}else if(semi)good=0;}
        if(!good||strcmp(fields[0],"alpine")||strcmp(fields[3],"default")||
           (strcmp(fields[1],"3.21")&&strcmp(fields[1],"3.22")&&strcmp(fields[1],"3.23"))||
           (strcmp(fields[2],"amd64")&&strcmp(fields[2],"arm64")))continue;
        if(strlen(fields[4])!=14||fields[4][8]!='_'||fields[4][11]!=':')continue;
        for(int i=0;i<14;i++)if(i!=8&&i!=11&&!isdigit((unsigned char)fields[4][i]))good=0;
        char expected[160];snprintf(expected,sizeof(expected),"/images/alpine/%s/%s/default/%s/",fields[1],fields[2],fields[4]);
        if(!good||strcmp(expected,fields[5]))continue;
        struct json_object *row=json_object_new_object();char id[80],url[256];
        snprintf(id,sizeof(id),"alpine/%s/%s/default",fields[1],fields[2]);nc_lxc_string(row,"id",id);
        nc_lxc_string(row,"distribution","alpine");nc_lxc_string(row,"release",fields[1]);nc_lxc_string(row,"architecture",fields[2]);
        nc_lxc_string(row,"variant","default");nc_lxc_string(row,"build",fields[4]);nc_lxc_string(row,"path",fields[5]);
        nc_lxc_string(row,"source",NC_LXC_IMAGE_ORIGIN);nc_lxc_bool(row,"source_verified",1);
        int compatible=!strcmp(fields[2],nc_lxc_image_arch());nc_lxc_bool(row,"compatible",compatible);
        int creatable=compatible&&nc_lxc_create_available();nc_lxc_bool(row,"creatable",creatable);nc_lxc_string(row,"reason",creatable?"":compatible?"lxc_create_dependencies_missing":"template_architecture_mismatch");
        snprintf(url,sizeof(url),NC_LXC_IMAGE_ORIGIN "%srootfs.tar.xz",fields[5]);nc_lxc_string(row,"rootfs_url",url);
        snprintf(url,sizeof(url),NC_LXC_IMAGE_ORIGIN "%smeta.tar.xz",fields[5]);nc_lxc_string(row,"metadata_url",url);
        json_object_object_add(row,"download_bytes",NULL);json_object_array_add(rows,row);accepted++;
        if(accepted>=64)break;
    }
    return accepted;
}

struct json_object *jmx_lxc_templates_get(void)
{
    struct json_object *d=json_object_new_object(),*arr=json_object_new_array(),*scripts=json_object_new_array(),*catalog=json_object_new_array();
    DIR *dir=opendir(NC_LXC_TEMPLATE_DIR);struct dirent *entry;
    if(dir){
        while((entry=readdir(dir))){
            if(strncmp(entry->d_name,"lxc-",4))continue;
            struct json_object *s=json_object_new_object();nc_lxc_string(s,"id",entry->d_name);
            nc_lxc_bool(s,"creatable",0);nc_lxc_string(s,"reason","template_script_only");
            json_object_array_add(scripts,s);json_object_array_add(arr,json_object_new_string(entry->d_name));
        }closedir(dir);
    }else nc_lxc_string(d,"scripts_error",errno==ENOENT?"lxc_templates_not_installed":"lxc_templates_unreadable");
    char *index=nc_lxc_catalog_fetch(d);
    if(index){
        int count=nc_lxc_catalog_parse(index,catalog);free(index);
        if(count){nc_lxc_bool(d,"ok",1);nc_lxc_string(d,"catalog_state","verified");}
        else{nc_lxc_error(d,"template_catalog_no_supported_images");nc_lxc_string(d,"catalog_state","unavailable");}
    }else nc_lxc_string(d,"catalog_state","unavailable");
    nc_lxc_string(d,"source",NC_LXC_IMAGE_ORIGIN);nc_lxc_string(d,"host_image_architecture",nc_lxc_image_arch());
    json_object_object_add(d,"fetched_at",json_object_new_int64(nc_now_s()));
    json_object_object_add(d,"templates",arr);json_object_object_add(d,"scripts",scripts);json_object_object_add(d,"catalog",catalog);
    return jmx_gen_api_response_data(nc_json_bool_def(d,"ok",0)?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

static void nc_lxc_quantity(struct json_object *d,const char *field,const char *value,int bytes)
{
    char *end=NULL;double number=strtod(value,&end);double scale=1;
    if(end==value || number<0 || !isfinite(number))return;
    while(isspace((unsigned char)*end))end++;
    if(bytes) {
        if(!strcmp(end,"KiB"))scale=1024;
        else if(!strcmp(end,"MiB"))scale=1048576;
        else if(!strcmp(end,"GiB"))scale=1073741824;
        else if(*end && strcmp(end,"bytes") && strcmp(end,"B"))return;
        if(number*scale>INT64_MAX)return;
        json_object_object_add(d,field,json_object_new_int64((int64_t)(number*scale)));
    } else if(!*end || !strcmp(end,"seconds"))json_object_object_add(d,field,json_object_new_double(number));
}

static char *nc_lxc_read_at(int directory,const char *name,size_t limit)
{
    int fd=openat(directory,name,O_RDONLY|O_CLOEXEC);if(fd<0)return NULL;
    FILE *fp=fdopen(fd,"r");if(!fp){close(fd);return NULL;}
    char *text=calloc(1,limit+1);if(!text){fclose(fp);return NULL;}
    size_t size=fread(text,1,limit,fp);int error=ferror(fp),extra=size==limit?fgetc(fp):EOF;
    if(fclose(fp)||error||extra!=EOF){free(text);return NULL;}
    return text;
}

/* LXC 7 does not report the v2 CPU/memory counters through lxc-info. Read
 * the selected init's namespace and cgroup; keep unavailable values null. */
static void nc_lxc_kernel_stats(struct json_object *d)
{
    struct json_object *pid_value=json_object_object_get(d,"pid");
    if(!pid_value||strcmp(nc_json_str_def(d,"state",""),"RUNNING"))return;
    int64_t pid=json_object_get_int64(pid_value);char path[PATH_MAX];struct stat host,target;
    if(pid<=0||snprintf(path,sizeof(path),NC_LXC_PROC_ROOT "/%lld",(long long)pid)>=(int)sizeof(path))return;
    int process=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(process<0)return;
    if(stat(NC_LXC_PROC_ROOT "/self/ns/pid",&host)||fstatat(process,"ns/pid",&target,0)||
       (host.st_dev==target.st_dev&&host.st_ino==target.st_ino)){close(process);return;}
    char *text=nc_lxc_read_at(process,"cgroup",16384),*save=NULL;
    if(text){
        for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
            if(strncmp(line,"0::/",4)||!line[4]||strstr(line+3,"/../")||strstr(line+3,"/./"))continue;
            if(snprintf(path,sizeof(path),NC_LXC_CGROUP_ROOT "%s",line+3)>=(int)sizeof(path))continue;
            int group=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(group<0)continue;
            char *cpu=nc_lxc_read_at(group,"cpu.stat",4096),*cpu_save=NULL;
            if(cpu){
                for(char *row=strtok_r(cpu,"\n",&cpu_save);row;row=strtok_r(NULL,"\n",&cpu_save)){
                    unsigned long long usec;char extra;
                    if(sscanf(row,"usage_usec %llu %c",&usec,&extra)==1)
                        json_object_object_add(d,"cpu_seconds",json_object_new_double((double)usec/1000000));
                }
                free(cpu);
            }
            const char *files[]={"memory.current","memory.max"},*fields[]={"memory_usage_bytes","memory_limit_bytes"};
            for(int i=0;i<2;i++){
                char *value=nc_lxc_read_at(group,files[i],128);
                if(value){nc_lxc_quantity(d,fields[i],nc_lxc_trim(value),1);free(value);}
            }
            close(group);break;
        }
        free(text);
    }
    text=nc_lxc_read_at(process,"net/dev",65536);save=NULL;
    if(text){
        int count=0,invalid=0;uint64_t rx=0,tx=0;
        for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
            char *colon=strchr(line,':');if(!colon)continue;*colon=0;
            if(!strcmp(nc_lxc_trim(line),"lo"))continue;
            unsigned long long received,sent;
            if(sscanf(colon+1,"%llu %*s %*s %*s %*s %*s %*s %*s %llu",&received,&sent)!=2||
               received>(uint64_t)INT64_MAX-rx||sent>(uint64_t)INT64_MAX-tx){invalid=1;break;}
            rx+=received;tx+=sent;count++;
        }
        if(count&&!invalid){
            json_object_object_add(d,"network_rx_bytes",json_object_new_int64((int64_t)rx));
            json_object_object_add(d,"network_tx_bytes",json_object_new_int64((int64_t)tx));
        }
        free(text);
    }
    close(process);
}

struct json_object *jmx_lxc_container_stats(const char *name)
{
    struct json_object *d=json_object_new_object();char root[PATH_MAX],path[PATH_MAX];
    if(nc_lxc_object(name,root,sizeof(root),path,sizeof(path),d))return jmx_gen_api_response_data(API_CODE_ERROR,d);
    struct nc_exec_result r={0};const char *argv[]={"lxc-info","-P",root,"-n",name,NULL};
    const char *nullable[]={"cpu_seconds","cpu_percent","memory_usage_bytes","memory_limit_bytes","network_rx_bytes","network_tx_bytes",NULL};
    for(int i=0;nullable[i];i++)json_object_object_add(d,nullable[i],NULL);
    if(!nc_lxc_exec_read(argv,5,16384,&r,d)) {
        char *save=NULL;int state_seen=0;int64_t rx=0,tx=0;int nrx=0,ntx=0;
        for(char *line=strtok_r(r.output,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
            char *colon=strchr(line,':');if(!colon)continue;*colon=0;
            char *key=nc_lxc_trim(line),*v=nc_lxc_trim(colon+1);
            if(!strcmp(key,"State")){nc_lxc_string(d,"state",v);state_seen=1;}
            else if(!strcmp(key,"PID")){char *end;long pid=strtol(v,&end,10);if(!*end && pid>0)json_object_object_add(d,"pid",json_object_new_int64(pid));}
            else if(!strcmp(key,"CPU use"))nc_lxc_quantity(d,"cpu_seconds",v,0);
            else if(!strcmp(key,"Memory use"))nc_lxc_quantity(d,"memory_usage_bytes",v,1);
            else if(!strcmp(key,"Bytes received")||!strcmp(key,"Bytes sent")||!strcmp(key,"RX bytes")||!strcmp(key,"TX bytes")) {
                struct json_object *tmp=json_object_new_object();nc_lxc_quantity(tmp,"value",v,1);
                struct json_object *number=json_object_object_get(tmp,"value");
                if(number){if(!strcmp(key,"Bytes received")||!strcmp(key,"RX bytes")){rx+=json_object_get_int64(number);nrx++;}else{tx+=json_object_get_int64(number);ntx++;}}
                json_object_put(tmp);
            }
        }
        if(nrx)json_object_object_add(d,"network_rx_bytes",json_object_new_int64(rx));
        if(ntx)json_object_object_add(d,"network_tx_bytes",json_object_new_int64(tx));
        if(state_seen){nc_lxc_bool(d,"ok",1);nc_lxc_kernel_stats(d);}else nc_lxc_error(d,"lxc_info_format_invalid");
    }
    nc_exec_result_free(&r);json_object_object_add(d,"sample_time",json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(nc_json_bool_def(d,"ok",0)?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

struct json_object *jmx_lxc_container_processes(const char *name)
{
    struct json_object *d=json_object_new_object();char root[PATH_MAX],path[PATH_MAX];
    if(nc_lxc_object(name,root,sizeof(root),path,sizeof(path),d))return jmx_gen_api_response_data(API_CODE_ERROR,d);
    const char *argv[]={"lxc-attach","-P",root,"-n",name,"--","/bin/ps",NULL};struct nc_exec_result r={0};
    if(!nc_lxc_exec_read(argv,5,16384,&r,d)) {nc_lxc_bool(d,"ok",1);nc_lxc_string(d,"processes",r.output);}
    nc_exec_result_free(&r);return jmx_gen_api_response_data(nc_json_bool_def(d,"ok",0)?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

struct json_object *jmx_lxc_container_logs(const char *name,struct json_object *cfg)
{
    struct json_object *d=json_object_new_object();char root[PATH_MAX],path[PATH_MAX],log[PATH_MAX]="";
    if(nc_lxc_object(name,root,sizeof(root),path,sizeof(path),d))return jmx_gen_api_response_data(API_CODE_ERROR,d);
    char *text=nc_lxc_read_text(path,32769);int found=nc_lxc_config_value(text,"lxc.log.file",log,sizeof(log));free(text);
    nc_lxc_string(d,"source","lxc_runtime");
    if(found!=1 || log[0]!='/'){nc_lxc_error(d,"lxc_log_source_unavailable");return jmx_gen_api_response_data(API_CODE_ERROR,d);}
    struct stat st;
    if(lstat(log,&st) || !S_ISREG(st.st_mode)){nc_lxc_error(d,"lxc_log_not_found_or_not_regular");return jmx_gen_api_response_data(API_CODE_ERROR,d);}
    int tail=cfg?nc_json_int_def(cfg,"tail",100):100;char number[16];if(tail<1)tail=1;if(tail>5000)tail=5000;snprintf(number,sizeof(number),"%d",tail);
    const char *argv[]={"tail","-n",number,log,NULL};struct nc_exec_result r={0};
    if(!nc_lxc_exec_read(argv,5,65536,&r,d)){nc_lxc_bool(d,"ok",1);nc_lxc_string(d,"logs",r.output);}
    nc_lxc_string(d,"log_path",log);json_object_object_add(d,"tail",json_object_new_int(tail));nc_exec_result_free(&r);
    return jmx_gen_api_response_data(nc_json_bool_def(d,"ok",0)?API_CODE_SUCCESS:API_CODE_ERROR,d);
}
