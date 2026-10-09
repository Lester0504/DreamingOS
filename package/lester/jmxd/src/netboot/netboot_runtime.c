// SPDX-License-Identifier: GPL-2.0-or-later
#include "netboot_internal.h"
#include "jmx_exec.h"
#include "jmx_netconfig_db.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NB_BEGIN "# BEGIN DREAMINGWRT NETBOOT\n"
#define NB_END "# END DREAMINGWRT NETBOOT\n"
struct json_object *nb_apply_candidate;
static struct json_object *last_result;

int nb_exec(char *const argv[],int timeout_ms)
{
    struct jmx_exec_result r={0};int rc=jmx_exec_wait(argv[0],argv,timeout_ms,&r);
    int ok=!rc&&!r.timed_out&&!r.term_signal&&!r.exit_code;jmx_exec_result_free(&r);return ok?0:-1;
}
static int device_name(const char *s)
{
    if(!*s||strlen(s)>=IFNAMSIZ)return 0;
    for(const char *p=s;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'||*p=='.'))return 0;
    return 1;
}
struct json_object *nb_interfaces(sqlite3 *db)
{
    struct json_object *out=json_object_new_array();sqlite3_stmt *st=NULL;
    const char *sql="SELECT l.id,l.name,l.device,l.enabled,la.ip,la.prefix,COALESCE(d.enabled,0),"
        "COALESCE(d.pool_start,''),COALESCE(d.pool_end,''),COALESCE(d.id,''),l.updated_at "
        "FROM lan l LEFT JOIN lan_address la ON la.lan_id=l.id AND la.is_primary=1 "
        "LEFT JOIN dhcp_scope d ON d.lan_id=l.id ORDER BY l.id";
    if(!db||sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK){json_object_put(out);return NULL;}
    struct ifaddrs *addrs=NULL;getifaddrs(&addrs);
    while(sqlite3_step(st)==SQLITE_ROW) {
        struct json_object *o=json_object_new_object();const char *keys[]={"id","name","device",NULL};
        for(int i=0;keys[i];i++)nb_text(o,keys[i],(const char *)sqlite3_column_text(st,i));
        nb_flag(o,"enabled",sqlite3_column_int(st,3));nb_text(o,"ipv4",(const char *)sqlite3_column_text(st,4));
        nb_int(o,"prefix",sqlite3_column_int(st,5));nb_flag(o,"dhcp_enabled",sqlite3_column_int(st,6));
        nb_text(o,"pool_start",(const char *)sqlite3_column_text(st,7));nb_text(o,"pool_end",(const char *)sqlite3_column_text(st,8));
        nb_text(o,"scope_id",(const char *)sqlite3_column_text(st,9));nb_int(o,"updated_at",sqlite3_column_int64(st,10));
        int present=0;
        for(struct ifaddrs *a=addrs;a;a=a->ifa_next)if(a->ifa_addr&&a->ifa_addr->sa_family==AF_INET&&!strcmp(a->ifa_name,nb_string(o,"device"))) {
            char ip[INET_ADDRSTRLEN];inet_ntop(AF_INET,&((struct sockaddr_in *)a->ifa_addr)->sin_addr,ip,sizeof ip);
            if(!strcmp(ip,nb_string(o,"ipv4"))&&(a->ifa_flags&IFF_UP))present=1;
        }
        nb_flag(o,"address_present",present);nb_text(o,"mode",nb_bool(o,"dhcp_enabled")?"dhcp_attach":"unavailable");
        const char *reason=!nb_bool(o,"enabled")?"interface_disabled":!device_name(nb_string(o,"device"))||!present?"interface_unavailable":
            !nb_bool(o,"dhcp_enabled")||!*nb_string(o,"pool_start")||!*nb_string(o,"pool_end")?"dhcp_mode_unavailable":"";
        nb_text(o,"reason",reason);nb_flag(o,"available",!*reason);json_object_array_add(out,o);
    }
    if(addrs)freeifaddrs(addrs);sqlite3_finalize(st);return out;
}
struct json_object *nb_resources(void)
{
    struct json_object *list=json_object_new_array(),*manifest=json_object_from_file(NB_BOOT_DIR "/manifest.json");
    const char *names[]={"undionly.kpxe","snponly.efi",NULL};
    for(int i=0;names[i];i++) {
        char path[256];snprintf(path,sizeof path,NB_BOOT_DIR "/%s",names[i]);
        struct stat st;struct json_object *o=json_object_new_object(),*meta=nb_value(manifest,names[i]);
        int present=!lstat(path,&st)&&S_ISREG(st.st_mode)&&st.st_size>0&&access(path,R_OK)==0;
        nb_text(o,"name",names[i]);nb_text(o,"path",path);nb_flag(o,"present",present);
        nb_text(o,"version",nb_string(meta,"version"));nb_text(o,"source",nb_string(meta,"source"));nb_text(o,"license",nb_string(meta,"license"));
        int ready=present&&*nb_string(meta,"version")&&*nb_string(meta,"source")&&*nb_string(meta,"license");
        nb_flag(o,"ready",ready);nb_text(o,"reason",!present?"boot_file_missing":!ready?"resource_manifest_missing":"");
        json_object_array_add(list,o);
    }
    if(manifest)json_object_put(manifest);return list;
}
static void problem(struct json_object *errors,const char *code,const char *field)
{struct json_object *e=json_object_new_object();nb_text(e,"code",code);nb_text(e,"field",field);json_object_array_add(errors,e);}
static int port_free(const char *ip,int port)
{
    if(nb_http_ready(ip,port))return 1;
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return 0;
    /* Match the HTTP listener so TIME_WAIT after a restart is not a conflict. */
    int one=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)};
    int ok=inet_pton(AF_INET,ip,&a.sin_addr)==1&&!bind(fd,(struct sockaddr *)&a,sizeof a);close(fd);return ok;
}
static int manual_conflict(sqlite3 *db,const char *scope)
{
    sqlite3_stmt *st=NULL;int conflict=1;
    if(sqlite3_prepare_v2(db,"SELECT count(*) FROM dhcp_option WHERE scope_id=? AND CAST(code AS INTEGER) IN(43,60,66,67,93,175)",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,scope,-1,SQLITE_TRANSIENT);if(sqlite3_step(st)==SQLITE_ROW)conflict=sqlite3_column_int(st,0)>0;
    }
    sqlite3_finalize(st);return conflict;
}
static int unmanaged_pxe(void)
{
    struct uci_context *ctx=uci_alloc_context();struct uci_package *pkg=NULL;int conflict=0;struct uci_element *e;
    if(!ctx||uci_load(ctx,"dhcp",&pkg)!=UCI_OK){if(ctx)uci_free_context(ctx);return 1;}
    uci_foreach_element(&pkg->sections,e) {
        struct uci_section *s=uci_to_section(e);
        if(!strcmp(s->type,"boot"))conflict=1;
        if(!strcmp(s->type,"dnsmasq")) {
            const char *tftp=uci_lookup_option_string(ctx,s,"enable_tftp"),*boot=uci_lookup_option_string(ctx,s,"dhcp_boot");
            if((tftp&&!strcmp(tftp,"1"))||(boot&&*boot))conflict=1;
            const char *extra=uci_lookup_option_string(ctx,s,"extraconftext");
            if(extra) {
                char *copy=strdup(extra),*begin=strstr(copy,NB_BEGIN),*end=begin?strstr(begin,NB_END):NULL;
                if(begin&&end)memmove(begin,end+strlen(NB_END),strlen(end+strlen(NB_END))+1);
                if(strstr(copy,"dhcp-boot=")||strstr(copy,"enable-tftp")||strstr(copy,"pxe-service="))conflict=1;
                free(copy);
            }
        }
    }
    uci_free_context(ctx);return conflict;
}
struct json_object *nb_preflight(sqlite3 *db,struct json_object *cfg)
{
    struct json_object *out=json_object_new_object(),*errors=json_object_new_array(),*s=nb_value(cfg,"settings");
    struct json_object *interfaces=nb_interfaces(db),*resources=nb_resources(),*selected=json_object_new_array(),*ids=nb_value(s,"interface_ids");
    int enabled=nb_bool(s,"enabled");
    if(!interfaces)problem(errors,"interface_inventory_unavailable","interface_ids");
    if(enabled&&!json_object_array_length(ids))problem(errors,"no_interface_selected","interface_ids");
    if(enabled&&json_object_array_length(ids)>1)problem(errors,"multi_lan_not_supported","interface_ids");
    for(size_t i=0;i<json_object_array_length(ids);i++) {
        const char *id=json_object_get_string(json_object_array_get_idx(ids,i));struct json_object *lan=nb_find(interfaces,id);
        if(!lan){if(enabled)problem(errors,"interface_unavailable",id);continue;}
        json_object_array_add(selected,nb_clone(lan));
        if(!enabled)continue;
        if(!nb_bool(lan,"available"))problem(errors,nb_string(lan,"reason"),id);
        if(manual_conflict(db,nb_string(lan,"scope_id")))problem(errors,"dhcp_option_conflict",id);
        if(nb_bool(lan,"available")&&!port_free(nb_string(lan,"ipv4"),nb_number(s,"http_port")))problem(errors,"port_in_use","http_port");
    }
    if(enabled) {
        if(access("/usr/sbin/dnsmasq",X_OK)||access("/etc/init.d/dnsmasq",X_OK))problem(errors,"dependency_missing","dnsmasq");
        if(unmanaged_pxe())problem(errors,"existing_pxe_configuration","dhcp");
        for(size_t i=0;i<json_object_array_length(resources);i++) {
            struct json_object *r=json_object_array_get_idx(resources,i);if(!nb_bool(r,"ready"))problem(errors,nb_string(r,"reason"),nb_string(r,"name"));
        }
    }
    json_object_object_add(out,"interfaces",selected);json_object_object_add(out,"resources",resources);
    json_object_object_add(out,"errors",errors);nb_flag(out,"ok",!json_object_array_length(errors));nb_flag(out,"enabled",enabled);
    nb_int(out,"revision",nb_number(cfg,"revision"));nb_int(out,"http_port",nb_number(s,"http_port"));
    nb_int(out,"menu_timeout",nb_number(s,"menu_timeout"));nb_text(out,"default_image_id",nb_string(s,"default_image_id"));nb_flag(out,"allow_unknown",nb_bool(s,"allow_unknown"));
    nb_flag(out,"has_menu_password",*nb_string(s,"password_hash")!=0);
    const char *text=json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN);unsigned char digest[32];unsigned int len;
    EVP_Digest(text,strlen(text),digest,&len,EVP_sha256(),NULL);char fingerprint[65];for(int i=0;i<32;i++)sprintf(fingerprint+i*2,"%02x",digest[i]);
    nb_text(out,"fingerprint",fingerprint);if(interfaces)json_object_put(interfaces);return out;
}

char *nb_dhcp_block(struct json_object *cfg,struct json_object *lan)
{
    char *block=NULL;const char *device=nb_string(lan,"device"),*ip=nb_string(lan,"ipv4"),*id=nb_string(lan,"id");
    if(!nb_bool(nb_value(cfg,"settings"),"enabled")||!lan)return strdup(NB_BEGIN NB_END);
    if(!device_name(device)||!nb_id_valid(id))return NULL;
    /* dnsmasq gives requests the ingress interface tag. Scope every boot rule. */
    if(asprintf(&block,NB_BEGIN "enable-tftp=%s\ntftp-root=" NB_BOOT_DIR ",%s\n"
        "dhcp-userclass=set:dw-nb-ipxe,iPXE\n"
        "dhcp-match=set:dw-nb-bios,option:client-arch,0\n"
        "dhcp-match=set:dw-nb-efi,option:client-arch,7\n"
        "dhcp-match=set:dw-nb-efi,option:client-arch,9\n"
        "dhcp-boot=tag:%s,tag:dw-nb-ipxe,http://%s:%lld/boot.ipxe\n"
        "dhcp-boot=tag:%s,tag:!dw-nb-ipxe,tag:dw-nb-bios,undionly.kpxe,,%s\n"
        "dhcp-boot=tag:%s,tag:!dw-nb-ipxe,tag:dw-nb-efi,snponly.efi,,%s\n" NB_END,
        device,device,device,ip,(long long)nb_number(nb_value(cfg,"settings"),"http_port"),device,ip,device,ip)<0)return NULL;
    return block;
}
int jmx_netboot_dhcp_project(struct uci_context *ctx,struct uci_package *pkg)
{
    sqlite3 *db=nb_open(0);struct json_object *cfg=nb_apply_candidate?nb_clone(nb_apply_candidate):nb_load(db);
    if(!cfg){if(db)sqlite3_close(db);return -1;}
    struct json_object *interfaces=nb_interfaces(db),*s=nb_value(cfg,"settings"),*ids=nb_value(s,"interface_ids");
    struct json_object *lan=json_object_array_length(ids)?nb_find(interfaces,json_object_get_string(json_object_array_get_idx(ids,0))):NULL;
    int enabled=nb_bool(s,"enabled");
    if(enabled&&(!lan||!nb_bool(lan,"available")||json_object_array_length(ids)!=1)) {
        /* A network edit must withdraw stale PXE rather than advertise an old URL. */
        nb_flag(s,"enabled",0);nb_http_stop();
    }
    char *block=NULL;struct uci_section *section=NULL;struct uci_element *e;
    uci_foreach_element(&pkg->sections,e){struct uci_section *s=uci_to_section(e);if(!strcmp(s->type,"dnsmasq")){section=s;break;}}
    int rc=-1;
    if(!section)goto done;
    const char *old=uci_lookup_option_string(ctx,section,"extraconftext");if(!old)old="";
    const char *begin=strstr(old,NB_BEGIN),*end=begin?strstr(begin,NB_END):NULL;
    /* Ordinary DHCP saves remain untouched until Netboot has a projection. */
    if(!nb_bool(s,"enabled")&&!begin){rc=0;goto done;}
    block=nb_dhcp_block(cfg,lan);if(!block)goto done;
    if(begin&&!end)goto done;
    size_t prefix=begin?(size_t)(begin-old):strlen(old);const char *suffix=end?end+strlen(NB_END):old+strlen(old);
    char *merged=NULL;if(asprintf(&merged,"%.*s\n%s%s",(int)prefix,old,block,suffix)<0)goto done;
    char temp[]="/tmp/dw-netboot-dnsmasq-XXXXXX";int fd=mkstemp(temp);
    if(fd<0){free(merged);goto done;}
    size_t bytes=strlen(merged);int written=write(fd,merged,bytes)==(ssize_t)bytes;close(fd);
    char option[128];snprintf(option,sizeof option,"--conf-file=%s",temp);
    char *argv[]={"/usr/sbin/dnsmasq","--test",option,NULL};
    int valid=written&&!nb_exec(argv,4000);unlink(temp);
    if(valid){
        struct uci_ptr p={.p=pkg,.s=section,.option="extraconftext",.value=merged};
        rc=uci_set(ctx,&p)==UCI_OK?0:-1;
        /* TFTP options live in extraconftext, so dnsmasq's init script cannot
         * infer the root for its procd mount namespace. Mount only our root. */
        struct uci_option *mounts=uci_lookup_option(ctx,section,"addnmount");
        int present=0;
        if(mounts&&mounts->type==UCI_TYPE_LIST) {
            struct uci_element *m;uci_foreach_element(&mounts->v.list,m)
                if(!strcmp(m->name,NB_BOOT_DIR))present=1;
        } else if(mounts&&mounts->type==UCI_TYPE_STRING)
            present=!strcmp(mounts->v.string,NB_BOOT_DIR);
        struct uci_ptr mount={.p=pkg,.s=section,.option="addnmount",.value=NB_BOOT_DIR};
        if(!rc&&nb_bool(s,"enabled")&&!present)rc=uci_add_list(ctx,&mount)==UCI_OK?0:-1;
        if(!rc&&!nb_bool(s,"enabled")&&present)rc=uci_del_list(ctx,&mount)==UCI_OK?0:-1;
    }
    free(merged);
done:
    free(block);if(interfaces)json_object_put(interfaces);json_object_put(cfg);if(db)sqlite3_close(db);return rc;
}
static char *read_small(const char *path)
{
    FILE *f=fopen(path,"r");if(!f)return NULL;char *s=calloc(1,131073);if(!s){fclose(f);return NULL;}
    size_t n=fread(s,1,131072,f);fclose(f);if(n==131072){free(s);return NULL;}return s;
}
int nb_dhcp_loaded(struct json_object *cfg,struct json_object *lan)
{
    char *block=nb_dhcp_block(cfg,lan);glob_t configs={0};int loaded=0;
    if(!block)return 0;
    glob("/tmp/etc/dnsmasq.conf.*",0,NULL,&configs);
    for(size_t i=0;i<configs.gl_pathc&&!loaded;i++) {
        char *config=read_small(configs.gl_pathv[i]);if(!config)continue;
        char *save=NULL;
        for(char *line=strtok_r(config,"\n",&save);line;line=strtok_r(NULL,"\n",&save))if(!strncmp(line,"conf-dir=",9)) {
            char path[512];snprintf(path,sizeof path,"%s/extraconfig.conf",line+9);char *extra=read_small(path);
            if(extra&&strstr(extra,block))loaded=1;free(extra);
        }
        free(config);
    }
    globfree(&configs);free(block);
    /* Generated text is not a listener. UDP 69 must actually be present. */
    if(loaded&&nb_bool(nb_value(cfg,"settings"),"enabled")) {
        FILE *f=fopen("/proc/net/udp","r");char line[512];int listening=0;unsigned addr,port;struct in_addr ip={0};
        inet_pton(AF_INET,nb_string(lan,"ipv4"),&ip);
        while(f&&fgets(line,sizeof line,f))if(sscanf(line," %*d: %x:%x",&addr,&port)==2&&port==69&&(addr==0||addr==ip.s_addr))listening=1;
        if(f)fclose(f);loaded=listening;
    }
    return loaded;
}
static int apply_one(struct json_object *cfg,struct json_object *previous,struct json_object *result)
{
    struct json_object *s=nb_value(cfg,"settings"),*old=nb_value(previous,"settings");int enabled=nb_bool(s,"enabled");
    nb_http_stop();nb_config_publish(cfg);
    sqlite3 *db=nb_open(0);struct json_object *interfaces=nb_interfaces(db);if(db)sqlite3_close(db);
    struct json_object *ids=nb_value(s,"interface_ids"),*oldids=nb_value(old,"interface_ids");
    struct json_object *lan=json_object_array_length(ids)?nb_find(interfaces,json_object_get_string(json_object_array_get_idx(ids,0))):NULL;
    if(enabled&&(!lan||nb_http_start(cfg,lan))){nb_text(result,"stage","http_bind");nb_text(result,"error","http_bind_failed");goto fail;}
    nb_apply_candidate=cfg;
    const char *targets[2]={json_object_array_length(ids)?json_object_get_string(json_object_array_get_idx(ids,0)):"",
                           json_object_array_length(oldids)?json_object_get_string(json_object_array_get_idx(oldids,0)):""};
    for(int i=0;i<2;i++)if(*targets[i] && (!i||strcmp(targets[0],targets[1])) && nb_find(interfaces,targets[i])) {
        if(jmx_dhcp_service_apply(targets[i])){nb_text(result,"stage","dhcp_apply");nb_text(result,"error","dhcp_apply_failed");nb_apply_candidate=NULL;goto fail;}
    }
    nb_apply_candidate=NULL;
    struct json_object *oldlan=json_object_array_length(oldids)?nb_find(interfaces,json_object_get_string(json_object_array_get_idx(oldids,0))):NULL;
    char *before=nb_dhcp_block(previous,oldlan),*after=nb_dhcp_block(cfg,lan);
    int changed=!before||!after||strcmp(before,after);free(before);free(after);
    /* procd watches dnsmasq's main config, not its extraconfig.conf. SIGHUP
     * does not reload PXE/TFTP directives. Restart only when our projection
     * changes; menu/password-only saves need no DHCP restart. */
    if(changed) {
        char *argv[]={"/etc/init.d/dnsmasq","restart",NULL};
        if(nb_exec(argv,10000)){nb_text(result,"stage","dhcp_restart");nb_text(result,"error","dnsmasq_restart_failed");goto fail;}
        nb_flag(result,"dnsmasq_restarted",1);
    }
    if(enabled) {
        int loaded=0;
        for(int i=0;i<20;i++){if(nb_dhcp_loaded(cfg,lan)){loaded=1;break;}usleep(100000);}
        if(!loaded){nb_text(result,"stage","dhcp_readback");nb_text(result,"error","dhcp_readback_failed");goto fail;}
    }
    if(!enabled&&json_object_array_length(oldids)) {
        if(oldlan&&!nb_dhcp_loaded(cfg,oldlan)){nb_text(result,"stage","dhcp_readback");nb_text(result,"error","withdrawal_readback_failed");goto fail;}
    }
    struct json_object *images=nb_value(cfg,"images");
    for(size_t i=0;i<json_object_array_length(images);i++) {
        struct json_object *image=json_object_array_get_idx(images,i);
        if(enabled&&nb_bool(image,"enabled"))nb_image_probe(image,0,0);
        else if(!enabled && nb_image_unmount(nb_string(image,"id"))) {
            nb_text(result,"stage","unmount");nb_text(result,"error","unmount_failed");goto fail;
        }
    }
    nb_config_publish(cfg);if(interfaces)json_object_put(interfaces);nb_flag(result,"applied",1);return 0;
fail:
    if(interfaces)json_object_put(interfaces);nb_http_stop();return -1;
}
int nb_runtime_apply(struct json_object *cfg,struct json_object *previous,struct json_object *result)
{
    int rc=apply_one(cfg,previous,result);
    if(rc) {
        struct json_object *restore=json_object_new_object();int restored=!apply_one(previous,cfg,restore);
        nb_flag(result,"rolled_back",restored);nb_flag(result,"rollback_failed",!restored);json_object_object_add(result,"restore",restore);
        nb_event("service-operation-failed","","",nb_string(result,"error"));
    }
    if(last_result)json_object_put(last_result);last_result=nb_clone(result);return rc;
}
struct json_object *nb_runtime_status(struct json_object *cfg)
{
    struct json_object *out=json_object_new_object(),*caps=json_object_new_object(),*s=nb_value(cfg,"settings"),*rows=json_object_new_array();
    nb_flag(out,"supported",1);nb_int(out,"revision",nb_number(cfg,"revision"));nb_flag(out,"configured_enabled",nb_bool(s,"enabled"));
    nb_flag(caps,"management",1);nb_flag(caps,"dhcp_attach",1);nb_flag(caps,"proxy_dhcp",0);nb_flag(caps,"multi_lan",0);
    nb_flag(caps,"manual_template",0);nb_flag(caps,"ubuntu",0);nb_flag(caps,"windows",0);nb_flag(caps,"arm64",0);nb_flag(caps,"secure_boot",0);nb_flag(caps,"uefi_http_boot",0);
    json_object_object_add(out,"capabilities",caps);json_object_object_add(out,"resources",nb_resources());
    sqlite3 *db=nb_open(0);struct json_object *interfaces=nb_interfaces(db);if(db)sqlite3_close(db);
    struct json_object *ids=nb_value(s,"interface_ids");int good=0,bad=0;
    for(size_t i=0;i<json_object_array_length(ids);i++) {
        const char *id=json_object_get_string(json_object_array_get_idx(ids,i));struct json_object *lan=nb_find(interfaces,id),*row=lan?nb_clone(lan):json_object_new_object();
        nb_text(row,"id",id);int http=lan&&nb_bool(lan,"available")&&nb_http_ready(nb_string(lan,"ipv4"),nb_number(s,"http_port"));
        int tftp=nb_bool(s,"enabled")&&lan&&nb_bool(lan,"available")&&nb_dhcp_loaded(cfg,lan);
        nb_text(row,"http",http?"ready":"unavailable");nb_text(row,"tftp",tftp?"ready":"unavailable");
        if(http&&nb_bool(s,"enabled")){char url[128];snprintf(url,sizeof url,"http://%s:%lld/boot.ipxe",nb_string(lan,"ipv4"),(long long)nb_number(s,"http_port"));nb_text(row,"url",url);}
        if(http&&tftp)good++;else bad++;json_object_array_add(rows,row);
    }
    nb_text(out,"runtime_state",!nb_bool(s,"enabled")?"stopped":good&&!bad?"running":good?"degraded":"failed");
    nb_flag(out,"boot_verified",0);nb_int(out,"observed_at",time(NULL));json_object_object_add(out,"interfaces",rows);
    if(last_result)json_object_object_add(out,"last_result",nb_clone(last_result));
    int ready=0;struct json_object *images=nb_value(cfg,"images");
    for(size_t i=0;i<json_object_array_length(images);i++){struct json_object *image=nb_clone(json_object_array_get_idx(images,i));nb_image_observe(image);if(!strcmp(nb_string(image,"image_status"),"ready")&&nb_bool(image,"enabled"))ready++;json_object_put(image);}
    nb_int(out,"image_count",json_object_array_length(images));nb_int(out,"ready_images",ready);json_object_object_add(out,"events",nb_events(0,10));
    if(interfaces)json_object_put(interfaces);return out;
}
void jmx_netboot_startup(void)
{
    sqlite3 *db=nb_open(0);struct json_object *cfg=nb_load(db);if(!cfg){if(db)sqlite3_close(db);return;}
    nb_config_publish(cfg);
    if(nb_bool(nb_value(cfg,"settings"),"enabled")) {
        struct json_object *check=nb_preflight(db,cfg);
        if(nb_bool(check,"ok")) {
            struct json_object *previous=nb_clone(cfg),*result=json_object_new_object();nb_flag(nb_value(previous,"settings"),"enabled",0);
            nb_runtime_apply(cfg,previous,result);json_object_put(result);json_object_put(previous);
        } else {if(last_result)json_object_put(last_result);last_result=check;check=NULL;nb_event("service-operation-failed","","","startup_preflight_failed");}
        if(check)json_object_put(check);
    }
    json_object_put(cfg);if(db)sqlite3_close(db);
}
