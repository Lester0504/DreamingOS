/* Additive create schema; called both before queueing and by the worker. */
#include "storage/storage_files.h"
#include <arpa/inet.h>
#include <sys/socket.h>

static int nc_docker_keys(struct json_object *o, const char *const allowed[])
{
    if (!json_object_is_type(o,json_type_object)) return 0;
    json_object_object_foreach(o,k,v) {
        int found=0; (void)v;
        for (int i=0;allowed[i];i++) if (!strcmp(k,allowed[i])) found=1;
        if (!found) return 0;
    }
    return 1;
}

static int nc_docker_string(struct json_object *o, size_t max)
{
    return o && json_object_is_type(o,json_type_string) &&
        (size_t)json_object_get_string_len(o)<=max &&
        strlen(json_object_get_string(o))==(size_t)json_object_get_string_len(o);
}

static int nc_docker_integer(struct json_object *o, int64_t min, int64_t max)
{
    return o && json_object_is_type(o,json_type_int) &&
        json_object_get_int64(o)>=min && json_object_get_int64(o)<=max;
}

static int nc_docker_env_key(const char *key)
{
    if (!key || strlen(key)>128 || !(isalpha((unsigned char)*key)||*key=='_')) return 0;
    for (const char *p=key+1;*p;p++) if (!(isalnum((unsigned char)*p)||*p=='_')) return 0;
    return 1;
}

static int nc_docker_path(const char *path)
{
    return path && path[0]=='/' && path[1] && strlen(path)<PATH_MAX &&
        !strchr(path,',') && !strchr(path,'\n') && !strchr(path,'\r') &&
        !strstr(path,"/../") && !strstr(path,"/./") &&
        strcmp(path+strlen(path)-(strlen(path)>=3?3:0),"/..") &&
        strcmp(path+strlen(path)-(strlen(path)>=2?2:0),"/.");
}

static int nc_docker_create_extended(struct json_object *cfg, struct json_object *canonical,
                                      struct json_object *out)
{
    struct json_object *ports=nc_docker_member(cfg,"ports"), *mounts=nc_docker_member(cfg,"mounts");
    struct json_object *env=nc_docker_member(cfg,"env"), *resources=nc_docker_member(cfg,"resources");
    struct json_object *start=nc_docker_member(cfg,"start_after_create");
    char field[96];
    const char *nullable[]={"ports","mounts","env","resources","start_after_create",NULL};
    for(int i=0;nullable[i];i++) {
        struct json_object *v=NULL;
        if(json_object_object_get_ex(cfg,nullable[i],&v)&&!v)
            return nc_docker_create_error(out,"invalid_container_create_request",nullable[i],"null_not_allowed");
    }
#define CREATE_BAD(f,r) return nc_docker_create_error(out,"invalid_container_create_request",f,r)
    if (start && !json_object_is_type(start,json_type_boolean)) { CREATE_BAD("start_after_create","boolean_required"); }
    if (start) json_object_object_add(canonical,"start_after_create",json_object_get(start));
    if (ports) {
        if (!json_object_is_type(ports,json_type_array)||json_object_array_length(ports)>32) { CREATE_BAD("ports","array_max_32"); }
        const char *const keys[]={"host_ip","host_port","container_port","protocol",NULL};
        for (size_t i=0;i<json_object_array_length(ports);i++) {
            struct json_object *p=json_object_array_get_idx(ports,i);
            snprintf(field,sizeof(field),"ports[%zu]",i);
            if (!nc_docker_keys(p,keys)) { CREATE_BAD(field,"unknown_field_or_not_object"); }
            if (!nc_docker_integer(nc_docker_member(p,"host_port"),1,65535)) { strcat(field,".host_port"); CREATE_BAD(field,"port_range_1_65535"); }
            if (!nc_docker_integer(nc_docker_member(p,"container_port"),1,65535)) { strcat(field,".container_port"); CREATE_BAD(field,"port_range_1_65535"); }
            const char *proto=nc_json_str_def(p,"protocol","");
            if (strcmp(proto,"tcp")&&strcmp(proto,"udp")) { strcat(field,".protocol"); CREATE_BAD(field,"tcp_or_udp_required"); }
            struct json_object *ip=nc_docker_member(p,"host_ip"); unsigned char addr[16];
            if (ip && (!nc_docker_string(ip,64) || (inet_pton(AF_INET,json_object_get_string(ip),addr)!=1 && inet_pton(AF_INET6,json_object_get_string(ip),addr)!=1))) { strcat(field,".host_ip"); CREATE_BAD(field,"invalid_ip_address"); }
            for (size_t j=0;j<i;j++) {
                struct json_object *q=json_object_array_get_idx(ports,j);
                const char *a=nc_json_str_def(p,"host_ip","0.0.0.0"), *b=nc_json_str_def(q,"host_ip","0.0.0.0");
                if (nc_json_int_def(p,"host_port",0)==nc_json_int_def(q,"host_port",0) && !strcmp(proto,nc_json_str_def(q,"protocol","")) &&
                    (!strcmp(a,b)||!strcmp(a,"0.0.0.0")||!strcmp(b,"0.0.0.0")||!strcmp(a,"::")||!strcmp(b,"::"))) {
                    strcat(field,".host_port"); return nc_docker_create_error(out,"port_conflict",field,"duplicate_host_binding");
                }
            }
        }
        json_object_object_add(canonical,"ports",json_object_get(ports));
    }
    if (mounts) {
        const char *const keys[]={"type","source","target","read_only",NULL};
        if (!json_object_is_type(mounts,json_type_array)||json_object_array_length(mounts)>32) { CREATE_BAD("mounts","array_max_32"); }
        for (size_t i=0;i<json_object_array_length(mounts);i++) {
            struct json_object *m=json_object_array_get_idx(mounts,i);
            snprintf(field,sizeof(field),"mounts[%zu]",i);
            if (!nc_docker_keys(m,keys)) { CREATE_BAD(field,"unknown_field_or_not_object"); }
            const char *type=nc_json_str_def(m,"type","");
            if (strcmp(type,"bind")&&strcmp(type,"volume")) { CREATE_BAD(field,"bind_or_volume_required"); }
            struct json_object *source=nc_docker_member(m,"source"),*target=nc_docker_member(m,"target"),*ro=nc_docker_member(m,"read_only");
            if (!nc_docker_string(source,PATH_MAX-1)||(!strcmp(type,"bind") ? !nc_docker_path(json_object_get_string(source)) : !nc_docker_name_valid(json_object_get_string(source)))) { strcat(field,".source"); CREATE_BAD(field,"invalid_mount_source"); }
            if (!nc_docker_string(target,PATH_MAX-1)||!nc_docker_path(json_object_get_string(target))) { strcat(field,".target"); CREATE_BAD(field,"absolute_non_root_path_required"); }
            if (ro&&!json_object_is_type(ro,json_type_boolean)) { CREATE_BAD(field,"read_only_boolean_required"); }
            for (size_t j=0;j<i;j++) if (!strcmp(json_object_get_string(target),nc_json_str_def(json_object_array_get_idx(mounts,j),"target",""))) { CREATE_BAD(field,"duplicate_mount_target"); }
        }
        json_object_object_add(canonical,"mounts",json_object_get(mounts));
    }
    if (env) {
        size_t total=0;
        if (!json_object_is_type(env,json_type_object)||json_object_object_length(env)>64) { CREATE_BAD("env","object_max_64"); }
        json_object_object_foreach(env,key,v) {
            if (!nc_docker_env_key(key)||!nc_docker_string(v,8192)||strchr(json_object_get_string(v),'\n')||strchr(json_object_get_string(v),'\r')) { CREATE_BAD("env","invalid_key_or_value"); }
            total+=strlen(key)+(size_t)json_object_get_string_len(v);
            if (total>32768) { CREATE_BAD("env","total_size_limit_exceeded"); }
        }
        json_object_object_add(canonical,"env",json_object_get(env));
    }
    if (resources) {
        const char *const keys[]={"memory_bytes","cpu_shares",NULL};
        struct json_object *memory=nc_docker_member(resources,"memory_bytes"), *cpu=nc_docker_member(resources,"cpu_shares");
        if (!nc_docker_keys(resources,keys)) { CREATE_BAD("resources","unknown_field_or_not_object"); }
        if (memory&&!nc_docker_integer(memory,6*1024*1024,INT64_MAX)) { CREATE_BAD("resources.memory_bytes","minimum_6_MiB"); }
        if (cpu&&!nc_docker_integer(cpu,2,262144)) { CREATE_BAD("resources.cpu_shares","range_2_262144"); }
        json_object_object_add(canonical,"resources",json_object_get(resources));
    }
    return 0;
#undef CREATE_BAD
}

static int nc_docker_create_preflight(struct json_object *cfg, struct json_object *out)
{
    struct json_object *ports=nc_docker_member(cfg,"ports"), *mounts=nc_docker_member(cfg,"mounts");
    char field[96];
    const char *const image_argv[]={"docker","image","inspect",nc_json_str_def(cfg,"image",""),NULL};
    struct json_object *image=nc_docker_read_json(image_argv,0,NULL);
    if (!image) return nc_docker_create_error(out,"image_unavailable","image","pull_image_before_create");
    json_object_put(image);
    for (size_t i=0;ports&&i<json_object_array_length(ports);i++) {
        struct json_object *p=json_object_array_get_idx(ports,i);
        const char *ip=nc_json_str_def(p,"host_ip","0.0.0.0");
        int af=strchr(ip,':')?AF_INET6:AF_INET, type=!strcmp(nc_json_str_def(p,"protocol","tcp"),"tcp")?SOCK_STREAM:SOCK_DGRAM;
        struct sockaddr_storage address={0}; socklen_t size;
        if (af==AF_INET6) {
            struct sockaddr_in6 *a=(struct sockaddr_in6 *)&address; a->sin6_family=AF_INET6;
            a->sin6_port=htons(nc_json_int_def(p,"host_port",0)); inet_pton(AF_INET6,ip,&a->sin6_addr); size=sizeof(*a);
        } else {
            struct sockaddr_in *a=(struct sockaddr_in *)&address; a->sin_family=AF_INET;
            a->sin_port=htons(nc_json_int_def(p,"host_port",0)); inet_pton(AF_INET,ip,&a->sin_addr); size=sizeof(*a);
        }
        int fd=socket(af,type|SOCK_CLOEXEC,0), rc=fd<0?-1:bind(fd,(struct sockaddr *)&address,size), saved=errno;
        if(fd>=0)close(fd);
        if(rc) { snprintf(field,sizeof(field),"ports[%zu].host_port",i); return nc_docker_create_error(out,saved==EADDRINUSE?"port_conflict":"port_unavailable",field,strerror(saved)); }
    }
    for(size_t i=0;mounts&&i<json_object_array_length(mounts);i++) {
        struct json_object *m=json_object_array_get_idx(mounts,i);
        const char *source=nc_json_str_def(m,"source","");
        snprintf(field,sizeof(field),"mounts[%zu].source",i);
        if(!strcmp(nc_json_str_def(m,"type",""),"bind")) {
            char canonical[PATH_MAX]; const char *reason="mount_unavailable";
            int fd=storage_files_open_dir("",source,!nc_json_bool_def(m,"read_only",0),canonical,sizeof(canonical),&reason);
            if(fd<0)return nc_docker_create_error(out,"invalid_mount",field,reason);
            close(fd);
            if(!strcmp(canonical,"/"))return nc_docker_create_error(out,"invalid_mount",field,"host_root_forbidden");
        } else {
            const char *const argv[]={"docker","volume","inspect",source,NULL};
            struct json_object *v=nc_docker_read_json(argv,0,NULL);
            if(!v)return nc_docker_create_error(out,"invalid_mount",field,"volume_not_found");
            json_object_put(v);
        }
    }
    return 0;
}
