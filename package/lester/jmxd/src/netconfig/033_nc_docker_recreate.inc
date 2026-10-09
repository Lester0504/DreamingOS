/* Clone/recreate preserve the original object until replacement is verified. */
#include <openssl/evp.h>

static struct json_object *nc_docker_engine_request(const char *method,const char *path,
                                                    struct json_object *body,long *status)
{
#ifndef NC_DOCKER_ENGINE_SOCKET
#define NC_DOCKER_ENGINE_SOCKET "/var/run/docker.sock"
#endif
    int migration_guard=nc_docker_migration_guard();
    if(migration_guard==-1){*status=0;return NULL;}
    CURL *curl=curl_easy_init();struct nc_docker_http_buffer buffer={0};char url[640];
    struct curl_slist *headers=NULL;struct json_object *response=NULL;*status=0;
    if(!curl){if(migration_guard>=0)close(migration_guard);return NULL;}
    snprintf(url,sizeof(url),"http://localhost%s",path);
    curl_easy_setopt(curl,CURLOPT_URL,url);curl_easy_setopt(curl,CURLOPT_UNIX_SOCKET_PATH,NC_DOCKER_ENGINE_SOCKET);
    curl_easy_setopt(curl,CURLOPT_PROXY,"");curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);curl_easy_setopt(curl,CURLOPT_TIMEOUT,30L);
    curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,method);curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,nc_docker_http_write);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buffer);
    if(body){headers=curl_slist_append(headers,"Content-Type: application/json");curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);curl_easy_setopt(curl,CURLOPT_POSTFIELDS,json_object_to_json_string_ext(body,JSON_C_TO_STRING_PLAIN));}
    if(curl_easy_perform(curl)==CURLE_OK){curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,status);if(buffer.data&&*buffer.data)response=json_tokener_parse(buffer.data);}
    if(!response)response=json_object_new_object();
    free(buffer.data);curl_slist_free_all(headers);curl_easy_cleanup(curl);if(migration_guard>=0)close(migration_guard);return response;
}

static struct json_object *nc_docker_raw_container(const char *id)
{
    if(!nc_docker_resource_id_valid(id))return NULL;
    const char *const argv[]={"docker","container","inspect",id,NULL};
    struct json_object *list=nc_docker_read_json(argv,0,NULL);
    struct json_object *raw=list?json_object_array_get_idx(list,0):NULL;
    if(raw) { json_object_get(raw); }
    if(list) { json_object_put(list); }
    return raw;
}

static int nc_docker_container_revision(struct json_object *raw,char hex[65])
{
    struct json_object *o=json_object_new_object();unsigned char digest[32];unsigned int n=0;
    nc_docker_copy(o,"id",raw,"Id");nc_docker_copy(o,"image",raw,"Image");
    nc_docker_copy(o,"name",raw,"Name");
    nc_docker_copy(o,"config",raw,"Config");nc_docker_copy(o,"host",raw,"HostConfig");
    nc_docker_copy(o,"networks",nc_docker_member(raw,"NetworkSettings"),"Networks");
    nc_docker_copy(o,"running",nc_docker_member(raw,"State"),"Running");
    nc_docker_copy(o,"paused",nc_docker_member(raw,"State"),"Paused");
    const char *text=json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN);
    int ok=EVP_Digest(text,strlen(text),digest,&n,EVP_sha256(),NULL)&&n==32;json_object_put(o);
    if(!ok)return -1;
    for(unsigned int i=0;i<n;i++)snprintf(hex+i*2,3,"%02x",digest[i]);
    return 0;
}

static struct json_object *nc_docker_container_template(const char *id)
{
    struct json_object *out=json_object_new_object(),*raw=nc_docker_raw_container(id);
    if(!raw){nc_docker_invalid(out,"container_not_found");return out;}
    struct json_object *config=nc_docker_member(raw,"Config"),*host=nc_docker_member(raw,"HostConfig");
    struct json_object *devices=nc_docker_member(host,"Devices"),*caps=nc_docker_member(host,"CapAdd");
    if(nc_json_bool_def(host,"Privileged",0)||nc_json_bool_def(host,"AutoRemove",0)||
       nc_json_bool_def(nc_docker_member(raw,"State"),"Paused",0)||nc_json_bool_def(nc_docker_member(raw,"State"),"Restarting",0)||
       (devices&&json_object_array_length(devices))||(caps&&json_object_array_length(caps))||
       !strcmp(nc_json_str_def(host,"PidMode",""),"host")||!strcmp(nc_json_str_def(host,"IpcMode",""),"host")||
       nc_docker_member(nc_docker_member(config,"Labels"),"com.docker.compose.project")) {
        nc_docker_invalid(out,"source_owner_or_privileged_container");json_object_put(raw);return out;
    }
    struct json_object *cfg=json_object_new_object(),*ports=json_object_new_array(),*mounts=json_object_new_array(),*env=json_object_new_object(),*resources=json_object_new_object();
    const char *name=nc_json_str_def(raw,"Name","");
    json_object_object_add(cfg,"name",json_object_new_string(*name=='/'?name+1:name));
    nc_docker_copy(cfg,"image",config,"Image");nc_docker_copy(cfg,"hostname",config,"Hostname");
    const char *network=nc_json_str_def(host,"NetworkMode","bridge");
    json_object_object_add(cfg,"network",json_object_new_string(!strcmp(network,"default")?"bridge":network));
    struct json_object *rp=nc_docker_member(host,"RestartPolicy");char policy[64];
    const char *restart=nc_json_str_def(rp,"Name","no");int attempts=nc_json_int_def(rp,"MaximumRetryCount",0);
    if(!strcmp(restart,"on-failure")&&attempts>0)snprintf(policy,sizeof(policy),"on-failure:%d",attempts);else snprintf(policy,sizeof(policy),"%s",*restart?restart:"no");
    json_object_object_add(cfg,"restart_policy",json_object_new_string(policy));
    struct json_object *command=nc_docker_member(config,"Cmd"),*labels=nc_docker_member(config,"Labels");
    if(command)json_object_object_add(cfg,"command",json_object_get(command));
    if(labels)json_object_object_add(cfg,"labels",json_object_get(labels));
    struct json_object *source_env=nc_docker_member(config,"Env");
    for(size_t i=0;source_env&&i<json_object_array_length(source_env);i++) {
        const char *value=json_object_get_string(json_object_array_get_idx(source_env,i)),*eq=strchr(value,'=');
        if(eq){char *key=strndup(value,eq-value);json_object_object_add(env,key,json_object_new_string(eq+1));free(key);}
    }
    json_object_object_add(cfg,"env",env);
    struct json_object *bindings=nc_docker_member(host,"PortBindings");
    if(bindings&&json_object_is_type(bindings,json_type_object)) {
        json_object_object_foreach(bindings,key,values) {
            const char *slash=strchr(key,'/');
            for(size_t i=0;values&&i<json_object_array_length(values);i++) {
                struct json_object *v=json_object_array_get_idx(values,i),*p=json_object_new_object();
                json_object_object_add(p,"container_port",json_object_new_int(atoi(key)));
                json_object_object_add(p,"host_port",json_object_new_int(atoi(nc_json_str_def(v,"HostPort","0"))));
                json_object_object_add(p,"protocol",json_object_new_string(slash?slash+1:"tcp"));
                const char *ip=nc_json_str_def(v,"HostIp","");if(*ip)json_object_object_add(p,"host_ip",json_object_new_string(ip));
                json_object_array_add(ports,p);
            }
        }
    }
    json_object_object_add(cfg,"ports",ports);
    struct json_object *source_mounts=nc_docker_member(raw,"Mounts");
    for(size_t i=0;source_mounts&&i<json_object_array_length(source_mounts);i++) {
        struct json_object *v=json_object_array_get_idx(source_mounts,i),*m=json_object_new_object();
        const char *type=nc_json_str_def(v,"Type","");
        nc_docker_copy(m,"type",v,"Type");nc_docker_copy(m,"source",v,!strcmp(type,"volume")?"Name":"Source");nc_docker_copy(m,"target",v,"Destination");
        json_object_object_add(m,"read_only",json_object_new_boolean(!nc_json_bool_def(v,"RW",1)));json_object_array_add(mounts,m);
    }
    json_object_object_add(cfg,"mounts",mounts);
    if(json_object_get_int64(nc_docker_member(host,"Memory"))>0)nc_docker_copy(resources,"memory_bytes",host,"Memory");
    if(nc_json_int_def(host,"CpuShares",0)>0)nc_docker_copy(resources,"cpu_shares",host,"CpuShares");
    json_object_object_add(cfg,"resources",resources);
    char revision[65];
    if(nc_docker_container_revision(raw,revision)) {json_object_put(raw);json_object_put(cfg);nc_docker_invalid(out,"revision_unavailable");return out;}
    json_object_object_add(out,"ok",json_object_new_boolean(1));nc_docker_copy(out,"id",raw,"Id");
    json_object_object_add(out,"revision",json_object_new_string(revision));json_object_object_add(out,"config",cfg);
    json_object_object_add(out,"running",json_object_new_boolean(nc_json_bool_def(nc_docker_member(raw,"State"),"Running",0)));
    json_object_put(raw);return out;
}

static int nc_docker_replace_submit(struct json_object *cfg,struct json_object *out,int clone)
{
    const char *id=nc_json_str_def(cfg,"id","");struct json_object *template=nc_docker_container_template(id);
    if(!nc_json_bool_def(template,"ok",0)){nc_docker_invalid(out,nc_json_str_def(template,"error","container_unavailable"));json_object_put(template);return -1;}
    if(strcmp(nc_json_str_def(cfg,"revision",""),nc_json_str_def(template,"revision",""))) {json_object_put(template);return nc_docker_invalid(out,"revision_conflict");}
    struct json_object *config=nc_docker_member(cfg,"config");char *canonical=NULL,image[256],name[129];
    int rc=nc_docker_create_normalize(config,&canonical,image,sizeof(image),name,sizeof(name),out);
    if(rc){json_object_put(template);return rc;}
    if(!*name){free(canonical);json_object_put(template);return nc_docker_create_error(out,"invalid_name","config.name","name_required");}
    const char *old_name=nc_json_str_def(nc_docker_member(template,"config"),"name","");
    if(clone&&!strcmp(name,old_name)){free(canonical);json_object_put(template);return nc_docker_invalid(out,"clone_requires_new_name");}
    if(!clone&&strcmp(name,old_name)){free(canonical);json_object_put(template);return nc_docker_invalid(out,"recreate_keeps_name");}
    struct json_object *snapshot=nc_docker_raw_container(nc_json_str_def(template,"id",""));
    char snapshot_revision[65];
    if(!snapshot || nc_docker_container_revision(snapshot,snapshot_revision) ||
       strcmp(snapshot_revision,nc_json_str_def(template,"revision",""))) {
        if(snapshot)json_object_put(snapshot);
        free(canonical);json_object_put(template);return nc_docker_invalid(out,"revision_conflict");
    }
    struct json_object *request=json_object_new_object();
    json_object_object_add(request,"source_snapshot",snapshot);
    json_object_object_add(request,"id",json_object_get(nc_docker_member(template,"id")));
    json_object_object_add(request,"revision",json_object_get(nc_docker_member(template,"revision")));
    json_object_object_add(request,"config",json_tokener_parse(canonical));free(canonical);
    rc=nc_container_job_submit(clone?"container_clone":"container_recreate",nc_json_str_def(template,"id",""),json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN),out);
    json_object_put(request);json_object_put(template);return rc;
}

/* Keep endpoint configuration, not transient endpoint IDs or dynamic addresses. */
static struct json_object *nc_docker_replacement_networks(struct json_object *raw,
                                                           struct json_object *cfg,int clone)
{
    struct json_object *networks=nc_docker_member(nc_docker_member(raw,"NetworkSettings"),"Networks");
    struct json_object *endpoints=json_object_new_object();
    const char *oldmode=nc_json_str_def(nc_docker_member(raw,"HostConfig"),"NetworkMode","bridge");
    const char *newmode=nc_json_str_def(cfg,"network","bridge");
    if(!strcmp(oldmode,"default"))oldmode="bridge";
    if(strcmp(oldmode,newmode)) {
        if(strcmp(newmode,"none"))json_object_object_add(endpoints,newmode,json_object_new_object());
        return endpoints;
    }
    const char *id=nc_json_str_def(raw,"Id",""),*name=nc_json_str_def(raw,"Name","");if(*name=='/')name++;
    if(networks) {
        json_object_object_foreach(networks,key,v) {
            if(!strcmp(key,"none"))continue;
            struct json_object *ep=json_object_new_object();
            const char *keys[]={"IPAMConfig","Links","DriverOpts","GwPriority",NULL};
            for(int i=0;keys[i];i++)if((!clone||strcmp(keys[i],"IPAMConfig"))&&nc_docker_member(v,keys[i]))nc_docker_copy(ep,keys[i],v,keys[i]);
            struct json_object *aliases=nc_docker_member(v,"Aliases"),*kept=json_object_new_array();
            for(size_t i=0;aliases&&i<json_object_array_length(aliases);i++) {
                const char *a=json_object_get_string(json_object_array_get_idx(aliases,i));
                if(!strcmp(a,id)||(!strncmp(a,id,12)&&strlen(a)==12)||!strcmp(a,name))continue;
                json_object_array_add(kept,json_object_new_string(a));
            }
            if(json_object_array_length(kept))json_object_object_add(ep,"Aliases",kept);else json_object_put(kept);
            json_object_object_add(endpoints,key,ep);
        }
    }
    return endpoints;
}

static int nc_docker_disconnect_networks(const char *id)
{
    struct json_object *raw=nc_docker_raw_container(id);
    if(!raw)return -1;
    struct json_object *networks=nc_docker_member(nc_docker_member(raw,"NetworkSettings"),"Networks");
    int rc=0;
    if(networks) {
        json_object_object_foreach(networks,key,endpoint) {
            if(!strcmp(key,"none"))continue;
            const char *network_id=nc_json_str_def(endpoint,"NetworkID","");
            if(!*network_id)continue;
            if(!nc_docker_resource_id_valid(network_id)){rc=-1;continue;}
            char path[256];long status;
            snprintf(path,sizeof(path),"/networks/%s/disconnect",network_id);
            struct json_object *body=json_object_new_object();
            json_object_object_add(body,"Container",json_object_new_string(id));
            json_object_object_add(body,"Force",json_object_new_boolean(1));
            struct json_object *r=nc_docker_engine_request("POST",path,body,&status);
            json_object_put(r);json_object_put(body);if(status!=200)rc=-1;
        }
    }
    json_object_put(raw);return rc;
}

static int nc_docker_restore_networks(struct json_object *snapshot)
{
    const char *id=nc_json_str_def(snapshot,"Id","");
    struct json_object *raw=nc_docker_raw_container(id);
    if(!raw)return -1;
    struct json_object *current=nc_docker_member(nc_docker_member(raw,"NetworkSettings"),"Networks");
    struct json_object *config=json_object_new_object();
    nc_docker_copy(config,"network",nc_docker_member(snapshot,"HostConfig"),"NetworkMode");
    if(!strcmp(nc_json_str_def(config,"network",""),"default"))json_object_object_add(config,"network",json_object_new_string("bridge"));
    struct json_object *saved=nc_docker_replacement_networks(snapshot,config,0);
    json_object_put(config);int rc=0;
    json_object_object_foreach(saved,key,endpoint) {
        if(*nc_json_str_def(nc_docker_member(current,key),"NetworkID",""))continue;
        struct json_object *old=nc_docker_member(nc_docker_member(nc_docker_member(snapshot,"NetworkSettings"),"Networks"),key);
        const char *network_id=nc_json_str_def(old,"NetworkID","");
        if(!nc_docker_resource_id_valid(network_id)){rc=-1;continue;}
        char path[256];long status;
        snprintf(path,sizeof(path),"/networks/%s/connect",network_id);
        struct json_object *body=json_object_new_object();
        json_object_object_add(body,"Container",json_object_new_string(id));
        json_object_object_add(body,"EndpointConfig",json_object_get(endpoint));
        struct json_object *r=nc_docker_engine_request("POST",path,body,&status);
        json_object_put(r);json_object_put(body);if(status!=200)rc=-1;
    }
    json_object_put(saved);json_object_put(raw);return rc;
}

static int nc_docker_set_restart(const char *id,struct json_object *policy)
{
    char path[256];long status;struct json_object *body=json_object_new_object();
    json_object_object_add(body,"RestartPolicy",json_object_get(policy));
    snprintf(path,sizeof(path),"/containers/%s/update",id);
    struct json_object *r=nc_docker_engine_request("POST",path,body,&status);
    json_object_put(r);json_object_put(body);return status==200?0:-1;
}

static struct json_object *nc_docker_replacement_body(struct json_object *raw,struct json_object *cfg,int clone)
{
    struct json_object *body=json_tokener_parse(json_object_to_json_string_ext(nc_docker_member(raw,"Config"),JSON_C_TO_STRING_PLAIN));
    struct json_object *host=json_tokener_parse(json_object_to_json_string_ext(nc_docker_member(raw,"HostConfig"),JSON_C_TO_STRING_PLAIN));
    nc_docker_copy(body,"Image",cfg,"image");nc_docker_copy(body,"Hostname",cfg,"hostname");
    if(nc_docker_member(cfg,"command"))nc_docker_copy(body,"Cmd",cfg,"command");
    if(nc_docker_member(cfg,"labels"))nc_docker_copy(body,"Labels",cfg,"labels");
    struct json_object *env=json_object_new_array(),*values=nc_docker_member(cfg,"env");
    if(values){json_object_object_foreach(values,k,v){char text[8400];snprintf(text,sizeof(text),"%s=%s",k,json_object_get_string(v));json_object_array_add(env,json_object_new_string(text));}}
    json_object_object_add(body,"Env",env);
    struct json_object *bindings=json_object_new_object(),*exposed=json_object_new_object(),*ports=nc_docker_member(cfg,"ports");
    for(size_t i=0;ports&&i<json_object_array_length(ports);i++) {
        struct json_object *p=json_object_array_get_idx(ports,i);char key[32],port[16];
        snprintf(key,sizeof(key),"%d/%s",nc_json_int_def(p,"container_port",0),nc_json_str_def(p,"protocol","tcp"));
        snprintf(port,sizeof(port),"%d",nc_json_int_def(p,"host_port",0));
        struct json_object *list=nc_docker_member(bindings,key);if(!list){list=json_object_new_array();json_object_object_add(bindings,key,list);}
        struct json_object *entry=json_object_new_object();json_object_object_add(entry,"HostPort",json_object_new_string(port));json_object_object_add(entry,"HostIp",json_object_new_string(nc_json_str_def(p,"host_ip","")));json_object_array_add(list,entry);
        json_object_object_add(exposed,key,json_object_new_object());
    }
    json_object_object_add(body,"ExposedPorts",exposed);json_object_object_add(host,"PortBindings",bindings);
    json_object_object_del(host,"Binds");json_object_object_del(host,"VolumesFrom");
    struct json_object *mounts=json_object_new_array(),*values_mounts=nc_docker_member(cfg,"mounts");
    for(size_t i=0;values_mounts&&i<json_object_array_length(values_mounts);i++) {
        struct json_object *m=json_object_array_get_idx(values_mounts,i),*entry=json_object_new_object();
        nc_docker_copy(entry,"Type",m,"type");nc_docker_copy(entry,"Source",m,"source");nc_docker_copy(entry,"Target",m,"target");
        json_object_object_add(entry,"ReadOnly",json_object_new_boolean(nc_json_bool_def(m,"read_only",0)));json_object_array_add(mounts,entry);
    }
    json_object_object_add(host,"Mounts",mounts);nc_docker_copy(host,"NetworkMode",cfg,"network");
    const char *policy=nc_json_str_def(cfg,"restart_policy","no"),*colon=strchr(policy,':');
    struct json_object *restart=json_object_new_object();json_object_object_add(restart,"Name",colon?json_object_new_string_len(policy,colon-policy):json_object_new_string(policy));
    json_object_object_add(restart,"MaximumRetryCount",json_object_new_int(colon?atoi(colon+1):0));json_object_object_add(host,"RestartPolicy",restart);
    struct json_object *resources=nc_docker_member(cfg,"resources");
    json_object_object_add(host,"Memory",json_object_new_int64(json_object_get_int64(nc_docker_member(resources,"memory_bytes"))));
    json_object_object_add(host,"CpuShares",json_object_new_int64(json_object_get_int64(nc_docker_member(resources,"cpu_shares"))));
    json_object_object_add(body,"HostConfig",host);
    struct json_object *networking=json_object_new_object();
    json_object_object_add(networking,"EndpointsConfig",nc_docker_replacement_networks(raw,cfg,clone));
    json_object_object_add(body,"NetworkingConfig",networking);return body;
}

static int nc_docker_recreate_record(sqlite3 *db,const char *job,struct json_object *detail,const char *phase)
{
    sqlite3_stmt *st=NULL;json_object_object_add(detail,"phase",json_object_new_string(phase));
    if(sqlite3_prepare_v2(db,"UPDATE container_job SET result_json=?1,updated_at=?2 WHERE id=?3 AND state='running'",-1,&st,NULL)!=SQLITE_OK)return -1;
    sqlite3_bind_text(st,1,json_object_to_json_string_ext(detail,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    sqlite3_bind_int64(st,2,nc_now_s());sqlite3_bind_text(st,3,job,-1,SQLITE_TRANSIENT);
    int rc=sqlite3_step(st)==SQLITE_DONE&&sqlite3_changes(db)==1?0:-1;sqlite3_finalize(st);return rc;
}

static int nc_docker_replace_execute(sqlite3 *db,const char *job,struct json_object *request,
                                     struct json_object *detail,int clone)
{
    const char *id=nc_json_str_def(request,"id","");struct json_object *raw=nc_docker_raw_container(id);
    char revision[65],path[640],backup[180],candidate[180];long status=0;int rc=125,stopped=0,renamed=0,started=0;
    struct json_object *response=NULL,*body=NULL,*cfg=nc_docker_member(request,"config");
    char *canonical=NULL,image[256],name[129];char created[129]="";
    if(!raw)return nc_docker_invalid(detail,"container_not_found"),125;
    if(nc_docker_container_revision(raw,revision)||strcmp(revision,nc_json_str_def(request,"revision",""))) {nc_docker_invalid(detail,"revision_conflict");goto done;}
    if(nc_docker_create_normalize(cfg,&canonical,image,sizeof(image),name,sizeof(name),detail)||!*name)goto done;
    free(canonical);canonical=NULL;
    struct json_object *probe=json_tokener_parse(json_object_to_json_string_ext(cfg,JSON_C_TO_STRING_PLAIN));
    /* The old container legitimately owns its bindings until the switch. */
    if(!clone)json_object_object_del(probe,"ports");
    int invalid=nc_docker_create_preflight(probe,detail);json_object_put(probe);if(invalid)goto done;
    if(nc_json_bool_def(nc_docker_member(raw,"HostConfig"),"Privileged",0)||nc_docker_member(nc_docker_member(nc_docker_member(raw,"Config"),"Labels"),"com.docker.compose.project")){nc_docker_invalid(detail,"source_owner_or_privileged_container");goto done;}
    int was_running=nc_json_bool_def(nc_docker_member(raw,"State"),"Running",0);
    snprintf(backup,sizeof(backup),"%s-backup-%.12s",name,job+4);
    snprintf(candidate,sizeof(candidate),clone?"%s":"%s-pending-%.12s",name,job+4);
    json_object_object_add(detail,"candidate_name",json_object_new_string(candidate));
    json_object_object_add(detail,"original_name",json_object_new_string(name));
    json_object_object_add(detail,"original_id",json_object_new_string(id));json_object_object_add(detail,"original_running",json_object_new_boolean(was_running));
    json_object_object_add(detail,"backup_name",clone?NULL:json_object_new_string(backup));
    json_object_object_add(detail,"data_copied",json_object_new_boolean(0));
    json_object_object_add(detail,"recoverable",json_object_new_boolean(!clone));
    if(nc_docker_recreate_record(db,job,detail,"creating"))goto done;
    if(!clone) {
        struct json_object *no_restart=json_object_new_object();
        json_object_object_add(no_restart,"Name",json_object_new_string("no"));
        if(nc_docker_recreate_record(db,job,detail,"stopping_original")||nc_docker_set_restart(id,no_restart)) {
            json_object_put(no_restart);nc_docker_invalid(detail,"original_restart_policy_failed");goto rollback;
        }
        json_object_put(no_restart);
        if(was_running) {
            snprintf(path,sizeof(path),"/containers/%s/stop?t=10",id);response=nc_docker_engine_request("POST",path,NULL,&status);json_object_put(response);response=NULL;
            if(status!=204&&status!=304){nc_docker_invalid(detail,"original_stop_failed");goto rollback;}stopped=1;
        }
        if(nc_docker_recreate_record(db,job,detail,"disconnecting_original")||nc_docker_disconnect_networks(id)) {
            nc_docker_invalid(detail,"original_network_disconnect_failed");goto rollback;
        }
    }
    body=nc_docker_replacement_body(raw,cfg,clone);
    struct json_object *candidate_labels=nc_docker_member(body,"Labels");
    if(!candidate_labels){candidate_labels=json_object_new_object();json_object_object_add(body,"Labels",candidate_labels);}
    json_object_object_add(candidate_labels,"io.dreamingwrt.replacement-job",json_object_new_string(job));
    snprintf(path,sizeof(path),"/containers/create?name=%s",candidate);
    response=nc_docker_engine_request("POST",path,body,&status);
    if(status!=201||!nc_docker_member(response,"Id")){nc_docker_invalid(detail,"replacement_create_failed");goto rollback;}
    snprintf(created,sizeof(created),"%s",nc_json_str_def(response,"Id",""));json_object_put(response);response=NULL;
    json_object_object_add(detail,"container_id",json_object_new_string(created));
    if(nc_docker_recreate_record(db,job,detail,"created"))goto rollback;
    if((clone&&nc_json_bool_def(cfg,"start_after_create",0))||(!clone&&was_running)) {
        snprintf(path,sizeof(path),"/containers/%s/start",created);response=nc_docker_engine_request("POST",path,NULL,&status);json_object_put(response);response=NULL;
        if(status!=204&&status!=304){nc_docker_invalid(detail,"replacement_start_failed");goto rollback;}started=1;
        struct json_object *check=nc_docker_raw_container(created);
        int running=check&&nc_json_bool_def(nc_docker_member(check,"State"),"Running",0);if(check)json_object_put(check);
        if(!running){nc_docker_invalid(detail,"replacement_not_running");goto rollback;}
    }
    if(!clone) {
        snprintf(path,sizeof(path),"/containers/%s/rename?name=%s",id,backup);response=nc_docker_engine_request("POST",path,NULL,&status);json_object_put(response);response=NULL;
        if(status!=204){nc_docker_invalid(detail,"backup_rename_failed");goto rollback;}renamed=1;
        if(nc_docker_recreate_record(db,job,detail,"original_retained"))goto rollback;
        snprintf(path,sizeof(path),"/containers/%s/rename?name=%s",created,name);response=nc_docker_engine_request("POST",path,NULL,&status);json_object_put(response);response=NULL;
        if(status!=204){nc_docker_invalid(detail,"replacement_rename_failed");goto rollback;}
    }
    json_object_object_add(detail,"container_name",json_object_new_string(name));
    json_object_object_add(detail,"original_retained",json_object_new_boolean(!clone));
    json_object_object_add(detail,"recoverable",json_object_new_boolean(0));
    json_object_object_add(detail,"phase",json_object_new_string("verified"));rc=0;goto done;
rollback:
    {
        int restored=1;
        if(started){snprintf(path,sizeof(path),"/containers/%s/stop?t=10",created);response=nc_docker_engine_request("POST",path,NULL,&status);json_object_put(response);response=NULL;if(status!=204&&status!=304)restored=0;}
        int disconnected=!*created||!nc_docker_disconnect_networks(created);
        int networks_restored=clone||!nc_docker_restore_networks(raw);
        int policy_restored=clone||!nc_docker_set_restart(id,nc_docker_member(nc_docker_member(raw,"HostConfig"),"RestartPolicy"));
        json_object_object_add(detail,"replacement_disconnected",json_object_new_boolean(disconnected));
        json_object_object_add(detail,"networks_restored",json_object_new_boolean(networks_restored));
        json_object_object_add(detail,"restart_policy_restored",json_object_new_boolean(policy_restored));
        if(!disconnected||!networks_restored||!policy_restored)restored=0;
        if(renamed){snprintf(path,sizeof(path),"/containers/%s/rename?name=%s",id,name);response=nc_docker_engine_request("POST",path,NULL,&status);json_object_put(response);response=NULL;if(status!=204)restored=0;}
        if(stopped){snprintf(path,sizeof(path),"/containers/%s/start",id);response=nc_docker_engine_request("POST",path,NULL,&status);json_object_put(response);response=NULL;if(status!=204&&status!=304)restored=0;}
        json_object_object_add(detail,"rollback_succeeded",json_object_new_boolean(restored));
        json_object_object_add(detail,"recoverable",json_object_new_boolean(!restored&&!clone));
        json_object_object_add(detail,"phase",json_object_new_string(restored?"original_restored":"recovery_required"));
    }
done:
    free(canonical);if(response)json_object_put(response);if(body)json_object_put(body);json_object_put(raw);return rc;
}


/* Recover a cancelled/interrupted replacement from its encrypted source snapshot.
 * The candidate is identified by both recorded name/id and our immutable label.
 * Neither container nor its data is deleted. GET job only reports this option. */
static int nc_docker_recover_execute(sqlite3 *db, const char *job,
                                      struct json_object *request,
                                      struct json_object *detail)
{
    struct json_object *snapshot=nc_docker_member(request,"source_snapshot");
    struct json_object *saved=nc_docker_member(request,"interrupted_result");
    const char *source_id=nc_json_str_def(snapshot,"Id","");
    const char *old_name=nc_json_str_def(snapshot,"Name","");
    const char *previous_job=nc_json_str_def(request,"interrupted_job","");
    const char *candidate_id=nc_json_str_def(saved,"container_id","");
    if(*old_name=='/')old_name++;
    if(!nc_docker_resource_id_valid(source_id)||!nc_docker_name_valid(old_name)||
       !nc_container_job_id_valid(previous_job))
        return nc_docker_invalid(detail,"invalid_recovery_snapshot"),125;
    struct json_object *original=nc_docker_raw_container(source_id);
    if(!original)return nc_docker_invalid(detail,"original_container_missing"),125;
    char candidate_name[180],path[640];long status;int ok=1;
    snprintf(candidate_name,sizeof(candidate_name),"%s-pending-%.12s",old_name,previous_job+4);
    struct json_object *candidate=nc_docker_raw_container(*candidate_id?candidate_id:candidate_name);
    if(!candidate) {
        candidate=nc_docker_raw_container(old_name);
        if(candidate&&!strcmp(nc_json_str_def(candidate,"Id",""),source_id)){
            json_object_put(candidate);candidate=NULL;
        }
    }
    if(candidate && strcmp(nc_json_str_def(nc_docker_member(nc_docker_member(candidate,"Config"),"Labels"),
                           "io.dreamingwrt.replacement-job",""),previous_job)) {
        json_object_put(candidate);json_object_put(original);
        return nc_docker_invalid(detail,"replacement_identity_conflict"),125;
    }
    nc_docker_copy(detail,"original_id",snapshot,"Id");
    json_object_object_add(detail,"original_name",json_object_new_string(old_name));
    json_object_object_add(detail,"interrupted_job",json_object_new_string(previous_job));
    json_object_object_add(detail,"recoverable",json_object_new_boolean(1));
    if(candidate) {
        candidate_id=nc_json_str_def(candidate,"Id","");
        json_object_object_add(detail,"container_id",json_object_new_string(candidate_id));
        if(nc_docker_recreate_record(db,job,detail,"stopping_replacement"))ok=0;
        if(ok) {
            snprintf(path,sizeof(path),"/containers/%s/stop?t=10",candidate_id);
            struct json_object *r=nc_docker_engine_request("POST",path,NULL,&status);
            json_object_put(r);if(status!=204&&status!=304)ok=0;
        }
        const char *actual_name=nc_json_str_def(candidate,"Name","");if(*actual_name=='/')actual_name++;
        if(ok&&strcmp(actual_name,candidate_name)) {
            snprintf(path,sizeof(path),"/containers/%s/rename?name=%s",candidate_id,candidate_name);
            struct json_object *r=nc_docker_engine_request("POST",path,NULL,&status);
            json_object_put(r);if(status!=204)ok=0;
        }
    }
    if(ok&&candidate&&nc_docker_disconnect_networks(candidate_id))ok=0;
    if(ok&&nc_docker_restore_networks(snapshot))ok=0;
    if(ok&&nc_docker_set_restart(source_id,nc_docker_member(nc_docker_member(snapshot,"HostConfig"),"RestartPolicy")))ok=0;
    const char *source_name=nc_json_str_def(original,"Name","");if(*source_name=='/')source_name++;
    if(ok&&strcmp(source_name,old_name)) {
        snprintf(path,sizeof(path),"/containers/%s/rename?name=%s",source_id,old_name);
        struct json_object *r=nc_docker_engine_request("POST",path,NULL,&status);
        json_object_put(r);if(status!=204)ok=0;
    }
    if(ok&&nc_json_bool_def(nc_docker_member(snapshot,"State"),"Running",0)) {
        snprintf(path,sizeof(path),"/containers/%s/start",source_id);
        struct json_object *r=nc_docker_engine_request("POST",path,NULL,&status);
        json_object_put(r);if(status!=204&&status!=304)ok=0;
    }
    struct json_object *check=nc_docker_raw_container(source_id);
    const char *name=nc_json_str_def(check,"Name","");if(*name=='/')name++;
    int expected_running=nc_json_bool_def(nc_docker_member(snapshot,"State"),"Running",0);
    if(!check||strcmp(name,old_name)||nc_json_bool_def(nc_docker_member(check,"State"),"Running",0)!=expected_running)ok=0;
    if(check)json_object_put(check);
    json_object_put(original);if(candidate)json_object_put(candidate);
    json_object_object_add(detail,"rollback_succeeded",json_object_new_boolean(ok));
    json_object_object_add(detail,"recoverable",json_object_new_boolean(!ok));
    json_object_object_add(detail,"phase",json_object_new_string(ok?"original_restored":"recovery_required"));
    if(!ok)return nc_docker_invalid(detail,"original_recovery_failed"),125;
    sqlite3_stmt *st=NULL;
    if(sqlite3_prepare_v2(db,"UPDATE container_job SET result_json=?1,updated_at=?2 WHERE id=?3 AND state IN ('failed','cancelled')",-1,&st,NULL)!=SQLITE_OK)return 125;
    sqlite3_bind_text(st,1,json_object_to_json_string_ext(detail,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    sqlite3_bind_int64(st,2,nc_now_s());sqlite3_bind_text(st,3,previous_job,-1,SQLITE_TRANSIENT);
    int rc=sqlite3_step(st)==SQLITE_DONE?0:125;sqlite3_finalize(st);return rc;
}

static int nc_docker_recover_submit(const char *id, struct json_object *out)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct ac_secrets *vault=NULL;
    unsigned char *clear=NULL;size_t len=0;struct json_object *request=NULL,*saved=NULL;
    char target[129]="",secret_id[80];int rc=-1,network=0;
    if(!nc_container_job_id_valid(id))return nc_docker_invalid(out,"invalid_job_id");
    if(nc_container_job_db_open(&db)||nc_container_jobs_reconcile(db))goto storage;
    if(sqlite3_prepare_v2(db,"SELECT kind,state,target,result_json FROM container_job WHERE id=?1",-1,&st,NULL)!=SQLITE_OK)goto storage;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)!=SQLITE_ROW){nc_docker_invalid(out,"container_job_not_found");goto done;}
    const char *kind=(const char *)sqlite3_column_text(st,0),*state=(const char *)sqlite3_column_text(st,1);
    saved=json_tokener_parse((const char *)sqlite3_column_text(st,3));
    network=!strcmp(kind,"network_recreate")||!strcmp(kind,"network_recover");
    if((strcmp(kind,"container_recreate")&&!network)|| (strcmp(state,"failed")&&strcmp(state,"cancelled"))||
       !nc_json_bool_def(saved,"recoverable",0)) {
        nc_docker_invalid(out,"container_job_not_recoverable");goto done;
    }
    snprintf(target,sizeof(target),"%s",sqlite3_column_text(st,2));sqlite3_finalize(st);st=NULL;
    snprintf(secret_id,sizeof(secret_id),"docker-%s",id);
    if(ac_secrets_open(db,NC_CONTAINER_SECRET_KEY_PATH,&vault)!=AC_SECRETS_OK||
       ac_secrets_get(vault,secret_id,1,&clear,&len)!=AC_SECRETS_OK)goto storage;
    request=json_tokener_parse((const char *)clear);
    if(!request||!nc_docker_member(request,network?"network_snapshot":"source_snapshot")){nc_docker_invalid(out,"recovery_snapshot_unavailable");goto done;}
    json_object_object_add(request,"interrupted_job",json_object_new_string(id));
    json_object_object_add(request,"interrupted_result",json_object_get(saved));
    rc=nc_container_job_submit(network?"network_recover":"container_recover",target,json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN),out);
    goto done;
storage:
    nc_docker_invalid(out,"recovery_storage_unavailable");
done:
    if(st)sqlite3_finalize(st);
    if(request)json_object_put(request);
    if(saved)json_object_put(saved);
    ac_secrets_clear(clear,len);ac_secrets_close(vault);if(db)sqlite3_close(db);return rc;
}
