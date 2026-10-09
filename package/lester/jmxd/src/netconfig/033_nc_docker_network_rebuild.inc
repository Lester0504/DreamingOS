/* Network replacement keeps containers/data and journals before disconnecting. */
static struct json_object *nc_docker_network_raw(const char *id)
{
    char path[256];long status=0;
    if(!nc_docker_resource_id_valid(id))return NULL;
    snprintf(path,sizeof(path),"/networks/%s",id);
    struct json_object *raw=nc_docker_engine_request("GET",path,NULL,&status);
    if(status==200)return raw;
    json_object_put(raw);return NULL;
}

static struct json_object *nc_docker_network_snapshot(const char *id,struct json_object *out)
{
    struct json_object *raw=nc_docker_network_raw(id),*list=NULL,*snapshot=NULL;
    if(!raw){nc_docker_invalid(out,"network_not_found");return NULL;}
    const char *name=nc_json_str_def(raw,"Name",""),*driver=nc_json_str_def(raw,"Driver","");
    struct json_object *pools=nc_docker_member(nc_docker_member(raw,"IPAM"),"Config");
    if(!strcmp(name,"bridge")||!strcmp(name,"host")||!strcmp(name,"none")||
       strcmp(nc_json_str_def(raw,"Scope",""),"local")||nc_json_bool_def(raw,"Ingress",0)||
       nc_json_bool_def(raw,"ConfigOnly",0)||nc_json_bool_def(raw,"EnableIPv6",0)||
       *nc_json_str_def(nc_docker_member(raw,"ConfigFrom"),"Network","")||
       (!strcmp(driver,"ipvlan")&&strcmp(nc_json_str_def(nc_docker_member(raw,"Options"),"ipvlan_mode","l2"),"l2"))||
       (!strcmp(driver,"macvlan")&&strcmp(nc_json_str_def(nc_docker_member(raw,"Options"),"macvlan_mode","bridge"),"bridge"))||
       (strcmp(driver,"bridge")&&strcmp(driver,"macvlan")&&strcmp(driver,"ipvlan"))||
       nc_docker_member(nc_docker_member(raw,"Labels"),"com.docker.compose.project")||
       !json_object_is_type(pools,json_type_array)||json_object_array_length(pools)!=1||
       (nc_docker_member(json_object_array_get_idx(pools,0),"AuxiliaryAddresses")&&json_object_object_length(nc_docker_member(json_object_array_get_idx(pools,0),"AuxiliaryAddresses")))){
        nc_docker_invalid(out,"network_recreate_unsupported");goto done;
    }
    long status=0;list=nc_docker_engine_request("GET","/containers/json?all=true",NULL,&status);
    if(status!=200||!json_object_is_type(list,json_type_array)){nc_docker_invalid(out,"network_endpoints_unavailable");goto done;}
    snapshot=json_object_new_object();struct json_object *endpoints=json_object_new_array();
    json_object_object_add(snapshot,"network",json_object_get(raw));
    json_object_object_add(snapshot,"endpoints",endpoints);
    for(size_t i=0;i<json_object_array_length(list);i++){
        struct json_object *item=json_object_array_get_idx(list,i);
        struct json_object *ep=nc_docker_member(nc_docker_member(nc_docker_member(item,"NetworkSettings"),"Networks"),name);
        if(!ep)continue;
        struct json_object *container=nc_docker_raw_container(nc_json_str_def(item,"Id",""));
        ep=nc_docker_member(nc_docker_member(nc_docker_member(container,"NetworkSettings"),"Networks"),name);
        if(!container||!ep||(*nc_json_str_def(ep,"NetworkID","")&&strcmp(nc_json_str_def(ep,"NetworkID",""),nc_json_str_def(raw,"Id","")))||json_object_array_length(endpoints)>=64){
            if(container)json_object_put(container);
            json_object_put(snapshot);snapshot=NULL;nc_docker_invalid(out,"network_endpoints_changed_or_too_many");goto done;
        }
        const char *mode=nc_json_str_def(nc_docker_member(container,"HostConfig"),"NetworkMode","");
        if(*mode&&strcmp(mode,name)&&!strncmp(nc_json_str_def(raw,"Id",""),mode,strlen(mode))){
            nc_docker_create_error(out,"network_id_bound_container",nc_json_str_def(container,"Name",""),"container_primary_network_uses_immutable_id");
            json_object_put(container);json_object_put(snapshot);snapshot=NULL;goto done;
        }
        struct json_object *entry=json_object_new_object(),*config=json_object_new_object();
        nc_docker_copy(entry,"id",container,"Id");nc_docker_copy(entry,"name",container,"Name");
        nc_docker_copy(entry,"running",nc_docker_member(container,"State"),"Running");
        nc_docker_copy(entry,"address",ep,"IPAddress");
        const char *keys[]={"IPAMConfig","Links","Aliases","DriverOpts","GwPriority","MacAddress",NULL};
        for(int j=0;keys[j];j++)if(nc_docker_member(ep,keys[j]))nc_docker_copy(config,keys[j],ep,keys[j]);
        json_object_object_add(entry,"config",config);json_object_array_add(endpoints,entry);
        json_object_put(container);
    }
done:
    if(list)json_object_put(list);
    json_object_put(raw);return snapshot;
}

static int nc_docker_network_revision(struct json_object *snapshot,char hex[65])
{
    /* Container order from Engine listing is stable by creation time. */
    const char *text=json_object_to_json_string_ext(snapshot,JSON_C_TO_STRING_PLAIN);
    unsigned char digest[32];unsigned int n=0;
    if(!EVP_Digest(text,strlen(text),digest,&n,EVP_sha256(),NULL)||n!=32)return -1;
    for(unsigned int i=0;i<n;i++)snprintf(hex+i*2,3,"%02x",digest[i]);
    return 0;
}

static struct json_object *nc_docker_network_edit_read(struct json_object *request)
{
    struct json_object *out=json_object_new_object(),*snapshot=nc_docker_network_snapshot(nc_json_str_def(request,"id",""),out);
    if(!snapshot)return out;
    struct json_object *raw=nc_docker_member(snapshot,"network"),*cfg=nc_docker_member(request,"config");
    char revision[65];
    if(nc_docker_network_revision(snapshot,revision)){nc_docker_invalid(out,"network_revision_unavailable");goto done;}
    if(cfg){
        if(strcmp(revision,nc_json_str_def(request,"revision",""))){nc_docker_invalid(out,"revision_conflict");goto done;}
        if(strcmp(nc_json_str_def(cfg,"name",""),nc_json_str_def(raw,"Name",""))||
           strcmp(nc_json_str_def(cfg,"driver",""),nc_json_str_def(raw,"Driver",""))){nc_docker_invalid(out,"network_recreate_keeps_name_and_driver");goto done;}
        struct json_object *plan=nc_docker_network_plan_for(cfg,raw);
        if(!nc_json_bool_def(plan,"ok",0)){
            json_object_put(out);out=plan;goto done;
        }
        json_object_put(plan);
        uint32_t first,last;
        if(nc_docker_ipv4_cidr(nc_json_str_def(nc_docker_member(cfg,"ipam"),"subnet",""),&first,&last)){
            nc_docker_invalid(out,"network_recreate_requires_subnet");goto done;
        }
        struct json_object *endpoints=nc_docker_member(snapshot,"endpoints");
        for(size_t i=0;i<json_object_array_length(endpoints);i++){
            struct json_object *ep=json_object_array_get_idx(endpoints,i);
            const char *ip=nc_json_str_def(nc_docker_member(nc_docker_member(ep,"config"),"IPAMConfig"),"IPv4Address","");
            struct in_addr address;
            if(*ip&&(inet_pton(AF_INET,ip,&address)!=1||ntohl(address.s_addr)<=first||ntohl(address.s_addr)>=last)){
                nc_docker_create_error(out,"static_endpoint_outside_subnet",nc_json_str_def(ep,"name",""),ip);goto done;
            }
        }
        json_object_object_add(out,"config",json_object_get(cfg));
    }else{
        cfg=json_object_new_object();struct json_object *ipam=json_object_new_object();
        struct json_object *pool=json_object_array_get_idx(nc_docker_member(nc_docker_member(raw,"IPAM"),"Config"),0);
        nc_docker_copy(cfg,"name",raw,"Name");nc_docker_copy(cfg,"driver",raw,"Driver");nc_docker_copy(cfg,"internal",raw,"Internal");
        nc_docker_copy(ipam,"subnet",pool,"Subnet");nc_docker_copy(ipam,"gateway",pool,"Gateway");
        const char *range=nc_json_str_def(pool,"IPRange","");
        if(*range)json_object_object_add(ipam,"ip_range",json_object_new_string(range));
        json_object_object_add(cfg,"ipam",ipam);
        if(strcmp(nc_json_str_def(raw,"Driver",""),"bridge"))nc_docker_copy(cfg,"parent",nc_docker_member(raw,"Options"),"parent");
        json_object_object_add(out,"config",cfg);
    }
    json_object_object_add(out,"ok",json_object_new_boolean(1));
    nc_docker_copy(out,"id",raw,"Id");json_object_object_add(out,"revision",json_object_new_string(revision));
    nc_docker_copy(out,"endpoints",snapshot,"endpoints");
    json_object_object_add(out,"disconnect_required",json_object_new_boolean(json_object_array_length(nc_docker_member(snapshot,"endpoints"))>0));
done:
    json_object_put(snapshot);return out;
}

static int nc_docker_network_rebuild_submit(struct json_object *cfg,struct json_object *out)
{
    struct json_object *plan=nc_docker_network_edit_read(cfg),*snapshot=NULL,*request=NULL;int rc=-1;
    if(!nc_json_bool_def(plan,"ok",0)){
        json_object_object_foreach(plan,key,value){json_object_object_add(out,key,json_object_get(value));}goto done;
    }
    if(nc_json_bool_def(plan,"disconnect_required",0)&&!nc_json_bool_def(cfg,"allow_disconnect",0)){
        nc_docker_invalid(out,"network_disconnect_confirmation_required");goto done;
    }
    struct json_object *config=nc_docker_member(cfg,"config");
    if(strcmp(nc_json_str_def(config,"driver",""),"bridge")&&!nc_json_bool_def(config,"acknowledge_dhcp",0)){
        nc_docker_invalid(out,"network_acknowledgement_required");goto done;
    }
    snapshot=nc_docker_network_snapshot(nc_json_str_def(plan,"id",""),out);char revision[65];
    if(!snapshot||nc_docker_network_revision(snapshot,revision)||strcmp(revision,nc_json_str_def(plan,"revision",""))){nc_docker_invalid(out,"revision_conflict");goto done;}
    request=json_object_new_object();json_object_object_add(request,"network_snapshot",json_object_get(snapshot));
    nc_docker_copy(request,"config",plan,"config");nc_docker_copy(request,"revision",plan,"revision");
    rc=nc_container_job_submit("network_recreate",nc_json_str_def(plan,"id",""),json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN),out);
done:
    if(snapshot)json_object_put(snapshot);
    if(request)json_object_put(request);
    json_object_put(plan);return rc;
}

static struct json_object *nc_docker_network_definition(struct json_object *raw,struct json_object *cfg,const char *job)
{
    struct json_object *body=json_object_new_object();
    const char *keys[]={"Name","Driver","Internal","Attachable","Options","Labels","IPAM","EnableIPv6","EnableIPv4",NULL};
    for(int i=0;keys[i];i++)if(nc_docker_member(raw,keys[i])){
        json_object_object_add(body,keys[i],json_tokener_parse(json_object_to_json_string_ext(nc_docker_member(raw,keys[i]),JSON_C_TO_STRING_PLAIN)));
    }
    if(cfg){
        nc_docker_copy(body,"Internal",cfg,"internal");
        struct json_object *ipam=nc_docker_member(body,"IPAM"),*pools=json_object_new_array(),*pool=json_object_new_object();
        nc_docker_copy(pool,"Subnet",nc_docker_member(cfg,"ipam"),"subnet");
        const char *keys2[][2]={{"Gateway","gateway"},{"IPRange","ip_range"},{NULL,NULL}};
        for(int i=0;keys2[i][0];i++)if(*nc_json_str_def(nc_docker_member(cfg,"ipam"),keys2[i][1],""))nc_docker_copy(pool,keys2[i][0],nc_docker_member(cfg,"ipam"),keys2[i][1]);
        json_object_array_add(pools,pool);json_object_object_add(ipam,"Config",pools);
        if(strcmp(nc_json_str_def(raw,"Driver",""),"bridge"))nc_docker_copy(nc_docker_member(body,"Options"),"parent",cfg,"parent");
    }
    struct json_object *labels=nc_docker_member(body,"Labels");
    if(!labels){labels=json_object_new_object();json_object_object_add(body,"Labels",labels);}
    json_object_object_add(labels,"io.dreamingwrt.network-job",json_object_new_string(job));
    return body;
}

static int nc_docker_network_endpoints_apply(const char *id,struct json_object *snapshot,int connect,struct json_object *detail)
{
    struct json_object *endpoints=nc_docker_member(snapshot,"endpoints"),*network=nc_docker_member(snapshot,"network");
    const char *name=nc_json_str_def(network,"Name","");
    for(size_t i=0;i<json_object_array_length(endpoints);i++){
        struct json_object *ep=json_object_array_get_idx(endpoints,i);
        struct json_object *current=nc_docker_raw_container(nc_json_str_def(ep,"id",""));
        if(!current){nc_docker_copy(detail,"blocked_container",ep,"id");return nc_docker_invalid(detail,"network_endpoint_container_missing");}
        struct json_object *attached=nc_docker_member(nc_docker_member(nc_docker_member(current,"NetworkSettings"),"Networks"),name);
        const char *actual=nc_json_str_def(attached,"NetworkID","");
        int present=*actual!=0,match=!strcmp(actual,id);json_object_put(current);
        if(present&&!match){nc_docker_copy(detail,"blocked_container",ep,"id");return nc_docker_invalid(detail,"network_endpoint_identity_changed");}
        if((connect&&present)||(!connect&&!present))continue;
        char path[256];long status=0;snprintf(path,sizeof(path),"/networks/%s/%s",id,connect?"connect":"disconnect");
        struct json_object *body=json_object_new_object();nc_docker_copy(body,"Container",ep,"id");
        if(connect)nc_docker_copy(body,"EndpointConfig",ep,"config");
        else json_object_object_add(body,"Force",json_object_new_boolean(0));
        struct json_object *r=nc_docker_engine_request("POST",path,body,&status);
        json_object_put(body);
        if(status!=200){
            nc_docker_copy(detail,"blocked_container",ep,"id");
            json_object_object_add(detail,"engine_status",json_object_new_int((int)status));
            json_object_object_add(detail,"engine_message",json_object_new_string_len(nc_json_str_def(r,"message",""),(int)strnlen(nc_json_str_def(r,"message",""),512)));
            json_object_put(r);return -1;
        }
        json_object_put(r);
    }
    return 0;
}

static int nc_docker_network_endpoints_verify(const char *id,struct json_object *snapshot)
{
    const char *name=nc_json_str_def(nc_docker_member(snapshot,"network"),"Name","");
    struct json_object *endpoints=nc_docker_member(snapshot,"endpoints");
    for(size_t i=0;i<json_object_array_length(endpoints);i++){
        struct json_object *saved=json_object_array_get_idx(endpoints,i);
        struct json_object *raw=nc_docker_raw_container(nc_json_str_def(saved,"id",""));
        struct json_object *ep=nc_docker_member(nc_docker_member(nc_docker_member(raw,"NetworkSettings"),"Networks"),name);
        const char *address=nc_json_str_def(nc_docker_member(nc_docker_member(saved,"config"),"IPAMConfig"),"IPv4Address","");
        int running=nc_json_bool_def(saved,"running",0);
        const char *actual_id=nc_json_str_def(ep,"NetworkID","");
        int ok=raw&&ep&&(!strcmp(actual_id,id)||(!running&&!*actual_id))&&
            nc_json_bool_def(nc_docker_member(raw,"State"),"Running",0)==running&&
            (!*address||!strcmp(address,running?nc_json_str_def(ep,"IPAddress",""):nc_json_str_def(nc_docker_member(ep,"IPAMConfig"),"IPv4Address","")));
        struct json_object *expected=nc_docker_member(nc_docker_member(saved,"config"),"Aliases"),*actual=nc_docker_member(ep,"Aliases");
        for(size_t a=0;ok&&expected&&a<json_object_array_length(expected);a++){
            int found=0;
            for(size_t b=0;actual&&b<json_object_array_length(actual);b++)
                if(!strcmp(json_object_get_string(json_object_array_get_idx(expected,a)),json_object_get_string(json_object_array_get_idx(actual,b))))found=1;
            if(!found)ok=0;
        }
        if(raw)json_object_put(raw);
        if(!ok)return -1;
    }
    return 0;
}

static int nc_docker_network_restore(struct json_object *snapshot,const char *job,struct json_object *detail)
{
    struct json_object *original=nc_docker_member(snapshot,"network");
    const char *name=nc_json_str_def(original,"Name",""),*old=nc_json_str_def(original,"Id","");
    struct json_object *current=nc_docker_network_raw(name);char id[129]="",path[256];long status=0;
    if(current){
        snprintf(id,sizeof(id),"%s",nc_json_str_def(current,"Id",""));
        int ours=!strcmp(nc_json_str_def(nc_docker_member(current,"Labels"),"io.dreamingwrt.network-job",""),job);
        if(strcmp(id,old)&&!ours){json_object_put(current);return nc_docker_invalid(detail,"network_recovery_identity_conflict");}
        json_object_put(current);
        if(strcmp(id,old)){
            if(nc_docker_network_endpoints_apply(id,snapshot,0,detail))return -1;
            snprintf(path,sizeof(path),"/networks/%s",id);
            struct json_object *r=nc_docker_engine_request("DELETE",path,NULL,&status);json_object_put(r);
            if(status!=204)return -1;
            id[0]=0;
        }
    }
    if(!*id){
        struct json_object *body=nc_docker_network_definition(original,NULL,job);
        struct json_object *r=nc_docker_engine_request("POST","/networks/create",body,&status);
        json_object_put(body);snprintf(id,sizeof(id),"%s",nc_json_str_def(r,"Id",""));json_object_put(r);
        if(status!=201||!*id)return -1;
    }
    json_object_object_add(detail,"network_id",json_object_new_string(id));
    if(nc_docker_network_endpoints_apply(id,snapshot,1,detail))return -1;
    return nc_docker_network_endpoints_verify(id,snapshot);
}

static int nc_docker_network_rebuild_execute(sqlite3 *db,const char *job,struct json_object *request,struct json_object *detail,int recover)
{
    struct json_object *snapshot=nc_docker_member(request,"network_snapshot"),*original=nc_docker_member(snapshot,"network");
    const char *old=nc_json_str_def(original,"Id",""),*name=nc_json_str_def(original,"Name","");
    if(!nc_docker_resource_id_valid(old)||!nc_docker_name_valid(name))return nc_docker_invalid(detail,"invalid_network_snapshot"),125;
    const char *origin=recover?nc_json_str_def(nc_docker_member(request,"interrupted_result"),"origin_job",""):job;
    if(!nc_container_job_id_valid(origin))return nc_docker_invalid(detail,"invalid_network_snapshot"),125;
    nc_docker_copy(detail,"original_id",original,"Id");nc_docker_copy(detail,"network_name",original,"Name");
    json_object_object_add(detail,"origin_job",json_object_new_string(origin));
    json_object_object_add(detail,"recoverable",json_object_new_boolean(1));
    if(recover)goto rollback;
    struct json_object *current=nc_docker_network_snapshot(old,detail);char revision[65];
    int valid=current&&!nc_docker_network_revision(current,revision)&&!strcmp(revision,nc_json_str_def(request,"revision",""));
    if(current)json_object_put(current);
    if(!valid){json_object_object_add(detail,"recoverable",json_object_new_boolean(0));return nc_docker_invalid(detail,"revision_conflict"),125;}
    struct json_object *validation=json_object_new_object();nc_docker_copy(validation,"id",original,"Id");
    nc_docker_copy(validation,"config",request,"config");nc_docker_copy(validation,"revision",request,"revision");
    struct json_object *plan=nc_docker_network_edit_read(validation);json_object_put(validation);
    valid=nc_json_bool_def(plan,"ok",0);json_object_put(plan);
    if(!valid){json_object_object_add(detail,"recoverable",json_object_new_boolean(0));return nc_docker_invalid(detail,"network_plan_changed"),125;}
    if(nc_docker_recreate_record(db,job,detail,"disconnecting_endpoints"))return 125;
    if(nc_docker_network_endpoints_apply(old,snapshot,0,detail)){nc_docker_invalid(detail,"network_disconnect_failed");goto rollback;}
    char path[256];long status=0;snprintf(path,sizeof(path),"/networks/%s",old);
    if(nc_docker_recreate_record(db,job,detail,"replacing_network"))goto rollback;
    struct json_object *r=nc_docker_engine_request("DELETE",path,NULL,&status);json_object_put(r);
    if(status!=204){nc_docker_invalid(detail,"network_remove_failed");goto rollback;}
    struct json_object *body=nc_docker_network_definition(original,nc_docker_member(request,"config"),origin);
    r=nc_docker_engine_request("POST","/networks/create",body,&status);json_object_put(body);
    char created[129];snprintf(created,sizeof(created),"%s",nc_json_str_def(r,"Id",""));json_object_put(r);
    if(status!=201||!*created){nc_docker_invalid(detail,"network_recreate_failed");goto rollback;}
    json_object_object_add(detail,"network_id",json_object_new_string(created));
    if(nc_docker_recreate_record(db,job,detail,"reconnecting_endpoints")||nc_docker_network_endpoints_apply(created,snapshot,1,detail)||nc_docker_network_endpoints_verify(created,snapshot)){
        nc_docker_invalid(detail,"network_reconnect_failed");goto rollback;
    }
    json_object_object_add(detail,"phase",json_object_new_string("verified"));
    json_object_object_add(detail,"recoverable",json_object_new_boolean(0));
    json_object_object_add(detail,"data_preserved",json_object_new_boolean(1));return 0;
rollback:
    if(!recover&&nc_docker_member(detail,"error"))nc_docker_copy(detail,"failure",detail,"error");
    if(nc_docker_recreate_record(db,job,detail,"restoring_network"))return 125;
    int restored=nc_docker_network_restore(snapshot,origin,detail)==0;
    json_object_object_add(detail,"rollback_succeeded",json_object_new_boolean(restored));
    json_object_object_add(detail,"recoverable",json_object_new_boolean(!restored));
    json_object_object_add(detail,"phase",json_object_new_string(restored?"network_restored":"recovery_required"));
    if(!restored)nc_docker_invalid(detail,"network_recovery_failed");
    if(recover&&restored){
        sqlite3_stmt *st=NULL;
        if(sqlite3_prepare_v2(db,"UPDATE container_job SET result_json=?1,updated_at=?2 WHERE (id=?3 OR id=?4) AND state IN ('failed','cancelled')",-1,&st,NULL)!=SQLITE_OK)return 125;
        sqlite3_bind_text(st,1,json_object_to_json_string_ext(detail,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
        sqlite3_bind_int64(st,2,nc_now_s());sqlite3_bind_text(st,3,origin,-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(st,4,nc_json_str_def(request,"interrupted_job",""),-1,SQLITE_TRANSIENT);
        int ok=sqlite3_step(st)==SQLITE_DONE;sqlite3_finalize(st);if(!ok)return 125;
    }
    return recover&&restored?0:125;
}
