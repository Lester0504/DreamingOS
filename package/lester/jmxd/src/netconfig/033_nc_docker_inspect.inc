/* Public inspect deliberately excludes environment values and arbitrary labels. */
struct json_object *jmx_docker_inspect(const char *kind, const char *id)
{
    struct json_object *d=json_object_new_object();
    if (!kind || (strcmp(kind,"container")&&strcmp(kind,"image")&&strcmp(kind,"network")&&strcmp(kind,"volume")) ||
        (!strcmp(kind,"image")?!nc_docker_image_id_valid(id):!nc_docker_resource_id_valid(id))) {
        nc_docker_invalid(d,"invalid_id"); return jmx_gen_api_response_data(API_CODE_ERROR,d);
    }
    const char *const argv[]={"docker",kind,"inspect",id,NULL};
    struct json_object *list=nc_docker_read_json(argv,0,d);
    struct json_object *raw=list&&json_object_is_type(list,json_type_array)?json_object_array_get_idx(list,0):NULL;
    if (!raw) {
        if(list)json_object_put(list);
        json_object_object_add(d,"ok",json_object_new_boolean(0));
        return jmx_gen_api_response_data(API_CODE_ERROR,d);
    }
    struct json_object *config=nc_docker_member(raw,"Config"), *host=nc_docker_member(raw,"HostConfig");
    nc_docker_copy(d,"id",raw,"Id"); nc_docker_copy(d,"name",raw,"Name");
    if (!strcmp(kind,"container")) {
        nc_docker_copy(d,"image",config,"Image"); nc_docker_copy(d,"image_id",raw,"Image");
        nc_docker_copy(d,"state",raw,"State");
        /* Health output and command/env may contain secrets. Only health state is public. */
        struct json_object *state=nc_docker_member(d,"state"),*health=nc_docker_member(state,"Health");
        if (health) json_object_object_del(health,"Log");
        if (state) json_object_object_del(state,"Error");
        nc_docker_copy(d,"mounts",raw,"Mounts"); nc_docker_copy(d,"restart_policy",host,"RestartPolicy");
        struct json_object *net=nc_docker_member(raw,"NetworkSettings");
        nc_docker_copy(d,"ports",net,"Ports"); nc_docker_copy(d,"networks",net,"Networks");
        nc_docker_copy(d,"network",host,"NetworkMode");
        struct json_object *resources=json_object_new_object();
        nc_docker_copy(resources,"memory_bytes",host,"Memory"); nc_docker_copy(resources,"cpu_shares",host,"CpuShares");
        json_object_object_add(d,"resources",resources);
        struct json_object *env=nc_docker_member(config,"Env"), *keys=json_object_new_array();
        for(size_t i=0;env&&i<json_object_array_length(env);i++) {
            const char *v=json_object_get_string(json_object_array_get_idx(env,i)),*eq=strchr(v,'=');
            if(eq)json_object_array_add(keys,json_object_new_string_len(v,(int)(eq-v)));
        }
        json_object_object_add(d,"env_keys",keys);
        json_object_object_add(d,"env_redacted",json_object_new_boolean(1));
        struct json_object *labels=nc_docker_member(config,"Labels"),*source=json_object_new_object();
        nc_docker_copy(source,"compose_project",labels,"com.docker.compose.project");
        nc_docker_copy(source,"compose_service",labels,"com.docker.compose.service");
        json_object_object_add(d,"source",source);
    } else if(!strcmp(kind,"image")) {
        nc_docker_copy(d,"architecture",raw,"Architecture"); nc_docker_copy(d,"os",raw,"Os");
        nc_docker_copy(d,"size_bytes",raw,"Size"); nc_docker_copy(d,"digests",raw,"RepoDigests");
        nc_docker_copy(d,"tags",raw,"RepoTags"); nc_docker_copy(d,"created",raw,"Created");
    } else {
        nc_docker_copy(d,"driver",raw,"Driver"); nc_docker_copy(d,"scope",raw,"Scope");
        if(!strcmp(kind,"network")) {
            nc_docker_copy(d,"ipam",raw,"IPAM"); nc_docker_copy(d,"containers",raw,"Containers");
            const char *name=nc_json_str_def(raw,"Name","");
            json_object_object_add(d,"builtin",json_object_new_boolean(!strcmp(name,"host")||!strcmp(name,"bridge")||!strcmp(name,"none")));
        } else {
            nc_docker_copy(d,"mountpoint",raw,"Mountpoint");
            char filter[320];snprintf(filter,sizeof(filter),"volume=%s",id);
            const char *const refs[]={"docker","ps","-a","--no-trunc","--filter",filter,"--format","{{json .}}",NULL};
            struct json_object *rows=nc_docker_read_json(refs,1,d);
            json_object_object_add(d,"containers",rows);
            if(!rows){json_object_put(list);json_object_object_add(d,"ok",json_object_new_boolean(0));return jmx_gen_api_response_data(API_CODE_ERROR,d);}
        }
    }
    json_object_put(list);
    json_object_object_add(d,"ok",json_object_new_boolean(1));
    json_object_object_add(d,"ts",json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}
