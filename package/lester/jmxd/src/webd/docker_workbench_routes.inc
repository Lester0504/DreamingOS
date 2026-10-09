    else if ((!strcmp(req.path,"/api/v1/container_service/docker/storage/preview") ||
              !strcmp(req.path,"/api/v1/container_service/docker/storage/migrate") ||
              !strcmp(req.path,"/api/v1/container_service/docker/storage/recover")) && !strcmp(req.method,"POST")) {
        int reading=strstr(req.path,"/preview")!=NULL;
        struct json_object *p=app_json_id_payload("",body_json);
        json_object_object_add(p,"operation",json_object_new_string(reading?"storage_preview":strstr(req.path,"/recover")?"storage_recover":"storage_migrate"));
        resp=app_ubus_invoke(reading?"docker_workbench_read":"docker_workbench_write",p);
        json_object_put(p);status=app_response_status(resp,status);
        if(!reading)jmx_app_audit_log(device_id[0]?device_id:"http",device_id,"docker.storage.migration","high","docker-engine","","");
    }
    else if ((!strcmp(req.path,"/api/v1/container_service/docker/config/apply") || !strcmp(req.path,"/api/v1/container_service/docker/config/recover")) && !strcmp(req.method,"POST")) {
        struct json_object *p=app_json_id_payload("",body_json);
        json_object_object_add(p,"operation",json_object_new_string(strstr(req.path,"/recover")?"config_recover":"config_apply"));
        resp=app_ubus_invoke("docker_workbench_write",p);json_object_put(p);status=app_response_status(resp,status);
        jmx_app_audit_log(device_id[0]?device_id:"http",device_id,"docker.config.apply","high","docker-engine","","");
    }
    else if (!strncmp(req.path,"/api/v1/container_service/docker/network/",41) &&
             strchr(req.path+41,'/') && (!strcmp(req.method,"GET")||!strcmp(req.method,"POST"))) {
        const char *end=strchr(req.path+41,'/');char id[129];
        int reading=(!strcmp(end,"/edit")&&!strcmp(req.method,"GET"))||(!strcmp(end,"/validate")&&!strcmp(req.method,"POST"));
        if(app_copy_safe_path_segment(id,sizeof(id),req.path+41,end)<=0||
           (!reading&&(strcmp(end,"/recreate")||strcmp(req.method,"POST")))){status=400;resp=app_path_segment_error("network_operation");}
        else{
            struct json_object *p=app_json_id_payload(id,body_json);
            json_object_object_add(p,"operation",json_object_new_string(reading?"network_edit":"network_recreate"));
            resp=app_ubus_invoke(reading?"docker_workbench_read":"docker_workbench_write",p);
            json_object_put(p);status=app_response_status(resp,status);
            if(!reading)jmx_app_audit_log(device_id[0]?device_id:"http",device_id,"docker.network.recreate","high",id,"","");
        }
    }
    else if (!strcmp(req.path,"/api/v1/container_service/docker/network/options") && !strcmp(req.method,"GET")) {
        struct json_object *p=json_object_new_object();
        json_object_object_add(p,"operation",json_object_new_string("network_options"));
        resp=app_ubus_invoke("docker_workbench_read",p);
        json_object_put(p);status=app_response_status(resp,status);
    }
    else if (!strcmp(req.path,"/api/v1/container_service/docker/network/validate") && !strcmp(req.method,"POST")) {
        struct json_object *p=app_json_id_payload("",body_json);
        json_object_object_add(p,"operation",json_object_new_string("network_validate"));
        resp=app_ubus_invoke("docker_workbench_read",p);
        json_object_put(p);status=app_response_status(resp,status);
    }
    else if ((!strcmp(req.path,"/api/v1/container_service/docker/cleanup/preview")&&!strcmp(req.method,"GET")) ||
             (!strcmp(req.path,"/api/v1/container_service/docker/cleanup")&&!strcmp(req.method,"POST"))) {
        int reading=!strcmp(req.method,"GET");
        struct json_object *p=reading?json_object_new_object():app_json_id_payload("",body_json);
        json_object_object_add(p,"operation",json_object_new_string(reading?"cleanup_preview":"cleanup_execute"));
        resp=app_ubus_invoke(reading?"docker_workbench_read":"docker_workbench_write",p);
        json_object_put(p);status=app_response_status(resp,status);
        if(!reading)jmx_app_audit_log(device_id[0]?device_id:"http",device_id,"docker.cleanup","high","selected_objects","","");
    }
    /* Docker workflows retain the container-service confirmation/auth gate. */
    else if (!strcmp(req.path,"/api/v1/container_service/docker/registry/search") && !strcmp(req.method,"GET")) {
        struct json_object *p=json_object_new_object();char value[256];int invalid=0;
        json_object_object_add(p,"operation",json_object_new_string("registry_search"));
        if(webd_query_get(req.query,"keyword",value,sizeof(value)))json_object_object_add(p,"keyword",json_object_new_string(value));
        const char *keys[]={"page","page_size",NULL};
        for(int i=0;keys[i];i++)if(webd_query_get(req.query,keys[i],value,sizeof(value))) {
            char *end=NULL;errno=0;long n=strtol(value,&end,10);
            if(errno||!*value||*end||n<1||n>100)invalid=1;
            else json_object_object_add(p,keys[i],json_object_new_int(n));
        }
        if(invalid){status=400;resp=app_path_segment_error("registry_query");}
        else resp=app_ubus_invoke("docker_workbench_read",p);
        json_object_put(p);status=app_response_status(resp,status);
    }
    else if (!strncmp(req.path,"/api/v1/container_service/docker/container-template/",sizeof("/api/v1/container_service/docker/container-template/")-1) && !strcmp(req.method,"GET")) {
        char id[129];const char *rest=req.path+sizeof("/api/v1/container_service/docker/container-template/")-1;
        if(strchr(rest,'/')||app_copy_safe_path_segment(id,sizeof(id),rest,NULL)<=0){status=400;resp=app_path_segment_error("container_id");}
        else {struct json_object *p=app_json_id_param(id);json_object_object_add(p,"operation",json_object_new_string("container_template"));resp=app_ubus_invoke("docker_workbench_read",p);json_object_put(p);status=app_response_status(resp,status);}
    }
    else if (!strncmp(req.path,"/api/v1/container_service/docker/container/",43) && !strcmp(req.method,"POST") &&
             (strstr(req.path+43,"/clone")||strstr(req.path+43,"/recreate"))) {
        const char *slash=strchr(req.path+43,'/');char id[129];
        if(!slash||app_copy_safe_path_segment(id,sizeof(id),req.path+43,slash)<=0||(strcmp(slash,"/clone")&&strcmp(slash,"/recreate"))){status=400;resp=app_path_segment_error("container_operation");}
        else {
            struct json_object *p=app_json_id_payload(id,body_json);json_object_object_add(p,"operation",json_object_new_string(!strcmp(slash,"/clone")?"container_clone":"container_recreate"));
            resp=app_ubus_invoke("docker_workbench_write",p);json_object_put(p);status=app_response_status(resp,status);
            jmx_app_audit_log(device_id[0]?device_id:"http",device_id,!strcmp(slash,"/clone")?"docker.container.clone":"docker.container.recreate","high",id,"","");
        }
    }
    else if (!strncmp(req.path,"/api/v1/container_service/docker/jobs/",sizeof("/api/v1/container_service/docker/jobs/")-1) && !strcmp(req.method,"POST")) {
        const char *rest=req.path+sizeof("/api/v1/container_service/docker/jobs/")-1;
        const char *slash=strchr(rest,'/');char id[64];
        if(!slash||strcmp(slash,"/recover")||app_copy_safe_path_segment(id,sizeof(id),rest,slash)<=0){status=400;resp=app_path_segment_error("job_recovery");}
        else {struct json_object *p=app_json_id_payload(id,body_json);json_object_object_add(p,"operation",json_object_new_string("container_recover"));resp=app_ubus_invoke("docker_workbench_write",p);json_object_put(p);status=app_response_status(resp,status);jmx_app_audit_log(device_id[0]?device_id:"http",device_id,"docker.container.recover","high",id,"","");}
    }
    else if (!strcmp(req.path,"/api/v1/container_service/docker/image/load") && !strcmp(req.method,"POST")) {
        struct json_object *p=app_json_id_payload("",body_json);
        json_object_object_add(p,"operation",json_object_new_string("image_load"));
        resp=app_ubus_invoke("docker_workbench_write",p);json_object_put(p);
        status=app_response_status(resp,status);
        jmx_app_audit_log(device_id[0]?device_id:"http",device_id,"docker.image.load","high","","","");
    }
    else if (!strcmp(req.path,"/api/v1/container_service/docker/compose") ||
             !strncmp(req.path,"/api/v1/container_service/docker/compose/",sizeof("/api/v1/container_service/docker/compose/")-1)) {
        const char *base="/api/v1/container_service/docker/compose";
        const char *rest=req.path+strlen(base),*op=NULL;char id[64]="";int reading=!strcmp(req.method,"GET");
        if(!*rest)op=reading?"compose_list":!strcmp(req.method,"POST")?"compose_save":NULL;
        else if(!strcmp(rest,"/import")&&!strcmp(req.method,"POST"))op="compose_save";
        else if(!strcmp(rest,"/validate")&&!strcmp(req.method,"POST"))op="compose_validate";
        else {
            const char *end=strchr(rest+1,'/');
            if(app_copy_safe_path_segment(id,sizeof(id),rest+1,end)<=0){status=400;resp=app_path_segment_error("compose_project_id");}
            else if(!end&&!strcmp(req.method,"DELETE"))op="delete";
            else if(end) {
                const char *action=end+1;
                if(!strcmp(action,"config"))op=reading?"compose_config":!strcmp(req.method,"PUT")?"compose_save":NULL;
                else if(!strcmp(action,"logs")&&reading)op="compose_logs";
                else if(!strcmp(req.method,"POST")&&(!strcmp(action,"up")||!strcmp(action,"stop")||!strcmp(action,"restart")||!strcmp(action,"pull")||!strcmp(action,"build")||!strcmp(action,"recreate")))op=action;
            }
        }
        if(!resp&&!op){status=404;resp=app_path_segment_error("compose_route");}
        if(op&&!resp) {
            struct json_object *p=reading?app_json_id_param(id):app_json_id_payload(id,body_json);
            json_object_object_add(p,"operation",json_object_new_string(op));
            if(reading&&!strcmp(op,"compose_logs")) {char service[128];if(webd_query_get(req.query,"service",service,sizeof(service)))json_object_object_add(p,"service",json_object_new_string(service));}
            resp=app_ubus_invoke(reading?"docker_workbench_read":"docker_workbench_write",p);
            json_object_put(p);status=app_response_status(resp,status);
            if(!reading)jmx_app_audit_log(device_id[0]?device_id:"http",device_id,"docker.compose","high",id,op,"");
        }
    }
