/* Cleanup deletes only selected, revalidated objects. Never issue a broad prune. */
static int nc_docker_cleanup_revision(struct json_object *value,char hex[65])
{
    const char *text=json_object_to_json_string_ext(value,JSON_C_TO_STRING_PLAIN);
    unsigned char digest[32];unsigned int n=0;
    if(!EVP_Digest(text,strlen(text),digest,&n,EVP_sha256(),NULL)||n!=32)return -1;
    for(unsigned int i=0;i<n;i++)snprintf(hex+i*2,3,"%02x",digest[i]);
    return 0;
}

static struct json_object *nc_docker_cleanup_get(const char *path)
{
    long status=0;struct json_object *data=nc_docker_engine_request("GET",path,NULL,&status);
    if(status!=200){if(data)json_object_put(data);return NULL;}
    return data;
}

static int nc_docker_cleanup_item(struct json_object *items,const char *kind,const char *id,
                                   const char *name,int64_t bytes,struct json_object *identity)
{
    char revision[65];
    struct json_object *stable = json_object_new_object();
    /* Status contains relative text such as "Exited (0) 5 seconds ago".
     * Keep State and the object metadata, but not that advancing display text. */
    json_object_object_foreach(identity, key, value) {
        if (!strcmp(kind, "container") && !strcmp(key, "Status")) continue;
        json_object_object_add(stable, key, json_object_get(value));
    }
    int rc = nc_docker_cleanup_revision(stable, revision);
    json_object_put(stable);
    if(rc)return -1;
    struct json_object *item=json_object_new_object();
    json_object_object_add(item,"kind",json_object_new_string(kind));
    json_object_object_add(item,"id",json_object_new_string(id));
    json_object_object_add(item,"name",json_object_new_string(name));
    json_object_object_add(item,"revision",json_object_new_string(revision));
    json_object_object_add(item,"estimated_bytes",bytes>=0?json_object_new_int64(bytes):NULL);
    json_object_object_add(item,"selected",json_object_new_boolean(0));
    json_object_object_add(item,"references",json_object_new_int(0));
    json_object_array_add(items,item);return 0;
}

static struct json_object *nc_docker_cleanup_preview(void)
{
    struct json_object *out=json_object_new_object(),*items=json_object_new_array();
    struct json_object *containers=nc_docker_cleanup_get("/containers/json?all=1&size=1");
    struct json_object *images=nc_docker_cleanup_get("/images/json?all=0&filters=%7B%22dangling%22%3A%5B%22true%22%5D%7D");
    struct json_object *networks=nc_docker_cleanup_get("/networks");
    struct json_object *volumes=nc_docker_cleanup_get("/volumes?filters=%7B%22dangling%22%3A%5B%22true%22%5D%7D");
    int failed=!containers||!images||!networks||!volumes;
    if(!failed&&(!json_object_is_type(containers,json_type_array)||!json_object_is_type(images,json_type_array)||
                !json_object_is_type(networks,json_type_array)||!json_object_is_type(volumes,json_type_object)))failed=1;
    if(failed)goto done;
    for(size_t i=0;i<json_object_array_length(containers);i++) {
        struct json_object *row=json_object_array_get_idx(containers,i);
        const char *state=nc_json_str_def(row,"State","");
        if(strcmp(state,"exited")&&strcmp(state,"created")&&strcmp(state,"dead"))continue;
        struct json_object *names=nc_docker_member(row,"Names");
        const char *name=names&&json_object_array_length(names)?json_object_get_string(json_object_array_get_idx(names,0)):"";
        if(nc_docker_cleanup_item(items,"container",nc_json_str_def(row,"Id",""),name,
            nc_docker_member(row,"SizeRw")?json_object_get_int64(nc_docker_member(row,"SizeRw")):-1,row))failed=1;
    }
    for(size_t i=0;i<json_object_array_length(images);i++) {
        struct json_object *row=json_object_array_get_idx(images,i);const char *id=nc_json_str_def(row,"Id","");int used=0;
        for(size_t j=0;j<json_object_array_length(containers);j++)
            if(!strcmp(id,nc_json_str_def(json_object_array_get_idx(containers,j),"ImageID","")))used=1;
        if(!used&&nc_docker_cleanup_item(items,"image",id,id,json_object_get_int64(nc_docker_member(row,"Size")),row))failed=1;
    }
    for(size_t i=0;i<json_object_array_length(networks);i++) {
        struct json_object *row=json_object_array_get_idx(networks,i);const char *name=nc_json_str_def(row,"Name","");
        const char *id=nc_json_str_def(row,"Id","");int used=0;
        if(!strcmp(name,"bridge")||!strcmp(name,"host")||!strcmp(name,"none")||strcmp(nc_json_str_def(row,"Scope",""),"local"))continue;
        for(size_t j=0;j<json_object_array_length(containers);j++) {
            struct json_object *nets=nc_docker_member(nc_docker_member(json_object_array_get_idx(containers,j),"NetworkSettings"),"Networks");
            if(nets){json_object_object_foreach(nets,k,v){(void)k;if(!strcmp(id,nc_json_str_def(v,"NetworkID","")))used=1;}}
        }
        if(!used&&nc_docker_cleanup_item(items,"network",id,name,0,row))failed=1;
    }
    struct json_object *rows=nc_docker_member(volumes,"Volumes");
    for(size_t i=0;rows&&i<json_object_array_length(rows);i++) {
        struct json_object *row=json_object_array_get_idx(rows,i);const char *name=nc_json_str_def(row,"Name","");
        if(nc_docker_cleanup_item(items,"volume",name,name,-1,row))failed=1;
    }
done:
    if(containers)json_object_put(containers);
    if(images)json_object_put(images);
    if(networks)json_object_put(networks);
    if(volumes)json_object_put(volumes);
    if(failed){json_object_put(items);nc_docker_invalid(out,"cleanup_preview_unavailable");return out;}
    json_object_object_add(out,"ok",json_object_new_boolean(1));json_object_object_add(out,"items",items);
    json_object_object_add(out,"ts",json_object_new_int64(nc_now_s()));
    json_object_object_add(out,"estimate_note",json_object_new_string("shared_image_layers_not_additive;volume_size_unknown"));
    return out;
}

static struct json_object *nc_docker_cleanup_find(struct json_object *items,struct json_object *wanted)
{
    for(size_t i=0;items&&i<json_object_array_length(items);i++) {
        struct json_object *item=json_object_array_get_idx(items,i);
        if(!strcmp(nc_json_str_def(item,"kind",""),nc_json_str_def(wanted,"kind",""))&&
           !strcmp(nc_json_str_def(item,"id",""),nc_json_str_def(wanted,"id",""))&&
           !strcmp(nc_json_str_def(item,"revision",""),nc_json_str_def(wanted,"revision","")))return item;
    }
    return NULL;
}

static int nc_docker_cleanup_validate(struct json_object *cfg,struct json_object *out)
{
    struct json_object *selected=nc_docker_member(cfg,"items");
    if(!selected||!json_object_is_type(selected,json_type_array)||!json_object_array_length(selected)||json_object_array_length(selected)>200)
        return nc_docker_invalid(out,"cleanup_selection_required");
    struct json_object *preview=nc_docker_cleanup_preview();int rc=0;
    if(!nc_json_bool_def(preview,"ok",0)){json_object_put(preview);return nc_docker_invalid(out,"cleanup_preview_unavailable");}
    for(size_t i=0;i<json_object_array_length(selected);i++) {
        struct json_object *item=json_object_array_get_idx(selected,i);
        if(!nc_docker_cleanup_find(nc_docker_member(preview,"items"),item)){rc=nc_docker_invalid(out,"cleanup_conflict");break;}
        for(size_t j=0;j<i;j++) {
            struct json_object *prior=json_object_array_get_idx(selected,j);
            if(!strcmp(nc_json_str_def(prior,"id",""),nc_json_str_def(item,"id",""))&&
               !strcmp(nc_json_str_def(prior,"kind",""),nc_json_str_def(item,"kind","")))rc=nc_docker_invalid(out,"duplicate_cleanup_item");
        }
    }
    json_object_put(preview);return rc;
}

static int nc_docker_cleanup_execute(struct json_object *cfg,struct json_object *out)
{
    if(nc_docker_cleanup_validate(cfg,out))return 125;
    struct json_object *selected=nc_docker_member(cfg,"items"),*results=json_object_new_array();int failed=0;
    for(size_t i=0;i<json_object_array_length(selected);i++) {
        struct json_object *item=json_object_array_get_idx(selected,i),*result=json_object_new_object();
        const char *kind=nc_json_str_def(item,"kind",""),*id=nc_json_str_def(item,"id","");
        nc_docker_copy(result,"kind",item,"kind");nc_docker_copy(result,"id",item,"id");
        struct json_object *current=nc_docker_cleanup_preview();
        int matches=nc_json_bool_def(current,"ok",0)&&nc_docker_cleanup_find(nc_docker_member(current,"items"),item);
        json_object_put(current);long status=0;
        if(matches) {
            const char *resource=!strcmp(kind,"container")?"containers":!strcmp(kind,"image")?"images":!strcmp(kind,"network")?"networks":"volumes";
            char path[256];snprintf(path,sizeof(path),"/%s/%s",resource,id);
            struct json_object *response=nc_docker_engine_request("DELETE",path,NULL,&status);
            if(response)json_object_put(response);
        }
        int ok=status==204||status==200;
        json_object_object_add(result,"ok",json_object_new_boolean(ok));
        json_object_object_add(result,"http_status",json_object_new_int((int)status));
        if(!ok){json_object_object_add(result,"error",json_object_new_string(matches?"docker_remove_failed":"cleanup_conflict"));failed=1;}
        json_object_object_add(result,"reclaimed_bytes",!strcmp(kind,"network")&&ok?json_object_new_int(0):NULL);
        json_object_array_add(results,result);
    }
    json_object_object_add(out,"items",results);json_object_object_add(out,"ok",json_object_new_boolean(!failed));
    json_object_object_add(out,"reclaimed_bytes",NULL);
    json_object_object_add(out,"reclaimed_bytes_reason",json_object_new_string("per_object_delete_does_not_report_reclaimed_bytes"));
    if(failed)nc_docker_invalid(out,"cleanup_partial_failure");
    return failed?1:0;
}
