/* Docker's JSON pull stream supplies byte counts; job.progress remains a stage. */
struct nc_docker_pull {
    sqlite3 *db;
    const char *job;
    struct json_object *result, *transfer, *layers;
    char line[16384];
    size_t used;
    int64_t flushed;
    int failed, complete;
};

static int nc_docker_pull_flush(struct nc_docker_pull *p, int force)
{
    int64_t now=nc_container_monotonic_ms();
    if(!force&&now-p->flushed<500)return 0;
    sqlite3_stmt *st=NULL;
    int ok=sqlite3_prepare_v2(p->db,"UPDATE container_job SET result_json=?1,updated_at=?2 WHERE id=?3 AND state='running'",-1,&st,NULL)==SQLITE_OK;
    if(ok)ok=sqlite3_bind_text(st,1,json_object_to_json_string_ext(p->result,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT)==SQLITE_OK&&
        sqlite3_bind_int64(st,2,nc_now_s())==SQLITE_OK&&sqlite3_bind_text(st,3,p->job,-1,SQLITE_TRANSIENT)==SQLITE_OK&&
        sqlite3_step(st)==SQLITE_DONE&&sqlite3_changes(p->db)==1;
    sqlite3_finalize(st);p->flushed=now;return ok?0:-1;
}

static int nc_docker_pull_line(struct nc_docker_pull *p)
{
    if(!p->used)return 0;
    p->line[p->used]=0;
    struct json_object *event=json_tokener_parse(p->line);p->used=0;
    if(!json_object_is_type(event,json_type_object)){json_object_put(event);return -1;}
    const char *error=nc_json_str_def(event,"error",nc_json_str_def(nc_docker_member(event,"errorDetail"),"message",""));
    const char *status=nc_json_str_def(event,"status",""),*id=nc_json_str_def(event,"id","");
    if(*error){
        char bounded[1024];snprintf(bounded,sizeof(bounded),"%s",error);
        json_object_object_add(p->transfer,"error",json_object_new_string(bounded));p->failed=1;
    }
    if(*status){
        char bounded[256];snprintf(bounded,sizeof(bounded),"%s",status);
        json_object_object_add(p->transfer,"status",json_object_new_string(bounded));
        if(!strncmp(status,"Status: Downloaded newer image for ",35)||!strncmp(status,"Status: Image is up to date for ",32))p->complete=1;
    }
    if(*id&&strlen(id)<=128){
        struct json_object *layer=NULL;
        for(size_t i=0;i<json_object_array_length(p->layers);i++){
            struct json_object *item=json_object_array_get_idx(p->layers,i);
            if(!strcmp(nc_json_str_def(item,"id",""),id)){layer=item;break;}
        }
        if(!layer&&json_object_array_length(p->layers)<256){
            layer=json_object_new_object();json_object_object_add(layer,"id",json_object_new_string(id));
            const char *keys[]={"downloaded_bytes","download_total_bytes","extracted_bytes","extract_total_bytes",NULL};
            for(int i=0;keys[i];i++)json_object_object_add(layer,keys[i],NULL);
            json_object_array_add(p->layers,layer);
        }
        if(!layer)json_object_object_add(p->transfer,"layers_truncated",json_object_new_boolean(1));
        else {
            char bounded[128];snprintf(bounded,sizeof(bounded),"%s",status);
            json_object_object_add(layer,"status",json_object_new_string(bounded));
            const char *current_key=NULL,*total_key=NULL;
            if(!strcmp(status,"Downloading")){current_key="downloaded_bytes";total_key="download_total_bytes";}
            if(!strcmp(status,"Extracting")){current_key="extracted_bytes";total_key="extract_total_bytes";}
            struct json_object *detail=nc_docker_member(event,"progressDetail");
            if(current_key){
                struct json_object *current=nc_docker_member(detail,"current"),*total=nc_docker_member(detail,"total");
                if(json_object_is_type(current,json_type_int)&&json_object_get_int64(current)>=0)json_object_object_add(layer,current_key,json_object_get(current));
                if(json_object_is_type(total,json_type_int)&&json_object_get_int64(total)>0)json_object_object_add(layer,total_key,json_object_get(total));
            }
        }
    }
    json_object_put(event);
    return nc_docker_pull_flush(p,0);
}

static size_t nc_docker_pull_stream(char *data,size_t size,size_t count,void *arg)
{
    struct nc_docker_pull *p=arg;size_t n=size*count;
    for(size_t i=0;i<n;i++){
        if(data[i]=='\n'){if(nc_docker_pull_line(p))return 0;}
        else {if(p->used>=sizeof(p->line)-1)return 0;p->line[p->used++]=data[i];}
    }
    return n;
}

static int nc_docker_pull_execute(sqlite3 *db,const char *job,const char *image,
                                  struct nc_exec_result *output,struct json_object *result)
{
    struct nc_docker_pull p={.db=db,.job=job,.result=result};
    p.transfer=json_object_new_object();p.layers=json_object_new_array();
    json_object_object_add(p.transfer,"phase",json_object_new_string("pulling"));
    json_object_object_add(p.transfer,"layers",p.layers);
    json_object_object_add(result,"transfer",p.transfer);
    CURL *curl=curl_easy_init();long status=0;int rc=125;
    if(!curl)return 125;
    char *encoded=curl_easy_escape(curl,image,0),url[1200];
    if(!encoded){curl_easy_cleanup(curl);return 125;}
    snprintf(url,sizeof(url),"http://localhost/images/create?fromImage=%s",encoded);curl_free(encoded);
    curl_easy_setopt(curl,CURLOPT_URL,url);curl_easy_setopt(curl,CURLOPT_UNIX_SOCKET_PATH,NC_DOCKER_ENGINE_SOCKET);
    curl_easy_setopt(curl,CURLOPT_PROXY,"");curl_easy_setopt(curl,CURLOPT_POST,1L);curl_easy_setopt(curl,CURLOPT_POSTFIELDS,"");
    curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);curl_easy_setopt(curl,CURLOPT_TIMEOUT,1800L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,nc_docker_pull_stream);curl_easy_setopt(curl,CURLOPT_WRITEDATA,&p);
    if(nc_docker_pull_flush(&p,1)){curl_easy_cleanup(curl);return 125;}
    CURLcode transport=curl_easy_perform(curl);
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    if(p.used&&nc_docker_pull_line(&p))p.failed=1;
    if(transport==CURLE_OPERATION_TIMEDOUT)rc=124;
    if(transport==CURLE_OK&&status==200&&!p.failed&&p.complete){
        encoded=curl_easy_escape(curl,image,0);char path[1200];
        if(encoded){
            snprintf(path,sizeof(path),"/images/%s/json",encoded);curl_free(encoded);
            struct json_object *actual=nc_docker_engine_request("GET",path,NULL,&status);
            const char *id=nc_json_str_def(actual,"Id","");
            if(status==200&&*id){rc=0;json_object_object_add(result,"image_id",json_object_new_string(id));}
            json_object_put(actual);
        }
    }
    json_object_object_add(p.transfer,"phase",json_object_new_string(rc?"failed":"complete"));
    if(rc&&!nc_docker_member(p.transfer,"error"))json_object_object_add(p.transfer,"error",json_object_new_string(transport!=CURLE_OK?curl_easy_strerror(transport):status!=200?"docker_engine_rejected_pull":"pull_completion_not_verified"));
    nc_docker_pull_flush(&p,1);
    output->output=strdup(nc_json_str_def(p.transfer,rc?"error":"status",rc?"docker_pull_failed":"image_pulled"));
    curl_easy_cleanup(curl);return rc;
}
