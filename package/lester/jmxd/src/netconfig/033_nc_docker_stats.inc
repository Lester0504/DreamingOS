/* Numeric samples from the local Engine API; CLI's rounded sizes aren't bytes. */
#include <curl/curl.h>
struct nc_docker_http_buffer { char *data; size_t len; };
static size_t nc_docker_http_write(void *ptr,size_t size,size_t count,void *ctx)
{
    struct nc_docker_http_buffer *b=ctx;
    if(size && count>SIZE_MAX/size)return 0;
    size_t n=size*count;
    if(n>1024*1024-b->len)return 0;
    char *next=realloc(b->data,b->len+n+1);if(!next)return 0;
    b->data=next;memcpy(next+b->len,ptr,n);b->len+=n;next[b->len]=0;return n;
}
static struct json_object *nc_docker_engine_get(const char *path)
{
    CURL *curl=curl_easy_init();struct nc_docker_http_buffer b={0};long status=0;
    char url[512];struct json_object *data=NULL;
    if(!curl)return NULL;
    snprintf(url,sizeof(url),"http://localhost%s",path);
    curl_easy_setopt(curl,CURLOPT_URL,url);
    curl_easy_setopt(curl,CURLOPT_UNIX_SOCKET_PATH,"/var/run/docker.sock");
    curl_easy_setopt(curl,CURLOPT_PROXY,"");
    curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,5L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,nc_docker_http_write);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,&b);
    CURLcode rc=curl_easy_perform(curl);
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    if(rc==CURLE_OK&&status==200&&b.data)data=json_tokener_parse(b.data);
    free(b.data);curl_easy_cleanup(curl);return data;
}
static pthread_mutex_t nc_docker_stats_lock=PTHREAD_MUTEX_INITIALIZER;
static struct json_object *nc_docker_previous_stats;
static struct json_object *nc_docker_stats_cache;
static int64_t nc_docker_stats_cache_time;

static struct json_object *nc_docker_stats_sample(struct json_object *raw)
{
    const char *id=nc_json_str_def(raw,"id","");
    struct json_object *sample=json_object_new_object(),*prev=nc_docker_member(nc_docker_previous_stats,id);
    struct json_object *cpu=nc_docker_member(raw,"cpu_stats"),*oldcpu=nc_docker_member(prev,"cpu_stats");
    struct json_object *usage=nc_docker_member(cpu,"cpu_usage"),*oldusage=nc_docker_member(oldcpu,"cpu_usage");
    int64_t current=json_object_get_int64(nc_docker_member(usage,"total_usage"));
    int64_t old=json_object_get_int64(nc_docker_member(oldusage,"total_usage"));
    int64_t sys=json_object_get_int64(nc_docker_member(cpu,"system_cpu_usage"))-json_object_get_int64(nc_docker_member(oldcpu,"system_cpu_usage"));
    int cores=nc_json_int_def(cpu,"online_cpus",0);
    nc_docker_copy(sample,"id",raw,"id");nc_docker_copy(sample,"name",raw,"name");
    json_object_object_add(sample,"cpu_percent",prev&&sys>0&&current>=old&&cores>0?json_object_new_double((double)(current-old)/(double)sys*cores*100):NULL);
    struct json_object *memory=nc_docker_member(raw,"memory_stats");
    nc_docker_copy(sample,"memory_usage_bytes",memory,"usage");nc_docker_copy(sample,"memory_limit_bytes",memory,"limit");
    struct json_object *nets=nc_docker_member(raw,"networks");int64_t rx=0,tx=0;
    if(nets) {json_object_object_foreach(nets,key,net){(void)key;rx+=json_object_get_int64(nc_docker_member(net,"rx_bytes"));tx+=json_object_get_int64(nc_docker_member(net,"tx_bytes"));}}
    json_object_object_add(sample,"network_rx_bytes",nets?json_object_new_int64(rx):NULL);
    json_object_object_add(sample,"network_tx_bytes",nets?json_object_new_int64(tx):NULL);
    nc_docker_copy(sample,"sampled_at",raw,"read");
    json_object_object_add(sample,"ts",json_object_new_int64(nc_now_s()));
    json_object_object_add(sample,"cpu_available",json_object_new_boolean(prev&&sys>0&&current>=old&&cores>0));
    json_object_object_add(nc_docker_previous_stats,id,json_object_get(raw));
    return sample;
}
struct json_object *jmx_docker_stats_get(const char *id)
{
    struct json_object *d=json_object_new_object(),*list=NULL,*samples=json_object_new_array();
    int aggregate=!id||!*id,rc=0;
    if(!aggregate&&!nc_docker_resource_id_valid(id)){json_object_put(samples);nc_docker_invalid(d,"invalid_id");return jmx_gen_api_response_data(API_CODE_ERROR,d);}
    pthread_mutex_lock(&nc_docker_stats_lock);
    if(aggregate&&nc_docker_stats_cache&&nc_now_s()-nc_docker_stats_cache_time<5){
        json_object_put(samples);json_object_put(d);d=json_object_get(nc_docker_stats_cache);
        pthread_mutex_unlock(&nc_docker_stats_lock);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
    }
    if(!nc_docker_previous_stats)nc_docker_previous_stats=json_object_new_object();
    if(aggregate)list=nc_docker_engine_get("/containers/json");
    if(aggregate&&(!list||!json_object_is_type(list,json_type_array)||json_object_array_length(list)>128))rc=-1;
    int64_t deadline=nc_container_monotonic_ms()+8000;
    size_t count=aggregate?(list?json_object_array_length(list):0):1;
    for(size_t i=0;!rc&&i<count;i++) {
        if(nc_container_monotonic_ms()>deadline){rc=-1;break;}
        const char *target=aggregate?nc_json_str_def(json_object_array_get_idx(list,i),"Id",""):id;
        char path[256];snprintf(path,sizeof(path),"/containers/%s/stats?stream=false&one-shot=true",target);
        struct json_object *raw=nc_docker_engine_get(path);
        if(!raw){rc=-1;break;}
        json_object_array_add(samples,nc_docker_stats_sample(raw));json_object_put(raw);
    }
    if(list)json_object_put(list);
    json_object_object_add(d,"ok",json_object_new_boolean(!rc));
    json_object_object_add(d,"available",json_object_new_boolean(!rc));
    json_object_object_add(d,"sample_interval_min_ms",json_object_new_int(5000));
    json_object_object_add(d,"ts",json_object_new_int64(nc_now_s()));
    if(rc)json_object_object_add(d,"error",json_object_new_string("stats_unavailable"));
    json_object_object_add(d,"samples",samples);
    if(!aggregate&&json_object_array_length(samples)) {
        struct json_object *sample=json_object_array_get_idx(samples,0);char text[128];
        json_object_object_add(d,"sample",json_object_get(sample));
        struct json_object *cpu=nc_docker_member(sample,"cpu_percent");
        if(cpu)snprintf(text,sizeof(text),"%.2f%%",json_object_get_double(cpu));else snprintf(text,sizeof(text),"等待下次采样");
        json_object_object_add(d,"cpu_percent",json_object_new_string(text));
        snprintf(text,sizeof(text),"%lld B / %lld B",(long long)json_object_get_int64(nc_docker_member(sample,"memory_usage_bytes")),(long long)json_object_get_int64(nc_docker_member(sample,"memory_limit_bytes")));
        json_object_object_add(d,"memory_usage",nc_docker_member(sample,"memory_usage_bytes")?json_object_new_string(text):NULL);
        snprintf(text,sizeof(text),"%lld B / %lld B",(long long)json_object_get_int64(nc_docker_member(sample,"network_rx_bytes")),(long long)json_object_get_int64(nc_docker_member(sample,"network_tx_bytes")));
        json_object_object_add(d,"net_io",nc_docker_member(sample,"network_rx_bytes")?json_object_new_string(text):NULL);
    }
    if(aggregate&&!rc){if(nc_docker_stats_cache)json_object_put(nc_docker_stats_cache);nc_docker_stats_cache=json_object_get(d);nc_docker_stats_cache_time=nc_now_s();}
    /* Bound the per-container history; restarting sampling makes CPU unavailable. */
    if(json_object_object_length(nc_docker_previous_stats)>256){json_object_put(nc_docker_previous_stats);nc_docker_previous_stats=json_object_new_object();}
    pthread_mutex_unlock(&nc_docker_stats_lock);
    return jmx_gen_api_response_data(rc?API_CODE_ERROR:API_CODE_SUCCESS,d);
}
