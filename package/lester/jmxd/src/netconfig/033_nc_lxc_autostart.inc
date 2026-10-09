/* Boot-only scheduling uses the same persistent, identity-checked start jobs as
 * the UI. Restarting core during this boot never restarts stopped containers. */
#ifndef NC_LXC_BOOT_MARKER
#define NC_LXC_BOOT_MARKER "/var/run/dreamingwrt-lxc-boot"
#endif

static struct uloop_timeout nc_lxc_boot_timer;
static struct json_object *nc_lxc_boot_items;
static size_t nc_lxc_boot_index;
static char nc_lxc_boot_job[64];
static int nc_lxc_boot_delay;

static int nc_lxc_boot_order(const void *a,const void *b)
{
    struct json_object *first=*(struct json_object *const *)a,*second=*(struct json_object *const *)b;
    int order=nc_json_int_def(first,"start_order",0)-nc_json_int_def(second,"start_order",0);
    return order?order:strcmp(nc_json_str_def(first,"name",""),nc_json_str_def(second,"name",""));
}

static struct json_object *nc_lxc_boot_candidates(void)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct json_object *items=json_object_new_array();
    if(sqlite3_open_v2(NC_LXC_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)!=SQLITE_OK)goto done;
    if(sqlite3_prepare_v2(db,"SELECT name,identity,applied FROM lxc_config_document WHERE state='idle' AND desired=applied",-1,&st,NULL)!=SQLITE_OK)goto done;
    while(sqlite3_step(st)==SQLITE_ROW){
        const char *text=(const char *)sqlite3_column_text(st,2);struct json_object *fields=nc_lxc_document_fields(text);
        if(nc_json_bool_def(fields,"autostart",0)){
            char fingerprint[65];
            if(!nc_lxc_document_hash(text,fingerprint)){
                nc_lxc_string(fields,"name",(const char *)sqlite3_column_text(st,0));
                nc_lxc_string(fields,"identity",(const char *)sqlite3_column_text(st,1));
                nc_lxc_string(fields,"fingerprint",fingerprint);
                json_object_array_add(items,json_object_get(fields));
            }
        }
        json_object_put(fields);
    }
done:
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    json_object_array_sort(items,nc_lxc_boot_order);return items;
}

static int nc_lxc_boot_launch(struct json_object *item,struct json_object *out)
{
    const char *name=nc_json_str_def(item,"name","");
    struct json_object *response=jmx_lxc_config_document_get(name),*d=nc_docker_member(response,"data"),*cfg=json_object_new_object();int rc=-1;
    if(!nc_json_bool_def(d,"ok",0)){nc_lxc_error(out,nc_json_str_def(d,"error","lxc_read_failed"));goto done;}
    if(!nc_json_bool_def(d,"applied",0)||!nc_json_bool_def(nc_docker_member(d,"fields"),"autostart",0)||
       strcmp(nc_json_str_def(item,"fingerprint",""),nc_json_str_def(d,"fingerprint",""))){nc_lxc_error(out,"lxc_config_state_conflict");goto done;}
    if(strcmp(nc_json_str_def(item,"identity",""),nc_json_str_def(d,"identity",""))){nc_lxc_error(out,"container_identity_changed");goto done;}
    char state[24];if(nc_lxc_state(nc_json_str_def(d,"lxcpath",""),name,state,sizeof(state),out))goto done;
    if(!strcmp(state,"RUNNING")){nc_lxc_bool(out,"ok",1);rc=0;goto done;}
    nc_lxc_bool(cfg,"confirm",1);nc_lxc_string(cfg,"identity",nc_json_str_def(item,"identity",""));
    rc=jmx_lxc_container_action(name,"start",cfg,out);
done:
    json_object_put(cfg);json_object_put(response);return rc;
}

void jmx_lxc_autostart_stop(void)
{
    uloop_timeout_cancel(&nc_lxc_boot_timer);
    json_object_put(nc_lxc_boot_items);nc_lxc_boot_items=NULL;
    nc_lxc_boot_index=0;nc_lxc_boot_job[0]=0;
}

static void nc_lxc_boot_tick(struct uloop_timeout *timer)
{
    if(!nc_lxc_boot_items)nc_lxc_boot_items=nc_lxc_boot_candidates();
    if(nc_lxc_boot_job[0]){
        struct json_object *response=jmx_lxc_job_get(nc_lxc_boot_job),*d=nc_docker_member(response,"data");
        const char *state=nc_json_str_def(d,"state","");
        int pending=!strcmp(state,"queued")||!strcmp(state,"running");
        if(!pending&&strcmp(state,"success"))LOG_WARN("LXC boot job %s failed: %s\n",nc_lxc_boot_job,nc_json_str_def(d,"error","lxc_boot_job_unavailable"));
        json_object_put(response);
        if(pending){uloop_timeout_set(timer,1000);return;}
        nc_lxc_boot_job[0]=0;
        if(nc_lxc_boot_delay>0){uloop_timeout_set(timer,nc_lxc_boot_delay*1000);nc_lxc_boot_delay=0;return;}
    }
    if(nc_lxc_boot_index>=json_object_array_length(nc_lxc_boot_items)){jmx_lxc_autostart_stop();return;}
    struct json_object *item=json_object_array_get_idx(nc_lxc_boot_items,nc_lxc_boot_index++),*out=json_object_new_object();
    if(nc_lxc_boot_launch(item,out))LOG_WARN("LXC autostart skipped %s: %s\n",nc_json_str_def(item,"name",""),nc_json_str_def(out,"error","lxc_autostart_failed"));
    else snprintf(nc_lxc_boot_job,sizeof(nc_lxc_boot_job),"%s",nc_json_str_def(out,"job_id",""));
    nc_lxc_boot_delay=nc_json_int_def(item,"start_delay",0);
    if(nc_lxc_boot_delay<0||nc_lxc_boot_delay>300)nc_lxc_boot_delay=0;
    json_object_put(out);uloop_timeout_set(timer,1000);
}

void jmx_lxc_autostart_start(void)
{
    if(nc_lxc_boot_items)return;
    int fd=open(NC_LXC_BOOT_MARKER,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){if(errno!=EEXIST)LOG_WARN("LXC boot marker unavailable\n");return;}
    close(fd);nc_lxc_boot_timer.cb=nc_lxc_boot_tick;
    uloop_timeout_set(&nc_lxc_boot_timer,1000);
}
