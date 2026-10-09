/* Docker workbench reads. Included by 033_nc_container.c; no shell payloads. */
static struct json_object *nc_docker_member(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (o) json_object_object_get_ex(o, key, &v);
    return v;
}

static void nc_docker_copy(struct json_object *to, const char *key,
                            struct json_object *from, const char *source)
{
    struct json_object *v = nc_docker_member(from, source);
    json_object_object_add(to, key, v ? json_object_get(v) : NULL);
}

static struct json_object *nc_docker_read_json(const char *const argv[],
                                               int lines, struct json_object *error)
{
    struct nc_exec_result result = {0};
    struct json_object *data = NULL;
    int rc = nc_exec_argv_capture(argv, 12, NC_CONTAINER_OUTPUT_MAX, &result);
    if (rc == 0 && !result.truncated) {
        if (lines) {
            char *save = NULL;
            data = json_object_new_array();
            for (char *line = strtok_r(result.output, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                struct json_object *row = json_tokener_parse(line);
                if (!row || !json_object_is_type(row, json_type_object)) {
                    if (row) json_object_put(row);
                    json_object_put(data); data = NULL; break;
                }
                json_object_array_add(data, row);
            }
        } else data = json_tokener_parse(result.output);
    }
    if (!data && error) {
        json_object_object_add(error, "error", json_object_new_string(
            result.truncated ? "read_limit_exceeded" : rc ? "docker_read_failed" : "invalid_docker_response"));
        json_object_object_add(error, "rc", json_object_new_int(rc));
        json_object_object_add(error, "retryable", json_object_new_boolean(rc != 0));
        /* Inspect errors can include user-controlled fields: don't echo raw JSON. */
    }
    nc_exec_result_free(&result);
    return data;
}

static int nc_docker_service_check(const char *action)
{
    const char *const argv[] = {"/etc/init.d/dockerd", action, NULL};
    struct nc_exec_result result = {0};
    int rc = nc_exec_argv_capture(argv, 3, 1024, &result);
    nc_exec_result_free(&result);
    return rc;
}

static struct json_object *nc_docker_workbench_get(void)
{
    struct json_object *d = json_object_new_object(), *cap = json_object_new_object();
    struct json_object *reasons = json_object_new_object(), *errors = json_object_new_object();
    struct json_object *runtime = json_object_new_object(), *service = json_object_new_object();
    struct json_object *info = NULL, *err = json_object_new_object();
    int installed = nc_cmd_exists("docker"), running = installed ? nc_docker_service_check("running") : 1;
    const char *const info_argv[] = {"docker", "info", "--format", "{{json .}}", NULL};
    if (installed) info = nc_docker_read_json(info_argv, 0, err);
    if(info && (!json_object_is_type(info,json_type_object) || !nc_json_str_def(info,"ServerVersion","")[0])) {
        json_object_put(info);info=NULL;
        json_object_object_add(err,"error",json_object_new_string("invalid_docker_response"));
    }
    const char *state = !installed ? "not_installed" : info ? "ready" : running == 1 ? "stopped" : "unreachable";
    json_object_object_add(runtime, "state", json_object_new_string(state));
    json_object_object_add(runtime, "installed", json_object_new_boolean(installed));
    json_object_object_add(runtime, "reachable", json_object_new_boolean(info != NULL));
    json_object_object_add(runtime, "daemon_running", running == 0 || running == 1 ? json_object_new_boolean(running == 0) : NULL);
    if (installed && !info) json_object_object_add(errors, "info", json_object_get(err));
    json_object_put(err);
    json_object_object_add(d, "runtime", runtime);
    json_object_object_add(d, "available", json_object_new_boolean(installed));
    json_object_object_add(d, "contract_version", json_object_new_string("container-service.v1"));
    json_object_object_add(d, "workbench_version", json_object_new_int(1));
    json_object_object_add(service, "running", json_object_new_boolean(running == 0));
    json_object_object_add(service, "enabled", json_object_new_boolean(installed && nc_docker_service_check("enabled") == 0));
    json_object_object_add(d, "service", service);
    const char *reads[] = {"read", "image_read", "network_read", "volume_read", "config_read", "service_read", "async_tasks", NULL};
    const char *actions[] = {"actions", "container_start", "container_stop", "container_restart", "container_pause", "container_unpause", "container_rename", "container_restart_policy", "container_logs", "container_stats", "container_inspect", "container_clone", "container_recreate", "container_create", "container_remove", "create_ports", "create_mounts", "create_env", "create_resources", "start_after_create", "image_pull", "image_remove", "image_inspect", "network_create", "network_remove", "network_inspect", "volume_create", "volume_remove", "volume_inspect", NULL};
    for (int i = 0; reads[i]; i++) json_object_object_add(cap, reads[i], json_object_new_boolean(1));
    for (int i = 0; actions[i]; i++) {
        json_object_object_add(cap, actions[i], json_object_new_boolean(info != NULL));
        if (!info) json_object_object_add(reasons, actions[i], json_object_new_string(state));
    }
    json_object_object_add(cap, "stats_aggregate", json_object_new_boolean(info != NULL));
    json_object_object_add(cap, "service_action", json_object_new_boolean(installed));
    json_object_object_add(cap,"storage_preview",json_object_new_boolean(info&&nc_cmd_exists("rsync")));
    if(!info||!nc_cmd_exists("rsync"))json_object_object_add(reasons,"storage_preview",json_object_new_string(info?"rsync_unavailable":state));
    json_object_object_add(cap, "registry_search", json_object_new_boolean(installed));
    json_object_object_add(cap, "image_load", json_object_new_boolean(info != NULL));
    json_object_object_add(cap,"cleanup_preview",json_object_new_boolean(info!=NULL));
    json_object_object_add(cap,"cleanup_execute",json_object_new_boolean(info!=NULL));
    int compose=installed && nc_docker_compose_available();
    json_object_object_add(cap, "compose", json_object_new_boolean(compose));
    if(!compose)json_object_object_add(reasons,"compose",json_object_new_string("compose_not_installed"));
    int build=compose&&nc_docker_compose_build_available();
    json_object_object_add(cap,"compose_build",json_object_new_boolean(build));
    if(!build)json_object_object_add(reasons,"compose_build",json_object_new_string("compose_buildx_unavailable"));
    int network_ipam = info && nc_docker_network_ipam_available();
    json_object_object_add(cap, "network_ipam", json_object_new_boolean(network_ipam));
    json_object_object_add(cap,"network_recreate",json_object_new_boolean(network_ipam));
    const char *network_drivers[]={"macvlan","ipvlan",NULL};
    for(int i=0;network_drivers[i];i++){
        char key[40];snprintf(key,sizeof(key),"network_%s",network_drivers[i]);
        int enabled=network_ipam&&nc_docker_network_driver_available(info,network_drivers[i]);
        json_object_object_add(cap,key,json_object_new_boolean(enabled));
        if(!enabled)json_object_object_add(reasons,key,json_object_new_string(info?"network_driver_or_routes_unavailable":state));
    }
    if (!network_ipam) json_object_object_add(reasons, "network_ipam", json_object_new_string(info ? "host_route_read_failed" : state));
    const char *pending[][2] = {
        {"terminal", "use_terminal_capabilities_endpoint"},
        {"storage_migration", "target_preflight_required"}, {"image_prune", "image_prune_preview_pending"},
        {"network_prune", "network_prune_preview_pending"}, {"volume_prune", "volume_prune_preview_pending"},
        {"privileged", "privileged_container_unsupported"}, {NULL, NULL}};
    for (int i = 0; pending[i][0]; i++) {
        json_object_object_add(cap, pending[i][0], json_object_new_boolean(0));
        json_object_object_add(reasons, pending[i][0], json_object_new_string(pending[i][1]));
    }
    json_object_object_add(d, "capabilities", cap);
    json_object_object_add(d, "capability_reasons", reasons);
    /* Interactive sessions are provided by the separately supervised runtime. */
    json_object_object_add(d, "terminal_capabilities_endpoint", json_object_new_string("/api/v1/container_service/docker/terminal/capabilities"));
    if (info) {
        struct json_object *summary = json_object_new_object(), *counts = json_object_new_object();
        const char *names[][2] = {{"version","ServerVersion"},{"storage_driver","Driver"},{"data_root","DockerRootDir"},{"os_type","OSType"},{"architecture","Architecture"},{NULL,NULL}};
        for (int i=0;names[i][0];i++) nc_docker_copy(summary,names[i][0],info,names[i][1]);
        const char *cnt[][2] = {{"containers","Containers"},{"running","ContainersRunning"},{"paused","ContainersPaused"},{"stopped","ContainersStopped"},{"images","Images"},{NULL,NULL}};
        for (int i=0;cnt[i][0];i++) nc_docker_copy(counts,cnt[i][0],info,cnt[i][1]);
        json_object_object_add(d,"info",summary); json_object_object_add(d,"counts",counts);
        json_object_put(info);
    }
    const char *commands[][7] = {
        {"docker","ps","-a","--no-trunc","--format","{{json .}}",NULL},
        {"docker","image","ls","--no-trunc","--format","{{json .}}",NULL},
        {"docker","network","ls","--no-trunc","--format","{{json .}}",NULL},
        {"docker","volume","ls","--format","{{json .}}",NULL,NULL},
        {"docker","system","df","--format","{{json .}}",NULL,NULL}};
    const char *keys[] = {"containers","images","networks","volumes","disk_usage"};
    const char *maps[][8][2] = {
        {{"id","ID"},{"name","Names"},{"image","Image"},{"status","Status"},{"ports","Ports"},{"created","CreatedAt"},{"state","State"},{NULL,NULL}},
        {{"id","ID"},{"repository","Repository"},{"tag","Tag"},{"size","Size"},{"created","CreatedAt"},{NULL,NULL}},
        {{"id","ID"},{"name","Name"},{"driver","Driver"},{"scope","Scope"},{NULL,NULL}},
        {{"name","Name"},{"driver","Driver"},{"mountpoint","Mountpoint"},{NULL,NULL}},
        {{"type","Type"},{"total","TotalCount"},{"active","Active"},{"size","Size"},{"reclaimable","Reclaimable"},{NULL,NULL}}};
    for (int k=0;k<5;k++) {
        struct json_object *rows = NULL, *list = json_object_new_array();
        err = json_object_new_object();
        if (!strcmp(state,"ready")) rows = nc_docker_read_json(commands[k],1,err);
        if (rows) {
            for (size_t j=0;j<json_object_array_length(rows);j++) {
                struct json_object *o=json_object_new_object(), *row=json_object_array_get_idx(rows,j);
                for (int m=0;maps[k][m][0];m++) nc_docker_copy(o,maps[k][m][0],row,maps[k][m][1]);
                json_object_array_add(list,o);
            }
            json_object_put(rows);
        } else if (!strcmp(state,"ready")) json_object_object_add(errors,keys[k],json_object_get(err));
        json_object_put(err); json_object_object_add(d,keys[k],list);
    }
    if (!strcmp(state,"ready") && json_object_object_length(errors))
        json_object_object_add(runtime,"state",json_object_new_string("error"));
    json_object_object_add(d,"read_errors",errors);
    struct json_object *config_response=jmx_docker_config_get();
    nc_docker_copy(d,"uci_config",nc_docker_member(config_response,"data"),"config");
    struct json_object *settings=nc_docker_member(config_response,"data");
    int config_write=nc_json_bool_def(settings,"config_write",0);
    json_object_object_add(cap,"config_write",json_object_new_boolean(config_write));
    json_object_object_add(cap,"config_apply",json_object_new_boolean(config_write));
    if(!config_write)json_object_object_add(reasons,"config_write",json_object_new_string(nc_json_str_def(settings,"reason","docker_settings_unavailable")));
    json_object_put(config_response);
    json_object_object_add(d,"source",json_object_new_string("docker-cli"));
    json_object_object_add(d,"ts",json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS,d);
}
