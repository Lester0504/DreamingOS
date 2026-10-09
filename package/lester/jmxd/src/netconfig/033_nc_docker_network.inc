/* Docker network IPAM. Preview and create share live parent/conflict checks. */
static int nc_docker_network_driver_available(struct json_object *info, const char *driver)
{
    struct json_object *drivers=nc_docker_member(nc_docker_member(info,"Plugins"),"Network");
    for(size_t i=0;drivers&&i<json_object_array_length(drivers);i++)
        if(!strcmp(json_object_get_string(json_object_array_get_idx(drivers,i)),driver))return 1;
    return 0;
}

static int nc_docker_network_parent_allowed(struct json_object *link)
{
    const char *name=nc_json_str_def(link,"ifname",""),*kind=nc_json_str_def(nc_docker_member(link,"linkinfo"),"info_kind","");
    if(!*name||strlen(name)>15||strcmp(nc_json_str_def(link,"link_type",""),"ether")||
       !strcmp(kind,"veth")||!strcmp(kind,"macvlan")||!strcmp(kind,"ipvlan")||!strcmp(kind,"vxlan"))return 0;
    for(const char *p=name;*p;p++)if(!isalnum((unsigned char)*p)&&*p!='_'&&*p!='-'&&*p!='.')return 0;
    return 1;
}

static struct json_object *nc_docker_network_options(void)
{
    const char *const argv[]={"ip","-j","-d","address","show",NULL};
    struct json_object *links=nc_docker_read_json(argv,0,NULL),*out=json_object_new_object(),*parents=json_object_new_array(),*drivers=json_object_new_array();
    long status=0;struct json_object *info=nc_docker_engine_request("GET","/info",NULL,&status);
    if(!json_object_is_type(links,json_type_array)||status!=200){nc_docker_invalid(out,"network_options_unavailable");goto done;}
    const char *names[]={"bridge","macvlan","ipvlan",NULL};
    for(int i=0;names[i];i++)if(nc_docker_network_driver_available(info,names[i]))json_object_array_add(drivers,json_object_new_string(names[i]));
    for(size_t i=0;i<json_object_array_length(links);i++){
        struct json_object *link=json_object_array_get_idx(links,i);
        if(!nc_docker_network_parent_allowed(link))continue;
        struct json_object *parent=json_object_new_object();
        nc_docker_copy(parent,"name",link,"ifname");nc_docker_copy(parent,"state",link,"operstate");
        nc_docker_copy(parent,"addresses",link,"addr_info");json_object_array_add(parents,parent);
    }
    json_object_object_add(out,"ok",json_object_new_boolean(1));
    json_object_object_add(out,"parents",json_object_get(parents));json_object_object_add(out,"drivers",json_object_get(drivers));
done:
    if(links)json_object_put(links);
    if(info)json_object_put(info);
    json_object_put(parents);json_object_put(drivers);return out;
}

static int nc_docker_network_ipam_available(void)
{
    const char *const argv[] = {"ip", "-j", "-4", "route", "show", "table", "all", NULL};
    struct json_object *routes = nc_docker_read_json(argv, 0, NULL);
    int available = json_object_is_type(routes, json_type_array);
    if (routes) json_object_put(routes);
    return available;
}

static int nc_docker_ipv4_cidr(const char *text, uint32_t *first, uint32_t *last)
{
    char address[INET_ADDRSTRLEN], *end = NULL;
    const char *slash = text ? strchr(text, '/') : NULL;
    struct in_addr ip;
    if (!slash || slash == text || (size_t)(slash - text) >= sizeof(address)) return -1;
    memcpy(address, text, (size_t)(slash - text)); address[slash - text] = 0;
    if (inet_pton(AF_INET, address, &ip) != 1 || !isdigit((unsigned char)slash[1])) return -1;
    long prefix = strtol(slash + 1, &end, 10);
    if (*end || prefix < 0 || prefix > 32) return -1;
    uint32_t mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
    *first = ntohl(ip.s_addr) & mask; *last = *first | ~mask;
    return ntohl(ip.s_addr) == *first ? 0 : -1;
}

static void nc_docker_network_conflict(struct json_object *items, const char *source,
                                        const char *subnet, const char *name)
{
    struct json_object *item = json_object_new_object();
    json_object_object_add(item, "source", json_object_new_string(source));
    json_object_object_add(item, "subnet", json_object_new_string(subnet));
    json_object_object_add(item, "name", json_object_new_string(name));
    json_object_array_add(items, item);
}

static struct json_object *nc_docker_network_plan_for(struct json_object *cfg, struct json_object *original)
{
    struct json_object *out = json_object_new_object(), *ipam = nc_docker_member(cfg, "ipam");
    struct json_object *networks = NULL, *routes = NULL, *options=NULL, *parent_link=NULL, *conflicts = json_object_new_array();
    const char *const keys[] = {"name", "driver", "ipam", "internal", "parent", "acknowledge_dhcp", "confirm", "id", "action", "operation", NULL};
    const char *const ipam_keys[] = {"subnet", "gateway", "ip_range", NULL};
    const char *name = nc_json_str_def(cfg, "name", ""), *driver = nc_json_str_def(cfg, "driver", "bridge");
    const char *subnet = nc_json_str_def(ipam, "subnet", ""), *gateway = nc_json_str_def(ipam, "gateway", "");
    const char *range = nc_json_str_def(ipam, "ip_range", "");
    const char *parent=nc_json_str_def(cfg,"parent","");int advanced=!strcmp(driver,"macvlan")||!strcmp(driver,"ipvlan");
    uint32_t first = 0, last = 0, range_first = 0, range_last = 0;
    struct in_addr gateway_address;
    struct json_object *internal = nc_docker_member(cfg, "internal");
#define NETWORK_BAD(code, field, reason) do { nc_docker_create_error(out, code, field, reason); goto done; } while (0)
    if (!nc_docker_keys(cfg, keys)) NETWORK_BAD("invalid_network_request", "network", "unknown_field_or_not_object");
    if (!nc_docker_string(nc_docker_member(cfg, "name"), 128) || !nc_docker_name_valid(name))
        NETWORK_BAD("invalid_network_request", "name", "invalid_name");
    if (json_object_object_get_ex(cfg, "driver", &internal) && !nc_docker_string(internal, 32))
        NETWORK_BAD("invalid_network_request", "driver", "string_required");
    if (strcmp(driver, "bridge")&&!advanced) NETWORK_BAD("capability_disabled", "driver", "unsupported_network_driver");
    if(!advanced&&(nc_docker_member(cfg,"parent")||nc_docker_member(cfg,"acknowledge_dhcp")))
        NETWORK_BAD("invalid_network_request","parent","parent_only_for_macvlan_ipvlan");
    if (json_object_object_get_ex(cfg, "internal", &internal) && !json_object_is_type(internal, json_type_boolean))
        NETWORK_BAD("invalid_network_request", "internal", "boolean_required");
    if (json_object_object_get_ex(cfg, "acknowledge_dhcp", &internal) && !json_object_is_type(internal, json_type_boolean))
        NETWORK_BAD("invalid_network_request", "acknowledge_dhcp", "boolean_required");
    if (json_object_object_get_ex(cfg, "ipam", &ipam)) {
        if (!nc_docker_keys(ipam, ipam_keys)) NETWORK_BAD("invalid_network_request", "ipam", "unknown_field_or_not_object");
        for (int i = 0; ipam_keys[i]; i++) {
            struct json_object *v = NULL;
            if (json_object_object_get_ex(ipam, ipam_keys[i], &v) && !nc_docker_string(v, 32))
                NETWORK_BAD("invalid_network_request", ipam_keys[i], "ipv4_string_required");
        }
        if (nc_docker_ipv4_cidr(subnet, &first, &last) || first == 0 || last - first < 3 ||
            (first >> 24) == 127 || last >= 0xe0000000U)
            NETWORK_BAD("invalid_network_request", "ipam.subnet", "canonical_ipv4_subnet_required_prefix_1_to_30");
        if (*gateway && (inet_pton(AF_INET, gateway, &gateway_address) != 1 ||
            ntohl(gateway_address.s_addr) <= first || ntohl(gateway_address.s_addr) >= last))
            NETWORK_BAD("invalid_network_request", "ipam.gateway", "gateway_must_be_usable_address_in_subnet");
        if (*range && (nc_docker_ipv4_cidr(range, &range_first, &range_last) || range_first < first || range_last > last))
            NETWORK_BAD("invalid_network_request", "ipam.ip_range", "canonical_range_must_be_inside_subnet");
    }
    if(advanced){
        if(!ipam||!*gateway||!*range)NETWORK_BAD("invalid_network_request","ipam","parent_network_requires_subnet_gateway_and_range");
        if(nc_json_bool_def(cfg,"internal",0))NETWORK_BAD("invalid_network_request","internal","parent_network_internal_unsupported");
        options=nc_docker_network_options();
        if(!nc_json_bool_def(options,"ok",0))NETWORK_BAD("network_validation_unavailable","parent","network_options_unavailable");
        int supported=0;struct json_object *drivers=nc_docker_member(options,"drivers"),*parents=nc_docker_member(options,"parents");
        for(size_t i=0;i<json_object_array_length(drivers);i++)if(!strcmp(driver,json_object_get_string(json_object_array_get_idx(drivers,i))))supported=1;
        if(!supported)NETWORK_BAD("capability_disabled","driver","network_driver_unavailable");
        for(size_t i=0;i<json_object_array_length(parents);i++){struct json_object *p=json_object_array_get_idx(parents,i);if(!strcmp(parent,nc_json_str_def(p,"name","")))parent_link=p;}
        if(!parent_link)NETWORK_BAD("invalid_network_request","parent","existing_ethernet_parent_required");
        struct json_object *addresses=nc_docker_member(parent_link,"addresses");
        for(size_t i=0;addresses&&i<json_object_array_length(addresses);i++){
            struct in_addr address;struct json_object *a=json_object_array_get_idx(addresses,i);
            if(inet_pton(AF_INET,nc_json_str_def(a,"local",""),&address)==1&&ntohl(address.s_addr)>=range_first&&ntohl(address.s_addr)<=range_last)
                NETWORK_BAD("network_conflict","ipam.ip_range","address_pool_contains_parent_address");
        }
    }
    long status = 0;
    networks = nc_docker_engine_request("GET", "/networks", NULL, &status);
    if (status != 200 || !json_object_is_type(networks, json_type_array))
        NETWORK_BAD("network_validation_unavailable", "network", "docker_network_list_failed");
    for (size_t i = 0; i < json_object_array_length(networks); i++) {
        struct json_object *network = json_object_array_get_idx(networks, i);
        if(original&&!strcmp(nc_json_str_def(original,"Id",""),nc_json_str_def(network,"Id","")))continue;
        if (!strcmp(name, nc_json_str_def(network, "Name", "")))
            NETWORK_BAD("network_conflict", "name", "network_name_already_exists");
        struct json_object *pools = nc_docker_member(nc_docker_member(network, "IPAM"), "Config");
        for (size_t j = 0; ipam && pools && j < json_object_array_length(pools); j++) {
            const char *other = nc_json_str_def(json_object_array_get_idx(pools, j), "Subnet", "");
            uint32_t a, b;
            if (!nc_docker_ipv4_cidr(other, &a, &b) && first <= b && a <= last)
                nc_docker_network_conflict(conflicts, "docker_network", other, nc_json_str_def(network, "Name", ""));
        }
    }
    if (ipam) {
        const char *const argv[] = {"ip", "-j", "-4", "route", "show", "table", "all", NULL};
        routes = nc_docker_read_json(argv, 0, NULL);
        if (!json_object_is_type(routes, json_type_array))
            NETWORK_BAD("network_validation_unavailable", "ipam.subnet", "host_route_read_failed");
        for (size_t i = 0; i < json_object_array_length(routes); i++) {
            struct json_object *route = json_object_array_get_idx(routes, i);
            const char *dst = nc_json_str_def(route, "dst", "");
            uint32_t a, b; char address[32];
            if (!*dst || !strcmp(dst, "default") || !strcmp(dst, "0.0.0.0/0")) continue;
            snprintf(address, sizeof(address), "%s%s", dst, strchr(dst, '/') ? "" : "/32");
            int own_parent=advanced&&!strcmp(parent,nc_json_str_def(route,"dev",""))&&
                !*nc_json_str_def(route,"gateway","")&&
                (!strcmp(nc_json_str_def(route,"scope",""),"link")||!strcmp(nc_json_str_def(route,"type",""),"local")||!strcmp(nc_json_str_def(route,"type",""),"broadcast"));
            char bridge[80]="";
            if(original&&!strcmp(nc_json_str_def(original,"Driver",""),"bridge")){
                snprintf(bridge,sizeof(bridge),"br-%.12s",nc_json_str_def(original,"Id",""));
                const char *custom=nc_json_str_def(nc_docker_member(original,"Options"),"com.docker.network.bridge.name","");
                if(*custom)snprintf(bridge,sizeof(bridge),"%s",custom);
            }
            if(*bridge&&!strcmp(bridge,nc_json_str_def(route,"dev","")))continue;
            if (!nc_docker_ipv4_cidr(address, &a, &b) && first <= b && a <= last&&!own_parent)
                nc_docker_network_conflict(conflicts, "host_route", dst, nc_json_str_def(route, "dev", ""));
        }
    }
    if (json_object_array_length(conflicts)) {
        json_object_object_add(out, "conflicts", json_object_get(conflicts));
        NETWORK_BAD("network_conflict", "ipam.subnet", "subnet_overlaps_host_route_or_docker_network");
    }
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "name", json_object_new_string(name));
    json_object_object_add(out, "driver", json_object_new_string(driver));
    json_object_object_add(out, "internal", json_object_new_boolean(nc_json_bool_def(cfg, "internal", 0)));
    json_object_object_add(out, "ipam", ipam ? json_object_get(ipam) : NULL);
    json_object_object_add(out, "automatic_subnet", json_object_new_boolean(!ipam));
    if(advanced){
        json_object_object_add(out,"parent",json_object_new_string(parent));
        json_object_object_add(out,"mode",json_object_new_string(!strcmp(driver,"macvlan")?"bridge":"l2"));
        json_object_object_add(out,"dhcp_check",json_object_new_string("manual_required"));
        json_object_object_add(out,"warning",json_object_new_string("parent_network_dhcp_reservation_and_host_isolation"));
    }
    json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
done:
    json_object_put(conflicts);
    if (networks) json_object_put(networks);
    if (routes) json_object_put(routes);
    if (options) json_object_put(options);
    return out;
#undef NETWORK_BAD
}

static struct json_object *nc_docker_network_plan(struct json_object *cfg)
{
    return nc_docker_network_plan_for(cfg,NULL);
}

int jmx_docker_network_create(struct json_object *cfg, struct json_object *out)
{
    if (!cfg || !out) return -1;
    if (nc_docker_confirmation_required(cfg, out)) return -1;
    struct json_object *plan = nc_docker_network_plan(cfg);
    if (!nc_json_bool_def(plan, "ok", 0)) {
        json_object_object_foreach(plan, key, value) { json_object_object_add(out, key, json_object_get(value)); }
        json_object_put(plan); return -1;
    }
    struct json_object *body = json_object_new_object(), *ipam = nc_docker_member(plan, "ipam");
    if(*nc_json_str_def(plan,"parent","")){
        if(!nc_json_bool_def(cfg,"acknowledge_dhcp",0)){
            nc_docker_create_error(out,"network_acknowledgement_required","acknowledge_dhcp","confirm_reserved_pool_outside_dhcp");
            json_object_put(plan);json_object_put(body);return -1;
        }
        struct json_object *options=json_object_new_object();
        nc_docker_copy(options,"parent",plan,"parent");
        nc_docker_copy(options,!strcmp(nc_json_str_def(plan,"driver",""),"macvlan")?"macvlan_mode":"ipvlan_mode",plan,"mode");
        json_object_object_add(body,"Options",options);
    }
    nc_docker_copy(body, "Name", plan, "name"); nc_docker_copy(body, "Driver", plan, "driver");
    nc_docker_copy(body, "Internal", plan, "internal");
    if (ipam) {
        struct json_object *model = json_object_new_object(), *pools = json_object_new_array(), *pool = json_object_new_object();
        nc_docker_copy(pool, "Subnet", ipam, "subnet");
        if (*nc_json_str_def(ipam, "gateway", "")) nc_docker_copy(pool, "Gateway", ipam, "gateway");
        if (*nc_json_str_def(ipam, "ip_range", "")) nc_docker_copy(pool, "IPRange", ipam, "ip_range");
        json_object_array_add(pools, pool); json_object_object_add(model, "Config", pools);
        json_object_object_add(body, "IPAM", model);
    }
    long status = 0;
    struct json_object *response = nc_docker_engine_request("POST", "/networks/create", body, &status);
    int ok = status == 201 && *nc_json_str_def(response, "Id", "");
    json_object_object_add(out, "ok", json_object_new_boolean(ok));
    json_object_object_add(out, "http_status", json_object_new_int((int)status));
    if (ok) { nc_docker_copy(out, "network_id", response, "Id"); nc_docker_copy(out, "warning", response, "Warning"); }
    else {
        nc_docker_create_error(out, "network_create_failed", "network", status ? "engine_rejected_network" : "engine_result_unknown_check_networks");
        nc_docker_copy(out, "message", response, "message");
    }
    json_object_put(plan); json_object_put(body);
    if (response) json_object_put(response);
    return ok ? 0 : -1;
}
