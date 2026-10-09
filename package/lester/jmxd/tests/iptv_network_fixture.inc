/* Transaction tests use the real validator, snapshot/vault and SQLite, with
 * network rendering/reload replaced. No live network configuration is used. */
static void check_original(void);
static int nc_iptv_prepare(struct json_object *config, const char *operation, struct json_object *prepared)
{
    const char *id = nc_json_str(config, "id", "");
    if (fail_apply) return -1;
    if (!strcmp(operation, "delete")) {
        struct json_object *empty = safeops_network_rows(g_netconfig_db, "iptv", id);
        json_object_object_foreach(empty, key, v) { (void)v; json_object_object_add(empty, key, json_object_new_array()); }
        int rc = safeops_network_restore_rows(g_netconfig_db, "iptv", id, empty);
        json_object_put(empty);
        if (rc) return rc;
    } else if (strcmp(operation, "reconnect")) {
        char *sql = sqlite3_mprintf("INSERT INTO wan(id,name,access_mode,password_ref,device,role,enabled,vlan_enabled,vlan_id,username,mtu,gateway)"
            " VALUES(%Q,%Q,%Q,%Q,%Q,'iptv',%d,%d,%Q,%Q,%d,%Q) ON CONFLICT(id) DO UPDATE SET name=excluded.name,"
            "access_mode=excluded.access_mode,device=excluded.device,enabled=excluded.enabled,vlan_enabled=excluded.vlan_enabled,"
            "vlan_id=excluded.vlan_id,username=excluded.username,mtu=excluded.mtu,gateway=excluded.gateway,"
            "password_ref=CASE WHEN excluded.password_ref='' THEN wan.password_ref ELSE excluded.password_ref END",
            id,nc_json_str(config,"name",""),nc_json_str(config,"access_mode",""),nc_json_str(config,"password",""),
            nc_json_str(config,"device",""),nc_json_bool(config,"enabled",0),nc_json_bool(config,"vlan_enabled",0),
            nc_json_str(config,"vlan_id",""),nc_json_str(config,"username",""),nc_json_int(config,"mtu",1500),nc_json_str(config,"gateway",""));
        int rc = nc_exec(sql); sqlite3_free(sql); if (rc) return rc;
    }
    apply_calls++;
    json_object_object_add(prepared,"network",json_object_new_string("iptv prepared network"));
    json_object_object_add(prepared,"firewall",json_object_new_string("iptv prepared firewall"));
    return 0;
}

static struct json_object *iptv_test_request(const char *operation, const char *key, const char *patch)
{
    struct json_object *req = json_tokener_parse("{\"domain\":\"iptv\",\"id\":\"iptv_ab12\",\"confirm_risk\":true,\"peer_ip\":\"192.0.2.5\"}");
    struct json_object *canonical = nc_tx_get(req);
    assert(nc_json_bool(canonical,"ok",0));
    json_object_object_add(req,"if_revision",json_object_new_string(nc_json_str(canonical,"revision","")));
    json_object_object_add(req,"operation",json_object_new_string(operation));
    json_object_object_add(req,"idempotency_key",json_object_new_string(key));
    if(patch)json_object_object_add(req,"config",json_tokener_parse(patch));
    json_object_put(canonical);return req;
}

static void iptv_test_rollback(sqlite3 *app, int id, int success)
{
    char *sql = sqlite3_mprintf("UPDATE config_apply_tasks SET state='rolling_back' WHERE id=%d",id);
    assert(sqlite3_exec(app,sql,NULL,NULL,NULL)==SQLITE_OK);sqlite3_free(sql);
    struct json_object *req=json_object_new_object();json_object_object_add(req,"task_id",json_object_new_int(id));
    struct json_object *resp=nc_tx_rollback(req);
    if(success&&!nc_json_bool(resp,"ok",0))fprintf(stderr,"rollback: %s\n",json_object_to_json_string(resp));
    assert(nc_json_bool(resp,"ok",0)==success);
    if(!success)assert(!strcmp(nc_json_str(resp,"error",""),"stale_watchdog_digest_mismatch"));
    json_object_put(resp);json_object_put(req);
    sql=sqlite3_mprintf("UPDATE config_apply_tasks SET state='rolled_back' WHERE id=%d",id);
    assert(sqlite3_exec(app,sql,NULL,NULL,NULL)==SQLITE_OK);sqlite3_free(sql);
}

static void iptv_fixture_schema(void)
{
    assert(nc_exec("ALTER TABLE wan ADD device TEXT DEFAULT 'eth0';ALTER TABLE wan ADD role TEXT DEFAULT 'primary';"
        "ALTER TABLE wan ADD enabled INTEGER DEFAULT 1;ALTER TABLE wan ADD vlan_enabled INTEGER DEFAULT 0;"
        "ALTER TABLE wan ADD vlan_id TEXT DEFAULT '';ALTER TABLE wan ADD username TEXT DEFAULT '';"
        "ALTER TABLE wan ADD mtu INTEGER DEFAULT 1500;ALTER TABLE wan ADD gateway TEXT DEFAULT '';"
        "ALTER TABLE wan_address ADD prefix INTEGER DEFAULT 24;ALTER TABLE lan_address ADD prefix INTEGER DEFAULT 24;"
        "ALTER TABLE wan_advanced ADD dhcp_vendor_class TEXT DEFAULT '';"
        "ALTER TABLE wan_advanced ADD iptv_igmp_version INTEGER DEFAULT 0;"
        "ALTER TABLE wan_advanced ADD iptv_multicast_source TEXT DEFAULT 'session';"
        "ALTER TABLE wan_advanced ADD iptv_carrier_mode TEXT DEFAULT 'dhcp';"
        "ALTER TABLE wan_advanced ADD iptv_carrier_address TEXT DEFAULT '';"
        "ALTER TABLE wan_advanced ADD iptv_carrier_prefix INTEGER DEFAULT 24;"
        "ALTER TABLE lan ADD device TEXT DEFAULT 'br-lan';ALTER TABLE lan_port ADD id TEXT;ALTER TABLE lan_port ADD port TEXT;"
        "CREATE TABLE physical_port(name TEXT PRIMARY KEY,label TEXT,kind TEXT,owner_type TEXT,owner_id TEXT);"
        "INSERT INTO physical_port VALUES('eth9','spare','ethernet','','');"
        "CREATE TABLE physical_port_config(ifname TEXT,profile_id TEXT,native_vlan INTEGER,tagged_vlans_json TEXT);"
        "CREATE TABLE physical_port_profile(id TEXT);CREATE TABLE multicast_config(id INTEGER);"
        "CREATE TABLE network_global(id INTEGER);CREATE TABLE iptv_record(kind TEXT,id TEXT,body TEXT);")==0);
}

static void iptv_fixture(sqlite3 *app)
{
    iptv_fixture_schema();
    const char *patch="{\"name\":\"IPTV\",\"device\":\"eth9\",\"access_mode\":\"dhcp\",\"option60\":\"IPTV test\"}";
    struct json_object *req=iptv_test_request("create","create-one",patch),*resp=nc_tx_validate(req,NULL);
    if(!nc_json_bool(resp,"valid",0))fprintf(stderr,"validate: %s\n",json_object_to_json_string(resp));
    assert(nc_json_bool(resp,"valid",0));assert(apply_calls==0);json_object_put(resp);
    const char *new_patches[]={
        "{\"igmp_version\":1}", "{\"igmp_version\":\"2\"}", "{\"multicast_source\":\"carrier\"}",
        "{\"access_mode\":\"pppoe\",\"username\":\"u\",\"password\":\"p\",\"option60\":\"\",\"multicast_source\":\"carrier\",\"carrier_access_mode\":\"static\",\"carrier_address\":\"239.1.1.1\"}",NULL};
    for(int n=0;new_patches[n];n++){
        struct json_object *bad=iptv_test_request("create","invalid-new",patch),*change=json_tokener_parse(new_patches[n]),*target=json_object_object_get(bad,"config");
        json_object_object_foreach(change,key,value){json_object_object_add(target,key,json_object_get(value));}
        struct json_object *check=nc_tx_validate(bad,NULL);assert(!nc_json_bool(check,"valid",1));json_object_put(check);json_object_put(change);json_object_put(bad);
    }
    struct json_object *carrier_req=iptv_test_request("create","valid-carrier","{\"name\":\"IPTV\",\"device\":\"eth9\",\"access_mode\":\"pppoe\",\"username\":\"u\",\"password\":\"p\",\"multicast_source\":\"carrier\",\"carrier_access_mode\":\"dhcp\",\"option60\":\"IPTV\",\"igmp_version\":3}");
    struct json_object *merged=NULL,*carrier_check=nc_tx_validate(carrier_req,&merged);
    if(!nc_json_bool(carrier_check,"valid",0))fprintf(stderr,"carrier validate %s\n",json_object_to_json_string(carrier_check));
    assert(nc_json_bool(carrier_check,"valid",0)&&nc_json_int(merged,"igmp_version",0)==3);json_object_put(merged);json_object_put(carrier_check);
    struct json_object *cp=json_object_object_get(carrier_req,"config");
    json_object_object_add(cp,"carrier_access_mode",json_object_new_string("static"));json_object_object_add(cp,"option60",json_object_new_string(""));
    json_object_object_add(cp,"carrier_address",json_object_new_string("198.18.1.2"));json_object_object_add(cp,"carrier_prefix",json_object_new_int(24));
    carrier_check=nc_tx_validate(carrier_req,NULL);assert(nc_json_bool(carrier_check,"valid",0));json_object_put(carrier_check);
    json_object_object_add(cp,"carrier_address",json_object_new_string("192.0.2.5"));
    carrier_check=nc_tx_validate(carrier_req,NULL);assert(!nc_json_bool(carrier_check,"valid",1)&&strstr(json_object_to_json_string(carrier_check),"subnet_in_use"));json_object_put(carrier_check);
    json_object_put(carrier_req);

    assert(scalar(g_netconfig_db,"SELECT count(*) FROM wan WHERE role='iptv'")==0);
    assert(scalar(app,"SELECT count(*) FROM config_apply_tasks")==0);
    /* Conflicts include other topology resources, not just the target WAN. */
    assert(nc_exec("INSERT INTO lan_port VALUES('lan','port','p1','eth9')")==0);
    resp=nc_tx_validate(req,NULL);assert(nc_json_int(resp,"code",0)==409);json_object_put(resp);
    json_object_put(req);req=iptv_test_request("create","occupied",patch);
    resp=nc_tx_validate(req,NULL);assert(!nc_json_bool(resp,"valid",1));json_object_put(resp);json_object_put(req);
    assert(nc_exec("DELETE FROM lan_port")==0);
    const char *invalid[]={"{\"device\":\"eth9;reboot\",\"name\":\"x\"}","{\"device\":\"eth9\",\"name\":\"x\",\"vlan_enabled\":true,\"vlan_id\":\"100x\"}",
        "{\"device\":\"eth9\",\"name\":\"x\",\"enabled\":1}","{\"device\":\"eth9\",\"name\":\"x\",\"default_route\":true}",
        "{\"device\":\"eth9\",\"name\":\"x\",\"access_mode\":\"pppoe\"}","{\"device\":\"eth9\",\"name\":\"x\",\"access_mode\":\"static\"}"};
    for(size_t n=0;n<sizeof(invalid)/sizeof(invalid[0]);n++){
        req=iptv_test_request("create","bad",invalid[n]);resp=nc_tx_validate(req,NULL);
        assert(!nc_json_bool(resp,"valid",1));json_object_put(resp);json_object_put(req);
    }
    req=iptv_test_request("create","create-one",patch);resp=nc_tx_apply(req);
    if(!nc_json_bool(resp,"ok",0))fprintf(stderr,"apply: %s\n",json_object_to_json_string(resp));
    assert(nc_json_bool(resp,"ok",0));int task=nc_json_int(resp,"task_id",0);json_object_put(resp);
    assert(scalar(g_netconfig_db,"SELECT count(*) FROM wan WHERE id='iptv_ab12'")==1);
    resp=nc_tx_apply(req);assert(nc_json_bool(resp,"idempotent_replay",0));json_object_put(resp);json_object_put(req);
    /* A normal owner projection refresh must not block rollback. */
    assert(nc_exec("UPDATE physical_port SET owner_type='wan',owner_id='iptv_ab12' WHERE name='eth9'")==0);
    iptv_test_rollback(app,task,1);assert(scalar(g_netconfig_db,"SELECT count(*) FROM wan WHERE id='iptv_ab12'")==0);check_original();
    assert(nc_exec("UPDATE physical_port SET owner_type='',owner_id='' WHERE name='eth9'")==0);
    req=iptv_test_request("create","create-two",patch);resp=nc_tx_apply(req);assert(nc_json_bool(resp,"ok",0));json_object_put(resp);json_object_put(req);
    assert(sqlite3_exec(app,"UPDATE config_apply_tasks SET state='confirmed'",NULL,NULL,NULL)==SQLITE_OK);
    assert(nc_exec("INSERT INTO iptv_record VALUES('channels','news','{\"input_id\":\"iptv_ab12\"}')")==0);
    req=iptv_test_request("delete","in-use",NULL);resp=nc_tx_validate(req,NULL);assert(!nc_json_bool(resp,"valid",1));json_object_put(resp);json_object_put(req);
    assert(nc_exec("DELETE FROM iptv_record")==0);
    req=iptv_test_request("delete","delete-one",NULL);resp=nc_tx_apply(req);
    if(!nc_json_bool(resp,"ok",0))fprintf(stderr,"delete: %s\n",json_object_to_json_string(resp));
    assert(nc_json_bool(resp,"ok",0));task=nc_json_int(resp,"task_id",0);json_object_put(resp);json_object_put(req);
    assert(scalar(g_netconfig_db,"SELECT count(*) FROM wan WHERE id='iptv_ab12'")==0);
    iptv_test_rollback(app,task,1);assert(scalar(g_netconfig_db,"SELECT count(*) FROM wan WHERE id='iptv_ab12'")==1);
    req=iptv_test_request("update","update-one","{\"name\":\"changed\"}");resp=nc_tx_apply(req);assert(nc_json_bool(resp,"ok",0));task=nc_json_int(resp,"task_id",0);json_object_put(resp);json_object_put(req);
    assert(nc_exec("UPDATE wan SET name='external edit' WHERE id='wan'")==0);
    iptv_test_rollback(app,task,0);assert(scalar(g_netconfig_db,"SELECT name='external edit' FROM wan WHERE id='wan'")==1);
}

static struct json_object *iptv_fixture_task(sqlite3 *app,const char *key)
{
    sqlite3_stmt *st=NULL;struct json_object *out=json_object_new_object();
    assert(sqlite3_prepare_v2(app,"SELECT id,state,readback_json,rollback_deadline,error FROM config_apply_tasks WHERE idempotency_key=?1 ORDER BY id DESC LIMIT 1",-1,&st,NULL)==SQLITE_OK);
    sqlite3_bind_text(st,1,key,-1,SQLITE_TRANSIENT);
    int found=sqlite3_step(st)==SQLITE_ROW;
    if(found){
        json_object_object_add(out,"task_id",json_object_new_int(sqlite3_column_int(st,0)));
        json_object_object_add(out,"state",json_object_new_string((const char *)sqlite3_column_text(st,1)));
        const char *readback=(const char *)sqlite3_column_text(st,2);
        json_object_object_add(out,"readback",readback?json_tokener_parse(readback):json_object_new_array());
        json_object_object_add(out,"rollback_deadline",json_object_new_int64(sqlite3_column_int64(st,3)));
        json_object_object_add(out,"error",json_object_new_string((const char *)sqlite3_column_text(st,4)?(const char *)sqlite3_column_text(st,4):""));
        json_object_object_add(out,"apply_executor",json_object_new_string(NC_TX_EXECUTOR));
        safeops_task_clock(out,nc_now_s());
    }
    sqlite3_finalize(st);json_object_object_add(out,"found",json_object_new_boolean(found));
    json_object_object_add(out,"ok",json_object_new_boolean(1));return out;
}

static void iptv_fixture_serve(sqlite3 *app)
{
    iptv_fixture_schema();setvbuf(stdout,NULL,_IOLBF,0);
    char *line=NULL;size_t capacity=0;
    while(getline(&line,&capacity,stdin)>0){
        struct json_object *request=json_tokener_parse(line),*body=json_object_object_get(request,"body"),*out=NULL;
        const char *method=nc_json_str(request,"method","");
        if(!strcmp(method,"get"))out=nc_tx_get(body);
        else if(!strcmp(method,"validate"))out=nc_tx_validate(body,NULL);
        else if(!strcmp(method,"apply")){
            out=nc_tx_apply(body);
            if(nc_json_bool(out,"ok",0)){json_object_put(out);out=iptv_fixture_task(app,nc_json_str(body,"idempotency_key",""));}
        }else if(!strcmp(method,"task"))out=iptv_fixture_task(app,nc_json_str(body,"key",""));
        else if(!strcmp(method,"confirm")){
            char *sql=sqlite3_mprintf("UPDATE config_apply_tasks SET state='confirmed' WHERE id=%d AND state='pending' AND rollback_deadline>%lld",nc_json_int(body,"task_id",0),(long long)nc_now_s());
            assert(sqlite3_exec(app,sql,NULL,NULL,NULL)==SQLITE_OK);sqlite3_free(sql);out=json_tokener_parse("{\"ok\":true}");
        }else if(!strcmp(method,"rollback")){
            int id=nc_json_int(body,"task_id",0);char *sql=sqlite3_mprintf("UPDATE config_apply_tasks SET state='rolling_back' WHERE id=%d AND state='pending'",id);
            assert(sqlite3_exec(app,sql,NULL,NULL,NULL)==SQLITE_OK);sqlite3_free(sql);out=nc_tx_rollback(body);
            sql=sqlite3_mprintf("UPDATE config_apply_tasks SET state=%Q WHERE id=%d",nc_json_bool(out,"ok",0)?"rolled_back":"rollback_failed",id);
            assert(sqlite3_exec(app,sql,NULL,NULL,NULL)==SQLITE_OK);sqlite3_free(sql);
        }else if(!strcmp(method,"inputs")){
            struct json_object *rows=nc_iptv_query("SELECT id,name,device,access_mode,enabled,vlan_id,role FROM wan WHERE role='iptv' ORDER BY id");
            for(size_t n=0;n<json_object_array_length(rows);n++){
                struct json_object *row=json_object_array_get_idx(rows,n);json_object_object_add(row,"available",json_object_new_boolean(0));
                json_object_object_add(row,"reason",json_object_new_string("input_address_unavailable"));
            }
            out=json_object_new_object();json_object_object_add(out,"items",rows);
        }else if(!strcmp(method,"drift")){
            assert(nc_exec("UPDATE wan SET name=name||' edited' WHERE id='wan'")==0);out=json_tokener_parse("{\"ok\":true}");
        }else out=nc_tx_error("fixture_method_unknown",400);
        puts(json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN));json_object_put(out);json_object_put(request);
    }
    free(line);
}
