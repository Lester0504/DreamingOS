/* SPDX-License-Identifier: GPL-2.0-or-later */
static void connection_source(struct json_object *s,const char *id,int available,const char *reason) {
    struct json_object *a=child(s,"sources");for(size_t i=0;i<json_object_array_length(a);i++){struct json_object *v=json_object_array_get_idx(a,i);if(!strcmp(str(v,"id"),id)){boolean(v,"available",available);text(v,"state",available?"ready":"unavailable");text(v,"reason",reason);}}
}
static struct json_object *connection_entry(struct json_object *s,const char *id,int64_t now) {
    struct json_object *map=child(s,"connections");if(!map){map=obj();json_object_object_add(s,"connections",map);}struct json_object *v=child(map,id);if(v)return v;
    if(json_object_object_length(map)>=512||strlen(json(s))>MAX_DOCUMENT-16384){boolean(s,"truncated",1);number(s,"connections_dropped",num(s,"connections_dropped")+1);text(s,"coverage_reason","connection_limit");return NULL;}
    v=obj();text(v,"id",id);number(v,"first_seen",now);text(v,"domain_attribution","unknown");json_object_object_add(map,id,v);return v;
}
static const char *flow_col(sqlite3_stmt *s,int col){const char *v=(const char *)sqlite3_column_text(s,col);return v?v:"";}
static int flow_db(const struct ada_environment *e,sqlite3 **db){return e->flow_database&&sqlite3_open_v2(e->flow_database,db,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,NULL)==SQLITE_OK;}
static void capture_connections(const struct ada_environment *e,struct json_object *s,int baseline) {
    if(e->conntrack){
        FILE *f=fopen(e->conntrack,"r");connection_source(s,"conn",f!=NULL,f?"periodic_tuple_snapshot_short_flows_may_be_missed":"conntrack_unavailable");
        if(f){char line[2048];size_t bytes=0;while(fgets(line,sizeof(line),f)){
            bytes+=strlen(line);if(bytes>READ_BYTES){boolean(s,"truncated",1);text(s,"coverage_reason","conntrack_scan_budget");break;}
            char rawsrc[80],rawdst[80],src[80],dst[80],proto[12];unsigned sp,dp;
            const char *tuple=strstr(line,"src=");if(!tuple||sscanf(tuple,"src=%79s dst=%79s sport=%u dport=%u",rawsrc,rawdst,&sp,&dp)!=4||!ip_normalize(rawsrc,src,sizeof(src))||strcmp(src,str(s,"device_ip"))||!ip_normalize(rawdst,dst,sizeof(dst)))continue;
            snprintf(proto,sizeof(proto),"%s",strstr(line," tcp ")?"tcp":strstr(line," udp ")?"udp":"other");
            char id[256];snprintf(id,sizeof(id),"ct-%s-%s-%u-%s-%u",proto,src,sp,dst,dp);struct json_object *v=connection_entry(s,id,e->now);if(!v)continue;
            text(v,"source","conntrack_snapshot");text(v,"destination_ip",dst);text(v,"protocol",proto);number(v,"destination_port",dp);number(v,"source_port",sp);text(v,"attribution","exact_original_source_ip");number(v,"last_seen",e->now);if(baseline)boolean(v,"present_at_start",1);
            text(v,"connection_state",strstr(line,"[UNREPLIED]")?"unreplied":strstr(line,"ESTABLISHED")?"established":"observed");
            if(!strcmp(proto,"udp")&&dp==443)connection_source(s,"udp443_ip",1,"ip_only_no_quic_hostname");
        }fclose(f);}
    }
    sqlite3 *db=NULL;if(!flow_db(e,&db)){if(db)sqlite3_close(db);return;}sqlite3_busy_timeout(db,20);
    sqlite3_stmt *st=NULL;const char *sql="SELECT flow_id,src_ip,dst_ip,src_port,dst_port,proto,first_seen,last_seen,destination_host,host_source,policy_id,policy_action,policy_source,client_mac FROM audit_flow_event_lifecycle WHERE destroy_ts>=?1 AND first_seen>=?1 AND src_ip=?2 ORDER BY destroy_ts DESC LIMIT 513";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_int64(st,1,num(s,"started_at"));sqlite3_bind_text(st,2,str(s,"device_ip"),-1,SQLITE_TRANSIENT);unsigned n=0;
        while(sqlite3_step(st)==SQLITE_ROW){if(++n>512){boolean(s,"truncated",1);text(s,"coverage_reason","flow_history_limit");break;}const char *mac=flow_col(st,13);if(*mac&&*str(s,"device_id")&&strcasecmp(mac,str(s,"device_id")))continue;
            char id[160];snprintf(id,sizeof(id),"flow-%s",flow_col(st,0));struct json_object *v=connection_entry(s,id,sqlite3_column_int64(st,6));if(!v)continue;
            text(v,"source","ctnetlink_destroy");text(v,"destination_ip",flow_col(st,2));number(v,"source_port",sqlite3_column_int(st,3));number(v,"destination_port",sqlite3_column_int(st,4));text(v,"protocol",flow_col(st,5));number(v,"last_seen",sqlite3_column_int64(st,7));text(v,"attribution",*mac?"exact_source_ip_mac":"exact_source_ip");
            text(v,"policy_id",flow_col(st,10));text(v,"policy_action",flow_col(st,11));text(v,"policy_source",flow_col(st,12));
            /* Never associate a destination-only fallback hostname with this
             * device or a shared CDN. Even a tuple hint is explicitly inferred. */
            const char *basis=flow_col(st,9);char name[256];
            if(!strcmp(basis,"af_active_host")&&domain_normalize(flow_col(st,8),name,sizeof(name))){text(v,"domain_hint",name);text(v,"domain_attribution","inferred_tuple_host");text(v,"host_source",basis);}
        }
        connection_source(s,"conn",1,"live_snapshots_and_completed_flows; hostname_hints_are_inferred");
    }
    sqlite3_finalize(st);sqlite3_close(db);
}
