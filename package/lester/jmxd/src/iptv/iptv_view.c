// SPDX-License-Identifier: GPL-2.0-or-later
/* IPTV adds grants to existing web identities, never another password realm.
 * TV sessions resolve an explicitly configured media_principal_id. */
#define _GNU_SOURCE
#include "iptv.h"
#include <libxml/tree.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
static void bindstr(sqlite3_stmt *s,int n,const char *v){sqlite3_bind_text(s,n,v,-1,SQLITE_TRANSIENT);}
static int scalar(sqlite3 *db,const char *sql,const char *arg)
{
    sqlite3_stmt *s=NULL;int yes=0;
    if(sqlite3_prepare_v2(db,sql,-1,&s,NULL)==SQLITE_OK){bindstr(s,1,arg);yes=sqlite3_step(s)==SQLITE_ROW;}
    sqlite3_finalize(s);return yes;
}
int iptv_principal_exists(sqlite3 *db,const char *principal)
{
    return !strncmp(principal,"web:",4)&&principal[4]&&strlen(principal)<128&&scalar(db,"SELECT 1 FROM web_users WHERE username=? AND status='enabled'",principal+4);
}
static int resolve(sqlite3 *db,const char *kind,const char *token,char *principal,size_t size)
{
    sqlite3_stmt *s=NULL;int yes=0;const char *sql;
    if(!strcmp(kind,"tv"))sql="SELECT COALESCE(NULLIF(t.media_principal_id,''),NULLIF(g.media_principal_id,''),'') FROM tvhome_session s JOIN tvhome_terminal t ON t.id=s.terminal_id JOIN tvhome_principal p ON p.id=s.principal_id LEFT JOIN tvhome_settings g ON g.id=1 WHERE s.token=? AND s.revoked=0 AND p.revoked=0 AND p.terminal_id=t.id AND s.expires_at_ms>?*1000 AND g.pin_required=0 AND COALESCE(json_extract(g.modules_json,'$.live.enabled'),json_extract(g.modules_json,'$.live'),0)=1";
    else sql="SELECT 'web:'||u.username FROM web_sessions s JOIN web_users u ON u.username=s.username WHERE s.token=? AND s.revoked=0 AND s.type='access' AND s.expires_at>? AND u.status='enabled'";
    if(sqlite3_prepare_v2(db,sql,-1,&s,NULL)==SQLITE_OK){bindstr(s,1,token);sqlite3_bind_int64(s,2,time(NULL));
        if(sqlite3_step(s)==SQLITE_ROW){snprintf(principal,size,"%s",sqlite3_column_text(s,0));yes=1;}}
    sqlite3_finalize(s);return yes&&iptv_principal_exists(db,principal);
}
static struct json_object *grant(sqlite3 *db,const char *principal)
{
    sqlite3_stmt *s=NULL;struct json_object *o=NULL;
    if(sqlite3_prepare_v2(db,"SELECT body FROM iptv_record WHERE kind='viewers' AND json_extract(body,'$.principal_id')=?",-1,&s,NULL)==SQLITE_OK){bindstr(s,1,principal);if(sqlite3_step(s)==SQLITE_ROW)o=json_tokener_parse((const char*)sqlite3_column_text(s,0));}
    sqlite3_finalize(s);return o;
}
int iptv_view_eligible(sqlite3 *db,const char *principal,struct json_object *channel)
{
    if(!iptv_principal_exists(db,principal)||!iptv_channel_enabled(db,channel))return 0;
    struct json_object *g=grant(db,principal),*categories=NULL,*expiry=NULL;int yes=0;
    if(!g||!iptv_integer(g,"enabled",0))goto out;
    json_object_object_get_ex(g,"expires_at",&expiry);
    int64_t until=json_object_get_int64(expiry);if(until&&until<=time(NULL))goto out;
    if(iptv_integer(g,"all_categories",0)){yes=1;goto out;}
    if(json_object_object_get_ex(g,"category_ids",&categories)&&json_object_is_type(categories,json_type_array))for(size_t i=0;i<json_object_array_length(categories);i++){
        if(!strcmp(json_object_get_string(json_object_array_get_idx(categories,i)),iptv_string(channel,"category_id"))){yes=1;break;}
    }
out:if(g)json_object_put(g);return yes;
}
int iptv_view_ticket_valid(sqlite3 *db,const char *ticket,struct json_object *channel)
{
    sqlite3_stmt *s=NULL;int yes=1;
    if(sqlite3_prepare_v2(db,"SELECT principal,origin,parent_token FROM iptv_view_lease WHERE ticket=?",-1,&s,NULL)!=SQLITE_OK)return 0;
    bindstr(s,1,ticket);
    int rc=sqlite3_step(s);
    if(rc==SQLITE_ROW){
        char principal[128]="";
        yes=resolve(db,(const char*)sqlite3_column_text(s,1),(const char*)sqlite3_column_text(s,2),principal,sizeof(principal))&&
            !strcmp(principal,(const char*)sqlite3_column_text(s,0))&&iptv_view_eligible(db,principal,channel);
    }else if(rc!=SQLITE_DONE)yes=0;
    sqlite3_finalize(s);return yes;
}
/* Export a bounded playlist without starting every channel. Tickets are
 * channel-scoped and inherit the exact parent session, with a five minute TTL. */
static struct json_object *playlist(sqlite3 *db,const char *principal,const char *origin,
    const char *parent,struct json_object *body,struct iptv_error *e)
{
    struct json_object *catalog=iptv_list(db,"channels",e),*items=NULL;
    if(!catalog)return NULL;
    json_object_object_get_ex(catalog,"items",&items);
    char *text=NULL;size_t length=0;FILE *f=open_memstream(&text,&length);
    if(!f){json_object_put(catalog);return iptv_fail(e,503,"out_of_memory","");}
    fputs("#EXTM3U\n",f);int count=0;sqlite3_stmt *s=NULL;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)goto failed;
    for(size_t i=0;i<json_object_array_length(items);i++){
        struct json_object *c=json_object_array_get_idx(items,i);if(!iptv_view_eligible(db,principal,c))continue;
        if(++count>1000){iptv_fail(e,422,"playlist_too_large","");goto failed;}
        fprintf(f,"#EXTINF:-1 tvg-id=\"%s\",%s\n",iptv_string(c,"id"),iptv_string(c,"name"));
        if(!strcmp(iptv_string(c,"mode"),"external")){
            char source[2304];if(iptv_source_url(db,c,source,sizeof(source),1,e))goto failed;
            fprintf(f,"%s\n",source);continue;
        }
        char ticket[49],actor[160];snprintf(actor,sizeof(actor),"viewer:%s",principal);
        if(iptv_id(ticket,sizeof(ticket))||sqlite3_prepare_v2(db,"INSERT INTO iptv_preview VALUES(?,?,?,unixepoch()+300)",-1,&s,NULL)!=SQLITE_OK)goto failed;
        bindstr(s,1,ticket);bindstr(s,2,actor);bindstr(s,3,iptv_string(c,"id"));
        if(sqlite3_step(s)!=SQLITE_DONE)goto failed;sqlite3_finalize(s);s=NULL;
        if(sqlite3_prepare_v2(db,"INSERT INTO iptv_view_lease VALUES(?,?,?,?)",-1,&s,NULL)!=SQLITE_OK)goto failed;
        bindstr(s,1,ticket);bindstr(s,2,principal);bindstr(s,3,origin);bindstr(s,4,parent);
        if(sqlite3_step(s)!=SQLITE_DONE)goto failed;sqlite3_finalize(s);s=NULL;
        if(sqlite3_prepare_v2(db,"INSERT INTO iptv_deferred_lease VALUES(?)",-1,&s,NULL)!=SQLITE_OK)goto failed;
        bindstr(s,1,ticket);if(sqlite3_step(s)!=SQLITE_DONE)goto failed;sqlite3_finalize(s);s=NULL;
        fprintf(f,"%s/api/v1/iptv/media/%s/%s/index.m3u8\n",iptv_string(body,"origin_url"),ticket,iptv_string(c,"id"));
    }
    if(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto failed;
    fclose(f);json_object_put(catalog);
    struct json_object *out=json_object_new_object();
    json_object_object_add(out,"text",json_object_new_string_len(text,length));free(text);
    json_object_object_add(out,"format",json_object_new_string("m3u"));
    json_object_object_add(out,"expires_at",json_object_new_int64(time(NULL)+300));
    json_object_object_add(out,"channels",json_object_new_int(count));
    json_object_object_add(out,"external_revocation",json_object_new_string("directory_only"));return out;
failed:
    sqlite3_finalize(s);if(!sqlite3_get_autocommit(db))sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    fclose(f);free(text);json_object_put(catalog);if(!e->status)iptv_fail(e,503,"media_session_create_failed","");return NULL;
}
static struct json_object *guide_export(sqlite3 *db,const char *principal,struct iptv_error *e)
{
    struct json_object *catalog=iptv_list(db,"channels",e),*items=NULL;
    if(!catalog)return NULL;json_object_object_get_ex(catalog,"items",&items);
    xmlDocPtr doc=xmlNewDoc(BAD_CAST "1.0");xmlNodePtr tv=xmlNewNode(NULL,BAD_CAST "tv");xmlDocSetRootElement(doc,tv);
    int count=0;
    for(size_t i=0;i<json_object_array_length(items);i++){
        struct json_object *channel=json_object_array_get_idx(items,i);if(!iptv_view_eligible(db,principal,channel))continue;
        const char *id=iptv_string(channel,"id");xmlNodePtr c=xmlNewChild(tv,NULL,BAD_CAST "channel",NULL);
        xmlNewProp(c,BAD_CAST "id",BAD_CAST id);xmlNewTextChild(c,NULL,BAD_CAST "display-name",BAD_CAST iptv_string(channel,"name"));
        char path[160];snprintf(path,sizeof(path),"epg/%s",id);struct iptv_error ignored={0};
        struct json_object *guide=iptv_epg_request(db,"GET",path,NULL,&ignored),*programmes=NULL;
        if(!guide)continue;json_object_object_get_ex(guide,"items",&programmes);
        for(size_t j=0;j<json_object_array_length(programmes)&&count<10000;j++,count++){
            struct json_object *row=json_object_array_get_idx(programmes,j);xmlNodePtr p=xmlNewChild(tv,NULL,BAD_CAST "programme",NULL);
            xmlNewProp(p,BAD_CAST "channel",BAD_CAST id);
            const char *keys[]={"start","end"};for(int k=0;k<2;k++){
                time_t when=json_object_get_int64(json_object_object_get(row,keys[k]));struct tm utc;gmtime_r(&when,&utc);char stamp[32];strftime(stamp,sizeof(stamp),"%Y%m%d%H%M%S +0000",&utc);
                xmlNewProp(p,BAD_CAST (k?"stop":"start"),BAD_CAST stamp);
            }
            xmlNewTextChild(p,NULL,BAD_CAST "title",BAD_CAST iptv_string(row,"title"));
            xmlNewTextChild(p,NULL,BAD_CAST "desc",BAD_CAST iptv_string(row,"description"));
        }json_object_put(guide);
    }
    xmlChar *text=NULL;int size=0;xmlDocDumpMemoryEnc(doc,&text,&size,"UTF-8");xmlFreeDoc(doc);json_object_put(catalog);
    if(!text)return iptv_fail(e,503,"out_of_memory","");
    struct json_object *out=json_object_new_object();json_object_object_add(out,"text",json_object_new_string_len((char*)text,size));xmlFree(text);
    json_object_object_add(out,"format",json_object_new_string("xmltv"));json_object_object_add(out,"truncated",json_object_new_boolean(count>=10000));return out;
}
/* One media subject owns this state across Web/mobile/TV sessions. The provider
 * catalogue remains the authority for opaque resource IDs and current access. */
static struct json_object *subject_state(sqlite3 *db,const char *principal,const char *kind,const char *id,struct iptv_error *e)
{
    sqlite3_stmt *s=NULL;struct json_object *out=NULL;
    if(sqlite3_prepare_v2(db,"SELECT body,revision FROM iptv_subject_state WHERE principal=? AND provider='iptv.local' AND kind=? AND resource_id=?",-1,&s,NULL)!=SQLITE_OK)return iptv_fail(e,503,"state_store_unavailable","");
    bindstr(s,1,principal);bindstr(s,2,kind);bindstr(s,3,id);
    int rc=sqlite3_step(s);int64_t revision=0;
    if(rc==SQLITE_ROW){out=json_tokener_parse((const char*)sqlite3_column_text(s,0));revision=sqlite3_column_int64(s,1);}
    sqlite3_finalize(s);
    if(rc!=SQLITE_ROW&&rc!=SQLITE_DONE)return iptv_fail(e,503,"state_store_unavailable","");
    if(!out)out=json_object_new_object();
    json_object_object_add(out,"revision",json_object_new_int64(revision));
    json_object_object_add(out,"provider_id",json_object_new_string("iptv.local"));
    json_object_object_add(out,"media_principal_id",json_object_new_string(principal));
    if(!strcmp(kind,"favorites")){
        struct json_object *ids=NULL,*allowed=json_object_new_array();json_object_object_get_ex(out,"channel_ids",&ids);
        for(size_t i=0,n=json_object_is_type(ids,json_type_array)?json_object_array_length(ids):0;i<n;i++){
            const char *channel_id=json_object_get_string(json_object_array_get_idx(ids,i));
            struct json_object *channel=iptv_record(db,"channels",channel_id);
            if(iptv_view_eligible(db,principal,channel))json_object_array_add(allowed,json_object_new_string(channel_id));
            if(channel)json_object_put(channel);
        }
        json_object_object_add(out,"channel_ids",allowed);
    }
    return out;
}
static struct json_object *state_conflict(struct json_object *canonical,struct iptv_error *e)
{
    iptv_fail(e,409,"revision_conflict","if_revision");
    struct json_object *out=json_object_new_object();json_object_object_add(out,"canonical",canonical);return out;
}
static struct json_object *view_state(sqlite3 *db,const char *principal,const char *kind,const char *id,struct json_object *body,int writing,struct iptv_error *e)
{
    int favorite=!strcmp(kind,"favorites");const char *resource=favorite?"main":id;
    struct json_object *canonical=NULL,*record=NULL,*out=NULL,*v=NULL;
    sqlite3_stmt *s=NULL;double duration=0,position=0;int desired=0;
    const char *action="watch",*key="";int64_t expected=0;
    char fingerprint[512]="";
    if(writing){
        if(!json_object_is_type(body,json_type_object))return iptv_fail(e,400,"invalid_parameter","body");
        json_object_object_foreach(body,k,val){
            (void)val;
            if(strcmp(k,"if_revision")&&strcmp(k,"idempotency_key")&&
                (favorite?strcmp(k,"favorite"):(strcmp(k,"position_seconds")&&strcmp(k,"action"))))
                return iptv_fail(e,400,"invalid_parameter",k);
        }
        if(!json_object_object_get_ex(body,"if_revision",&v)||!json_object_is_type(v,json_type_int)||(expected=json_object_get_int64(v))<0)
            return iptv_fail(e,400,"invalid_parameter","if_revision");
        key=iptv_string(body,"idempotency_key");
        if(!iptv_valid_id(key))return iptv_fail(e,400,"invalid_parameter","idempotency_key");
        if(favorite){
            if(!json_object_object_get_ex(body,"favorite",&v)||!json_object_is_type(v,json_type_boolean))return iptv_fail(e,400,"invalid_parameter","favorite");
            desired=json_object_get_boolean(v);
        }else{
            action=iptv_string(body,"action");
            if(strcmp(action,"watch")&&strcmp(action,"restart"))return iptv_fail(e,400,"invalid_parameter","action");
            if(!json_object_object_get_ex(body,"position_seconds",&v)||(!json_object_is_type(v,json_type_int)&&!json_object_is_type(v,json_type_double)))return iptv_fail(e,400,"invalid_parameter","position_seconds");
            position=json_object_get_double(v);
            if(!isfinite(position)||position<0||(!strcmp(action,"restart")&&position!=0))return iptv_fail(e,400,"invalid_parameter","position_seconds");
        }
        snprintf(fingerprint,sizeof(fingerprint),"%s|%s|%lld|%s|%.17g",kind,id,(long long)expected,action,favorite?(double)desired:position);
        if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return iptv_fail(e,409,"state_store_busy","");
    }
    /* A remembered favourite/progress record never grants permission. */
    if(*id){
        const char *channel_id=id;
        if(!favorite){
            record=iptv_record(db,"recordings",id);
            if(!record){iptv_fail(e,404,"recording_not_found","");goto done;}
            channel_id=iptv_string(record,"channel_id");
            if(strcmp(iptv_string(record,"state"),"ready")){iptv_fail(e,409,"recording_not_ready","");goto done;}
            duration=json_object_get_double(json_object_object_get(record,"end"))-json_object_get_double(json_object_object_get(record,"start"));
            if(!isfinite(duration)||duration<=0){iptv_fail(e,409,"recording_duration_unavailable","");goto done;}
        }
        struct json_object *channel=iptv_record(db,"channels",channel_id);
        int allowed=iptv_view_eligible(db,principal,channel);if(channel)json_object_put(channel);
        if(!allowed){iptv_fail(e,403,"watching_not_permitted","");goto done;}
    }
    canonical=subject_state(db,principal,kind,resource,e);if(!canonical)goto done;
    if(!favorite){
        if(!json_object_object_get_ex(canonical,"position_seconds",&v)){
            json_object_object_add(canonical,"position_seconds",json_object_new_double(0));
            json_object_object_add(canonical,"finished",json_object_new_boolean(0));
            json_object_object_add(canonical,"last_action",json_object_new_string("watch"));
        }
        json_object_object_add(canonical,"duration_seconds",json_object_new_double(duration));
        json_object_object_add(canonical,"episode_id",json_object_new_string(id));
        json_object_object_add(canonical,"resource_id",json_object_new_string(id));
    }
    if(!writing){out=canonical;canonical=NULL;goto done;}
    if(sqlite3_prepare_v2(db,"SELECT request,result FROM iptv_subject_request WHERE principal=? AND provider='iptv.local' AND idempotency_key=?",-1,&s,NULL)!=SQLITE_OK)goto failed;
    bindstr(s,1,principal);bindstr(s,2,key);int rc=sqlite3_step(s);
    if(rc==SQLITE_ROW){
        if(strcmp(fingerprint,(const char*)sqlite3_column_text(s,0)))iptv_fail(e,409,"idempotency_key_reused","idempotency_key");
        else out=json_tokener_parse((const char*)sqlite3_column_text(s,1));
        sqlite3_finalize(s);s=NULL;goto done;
    }
    sqlite3_finalize(s);s=NULL;if(rc!=SQLITE_DONE)goto failed;
    int64_t revision=json_object_get_int64(json_object_object_get(canonical,"revision"));
    if(expected!=revision){out=state_conflict(canonical,e);canonical=NULL;goto done;}
    if(favorite){
        struct json_object *ids=NULL,*next=json_object_new_array();json_object_object_get_ex(canonical,"channel_ids",&ids);
        for(size_t i=0,n=json_object_is_type(ids,json_type_array)?json_object_array_length(ids):0;i<n;i++){
            const char *saved=json_object_get_string(json_object_array_get_idx(ids,i));
            if(strcmp(saved,id))json_object_array_add(next,json_object_new_string(saved));
        }
        if(desired)json_object_array_add(next,json_object_new_string(id));
        json_object_object_add(canonical,"channel_ids",next);
    }else{
        /* Frozen TVHome rule; a rolling live/timeshift window is never a film. */
        position=fmin(position,duration);double remaining=duration-position;
        int finished=strcmp(action,"restart")&&(remaining<=fmin(90,duration*.10)||remaining<=duration*.03);
        json_object_object_add(canonical,"position_seconds",json_object_new_double(position));
        json_object_object_add(canonical,"finished",json_object_new_boolean(finished));
        json_object_object_add(canonical,"last_action",json_object_new_string(action));
    }
    json_object_object_add(canonical,"revision",json_object_new_int64(revision+1));
    json_object_object_add(canonical,"updated_at",json_object_new_int64(time(NULL)));
    if(sqlite3_prepare_v2(db,"INSERT INTO iptv_subject_state VALUES(?,'iptv.local',?,?,?,?) ON CONFLICT(principal,provider,kind,resource_id) DO UPDATE SET revision=excluded.revision,body=excluded.body",-1,&s,NULL)!=SQLITE_OK)goto failed;
    bindstr(s,1,principal);bindstr(s,2,kind);bindstr(s,3,resource);sqlite3_bind_int64(s,4,revision+1);bindstr(s,5,json_object_to_json_string_ext(canonical,JSON_C_TO_STRING_PLAIN));
    rc=sqlite3_step(s);sqlite3_finalize(s);s=NULL;if(rc!=SQLITE_DONE)goto failed;
    if(sqlite3_prepare_v2(db,"INSERT INTO iptv_subject_request VALUES(?,'iptv.local',?,?,?)",-1,&s,NULL)!=SQLITE_OK)goto failed;
    bindstr(s,1,principal);bindstr(s,2,key);bindstr(s,3,fingerprint);bindstr(s,4,json_object_to_json_string_ext(canonical,JSON_C_TO_STRING_PLAIN));
    rc=sqlite3_step(s);sqlite3_finalize(s);s=NULL;if(rc!=SQLITE_DONE)goto failed;
    if(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto failed;
    out=canonical;canonical=NULL;goto done;
failed:
    iptv_fail(e,503,"state_store_unavailable","");
done:
    sqlite3_finalize(s);if(writing&&!sqlite3_get_autocommit(db))sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    if(canonical)json_object_put(canonical);if(record)json_object_put(record);return out;
}

struct json_object *iptv_view_request(sqlite3 *db,const char *origin,const char *token,const char *path,struct json_object *body,int writing,struct iptv_error *e)
{
    char principal[128]="";
    if(!resolve(db,origin,token,principal,sizeof(principal)))return iptv_fail(e,401,"media_identity_unavailable","");
    char kind[32]="",id[97]="",action[32]="",extra=0;
    int parts=sscanf(path,"%31[^/]/%96[^/]/%31[^/]%c",kind,id,action,&extra);
    struct json_object *result=NULL,*cfg=iptv_settings(db);
    int on=iptv_integer(cfg,"enabled",0);if(cfg)json_object_put(cfg);
    if(!on)return iptv_fail(e,409,"module_disabled","");
    if(!strcmp(kind,"favorites")||!strcmp(kind,"progress")){
        int favorite=!strcmp(kind,"favorites");
        if((favorite&&parts==1&&!writing)||(parts==2&&iptv_valid_id(id)&&(!favorite||writing)))
            return view_state(db,principal,kind,parts==1?"":id,body,writing,e);
        return iptv_fail(e,405,"method_not_allowed","");
    }
    if(parts==1&&!strcmp(kind,"playlist"))return playlist(db,principal,origin,token,body,e);
    if(parts==1&&!strcmp(kind,"xmltv"))return guide_export(db,principal,e);
    if(parts==1&&!strcmp(kind,"categories")){
        struct json_object *catalog=iptv_list(db,"channels",e),*items=NULL,*groups=iptv_list(db,"categories",e),*all=NULL,*allowed=json_object_new_array();
        if(!catalog||!groups){if(catalog)json_object_put(catalog);if(groups)json_object_put(groups);json_object_put(allowed);return NULL;}
        json_object_object_get_ex(catalog,"items",&items);json_object_object_get_ex(groups,"items",&all);
        for(size_t i=0;i<json_object_array_length(all);i++){
            struct json_object *group=json_object_array_get_idx(all,i);int visible=0;
            for(size_t j=0;j<json_object_array_length(items);j++){struct json_object *channel=json_object_array_get_idx(items,j);if(!strcmp(iptv_string(group,"id"),iptv_string(channel,"category_id"))&&iptv_view_eligible(db,principal,channel)){visible=1;break;}}
            if(visible)json_object_array_add(allowed,json_object_get(group));
        }
        json_object_put(catalog);json_object_object_add(groups,"items",allowed);return groups;
    }
    if(parts==1&&!strcmp(kind,"channels")){
        result=iptv_list(db,"channels",e);if(!result)return NULL;
        struct json_object *items=NULL,*allowed=json_object_new_array();json_object_object_get_ex(result,"items",&items);
        for(size_t i=0;i<json_object_array_length(items);i++){
            struct json_object *row=json_object_array_get_idx(items,i);if(!iptv_view_eligible(db,principal,row))continue;
            struct json_object *out=json_object_new_object();const char *keys[]={"id","name","number","category_id","position","mode","logo_url","epg_id",NULL};
            for(int j=0;keys[j];j++){struct json_object *v=NULL;if(json_object_object_get_ex(row,keys[j],&v))json_object_object_add(out,keys[j],json_object_get(v));}
            json_object_array_add(allowed,out);
        }json_object_object_add(result,"items",allowed);
        json_object_object_add(result,"provider_id",json_object_new_string("iptv.local"));json_object_object_add(result,"media_principal_id",json_object_new_string(principal));return result;
    }
    if(parts==2&&!strcmp(kind,"snapshot")&&iptv_valid_id(id)){
        struct json_object *channel=iptv_record(db,"channels",id);
        if(!iptv_view_eligible(db,principal,channel))result=iptv_fail(e,403,"channel_not_authorized","");
        else {result=iptv_snapshot_read(db,id,e);if(result)json_object_object_del(result,"last_attempt");}
        if(channel)json_object_put(channel);return result;
    }
    if(parts==2&&(!strcmp(kind,"release")||!strcmp(kind,"renew"))&&iptv_valid_id(id)){
        sqlite3_stmt *stmt=NULL;const char *sql=!strcmp(kind,"release")?
            "DELETE FROM iptv_preview WHERE token=?1 AND token IN(SELECT ticket FROM iptv_view_lease WHERE principal=?2 AND origin=?3 AND parent_token=?4)":
            "UPDATE iptv_preview SET expires=?5 WHERE token=?1 AND expires>?6 AND token IN(SELECT ticket FROM iptv_view_lease WHERE principal=?2 AND origin=?3 AND parent_token=?4)";
        if(!iptv_integer(body,"confirmed",0))return iptv_fail(e,405,"explicit_session_action_required","");
        if(sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK)return iptv_fail(e,503,"config_db_unavailable","");
        bindstr(stmt,1,id);bindstr(stmt,2,principal);bindstr(stmt,3,origin);bindstr(stmt,4,token);
        if(!strcmp(kind,"renew")){sqlite3_bind_int64(stmt,5,time(NULL)+300);sqlite3_bind_int64(stmt,6,time(NULL));}
        int rc=sqlite3_step(stmt),changed=sqlite3_changes(db);sqlite3_finalize(stmt);
        if(rc!=SQLITE_DONE)return iptv_fail(e,503,"config_db_unavailable","");
        if(!changed&&strcmp(kind,"release"))return iptv_fail(e,401,"media_session_expired","");
        result=json_object_new_object();json_object_object_add(result,"released",json_object_new_boolean(!strcmp(kind,"release")));
        if(strcmp(kind,"release"))json_object_object_add(result,"expires_at",json_object_new_int64(time(NULL)+300));return result;
    }
    if((parts!=2&&parts!=3)||!iptv_valid_id(id))return iptv_fail(e,404,"resource_not_found","");
    char channel_id[97];snprintf(channel_id,sizeof(channel_id),"%s",id);
    int recording=parts==2&&!strcmp(kind,"recording");
    if(recording){
        struct json_object *file=iptv_record(db,"recordings",id);
        if(!file)return iptv_fail(e,404,"recording_not_found","");
        snprintf(channel_id,sizeof(channel_id),"%s",iptv_string(file,"channel_id"));json_object_put(file);
    }
    struct json_object *channel=iptv_record(db,"channels",channel_id);
    int permitted=iptv_view_eligible(db,principal,channel);if(channel)json_object_put(channel);
    if(!permitted)return iptv_fail(e,403,"watching_not_permitted","");
    if((parts==2||parts==3)&&!strcmp(kind,"epg"))return iptv_epg_request(db,"GET",path,NULL,e);
    if((parts==2||parts==3)&&!strcmp(kind,"recordings")){
        result=iptv_recordings_request(db,"GET","recordings",NULL,"",e);if(!result)return NULL;
        struct json_object *items=NULL,*allowed=json_object_new_array();json_object_object_get_ex(result,"items",&items);
        for(size_t i=0;i<json_object_array_length(items);i++){struct json_object *r=json_object_array_get_idx(items,i);if(!strcmp(iptv_string(r,"channel_id"),id)){
            time_t start=json_object_get_double(json_object_object_get(r,"start"));struct tm utc;gmtime_r(&start,&utc);char day[16];strftime(day,sizeof(day),"%Y-%m-%d",&utc);
            if(parts==2||!strcmp(action,day))json_object_array_add(allowed,json_object_get(r));
        }}
        json_object_object_add(result,"items",allowed);json_object_object_del(result,"captures");json_object_object_del(result,"used_bytes");
        return result;
    }
    long long from=0;
    if(!strcmp(kind,"timeshift")&&parts==3){
        struct json_object *window=iptv_runtime_window(id,e);
        if(!window)return NULL;
        if(!strcmp(action,"info"))return window;
        char *end=NULL;from=strtoll(action,&end,10);
        char *playlist=NULL;size_t length=0;
        int invalid=from<=0||!end||*end;
        if(!invalid)invalid=iptv_window_playlist(window,(double)from,0,&playlist,&length,e);
        free(playlist);json_object_put(window);
        if(invalid){if(!e->status)iptv_fail(e,400,"invalid_parameter","start");return NULL;}
    }else if(!recording&&(parts!=2||strcmp(kind,"stream")))return iptv_fail(e,404,"resource_not_found","");
    char actor[160];snprintf(actor,sizeof(actor),"viewer:%s",principal);
    if(recording){char resource[160];snprintf(resource,sizeof(resource),"recordings/%s/preview",id);result=iptv_recordings_request(db,"POST",resource,NULL,actor,e);}
    else result=iptv_preview_issue(db,id,actor,e);
    if(!result)return NULL;
    const char *ticket=iptv_string(result,"session_id");
    if(*ticket){sqlite3_stmt *s=NULL;
        if(sqlite3_prepare_v2(db,"INSERT INTO iptv_view_lease(ticket,principal,origin,parent_token) VALUES(?,?,?,?)",-1,&s,NULL)!=SQLITE_OK)goto bad;
        bindstr(s,1,ticket);bindstr(s,2,principal);bindstr(s,3,origin);bindstr(s,4,token);int rc=sqlite3_step(s);sqlite3_finalize(s);if(rc!=SQLITE_DONE)goto bad;
    }
    if(from>0){char url[320];snprintf(url,sizeof(url),"/api/v1/iptv/media/%s/%s/at%lld.m3u8",ticket,id,from);json_object_object_add(result,"url",json_object_new_string(url));}
    json_object_object_add(result,"provider_id",json_object_new_string("iptv.local"));json_object_object_add(result,"resource_id",json_object_new_string(id));
    return result;
bad:
    {sqlite3_stmt *cleanup=NULL;
        if(sqlite3_prepare_v2(db,"DELETE FROM iptv_preview WHERE token=?",-1,&cleanup,NULL)==SQLITE_OK){bindstr(cleanup,1,ticket);sqlite3_step(cleanup);}sqlite3_finalize(cleanup);}
    json_object_put(result);return iptv_fail(e,503,"media_session_create_failed","");
}
struct json_object *iptv_principals(sqlite3 *db,struct iptv_error *e)
{
    sqlite3_stmt *s=NULL;
    if(sqlite3_prepare_v2(db,"SELECT username,status FROM web_users ORDER BY username",-1,&s,NULL)!=SQLITE_OK)return iptv_fail(e,503,"media_identity_unavailable","");
    struct json_object *result=json_object_new_object(),*items=json_object_new_array();
    while(sqlite3_step(s)==SQLITE_ROW){struct json_object *row=json_object_new_object();char principal[128];snprintf(principal,sizeof(principal),"web:%s",sqlite3_column_text(s,0));
        json_object_object_add(row,"id",json_object_new_string(principal));json_object_object_add(row,"name",json_object_new_string((const char*)sqlite3_column_text(s,0)));json_object_object_add(row,"enabled",json_object_new_boolean(!strcmp((const char*)sqlite3_column_text(s,1),"enabled")));json_object_array_add(items,row);}
    sqlite3_finalize(s);json_object_object_add(result,"items",items);return result;
}

/* Management gets a digest identifier, never the playable ticket or the parent
 * web/TV credential. Revocation deletes only this module's media lease. */
static void session_id(const char *token,char id[65])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];SHA256((const unsigned char*)token,strlen(token),digest);
    for(size_t i=0;i<sizeof(digest);i++)snprintf(id+i*2,3,"%02x",digest[i]);
}
struct json_object *iptv_view_sessions(sqlite3 *db,const char *method,const char *path,struct json_object *body,struct iptv_error *e)
{
    int listing=!strcmp(method,"GET")&&!strcmp(path,"sessions");char requested[65],extra;
    int revoking=!strcmp(method,"POST")&&sscanf(path,"sessions/%64[0-9a-f]/revoke%c",requested,&extra)==1&&strlen(requested)==64&&strstr(path,"/revoke")&&strlen(path)==80;
    if(!listing&&!revoking)return iptv_fail(e,404,"resource_not_found","");
    if(revoking&&!iptv_integer(body,"confirm",0))return iptv_fail(e,409,"requires_confirmation","confirm");
    sqlite3_stmt *s=NULL;char revoke_token[49]="";
    if(sqlite3_prepare_v2(db,"SELECT p.token,p.channel,p.expires,COALESCE(v.principal,''),COALESCE(v.origin,'management'),COALESCE(r.recording,'') FROM iptv_preview p LEFT JOIN iptv_view_lease v ON v.ticket=p.token LEFT JOIN iptv_recording_lease r ON r.ticket=p.token WHERE p.expires>unixepoch() ORDER BY p.expires DESC LIMIT 4096",-1,&s,NULL)!=SQLITE_OK)return iptv_fail(e,503,"config_db_unavailable","");
    struct json_object *out=json_object_new_object(),*items=json_object_new_array();
    while(sqlite3_step(s)==SQLITE_ROW){
        const char *token=(const char*)sqlite3_column_text(s,0);char id[65];session_id(token,id);
        if(revoking&&!strcmp(id,requested)){snprintf(revoke_token,sizeof(revoke_token),"%s",token);break;}
        if(!listing)continue;
        struct json_object *row=json_object_new_object();json_object_object_add(row,"id",json_object_new_string(id));
        const char *keys[]={"channel_id","expires_at","principal_id","origin","recording_id"};
        for(int i=1;i<6;i++)json_object_object_add(row,keys[i-1],i==2?json_object_new_int64(sqlite3_column_int64(s,i)):json_object_new_string((const char*)sqlite3_column_text(s,i)));
        json_object_array_add(items,row);
    }
    sqlite3_finalize(s);s=NULL;
    if(listing){json_object_object_add(out,"items",items);json_object_object_add(out,"meaning",json_object_new_string("unexpired_media_leases_not_live_audience"));return out;}
    json_object_put(items);
    if(*revoke_token&&sqlite3_prepare_v2(db,"DELETE FROM iptv_preview WHERE token=?",-1,&s,NULL)==SQLITE_OK){bindstr(s,1,revoke_token);if(sqlite3_step(s)!=SQLITE_DONE){sqlite3_finalize(s);json_object_put(out);return iptv_fail(e,503,"config_db_unavailable","");}}
    sqlite3_finalize(s);json_object_object_add(out,"revoked",json_object_new_boolean(*revoke_token!=0));return out;
}
