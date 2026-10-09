// SPDX-License-Identifier: GPL-2.0-or-later
/* One-shot direct playlist import. Preview is pure; commit revalidates rows
 * against the current catalogue and returns an outcome for every input row. */
#define _GNU_SOURCE
#include "iptv.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void str(struct json_object *o,const char *k,const char *v)
{ json_object_object_add(o,k,json_object_new_string(v?v:"")); }
static struct json_object *clone(struct json_object *o)
{ return json_tokener_parse(json_object_to_json_string(o)); }
static char *trim(char *s)
{
    while(isspace((unsigned char)*s))s++;
    char *end=s+strlen(s);while(end>s&&isspace((unsigned char)end[-1]))*--end=0;
    return s;
}
static void attribute(const char *line,const char *key,char *out,size_t size)
{
    char needle[64];snprintf(needle,sizeof(needle),"%s=\"",key);
    const char *p=strstr(line,needle);out[0]=0;if(!p)return;p+=strlen(needle);
    const char *end=strchr(p,'"');if(!end)return;
    snprintf(out,size,"%.*s",(int)(end-p),p);
}
static struct json_object *parse_text(const char *text,struct iptv_error *e)
{
    if(!*text||strlen(text)>512*1024)return iptv_fail(e,400,"playlist_size_invalid","text");
    char *buf=strdup(text),*saveptr=NULL,*line;int number=0;
    char name[256]="",category[256]="",epg[256]="",logo[2049]="";
    struct json_object *rows=json_object_new_array();
    if(!buf){json_object_put(rows);return iptv_fail(e,503,"out_of_memory","");}
    for(line=strtok_r(buf,"\n",&saveptr);line;line=strtok_r(NULL,"\n",&saveptr)){
        number++;line=trim(line);if(!strncmp(line,"\xef\xbb\xbf",3))line+=3;
        if(!*line)continue;
        if(!strncmp(line,"#EXTINF:",8)){
            const char *comma=NULL;int quoted=0;
            for(const char *p=line;*p;p++){if(*p=='"')quoted=!quoted;if(*p==','&&!quoted){comma=p;break;}}
            snprintf(name,sizeof(name),"%s",comma?comma+1:"");
            attribute(line,"group-title",category,sizeof(category));attribute(line,"tvg-id",epg,sizeof(epg));attribute(line,"tvg-logo",logo,sizeof(logo));continue;
        }
        if(*line=='#')continue;
        char *url=line,*comma=strchr(line,',');
        if(comma){*comma=0;snprintf(name,sizeof(name),"%s",trim(line));url=trim(comma+1);
            if(!strcmp(url,"#genre#")){snprintf(category,sizeof(category),"%s",name);name[0]=0;continue;}}
        struct json_object *row=json_object_new_object();
        json_object_object_add(row,"line",json_object_new_int(number));
        str(row,"name",name);str(row,"source_url",url);str(row,"category_name",category);str(row,"epg_id",epg);str(row,"logo_url",logo);
        /* TXT alternatives have no automatic failover semantics. */
        if(strchr(url,'#'))str(row,"parse_error","alternate_sources_require_separate_rows");
        json_object_array_add(rows,row);name[0]=epg[0]=logo[0]=0;
        if(json_object_array_length(rows)>1000){json_object_put(rows);rows=iptv_fail(e,413,"playlist_row_limit","text");break;}
    }
    free(buf);return rows;
}
static struct json_object *lookup(struct json_object *items,const char *key,const char *value)
{
    for(size_t i=json_object_array_length(items);i>0;i--){
        struct json_object *v=json_object_array_get_idx(items,i-1);
        if(!strcmp(iptv_string(v,key),value))return v;
    }return NULL;
}
static struct json_object *imports(sqlite3 *db,const char *path,struct json_object *body,struct iptv_error *e)
{
    int commit=!strcmp(path,"imports/commit");
    if(!commit&&strcmp(path,"imports/preview"))return iptv_fail(e,404,"resource_not_found","");
    const char *format=iptv_string(body,"format"),*policy=iptv_string(body,"duplicates");
    if(strcmp(format,"m3u")&&strcmp(format,"txt")&&strcmp(format,"xlsx"))return iptv_fail(e,422,"import_format_unsupported","format");
    if(*policy&&strcmp(policy,"skip")&&strcmp(policy,"update"))return iptv_fail(e,400,"invalid_parameter","duplicates");
    struct json_object *rows=!strcmp(format,"xlsx")?iptv_workbook_read(iptv_string(body,"base64"),e):parse_text(iptv_string(body,"text"),e);if(!rows)return NULL;
    if(commit&&iptv_integer(body,"if_revision",-1)!=iptv_revision(db)){json_object_put(rows);return iptv_fail(e,409,"revision_conflict","if_revision");}
    struct json_object *catalog=iptv_list(db,"channels",e),*groups=iptv_list(db,"categories",e),*items=NULL,*cats=NULL;
    if(!catalog||!groups){if(catalog)json_object_put(catalog);if(groups)json_object_put(groups);json_object_put(rows);return NULL;}
    json_object_object_get_ex(catalog,"items",&items);json_object_object_get_ex(groups,"items",&cats);
    struct json_object *result=json_object_new_object(),*outcomes=json_object_new_array();
    int base=iptv_revision(db),success=0;
    for(size_t i=0;i<json_object_array_length(rows);i++){
        struct json_object *row=json_object_array_get_idx(rows,i),*out=clone(row),*channel=json_object_new_object();
        struct iptv_error rowerr={0};char id[49];
        const char *group=iptv_string(row,"category_name");struct json_object *category=*group?lookup(cats,"name",group):NULL;
        struct json_object *existing=lookup(items,"source_url",iptv_string(row,"source_url"));
        str(channel,"name",iptv_string(row,"name"));str(channel,"mode",!strcmp(format,"xlsx")?(*iptv_string(row,"mode")?iptv_string(row,"mode"):"managed"):"external");str(channel,"source_url",iptv_string(row,"source_url"));
        str(channel,"epg_source_id",iptv_string(row,"epg_source_id"));str(channel,"input_id",iptv_string(row,"input_id"));
        str(channel,"category_id",category?iptv_string(category,"id"):"");str(channel,"epg_id",iptv_string(row,"epg_id"));str(channel,"logo_url",iptv_string(row,"logo_url"));
        json_object_object_add(channel,"enabled",json_object_new_boolean(iptv_integer(row,"enabled",1)));
        json_object_object_add(channel,"timeshift_minutes",json_object_new_int(iptv_integer(row,"timeshift_minutes",0)));
        json_object_object_add(channel,"program_id",json_object_new_int(iptv_integer(row,"program_id",0)));
        str(channel,"rtsp_transport",iptv_string(row,"rtsp_transport"));str(channel,"user_agent",iptv_string(row,"user_agent"));
        str(channel,"video_encoder",*iptv_string(row,"video_encoder")?iptv_string(row,"video_encoder"):"copy");
        str(channel,"audio_encoder",*iptv_string(row,"audio_encoder")?iptv_string(row,"audio_encoder"):"copy");
        json_object_object_add(channel,"video_bitrate_kbps",json_object_new_int(iptv_integer(row,"video_bitrate_kbps",2000)));
        json_object_object_add(channel,"audio_bitrate_kbps",json_object_new_int(iptv_integer(row,"audio_bitrate_kbps",192)));
        if(*iptv_string(row,"hls_container"))str(channel,"hls_container",iptv_string(row,"hls_container"));
        json_object_object_add(channel,"position",json_object_new_int(iptv_integer(row,"position",(int)i)));json_object_object_add(channel,"number",json_object_new_int(iptv_integer(row,"number",0)));
        if(*iptv_string(row,"parse_error"))iptv_fail(&rowerr,422,iptv_string(row,"parse_error"),"source_url");
        else if(!iptv_validate(db,"channels",channel,&rowerr)){}
        else if(existing&&strcmp(policy,"update"))str(out,"action","skip");
        else{
            str(out,"action",existing?"update":"create");
            if(*group&&!category)str(out,"category_action","create");
            if(commit){
                if(*group&&!category){
                    struct json_object *c=json_object_new_object();str(c,"name",group);
                    struct json_object *saved=NULL;
                    if(!iptv_id(id,sizeof(id)))saved=iptv_save(db,"categories",id,c,1,&rowerr);
                    else iptv_fail(&rowerr,503,"entropy_unavailable","");
                    json_object_put(c);
                    if(saved){struct json_object *v=NULL;json_object_object_get_ex(saved,"record",&v);category=json_object_get(v);json_object_array_add(cats,category);json_object_put(saved);str(channel,"category_id",iptv_string(category,"id"));}
                }
                if(!rowerr.status){
                    if(existing){snprintf(id,sizeof(id),"%s",iptv_string(existing,"id"));json_object_object_add(channel,"if_revision",json_object_new_int(iptv_integer(existing,"revision",0)));}
                    else if(iptv_id(id,sizeof(id)))iptv_fail(&rowerr,503,"entropy_unavailable","");
                    struct json_object *saved=rowerr.status?NULL:iptv_save(db,"channels",id,channel,!existing,&rowerr);
                    if(saved){struct json_object *v=NULL;json_object_object_get_ex(saved,"record",&v);json_object_array_add(items,json_object_get(v));str(out,"id",id);success++;json_object_put(saved);}
                }
            }else if(!existing){/* Preview must find duplicates within the same input too. */
                json_object_array_add(items,clone(channel));
            }
        }
        if(rowerr.status){str(out,"action","error");str(out,"error",rowerr.code);str(out,"field",rowerr.field);}
        json_object_array_add(outcomes,out);json_object_put(channel);
    }
    json_object_object_add(result,"rows",outcomes);json_object_object_add(result,"persisted",json_object_new_boolean(commit));
    json_object_object_add(result,"base_revision",json_object_new_int(base));json_object_object_add(result,"revision",json_object_new_int(iptv_revision(db)));
    json_object_object_add(result,"saved",json_object_new_int(success));str(result,"mode",!strcmp(format,"xlsx")?"per_row":"external");
    json_object_put(catalog);json_object_put(groups);json_object_put(rows);return result;
}
static struct json_object *reorder(sqlite3 *db,struct json_object *body,struct iptv_error *e)
{
    const char *kind=iptv_string(body,"kind");struct json_object *ids=NULL;
    if((strcmp(kind,"channels")&&strcmp(kind,"categories"))||!json_object_object_get_ex(body,"ids",&ids)||!json_object_is_type(ids,json_type_array))return iptv_fail(e,400,"invalid_parameter","ids");
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return iptv_fail(e,409,"config_busy","");
    struct json_object *catalog=iptv_list(db,kind,e),*items=NULL,*result=NULL;sqlite3_stmt *s=NULL;
    if(!catalog)goto out;
    json_object_object_get_ex(catalog,"items",&items);
    if(iptv_integer(body,"if_revision",-1)!=iptv_revision(db)){iptv_fail(e,409,"revision_conflict","if_revision");goto out;}
    if(json_object_array_length(ids)!=json_object_array_length(items)){iptv_fail(e,409,"reorder_set_changed","ids");goto out;}
    for(size_t i=0;i<json_object_array_length(ids);i++){
        struct json_object *v=json_object_array_get_idx(ids,i);const char *id=json_object_get_string(v);
        if(!json_object_is_type(v,json_type_string)||!lookup(items,"id",id)){iptv_fail(e,400,"invalid_parameter","ids");goto out;}
        for(size_t j=0;j<i;j++)if(!strcmp(id,json_object_get_string(json_object_array_get_idx(ids,j)))){iptv_fail(e,400,"duplicate_id","ids");goto out;}
    }
    if(sqlite3_prepare_v2(db,"UPDATE iptv_record SET body=json_set(body,'$.position',?1,'$.revision',revision+1),revision=revision+1 WHERE kind=?2 AND id=?3",-1,&s,NULL)!=SQLITE_OK)goto bad;
    for(size_t i=0;i<json_object_array_length(ids);i++){
        sqlite3_reset(s);sqlite3_bind_int(s,1,(int)i);sqlite3_bind_text(s,2,kind,-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,3,json_object_get_string(json_object_array_get_idx(ids,i)),-1,SQLITE_TRANSIENT);
        if(sqlite3_step(s)!=SQLITE_DONE)goto bad;
    }
    if(sqlite3_exec(db,"UPDATE iptv_meta SET revision=revision+1 WHERE id=1;COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto bad;
    result=json_object_new_object();json_object_object_add(result,"persisted",json_object_new_boolean(1));json_object_object_add(result,"revision",json_object_new_int(iptv_revision(db)));goto out;
bad:iptv_fail(e,503,"config_db_unavailable","");
out:sqlite3_finalize(s);if(!sqlite3_get_autocommit(db))sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);if(catalog)json_object_put(catalog);return result;
}
static void csv_cell(FILE *f,const char *value)
{
    fputc('"',f);if(*value&&strchr("=+-@",*value))fputc('\'',f);
    for(const char *p=value;*p;p++){if(*p=='"')fputc('"',f);fputc(*p,f);}fputc('"',f);
}
static struct json_object *viewers_csv(sqlite3 *db,struct iptv_error *e)
{
    struct json_object *list=iptv_list(db,"viewers",e),*items=NULL;if(!list)return NULL;
    json_object_object_get_ex(list,"items",&items);char *text=NULL;size_t size=0;FILE *f=open_memstream(&text,&size);
    if(!f){json_object_put(list);return iptv_fail(e,503,"out_of_memory","");}
    const char *keys[]={"name","principal_id","enabled","expires_at","all_categories","category_ids"};
    fputs("name,principal_id,enabled,expires_at,all_categories,category_ids\r\n",f);
    for(size_t i=0;i<json_object_array_length(items);i++){
        struct json_object *row=json_object_array_get_idx(items,i);
        for(int j=0;j<6;j++){struct json_object *v=NULL;json_object_object_get_ex(row,keys[j],&v);if(j)fputc(',',f);csv_cell(f,v?json_object_get_string(v):"");}fputs("\r\n",f);
    }
    fclose(f);json_object_put(list);struct json_object *out=json_object_new_object();str(out,"text",text);str(out,"format","csv");free(text);return out;
}
static struct json_object *batch(sqlite3 *db,const char *kind,struct json_object *body,struct iptv_error *e)
{
    const char *operation=iptv_string(body,"operation");struct json_object *rows=NULL,*patch=NULL;
    if((strcmp(kind,"channels")&&strcmp(kind,"viewers"))||
       (strcmp(operation,"create")&&strcmp(operation,"update")&&strcmp(operation,"delete"))||
       !json_object_object_get_ex(body,"rows",&rows)||!json_object_is_type(rows,json_type_array)||
       !json_object_array_length(rows)||json_object_array_length(rows)>200)return iptv_fail(e,400,"invalid_parameter","rows");
    json_object_object_get_ex(body,"patch",&patch);
    struct json_object *out=json_object_new_object(),*results=json_object_new_array();int saved=0;
    for(size_t i=0;i<json_object_array_length(rows);i++){
        struct json_object *row=json_object_array_get_idx(rows,i),*payload=NULL,*result=NULL,*item=json_object_new_object();struct iptv_error failure={0};
        const char *id=iptv_string(row,"id");char generated[49];
        if(!strcmp(operation,"create")){
            if(iptv_id(generated,sizeof(generated)))iptv_fail(&failure,503,"entropy_unavailable","");
            else{payload=json_tokener_parse(json_object_to_json_string(row));id=generated;result=iptv_save(db,kind,id,payload,1,&failure);}
        }else if(!iptv_valid_id(id))iptv_fail(&failure,400,"invalid_parameter","id");
        else{
            payload=patch&&json_object_is_type(patch,json_type_object)?json_tokener_parse(json_object_to_json_string(patch)):json_object_new_object();
            json_object_object_add(payload,"if_revision",json_object_new_int(iptv_integer(row,"if_revision",-1)));
            if(!strcmp(operation,"delete")){json_object_put(payload);payload=json_object_new_object();json_object_object_add(payload,"if_revision",json_object_new_int(iptv_integer(row,"if_revision",-1)));result=iptv_remove(db,kind,id,payload,&failure);}
            else result=iptv_save(db,kind,id,payload,0,&failure);
        }
        json_object_object_add(item,"index",json_object_new_int(i));str(item,"id",id);
        json_object_object_add(item,"saved",json_object_new_boolean(result!=NULL));
        if(result){saved++;json_object_object_add(item,"result",result);}else{str(item,"error",failure.code);str(item,"field",failure.field);}
        json_object_array_add(results,item);if(payload)json_object_put(payload);
    }
    json_object_object_add(out,"items",results);json_object_object_add(out,"saved",json_object_new_int(saved));return out;
}
struct json_object *iptv_catalog_request(sqlite3 *db,const char *method,const char *path,struct json_object *body,struct iptv_error *e)
{
    if(!strcmp(method,"GET")&&!strcmp(path,"exports/viewers.csv"))return viewers_csv(db,e);
    if(!strcmp(method,"POST")&&(!strcmp(path,"channels/batch")||!strcmp(path,"viewers/batch")))return batch(db,path[0]=='c'?"channels":"viewers",body,e);
    if(!strcmp(method,"GET")&&(!strcmp(path,"exports/xlsx")||!strcmp(path,"exports/template")))return iptv_workbook_write(db,!strcmp(path,"exports/template"),e);
    if(!strncmp(path,"imports/",8)&&!strcmp(method,"POST"))return imports(db,path,body,e);
    if(!strcmp(path,"playlist/reorder")&&!strcmp(method,"PUT"))return reorder(db,body,e);
    if(!strcmp(path,"exports/m3u")&&!strcmp(method,"GET")){
        struct json_object *list=iptv_list(db,"channels",e),*items=NULL;if(!list)return NULL;
        json_object_object_get_ex(list,"items",&items);char *text=NULL;size_t length=0;FILE *f=open_memstream(&text,&length);
        if(!f){json_object_put(list);return iptv_fail(e,503,"out_of_memory","");}
        fputs("#EXTM3U\n",f);int omitted=0,secrets=0;
        for(size_t i=0;i<json_object_array_length(items);i++){
            struct json_object *c=json_object_array_get_idx(items,i);
            if(strcmp(iptv_string(c,"mode"),"external")||!iptv_channel_enabled(db,c)){omitted++;continue;}
            if(iptv_integer(c,"has_access_url",0)){secrets++;continue;}
            fprintf(f,"#EXTINF:-1,%s\n%s\n",iptv_string(c,"name"),iptv_string(c,"source_url"));
        }
        fclose(f);struct json_object *result=json_object_new_object();str(result,"text",text);str(result,"format","m3u");
        json_object_object_add(result,"omitted_credential_sources",json_object_new_int(secrets));
        json_object_object_add(result,"omitted_managed_or_disabled",json_object_new_int(omitted));free(text);json_object_put(list);return result;
    }
    return iptv_fail(e,404,"resource_not_found","");
}
