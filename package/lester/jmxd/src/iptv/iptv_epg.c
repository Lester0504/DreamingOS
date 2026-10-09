// SPDX-License-Identifier: GPL-2.0-or-later
/* XMLTV updates are asynchronous, bounded and replace a source atomically.
 * A failed fetch/parse leaves the last successful programme rows intact. */
#define _GNU_SOURCE
#include "iptv.h"
#include <curl/curl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>
#define EPG_LIMIT (8*1024*1024)
static pthread_t epg_thread;
static pthread_mutex_t epg_lock=PTHREAD_MUTEX_INITIALIZER;
static int stopping,started;
struct buffer { char *data;size_t size; };
static void bindstr(sqlite3_stmt *s,int i,const char *v){sqlite3_bind_text(s,i,v,-1,SQLITE_TRANSIENT);}
static size_t collect(char *p,size_t n,size_t size,void *opaque)
{
    struct buffer *b=opaque;size_t len=n*size;
    if(len>EPG_LIMIT-b->size)return 0;
    char *next=realloc(b->data,b->size+len+1);if(!next)return 0;
    b->data=next;memcpy(b->data+b->size,p,len);b->size+=len;b->data[b->size]=0;return len;
}
static int cancelled(void *opaque,curl_off_t a,curl_off_t b,curl_off_t c,curl_off_t d)
{
    (void)opaque;(void)a;(void)b;(void)c;(void)d;
    pthread_mutex_lock(&epg_lock);int value=stopping;pthread_mutex_unlock(&epg_lock);return value;
}
static char *fetch(const char *url,struct iptv_error *e)
{
    struct buffer b={0};CURL *c=curl_easy_init();if(!c)return (iptv_fail(e,503,"fetch_unavailable",""),NULL);
    curl_easy_setopt(c,CURLOPT_URL,url);curl_easy_setopt(c,CURLOPT_PROTOCOLS_STR,"http,https");
    curl_easy_setopt(c,CURLOPT_REDIR_PROTOCOLS_STR,"http,https");curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,1L);curl_easy_setopt(c,CURLOPT_MAXREDIRS,3L);
    curl_easy_setopt(c,CURLOPT_CONNECTTIMEOUT,5L);curl_easy_setopt(c,CURLOPT_TIMEOUT,20L);curl_easy_setopt(c,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(c,CURLOPT_ACCEPT_ENCODING,"");curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,collect);curl_easy_setopt(c,CURLOPT_WRITEDATA,&b);
    curl_easy_setopt(c,CURLOPT_XFERINFOFUNCTION,cancelled);curl_easy_setopt(c,CURLOPT_NOPROGRESS,0L);
    CURLcode rc=curl_easy_perform(c);long status=0;curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&status);curl_easy_cleanup(c);
    if(rc||status<200||status>=300||!b.size){free(b.data);iptv_fail(e,502,rc==CURLE_OPERATION_TIMEDOUT?"source_timeout":"epg_fetch_failed","");return NULL;}
    if(b.size>=2&&(unsigned char)b.data[0]==0x1f&&(unsigned char)b.data[1]==0x8b){
        char *out=malloc(EPG_LIMIT+1);z_stream z={0};if(!out){free(b.data);iptv_fail(e,503,"out_of_memory","");return NULL;}
        z.next_in=(unsigned char*)b.data;z.avail_in=(unsigned)b.size;z.next_out=(unsigned char*)out;z.avail_out=EPG_LIMIT;
        int code=inflateInit2(&z,16+MAX_WBITS);if(code==Z_OK){code=inflate(&z,Z_FINISH);inflateEnd(&z);}free(b.data);
        if(code!=Z_STREAM_END||z.avail_in){free(out);iptv_fail(e,422,"epg_gzip_invalid_or_too_large","");return NULL;}
        out[z.total_out]=0;return out;
    }return b.data;
}
static int64_t xml_time(const char *s)
{
    if(!s||strlen(s)!=20||(s[15]!='+'&&s[15]!='-')||s[14]!=' ')return -1;
    for(int i=0;i<20;i++)if(i!=14&&i!=15&&(s[i]<'0'||s[i]>'9'))return -1;
    struct tm tm={0};char *end=strptime(s,"%Y%m%d%H%M%S",&tm);if(!end||end!=s+14)return -1;
    struct tm check=tm;time_t t=timegm(&tm);if(tm.tm_year!=check.tm_year||tm.tm_mon!=check.tm_mon||tm.tm_mday!=check.tm_mday||tm.tm_hour!=check.tm_hour||tm.tm_min!=check.tm_min||tm.tm_sec!=check.tm_sec)return -1;
    int h=(s[16]-'0')*10+s[17]-'0',m=(s[18]-'0')*10+s[19]-'0';if(h>14||m>59)return -1;
    return (int64_t)t-(s[15]=='+'?1:-1)*(h*3600+m*60);
}
static int parse(sqlite3 *db,const char *source,int expected_revision,const char *text,struct iptv_error *e)
{
    if(strstr(text,"<!DOCTYPE")||strstr(text,"<!ENTITY")){iptv_fail(e,422,"epg_dtd_not_allowed","");return -1;}
    xmlDocPtr doc=xmlReadMemory(text,(int)strlen(text),"epg.xml",NULL,XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    xmlNodePtr root=doc?xmlDocGetRootElement(doc):NULL;
    if(!root||xmlStrcmp(root->name,BAD_CAST "tv")){if(doc)xmlFreeDoc(doc);iptv_fail(e,422,"epg_xml_invalid","");return -1;}
    /* Parse and validate the entire document before opening a write transaction. */
    struct json_object *rows=json_object_new_array();int ok=1;
    for(xmlNodePtr n=root->children;n;n=n->next){
        if(n->type!=XML_ELEMENT_NODE||xmlStrcmp(n->name,BAD_CAST "programme"))continue;
        xmlChar *channel=xmlGetProp(n,BAD_CAST "channel"),*start=xmlGetProp(n,BAD_CAST "start"),*stop=xmlGetProp(n,BAD_CAST "stop");
        int64_t from=xml_time((char*)start),to=xml_time((char*)stop);struct json_object *row=json_object_new_object();
        if(!channel||!channel[0]||xmlStrlen(channel)>192||from<0||to<=from||to-from>7*86400){ok=0;}
        else{
            json_object_object_add(row,"channel",json_object_new_string((char*)channel));
            json_object_object_add(row,"start",json_object_new_int64(from));json_object_object_add(row,"end",json_object_new_int64(to));
            for(xmlNodePtr child=n->children;child;child=child->next){
                if(child->type!=XML_ELEMENT_NODE)continue;
                const char *key=!xmlStrcmp(child->name,BAD_CAST "title")?"title":!xmlStrcmp(child->name,BAD_CAST "desc")?"description":NULL;
                if(key){xmlChar *value=xmlNodeGetContent(child);if(value){if(xmlStrlen(value)>8192)ok=0;else json_object_object_add(row,key,json_object_new_string((char*)value));xmlFree(value);}}
            }
        }
        xmlFree(channel);xmlFree(start);xmlFree(stop);json_object_array_add(rows,row);
        if(!ok||json_object_array_length(rows)>100000){ok=0;break;}
    }
    xmlFreeDoc(doc);
    if(!ok||json_object_array_length(rows)==0){json_object_put(rows);iptv_fail(e,422,"epg_programme_invalid","");return -1;}
    sqlite3_stmt *s=NULL;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)goto bad;
    struct json_object *current=iptv_record(db,"epg-sources",source);
    int valid=current&&iptv_integer(current,"revision",0)==expected_revision&&iptv_integer(current,"enabled",0);
    if(current)json_object_put(current);
    if(!valid){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);json_object_put(rows);iptv_fail(e,409,"epg_source_changed","");return -1;}
    if(sqlite3_prepare_v2(db,"DELETE FROM iptv_programme WHERE source=?",-1,&s,NULL)!=SQLITE_OK)goto bad;
    bindstr(s,1,source);if(sqlite3_step(s)!=SQLITE_DONE)goto bad;sqlite3_finalize(s);s=NULL;
    if(sqlite3_prepare_v2(db,"INSERT INTO iptv_programme(source,channel,start,end,title,description) VALUES(?,?,?,?,?,?)",-1,&s,NULL)!=SQLITE_OK)goto bad;
    for(size_t i=0;i<json_object_array_length(rows);i++){
        struct json_object *row=json_object_array_get_idx(rows,i);sqlite3_reset(s);bindstr(s,1,source);bindstr(s,2,iptv_string(row,"channel"));
        sqlite3_bind_int64(s,3,json_object_get_int64(json_object_object_get(row,"start")));sqlite3_bind_int64(s,4,json_object_get_int64(json_object_object_get(row,"end")));bindstr(s,5,iptv_string(row,"title"));bindstr(s,6,iptv_string(row,"description"));
        if(sqlite3_step(s)!=SQLITE_DONE)goto bad;
    }
    sqlite3_finalize(s);s=NULL;
    if(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto bad;
    int count=(int)json_object_array_length(rows);json_object_put(rows);return count;
bad:
    sqlite3_finalize(s);sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);json_object_put(rows);iptv_fail(e,503,"epg_store_failed","");return -1;
}
static void *worker(void *unused)
{
    (void)unused;
    while(!cancelled(NULL,0,0,0,0)){
        struct timespec delay={1,0};nanosleep(&delay,NULL);
        struct iptv_error e={0};sqlite3 *db=iptv_db(&e);if(!db)continue;
        sqlite3_stmt *s=NULL;char id[97]="";
        if(sqlite3_prepare_v2(db,"SELECT r.id FROM iptv_record r LEFT JOIN iptv_epg_job j ON j.source=r.id WHERE r.kind='epg-sources' AND json_extract(r.body,'$.enabled')=1 AND (j.state='queued' OR j.source IS NULL OR (j.next_run>0 AND j.next_run<=?)) ORDER BY j.next_run LIMIT 1",-1,&s,NULL)==SQLITE_OK){
            sqlite3_bind_int64(s,1,time(NULL));if(sqlite3_step(s)==SQLITE_ROW)snprintf(id,sizeof(id),"%s",sqlite3_column_text(s,0));
        }sqlite3_finalize(s);s=NULL;
        if(!*id){sqlite3_close(db);continue;}
        struct json_object *source=iptv_record(db,"epg-sources",id);if(!source){sqlite3_close(db);continue;}
        if(sqlite3_prepare_v2(db,"INSERT INTO iptv_epg_job(source,state) VALUES(?,'running') ON CONFLICT(source) DO UPDATE SET state='running',error=''",-1,&s,NULL)==SQLITE_OK){bindstr(s,1,id);sqlite3_step(s);}sqlite3_finalize(s);s=NULL;
        char *data=fetch(iptv_string(source,"url"),&e);int count=data?parse(db,id,iptv_integer(source,"revision",0),data,&e):-1;free(data);
        if(sqlite3_prepare_v2(db,"UPDATE iptv_epg_job SET state=?,error=?,last_attempt=?,last_success=CASE WHEN ?<0 THEN last_success ELSE ? END,programmes=CASE WHEN ?<0 THEN programmes ELSE ? END,next_run=? WHERE source=?",-1,&s,NULL)==SQLITE_OK){
            bindstr(s,1,count<0?"failed":"complete");bindstr(s,2,e.code);sqlite3_bind_int64(s,3,time(NULL));sqlite3_bind_int(s,4,count);sqlite3_bind_int64(s,5,time(NULL));sqlite3_bind_int(s,6,count);sqlite3_bind_int(s,7,count);
            sqlite3_bind_int64(s,8,time(NULL)+(count<0?3600:iptv_integer(source,"interval_hours",24)*3600));bindstr(s,9,id);sqlite3_step(s);
        }sqlite3_finalize(s);json_object_put(source);sqlite3_close(db);
    }return NULL;
}
int iptv_epg_start(struct iptv_error *e)
{
    sqlite3 *db=iptv_db(e);if(!db)return -1;
    int rc=sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS iptv_programme(source TEXT NOT NULL,channel TEXT NOT NULL,start INTEGER NOT NULL,end INTEGER NOT NULL,title TEXT NOT NULL,description TEXT NOT NULL);CREATE INDEX IF NOT EXISTS iptv_programme_channel ON iptv_programme(source,channel,start);CREATE TABLE IF NOT EXISTS iptv_epg_job(source TEXT PRIMARY KEY,state TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',last_attempt INTEGER NOT NULL DEFAULT 0,last_success INTEGER NOT NULL DEFAULT 0,programmes INTEGER NOT NULL DEFAULT 0,next_run INTEGER NOT NULL DEFAULT 0);UPDATE iptv_epg_job SET state='interrupted',error='service_restarted' WHERE state='running';",NULL,NULL,NULL);
    sqlite3_close(db);if(rc!=SQLITE_OK){iptv_fail(e,503,"epg_store_failed","");return -1;}
    curl_global_init(CURL_GLOBAL_DEFAULT);stopping=0;
    if(pthread_create(&epg_thread,NULL,worker,NULL)){iptv_fail(e,503,"epg_worker_unavailable","");return -1;}started=1;return 0;
}
void iptv_epg_shutdown(void)
{
    pthread_mutex_lock(&epg_lock);stopping=1;pthread_mutex_unlock(&epg_lock);
    if(started)pthread_join(epg_thread,NULL);
    started=0;
}
struct json_object *iptv_epg_request(sqlite3 *db,const char *method,const char *path,struct json_object *body,struct iptv_error *e)
{
    (void)body;char kind[32],id[97],action[32],extra;int parts=sscanf(path,"%31[^/]/%96[^/]/%31[^/]%c",kind,id,action,&extra);sqlite3_stmt *s=NULL;
    if(!strcmp(path,"epg/jobs")&&!strcmp(method,"GET")){
        struct json_object *o=json_object_new_object(),*items=json_object_new_array();
        if(sqlite3_prepare_v2(db,"SELECT source,state,error,last_attempt,last_success,programmes,next_run FROM iptv_epg_job",-1,&s,NULL)!=SQLITE_OK){json_object_put(o);json_object_put(items);return iptv_fail(e,503,"epg_store_failed","");}
        while(sqlite3_step(s)==SQLITE_ROW){struct json_object *row=json_object_new_object();const char *keys[]={"source_id","state","error","last_attempt","last_success","programmes","next_run"};
            for(int i=0;i<7;i++)json_object_object_add(row,keys[i],i<3?json_object_new_string((const char*)sqlite3_column_text(s,i)):json_object_new_int64(sqlite3_column_int64(s,i)));
            json_object_array_add(items,row);}
        sqlite3_finalize(s);json_object_object_add(o,"items",items);return o;
    }
    if(parts==3&&!strcmp(kind,"epg-sources")&&!strcmp(action,"refresh")&&!strcmp(method,"POST")){
        struct json_object *source=iptv_record(db,kind,id);if(!source)return iptv_fail(e,404,"resource_not_found","");
        int enabled=iptv_integer(source,"enabled",0);json_object_put(source);if(!enabled)return iptv_fail(e,409,"epg_source_disabled","");
        if(sqlite3_prepare_v2(db,"INSERT INTO iptv_epg_job(source,state) VALUES(?,'queued') ON CONFLICT(source) DO UPDATE SET state=CASE WHEN state='running' THEN state ELSE 'queued' END",-1,&s,NULL)!=SQLITE_OK)return iptv_fail(e,503,"epg_store_failed","");
        bindstr(s,1,id);int rc=sqlite3_step(s);sqlite3_finalize(s);if(rc!=SQLITE_DONE)return iptv_fail(e,503,"epg_store_failed","");return json_tokener_parse("{\"state\":\"accepted\"}");
    }
    if((parts==2||parts==3)&&!strcmp(kind,"epg")&&!strcmp(method,"GET")){
        int64_t from=time(NULL)-86400,to=time(NULL)+7*86400;
        if(parts==3){
            if(!strcmp(action,"now")){from=time(NULL);to=from+1;}
            else{struct tm date={0};char *end=strptime(action,"%Y-%m-%d",&date);char check[16];
                if(!end||*end)return iptv_fail(e,400,"invalid_date","date");
                from=timegm(&date);strftime(check,sizeof(check),"%Y-%m-%d",&date);
                if(strcmp(check,action))return iptv_fail(e,400,"invalid_date","date");to=from+86400;
            }
        }
        struct json_object *channel=iptv_record(db,"channels",id);if(!channel)return iptv_fail(e,404,"resource_not_found","");
        const char *source=iptv_string(channel,"epg_source_id"),*epg=iptv_string(channel,"epg_id");
        if(!*source||!*epg){json_object_put(channel);return iptv_fail(e,409,"epg_mapping_required","");}
        if(sqlite3_prepare_v2(db,"SELECT start,end,title,description FROM iptv_programme WHERE source=? AND channel=? AND end>? AND start<? ORDER BY start LIMIT 1000",-1,&s,NULL)!=SQLITE_OK){json_object_put(channel);return iptv_fail(e,503,"epg_store_failed","");}
        bindstr(s,1,source);bindstr(s,2,epg);sqlite3_bind_int64(s,3,from);sqlite3_bind_int64(s,4,to);
        struct json_object *o=json_object_new_object(),*items=json_object_new_array();
        while(sqlite3_step(s)==SQLITE_ROW){struct json_object *row=json_object_new_object();json_object_object_add(row,"start",json_object_new_int64(sqlite3_column_int64(s,0)));json_object_object_add(row,"end",json_object_new_int64(sqlite3_column_int64(s,1)));json_object_object_add(row,"title",json_object_new_string((const char*)sqlite3_column_text(s,2)));json_object_object_add(row,"description",json_object_new_string((const char*)sqlite3_column_text(s,3)));struct json_object *ranges=json_object_new_array();sqlite3_stmt *r=NULL;
            if(sqlite3_prepare_v2(db,"SELECT body FROM iptv_record WHERE kind='recordings' AND json_extract(body,'$.channel_id')=? AND json_extract(body,'$.state')='ready' AND json_extract(body,'$.end')>? AND json_extract(body,'$.start')<? ORDER BY json_extract(body,'$.start') LIMIT 100",-1,&r,NULL)==SQLITE_OK){
                bindstr(r,1,id);sqlite3_bind_int64(r,2,sqlite3_column_int64(s,0));sqlite3_bind_int64(r,3,sqlite3_column_int64(s,1));
                while(sqlite3_step(r)==SQLITE_ROW){struct json_object *record=json_tokener_parse((const char*)sqlite3_column_text(r,0));if(!record)continue;
                    struct json_object *range=json_object_new_object();double start=json_object_get_double(json_object_object_get(record,"start")),end=json_object_get_double(json_object_object_get(record,"end"));
                    double programme_start=sqlite3_column_int64(s,0),programme_end=sqlite3_column_int64(s,1),available_start=start>programme_start?start:programme_start,available_end=end<programme_end?end:programme_end;
                    json_object_object_add(range,"recording_id",json_object_new_string(iptv_string(record,"id")));
                    json_object_object_add(range,"start",json_object_new_double(available_start));json_object_object_add(range,"end",json_object_new_double(available_end));
                    json_object_object_add(range,"offset_seconds",json_object_new_double(available_start-start));json_object_array_add(ranges,range);json_object_put(record);
                }
            }sqlite3_finalize(r);
            json_object_object_add(row,"recording_available",json_object_new_boolean(json_object_array_length(ranges)>0));
            json_object_object_add(row,"recordings",ranges);json_object_array_add(items,row);}
        sqlite3_finalize(s);json_object_put(channel);json_object_object_add(o,"items",items);json_object_object_add(o,"server_time",json_object_new_int64(time(NULL)));json_object_object_add(o,"date_timezone",json_object_new_string("UTC"));return o;
    }
    return iptv_fail(e,404,"resource_not_found","");
}
