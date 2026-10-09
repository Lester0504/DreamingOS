// SPDX-License-Identifier: GPL-2.0-or-later
/* User-scoped records and CAS. This database never contains plaintext credentials. */
#include "tm.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

sqlite3 *tm_db;
struct ac_secrets *tm_secrets;
pthread_mutex_t tm_store_lock=PTHREAD_MUTEX_INITIALIZER;

static sqlite3_stmt *prepare(const char *sql) {
    sqlite3_stmt *st=NULL;
    return sqlite3_prepare_v2(tm_db,sql,-1,&st,NULL)==SQLITE_OK?st:NULL;
}

int tm_store_open(const char *path,const char *key) {
    if(sqlite3_open_v2(path,&tm_db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,NULL)!=SQLITE_OK)return -1;
    chmod(path,0600);sqlite3_busy_timeout(tm_db,3000);
    if(sqlite3_exec(tm_db,"PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS records(owner TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,doc TEXT NOT NULL,PRIMARY KEY(owner,kind,id)); CREATE TABLE IF NOT EXISTS host_keys(owner TEXT,address TEXT,port INTEGER,fingerprint TEXT,PRIMARY KEY(owner,address,port));",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    if(ac_secrets_schema_init(tm_db)!=AC_SECRETS_OK)return -1;
    /* Reuse the installed protected key; provisioning/rotation is not a side effect of opening this App. */
    ac_secrets_open(tm_db,key,&tm_secrets);
#if defined(TM_TESTING) && defined(AC_SECRETS_TESTING)
    if (!tm_secrets) {
        unsigned char bytes[AC_SECRET_KEY_BYTES];
        FILE *fixture=fopen(key,"rb");
        if(fixture){if(fread(bytes,1,sizeof(bytes),fixture)==sizeof(bytes))ac_secrets_open_with_key(tm_db,bytes,&tm_secrets);fclose(fixture);memset(bytes,0,sizeof(bytes));}
    }
#endif
    return 0;
}

J *tm_defaults(void) {
    return json_tokener_parse("{\"font_family\":\"monospace\",\"font_size\":14,\"cursor_style\":\"block\",\"cursor_blink\":true,\"scrollback\":5000,\"right_click_paste\":false,\"save_hosts_default\":false,\"follow_directory\":false,\"show_hidden\":false,\"color_scheme\":\"system\",\"baud_rates\":[9600,19200,38400,57600,115200]}");
}

static J *record(const char *owner,const char *kind,const char *id) {
    sqlite3_stmt *st=prepare("SELECT revision,doc FROM records WHERE owner=? AND kind=? AND id=?");
    if(!st)return NULL;
    sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,kind,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,id,-1,SQLITE_TRANSIENT);
    J *j=NULL;
    if(sqlite3_step(st)==SQLITE_ROW){j=json_tokener_parse((const char *)sqlite3_column_text(st,1));if(j){tm_number(j,"revision",sqlite3_column_int64(st,0));tm_string(j,"id",id);}}
    sqlite3_finalize(st);return j;
}

static int save_record(const char *owner,const char *kind,const char *id,int64_t rev,J *j) {
    sqlite3_stmt *st=prepare("INSERT INTO records(owner,kind,id,revision,doc) VALUES(?,?,?,?,?) ON CONFLICT(owner,kind,id) DO UPDATE SET revision=excluded.revision,doc=excluded.doc");
    if(!st)return -1;
    sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,kind,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,4,rev);sqlite3_bind_text(st,5,json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    int rc=sqlite3_step(st);sqlite3_finalize(st);return rc==SQLITE_DONE?0:-1;
}

static void secret_id(char out[256],const char *owner,const char *id) {
    snprintf(out,256,"terminal:%s:%s",owner,id);
}

J *tm_store_host(const char *owner,const char *id,int with_auth) {
    pthread_mutex_lock(&tm_store_lock);J *j=record(owner,"hosts",id);
    if(j&&with_auth&&tm_bool(j,"credential_configured",0)) {
        unsigned char *plain=NULL;size_t len=0;char key[256];secret_id(key,owner,id);
        if(tm_secrets&&ac_secrets_get(tm_secrets,key,tm_int(j,"credential_revision",0),&plain,&len)==AC_SECRETS_OK) {
            struct json_tokener *tok=json_tokener_new();J *auth=json_tokener_parse_ex(tok,(const char *)plain,len);json_tokener_free(tok);
            if(auth)json_object_object_add(j,"auth",auth);ac_secrets_clear(plain,len);
        }
    }
    if(j)json_object_object_del(j,"credential_revision");pthread_mutex_unlock(&tm_store_lock);return j;
}

static int text_valid(const char *s,size_t max) {
    if(!s||strlen(s)>max)return 0;
    for(const unsigned char *p=(const unsigned char *)s;*p;p++)if(*p<32||*p==127)return 0;
    return 1;
}

const char *tm_validate_host(J *j) {
    const char *type=tm_str(j,"type",""),*name=tm_str(j,"name","");
    if(!*name||!text_valid(name,128))return "name";
    if(strcmp(type,"local")&&strcmp(type,"ssh")&&strcmp(type,"telnet")&&strcmp(type,"serial"))return "type";
    if(!text_valid(tm_str(j,"notes",""),2048))return "notes";
    if(!strcmp(type,"ssh")||!strcmp(type,"telnet")) {
        const char *host=tm_str(j,"address","");int64_t port=tm_int(j,"port",!strcmp(type,"ssh")?22:23);
        if(!*host||!text_valid(host,253)||strpbrk(host," /\\\t\r\n"))return "address";
        if(port<1||port>65535)return "port";tm_number(j,"port",port);
        if(!strcmp(type,"ssh")&&(!*tm_str(j,"username","")||!text_valid(tm_str(j,"username",""),128)))return "username";
    }
    if(!strcmp(type,"serial")) {
        const char *device=tm_str(j,"device_id","");if(strncmp(device,"/dev/",5)||!text_valid(device,240)||strstr(device,".."))return "device_id";
        int64_t baud=tm_int(j,"baud_rate",115200),bits=tm_int(j,"data_bits",8),stop=tm_int(j,"stop_bits",1);
        if(baud!=9600&&baud!=19200&&baud!=38400&&baud!=57600&&baud!=115200)return "baud_rate";
        if(bits<5||bits>8)return "data_bits";if(stop!=1&&stop!=2)return "stop_bits";
        const char *parity=tm_str(j,"parity","none"),*flow=tm_str(j,"flow_control","none");
        if(strcmp(parity,"none")&&strcmp(parity,"even")&&strcmp(parity,"odd"))return "parity";
        if(strcmp(flow,"none")&&strcmp(flow,"rtscts")&&strcmp(flow,"xonxoff"))return "flow_control";
        tm_number(j,"baud_rate",baud);tm_number(j,"data_bits",bits);tm_number(j,"stop_bits",stop);tm_string(j,"parity",parity);tm_string(j,"flow_control",flow);
    }
    const char *bs=tm_str(j,"backspace","del");if(strcmp(bs,"del")&&strcmp(bs,"bs"))return "backspace";
    tm_string(j,"backspace",bs);return NULL;
}

static const char *validate_preferences(J *j) {
    int64_t size=tm_int(j,"font_size",14),lines=tm_int(j,"scrollback",5000);
    if(size<10||size>32)return "font_size";if(lines<100||lines>50000)return "scrollback";
    const char *font=tm_str(j,"font_family","monospace");
    if(strcmp(font,"monospace")&&strcmp(font,"Menlo")&&strcmp(font,"Consolas"))return "font_family";
    const char *cur=tm_str(j,"cursor_style","block");if(strcmp(cur,"block")&&strcmp(cur,"underline")&&strcmp(cur,"bar"))return "cursor_style";
    if(strcmp(tm_str(j,"color_scheme","system"),"system"))return "color_scheme";
    J *baud=tm_get(j,"baud_rates");if(!baud||!json_object_is_type(baud,json_type_array)||json_object_array_length(baud)>5)return "baud_rates";
    for(size_t i=0;i<json_object_array_length(baud);i++){int b=json_object_get_int(json_object_array_get_idx(baud,i));if(b!=9600&&b!=19200&&b!=38400&&b!=57600&&b!=115200)return "baud_rates";}
    return NULL;
}

static J *store_locked(const char *method,const char *path,const char *owner,J *body,int *status) {
    char kind[32],id[64]="";const char *slash=strchr(path,'/');size_t n=slash?(size_t)(slash-path):strlen(path);
    if(n>=sizeof(kind))return tm_error(status,404,"not_found","资源不存在");memcpy(kind,path,n);kind[n]=0;
    if(slash)snprintf(id,sizeof(id),"%s",slash+1);
    int prefs=!strcmp(kind,"preferences"),hosts=!strcmp(kind,"hosts"),groups=!strcmp(kind,"groups");
    if(!prefs&&!hosts&&!groups)return tm_error(status,404,"not_found","资源不存在");
    if(prefs)snprintf(id,sizeof(id),"user");
    if(!strcmp(method,"GET")&&!id[0]) {
        J *out=json_object_new_object(),*items=json_object_new_array();sqlite3_stmt *st=prepare("SELECT id,revision,doc FROM records WHERE owner=? AND kind=? ORDER BY json_extract(doc,'$.order'),json_extract(doc,'$.name'),id");
        if(!st){json_object_put(out);json_object_put(items);return tm_error(status,503,"store_unavailable","主机资料不可用");}
        sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,kind,-1,SQLITE_TRANSIENT);
        while(sqlite3_step(st)==SQLITE_ROW){J *j=json_tokener_parse((const char *)sqlite3_column_text(st,2));if(!j)continue;tm_string(j,"id",(const char *)sqlite3_column_text(st,0));tm_number(j,"revision",sqlite3_column_int64(st,1));json_object_object_del(j,"credential_revision");json_object_array_add(items,j);}
        sqlite3_finalize(st);json_object_object_add(out,"items",items);return out;
    }
    J *old=id[0]?record(owner,kind,id):NULL;
    if(prefs&&!old){old=tm_defaults();tm_number(old,"revision",0);}
    if(!strcmp(method,"GET")){if(old)json_object_object_del(old,"credential_revision");return old?old:tm_error(status,404,"not_found","资源不存在");}
    int create=!strcmp(method,"POST")&&!id[0]&&!prefs;
    if(!create&&!old)return tm_error(status,404,"not_found","资源不存在");
    if(!create&&strcmp(method,"PATCH")&&strcmp(method,"DELETE")&&!(prefs&&!strcmp(method,"PUT"))){json_object_put(old);return tm_error(status,405,"method_not_allowed","不支持的操作");}
    if(!create&&tm_int(body,"revision",-1)!=tm_int(old,"revision",0)){json_object_put(old);return tm_error(status,409,"revision_conflict","资料已被另一窗口修改，请保留草稿并重新核对");}
    if(!strcmp(method,"DELETE")) {
        if(groups){sqlite3_stmt *st=prepare("UPDATE records SET doc=json_set(doc,'$.group_id',''),revision=revision+1 WHERE owner=? AND kind='hosts' AND json_extract(doc,'$.group_id')=?");if(!st)goto db_error;sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,id,-1,SQLITE_TRANSIENT);int rc=sqlite3_step(st);sqlite3_finalize(st);if(rc!=SQLITE_DONE)goto db_error;}
        if(hosts&&tm_secrets){char key[256];secret_id(key,owner,id);if(ac_secrets_delete(tm_secrets,key)!=AC_SECRETS_OK)goto db_error;}
        sqlite3_stmt *st=prepare("DELETE FROM records WHERE owner=? AND kind=? AND id=?");if(!st)goto db_error;sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,kind,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,id,-1,SQLITE_TRANSIENT);int rc=sqlite3_step(st);sqlite3_finalize(st);if(rc!=SQLITE_DONE)goto db_error;
        json_object_put(old);J *r=json_object_new_object();tm_boolean(r,"deleted",1);return r;
    }
    if(create)tm_uuid(id);
    J *j=old?tm_copy(old):json_object_new_object();
    const char *host_fields[]={"name","type","address","port","username","group_id","notes","device_id","baud_rate","data_bits","parity","stop_bits","flow_control","backspace",NULL};
    const char *group_fields[]={"name","order",NULL};
    const char *pref_fields[]={"font_family","font_size","cursor_style","cursor_blink","scrollback","right_click_paste","save_hosts_default","follow_directory","show_hidden","color_scheme","baud_rates",NULL};
    const char **fields=hosts?host_fields:groups?group_fields:pref_fields;
    for(int i=0;fields[i];i++){J *v=tm_get(body,fields[i]);if(v)json_object_object_add(j,fields[i],json_object_get(v));}
    const char *bad=hosts?tm_validate_host(j):prefs?validate_preferences(j):!*tm_str(j,"name","")||!text_valid(tm_str(j,"name",""),128)?"name":NULL;
    if(bad){J *err=tm_error(status,422,"invalid_field","字段值不受支持");tm_string(err,"field",bad);json_object_put(j);json_object_put(old);return err;}
    if(hosts&&*tm_str(j,"group_id","")){J *g=record(owner,"groups",tm_str(j,"group_id",""));if(!g){json_object_put(j);json_object_put(old);return tm_error(status,422,"group_not_found","分组不存在");}json_object_put(g);}
    int64_t rev=tm_int(old,"revision",0)+1;
    if(hosts&&tm_get(body,"auth")) {
        J *auth=tm_get(body,"auth");char key[256];secret_id(key,owner,id);
        if(!tm_secrets){json_object_put(j);json_object_put(old);return tm_error(status,503,"credential_store_unavailable","设备受保护凭据存储尚未就绪；可使用临时连接");}
        if(tm_bool(auth,"clear",0)){if(ac_secrets_delete(tm_secrets,key)!=AC_SECRETS_OK){json_object_put(j);goto db_error;}tm_boolean(j,"credential_configured",0);json_object_object_del(j,"credential_revision");tm_string(j,"auth_type","");}
        else {
            const char *type=tm_str(auth,"type","");int valid=((!strcmp(type,"password")||!strcmp(type,"keyboard-interactive"))&&*tm_str(auth,"password",""))||(!strcmp(type,"key")&&*tm_str(auth,"private_key",""));
            if(!valid){json_object_put(j);json_object_put(old);return tm_error(status,422,"invalid_auth","凭据替换必须提供非空密码或私钥；留空应省略 auth");}
            const char *secret=json_object_to_json_string_ext(auth,JSON_C_TO_STRING_PLAIN);
            if(strlen(secret)>32768||ac_secrets_put(tm_secrets,key,rev,(const unsigned char *)secret,strlen(secret))!=AC_SECRETS_OK){json_object_put(j);goto db_error;}
            tm_boolean(j,"credential_configured",1);tm_number(j,"credential_revision",rev);tm_string(j,"auth_type",type);
        }
    }
    tm_string(j,"id",id);tm_string(j,"owner",owner);tm_number(j,"revision",rev);
    if(save_record(owner,kind,id,rev,j)){json_object_put(j);goto db_error;}
    json_object_object_del(j,"credential_revision");json_object_put(old);*status=create?201:200;return j;
db_error:
    json_object_put(old);return tm_error(status,503,"store_unavailable","保存失败，原资料未改变");
}

J *tm_store_route(const char *method,const char *path,const char *owner,J *body,int *status) {
    pthread_mutex_lock(&tm_store_lock);
    int write=strcmp(method,"GET")!=0;
    if(write&&sqlite3_exec(tm_db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK){pthread_mutex_unlock(&tm_store_lock);return tm_error(status,503,"store_busy","资料正在保存，请稍后重试");}
    J *r=store_locked(method,path,owner,body,status);
    if(write&&sqlite3_exec(tm_db,*status<400?"COMMIT":"ROLLBACK",NULL,NULL,NULL)!=SQLITE_OK){json_object_put(r);sqlite3_exec(tm_db,"ROLLBACK",NULL,NULL,NULL);r=tm_error(status,503,"store_unavailable","保存未完成");}
    pthread_mutex_unlock(&tm_store_lock);return r;
}

int tm_known_key(const char *owner,const char *address,int port,char out[96]) {
    pthread_mutex_lock(&tm_store_lock);sqlite3_stmt *st=prepare("SELECT fingerprint FROM host_keys WHERE owner=? AND address=? AND port=?");int found=0;
    if(st){sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,address,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,port);if(sqlite3_step(st)==SQLITE_ROW){snprintf(out,96,"%s",sqlite3_column_text(st,0));found=1;}sqlite3_finalize(st);}pthread_mutex_unlock(&tm_store_lock);return found;
}
int tm_trust_key(const char *owner,const char *address,int port,const char *old,const char *fingerprint) {
    pthread_mutex_lock(&tm_store_lock);sqlite3_stmt *st=prepare("INSERT INTO host_keys(owner,address,port,fingerprint) SELECT ?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM host_keys WHERE owner=? AND address=? AND port=?) ON CONFLICT(owner,address,port) DO NOTHING");int rc=-1;
    /* Changed keys cannot be overwritten by a first-use confirmation. */
    if(st&&!*old){sqlite3_bind_text(st,1,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,address,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,port);sqlite3_bind_text(st,4,fingerprint,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,address,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,7,port);if(sqlite3_step(st)==SQLITE_DONE&&sqlite3_changes(tm_db))rc=0;}sqlite3_finalize(st);pthread_mutex_unlock(&tm_store_lock);return rc;
}
void tm_host_success(const char *owner,const char *id) {
    if(!*id)return;pthread_mutex_lock(&tm_store_lock);sqlite3_stmt *st=prepare("UPDATE records SET doc=json_set(doc,'$.last_connected_at',?) WHERE owner=? AND kind='hosts' AND id=?");
    if(st){sqlite3_bind_int64(st,1,tm_now());sqlite3_bind_text(st,2,owner,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,id,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}pthread_mutex_unlock(&tm_store_lock);
}
