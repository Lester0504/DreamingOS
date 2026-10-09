// SPDX-License-Identifier: GPL-2.0-or-later
/* Write-only upstream access URLs reuse the existing encrypted secret store.
 * This module never creates or rotates the device key. */
#include "iptv.h"
#include "ac/ac_secrets.h"
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

#ifndef IPTV_SECRET_KEY_PATH
#define IPTV_SECRET_KEY_PATH "/etc/dreamingwrt/ac-secrets.key"
#endif

int iptv_access_validate(struct json_object *channel, struct iptv_error *e)
{
    struct json_object *value=NULL;
    if(json_object_object_get_ex(channel,"access_url",&value)&&!json_object_is_type(value,json_type_string))
        return iptv_fail(e,400,"invalid_parameter","access_url"),-1;
    const char *access=iptv_string(channel,"access_url");
    if(!*access)return 0;
    if(iptv_integer(channel,"clear_access_url",0))
        return iptv_fail(e,400,"source_access_conflict","access_url"),-1;
    if(strlen(access)>2048||strpbrk(access,"\r\n\t "))
        return iptv_fail(e,400,"invalid_parameter","access_url"),-1;
    const char *base=iptv_string(channel,"source_url");
    if(strncmp(base,"http://",7)&&strncmp(base,"https://",8)&&strncmp(base,"rtsp://",7)&&strncmp(base,"rtmp://",7))
        return iptv_fail(e,422,"source_access_protocol_unsupported","access_url"),-1;
    CURLU *url=curl_url();char *public_url=NULL;int valid=0;
    if(url&&!curl_url_set(url,CURLUPART_URL,access,CURLU_NON_SUPPORT_SCHEME)){
        curl_url_set(url,CURLUPART_USER,NULL,0);curl_url_set(url,CURLUPART_PASSWORD,NULL,0);
        curl_url_set(url,CURLUPART_QUERY,NULL,0);curl_url_set(url,CURLUPART_FRAGMENT,NULL,0);
        if(!curl_url_get(url,CURLUPART_URL,&public_url,0))valid=!strcmp(public_url,base);
    }
    curl_free(public_url);curl_url_cleanup(url);
    if(!valid)return iptv_fail(e,422,"source_access_address_mismatch","access_url"),-1;
    return 0;
}

int iptv_access_available(sqlite3 *db)
{
    struct ac_secrets *secrets=NULL;
    int ready=ac_secrets_open(db,IPTV_SECRET_KEY_PATH,&secrets)==AC_SECRETS_OK;
    ac_secrets_close(secrets);return ready;
}

static void secret_id(struct json_object *channel,char id[128])
{snprintf(id,128,"iptv.source:%s",iptv_string(channel,"id"));}

int iptv_access_save(sqlite3 *db,struct json_object *channel,struct json_object *old,struct iptv_error *e)
{
    const char *access=iptv_string(channel,"access_url");
    int clear=iptv_integer(channel,"clear_access_url",0)||
        strcmp(iptv_string(channel,"source_url"),iptv_string(old,"source_url"));
    int had=iptv_integer(old,"has_access_url",0),has=had;
    if(*access|| (clear&&had)){
        char id[128];secret_id(channel,id);struct ac_secrets *secrets=NULL;
        if(ac_secrets_open(db,IPTV_SECRET_KEY_PATH,&secrets)!=AC_SECRETS_OK)
            return iptv_fail(e,503,"source_secret_store_unavailable","access_url"),-1;
        int rc=ac_secrets_schema_init(db);
        if(rc==AC_SECRETS_OK)rc=*access?ac_secrets_put(secrets,id,1,(const unsigned char*)access,strlen(access)):
            ac_secrets_delete(secrets,id);
        ac_secrets_close(secrets);
        if(rc!=AC_SECRETS_OK)return iptv_fail(e,503,"source_secret_store_unavailable","access_url"),-1;
        has=*access!=0;
    }
    json_object_object_del(channel,"access_url");json_object_object_del(channel,"clear_access_url");
    json_object_object_add(channel,"has_access_url",json_object_new_boolean(has));
    return 0;
}

int iptv_access_remove(sqlite3 *db,struct json_object *channel,struct iptv_error *e)
{
    if(!iptv_integer(channel,"has_access_url",0))return 0;
    char id[128];secret_id(channel,id);struct ac_secrets *secrets=NULL;
    if(ac_secrets_open(db,IPTV_SECRET_KEY_PATH,&secrets)!=AC_SECRETS_OK)
        return iptv_fail(e,503,"source_secret_store_unavailable","access_url"),-1;
    int rc=ac_secrets_delete(secrets,id);ac_secrets_close(secrets);
    if(rc!=AC_SECRETS_OK)return iptv_fail(e,503,"source_secret_store_unavailable","access_url"),-1;
    return 0;
}

int iptv_access_resolve(sqlite3 *db,struct json_object *channel,char *out,size_t size,struct iptv_error *e)
{
    const char *draft=iptv_string(channel,"access_url");
    if(*draft){if(iptv_access_validate(channel,e))return -1;
        return snprintf(out,size,"%s",draft)<(int)size?0:-1;}
    if(!iptv_integer(channel,"has_access_url",0))
        return snprintf(out,size,"%s",iptv_string(channel,"source_url"))<(int)size?0:-1;
    char id[128];secret_id(channel,id);struct ac_secrets *secrets=NULL;
    unsigned char *plain=NULL;size_t length=0;
    if(ac_secrets_open(db,IPTV_SECRET_KEY_PATH,&secrets)!=AC_SECRETS_OK)
        return iptv_fail(e,503,"source_secret_store_unavailable","access_url"),-1;
    int rc=ac_secrets_get(secrets,id,1,&plain,&length);ac_secrets_close(secrets);
    if(rc!=AC_SECRETS_OK||!length||length>=size){ac_secrets_clear(plain,length);
        return iptv_fail(e,503,"source_secret_store_unavailable","access_url"),-1;}
    memcpy(out,plain,length);out[length]=0;ac_secrets_clear(plain,length);return 0;
}
