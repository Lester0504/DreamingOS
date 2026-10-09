// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef API_APPSTORE_NETWORK_H
#define API_APPSTORE_NETWORK_H
#include <json-c/json.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

static inline void appstore_network_identity(const char *id, char iface[16], char zone[20])
{
    unsigned char digest[32]; unsigned int n=0; char hex[11];
    EVP_Digest(id,strlen(id),digest,&n,EVP_sha256(),NULL);
    for(int i=0;i<5;i++) snprintf(hex+i*2,3,"%02x",digest[i]);
    snprintf(iface,16,"da%s",hex); snprintf(zone,20,"dapp_%s",hex);
}
static inline int appstore_manifest_tun(struct json_object *mf)
{
    struct json_object *requires=NULL,*caps=NULL;
    if(!mf || !json_object_object_get_ex(mf,"requires",&requires) ||
       !json_object_object_get_ex(requires,"capabilities",&caps) ||
       !json_object_is_type(caps,json_type_array)) return 0;
    for(size_t i=0;i<json_object_array_length(caps);i++) {
        struct json_object *v=json_object_array_get_idx(caps,i);
        if(json_object_is_type(v,json_type_string) && !strcmp(json_object_get_string(v),"tun")) return 1;
    }
    return 0;
}
static inline struct json_object *appstore_network_defaults(void)
{
    struct json_object *p=json_object_new_object();
    const char *keys[]={"toHost","toLan","toWan","exitNode","snat"};
    for(size_t i=0;i<5;i++) json_object_object_add(p,keys[i],json_object_new_boolean(0));
    return p;
}
static inline int appstore_network_validate(struct json_object *p)
{
    if(!json_object_is_type(p,json_type_object) || json_object_object_length(p)!=5) return -1;
    const char *keys[]={"toHost","toLan","toWan","exitNode","snat"};
    for(size_t i=0;i<5;i++) {
        struct json_object *v=NULL;
        if(!json_object_object_get_ex(p,keys[i],&v) || !json_object_is_type(v,json_type_boolean)) return -1;
    }
    return 0;
}
static inline void appstore_network_revision(struct json_object *p, char revision[65])
{
    /* Fixed field order makes the revision independent of a caller's key order. */
    struct json_object *canonical=appstore_network_defaults(),*v=NULL;
    const char *keys[]={"toHost","toLan","toWan","exitNode","snat"};
    for(size_t i=0;i<5;i++) if(json_object_object_get_ex(p,keys[i],&v))
        json_object_object_add(canonical,keys[i],json_object_get(v));
    const char *text=json_object_to_json_string_ext(canonical,JSON_C_TO_STRING_PLAIN);
    unsigned char digest[32];unsigned int n=0;
    EVP_Digest(text,strlen(text),digest,&n,EVP_sha256(),NULL);
    for(int i=0;i<32;i++) snprintf(revision+i*2,3,"%02x",digest[i]);
    json_object_put(canonical);
}
#endif
