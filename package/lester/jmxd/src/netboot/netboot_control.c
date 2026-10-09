// SPDX-License-Identifier: GPL-2.0-or-later
#include "netboot_internal.h"
#include <errno.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t snapshot_lock=PTHREAD_MUTEX_INITIALIZER;
static struct json_object *snapshot;
struct json_object *nb_config_snapshot(void)
{
    pthread_mutex_lock(&snapshot_lock);struct json_object *copy=nb_clone(snapshot);
    pthread_mutex_unlock(&snapshot_lock);return copy;
}
void nb_config_publish(struct json_object *config)
{
    pthread_mutex_lock(&snapshot_lock);
    if(snapshot)json_object_put(snapshot);snapshot=nb_clone(config);
    pthread_mutex_unlock(&snapshot_lock);
}
static struct json_object *settings_public(struct json_object *cfg)
{
    struct json_object *s=nb_clone(nb_value(cfg,"settings"));
    nb_flag(s,"has_menu_password",*nb_string(s,"password_hash")!=0);
    json_object_object_del(s,"password_hash");json_object_object_del(s,"password_salt");
    nb_int(s,"revision",nb_number(cfg,"revision"));return s;
}
static int field_type(struct json_object *o,const char *key,enum json_type type)
{ struct json_object *v=nb_value(o,key);return !v || json_object_is_type(v,type); }
static const char *settings_merge(struct json_object *cfg,struct json_object *patch)
{
    struct json_object *s=nb_value(cfg,"settings"),*v;
    const char *booleans[]={"enabled","allow_unknown",NULL};
    const char *numbers[]={"http_port","menu_timeout",NULL};
    for(int i=0;booleans[i];i++) {
        if(!field_type(patch,booleans[i],json_type_boolean))return booleans[i];
        if((v=nb_value(patch,booleans[i])))json_object_object_add(s,booleans[i],nb_clone(v));
    }
    for(int i=0;numbers[i];i++) {
        if(!field_type(patch,numbers[i],json_type_int))return numbers[i];
        if((v=nb_value(patch,numbers[i])))json_object_object_add(s,numbers[i],nb_clone(v));
    }
    if(nb_number(s,"http_port")<1024||nb_number(s,"http_port")>65535)return "http_port";
    if(nb_number(s,"menu_timeout")<0||nb_number(s,"menu_timeout")>600)return "menu_timeout";
    if(!field_type(patch,"interface_ids",json_type_array))return "interface_ids";
    if((v=nb_value(patch,"interface_ids"))) {
        for(size_t i=0;i<json_object_array_length(v);i++) {
            struct json_object *id=json_object_array_get_idx(v,i);
            if(!json_object_is_type(id,json_type_string)||!nb_id_valid(json_object_get_string(id)))return "interface_ids";
            for(size_t j=0;j<i;j++)if(!strcmp(json_object_get_string(id),json_object_get_string(json_object_array_get_idx(v,j))))return "interface_ids";
        }
        json_object_object_add(s,"interface_ids",nb_clone(v));
    }
    if(!field_type(patch,"default_image_id",json_type_string))return "default_image_id";
    if((v=nb_value(patch,"default_image_id"))) {
        const char *id=json_object_get_string(v);
        if(*id&&!nb_find(nb_value(cfg,"images"),id))return "default_image_id";
        nb_text(s,"default_image_id",id);
    }
    if(!field_type(patch,"menu_password",json_type_string))return "menu_password";
    if((v=nb_value(patch,"menu_password"))&&nb_password_set(s,json_object_get_string(v)))return "menu_password";
    return NULL;
}
static struct json_object *clients_public(struct json_object *cfg)
{
    struct json_object *items=nb_clone(nb_value(cfg,"clients")),*observed=nb_observed_clients();
    for(size_t i=0;i<json_object_array_length(observed);i++) {
        struct json_object *entry=json_object_array_get_idx(observed,i),*saved=nb_find(items,nb_string(entry,"id"));
        if(!saved)json_object_array_add(items,nb_clone(entry));
        else {
            const char *keys[]={"last_seen","ip","arch","platform",NULL};
            for(int k=0;keys[k];k++)if(nb_value(entry,keys[k]))json_object_object_add(saved,keys[k],nb_clone(nb_value(entry,keys[k])));
        }
    }
    json_object_put(observed);return items;
}
static struct json_object *list_data(struct json_object *cfg,const char *resource)
{
    struct json_object *d=json_object_new_object(),*items;
    if(!strcmp(resource,"clients"))items=clients_public(cfg);
    else {
        items=nb_clone(nb_value(cfg,"images"));
        for(size_t i=0;i<json_object_array_length(items);i++) {
            struct json_object *image=json_object_array_get_idx(items,i);
            nb_image_observe(image);
            nb_flag(image,"global_default",!strcmp(nb_string(image,"id"),nb_string(nb_value(cfg,"settings"),"default_image_id")));
            int references=0;struct json_object *clients=nb_value(cfg,"clients");
            for(size_t j=0;j<json_object_array_length(clients);j++)
                references+=!strcmp(nb_string(image,"id"),nb_string(json_object_array_get_idx(clients,j),"default_image_id"));
            nb_int(image,"client_references",references);nb_flag(image,"busy",nb_http_busy(nb_string(image,"id")));
        }
    }
    json_object_object_add(d,"items",items);nb_int(d,"revision",nb_number(cfg,"revision"));return d;
}
static void make_id(char id[32])
{
    unsigned char random[12];if(RAND_bytes(random,sizeof random)!=1){id[0]=0;return;}
    strcpy(id,"nb-");for(size_t i=0;i<sizeof random;i++)sprintf(id+3+i*2,"%02x",random[i]);
}
static void remove_item(struct json_object *items,const char *id)
{
    for(size_t i=0;i<json_object_array_length(items);i++)if(!strcmp(nb_string(json_object_array_get_idx(items,i),"id"),id)) {
        json_object_array_del_idx(items,i,1);return;
    }
}
static struct json_object *image_write(struct json_object *cfg,const char *method,const char *id,const char *action,struct json_object *body)
{
    struct json_object *items=nb_value(cfg,"images"),*image=nb_find(items,id),*out=json_object_new_object();
    if(!strcmp(id,"order")&&!strcmp(method,"PUT")) {
        struct json_object *ids=nb_value(body,"ids"),*ordered=json_object_new_array();
        if(!json_object_is_type(ids,json_type_array)||json_object_array_length(ids)!=json_object_array_length(items))goto bad_order;
        for(size_t i=0;i<json_object_array_length(ids);i++) {
            const char *key=json_object_get_string(json_object_array_get_idx(ids,i));
            struct json_object *entry=key?nb_find(items,key):NULL;
            if(!entry||nb_find(ordered,key))goto bad_order;
            json_object_array_add(ordered,nb_clone(entry));
        }
        json_object_object_add(cfg,"images",ordered);return out;
bad_order:
        json_object_put(ordered);json_object_put(out);return nb_error(400,"invalid_image_order","ids");
    }
    if(!*id&&!strcmp(method,"POST")) {
        const char *path=nb_string(body,"path"),*name=nb_string(body,"name");
        if(json_object_array_length(items)>=NB_MAX_IMAGES || !*name || !nb_safe_text(name,128) || !*path ||
           !nb_safe_text(path,4095) || !nb_safe_text(nb_string(body,"root_id"),47))goto invalid;
        image=json_object_new_object();char new_id[32];make_id(new_id);
        if(!*new_id){json_object_put(image);goto invalid;}
        nb_text(image,"id",new_id);nb_text(image,"name",name);nb_text(image,"path",path);nb_text(image,"root_id",nb_string(body,"root_id"));
        if(!field_type(body,"enabled",json_type_boolean)){json_object_put(image);goto invalid;}
        nb_flag(image,"enabled",nb_value(body,"enabled")?nb_bool(body,"enabled"):1);nb_flag(image,"boot_verified",0);
        nb_image_register(image); /* A missing file is a registered but failed image. */
        if(nb_number(image,"source_inode"))nb_image_probe(image,0,0);
        json_object_array_add(items,image);nb_flag(out,"registered",1);
    } else if(!image) {json_object_put(out);return nb_error(404,"image_not_found","id");}
    else if(!strcmp(method,"DELETE") && !*action) {
        if(nb_image_unmount(id)) {json_object_put(out);return nb_error(409,errno==EBUSY?"image_busy":"unmount_failed","id");}
        remove_item(items,id);nb_flag(out,"iso_preserved",1);nb_text(out,"default_fallback","menu_or_local");return out;
    } else if(!strcmp(method,"POST")&&(!strcmp(action,"redetect")||!strcmp(action,"remount"))) {
        if(nb_http_busy(id)){json_object_put(out);return nb_error(409,"image_busy","id");}
        nb_image_probe(image,!strcmp(action,"remount"),0);
    } else if(!strcmp(method,"PUT")&&!*action) {
        if(!field_type(body,"name",json_type_string)||!field_type(body,"enabled",json_type_boolean))goto invalid;
        if(nb_value(body,"name")) {
            if(!*nb_string(body,"name")||!nb_safe_text(nb_string(body,"name"),128))goto invalid;
            nb_text(image,"name",nb_string(body,"name"));
        }
        if(nb_value(body,"kernel")||nb_value(body,"initrd")||nb_value(body,"args")||nb_value(body,"method")) {
            json_object_put(out);return nb_error(409,"capability_disabled","manual_template");
        }
        if(nb_value(body,"enabled"))nb_flag(image,"enabled",nb_bool(body,"enabled"));
    } else {json_object_put(out);return nb_error(405,"method_not_allowed","method");}
    nb_int(image,"revision",nb_number(cfg,"revision")+1);
    json_object_object_add(out,"image",nb_clone(image));return out;
invalid:
    json_object_put(out);return nb_error(400,"invalid_image","image");
}
static struct json_object *client_write(struct json_object *cfg,const char *method,const char *id,struct json_object *body)
{
    struct json_object *items=nb_value(cfg,"clients"),*client=nb_find(items,id),*out=json_object_new_object();
    char mac[18];
    if(!*id&&!strcmp(method,"POST")) {
        if(nb_mac(nb_string(body,"mac"),mac))goto invalid;
        if(nb_find(items,mac)){json_object_put(out);return nb_error(409,"duplicate_mac","mac");}
        if(json_object_array_length(items)>=NB_MAX_CLIENTS)goto invalid;
        client=json_object_new_object();nb_text(client,"id",mac);nb_text(client,"mac",mac);
        nb_text(client,"source","manual");nb_text(client,"name","");nb_text(client,"default_image_id","");nb_flag(client,"allowed",0);
        json_object_array_add(items,client);
    } else if(!client && !strcmp(method,"PUT") && !nb_mac(id,mac)) {
        if(json_object_array_length(items)>=NB_MAX_CLIENTS)goto invalid;
        client=json_object_new_object();nb_text(client,"id",mac);nb_text(client,"mac",mac);
        nb_text(client,"source","manual");nb_flag(client,"allowed",0);json_object_array_add(items,client);
    } else if(!client){json_object_put(out);return nb_error(404,"client_not_found","id");}
    else if(!strcmp(method,"DELETE")) {remove_item(items,id);nb_text(out,"subsequent_policy","allow_unknown");return out;}
    else if(strcmp(method,"PUT")){json_object_put(out);return nb_error(405,"method_not_allowed","method");}
    if(!field_type(body,"name",json_type_string)||!nb_safe_text(nb_string(body,"name"),128)||
       !field_type(body,"allowed",json_type_boolean)||!field_type(body,"default_image_id",json_type_string))goto invalid;
    if(nb_value(body,"name"))nb_text(client,"name",nb_string(body,"name"));
    if(nb_value(body,"allowed"))nb_flag(client,"allowed",nb_bool(body,"allowed"));
    if(nb_value(body,"default_image_id")) {
        const char *image=nb_string(body,"default_image_id");if(*image&&!nb_find(nb_value(cfg,"images"),image))goto invalid;
        nb_text(client,"default_image_id",image);
    }
    nb_int(client,"revision",nb_number(cfg,"revision")+1);json_object_object_add(out,"client",nb_clone(client));return out;
invalid:
    json_object_put(out);return nb_error(400,"invalid_client","client");
}

struct json_object *jmx_netboot_request(const char *method,const char *resource,const char *id,const char *action,struct json_object *body)
{
    int preflight=!strcmp(resource,"preflight")&&!strcmp(method,"POST");
    int writing=strcmp(method,"GET")&&!preflight;
    sqlite3 *db=nb_open(writing);if(!db)return nb_error(503,"config_authority_unavailable","");
    if(writing && sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return nb_error(409,"config_busy","");
    struct json_object *cfg=nb_load(db),*previous=NULL,*response=NULL,*out=NULL;
    if(!cfg){response=nb_error(503,"config_read_failed","");goto done;}
    if(!writing&&!preflight) {
        if(!strcmp(resource,"settings")&&!*id)out=settings_public(cfg);
        else if(!strcmp(resource,"status")&&!*id)out=nb_runtime_status(cfg);
        else if(!strcmp(resource,"interfaces")&&!*id){out=json_object_new_object();json_object_object_add(out,"items",nb_interfaces(db));}
        else if((!strcmp(resource,"images")||!strcmp(resource,"clients"))&&!*id)out=list_data(cfg,resource);
        else if(!strcmp(resource,"logs")&&!*id)out=nb_events((int)nb_number(body,"offset"),(int)nb_number(body,"limit"));
        else {response=nb_error(404,"resource_not_found","resource");goto done;}
        response=nb_reply(out);goto done;
    }
    if(!json_object_is_type(nb_value(body,"expected_revision"),json_type_int) || nb_number(body,"expected_revision")!=nb_number(cfg,"revision")) {
        response=nb_error(409,"revision_conflict","expected_revision");nb_int(nb_value(response,"data"),"revision",nb_number(cfg,"revision"));goto done;
    }
    if(!preflight && (!json_object_is_type(nb_value(body,"confirm"),json_type_boolean)||!nb_bool(body,"confirm"))) {
        response=nb_error(400,"confirmation_required","confirm");goto done;
    }
    previous=nb_clone(cfg);
    if(preflight||(!strcmp(resource,"settings")&&!strcmp(method,"PUT")&&!*id)) {
        const char *bad=settings_merge(cfg,body);
        if(bad){response=nb_error(400,"invalid_settings",bad);goto done;}
        struct json_object *check=nb_preflight(db,cfg);
        if(preflight){response=nb_reply(check);goto done;}
        if(!nb_bool(body,"apply")){json_object_put(check);response=nb_error(400,"apply_required","apply");goto done;}
        if(!nb_bool(check,"ok")) {
            response=nb_error(409,"preflight_failed","");json_object_object_add(nb_value(response,"data"),"preflight",check);goto done;
        }
        if(strcmp(nb_string(check,"fingerprint"),nb_string(body,"preflight_token"))) {
            response=nb_error(409,"preflight_changed","preflight_token");json_object_object_add(nb_value(response,"data"),"preflight",check);goto done;
        }
        json_object_put(check);out=json_object_new_object();
        if(nb_runtime_apply(cfg,previous,out)) {
            response=nb_error(503,"apply_failed","");json_object_object_add(nb_value(response,"data"),"result",out);goto done;
        }
        nb_flag(out,"applied",1);
    } else if(!strcmp(resource,"images"))out=image_write(cfg,method,id,action,body);
    else if(!strcmp(resource,"clients")&&!*action)out=client_write(cfg,method,id,body);
    else if(!strcmp(resource,"logs")&&!strcmp(method,"DELETE")&&!*id) {
        nb_events_clear();out=json_object_new_object();nb_flag(out,"cleared",1);response=nb_reply(out);goto done;
    } else {response=nb_error(405,"method_not_allowed","method");goto done;}
    if(nb_value(out,"http_status")){response=out;goto done;}
    nb_int(cfg,"revision",nb_number(cfg,"revision")+1);
    if(nb_store(db,cfg) || sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) {
        sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
        if(!strcmp(resource,"settings")) {
            struct json_object *restore=json_object_new_object();nb_runtime_apply(previous,cfg,restore);
            json_object_object_add(out,"restore",restore);
        } else if(!strcmp(resource,"images")&&!*id) {
            nb_flag(out,"resource_cleanup_failed",nb_image_unmount_known(nb_value(out,"image"))!=0);
        }
        response=nb_error(503,"config_commit_failed","");json_object_object_add(nb_value(response,"data"),"result",out);goto done;
    }
    nb_config_publish(cfg);nb_int(out,"revision",nb_number(cfg,"revision"));nb_flag(out,"persisted",1);
    if(!strcmp(resource,"settings"))json_object_object_add(out,"settings",settings_public(cfg));
    response=nb_reply(out);
done:
    if(writing)sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    if(previous)json_object_put(previous);if(cfg)json_object_put(cfg);if(!writing)sqlite3_close(db);return response;
}
