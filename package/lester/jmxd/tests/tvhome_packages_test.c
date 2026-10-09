// SPDX-License-Identifier: GPL-2.0-or-later
/* Production package service with a disposable database, disk and signed fixture. */
#include "tvhome/tvhome_packages.h"
#include "tvhome/tvhome_assets.h"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef TVH_DB_PATH
#error Disposable TVH_DB_PATH required
#endif
static int checks;
#define CHECK(c) do{checks++;if(!(c)){fprintf(stderr,"FAIL line %d: %s [%d %s %s]\n",__LINE__,#c,e.http_status,e.code,e.message);exit(1);}}while(0)
int tvhome_ws_count(const char *id){(void)id;return 0;}
int storage_files_open_dir(const char *root,const char *path,int w,char *canonical,size_t n,const char **reason){(void)path;(void)w;if(strcmp(root,"test-disk")){*reason="unknown_root";return -1;}snprintf(canonical,n,"/tmp/hw-tvhome-resume-1004/packages-disk");mkdir(canonical,0700);return open(canonical,O_RDONLY|O_DIRECTORY);}
static struct json_object *parse(const char *s){return json_tokener_parse(s);}
static struct json_object *upload_fixture(const char *path,char **id,struct tvhome_err *e){
 int fd=open(path,O_RDONLY);struct stat st;if(fd<0||fstat(fd,&st))return NULL;
 struct json_object *b=parse("{\"name\":\"Other version\"}");json_object_object_add(b,"size",json_object_new_int64(st.st_size));struct json_object *r=tvhome_package_create(b,e);json_object_put(b);if(!r){close(fd);return NULL;}*id=strdup(tv_str(r,"id"));json_object_put(r);unsigned char buf[65536];int64_t offset=0;ssize_t n;
 while((n=read(fd,buf,sizeof(buf)))>0){r=tvhome_package_chunk(*id,offset,buf,n,e);if(!r){close(fd);return NULL;}json_object_put(r);offset+=n;}close(fd);return tvhome_package_complete(*id,e);
}
static char *activate(const char *device,char **terminal,struct tvhome_err *e){struct json_object *b=json_object_new_object(),*d=json_object_new_object();json_object_object_add(d,"device_id",json_object_new_string(device));json_object_object_add(b,"device",d);struct json_object *r=tvhome_activation_request(b,e);if(!r)return NULL;char *id=strdup(tv_str(r,"id"));json_object_put(r);r=tvhome_activation_decide(id,1,NULL,e);free(id);if(!r)return NULL;*terminal=strdup(tv_str(r,"terminal_id"));struct json_object *a=json_object_new_object();json_object_object_add(a,"code",json_object_new_string(tv_str(r,"activation_code")));json_object_object_add(b,"activation",a);json_object_put(r);r=tvhome_session_create(b,e);json_object_put(b);if(!r)return NULL;char *token=strdup(tv_str(r,"token"));json_object_put(r);return token;}
int main(int argc,char **argv){
 struct tvhome_err e={0};CHECK(argc==3&&!strncmp(TVH_DB_PATH,"/tmp/",5));unlink(TVH_DB_PATH);char *ta,*tb,*token=activate("pkg-a",&ta,&e),*other=activate("pkg-b",&tb,&e);CHECK(token&&other);
 struct json_object *b=parse("{\"root_id\":\"test-disk\",\"path\":\"\"}"),*r=tvhome_assets_storage(b,&e);CHECK(r);json_object_put(b);json_object_put(r);
 r=tvhome_overview(&e);CHECK(r&&json_object_get_boolean(tv_get(tv_get(tv_get(r,"capabilities"),"apps"),"available"))&&!json_object_get_boolean(tv_get(tv_get(tv_get(r,"capabilities"),"live"),"available")));json_object_put(r);
 r=tvhome_themes_list(&e);CHECK(r&&json_object_get_boolean(tv_get(tv_get(tv_get(r,"capabilities"),"apps"),"permitted"))&&!json_object_get_boolean(tv_get(tv_get(tv_get(r,"capabilities"),"files"),"available")));json_object_put(r);
 int input=open(argv[1],O_RDONLY);struct stat st;CHECK(input>=0&&!fstat(input,&st));b=parse("{\"name\":\"Fixture\"}");json_object_object_add(b,"size",json_object_new_int64(st.st_size));r=tvhome_package_create(b,&e);CHECK(r);char *id=strdup(tv_str(r,"id"));json_object_put(b);json_object_put(r);
 r=tvhome_package_complete(id,&e);CHECK(!r&&e.http_status==409);unsigned char data[1024*1024];int64_t offset=0;ssize_t n;
 while((n=read(input,data,sizeof(data)))>0){r=tvhome_package_chunk(id,offset,data,n,&e);CHECK(r);json_object_put(r);if(!offset){r=tvhome_package_chunk(id,offset,data,n,&e);CHECK(r);json_object_put(r);}offset+=n;}close(input);
 r=tvhome_package_complete(id,&e);CHECK(r&&!strcmp(tv_str(r,"state"),"ready"));struct json_object *meta=json_object_get(tv_get(r,"metadata"));CHECK(tv_num(meta,"version_code")==2);json_object_put(r);
 r=tvhome_assets_get(NULL,&e);CHECK(r&&json_object_array_length(tv_get(r,"assets"))==0);json_object_put(r);
 b=parse("{\"root_id\":\"test-disk\",\"path\":\"other\"}");r=tvhome_assets_storage(b,&e);CHECK(!r&&e.http_status==409);json_object_put(b);
 b=parse("{\"expected_revision\":1,\"policy\":{\"enabled\":true,\"forced\":false,\"recommended\":true,\"category\":\"Test\",\"min_version_code\":0,\"target\":{\"mode\":\"terminals\",\"ids\":[]}}}");json_object_array_add(tv_get(tv_get(tv_get(b,"policy"),"target"),"ids"),json_object_new_string(ta));r=tvhome_package_update(id,b,&e);CHECK(r&&tv_num(r,"revision")==2);json_object_put(r);r=tvhome_package_update(id,b,&e);CHECK(!r&&e.http_status==409);
 int64_t size;CHECK(tvhome_package_open(id,token,&size,&e)<0&&e.http_status==403);
 r=tvhome_packages_check(other,NULL,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==0);json_object_put(r);
 struct json_object *inventory=parse("{\"sdk_int\":36,\"supported_abis\":[\"arm64-v8a\"],\"packages\":[]}"),*installed=parse("{\"installed\":false}");json_object_object_add(installed,"package_name",json_object_get(tv_get(meta,"package_name")));json_object_array_add(tv_get(inventory,"packages"),installed);
 r=tvhome_packages_check(token,inventory,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==1);json_object_put(r);int fd=tvhome_package_open(id,token,&size,&e);CHECK(fd>=0&&size==st.st_size);close(fd);CHECK(tvhome_package_open(id,other,&size,&e)<0&&e.http_status==403);
 json_object_object_add(inventory,"sdk_int",json_object_new_int(1));r=tvhome_packages_check(token,inventory,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==0&&!strcmp(tv_str(json_object_array_get_idx(tv_get(r,"rejected"),0),"reason"),"sdk_incompatible"));json_object_put(r);CHECK(tvhome_package_open(id,token,&size,&e)<0);json_object_object_add(inventory,"sdk_int",json_object_new_int(36));
 json_object_object_add(inventory,"supported_abis",parse("[\"armeabi-v7a\"]"));r=tvhome_packages_check(token,inventory,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==0&&!strcmp(tv_str(json_object_array_get_idx(tv_get(r,"rejected"),0),"reason"),"abi_incompatible"));json_object_put(r);CHECK(tvhome_package_open(id,token,&size,&e)<0);json_object_object_add(inventory,"supported_abis",parse("[\"arm64-v8a\"]"));
 json_object_object_add(installed,"installed",json_object_new_boolean(1));json_object_object_add(installed,"version_code",json_object_new_int(1));json_object_object_add(installed,"signer_sha256",parse("[\"0000000000000000000000000000000000000000000000000000000000000000\"]"));r=tvhome_packages_check(token,inventory,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==0&&!strcmp(tv_str(json_object_array_get_idx(tv_get(r,"rejected"),0),"reason"),"signature_mismatch"));json_object_put(r);
 json_object_object_add(installed,"signer_sha256",json_object_get(tv_get(meta,"signer_sha256")));r=tvhome_packages_check(token,inventory,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==1);json_object_put(r);
 json_object_object_add(b,"expected_revision",json_object_new_int(2));json_object_object_add(tv_get(b,"policy"),"min_version_code",json_object_new_int(2));r=tvhome_package_update(id,b,&e);CHECK(r);json_object_put(r);r=tvhome_packages_check(token,inventory,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==0&&!strcmp(tv_str(json_object_array_get_idx(tv_get(r,"rejected"),0),"reason"),"minimum_start_version"));json_object_put(r);
 json_object_object_add(b,"expected_revision",json_object_new_int(3));json_object_object_add(tv_get(b,"policy"),"min_version_code",json_object_new_int(0));r=tvhome_package_update(id,b,&e);CHECK(r);json_object_put(r);
 char *duplicate=NULL;r=upload_fixture(argv[1],&duplicate,&e);CHECK(!r&&e.http_status==409&&!strcmp(e.code,"package_version_exists"));r=tvhome_package_delete(duplicate,&e);CHECK(r);json_object_put(r);free(duplicate);
 char *newer=NULL;r=upload_fixture(argv[2],&newer,&e);CHECK(r&&tv_num(tv_get(r,"metadata"),"version_code")==3);json_object_put(r);
 struct json_object *policy=parse(tv_json(b));json_object_object_add(policy,"expected_revision",json_object_new_int(1));r=tvhome_package_update(newer,policy,&e);CHECK(r);json_object_put(r);
 r=tvhome_packages_check(token,inventory,&e);CHECK(r&&json_object_array_length(tv_get(r,"packages"))==1&&!strcmp(tv_str(json_object_array_get_idx(tv_get(r,"packages"),0),"id"),newer));json_object_put(r);CHECK(tvhome_package_open(id,token,&size,&e)<0&&e.http_status==403);fd=tvhome_package_open(newer,token,&size,&e);CHECK(fd>=0);close(fd);
 json_object_object_add(policy,"expected_revision",json_object_new_int(2));json_object_object_add(tv_get(policy,"policy"),"enabled",json_object_new_boolean(0));r=tvhome_package_update(newer,policy,&e);CHECK(r);json_object_put(r);r=tvhome_package_delete(newer,&e);CHECK(r);json_object_put(r);json_object_put(policy);free(newer);
 struct json_object *result=parse("{\"attempt_id\":\"attempt-one\",\"stage\":\"downloaded\"}");r=tvhome_package_result(token,id,result,&e);CHECK(r);json_object_put(r);json_object_object_add(result,"stage",json_object_new_string("installed"));r=tvhome_package_result(token,id,result,&e);CHECK(!r&&e.http_status==409);
 struct json_object *actual=json_object_get(installed);json_object_object_add(actual,"version_code",json_object_new_int(2));json_object_object_add(result,"actual",actual);r=tvhome_package_result(token,id,result,&e);CHECK(r);json_object_put(r);json_object_object_add(result,"stage",json_object_new_string("downloaded"));r=tvhome_package_result(token,id,result,&e);CHECK(r&&!strcmp(tv_str(r,"stage"),"installed"));json_object_put(r);
 r=tvhome_package_delete(id,&e);CHECK(!r&&e.http_status==409);json_object_object_add(b,"expected_revision",json_object_new_int(4));json_object_object_add(tv_get(b,"policy"),"enabled",json_object_new_boolean(0));r=tvhome_package_update(id,b,&e);CHECK(r);json_object_put(r);CHECK(tvhome_package_open(id,token,&size,&e)<0&&e.http_status==403);
 r=tvhome_packages_get(id,&e);CHECK(r&&json_object_array_length(tv_get(r,"results"))==1);json_object_put(r);r=tvhome_package_delete(id,&e);CHECK(r);json_object_put(r);
 json_object_put(b);json_object_put(inventory);json_object_put(result);json_object_put(meta);free(id);free(ta);free(tb);free(token);free(other);
 printf("PASS %d checks: signed upload, immutability, scoped catalog/download, SDK/signature/minimum version, revision, pause, install evidence and dedupe\n",checks);return 0;
}
