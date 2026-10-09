// SPDX-License-Identifier: GPL-2.0-or-later
/* Local APK policy. dist remains the TVHome release authority. */
#include "tvhome_packages.h"
#include "tvhome_assets.h"
#include "tvhome_ops.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef TVHOME_APK_HELPER
#define TVHOME_APK_HELPER "/usr/libexec/dreamingwrt/tvhome-apk"
#endif
#define APK_LIMIT (512LL*1024*1024)
#define LIBRARY_LIMIT (2LL*1024*1024*1024)
#define SELF_PACKAGE "com.dreamingos.tvhome"
extern char **environ;
static void str(struct json_object *o,const char *k,const char *v){json_object_object_add(o,k,json_object_new_string(v));}
static void num(struct json_object *o,const char *k,int64_t v){json_object_object_add(o,k,json_object_new_int64(v));}
static struct json_object *copy(struct json_object *o){return o?json_tokener_parse(tv_json(o)):NULL;}
static int valid_id(const char *s){if(!s||strlen(s)!=36||strncmp(s,"apk-",4))return 0;for(s+=4;*s;s++)if(!strchr("0123456789abcdef",*s))return 0;return 1;}
static size_t array_length(struct json_object *o){return json_object_is_type(o,json_type_array)?json_object_array_length(o):0;}
static int contains(struct json_object *a,const char *s){for(size_t i=0;i<array_length(a);i++)if(!strcmp(json_object_get_string(json_object_array_get_idx(a,i)),s))return 1;return 0;}
static int signers_equal(struct json_object *a,struct json_object *b){size_t n=array_length(a);if(!n||n!=array_length(b))return 0;for(size_t i=0;i<n;i++)if(!contains(b,json_object_get_string(json_object_array_get_idx(a,i))))return 0;return 1;}
int tvhome_packages_schema(sqlite3 *db)
{
 return tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_package(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,size INTEGER NOT NULL,received INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT 'uploading',metadata TEXT NOT NULL DEFAULT '{}',source TEXT NOT NULL DEFAULT '{}',policy TEXT NOT NULL DEFAULT '{\"enabled\":false,\"target\":{\"mode\":\"terminals\",\"ids\":[]},\"min_version_code\":0,\"forced\":false,\"category\":\"\",\"recommended\":false}',revision INTEGER NOT NULL DEFAULT 0)",0)||
 tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_package_inventory(terminal_id TEXT PRIMARY KEY,body TEXT NOT NULL,updated INTEGER NOT NULL)",0)||
 tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_package_result(package_id TEXT NOT NULL,terminal_id TEXT NOT NULL,body TEXT NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(package_id,terminal_id))",0);
}
/* Fixed executable and argument vector. The child receives only its APK fd and
 * pipes; no admin/TV token or user-controlled shell fragment. */
static struct json_object *helper(const char *mode,const char *channel,int fd,struct tvhome_err *e)
{
 if(access(TVHOME_APK_HELPER,X_OK)){return tvhome_error(e,503,"apk_verifier_unavailable","","APK verification helper is not installed");}
 int p[2];if(pipe(p))return tvhome_error(e,503,"apk_verifier_unavailable","","Cannot start APK verifier");
 posix_spawn_file_actions_t a;posix_spawn_file_actions_init(&a);
 posix_spawn_file_actions_adddup2(&a,p[1],STDOUT_FILENO);
 posix_spawn_file_actions_addopen(&a,STDERR_FILENO,"/dev/null",O_WRONLY,0);
 posix_spawn_file_actions_addclose(&a,p[0]);posix_spawn_file_actions_addclose(&a,p[1]);
 if(fd>=0)posix_spawn_file_actions_adddup2(&a,fd,STDIN_FILENO);
#ifdef __APPLE__
 const char *path="/dev/fd/0";
#else
 const char *path="/proc/self/fd/0";
#endif
 char *args[5]={(char *)TVHOME_APK_HELPER,NULL,NULL,NULL,NULL};
 if(!strcmp(mode,"inspect"))args[1]=(char *)path;
 else{args[1]=(char *)mode;args[2]=(char *)channel;if(fd>=0)args[3]=(char *)path;}
 pid_t pid;int rc=posix_spawn(&pid,TVHOME_APK_HELPER,&a,NULL,args,environ);posix_spawn_file_actions_destroy(&a);close(p[1]);
 if(rc){close(p[0]);return tvhome_error(e,503,"apk_verifier_unavailable","","APK verifier could not start");}
 char out[32768];size_t used=0;int failed=0,status=0;int64_t deadline=tv_now()+180000;
 while(used<sizeof(out)-1){struct pollfd poller={p[0],POLLIN,0};int remain=(int)(deadline-tv_now());if(remain<=0){failed=1;break;}int r=poll(&poller,1,remain);if(r<0&&errno==EINTR)continue;if(r<=0){failed=1;break;}ssize_t n=read(p[0],out+used,sizeof(out)-1-used);if(n==0)break;if(n<0){if(errno==EINTR)continue;failed=1;break;}used+=(size_t)n;}
 if(used==sizeof(out)-1)failed=1;close(p[0]);if(failed)kill(pid,SIGKILL);while(waitpid(pid,&status,0)<0&&errno==EINTR){}
 out[used]=0;struct json_object *o=!failed&&WIFEXITED(status)&&WEXITSTATUS(status)==0?json_tokener_parse(out):NULL;
 if(!json_object_is_type(o,json_type_object)){
  if(o)json_object_put(o);
  /* Source queries never inspect an APK. Keep older helpers' source failures
   * accurate too; exit 3 additionally distinguishes import transport failures. */
  if(!strcmp(mode,"source")||(!strcmp(mode,"import")&&WIFEXITED(status)&&WEXITSTATUS(status)==3))
   return tvhome_error(e,502,"release_source_unavailable","channel","Cannot read or verify the TV release source; check DNS, network and release service");
  return tvhome_error(e,400,"apk_verification_failed","apk","APK signature or manifest verification failed");
 }return o;
}
static struct json_object *read_package(sqlite3 *db,const char *id,int results)
{
 sqlite3_stmt *s=NULL;struct json_object *o=NULL;
 if(sqlite3_prepare_v2(db,"SELECT id,name,kind,size,received,state,metadata,source,policy,revision FROM tvhome_package WHERE id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW){o=json_object_new_object();const char *keys[]={"id","name","kind","size","received","state","metadata","source","policy","revision"};for(int i=0;i<10;i++){if(i==3||i==4||i==9)num(o,keys[i],sqlite3_column_int64(s,i));else if(i>=6&&i<=8)json_object_object_add(o,keys[i],json_tokener_parse(tv_col(s,i)));else str(o,keys[i],tv_col(s,i));}}sqlite3_finalize(s);}
 if(o&&results){struct json_object *r=json_object_new_array();if(sqlite3_prepare_v2(db,"SELECT terminal_id,body,updated FROM tvhome_package_result WHERE package_id=? ORDER BY updated DESC",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);while(sqlite3_step(s)==SQLITE_ROW){struct json_object *v=json_tokener_parse(tv_col(s,1));if(v){str(v,"terminal_id",tv_col(s,0));num(v,"updated_at_ms",sqlite3_column_int64(s,2));json_object_array_add(r,v);}}sqlite3_finalize(s);}json_object_object_add(o,"results",r);}return o;
}
struct json_object *tvhome_packages_get(const char *id,struct tvhome_err *e)
{
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;if(id){struct json_object *o=read_package(db,id,1);sqlite3_close(db);return o?o:tvhome_error(e,404,"resource_not_found","id","APK not found");}
 struct json_object *o=json_object_new_object(),*rows=json_object_new_array();sqlite3_stmt *s=NULL;
 if(sqlite3_prepare_v2(db,"SELECT id FROM tvhome_package ORDER BY rowid DESC",-1,&s,NULL)==SQLITE_OK){while(sqlite3_step(s)==SQLITE_ROW)json_object_array_add(rows,read_package(db,tv_col(s,0),1));sqlite3_finalize(s);}sqlite3_close(db);
 json_object_object_add(o,"packages",rows);json_object_object_add(o,"verifier_available",json_object_new_boolean(access(TVHOME_APK_HELPER,X_OK)==0));num(o,"max_apk_bytes",APK_LIMIT);num(o,"chunk_bytes",TVHOME_ASSET_CHUNK);return o;
}
static struct json_object *create_upload(const char *name,int64_t size,const char *kind,struct tvhome_err *e)
{
 if(!*name||strlen(name)>160||size<1||size>APK_LIMIT)return tvhome_error(e,400,"invalid_parameter","size","APK name and size up to 512 MiB required");
 if(access(TVHOME_APK_HELPER,X_OK))return tvhome_error(e,503,"apk_verifier_unavailable","","APK verification helper is not installed");
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}
 if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}sqlite3_stmt *s=NULL;int64_t used=LIBRARY_LIMIT;
 if(sqlite3_prepare_v2(db,"SELECT (SELECT COALESCE(SUM(size),0) FROM tvhome_asset)+(SELECT COALESCE(SUM(size),0) FROM tvhome_package)",-1,&s,NULL)==SQLITE_OK){if(sqlite3_step(s)==SQLITE_ROW)used=sqlite3_column_int64(s,0);sqlite3_finalize(s);}
 struct statvfs space;if(used+size>LIBRARY_LIMIT||fstatvfs(dir,&space)||(uint64_t)space.f_bavail*space.f_frsize<(uint64_t)size+16*1024*1024){close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,413,"storage_capacity_exceeded","size","APK exceeds library quota or available disk capacity");}
 char id[37]="apk-",part[48],length[32];unsigned char random[16];if(RAND_bytes(random,16)!=1){close(dir);return tv_db_error(db,e);}for(int i=0;i<16;i++)snprintf(id+4+i*2,3,"%02x",random[i]);snprintf(part,sizeof(part),"%s.part",id);
 int fd=openat(dir,part,O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW,0600);if(fd<0){close(dir);return tv_db_error(db,e);}close(fd);snprintf(length,sizeof(length),"%lld",(long long)size);
 if(tv_run(db,"INSERT INTO tvhome_package(id,name,kind,size) VALUES(?,?,?,?)",4,id,name,kind,length)||tv_run(db,"COMMIT",0)){unlinkat(dir,part,0);close(dir);return tv_db_error(db,e);}close(dir);struct json_object *o=read_package(db,id,0);sqlite3_close(db);return o;
}
struct json_object *tvhome_package_create(struct json_object *body,struct tvhome_err *e){return create_upload(tv_str(body,"name"),tv_num(body,"size"),"app",e);}
struct json_object *tvhome_package_chunk(const char *id,int64_t offset,const void *data,size_t len,struct tvhome_err *e)
{
 if(!valid_id(id)||offset<0||!len||len>TVHOME_ASSET_CHUNK)return tvhome_error(e,400,"invalid_chunk","offset","Use an APK ID and byte chunk up to 1 MiB");
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}struct json_object *o=read_package(db,id,0);
 if(!o||strcmp(tv_str(o,"state"),"uploading")||strcmp(tv_str(o,"kind"),"app")||offset>tv_num(o,"received")||offset>tv_num(o,"size")-(int64_t)len){if(o)json_object_put(o);close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"upload_offset_conflict","offset","Read received offset and retry this upload");}
 int64_t received=tv_num(o,"received");json_object_put(o);char part[48],next[32];snprintf(part,sizeof(part),"%s.part",id);int fd=openat(dir,part,O_RDWR|O_NOFOLLOW);close(dir);if(fd<0)return tv_db_error(db,e);
 if(offset<received){void *old=malloc(len);int same=old&&offset+(int64_t)len<=received&&pread(fd,old,len,offset)==(ssize_t)len&&!memcmp(old,data,len);free(old);close(fd);tv_run(db,"ROLLBACK",0);o=same?read_package(db,id,0):NULL;sqlite3_close(db);return o?o:tvhome_error(e,409,"upload_offset_conflict","offset","Retried bytes differ");}
 int rc=pwrite(fd,data,len,offset)!=(ssize_t)len||fdatasync(fd);close(fd);snprintf(next,sizeof(next),"%lld",(long long)offset+len);
 if(rc||tv_run(db,"UPDATE tvhome_package SET received=? WHERE id=?",2,next,id)||tv_run(db,"COMMIT",0))return tv_db_error(db,e);o=read_package(db,id,0);sqlite3_close(db);return o;
}
static int metadata_valid(struct json_object *m){return *tv_str(m,"package_name")&&tv_num(m,"version_code")>0&&tv_num(m,"min_sdk")>0&&strlen(tv_str(m,"sha256"))==64&&array_length(tv_get(m,"signer_sha256"))>0;}
/* Caller holds the transaction and the staging directory. Published files never
 * get overwritten; duplicate package/version identities are rejected. */
static struct json_object *publish(sqlite3 *db,int dir,const char *id,struct json_object *meta,struct json_object *source,struct tvhome_err *e)
{
 sqlite3_stmt *s=NULL;int duplicate=0;
 if(sqlite3_prepare_v2(db,"SELECT metadata FROM tvhome_package WHERE state='ready' AND id<>?",-1,&s,NULL)!=SQLITE_OK){close(dir);return tv_db_error(db,e);}sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);
 while(sqlite3_step(s)==SQLITE_ROW){struct json_object *m=json_tokener_parse(tv_col(s,0));if(!strcmp(tv_str(m,"package_name"),tv_str(meta,"package_name"))&&tv_num(m,"version_code")==tv_num(meta,"version_code"))duplicate=1;if(m)json_object_put(m);}sqlite3_finalize(s);
 if(duplicate){close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"package_version_exists","version_code","This package version is already immutable in the library");}
 char part[48],size[32];snprintf(part,sizeof(part),"%s.part",id);snprintf(size,sizeof(size),"%lld",(long long)tv_num(meta,"size"));
 if(renameat(dir,part,dir,id)||fsync(dir)){close(dir);return tv_db_error(db,e);}
 if(tv_run(db,"UPDATE tvhome_package SET state='ready',metadata=?,source=?,size=?,received=?,revision=1 WHERE id=?",5,tv_json(meta),source?tv_json(source):"{}",size,size,id)||tv_run(db,"COMMIT",0)){renameat(dir,id,dir,part);close(dir);return tv_db_error(db,e);}close(dir);struct json_object *o=read_package(db,id,0);sqlite3_close(db);return o;
}
struct json_object *tvhome_package_complete(const char *id,struct tvhome_err *e)
{
 if(!valid_id(id))return tvhome_error(e,404,"resource_not_found","id","APK missing");sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}struct json_object *o=read_package(db,id,0);
 if(o&&!strcmp(tv_str(o,"state"),"ready")){close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return o;}
 char part[48];snprintf(part,sizeof(part),"%s.part",id);int fd=openat(dir,part,O_RDONLY|O_NOFOLLOW);struct stat st;
 if(!o||strcmp(tv_str(o,"kind"),"app")||fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size!=tv_num(o,"size")||tv_num(o,"received")!=st.st_size){if(fd>=0)close(fd);if(o)json_object_put(o);close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"upload_incomplete","size","Complete the APK upload first");}json_object_put(o);
 struct json_object *meta=helper("inspect",NULL,fd,e);close(fd);
 if(!meta||!metadata_valid(meta)||!strcmp(tv_str(meta,"package_name"),SELF_PACKAGE)){if(meta){json_object_put(meta);tvhome_error(e,400,"self_upgrade_requires_dist","package_name","Import TVHome from the TV release channel");}close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}
 o=publish(db,dir,id,meta,NULL,e);json_object_put(meta);return o;
}
struct json_object *tvhome_release_source(const char *channel,struct tvhome_err *e){if(e)e->http_status=0;if(!channel||(strcmp(channel,"stable")&&strcmp(channel,"beta")))return tvhome_error(e,400,"invalid_parameter","channel","Use the stable or beta TV channel");return helper("source",channel,-1,e);}
struct json_object *tvhome_release_import(const char *channel,struct tvhome_err *e)
{
 struct json_object *src=tvhome_release_source(channel,e);if(!src)return NULL;struct json_object *rel=tv_get(src,"latest");
 if(!rel){json_object_put(src);return tvhome_error(e,404,"release_unavailable","channel","No published TV release in this channel");}
 struct json_object *o=create_upload(tv_str(rel,"version"),tv_num(rel,"size"),"release",e);char expected[160],expected_hash[65];int64_t expected_size=tv_num(rel,"size");snprintf(expected,sizeof(expected),"%s",tv_str(rel,"id"));snprintf(expected_hash,sizeof(expected_hash),"%s",tv_str(rel,"sha256"));json_object_put(src);if(!o)return NULL;char id[37];snprintf(id,sizeof(id),"%s",tv_str(o,"id"));json_object_put(o);
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}char part[48];snprintf(part,sizeof(part),"%s.part",id);int fd=openat(dir,part,O_RDWR|O_NOFOLLOW);
 if(fd<0){close(dir);sqlite3_close(db);return tvhome_error(e,503,"storage_unavailable","","APK staging file unavailable");}
 // A network download must not hold the database write lock. The importing
 // state prevents deletes, while any package row protects the storage root.
 if(tv_run(db,"UPDATE tvhome_package SET state='importing' WHERE id=?",1,id)){close(fd);close(dir);return tv_db_error(db,e);}
 struct json_object *verified=helper("import",channel,fd,e);close(fd);
 if(tv_run(db,"BEGIN IMMEDIATE",0)){if(verified)json_object_put(verified);close(dir);return tv_db_error(db,e);}
 if(tv_run(db,"UPDATE tvhome_package SET state='uploading' WHERE id=?",1,id)){if(verified)json_object_put(verified);close(dir);return tv_db_error(db,e);}
 if(!verified||!metadata_valid(tv_get(verified,"metadata"))||strcmp(expected,tv_str(tv_get(verified,"source"),"id"))||strcmp(expected_hash,tv_str(tv_get(verified,"metadata"),"sha256"))||expected_size!=tv_num(tv_get(verified,"metadata"),"size")){if(verified)tvhome_error(e,409,"release_changed","channel","The published release changed during import; query the source again");if(verified)json_object_put(verified);tv_run(db,"COMMIT",0);close(dir);sqlite3_close(db);struct tvhome_err ignored={0};o=tvhome_package_delete(id,&ignored);if(o)json_object_put(o);return NULL;}
 o=publish(db,dir,id,tv_get(verified,"metadata"),tv_get(verified,"source"),e);json_object_put(verified);return o;
}
struct json_object *tvhome_package_update(const char *id,struct json_object *body,struct tvhome_err *e)
{
 struct json_object *policy=tv_get(body,"policy");if(!json_object_is_type(tv_get(policy,"enabled"),json_type_boolean)||!json_object_is_type(tv_get(policy,"forced"),json_type_boolean)||!json_object_is_type(tv_get(policy,"recommended"),json_type_boolean)||tv_num(policy,"min_version_code")<0||strlen(tv_str(policy,"category"))>80)return tvhome_error(e,400,"invalid_parameter","policy","Explicit enabled, forced, recommended and valid version policy required");
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,e);struct json_object *o=read_package(db,id,0);
 if(!o||strcmp(tv_str(o,"state"),"ready")||!tv_get(body,"expected_revision")||tv_num(body,"expected_revision")!=tv_num(o,"revision")){if(o)json_object_put(o);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"revision_conflict","expected_revision","Reload the verified APK before saving its policy");}
 struct json_object *members=tvhome_target_members(db,tv_get(policy,"target"),e);if(!members){json_object_put(o);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return NULL;}json_object_put(members);
 char revision[32];snprintf(revision,sizeof(revision),"%lld",(long long)tv_num(o,"revision")+1);json_object_put(o);
 struct json_object *clean=json_object_new_object();const char *keys[]={"enabled","forced","recommended","target","min_version_code","category",NULL};for(int i=0;keys[i];i++)json_object_object_add(clean,keys[i],copy(tv_get(policy,keys[i])));
 int rc=tv_run(db,"UPDATE tvhome_package SET policy=?,revision=? WHERE id=?",3,tv_json(clean),revision,id)||tv_changed(db)||tv_run(db,"COMMIT",0);json_object_put(clean);if(rc)return tv_db_error(db,e);o=read_package(db,id,1);sqlite3_close(db);return o;
}
struct json_object *tvhome_package_delete(const char *id,struct tvhome_err *e)
{
 if(!valid_id(id))return tvhome_error(e,404,"resource_not_found","id","APK missing");sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}struct json_object *o=read_package(db,id,0);
 if(!o||!strcmp(tv_str(o,"state"),"importing")||json_object_get_boolean(tv_get(tv_get(o,"policy"),"enabled"))){if(o)json_object_put(o);close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"package_enabled","id","Pause this APK before deleting it");}
 char file[48],trash[48];snprintf(file,sizeof(file),!strcmp(tv_str(o,"state"),"ready")?"%s":"%s.part",id);snprintf(trash,sizeof(trash),"%s.deleted",id);json_object_put(o);int moved=!renameat(dir,file,dir,trash);if(!moved&&errno!=ENOENT){close(dir);return tv_db_error(db,e);}
 if(tv_run(db,"DELETE FROM tvhome_package WHERE id=?",1,id)||tv_changed(db)||tv_run(db,"COMMIT",0)){if(moved)renameat(dir,trash,dir,file);close(dir);return tv_db_error(db,e);}if(moved)unlinkat(dir,trash,0);close(dir);sqlite3_close(db);o=json_object_new_object();str(o,"id",id);return o;
}
static struct json_object *inventory_package(struct json_object *inv,const char *package){struct json_object *a=tv_get(inv,"packages");for(size_t i=0;i<array_length(a);i++){struct json_object *v=json_object_array_get_idx(a,i);if(!strcmp(tv_str(v,"package_name"),package))return v;}return NULL;}
static const char *eligible(struct json_object *o,const char *terminal,const char *group,struct json_object *inv,int64_t updated)
{
 struct json_object *p=tv_get(o,"policy"),*m=tv_get(o,"metadata"),*installed=inventory_package(inv,tv_str(m,"package_name"));
 if(strcmp(tv_str(o,"state"),"ready"))return "not_ready";
 if(!json_object_get_boolean(tv_get(p,"enabled")))return "paused";
 if(!tvhome_target_matches(tv_get(p,"target"),terminal,group))return "not_targeted";
 if(!inv||updated<tv_now()-300000||!installed)return "inventory_required";
 if(tv_num(inv,"sdk_int")<tv_num(m,"min_sdk"))return "sdk_incompatible";
 if(!json_object_get_boolean(tv_get(m,"no_native_code"))){int found=0;struct json_object *abis=tv_get(inv,"supported_abis"),*supported=tv_get(m,"supported_abis");for(size_t i=0;i<array_length(abis);i++)if(contains(supported,json_object_get_string(json_object_array_get_idx(abis,i))))found=1;if(!found)return "abi_incompatible";}
 int exists=json_object_get_boolean(tv_get(installed,"installed"));int64_t version=exists?tv_num(installed,"version_code"):0;
 if(!strcmp(tv_str(o,"kind"),"release")&&(!exists||strcmp(tv_str(m,"package_name"),SELF_PACKAGE)))return "self_package_mismatch";
 if(version>=tv_num(m,"version_code"))return "version_not_newer";
 if(version<tv_num(p,"min_version_code"))return "minimum_start_version";
 if(exists&&!signers_equal(tv_get(m,"signer_sha256"),tv_get(installed,"signer_sha256")))return "signature_mismatch";
 return NULL;
}
static struct json_object *read_inventory(sqlite3 *db,const char *terminal,int64_t *updated){sqlite3_stmt *s=NULL;struct json_object *o=NULL;*updated=0;if(sqlite3_prepare_v2(db,"SELECT body,updated FROM tvhome_package_inventory WHERE terminal_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,terminal,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW){o=json_tokener_parse(tv_col(s,0));*updated=sqlite3_column_int64(s,1);}sqlite3_finalize(s);}return o;}
static void terminal_group(sqlite3 *db,const char *terminal,char *group,size_t size){sqlite3_stmt *s=NULL;*group=0;if(sqlite3_prepare_v2(db,"SELECT group_id FROM tvhome_terminal WHERE id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,terminal,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW)snprintf(group,size,"%s",tv_col(s,0));sqlite3_finalize(s);}}
static int inventory_valid(struct json_object *body)
{
 struct json_object *abis=tv_get(body,"supported_abis"),*packages=tv_get(body,"packages");if(tv_num(body,"sdk_int")<1||tv_num(body,"sdk_int")>200||!json_object_is_type(abis,json_type_array)||!array_length(abis)||array_length(abis)>16||!json_object_is_type(packages,json_type_array)||array_length(packages)>500)return 0;
 for(size_t i=0;i<array_length(abis);i++){struct json_object *v=json_object_array_get_idx(abis,i);if(!json_object_is_type(v,json_type_string)||strlen(json_object_get_string(v))>32)return 0;}
 for(size_t i=0;i<array_length(packages);i++){struct json_object *v=json_object_array_get_idx(packages,i),*signers=tv_get(v,"signer_sha256");if(!*tv_str(v,"package_name")||strlen(tv_str(v,"package_name"))>240||!json_object_is_type(tv_get(v,"installed"),json_type_boolean))return 0;if(json_object_get_boolean(tv_get(v,"installed"))&&(tv_num(v,"version_code")<1||!array_length(signers)))return 0;for(size_t j=0;j<array_length(signers);j++){struct json_object *sig=json_object_array_get_idx(signers,j);if(!json_object_is_type(sig,json_type_string)||strlen(json_object_get_string(sig))!=64)return 0;}}
 return 1;
}
static int version_below(const char *version,const char *minimum) {
 if(!*version||!*minimum)return 0;const char *a=version,*b=minimum;
 if(*a=='v')a++;if(*b=='v')b++;
 for(int i=0;i<4;i++){char *ae,*be;unsigned long x=strtoul(a,&ae,10),y=strtoul(b,&be,10);if(a==ae&&*a)return 0;if(b==be&&*b)return 0;if((*ae&&*ae!='.')||(*be&&*be!='.'))return 0;if(x!=y)return x<y;if(!*ae&&!*be)return 0;a=*ae?ae+1:ae;b=*be?be+1:be;}return 0;
}
static struct json_object *candidates(sqlite3 *db,const char *terminal,const char *group,struct json_object *inv,int64_t updated,int catalog)
{
 struct json_object *o=json_object_new_object(),*items=json_object_new_array(),*rejected=json_object_new_array(),*best=json_object_new_object();sqlite3_stmt *s=NULL;
 if(sqlite3_prepare_v2(db,"SELECT id FROM tvhome_package WHERE state='ready' ORDER BY id",-1,&s,NULL)==SQLITE_OK){while(sqlite3_step(s)==SQLITE_ROW){struct json_object *p=read_package(db,tv_col(s,0),0),*policy=tv_get(p,"policy"),*m=tv_get(p,"metadata");const char *why=eligible(p,terminal,group,inv,updated);
   if(!json_object_get_boolean(tv_get(policy,"enabled"))||!tvhome_target_matches(tv_get(policy,"target"),terminal,group)){json_object_put(p);continue;}
   if(catalog){json_object_array_add(items,p);continue;}
   if(why){struct json_object *r=json_object_new_object();str(r,"id",tv_str(p,"id"));str(r,"reason",why);json_object_array_add(rejected,r);json_object_put(p);continue;}
   struct json_object *source=tv_get(p,"source"),*installed=inventory_package(inv,tv_str(m,"package_name"));
   int required=json_object_get_boolean(tv_get(policy,"forced"))||json_object_get_boolean(tv_get(source,"force_update"))||version_below(tv_str(installed,"version_name"),tv_str(source,"min_version"));
   json_object_object_add(p,"required_update",json_object_new_boolean(required));
   const char *name=tv_str(m,"package_name");struct json_object *old=tv_get(best,name);if(!old||tv_num(tv_get(old,"metadata"),"version_code")<tv_num(m,"version_code"))json_object_object_add(best,name,p);else json_object_put(p);
  }sqlite3_finalize(s);}
 if(!catalog){json_object_object_foreach(best,k,v){(void)k;json_object_array_add(items,json_object_get(v));}}
 json_object_put(best);json_object_object_add(o,"packages",items);json_object_object_add(o,"rejected",rejected);return o;
}
struct json_object *tvhome_packages_check(const char *token,struct json_object *body,struct tvhome_err *e)
{
 sqlite3 *db=NULL;char terminal[128],group[128];if(tvhome_db_open(&db,e))return NULL;if(tvhome_authorize(db,token,terminal,sizeof(terminal),e)){sqlite3_close(db);return NULL;}terminal_group(db,terminal,group,sizeof(group));
 if(body){if(!inventory_valid(body)){sqlite3_close(db);return tvhome_error(e,400,"invalid_inventory","packages","Report actual SDK, ABIs and installed package/version/signatures");}char now[32];snprintf(now,sizeof(now),"%lld",(long long)tv_now());if(tv_run(db,"INSERT OR REPLACE INTO tvhome_package_inventory VALUES(?,?,?)",3,terminal,tv_json(body),now))return tv_db_error(db,e);}
 int64_t updated=0;struct json_object *inv=read_inventory(db,terminal,&updated),*o=candidates(db,terminal,group,inv,updated,body==NULL);if(inv)json_object_put(inv);sqlite3_close(db);return o;
}
int tvhome_package_open(const char *id,const char *token,int64_t *size,struct tvhome_err *e)
{
 if(!valid_id(id)){tvhome_error(e,404,"resource_not_found","id","APK missing");return -1;}sqlite3 *db=NULL;char terminal[128],group[128];if(tvhome_db_open(&db,e))return -1;if(tvhome_authorize(db,token,terminal,sizeof(terminal),e)){sqlite3_close(db);return -1;}terminal_group(db,terminal,group,sizeof(group));int64_t updated;struct json_object *inv=read_inventory(db,terminal,&updated),*list=candidates(db,terminal,group,inv,updated,0),*selected=NULL,*items=tv_get(list,"packages");
 for(size_t i=0;i<array_length(items);i++){struct json_object *v=json_object_array_get_idx(items,i);if(!strcmp(tv_str(v,"id"),id))selected=v;}
 if(!selected){if(inv)json_object_put(inv);json_object_put(list);sqlite3_close(db);tvhome_error(e,403,"package_not_eligible","id","APK is paused, not targeted, incompatible, or superseded; check again");return -1;}
 int dir=tvhome_storage_dir(db,e),fd=dir<0?-1:openat(dir,id,O_RDONLY|O_NOFOLLOW);if(dir>=0)close(dir);struct stat st;int ok=fd>=0&&!fstat(fd,&st)&&S_ISREG(st.st_mode)&&st.st_size==tv_num(selected,"size");if(ok)*size=st.st_size;if(inv)json_object_put(inv);json_object_put(list);sqlite3_close(db);if(!ok){if(fd>=0)close(fd);tvhome_error(e,503,"package_data_unavailable","id","Verified APK bytes are unavailable");return -1;}return fd;
}
static int stage_rank(const char *s){const char *stages[]={"queued","downloading","downloaded","awaiting_install","installer_launched","cancelled","failed","installed","started",NULL};for(int i=0;stages[i];i++)if(!strcmp(s,stages[i]))return i;return -1;}
struct json_object *tvhome_package_result(const char *token,const char *id,struct json_object *body,struct tvhome_err *e)
{
 const char *stage=tv_str(body,"stage"),*attempt=tv_str(body,"attempt_id");int rank=stage_rank(stage);if(rank<0||!*attempt||strlen(attempt)>96||strlen(tv_str(body,"detail"))>240)return tvhome_error(e,400,"invalid_parameter","stage","Known install stage and stable attempt ID required");
 sqlite3 *db=NULL;char terminal[128],group[128];if(tvhome_db_open(&db,e))return NULL;if(tvhome_authorize(db,token,terminal,sizeof(terminal),e)){sqlite3_close(db);return NULL;}if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,e);terminal_group(db,terminal,group,sizeof(group));struct json_object *p=read_package(db,id,0),*old=NULL;sqlite3_stmt *s=NULL;
 if(sqlite3_prepare_v2(db,"SELECT body FROM tvhome_package_result WHERE package_id=? AND terminal_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(s,2,terminal,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW)old=json_tokener_parse(tv_col(s,0));sqlite3_finalize(s);}
 int continuation=old&&!strcmp(tv_str(old,"attempt_id"),attempt);
 if(!p||(!continuation&&(!json_object_get_boolean(tv_get(tv_get(p,"policy"),"enabled"))||!tvhome_target_matches(tv_get(tv_get(p,"policy"),"target"),terminal,group)))){if(p)json_object_put(p);if(old)json_object_put(old);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,403,"package_not_eligible","id","Install result is outside this terminal's assignment");}
 struct json_object *m=tv_get(p,"metadata"),*actual=tv_get(body,"actual");
 if(rank>=7&&(!actual||strcmp(tv_str(actual,"package_name"),tv_str(m,"package_name"))||tv_num(actual,"version_code")!=tv_num(m,"version_code")||!signers_equal(tv_get(actual,"signer_sha256"),tv_get(m,"signer_sha256")))){json_object_put(p);if(old)json_object_put(old);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"install_evidence_mismatch","actual","Installed package/version/signature must match the verified APK");}
 if(continuation&&rank<stage_rank(tv_str(old,"stage"))){json_object_put(p);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return old;}
 if(old)json_object_put(old);json_object_put(p);struct json_object *clean=json_object_new_object();str(clean,"stage",stage);str(clean,"attempt_id",attempt);str(clean,"detail",tv_str(body,"detail"));if(actual)json_object_object_add(clean,"actual",copy(actual));char now[32];snprintf(now,sizeof(now),"%lld",(long long)tv_now());
 if(tv_run(db,"INSERT OR REPLACE INTO tvhome_package_result VALUES(?,?,?,?)",4,id,terminal,tv_json(clean),now)||tv_run(db,"COMMIT",0)){json_object_put(clean);return tv_db_error(db,e);}sqlite3_close(db);return clean;
}
