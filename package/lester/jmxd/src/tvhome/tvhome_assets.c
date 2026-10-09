// SPDX-License-Identifier: GPL-2.0-or-later
/* Assets live under an explicitly selected storage root. IDs never carry paths. */
#include "tvhome_assets.h"
#include "storage/storage_files.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#define IMAGE_LIMIT (16LL*1024*1024)
#define VIDEO_LIMIT (256LL*1024*1024)
#define LIBRARY_LIMIT (2LL*1024*1024*1024)
int tvhome_assets_schema(sqlite3 *db)
{
 return tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_asset_storage(id INTEGER PRIMARY KEY,root_id TEXT NOT NULL,path TEXT NOT NULL)",0)||
 tv_run(db,"CREATE TABLE IF NOT EXISTS tvhome_asset(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,mime TEXT NOT NULL DEFAULT '',size INTEGER NOT NULL,sha256 TEXT NOT NULL DEFAULT '',received INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT 'uploading')",0);
}
static int valid_id(const char *id) {if(!id||strlen(id)!=38||strncmp(id,"asset-",6))return 0;for(const char *p=id+6;*p;p++)if(!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f')))return 0;return 1;}
static int kind_valid(const char *k) {return !strcmp(k,"image")||!strcmp(k,"video")||!strcmp(k,"icon")||!strcmp(k,"logo");}
static void str(struct json_object *o,const char *k,const char *v) {json_object_object_add(o,k,json_object_new_string(v));}
static void num(struct json_object *o,const char *k,int64_t v) {json_object_object_add(o,k,json_object_new_int64(v));}
int tvhome_storage_dir(sqlite3 *db,struct tvhome_err *e)
{
 sqlite3_stmt *s=NULL;char root[96]="",path[4096]="",canonical[4096];const char *reason=NULL;
 if(sqlite3_prepare_v2(db,"SELECT root_id,path FROM tvhome_asset_storage WHERE id=1",-1,&s,NULL)==SQLITE_OK){if(sqlite3_step(s)==SQLITE_ROW){snprintf(root,sizeof(root),"%s",tv_col(s,0));snprintf(path,sizeof(path),"%s",tv_col(s,1));}sqlite3_finalize(s);}
 if(!*root){tvhome_error(e,503,"storage_not_configured","storage","Select a writable data disk for TV assets first");return -1;}
 int parent=storage_files_open_dir(root,path,1,canonical,sizeof(canonical),&reason);
 if(parent<0){tvhome_error(e,503,"storage_unavailable","storage",reason?reason:"Data disk unavailable");return -1;}
 if(mkdirat(parent,".dreaming-tvhome",0700)<0&&errno!=EEXIST){close(parent);tvhome_error(e,503,"storage_unavailable","storage","Cannot create asset directory");return -1;}
 int fd=openat(parent,".dreaming-tvhome",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);close(parent);
 if(fd<0)tvhome_error(e,503,"storage_unavailable","storage","Asset directory unavailable");return fd;
}
/* Record exact JSON paths for all actual uses, including non-theme display layers. */
static void references(struct json_object *v,const char *id,const char *path,struct json_object *out,const char *type,const char *owner)
{
 if(json_object_is_type(v,json_type_string)&&!strcmp(json_object_get_string(v),id)){
  struct json_object *r=json_object_new_object();str(r,"type",type);str(r,"id",owner);str(r,"field",path);json_object_array_add(out,r);
 }else if(json_object_is_type(v,json_type_object)){json_object_object_foreach(v,k,item){char child[512];snprintf(child,sizeof(child),"%s%s%s",path,*path?".":"",k);references(item,id,child,out,type,owner);}}
 else if(json_object_is_type(v,json_type_array)){for(size_t i=0;i<json_object_array_length(v);i++){char child[512];snprintf(child,sizeof(child),"%s[%zu]",path,i);references(json_object_array_get_idx(v,i),id,child,out,type,owner);}}
}
static struct json_object *asset_refs(sqlite3 *db,const char *id)
{
 const char *queries[]={"SELECT id,spec_json FROM tvhome_theme","SELECT id,display_json FROM tvhome_terminal","SELECT id,display_json FROM tvhome_group","SELECT 'notice',body FROM tvhome_notice","SELECT id,body FROM tvhome_command WHERE state='active' AND expires>CAST(strftime('%s','now') AS INTEGER)*1000",NULL};
 const char *types[]={"theme","terminal","group","notice","command"};struct json_object *a=json_object_new_array();
 for(int i=0;queries[i];i++){sqlite3_stmt *s=NULL;if(sqlite3_prepare_v2(db,queries[i],-1,&s,NULL)==SQLITE_OK){while(sqlite3_step(s)==SQLITE_ROW){struct json_object *o=json_tokener_parse(tv_col(s,1));references(o,id,"",a,types[i],tv_col(s,0));if(o)json_object_put(o);}sqlite3_finalize(s);}}return a;
}
static struct json_object *asset_read(sqlite3 *db,const char *id)
{
 sqlite3_stmt *s=NULL;struct json_object *o=NULL;
 if(sqlite3_prepare_v2(db,"SELECT id,name,kind,mime,size,sha256,received,state FROM tvhome_asset WHERE id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_TRANSIENT);if(sqlite3_step(s)==SQLITE_ROW){o=json_object_new_object();const char *keys[]={"id","name","kind","mime","size","sha256","received","state"};for(int i=0;i<8;i++)if(i==4||i==6)num(o,keys[i],sqlite3_column_int64(s,i));else str(o,keys[i],tv_col(s,i));}sqlite3_finalize(s);}
 if(o)json_object_object_add(o,"references",asset_refs(db,id));return o;
}
struct json_object *tvhome_assets_storage(struct json_object *body,struct tvhome_err *e)
{
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;
 if(body){const char *root=tv_str(body,"root_id"),*path=tv_str(body,"path"),*reason=NULL;char canonical[4096];
  if(!*root||strlen(root)>95||strlen(path)>4000){sqlite3_close(db);return tvhome_error(e,400,"invalid_parameter","root_id","Choose a storage root and relative directory");}
  int fd=storage_files_open_dir(root,path,1,canonical,sizeof(canonical),&reason);if(fd<0){sqlite3_close(db);return tvhome_error(e,400,"invalid_storage","root_id",reason?reason:"Writable data directory required");}close(fd);
  if(tv_run(db,"BEGIN IMMEDIATE",0))return tv_db_error(db,e);
  if(tv_exists(db,"SELECT 1 FROM tvhome_asset WHERE id<>? UNION ALL SELECT 1 FROM tvhome_package LIMIT 1","")){tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"asset_in_use","storage","Empty the asset library before changing its storage");}
  if(tv_run(db,"INSERT OR REPLACE INTO tvhome_asset_storage VALUES(1,?,?)",2,root,path)||tv_run(db,"COMMIT",0))return tv_db_error(db,e);
 }
 struct json_object *o=json_object_new_object();sqlite3_stmt *s=NULL;
 if(sqlite3_prepare_v2(db,"SELECT root_id,path FROM tvhome_asset_storage WHERE id=1",-1,&s,NULL)==SQLITE_OK){if(sqlite3_step(s)==SQLITE_ROW){str(o,"root_id",tv_col(s,0));str(o,"path",tv_col(s,1));}sqlite3_finalize(s);}
 num(o,"max_image_bytes",IMAGE_LIMIT);num(o,"max_video_bytes",VIDEO_LIMIT);num(o,"chunk_bytes",TVHOME_ASSET_CHUNK);num(o,"quota_bytes",LIBRARY_LIMIT);
 json_object_object_add(o,"configured",json_object_new_boolean(*tv_str(o,"root_id")!=0));sqlite3_close(db);return o;
}
struct json_object *tvhome_assets_get(const char *id,struct tvhome_err *e)
{
 sqlite3 *db=NULL;sqlite3_stmt *s=NULL;if(tvhome_db_open(&db,e))return NULL;struct json_object *o;
 if(id&&*id){o=asset_read(db,id);sqlite3_close(db);return o?o:tvhome_error(e,404,"resource_not_found","id","Asset not found");}
 o=json_object_new_object();struct json_object *a=json_object_new_array();
 if(sqlite3_prepare_v2(db,"SELECT id FROM tvhome_asset ORDER BY name",-1,&s,NULL)==SQLITE_OK){while(sqlite3_step(s)==SQLITE_ROW)json_object_array_add(a,asset_read(db,tv_col(s,0)));sqlite3_finalize(s);}json_object_object_add(o,"assets",a);sqlite3_close(db);return o;
}
struct json_object *tvhome_asset_create(struct json_object *body,struct tvhome_err *e)
{
 const char *name=tv_str(body,"name"),*kind=tv_str(body,"kind");int64_t size=tv_num(body,"size");
 if(!*name||strlen(name)>160||!kind_valid(kind)||size<1)return tvhome_error(e,400,"invalid_parameter","asset","Name, kind and a positive file size required");
 if(size>(!strcmp(kind,"video")?VIDEO_LIMIT:IMAGE_LIMIT))return tvhome_error(e,413,"upload_too_large","size","Asset exceeds the declared per-file limit");
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}
 if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}sqlite3_stmt *s=NULL;int64_t used=0;
 if(sqlite3_prepare_v2(db,"SELECT (SELECT COALESCE(SUM(size),0) FROM tvhome_asset)+(SELECT COALESCE(SUM(size),0) FROM tvhome_package)",-1,&s,NULL)==SQLITE_OK){if(sqlite3_step(s)==SQLITE_ROW)used=sqlite3_column_int64(s,0);sqlite3_finalize(s);}
 struct statvfs space;int full=used+size>LIBRARY_LIMIT || fstatvfs(dir,&space) || (uint64_t)space.f_bavail*space.f_frsize<(uint64_t)size+16*1024*1024;
 if(full){close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,413,"storage_capacity_exceeded","size","Asset quota or data disk capacity exceeded");}
 char id[39]="asset-",file[48],length[32];unsigned char random[16];
 if(RAND_bytes(random,sizeof(random))!=1){close(dir);return tv_db_error(db,e);}for(int i=0;i<16;i++)snprintf(id+6+i*2,3,"%02x",random[i]);snprintf(file,sizeof(file),"%s.part",id);
 int fd=openat(dir,file,O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW,0600);if(fd<0){close(dir);return tv_db_error(db,e);}close(fd);snprintf(length,sizeof(length),"%lld",(long long)size);
 if(tv_run(db,"INSERT INTO tvhome_asset(id,name,kind,size) VALUES(?,?,?,?)",4,id,name,kind,length)||tv_run(db,"COMMIT",0)){unlinkat(dir,file,0);close(dir);return tv_db_error(db,e);}close(dir);struct json_object *o=asset_read(db,id);sqlite3_close(db);return o;
}
struct json_object *tvhome_asset_chunk(const char *id,int64_t offset,const void *data,size_t len,struct tvhome_err *e)
{
 if(!valid_id(id)||offset<0||!len||len>TVHOME_ASSET_CHUNK)return tvhome_error(e,len>TVHOME_ASSET_CHUNK?413:400,"invalid_chunk","offset","Use a valid asset ID, byte offset and chunk up to 1 MiB");
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}
 if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}struct json_object *o=asset_read(db,id);
 if(!o||strcmp(tv_str(o,"state"),"uploading")||offset+len>(uint64_t)tv_num(o,"size")||offset>tv_num(o,"received")){
  if(o)json_object_put(o);close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"upload_offset_conflict","offset","Read the asset's received offset and retry");}
 int64_t received=tv_num(o,"received");json_object_put(o);char file[48],next[32];snprintf(file,sizeof(file),"%s.part",id);int fd=openat(dir,file,O_RDWR|O_NOFOLLOW);close(dir);
 if(fd<0)return tv_db_error(db,e);
 if(offset<received){unsigned char *old=malloc(len);int same=old&&offset+(int64_t)len<=received&&pread(fd,old,len,offset)==(ssize_t)len&&!memcmp(old,data,len);free(old);close(fd);tv_run(db,"ROLLBACK",0);if(!same){sqlite3_close(db);return tvhome_error(e,409,"upload_offset_conflict","offset","Retried bytes differ from the accepted chunk");}o=asset_read(db,id);sqlite3_close(db);return o;}
 ssize_t n=pwrite(fd,data,len,offset);int rc=n!=(ssize_t)len||fdatasync(fd);close(fd);snprintf(next,sizeof(next),"%lld",(long long)offset+len);
 if(rc||tv_run(db,"UPDATE tvhome_asset SET received=? WHERE id=?",2,next,id)||tv_run(db,"COMMIT",0))return tv_db_error(db,e);o=asset_read(db,id);sqlite3_close(db);return o;
}
static const char *sniff(const unsigned char *b,size_t n) {
 if(n>=8&&!memcmp(b,"\211PNG\r\n\032\n",8))return "image/png";
 if(n>=3&&b[0]==255&&b[1]==216&&b[2]==255)return "image/jpeg";
 if(n>=6&&(!memcmp(b,"GIF87a",6)||!memcmp(b,"GIF89a",6)))return "image/gif";
 if(n>=12&&!memcmp(b,"RIFF",4)&&!memcmp(b+8,"WEBP",4))return "image/webp";
 if(n>=12&&!memcmp(b+4,"ftyp",4)&&(!memcmp(b+8,"isom",4)||!memcmp(b+8,"mp42",4)||!memcmp(b+8,"mp41",4)||!memcmp(b+8,"avc1",4)||!memcmp(b+8,"iso2",4)))return "video/mp4";
 if(n>=4&&!memcmp(b,"\032E\337\243",4))return "video/webm";
 return NULL;
}
struct json_object *tvhome_asset_complete(const char *id,struct tvhome_err *e)
{
 if(!valid_id(id))return tvhome_error(e,404,"resource_not_found","id","Asset not found");sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;
 int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}
 struct json_object *o=asset_read(db,id);if(!o){close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,404,"resource_not_found","id","Asset not found");}
 if(!strcmp(tv_str(o,"state"),"ready")){close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return o;}
 char part[48];snprintf(part,sizeof(part),"%s.part",id);int fd=openat(dir,part,O_RDONLY|O_NOFOLLOW);struct stat st;
 if(fd<0||fstat(fd,&st)||st.st_size!=tv_num(o,"size")||tv_num(o,"received")!=st.st_size){if(fd>=0)close(fd);close(dir);json_object_put(o);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"upload_incomplete","size","All bytes must be accepted before publishing the asset");}
 unsigned char buf[65536],digest[32];ssize_t n=read(fd,buf,sizeof(buf));const char *mime=n>0?sniff(buf,n):NULL;
 if(!mime||(!strncmp(mime,"video/",6)!=!strcmp(tv_str(o,"kind"),"video"))){close(fd);close(dir);json_object_put(o);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,400,"invalid_asset_format","kind","File signature does not match the selected image/video kind");}
 EVP_MD_CTX *hash=EVP_MD_CTX_new();unsigned int count=0;int rc=!hash||!EVP_DigestInit_ex(hash,EVP_sha256(),NULL);lseek(fd,0,SEEK_SET);
 while(!rc&&(n=read(fd,buf,sizeof(buf)))>0)rc=!EVP_DigestUpdate(hash,buf,n);
 if(n<0)rc=1;if(!rc)rc=!EVP_DigestFinal_ex(hash,digest,&count)||count!=32;if(hash)EVP_MD_CTX_free(hash);close(fd);json_object_put(o);
 char hex[65];for(int i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",digest[i]);
 if(rc||renameat(dir,part,dir,id)||fsync(dir)){close(dir);return tv_db_error(db,e);}
 if(tv_run(db,"UPDATE tvhome_asset SET state='ready',mime=?,sha256=? WHERE id=?",3,mime,hex,id)||tv_run(db,"COMMIT",0)){renameat(dir,id,dir,part);close(dir);return tv_db_error(db,e);}close(dir);o=asset_read(db,id);sqlite3_close(db);return o;
}
struct json_object *tvhome_asset_update(const char *id,struct json_object *body,struct tvhome_err *e)
{
 const char *name=tv_str(body,"name"),*kind=tv_str(body,"kind");if(!*name||strlen(name)>160||!kind_valid(kind))return tvhome_error(e,400,"invalid_parameter","asset","Valid name and kind required");
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;struct json_object *o=asset_read(db,id);
 if(!o){sqlite3_close(db);return tvhome_error(e,404,"resource_not_found","id","Asset not found");}
 if(!strcmp(kind,"video")!=!strcmp(tv_str(o,"kind"),"video")){json_object_put(o);sqlite3_close(db);return tvhome_error(e,400,"invalid_asset_format","kind","Cannot relabel a video as an image or vice versa");}json_object_put(o);
 if(tv_run(db,"UPDATE tvhome_asset SET name=?,kind=? WHERE id=?",3,name,kind,id))return tv_db_error(db,e);o=asset_read(db,id);sqlite3_close(db);return o;
}
struct json_object *tvhome_asset_delete(const char *id,struct tvhome_err *e)
{
 if(!valid_id(id))return tvhome_error(e,404,"resource_not_found","id","Asset not found");sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return NULL;
 int dir=tvhome_storage_dir(db,e);if(dir<0){sqlite3_close(db);return NULL;}if(tv_run(db,"BEGIN IMMEDIATE",0)){close(dir);return tv_db_error(db,e);}
 struct json_object *o=asset_read(db,id);if(!o){close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,404,"resource_not_found","id","Asset not found");}
 if(json_object_array_length(tv_get(o,"references"))){json_object_put(o);close(dir);tv_run(db,"ROLLBACK",0);sqlite3_close(db);return tvhome_error(e,409,"asset_in_use","references","Read this asset's references to locate each use before deleting");}
 char file[48],trash[48];snprintf(file,sizeof(file),!strcmp(tv_str(o,"state"),"ready")?"%s":"%s.part",id);snprintf(trash,sizeof(trash),"%s.deleted",id);json_object_put(o);
 int moved=renameat(dir,file,dir,trash)==0;if(!moved&&errno!=ENOENT){close(dir);return tv_db_error(db,e);}
 if(tv_run(db,"DELETE FROM tvhome_asset WHERE id=?",1,id)||tv_run(db,"COMMIT",0)){if(moved)renameat(dir,trash,dir,file);close(dir);return tv_db_error(db,e);}if(moved)unlinkat(dir,trash,0);close(dir);sqlite3_close(db);o=json_object_new_object();str(o,"id",id);json_object_object_add(o,"deleted",json_object_new_boolean(1));return o;
}
static int validate(sqlite3 *db,struct json_object *o,const char *key,const char *path,struct tvhome_err *e)
{
 if(json_object_is_type(o,json_type_string)){
  const char *v=json_object_get_string(o);int asset=!strcmp(key,"assetId")||!strcmp(key,"asset_id")||!strcmp(key,"assetIds")||!strcmp(key,"image")||!strcmp(key,"thumbnail")||(!strcmp(key,"icon")&&!strncmp(v,"asset-",6));
  if(asset&&*v&&!tv_exists(db,"SELECT 1 FROM tvhome_asset WHERE id=? AND state='ready'",v)){tvhome_error(e,400,"missing_asset",path,v);return -1;}
 }else if(json_object_is_type(o,json_type_object)){json_object_object_foreach(o,k,v){char next[512];snprintf(next,sizeof(next),"%s%s%s",path,*path?".":"",k);if(validate(db,v,k,next,e))return -1;}}
 else if(json_object_is_type(o,json_type_array)){for(size_t i=0;i<json_object_array_length(o);i++){char next[512];snprintf(next,sizeof(next),"%s[%zu]",path,i);if(validate(db,json_object_array_get_idx(o,i),key,next,e))return -1;}}
 return 0;
}
int tvhome_assets_validate(sqlite3 *db,struct json_object *o,struct tvhome_err *e) {return validate(db,o,"","",e);}
int tvhome_asset_open(const char *id,const char *token,char *mime,size_t mime_size,int64_t *size,struct tvhome_err *e)
{
 if(!valid_id(id)){tvhome_error(e,404,"resource_not_found","id","Asset not found");return -1;}
 if(token){struct json_object *boot=tvhome_bootstrap(token,e);if(!boot)return -1;struct json_object *refs=json_object_new_array();
  references(tv_get(boot,"theme"),id,"",refs,"theme","");references(tv_get(boot,"display"),id,"",refs,"display","");references(tv_get(boot,"notice"),id,"",refs,"notice","");
  struct json_object *commands=tv_get(boot,"commands");for(size_t i=0;i<json_object_array_length(commands);i++){struct json_object *c=json_object_array_get_idx(commands,i);if(!strcmp(tv_str(c,"state"),"active"))references(tv_get(c,"payload"),id,"",refs,"command","");}
  int allowed=json_object_array_length(refs)>0;json_object_put(refs);json_object_put(boot);if(!allowed){tvhome_error(e,403,"tv_forbidden","id","Asset is not assigned to this TV");return -1;}
 }
 sqlite3 *db=NULL;if(tvhome_db_open(&db,e))return -1;struct json_object *o=asset_read(db,id);
 if(!o||strcmp(tv_str(o,"state"),"ready")){if(o)json_object_put(o);sqlite3_close(db);tvhome_error(e,404,"resource_not_found","id","Ready asset not found");return -1;}
 int dir=tvhome_storage_dir(db,e),fd=dir>=0?openat(dir,id,O_RDONLY|O_NOFOLLOW):-1;if(dir>=0)close(dir);sqlite3_close(db);
 struct stat st;if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size!=tv_num(o,"size")){if(fd>=0)close(fd);json_object_put(o);tvhome_error(e,503,"asset_unavailable","id","Asset data is missing or incomplete");return -1;}
 snprintf(mime,mime_size,"%s",tv_str(o,"mime"));*size=st.st_size;json_object_put(o);return fd;
}
