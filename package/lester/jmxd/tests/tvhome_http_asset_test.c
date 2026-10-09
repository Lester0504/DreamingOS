// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise the production byte handler, including auth, Range and raw uploads.
 * Only the storage root and config database are isolated. */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include "webd/api/api_tvhome.c"
#ifndef TVH_DB_PATH
#error Disposable TVH_DB_PATH required
#endif
static int checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1); } } while (0)
int tvhome_ws_count(const char *id) { (void)id;return 0; }
int storage_files_open_dir(const char *root,const char *path,int writing,char *canonical,size_t size,const char **reason) {
    (void)root;(void)path;(void)writing;(void)reason;
    snprintf(canonical,size,"%s",TVH_DB_PATH);
    char *slash=strrchr(canonical,'/');if(slash)*slash=0;
    return open(canonical,O_RDONLY|O_DIRECTORY);
}
static struct json_object *data(const char *s) { struct json_object *o=json_tokener_parse(s);CHECK(o);return o; }
static struct json_object *bytes_call(struct http_req *req,int expected,char *wire,size_t capacity) {
    int pair[2];CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    struct jmx_api_ctx ctx={.req=req,.fd=pair[1]};
    struct json_object *reply=tvh_asset_bytes(&ctx);CHECK(ctx.status==expected);close(pair[1]);
    ssize_t n=read(pair[0],wire,capacity-1);CHECK(n>=0);wire[n]=0;close(pair[0]);return reply;
}
int main(void) {
    CHECK(!strncmp(TVH_DB_PATH,"/tmp/",5));unlink(TVH_DB_PATH);
    struct tvhome_err err={0};struct json_object *body=data("{\"root_id\":\"test-disk\",\"path\":\"\"}");
    struct json_object *r=tvhome_assets_storage(body,&err);CHECK(r);json_object_put(r);json_object_put(body);
    const unsigned char png[]={137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,1,0,0,0,1,8,4,0,0,0,181,28,12,2,0,0,0,11,73,68,65,84,120,218,99,100,248,15,0,1,5,1,1,39,24,227,102,0,0,0,0,73,69,78,68,174,66,96,130};
    body=data("{\"name\":\"HTTP test\",\"kind\":\"image\",\"size\":68}");
    r=tvhome_asset_create(body,&err);CHECK(r);char id[64];snprintf(id,sizeof(id),"%s",tv_str(r,"id"));json_object_put(r);json_object_put(body);
    struct http_req req={0};strcpy(req.method,"PUT");snprintf(req.path,sizeof(req.path),"/api/v1/tvhome/assets/%s/content",id);
    strcpy(req.query,"offset=0");req.body=(const char *)png;req.body_len=sizeof(png);char wire[2048];
    r=bytes_call(&req,200,wire,sizeof(wire));CHECK(r&&tv_num(tv_get(r,"data"),"received")==68);json_object_put(r);
    r=tvhome_asset_complete(id,&err);CHECK(r);json_object_put(r);
    req.body=NULL;req.body_len=0;req.query[0]=0;strcpy(req.method,"GET");
    r=bytes_call(&req,200,wire,sizeof(wire));CHECK(!r&&strstr(wire,"Content-Length: 68\r\n")&&strstr(wire,"image/png"));
    char *payload=strstr(wire,"\r\n\r\n");CHECK(payload&&!memcmp(payload+4,png,sizeof(png)));
    strcpy(req.range,"bytes=0-7");r=bytes_call(&req,206,wire,sizeof(wire));CHECK(!r&&strstr(wire,"Content-Range: bytes 0-7/68\r\n"));
    payload=strstr(wire,"\r\n\r\n");CHECK(payload&&!memcmp(payload+4,png,8));
    strcpy(req.range,"bytes=-8");r=bytes_call(&req,206,wire,sizeof(wire));CHECK(!r&&strstr(wire,"Content-Range: bytes 60-67/68\r\n"));
    strcpy(req.method,"HEAD");req.range[0]=0;r=bytes_call(&req,200,wire,sizeof(wire));CHECK(!r&&strstr(wire,"Content-Length: 68\r\n"));
    payload=strstr(wire,"\r\n\r\n");CHECK(payload&&payload[4]==0);
    strcpy(req.method,"GET");strcpy(req.range,"bytes=999-");r=bytes_call(&req,416,wire,sizeof(wire));CHECK(!r&&strstr(wire,"Content-Range: bytes */68"));
    req.range[0]=0;snprintf(req.path,sizeof(req.path),"/api/v1/tv/client/assets/%s",id);
    r=bytes_call(&req,401,wire,sizeof(wire));CHECK(r&&!wire[0]);json_object_put(r);
    r=tvhome_asset_delete(id,&err);CHECK(r);json_object_put(r);
    printf("PASS %d checks: raw chunk handler, GET/HEAD/Range/suffix/416, missing TV auth\n",checks);
    return 0;
}
