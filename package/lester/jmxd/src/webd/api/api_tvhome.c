// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * TVHome REST adapter (Package A).
 *
 * Thin webd route layer over the Pattern-B store in jmxd/src/tvhome/. Each
 * handler forwards the request body / a path id / the TV-session bearer to a
 * tvhome_store.c entry point, then maps the returned data + struct tvhome_err
 * onto webd_envelope()/webd_error() and ctx->status. Envelope/error/route
 * contract: PM-tvhome-package-a-contract.md sections 2-7; names frozen (8).
 *
 * Two dispatch halves (api_router.c):
 *   T (/api/v1/tv/client/...) are JMX_API_PREAUTH: answered before the admin
 *     permission gate because a TV client carries no admin role. Identity is
 *     the short-lived tv_sess bearer, enforced in the store (401 on a bad /
 *     expired / revoked token). ping and session need no token; ws is a
 *     Package-A stub (503 service_not_ready).
 *   A (/api/v1/tvhome/...) are post-auth admin routes; with no row in
 *     jmx_app_perms.c they inherit the MEDIUM default, which admits admin.
 *
 * The store validates its own inputs and is the sole DB owner, so this file
 * never touches SQLite or parses spec json beyond pulling a path id.
 */
#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "api_tvhome.h"
#include "api_error.h"
#include "webd_http_req.h"
#include "tvhome/tvhome_store.h"
#include "tvhome/tvhome_ws.h"
#include "tvhome/tvhome_ops.h"
#include "api_request.h"
#include "api_util.h"
#include "tvhome/tvhome_assets.h"
#include "tvhome/tvhome_packages.h"
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>

#define TVH_SOURCE          "webd.tvhome"
#define TVH_ID_BUF          128

#define TVH_PFX_THEMES      "/api/v1/tvhome/themes/"
#define TVH_PFX_TERMINALS   "/api/v1/tvhome/terminals/"
#define TVH_PFX_GROUPS      "/api/v1/tvhome/groups/"

/*
 * Map a store result onto the response. On success (err.http_status == 0) the
 * caller-owned data is wrapped in the standard envelope; otherwise data is NULL
 * and err carries a frozen error code (contract section 2) plus an optional
 * field locator.
 */
static struct json_object *tvh_reply(struct jmx_api_ctx *ctx,
                                     struct json_object *data,
                                     const struct tvhome_err *err)
{
    if (data && err->http_status == 0) {
        ctx->status = 200;
        return webd_envelope(data, TVH_SOURCE);
    }
    if (data)
        json_object_put(data);
    ctx->status = err->http_status ? err->http_status : 500;
    return webd_error(err->code[0] ? err->code : "internal_error",
                      err->message[0] ? err->message : "internal error",
                      err->field[0] ? err->field : "",
                      TVH_SOURCE);
}

/*
 * Split "<prefix><id>[/<action>]" into id and action. Returns 0 on a non-empty
 * id that fits, -1 otherwise. action points into path (borrowed) or "" when the
 * request is a bare "/<prefix><id>" with no sub-resource.
 */
static int tvh_split(const char *path, const char *prefix,
                     char *id, size_t idsz, const char **action)
{
    size_t plen = strlen(prefix);
    const char *tail, *slash;
    size_t idlen;

    *action = "";
    if (!path || strncmp(path, prefix, plen) != 0)
        return -1;
    tail = path + plen;
    slash = strchr(tail, '/');
    idlen = slash ? (size_t)(slash - tail) : strlen(tail);
    if (idlen == 0 || idlen >= idsz)
        return -1;
    memcpy(id, tail, idlen);
    id[idlen] = '\0';
    if (slash)
        *action = slash + 1;
    return 0;
}

/*
 * The TV-session bearer. "Authorization: Bearer tv_sess_..." is copied verbatim
 * into req.auth_token by webd's extract_bearer (any scheme value, <=64 chars;
 * a tv_sess token is 48). Returns "" when absent, which the store rejects 401.
 */
static const char *tvh_bearer(struct jmx_api_ctx *ctx)
{
    return ctx->req->auth_token;
}

/* not_found is the shared shape for a malformed / missing path id. */
static struct json_object *tvh_not_found(struct jmx_api_ctx *ctx,
                                         const char *field, const char *message)
{
    ctx->status = 404;
    return webd_error("resource_not_found", message, field, TVH_SOURCE);
}

/* ── T terminal surface (PREAUTH; store enforces the tv_sess token) ──────── */

static struct json_object *t_ping(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_ping(&e), &e);
}

static struct json_object *t_session_create(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_session_create(ctx->body, &e), &e);
}

static struct json_object *t_session_delete(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_session_delete(tvh_bearer(ctx), &e), &e);
}

static struct json_object *t_bootstrap(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_bootstrap(tvh_bearer(ctx), &e), &e);
}

static struct json_object *t_heartbeat(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_heartbeat(tvh_bearer(ctx), ctx->body, &e), &e);
}

static struct json_object *t_theme(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_theme_resolved(tvh_bearer(ctx), &e), &e);
}

static struct json_object *t_ws(struct jmx_api_ctx *ctx)
{
    tvhome_ws_session(ctx->fd, ctx->req);
    return NULL;
}
static struct json_object *t_activation(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx,tvhome_activation_request(ctx->body,&e),&e);
}
static struct json_object *t_activation_status(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    const char *id=ctx->req->path+strlen("/api/v1/tv/client/activations/");
    return tvh_reply(ctx,tvhome_activations(id,tvh_bearer(ctx),&e),&e);
}
static struct json_object *t_session_refresh(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx,tvhome_session_refresh(tvh_bearer(ctx),&e),&e);
}
static struct json_object *a_activations(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx,tvhome_activations(NULL,NULL,&e),&e);
}
static struct json_object *a_activation_decide(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e; char id[TVH_ID_BUF]; const char *action;
    if(tvh_split(ctx->req->path,"/api/v1/tvhome/activations/",id,sizeof(id),&action) ||
       (strcmp(action,"approve") && strcmp(action,"revoke"))) return tvh_not_found(ctx,"action","unknown activation action");
    return tvh_reply(ctx,tvhome_activation_decide(id,!strcmp(action,"approve"),ctx->body,&e),&e);
}
static struct json_object *a_terminal_action(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e; char id[TVH_ID_BUF]; const char *action;
    if(tvh_split(ctx->req->path,TVH_PFX_TERMINALS,id,sizeof(id),&action)) return tvh_not_found(ctx,"id","terminal id required");
    return tvh_reply(ctx,tvhome_terminal_action(id,action,&e),&e);
}

/* ── A management surface (post-auth admin) ─────────────────────────────── */

static struct json_object *a_overview(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_overview(&e), &e);
}

static struct json_object *a_settings_get(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_settings_get(&e), &e);
}

static struct json_object *a_settings_put(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_settings_put(ctx->body, &e), &e);
}

static struct json_object *a_themes_list(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_themes_list(&e), &e);
}

static struct json_object *a_theme_import(struct jmx_api_ctx *ctx) {struct tvhome_err e={0};return tvh_reply(ctx,tvhome_theme_import(ctx->body,&e),&e);}

static struct json_object *a_theme_create(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_theme_create(ctx->body, &e), &e);
}

/* validate + preview are side-effect free (contract 3 / schema rule 9). */
static struct json_object *a_theme_validate(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_theme_check(ctx->body, 0, &e), &e);
}

static struct json_object *a_theme_preview(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_theme_check(ctx->body, 1, &e), &e);
}

static struct json_object *a_theme_get(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_THEMES, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "theme id missing");
    if(!strcmp(action,"export"))return tvh_reply(ctx,tvhome_theme_export(id,&e),&e);
    if(*action)return tvh_not_found(ctx,"action","Unknown theme resource");
    return tvh_reply(ctx, tvhome_theme_get(id, &e), &e);
}

static struct json_object *a_theme_update(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_THEMES, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "theme id missing");
    return tvh_reply(ctx, tvhome_theme_update(id, ctx->body, &e), &e);
}

static struct json_object *a_theme_delete(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_THEMES, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "theme id missing");
    return tvh_reply(ctx, tvhome_theme_delete(id, &e), &e);
}

/*
 * POST /themes/:id/default and /themes/:id/duplicate share the POST prefix; the
 * exact /themes/validate and /themes/preview rows are matched earlier in the
 * table, so any other POST suffix here is an unknown sub-action.
 */
static struct json_object *a_theme_post_sub(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_THEMES, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "theme id missing");
    if (!strcmp(action,"reset"))return tvh_reply(ctx,tvhome_theme_reset(id,ctx->body,&e),&e);
    if (!strcmp(action, "default"))
        return tvh_reply(ctx, tvhome_theme_set_default(id, &e), &e);
    if (!strcmp(action, "duplicate"))
        return tvh_reply(ctx, tvhome_theme_duplicate(id, ctx->body, &e), &e);
    return tvh_not_found(ctx, "", "unknown theme sub-action");
}

static struct json_object *a_terminals_list(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_terminals_list(&e), &e);
}

/* GET /terminals/:id/display is the only terminal sub-resource (contract 3). */
static struct json_object *a_terminal_get_sub(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_TERMINALS, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "terminal id missing");
    if (!strcmp(action, "display"))
        return tvh_reply(ctx, tvhome_terminal_display_get(id, &e), &e);
    return tvh_not_found(ctx, "", "unknown terminal sub-resource");
}

/* PUT /terminals/:id (profile) or /terminals/:id/display (override layer). */
static struct json_object *a_terminal_put_sub(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_TERMINALS, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "terminal id missing");
    if (!action[0])
        return tvh_reply(ctx, tvhome_terminal_update(id, ctx->body, &e), &e);
    if (!strcmp(action, "display"))
        return tvh_reply(ctx, tvhome_terminal_display_put(id, ctx->body, &e), &e);
    return tvh_not_found(ctx, "", "unknown terminal sub-resource");
}

static struct json_object *a_terminal_delete(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_TERMINALS, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "terminal id missing");
    return tvh_reply(ctx, tvhome_terminal_delete(id, &e), &e);
}

static struct json_object *a_groups_list(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_groups_list(&e), &e);
}

static struct json_object *a_group_create(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    return tvh_reply(ctx, tvhome_group_create(ctx->body, &e), &e);
}

/* PUT /groups/:id (profile) or /groups/:id/display (group override layer). */
static struct json_object *a_group_put_sub(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_GROUPS, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "group id missing");
    if (!action[0])
        return tvh_reply(ctx, tvhome_group_update(id, ctx->body, &e), &e);
    if (!strcmp(action, "display"))
        return tvh_reply(ctx, tvhome_group_display_put(id, ctx->body, &e), &e);
    return tvh_not_found(ctx, "", "unknown group sub-resource");
}

static struct json_object *a_group_delete(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e;
    char id[TVH_ID_BUF];
    const char *action;

    if (tvh_split(ctx->req->path, TVH_PFX_GROUPS, id, sizeof(id), &action) != 0)
        return tvh_not_found(ctx, "id", "group id missing");
    return tvh_reply(ctx, tvhome_group_delete(id, &e), &e);
}

static struct json_object *a_group_get_sub(struct jmx_api_ctx *ctx)
{
    struct tvhome_err e; char id[TVH_ID_BUF]; const char *action;
    if(tvh_split(ctx->req->path,TVH_PFX_GROUPS,id,sizeof(id),&action) || strcmp(action,"display")) return tvh_not_found(ctx,"action","unknown group resource");
    return tvh_reply(ctx,tvhome_group_display_get(id,&e),&e);
}

/*
 * Route table. Declaration order is dispatch order (first match wins), so the
 * exact /themes/validate and /themes/preview rows precede the /themes/ POST
 * prefix, and every bare-collection GET (/themes, /terminals, /groups) precedes
 * its trailing-slash prefix sibling. seqs are a fresh 924-949 append block above
 * the current max (923); real, unique, never 0 (api_router.h append-block rule).
 */

static struct json_object *a_asset_storage(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,tvhome_assets_storage(!strcmp(ctx->req->method,"GET")?NULL:ctx->body,&e),&e);
}
static struct json_object *a_assets(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,!strcmp(ctx->req->method,"GET")?tvhome_assets_get(NULL,&e):tvhome_asset_create(ctx->body,&e),&e);
}
static struct json_object *a_asset_sub(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char id[128];const char *action;
    if(tvh_split(ctx->req->path,"/api/v1/tvhome/assets/",id,sizeof(id),&action))return tvh_not_found(ctx,"id","Asset missing");
    if(!strcmp(action,"complete")&&!strcmp(ctx->req->method,"POST"))return tvh_reply(ctx,tvhome_asset_complete(id,&e),&e);
    if(*action)return tvh_not_found(ctx,"action","Unknown asset operation");
    if(!strcmp(ctx->req->method,"GET"))return tvh_reply(ctx,tvhome_assets_get(id,&e),&e);
    if(!strcmp(ctx->req->method,"PUT"))return tvh_reply(ctx,tvhome_asset_update(id,ctx->body,&e),&e);
    if(!strcmp(ctx->req->method,"DELETE"))return tvh_reply(ctx,tvhome_asset_delete(id,&e),&e);
    return tvh_not_found(ctx,"method","Unknown asset operation");
}
static int tvh_asset_content_path(const char *path) {
    char id[128];const char *action;return !tvh_split(path,"/api/v1/tvhome/assets/",id,sizeof(id),&action)&&!strcmp(action,"content");
}
static struct json_object *tvh_stream_file(struct jmx_api_ctx *ctx,int file,const char *mime,int64_t size) {
    char header[640],range[160]="";
    unsigned long long first=0,last=(unsigned long long)size-1,a=0,b=0;int status=200;
    if(*ctx->req->range){int used=0,valid=0;
        if(sscanf(ctx->req->range,"bytes=%llu-%llu%n",&a,&b,&used)==2&&used>0&&!ctx->req->range[used]){first=a;last=b<(unsigned long long)size?b:(unsigned long long)size-1;valid=1;}
        else {used=0;if(sscanf(ctx->req->range,"bytes=%llu-%n",&a,&used)==1&&used>0&&!ctx->req->range[used]){first=a;valid=1;}
        else {used=0;if(sscanf(ctx->req->range,"bytes=-%llu%n",&b,&used)==1&&used>0&&!ctx->req->range[used]&&b){first=b<(unsigned long long)size?(unsigned long long)size-b:0;valid=1;}}}
        if(!valid||first>last||first>=(unsigned long long)size){int n=snprintf(header,sizeof(header),"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */%lld\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",(long long)size);webd_write_all(ctx->fd,header,n);close(file);ctx->status=416;return NULL;}
        status=206;snprintf(range,sizeof(range),"Content-Range: bytes %llu-%llu/%lld\r\n",first,last,(long long)size);
    }
    int n=snprintf(header,sizeof(header),"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %llu\r\nAccept-Ranges: bytes\r\nCache-Control: private, no-store\r\nX-Content-Type-Options: nosniff\r\n%sConnection: close\r\n\r\n",status,status==206?"Partial Content":"OK",mime,last-first+1,range);
    struct timeval timeout={5,0};setsockopt(ctx->fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    if(!webd_write_all(ctx->fd,header,n)&&strcmp(ctx->req->method,"HEAD")){
        unsigned char buf[65536];unsigned long long remaining=last-first+1;lseek(file,(off_t)first,SEEK_SET);
        while(remaining){ssize_t count=read(file,buf,remaining<sizeof(buf)?remaining:sizeof(buf));if(count<0&&errno==EINTR)continue;if(count<=0||webd_write_all(ctx->fd,buf,count))break;remaining-=count;}
    }
    close(file);ctx->status=status;return NULL;
}
static struct json_object *tvh_asset_bytes(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char id[128],mime[64];const char *action;
    int terminal=!strncmp(ctx->req->path,"/api/v1/tv/client/",18);
    if(tvh_split(ctx->req->path,terminal?"/api/v1/tv/client/assets/":"/api/v1/tvhome/assets/",id,sizeof(id),&action)||
       (terminal?*action:strcmp(action,"content")))return tvh_not_found(ctx,"id","Asset content missing");
    if(!strcmp(ctx->req->method,"PUT")){
        char offset[32],*end=NULL;if(!webd_query_get(ctx->req->query,"offset",offset,sizeof(offset)))return tvh_not_found(ctx,"offset","Upload offset missing");
        errno=0;long long position=strtoll(offset,&end,10);
        if(errno||!end||*end||position<0){e.http_status=400;strcpy(e.code,"invalid_offset");return tvh_reply(ctx,NULL,&e);}
        return tvh_reply(ctx,tvhome_asset_chunk(id,position,ctx->req->body,(size_t)ctx->req->body_len,&e),&e);
    }
    int64_t size=0;int file=tvhome_asset_open(id,terminal?tvh_bearer(ctx):NULL,mime,sizeof(mime),&size,&e);
    if(file<0)return tvh_reply(ctx,NULL,&e);
    return tvh_stream_file(ctx,file,mime,size);
}

static struct json_object *a_notice(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,!strcmp(ctx->req->method,"GET")?tvhome_notice_get(&e):tvhome_notice_put(ctx->body,&e),&e);
}
static struct json_object *a_commands(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,!strcmp(ctx->req->method,"GET")?tvhome_commands_get(NULL,&e):tvhome_command_create(ctx->body,&e),&e);
}
static struct json_object *a_command_sub(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char id[128];const char *action;
    if(tvh_split(ctx->req->path,"/api/v1/tvhome/commands/",id,sizeof(id),&action))return tvh_not_found(ctx,"command_id","Command missing");
    if(!strcmp(ctx->req->method,"GET")&&!*action)return tvh_reply(ctx,tvhome_commands_get(id,&e),&e);
    if(!strcmp(ctx->req->method,"POST")&&!strcmp(action,"stop"))return tvh_reply(ctx,tvhome_command_stop(id,&e),&e);
    return tvh_not_found(ctx,"action","Unknown command operation");
}
static struct json_object *t_command_ack(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char id[128];const char *action;
    if(tvh_split(ctx->req->path,"/api/v1/tv/client/commands/",id,sizeof(id),&action)||strcmp(action,"ack"))return tvh_not_found(ctx,"command_id","Command acknowledgement missing");
    return tvh_reply(ctx,tvhome_command_ack(tvh_bearer(ctx),id,ctx->body,&e),&e);
}
static struct json_object *t_event(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,tvhome_event_create(tvh_bearer(ctx),ctx->body,&e),&e);
}
static struct json_object *a_events(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};struct json_object *params=json_object_new_object();char value[160];const char *keys[]={"terminal_id","kind","before_ms","limit","before_id",NULL};
    for(int i=0;keys[i];i++)if(webd_query_get(ctx->req->query,keys[i],value,sizeof(value))>0)json_object_object_add(params,keys[i],i<2?json_object_new_string(value):json_object_new_int64(strtoll(value,NULL,10)));
    struct json_object *o=tvhome_events_get(params,&e);json_object_put(params);return tvh_reply(ctx,o,&e);
}

static struct json_object *a_packages(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,!strcmp(ctx->req->method,"GET")?tvhome_packages_get(NULL,&e):tvhome_package_create(ctx->body,&e),&e);
}
static struct json_object *a_package_sub(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char id[128];const char *action;
    if(tvh_split(ctx->req->path,"/api/v1/tvhome/packages/",id,sizeof(id),&action))return tvh_not_found(ctx,"id","APK missing");
    if(!strcmp(action,"complete")&&!strcmp(ctx->req->method,"POST"))return tvh_reply(ctx,tvhome_package_complete(id,&e),&e);
    if(*action)return tvh_not_found(ctx,"action","Unknown APK operation");
    if(!strcmp(ctx->req->method,"GET"))return tvh_reply(ctx,tvhome_packages_get(id,&e),&e);
    if(!strcmp(ctx->req->method,"PUT"))return tvh_reply(ctx,tvhome_package_update(id,ctx->body,&e),&e);
    if(!strcmp(ctx->req->method,"DELETE"))return tvh_reply(ctx,tvhome_package_delete(id,&e),&e);
    return tvh_not_found(ctx,"method","Unknown APK operation");
}
static int tvh_package_content_path(const char *path) {
    char id[128];const char *action;return !tvh_split(path,"/api/v1/tvhome/packages/",id,sizeof(id),&action)&&!strcmp(action,"content");
}
static struct json_object *a_package_bytes(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char id[128],offset[32],*end=NULL;const char *action;
    if(tvh_split(ctx->req->path,"/api/v1/tvhome/packages/",id,sizeof(id),&action)||!webd_query_get(ctx->req->query,"offset",offset,sizeof(offset)))return tvh_not_found(ctx,"offset","APK and offset required");
    errno=0;long long position=strtoll(offset,&end,10);if(errno||!end||*end||position<0){e.http_status=400;strcpy(e.code,"invalid_offset");return tvh_reply(ctx,NULL,&e);}
    return tvh_reply(ctx,tvhome_package_chunk(id,position,ctx->req->body,(size_t)ctx->req->body_len,&e),&e);
}
static struct json_object *a_release_source(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char channel[16]="stable";webd_query_get(ctx->req->query,"channel",channel,sizeof(channel));return tvh_reply(ctx,tvhome_release_source(channel,&e),&e);
}
static struct json_object *a_release_import(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,tvhome_release_import(tv_str(ctx->body,"channel"),&e),&e);
}
static struct json_object *t_packages(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};return tvh_reply(ctx,tvhome_packages_check(tvh_bearer(ctx),!strcmp(ctx->req->method,"POST")?ctx->body:NULL,&e),&e);
}
static struct json_object *t_package_sub(struct jmx_api_ctx *ctx) {
    struct tvhome_err e={0};char id[128];const char *action;
    if(tvh_split(ctx->req->path,"/api/v1/tv/client/packages/",id,sizeof(id),&action))return tvh_not_found(ctx,"id","APK missing");
    if(!strcmp(action,"result")&&!strcmp(ctx->req->method,"POST"))return tvh_reply(ctx,tvhome_package_result(tvh_bearer(ctx),id,ctx->body,&e),&e);
    if(!strcmp(action,"download")&&(!strcmp(ctx->req->method,"GET")||!strcmp(ctx->req->method,"HEAD"))){int64_t size=0;int fd=tvhome_package_open(id,tvh_bearer(ctx),&size,&e);if(fd<0)return tvh_reply(ctx,NULL,&e);return tvh_stream_file(ctx,fd,"application/vnd.android.package-archive",size);}
    return tvh_not_found(ctx,"action","Unknown APK operation");
}

const struct jmx_api_route tvhome_api_routes[] = {
    /* T TV client surface — PREAUTH; the store enforces the tv_sess bearer. */
    JMX_API_ROUTE(924, "/api/v1/tv/client/ping",      "GET",    JMX_API_PREAUTH, t_ping),
    JMX_API_ROUTE(925, "/api/v1/tv/client/session",   "POST",   JMX_API_PREAUTH, t_session_create),
    JMX_API_ROUTE(926, "/api/v1/tv/client/session",   "DELETE", JMX_API_PREAUTH, t_session_delete),
    JMX_API_ROUTE(927, "/api/v1/tv/client/bootstrap", "GET",    JMX_API_PREAUTH, t_bootstrap),
    JMX_API_ROUTE(928, "/api/v1/tv/client/heartbeat", "POST",   JMX_API_PREAUTH, t_heartbeat),
    JMX_API_ROUTE(929, "/api/v1/tv/client/ws",        "GET",    JMX_API_PREAUTH | JMX_API_RAW_FD, t_ws),
    JMX_API_ROUTE(930, "/api/v1/tv/client/theme",     "GET",    JMX_API_PREAUTH, t_theme),

    /* A management surface — post-auth admin (no perms row => MEDIUM default). */
    JMX_API_ROUTE(931, "/api/v1/tvhome/overview",        "GET",    JMX_API_EXACT,  a_overview),
    JMX_API_ROUTE(932, "/api/v1/tvhome/settings",        "GET",    JMX_API_EXACT,  a_settings_get),
    JMX_API_ROUTE(933, "/api/v1/tvhome/settings",        "PUT",    JMX_API_EXACT,  a_settings_put),
    JMX_API_ROUTE(934, "/api/v1/tvhome/themes",          "GET",    JMX_API_EXACT,  a_themes_list),
    JMX_API_ROUTE(935, "/api/v1/tvhome/themes",          "POST",   JMX_API_EXACT,  a_theme_create),
    JMX_API_ROUTE(936, "/api/v1/tvhome/themes/validate", "POST",   JMX_API_EXACT,  a_theme_validate),
    JMX_API_ROUTE(937, "/api/v1/tvhome/themes/preview",  "POST",   JMX_API_EXACT,  a_theme_preview),
    JMX_API_ROUTE(9617, "/api/v1/tvhome/themes/import", "POST", JMX_API_EXACT, a_theme_import),
    JMX_API_ROUTE(938, "/api/v1/tvhome/themes/",         "GET",    JMX_API_PREFIX, a_theme_get),
    JMX_API_ROUTE(939, "/api/v1/tvhome/themes/",         "PUT",    JMX_API_PREFIX, a_theme_update),
    JMX_API_ROUTE(940, "/api/v1/tvhome/themes/",         "DELETE", JMX_API_PREFIX, a_theme_delete),
    JMX_API_ROUTE(941, "/api/v1/tvhome/themes/",         "POST",   JMX_API_PREFIX, a_theme_post_sub),
    JMX_API_ROUTE(942, "/api/v1/tvhome/terminals",       "GET",    JMX_API_EXACT,  a_terminals_list),
    JMX_API_ROUTE(943, "/api/v1/tvhome/terminals/",      "GET",    JMX_API_PREFIX, a_terminal_get_sub),
    JMX_API_ROUTE(944, "/api/v1/tvhome/terminals/",      "PUT",    JMX_API_PREFIX, a_terminal_put_sub),
    JMX_API_ROUTE(945, "/api/v1/tvhome/terminals/",      "DELETE", JMX_API_PREFIX, a_terminal_delete),
    JMX_API_ROUTE(946, "/api/v1/tvhome/groups",          "GET",    JMX_API_EXACT,  a_groups_list),
    JMX_API_ROUTE(947, "/api/v1/tvhome/groups",          "POST",   JMX_API_EXACT,  a_group_create),
    JMX_API_ROUTE(948, "/api/v1/tvhome/groups/",         "PUT",    JMX_API_PREFIX, a_group_put_sub),
    JMX_API_ROUTE(949, "/api/v1/tvhome/groups/",         "DELETE", JMX_API_PREFIX, a_group_delete),
    JMX_API_ROUTE(1102, "/api/v1/tv/client/activations", "POST", JMX_API_PREAUTH, t_activation),
    JMX_API_ROUTE(1103, "/api/v1/tv/client/activations/", "GET", JMX_API_PREAUTH | JMX_API_PREFIX, t_activation_status),
    JMX_API_ROUTE(1104, "/api/v1/tv/client/session/refresh", "POST", JMX_API_PREAUTH, t_session_refresh),
    JMX_API_ROUTE(1105, "/api/v1/tvhome/activations", "GET", JMX_API_EXACT, a_activations),
    JMX_API_ROUTE(1106, "/api/v1/tvhome/activations/", "POST", JMX_API_PREFIX, a_activation_decide),
    JMX_API_ROUTE(1107, "/api/v1/tvhome/terminals/", "POST", JMX_API_PREFIX, a_terminal_action),
    JMX_API_ROUTE(9615, "/api/v1/tvhome/groups/", "GET", JMX_API_PREFIX, a_group_get_sub),
    JMX_API_ROUTE(9616, "/api/v1/tvhome/notice", "GET,PUT", JMX_API_EXACT, a_notice),
    JMX_API_ROUTE(1114, "/api/v1/tvhome/commands", "GET,POST", JMX_API_EXACT, a_commands),
    JMX_API_ROUTE(1115, "/api/v1/tvhome/commands/", "GET,POST", JMX_API_PREFIX, a_command_sub),
    JMX_API_ROUTE(1116, "/api/v1/tv/client/commands/", "POST", JMX_API_PREAUTH | JMX_API_PREFIX, t_command_ack),
    JMX_API_ROUTE(1117, "/api/v1/tv/client/events", "POST", JMX_API_PREAUTH, t_event),
    JMX_API_ROUTE(1118, "/api/v1/tvhome/events", "GET", JMX_API_EXACT, a_events),
    JMX_API_ROUTE(1119, "/api/v1/tvhome/assets/storage", "GET,PUT", JMX_API_EXACT, a_asset_storage),
    JMX_API_ROUTE(1120, "/api/v1/tvhome/assets", "GET,POST", JMX_API_EXACT, a_assets),
    JMX_API_PREDICATE_ROUTE(1121, "/api/v1/tvhome/assets/{id}/content", "GET,HEAD,PUT", JMX_API_PREDICATE_ONLY | JMX_API_NO_BODY | JMX_API_RAW_FD, tvh_asset_content_path, tvh_asset_bytes),
    JMX_API_ROUTE(1122, "/api/v1/tvhome/assets/", "GET,PUT,POST,DELETE", JMX_API_PREFIX, a_asset_sub),
    JMX_API_ROUTE(1123, "/api/v1/tv/client/assets/", "GET,HEAD", JMX_API_PREAUTH | JMX_API_PREFIX | JMX_API_RAW_FD, tvh_asset_bytes),
    JMX_API_ROUTE(9600, "/api/v1/tvhome/packages", "GET,POST", JMX_API_EXACT, a_packages),
    JMX_API_PREDICATE_ROUTE(9601, "/api/v1/tvhome/packages/{id}/content", "PUT", JMX_API_PREDICATE_ONLY | JMX_API_NO_BODY, tvh_package_content_path, a_package_bytes),
    JMX_API_ROUTE(9602, "/api/v1/tvhome/packages/", "GET,PUT,POST,DELETE", JMX_API_PREFIX, a_package_sub),
    JMX_API_ROUTE(9603, "/api/v1/tvhome/releases/source", "GET", JMX_API_EXACT, a_release_source),
    JMX_API_ROUTE(9604, "/api/v1/tvhome/releases/import", "POST", JMX_API_EXACT, a_release_import),
    JMX_API_ROUTE(9605, "/api/v1/tv/client/packages", "GET", JMX_API_PREAUTH, t_packages),
    JMX_API_ROUTE(9606, "/api/v1/tv/client/packages/check", "POST", JMX_API_PREAUTH, t_packages),
    JMX_API_ROUTE(9607, "/api/v1/tv/client/packages/", "GET,HEAD,POST", JMX_API_PREAUTH | JMX_API_PREFIX | JMX_API_RAW_FD, t_package_sub),
    JMX_API_ROUTE_END,
};
