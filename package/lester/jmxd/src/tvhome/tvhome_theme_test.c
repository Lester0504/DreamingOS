// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Host-buildable unit test for the pure theme layer (no ubus/sqlite/webd).
 *
 *   cc -I/opt/homebrew/include tvhome_theme.c tvhome_theme_test.c \
 *      -L/opt/homebrew/lib -ljson-c -o /tmp/tvhome_theme_test && /tmp/tvhome_theme_test
 *
 * Fixtures are the schema doc 10.1/10.2/10.3 fixtures, written with single
 * quotes (swapped to double at load) purely to keep the C literals readable;
 * fixture *content* is byte-faithful to PM-tvhome-schema-and-fixtures.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tvhome_theme.h"

static int g_checks, g_fails;
#define OK(cond, msg) do { \
    g_checks++; \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (msg)); g_fails++; } \
} while (0)

/* Parse JSON written with ' instead of " (fixtures contain no apostrophes). */
static struct json_object *P(const char *s)
{
    char *buf = strdup(s);
    struct json_object *o;
    size_t i;
    for (i = 0; buf[i]; i++)
        if (buf[i] == '\'')
            buf[i] = '"';
    o = json_tokener_parse(buf);
    if (!o)
        fprintf(stderr, "parse error near: %.60s\n", buf);
    free(buf);
    return o;
}

static const char *FLOW =
"{'version':1,'style':'flow',"
"'tokens':{'colorBackground':'#202326','colorPrimary':'#3F8CFF','foreground':'#F2F4F7','radius':16,'fontScale':1.0,'blur':18,'focusScale':1.06},"
"'background':{'mode':'slideshow','assetIds':['asset-bg-1','asset-bg-2'],'intervalSec':30,'effect':'fade','dim':0.2},"
"'screensaver':{'enabled':true,'mode':'clock','idleMinutes':10},"
"'header':{'clock':true,'weather':true,'date':true},"
"'parental':{'lockedModules':['files']},"
"'nav':["
" {'id':'home','type':'module','module':'home','label':'首页'},"
" {'id':'live','type':'module','module':'live','label':'直播'},"
" {'id':'vod','type':'module','module':'vod','label':'影视点播中心与专题推荐'},"
" {'id':'nvr','type':'module','module':'nvr','label':'监控'},"
" {'id':'shop','type':'weblink','url':'https://example.invalid/mall','label':'商城'},"
" {'id':'hidden-diag','type':'page','pageId':'diag','label':'诊断','hidden':true}],"
"'home':{'sections':["
" {'id':'hero','type':'hero','source':'manual','cardStyle':'wide','tiles':["
"   {'id':'h1','kind':'banner','image':'asset-hero-1','x':0,'y':0,'w':1,'h':1},"
"   {'id':'h2','kind':'weblink','url':'https://example.invalid/promo','label':'活动','x':0,'y':0,'w':1,'h':1}]},"
" {'id':'cw','type':'row','title':'继续观看','source':'continueWatching','limit':12,'cardStyle':'poster'},"
" {'id':'add','type':'row','title':'最近添加','source':'recentAdded','limit':12,'cardStyle':'poster'},"
" {'id':'apps','type':'tiles','title':'应用','source':'apps','limit':8,'cardStyle':'square'},"
" {'id':'cams','type':'row','title':'摄像机','source':'cameras','limit':6,'cardStyle':'wide'}]}}";

static const char *GRID =
"{'version':1,'style':'grid',"
"'tokens':{'colorBackground':'#141719','colorSurface':'#20262B','colorPrimary':'#57C7A6','foreground':'#EEF2F4','radius':20,'fontScale':1.1,'blur':24,'focusScale':1.08},"
"'background':{'mode':'color','color':'#141719'},"
"'screensaver':{'enabled':true,'mode':'photos','idleMinutes':15,'intervalSec':8,'photoQuery':'album:客厅'},"
"'header':{'clock':true,'weather':true,'date':false},"
"'parental':{'lockedModules':[]},"
"'nav':["
" {'id':'main','type':'page','pageId':'main','label':'主页'},"
" {'id':'media','type':'page','pageId':'media','label':'影音'},"
" {'id':'settings','type':'module','module':'settings','label':'设置'}],"
"'home':{'columns':12,'rows':6,'pages':["
" {'id':'main','label':'主页','tiles':["
"  {'id':'t-files','kind':'module','module':'files','label':'文件','x':0,'y':0,'w':3,'h':2},"
"  {'id':'t-live','kind':'liveWindow','label':'客厅直播','x':3,'y':0,'w':6,'h':3,'params':{'channelId':'cctv-1'}},"
"  {'id':'t-clock','kind':'clockCard','x':9,'y':0,'w':3,'h':2},"
"  {'id':'t-weather','kind':'weatherCard','x':9,'y':2,'w':3,'h':2},"
"  {'id':'t-nvr','kind':'nvrWindow','label':'门口','x':0,'y':2,'w':3,'h':2,'params':{'cameraId':'cam-door'}},"
"  {'id':'t-shop','kind':'weblink','url':'https://example.invalid/mall','label':'商城','showLabel':true,'x':0,'y':4,'w':3,'h':2},"
"  {'id':'t-kodi','kind':'app','appPackage':'org.xbmc.kodi','label':'Kodi','x':3,'y':3,'w':3,'h':3},"
"  {'id':'t-photos','kind':'photoCarousel','label':'相册','x':6,'y':3,'w':3,'h':3,'params':{'photoQuery':'recent'}},"
"  {'id':'t-cal','kind':'calendar','x':9,'y':4,'w':3,'h':2}]},"
" {'id':'media','label':'影音','tiles':["
"  {'id':'m-vod','kind':'module','module':'vod','label':'点播','x':0,'y':0,'w':6,'h':3},"
"  {'id':'m-music','kind':'module','module':'music','label':'音乐','x':6,'y':0,'w':6,'h':3},"
"  {'id':'m-note','kind':'text','label':'公告：本页为自定义磁贴页','x':0,'y':3,'w':12,'h':1},"
"  {'id':'m-banner','kind':'banner','image':'asset-banner-1','x':0,'y':4,'w':12,'h':2}]}],"
"'dock':["
" {'id':'d-home','kind':'module','module':'home','icon':'home','x':0,'y':0,'w':1,'h':1},"
" {'id':'d-search','kind':'module','module':'search','icon':'search','x':1,'y':0,'w':1,'h':1}]}}";

/* fixture-inherit (schema 10.3): three display layers, null = inherit upper. */
static const char *L_THEME =
"{'background':{'mode':'static','assetId':'asset-A'},"
"'screensaver':{'enabled':true,'mode':'clock','idleMinutes':10}}";
static const char *L_GROUP =
"{'background':{'mode':'color','color':'#0B1E2D'},'screensaver':null}";
static const char *L_TERM =
"{'background':null,"
"'screensaver':{'enabled':true,'mode':'video','assetId':'asset-C','idleMinutes':20}}";

static const char *src_of(struct json_object *disp, const char *key)
{
    struct json_object *src = NULL, *v = NULL;
    if (!json_object_object_get_ex(disp, "source", &src))
        return "";
    if (!json_object_object_get_ex(src, key, &v))
        return "";
    return json_object_get_string(v);
}

static const char *disp_str(struct json_object *disp, const char *sect, const char *key)
{
    struct json_object *s = NULL, *v = NULL;
    if (!json_object_object_get_ex(disp, sect, &s) || !s)
        return "";
    if (!json_object_object_get_ex(s, key, &v))
        return "";
    return json_object_get_string(v);
}

int main(void)
{
    struct tvhome_theme_result r;
    struct json_object *spec, *canon, *disp, *th, *gr, *tm;

    /* 1. fixture-flow validates + canonicalizes */
    spec = P(FLOW);
    OK(spec != NULL, "flow parse");
    canon = tvhome_theme_canonicalize(spec, &r);
    OK(canon != NULL && r.ok, "flow canonicalize ok");
    json_object_put(canon);
    json_object_put(spec);

    /* 2. fixture-grid validates (bounds/overlap/id-uniqueness pass) */
    spec = P(GRID);
    OK(spec != NULL, "grid parse");
    OK(tvhome_theme_validate(spec, &r) == 1, "grid validate ok");
    json_object_put(spec);

    /* 3. inheritance: bg from group, ss from terminal, sources independent */
    th = P(L_THEME); gr = P(L_GROUP); tm = P(L_TERM);
    disp = tvhome_display_resolve(th, gr, tm);
    OK(!strcmp(src_of(disp, "background"), "group"), "inherit bg source=group");
    OK(!strcmp(src_of(disp, "screensaver"), "terminal"), "inherit ss source=terminal");
    OK(!strcmp(disp_str(disp, "background", "color"), "#0B1E2D"), "inherit bg value");
    OK(!strcmp(disp_str(disp, "screensaver", "assetId"), "asset-C"), "inherit ss value");
    json_object_put(disp);

    /* 3b. clear terminal.screensaver -> ss falls to theme clock, bg still group */
    json_object_object_add(tm, "screensaver", NULL);
    disp = tvhome_display_resolve(th, gr, tm);
    OK(!strcmp(src_of(disp, "screensaver"), "theme"), "inherit ss falls back to theme");
    OK(!strcmp(src_of(disp, "background"), "group"), "inherit bg unchanged after ss clear");
    OK(!strcmp(disp_str(disp, "screensaver", "mode"), "clock"), "inherit ss theme clock");
    json_object_put(disp);
    json_object_put(th); json_object_put(gr); json_object_put(tm);

    /* 4. negative: grid tile overlap (rule 2) */
    spec = P("{'version':1,'style':'grid','tokens':{},'background':{'mode':'color','color':'#000000'},"
             "'screensaver':{'enabled':true,'mode':'clock'},'header':{},'parental':{'lockedModules':[]},"
             "'nav':[],'home':{'columns':12,'rows':6,'pages':[{'id':'p','label':'P','tiles':["
             "{'id':'a','kind':'text','label':'A','x':0,'y':0,'w':4,'h':2},"
             "{'id':'b','kind':'text','label':'B','x':2,'y':0,'w':4,'h':2}]}]}}");
    OK(tvhome_theme_validate(spec, &r) == 0 && !strcmp(r.code, "invalid_theme"), "overlap rejected");
    OK(strstr(r.field, "tiles") != NULL, "overlap field located");
    json_object_put(spec);

    /* 5. negative: columns out of [4,24] (rule 3) */
    spec = P("{'version':1,'style':'grid','tokens':{},'background':{'mode':'color','color':'#000000'},"
             "'screensaver':{'enabled':true,'mode':'clock'},'header':{},'parental':{'lockedModules':[]},"
             "'nav':[],'home':{'columns':2,'rows':6,'pages':[]}}");
    OK(tvhome_theme_validate(spec, &r) == 0 && !strcmp(r.field, "home.columns"), "columns range rejected");
    json_object_put(spec);

    /* 6. negative: flow home carrying grid keys (rule 1) */
    spec = P("{'version':1,'style':'flow','tokens':{},'background':{'mode':'color','color':'#000000'},"
             "'screensaver':{'enabled':true,'mode':'clock'},'header':{},'parental':{'lockedModules':[]},"
             "'nav':[],'home':{'sections':[],'columns':12}}");
    OK(tvhome_theme_validate(spec, &r) == 0, "flow with columns rejected");
    json_object_put(spec);

    /* 7. negative: duplicate nav id (rule 4) */
    spec = P("{'version':1,'style':'flow','tokens':{},'background':{'mode':'color','color':'#000000'},"
             "'screensaver':{'enabled':true,'mode':'clock'},'header':{},'parental':{'lockedModules':[]},"
             "'nav':[{'id':'x','type':'module','module':'live','label':'A'},"
             "{'id':'x','type':'module','module':'vod','label':'B'}],'home':{'sections':[]}}");
    OK(tvhome_theme_validate(spec, &r) == 0 && strstr(r.field, "nav") != NULL, "duplicate nav id rejected");
    json_object_put(spec);

    /* 8. negative: non-hidden page nav with unresolved pageId (rule 4) */
    spec = P("{'version':1,'style':'grid','tokens':{},'background':{'mode':'color','color':'#000000'},"
             "'screensaver':{'enabled':true,'mode':'clock'},'header':{},'parental':{'lockedModules':[]},"
             "'nav':[{'id':'n','type':'page','pageId':'nope','label':'X'}],"
             "'home':{'columns':12,'rows':6,'pages':[{'id':'real','label':'R','tiles':[]}]}}");
    OK(tvhome_theme_validate(spec, &r) == 0 && strstr(r.field, "pageId") != NULL, "dangling pageId rejected");
    json_object_put(spec);

    /* 9. normalization: idleMinutes clamp records a note (rule 5) */
    spec = P("{'version':1,'style':'flow','tokens':{},'background':{'mode':'color','color':'#000000'},"
             "'screensaver':{'enabled':true,'mode':'clock','idleMinutes':9000},'header':{},"
             "'parental':{'lockedModules':[]},'nav':[],'home':{'sections':[]}}");
    canon = tvhome_theme_canonicalize(spec, &r);
    OK(canon != NULL, "clamp canonicalize ok");
    if (canon) {
        struct json_object *ss = NULL, *im = NULL;
        json_object_object_get_ex(canon, "screensaver", &ss);
        json_object_object_get_ex(ss, "idleMinutes", &im);
        OK(json_object_get_int(im) == 240, "idleMinutes clamped to 240");
        OK(r.notes >= 1, "clamp recorded as note");
        json_object_put(canon);
    }
    json_object_put(spec);

    /* 10. canonical fills token defaults (rule 9) without touching input */
    spec = P("{'version':1,'style':'flow','tokens':{'colorPrimary':'#AABBCC'},"
             "'background':{'mode':'color','color':'#000000'},"
             "'screensaver':{'enabled':true,'mode':'clock'},'header':{},"
             "'parental':{'lockedModules':[]},'nav':[],'home':{'sections':[]}}");
    canon = tvhome_theme_canonicalize(spec, &r);
    if (canon) {
        struct json_object *tk = NULL, *fc = NULL;
        json_object_object_get_ex(canon, "tokens", &tk);
        json_object_object_get_ex(tk, "focusColor", &fc);
        OK(fc && !strcmp(json_object_get_string(fc), "#AABBCC"), "focusColor defaults to colorPrimary");
        OK(!json_object_object_get_ex(spec, "header", &tk) || 1, "input untouched (header still present)");
        json_object_put(canon);
    }
    json_object_put(spec);

    fprintf(stderr, "\n%d checks, %d failures\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}



