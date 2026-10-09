// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * TVHome theme validation / canonicalization / display inheritance.
 *
 * Pure json-c. Schema truth source: PM-tvhome-schema-and-fixtures.md 2-9.
 * The cross-field constraints JSON Schema cannot express (tile overlap, bounds,
 * page-local id uniqueness, nav page-target resolution) live here (schema 7,9).
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "tvhome_theme.h"

/* ---- result helpers ---- */
static int theme_ok(struct tvhome_theme_result *res)
{
    res->ok = 1;
    res->code[0] = '\0';
    res->field[0] = '\0';
    res->message[0] = '\0';
    return 1;
}

static int theme_fail(struct tvhome_theme_result *res, const char *code,
                      const char *field, const char *message)
{
    res->ok = 0;
    snprintf(res->code, sizeof(res->code), "%s", code ? code : "invalid_theme");
    snprintf(res->field, sizeof(res->field), "%s", field ? field : "");
    snprintf(res->message, sizeof(res->message), "%s", message ? message : "invalid theme");
    return 0;
}

/* ---- json shape helpers (kept local so the unit test links standalone) ---- */
static struct json_object *obj_get(struct json_object *o, const char *k)
{
    struct json_object *v = NULL;
    if (o && json_object_is_type(o, json_type_object) &&
        json_object_object_get_ex(o, k, &v))
        return v;
    return NULL;
}

static int has_key(struct json_object *o, const char *k) { return obj_get(o, k) != NULL; }
static int is_arr(struct json_object *o) { return o && json_object_is_type(o, json_type_array); }
static int is_obj(struct json_object *o) { return o && json_object_is_type(o, json_type_object); }

static int as_int(struct json_object *o, int def)
{
    if (o && (json_object_is_type(o, json_type_int) || json_object_is_type(o, json_type_double)))
        return json_object_get_int(o);
    return def;
}

static const char *as_str(struct json_object *o)
{
    if (o && json_object_is_type(o, json_type_string))
        return json_object_get_string(o);
    return NULL;
}

static int str_in(const char *s, const char *const *set, size_t n)
{
    size_t i;
    if (!s)
        return 0;
    for (i = 0; i < n; i++)
        if (!strcmp(s, set[i]))
            return 1;
    return 0;
}

/* ---- tile validation (schema 7 rule 2) ---- */
static int tile_bounds(struct json_object *tile, int idx, int columns, int rows,
                       const char *ppath, int grid_bounds, struct tvhome_theme_result *res)
{
    char f[160];
    const char *id = as_str(obj_get(tile, "id"));
    const char *kind = as_str(obj_get(tile, "kind"));
    static const char *const kinds[] = {
        "module", "app", "weblink", "liveWindow", "photoCarousel", "weatherCard",
        "clockCard", "calendar", "banner", "nvrWindow", "text"
    };
    int x, y, w, h;

    if (!id || !id[0]) {
        snprintf(f, sizeof(f), "%s.tiles[%d].id", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "tile id required");
    }
    if (!str_in(kind, kinds, sizeof(kinds) / sizeof(kinds[0]))) {
        snprintf(f, sizeof(f), "%s.tiles[%d].kind", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "tile kind invalid");
    }
    if (!has_key(tile, "x") || !has_key(tile, "y") ||
        !has_key(tile, "w") || !has_key(tile, "h")) {
        snprintf(f, sizeof(f), "%s.tiles[%d]", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "tile requires x,y,w,h");
    }
    x = as_int(obj_get(tile, "x"), -1);
    y = as_int(obj_get(tile, "y"), -1);
    w = as_int(obj_get(tile, "w"), 0);
    h = as_int(obj_get(tile, "h"), 0);
    if (x < 0 || y < 0) {
        snprintf(f, sizeof(f), "%s.tiles[%d]", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "tile x,y must be >= 0");
    }
    if (w < 1 || h < 1) {
        snprintf(f, sizeof(f), "%s.tiles[%d]", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "tile w,h must be >= 1");
    }
    if (grid_bounds && x + w > columns) {
        snprintf(f, sizeof(f), "%s.tiles[%d].w", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "tile exceeds columns");
    }
    if (grid_bounds && y + h > rows) {
        snprintf(f, sizeof(f), "%s.tiles[%d].h", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "tile exceeds rows");
    }
    if (!strcmp(kind, "module") && !as_str(obj_get(tile, "module"))) {
        snprintf(f, sizeof(f), "%s.tiles[%d].module", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "module tile requires module");
    }
    if (!strcmp(kind, "app") && !as_str(obj_get(tile, "appPackage"))) {
        snprintf(f, sizeof(f), "%s.tiles[%d].appPackage", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "app tile requires appPackage");
    }
    if (!strcmp(kind, "weblink") && !as_str(obj_get(tile, "url"))) {
        snprintf(f, sizeof(f), "%s.tiles[%d].url", ppath, idx);
        return theme_fail(res, "invalid_theme", f, "weblink tile requires url");
    }
    return 1;
}

static int rects_overlap(struct json_object *a, struct json_object *b)
{
    int ax = as_int(obj_get(a, "x"), 0), ay = as_int(obj_get(a, "y"), 0);
    int aw = as_int(obj_get(a, "w"), 0), ah = as_int(obj_get(a, "h"), 0);
    int bx = as_int(obj_get(b, "x"), 0), by = as_int(obj_get(b, "y"), 0);
    int bw = as_int(obj_get(b, "w"), 0), bh = as_int(obj_get(b, "h"), 0);
    return ax < bx + bw && bx < ax + aw && ay < by + bh && by < ay + ah;
}

/* One grid page: tile bounds, page-local id uniqueness, no overlap (rule 2). */
static int validate_grid_page(struct json_object *page, int pidx, int columns, int rows,
                              struct tvhome_theme_result *res)
{
    char ppath[64], f[160];
    struct json_object *tiles;
    size_t n, i, j;

    snprintf(ppath, sizeof(ppath), "home.pages[%d]", pidx);
    if (!as_str(obj_get(page, "id"))) {
        snprintf(f, sizeof(f), "%s.id", ppath);
        return theme_fail(res, "invalid_theme", f, "page id required");
    }
    if (!as_str(obj_get(page, "label"))) {
        snprintf(f, sizeof(f), "%s.label", ppath);
        return theme_fail(res, "invalid_theme", f, "page label required");
    }
    tiles = obj_get(page, "tiles");
    if (!is_arr(tiles)) {
        snprintf(f, sizeof(f), "%s.tiles", ppath);
        return theme_fail(res, "invalid_theme", f, "page tiles array required");
    }
    n = json_object_array_length(tiles);
    for (i = 0; i < n; i++)
        if (!tile_bounds(json_object_array_get_idx(tiles, i), (int)i,
                         columns, rows, ppath, 1, res))
            return 0;
    for (i = 0; i < n; i++) {
        struct json_object *ti = json_object_array_get_idx(tiles, i);
        const char *idi = as_str(obj_get(ti, "id"));
        for (j = 0; j < i; j++) {
            struct json_object *tj = json_object_array_get_idx(tiles, j);
            const char *idj = as_str(obj_get(tj, "id"));
            if (idi && idj && !strcmp(idi, idj)) {
                snprintf(f, sizeof(f), "%s.tiles[%zu].id", ppath, i);
                return theme_fail(res, "invalid_theme", f, "duplicate tile id in page");
            }
            if (rects_overlap(ti, tj)) {
                snprintf(f, sizeof(f), "%s.tiles[%zu]", ppath, i);
                return theme_fail(res, "invalid_theme", f, "tiles overlap");
            }
        }
    }
    return 1;
}

/* ---- flow sections (schema 6.1) ---- */
static int validate_flow_sections(struct json_object *sections, struct tvhome_theme_result *res)
{
    static const char *const types[] = { "hero", "row", "tiles" };
    static const char *const sources[] = {
        "manual", "continueWatching", "liveNow", "recentPhotos",
        "recentAdded", "playlists", "apps", "cameras"
    };
    static const char *const cards[] = { "poster", "wide", "square", "circle" };
    size_t n, i, j;
    char f[160];

    n = json_object_array_length(sections);
    for (i = 0; i < n; i++) {
        struct json_object *sec = json_object_array_get_idx(sections, i);
        const char *id = as_str(obj_get(sec, "id"));
        const char *type = as_str(obj_get(sec, "type"));
        const char *source = as_str(obj_get(sec, "source"));
        const char *card = as_str(obj_get(sec, "cardStyle"));
        struct json_object *tiles;

        if (!id || !id[0]) {
            snprintf(f, sizeof(f), "home.sections[%zu].id", i);
            return theme_fail(res, "invalid_theme", f, "section id required");
        }
        if (!str_in(type, types, sizeof(types) / sizeof(types[0]))) {
            snprintf(f, sizeof(f), "home.sections[%zu].type", i);
            return theme_fail(res, "invalid_theme", f, "section type invalid");
        }
        if (!str_in(source, sources, sizeof(sources) / sizeof(sources[0]))) {
            snprintf(f, sizeof(f), "home.sections[%zu].source", i);
            return theme_fail(res, "invalid_theme", f, "section source invalid");
        }
        if (card && !str_in(card, cards, sizeof(cards) / sizeof(cards[0]))) {
            snprintf(f, sizeof(f), "home.sections[%zu].cardStyle", i);
            return theme_fail(res, "invalid_theme", f, "section cardStyle invalid");
        }
        for (j = 0; j < i; j++) {
            const char *pid = as_str(obj_get(json_object_array_get_idx(sections, j), "id"));
            if (pid && !strcmp(pid, id)) {
                snprintf(f, sizeof(f), "home.sections[%zu].id", i);
                return theme_fail(res, "invalid_theme", f, "duplicate section id");
            }
        }
        /* tiles only meaningful for manual source; validate without grid bounds */
        tiles = obj_get(sec, "tiles");
        if (is_arr(tiles)) {
            size_t t, tn = json_object_array_length(tiles);
            char sp[64];
            snprintf(sp, sizeof(sp), "home.sections[%zu]", i);
            for (t = 0; t < tn; t++)
                if (!tile_bounds(json_object_array_get_idx(tiles, t), (int)t, 0, 0, sp, 0, res))
                    return 0;
        }
    }
    return 1;
}

static int page_id_exists(struct json_object *home, const char *page_id)
{
    struct json_object *pages = obj_get(home, "pages");
    size_t n, i;
    if (!is_arr(pages) || !page_id)
        return 0;
    n = json_object_array_length(pages);
    for (i = 0; i < n; i++) {
        const char *pid = as_str(obj_get(json_object_array_get_idx(pages, i), "id"));
        if (pid && !strcmp(pid, page_id))
            return 1;
    }
    return 0;
}

/* ---- nav (schema 5, rule 4) ---- */
static int validate_nav(struct json_object *nav, struct json_object *home,
                        const char *style, struct tvhome_theme_result *res)
{
    static const char *const types[] = { "module", "page", "app", "weblink" };
    size_t n, i, j;
    char f[160];

    n = json_object_array_length(nav);
    for (i = 0; i < n; i++) {
        struct json_object *it = json_object_array_get_idx(nav, i);
        const char *id = as_str(obj_get(it, "id"));
        const char *type = as_str(obj_get(it, "type"));
        const char *label = as_str(obj_get(it, "label"));
        int hidden = obj_get(it, "hidden") &&
                     json_object_get_boolean(obj_get(it, "hidden"));

        if (!id || !id[0]) {
            snprintf(f, sizeof(f), "nav[%zu].id", i);
            return theme_fail(res, "invalid_theme", f, "nav id required");
        }
        if (!str_in(type, types, sizeof(types) / sizeof(types[0]))) {
            snprintf(f, sizeof(f), "nav[%zu].type", i);
            return theme_fail(res, "invalid_theme", f, "nav type invalid");
        }
        if (!label || !label[0]) {
            snprintf(f, sizeof(f), "nav[%zu].label", i);
            return theme_fail(res, "invalid_theme", f, "nav label required");
        }
        for (j = 0; j < i; j++) {
            const char *pid = as_str(obj_get(json_object_array_get_idx(nav, j), "id"));
            if (pid && !strcmp(pid, id)) {
                snprintf(f, sizeof(f), "nav[%zu].id", i);
                return theme_fail(res, "invalid_theme", f, "duplicate nav id");
            }
        }
        if (!strcmp(type, "module") && !as_str(obj_get(it, "module"))) {
            snprintf(f, sizeof(f), "nav[%zu].module", i);
            return theme_fail(res, "invalid_theme", f, "module nav requires module");
        }
        if (!strcmp(type, "app") && !as_str(obj_get(it, "appPackage"))) {
            snprintf(f, sizeof(f), "nav[%zu].appPackage", i);
            return theme_fail(res, "invalid_theme", f, "app nav requires appPackage");
        }
        if (!strcmp(type, "weblink") && !as_str(obj_get(it, "url"))) {
            snprintf(f, sizeof(f), "nav[%zu].url", i);
            return theme_fail(res, "invalid_theme", f, "weblink nav requires url");
        }
        if (!strcmp(type, "page")) {
            const char *page_id = as_str(obj_get(it, "pageId"));
            if (!page_id) {
                snprintf(f, sizeof(f), "nav[%zu].pageId", i);
                return theme_fail(res, "invalid_theme", f, "page nav requires pageId");
            }
            /* rule 4: pageId must resolve to a grid page. Hidden items are
             * retained-but-parked (schema 5 "隐藏但保留") and exempt from target
             * resolution; a flow theme has no grid pages so only hidden page-nav
             * is allowed there. */
            if (!hidden && (strcmp(style, "grid") || !page_id_exists(home, page_id))) {
                snprintf(f, sizeof(f), "nav[%zu].pageId", i);
                return theme_fail(res, "invalid_theme", f, "pageId does not resolve to a page");
            }
        }
    }
    return 1;
}

/* ---- top-level validate (schema 7 rules 1-4, plus required shape) ---- */
int tvhome_theme_validate(struct json_object *spec, struct tvhome_theme_result *res)
{
    static const char *const bg_modes[] = { "color", "static", "slideshow", "video", "photos" };
    static const char *const ss_modes[] = { "photos", "clock", "video", "black" };
    struct json_object *home, *nav, *bg, *ss;
    const char *style, *bg_mode, *ss_mode;

    if (!res)
        return 0;
    theme_ok(res);
    if (!is_obj(spec))
        return theme_fail(res, "invalid_theme", "", "spec must be an object");
    if (as_int(obj_get(spec, "version"), -1) != TVHOME_SPEC_VERSION)
        return theme_fail(res, "invalid_theme", "version", "spec.version must be 1");

    style = as_str(obj_get(spec, "style"));
    if (!style || (strcmp(style, "flow") && strcmp(style, "grid")))
        return theme_fail(res, "invalid_theme", "style", "style must be flow or grid");

    if (!is_obj(obj_get(spec, "tokens")))
        return theme_fail(res, "invalid_theme", "tokens", "tokens object required");
    if (!is_obj(obj_get(spec, "header")))
        return theme_fail(res, "invalid_theme", "header", "header object required");
    if (!is_obj(obj_get(spec, "parental")))
        return theme_fail(res, "invalid_theme", "parental", "parental object required");

    bg = obj_get(spec, "background");
    if (!is_obj(bg))
        return theme_fail(res, "invalid_theme", "background", "background object required");
    bg_mode = as_str(obj_get(bg, "mode"));
    if (!str_in(bg_mode, bg_modes, sizeof(bg_modes) / sizeof(bg_modes[0])))
        return theme_fail(res, "invalid_theme", "background.mode", "background.mode invalid");

    ss = obj_get(spec, "screensaver");
    if (!is_obj(ss))
        return theme_fail(res, "invalid_theme", "screensaver", "screensaver object required");
    if (!has_key(ss, "enabled"))
        return theme_fail(res, "invalid_theme", "screensaver.enabled", "screensaver.enabled required");
    ss_mode = as_str(obj_get(ss, "mode"));
    if (!str_in(ss_mode, ss_modes, sizeof(ss_modes) / sizeof(ss_modes[0])))
        return theme_fail(res, "invalid_theme", "screensaver.mode", "screensaver.mode invalid");

    home = obj_get(spec, "home");
    if (!is_obj(home))
        return theme_fail(res, "invalid_theme", "home", "home object required");
    nav = obj_get(spec, "nav");
    if (!is_arr(nav))
        return theme_fail(res, "invalid_theme", "nav", "nav array required");

    if (!strcmp(style, "flow")) {
        if (!is_arr(obj_get(home, "sections")))
            return theme_fail(res, "invalid_theme", "home.sections", "flow home requires sections");
        if (has_key(home, "columns") || has_key(home, "rows") || has_key(home, "pages"))
            return theme_fail(res, "invalid_theme", "home",
                              "flow home must not carry columns/rows/pages");
        if (!validate_flow_sections(obj_get(home, "sections"), res))
            return 0;
    } else {
        struct json_object *pages, *dock;
        int columns, rows;
        size_t np, i, j;

        if (!has_key(home, "columns") || !has_key(home, "rows") || !is_arr(obj_get(home, "pages")))
            return theme_fail(res, "invalid_theme", "home", "grid home requires columns,rows,pages");
        columns = as_int(obj_get(home, "columns"), -1);
        rows = as_int(obj_get(home, "rows"), -1);
        if (columns < TVHOME_GRID_COLS_MIN || columns > TVHOME_GRID_COLS_MAX)
            return theme_fail(res, "invalid_theme", "home.columns", "columns out of [4,24]");
        if (rows < TVHOME_GRID_ROWS_MIN || rows > TVHOME_GRID_ROWS_MAX)
            return theme_fail(res, "invalid_theme", "home.rows", "rows out of [2,12]");
        pages = obj_get(home, "pages");
        np = json_object_array_length(pages);
        for (i = 0; i < np; i++)
            if (!validate_grid_page(json_object_array_get_idx(pages, i), (int)i, columns, rows, res))
                return 0;
        for (i = 0; i < np; i++) {
            const char *idi = as_str(obj_get(json_object_array_get_idx(pages, i), "id"));
            for (j = 0; j < i; j++) {
                const char *idj = as_str(obj_get(json_object_array_get_idx(pages, j), "id"));
                if (idi && idj && !strcmp(idi, idj)) {
                    char f[64];
                    snprintf(f, sizeof(f), "home.pages[%zu].id", i);
                    return theme_fail(res, "invalid_theme", f, "duplicate page id");
                }
            }
        }
        dock = obj_get(home, "dock");
        if (is_arr(dock)) {
            size_t dn = json_object_array_length(dock), d;
            for (d = 0; d < dn; d++)
                if (!tile_bounds(json_object_array_get_idx(dock, d), (int)d, columns, rows,
                                 "home.dock", 0, res))
                    return 0;
        }
    }

    if (!validate_nav(nav, home, style, res))
        return 0;
    return theme_ok(res);
}

/* ---- canonicalization (schema 3 defaults + rule 5 clamp) ---- */
static void ensure_str(struct json_object *o, const char *k, const char *def)
{
    if (!as_str(obj_get(o, k)))
        json_object_object_add(o, k, json_object_new_string(def));
}

static void ensure_int(struct json_object *o, const char *k, int def)
{
    if (!has_key(o, k))
        json_object_object_add(o, k, json_object_new_int(def));
}

static void ensure_double(struct json_object *o, const char *k, double def)
{
    if (!has_key(o, k))
        json_object_object_add(o, k, json_object_new_double(def));
}

static void ensure_bool(struct json_object *o, const char *k, int def)
{
    if (!has_key(o, k))
        json_object_object_add(o, k, json_object_new_boolean(def));
}

static struct json_object *deep_clone(struct json_object *src)
{
    /* Reparse round-trip: portable across json-c versions that lack
     * json_object_deep_copy, and sufficient for pure-data spec trees. */
    return json_tokener_parse(json_object_to_json_string_ext(src, JSON_C_TO_STRING_PLAIN));
}

struct json_object *tvhome_theme_canonicalize(struct json_object *spec,
                                              struct tvhome_theme_result *res)
{
    struct json_object *out, *tokens, *header, *parental, *ss, *primary;
    const char *primary_hex;

    if (!tvhome_theme_validate(spec, res))
        return NULL;
    out = deep_clone(spec);
    if (!out)
        return theme_fail(res, "internal_error", "", "clone failed"), NULL;

    tokens = obj_get(out, "tokens");
    ensure_str(tokens, "colorBackground", "#202326");
    ensure_str(tokens, "colorSurface", "#2A2E33");
    ensure_str(tokens, "colorPrimary", "#3F8CFF");
    ensure_str(tokens, "foreground", "#F2F4F7");
    primary = obj_get(tokens, "colorPrimary");
    primary_hex = as_str(primary);
    ensure_str(tokens, "focusColor", primary_hex ? primary_hex : "#3F8CFF");
    ensure_int(tokens, "radius", 16);
    ensure_double(tokens, "fontScale", 1.0);
    ensure_int(tokens, "blur", 18);
    ensure_double(tokens, "focusScale", 1.06);

    header = obj_get(out, "header");
    ensure_bool(header, "clock", 1);
    ensure_bool(header, "weather", 0);
    ensure_bool(header, "date", 0);

    parental = obj_get(out, "parental");
    if (!is_arr(obj_get(parental, "lockedModules")))
        json_object_object_add(parental, "lockedModules", json_object_new_array());

    /* rule 5: clamp idleMinutes into [1,240], recording the normalization. */
    ss = obj_get(out, "screensaver");
    if (has_key(ss, "idleMinutes")) {
        int v = as_int(obj_get(ss, "idleMinutes"), TVHOME_IDLE_DEFAULT);
        int c = v < TVHOME_IDLE_MIN ? TVHOME_IDLE_MIN
              : (v > TVHOME_IDLE_MAX ? TVHOME_IDLE_MAX : v);
        if (c != v) {
            json_object_object_add(ss, "idleMinutes", json_object_new_int(c));
            res->notes++;
        }
    } else {
        json_object_object_add(ss, "idleMinutes", json_object_new_int(TVHOME_IDLE_DEFAULT));
    }
    return out;
}

/* ---- display inheritance (schema 8) ---- */
static int layer_provides(struct json_object *layer, const char *key, struct json_object **out)
{
    struct json_object *v;
    if (!is_obj(layer))
        return 0;
    if (!json_object_object_get_ex(layer, key, &v))
        return 0;                 /* absent = inherit upper */
    if (!v || json_object_is_type(v, json_type_null))
        return 0;                 /* explicit null = inherit upper, not blank */
    *out = v;
    return 1;
}

static void resolve_one(struct json_object *disp, struct json_object *src, const char *key,
                        struct json_object *theme, struct json_object *group,
                        struct json_object *terminal)
{
    struct json_object *v = NULL;
    const char *who;

    if (layer_provides(terminal, key, &v))
        who = "terminal";
    else if (layer_provides(group, key, &v))
        who = "group";
    else if (layer_provides(theme, key, &v))
        who = "theme";
    else {
        who = "none";
        v = NULL;
    }
    json_object_object_add(disp, key, v ? deep_clone(v) : NULL);
    json_object_object_add(src, key, json_object_new_string(who));
}

struct json_object *tvhome_display_resolve(struct json_object *theme_layer,
                                          struct json_object *group_layer,
                                          struct json_object *terminal_layer)
{
    struct json_object *disp = json_object_new_object();
    struct json_object *src = json_object_new_object();

    resolve_one(disp, src, "background", theme_layer, group_layer, terminal_layer);
    resolve_one(disp, src, "screensaver", theme_layer, group_layer, terminal_layer);
    json_object_object_add(disp, "source", src);
    return disp;
}







