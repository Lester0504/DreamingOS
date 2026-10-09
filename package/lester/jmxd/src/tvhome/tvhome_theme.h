// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * TVHome theme spec: server-authoritative validation, canonicalization and the
 * per-item display inheritance resolver.
 *
 * This translation unit is deliberately pure json-c: it does not touch ubus, the
 * database or the request context, so it links into the webd executable and is
 * also buildable + unit-testable on a plain host toolchain (tvhome_theme_test.c).
 *
 * Field/enum/default truth source: PM-tvhome-schema-and-fixtures.md sections 2-9.
 * Envelope naming is snake_case; spec (spec.*) naming is camelCase (contract 8).
 */
#ifndef JMX_TVHOME_THEME_H
#define JMX_TVHOME_THEME_H

#include <json-c/json.h>

/* spec.version frozen value (schema 2). */
#define TVHOME_SPEC_VERSION 1
/* Normalized clamp bounds (schema 4/5/6). */
#define TVHOME_IDLE_MIN 1
#define TVHOME_IDLE_MAX 240
#define TVHOME_IDLE_DEFAULT 10
#define TVHOME_GRID_COLS_MIN 4
#define TVHOME_GRID_COLS_MAX 24
#define TVHOME_GRID_ROWS_MIN 2
#define TVHOME_GRID_ROWS_MAX 12

/*
 * Result of validate/canonicalize. On success ok==1, code=="" and field=="".
 * On failure ok==0, code holds a stable error code (e.g. "invalid_theme") and
 * field locates the offending path (schema 3 requires field-level location).
 * notes counts non-fatal normalizations applied (e.g. idleMinutes clamp), which
 * schema rule 5 requires be recorded rather than swallowed silently.
 */
struct tvhome_theme_result {
    int  ok;
    char code[48];
    char field[160];
    char message[192];
    int  notes;
};

/*
 * Validate a theme spec against schema rules 1-5,9 (self-consistency, grid tile
 * bounds/overlap/id-uniqueness, columns/rows range, nav/page id uniqueness and
 * page-target resolution). Pure read; no mutation. Returns 1 if valid.
 *
 * res must be non-NULL and is always fully populated.
 */
int tvhome_theme_validate(struct json_object *spec, struct tvhome_theme_result *res);

/*
 * Validate, then return a newly-allocated canonical spec (caller owns) with
 * defaults filled (schema 3 tokens, header booleans, parental.lockedModules) and
 * idleMinutes clamped into [1,240] (rule 5). Side-effect free: the input object
 * is never mutated, which is what lets themes/validate and themes/preview run
 * with no persistence (rule 9). Returns NULL on validation failure with res set.
 */
struct json_object *tvhome_theme_canonicalize(struct json_object *spec,
                                              struct tvhome_theme_result *res);

/*
 * Per-item display inheritance (schema 8). terminal > group > theme, background
 * and screensaver resolved independently by firstNonNull; a layer "provides" a
 * value only when its key is present and not JSON null (null = inherit upper,
 * never blank-to-black). Each layer arg may be NULL or a {background?,
 * screensaver?} object. Returns a new object:
 *   { "background": <obj>, "screensaver": <obj>,
 *     "source": { "background": <layer>, "screensaver": <layer> } }
 * where <layer> is "terminal"|"group"|"theme"|"none". Caller owns the result.
 */
struct json_object *tvhome_display_resolve(struct json_object *theme_layer,
                                          struct json_object *group_layer,
                                          struct json_object *terminal_layer);

#endif /* JMX_TVHOME_THEME_H */
