// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TVHOME_ASSETS_H
#define TVHOME_ASSETS_H
#include "tvhome_internal.h"
#define TVHOME_ASSET_CHUNK (1024 * 1024)
int tvhome_assets_schema(sqlite3 *);
int tvhome_storage_dir(sqlite3 *,struct tvhome_err *);
int tvhome_assets_validate(sqlite3 *,struct json_object *,struct tvhome_err *);
struct json_object *tvhome_assets_storage(struct json_object *,struct tvhome_err *);
struct json_object *tvhome_assets_get(const char *,struct tvhome_err *);
struct json_object *tvhome_asset_create(struct json_object *,struct tvhome_err *);
struct json_object *tvhome_asset_update(const char *,struct json_object *,struct tvhome_err *);
struct json_object *tvhome_asset_delete(const char *,struct tvhome_err *);
struct json_object *tvhome_asset_chunk(const char *,int64_t,const void *,size_t,struct tvhome_err *);
struct json_object *tvhome_asset_complete(const char *,struct tvhome_err *);
int tvhome_asset_open(const char *,const char *,char *,size_t,int64_t *,struct tvhome_err *);
#endif
