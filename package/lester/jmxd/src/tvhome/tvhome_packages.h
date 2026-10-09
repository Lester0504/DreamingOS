// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TVHOME_PACKAGES_H
#define TVHOME_PACKAGES_H
#include "tvhome_internal.h"
int tvhome_packages_schema(sqlite3 *);
struct json_object *tvhome_packages_get(const char *,struct tvhome_err *);
struct json_object *tvhome_package_create(struct json_object *,struct tvhome_err *);
struct json_object *tvhome_package_chunk(const char *,int64_t,const void *,size_t,struct tvhome_err *);
struct json_object *tvhome_package_complete(const char *,struct tvhome_err *);
struct json_object *tvhome_package_update(const char *,struct json_object *,struct tvhome_err *);
struct json_object *tvhome_package_delete(const char *,struct tvhome_err *);
struct json_object *tvhome_release_source(const char *,struct tvhome_err *);
struct json_object *tvhome_release_import(const char *,struct tvhome_err *);
struct json_object *tvhome_packages_check(const char *,struct json_object *,struct tvhome_err *);
struct json_object *tvhome_package_result(const char *,const char *,struct json_object *,struct tvhome_err *);
int tvhome_package_open(const char *,const char *,int64_t *,struct tvhome_err *);
#endif
