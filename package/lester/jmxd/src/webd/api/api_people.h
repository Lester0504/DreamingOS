// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_PEOPLE_H
#define WEBD_API_PEOPLE_H
#include <sqlite3.h>
#include "api_router.h"
int webd_people_init(sqlite3 *db);
struct json_object *webd_people_for_mac(sqlite3 *db, const char *mac);
void webd_people_project_clients(struct json_object *response);
extern const struct jmx_api_route people_api_routes[];
#endif
