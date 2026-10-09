// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/ac/ac_client_candidates.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    sqlite3 *db = NULL;
    struct json_object *request, *result;
    char buffer[4096];
    if (argc != 2 || !fgets(buffer, sizeof(buffer), stdin)) return 1;
    request = json_tokener_parse(buffer);
    if (!request) return 2;
    if (strcmp(argv[1], "-") &&
        sqlite3_open_v2(argv[1], &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return 3;
    result = ac_client_candidates_query(db,
        json_object_get_string(json_object_object_get(request, "mac")),
        json_object_get_int64(json_object_object_get(request, "start")),
        json_object_get_int64(json_object_object_get(request, "end")),
        json_object_get_int64(json_object_object_get(request, "now")));
    puts(json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
    if (db && sqlite3_total_changes(db)) return 4;
    json_object_put(request);
    json_object_put(result);
    sqlite3_close(db);
    return 0;
}
