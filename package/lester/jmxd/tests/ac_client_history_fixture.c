// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/ac/ac_client_history.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    sqlite3 *db = NULL;
    struct json_object *input, *result;
    char buffer[32768];
    const char *operation;
    int rc = 0;
    if (argc != 2 || !fgets(buffer, sizeof(buffer), stdin)) return 1;
    input = json_tokener_parse(buffer);
    if (!input || sqlite3_open(argv[1], &db) != SQLITE_OK || ac_client_history_init(db)) return 2;
    operation = json_object_get_string(json_object_object_get(input, "operation"));
    if (operation && !strcmp(operation, "ingest")) {
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        rc = ac_client_history_ingest(db,
            json_object_get_string(json_object_object_get(input, "ap_id")),
            json_object_get_string(json_object_object_get(input, "epoch")),
            json_object_get_int64(json_object_object_get(input, "observed")),
            json_object_get_int64(json_object_object_get(input, "received")),
            json_object_object_get(input, "snapshot"));
        sqlite3_exec(db, rc || json_object_get_boolean(json_object_object_get(input, "rollback")) ?
            "ROLLBACK" : "COMMIT", NULL, NULL, NULL);
        printf("{\"rc\":%d}\n", rc);
    } else {
        result = ac_client_history_query(db,
            json_object_get_string(json_object_object_get(input, "mac")),
            json_object_get_int64(json_object_object_get(input, "start")),
            json_object_get_int64(json_object_object_get(input, "end")),
            json_object_get_int(json_object_object_get(input, "limit")),
            json_object_get_int64(json_object_object_get(input, "after_id")),
            json_object_get_int64(json_object_object_get(input, "now")));
        puts(json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
        json_object_put(result);
    }
    json_object_put(input);
    sqlite3_close(db);
    return rc ? 3 : 0;
}
