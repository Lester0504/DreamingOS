// SPDX-License-Identifier: GPL-2.0-or-later
/* Isolated integration driver; never installed in the device package. */
#define _POSIX_C_SOURCE 200809L
#include "../src/webd/webd_support.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
static void subject_lifecycle(void)
{
    sqlite3 *db = NULL; assert(sqlite3_open(":memory:", &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "PRAGMA foreign_keys=ON; CREATE TABLE web_users(username TEXT PRIMARY KEY,status TEXT); INSERT INTO web_users VALUES('before','enabled')", NULL, NULL, NULL) == SQLITE_OK);
    char one[65], two[65]; assert(!support_subject(db, "before", one));
    assert(sqlite3_exec(db, "UPDATE web_users SET username='after' WHERE username='before'", NULL, NULL, NULL) == SQLITE_OK);
    assert(!support_subject(db, "after", two)); assert(!strcmp(one, two));
    assert(sqlite3_exec(db, "DELETE FROM web_users; INSERT INTO web_users VALUES('after','enabled')", NULL, NULL, NULL) == SQLITE_OK);
    assert(!support_subject(db, "after", two)); assert(strcmp(one, two)); sqlite3_close(db);
}
int main(int argc, char **argv)
{
    if (argc < 5) return 2;
    struct support_config config = {0};
    snprintf(config.db_path, sizeof(config.db_path), "%s", argv[1]); snprintf(config.key_dir, sizeof(config.key_dir), "%s", argv[2]); snprintf(config.url, sizeof(config.url), "%s", argv[3]);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    if (!strcmp(argv[4], "sync")) { printf("{\"worked\":%d}\n", support_sync_step(&config)); return 0; }
    if (!strcmp(argv[4], "subjects")) { subject_lifecycle(); puts("{\"ok\":true}"); return 0; }
    if (argc < 9) return 2;
    sqlite3 *db = NULL; if (support_db_open(config.db_path, &db)) return 3;
    char *input = calloc(1, 4U*1024U*1024U); if (!input) return 4;
    size_t n = fread(input, 1, 4U*1024U*1024U-1, stdin); input[n] = 0;
    struct json_object *o = json_tokener_parse(input), *query = NULL, *body = NULL;
    free(input); if (o) { json_object_object_get_ex(o, "query", &query); json_object_object_get_ex(o, "body", &body); }
    int status = 200;
    struct json_object *result = support_handle(db, &config, argv[5], atoi(argv[6]), argv[7], argv[8], query, body, &status);
    json_object_object_add(result, "http_status", json_object_new_int(status)); puts(json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
    json_object_put(result); json_object_put(o); sqlite3_close(db); curl_global_cleanup(); return 0;
}
