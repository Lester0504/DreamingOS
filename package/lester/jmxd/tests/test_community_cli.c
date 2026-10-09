// SPDX-License-Identifier: GPL-2.0-or-later
/* Isolated integration driver; never installed in the device package. */
#define _POSIX_C_SOURCE 200809L
#include "../src/webd/webd_community.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
int main(int argc, char **argv)
{
    if (argc < 5) return 2;
    struct support_config config = {0};
    snprintf(config.db_path, sizeof(config.db_path), "%s", argv[1]); snprintf(config.key_dir, sizeof(config.key_dir), "%s", argv[2]); snprintf(config.url, sizeof(config.url), "%s", argv[3]);
    snprintf(config.proof_domain, sizeof(config.proof_domain), "dreamingos-community-v1");
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    
    if (argc < 9) return 2;
    sqlite3 *db = NULL; if (community_db_open(config.db_path, &db)) return 3;
    char *input = calloc(1, 4U*1024U*1024U); if (!input) return 4;
    size_t n = fread(input, 1, 4U*1024U*1024U-1, stdin); input[n] = 0;
    struct json_object *o = json_tokener_parse(input), *query = NULL, *body = NULL;
    free(input); if (o) { json_object_object_get_ex(o, "query", &query); json_object_object_get_ex(o, "body", &body); }
    int status = 200;
    struct json_object *result = community_handle(db, &config, argv[5], atoi(argv[6]), argv[7], argv[8], query, body, &status);
    json_object_object_add(result, "http_status", json_object_new_int(status)); puts(json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
    json_object_put(result); json_object_put(o); sqlite3_close(db); curl_global_cleanup(); return 0;
}
