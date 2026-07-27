// SPDX-License-Identifier: GPL-2.0-or-later
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/storage/storage_files.h"

struct json_object *jmx_gen_api_response_data(int code,
                                               struct json_object *data_obj)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "code", json_object_new_int(code));
    json_object_object_add(root, "data", data_obj ? data_obj :
                           json_object_new_object());
    return root;
}

int main(int argc, char **argv)
{
    struct json_object *response;
    int content_mode = argc > 1 && !strcmp(argv[1], "content");
    int offset = content_mode ? 1 : 0;
    const char *root_id = argc > 1 + offset ? argv[1 + offset] : "";
    const char *path = argc > 2 + offset ? argv[2 + offset] : "/";
    const char *search = argc > 3 + offset ? argv[3 + offset] : "";

    response = content_mode ? jmx_storage_files_content(root_id, path) :
                              jmx_storage_files_list(root_id, path, search);
    if (!response)
        return 2;
    puts(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN));
    json_object_put(response);
    return 0;
}
