// SPDX-License-Identifier: GPL-2.0-or-later
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    int mutate_mode = argc > 1 && !strcmp(argv[1], "mutate");
    int content_mode = argc > 1 && !strcmp(argv[1], "content");
    int stream_mode = argc > 1 && !strcmp(argv[1], "stream");
    int offset = (content_mode || mutate_mode || stream_mode) ? 1 : 0;
    const char *root_id = argc > 1 + offset ? argv[1 + offset] : "";
    const char *path = argc > 2 + offset ? argv[2 + offset] : "/";
    const char *search = argc > 3 + offset ? argv[3 + offset] : "";

    /* Byte-stream open: reports what the HTTP layer needs (size, name, first
     * bytes actually readable) instead of a JSON body, since the real route
     * streams the descriptor rather than serialising the file. */
    if (stream_mode) {
        struct storage_files_stream stream;
        const char *reason = "";
        struct json_object *out = json_object_new_object();

        if (storage_files_open_stream(root_id, path, &stream, &reason) != 0) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "reason", json_object_new_string(reason));
        } else {
            unsigned char head[8];
            ssize_t got = read(stream.fd, head, sizeof(head));
            char hex[32] = "";

            for (ssize_t i = 0; i < got && i < 4; i++)
                snprintf(hex + strlen(hex), sizeof(hex) - strlen(hex),
                         "%02x", head[i]);
            json_object_object_add(out, "ok", json_object_new_boolean(1));
            json_object_object_add(out, "size_bytes",
                                   json_object_new_int64((int64_t)stream.size_bytes));
            json_object_object_add(out, "basename",
                                   json_object_new_string(stream.basename));
            json_object_object_add(out, "root_id",
                                   json_object_new_string(stream.root_id));
            json_object_object_add(out, "display_path",
                                   json_object_new_string(stream.display_path));
            json_object_object_add(out, "bytes_read",
                                   json_object_new_int((int)got));
            json_object_object_add(out, "head_hex", json_object_new_string(hex));
            close(stream.fd);
        }
        puts(json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
        json_object_put(out);
        return 0;
    }

    if (mutate_mode) {
        struct json_object *payload = json_tokener_parse(
            argc > 2 ? argv[2] : "{}");

        response = jmx_storage_files_mutate(payload);
        if (payload)
            json_object_put(payload);
    } else {
        response = content_mode ? jmx_storage_files_content(root_id, path) :
                                  jmx_storage_files_list(root_id, path, search);
    }
    if (!response)
        return 2;
    puts(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN));
    json_object_put(response);
    return 0;
}
