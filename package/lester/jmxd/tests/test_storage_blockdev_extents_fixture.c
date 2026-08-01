#include <json-c/json.h>
#include <stdio.h>

#include "../src/storage/storage_blockdev.h"

struct json_object *jmx_gen_api_response_data(int code,
                                               struct json_object *data_obj)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "code", json_object_new_int(code));
    json_object_object_add(root, "data", data_obj);
    return root;
}

int main(void)
{
    struct json_object *response = jmx_storage_partitions_get();

    puts(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN));
    json_object_put(response);
    return 0;
}
