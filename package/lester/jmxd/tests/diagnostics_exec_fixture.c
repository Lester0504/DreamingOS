/* Fixture for the traceroute/nslookup diagnostics helpers.
 *
 * dw_diag_target_ok() and dw_traceroute_parse_line() are extracted verbatim
 * from src/jmx_dreamingwrt_api.c, so this exercises shipped code. The point is
 * to prove two things a static read cannot: that the validator rejects every
 * byte that could turn into a shell metacharacter or a leading option, and
 * that hop parsing handles the real output shapes including full timeouts.
 *
 * argv[1] = "validate" reads candidate targets from stdin, one per line, and
 *           reports accept/reject for each.
 * argv[1] = "parse" reads traceroute output from stdin and emits the hop array.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void dw_copy_string(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_len, "%s", src);
}

/* Verbatim from src/jmx_dreamingwrt_api.c via the harness. */
#include "diagnostics_extracted.h"

static void trim_newline(char *s)
{
    size_t len = strlen(s);

    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'))
        s[--len] = '\0';
}

int main(int argc, char **argv)
{
    char line[1024];

    if (argc < 2) {
        fprintf(stderr, "usage: %s validate|parse\n", argv[0]);
        return 2;
    }

    if (!strcmp(argv[1], "validate")) {
        struct json_object *out = json_object_new_array();

        while (fgets(line, sizeof(line), stdin)) {
            struct json_object *entry = json_object_new_object();

            trim_newline(line);
            json_object_object_add(entry, "target", json_object_new_string(line));
            json_object_object_add(entry, "accepted",
                json_object_new_boolean(dw_diag_target_ok(line)));
            json_object_array_add(out, entry);
        }
        printf("%s\n", json_object_to_json_string(out));
        json_object_put(out);
        return 0;
    }

    if (!strcmp(argv[1], "parse")) {
        struct json_object *out = json_object_new_array();

        while (fgets(line, sizeof(line), stdin)) {
            int hop_no = 0;
            struct json_object *hop;

            trim_newline(line);
            hop = dw_traceroute_parse_line(line, &hop_no);
            if (hop)
                json_object_array_add(out, hop);
        }
        printf("%s\n", json_object_to_json_string(out));
        json_object_put(out);
        return 0;
    }

    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
