// SPDX-License-Identifier: GPL-2.0-or-later
#include "toolkit_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct json_object *toolkit_read_stdin(void)
{
    char *raw = NULL;
    size_t len = 0, cap = 4096;
    struct json_object *body;
    raw = malloc(cap);
    if (!raw) return NULL;
    while (!feof(stdin)) {
        size_t got;
        if (len + 2048 + 1 > cap) {
            char *next;
            if (cap >= 4 * 1024 * 1024) { free(raw); return NULL; }
            cap *= 2;
            next = realloc(raw, cap);
            if (!next) { free(raw); return NULL; }
            raw = next;
        }
        got = fread(raw + len, 1, cap - len - 1, stdin);
        len += got;
        if (ferror(stdin)) { free(raw); return NULL; }
    }
    raw[len] = 0;
    body = len ? json_tokener_parse(raw) : json_object_new_object();
    free(raw);
    if (!body || !json_object_is_type(body, json_type_object)) {
        if (body) json_object_put(body);
        return NULL;
    }
    return body;
}

static void toolkit_usage(FILE *out)
{
    fprintf(out,
        "Usage: dreamingwrt-toolkit <command>\n"
        "Commands: status router-check port-mirror-list port-mirror-set "
        "port-mirror-delete ddns-list ddns-set ddns-delete ddns-update "
        "wake-on-lan throughput-start throughput-status throughput-stop\n"
        "Request JSON is read from stdin; exactly one JSON response is written to stdout.\n");
}

int main(int argc, char **argv)
{
    struct json_object *body = NULL, *resp = NULL;
    const char *command;
    int needs_db = 0;

    if (argc != 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
        !strcmp(argv[1], "help")) {
        toolkit_usage(argc == 2 ? stdout : stderr);
        return argc == 2 ? 0 : 2;
    }
    command = argv[1];
    body = toolkit_read_stdin();
    if (!body) {
        resp = toolkit_error("invalid_json", "stdin must contain one JSON object");
        goto done;
    }
    needs_db = !strncmp(command, "port-mirror-", 12) || !strncmp(command, "ddns-", 5);
    if (needs_db && toolkit_db_init() != 0) {
        resp = toolkit_error("storage_unavailable", "config.db is unavailable");
        goto done;
    }
    if (!strcmp(command, "status")) resp = toolkit_status();
    else if (!strcmp(command, "router-check")) resp = toolkit_router_check();
    else if (!strcmp(command, "port-mirror-list")) resp = toolkit_port_mirror_list();
    else if (!strcmp(command, "port-mirror-set")) resp = toolkit_port_mirror_set(body);
    else if (!strcmp(command, "port-mirror-delete")) resp = toolkit_port_mirror_delete(body);
    else if (!strcmp(command, "ddns-list")) resp = toolkit_ddns_list();
    else if (!strcmp(command, "ddns-set")) resp = toolkit_ddns_set(body);
    else if (!strcmp(command, "ddns-delete")) resp = toolkit_ddns_delete(body);
    else if (!strcmp(command, "ddns-update")) resp = toolkit_ddns_update(body);
    else if (!strcmp(command, "wake-on-lan")) resp = toolkit_wake_on_lan(body);
    else if (!strcmp(command, "throughput-start")) resp = toolkit_throughput_start(body);
    else if (!strcmp(command, "throughput-status")) resp = toolkit_throughput_status(body);
    else if (!strcmp(command, "throughput-stop")) resp = toolkit_throughput_stop(body);
    else resp = toolkit_error("unknown_command", "unsupported toolkit command");

done:
    if (g_toolkit_db) toolkit_db_close();
    if (!resp) resp = toolkit_error("internal_error", strerror(errno));
    fputs(json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PLAIN), stdout);
    fputc('\n', stdout);
    json_object_put(resp);
    if (body) json_object_put(body);
    return 0;
}
