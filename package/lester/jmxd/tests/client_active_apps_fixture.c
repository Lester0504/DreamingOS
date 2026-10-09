// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Runtime fixture for /api/v1/clients?with_apps=1.
 *
 * The aggregation under test is extracted verbatim from
 * src/webd/jmx_app_api.c by the Python runner, so this exercises the shipped
 * code rather than a restatement of it. A static grep could only prove the
 * function exists; the interesting failures live in the bucketing, the
 * staleness cut, the MAC join and the "source unavailable" path.
 *
 * Only the small helpers the extracted code calls are stubbed here, and each
 * stub mirrors the real one's contract.
 */
#include <ctype.h>
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Overridden so the fixture can point the reader at a temporary file instead of
 * /proc. Same signature as src/proc_path.h. */
static const char *g_af_active_app_path;

static FILE *jmx_fopen_af(const char *filename, const char *mode)
{
    (void)filename;
    if (!g_af_active_app_path || !g_af_active_app_path[0])
        return NULL;
    return fopen(g_af_active_app_path, mode);
}

static const char *app_nc_json_str(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, k, &v) || !v)
        return def;
    {
        const char *s = json_object_get_string(v);

        return s ? s : def;
    }
}

static void webd_obj_add_str(struct json_object *obj, const char *key, const char *value)
{
    if (!obj || !key)
        return;
    json_object_object_add(obj, key, json_object_new_string(value ? value : ""));
}

static struct json_object *webd_meta(const char *source)
{
    struct json_object *meta = json_object_new_object();

    webd_obj_add_str(meta, "source", source ? source : "");
    return meta;
}

/*
 * Signature-DB lookup stub. The real one queries sqlite; the contract the
 * extracted code depends on is "returns non-zero and fills name when the app is
 * known". Odd ids are treated as known so both branches get exercised.
 *
 * The icon join is part of the same lookup in the real implementation, so the
 * stub mirrors that: ids divisible by 3 have no icon mapping, which is how the
 * "known app, no icon" case gets exercised alongside "known app with icon".
 */
static int webd_insights_app_lookup_ex(int app_id,
                                       char *name, size_t name_len,
                                       char *category, size_t category_len,
                                       char *family, size_t family_len,
                                       char *icon_url, size_t icon_url_len,
                                       int *canonical_app_id)
{
    if (icon_url && icon_url_len)
        icon_url[0] = '\0';
    if (canonical_app_id)
        *canonical_app_id = app_id;
    if (app_id % 2 == 0)
        return 0;
    if (name && name_len)
        snprintf(name, name_len, "app-%d", app_id);
    if (category && category_len)
        snprintf(category, category_len, "category-%d", app_id % 3);
    if (family && family_len)
        snprintf(family, family_len, "family-%d", app_id % 5);
    if (icon_url && icon_url_len && app_id % 3)
        snprintf(icon_url, icon_url_len,
                 "/static/images/logo/app-%d.svg", app_id);
    return 1;
}

/* The code under test, spliced in by the runner. */
#include "client_active_apps_extracted.h"

static struct json_object *build_clients(int argc, char **argv, int first)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *data = json_object_new_object();
    struct json_object *clients = json_object_new_array();
    int i;

    for (i = first; i < argc; i++) {
        struct json_object *client = json_object_new_object();

        json_object_object_add(client, "mac", json_object_new_string(argv[i]));
        json_object_array_add(clients, client);
    }
    json_object_object_add(data, "clients", clients);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "data", data);
    return resp;
}

int main(int argc, char **argv)
{
    struct json_object *resp;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <af_active_app|-> [mac...]\n", argv[0]);
        return 2;
    }
    g_af_active_app_path = strcmp(argv[1], "-") ? argv[1] : NULL;

    resp = build_clients(argc, argv, 2);
    webd_clients_attach_apps(resp);
    puts(json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PLAIN));
    json_object_put(resp);
    return 0;
}
