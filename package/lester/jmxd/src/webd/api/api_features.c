// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Feature registry REST adapter (post-auth, read-only).
 *
 *   GET /api/v1/features        -> feature_registry_list()
 *   GET /api/v1/features/{id}   -> feature_registry_status(id)
 *
 * The registry (jmx_feature_registry.c) is ubus-only and emits each feature's
 * permissions{} with every entry hardcoded true, because ubus callers gate
 * elsewhere. Over HTTP the requesting role is known (ctx->role), so this
 * adapter reuses the same envelope and rewrites each permissions{} boolean to
 * what the role may actually do.
 *
 * The projection is anchored to real dispatcher authority, not a fabricated
 * per-resource table: a ":read" permission maps to JMX_RISK_LOW (the read tier;
 * viewer/ai-agent and above pass), and a write permission maps to the live risk
 * jmx_perm_route_risk() reports for that feature's canonical write route. If a
 * route's risk changes in jmx_app_perms.c, this projection follows it.
 *
 * This is B01-b's minimal honest slice: it exposes the registry over HTTP and
 * fixes permissions{} to be role-aware. The deeper §4.1/§5.1 reshape
 * ({supported,readable,writable,runtime} / {read,write,manage,required[]}) is
 * left for later — it needs each resource to self-report per-action risk, which
 * does not exist yet and cannot be invented without misclassifying.
 */
#include <string.h>

#include <json-c/json.h>

#include "api_context.h"
#include "api_router.h"
#include "api_error.h"
#include "api_features.h"
#include "../jmx_feature_registry.h"
#include "../jmx_app_perms.h"

/*
 * The risk tier a feature's write permission is gated at, read live from the
 * dispatcher's route-risk table via a canonical write route per feature:
 *   wifi.management -> POST /api/v1/wifi/config              (MEDIUM)
 *   auth.accounts   -> POST /api/v1/authentication/accounts  (MEDIUM)
 *   system.ota      -> POST /api/v1/system/ota/apply         (HIGH)
 * An unknown/future feature falls back to the dispatcher's own default for an
 * unlisted write (MEDIUM), never to a guessed lower tier.
 */
static jmx_risk_t feature_write_risk(const char *feature_id)
{
    if (!feature_id)
        return JMX_RISK_MEDIUM;
    if (!strcmp(feature_id, "wifi.management"))
        return jmx_perm_route_risk("POST", "/api/v1/wifi/config");
    if (!strcmp(feature_id, "auth.accounts"))
        return jmx_perm_route_risk("POST", "/api/v1/authentication/accounts");
    if (!strcmp(feature_id, "system.ota"))
        return jmx_perm_route_risk("POST", "/api/v1/system/ota/apply");
    return JMX_RISK_MEDIUM;
}

/* Rewrite one envelope's permissions{} booleans onto the requesting role. */
static void feature_project_permissions(struct json_object *env, jmx_role_t role)
{
    struct json_object *data, *fid_o, *perms;
    const char *fid;
    jmx_risk_t wrisk;

    if (!env || !json_object_object_get_ex(env, "data", &data))
        return;
    if (!json_object_object_get_ex(data, "feature_id", &fid_o))
        return;
    if (!json_object_object_get_ex(env, "permissions", &perms) ||
        !json_object_is_type(perms, json_type_object))
        return;

    fid = json_object_get_string(fid_o);
    wrisk = feature_write_risk(fid);

    /*
     * Replacing the value of an existing key during iteration is safe: the key
     * set and hash structure are unchanged, only the boolean is swapped.
     */
    json_object_object_foreach(perms, key, val) {
        size_t klen = strlen(key);
        int is_read = klen >= 5 && !strcmp(key + klen - 5, ":read");
        int allowed = jmx_perm_check(role, is_read ? JMX_RISK_LOW : wrisk);

        (void)val;
        json_object_object_add(perms, key, json_object_new_boolean(allowed));
    }
}

static struct json_object *feature_api_list(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = feature_registry_list();
    struct json_object *data;
    size_t i, n;

    if (resp && json_object_object_get_ex(resp, "data", &data) &&
        json_object_is_type(data, json_type_array)) {
        n = json_object_array_length(data);
        for (i = 0; i < n; i++)
            feature_project_permissions(json_object_array_get_idx(data, i),
                                        ctx->role);
    }
    return resp;
}

static struct json_object *feature_api_status(struct jmx_api_ctx *ctx)
{
    static const char pfx[] = "/api/v1/features/";
    const char *fid;
    struct json_object *resp;

    if (!ctx->req)
        return NULL;
    /* The prefix route guarantees the path starts with pfx. */
    fid = ctx->req->path + (sizeof(pfx) - 1);
    if (!*fid) {
        ctx->status = 404;
        return webd_error("resource_not_found", "feature_id is required",
                          "feature_id", "webd.registry");
    }

    resp = feature_registry_status(fid);
    if (!resp) {
        ctx->status = 404;
        return webd_error("resource_not_found", "unknown feature_id",
                          "feature_id", "webd.registry");
    }

    feature_project_permissions(resp, ctx->role);
    return resp;
}

const struct jmx_api_route feature_api_routes[] = {
    JMX_API_ROUTE(957, "/api/v1/features",  "GET", JMX_API_EXACT,  feature_api_list),
    JMX_API_ROUTE(958, "/api/v1/features/", "GET", JMX_API_PREFIX, feature_api_status),
    JMX_API_ROUTE_END,
};
