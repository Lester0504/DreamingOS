// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Auth session resource projection for product-plane.v1.
 *
 * The input is webd's authenticated session object, not authd daemon state:
 * this endpoint describes the requester that is actually making the call.
 */
#include <string.h>

#include <json-c/json.h>

#include "jmx_app_perms.h"
#include "jmx_auth_contract.h"

static void add_permission(struct json_object *perms, const char *name,
                           jmx_role_t role, jmx_risk_t risk)
{
    json_object_object_add(perms, name,
                           json_object_new_boolean(jmx_perm_check(role, risk)));
}

static struct json_object *build_permissions(jmx_role_t role)
{
    struct json_object *perms = json_object_new_object();

    add_permission(perms, "wifi:read", role, JMX_RISK_LOW);
    add_permission(perms, "wifi:write", role, JMX_RISK_MEDIUM);
    add_permission(perms, "system:read", role, JMX_RISK_LOW);
    add_permission(perms, "system:write", role, JMX_RISK_MEDIUM);
    add_permission(perms, "auth:read", role, JMX_RISK_LOW);
    add_permission(perms, "auth:write", role, JMX_RISK_MEDIUM);

    return perms;
}

struct json_object *auth_contract_session_read(struct json_object *session,
                                               const char *role_name)
{
    struct json_object *envelope = json_object_new_object();
    struct json_object *data = json_object_new_object();
    struct json_object *caps = json_object_new_object();
    struct json_object *value = NULL;
    jmx_role_t role = jmx_perm_parse_role(role_name);
    const char *username = NULL;

    json_object_object_add(envelope, "contract",
                           json_object_new_string("product-plane.v1"));
    json_object_object_add(envelope, "resource",
                           json_object_new_string("auth.session"));
    json_object_object_add(envelope, "ok", json_object_new_boolean(1));

    if (session && json_object_object_get_ex(session, "username", &value) &&
        value && json_object_is_type(value, json_type_string))
        username = json_object_get_string(value);
    else if (session && json_object_object_get_ex(session, "device_name", &value) &&
             value && json_object_is_type(value, json_type_string))
        username = json_object_get_string(value);

    json_object_object_add(data, "authenticated", json_object_new_boolean(1));
    json_object_object_add(data, "username", username ?
                           json_object_new_string(username) : NULL);
    json_object_object_add(data, "role", json_object_new_string(
        role_name && role_name[0] ? role_name : "operator"));
    json_object_object_add(envelope, "data", data);

    json_object_object_add(caps, "2fa", json_object_new_boolean(0));
    json_object_object_add(caps, "captcha", json_object_new_boolean(0));
    json_object_object_add(envelope, "capabilities", caps);
    json_object_object_add(envelope, "permissions", build_permissions(role));

    return envelope;
}

struct json_object *auth_contract_session_error(const char *code,
                                                const char *message)
{
    struct json_object *envelope = json_object_new_object();
    struct json_object *error = json_object_new_object();

    json_object_object_add(envelope, "contract",
                           json_object_new_string("product-plane.v1"));
    json_object_object_add(envelope, "resource",
                           json_object_new_string("auth.session"));
    json_object_object_add(envelope, "ok", json_object_new_boolean(0));
    json_object_object_add(error, "code", json_object_new_string(code));
    json_object_object_add(error, "message", json_object_new_string(message));
    json_object_object_add(envelope, "error", error);
    json_object_object_add(envelope, "capabilities",
                           json_object_new_object());
    json_object_object_add(envelope, "permissions",
                           json_object_new_object());

    return envelope;
}
