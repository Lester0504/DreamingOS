// SPDX-License-Identifier: GPL-2.0-or-later
#include "wan_sla_route_guard.h"
#include "../flowd/wan_sla_config.h"

#include <stdio.h>
#include <string.h>

static struct json_object *field(struct json_object *o, const char *key)
{
    struct json_object *value = NULL;

    if (o)
        json_object_object_get_ex(o, key, &value);
    return value;
}

static const char *text(struct json_object *o, const char *key)
{
    const char *value = json_object_get_string(field(o, key));

    return value ? value : "";
}

static int reject(char *reason, size_t reason_len, const char *value)
{
    if (reason && reason_len)
        snprintf(reason, reason_len, "%s", value);
    return WAN_SLA_ROUTE_REJECT;
}

int wan_sla_route_guard_validate(struct json_object *request,
                                 struct json_object *current_config,
                                 int64_t now,
                                 int eligible_alternatives,
                                 char *reason, size_t reason_len)
{
    struct json_object *requested_level_obj = field(request, "requested_level");
    struct json_object *revision_obj = field(request, "sla_revision");
    struct json_object *evaluated_obj = field(request, "evaluated_at");
    struct json_object *expires_obj = field(request, "expires_at");
    struct json_object *reasons = field(request, "reasons");
    struct json_object *window = field(request, "evidence_window");
    int64_t revision, current_revision, evaluated_at, expires_at;
    int requested_level;
    char digest[17];

    if (reason && reason_len)
        reason[0] = '\0';
    if (!request || !current_config ||
        !json_object_is_type(request, json_type_object) ||
        !json_object_is_type(current_config, json_type_object))
        return reject(reason, reason_len, "invalid_request");
    if (!text(request, "sla_id")[0] || !text(request, "decision_id")[0] ||
        !text(request, "wan_id")[0] || !text(request, "config_digest")[0] ||
        !text(request, "stable_state")[0])
        return reject(reason, reason_len, "required_field_missing");
    if (!requested_level_obj || !json_object_is_type(requested_level_obj, json_type_int) ||
        !revision_obj || !json_object_is_type(revision_obj, json_type_int) ||
        !evaluated_obj || !json_object_is_type(evaluated_obj, json_type_int) ||
        !expires_obj || !json_object_is_type(expires_obj, json_type_int) ||
        !reasons || !json_object_is_type(reasons, json_type_array) ||
        !window || !json_object_is_type(window, json_type_object))
        return reject(reason, reason_len, "invalid_field_type");

    requested_level = json_object_get_int(requested_level_obj);
    revision = json_object_get_int64(revision_obj);
    current_revision = json_object_get_int64(field(current_config, "revision"));
    evaluated_at = json_object_get_int64(evaluated_obj);
    expires_at = json_object_get_int64(expires_obj);
    if (requested_level < 0 || requested_level > 3)
        return reject(reason, reason_len, "requested_level_invalid");
    if (strcmp(text(request, "sla_id"), text(current_config, "id")))
        return reject(reason, reason_len, "sla_identity_mismatch");
    if (!json_object_get_boolean(field(current_config, "enabled")))
        return reject(reason, reason_len, "sla_disabled");
    if (revision <= 0 || revision != current_revision)
        return reject(reason, reason_len, "stale_revision");
    if (strcmp(text(request, "wan_id"), text(current_config, "wan")))
        return reject(reason, reason_len, "wan_identity_mismatch");
    wan_sla_config_digest(current_config, digest);
    if (strcmp(text(request, "config_digest"), digest))
        return reject(reason, reason_len, "config_digest_mismatch");
    if (evaluated_at <= 0 || expires_at < evaluated_at || evaluated_at > now)
        return reject(reason, reason_len, "decision_time_invalid");
    if (now > expires_at)
        return reject(reason, reason_len, "decision_expired");
    if ((requested_level == 0 && strcmp(text(request, "stable_state"), "healthy")) ||
        (requested_level == 1 && strcmp(text(request, "stable_state"), "degraded")) ||
        (requested_level == 2 && strcmp(text(request, "stable_state"), "critical")) ||
        (requested_level == 3 && strcmp(text(request, "stable_state"), "down")))
        return reject(reason, reason_len, "state_level_mismatch");
    if (requested_level == 3 && eligible_alternatives < 1) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s", "last_available_wan");
        return WAN_SLA_ROUTE_SUPPRESS;
    }
    if (!strcmp(text(current_config, "action_mode"), "observe"))
        return reject(reason, reason_len, "action_mode_observe");
    if (!strcmp(text(current_config, "action_mode"), "degrade") &&
        requested_level == 3) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s", "action_mode_degrade_only");
        return WAN_SLA_ROUTE_SUPPRESS;
    }
    if (strcmp(text(current_config, "action_mode"), "degrade") &&
        strcmp(text(current_config, "action_mode"), "failover"))
        return reject(reason, reason_len, "action_mode_invalid");
    return WAN_SLA_ROUTE_ALLOW;
}
