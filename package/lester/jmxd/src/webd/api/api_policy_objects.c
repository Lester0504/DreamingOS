// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
/* Policy engine zones and composite objects. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sqlite3.h>
#include <json-c/json.h>
#include <uci.h>

#include "api_policy_objects.h"
#include "api_policy_write_internal.h"
#include "api_policy_paths.h"
#include "api_policy_objects_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_router.h"
#include "api_ubus.h"
#include "api_util.h"
#include "../webd_admin_transaction.h"


static const char *webd_policy_zone_type(const char *name)
{
    if (!name || !name[0])
        return "custom";
    if (!strcasecmp(name, "wan") || strstr(name, "external"))
        return "external";
    if (!strcasecmp(name, "lan") || strstr(name, "internal"))
        return "internal";
    if (strstr(name, "hotspot") || strstr(name, "guest"))
        return "hotspot";
    if (strstr(name, "vpn") || strstr(name, "wg") || strstr(name, "tun"))
        return "vpn";
    if (strstr(name, "dmz"))
        return "dmz";
    return "custom";
}

static struct uci_section *webd_policy_find_zone_section(struct uci_package *pkg,
                                                          const char *id)
{
    struct uci_element *e;

    if (!pkg || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        char name[128] = "";

        if (!s || !s->type || strcmp(s->type, "zone"))
            continue;
        webd_policy_uci_option(s, "name", name, sizeof(name));
        if ((s->e.name && !strcmp(s->e.name, id)) || (name[0] && !strcmp(name, id)))
            return s;
    }
    return NULL;
}

static struct json_object *webd_policy_zone_members(struct uci_section *s)
{
    struct json_object *members = json_object_new_array();
    struct uci_element *e;

    if (!s)
        return members;
    uci_foreach_element(&s->options, e) {
        struct uci_option *o = uci_to_option(e);

        if (!o || strcmp(o->e.name, "network"))
            continue;
        if (o->type == UCI_TYPE_STRING && o->v.string) {
            char value[512];
            char *tok;
            char *saveptr = NULL;

            snprintf(value, sizeof(value), "%s", o->v.string);
            for (tok = strtok_r(value, " ,\t", &saveptr); tok;
                 tok = strtok_r(NULL, " ,\t", &saveptr))
                json_object_array_add(members, json_object_new_string(tok));
        } else if (o->type == UCI_TYPE_LIST) {
            struct uci_element *le;
            uci_foreach_element(&o->v.list, le) {
                if (le && le->name && le->name[0])
                    json_object_array_add(members, json_object_new_string(le->name));
            }
        }
        break;
    }
    return members;
}

static int webd_policy_zone_ref_count(struct uci_package *pkg, const char *name,
                                      int *rule_count, int *forward_count)
{
    struct uci_element *e;
    int rules = 0;
    int forwards = 0;

    if (!pkg || !name || !name[0])
        return 0;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        char src[128] = "";
        char dest[128] = "";

        if (!s || !s->type)
            continue;
        if (strcmp(s->type, "rule") && strcmp(s->type, "forwarding") &&
            strcmp(s->type, "redirect") && strcmp(s->type, "nat"))
            continue;
        webd_policy_uci_option(s, "src", src, sizeof(src));
        webd_policy_uci_option(s, "dest", dest, sizeof(dest));
        if (strcmp(src, name) && strcmp(dest, name))
            continue;
        if (!strcmp(s->type, "forwarding"))
            forwards++;
        else
            rules++;
    }
    if (rule_count)
        *rule_count = rules;
    if (forward_count)
        *forward_count = forwards;
    return rules + forwards;
}

static struct json_object *webd_policy_zone_json(struct uci_package *pkg,
                                                  struct uci_section *s)
{
    struct json_object *o = json_object_new_object();
    struct json_object *defaults = json_object_new_object();
    struct json_object *locked_fields = json_object_new_array();
    char name[128] = "";
    char input[32] = "reject";
    char output[32] = "accept";
    char forward[32] = "reject";
    char masq[16] = "0";
    char mtu_fix[16] = "0";
    int rules = 0;
    int forwards = 0;
    int system_zone;

    webd_policy_uci_option(s, "name", name, sizeof(name));
    webd_policy_uci_option_keep(s, "input", input, sizeof(input));
    webd_policy_uci_option_keep(s, "output", output, sizeof(output));
    webd_policy_uci_option_keep(s, "forward", forward, sizeof(forward));
    webd_policy_uci_option_keep(s, "masq", masq, sizeof(masq));
    webd_policy_uci_option_keep(s, "mtu_fix", mtu_fix, sizeof(mtu_fix));
    system_zone = !strcmp(name, "lan") || !strcmp(name, "wan");
    webd_policy_zone_ref_count(pkg, name, &rules, &forwards);

    webd_obj_add_str(o, "id", name[0] ? name : (s->e.name ? s->e.name : ""));
    webd_obj_add_str(o, "section_id", s->e.name ? s->e.name : "");
    webd_obj_add_str(o, "name", name);
    webd_obj_add_str(o, "display_name", webd_policy_zone_label(name));
    webd_obj_add_str(o, "type", webd_policy_zone_type(name));
    json_object_object_add(o, "locked", json_object_new_boolean(0));
    json_object_object_add(o, "delete_locked", json_object_new_boolean(system_zone));
    if (system_zone) {
        json_object_array_add(locked_fields, json_object_new_string("name"));
        json_object_array_add(locked_fields, json_object_new_string("type"));
    }
    json_object_object_add(o, "locked_fields", locked_fields);
    json_object_object_add(o, "members", webd_policy_zone_members(s));
    webd_obj_add_str(defaults, "input", input);
    webd_obj_add_str(defaults, "output", output);
    webd_obj_add_str(defaults, "forward", forward);
    json_object_object_add(defaults, "masq", json_object_new_boolean(webd_policy_str_true(masq)));
    json_object_object_add(defaults, "mtu_fix", json_object_new_boolean(webd_policy_str_true(mtu_fix)));
    json_object_object_add(o, "default_actions", defaults);
    json_object_object_add(o, "rule_count", json_object_new_int(rules));
    json_object_object_add(o, "forwarding_count", json_object_new_int(forwards));
    json_object_object_add(o, "reference_count", json_object_new_int(rules + forwards));
    webd_obj_add_str(o, "source", "uci:firewall.zone");
    return o;
}

static struct json_object *webd_policy_zones_response(int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *zones = json_object_new_array();
    struct json_object *virtual_zones = json_object_new_array();
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_element *e;

    if (http_status)
        *http_status = 200;
    if (!ctx || uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) {
        if (ctx)
            uci_free_context(ctx);
        if (http_status)
            *http_status = 503;
        return webd_error("source_unavailable", "UCI firewall zones are unavailable",
                          "/etc/config/firewall", "webd.policy_engine.zones");
    }
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (s && s->type && !strcmp(s->type, "zone"))
            json_object_array_add(zones, webd_policy_zone_json(pkg, s));
    }
    {
        struct json_object *gateway = json_object_new_object();
        struct json_object *locked_fields = json_object_new_array();
        json_object_array_add(locked_fields, json_object_new_string("name"));
        json_object_array_add(locked_fields, json_object_new_string("members"));
        webd_obj_add_str(gateway, "id", "gateway");
        webd_obj_add_str(gateway, "name", "Gateway");
        webd_obj_add_str(gateway, "display_name", "Gateway");
        webd_obj_add_str(gateway, "type", "gateway");
        webd_obj_add_str(gateway, "source", "virtual:self");
        json_object_object_add(gateway, "virtual", json_object_new_boolean(1));
        json_object_object_add(gateway, "locked", json_object_new_boolean(1));
        json_object_object_add(gateway, "delete_locked", json_object_new_boolean(1));
        json_object_object_add(gateway, "locked_fields", locked_fields);
        json_object_object_add(gateway, "members", json_object_new_array());
        json_object_array_add(virtual_zones, gateway);
    }
    json_object_object_add(data, "zones", zones);
    json_object_object_add(data, "virtual_zones", virtual_zones);
    json_object_object_add(data, "total", json_object_new_int(json_object_array_length(zones)));
    json_object_object_add(data, "network_membership_unique", json_object_new_boolean(1));
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    webd_obj_add_str(data, "source", "uci:firewall.zone+virtual:self");
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.zones");
}

static struct json_object *webd_policy_zone_detail_response(const char *id,
                                                             int *http_status)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_section *s;
    struct json_object *data;

    if (http_status)
        *http_status = 200;
    if (!id || !id[0]) {
        if (ctx)
            uci_free_context(ctx);
        if (http_status)
            *http_status = 400;
        return webd_error("zone_id_required", "Zone id is required", "id",
                          "webd.policy_engine.zones");
    }
    if (!ctx || uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) {
        if (ctx)
            uci_free_context(ctx);
        if (http_status)
            *http_status = 503;
        return webd_error("source_unavailable", "UCI firewall zones are unavailable",
                          "/etc/config/firewall", "webd.policy_engine.zones");
    }
    s = webd_policy_find_zone_section(pkg, id);
    if (!s) {
        uci_unload(ctx, pkg);
        uci_free_context(ctx);
        if (http_status)
            *http_status = 404;
        return webd_error("zone_not_found", "Zone was not found", id,
                          "webd.policy_engine.zones");
    }
    data = webd_policy_zone_json(pkg, s);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.zone_detail");
}

static int webd_policy_zone_members_conflict(struct uci_package *pkg,
                                              struct uci_section *current,
                                              struct json_object *members,
                                              char *network, size_t network_len,
                                              char *owner, size_t owner_len)
{
    struct uci_element *e;
    int i, n;

    if (network && network_len) network[0] = '\0';
    if (owner && owner_len) owner[0] = '\0';
    if (!pkg || !members || !json_object_is_type(members, json_type_array))
        return 0;
    n = json_object_array_length(members);
    for (i = 0; i < n; i++) {
        const char *wanted = json_object_get_string(json_object_array_get_idx(members, i));
        int k;
        if (!wanted || !wanted[0])
            continue;
        for (k = 0; k < i; k++) {
            const char *previous = json_object_get_string(json_object_array_get_idx(members, k));
            if (previous && !strcmp(previous, wanted)) {
                if (network && network_len) snprintf(network, network_len, "%s", wanted);
                if (owner && owner_len) snprintf(owner, owner_len, "%s", "same_request");
                return 1;
            }
        }
        uci_foreach_element(&pkg->sections, e) {
            struct uci_section *s = uci_to_section(e);
            struct json_object *existing;
            char zone_name[128] = "";
            int j, en;

            if (!s || s == current || !s->type || strcmp(s->type, "zone"))
                continue;
            existing = webd_policy_zone_members(s);
            en = json_object_array_length(existing);
            for (j = 0; j < en; j++) {
                const char *value = json_object_get_string(json_object_array_get_idx(existing, j));
                if (value && !strcmp(value, wanted)) {
                    webd_policy_uci_option(s, "name", zone_name, sizeof(zone_name));
                    if (network && network_len) snprintf(network, network_len, "%s", wanted);
                    if (owner && owner_len) snprintf(owner, owner_len, "%s", zone_name);
                    json_object_put(existing);
                    return 1;
                }
            }
            json_object_put(existing);
        }
    }
    return 0;
}

static int webd_policy_zone_set_members(struct uci_context *ctx,
                                         struct uci_section *s,
                                         struct json_object *members,
                                         char *err, size_t err_len)
{
    struct uci_ptr ptr;
    char lookup[768];
    int i, n;

    if (!ctx || !s || !s->e.name || !members ||
        !json_object_is_type(members, json_type_array))
        return -1;
    snprintf(lookup, sizeof(lookup), "firewall.%s.network", s->e.name);
    memset(&ptr, 0, sizeof(ptr));
    if (uci_lookup_ptr(ctx, &ptr, lookup, true) == UCI_OK && ptr.o &&
        uci_delete(ctx, &ptr) != UCI_OK) {
        if (err && err_len) snprintf(err, err_len, "failed to clear zone network members");
        return -1;
    }
    n = json_object_array_length(members);
    for (i = 0; i < n; i++) {
        const char *value = json_object_get_string(json_object_array_get_idx(members, i));
        if (!value || !value[0] || !webd_policy_pbr_id_ok(value)) {
            if (err && err_len) snprintf(err, err_len, "invalid network member at index %d", i);
            return -1;
        }
        snprintf(lookup, sizeof(lookup), "firewall.%s.network=%s", s->e.name, value);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK ||
            uci_add_list(ctx, &ptr) != UCI_OK) {
            if (err && err_len) snprintf(err, err_len, "failed to add network member %s", value);
            return -1;
        }
    }
    return 0;
}

static struct json_object *webd_policy_zone_write_response(const struct http_req *req,
                                                            struct json_object *body,
                                                            const char *id,
                                                            int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *members = NULL;
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    char backup[256] = "";
    char err[512] = "";
    char name[128] = "";
    char conflict_network[128] = "";
    char conflict_zone[128] = "";
    const char *method = req ? req->method : "";
    int create = !strcmp(method, "POST") && (!id || !id[0]);
    int deleting = !strcmp(method, "DELETE");
    int rc = -1;

    if (http_status) *http_status = 200;
    if (!body || !json_object_is_type(body, json_type_object))
        body = json_object_new_object();
    snprintf(name, sizeof(name), "%s", app_nc_json_str(body, "name",
             app_nc_json_str(body, "id", id ? id : "")));
    if (create && (!name[0] || !webd_policy_pbr_id_ok(name))) {
        if (http_status) *http_status = 400;
        snprintf(err, sizeof(err), "zone name is required and must be a stable token");
        goto fail;
    }
    if (webd_policy_firewall_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_array_add(steps, json_object_new_string("backup /etc/config/firewall"));
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) {
        if (http_status) *http_status = 503;
        snprintf(err, sizeof(err), "uci firewall unavailable");
        goto fail;
    }
    if (create) {
        if (webd_policy_find_zone_section(pkg, name)) {
            if (http_status) *http_status = 409;
            snprintf(err, sizeof(err), "zone already exists: %s", name);
            goto fail;
        }
        if (uci_add_section(ctx, pkg, "zone", &s) != UCI_OK || !s) {
            if (http_status) *http_status = 500;
            snprintf(err, sizeof(err), "failed to create firewall zone");
            goto fail;
        }
        if (webd_policy_uci_set_option(ctx, s->e.name, "name", name, 0, err, sizeof(err)) != 0)
            goto fail;
        webd_policy_uci_set_option(ctx, s->e.name, "input", app_nc_json_str(body, "input", "REJECT"), 0, err, sizeof(err));
        webd_policy_uci_set_option(ctx, s->e.name, "output", app_nc_json_str(body, "output", "ACCEPT"), 0, err, sizeof(err));
        webd_policy_uci_set_option(ctx, s->e.name, "forward", app_nc_json_str(body, "forward", "REJECT"), 0, err, sizeof(err));
        json_object_array_add(steps, json_object_new_string("create UCI firewall zone"));
    } else {
        s = webd_policy_find_zone_section(pkg, id);
        if (!s) {
            if (http_status) *http_status = 404;
            snprintf(err, sizeof(err), "zone not found: %s", id ? id : "");
            goto fail;
        }
        webd_policy_uci_option(s, "name", name, sizeof(name));
    }
    if (deleting) {
        struct uci_ptr ptr;
        char lookup[256];
        int refs = webd_policy_zone_ref_count(pkg, name, NULL, NULL);
        if (!strcmp(name, "lan") || !strcmp(name, "wan")) {
            if (http_status) *http_status = 409;
            snprintf(err, sizeof(err), "default zone %s cannot be deleted", name);
            goto fail;
        }
        if (refs > 0) {
            if (http_status) *http_status = 409;
            snprintf(err, sizeof(err), "zone %s is referenced by %d firewall entries", name, refs);
            goto fail;
        }
        snprintf(lookup, sizeof(lookup), "firewall.%s", s->e.name);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            uci_delete(ctx, &ptr) != UCI_OK) {
            if (http_status) *http_status = 500;
            snprintf(err, sizeof(err), "failed to delete zone %s", name);
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("delete unreferenced UCI firewall zone"));
    } else {
        if (json_object_object_get_ex(body, "members", &members) && members) {
            if (!json_object_is_type(members, json_type_array)) {
                if (http_status) *http_status = 400;
                snprintf(err, sizeof(err), "members must be an array");
                goto fail;
            }
            if (webd_policy_zone_members_conflict(pkg, s, members,
                                                   conflict_network, sizeof(conflict_network),
                                                   conflict_zone, sizeof(conflict_zone))) {
                if (http_status) *http_status = 409;
                snprintf(err, sizeof(err), "network %s already belongs to zone %s",
                         conflict_network, conflict_zone);
                goto fail;
            }
            if (webd_policy_zone_set_members(ctx, s, members, err, sizeof(err)) != 0) {
                if (http_status) *http_status = 400;
                goto fail;
            }
        }
        if (!create) {
            static const char *keys[] = { "input", "output", "forward" };
            size_t k;
            for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
                struct json_object *v = NULL;
                if (json_object_object_get_ex(body, keys[k], &v) && v &&
                    webd_policy_uci_set_option(ctx, s->e.name, keys[k],
                                               json_object_get_string(v), 0,
                                               err, sizeof(err)) != 0)
                    goto fail;
            }
        }
        if (app_nc_json_has(body, "masq"))
            webd_policy_uci_set_option(ctx, s->e.name, "masq",
                                       app_nc_json_bool(body, "masq", 0) ? "1" : "0",
                                       0, err, sizeof(err));
        if (app_nc_json_has(body, "mtu_fix"))
            webd_policy_uci_set_option(ctx, s->e.name, "mtu_fix",
                                       app_nc_json_bool(body, "mtu_fix", 0) ? "1" : "0",
                                       0, err, sizeof(err));
        json_object_array_add(steps, json_object_new_string("validate unique zone network membership"));
    }
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        if (http_status) *http_status = 500;
        snprintf(err, sizeof(err), "uci commit firewall failed");
        goto restore;
    }
    json_object_array_add(steps, json_object_new_string("commit UCI firewall transaction"));
    if (webd_policy_firewall_validate(steps, warnings, err, sizeof(err)) != 0) {
        if (http_status) *http_status = 409;
        goto restore;
    }
    if (webd_policy_firewall_reload(steps, warnings) != 0) {
        if (http_status) *http_status = 503;
        snprintf(err, sizeof(err), "firewall runtime reload failed");
        goto restore;
    }
    rc = 0;
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    webd_obj_add_str(data, "operation", deleting ? "delete" : (create ? "create" : "update"));
    webd_obj_add_str(data, "zone_id", name);
    json_object_object_add(data, "steps", steps);
    json_object_object_add(data, "warnings", warnings);
    json_object_object_add(data, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.zone_write");

restore:
    if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_FIREWALL, NULL, 0) == 0) {
        json_object_array_add(warnings, json_object_new_string("firewall_config_restored_from_backup"));
        webd_policy_firewall_reload(steps, warnings);
    } else {
        json_object_array_add(warnings, json_object_new_string("firewall_config_restore_failed"));
    }
fail:
    if (rc != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        webd_obj_add_str(data, "error", (http_status && *http_status == 409) ? "zone_conflict" : "zone_write_failed");
        webd_obj_add_str(data, "message", err[0] ? err : "zone write failed");
        if (conflict_network[0]) webd_obj_add_str(data, "conflicting_network", conflict_network);
        if (conflict_zone[0]) webd_obj_add_str(data, "conflicting_zone_id", conflict_zone);
        json_object_object_add(data, "steps", steps);
        json_object_object_add(data, "warnings", warnings);
        json_object_object_add(data, "rollback_supported", json_object_new_boolean(1));
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    if (pkg && ctx) uci_unload(ctx, pkg);
    if (ctx) uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.zone_write");
}

static int webd_policy_matrix_rule_matches(const char *rule_zone, const char *zone)
{
    return !rule_zone || !rule_zone[0] || !strcmp(rule_zone, "*") ||
           !strcmp(rule_zone, "any") || !strcmp(rule_zone, zone);
}

static struct json_object *webd_policy_zone_matrix_response(int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *pairs = json_object_new_array();
    struct json_object *zone_names = json_object_new_array();
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int i, j, n;

    if (http_status)
        *http_status = 200;
    if (!ctx || uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) {
        if (ctx)
            uci_free_context(ctx);
        if (http_status)
            *http_status = 503;
        return webd_error("source_unavailable", "UCI firewall zone matrix is unavailable",
                          "/etc/config/firewall", "webd.policy_engine.zone_matrix");
    }
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        char name[128] = "";
        if (!s || !s->type || strcmp(s->type, "zone"))
            continue;
        webd_policy_uci_option(s, "name", name, sizeof(name));
        if (name[0])
            json_object_array_add(zone_names, json_object_new_string(name));
    }
    n = json_object_array_length(zone_names);
    for (i = 0; i < n; i++) {
        const char *src_name = json_object_get_string(json_object_array_get_idx(zone_names, i));
        for (j = 0; j < n; j++) {
            const char *dst_name = json_object_get_string(json_object_array_get_idx(zone_names, j));
            struct json_object *pair = json_object_new_object();
            struct json_object *rule_ids = json_object_new_array();
            int forwarding = !strcmp(src_name, dst_name);
            int ipv4 = 0, ipv6 = 0, rules = 0;
            const char *effective = forwarding ? "allow" : "block";

            uci_foreach_element(&pkg->sections, e) {
                struct uci_section *s = uci_to_section(e);
                char src[128] = "", dest[128] = "", target[64] = "", family[32] = "";
                char enabled[16] = "1";
                if (!s || !s->type)
                    continue;
                webd_policy_uci_option(s, "src", src, sizeof(src));
                webd_policy_uci_option(s, "dest", dest, sizeof(dest));
                if (!strcmp(s->type, "forwarding")) {
                    if (!strcmp(src, src_name) && !strcmp(dest, dst_name))
                        forwarding = 1;
                    continue;
                }
                if (strcmp(s->type, "rule"))
                    continue;
                webd_policy_uci_option(s, "enabled", enabled, sizeof(enabled));
                if (!webd_policy_str_true(enabled) ||
                    !webd_policy_matrix_rule_matches(src, src_name) ||
                    !webd_policy_matrix_rule_matches(dest, dst_name))
                    continue;
                webd_policy_uci_option(s, "target", target, sizeof(target));
                webd_policy_uci_option(s, "family", family, sizeof(family));
                rules++;
                if (!strcmp(family, "ipv4")) ipv4++;
                else if (!strcmp(family, "ipv6")) ipv6++;
                else { ipv4++; ipv6++; }
                if (s->e.name)
                    json_object_array_add(rule_ids, json_object_new_string(s->e.name));
                if (!strcasecmp(target, "DROP") || !strcasecmp(target, "REJECT"))
                    effective = "block";
                else if (!strcasecmp(target, "ACCEPT"))
                    effective = "allow";
            }
            if (forwarding && !rules)
                effective = "allow";
            webd_obj_add_str(pair, "source_zone_id", src_name);
            webd_obj_add_str(pair, "destination_zone_id", dst_name);
            webd_obj_add_str(pair, "effective_action", effective);
            webd_obj_add_str(pair, "return_action", "allow_return");
            json_object_object_add(pair, "forwarding_enabled", json_object_new_boolean(forwarding));
            json_object_object_add(pair, "policy_count", json_object_new_int(rules));
            json_object_object_add(pair, "ipv4_policy_count", json_object_new_int(ipv4));
            json_object_object_add(pair, "ipv6_policy_count", json_object_new_int(ipv6));
            json_object_object_add(pair, "rule_ids", rule_ids);
            json_object_array_add(pairs, pair);
        }
    }
    json_object_object_add(data, "zones", zone_names);
    json_object_object_add(data, "pairs", pairs);
    json_object_object_add(data, "total", json_object_new_int(json_object_array_length(pairs)));
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    webd_obj_add_str(data, "source", "uci:firewall.zone+forwarding+rule");
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.zone_matrix");
}

static struct json_object *webd_policy_objects_response(int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *legacy = json_object_new_array();
    struct json_object *blocked = json_object_new_array();
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int composite_total = 0;

    if (http_status)
        *http_status = 200;
    if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK && db) {
        sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);
        /* Read legacy route objects (routed's own table) */
        if (sqlite3_prepare_v2(db,
            "SELECT id,name,object_type,family,value,comment,enabled,updated_at "
            "FROM route_object ORDER BY name,id", -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                struct json_object *o = json_object_new_object();
                webd_obj_add_str(o, "id", webd_sql_text(st, 0));
                webd_obj_add_str(o, "name", webd_sql_text(st, 1));
                webd_obj_add_str(o, "object_type", webd_sql_text(st, 2));
                webd_obj_add_str(o, "family", webd_sql_text(st, 3));
                webd_obj_add_str(o, "value", webd_sql_text(st, 4));
                webd_obj_add_str(o, "comment", webd_sql_text(st, 5));
                json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
                json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
                webd_obj_add_str(o, "source", "config.db:route_object");
                json_object_array_add(legacy, o);
            }
            sqlite3_finalize(st);
        }
        /* Read composite policy objects */
        if (sqlite3_prepare_v2(db,
            "SELECT id,name,object_type,family,value,components_json,comment,enabled,updated_at "
            "FROM policy_composite_object ORDER BY name,id", -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                struct json_object *o = json_object_new_object();
                webd_obj_add_str(o, "id", webd_sql_text(st, 0));
                webd_obj_add_str(o, "name", webd_sql_text(st, 1));
                webd_obj_add_str(o, "object_type", webd_sql_text(st, 2));
                webd_obj_add_str(o, "family", webd_sql_text(st, 3));
                webd_obj_add_str(o, "value", webd_sql_text(st, 4));
                webd_obj_add_str(o, "components_json", webd_sql_text(st, 5));
                webd_obj_add_str(o, "comment", webd_sql_text(st, 6));
                json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 7)));
                json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
                webd_obj_add_str(o, "source", "config.db:policy_composite_object");
                json_object_array_add(items, o);
                composite_total++;
            }
            sqlite3_finalize(st);
        }
        sqlite3_close(db);
    }
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "legacy_route_objects", legacy);
    json_object_object_add(data, "total", json_object_new_int(composite_total));
    json_object_object_add(data, "read_only", json_object_new_boolean(0));
    json_object_object_add(data, "blocked_by", blocked);
    /*
     * read_only above covers composite objects only. legacy_route_objects are
     * routed's own objects and ARE writable through routed; say so here so the page
     * can offer a jump instead of a dead read-only notice.
     */
    webd_obj_add_str(data, "read_only_scope", "policy_engine:composite_object");
    json_object_object_add(data, "legacy_route_objects_read_only", json_object_new_boolean(0));
    webd_obj_add_str(data, "legacy_route_objects_write_endpoint", "/api/v1/routing/objects");
    webd_obj_add_str(data, "legacy_route_objects_owner", "routed");
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    webd_obj_add_str(data, "source", "config.db:route_object+policy_engine_contract");
    return webd_envelope(data, "webd.policy_engine.objects");
}

/* ---- cross-component composite object transaction callbacks ---- */

/*
 * The composite steps below reuse the single-component write helpers, which are
 * defined further down next to their own CRUD routes. Declared here rather than
 * moved, so the coordinator stays next to the capability surface it serves and
 * the single-component paths keep their existing locality.
 */

struct composite_firewall_ctx {
    struct json_object *params;
    char backup_path[256];
};

struct composite_pbr_ctx {
    struct json_object *params;
    char rule_id[128];
};

struct composite_sqm_ctx {
    struct json_object *params;
    char backup_path[256];
};

struct composite_flowd_ctx {
    struct json_object *params;
    char object_id[128];
};

struct composite_txn_ctx {
    struct composite_firewall_ctx *firewall;
    struct composite_pbr_ctx *pbr;
    struct composite_sqm_ctx *sqm;
    struct composite_flowd_ctx *flowd;
    size_t step_count;
};

/* --- firewall callbacks --- */

static int composite_firewall_preflight(void *ctx, char *err, size_t err_len)
{
    struct composite_firewall_ctx *c = ctx;
    const char *name = app_nc_json_str(c->params, "name", "");

    if (!name[0]) {
        if (err) snprintf(err, err_len, "firewall rule name is required");
        return -1;
    }
    return 0;
}

static int composite_firewall_snapshot(void *ctx, void **snap,
                                       char *err, size_t err_len)
{
    struct composite_firewall_ctx *c = ctx;

    if (webd_policy_firewall_backup(c->backup_path, sizeof(c->backup_path),
                                    err, err_len) != 0)
        return -1;
    *snap = malloc(1);
    return *snap ? 0 : -1;
}

static int composite_firewall_apply(void *ctx, char *err, size_t err_len)
{
    struct composite_firewall_ctx *c = ctx;
    struct json_object *steps_arr = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *uci = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    const char *s_name = NULL;
    int rc = -1;

    uci = uci_alloc_context();
    if (!uci) {
        if (err) snprintf(err, err_len, "uci_alloc_context failed");
        goto out;
    }
    if (uci_load(uci, "firewall", &pkg) != UCI_OK) {
        if (err) snprintf(err, err_len, "uci load firewall failed");
        goto out;
    }
    if (uci_add_section(uci, pkg, "rule", &s) != UCI_OK || !s) {
        if (err) snprintf(err, err_len, "uci_add_section firewall rule failed");
        goto out;
    }
    s_name = s->e.name;
    if (!s_name || !s_name[0]) {
        if (err) snprintf(err, err_len, "new firewall section has no name");
        goto out;
    }
    rc = webd_policy_firewall_rule_apply_fields(
        uci, s, c->params, 1, "create", err, err_len, diff);
    if (rc != 0)
        goto out;
    rc = uci_commit(uci, &pkg, 0);
    if (rc != UCI_OK) {
        rc = -1;
        if (err) snprintf(err, err_len, "uci commit firewall failed");
        goto out;
    }
    uci_free_context(uci);
    uci = NULL;
    if (webd_policy_firewall_validate(steps_arr, warnings, err, err_len) != 0) {
        rc = -1;
        goto out;
    }
    return webd_policy_firewall_reload(steps_arr, warnings);
out:
    if (uci) uci_free_context(uci);
    json_object_put(steps_arr);
    json_object_put(warnings);
    json_object_put(diff);
    return rc;
}

static void composite_firewall_snapshot_free(void *ctx, void *snap)
{
    (void)ctx;
    free(snap);
}

static int composite_firewall_restore(void *ctx, void *snap,
                                      char *err, size_t err_len)
{
    struct composite_firewall_ctx *c = ctx;
    struct json_object *steps_arr = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    int rc;

    (void)snap;
    if (!c->backup_path[0])
        return 0;
    rc = webd_policy_copy_file(c->backup_path,
                               WEBD_POLICY_CONFIG_FIREWALL, err, err_len);
    if (rc != 0)
        return rc;
    return webd_policy_firewall_reload(steps_arr, warnings);
}

/* --- PBR callbacks --- */

static int composite_pbr_preflight(void *ctx, char *err, size_t err_len)
{
    struct composite_pbr_ctx *c = ctx;
    const char *target = app_nc_json_str(c->params, "target", "");

    if (!c->rule_id[0]) {
        if (err) snprintf(err, err_len, "pbr rule id is required");
        return -1;
    }
    if (!target[0]) {
        if (err) snprintf(err, err_len, "pbr rule target is required");
        return -1;
    }
    return 0;
}

static int composite_pbr_snapshot(void *ctx, void **snap,
                                  char *err, size_t err_len)
{
    (void)ctx; (void)err; (void)err_len;
    *snap = malloc(1);
    return *snap ? 0 : -1;
}

static int composite_pbr_apply(void *ctx, char *err, size_t err_len)
{
    struct composite_pbr_ctx *c = ctx;
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    const char *name_s = app_nc_json_str(c->params, "name", "");
    const char *action_raw = app_nc_json_str(c->params, "action", "route");
    const char *target = app_nc_json_str(c->params, "target", "");
    const char *src = app_nc_json_str(c->params, "source_object", "");
    const char *dst = app_nc_json_str(c->params, "dest_object", "");
    const char *proto = app_nc_json_str(c->params, "proto", "");
    const char *ports = app_nc_json_str(c->params, "ports", "");
    const char *route_table = app_nc_json_str(c->params, "route_table", "");
    const char *comment_s = app_nc_json_str(c->params, "comment", "");
    const char *src_kind = app_nc_json_str(c->params, "source_kind", "");
    const char *src_ref = app_nc_json_str(c->params, "source_ref", "");
    int enabled = app_nc_json_bool(c->params, "enabled", 1);
    int priority = app_nc_json_int(c->params, "priority", 100);
    int pin_wan = app_nc_json_bool(c->params, "pin_wan", 0);
    char action[32] = "route";
    char schedule[64] = "always";

    if (!strcasecmp(action_raw, "route") || !strcasecmp(action_raw, "nexthop"))
        snprintf(action, sizeof(action), "route");
    else if (!strcasecmp(action_raw, "main") || !strcasecmp(action_raw, "drop") ||
             !strcasecmp(action_raw, "mark"))
        snprintf(action, sizeof(action), "%s", action_raw);

    {
        const char *sched_raw = app_nc_json_str(c->params, "schedule", "");
        if (sched_raw[0])
            snprintf(schedule, sizeof(schedule), "%s", sched_raw);
    }

    if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db,
                        SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK || !db) {
        if (err) snprintf(err, err_len, "open config.db failed");
        goto out;
    }
    sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);

    if (sqlite3_prepare_v2(db,
        "INSERT INTO policy_route_rule("
        "id,enabled,priority,name,source_object,dest_object,proto,ports,action,target,"
        "route_table,schedule,sticky,comment,updated_at,source_kind,source_ref,pin_wan"
        ") VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18) "
        "ON CONFLICT(id) DO UPDATE SET "
        "enabled=excluded.enabled,priority=excluded.priority,name=excluded.name,"
        "source_object=excluded.source_object,dest_object=excluded.dest_object,"
        "proto=excluded.proto,ports=excluded.ports,action=excluded.action,"
        "target=excluded.target,route_table=excluded.route_table,"
        "schedule=excluded.schedule,sticky=excluded.sticky,comment=excluded.comment,"
        "updated_at=excluded.updated_at,source_kind=excluded.source_kind,"
        "source_ref=excluded.source_ref,pin_wan=excluded.pin_wan",
        -1, &st, NULL) != SQLITE_OK) {
        if (err) snprintf(err, err_len, "prepare policy_route_rule upsert failed: %s",
                          sqlite3_errmsg(db));
        goto out;
    }
    sqlite3_bind_text(st, 1, c->rule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, enabled);
    sqlite3_bind_int(st, 3, priority);
    sqlite3_bind_text(st, 4, name_s, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, src, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, dst, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, ports, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, target, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, route_table, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, schedule, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 13, app_nc_json_bool(c->params, "sticky", 1));
    sqlite3_bind_text(st, 14, comment_s, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 15, now_s());
    sqlite3_bind_text(st, 16, src_kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 17, src_ref, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 18, pin_wan ? 1 : 0);
    if (sqlite3_step(st) != SQLITE_DONE) {
        if (err) snprintf(err, err_len, "write policy_route_rule failed: %s",
                          sqlite3_errmsg(db));
        sqlite3_finalize(st);
        st = NULL;
        goto out;
    }
    sqlite3_finalize(st);
    st = NULL;
    rc = 0;
out:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    if (rc == 0) {
        struct json_object *resp;
        resp = app_ubus_invoke_timeout("route_reload", NULL, 5000);
        if (resp) json_object_put(resp);
    }
    return rc;
}

static void composite_pbr_snapshot_free(void *ctx, void *snap)
{
    (void)ctx;
    free(snap);
}

static int composite_pbr_restore(void *ctx, void *snap,
                                 char *err, size_t err_len)
{
    struct composite_pbr_ctx *c = ctx;
    struct json_object *resp;
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;

    (void)snap; (void)err; (void)err_len;
    if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db,
                        SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK || !db)
        return -1;
    sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);
    if (sqlite3_prepare_v2(db,
            "DELETE FROM policy_route_rule WHERE id=?1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, c->rule_id, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    resp = app_ubus_invoke_timeout("route_reload", NULL, 5000);
    if (resp) json_object_put(resp);
    return 0;
}

/* --- SQM callbacks --- */

static int composite_sqm_preflight(void *ctx, char *err, size_t err_len)
{
    struct composite_sqm_ctx *c = ctx;
    const char *iface = app_nc_json_str(c->params, "interface", "");

    if (!iface[0]) {
        if (err) snprintf(err, err_len, "sqm interface is required");
        return -1;
    }
    return 0;
}

static int composite_sqm_snapshot(void *ctx, void **snap,
                                  char *err, size_t err_len)
{
    struct composite_sqm_ctx *c = ctx;

    if (webd_policy_sqm_backup(c->backup_path, sizeof(c->backup_path),
                                err, err_len) != 0)
        return -1;
    *snap = malloc(1);
    return *snap ? 0 : -1;
}

static int composite_sqm_apply(void *ctx, char *err, size_t err_len)
{
    struct composite_sqm_ctx *c = ctx;
    struct json_object *steps_arr = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *uci = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    const char *s_name = NULL;
    int rc = -1;

    uci = uci_alloc_context();
    if (!uci) {
        if (err) snprintf(err, err_len, "uci_alloc_context failed");
        goto out;
    }
    if (uci_load(uci, "sqm", &pkg) != UCI_OK) {
        if (err) snprintf(err, err_len, "uci load sqm failed");
        goto out;
    }
    if (uci_add_section(uci, pkg, "queue", &s) != UCI_OK || !s) {
        if (err) snprintf(err, err_len, "uci_add_section sqm queue failed");
        goto out;
    }
    s_name = s->e.name;
    if (!s_name || !s_name[0]) {
        if (err) snprintf(err, err_len, "new sqm section has no name");
        goto out;
    }
    rc = webd_policy_sqm_apply_fields(
        uci, s, c->params, 1, "create", err, err_len, diff);
    if (rc != 0)
        goto out;
    rc = uci_commit(uci, &pkg, 0);
    if (rc != UCI_OK) {
        rc = -1;
        if (err) snprintf(err, err_len, "uci commit sqm failed");
        goto out;
    }
    uci_free_context(uci);
    uci = NULL;
    return webd_policy_sqm_reload(steps_arr, warnings);
out:
    if (uci) uci_free_context(uci);
    json_object_put(steps_arr);
    json_object_put(warnings);
    json_object_put(diff);
    return rc;
}

static void composite_sqm_snapshot_free(void *ctx, void *snap)
{
    (void)ctx;
    free(snap);
}

static int composite_sqm_restore(void *ctx, void *snap,
                                 char *err, size_t err_len)
{
    struct composite_sqm_ctx *c = ctx;
    struct json_object *steps_arr = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    int rc;

    (void)snap;
    if (!c->backup_path[0])
        return 0;
    rc = webd_policy_copy_file(c->backup_path,
                               WEBD_POLICY_CONFIG_SQM, err, err_len);
    if (rc != 0)
        return rc;
    return webd_policy_sqm_reload(steps_arr, warnings);
}

/* --- flowd callbacks (IRREVERSIBLE) --- */

static int composite_flowd_preflight(void *ctx, char *err, size_t err_len)
{
    struct composite_flowd_ctx *c = ctx;
    const char *type = app_nc_json_str(c->params, "type", "");
    const char *id = app_nc_json_str(c->params, "id", "");

    if (!type[0]) {
        if (err) snprintf(err, err_len, "flowd object type is required");
        return -1;
    }
    if (strcmp(type, "ip_set") && strcmp(type, "mac_set") &&
        strcmp(type, "domain_set") && strcmp(type, "port_set")) {
        if (err) snprintf(err, err_len, "unsupported flowd object type: %s", type);
        return -1;
    }
    if (!id[0]) {
        if (err) snprintf(err, err_len, "flowd object id is required");
        return -1;
    }
    if (webd_policy_value_safe(id) && webd_policy_value_safe(type))
        return 0;
    if (err) snprintf(err, err_len, "invalid flowd object id or type");
    return -1;
}

static int composite_flowd_apply(void *ctx, char *err, size_t err_len)
{
    struct composite_flowd_ctx *c = ctx;
    struct json_object *req = json_object_new_object();
    struct json_object *resp;
    int ok;

    json_object_object_add(req, "id",
        json_object_new_string(app_nc_json_str(c->params, "id", "")));
    json_object_object_add(req, "type",
        json_object_new_string(app_nc_json_str(c->params, "type", "")));
    json_object_object_add(req, "name",
        json_object_new_string(app_nc_json_str(c->params, "name", "")));
    json_object_object_add(req, "enabled", json_object_new_boolean(1));
    {
        struct json_object *vj = NULL;
        struct json_object *rm = NULL;

        if (json_object_object_get_ex(c->params, "value_json", &vj))
            json_object_object_add(req, "value_json", json_object_get(vj));
        if (json_object_object_get_ex(c->params, "remark", &rm))
            json_object_object_add(req, "remark", json_object_get(rm));
    }

    resp = app_ubus_invoke_object_timeout(
        "dreamingwrt.flowd", "object_set", req, 8000);
    ok = app_ubus_response_ok(resp);
    if (resp) json_object_put(resp);
    if (!ok) {
        if (err) snprintf(err, err_len, "flowd object_set failed");
        return -1;
    }

    {
        struct json_object *compile_req = json_object_new_object();
        struct json_object *compile_resp;

        json_object_object_add(compile_req, "apply", json_object_new_boolean(1));
        compile_resp = app_ubus_invoke_object_timeout(
            "dreamingwrt.flowd", "compile", compile_req, 15000);
        ok = app_ubus_response_ok(compile_resp);
        if (compile_resp) json_object_put(compile_resp);
        if (!ok) {
            struct json_object *del_req = json_object_new_object();
            struct json_object *del_resp;

            json_object_object_add(del_req, "id",
                json_object_new_string(app_nc_json_str(c->params, "id", "")));
            del_resp = app_ubus_invoke_object_timeout(
                "dreamingwrt.flowd", "object_delete", del_req, 5000);
            if (del_resp) json_object_put(del_resp);
            if (err) snprintf(err, err_len,
                              "flowd compile failed; object rolled back");
            return -1;
        }
    }
    return 0;
}

/* --- composite step builder / teardown --- */

static void composite_txn_free_steps(struct webd_admin_txn_step *steps,
                                     size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (!steps[i].context)
            continue;
        if (!strcmp(steps[i].name, "firewall")) {
            struct composite_firewall_ctx *c = steps[i].context;
            if (c->params) json_object_put(c->params);
            free(c);
        } else if (!strcmp(steps[i].name, "pbr")) {
            struct composite_pbr_ctx *c = steps[i].context;
            if (c->params) json_object_put(c->params);
            free(c);
        } else if (!strcmp(steps[i].name, "sqm")) {
            struct composite_sqm_ctx *c = steps[i].context;
            if (c->params) json_object_put(c->params);
            free(c);
        } else if (!strcmp(steps[i].name, "flowd")) {
            struct composite_flowd_ctx *c = steps[i].context;
            if (c->params) json_object_put(c->params);
            free(c);
        }
    }
}

static int composite_txn_build_steps(const char *components_json_str,
                                     struct webd_admin_txn_step *steps,
                                     size_t *step_count,
                                     struct composite_txn_ctx *all_ctx)
{
    struct json_object *arr = json_tokener_parse(components_json_str);
    size_t i, n;

    all_ctx->step_count = 0;
    all_ctx->firewall = NULL;
    all_ctx->pbr = NULL;
    all_ctx->sqm = NULL;
    all_ctx->flowd = NULL;
    *step_count = 0;
    if (!arr || !json_object_is_type(arr, json_type_array)) {
        if (arr) json_object_put(arr);
        return -1;
    }
    n = json_object_array_length(arr);
    for (i = 0; i < n && *step_count < 4; i++) {
        struct json_object *comp = json_object_array_get_idx(arr, i);
        const char *type = app_nc_json_str(comp, "type", "");
        struct json_object *params = NULL;

        json_object_object_get_ex(comp, "params", &params);

        if (!strcmp(type, "firewall") && !all_ctx->firewall) {
            struct composite_firewall_ctx *c = calloc(1, sizeof(*c));
            if (!c) { json_object_put(arr); return -1; }
            c->params = json_object_get(params ? params : json_object_new_object());
            all_ctx->firewall = c;
            steps[(*step_count)++] = (struct webd_admin_txn_step) {
                .name = "firewall",
                .context = c,
                .preflight = composite_firewall_preflight,
                .snapshot = composite_firewall_snapshot,
                .apply = composite_firewall_apply,
                .restore = composite_firewall_restore,
                .snapshot_free = composite_firewall_snapshot_free,
            };
        } else if (!strcmp(type, "pbr") && !all_ctx->pbr) {
            struct composite_pbr_ctx *c = calloc(1, sizeof(*c));
            if (!c) { json_object_put(arr); return -1; }
            c->params = json_object_get(params ? params : json_object_new_object());
            webd_policy_pbr_sanitize_id(
                app_nc_json_str(c->params, "id", ""), c->rule_id, sizeof(c->rule_id));
            all_ctx->pbr = c;
            steps[(*step_count)++] = (struct webd_admin_txn_step) {
                .name = "pbr",
                .context = c,
                .preflight = composite_pbr_preflight,
                .snapshot = composite_pbr_snapshot,
                .apply = composite_pbr_apply,
                .restore = composite_pbr_restore,
                .snapshot_free = composite_pbr_snapshot_free,
            };
        } else if (!strcmp(type, "sqm") && !all_ctx->sqm) {
            struct composite_sqm_ctx *c = calloc(1, sizeof(*c));
            if (!c) { json_object_put(arr); return -1; }
            c->params = json_object_get(params ? params : json_object_new_object());
            all_ctx->sqm = c;
            steps[(*step_count)++] = (struct webd_admin_txn_step) {
                .name = "sqm",
                .context = c,
                .preflight = composite_sqm_preflight,
                .snapshot = composite_sqm_snapshot,
                .apply = composite_sqm_apply,
                .restore = composite_sqm_restore,
                .snapshot_free = composite_sqm_snapshot_free,
            };
        } else if (!strcmp(type, "flowd") && !all_ctx->flowd) {
            struct composite_flowd_ctx *c = calloc(1, sizeof(*c));
            if (!c) { json_object_put(arr); return -1; }
            c->params = json_object_get(params ? params : json_object_new_object());
            snprintf(c->object_id, sizeof(c->object_id), "%s",
                     app_nc_json_str(c->params, "id", ""));
            all_ctx->flowd = c;
            steps[(*step_count)++] = (struct webd_admin_txn_step) {
                .name = "flowd",
                .flags = WEBD_ADMIN_TXN_IRREVERSIBLE,
                .context = c,
                .preflight = composite_flowd_preflight,
                .apply = composite_flowd_apply,
            };
        }
    }
    json_object_put(arr);
    all_ctx->step_count = *step_count;
    return *step_count > 0 ? 0 : -1;
}

/*
 * CRUD handler for composite policy objects (POST/PUT/DELETE).
 * atomic_apply is now true — enabled objects with components trigger a
 * cross-component transaction (firewall/PBR/SQM/flowd) before DB save.
 */
static struct json_object *webd_policy_objects_crud(
    struct json_object *body, const char *method,
    const char *path_tail, int *http_status)
{
    struct json_object *data = json_object_new_object();
    sqlite3 *db = NULL;
    char err[256] = "";
    int rc;

    if (http_status)
        *http_status = 200;
    if (!method) {
        if (http_status) *http_status = 400;
        webd_obj_add_str(data, "error", "missing_method");
        return webd_envelope(data, "webd.policy_engine.objects");
    }
    if (!body)
        body = json_object_new_object();

    /* DELETE /api/v1/policy-engine/objects/<id> */
    if (!strcmp(method, "DELETE")) {
        const char *id = path_tail && path_tail[0] ? path_tail : "";
        sqlite3_stmt *ck = NULL;

        if (!id[0]) {
            if (http_status) *http_status = 400;
            webd_obj_add_str(data, "error", "missing_id");
            webd_obj_add_str(data, "message", "Object id is required for delete");
            return webd_envelope(data, "webd.policy_engine.objects");
        }
        /* Refuse if PBR rules reference this composite object */
        if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK && db) {
            sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);
            if (sqlite3_prepare_v2(db,
                "SELECT id,name FROM policy_route_rule "
                "WHERE source_object=?1 OR dest_object=?1 LIMIT 1",
                -1, &ck, NULL) == SQLITE_OK) {
                sqlite3_bind_text(ck, 1, id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(ck) == SQLITE_ROW) {
                    if (http_status) *http_status = 409;
                    json_object_object_add(data, "ok", json_object_new_boolean(0));
                    webd_obj_add_str(data, "error", "composite_object_referenced");
                    snprintf(err, sizeof(err),
                             "PBR rule '%s' references object '%s'; remove the rule first",
                             webd_sql_text(ck, 0), id);
                    webd_obj_add_str(data, "message", err);
                    webd_obj_add_str(data, "referenced_by_rule", webd_sql_text(ck, 0));
                    webd_obj_add_str(data, "referenced_by_rule_name", webd_sql_text(ck, 1));
                    sqlite3_finalize(ck);
                    sqlite3_close(db);
                    return webd_envelope(data, "webd.policy_engine.objects");
                }
                sqlite3_finalize(ck);
            }
            sqlite3_close(db);
        }
        /* Proceed with delete */
        if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK || !db) {
            if (http_status) *http_status = 500;
            webd_obj_add_str(data, "error", "database_unavailable");
            return webd_envelope(data, "webd.policy_engine.objects");
        }
        sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);
        {
            sqlite3_stmt *del = NULL;
            rc = sqlite3_prepare_v2(db,
                "DELETE FROM policy_composite_object WHERE id=?1", -1, &del, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(del, 1, id, -1, SQLITE_TRANSIENT);
                rc = sqlite3_step(del);
                sqlite3_finalize(del);
            }
        }
        if (rc != SQLITE_DONE) {
            if (http_status) *http_status = 500;
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            webd_obj_add_str(data, "error", "delete_failed");
            webd_obj_add_str(data, "message", sqlite3_errmsg(db));
        } else {
            json_object_object_add(data, "ok", json_object_new_boolean(1));
            webd_obj_add_str(data, "deleted_id", id);
        }
        sqlite3_close(db);
        return webd_envelope(data, "webd.policy_engine.objects");
    }

    /* POST/PUT — create or update */
    {
        const char *id = path_tail && path_tail[0] ? path_tail :
                         app_nc_json_str(body, "id", "");
        const char *name = app_nc_json_str(body, "name", "");
        const char *object_type = app_nc_json_str(body, "object_type", "composite");
        const char *family = app_nc_json_str(body, "family", "mixed");
        const char *value = app_nc_json_str(body, "value", "");
        const char *components_json = app_nc_json_str(body, "components_json", "[]");
        const char *comment = app_nc_json_str(body, "comment", "");
        int enabled = 1;
        struct json_object *enabled_obj = NULL;
        int64_t now;

        if (json_object_object_get_ex(body, "enabled", &enabled_obj))
            enabled = json_object_get_boolean(enabled_obj);
        if (!name[0]) {
            if (http_status) *http_status = 400;
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            webd_obj_add_str(data, "error", "missing_name");
            webd_obj_add_str(data, "message", "Composite object name is required");
            return webd_envelope(data, "webd.policy_engine.objects");
        }
        /* ---- cross-component transaction for enabled composite objects ---- */
        {
            struct webd_admin_txn_step txn_steps[4];
            struct webd_admin_txn_result txn_result;
            struct composite_txn_ctx txn_all_ctx;
            size_t txn_count = 0;

            memset(txn_steps, 0, sizeof(txn_steps));
            memset(&txn_all_ctx, 0, sizeof(txn_all_ctx));
            if (enabled && components_json[0] &&
                strcmp(components_json, "[]") != 0) {
                struct json_object *test_parse = json_tokener_parse(components_json);

                if (test_parse && json_object_is_type(test_parse, json_type_array) &&
                    json_object_array_length(test_parse) > 0) {
                    json_object_put(test_parse);
                    if (composite_txn_build_steps(components_json, txn_steps,
                                                  &txn_count, &txn_all_ctx) != 0) {
                        if (http_status) *http_status = 400;
                        json_object_object_add(data, "ok", json_object_new_boolean(0));
                        webd_obj_add_str(data, "error", "invalid_components");
                        webd_obj_add_str(data, "message",
                                         "Failed to parse composite object components");
                        return webd_envelope(data, "webd.policy_engine.objects");
                    }
                    if (webd_admin_txn_execute(txn_steps, txn_count,
                                               &txn_result) != WEBD_ADMIN_TXN_OK) {
                        if (http_status) *http_status = 500;
                        json_object_object_add(data, "ok", json_object_new_boolean(0));
                        webd_obj_add_str(data, "error", "composite_transaction_failed");
                        snprintf(err, sizeof(err),
                                 "Component '%s' failed at %s: %s",
                                 txn_result.failed_step,
                                 txn_result.phase == WEBD_ADMIN_TXN_PHASE_APPLY ?
                                     "apply" :
                                 txn_result.phase == WEBD_ADMIN_TXN_PHASE_PREFLIGHT ?
                                     "preflight" :
                                 txn_result.phase == WEBD_ADMIN_TXN_PHASE_ROLLBACK ?
                                     "rollback" : "snapshot",
                                 txn_result.error);
                        webd_obj_add_str(data, "message", err);
                        webd_obj_add_str(data, "failed_component",
                                         txn_result.failed_step);
                        composite_txn_free_steps(txn_steps, txn_count);
                        return webd_envelope(data, "webd.policy_engine.objects");
                    }
                    composite_txn_free_steps(txn_steps, txn_count);
                } else {
                    if (test_parse) json_object_put(test_parse);
                }
            }
        }
        if (sqlite3_open_v2(WEBD_POLICY_CONFIG_DB, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK || !db) {
            if (http_status) *http_status = 500;
            webd_obj_add_str(data, "error", "database_unavailable");
            return webd_envelope(data, "webd.policy_engine.objects");
        }
        sqlite3_busy_timeout(db, WEBD_DB_BUSY_TIMEOUT_MS);
        now = (int64_t)time(NULL);

        if (id[0]) {
            /* Update existing */
            sqlite3_stmt *upd = NULL;
            rc = sqlite3_prepare_v2(db,
                "UPDATE policy_composite_object SET "
                "name=?1, object_type=?2, family=?3, value=?4, "
                "components_json=?5, comment=?6, enabled=?7, updated_at=?8 "
                "WHERE id=?9", -1, &upd, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(upd, 1, name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(upd, 2, object_type, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(upd, 3, family, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(upd, 4, value, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(upd, 5, components_json, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(upd, 6, comment, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(upd, 7, enabled);
                sqlite3_bind_int64(upd, 8, now);
                sqlite3_bind_text(upd, 9, id, -1, SQLITE_TRANSIENT);
                rc = sqlite3_step(upd);
                sqlite3_finalize(upd);
            }
            if (rc != SQLITE_DONE) {
                if (http_status) *http_status = 500;
                json_object_object_add(data, "ok", json_object_new_boolean(0));
                webd_obj_add_str(data, "error", "update_failed");
                webd_obj_add_str(data, "message", sqlite3_errmsg(db));
            } else if (sqlite3_changes(db) == 0) {
                if (http_status) *http_status = 404;
                json_object_object_add(data, "ok", json_object_new_boolean(0));
                webd_obj_add_str(data, "error", "not_found");
                snprintf(err, sizeof(err), "Composite object '%s' not found", id);
                webd_obj_add_str(data, "message", err);
            } else {
                json_object_object_add(data, "ok", json_object_new_boolean(1));
                webd_obj_add_str(data, "id", id);
            }
        } else {
            /* Insert new — generate id from name */
            char gen_id[192];
            sqlite3_stmt *ins = NULL;
            snprintf(gen_id, sizeof(gen_id), "comp-%s", name);
            /* Sanitize id */
            {
                size_t i;
                for (i = 0; gen_id[i]; i++) {
                    unsigned char c = (unsigned char)gen_id[i];
                    if (!isalnum(c) && c != '_' && c != '-')
                        gen_id[i] = '-';
                }
            }
            rc = sqlite3_prepare_v2(db,
                "INSERT INTO policy_composite_object "
                "(id, enabled, name, object_type, family, value, "
                "components_json, comment, updated_at) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", -1, &ins, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(ins, 1, gen_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(ins, 2, enabled);
                sqlite3_bind_text(ins, 3, name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins, 4, object_type, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins, 5, family, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins, 6, value, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins, 7, components_json, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins, 8, comment, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(ins, 9, now);
                rc = sqlite3_step(ins);
                sqlite3_finalize(ins);
            }
            if (rc != SQLITE_DONE) {
                if (http_status) *http_status = (rc == SQLITE_CONSTRAINT) ? 409 : 500;
                json_object_object_add(data, "ok", json_object_new_boolean(0));
                webd_obj_add_str(data, "error", rc == SQLITE_CONSTRAINT ?
                                 "duplicate_name" : "insert_failed");
                webd_obj_add_str(data, "message", sqlite3_errmsg(db));
            } else {
                json_object_object_add(data, "ok", json_object_new_boolean(1));
                webd_obj_add_str(data, "id", gen_id);
                if (http_status) *http_status = 201;
            }
        }
        sqlite3_close(db);
    }
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    return webd_envelope(data, "webd.policy_engine.objects");
}

static int policy_zone_id_path(const char *path)
{
    const char *base = "/api/v1/policy-engine/zones/";
    const char *tail;

    if (!path || strncmp(path, base, strlen(base)) != 0)
        return 0;
    tail = path + strlen(base);
    return tail[0] && !strchr(tail, '/');
}

static int policy_objects_path(const char *path)
{
    if (!path || !strcmp(path, "/api/v1/policy-engine/objects/"))
        return 0;
    return !strcmp(path, "/api/v1/policy-engine/objects") ||
           (strncmp(path, "/api/v1/policy-engine/objects/", 30) == 0 &&
            path[30] != '\0');
}

static struct json_object *policy_zones(struct jmx_api_ctx *ctx)
{
    return webd_policy_zones_response(&ctx->status);
}

static struct json_object *policy_zone_create(struct jmx_api_ctx *ctx)
{
    return webd_policy_zone_write_response(ctx->req, ctx->body, "",
                                           &ctx->status);
}

static struct json_object *policy_zone_detail(struct jmx_api_ctx *ctx)
{
    const char *base = "/api/v1/policy-engine/zones/";

    return webd_policy_zone_detail_response(ctx->req->path + strlen(base),
                                             &ctx->status);
}

static struct json_object *policy_zone_update(struct jmx_api_ctx *ctx)
{
    const char *base = "/api/v1/policy-engine/zones/";

    return webd_policy_zone_write_response(ctx->req, ctx->body,
                                           ctx->req->path + strlen(base),
                                           &ctx->status);
}

static struct json_object *policy_zone_matrix(struct jmx_api_ctx *ctx)
{
    return webd_policy_zone_matrix_response(&ctx->status);
}

static struct json_object *policy_objects(struct jmx_api_ctx *ctx)
{
    return webd_policy_objects_response(&ctx->status);
}

static struct json_object *policy_objects_write(struct jmx_api_ctx *ctx)
{
    const char *base = "/api/v1/policy-engine/objects/";
    const char *tail = "";

    if (!strncmp(ctx->req->path, base, strlen(base)))
        tail = ctx->req->path + strlen(base);
    return webd_policy_objects_crud(ctx->body, ctx->req->method, tail,
                                    &ctx->status);
}

const struct jmx_api_route policy_objects_api_routes[] = {
    JMX_API_ROUTE(144, "/api/v1/policy-engine/zones", "GET", JMX_API_EXACT, policy_zones),
    JMX_API_ROUTE(145, "/api/v1/policy-engine/zones", "POST", JMX_API_EXACT, policy_zone_create),
    JMX_API_PREDICATE_ROUTE(146, "/api/v1/policy-engine/zones/", "GET", JMX_API_PREDICATE_ONLY, policy_zone_id_path, policy_zone_detail),
    JMX_API_PREDICATE_ROUTE(147, "/api/v1/policy-engine/zones/", "PUT,PATCH,DELETE", JMX_API_PREDICATE_ONLY, policy_zone_id_path, policy_zone_update),
    JMX_API_ROUTE(148, "/api/v1/policy-engine/zone-matrix", "GET", JMX_API_EXACT, policy_zone_matrix),
    JMX_API_PREDICATE_ROUTE(149, "/api/v1/policy-engine/objects", "GET", JMX_API_PREDICATE_MIXED, policy_objects_path, policy_objects),
    JMX_API_PREDICATE_ROUTE(150, "/api/v1/policy-engine/objects", "POST,PUT,PATCH,DELETE", JMX_API_PREDICATE_MIXED, policy_objects_path, policy_objects_write),
    JMX_API_ROUTE_END,
};
