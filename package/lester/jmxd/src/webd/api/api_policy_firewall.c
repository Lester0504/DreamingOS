// SPDX-License-Identifier: GPL-2.0-or-later
/* Policy Table: firewall executors. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <libubox/utils.h>

#include "api_policy_write.h"
#include "api_policy_write_internal.h"
#include "api_policy_paths.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_shared_json.h"
#include "api_ubus.h"
#include "api_util.h"
#include "../webd_admin_transaction.h"
#include "../terminal_groups.h"

static void webd_policy_proto_to_uci(const char *in, char *out, size_t out_len);
static struct uci_section *webd_policy_find_firewall_rule_section(struct uci_package *pkg,
                                                                  const char *id,
                                                                  int *section_no_out);
static struct uci_section *webd_policy_find_firewall_redirect_section(struct uci_package *pkg,
                                                                      const char *id,
                                                                      int *section_no_out);
static int webd_policy_port_ranges_parse(const char *spec,
                                         int ranges[][2],
                                         int max_ranges,
                                         int *count_out,
                                         char *err, size_t err_len);
static int webd_policy_port_specs_overlap(const char *a, const char *b);
static int webd_policy_proto_any(const char *proto);
static int webd_policy_proto_specs_overlap(const char *a, const char *b);
static int webd_policy_redirect_validate_and_check_conflict(struct uci_package *pkg,
                                                            struct uci_section *current,
                                                            char *err, size_t err_len,
                                                            struct json_object *warnings);
static int webd_policy_firewall_redirect_apply_fields(struct uci_context *ctx,
                                                      struct uci_section *s,
                                                      struct json_object *body,
                                                      int create,
                                                      const char *operation,
                                                      char *err, size_t err_len,
                                                      struct json_object *diff);
static struct uci_section *webd_policy_find_firewall_nat_section(struct uci_package *pkg,
                                                                 const char *id,
                                                                 int *section_no_out);
static void webd_policy_nat_target_to_uci(const char *in,
                                          const char *snat_ip,
                                          char *out, size_t out_len);
static int webd_policy_firewall_nat_apply_fields(struct uci_context *ctx,
                                                 struct uci_section *s,
                                                 struct json_object *body,
                                                 int create,
                                                 const char *operation,
                                                 char *err, size_t err_len,
                                                 struct json_object *diff);
static const char *webd_policy_acl_array_name(const char *type);
static int webd_policy_acl_raw_id_ok(const char *id);
static int webd_policy_acl_single_line_ok(const char *text, size_t max_len);
static int webd_policy_acl_hhmm_ok(const char *s);
static int webd_policy_acl_schedule_ok(const char *schedule, char *err, size_t err_len);
static int webd_policy_acl_port_spec_ok(const char *spec);
static struct json_object *webd_policy_acl_existing(const char *type, const char *raw_id);
static void webd_policy_acl_copy_body_fields(struct json_object *rule,
                                             struct json_object *body);
static int webd_policy_acl_build_rule(struct json_object *body, const char *type,
                                      const char *raw_id, const char *operation,
                                      struct json_object *existing,
                                      struct json_object **out, char *err, size_t err_len);

static void webd_policy_proto_to_uci(const char *in, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (webd_policy_value_is_any(in))
        return;
    if (!strcasecmp(in, "tcp_udp") || !strcasecmp(in, "tcp/udp") ||
        !strcasecmp(in, "tcp+udp") || !strcmp(in, "TCP/UDP"))
        snprintf(out, out_len, "tcp udp");
    else if (!strcasecmp(in, "IPv4") || !strcasecmp(in, "IPv6") ||
             !strcasecmp(in, "ipv4_ipv6"))
        out[0] = '\0';
    else {
        size_t i;
        snprintf(out, out_len, "%s", in);
        for (i = 0; out[i]; i++)
            out[i] = (char)tolower((unsigned char)out[i]);
    }
}

int webd_policy_firewall_rule_id_match(struct uci_section *s,
                                              const char *id,
                                              int section_no)
{
    char generated[256];

    if (!s || !id || !id[0])
        return 0;
    snprintf(generated, sizeof(generated), "uci-firewall-%s-%s-%d",
             s->type ? s->type : "rule",
             s->e.name ? s->e.name : "anon",
             section_no);
    if (!strcmp(id, generated))
        return 1;
    if (s->e.name && !strcmp(id, s->e.name))
        return 1;
    return 0;
}

static struct uci_section *webd_policy_find_firewall_rule_section(struct uci_package *pkg,
                                                                  const char *id,
                                                                  int *section_no_out)
{
    struct uci_element *e;
    int section_no = 0;

    if (!pkg || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type)
            continue;
        section_no++;
        if (strcmp(s->type, "rule"))
            continue;
        if (webd_policy_firewall_rule_id_match(s, id, section_no)) {
            if (section_no_out)
                *section_no_out = section_no;
            return s;
        }
    }
    return NULL;
}

static struct uci_section *webd_policy_find_firewall_redirect_section(struct uci_package *pkg,
                                                                      const char *id,
                                                                      int *section_no_out)
{
    struct uci_element *e;
    int section_no = 0;

    if (!pkg || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type)
            continue;
        section_no++;
        if (strcmp(s->type, "redirect"))
            continue;
        if (webd_policy_firewall_rule_id_match(s, id, section_no)) {
            if (section_no_out)
                *section_no_out = section_no;
            return s;
        }
    }
    return NULL;
}

int webd_policy_firewall_backup(char *backup, size_t backup_len,
                                       char *err, size_t err_len)
{
    time_t now = now_s();

    if (!backup || backup_len == 0)
        return -1;
    backup[0] = '\0';
    mkdir("/tmp/dreamingwrt", 0755);
    mkdir("/tmp/dreamingwrt/policy-backups", 0755);
    snprintf(backup, backup_len, "/tmp/dreamingwrt/policy-backups/firewall.%lld.%ld.bak",
             (long long)now, (long)getpid());
    return webd_policy_copy_file(WEBD_POLICY_CONFIG_FIREWALL, backup, err, err_len);
}

int webd_policy_firewall_validate(struct json_object *steps,
                                         struct json_object *warnings,
                                         char *err, size_t err_len)
{
    int rc;

    if (access("/sbin/fw4", X_OK) == 0 || access("/usr/sbin/fw4", X_OK) == 0 ||
        access("/usr/bin/fw4", X_OK) == 0) {
        json_object_array_add(steps, json_object_new_string("fw4 check"));
        rc = webd_policy_run_cmd("fw4 check >/tmp/dreamingwrt-policy-fw4-check.log 2>&1");
        if (rc != 0) {
            if (err && err_len)
                snprintf(err, err_len, "fw4 check failed rc=%d, see /tmp/dreamingwrt-policy-fw4-check.log", rc);
            return -1;
        }
        return 0;
    }
    if (access("/sbin/fw3", X_OK) == 0 || access("/usr/sbin/fw3", X_OK) == 0 ||
        access("/usr/bin/fw3", X_OK) == 0) {
        json_object_array_add(steps, json_object_new_string("fw3 print"));
        rc = webd_policy_run_cmd("fw3 print >/tmp/dreamingwrt-policy-fw3-print.log 2>&1");
        if (rc != 0) {
            if (err && err_len)
                snprintf(err, err_len, "fw3 print failed rc=%d, see /tmp/dreamingwrt-policy-fw3-print.log", rc);
            return -1;
        }
        return 0;
    }
    json_object_array_add(warnings, json_object_new_string("firewall_validator_unavailable"));
    json_object_array_add(steps, json_object_new_string("validator unavailable; UCI commit accepted without fw4/fw3 validation"));
    return 0;
}

int webd_policy_firewall_reload(struct json_object *steps,
                                       struct json_object *warnings)
{
    int rc;

    json_object_array_add(steps, json_object_new_string("reload firewall runtime"));
    rc = webd_policy_run_cmd("(/etc/init.d/firewall reload || fw4 reload) >/tmp/dreamingwrt-policy-firewall-reload.log 2>&1");
    if (rc != 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "firewall_reload_failed_rc_%d", rc);
        json_object_array_add(warnings, json_object_new_string(msg));
        return -1;
    }
    return 0;
}

int webd_policy_firewall_rule_apply_fields(struct uci_context *ctx,
                                                  struct uci_section *s,
                                                  struct json_object *body,
                                                  int create,
                                                  const char *operation,
                                                  char *err, size_t err_len,
                                                  struct json_object *diff)
{
    static const char *name_keys[] = { "name", "label", "description", "rule_name", NULL };
    static const char *action_keys[] = { "action_key", "action", "target", NULL };
    static const char *proto_keys[] = { "proto", "protocol", "ip_protocol", NULL };
    static const char *src_zone_keys[] = { "src", "source_zone", "src_zone", "sourceZone", NULL };
    static const char *dest_zone_keys[] = { "dest", "destination_zone", "dest_zone", "destinationZone", NULL };
    static const char *src_ip_keys[] = { "src_ip", "source_ip", "source_address", "source_addr", NULL };
    static const char *dest_ip_keys[] = { "dest_ip", "destination_ip", "destination_address", "dest_addr", NULL };
    static const char *src_mac_keys[] = { "src_mac", "source_mac", NULL };
    static const char *dest_mac_keys[] = { "dest_mac", "destination_mac", NULL };
    static const char *src_port_keys[] = { "src_port", "source_port", NULL };
    static const char *dest_port_keys[] = { "dest_port", "destination_port", "dst_port", "port", NULL };
    static const char *family_keys[] = { "family", "ip_version", "ipVersion", NULL };
    static const char *enabled_keys[] = { "enabled", NULL };
    char section[128];
    char value[512];
    char mapped[512];
    int present;

    if (!ctx || !s || !s->e.name || !body)
        return -1;
    snprintf(section, sizeof(section), "%s", s->e.name);

    if (create && !webd_policy_body_string_any(body, name_keys, value, sizeof(value))) {
        if (err && err_len)
            snprintf(err, err_len, "name is required for firewall rule create");
        return -1;
    }
    if ((create || webd_policy_body_string_any(body, name_keys, value, sizeof(value))) && value[0]) {
        if (webd_policy_uci_set_option(ctx, section, "name", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ firewall rule name"));
    }

    value[0] = '\0';
    present = webd_policy_body_string_any(body, action_keys, value, sizeof(value));
    if (create || present) {
        const char *target;
        if (!value[0])
            snprintf(value, sizeof(value), "allow");
        target = webd_policy_action_to_target(value);
        if (!target[0]) {
            if (err && err_len)
                snprintf(err, err_len, "unsupported firewall rule action: %s", value);
            return -1;
        }
        if (webd_policy_uci_set_option(ctx, section, "target", target, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ firewall rule target"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, proto_keys, value, sizeof(value)) || create) {
        webd_policy_proto_to_uci(value, mapped, sizeof(mapped));
        if (webd_policy_uci_set_option(ctx, section, "proto", mapped, 1, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ firewall rule proto"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, src_zone_keys, value, sizeof(value)) || create) {
        webd_policy_zone_to_uci(value, mapped, sizeof(mapped));
        if (webd_policy_uci_set_option(ctx, section, "src", mapped, 1, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ firewall rule src zone"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, dest_zone_keys, value, sizeof(value)) || create) {
        webd_policy_zone_to_uci(value, mapped, sizeof(mapped));
        if (webd_policy_uci_set_option(ctx, section, "dest", mapped, 1, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ firewall rule dest zone"));
    }

#define WEBD_POLICY_SET_BODY_OPTION(keys, option_name) do { \
        value[0] = '\0'; \
        if (webd_policy_body_string_any(body, keys, value, sizeof(value))) { \
            if (webd_policy_value_is_any(value)) value[0] = '\0'; \
            if (webd_policy_uci_set_option(ctx, section, option_name, value, 1, err, err_len) != 0) \
                return -1; \
            json_object_array_add(diff, json_object_new_string("+ firewall rule " option_name)); \
        } \
    } while (0)
    WEBD_POLICY_SET_BODY_OPTION(src_ip_keys, "src_ip");
    WEBD_POLICY_SET_BODY_OPTION(dest_ip_keys, "dest_ip");
    WEBD_POLICY_SET_BODY_OPTION(src_mac_keys, "src_mac");
    WEBD_POLICY_SET_BODY_OPTION(dest_mac_keys, "dest_mac");
    WEBD_POLICY_SET_BODY_OPTION(src_port_keys, "src_port");
    WEBD_POLICY_SET_BODY_OPTION(dest_port_keys, "dest_port");
    WEBD_POLICY_SET_BODY_OPTION(family_keys, "family");
#undef WEBD_POLICY_SET_BODY_OPTION

    present = 0;
    {
        int enabled = webd_policy_body_bool_any(body, enabled_keys, 1, &present);
        if (present || create || !strcmp(operation, "enable") || !strcmp(operation, "disable")) {
        if (!strcmp(operation, "disable"))
            enabled = 0;
        else if (!strcmp(operation, "enable"))
            enabled = 1;
        if (webd_policy_uci_set_option(ctx, section, "enabled", enabled ? "1" : "0", 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ firewall rule enabled"));
        }
    }
    return 0;
}

struct json_object *webd_policy_firewall_rule_apply_response(const struct http_req *req,
                                                                    struct json_object *body,
                                                                    const char *operation,
                                                                    const char *id,
                                                                    int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    char backup[256] = "";
    char err[512] = "";
    char section_name[128] = "";
    int rc = -1;
    int create = operation && !strcmp(operation, "create");
    int reload_firewall;

    if (http_status)
        *http_status = 200;
    json_object_array_add(steps, json_object_new_string("backup /etc/config/firewall"));
    if (webd_policy_firewall_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_object_add(tx, "backup_path", json_object_new_string(backup));

    ctx = uci_alloc_context();
    if (!ctx) {
        snprintf(err, sizeof(err), "uci_alloc_context failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    if (uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) {
        snprintf(err, sizeof(err), "uci_load firewall failed");
        if (http_status) *http_status = 500;
        goto fail;
    }

    if (create) {
        if (uci_add_section(ctx, pkg, "rule", &s) != UCI_OK || !s) {
            snprintf(err, sizeof(err), "uci_add_section firewall rule failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("create firewall rule section"));
    } else {
        if (!id || !id[0]) {
            snprintf(err, sizeof(err), "policy id is required");
            if (http_status) *http_status = 400;
            goto fail;
        }
        s = webd_policy_find_firewall_rule_section(pkg, id, NULL);
        if (!s) {
            snprintf(err, sizeof(err), "firewall rule not found: %s", id);
            if (http_status) *http_status = 404;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("load firewall rule section"));
    }
    snprintf(section_name, sizeof(section_name), "%s", s && s->e.name ? s->e.name : "");
    webd_obj_add_str(tx, "section", section_name);


    if (!strcmp(operation, "delete")) {
        struct uci_ptr ptr;
        char lookup[256];

        snprintf(lookup, sizeof(lookup), "firewall.%s", section_name);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            uci_delete(ctx, &ptr) != UCI_OK) {
            snprintf(err, sizeof(err), "uci_delete firewall rule failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(diff, json_object_new_string("- firewall rule section"));
        json_object_array_add(steps, json_object_new_string("delete firewall rule section"));
    } else if (webd_policy_firewall_rule_apply_fields(ctx, s, body, create, operation,
                                                       err, sizeof(err), diff) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 400;
        goto fail;
    }

    json_object_array_add(steps, json_object_new_string("uci commit firewall"));
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        snprintf(err, sizeof(err), "uci_commit firewall failed");
        if (http_status) *http_status = 500;
        goto fail_restore;
    }
    if (webd_policy_firewall_validate(steps, warnings, err, sizeof(err)) != 0) {
        if (http_status) *http_status = 409;
        goto fail_restore;
    }
    reload_firewall = webd_policy_query_or_body_bool(req, body, "reload_firewall", 1);
    if (reload_firewall)
        webd_policy_firewall_reload(steps, warnings);
    else
        json_object_array_add(warnings, json_object_new_string("firewall_reload_skipped"));

    rc = 0;
    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.firewall_rule_apply");

fail_restore:
    json_object_array_add(steps, json_object_new_string("restore firewall backup after failed validation/commit"));
    if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_FIREWALL, NULL, 0) == 0)
        json_object_array_add(warnings, json_object_new_string("firewall_config_restored_from_backup"));
    else
        json_object_array_add(warnings, json_object_new_string("firewall_config_restore_failed"));
fail:
    if (rc != 0) {
        json_object_object_add(tx, "ok", json_object_new_boolean(0));
        json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
        json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
        json_object_object_add(tx, "applied", json_object_new_boolean(0));
        json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
        json_object_object_add(tx, "error", json_object_new_string(err[0] ? err : "policy transaction failed"));
        json_object_object_add(tx, "steps", steps);
        json_object_object_add(tx, "warnings", warnings);
        json_object_object_add(tx, "diff", diff);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("policy_firewall_rule_apply_failed"));
        json_object_object_add(data, "message", json_object_new_string(err[0] ? err : "policy transaction failed"));
        json_object_object_add(data, "transaction", tx);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    if (pkg && ctx)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.firewall_rule_apply");
}

static int webd_policy_port_ranges_parse(const char *spec,
                                         int ranges[][2],
                                         int max_ranges,
                                         int *count_out,
                                         char *err, size_t err_len)
{
    char tmp[512];
    char *tok;
    char *saveptr = NULL;
    int count = 0;

    if (count_out)
        *count_out = 0;
    if (!spec || !spec[0]) {
        if (err && err_len)
            snprintf(err, err_len, "port is required");
        return 0;
    }
    if (strlen(spec) >= sizeof(tmp)) {
        if (err && err_len)
            snprintf(err, err_len, "port spec is too long");
        return 0;
    }
    snprintf(tmp, sizeof(tmp), "%s", spec);
    for (tok = strtok_r(tmp, " ,\t", &saveptr); tok; tok = strtok_r(NULL, " ,\t", &saveptr)) {
        char *dash;
        char *endp = NULL;
        long a, b;

        if (!tok[0])
            continue;
        if (count >= max_ranges) {
            if (err && err_len)
                snprintf(err, err_len, "too many port ranges");
            return 0;
        }
        dash = strchr(tok, '-');
        errno = 0;
        a = strtol(tok, &endp, 10);
        if (errno || endp == tok || (dash ? endp != dash : *endp != '\0')) {
            if (err && err_len)
                snprintf(err, err_len, "invalid port token: %s", tok);
            return 0;
        }
        if (dash) {
            errno = 0;
            b = strtol(dash + 1, &endp, 10);
            if (errno || endp == dash + 1 || *endp != '\0') {
                if (err && err_len)
                    snprintf(err, err_len, "invalid port range: %s", tok);
                return 0;
            }
        } else {
            b = a;
        }
        if (a < 1 || a > 65535 || b < 1 || b > 65535 || a > b) {
            if (err && err_len)
                snprintf(err, err_len, "port out of range: %s", tok);
            return 0;
        }
        ranges[count][0] = (int)a;
        ranges[count][1] = (int)b;
        count++;
    }
    if (count <= 0) {
        if (err && err_len)
            snprintf(err, err_len, "port is required");
        return 0;
    }
    if (count_out)
        *count_out = count;
    return 1;
}

static int webd_policy_port_specs_overlap(const char *a, const char *b)
{
    int ar[32][2];
    int br[32][2];
    int an = 0, bn = 0;
    int i, j;

    if (!webd_policy_port_ranges_parse(a, ar, 32, &an, NULL, 0) ||
        !webd_policy_port_ranges_parse(b, br, 32, &bn, NULL, 0))
        return 0;
    for (i = 0; i < an; i++) {
        for (j = 0; j < bn; j++) {
            if (ar[i][0] <= br[j][1] && br[j][0] <= ar[i][1])
                return 1;
        }
    }
    return 0;
}

static int webd_policy_proto_any(const char *proto)
{
    return webd_policy_value_is_any(proto) ||
           !strcasecmp(proto ? proto : "", "all") ||
           !strcasecmp(proto ? proto : "", "tcp_udp") ||
           !strcasecmp(proto ? proto : "", "tcp/udp") ||
           !strcasecmp(proto ? proto : "", "tcp udp");
}

static int webd_policy_proto_specs_overlap(const char *a, const char *b)
{
    char ta[128];
    char tb[128];
    char *tok_a;
    char *save_a = NULL;

    if (webd_policy_proto_any(a) || webd_policy_proto_any(b))
        return 1;
    snprintf(ta, sizeof(ta), "%s", a ? a : "");
    snprintf(tb, sizeof(tb), "%s", b ? b : "");
    for (tok_a = strtok_r(ta, " ,/\t", &save_a); tok_a; tok_a = strtok_r(NULL, " ,/\t", &save_a)) {
        char tb_copy[128];
        char *tok_b;
        char *save_b = NULL;
        size_t i;

        for (i = 0; tok_a[i]; i++)
            tok_a[i] = (char)tolower((unsigned char)tok_a[i]);
        snprintf(tb_copy, sizeof(tb_copy), "%s", tb);
        for (tok_b = strtok_r(tb_copy, " ,/\t", &save_b); tok_b; tok_b = strtok_r(NULL, " ,/\t", &save_b)) {
            for (i = 0; tok_b[i]; i++)
                tok_b[i] = (char)tolower((unsigned char)tok_b[i]);
            if (!strcmp(tok_a, tok_b))
                return 1;
        }
    }
    return 0;
}

static int webd_policy_redirect_validate_and_check_conflict(struct uci_package *pkg,
                                                            struct uci_section *current,
                                                            char *err, size_t err_len,
                                                            struct json_object *warnings)
{
    struct uci_element *e;
    char src[128] = "";
    char src_ip[256] = "";
    char proto[128] = "";
    char src_dport[256] = "";
    char enabled_s[32] = "";
    int ranges[32][2];
    int range_count = 0;
    int enabled;

    if (!pkg || !current) {
        if (err && err_len)
            snprintf(err, err_len, "redirect section missing");
        return -1;
    }
    webd_policy_uci_option(current, "src", src, sizeof(src));
    webd_policy_uci_option(current, "src_ip", src_ip, sizeof(src_ip));
    webd_policy_uci_option(current, "proto", proto, sizeof(proto));
    webd_policy_uci_option(current, "src_dport", src_dport, sizeof(src_dport));
    webd_policy_uci_option(current, "enabled", enabled_s, sizeof(enabled_s));
    if (!src[0])
        snprintf(src, sizeof(src), "wan");
    if (!proto[0])
        snprintf(proto, sizeof(proto), "tcp udp");
    enabled = webd_policy_str_true(enabled_s);

    if (!webd_policy_port_ranges_parse(src_dport, ranges, 32, &range_count, err, err_len))
        return -1;
    if (!enabled) {
        json_object_array_add(warnings, json_object_new_string("port_forwarding_conflict_check_skipped_for_disabled_rule"));
        return 0;
    }

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        char other_enabled_s[32] = "";
        char other_src[128] = "";
        char other_src_ip[256] = "";
        char other_proto[128] = "";
        char other_port[256] = "";

        if (!s || s == current || !s->type || strcmp(s->type, "redirect"))
            continue;
        webd_policy_uci_option(s, "enabled", other_enabled_s, sizeof(other_enabled_s));
        if (!webd_policy_str_true(other_enabled_s))
            continue;
        webd_policy_uci_option(s, "src", other_src, sizeof(other_src));
        webd_policy_uci_option(s, "src_ip", other_src_ip, sizeof(other_src_ip));
        webd_policy_uci_option(s, "proto", other_proto, sizeof(other_proto));
        webd_policy_uci_option(s, "src_dport", other_port, sizeof(other_port));
        if (!other_src[0])
            snprintf(other_src, sizeof(other_src), "wan");
        if (!other_proto[0])
            snprintf(other_proto, sizeof(other_proto), "tcp udp");
        if (strcmp(src, other_src))
            continue;
        if (src_ip[0] && other_src_ip[0] && strcmp(src_ip, other_src_ip))
            continue;
        if (!webd_policy_proto_specs_overlap(proto, other_proto))
            continue;
        if (!webd_policy_port_specs_overlap(src_dport, other_port))
            continue;
        if (err && err_len)
            snprintf(err, err_len, "port forwarding conflict with %s on %s/%s/%s",
                     s->e.name ? s->e.name : "redirect",
                     src,
                     proto,
                     src_dport);
        return -1;
    }
    return 0;
}

static int webd_policy_firewall_redirect_apply_fields(struct uci_context *ctx,
                                                      struct uci_section *s,
                                                      struct json_object *body,
                                                      int create,
                                                      const char *operation,
                                                      char *err, size_t err_len,
                                                      struct json_object *diff)
{
    static const char *name_keys[] = { "name", "label", "description", "rule_name", NULL };
    static const char *proto_keys[] = { "proto", "protocol", "ip_protocol", NULL };
    static const char *src_zone_keys[] = { "src", "source_zone", "src_zone", "sourceZone", NULL };
    static const char *dest_zone_keys[] = { "dest", "destination_zone", "dest_zone", "destinationZone", NULL };
    static const char *src_dport_keys[] = { "src_dport", "source_port", "external_port", "wan_port", "destination_port", "dst_port", "port", NULL };
    static const char *dest_ip_keys[] = { "dest_ip", "internal_ip", "target_ip", "lan_ip", NULL };
    static const char *dest_port_keys[] = { "dest_port", "internal_port", "target_port", "to_port", NULL };
    static const char *src_ip_keys[] = { "src_ip", "source_ip", "source_address", "source_addr", NULL };
    static const char *family_keys[] = { "family", "ip_version", "ipVersion", NULL };
    static const char *enabled_keys[] = { "enabled", NULL };
    char section[128];
    char value[512];
    char mapped[512];
    int present;

    if (!ctx || !s || !s->e.name || !body)
        return -1;
    snprintf(section, sizeof(section), "%s", s->e.name);

    if (create && !webd_policy_body_string_any(body, name_keys, value, sizeof(value))) {
        if (err && err_len)
            snprintf(err, err_len, "name is required for port forwarding create");
        return -1;
    }
    if ((create || webd_policy_body_string_any(body, name_keys, value, sizeof(value))) && value[0]) {
        if (webd_policy_uci_set_option(ctx, section, "name", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ redirect name"));
    }

    if (webd_policy_uci_set_option(ctx, section, "target", "DNAT", 0, err, err_len) != 0)
        return -1;
    json_object_array_add(diff, json_object_new_string("+ redirect target DNAT"));

    value[0] = '\0';
    if (webd_policy_body_string_any(body, proto_keys, value, sizeof(value)) || create) {
        webd_policy_proto_to_uci(value, mapped, sizeof(mapped));
        if (webd_policy_uci_set_option(ctx, section, "proto", mapped[0] ? mapped : "tcp udp", 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ redirect proto"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, src_zone_keys, value, sizeof(value)) || create) {
        webd_policy_zone_to_uci(value[0] ? value : "wan", mapped, sizeof(mapped));
        if (!mapped[0])
            snprintf(mapped, sizeof(mapped), "wan");
        if (webd_policy_uci_set_option(ctx, section, "src", mapped, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ redirect src zone"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, dest_zone_keys, value, sizeof(value)) || create) {
        webd_policy_zone_to_uci(value[0] ? value : "lan", mapped, sizeof(mapped));
        if (!mapped[0])
            snprintf(mapped, sizeof(mapped), "lan");
        if (webd_policy_uci_set_option(ctx, section, "dest", mapped, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ redirect dest zone"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, src_dport_keys, value, sizeof(value)) || create) {
        if (webd_policy_value_is_any(value))
            value[0] = '\0';
        if (!value[0]) {
            if (err && err_len)
                snprintf(err, err_len, "external/source port is required for port forwarding");
            return -1;
        }
        if (webd_policy_uci_set_option(ctx, section, "src_dport", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ redirect src_dport"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, dest_ip_keys, value, sizeof(value)) || create) {
        if (webd_policy_value_is_any(value))
            value[0] = '\0';
        if (!value[0]) {
            if (err && err_len)
                snprintf(err, err_len, "internal/destination IP is required for port forwarding");
            return -1;
        }
        if (webd_policy_uci_set_option(ctx, section, "dest_ip", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ redirect dest_ip"));
    }

#define WEBD_POLICY_SET_REDIRECT_OPTION(keys, option_name) do { \
        value[0] = '\0'; \
        if (webd_policy_body_string_any(body, keys, value, sizeof(value))) { \
            if (webd_policy_value_is_any(value)) value[0] = '\0'; \
            if (webd_policy_uci_set_option(ctx, section, option_name, value, 1, err, err_len) != 0) \
                return -1; \
            json_object_array_add(diff, json_object_new_string("+ redirect " option_name)); \
        } \
    } while (0)
    WEBD_POLICY_SET_REDIRECT_OPTION(dest_port_keys, "dest_port");
    WEBD_POLICY_SET_REDIRECT_OPTION(src_ip_keys, "src_ip");
    WEBD_POLICY_SET_REDIRECT_OPTION(family_keys, "family");
#undef WEBD_POLICY_SET_REDIRECT_OPTION

    present = 0;
    {
        int enabled = webd_policy_body_bool_any(body, enabled_keys, 1, &present);
        if (present || create || !strcmp(operation, "enable") || !strcmp(operation, "disable")) {
            if (!strcmp(operation, "disable"))
                enabled = 0;
            else if (!strcmp(operation, "enable"))
                enabled = 1;
            if (webd_policy_uci_set_option(ctx, section, "enabled", enabled ? "1" : "0", 0, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ redirect enabled"));
        }
    }
    return 0;
}

struct json_object *webd_policy_firewall_redirect_apply_response(const struct http_req *req,
                                                                        struct json_object *body,
                                                                        const char *operation,
                                                                        const char *id,
                                                                        int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    char backup[256] = "";
    char err[512] = "";
    char section_name[128] = "";
    int rc = -1;
    int create = operation && !strcmp(operation, "create");
    int reload_firewall;

    if (http_status)
        *http_status = 200;
    json_object_array_add(steps, json_object_new_string("backup /etc/config/firewall"));
    if (webd_policy_firewall_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_object_add(tx, "backup_path", json_object_new_string(backup));

    ctx = uci_alloc_context();
    if (!ctx) {
        snprintf(err, sizeof(err), "uci_alloc_context failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    if (uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) {
        snprintf(err, sizeof(err), "uci_load firewall failed");
        if (http_status) *http_status = 500;
        goto fail;
    }

    if (create) {
        if (uci_add_section(ctx, pkg, "redirect", &s) != UCI_OK || !s) {
            snprintf(err, sizeof(err), "uci_add_section firewall redirect failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("create firewall redirect section"));
    } else {
        if (!id || !id[0]) {
            snprintf(err, sizeof(err), "policy id is required");
            if (http_status) *http_status = 400;
            goto fail;
        }
        s = webd_policy_find_firewall_redirect_section(pkg, id, NULL);
        if (!s) {
            snprintf(err, sizeof(err), "firewall redirect not found: %s", id);
            if (http_status) *http_status = 404;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("load firewall redirect section"));
    }
    snprintf(section_name, sizeof(section_name), "%s", s && s->e.name ? s->e.name : "");
    webd_obj_add_str(tx, "section", section_name);

    if (!strcmp(operation, "delete")) {
        struct uci_ptr ptr;
        char lookup[256];

        snprintf(lookup, sizeof(lookup), "firewall.%s", section_name);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            uci_delete(ctx, &ptr) != UCI_OK) {
            snprintf(err, sizeof(err), "uci_delete firewall redirect failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(diff, json_object_new_string("- redirect section"));
        json_object_array_add(steps, json_object_new_string("delete firewall redirect section"));
    } else if (webd_policy_firewall_redirect_apply_fields(ctx, s, body, create, operation,
                                                           err, sizeof(err), diff) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 400;
        goto fail;
    }
    if (strcmp(operation, "delete") &&
        webd_policy_redirect_validate_and_check_conflict(pkg, s, err, sizeof(err), warnings) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 409;
        goto fail;
    }

    json_object_array_add(steps, json_object_new_string("uci commit firewall"));
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        snprintf(err, sizeof(err), "uci_commit firewall failed");
        if (http_status) *http_status = 500;
        goto fail_restore;
    }
    if (webd_policy_firewall_validate(steps, warnings, err, sizeof(err)) != 0) {
        if (http_status) *http_status = 409;
        goto fail_restore;
    }
    reload_firewall = webd_policy_query_or_body_bool(req, body, "reload_firewall", 1);
    if (reload_firewall)
        webd_policy_firewall_reload(steps, warnings);
    else
        json_object_array_add(warnings, json_object_new_string("firewall_reload_skipped"));

    rc = 0;
    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.port_forwarding_apply");

fail_restore:
    json_object_array_add(steps, json_object_new_string("restore firewall backup after failed validation/commit"));
    if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_FIREWALL, NULL, 0) == 0)
        json_object_array_add(warnings, json_object_new_string("firewall_config_restored_from_backup"));
    else
        json_object_array_add(warnings, json_object_new_string("firewall_config_restore_failed"));
fail:
    if (rc != 0) {
        json_object_object_add(tx, "ok", json_object_new_boolean(0));
        json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
        json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
        json_object_object_add(tx, "applied", json_object_new_boolean(0));
        json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
        json_object_object_add(tx, "error", json_object_new_string(err[0] ? err : "policy transaction failed"));
        json_object_object_add(tx, "steps", steps);
        json_object_object_add(tx, "warnings", warnings);
        json_object_object_add(tx, "diff", diff);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("policy_port_forwarding_apply_failed"));
        json_object_object_add(data, "message", json_object_new_string(err[0] ? err : "policy transaction failed"));
        json_object_object_add(data, "transaction", tx);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    if (pkg && ctx)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.port_forwarding_apply");
}

static struct uci_section *webd_policy_find_firewall_nat_section(struct uci_package *pkg,
                                                                 const char *id,
                                                                 int *section_no_out)
{
    struct uci_element *e;
    int section_no = 0;

    if (!pkg || !id || !id[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!s || !s->type)
            continue;
        section_no++;
        if (strcmp(s->type, "nat"))
            continue;
        if (webd_policy_firewall_rule_id_match(s, id, section_no)) {
            if (section_no_out)
                *section_no_out = section_no;
            return s;
        }
    }
    return NULL;
}

static void webd_policy_nat_target_to_uci(const char *in,
                                          const char *snat_ip,
                                          char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!in || !in[0] || webd_policy_value_is_any(in) ||
        !strcasecmp(in, "convert") || !strcmp(in, "转换")) {
        snprintf(out, out_len, "%s", (snat_ip && snat_ip[0]) ? "SNAT" : "MASQUERADE");
        return;
    }
    if (!strcasecmp(in, "snat") || !strcasecmp(in, "source_nat"))
        snprintf(out, out_len, "SNAT");
    else if (!strcasecmp(in, "masquerade") || !strcasecmp(in, "masq"))
        snprintf(out, out_len, "MASQUERADE");
    else if (!strcasecmp(in, "dnat"))
        snprintf(out, out_len, "DNAT");
    else if (!strcasecmp(in, "redirect"))
        snprintf(out, out_len, "REDIRECT");
    else {
        size_t i;
        snprintf(out, out_len, "%s", in);
        for (i = 0; out[i]; i++)
            out[i] = (char)toupper((unsigned char)out[i]);
    }
}

static int webd_policy_firewall_nat_apply_fields(struct uci_context *ctx,
                                                 struct uci_section *s,
                                                 struct json_object *body,
                                                 int create,
                                                 const char *operation,
                                                 char *err, size_t err_len,
                                                 struct json_object *diff)
{
    static const char *name_keys[] = { "name", "label", "description", "rule_name", NULL };
    static const char *target_keys[] = { "target", "action", "action_key", "nat_type", NULL };
    static const char *proto_keys[] = { "proto", "protocol", "ip_protocol", NULL };
    static const char *src_zone_keys[] = { "src", "source_zone", "src_zone", "sourceZone", NULL };
    static const char *dest_zone_keys[] = { "dest", "destination_zone", "dest_zone", "destinationZone", NULL };
    static const char *src_ip_keys[] = { "src_ip", "source_ip", "source_address", "source_addr", NULL };
    static const char *dest_ip_keys[] = { "dest_ip", "destination_ip", "destination_address", "dest_addr", NULL };
    static const char *src_port_keys[] = { "src_port", "source_port", NULL };
    static const char *dest_port_keys[] = { "dest_port", "destination_port", "dst_port", "port", NULL };
    static const char *snat_ip_keys[] = { "snat_ip", "to_ip", "translated_ip", "translation_ip", NULL };
    static const char *snat_port_keys[] = { "snat_port", "to_port", "translated_port", "translation_port", NULL };
    static const char *family_keys[] = { "family", "ip_version", "ipVersion", NULL };
    static const char *enabled_keys[] = { "enabled", NULL };
    char section[128];
    char value[512];
    char mapped[512];
    char snat_ip[256] = "";
    int present;

    if (!ctx || !s || !s->e.name || !body)
        return -1;
    snprintf(section, sizeof(section), "%s", s->e.name);
    webd_policy_body_string_any(body, snat_ip_keys, snat_ip, sizeof(snat_ip));

    if (create && !webd_policy_body_string_any(body, name_keys, value, sizeof(value))) {
        if (err && err_len)
            snprintf(err, err_len, "name is required for NAT create");
        return -1;
    }
    if ((create || webd_policy_body_string_any(body, name_keys, value, sizeof(value))) && value[0]) {
        if (webd_policy_uci_set_option(ctx, section, "name", value, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ nat name"));
    }

    value[0] = '\0';
    present = webd_policy_body_string_any(body, target_keys, value, sizeof(value));
    if (create || present) {
        webd_policy_nat_target_to_uci(value, snat_ip, mapped, sizeof(mapped));
        if (!strcmp(mapped, "SNAT") && !snat_ip[0]) {
            char existing[256] = "";
            webd_policy_uci_option(s, "snat_ip", existing, sizeof(existing));
            if (!existing[0]) {
                if (err && err_len)
                    snprintf(err, err_len, "snat_ip is required when NAT target is SNAT");
                return -1;
            }
        }
        if (webd_policy_uci_set_option(ctx, section, "target", mapped, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ nat target"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, proto_keys, value, sizeof(value)) || create) {
        webd_policy_proto_to_uci(value, mapped, sizeof(mapped));
        if (webd_policy_uci_set_option(ctx, section, "proto", mapped, 1, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ nat proto"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, src_zone_keys, value, sizeof(value)) || create) {
        webd_policy_zone_to_uci(value[0] ? value : "lan", mapped, sizeof(mapped));
        if (!mapped[0])
            snprintf(mapped, sizeof(mapped), "lan");
        if (webd_policy_uci_set_option(ctx, section, "src", mapped, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ nat src zone"));
    }

    value[0] = '\0';
    if (webd_policy_body_string_any(body, dest_zone_keys, value, sizeof(value)) || create) {
        webd_policy_zone_to_uci(value[0] ? value : "wan", mapped, sizeof(mapped));
        if (!mapped[0])
            snprintf(mapped, sizeof(mapped), "wan");
        if (webd_policy_uci_set_option(ctx, section, "dest", mapped, 0, err, err_len) != 0)
            return -1;
        json_object_array_add(diff, json_object_new_string("+ nat dest zone"));
    }

#define WEBD_POLICY_SET_NAT_OPTION(keys, option_name) do { \
        value[0] = '\0'; \
        if (webd_policy_body_string_any(body, keys, value, sizeof(value))) { \
            if (webd_policy_value_is_any(value)) value[0] = '\0'; \
            if (webd_policy_uci_set_option(ctx, section, option_name, value, 1, err, err_len) != 0) \
                return -1; \
            json_object_array_add(diff, json_object_new_string("+ nat " option_name)); \
        } \
    } while (0)
    WEBD_POLICY_SET_NAT_OPTION(src_ip_keys, "src_ip");
    WEBD_POLICY_SET_NAT_OPTION(dest_ip_keys, "dest_ip");
    WEBD_POLICY_SET_NAT_OPTION(src_port_keys, "src_port");
    WEBD_POLICY_SET_NAT_OPTION(dest_port_keys, "dest_port");
    WEBD_POLICY_SET_NAT_OPTION(snat_ip_keys, "snat_ip");
    WEBD_POLICY_SET_NAT_OPTION(snat_port_keys, "snat_port");
    WEBD_POLICY_SET_NAT_OPTION(family_keys, "family");
#undef WEBD_POLICY_SET_NAT_OPTION

    present = 0;
    {
        int enabled = webd_policy_body_bool_any(body, enabled_keys, 1, &present);
        if (present || create || !strcmp(operation, "enable") || !strcmp(operation, "disable")) {
            if (!strcmp(operation, "disable"))
                enabled = 0;
            else if (!strcmp(operation, "enable"))
                enabled = 1;
            if (webd_policy_uci_set_option(ctx, section, "enabled", enabled ? "1" : "0", 0, err, err_len) != 0)
                return -1;
            json_object_array_add(diff, json_object_new_string("+ nat enabled"));
        }
    }
    return 0;
}

struct json_object *webd_policy_firewall_nat_apply_response(const struct http_req *req,
                                                                   struct json_object *body,
                                                                   const char *operation,
                                                                   const char *id,
                                                                   int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *diff = json_object_new_array();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    char backup[256] = "";
    char err[512] = "";
    char section_name[128] = "";
    int rc = -1;
    int create = operation && !strcmp(operation, "create");
    int reload_firewall;

    if (http_status)
        *http_status = 200;
    json_object_array_add(steps, json_object_new_string("backup /etc/config/firewall"));
    if (webd_policy_firewall_backup(backup, sizeof(backup), err, sizeof(err)) != 0) {
        if (http_status) *http_status = 500;
        goto fail;
    }
    json_object_object_add(tx, "backup_path", json_object_new_string(backup));

    ctx = uci_alloc_context();
    if (!ctx) {
        snprintf(err, sizeof(err), "uci_alloc_context failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    if (uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) {
        snprintf(err, sizeof(err), "uci_load firewall failed");
        if (http_status) *http_status = 500;
        goto fail;
    }

    if (create) {
        if (uci_add_section(ctx, pkg, "nat", &s) != UCI_OK || !s) {
            snprintf(err, sizeof(err), "uci_add_section firewall nat failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("create firewall nat section"));
    } else {
        if (!id || !id[0]) {
            snprintf(err, sizeof(err), "policy id is required");
            if (http_status) *http_status = 400;
            goto fail;
        }
        s = webd_policy_find_firewall_nat_section(pkg, id, NULL);
        if (!s) {
            snprintf(err, sizeof(err), "firewall nat not found: %s", id);
            if (http_status) *http_status = 404;
            goto fail;
        }
        json_object_array_add(steps, json_object_new_string("load firewall nat section"));
    }
    snprintf(section_name, sizeof(section_name), "%s", s && s->e.name ? s->e.name : "");
    webd_obj_add_str(tx, "section", section_name);

    if (!strcmp(operation, "delete")) {
        struct uci_ptr ptr;
        char lookup[256];

        snprintf(lookup, sizeof(lookup), "firewall.%s", section_name);
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            uci_delete(ctx, &ptr) != UCI_OK) {
            snprintf(err, sizeof(err), "uci_delete firewall nat failed");
            if (http_status) *http_status = 500;
            goto fail;
        }
        json_object_array_add(diff, json_object_new_string("- nat section"));
        json_object_array_add(steps, json_object_new_string("delete firewall nat section"));
    } else if (webd_policy_firewall_nat_apply_fields(ctx, s, body, create, operation,
                                                      err, sizeof(err), diff) != 0) {
        if (http_status && *http_status == 200)
            *http_status = 400;
        goto fail;
    }

    json_object_array_add(steps, json_object_new_string("uci commit firewall"));
    if (uci_commit(ctx, &pkg, 0) != UCI_OK) {
        snprintf(err, sizeof(err), "uci_commit firewall failed");
        if (http_status) *http_status = 500;
        goto fail_restore;
    }
    if (webd_policy_firewall_validate(steps, warnings, err, sizeof(err)) != 0) {
        if (http_status) *http_status = 409;
        goto fail_restore;
    }
    reload_firewall = webd_policy_query_or_body_bool(req, body, "reload_firewall", 1);
    if (reload_firewall)
        webd_policy_firewall_reload(steps, warnings);
    else
        json_object_array_add(warnings, json_object_new_string("firewall_reload_skipped"));

    rc = 0;
    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "warnings", warnings);
    json_object_object_add(tx, "diff", diff);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (pkg)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.nat_apply");

fail_restore:
    json_object_array_add(steps, json_object_new_string("restore firewall backup after failed validation/commit"));
    if (backup[0] && webd_policy_copy_file(backup, WEBD_POLICY_CONFIG_FIREWALL, NULL, 0) == 0)
        json_object_array_add(warnings, json_object_new_string("firewall_config_restored_from_backup"));
    else
        json_object_array_add(warnings, json_object_new_string("firewall_config_restore_failed"));
fail:
    if (rc != 0) {
        json_object_object_add(tx, "ok", json_object_new_boolean(0));
        json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
        json_object_object_add(tx, "policy_id", json_object_new_string(id ? id : ""));
        json_object_object_add(tx, "applied", json_object_new_boolean(0));
        json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
        json_object_object_add(tx, "error", json_object_new_string(err[0] ? err : "nat transaction failed"));
        json_object_object_add(tx, "steps", steps);
        json_object_object_add(tx, "warnings", warnings);
        json_object_object_add(tx, "diff", diff);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("policy_nat_apply_failed"));
        json_object_object_add(data, "message", json_object_new_string(err[0] ? err : "nat transaction failed"));
        json_object_object_add(data, "transaction", tx);
        json_object_object_add(data, "capabilities", webd_policy_capabilities());
    }
    if (pkg && ctx)
        uci_unload(ctx, pkg);
    if (ctx)
        uci_free_context(ctx);
    return webd_envelope(data, "webd.policy_engine.nat_apply");
}

int webd_policy_firewall_section_is_type(const char *id, const char *type)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int section_no = 0;
    int ok = 0;

    if (!id || !id[0] || !type || !type[0])
        return 0;
    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg)
        goto out;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        char generated[256];

        if (!s || !s->type)
            continue;
        section_no++;
        if (strcmp(s->type, type))
            continue;
        snprintf(generated, sizeof(generated), "uci-firewall-%s-%s-%d",
                 s->type ? s->type : type,
                 s->e.name ? s->e.name : "anon",
                 section_no);
        if ((s->e.name && !strcmp(id, s->e.name)) || !strcmp(id, generated)) {
            ok = 1;
            break;
        }
    }
out:
    if (pkg)
        uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return ok;
}

int webd_policy_acl_type_supported(const char *type)
{
    return type && !strcmp(type, "mac");
}

static const char *webd_policy_acl_array_name(const char *type)
{
    if (type && !strcmp(type, "mac"))
        return "mac_rules";
    if (type && !strcmp(type, "connection_limit"))
        return "connection_limits";
    return "";
}

int webd_policy_acl_parse_id(const char *policy_id, char *type, size_t type_len,
                                    char *raw_id, size_t raw_id_len)
{
    static const char prefix[] = "network_control.";
    const char *p;
    const char *dot;
    size_t n;

    if (type && type_len)
        type[0] = '\0';
    if (raw_id && raw_id_len)
        raw_id[0] = '\0';
    if (!policy_id || strncmp(policy_id, prefix, sizeof(prefix) - 1))
        return 0;
    p = policy_id + sizeof(prefix) - 1;
    dot = strchr(p, '.');
    if (!dot || dot == p || !dot[1])
        return 0;
    n = (size_t)(dot - p);
    if (!type || !raw_id || n >= type_len || strlen(dot + 1) >= raw_id_len)
        return 0;
    memcpy(type, p, n);
    type[n] = '\0';
    snprintf(raw_id, raw_id_len, "%s", dot + 1);
    return 1;
}

static int webd_policy_acl_raw_id_ok(const char *id)
{
    const unsigned char *p = (const unsigned char *)id;

    if (!id || !id[0] || strlen(id) > 96)
        return 0;
    for (; *p; p++) {
        if (isalnum(*p) || *p == '_' || *p == '-' || *p == '.')
            continue;
        return 0;
    }
    return 1;
}

static int webd_policy_acl_single_line_ok(const char *text, size_t max_len)
{
    const unsigned char *p = (const unsigned char *)text;

    if (!text || !text[0] || strlen(text) > max_len)
        return 0;
    for (; *p; p++) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

static int webd_policy_acl_hhmm_ok(const char *s)
{
    int hh, mm;

    if (!s || strlen(s) != 5 || s[2] != ':')
        return 0;
    if (!isdigit((unsigned char)s[0]) || !isdigit((unsigned char)s[1]) ||
        !isdigit((unsigned char)s[3]) || !isdigit((unsigned char)s[4]))
        return 0;
    hh = (s[0] - '0') * 10 + (s[1] - '0');
    mm = (s[3] - '0') * 10 + (s[4] - '0');
    if (hh == 24)
        return mm == 0;
    return hh <= 23 && mm <= 59;
}

static int webd_policy_acl_schedule_ok(const char *schedule, char *err, size_t err_len)
{
    struct json_object *parsed, *entry, *days, *v;
    const char *start, *end;
    int i, day_count;

    if (!schedule || schedule[0] != '[') {
        snprintf(err, err_len,
                 "schedule must be \"always\" or a JSON array such as "
                 "[{\"weekdays\":[1,2,3,4,5],\"start_time\":\"18:00\",\"end_time\":\"22:00\"}]");
        return -1;
    }
    parsed = json_tokener_parse(schedule);
    if (!parsed || !json_object_is_type(parsed, json_type_array)) {
        if (parsed) json_object_put(parsed);
        snprintf(err, err_len, "schedule is not a valid JSON array");
        return -1;
    }
    if (json_object_array_length(parsed) != 1) {
        json_object_put(parsed);
        snprintf(err, err_len,
                 "schedule must contain exactly one window; nftables matches one "
                 "time expression per rule, so multiple windows need multiple rules");
        return -1;
    }
    entry = json_object_array_get_idx(parsed, 0);
    if (!entry || !json_object_is_type(entry, json_type_object)) {
        json_object_put(parsed);
        snprintf(err, err_len, "schedule entry must be an object");
        return -1;
    }
    start = json_object_object_get_ex(entry, "start_time", &v) && v ?
            json_object_get_string(v) : NULL;
    end = json_object_object_get_ex(entry, "end_time", &v) && v ?
          json_object_get_string(v) : NULL;
    if (!webd_policy_acl_hhmm_ok(start) || !webd_policy_acl_hhmm_ok(end)) {
        json_object_put(parsed);
        snprintf(err, err_len, "start_time and end_time must be \"HH:MM\"");
        return -1;
    }
    if (!strcmp(start, end)) {
        json_object_put(parsed);
        snprintf(err, err_len,
                 "start_time and end_time must differ; an empty window would never match");
        return -1;
    }
    if (json_object_object_get_ex(entry, "weekdays", &days) && days) {
        if (!json_object_is_type(days, json_type_array)) {
            json_object_put(parsed);
            snprintf(err, err_len, "weekdays must be an array of integers 0-6 (0 = Sunday)");
            return -1;
        }
        day_count = json_object_array_length(days);
        if (day_count > 7) {
            json_object_put(parsed);
            snprintf(err, err_len, "weekdays must not contain more than 7 entries");
            return -1;
        }
        {
            int seen[7] = { 0 };

            for (i = 0; i < day_count; i++) {
                struct json_object *d = json_object_array_get_idx(days, i);
                int n;

                if (!d || !json_object_is_type(d, json_type_int)) {
                    json_object_put(parsed);
                    snprintf(err, err_len, "weekdays entries must be integers 0-6 (0 = Sunday)");
                    return -1;
                }
                n = json_object_get_int(d);
                if (n < 0 || n > 6) {
                    json_object_put(parsed);
                    snprintf(err, err_len, "weekdays entries must be in 0-6 (0 = Sunday)");
                    return -1;
                }
                if (seen[n]) {
                    json_object_put(parsed);
                    snprintf(err, err_len, "weekdays must not repeat a day");
                    return -1;
                }
                seen[n] = 1;
            }
        }
    }
    json_object_put(parsed);
    return 0;
}

static int webd_policy_acl_port_spec_ok(const char *spec)
{
    char copy[64];
    char *dash;
    char *end = NULL;
    long first;
    long last;

    if (!spec || !spec[0] || !strcmp(spec, "any"))
        return 1;
    if (strlen(spec) >= sizeof(copy))
        return 0;
    snprintf(copy, sizeof(copy), "%s", spec);
    dash = strchr(copy, '-');
    if (dash)
        *dash++ = '\0';
    first = strtol(copy, &end, 10);
    if (!end || *end || first < 1 || first > 65535)
        return 0;
    if (!dash)
        return 1;
    last = strtol(dash, &end, 10);
    return end && !*end && last >= first && last <= 65535;
}

static struct json_object *webd_policy_acl_existing(const char *type, const char *raw_id)
{
    struct json_object *resp = NULL;
    struct json_object *data = NULL;
    struct json_object *arr = NULL;
    struct json_object *found = NULL;
    const char *array_name = webd_policy_acl_array_name(type);
    int i;

    if (!array_name[0] || !raw_id || !raw_id[0])
        return NULL;
    resp = app_ubus_invoke_timeout("network_control_get", NULL, 1500);
    data = webd_policy_extract_data_ref(resp);
    if (!data || !json_object_object_get_ex(data, array_name, &arr) || !arr ||
        !json_object_is_type(arr, json_type_array))
        goto out;
    for (i = 0; i < (int)json_object_array_length(arr); i++) {
        struct json_object *rule = json_object_array_get_idx(arr, i);

        if (rule && !strcmp(app_nc_json_str(rule, "id", ""), raw_id)) {
            found = json_object_get(rule);
            break;
        }
    }
out:
    if (data)
        json_object_put(data);
    if (resp)
        json_object_put(resp);
    return found;
}

static void webd_policy_acl_copy_body_fields(struct json_object *rule,
                                             struct json_object *body)
{
    static const char *fields[] = {
        "name", "enabled", "priority", "source", "schedule", "remark",
        "mode", "mac", "source_mac", "terminal_name", "protocol", "wan_port",
        "connection_limit", "burst", "action", "expires", NULL
    };
    int i;

    if (!rule || !body)
        return;
    for (i = 0; fields[i]; i++) {
        struct json_object *v = NULL;

        if (json_object_object_get_ex(body, fields[i], &v) && v)
            json_object_object_add(rule, fields[i], json_object_get(v));
    }
}

static int webd_policy_acl_build_rule(struct json_object *body, const char *type,
                                      const char *raw_id, const char *operation,
                                      struct json_object *existing,
                                      struct json_object **out, char *err, size_t err_len)
{
    struct json_object *rule;
    char mac[32] = "";
    const char *name;

    if (out)
        *out = NULL;
    if (!body || !type || !raw_id || !operation || !out)
        return -1;
    rule = existing ? json_tokener_parse(json_object_to_json_string_ext(
        existing, JSON_C_TO_STRING_PLAIN)) : json_object_new_object();
    if (!rule || !json_object_is_type(rule, json_type_object)) {
        if (rule) json_object_put(rule);
        snprintf(err, err_len, "failed to copy existing ACL rule");
        return -1;
    }
    webd_policy_acl_copy_body_fields(rule, body);
    json_object_object_add(rule, "id", json_object_new_string(raw_id));
    name = app_nc_json_str(rule, "name", "");
    if (!name[0])
        json_object_object_add(rule, "name", json_object_new_string(raw_id));
    else if (!webd_policy_acl_single_line_ok(name, 64)) {
        snprintf(err, err_len, "ACL name must be a printable single line up to 64 bytes");
        json_object_put(rule);
        return -1;
    }
    if (!strcmp(operation, "enable"))
        json_object_object_add(rule, "enabled", json_object_new_boolean(1));
    else if (!strcmp(operation, "disable"))
        json_object_object_add(rule, "enabled", json_object_new_boolean(0));
    else if (!app_nc_json_has(rule, "enabled"))
        json_object_object_add(rule, "enabled", json_object_new_boolean(1));

    {
        const char *schedule = app_nc_json_str(rule, "schedule", "always");

        /*
         * Validated against exactly what the nft generator can express, so a
         * schedule that is accepted here always reaches the ruleset. Anything
         * broader would be stored and then silently dropped at apply time,
         * leaving a rule the user believes is time-limited but which blocks all
         * day.
         */
        if (!schedule[0] || !strcmp(schedule, "always")) {
            json_object_object_add(rule, "schedule", json_object_new_string("always"));
        } else if (webd_policy_acl_schedule_ok(schedule, err, err_len) != 0) {
            json_object_put(rule);
            return -1;
        }
    }

    {
        /*
         * expires: absolute unix seconds, 0 = never. A timestamp already in the
         * past is refused rather than accepted-and-ignored, because storing it
         * would create a rule that can never take effect.
         *
         * The refusal applies only to a value the client sent in this request.
         * update/enable/disable start from the existing row, which carries its
         * own expires, so validating the inherited value would make every write
         * against an already-lapsed rule fail with 400 - including the "enable"
         * that re-arms it. That contradicts acl_expires_retains_rule: the row is
         * kept precisely so the user can act on it, which leaves delete-and-
         * recreate as the only way to recover from a lapse.
         */
        int64_t expires = 0;
        struct json_object *ev = NULL;
        struct json_object *body_ev = NULL;
        int from_body = body && json_object_object_get_ex(body, "expires", &body_ev) &&
                        body_ev && !json_object_is_type(body_ev, json_type_null);

        if (json_object_object_get_ex(rule, "expires", &ev) && ev &&
            !json_object_is_type(ev, json_type_null)) {
            if (!json_object_is_type(ev, json_type_int)) {
                snprintf(err, err_len, "expires must be an integer unix timestamp in seconds");
                json_object_put(rule);
                return -1;
            }
            expires = (int64_t)json_object_get_int64(ev);
            if (expires < 0) {
                snprintf(err, err_len, "expires must not be negative");
                json_object_put(rule);
                return -1;
            }
            if (from_body && expires > 0 && expires <= (int64_t)time(NULL)) {
                snprintf(err, err_len,
                         "expires is already in the past; use 0 for a rule that never expires");
                json_object_put(rule);
                return -1;
            }
        }
        json_object_object_add(rule, "expires", json_object_new_int64(expires));
    }

    if (!strcmp(type, "mac")) {
        const char *input = app_nc_json_str(rule, "mac",
                            app_nc_json_str(rule, "source_mac",
                            app_nc_json_str(rule, "source", "")));
        const char *action = app_nc_json_str(rule, "action", "");
        const char *source_kind = app_nc_json_str(rule, "source_kind", "");
        const char *source_ref = app_nc_json_str(rule, "source_ref", "");
        int group_bound = 0;

        /*
         * source_kind:"group" + source_ref:"<group_id>" binds the rule to a
         * terminal group rather than to one device. It is stored as
         * source:"terminal_group:<id>" and left alone from here on: the ruleset
         * generator expands the group's members at apply time, so adding or
         * removing a device from the group changes what the rule blocks without
         * the rule being rewritten. Overwriting source with a single MAC, which
         * is what the single-device path does below, is exactly what made group
         * binding impossible.
         */
        if (source_kind[0] && strcmp(source_kind, "mac") && strcmp(source_kind, "group")) {
            snprintf(err, err_len, "source_kind must be \"mac\" or \"group\"");
            json_object_put(rule);
            return -1;
        }
        if (!strcmp(source_kind, "group")) {
            if (!webd_terminal_group_id_ok(source_ref)) {
                snprintf(err, err_len,
                         "source_kind \"group\" requires source_ref to be a terminal group id");
                json_object_put(rule);
                return -1;
            }
            if (!webd_terminal_group_exists(source_ref)) {
                snprintf(err, err_len, "terminal group not found: %s", source_ref);
                json_object_put(rule);
                return -1;
            }
            group_bound = 1;
        } else if (!source_kind[0] &&
                   !strncmp(app_nc_json_str(rule, "source", ""), "terminal_group:", 15)) {
            /* An existing group rule edited without restating source_kind keeps
             * its binding instead of silently collapsing to a single MAC. */
            const char *existing_ref = app_nc_json_str(rule, "source", "") + 15;

            if (!webd_terminal_group_id_ok(existing_ref) ||
                !webd_terminal_group_exists(existing_ref)) {
                snprintf(err, err_len,
                         "rule is bound to terminal group '%s' which no longer exists; "
                         "set source_kind and source_ref to rebind it",
                         existing_ref);
                json_object_put(rule);
                return -1;
            }
            source_ref = existing_ref;
            group_bound = 1;
        }
        if (!group_bound && webd_normalize_mac_text(input, mac, sizeof(mac)) != 0) {
            snprintf(err, err_len, "mac ACL requires a valid mac address");
            json_object_put(rule);
            return -1;
        }
        if (group_bound) {
            char source_value[160];

            snprintf(source_value, sizeof(source_value), "terminal_group:%s", source_ref);
            /* Empty mac marks the rule as group-bound in
             * network_control_mac_rule; the uniqueness index over mac is partial
             * so several group rules coexist. */
            json_object_object_add(rule, "mac", json_object_new_string(""));
            json_object_object_add(rule, "source", json_object_new_string(source_value));
            json_object_object_add(rule, "source_kind", json_object_new_string("group"));
            json_object_object_add(rule, "source_ref", json_object_new_string(source_ref));
        } else {
            json_object_object_add(rule, "mac", json_object_new_string(mac));
            json_object_object_add(rule, "source", json_object_new_string(mac));
            json_object_object_add(rule, "source_kind", json_object_new_string("mac"));
            json_object_object_del(rule, "source_ref");
        }
        const char *mode = app_nc_json_str(rule, "mode", "");

        if (action[0] && strcasecmp(action, "deny") && strcasecmp(action, "block") &&
            strcasecmp(action, "drop")) {
            snprintf(err, err_len, "MAC ACL currently supports deny only");
            json_object_put(rule);
            return -1;
        }
        if (!action[0] && mode[0] && strcmp(mode, "deny") && strcmp(mode, "block")) {
            snprintf(err, err_len, "MAC ACL currently supports deny only");
            json_object_put(rule);
            return -1;
        }
        if (action[0])
            json_object_object_add(rule, "mode", json_object_new_string("deny"));
        else if (!mode[0])
            json_object_object_add(rule, "mode", json_object_new_string("deny"));
    } else if (!strcmp(type, "connection_limit")) {
        int limit = app_nc_json_int(rule, "connection_limit", 0);
        int burst = app_nc_json_int(rule, "burst", 80);
        const char *protocol = app_nc_json_str(rule, "protocol", "tcp");
        const char *wan_port = app_nc_json_str(rule, "wan_port", "any");

        if (limit <= 0 || limit > 1000000 || burst < 0 || burst > 1000000) {
            snprintf(err, err_len, "connection_limit must be 1..1000000 and burst 0..1000000");
            json_object_put(rule);
            return -1;
        }
        if (strcmp(protocol, "tcp") && strcmp(protocol, "udp") &&
            strcmp(protocol, "tcp,udp") && strcmp(protocol, "udp,tcp")) {
            snprintf(err, err_len, "connection_limit protocol must be tcp, udp, or tcp,udp");
            json_object_put(rule);
            return -1;
        }
        if (!webd_policy_acl_port_spec_ok(wan_port)) {
            snprintf(err, err_len, "wan_port must be any, one port, or a numeric port range");
            json_object_put(rule);
            return -1;
        }
        if (!app_nc_json_has(rule, "protocol"))
            json_object_object_add(rule, "protocol", json_object_new_string("tcp"));
        if (!app_nc_json_has(rule, "wan_port"))
            json_object_object_add(rule, "wan_port", json_object_new_string("any"));
        if (!app_nc_json_has(rule, "action"))
            json_object_object_add(rule, "action", json_object_new_string("limit"));
    } else {
        snprintf(err, err_len, "unsupported ACL type");
        json_object_put(rule);
        return -1;
    }
    *out = rule;
    return 0;
}

struct json_object *webd_policy_acl_apply_response(struct json_object *body,
                                                          const char *operation,
                                                          const char *policy_id,
                                                          int *http_status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tx = json_object_new_object();
    struct json_object *steps = json_object_new_array();
    struct json_object *rule = NULL;
    struct json_object *existing = NULL;
    struct json_object *params = NULL;
    struct json_object *save_resp = NULL;
    struct json_object *apply_resp = NULL;
    struct json_object *rollback_resp = NULL;
    struct json_object *arr;
    char id_type[64] = "";
    char type[64] = "";
    char raw_id[128] = "";
    char generated[128] = "";
    char err[256] = "";
    const char *requested_type = app_nc_json_str(body, "acl_type", "");
    const char *array_name;
    int create = operation && !strcmp(operation, "create");
    int delete_rule = operation && !strcmp(operation, "delete");
    int saved = 0;
    int applied = 0;
    int rolled_back = 0;

    if (http_status)
        *http_status = 200;
    if (!operation || (strcmp(operation, "create") && strcmp(operation, "update") &&
                       strcmp(operation, "delete") && strcmp(operation, "enable") &&
                       strcmp(operation, "disable"))) {
        snprintf(err, sizeof(err), "unsupported ACL operation");
        if (http_status) *http_status = 400;
        goto fail;
    }
    if (policy_id && policy_id[0])
        webd_policy_acl_parse_id(policy_id, id_type, sizeof(id_type), raw_id, sizeof(raw_id));
    snprintf(type, sizeof(type), "%s", requested_type[0] ? requested_type : id_type);
    if (id_type[0] && requested_type[0] && strcmp(id_type, requested_type)) {
        snprintf(err, sizeof(err), "acl_type does not match policy id");
        if (http_status) *http_status = 409;
        goto fail;
    }
    if (!webd_policy_acl_type_supported(type)) {
        snprintf(err, sizeof(err), "ACL type requires acl_type=mac; other ACL dataplanes are not ready");
        if (http_status) *http_status = 400;
        goto fail;
    }
    if (create && !raw_id[0]) {
        const char *candidate = app_nc_json_str(body, "rule_id",
                                app_nc_json_str(body, "config_id", ""));
        if (candidate[0])
            snprintf(raw_id, sizeof(raw_id), "%s", candidate);
        else {
            snprintf(generated, sizeof(generated), "policy-acl-%s-%lld-%ld",
                     type, (long long)now_s(), random() & 0xffff);
            snprintf(raw_id, sizeof(raw_id), "%s", generated);
        }
    }
    if (!webd_policy_acl_raw_id_ok(raw_id)) {
        snprintf(err, sizeof(err), "ACL rule id is missing or invalid");
        if (http_status) *http_status = 400;
        goto fail;
    }
    existing = webd_policy_acl_existing(type, raw_id);
    if (create && existing) {
        snprintf(err, sizeof(err), "ACL rule already exists");
        if (http_status) *http_status = 409;
        goto fail;
    }
    if (!create && !existing) {
        snprintf(err, sizeof(err), "ACL rule was not found in the requested subtype");
        if (http_status) *http_status = 404;
        goto fail;
    }
    array_name = webd_policy_acl_array_name(type);
    if (delete_rule) {
        params = json_object_new_object();
        arr = json_object_new_array();
        json_object_array_add(arr, json_object_new_string(raw_id));
        json_object_object_add(params, "ids", arr);
        json_object_array_add(steps, json_object_new_string("delete one config.db network_control rule"));
        save_resp = app_ubus_or_error("network_control_bulk_delete", params);
        json_object_put(params);
        params = NULL;
    } else {
        if (webd_policy_acl_build_rule(body, type, raw_id, operation, existing,
                                       &rule, err, sizeof(err)) != 0) {
            if (http_status) *http_status = 400;
            goto fail;
        }
        params = json_object_new_object();
        arr = json_object_new_array();
        json_object_array_add(arr, json_object_get(rule));
        json_object_object_add(params, array_name, arr);
        json_object_array_add(steps, json_object_new_string("upsert one config.db network_control rule"));
        save_resp = app_ubus_or_error("network_control_save", params);
        json_object_put(params);
        params = NULL;
    }
    saved = app_ubus_response_ok(save_resp);
    if (!saved) {
        snprintf(err, sizeof(err), "network_control persistence failed");
        if (http_status) *http_status = 500;
        goto fail;
    }
    params = json_object_new_object();
    json_object_object_add(params, "apply_nft", json_object_new_boolean(1));
    json_object_object_add(params, "apply_tc", json_object_new_boolean(0));
    json_object_array_add(steps, json_object_new_string("guarded nft syntax check, apply, and health check"));
    apply_resp = app_ubus_or_error("network_control_apply", params);
    json_object_put(params);
    params = NULL;
    applied = app_ubus_response_ok(apply_resp);
    if (!applied) {
        struct json_object *restore = json_object_new_object();
        struct json_object *restore_arr = json_object_new_array();

        if (existing) {
            json_object_array_add(restore_arr, json_object_get(existing));
            json_object_object_add(restore, array_name, restore_arr);
            rollback_resp = app_ubus_or_error("network_control_save", restore);
            json_object_put(restore);
        } else {
            json_object_put(restore_arr);
            json_object_put(restore);
            restore = json_object_new_object();
            restore_arr = json_object_new_array();
            json_object_array_add(restore_arr, json_object_new_string(raw_id));
            json_object_object_add(restore, "ids", restore_arr);
            rollback_resp = app_ubus_or_error("network_control_bulk_delete", restore);
            json_object_put(restore);
        }
        rolled_back = app_ubus_response_ok(rollback_resp);
        if (rolled_back) {
            struct json_object *reload = json_object_new_object();
            struct json_object *reload_resp;

            json_object_object_add(reload, "apply_nft", json_object_new_boolean(1));
            json_object_object_add(reload, "apply_tc", json_object_new_boolean(0));
            reload_resp = app_ubus_or_error("network_control_apply", reload);
            json_object_put(reload);
            rolled_back = app_ubus_response_ok(reload_resp);
            json_object_put(reload_resp);
        }
        snprintf(err, sizeof(err), "ACL runtime apply failed%s",
                 rolled_back ? "; previous rule restored" : "; rollback failed");
        if (http_status) *http_status = 500;
        goto fail;
    }

    json_object_object_add(tx, "ok", json_object_new_boolean(1));
    json_object_object_add(tx, "operation", json_object_new_string(operation));
    json_object_object_add(tx, "policy_id", json_object_new_string(policy_id && policy_id[0] ?
        policy_id : ""));
    webd_obj_add_str(tx, "acl_type", type);
    webd_obj_add_str(tx, "rule_id", raw_id);
    json_object_object_add(tx, "applied", json_object_new_boolean(1));
    json_object_object_add(tx, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(tx, "save_response", save_resp ? save_resp : json_object_new_object());
    save_resp = NULL;
    json_object_object_add(tx, "apply_response", apply_resp ? apply_resp : json_object_new_object());
    apply_resp = NULL;
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    /*
     * A rule bound to a group with no MAC-bearing members renders zero nft
     * rules. That is a legitimate state, but it looks identical to a working
     * block from the response alone, so say it explicitly rather than letting
     * the caller assume the devices are cut off.
     */
    if (rule) {
        const char *bound_kind = app_nc_json_str(rule, "source_kind", "");
        const char *bound_ref = app_nc_json_str(rule, "source_ref", "");

        if (!strcmp(bound_kind, "group") && bound_ref[0]) {
            int members = webd_terminal_group_member_count(bound_ref);

            webd_obj_add_str(data, "source_kind", "group");
            webd_obj_add_str(data, "source_ref", bound_ref);
            json_object_object_add(data, "group_member_macs",
                                   json_object_new_int(members));
            if (members == 0)
                webd_obj_add_str(data, "warning",
                    "terminal group has no member with a MAC; this rule currently blocks nothing");
            else if (members < 0)
                webd_obj_add_str(data, "warning",
                    "terminal group member count is unavailable; rule expansion was not verified");
        }
    }
    /*
     * A lapsed rule is writable again (its expires is inherited, not revalidated),
     * but the ruleset generator still skips expires<=now, so enabling one renders
     * zero nft rules. Reported explicitly: "enable succeeded" and "the device is
     * blocked" are different claims, and the caller cannot tell them apart from
     * ok/applied alone. Re-arming needs a fresh future expires, or 0 for never.
     */
    if (rule) {
        struct json_object *ev = NULL;

        if (json_object_object_get_ex(rule, "expires", &ev) && ev &&
            json_object_is_type(ev, json_type_int)) {
            int64_t expires = (int64_t)json_object_get_int64(ev);

            json_object_object_add(data, "expires", json_object_new_int64(expires));
            if (expires > 0 && expires <= (int64_t)time(NULL)) {
                json_object_object_add(data, "expired", json_object_new_boolean(1));
                webd_obj_add_str(data, "expires_warning",
                    "rule expires in the past; it is stored but renders no ruleset entry "
                    "until expires is set to a future timestamp or 0 for never");
            } else {
                json_object_object_add(data, "expired", json_object_new_boolean(0));
            }
        }
    }
    {
        char stable_id[256];
        snprintf(stable_id, sizeof(stable_id), "network_control.%s.%s", type, raw_id);
        webd_obj_add_str(data, "id", stable_id);
    }
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    if (existing) json_object_put(existing);
    if (rule) json_object_put(rule);
    return webd_envelope(data, "webd.policy_engine.acl_apply");

fail:
    if (params) json_object_put(params);
    if (save_resp) json_object_put(save_resp);
    if (apply_resp) json_object_put(apply_resp);
    if (rollback_resp) json_object_put(rollback_resp);
    if (existing) json_object_put(existing);
    if (rule) json_object_put(rule);
    json_object_object_add(tx, "ok", json_object_new_boolean(0));
    json_object_object_add(tx, "operation", json_object_new_string(operation ? operation : ""));
    webd_obj_add_str(tx, "acl_type", type);
    webd_obj_add_str(tx, "rule_id", raw_id);
    json_object_object_add(tx, "persisted", json_object_new_boolean(saved));
    json_object_object_add(tx, "applied", json_object_new_boolean(0));
    json_object_object_add(tx, "rolled_back", json_object_new_boolean(rolled_back));
    json_object_object_add(tx, "steps", steps);
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    webd_obj_add_str(data, "error", saved ? "policy_acl_apply_failed" : "policy_acl_invalid_or_unavailable");
    webd_obj_add_str(data, "message", err[0] ? err : "ACL transaction failed");
    json_object_object_add(data, "transaction", tx);
    json_object_object_add(data, "capabilities", webd_policy_capabilities());
    return webd_envelope(data, "webd.policy_engine.acl_apply");
}
