// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmctl - DreamingWrt console/control CLI.
 *
 * This is intentionally a thin client. Normal operations go through
 * dreamingwrt-core ubus methods so CLI, webd, and future console share the
 * same config.db transaction/apply path.
 */
#include <ctype.h>
#include <errno.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include <libubus.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "ai_local_rpc_protocol.h"

#define JMCTL_VERSION "0.1.0"
#define JMCTL_DEFAULT_TIMEOUT_MS 8000
#define JMCTL_LINE_MAX 1024
#define JMCTL_ARG_MAX 64
#define JMCTL_COMPLETION_MAX 64
#define JMCTL_COMPLETION_WORD_MAX 64

struct jmctl_opts {
    int json;
    int dry_run;
    const char *backend;
    int timeout_ms;
    int timeout_set;
};

struct jmctl_ubus_result {
    int got_reply;
    int rc;
    char *json;
};

struct jmctl_completion_cache {
    int loaded;
    char ports[JMCTL_COMPLETION_MAX][JMCTL_COMPLETION_WORD_MAX];
    int port_count;
    char wans[JMCTL_COMPLETION_MAX][JMCTL_COMPLETION_WORD_MAX];
    int wan_count;
    char lans[JMCTL_COMPLETION_MAX][JMCTL_COMPLETION_WORD_MAX];
    int lan_count;
};

static struct jmctl_completion_cache g_completion_cache;

static void usage(FILE *out)
{
    fprintf(out,
        "Usage:\n"
        "  jmctl                         Start interactive console\n"
        "  jmctl [--json] [--dry-run] <command> [args...]\n"
        "\n"
        "Interactive:\n"
        "  jmctl> help                   Show context help\n"
        "  jmctl> exit                   Leave jmctl console\n"
        "  jmctl> refresh                Reload runtime completion candidates\n"
        "  jmctl> set                    Enter guided set context\n"
        "  jmctl> @llm <question>         Ask the configured AI assistant\n"
        "\n"
        "Discovery:\n"
        "  jmctl list ports\n"
        "  jmctl list wans\n"
        "  jmctl list lans\n"
        "  jmctl status\n"
        "  jmctl doctor\n"
        "  jmctl audit status\n"
        "  jmctl audit prune [--dry-run]\n"
        "  jmctl audit compact\n"
        "  jmctl storage status\n"
        "  jmctl storage prune [--dry-run]\n"
        "  jmctl storage compact\n"
        "\n"
        "Network:\n"
        "  jmctl add wan1 eth1\n"
        "  jmctl del wan1\n"
        "  jmctl set wan1 eth2\n"
        "  jmctl set wan1 dhcp\n"
        "  jmctl set wan1 pppoe <username> <password>\n"
        "  jmctl set wan1 static <ip/prefix> <gateway> [dns...]\n"
        "  jmctl add lan1 eth0\n"
        "  jmctl del lan1\n"
        "  jmctl set gateway.addr <ipv4>\n"
        "\n"
        "Users:\n"
        "  jmctl user password set <username> <new-password> [--sync-system]\n"
        "  jmctl user password reset <username> <new-password> [--sync-system]\n"
        "\n"
        "Raw ubus:\n"
        "  jmctl ubus <object> <method> [json]\n"
        "\n"
        "AI assistant:\n"
        "  jmctl @llm <question-or-task>\n"
        "    Requires AI provider config and router Internet access. Tool calls still\n"
        "    use normal jmxd authorization/audit policy.\n"
        "\n"
        "Options:\n"
        "  -h, --help          Show this help\n"
        "  --json              Emit machine-readable JSON\n"
        "  --dry-run           Build and print the request without applying it\n"
        "  --backend <name>    Backend to use; default: ubus\n"
        "  --timeout <ms>      ubus timeout; default: 8000\n"
        "  --                  Stop parsing options; useful before passwords\n");
}

static int starts_with(const char *s, const char *prefix)
{
    return s && prefix && strncmp(s, prefix, strlen(prefix)) == 0;
}

static int is_name_safe(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!s || !s[0])
        return 0;
    for (; *p; p++) {
        if (isalnum(*p) || *p == '_' || *p == '-' || *p == '.')
            continue;
        return 0;
    }
    return 1;
}

static void json_add_string(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

static const char *json_get_string_def(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !key)
        return def;
    if (json_object_object_get_ex(o, key, &v) && v)
        return json_object_get_string(v);
    return def;
}

static int json_get_bool_def(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key)
        return def;
    if (json_object_object_get_ex(o, key, &v) && v)
        return json_object_get_boolean(v);
    return def;
}

static struct json_object *jmctl_error(const char *error, const char *message)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_add_string(o, "error", error);
    json_add_string(o, "message", message);
    return o;
}

static void print_json_obj(struct json_object *o)
{
    printf("%s\n", json_object_to_json_string_ext(o, JSON_C_TO_STRING_PRETTY));
}

static int print_error(struct jmctl_opts *opts, const char *error, const char *message)
{
    struct json_object *o = jmctl_error(error, message);
    if (opts && opts->json)
        print_json_obj(o);
    else
        fprintf(stderr, "jmctl: %s: %s\n", error ? error : "error", message ? message : "");
    json_object_put(o);
    return 1;
}

static int response_success(struct json_object *resp)
{
    struct json_object *v = NULL;
    if (!resp)
        return 0;
    if (json_object_object_get_ex(resp, "ok", &v))
        return json_object_get_boolean(v);
    if (json_object_object_get_ex(resp, "code", &v))
        return json_object_get_int(v) == 2000;
    return 1;
}

static void ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct jmctl_ubus_result *r = req->priv;
    char *s;
    (void)type;
    if (!r || !msg)
        return;
    s = blobmsg_format_json(msg, true);
    if (!s)
        return;
    free(r->json);
    r->json = s;
    r->got_reply = 1;
}

static struct json_object *ubus_invoke_json(struct jmctl_opts *opts,
                                            const char *object,
                                            const char *method,
                                            struct json_object *payload,
                                            int *out_rc)
{
    struct ubus_context *ctx = NULL;
    struct blob_buf b = {};
    uint32_t id = 0;
    int rc;
    const char *s;
    struct jmctl_ubus_result result = {0, -1, NULL};
    struct json_object *resp = NULL;

    if (out_rc)
        *out_rc = -1;

    ctx = ubus_connect(NULL);
    if (!ctx)
        return jmctl_error("ubus_connect_failed", "cannot connect to ubus");

    rc = ubus_lookup_id(ctx, object, &id);
    if (rc != 0) {
        resp = jmctl_error("ubus_object_not_found", object);
        goto done;
    }

    blob_buf_init(&b, 0);
    if (payload) {
        s = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);
        if (!blobmsg_add_json_from_string(&b, s)) {
            resp = jmctl_error("payload_encode_failed", "cannot encode JSON payload for ubus");
            goto done;
        }
    }

    rc = ubus_invoke(ctx, id, method, b.head, ubus_cb, &result,
                     opts && opts->timeout_ms > 0 ? opts->timeout_ms : JMCTL_DEFAULT_TIMEOUT_MS);
    result.rc = rc;
    if (out_rc)
        *out_rc = rc;
    if (rc != 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "%s.%s rc=%d", object, method, rc);
        resp = jmctl_error("ubus_invoke_failed", msg);
        goto done;
    }
    if (!result.got_reply || !result.json) {
        resp = jmctl_error("ubus_empty_reply", method);
        goto done;
    }
    resp = json_tokener_parse(result.json);
    if (!resp)
        resp = jmctl_error("reply_parse_failed", result.json);

done:
    blob_buf_free(&b);
    free(result.json);
    if (ctx)
        ubus_free(ctx);
    return resp;
}

static struct json_object *result_wrap(struct jmctl_opts *opts, const char *command,
                                       const char *method, struct json_object *request,
                                       struct json_object *response)
{
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(response_success(response)));
    json_add_string(root, "command", command);
    json_add_string(root, "backend", opts && opts->backend ? opts->backend : "ubus");
    if (method)
        json_add_string(root, "method", method);
    if (request)
        json_object_object_add(root, "request", json_object_get(request));
    if (response)
        json_object_object_add(root, "response", json_object_get(response));
    return root;
}

static int emit_result(struct jmctl_opts *opts, const char *command, const char *method,
                       struct json_object *request, struct json_object *response)
{
    int ok = response_success(response);
    if (opts && opts->json) {
        struct json_object *root = result_wrap(opts, command, method, request, response);
        print_json_obj(root);
        json_object_put(root);
    } else if (ok) {
        printf("ok\n");
    } else {
        fprintf(stderr, "failed\n");
        if (response)
            fprintf(stderr, "%s\n", json_object_to_json_string_ext(response, JSON_C_TO_STRING_PRETTY));
    }
    return ok ? 0 : 1;
}

static struct json_object *jmx_get_data_object(struct json_object *resp)
{
    struct json_object *data = NULL;
    if (!resp)
        return NULL;
    if (json_object_object_get_ex(resp, "data", &data) && data)
        return data;
    return resp;
}

static void completion_add_word(char words[][JMCTL_COMPLETION_WORD_MAX],
                                int *count, const char *word)
{
    int i;

    if (!words || !count || !word || !word[0] || *count >= JMCTL_COMPLETION_MAX)
        return;
    if (!is_name_safe(word))
        return;
    for (i = 0; i < *count; i++) {
        if (!strcmp(words[i], word))
            return;
    }
    snprintf(words[*count], JMCTL_COMPLETION_WORD_MAX, "%s", word);
    (*count)++;
}

static void completion_extract_array(struct json_object *data, const char *array_key,
                                     const char *primary_key,
                                     char words[][JMCTL_COMPLETION_WORD_MAX],
                                     int *count)
{
    struct json_object *arr = NULL;
    int i;

    if (!data || !array_key || !primary_key || !words || !count)
        return;
    if (!json_object_object_get_ex(data, array_key, &arr) ||
        !arr || !json_object_is_type(arr, json_type_array))
        return;
    for (i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        completion_add_word(words, count, json_get_string_def(item, primary_key, ""));
    }
}

static void completion_cache_clear(void)
{
    memset(&g_completion_cache, 0, sizeof(g_completion_cache));
}

static void completion_load(struct jmctl_opts *opts)
{
    struct json_object *resp = NULL;
    struct json_object *data = NULL;

    if (g_completion_cache.loaded)
        return;
    completion_cache_clear();

    resp = ubus_invoke_json(opts, "dreamingwrt", "physical_port_list", NULL, NULL);
    data = jmx_get_data_object(resp);
    completion_extract_array(data, "ports", "name",
                             g_completion_cache.ports, &g_completion_cache.port_count);
    if (resp)
        json_object_put(resp);

    resp = ubus_invoke_json(opts, "dreamingwrt", "wan_list", NULL, NULL);
    data = jmx_get_data_object(resp);
    completion_extract_array(data, "wans", "id",
                             g_completion_cache.wans, &g_completion_cache.wan_count);
    completion_extract_array(data, "wans", "ifname",
                             g_completion_cache.wans, &g_completion_cache.wan_count);
    if (resp)
        json_object_put(resp);

    resp = ubus_invoke_json(opts, "dreamingwrt", "lan_config", NULL, NULL);
    data = jmx_get_data_object(resp);
    completion_extract_array(data, "lans", "id",
                             g_completion_cache.lans, &g_completion_cache.lan_count);
    completion_extract_array(data, "lans", "ifname",
                             g_completion_cache.lans, &g_completion_cache.lan_count);
    if (resp)
        json_object_put(resp);

    completion_add_word(g_completion_cache.ports, &g_completion_cache.port_count, "eth0");
    completion_add_word(g_completion_cache.ports, &g_completion_cache.port_count, "eth1");
    completion_add_word(g_completion_cache.wans, &g_completion_cache.wan_count, "wan");
    completion_add_word(g_completion_cache.wans, &g_completion_cache.wan_count, "wan1");
    completion_add_word(g_completion_cache.wans, &g_completion_cache.wan_count, "wan2");
    completion_add_word(g_completion_cache.lans, &g_completion_cache.lan_count, "lan");
    completion_add_word(g_completion_cache.lans, &g_completion_cache.lan_count, "lan1");
    completion_add_word(g_completion_cache.lans, &g_completion_cache.lan_count, "lan2");
    g_completion_cache.loaded = 1;
}

static void completion_refresh(struct jmctl_opts *opts)
{
    completion_cache_clear();
    completion_load(opts);
}

static struct json_object *fetch_wan_config(struct jmctl_opts *opts, const char *id)
{
    struct json_object *req = json_object_new_object();
    struct json_object *resp, *data, *wan = NULL;
    json_add_string(req, "id", id);
    resp = ubus_invoke_json(opts, "dreamingwrt", "wan_config_get", req, NULL);
    json_object_put(req);
    data = jmx_get_data_object(resp);
    if (data)
        json_object_object_get_ex(data, "wan", &wan);
    if (wan)
        json_object_get(wan);
    if (resp)
        json_object_put(resp);
    return wan;
}

static struct json_object *fetch_lan_config(struct jmctl_opts *opts, const char *id)
{
    struct json_object *req = json_object_new_object();
    struct json_object *resp, *data, *lan = NULL;
    json_add_string(req, "id", id);
    resp = ubus_invoke_json(opts, "dreamingwrt", "lan_get", req, NULL);
    json_object_put(req);
    data = jmx_get_data_object(resp);
    if (data)
        json_object_object_get_ex(data, "lan", &lan);
    if (lan)
        json_object_get(lan);
    if (resp)
        json_object_put(resp);
    return lan;
}

static struct json_object *default_wan_config(const char *id, const char *device)
{
    struct json_object *o = json_object_new_object();
    json_add_string(o, "id", id);
    json_add_string(o, "name", id);
    json_add_string(o, "ifname", id);
    json_add_string(o, "device", device);
    json_add_string(o, "access_mode", "dhcp");
    json_object_object_add(o, "enabled", json_object_new_boolean(1));
    json_object_object_add(o, "metric", json_object_new_int(10));
    return o;
}

static struct json_object *default_lan_config(const char *id, const char *port)
{
    char br[64];
    struct json_object *o = json_object_new_object();
    struct json_object *ports = json_object_new_array();
    snprintf(br, sizeof(br), "br-%s", id);
    json_add_string(o, "id", id);
    json_add_string(o, "name", id);
    json_add_string(o, "ifname", id);
    json_add_string(o, "device", br);
    json_add_string(o, "mode", "bridge");
    json_object_object_add(o, "enabled", json_object_new_boolean(1));
    if (port && port[0])
        json_object_array_add(ports, json_object_new_string(port));
    json_object_object_add(o, "ports", ports);
    return o;
}

static void set_wan_proto_dhcp(struct json_object *wan)
{
    json_add_string(wan, "access_mode", "dhcp");
    json_object_object_del(wan, "addresses");
    json_object_object_del(wan, "gateway");
    json_object_object_del(wan, "username");
    json_object_object_del(wan, "password");
    json_object_object_del(wan, "password_ref");
}

static void set_wan_proto_pppoe(struct json_object *wan, const char *username, const char *password)
{
    json_add_string(wan, "access_mode", "pppoe");
    json_add_string(wan, "username", username);
    json_add_string(wan, "password", password);
    json_add_string(wan, "password_ref", password);
    json_object_object_del(wan, "addresses");
    json_object_object_del(wan, "gateway");
}

static int parse_cidr(const char *cidr, char *ip, size_t ip_len, int *prefix)
{
    char buf[96];
    char *slash;
    struct in_addr tmp;
    if (!cidr || !cidr[0] || !ip || !prefix)
        return -1;
    snprintf(buf, sizeof(buf), "%s", cidr);
    slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        *prefix = atoi(slash + 1);
    } else {
        *prefix = 24;
    }
    if (*prefix < 1 || *prefix > 32 || !buf[0])
        return -1;
    if (inet_pton(AF_INET, buf, &tmp) != 1)
        return -1;
    snprintf(ip, ip_len, "%s", buf);
    return 0;
}

static int valid_ipv4(const char *ip)
{
    struct in_addr tmp;

    return ip && inet_pton(AF_INET, ip, &tmp) == 1;
}

static int set_wan_proto_static(struct json_object *wan, const char *cidr,
                                const char *gateway, int dns_argc, char **dns_argv)
{
    char ip[64];
    int prefix = 24;
    int i;
    struct json_object *addresses = json_object_new_array();
    struct json_object *addr = json_object_new_object();
    if (parse_cidr(cidr, ip, sizeof(ip), &prefix) != 0) {
        json_object_put(addresses);
        json_object_put(addr);
        return -1;
    }
    if (!valid_ipv4(gateway)) {
        json_object_put(addresses);
        json_object_put(addr);
        return -1;
    }
    json_add_string(wan, "access_mode", "static");
    json_add_string(wan, "gateway", gateway);
    json_add_string(addr, "ip", ip);
    json_object_object_add(addr, "prefix", json_object_new_int(prefix));
    json_object_object_add(addr, "primary", json_object_new_boolean(1));
    json_object_object_add(addr, "is_primary", json_object_new_boolean(1));
    json_object_array_add(addresses, addr);
    json_object_object_add(wan, "addresses", addresses);
    if (dns_argc > 0) {
        struct json_object *dns = json_object_new_array();
        for (i = 0; i < dns_argc; i++)
            json_object_array_add(dns, json_object_new_string(dns_argv[i]));
        json_object_object_add(wan, "dns_json", dns);
    }
    json_object_object_del(wan, "username");
    json_object_object_del(wan, "password");
    json_object_object_del(wan, "password_ref");
    return 0;
}

static int invoke_or_dry_run(struct jmctl_opts *opts, const char *cmd, const char *method,
                             struct json_object *req)
{
    struct json_object *resp;
    int rc;
    if (opts->dry_run) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
        json_add_string(resp, "would_call", method);
        rc = emit_result(opts, cmd, method, req, resp);
        json_object_put(resp);
        if (req)
            json_object_put(req);
        return rc;
    }
    resp = ubus_invoke_json(opts, "dreamingwrt", method, req, NULL);
    rc = emit_result(opts, cmd, method, req, resp);
    if (resp)
        json_object_put(resp);
    if (req)
        json_object_put(req);
    return rc;
}

static int cmd_list(struct jmctl_opts *opts, int argc, char **argv)
{
    const char *method;
    struct json_object *resp;
    int rc;
    if (argc < 1)
        return print_error(opts, "usage", "jmctl list ports|wans|lans");
    if (!strcmp(argv[0], "ports"))
        method = "physical_port_list";
    else if (!strcmp(argv[0], "wans"))
        method = "wan_list";
    else if (!strcmp(argv[0], "lans"))
        method = "lan_config";
    else
        return print_error(opts, "usage", "jmctl list ports|wans|lans");
    resp = ubus_invoke_json(opts, "dreamingwrt", method, NULL, NULL);
    if (opts->json)
        rc = emit_result(opts, "list", method, NULL, resp);
    else {
        print_json_obj(resp);
        rc = response_success(resp) ? 0 : 1;
    }
    if (resp)
        json_object_put(resp);
    return rc;
}

static int cmd_status(struct jmctl_opts *opts)
{
    struct json_object *resp = ubus_invoke_json(opts, "dreamingwrt", "summary", NULL, NULL);
    int rc;
    if (opts->json)
        rc = emit_result(opts, "status", "summary", NULL, resp);
    else {
        print_json_obj(resp);
        rc = response_success(resp) ? 0 : 1;
    }
    if (resp)
        json_object_put(resp);
    return rc;
}

static int cmd_doctor(struct jmctl_opts *opts)
{
    struct json_object *root = json_object_new_object();
    struct json_object *checks = json_object_new_array();
    struct json_object *resp;
    int ok = 1;

    resp = ubus_invoke_json(opts, "dreamingwrt", "summary", NULL, NULL);
    {
        struct json_object *c = json_object_new_object();
        json_add_string(c, "name", "dreamingwrt.summary");
        json_object_object_add(c, "ok", json_object_new_boolean(response_success(resp)));
        json_object_array_add(checks, c);
        if (!response_success(resp))
            ok = 0;
    }
    if (resp)
        json_object_put(resp);

    resp = ubus_invoke_json(opts, "dreamingwrt", "physical_port_list", NULL, NULL);
    {
        struct json_object *c = json_object_new_object();
        json_add_string(c, "name", "dreamingwrt.physical_port_list");
        json_object_object_add(c, "ok", json_object_new_boolean(response_success(resp)));
        json_object_array_add(checks, c);
        if (!response_success(resp))
            ok = 0;
    }
    if (resp)
        json_object_put(resp);

    json_object_object_add(root, "ok", json_object_new_boolean(ok));
    json_add_string(root, "version", JMCTL_VERSION);
    json_add_string(root, "backend", opts->backend);
    json_object_object_add(root, "checks", checks);
    print_json_obj(root);
    json_object_put(root);
    return ok ? 0 : 1;
}

static int cmd_audit(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *req = NULL;
    const char *action;
    int dry_run = opts->dry_run;
    int compact = 0;
    int checkpoint = 1;
    int i;

    if (argc < 1)
        return print_error(opts, "usage", "jmctl audit status|prune|compact");
    action = argv[0];

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dry-run"))
            dry_run = 1;
        else if (!strcmp(argv[i], "--compact") || !strcmp(argv[i], "--vacuum"))
            compact = 1;
        else if (!strcmp(argv[i], "--no-checkpoint"))
            checkpoint = 0;
        else
            return print_error(opts, "usage", "jmctl audit prune [--dry-run] [--compact|--vacuum] [--no-checkpoint]");
    }

    if (!strcmp(action, "status")) {
        struct json_object *resp = ubus_invoke_json(opts, "dreamingwrt", "audit_status", NULL, NULL);
        int rc;
        if (opts->json)
            rc = emit_result(opts, "audit status", "audit_status", NULL, resp);
        else {
            print_json_obj(resp);
            rc = response_success(resp) ? 0 : 1;
        }
        if (resp)
            json_object_put(resp);
        return rc;
    }

    if (!strcmp(action, "compact"))
        compact = 1;
    else if (strcmp(action, "prune"))
        return print_error(opts, "usage", "jmctl audit status|prune|compact");

    req = json_object_new_object();
    json_object_object_add(req, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(req, "checkpoint", json_object_new_boolean(checkpoint));
    json_object_object_add(req, "vacuum", json_object_new_boolean(compact));
    json_object_object_add(req, "compact", json_object_new_boolean(compact));

    /*
     * audit_prune has a real backend dry-run estimator. Call it even when
     * global --dry-run is set, otherwise operators cannot see would_delete_*.
     */
    {
        struct json_object *resp = ubus_invoke_json(opts, "dreamingwrt", "audit_prune", req, NULL);
        int rc = emit_result(opts, compact ? "audit compact" : "audit prune",
                             "audit_prune", req, resp);
        if (resp)
            json_object_put(resp);
        if (req)
            json_object_put(req);
        return rc;
    }
}

static int cmd_storage(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *req = NULL;
    const char *action;
    int dry_run = opts->dry_run;
    int compact = 0;
    int i;

    if (argc < 1)
        return print_error(opts, "usage", "jmctl storage status|prune|compact");
    action = argv[0];

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dry-run"))
            dry_run = 1;
        else if (!strcmp(argv[i], "--compact") || !strcmp(argv[i], "--vacuum"))
            compact = 1;
        else if (!strcmp(argv[i], "--no-checkpoint")) {
            /* handled below via request field */
        } else {
            return print_error(opts, "usage", "jmctl storage prune [--dry-run] [--compact|--vacuum] [--no-checkpoint]");
        }
    }

    if (!strcmp(action, "status")) {
        struct json_object *resp = ubus_invoke_json(opts, "dreamingwrt", "storage_status", NULL, NULL);
        int rc;
        if (opts->json)
            rc = emit_result(opts, "storage status", "storage_status", NULL, resp);
        else {
            print_json_obj(resp);
            rc = response_success(resp) ? 0 : 1;
        }
        if (resp)
            json_object_put(resp);
        return rc;
    }

    if (!strcmp(action, "compact"))
        compact = 1;
    else if (strcmp(action, "prune"))
        return print_error(opts, "usage", "jmctl storage status|prune|compact");

    req = json_object_new_object();
    json_object_object_add(req, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(req, "checkpoint", json_object_new_boolean(1));
    json_object_object_add(req, "vacuum", json_object_new_boolean(compact));
    json_object_object_add(req, "compact", json_object_new_boolean(compact));
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--no-checkpoint")) {
            json_object_object_del(req, "checkpoint");
            json_object_object_add(req, "checkpoint", json_object_new_boolean(0));
        }
    }
    return invoke_or_dry_run(opts, compact ? "storage compact" : "storage prune",
                             "storage_prune", req);
}

static int cmd_add(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *req;
    const char *id, *dev;
    if (argc < 2)
        return print_error(opts, "usage", "jmctl add wan1 eth1 | jmctl add lan1 eth0");
    id = argv[0];
    dev = argv[1];
    if (!is_name_safe(id) || !is_name_safe(dev))
        return print_error(opts, "invalid_name", "id/device contains unsupported characters");
    if (starts_with(id, "wan")) {
        req = default_wan_config(id, dev);
        return invoke_or_dry_run(opts, "add", "wan_set", req);
    }
    if (starts_with(id, "lan")) {
        req = default_lan_config(id, dev);
        return invoke_or_dry_run(opts, "add", "lan_set", req);
    }
    return print_error(opts, "usage", "interface id must start with wan or lan");
}

static int cmd_del(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *req;
    const char *id;
    const char *method;
    if (argc < 1)
        return print_error(opts, "usage", "jmctl del wan1 | jmctl del lan1");
    id = argv[0];
    if (!is_name_safe(id))
        return print_error(opts, "invalid_name", "id contains unsupported characters");
    if (starts_with(id, "wan"))
        method = "wan_delete";
    else if (starts_with(id, "lan"))
        method = "lan_delete";
    else
        return print_error(opts, "usage", "interface id must start with wan or lan");
    req = json_object_new_object();
    json_add_string(req, "id", id);
    return invoke_or_dry_run(opts, "del", method, req);
}

static int cmd_set_gateway_addr(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *lan, *addresses, *addr;
    char ip[64];
    int prefix = 24;
    if (argc < 1)
        return print_error(opts, "usage", "jmctl set gateway.addr <ipv4>");
    lan = fetch_lan_config(opts, "lan");
    if (!lan)
        lan = default_lan_config("lan", "");
    if (parse_cidr(argv[0], ip, sizeof(ip), &prefix) != 0) {
        json_object_put(lan);
        return print_error(opts, "invalid_gateway_address", "expected IPv4 or IPv4/prefix, for example 192.168.1.1/24");
    }
    addresses = json_object_new_array();
    addr = json_object_new_object();
    json_add_string(addr, "ip", ip);
    json_object_object_add(addr, "prefix", json_object_new_int(prefix));
    json_object_object_add(addr, "primary", json_object_new_boolean(1));
    json_object_object_add(addr, "is_primary", json_object_new_boolean(1));
    json_object_array_add(addresses, addr);
    json_object_object_add(lan, "addresses", addresses);
    json_add_string(lan, "ipaddr", ip);
    json_object_object_add(lan, "prefix", json_object_new_int(prefix));
    return invoke_or_dry_run(opts, "set", "lan_set", lan);
}

static int cmd_set_wan(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *wan;
    const char *id;
    int protocol_change = 0;
    if (argc < 2)
        return print_error(opts, "usage", "jmctl set wan1 eth2|dhcp|pppoe|static ...");
    id = argv[0];
    if (!is_name_safe(id) || !starts_with(id, "wan"))
        return print_error(opts, "invalid_name", "WAN id must start with wan");
    wan = fetch_wan_config(opts, id);
    protocol_change = !strcmp(argv[1], "dhcp") || !strcmp(argv[1], "pppoe") || !strcmp(argv[1], "static");
    if (!wan && protocol_change)
        return print_error(opts, "wan_not_found", "bind a physical device first, for example: jmctl add wan1 eth1");
    if (!wan)
        wan = default_wan_config(id, "");

    if (!strcmp(argv[1], "dhcp")) {
        set_wan_proto_dhcp(wan);
    } else if (!strcmp(argv[1], "pppoe")) {
        if (argc < 4) {
            json_object_put(wan);
            return print_error(opts, "usage", "jmctl set wan1 pppoe <username> <password>");
        }
        set_wan_proto_pppoe(wan, argv[2], argv[3]);
    } else if (!strcmp(argv[1], "static")) {
        if (argc < 4) {
            json_object_put(wan);
            return print_error(opts, "usage", "jmctl set wan1 static <ip/prefix> <gateway> [dns...]");
        }
        if (set_wan_proto_static(wan, argv[2], argv[3], argc - 4, argv + 4) != 0) {
            json_object_put(wan);
            return print_error(opts, "invalid_static_address", "expected <ip/prefix> and IPv4 gateway, for example 10.0.0.2/24 10.0.0.1");
        }
    } else {
        if (!is_name_safe(argv[1])) {
            json_object_put(wan);
            return print_error(opts, "invalid_device", "device contains unsupported characters");
        }
        json_add_string(wan, "device", argv[1]);
        if (!json_object_object_get(wan, "access_mode"))
            json_add_string(wan, "access_mode", "dhcp");
    }
    if (!json_get_string_def(wan, "device", "")[0]) {
        json_object_put(wan);
        return print_error(opts, "missing_device", "WAN has no physical device; run jmctl set wan1 ethX first");
    }
    return invoke_or_dry_run(opts, "set", "wan_set", wan);
}

static int cmd_set(struct jmctl_opts *opts, int argc, char **argv)
{
    if (argc < 1)
        return print_error(opts, "usage", "jmctl set gateway.addr <ip> | jmctl set wan1 ...");
    if (!strcmp(argv[0], "gateway.addr"))
        return cmd_set_gateway_addr(opts, argc - 1, argv + 1);
    if (starts_with(argv[0], "wan"))
        return cmd_set_wan(opts, argc, argv);
    return print_error(opts, "usage", "supported set targets: gateway.addr, wan*");
}

static int cmd_user(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *req;
    int sync_system = 0;
    if (argc < 4 || strcmp(argv[0], "password") ||
        (strcmp(argv[1], "set") && strcmp(argv[1], "reset"))) {
        return print_error(opts, "usage", "jmctl user password set|reset <username> <new-password> [--sync-system]");
    }
    if (argc >= 5) {
        if (!strcmp(argv[4], "--sync-system"))
            sync_system = 1;
        else
            return print_error(opts, "usage", "only optional flag is --sync-system");
    }
    if (!is_name_safe(argv[2]))
        return print_error(opts, "invalid_username", "username contains unsupported characters");
    req = json_object_new_object();
    json_add_string(req, "username", argv[2]);
    json_add_string(req, "new_password", argv[3]);
    json_add_string(req, "confirm_password", argv[3]);
    json_object_object_add(req, "sync_system_password", json_object_new_boolean(sync_system));
    return invoke_or_dry_run(opts, "user password", "system_admin_password_set", req);
}

static int cmd_raw_ubus(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *payload = NULL;
    struct json_object *resp;
    int rc;
    if (argc < 2)
        return print_error(opts, "usage", "jmctl ubus <object> <method> [json]");
    if (argc >= 3) {
        payload = json_tokener_parse(argv[2]);
        if (!payload)
            return print_error(opts, "invalid_json", "raw ubus payload is not valid JSON");
    }
    resp = ubus_invoke_json(opts, argv[0], argv[1], payload, NULL);
    if (opts->json)
        rc = emit_result(opts, "ubus", argv[1], payload, resp);
    else {
        print_json_obj(resp);
        rc = response_success(resp) ? 0 : 1;
    }
    if (payload)
        json_object_put(payload);
    if (resp)
        json_object_put(resp);
    return rc;
}

static char *join_args(int argc, char **argv)
{
    size_t len = 1;
    char *out;
    int i;

    for (i = 0; i < argc; i++)
        len += strlen(argv[i]) + 1;
    out = calloc(1, len);
    if (!out)
        return NULL;
    for (i = 0; i < argc; i++) {
        if (i)
            strncat(out, " ", len - strlen(out) - 1);
        strncat(out, argv[i], len - strlen(out) - 1);
    }
    return out;
}

static int router_has_internet(struct jmctl_opts *opts, char *reason, size_t reason_len)
{
    struct json_object *resp = NULL, *data = NULL, *wans = NULL;
    int online = 0;

    if (reason && reason_len)
        snprintf(reason, reason_len, "%s", "unknown");
    resp = ubus_invoke_json(opts, "dreamingwrt", "summary", NULL, NULL);
    if (!response_success(resp)) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s", "summary_unavailable");
        if (resp)
            json_object_put(resp);
        return 0;
    }
    data = jmx_get_data_object(resp);
    if (data && json_object_object_get_ex(data, "wans", &wans) &&
        wans && json_object_is_type(wans, json_type_array)) {
        int i, n = json_object_array_length(wans);
        for (i = 0; i < n; i++) {
            struct json_object *w = json_object_array_get_idx(wans, i);
            const char *status = json_get_string_def(w, "status", "");
            if (json_get_bool_def(w, "online", 0) ||
                !strcmp(status, "ok") || !strcmp(status, "online")) {
                online = 1;
                break;
            }
        }
    }
    if (!online && reason && reason_len)
        snprintf(reason, reason_len, "%s", "no_online_wan");
    if (resp)
        json_object_put(resp);
    return online;
}

static int local_rpc_write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *input = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t sent = send(fd, input + offset, length - offset, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (sent == 0)
            return -1;
        offset += (size_t)sent;
    }
    return 0;
}

static int local_rpc_read_all(int fd, void *buffer, size_t length)
{
    unsigned char *output = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t got = recv(fd, output + offset, length - offset, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1;
        offset += (size_t)got;
    }
    return 0;
}

static struct json_object *jmctl_ai_local_invoke(struct jmctl_opts *opts,
                                                  struct json_object *request)
{
    struct sockaddr_un address;
    struct timeval timeout;
    const char *payload;
    char *response_text = NULL;
    struct json_object *response = NULL;
    uint32_t frame_length;
    size_t payload_length, response_length;
    int timeout_ms = opts && opts->timeout_set ? opts->timeout_ms :
                     DREAMINGWRT_AI_LOCAL_DEFAULT_TIMEOUT_MS;
    int fd = -1;

    payload = request ? json_object_to_json_string_ext(
        request, JSON_C_TO_STRING_PLAIN) : NULL;
    payload_length = payload ? strlen(payload) : 0;
    if (!payload || payload_length == 0 ||
        payload_length > DREAMINGWRT_AI_LOCAL_REQUEST_MAX)
        return jmctl_error("llm_request_too_large", "local AI request exceeds the size limit");
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return jmctl_error("llm_runtime_unavailable", "cannot create local AI socket");
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s",
             DREAMINGWRT_AI_LOCAL_SOCKET);
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        response = jmctl_error("llm_runtime_unavailable",
                               "dreamingwrt-webd local AI runtime is unavailable");
        goto done;
    }
    frame_length = htonl((uint32_t)payload_length);
    if (local_rpc_write_all(fd, &frame_length, sizeof(frame_length)) != 0 ||
        local_rpc_write_all(fd, payload, payload_length) != 0 ||
        local_rpc_read_all(fd, &frame_length, sizeof(frame_length)) != 0) {
        response = jmctl_error(errno == EAGAIN || errno == EWOULDBLOCK ?
                               "llm_runtime_timeout" : "llm_runtime_io_failed",
                               "local AI runtime did not return a complete response");
        goto done;
    }
    response_length = (size_t)ntohl(frame_length);
    if (response_length == 0 ||
        response_length > DREAMINGWRT_AI_LOCAL_RESPONSE_MAX) {
        response = jmctl_error("llm_response_too_large",
                               "local AI response exceeds the size limit");
        goto done;
    }
    response_text = calloc(1, response_length + 1);
    if (!response_text ||
        local_rpc_read_all(fd, response_text, response_length) != 0) {
        response = jmctl_error("llm_runtime_io_failed",
                               "local AI response body is incomplete");
        goto done;
    }
    response = json_tokener_parse(response_text);
    if (!response)
        response = jmctl_error("llm_response_invalid",
                               "local AI runtime returned invalid JSON");

done:
    if (fd >= 0)
        close(fd);
    free(response_text);
    return response;
}

static int cmd_llm(struct jmctl_opts *opts, int argc, char **argv)
{
    struct json_object *cfg = NULL, *cfg_data = NULL;
    struct json_object *req = NULL, *messages = NULL, *msg = NULL, *resp = NULL, *data = NULL;
    const char *text;
    char reason[96];
    char *prompt;
    int rc;

    if (argc < 1)
        return print_error(opts, "usage", "jmctl @llm <question-or-task>");

    prompt = join_args(argc, argv);
    if (!prompt || !prompt[0]) {
        free(prompt);
        return print_error(opts, "usage", "jmctl @llm <question-or-task>");
    }

    cfg = ubus_invoke_json(opts, "dreamingwrt", "ai_config_get", NULL, NULL);
    if (!response_success(cfg)) {
        free(prompt);
        if (cfg)
            json_object_put(cfg);
        return print_error(opts, "llm_config_unavailable", "cannot read AI provider configuration");
    }
    cfg_data = jmx_get_data_object(cfg);
    const char *auth_mode = json_get_string_def(cfg_data, "auth_mode", "api_key");
    if (!json_get_bool_def(cfg_data, "enabled", 0) ||
        (!strcmp(auth_mode, "api_key") &&
         !json_get_bool_def(cfg_data, "api_key_set", 0)) ||
        (strcmp(auth_mode, "api_key") && strcmp(auth_mode, "oauth"))) {
        free(prompt);
        if (cfg)
            json_object_put(cfg);
        return print_error(opts, "llm_not_configured",
                           "AI provider authentication is not configured");
    }
    if (!router_has_internet(opts, reason, sizeof(reason))) {
        free(prompt);
        if (cfg)
            json_object_put(cfg);
        return print_error(opts, "router_offline", reason);
    }

    req = json_object_new_object();
    json_add_string(req, "source", "jmctl");
    json_add_string(req, "message", prompt);
    messages = json_object_new_array();
    msg = json_object_new_object();
    json_add_string(msg, "role", "user");
    json_add_string(msg, "content", prompt);
    json_object_array_add(messages, msg);
    json_object_object_add(req, "messages", messages);

    resp = jmctl_ai_local_invoke(opts, req);
    if (opts->json) {
        rc = emit_result(opts, "@llm", "webd.ai.local", req, resp);
    } else if (response_success(resp)) {
        data = jmx_get_data_object(resp);
        text = json_get_string_def(data, "reply",
               json_get_string_def(data, "content",
               json_get_string_def(data, "message", "")));
        if (text && text[0])
            printf("%s\n", text);
        else
            print_json_obj(resp);
        rc = 0;
    } else {
        rc = emit_result(opts, "@llm", "webd.ai.local", req, resp);
    }

    free(prompt);
    if (cfg)
        json_object_put(cfg);
    if (req)
        json_object_put(req);
    if (resp)
        json_object_put(resp);
    return rc;
}

static int split_args(char *line, int *argc, char **argv, int max_args)
{
    char *src = line;
    int n = 0;

    while (*src) {
        char quote = 0;
        int closed_quote = 0;
        char *dst;

        while (*src && isspace((unsigned char)*src))
            src++;
        if (!*src)
            break;
        if (n >= max_args)
            return -1;
        if (*src == '\'' || *src == '"')
            quote = *src++;
        argv[n++] = src;
        dst = src;
        while (*src) {
            if (quote) {
                if (*src == quote) {
                    src++;
                    closed_quote = 1;
                    break;
                }
            } else if (isspace((unsigned char)*src)) {
                break;
            }
            if (*src == '\\' && src[1])
                src++;
            *dst++ = *src++;
        }
        if (!quote && *src && isspace((unsigned char)*src))
            src++;
        *dst = '\0';
        if (quote && !closed_quote)
            return -2;
        while (*src && isspace((unsigned char)*src))
            src++;
    }
    argv[n] = NULL;
    *argc = n;
    return 0;
}

static int dispatch_argv(struct jmctl_opts *opts, int argc, char **argv)
{
    if (argc < 1)
        return 0;
    if (!strcmp(argv[0], "help") || !strcmp(argv[0], "-h") || !strcmp(argv[0], "--help")) {
        usage(stdout);
        return 0;
    }
    if (strcmp(opts->backend, "ubus") != 0)
        return print_error(opts, "unsupported_backend", "only --backend ubus is implemented in phase 1");
    if (!strcmp(argv[0], "list"))
        return cmd_list(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "status"))
        return cmd_status(opts);
    if (!strcmp(argv[0], "doctor"))
        return cmd_doctor(opts);
    if (!strcmp(argv[0], "audit"))
        return cmd_audit(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "storage"))
        return cmd_storage(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "add"))
        return cmd_add(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "del") || !strcmp(argv[0], "delete"))
        return cmd_del(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "set"))
        return cmd_set(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "user"))
        return cmd_user(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "ubus"))
        return cmd_raw_ubus(opts, argc - 1, argv + 1);
    if (!strcmp(argv[0], "@llm"))
        return cmd_llm(opts, argc - 1, argv + 1);
    usage(stderr);
    return 1;
}

static int dispatch_line(struct jmctl_opts *opts, const char *line)
{
    char *buf;
    char *argv[JMCTL_ARG_MAX + 1];
    int argc = 0;
    int rc;

    if (!line)
        return 0;
    buf = strdup(line);
    if (!buf)
        return print_error(opts, "oom", "cannot allocate command buffer");
    rc = split_args(buf, &argc, argv, JMCTL_ARG_MAX);
    if (rc == -2) {
        free(buf);
        return print_error(opts, "usage", "unterminated quote");
    }
    if (rc != 0) {
        free(buf);
        return print_error(opts, "usage", "too many arguments");
    }
    rc = dispatch_argv(opts, argc, argv);
    free(buf);
    return rc;
}

enum console_ctx_type {
    CTX_NONE = 0,
    CTX_AUDIT,
    CTX_LIST,
    CTX_SET,
    CTX_SET_WAN,
    CTX_SET_WAN_ID,
    CTX_SET_GATEWAY,
    CTX_ADD,
    CTX_ADD_WAN,
    CTX_ADD_LAN,
    CTX_DEL,
    CTX_USER,
    CTX_USER_PASSWORD
};

struct console_ctx {
    enum console_ctx_type type;
    char arg[64];
};

static void console_reset(struct console_ctx *ctx)
{
    ctx->type = CTX_NONE;
    ctx->arg[0] = '\0';
}

static const char *console_prompt(struct console_ctx *ctx)
{
    switch (ctx->type) {
    case CTX_AUDIT: return "jmctl audit> ";
    case CTX_LIST: return "jmctl list> ";
    case CTX_SET: return "jmctl set> ";
    case CTX_SET_WAN: return "jmctl set wan> ";
    case CTX_SET_WAN_ID: return "jmctl set wan-id> ";
    case CTX_SET_GATEWAY: return "jmctl set gateway.addr> ";
    case CTX_ADD: return "jmctl add> ";
    case CTX_ADD_WAN: return "jmctl add wan> ";
    case CTX_ADD_LAN: return "jmctl add lan> ";
    case CTX_DEL: return "jmctl del> ";
    case CTX_USER: return "jmctl user> ";
    case CTX_USER_PASSWORD: return "jmctl user password> ";
    case CTX_NONE:
    default:
        return "jmctl> ";
    }
}

static void console_help(struct console_ctx *ctx)
{
    switch (ctx->type) {
    case CTX_AUDIT:
        printf("audit usage:\n");
        printf("  status\n");
        printf("  prune [--dry-run] [--no-checkpoint]\n");
        printf("  compact              Prune, WAL checkpoint, then VACUUM audit.db\n");
        break;
    case CTX_LIST:
        printf("list usage: ports | wans | lans\n");
        break;
    case CTX_SET:
        printf("set targets:\n");
        printf("  wan                 Configure a WAN step by step\n");
        printf("  wan1 <...>          Configure a concrete WAN, for example: wan1 dhcp\n");
        printf("  gateway.addr <ip>   Set gateway LAN address\n");
        break;
    case CTX_SET_WAN:
        printf("set wan usage:\n");
        printf("  wan | wan1          Select WAN id, then choose dhcp/pppoe/static/device\n");
        printf("  wan dhcp\n");
        printf("  wan1 dhcp\n");
        printf("  wan1 pppoe <username> <password>\n");
        printf("  wan1 static <ip/prefix> <gateway> [dns...]\n");
        printf("  wan1 eth2           Bind device\n");
        break;
    case CTX_SET_WAN_ID:
        printf("set %s usage:\n", ctx->arg[0] ? ctx->arg : "wanX");
        printf("  dhcp\n");
        printf("  pppoe <username> <password>\n");
        printf("  static <ip/prefix> <gateway> [dns...]\n");
        printf("  eth0 | eth1 | eth2  Bind physical device\n");
        break;
    case CTX_SET_GATEWAY:
        printf("set gateway.addr usage: <ipv4> or <ipv4/prefix>, for example 192.168.1.1/24\n");
        break;
    case CTX_ADD:
        printf("add usage:\n");
        printf("  wan                 Enter WAN add context\n");
        printf("  lan                 Enter LAN add context\n");
        printf("  wan1 eth1           Add WAN directly\n");
        printf("  lan1 eth0           Add LAN directly\n");
        break;
    case CTX_ADD_WAN:
        printf("add wan usage: wan1 eth1\n");
        break;
    case CTX_ADD_LAN:
        printf("add lan usage: lan1 eth0\n");
        break;
    case CTX_DEL:
        printf("del usage: wan1 | lan1\n");
        break;
    case CTX_USER:
        printf("user usage: password\n");
        break;
    case CTX_USER_PASSWORD:
        printf("user password usage: set|reset <username> <new-password> [--sync-system]\n");
        break;
    case CTX_NONE:
    default:
        printf("DreamingWrt jmctl commands:\n");
        printf("  list        ports/wans/lans\n");
        printf("  status      show runtime summary\n");
        printf("  doctor      run basic checks\n");
        printf("  audit       show/prune/compact audit database\n");
        printf("  storage     show/prune database and WAL storage\n");
        printf("  add         add WAN/LAN\n");
        printf("  del         delete WAN/LAN\n");
        printf("  set         update WAN/gateway settings\n");
        printf("  user        web admin password operations\n");
        printf("  ubus        raw ubus escape hatch\n");
        printf("  @llm        ask configured AI assistant\n");
        printf("  refresh     reload WAN/LAN/port completion candidates\n");
        printf("  help        show help for current context\n");
        printf("  back        leave current context\n");
        printf("  exit        leave jmctl console\n");
        break;
    }
}

static int line_is(const char *line, const char *word)
{
    return line && word && !strcmp(line, word);
}

static int first_arg_is(const char *line, const char *word)
{
    size_t n;
    if (!line || !word)
        return 0;
    n = strlen(word);
    return !strncmp(line, word, n) && (!line[n] || isspace((unsigned char)line[n]));
}

static int console_exec_prefixed(struct jmctl_opts *opts, const char *prefix, const char *line)
{
    char buf[JMCTL_LINE_MAX * 2];
    snprintf(buf, sizeof(buf), "%s%s%s", prefix, line && line[0] ? " " : "", line ? line : "");
    return dispatch_line(opts, buf);
}

static int console_handle_line(struct jmctl_opts *opts, struct console_ctx *ctx, char *line)
{
    char *p = line;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!*p)
        return 0;
    if (line_is(p, "exit") || line_is(p, "quit"))
        return -1;
    if (line_is(p, "back") || line_is(p, "cancel")) {
        console_reset(ctx);
        printf("Back to jmctl root. Type exit to leave.\n");
        return 0;
    }
    if (line_is(p, "help") || line_is(p, "-h") || line_is(p, "--help")) {
        console_help(ctx);
        return 0;
    }
    if (line_is(p, "refresh") || line_is(p, "reload")) {
        completion_refresh(opts);
        printf("Completion candidates refreshed: ports=%d wans=%d lans=%d\n",
               g_completion_cache.port_count,
               g_completion_cache.wan_count,
               g_completion_cache.lan_count);
        return 0;
    }
    if (first_arg_is(p, "@llm")) {
        int rc = dispatch_line(opts, p);
        console_reset(ctx);
        return rc;
    }

    switch (ctx->type) {
    case CTX_NONE:
        if (line_is(p, "audit")) {
            ctx->type = CTX_AUDIT;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "list")) {
            ctx->type = CTX_LIST;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "set")) {
            ctx->type = CTX_SET;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "set wan")) {
            ctx->type = CTX_SET_WAN;
            console_help(ctx);
            return 0;
        }
        if (starts_with(p, "set wan") && !strchr(p + 4, ' ')) {
            ctx->type = CTX_SET_WAN_ID;
            snprintf(ctx->arg, sizeof(ctx->arg), "%s", p + 4);
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "set gateway.addr")) {
            ctx->type = CTX_SET_GATEWAY;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "add")) {
            ctx->type = CTX_ADD;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "del") || line_is(p, "delete")) {
            ctx->type = CTX_DEL;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "user")) {
            ctx->type = CTX_USER;
            console_help(ctx);
            return 0;
        }
        return dispatch_line(opts, p);

    case CTX_AUDIT:
        if (!strcmp(p, "status") || starts_with(p, "prune") || starts_with(p, "compact")) {
            int rc = console_exec_prefixed(opts, "audit", p);
            console_reset(ctx);
            return rc;
        }
        console_help(ctx);
        return 0;

    case CTX_LIST:
        if (!strcmp(p, "ports") || !strcmp(p, "wans") || !strcmp(p, "lans")) {
            int rc = console_exec_prefixed(opts, "list", p);
            console_reset(ctx);
            return rc;
        }
        console_help(ctx);
        return 0;

    case CTX_SET:
        if (line_is(p, "wan")) {
            ctx->type = CTX_SET_WAN;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "gateway") || line_is(p, "gateway.addr")) {
            ctx->type = CTX_SET_GATEWAY;
            console_help(ctx);
            return 0;
        }
        if (starts_with(p, "wan") && !strchr(p, ' ')) {
            ctx->type = CTX_SET_WAN_ID;
            snprintf(ctx->arg, sizeof(ctx->arg), "%s", p);
            console_help(ctx);
            return 0;
        }
        {
            int rc = console_exec_prefixed(opts, "set", p);
            console_reset(ctx);
            return rc;
        }

    case CTX_SET_WAN:
        if (starts_with(p, "wan") && !strchr(p, ' ')) {
            ctx->type = CTX_SET_WAN_ID;
            snprintf(ctx->arg, sizeof(ctx->arg), "%s", p);
            console_help(ctx);
            return 0;
        }
        if (starts_with(p, "wan")) {
            int rc = console_exec_prefixed(opts, "set", p);
            console_reset(ctx);
            return rc;
        }
        console_help(ctx);
        return 0;

    case CTX_SET_WAN_ID:
        {
            char prefix[96];
            int rc;
            snprintf(prefix, sizeof(prefix), "set %s", ctx->arg);
            rc = console_exec_prefixed(opts, prefix, p);
            console_reset(ctx);
            return rc;
        }

    case CTX_SET_GATEWAY:
        {
            int rc = console_exec_prefixed(opts, "set gateway.addr", p);
            console_reset(ctx);
            return rc;
        }

    case CTX_ADD:
        if (line_is(p, "wan")) {
            ctx->type = CTX_ADD_WAN;
            console_help(ctx);
            return 0;
        }
        if (line_is(p, "lan")) {
            ctx->type = CTX_ADD_LAN;
            console_help(ctx);
            return 0;
        }
        {
            int rc = console_exec_prefixed(opts, "add", p);
            console_reset(ctx);
            return rc;
        }

    case CTX_ADD_WAN:
        {
            int rc = console_exec_prefixed(opts, "add", p);
            console_reset(ctx);
            return rc;
        }

    case CTX_ADD_LAN:
        {
            int rc = console_exec_prefixed(opts, "add", p);
            console_reset(ctx);
            return rc;
        }

    case CTX_DEL:
        {
            int rc = console_exec_prefixed(opts, "del", p);
            console_reset(ctx);
            return rc;
        }

    case CTX_USER:
        if (line_is(p, "password")) {
            ctx->type = CTX_USER_PASSWORD;
            console_help(ctx);
            return 0;
        }
        {
            int rc = console_exec_prefixed(opts, "user", p);
            console_reset(ctx);
            return rc;
        }

    case CTX_USER_PASSWORD:
        {
            int rc = console_exec_prefixed(opts, "user password", p);
            console_reset(ctx);
            return rc;
        }
    }
    return 0;
}

static const char *root_words[] = {
    "@llm", "add", "audit", "back", "del", "delete", "doctor", "exit", "help",
    "list", "refresh", "reload", "set", "status", "storage", "ubus", "user", NULL
};
static const char *audit_words[] = { "status", "prune", "compact", NULL };
static const char *list_words[] = { "ports", "wans", "lans", NULL };
static const char *set_words[] = { "gateway.addr", "wan", "wan1", "wan2", NULL };
static const char *wan_id_words[] = { "wan", "wan1", "wan2", NULL };
static const char *wan_action_words[] = { "dhcp", "pppoe", "static", "eth0", "eth1", "eth2", "eth3", NULL };
static const char *add_words[] = { "wan", "wan1", "wan2", "lan", "lan1", "lan2", NULL };
static const char *add_wan_words[] = { "wan1", "wan2", NULL };
static const char *add_lan_words[] = { "lan1", "lan2", NULL };
static const char *del_words[] = { "wan1", "wan2", "lan1", "lan2", NULL };
static const char *user_words[] = { "password", NULL };
static const char *user_password_words[] = { "set", "reset", NULL };

static const char **completion_words(struct console_ctx *ctx)
{
    switch (ctx->type) {
    case CTX_AUDIT: return audit_words;
    case CTX_LIST: return list_words;
    case CTX_SET: return set_words;
    case CTX_SET_WAN: return wan_id_words;
    case CTX_SET_WAN_ID: return wan_action_words;
    case CTX_ADD: return add_words;
    case CTX_ADD_WAN: return add_wan_words;
    case CTX_ADD_LAN: return add_lan_words;
    case CTX_DEL: return del_words;
    case CTX_USER: return user_words;
    case CTX_USER_PASSWORD: return user_password_words;
    case CTX_SET_GATEWAY:
    case CTX_NONE:
    default: return root_words;
    }
}

static void completion_add_match(const char **matches, int *count, int max_matches,
                                 const char *word, const char *prefix, int prefix_len)
{
    int i;

    if (!matches || !count || !word || !word[0] || *count >= max_matches)
        return;
    if (prefix_len > 0 && strncmp(word, prefix, (size_t)prefix_len))
        return;
    for (i = 0; i < *count; i++) {
        if (!strcmp(matches[i], word))
            return;
    }
    matches[(*count)++] = word;
}

static void completion_add_static_matches(const char **matches, int *count, int max_matches,
                                          const char **words, const char *prefix, int prefix_len)
{
    int i;

    for (i = 0; words && words[i]; i++)
        completion_add_match(matches, count, max_matches, words[i], prefix, prefix_len);
}

static void completion_add_cache_matches(const char **matches, int *count, int max_matches,
                                         char words[][JMCTL_COMPLETION_WORD_MAX], int word_count,
                                         const char *prefix, int prefix_len)
{
    int i;

    for (i = 0; i < word_count; i++)
        completion_add_match(matches, count, max_matches, words[i], prefix, prefix_len);
}

static int completion_collect_matches(struct jmctl_opts *opts, struct console_ctx *ctx,
                                      const char *prefix, int prefix_len,
                                      int word_index, const char **matches,
                                      int max_matches)
{
    int count = 0;

    completion_load(opts);
    completion_add_static_matches(matches, &count, max_matches,
                                  completion_words(ctx), prefix, prefix_len);
    switch (ctx->type) {
    case CTX_SET:
        completion_add_cache_matches(matches, &count, max_matches,
                                     g_completion_cache.wans, g_completion_cache.wan_count,
                                     prefix, prefix_len);
        break;
    case CTX_SET_WAN:
        if (word_index == 0) {
            completion_add_cache_matches(matches, &count, max_matches,
                                         g_completion_cache.wans, g_completion_cache.wan_count,
                                         prefix, prefix_len);
        } else {
            completion_add_cache_matches(matches, &count, max_matches,
                                         g_completion_cache.ports, g_completion_cache.port_count,
                                         prefix, prefix_len);
        }
        break;
    case CTX_SET_WAN_ID:
        completion_add_cache_matches(matches, &count, max_matches,
                                     g_completion_cache.ports, g_completion_cache.port_count,
                                     prefix, prefix_len);
        break;
    case CTX_ADD_WAN:
        if (word_index == 0) {
            completion_add_cache_matches(matches, &count, max_matches,
                                         g_completion_cache.wans, g_completion_cache.wan_count,
                                         prefix, prefix_len);
        } else {
            completion_add_cache_matches(matches, &count, max_matches,
                                         g_completion_cache.ports, g_completion_cache.port_count,
                                         prefix, prefix_len);
        }
        break;
    case CTX_ADD_LAN:
        if (word_index == 0) {
            completion_add_cache_matches(matches, &count, max_matches,
                                         g_completion_cache.lans, g_completion_cache.lan_count,
                                         prefix, prefix_len);
        } else {
            completion_add_cache_matches(matches, &count, max_matches,
                                         g_completion_cache.ports, g_completion_cache.port_count,
                                         prefix, prefix_len);
        }
        break;
    case CTX_DEL:
        completion_add_cache_matches(matches, &count, max_matches,
                                     g_completion_cache.wans, g_completion_cache.wan_count,
                                     prefix, prefix_len);
        completion_add_cache_matches(matches, &count, max_matches,
                                     g_completion_cache.lans, g_completion_cache.lan_count,
                                     prefix, prefix_len);
        break;
    default:
        break;
    }
    return count;
}

static int current_word_bounds(const char *buf, int len, int *start)
{
    int s = len;
    while (s > 0 && !isspace((unsigned char)buf[s - 1]))
        s--;
    *start = s;
    return len - s;
}

static int completion_word_index(const char *buf, int start)
{
    int i;
    int in_word = 0;
    int words = 0;

    if (!buf || start <= 0)
        return 0;
    for (i = 0; i < start; i++) {
        if (isspace((unsigned char)buf[i])) {
            in_word = 0;
        } else if (!in_word) {
            words++;
            in_word = 1;
        }
    }
    return words;
}

static void redraw_line(const char *prompt, const char *buf)
{
    printf("\r\033[K%s%s", prompt, buf);
    fflush(stdout);
}

static void complete_line(struct jmctl_opts *opts, struct console_ctx *ctx,
                          const char *prompt, char *buf, int *len)
{
    const char *matches[32];
    int start = 0, i;
    int word_len = current_word_bounds(buf, *len, &start);
    const char *prefix = buf + start;
    int word_index = completion_word_index(buf, start);
    int m = completion_collect_matches(opts, ctx, prefix, word_len,
                                       word_index, matches,
                                       (int)(sizeof(matches) / sizeof(matches[0])));

    if (ctx->type == CTX_NONE && word_len == 1 && prefix[0] == 's') {
        matches[0] = "set";
        m = 1;
    }
    if (m == 1) {
        const char *match = matches[0];
        int rest = (int)strlen(match) - word_len;
        if (rest > 0 && *len + rest < JMCTL_LINE_MAX - 2) {
            memcpy(buf + *len, match + word_len, rest);
            *len += rest;
            buf[*len] = '\0';
        }
        if (*len < JMCTL_LINE_MAX - 2) {
            buf[(*len)++] = ' ';
            buf[*len] = '\0';
        }
        redraw_line(prompt, buf);
    } else if (m > 1) {
        printf("\n");
        for (i = 0; i < m; i++)
            printf("%s%s", matches[i], i == m - 1 ? "\n" : "  ");
        redraw_line(prompt, buf);
    } else {
        putchar('\a');
        fflush(stdout);
    }
}

static char *read_console_line(struct jmctl_opts *opts, struct console_ctx *ctx)
{
    static struct termios orig_termios;
    static int raw_enabled = 0;
    struct termios raw;
    char *line = calloc(1, JMCTL_LINE_MAX);
    int len = 0;
    const char *prompt = console_prompt(ctx);

    if (!line)
        return NULL;
    if (!isatty(STDIN_FILENO)) {
        if (!fgets(line, JMCTL_LINE_MAX, stdin)) {
            free(line);
            return NULL;
        }
        line[strcspn(line, "\r\n")] = '\0';
        return line;
    }

    if (!raw_enabled && tcgetattr(STDIN_FILENO, &orig_termios) == 0) {
        raw = orig_termios;
        raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
        raw.c_iflag &= (tcflag_t)~(IXON | ICRNL);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0)
            raw_enabled = 1;
    }

    printf("%s", prompt);
    fflush(stdout);
    for (;;) {
        unsigned char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) {
            free(line);
            line = NULL;
            break;
        }
        if (c == '\r' || c == '\n') {
            printf("\n");
            line[len] = '\0';
            break;
        }
        if (c == 4) {
            if (len == 0) {
                printf("\n");
                free(line);
                line = NULL;
                break;
            }
            continue;
        }
        if (c == 3) {
            printf("^C\n");
            line[0] = '\0';
            break;
        }
        if (c == '\t') {
            complete_line(opts, ctx, prompt, line, &len);
            continue;
        }
        if (c == 127 || c == 8) {
            if (len > 0) {
                len--;
                line[len] = '\0';
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        if (c == 27) {
            unsigned char discard[2];
            (void)read(STDIN_FILENO, discard, sizeof(discard));
            continue;
        }
        if (isprint(c) && len < JMCTL_LINE_MAX - 1) {
            line[len++] = (char)c;
            line[len] = '\0';
            putchar(c);
            fflush(stdout);
        }
    }

    if (raw_enabled) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        raw_enabled = 0;
    }
    return line;
}

static int interactive_loop(struct jmctl_opts *opts)
{
    struct console_ctx ctx;
    int rc = 0;

    console_reset(&ctx);
    printf("DreamingWrt jmctl interactive console. This is not a shell.\n");
    printf("Type help for commands, back for root context, exit to leave.\n");
    for (;;) {
        char *line = read_console_line(opts, &ctx);
        if (!line)
            break;
        if (console_handle_line(opts, &ctx, line) < 0) {
            free(line);
            break;
        }
        free(line);
    }
    return rc;
}

static int parse_opts(struct jmctl_opts *opts, int *argc, char ***argv)
{
    int out = 1;
    int i;
    opts->json = 0;
    opts->dry_run = 0;
    opts->backend = "ubus";
    opts->timeout_ms = JMCTL_DEFAULT_TIMEOUT_MS;
    opts->timeout_set = 0;

    for (i = 1; i < *argc; i++) {
        char *a = (*argv)[i];
        if (!strcmp(a, "--")) {
            while (++i < *argc)
                (*argv)[out++] = (*argv)[i];
            break;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            exit(0);
        } else if (!strcmp(a, "--json")) {
            opts->json = 1;
        } else if (!strcmp(a, "--dry-run")) {
            opts->dry_run = 1;
        } else if (!strcmp(a, "--backend")) {
            if (i + 1 >= *argc)
                return -1;
            opts->backend = (*argv)[++i];
        } else if (!strcmp(a, "--timeout")) {
            if (i + 1 >= *argc)
                return -1;
            opts->timeout_ms = atoi((*argv)[++i]);
            if (opts->timeout_ms <= 0)
                opts->timeout_ms = JMCTL_DEFAULT_TIMEOUT_MS;
            opts->timeout_set = 1;
        } else {
            (*argv)[out++] = (*argv)[i];
        }
    }
    *argc = out;
    return 0;
}

int main(int argc, char **argv)
{
    struct jmctl_opts opts;

    if (parse_opts(&opts, &argc, &argv) != 0)
        return print_error(&opts, "usage", "invalid option");

    if (argc < 2) {
        if (opts.json)
            return print_error(&opts, "usage", "missing command");
        return interactive_loop(&opts);
    }

    return dispatch_argv(&opts, argc - 1, argv + 1);
}
