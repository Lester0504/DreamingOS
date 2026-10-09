// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/webd/api/api_cloud.c"
#include <assert.h>

static int calls, checks, unavailable, binding_calls, modern;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); abort(); } } while (0)

/* ASan retains the route table; unrelated handlers must never run in this test. */
int webd_passkey_rp_id(char *out, size_t size)
{ (void)out; (void)size; CHECK(0); return -1; }
struct json_object *webd_cloud_domain_snapshot(struct uci_context *u, const char *rp,
                                               const char *hosts, const char *cert)
{ (void)u; (void)rp; (void)hosts; (void)cert; CHECK(0); return NULL; }
struct json_object *app_ubus_invoke_object_diag(const char *o, const char *m,
    struct json_object *p, int t, struct app_ubus_call_diag *d)
{
    (void)d;
    ++binding_calls;
    CHECK(!strcmp(o, "dreamingos.cloud") && t == 3000);
    if (!strcmp(m, "bind_code")) {
        struct json_object *v = NULL;
        CHECK(json_object_object_get_ex(p, "code", &v));
        CHECK(!strcmp(json_object_get_string(v), "0123456789abcdef01234567"));
        CHECK(json_object_object_get_ex(p, "display_name", &v));
        CHECK(!strcmp(json_object_get_string(v), "browser-test"));
        return json_tokener_parse("{\"ok\":true,\"data\":{\"state\":\"running\"}}");
    }
    CHECK(!strcmp(m, "bind_status") && p == NULL);
    return json_tokener_parse("{\"ok\":true,\"data\":{\"state\":\"succeeded\",\"canonical_host\":\"lester.dev.dreamingnet.com\"}}");
}
int webd_policy_uci_set_pkg_option(struct uci_context *u, const char *p, const char *s,
    const char *o, const char *v, int d, char *e, size_t n)
{ (void)u; (void)p; (void)s; (void)o; (void)v; (void)d; (void)e; (void)n; CHECK(0); return -1; }

struct json_object *webd_error(const char *code, const char *message,
                               const char *missing, const char *source)
{
    (void)message; (void)missing; (void)source;
    struct json_object *o = json_object_new_object();
    struct json_object *error = json_object_new_object();
    json_object_object_add(error, "code", json_object_new_string(code));
    json_object_object_add(o, "error", error);
    return o;
}
struct json_object *webd_envelope(struct json_object *data, const char *source)
{
    (void)source;
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "data", data);
    return o;
}
void jmx_app_audit_log(const char *a, const char *b, const char *c, const char *d,
                       const char *e, const char *f, const char *g)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; }
struct json_object *app_ubus_invoke_object_timeout(const char *object, const char *method,
                                                  struct json_object *args, int timeout)
{
    ++calls;
    CHECK(!strcmp(object, "dreamingos.cloud") && !strcmp(method, "web_access") && timeout == 3000);
    struct json_object *actor = NULL, *action = NULL;
    CHECK(json_object_object_get_ex(args, "actor", &actor));
    CHECK(!strcmp(json_object_get_string(actor), "user:test"));
    CHECK(json_object_object_get_ex(args, "action", &action));
    if (unavailable) return NULL;
    const char *name = json_object_get_string(action);
    if (!strcmp(name, "job"))
        return json_tokener_parse("{\"ok\":false,\"http_status\":404,\"code\":\"not_found\"}");
    if (!strcmp(name, "status"))
        return json_tokener_parse(modern ?
            "{\"ok\":true,\"http_status\":200,\"data\":{\"state\":\"connected\",\"websocket\":true,"
            "\"sse\":true,\"upload_max_bytes\":1073741824,\"response_max_bytes\":1073741824,"
            "\"capability_state\":\"negotiated\",\"account_quota\":{\"state\":\"enforced\"}}}" :
            "{\"ok\":true,\"http_status\":200,\"data\":{\"state\":\"disabled\"}}");
    return json_tokener_parse("{\"ok\":true,\"http_status\":202,\"data\":{\"state\":\"queued\"}}");
}
static struct json_object *request(const char *suffix, const char *method, const char *body,
                                    jmx_role_t role, int expected)
{
    struct http_req req = {0};
    snprintf(req.path, sizeof(req.path), "/api/v1/cloud/web-access/%s", suffix);
    snprintf(req.method, sizeof(req.method), "%s", method);
    struct jmx_api_ctx ctx = {.req = &req, .body = json_tokener_parse(body),
                              .role = role, .device_id = "user:test", .status = 200};
    struct json_object *r = cloud_browser_api(&ctx);
    CHECK(ctx.status == expected);
    json_object_put(ctx.body);
    return r;
}
int main(void)
{
    struct jmx_api_ctx binding = {.body = json_tokener_parse("{}"),
        .device_id = "user:test", .status = 200};
    struct json_object *bound = cloud_bind_code(&binding);
    CHECK(binding.status == 409 && binding_calls == 0);
    json_object_put(bound);
    json_object_put(binding.body);
    binding.body = json_tokener_parse("{\"confirm\":true}");
    bound = cloud_bind_code(&binding);
    CHECK(binding.status == 422 && binding_calls == 0);
    json_object_put(bound);
    json_object_put(binding.body);
    binding.body = json_tokener_parse("{\"confirm\":true,\"binding_code\":\"0123456789abcdef01234567\",\"display_name\":\"browser-test\"}");
    bound = cloud_bind_code(&binding);
    CHECK(binding.status == 200 && binding_calls == 1);
    json_object_put(bound);
    json_object_put(binding.body);
    binding.body = NULL;
    bound = cloud_bind_status(&binding);
    CHECK(binding.status == 200 && binding_calls == 2);
    json_object_put(bound);
    json_object_put(request("enable", "POST", "{\"confirm\":true}", JMX_ROLE_VIEWER, 403));
    json_object_put(request("disable", "POST", "{\"confirm\":true}", JMX_ROLE_ADMIN, 403));
    CHECK(calls == 0);
    json_object_put(request("services/nas", "PATCH", "{}", JMX_ROLE_VIEWER, 403));
    json_object_put(request("services/nas", "DELETE", "{}", JMX_ROLE_ADMIN, 403));
    json_object_put(request("services/nas/probe/extra", "POST", "{}", JMX_ROLE_OWNER, 404));
    json_object_put(request("services/nas", "PATCH", "{\"service_id\":\"other\"}", JMX_ROLE_OWNER, 422));
    CHECK(calls == 0);
    json_object_put(request("services", "GET", "{}", JMX_ROLE_VIEWER, 202));
    json_object_put(request("services/nas", "PATCH", "{\"enabled\":false}", JMX_ROLE_OWNER, 202));
    json_object_put(request("services/nas", "DELETE", "{\"confirm\":true}", JMX_ROLE_OWNER, 202));
    json_object_put(request("services/nas/probe", "POST", "{}", JMX_ROLE_OWNER, 202));
    json_object_put(request("enable", "POST", "{\"confirm\":\"true\"}", JMX_ROLE_OWNER, 422));
    json_object_put(request("enable", "POST", "{\"return_url\":\"evil\"}", JMX_ROLE_OWNER, 422));
    json_object_put(request("preflight", "POST", "{\"actor\":\"user:other\"}", JMX_ROLE_OWNER, 422));
    json_object_put(request("preflight", "POST", "[]", JMX_ROLE_OWNER, 422));
    json_object_put(request("jobs/../other", "GET", "{}", JMX_ROLE_OWNER, 404));
    CHECK(calls == 4);
    json_object_put(request("status", "GET", "{}", JMX_ROLE_VIEWER, 200));
    json_object_put(request("preflight", "POST", "{}", JMX_ROLE_OWNER, 202));
    json_object_put(request("enable", "POST",
        "{\"confirm\":true,\"preflight_id\":\"01234567890123456789012345678901\",\"legacy_hostname_ack\":true}",
        JMX_ROLE_OWNER, 202));
    json_object_put(request("jobs/01234567890123456789012345678901", "GET", "{}", JMX_ROLE_OWNER, 404));
    struct json_object *r = request("capabilities", "GET", "{}", JMX_ROLE_VIEWER, 200);
    struct json_object *data = NULL, *v = NULL;
    CHECK(json_object_object_get_ex(r, "data", &data));
    CHECK(json_object_object_get_ex(data, "can_write", &v) && !json_object_get_boolean(v));
    CHECK(json_object_object_get_ex(data, "supported", &v) && json_object_get_boolean(v));
    CHECK(json_object_object_get_ex(data, "websocket", &v) && !json_object_get_boolean(v));
    CHECK(json_object_object_get_ex(data, "upload_max_bytes", &v) && json_object_get_int(v) == 262144);
    json_object_put(r);
    modern = 1;
    r = request("capabilities", "GET", "{}", JMX_ROLE_OWNER, 200);
    data = json_object_object_get(r, "data");
    CHECK(json_object_get_boolean(json_object_object_get(data, "websocket")));
    CHECK(json_object_get_boolean(json_object_object_get(data, "sse")));
    CHECK(json_object_get_int64(json_object_object_get(data, "upload_max_bytes")) == 1073741824);
    CHECK(json_object_object_get(data, "account_quota") != NULL);
    json_object_put(r);
    unavailable = 1;
    r = request("capabilities", "GET", "{}", JMX_ROLE_OWNER, 200);
    CHECK(json_object_object_get_ex(r, "data", &data));
    CHECK(json_object_object_get_ex(data, "supported", &v) && !json_object_get_boolean(v));
    json_object_put(r);
    json_object_put(request("status", "GET", "{}", JMX_ROLE_OWNER, 503));
    printf("browser API: %d checks passed\n", checks);
    return 0;
}
