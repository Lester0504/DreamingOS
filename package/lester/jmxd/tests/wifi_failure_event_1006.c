#include <assert.h>
#include <pthread.h>
#include <time.h>
#include "wifi/wifi_failure_event.h"
struct request { const char *client_ip; };
struct jmx_api_ctx { struct json_object *body; const char *device_id; struct request *req; };
static int ap, forward_fail, delivery_fail, writes, logs, forwards;
static int64_t clock_time = 1000;
static int64_t g_webd_audit_record_id;
static int g_webd_wifi_logd_ok;
static struct json_object *last;
static int webd_device_role_is_ap(void) { return ap; }
static int64_t now_s(void) { return clock_time; }
static struct json_object *webd_obj_child_obj(struct json_object *o, const char *key) {
    struct json_object *v = NULL; if (o) json_object_object_get_ex(o, key, &v);
    return v && json_object_is_type(v, json_type_object) ? v : NULL;
}
static const char *app_nc_json_str(struct json_object *o, const char *key, const char *def) {
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && json_object_is_type(v,json_type_string) ? json_object_get_string(v) : def;
}
static int app_ubus_response_ok(struct json_object *o) {
    struct json_object *v; return o && json_object_object_get_ex(o,"ok",&v) && json_object_get_boolean(v);
}
static const char *app_ubus_response_error_code(struct json_object *o) { return app_nc_json_str(webd_obj_child_obj(o,"error"),"code","operation_failed"); }
static void jmx_app_audit_log_full_stage(const char *actor,const char *app,const char *action,
    const char *risk,const char *target,const char *before,const char *after,const char *ip,
    const char *result,const char *code,const char *stage) {
    assert(!ap); assert(!strcmp(actor,"web:admin")); assert(dw_wifi_failure_event(action));
    ++writes; ++logs; g_webd_audit_record_id = writes; g_webd_wifi_logd_ok = !delivery_fail;
    json_object_put(last); last = json_tokener_parse(target); assert(last);
}
static int webd_ap_audit_terminal(const char *actor,const char *session,const char *ip,
    const char *action,const char *risk,const char *target,const char *result,const char *code) {
    assert(ap); assert(!strcmp(session,"")); assert(dw_wifi_failure_event(action)); ++forwards;
    json_object_put(last); last = json_tokener_parse(target); assert(last);
    return forward_fail ? -1 : 0;
}
#include "observer.inc"
int main(void) {
    struct request request = {"192.0.2.1"};
    struct jmx_api_ctx ctx = { .device_id="web:admin", .req=&request };
    ctx.body=json_tokener_parse("{\"psk\":\"NEVER-LOG-THIS\",\"certificate\":\"PRIVATE\"}");
    struct json_object *response=json_tokener_parse("{\"ok\":false,\"error\":{\"code\":\"stale_local_snapshot\",\"reason\":\"original-reason\",\"stage\":\"core.wifi\"}}");
    const char *before = json_object_to_json_string(webd_obj_child_obj(response,"error")); char *error_copy=strdup(before);
    webd_wifi_failure_observe(&ctx,"wifi_config_save",response,409);
    assert(writes==1 && logs==1 && forwards==0);
    assert(!strcmp(error_copy,json_object_to_json_string(webd_obj_child_obj(response,"error"))));
    assert(!strcmp(app_nc_json_str(last,"error_code",""),"stale_local_snapshot"));
    assert(!strstr(json_object_to_json_string(last),"NEVER-LOG-THIS"));
    assert(!strstr(json_object_to_json_string(last),"PRIVATE"));
    webd_wifi_failure_observe(&ctx,"wifi_config_save",response,409);
    assert(writes==1 && logs==1 && forwards==0);
    clock_time+=31;webd_wifi_failure_observe(&ctx,"wifi_config_save",response,409);assert(writes==2);
    ap=1;json_object_object_add(ctx.body,"ap_id",json_object_new_string("11111111-1111-4111-8111-111111111111"));
    webd_wifi_failure_observe(&ctx,"wifi_config_apply",response,409);
    assert(writes==2 && forwards==1);
    assert(!strcmp(app_nc_json_str(last,"scope",""),"managed_ap"));
    assert(!strcmp(app_nc_json_str(last,"ap_id",""),"11111111-1111-4111-8111-111111111111"));
    webd_wifi_failure_observe(&ctx,"wifi_config_apply",response,409);assert(forwards==1);
    clock_time+=31; forward_fail=1; webd_wifi_failure_observe(&ctx,"wifi_config_apply",response,409);
    assert(forwards==2 && writes==2);
    assert(!strcmp(app_nc_json_str(webd_obj_child_obj(response,"failure_event"),"state",""),"controller_audit_unavailable"));
    webd_wifi_failure_observe(&ctx,"wifi_config_apply",response,409); assert(forwards==2);
    assert(!strcmp(error_copy,json_object_to_json_string(webd_obj_child_obj(response,"error"))));
    assert(!strcmp(dw_wifi_failure_id("wifi_config_apply","radio_readback_mismatch"),"WIFI_CONFIG_READBACK_MISMATCH"));
    assert(!strcmp(dw_wifi_failure_token("psk=secret","operation_failed"),"operation_failed"));
    ap=0;delivery_fail=1;clock_time+=31;
    webd_wifi_failure_observe(&ctx,"wifi_config_apply",response,409);
    assert(!strcmp(app_nc_json_str(webd_obj_child_obj(response,"failure_event"),"state",""),"failure_event_delivery_failed"));
    assert(!strcmp(error_copy,json_object_to_json_string(webd_obj_child_obj(response,"error"))));
    free(error_copy);json_object_put(last);json_object_put(response);json_object_put(ctx.body);
    puts("PASS: WiFi local audit/log, AP forwarding-only, dedupe, redaction, original errors and forwarding failure state");
}
