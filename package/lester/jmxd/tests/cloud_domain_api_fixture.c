// SPDX-License-Identifier: GPL-2.0-or-later
/* Execute actual route/job code. Account, DNS executor and TLS are controlled
 * doubles; Passkey signatures and UCI transactions have separate real fixtures. */
#define webd_cloud_domain_snapshot test_snapshot
#define webd_cloud_domain_plan test_plan
#define webd_cloud_domain_apply test_apply
#include "../src/webd/api/api_cloud.c"
#undef webd_cloud_domain_snapshot
#undef webd_cloud_domain_plan
#undef webd_cloud_domain_apply
#include <assert.h>
#include <sys/wait.h>

static int checks, plans, password_calls, passkey_calls, apply_failure;
static int applicable = 1;
static char last_binding[65];
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); abort(); } } while (0)

struct json_object *webd_error(const char *code, const char *msg, const char *missing, const char *source)
{
    (void)msg; (void)missing; (void)source;
    struct json_object *o = json_object_new_object(), *e = json_object_new_object();
    cloud_domain_text(e,"code",code); json_object_object_add(o,"error",e); return o;
}
struct json_object *webd_envelope(struct json_object *data, const char *source)
{ (void)source; struct json_object *o=json_object_new_object(); json_object_object_add(o,"data",data); return o; }
const char *webd_identity_username(const char *id) { return !strncmp(id,"user:",5) ? id+5 : ""; }
int webd_cloud_local_request_allowed(const struct http_req *req) { return !strcmp(req->ip_source,"local"); }
const char *webd_cloud_work_mode(void) { return "gateway"; }
int webd_passkey_rp_id(char *out,size_t size) { snprintf(out,size,"box.dev.example"); return 0; }
void jmx_app_audit_log(const char *a,const char *b,const char *c,const char *d,const char *e,const char *f,const char *g)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g; }
struct json_object *test_snapshot(struct uci_context *u,const char *r,const char *h,const char *c)
{ (void)u;(void)r;(void)h;(void)c; return json_object_new_object(); }
struct json_object *test_plan(struct json_object *s,const char *m,const struct webd_cloud_domain_paths *p)
{
    (void)s;(void)m;(void)p; plans++;
    struct json_object *o=json_tokener_parse("{\"domain\":\"box.dev.example\",\"revision\":\"revision-1\",\"records\":[{\"host\":\"box.dev.example\",\"address\":\"192.168.1.3\",\"type\":\"A\"}]}");
    json_object_object_add(o,"can_apply",json_object_new_boolean(applicable));
    cloud_domain_text(o,"reason",applicable ? "" : "external_dns_action_required"); return o;
}
struct json_object *test_apply(struct uci_context *u,struct json_object *p,const struct webd_cloud_domain_paths *paths,int (*reload)(void *),void *opaque)
{
    (void)u;(void)p;(void)paths;(void)reload;(void)opaque;
    return json_tokener_parse(apply_failure ? "{\"configured\":false,\"error\":\"dns_reload_failed\",\"rolled_back\":true}" : "{\"configured\":true,\"reloaded\":true,\"client_verified\":false}");
}
struct json_object *webd_cloud_confirm_password(const char *owner,const char *password,const char *ip,int *status)
{
    (void)ip; password_calls++; CHECK(!strcmp(owner,"alice"));
    *status = !strcmp(password,"correct") ? 200 : 401;
    return *status == 200 ? NULL : webd_error("invalid_password","","","");
}
struct json_object *webd_passkey_reauthenticate_begin(const char *owner,const char *binding,int *status)
{
    CHECK(!strcmp(owner,"alice")); CHECK(strlen(binding)==64);
    snprintf(last_binding,sizeof(last_binding),"%s",binding); *status=200;
    return json_tokener_parse("{\"ok\":true,\"publicKeyCredentialRequestOptions\":{\"challenge\":\"AA\"}}");
}
struct json_object *webd_cloud_confirm_passkey(struct json_object *assertion,const char *owner,const char *binding,int *status)
{
    (void)assertion; CHECK(!strcmp(owner,"alice")); passkey_calls++;
    *status=!strcmp(last_binding,binding) ? 200 : 401;
    return json_tokener_parse(*status==200 ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"invalid_challenge\",\"message\":\"binding mismatch\"}");
}
int jmx_exec_capture(const char *file,char *const argv[],size_t max,int timeout,struct jmx_exec_result *out)
{
    (void)file;(void)argv;(void)max;(void)timeout;
    usleep(100000);
    memset(out,0,sizeof(*out)); out->output=strdup("Server: 127.0.0.1\nAddress: 127.0.0.1:53\n\nName: box.dev.example\nAddress: 192.168.1.3\n"); return 0;
}
int jmx_exec_wait(const char *f,char *const a[],int t,struct jmx_exec_result *r)
{ (void)f;(void)a;(void)t; memset(r,0,sizeof(*r)); return 0; }
void jmx_exec_result_free(struct jmx_exec_result *r) { free(r->output); }
CURLcode curl_easy_perform(CURL *c) { (void)c; return CURLE_OK; }

static struct json_object *request(const char *suffix,const char *method,const char *body,jmx_role_t role,const char *identity,const char *source,const char *token,int expected)
{
    struct http_req req={0};
    snprintf(req.path,sizeof(req.path),"/api/v1/cloud/local-domain/%s",suffix);
    snprintf(req.method,sizeof(req.method),"%s",method);
    snprintf(req.ip_source,sizeof(req.ip_source),"%s",source);
    snprintf(req.auth_token,sizeof(req.auth_token),"%s",token);
    struct jmx_api_ctx ctx={.req=&req,.body=json_tokener_parse(body),.role=role,.device_id=identity,.status=200};
    struct json_object *r=cloud_domain_action(&ctx); CHECK(ctx.status==expected); json_object_put(ctx.body); return r;
}
static struct json_object *call(const char *suffix,const char *body,int status)
{ return request(suffix,"POST",body,JMX_ROLE_OWNER,"user:alice","local","session-a",status); }
static void finish_job(struct json_object *reply,const char *state)
{
    struct json_object *data=NULL; json_object_object_get_ex(reply,"data",&data);
    const char *id=cloud_domain_string(data,"job_id"); CHECK(strlen(id)==32);
    CHECK(!strcmp(cloud_domain_string(data,"state"),"queued"));
    int wait_status=0; CHECK(waitpid(-1,&wait_status,0)>0); CHECK(WIFEXITED(wait_status)&&WEXITSTATUS(wait_status)==0);
    struct json_object *job=cloud_domain_job_read(id,"alice"); CHECK(job);
    CHECK(!strcmp(cloud_domain_string(job,"state"),state));
    CHECK(!cloud_domain_job_read(id,"bob"));
    CHECK(!strstr(json_object_to_json_string(job),"correct"));
    CHECK(!strstr(json_object_to_json_string(job),"assertion"));
    json_object_put(job); json_object_put(reply);
}
int main(void)
{
    const char *apply="{\"revision\":\"revision-1\",\"confirm\":true,\"authentication\":{\"method\":\"password\",\"password\":\"correct\"}}";
    json_object_put(request("apply","POST",apply,JMX_ROLE_VIEWER,"user:alice","local","session-a",403));
    json_object_put(request("apply","POST",apply,JMX_ROLE_OWNER,"device:one","local","session-a",403));
    json_object_put(request("apply","POST",apply,JMX_ROLE_OWNER,"user:alice","remote_web","session-a",403));
    CHECK(plans==0&&password_calls==0);
    int lock=open(DOMAIN_LOCK,O_RDWR|O_CREAT,0600); CHECK(lock>=0&&!flock(lock,LOCK_EX|LOCK_NB));
    json_object_put(call("apply",apply,409)); CHECK(plans==0); close(lock);
    json_object_put(call("apply","{}",409)); CHECK(password_calls==0);
    json_object_put(call("apply","{\"revision\":\"revision-1\"}",409)); CHECK(password_calls==0);
    json_object_put(call("apply","{\"revision\":\"revision-1\",\"confirm\":true}",401));
    json_object_put(call("apply","{\"revision\":\"revision-1\",\"confirm\":true,\"authentication\":{\"method\":\"password\",\"password\":\"wrong\"}}",401));
    CHECK(password_calls==1); finish_job(call("apply",apply,202),"succeeded");
    apply_failure=1; finish_job(call("apply",apply,202),"failed"); apply_failure=0;
    applicable=0; json_object_put(call("apply",apply,409)); finish_job(call("probe","{}",202),"succeeded"); applicable=1;
    json_object_put(call("reauth/begin","{\"revision\":\"revision-1\"}",200));
    const char *pk="{\"revision\":\"revision-1\",\"confirm\":true,\"authentication\":{\"method\":\"passkey\",\"assertion\":{}}}";
    struct json_object *denied=request("apply","POST",pk,JMX_ROLE_OWNER,"user:alice","local","session-b",401), *denied_error=NULL;
    CHECK(json_object_object_get_ex(denied,"error",&denied_error));
    CHECK(!strcmp(cloud_domain_string(denied_error,"code"),"invalid_challenge")); json_object_put(denied);
    finish_job(call("apply",pk,202),"succeeded"); CHECK(passkey_calls==2);
    const char *id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; char path[512];
    snprintf(path,sizeof(path),"%s/%s.json",DOMAIN_JOBS,id);
    CHECK(!webd_cloud_domain_write_atomic(path,"{\"owner\":\"alice\",\"state\":\"running\",\"updated_at\":1}",0600));
    struct json_object *stale=cloud_domain_job_read(id,"alice");
    CHECK(!strcmp(cloud_domain_string(stale,"error"),"job_interrupted")); json_object_put(stale);
    CHECK(!cloud_domain_job_read("../../bad","alice"));
    printf("domain_api_ok checks=%d\n",checks); return 0;
}
