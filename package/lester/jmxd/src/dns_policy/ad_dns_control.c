/* SPDX-License-Identifier: GPL-2.0-or-later
 * AegisX's atomic projection into the native resolver. Permanent rules remain
 * aegis_domain_overrides/content_policies; only temporary leases live here.
 */
#define _GNU_SOURCE
#include "ad_dns_control.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static struct json_object *get(struct json_object *o,const char *k) {struct json_object *v=NULL;if(o)json_object_object_get_ex(o,k,&v);return v;}
static const char *str(struct json_object *o,const char *k) {struct json_object *v=get(o,k);return v&&json_object_is_type(v,json_type_string)?json_object_get_string(v):"";}
static int64_t num(struct json_object *o,const char *k) {return json_object_get_int64(get(o,k));}
static void txt(struct json_object *o,const char *k,const char *v) {json_object_object_add(o,k,json_object_new_string(v?v:""));}
static void integer(struct json_object *o,const char *k,int64_t v) {json_object_object_add(o,k,json_object_new_int64(v));}
static void boolean(struct json_object *o,const char *k,int v) {json_object_object_add(o,k,json_object_new_boolean(v));}
static const char *js(struct json_object *o) {return json_object_to_json_string_ext(o,JSON_C_TO_STRING_PLAIN);}
static struct json_object *clone(struct json_object *o) {return o?json_tokener_parse(js(o)):NULL;}
static struct json_object *failure(const char *code,const char *message) {struct json_object *o=json_object_new_object(),*err=json_object_new_object();boolean(o,"ok",0);txt(err,"code",code);txt(err,"message",message);json_object_object_add(o,"error",err);return o;}
static sqlite3_stmt *prepare(sqlite3 *db,const char *sql) {sqlite3_stmt *s=NULL;return sqlite3_prepare_v2(db,sql,-1,&s,NULL)==SQLITE_OK?s:NULL;}
static const char *col(sqlite3_stmt *s,int i) {const char *v=(const char *)sqlite3_column_text(s,i);return v?v:"";}
static void bind_text(sqlite3_stmt *s,int i,const char *v) {sqlite3_bind_text(s,i,v,-1,SQLITE_TRANSIENT);}
static int step(sqlite3_stmt *s) {int ok=s&&sqlite3_step(s)==SQLITE_DONE;sqlite3_finalize(s);return ok?0:-1;}
static int ident(const char *s) {if(!*s||strlen(s)>96)return 0;for(;*s;s++)if(!isalnum((unsigned char)*s)&&*s!='_'&&*s!='-')return 0;return 1;}
static int mac_ok(const char *s) {if(strlen(s)!=17)return 0;for(int i=0;i<17;i++)if(i%3==2?s[i]!=':':!isxdigit((unsigned char)s[i]))return 0;return 1;}
static int domain_ok(const char *s) {
    int label=0;if(!*s||strlen(s)>253||!strchr(s,'.'))return 0;
    for(const char *p=s;*p;p++) {if(*p=='.'){if(!label||p[-1]=='-')return 0;label=0;}else{if((!isalnum((unsigned char)*p)&&*p!='-')||(!label&&*p=='-')||++label>63)return 0;}}
    return label&&s[strlen(s)-1]!='-';
}
static int64_t revision(const struct ad_dns_environment *e) {sqlite3_stmt *s=prepare(e->db,"SELECT revision FROM aegis_ad_dns_meta WHERE id=1");int64_t n=s&&sqlite3_step(s)==SQLITE_ROW?sqlite3_column_int64(s,0):0;sqlite3_finalize(s);return n;}
/* Query the actual running resolver, not its binary or a filesystem marker. */
static int probe(const struct ad_dns_environment *e,int64_t expected,int *valid) {
    unsigned char q[80]={0x44,0x41,1,0,0,1},r[256];size_t n=12;const char *labels[]={"_dwrt-ad-policy","invalid",NULL};
    for(int i=0;labels[i];i++){size_t len=strlen(labels[i]);q[n++]=len;memcpy(q+n,labels[i],len);n+=len;}
    q[n++]=0;q[n++]=0;q[n++]=16;q[n++]=0;q[n++]=1;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return 0;
    struct timeval tv={.tv_sec=0,.tv_usec=400000};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(e->dns_port?e->dns_port:53),.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    int ready=0;if(!connect(fd,(void *)&a,sizeof(a))&&send(fd,q,n,0)==(ssize_t)n){ssize_t len=recv(fd,r,sizeof(r)-1,0);if(len>(ssize_t)n+13&&r[0]==q[0]&&r[1]==q[1]&&(r[2]&128)&&r[7]==1){size_t p=n+12,z=r[p++];if(p+z<=(size_t)len){r[p+z]=0;long long rev;int ok;if(sscanf((char *)r+p,"DWAD1 %lld %d",&rev,&ok)==2){ready=expected<0||rev==expected;if(valid)*valid=ok;}}}}
    close(fd);return ready;
}
static int target_valid(const struct ad_dns_environment *e,const char *ip,const char *mac) {
    FILE *f=fopen(e->leases,"r");char line[1024],m[80],a[80];long long expiry;int ok=0;
    if(!f)return 0;
    while(fgets(line,sizeof(line),f))if(sscanf(line,"%lld %79s %79s",&expiry,m,a)==3&&(!expiry||expiry>e->now)&&!strcmp(ip,a)&&!strcasecmp(mac,m)){ok=1;break;}
    fclose(f);return ok;
}
int ad_dns_init(const struct ad_dns_environment *e) {
    if(sqlite3_exec(e->db,
      "CREATE TABLE IF NOT EXISTS aegis_ad_dns_meta(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL);"
      "INSERT OR IGNORE INTO aegis_ad_dns_meta VALUES(1,1);"
      "CREATE TABLE IF NOT EXISTS aegis_ad_dns_leases(session TEXT NOT NULL,kind TEXT NOT NULL,owner TEXT NOT NULL,mac TEXT NOT NULL,ip TEXT NOT NULL,expires INTEGER NOT NULL,document TEXT NOT NULL,PRIMARY KEY(session,kind));"
      "CREATE TABLE IF NOT EXISTS aegis_ad_dns_requests(owner TEXT NOT NULL,id TEXT NOT NULL,signature TEXT NOT NULL,response TEXT NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(owner,id));",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    sqlite3_stmt *s=prepare(e->db,"PRAGMA table_info(aegis_domain_overrides)");int found=0;while(s&&sqlite3_step(s)==SQLITE_ROW)if(!strcmp(col(s,1),"match_kind"))found=1;sqlite3_finalize(s);
    if(!found&&sqlite3_exec(e->db,"ALTER TABLE aegis_domain_overrides ADD COLUMN match_kind TEXT NOT NULL DEFAULT 'suffix'",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    s=prepare(e->db,"PRAGMA table_info(aegis_content_policies)");found=0;while(s&&sqlite3_step(s)==SQLITE_ROW)if(!strcmp(col(s,1),"enforcement"))found=1;sqlite3_finalize(s);
    if(!found&&sqlite3_exec(e->db,"ALTER TABLE aegis_content_policies ADD COLUMN enforcement TEXT NOT NULL DEFAULT 'legacy'",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    /* Provider revisions cover changes made through the canonical content API too. */
    const char *tables[]={"aegis_domain_overrides","aegis_content_policies",NULL};const char *ops[]={"INSERT","UPDATE","DELETE"};char sql[512];
    for(int i=0;tables[i];i++)for(int j=0;j<3;j++){snprintf(sql,sizeof(sql),"CREATE TRIGGER IF NOT EXISTS ad_dns_%s_%s AFTER %s ON %s BEGIN UPDATE aegis_ad_dns_meta SET revision=revision+1 WHERE id=1; END",tables[i],ops[j],ops[j],tables[i]);if(sqlite3_exec(e->db,sql,NULL,NULL,NULL)!=SQLITE_OK)return -1;}
    return 0;
}
static int emit(FILE *f,int *count,char kind,const char *id,const char *mac,const char *ip,int64_t exp,const char *action,const char *domain) {
    if(++*count>4096)return -1;
    return fprintf(f,"%c %s %s %s %lld %c %c %s\n",kind,id,*mac?mac:"*",*ip?ip:"*",(long long)exp,!strcmp(action,"block")?'B':!strcmp(action,"allow")?'A':'-',kind=='O'?'-':'E',*domain?domain:"*")<0?-1:0;
}
static int project(const struct ad_dns_environment *e) {
    char path[512],tmp[512];snprintf(path,sizeof(path),"%s/policy",e->directory);snprintf(tmp,sizeof(tmp),"%s/policy.XXXXXX",e->directory);
    int fd=mkstemp(tmp);if(fd<0)return -1;fchmod(fd,0644);FILE *f=fdopen(fd,"w");if(!f){close(fd);unlink(tmp);return -1;}
    int count=0,rc=0;fprintf(f,"DWAD1 %lld\n",(long long)revision(e));
    sqlite3_stmt *s=prepare(e->db,"SELECT session,kind,mac,ip,expires,document FROM aegis_ad_dns_leases WHERE expires>?1 ORDER BY session,kind");
    if(!s)rc=-1;else sqlite3_bind_int64(s,1,e->now);
    while(!rc&&sqlite3_step(s)==SQLITE_ROW){
        if(!strcmp(col(s,1),"observe"))rc=emit(f,&count,'O',col(s,0),col(s,2),col(s,3),sqlite3_column_int64(s,4),"","");
        else {struct json_object *o=json_tokener_parse(col(s,5)),*rules=get(o,"rules");for(size_t i=0;i<json_object_array_length(rules)&&!rc;i++){struct json_object *r=json_object_array_get_idx(rules,i);rc=emit(f,&count,'R',col(s,0),col(s,2),col(s,3),sqlite3_column_int64(s,4),str(r,"action"),str(r,"domain"));}json_object_put(o);}
    }sqlite3_finalize(s);
    s=prepare(e->db,"SELECT o.id,o.domain,o.action,p.scope_json FROM aegis_domain_overrides o LEFT JOIN aegis_content_policies p ON p.id=o.policy_id WHERE o.match_kind='exact' AND o.enabled=1 AND (o.policy_id='' OR (p.enabled=1 AND p.mode<>'off')) ORDER BY o.id");
    if(!s)rc=-1;
    while(!rc&&sqlite3_step(s)==SQLITE_ROW){struct json_object *scope=json_tokener_parse(col(s,3));const char *type=str(scope,"type");if(!*type||!strcmp(type,"all"))rc=emit(f,&count,'R',col(s,0),"*","*",0,col(s,2),col(s,1));else if(!strcmp(type,"devices")){struct json_object *devices=get(scope,"devices");for(size_t i=0;i<json_object_array_length(devices)&&!rc;i++){const char *mac=json_object_get_string(json_object_array_get_idx(devices,i));if(!mac_ok(mac)){rc=-1;break;}rc=emit(f,&count,'R',col(s,0),mac,"*",0,col(s,2),col(s,1));}}else rc=-1;json_object_put(scope);}
    sqlite3_finalize(s);
    if(fflush(f)||fsync(fd))rc=-1;if(fclose(f))rc=-1;
    if(!rc&&rename(tmp,path))rc=-1;if(rc)unlink(tmp);return rc;
}
static char *snapshot(const struct ad_dns_environment *e) {char path[512];snprintf(path,sizeof(path),"%s/policy",e->directory);FILE *f=fopen(path,"r");if(!f)return strdup("");if(fseek(f,0,SEEK_END)){fclose(f);return NULL;}long n=ftell(f);if(n<0||n>3*1024*1024){fclose(f);return NULL;}rewind(f);char *b=calloc(n+1,1);if(b&&fread(b,1,n,f)!=(size_t)n){free(b);b=NULL;}fclose(f);return b;}
static int restore(const struct ad_dns_environment *e,const char *old) {char path[512],tmp[512];snprintf(path,sizeof(path),"%s/policy",e->directory);snprintf(tmp,sizeof(tmp),"%s/restore.XXXXXX",e->directory);int fd=mkstemp(tmp);if(fd<0)return -1;size_t len=strlen(old);int rc=write(fd,old,len)==(ssize_t)len&&fchmod(fd,0644)==0&&fsync(fd)==0?0:-1;close(fd);if(!rc)rc=rename(tmp,path);if(rc)unlink(tmp);return rc;}
static int finish(const struct ad_dns_environment *e,char *old) {
    int valid=0;
    if(!project(e)&&probe(e,revision(e),&valid)&&valid&&sqlite3_exec(e->db,"COMMIT",NULL,NULL,NULL)==SQLITE_OK){free(old);return 0;}
    sqlite3_exec(e->db,"ROLLBACK",NULL,NULL,NULL);int rc=restore(e,old);free(old);return rc?-2:-1;
}
static int remove_lease(const struct ad_dns_environment *e,const char *session,const char *kind){sqlite3_stmt *s=prepare(e->db,"DELETE FROM aegis_ad_dns_leases WHERE session=?1 AND (?2='' OR kind=?2)");if(!s)return -1;bind_text(s,1,session);bind_text(s,2,kind);return step(s);}
int ad_dns_reconcile(const struct ad_dns_environment *e,int restart) {
    if(sqlite3_exec(e->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    sqlite3_stmt *s=prepare(e->db,"SELECT session,kind,mac,ip,expires FROM aegis_ad_dns_leases");struct json_object *expired=json_object_new_array();
    while(s&&sqlite3_step(s)==SQLITE_ROW)if(restart||sqlite3_column_int64(s,4)<=e->now||(*col(s,2)&&!target_valid(e,col(s,3),col(s,2)))){struct json_object *v=json_object_new_object();txt(v,"id",col(s,0));txt(v,"kind",col(s,1));json_object_array_add(expired,v);}sqlite3_finalize(s);
    int changed=0;for(size_t i=0;i<json_object_array_length(expired);i++){struct json_object *v=json_object_array_get_idx(expired,i);if(remove_lease(e,str(v,"id"),str(v,"kind")))goto fail;changed=1;}json_object_put(expired);expired=NULL;
    if(changed&&sqlite3_exec(e->db,"UPDATE aegis_ad_dns_meta SET revision=revision+1",NULL,NULL,NULL)!=SQLITE_OK)goto fail;
    if(restart)sqlite3_exec(e->db,"DELETE FROM aegis_ad_dns_requests WHERE response LIKE '%\"expires_at\"%'",NULL,NULL,NULL);
    /* Cleanup must persist even while dnsmasq is down. The query hook independently expires leases. */
    if(sqlite3_exec(e->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    int valid=0;if(!changed&&!restart&&probe(e,revision(e),&valid)&&valid)return 0;
    return project(e);
fail:
    json_object_put(expired);sqlite3_exec(e->db,"ROLLBACK",NULL,NULL,NULL);return -1;
}
static struct json_object *normalize_rules(struct json_object *b) {
    struct json_object *in=get(b,"rules"),*a=json_object_new_array(),*seen=json_object_new_object();size_t n=json_object_array_length(in);
    if(!json_object_is_type(in,json_type_array)||!n||n>128)goto fail;
    for(size_t i=0;i<n;i++){struct json_object *r=json_object_array_get_idx(in,i);char d[254];snprintf(d,sizeof(d),"%s",str(r,"domain"));if(strlen(str(r,"domain"))>253)goto fail;for(char *p=d;*p;p++)*p=tolower((unsigned char)*p);size_t len=strlen(d);if(len&&d[len-1]=='.')d[len-1]=0;
      const char *act=str(r,"action");if(!domain_ok(d)||strcmp(str(r,"match"),"exact")||(strcmp(act,"block")&&strcmp(act,"allow")))goto fail;
      if(get(seen,d)){if(strcmp(str(seen,d),act))goto fail;continue;}txt(seen,d,act);struct json_object *v=json_object_new_object();txt(v,"domain",d);txt(v,"match","exact");txt(v,"action",act);json_object_array_add(a,v);}
    json_object_put(seen);return a;
fail:json_object_put(seen);json_object_put(a);return NULL;
}
static void ids(const char *mac,const char *domain,char policy[80],char rule[96]) {
    uint64_t hash=1469598103934665603ULL;snprintf(policy,80,"ad-device-");size_t j=strlen(policy);for(const char *p=mac;*p;p++)if(*p!=':')policy[j++]=tolower((unsigned char)*p);policy[j]=0;
    if(!*mac)policy[0]=0;
    for(const unsigned char *p=(const unsigned char *)mac;*p;p++){hash^=*p;hash*=1099511628211ULL;}hash^='|';hash*=1099511628211ULL;for(const unsigned char *p=(const unsigned char *)domain;*p;p++){hash^=*p;hash*=1099511628211ULL;}snprintf(rule,96,"ad-domain-%016llx",(unsigned long long)hash);
}
static struct json_object *rules_preview(const struct ad_dns_environment *e,struct json_object *b,struct json_object *rules) {
    struct json_object *o=json_object_new_object(),*out=json_object_new_array();const char *mac=!strcmp(str(get(b,"scope"),"type"),"all")?"":str(b,"device_id");
    boolean(o,"ok",1);integer(o,"provider_revision",revision(e));txt(o,"provider","aegisxd-content-policy");json_object_object_add(o,"scope",clone(get(b,"scope")));boolean(o,"can_commit",1);
    for(size_t i=0;i<json_object_array_length(rules);i++){struct json_object *r=clone(json_object_array_get_idx(rules,i));char policy[80],id[96];ids(mac,str(r,"domain"),policy,id);sqlite3_stmt *s=prepare(e->db,"SELECT id,action,match_kind FROM aegis_domain_overrides WHERE policy_id=?1 AND domain=?2");if(s){bind_text(s,1,policy);bind_text(s,2,str(r,"domain"));if(sqlite3_step(s)==SQLITE_ROW){snprintf(id,sizeof(id),"%s",col(s,0));txt(r,"operation",!strcmp(col(s,1),str(r,"action"))&&!strcmp(col(s,2),"exact")?"unchanged":"update");txt(r,"previous_action",col(s,1));txt(r,"previous_match",col(s,2));}else txt(r,"operation","create");}sqlite3_finalize(s);txt(r,"id",id);txt(r,"policy_id",policy);txt(r,"provider","aegisxd-content-policy");txt(r,"management_route","/app/#/policy-engine/aegisx");json_object_array_add(out,r);}
    json_object_object_add(o,"rules",out);
    struct json_object *conflicts=e->conflicts?e->conflicts(b):json_object_new_array();if(json_object_array_length(conflicts))boolean(o,"can_commit",0);json_object_object_add(o,"conflicts",conflicts);return o;
}
static int commit_rules(const struct ad_dns_environment *e,struct json_object *preview,struct json_object *b) {
    struct json_object *rules=get(preview,"rules");const char *mac=!strcmp(str(get(b,"scope"),"type"),"all")?"":str(b,"device_id");char policy[80],id[96];ids(mac,"",policy,id);
    if(*policy){struct json_object *scope=json_object_new_object(),*dev=json_object_new_array();txt(scope,"type","devices");json_object_array_add(dev,json_object_new_string(mac));json_object_object_add(scope,"devices",dev);json_object_object_add(scope,"networks",json_object_new_array());sqlite3_stmt *s=prepare(e->db,"INSERT INTO aegis_content_policies(id,name,scope_json,apply_state,created_at,updated_at,enforcement) VALUES(?1,'广告分析精确域名规则',?2,'applied',?3,?3,'dns_exact') ON CONFLICT(id) DO UPDATE SET enabled=1,mode='basic',apply_state='applied',revision=revision+1,updated_at=excluded.updated_at");if(!s){json_object_put(scope);return -1;}bind_text(s,1,policy);bind_text(s,2,js(scope));sqlite3_bind_int64(s,3,e->now);int rc=step(s);json_object_put(scope);if(rc)return -1;}
    for(size_t i=0;i<json_object_array_length(rules);i++){struct json_object *r=json_object_array_get_idx(rules,i);sqlite3_stmt *s=prepare(e->db,"INSERT INTO aegis_domain_overrides(id,policy_id,domain,action,enabled,note,apply_state,match_kind,created_at,updated_at) VALUES(?1,?2,?3,?4,1,'广告分析明确保存','applied','exact',?5,?5) ON CONFLICT(id) DO UPDATE SET action=excluded.action,enabled=1,match_kind='exact',apply_state='applied',last_error='',updated_at=excluded.updated_at");if(!s)return -1;bind_text(s,1,str(r,"id"));bind_text(s,2,policy);bind_text(s,3,str(r,"domain"));bind_text(s,4,str(r,"action"));sqlite3_bind_int64(s,5,e->now);if(step(s))return -1;txt(r,"apply_state","applied");boolean(r,"saved",1);}
    return 0;
}
struct json_object *ad_dns_handle(const struct ad_dns_environment *e,const char *op,struct json_object *b) {
    if(!strcmp(op,"capabilities")){struct json_object *o=json_object_new_object();int valid=0,ready=probe(e,revision(e),&valid)&&valid;boolean(o,"ok",1);boolean(o,"ready",ready);txt(o,"id","aegisxd-content-policy");txt(o,"version","native-dns-DWAD1");integer(o,"provider_revision",revision(e));txt(o,"enforcement","source_mac_ip_exact_query");txt(o,"reason",ready?"":"native_dns_provider_not_ready");txt(o,"dns_log",e->directory);return o;}
    const char *session=str(b,"session_id"),*owner=str(b,"operator_id"),*rid=str(b,"request_id"),*mac=str(b,"device_id"),*ip=str(b,"device_ip");
    if(!ident(session)||!*owner||strlen(owner)>160)return failure("invalid_owner","需要明确会话及操作者");
    if(!strcmp(op,"status")){struct json_object *o=json_object_new_object();boolean(o,"ok",1);sqlite3_stmt *s=prepare(e->db,"SELECT document,expires FROM aegis_ad_dns_leases WHERE session=?1 AND owner=?2 AND kind='trial'");if(s){bind_text(s,1,session);bind_text(s,2,owner);if(sqlite3_step(s)==SQLITE_ROW){struct json_object *t=json_tokener_parse(col(s,0));txt(t,"apply_state",sqlite3_column_int64(s,1)>e->now?"applied":"expired");json_object_object_add(o,"trial",t);}}sqlite3_finalize(s);return o;}
    if(!ident(rid))return failure("request_id_required","操作需要幂等标识");
    if(sqlite3_exec(e->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return failure("provider_busy","规则配置正在更新");
    struct json_object *result=NULL,*rules=NULL;char *signature=NULL,*old=NULL;sqlite3_stmt *s=NULL;
    if(asprintf(&signature,"%s %s",op,js(b))<0)signature=NULL;if(!signature)goto storage;
    s=prepare(e->db,"SELECT signature,response FROM aegis_ad_dns_requests WHERE owner=?1 AND id=?2");if(!s)goto storage;bind_text(s,1,owner);bind_text(s,2,rid);
    if(sqlite3_step(s)==SQLITE_ROW){result=!strcmp(col(s,0),signature)?json_tokener_parse(col(s,1)):failure("request_id_conflict","幂等标识已用于其他请求");sqlite3_finalize(s);s=NULL;goto done;}
    sqlite3_finalize(s);s=NULL;
    s=prepare(e->db,"SELECT owner FROM aegis_ad_dns_leases WHERE session=?1");if(!s)goto storage;bind_text(s,1,session);if(sqlite3_step(s)==SQLITE_ROW&&strcmp(col(s,0),owner)){sqlite3_finalize(s);s=NULL;result=failure("resource_owner_required","不能撤回其他操作者的租约");goto done;}sqlite3_finalize(s);s=NULL;
    int observe=!strcmp(op,"observe"),replace=!strcmp(op,"replace"),preview=!strcmp(op,"preview"),commit=!strcmp(op,"commit"),revoke=!strcmp(op,"revoke"),stop=!strcmp(op,"stop");
    if(!observe&&!replace&&!preview&&!commit&&!revoke&&!stop){result=failure("invalid_operation","未知规则操作");goto done;}
    if((replace||commit||preview)&&(!mac_ok(mac)||!target_valid(e,ip,mac))){result=failure("device_identity_changed","试验与保存需要仍有效的目标设备租约");goto done;}
    if(observe&&*mac&&(!mac_ok(mac)||!target_valid(e,ip,mac))){result=failure("device_identity_changed","观察设备归属已变化");goto done;}
    if(observe){unsigned char a[16];if(inet_pton(AF_INET,ip,a)!=1&&inet_pton(AF_INET6,ip,a)!=1){result=failure("invalid_target","观察需要合法 IP");goto done;}}
    if(replace||preview||commit){
      rules=normalize_rules(b);if(!rules){result=failure("invalid_rules","需要 1–128 条完整域名、exact 与明确动作；同域不能冲突");goto done;}
      const char *type=str(get(b,"scope"),"type");if(strcmp(type,"device")&&!(strcmp(op,"replace")&&!strcmp(type,"all")&&num(b,"confirm_global"))){result=failure("scope_conflict","范围必须明确；全网保存需要独立确认");goto done;}
      if(!strcmp(type,"device")&&strcmp(str(get(b,"scope"),"device_id"),mac)){result=failure("scope_conflict","范围与会话设备不一致");goto done;}
      result=rules_preview(e,b,rules);
      if(preview)goto done;
      if(!num(result,"can_commit")){struct json_object *conf=clone(get(result,"conflicts"));json_object_put(result);result=failure("provider_conflict","存在此 DNS 放行不能覆盖的连接层阻断");json_object_object_add(result,"conflicts",conf);goto done;}
      if(num(b,"provider_revision")!=revision(e)){json_object_put(result);result=failure("provider_revision_conflict","规则版本已变化，请重新预览");goto done;}
    }
    old=snapshot(e);if(!old)goto storage;
    if(observe||replace){
      int ttl=(int)num(b,observe?"observe_ttl":"ttl_seconds");if(ttl<30||ttl>(observe?1800:900)){json_object_put(result);result=failure("invalid_ttl","租约时限超出范围");goto done;}
      s=prepare(e->db,"SELECT count(*) FROM aegis_ad_dns_leases WHERE kind=?1 AND session<>?2 AND expires>?3");if(!s)goto storage;bind_text(s,1,observe?"observe":"trial");bind_text(s,2,session);sqlite3_bind_int64(s,3,e->now);int count=sqlite3_step(s)==SQLITE_ROW?sqlite3_column_int(s,0):99;sqlite3_finalize(s);s=NULL;if(count>=2){json_object_put(result);result=failure("lease_capacity","并发租约已达上限");goto done;}
      s=prepare(e->db,"SELECT 1 FROM aegis_ad_dns_leases WHERE session<>?1 AND (mac=?2 OR ip=?3) AND kind=?4 AND expires>?5");if(!s)goto storage;bind_text(s,1,session);bind_text(s,2,mac);bind_text(s,3,ip);bind_text(s,4,observe?"observe":"trial");sqlite3_bind_int64(s,5,e->now);int busy=sqlite3_step(s)==SQLITE_ROW;sqlite3_finalize(s);s=NULL;if(busy){json_object_put(result);result=failure("device_trial_in_use","目标设备已有其他活动租约");goto done;}
      json_object_put(result);result=json_object_new_object();boolean(result,"ok",1);txt(result,"id",str(b,"trial_id"));txt(result,"session_id",session);txt(result,"apply_state","applied");integer(result,"expires_at",e->now+ttl);json_object_object_add(result,"rules",rules?clone(rules):json_object_new_array());json_object_object_add(result,"scope",clone(get(b,"scope")));
      s=prepare(e->db,"INSERT INTO aegis_ad_dns_leases VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(session,kind) DO UPDATE SET expires=excluded.expires,document=excluded.document");if(!s)goto storage;bind_text(s,1,session);bind_text(s,2,observe?"observe":"trial");bind_text(s,3,owner);bind_text(s,4,mac);bind_text(s,5,ip);sqlite3_bind_int64(s,6,e->now+ttl);bind_text(s,7,js(result));if(step(s)){s=NULL;goto storage;}s=NULL;
    }else if(commit){if(commit_rules(e,result,b))goto storage;txt(result,"apply_state","applied");boolean(result,"saved",1);integer(result,"saved_at",e->now);
    }else {if(remove_lease(e,session,revoke?"trial":"observe"))goto storage;result=json_object_new_object();boolean(result,"ok",1);txt(result,"apply_state","reverted");}
    if(sqlite3_exec(e->db,"UPDATE aegis_ad_dns_meta SET revision=revision+1",NULL,NULL,NULL)!=SQLITE_OK)goto storage;
    integer(result,"provider_revision",revision(e));
    s=prepare(e->db,"INSERT INTO aegis_ad_dns_requests VALUES(?1,?2,?3,?4,?5)");if(!s)goto storage;bind_text(s,1,owner);bind_text(s,2,rid);bind_text(s,3,signature);bind_text(s,4,js(result));sqlite3_bind_int64(s,5,e->now);if(step(s)){s=NULL;goto storage;}s=NULL;
    if(sqlite3_exec(e->db,"DELETE FROM aegis_ad_dns_requests WHERE rowid NOT IN(SELECT rowid FROM aegis_ad_dns_requests ORDER BY created DESC,rowid DESC LIMIT 256)",NULL,NULL,NULL)!=SQLITE_OK)goto storage;
    int rc=finish(e,old);old=NULL;if(rc){json_object_put(result);result=failure("provider_apply_failed","解析器版本回读或持久化失败，已尝试恢复之前的规则");boolean(result,"rollback_ok",rc==-1);txt(result,"apply_state",rc==-1?"reverted":"rollback_failed");}
    free(signature);json_object_put(rules);return result;
storage:
    sqlite3_finalize(s);json_object_put(result);result=failure("storage_unavailable","规则事务未完成");
done:
    sqlite3_exec(e->db,"ROLLBACK",NULL,NULL,NULL);free(old);free(signature);json_object_put(rules);return result;
}

/* Canonical content-rule editor: keep exact rules in the same provider and
 * project them without invoking the legacy resolved-IP compiler or DNS restart. */
struct json_object *ad_dns_canonical(const struct ad_dns_environment *e,struct json_object *b,int deleting) {
    const char *id=str(b,"id");if(!ident(id))return failure("invalid_domain_override_id","规则标识无效");
    if(!num(b,"confirm")){struct json_object *r=json_object_new_object();boolean(r,"ok",1);boolean(r,"dry_run",1);boolean(r,"confirm_required",1);txt(r,"id",id);return r;}
    if(!num(b,"apply"))return failure("exact_rule_requires_apply","精确域名修改需要同时应用并回读");
    if(!deleting&&(!domain_ok(str(b,"domain"))||(strcmp(str(b,"action"),"block")&&strcmp(str(b,"action"),"allow"))||(*str(b,"match")&&strcmp(str(b,"match"),"exact"))||strlen(str(b,"note"))>256))return failure("invalid_rule","保留精确匹配，提供合法域名和动作");
    if(sqlite3_exec(e->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return failure("provider_busy","规则正在更新");
    char *old=snapshot(e);sqlite3_stmt *s=NULL;int rc=-1;
    if(old){s=prepare(e->db,deleting?"DELETE FROM aegis_domain_overrides WHERE id=?1 AND match_kind='exact'":"UPDATE aegis_domain_overrides SET domain=?2,action=?3,enabled=?4,note=?5,apply_state='applied',last_error='',updated_at=?6 WHERE id=?1 AND match_kind='exact'");if(s){bind_text(s,1,id);if(!deleting){bind_text(s,2,str(b,"domain"));bind_text(s,3,str(b,"action"));sqlite3_bind_int(s,4,get(b,"enabled")?num(b,"enabled"):1);bind_text(s,5,str(b,"note"));sqlite3_bind_int64(s,6,e->now);}rc=step(s);}}
    if(rc||sqlite3_changes(e->db)!=1){sqlite3_exec(e->db,"ROLLBACK",NULL,NULL,NULL);free(old);return failure("rule_update_failed","规则不存在或与现有域名冲突");}
    rc=finish(e,old);if(rc){struct json_object *r=failure("provider_apply_failed","规则未能应用，已尝试恢复");boolean(r,"rollback_ok",rc==-1);return r;}
    struct json_object *r=json_object_new_object();boolean(r,"ok",1);boolean(r,"changed",1);boolean(r,"dataplane_changed",1);txt(r,"id",id);txt(r,"apply_state",deleting?"deleted":"applied");integer(r,"provider_revision",revision(e));return r;
}
