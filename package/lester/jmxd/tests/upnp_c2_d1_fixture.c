/* Real SQLite/json-c/libuci fixture. Only process/filesystem boundaries are
 * redirected into an isolated /tmp directory; production SQL and apply run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <json-c/json.h>
#include <uci.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
#define API_CODE_SUCCESS 0
#define API_CODE_ERROR 1
#define NC_UPNP_NFT_TABLE "dreamingwrt_upnp"
static sqlite3 *g_netconfig_db;
static char confdir[512], savedir[512], runtime_path[512], render_cmd[1200];
static int fault_once, render_count, restore_count;
static int nc_exec(const char *s) { char *err=NULL; int r=sqlite3_exec(g_netconfig_db,s,NULL,NULL,&err); if(r)fprintf(stderr,"SQL: %s: %s\n",s,err);sqlite3_free(err);return r==SQLITE_OK?0:-1; }
static int nc_prepare(sqlite3_stmt **s,const char *q) { int r=sqlite3_prepare_v2(g_netconfig_db,q,-1,s,NULL);if(r)fprintf(stderr,"PREPARE %s: %s\n",q,sqlite3_errmsg(g_netconfig_db));return r==SQLITE_OK?0:-1; }
static int nc_step_done(sqlite3_stmt *s) { return sqlite3_step(s)==SQLITE_DONE?0:-1; }
static int64_t nc_now_s(void) { return 1791550000; }
static int jmx_netconfig_db_init(void) { return g_netconfig_db ? 0 : -1; }
static int nc_upnp_nft_available(void) { return 0; }
static void nc_upnp_refresh_mappings(void) { }
static void nc_upnp_add_mappings(struct json_object *o) { (void)o; }
static struct json_object *jmx_gen_api_response_data(int code,struct json_object *data) { struct json_object *r=json_object_new_object();json_object_object_add(r,"code",json_object_new_int(code));json_object_object_add(r,"data",data);return r; }
static int nc_file_exists(const char *p) { return !strcmp(p,"/etc/init.d/miniupnpd"); }
static const char *nc_uci_str(struct uci_context *c,struct uci_section *s,const char *k,const char *d) { const char *v=uci_lookup_option_string(c,s,k);return v?v:d; }
static int nc_uci_int(struct uci_context *c,struct uci_section *s,const char *k,int d) { const char *v=uci_lookup_option_string(c,s,k);return v?atoi(v):d; }
static struct uci_context *fixture_uci_alloc(void) { struct uci_context *c=uci_alloc_context();CHECK(c);CHECK(uci_set_confdir(c,confdir)==UCI_OK);CHECK(uci_set_savedir(c,savedir)==UCI_OK);return c; }
static FILE *fixture_fopen(const char *p,const char *mode) { return fopen(!strcmp(p,"/var/etc/miniupnpd.conf")?runtime_path:p,mode); }
static int copyfile(const char *a,const char *b) { FILE *in=fopen(a,"rb"),*out=NULL; char buf[4096];size_t n;if(!in)return -1;out=fopen(b,"wb");if(!out){fclose(in);return -1;}while((n=fread(buf,1,sizeof(buf),in)))CHECK(fwrite(buf,1,n,out)==n);fclose(in);return fclose(out); }
static int nc_backup_config(const char *pkg,char *b,size_t n) { char p[1024];snprintf(p,sizeof(p),"%s/%s",confdir,pkg);snprintf(b,n,"%s/upnpd.backup",savedir);return copyfile(p,b); }
static void nc_restore_config(const char *pkg,const char *b) { char p[1024];snprintf(p,sizeof(p),"%s/%s",confdir,pkg);CHECK(copyfile(b,p)==0);restore_count++; }
static void nc_cleanup_backup(const char *b) { unlink(b); }
static int jmx_uci_commit(struct uci_context *c,const char *pkg) { struct uci_ptr ptr={0};char name[64];snprintf(name,sizeof(name),"%s",pkg);CHECK(uci_lookup_ptr(c,&ptr,name,true)==UCI_OK);CHECK(ptr.p);int r=uci_commit(c,&ptr.p,false);if(ptr.p)uci_unload(c,ptr.p);return r; }
static int nc_run_quiet(const char *unused) { (void)unused;render_count++;if(system(render_cmd)!=0)return -1;if(fault_once){FILE *f=fopen(runtime_path,"a");CHECK(f);fputs("allow 1-65535 0.0.0.0/0 1-65535 # injected extra ACL\n",f);fclose(f);fault_once=0;}return 0; }

#define uci_alloc_context fixture_uci_alloc
#define fopen fixture_fopen
#include "production.inc"
#undef fopen
#undef uci_alloc_context

static int scalar(const char *q) { sqlite3_stmt *s=NULL;CHECK(nc_prepare(&s,q)==0);CHECK(sqlite3_step(s)==SQLITE_ROW);int n=sqlite3_column_int(s,0);sqlite3_finalize(s);return n; }
static char *text_value(const char *q) { sqlite3_stmt *s=NULL;CHECK(nc_prepare(&s,q)==0);CHECK(sqlite3_step(s)==SQLITE_ROW);char *v=strdup((const char *)sqlite3_column_text(s,0));sqlite3_finalize(s);return v; }
static char *read_file(const char *p) { FILE *f=fopen(p,"rb");CHECK(f);CHECK(fseek(f,0,SEEK_END)==0);long size=ftell(f);CHECK(size>=0);rewind(f);char *s=calloc((size_t)size+1,1);CHECK(s);CHECK(fread(s,1,(size_t)size,f)==(size_t)size);fclose(f);return s; }
static void write_file(const char *p,const char *s) { FILE *f=fopen(p,"wb");CHECK(f);CHECK(fwrite(s,1,strlen(s),f)==strlen(s));CHECK(fclose(f)==0); }
static struct json_object *member(struct json_object *o,const char *key) { struct json_object *v=NULL;CHECK(json_object_object_get_ex(o,key,&v));return v; }
static int set_service(const char *s) { struct json_object *o=json_tokener_parse(s);CHECK(o);int r=jmx_upnp_service_set(o);json_object_put(o);return r; }
static struct json_object *save_service(const char *s) { struct json_object *o=json_tokener_parse(s);CHECK(o);struct json_object *r=jmx_upnp_service_save_apply_result(o);json_object_put(o);return r; }
static void seed_uci(int defaults) {
 char path[1024];snprintf(path,sizeof(path),"%s/upnpd",confdir);FILE *f=fopen(path,"w");CHECK(f);
 fputs("config upnpd 'config'\n option enabled '1'\n option enable_upnp '1'\n option enable_natpmp '1'\n option use_stun '1'\n option stun_host 'stun.example.org'\n option stun_port '3479'\n option enable_pcp_pmp '1'\n option clean_ruleset_interval '60'\n option uuid 'fixture-uuid'\n list internal_iface 'lan'\n",f);
 fputs("config perm_rule 'deny_first'\n option action 'deny'\n option ext_ports '0-1023'\n option int_addr '0.0.0.0/0'\n option int_ports '0-65535'\n option comment 'Keep first'\n",f);
 if(defaults)fputs("config perm_rule 'default_allow'\n option action 'allow'\n option ext_ports '1024-65535'\n option int_addr '0.0.0.0/0'\n option int_ports '1024-65535'\n option comment 'Default'\n",f);
 fputs("config perm_rule 'custom'\n option action 'allow'\n option ext_ports '900'\n option int_addr '192.0.2.5'\n option int_ports '900'\n option comment 'Keep custom'\n",f);
 if(defaults)fputs("config perm_rule 'duplicate'\n option action 'allow'\n option ext_ports '1024:65535'\n option int_addr '0.0.0.0/0'\n option int_ports '1024:65535'\n",f);
 fputs("config perm_rule 'deny_last'\n option action 'deny'\n option ext_ports '0-65535'\n option int_addr '0.0.0.0/0'\n option int_ports '0-65535'\n",f);fclose(f);
}
static void fresh(int legacy,int defaults) {
 if(g_netconfig_db)sqlite3_close(g_netconfig_db);CHECK(sqlite3_open(":memory:",&g_netconfig_db)==SQLITE_OK);
 CHECK(nc_exec(legacy?legacy_schema:current_schema)==0);
 CHECK(nc_exec("INSERT INTO upnp_service(id,uuid) VALUES(1,'fixture-uuid');CREATE TABLE lan(id TEXT);INSERT INTO lan VALUES('lan');CREATE TABLE wan(id TEXT,ifname TEXT);")==0);
 if(legacy)CHECK(nc_exec("UPDATE upnp_service SET force_forwarding=1,port_start=2345;ALTER TABLE upnp_service ADD COLUMN future_field TEXT DEFAULT 'preserve';")==0);
 CHECK(fixture_migrate()==0);CHECK(fixture_migrate()==0);CHECK(!nc_table_has_column("upnp_service","force_forwarding"));
 if(legacy){CHECK(scalar("SELECT port_start FROM upnp_service")==2345);char *v=text_value("SELECT future_field FROM upnp_service");CHECK(!strcmp(v,"preserve"));free(v);}
 seed_uci(defaults);g_nc_upnp_readback_failed=0;fault_once=0;CHECK(nc_upnp_import_uci_once()==0);
}
static void check_caps(int range,int runtime) {
 struct json_object *r=jmx_upnp_service_get(),*d=member(r,"data"),*c=member(d,"capabilities"),*v=NULL;
 CHECK(!json_object_object_get_ex(d,"force_forwarding",&v));CHECK(!json_object_object_get_ex(c,"force_forwarding",&v));
 CHECK(json_object_get_boolean(member(c,"port_range"))==range);CHECK(json_object_get_boolean(member(c,"port_range_runtime_verified"))==runtime);json_object_put(r);
}
int main(int argc,char **argv) {
 CHECK(argc==3);CHECK(strlen(argv[1])<180);snprintf(confdir,sizeof(confdir),"%s/config",argv[1]);snprintf(savedir,sizeof(savedir),"%s/state",argv[1]);snprintf(runtime_path,sizeof(runtime_path),"%s/runtime.conf",argv[1]);snprintf(render_cmd,sizeof(render_cmd),"bash '%s' '%s' '%s' '%s'",argv[2],confdir,savedir,runtime_path);mkdir(confdir,0700);mkdir(savedir,0700);
 fresh(1,1);
 CHECK(scalar("SELECT COUNT(*) FROM upnp_acl")==4);CHECK(scalar("SELECT sort_order FROM upnp_acl WHERE managed='port_range'")==1);
 char *id=text_value("SELECT id FROM upnp_acl WHERE managed='port_range'");CHECK(!strcmp(id,"migrated_1"));free(id);
 CHECK(scalar("SELECT use_stun AND pcp AND stun_port=3479 AND clean_interval=60 FROM upnp_service")==1);
 CHECK(scalar("SELECT port_start=1024 AND port_end=65535 FROM upnp_service")==1);
 CHECK(nc_upnp_manage_default_acl()==0);CHECK(scalar("SELECT COUNT(*) FROM upnp_acl")==4);
 CHECK(jmx_upnp_service_apply()==0);CHECK(nc_upnp_runtime_readback()==0);check_caps(1,1);
 puts("PASS legacy/new schema migration, duplicate default dedupe, original ID/order, custom/deny preservation, import and real init readback");
 char *original=read_file(runtime_path),*mutated=strdup(original),*first=strstr(mutated,"deny 0-1023 "),*next=strchr(first,'\n')+1;
 CHECK(first&&next);memmove(first,next,strlen(next)+1);write_file(runtime_path,mutated);CHECK(nc_upnp_runtime_readback()==-1);free(mutated);
 mutated=strdup(original);char *allow=strstr(mutated,"allow 1024-65535 ");CHECK(allow);allow[9]='5';write_file(runtime_path,mutated);CHECK(nc_upnp_runtime_readback()==-1);free(mutated);
 mutated=strdup(original);first=strstr(mutated,"deny 0-1023 ");next=strchr(first,'\n')+1;char *after=strchr(next,'\n')+1;size_t len1=(size_t)(next-first),len2=(size_t)(after-next);char *line=strndup(first,len1);memmove(first,next,len2);memcpy(first+len2,line,len1);free(line);write_file(runtime_path,mutated);CHECK(nc_upnp_runtime_readback()==-1);free(mutated);write_file(runtime_path,original);free(original);
 struct uci_context *uc=fixture_uci_alloc();struct uci_package *up=NULL;CHECK(uci_load(uc,"upnpd",&up)==UCI_OK);CHECK(nc_uci_set_pkg(uc,"upnpd","dw_migrated_1","ext_ports","7777-8888")==0);CHECK(jmx_uci_commit(uc,"upnpd")==UCI_OK);uci_free_context(uc);CHECK(nc_upnp_runtime_readback()==-1);CHECK(jmx_upnp_service_apply()==0);
 puts("PASS missing/changed/reordered generated ACL and independent UCI mismatch all rejected");
 CHECK(set_service("{\"port_range\":{\"start\":2000}} ")==0);CHECK(scalar("SELECT port_start=2000 AND port_end=65535 FROM upnp_service")==1);
 CHECK(set_service("{\"port_end\":3000}")==0);CHECK(jmx_upnp_service_apply()==0);CHECK(nc_upnp_runtime_readback()==0);
 char *ext=text_value("SELECT external_ports FROM upnp_acl WHERE managed='port_range'");CHECK(!strcmp(ext,"2000-3000"));free(ext);
 CHECK(set_service("{\"port_start\":2001,\"port_range\":{\"start\":2001}}")==0);
 const char *invalid[]={"{\"port_start\":0}","{\"port_end\":65536}","{\"port_start\":3001}","{\"port_start\":1.5}","{\"port_start\":\"2001\"}","{\"port_start\":true}","{\"port_start\":null}","{\"port_range\":null}","{\"port_range\":[]}","{\"port_start\":2001,\"port_range\":{\"start\":2002}}","{\"port_start\":9223372036854775807}"};
 for(size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++){CHECK(set_service(invalid[i])==-2);CHECK(scalar("SELECT port_start=2001 AND port_end=3000 FROM upnp_service")==1);}
 CHECK(set_service("{\"force_forwarding\":false}")==-3);
 struct json_object *r=save_service("{\"force_forwarding\":false}");CHECK(!strcmp(json_object_get_string(member(member(r,"data"),"reason")),"upnp_force_forwarding_removed"));json_object_put(r);
 puts("PASS partial range merge, aliases, strict invalid inputs without DB changes, obsolete field explicit rejection");
 struct json_object *bad=json_tokener_parse("{\"id\":\"migrated_1\",\"external\":\"1-65535\"}");CHECK(jmx_upnp_acl_set(bad)==-3);json_object_put(bad);CHECK(jmx_upnp_acl_delete("migrated_1")==-3);
 r=jmx_upnp_service_get();struct json_object *d=member(r,"data"),*acl=member(d,"acl"),*managed=json_object_array_get_idx(acl,1);
 CHECK(!strcmp(json_object_get_string(member(managed,"managed")),"port_range"));CHECK(!json_object_get_boolean(member(managed,"editable")));CHECK(!json_object_get_boolean(member(managed,"deletable")));
 CHECK(jmx_upnp_service_set(d)==0);json_object_object_add(managed,"enabled",json_object_new_boolean(0));CHECK(jmx_upnp_service_set(d)==-3);json_object_put(r);
 CHECK(set_service("{\"acl\":[],\"port_range\":{\"start\":2100,\"end\":2200}}")==0);CHECK(scalar("SELECT COUNT(*) FROM upnp_acl")==1);
 CHECK(set_service("{\"acl\":[{\"id\":\"bad\",\"external\":\"invalid\"}]}")==-2);CHECK(scalar("SELECT COUNT(*) FROM upnp_acl")==1);
 puts("PASS managed ACL edit/delete/bulk protection, snapshot roundtrip, invalid bulk transaction rollback");
 fresh(0,1);CHECK(jmx_upnp_service_apply()==0);int before_restore=restore_count;
 fault_once=1;r=save_service("{\"port_range\":{\"start\":2100,\"end\":2200}}");d=member(r,"data");
 CHECK(!json_object_get_boolean(member(d,"ok")));CHECK(json_object_get_boolean(member(d,"runtime_rolled_back")));CHECK(!json_object_get_boolean(member(d,"persisted")));CHECK(!strcmp(json_object_get_string(member(d,"error")),"upnp_runtime_readback_mismatch"));json_object_put(r);
 CHECK(restore_count==before_restore+1);CHECK(scalar("SELECT port_start=1024 AND port_end=65535 FROM upnp_service")==1);CHECK(nc_upnp_runtime_readback()==0);CHECK(g_nc_upnp_readback_failed);check_caps(0,0);
 r=save_service("{\"port_range\":{\"start\":2100,\"end\":2200},\"use_stun\":false,\"pcp\":false,\"clean_interval\":0}");CHECK(json_object_get_boolean(member(member(r,"data"),"ok")));json_object_put(r);check_caps(1,1);
 puts("PASS injected generated ACL mismatch: DB/UCI/runtime rollback, failure capability latch and subsequent valid recovery; STUN/PCP/cleanup off/zero");
 CHECK(set_service("{\"enabled\":false,\"port_start\":2150}")==0);CHECK(jmx_upnp_service_apply()==0);CHECK(nc_upnp_runtime_readback()==1);check_caps(1,0);
 fresh(1,0);CHECK(nc_upnp_managed_acl_id(NULL,0)==0);CHECK(set_service("{\"port_start\":2000}")==-3);CHECK(set_service("{\"port_range\":{\"start\":2345,\"end\":65535}}")==-3);CHECK(jmx_upnp_service_apply()==0);check_caps(0,0);
 CHECK(scalar("SELECT COUNT(*) FROM upnp_acl")==3);CHECK(set_service("{\"notify_interval\":60}")==0);
 CHECK(jmx_upnp_service_apply()==0);fault_once=1;r=save_service("{\"notify_interval\":61}");d=member(r,"data");CHECK(json_object_get_boolean(member(d,"runtime_rolled_back")));json_object_put(r);CHECK(scalar("SELECT notify_interval FROM upnp_service")==60);CHECK(nc_upnp_runtime_readback()==0);CHECK(scalar("SELECT COUNT(*) FROM upnp_acl")==3);
 puts("PASS disabled service UCI proof and custom-only policy without synthetic allow; unrelated settings remain writable");
 /* Already-imported old DB: don't import UCI over saved custom settings. */
 fresh(1,1);CHECK(nc_exec("DELETE FROM upnp_migration_state WHERE key='default_allow_v1';UPDATE upnp_acl SET managed='';UPDATE upnp_service SET port_start=8888,notify_interval=77;INSERT INTO upnp_acl(id,external_ports,internal_ports,sort_order) VALUES('legacy_duplicate','1024-65535','1024-65535',9);")==0);
 CHECK(nc_upnp_import_uci_once()==0);CHECK(scalar("SELECT notify_interval FROM upnp_service")==77);CHECK(scalar("SELECT port_start FROM upnp_service")==1024);CHECK(scalar("SELECT COUNT(*) FROM upnp_acl")==4);CHECK(scalar("SELECT sort_order FROM upnp_acl WHERE managed='port_range'")==1);
 puts("PASS existing imported DB migration preserves service settings and original ACL order");
 sqlite3_close(g_netconfig_db);printf("PASS all C2/D1 SQLite/libuci/init cases (%d render operations)\n",render_count);return 0;
}
