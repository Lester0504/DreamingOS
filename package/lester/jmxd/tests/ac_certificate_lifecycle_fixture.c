// SPDX-License-Identifier: GPL-2.0-or-later
#define APD_CREDENTIALS_TEST_STANDALONE
#include "../src/apd/apd_credentials.c"
#include "../src/ac/ac_certificate_lifecycle.h"
#include "../src/ap_control_wire.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <time.h>

static const char *ap_ids[] = {"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"};
static const char *old_ids[] = {"cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"};
static EVP_PKEY *keys[2];
static SSL_CTX *server_context;
static int selected_ap, fail_reload;
static char directories[2][4096], db_path[4096];
static sqlite3 *database;
int apd_enrollment_csr_create(unsigned char *, size_t, size_t *, unsigned char[32]);
int fixture_peer_authorize(sqlite3 *, const char *, const char *, const unsigned char[32]);
int64_t apd_now_s(void) { return time(NULL); }
int apd_db_identity_get(struct apd_node_identity *out)
{
    size_t length = 32;
    memset(out, 0, sizeof(*out));
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", ap_ids[selected_ap]);
    snprintf(out->key_id, sizeof(out->key_id), "sha256:%064d", selected_ap);
    return EVP_PKEY_get_raw_public_key(keys[selected_ap], out->public_key, &length) == 1 && length == 32 ? 0 : -1;
}
EVP_PKEY *apd_identity_key_open(void) { assert(EVP_PKEY_up_ref(keys[selected_ap]) == 1); return keys[selected_ap]; }
static void select_ap(int ap) { selected_ap = ap; assert(setenv("DREAMINGWRT_APD_PKI_DIR", directories[ap], 1) == 0); }
static SSL_CTX *server_new(struct ac_pki *pki)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    X509 *cert = ac_pki_server_certificate_dup(pki), *ca = ac_pki_ca_certificate_dup(pki), *alt = ac_pki_alternate_ca_dup(pki);
    EVP_PKEY *key = ac_pki_server_private_key_dup(pki);
    assert(ctx && cert && key && ca);
    assert(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1);
    assert(SSL_CTX_use_certificate(ctx, cert) == 1 && SSL_CTX_use_PrivateKey(ctx, key) == 1);
    assert(X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca) == 1);
    if (alt && X509_cmp(alt, ca)) assert(X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), alt) == 1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    X509_free(cert); X509_free(ca); X509_free(alt); EVP_PKEY_free(key); return ctx;
}
int ac_transport_certificate_reload(void)
{
    struct ac_pki *pki = NULL; SSL_CTX *next;
    if (fail_reload) return -1;
    if (ac_pki_init(&pki)) return -1;
    next = server_new(pki); ac_pki_free(pki); SSL_CTX_free(server_context); server_context = next;
    return 0;
}
static void sql(const char *text) { char *err=NULL; if(sqlite3_exec(database,text,NULL,NULL,&err)!=SQLITE_OK){fprintf(stderr,"sql: %s\n",err);abort();} }
static int count(const char *text) {sqlite3_stmt *st=NULL;assert(sqlite3_prepare_v2(database,text,-1,&st,NULL)==SQLITE_OK);assert(sqlite3_step(st)==SQLITE_ROW);int n=sqlite3_column_int(st,0);sqlite3_finalize(st);return n;}
static void prepare_ap(int ap, struct ac_pki *pki)
{
    struct apd_enrollment_metadata metadata = {0};
    struct apd_node_identity identity;
    struct ac_pki_issued_certificate *issued=NULL;
    unsigned char csr[2048], digest[32], *pem=NULL; size_t csr_len=0,pem_len=0,der_len=0;
    const unsigned char *der;
    sqlite3_stmt *st=NULL;
    select_ap(ap); assert(mkdir(directories[ap],0700)==0);
    EVP_PKEY_CTX *keyctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
    assert(keyctx && EVP_PKEY_keygen_init(keyctx)==1 && EVP_PKEY_keygen(keyctx,&keys[ap])==1);EVP_PKEY_CTX_free(keyctx);
    assert(apd_db_identity_get(&identity)==0 && apd_enrollment_csr_create(csr,sizeof(csr),&csr_len,digest)==0);
    assert(ac_pki_issue_ap_certificate(pki,identity.ap_id,identity.public_key,csr,csr_len,&issued)==0);
    der=ac_pki_issued_certificate_der(issued,&der_len);assert(ac_pki_trust_pem(pki,&pem,&pem_len)==0);
    assert(apd_credentials_atomic_write(directories[ap],APD_CREDENTIALS_CA_FILE,pem,pem_len)==0);
    char path[4096]; assert(apd_credentials_path(path,sizeof(path),directories[ap],APD_CREDENTIALS_CA_FILE)==0);
    metadata.version=1;metadata.controller_port=18443;
    snprintf(metadata.controller_id,sizeof(metadata.controller_id),"%s",ac_pki_controller_id(pki));
    snprintf(metadata.controller_host,sizeof(metadata.controller_host),"ac.test");
    snprintf(metadata.enrollment_id,sizeof(metadata.enrollment_id),"%s",ap_ids[ap]);
    snprintf(metadata.certificate_id,sizeof(metadata.certificate_id),"%s",old_ids[ap]);
    snprintf(metadata.state,sizeof(metadata.state),"adopted");
    assert(apd_credentials_certificate_validate(der,der_len,path,&metadata)==0);
    unsigned char encoded[16384];size_t length=0;assert(apd_credentials_metadata_encode(&metadata,encoded,sizeof(encoded),&length)==0);
    assert(apd_credentials_atomic_write(directories[ap],APD_CREDENTIALS_CERT_FILE,der,der_len)==0);
    assert(apd_credentials_atomic_write(directories[ap],APD_CREDENTIALS_METADATA_FILE,encoded,length)==0);
    assert(sqlite3_prepare_v2(database,"INSERT INTO ac_device_certificates(certificate_id,ap_id,serial,key_id,not_before,not_after,state,certificate_der,fingerprint_sha256,issuer_key_id,issued_at) VALUES(?1,?2,'initial','node',?3,?4,'active',?5,?6,'initial',?7)",-1,&st,NULL)==SQLITE_OK);
    sqlite3_bind_text(st,1,old_ids[ap],-1,SQLITE_STATIC);sqlite3_bind_text(st,2,ap_ids[ap],-1,SQLITE_STATIC);sqlite3_bind_int64(st,3,metadata.not_before);sqlite3_bind_int64(st,4,metadata.not_after);sqlite3_bind_blob(st,5,der,(int)der_len,SQLITE_TRANSIENT);sqlite3_bind_blob(st,6,ac_pki_issued_certificate_fingerprint_sha256(issued),32,SQLITE_TRANSIENT);sqlite3_bind_int64(st,7,time(NULL));assert(sqlite3_step(st)==SQLITE_DONE);sqlite3_finalize(st);
    assert(sqlite3_prepare_v2(database,"INSERT INTO ac_enrollments VALUES(?1,?2,'adopted',?3,?4,'node',0)",-1,&st,NULL)==SQLITE_OK);sqlite3_bind_text(st,1,ap_ids[ap],-1,SQLITE_STATIC);sqlite3_bind_text(st,2,ap_ids[ap],-1,SQLITE_STATIC);sqlite3_bind_text(st,3,old_ids[ap],-1,SQLITE_STATIC);sqlite3_bind_blob(st,4,identity.public_key,32,SQLITE_TRANSIENT);assert(sqlite3_step(st)==SQLITE_DONE);sqlite3_finalize(st);
    OPENSSL_free(pem);ac_pki_issued_certificate_free(issued);
}
static SSL *handshake(int ap, SSL_CTX *server, SSL **server_ssl)
{
    struct apd_enrollment_metadata metadata;
    unsigned char *der=NULL,*pem=NULL;size_t der_len=0,pem_len=0;
    char path[4096];BIO *bio,*left,*right;X509 *ca,*cert;const unsigned char *cursor;
    select_ap(ap);assert(apd_credentials_validate_startup(&metadata)==0);
    assert(apd_credentials_path(path,sizeof(path),apd_credentials_pki_dir(),APD_CREDENTIALS_CERT_FILE)==0);
    assert(apd_credentials_read_binary_secure(path,65536,&der,&der_len)==0);cursor=der;cert=d2i_X509(NULL,&cursor,(long)der_len);assert(cert);
    assert(apd_credentials_read_secure(metadata.ca_cert_pem_path,65536,&pem,&pem_len)==0);bio=BIO_new_mem_buf(pem,(int)pem_len);
    SSL_CTX *client=SSL_CTX_new(TLS_client_method());assert(client);SSL_CTX_set_verify(client,SSL_VERIFY_PEER,NULL);assert(SSL_CTX_set_min_proto_version(client,TLS1_3_VERSION)==1);
    while((ca=PEM_read_bio_X509(bio,NULL,NULL,NULL))){assert(X509_STORE_add_cert(SSL_CTX_get_cert_store(client),ca)==1);X509_free(ca);}BIO_free(bio);ERR_clear_error();
    assert(SSL_CTX_use_certificate(client,cert)==1 && SSL_CTX_use_PrivateKey(client,keys[ap])==1);X509_free(cert);free(der);free(pem);
    SSL *c=SSL_new(client),*s=SSL_new(server);assert(c&&s&&BIO_new_bio_pair(&left,0,&right,0)==1);SSL_set_bio(c,left,left);SSL_set_bio(s,right,right);SSL_set_connect_state(c);SSL_set_accept_state(s);assert(SSL_set1_host(c,"ac.test")==1);SSL_CTX_free(client);
    for(int i=0;i<100&&! (SSL_is_init_finished(c)&&SSL_is_init_finished(s));i++){
        int a=SSL_do_handshake(c);if(a!=1){int e=SSL_get_error(c,a);if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE){ERR_print_errors_fp(stderr);abort();}}
        a=SSL_do_handshake(s);if(a!=1){int e=SSL_get_error(s,a);if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE){ERR_print_errors_fp(stderr);abort();}}
    }
    assert(SSL_is_init_finished(c)&&SSL_is_init_finished(s));*server_ssl=s;return c;
}
static int poll_ap(int ap, SSL_CTX *ctx, int apply)
{
    struct apd_enrollment_metadata metadata;
    unsigned char csr[2048],csr_hash[32],peer[32],server[32],trust[32];size_t csr_len=0;unsigned int n=0;
    SSL *s,*c=handshake(ap,ctx?ctx:server_context,&s);X509 *peer_cert=SSL_get1_peer_certificate(s);
    assert(apd_credentials_validate_startup(&metadata)==0 && apd_credentials_trust_fingerprint(trust)==0);
    assert(apd_enrollment_csr_create(csr,sizeof(csr),&csr_len,csr_hash)==0);
    assert(X509_digest(peer_cert,EVP_sha256(),peer,&n)==1&&n==32);X509_free(peer_cert);
    assert(X509_digest(SSL_get_certificate(s),EVP_sha256(),server,&n)==1&&n==32);
    assert(fixture_peer_authorize(database,metadata.certificate_id,metadata.ap_id,peer));
    struct json_object *result=ac_certificate_lifecycle_poll(database,metadata.ap_id,metadata.certificate_id,peer,server,trust,csr,csr_len);
    struct json_object *field=NULL; if(json_object_object_get_ex(result,"error",&field)){fprintf(stderr,"poll: %s\n",json_object_to_json_string(result));abort();}
    const char *action=json_object_get_string(json_object_object_get(result,"action"));assert(action);
    int changed=strcmp(action,"idle")!=0;
    if(apply&&!strcmp(action,"install")){
        const char *hex=json_object_get_string(json_object_object_get(result,"certificate_der"));size_t length=strlen(hex)/2,used=0;unsigned char *der=malloc(length);
        assert(ap_control_hex_decode(hex,der,length,&used)==0);
        const char *pem=json_object_get_string(json_object_object_get(result,"trust_pem"));
        if (getenv("APD_CREDENTIALS_TEST_ROTATION_INTERRUPT")) {
            char before[4096];snprintf(before,sizeof(before),"%s",apd_credentials_pki_dir());
            assert(apd_credentials_rotation_install(json_object_get_string(json_object_object_get(result,"task_id")),json_object_get_string(json_object_object_get(result,"certificate_id")),der,length,pem,strlen(pem))!=0);
            assert(!strcmp(before,apd_credentials_pki_dir()));
        } else assert(apd_credentials_rotation_install(json_object_get_string(json_object_object_get(result,"task_id")),json_object_get_string(json_object_object_get(result,"certificate_id")),der,length,pem,strlen(pem))==0);
        free(der);
    }else if(apply&&!strcmp(action,"trust_commit")){
        const char *pem=json_object_get_string(json_object_object_get(result,"trust_pem"));assert(apd_credentials_rotation_trust_commit(pem,strlen(pem))==0);
    }
    json_object_put(result);SSL_free(c);SSL_free(s);return changed;
}
static struct json_object *request(const char *action,const char *id,const char *operation,const char *ap)
{
    struct json_object *req=json_object_new_object();
    json_object_object_add(req,"action",json_object_new_string(action));json_object_object_add(req,!strcmp(action,"submit")?"request_id":"task_id",json_object_new_string(id));
    json_object_object_add(req,"operation",json_object_new_string(operation));json_object_object_add(req,"ap_id",json_object_new_string(ap));json_object_object_add(req,"actor",json_object_new_string("isolated-test"));json_object_object_add(req,"reason",json_object_new_string("certificate fixture"));json_object_object_add(req,"confirmed",json_object_new_boolean(1));
    struct json_object *result=ac_certificate_lifecycle_request(database,req);json_object_put(req);return result;
}
static void expect_state(const char *id,const char *state)
{
    struct json_object *r=request("status",id,"","");
    struct json_object *task=json_object_array_get_idx(json_object_object_get(r,"tasks"),0);assert(task);
    if(strcmp(json_object_get_string(json_object_object_get(task,"state")),state)){fprintf(stderr,"status wanted %s: %s\n",state,json_object_to_json_string(r));abort();}json_object_put(r);
}

static void readiness_failures(void)
{
    sqlite3 *readonly = NULL;
    int before = sqlite3_total_changes(database);
    assert(ac_certificate_lifecycle_ready(database));
    assert(sqlite3_total_changes(database) == before);
    sql("PRAGMA query_only=ON"); assert(!ac_certificate_lifecycle_ready(database));
    sql("PRAGMA query_only=OFF");
    assert(sqlite3_open_v2(db_path, &readonly, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
    assert(!ac_certificate_lifecycle_ready(readonly)); sqlite3_close(readonly);
    sql("ALTER TABLE ac_certificate_audit RENAME TO unavailable_audit");
    assert(!ac_certificate_lifecycle_ready(database));
    sql("ALTER TABLE unavailable_audit RENAME TO ac_certificate_audit");
    assert(ac_certificate_lifecycle_ready(database));
    puts("PASS capability store readiness: missing schema, read-only and query-only fail closed; reads do not mutate");
}

static void rejected_poll(const char *task, int issued)
{
    struct apd_enrollment_metadata metadata;
    unsigned char csr[2048], digest[32], peer[32], server[32], trust[32];
    size_t csr_len = 0; unsigned int n = 0;
    select_ap(0); assert(apd_credentials_validate_startup(&metadata) == 0);
    assert(apd_enrollment_csr_create(csr, sizeof(csr), &csr_len, digest) == 0);
    assert(apd_credentials_trust_fingerprint(trust) == 0);
    assert(X509_digest(SSL_CTX_get0_certificate(server_context), EVP_sha256(), server, &n) == 1 && n == 32);
    memset(peer, 0, sizeof(peer));
    int before = count("SELECT count(*) FROM ac_device_certificates");
    struct json_object *r;
    if (!issued) {
        csr[csr_len - 1] ^= 1;
        r = ac_certificate_lifecycle_poll(database, metadata.ap_id, metadata.certificate_id,
                                          peer, server, trust, csr, csr_len);
        assert(!strcmp(json_object_get_string(json_object_object_get(r, "error")), "certificate_csr_rejected"));
    } else {
        sqlite3_stmt *st = NULL;
        char next[37];
        assert(sqlite3_prepare_v2(database, "SELECT new_certificate_id FROM ac_certificate_targets WHERE task_id=?1", -1, &st, NULL) == SQLITE_OK);
        sqlite3_bind_text(st, 1, task, -1, SQLITE_STATIC); assert(sqlite3_step(st) == SQLITE_ROW);
        snprintf(next, sizeof(next), "%s", sqlite3_column_text(st, 0)); sqlite3_finalize(st);
        r = ac_certificate_lifecycle_poll(database, metadata.ap_id, next,
                                          peer, server, trust, csr, csr_len);
        assert(!strcmp(json_object_get_string(json_object_object_get(r, "error")), "certificate_mtls_proof_rejected"));
    }
    json_object_put(r);
    assert(count("SELECT count(*) FROM ac_device_certificates") == before);
    assert(count("SELECT revoked_at FROM ac_device_certificates WHERE certificate_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'") == 0);
    r = ac_certificate_lifecycle_poll(database, metadata.ap_id, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                                      peer, server, trust, csr, csr_len);
    assert(!strcmp(json_object_get_string(json_object_object_get(r, "error")), "certificate_task_identity_mismatch"));
    json_object_put(r);
}

static void explicit_revocation(void)
{
    struct apd_enrollment_metadata metadata;
    struct json_object *req = json_object_new_object(), *r;
    select_ap(1); assert(apd_credentials_validate_startup(&metadata) == 0);
    const char *task = "aaaaaaaa-1111-4111-8111-111111111111";
    r=request("submit",task,"ap_renew",ap_ids[1]);json_object_put(r);
    assert(poll_ap(1,NULL,0)==1);
    json_object_object_add(req, "action", json_object_new_string("revoke"));
    json_object_object_add(req, "certificate_id", json_object_new_string(metadata.certificate_id));
    json_object_object_add(req, "actor", json_object_new_string("isolated-test"));
    json_object_object_add(req, "reason", json_object_new_string("retire AP"));
    r = ac_certificate_lifecycle_request(database, req);
    assert(!strcmp(json_object_get_string(json_object_object_get(r, "error")), "operator_confirmation_required"));
    json_object_put(r);
    assert(count("SELECT count(*) FROM ac_enrollments WHERE state='adopted'") == 2);
    json_object_object_add(req, "confirmed", json_object_new_boolean(1));
    sql("CREATE TRIGGER fail_revoke_audit BEFORE INSERT ON ac_certificate_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END");
    r = ac_certificate_lifecycle_request(database, req);
    assert(!strcmp(json_object_get_string(json_object_object_get(r, "error")), "certificate_store_unavailable"));
    json_object_put(r);
    assert(count("SELECT count(*) FROM ac_enrollments WHERE state='adopted'") == 2);
    sql("DROP TRIGGER fail_revoke_audit");
    r = ac_certificate_lifecycle_request(database, req);
    assert(json_object_get_boolean(json_object_object_get(r, "ok"))); json_object_put(r);
    assert(count("SELECT count(*) FROM ac_enrollments WHERE state='revoked'") == 1);
    assert(count("SELECT count(*) FROM ac_certificate_audit WHERE action='revoke' AND actor='isolated-test' AND reason='retire AP'") == 1);
    sqlite3_stmt *st = NULL;
    assert(sqlite3_prepare_v2(database, "SELECT certificate_id,fingerprint_sha256 FROM ac_device_certificates WHERE ap_id=?1 AND state='active'", -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_text(st,1,ap_ids[1],-1,SQLITE_STATIC);
    while(sqlite3_step(st)==SQLITE_ROW)
        assert(!fixture_peer_authorize(database,(const char *)sqlite3_column_text(st,0),ap_ids[1],sqlite3_column_blob(st,1)));
    sqlite3_finalize(st);
    json_object_put(req);
    puts("PASS explicit revoke requires confirmation and reason; audit failure rolls back; revoked AP cannot authorize even a previously issued replacement certificate");
}

static void tls_retired_ca_rejected(void)
{
    char path[4096]; unsigned char *der=NULL;size_t length=0;
    select_ap(0);assert(apd_credentials_path(path,sizeof(path),directories[0],APD_CREDENTIALS_CERT_FILE)==0);
    assert(apd_credentials_read_binary_secure(path,65536,&der,&length)==0);
    const unsigned char *cursor=der;X509 *old=d2i_X509(NULL,&cursor,(long)length);assert(old);free(der);
    SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());assert(ctx);assert(SSL_CTX_use_certificate(ctx,old)==1&&SSL_CTX_use_PrivateKey(ctx,keys[0])==1);X509_free(old);
    SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);SSL *client=SSL_new(ctx),*server=SSL_new(server_context);SSL_CTX_free(ctx);BIO *a,*b;assert(BIO_new_bio_pair(&a,0,&b,0)==1);SSL_set_bio(client,a,a);SSL_set_bio(server,b,b);SSL_set_connect_state(client);SSL_set_accept_state(server);
    int rejected=0;
    for(int i=0;i<100&&!rejected;i++) {
        (void)SSL_do_handshake(client);int r=SSL_do_handshake(server);
        if(r!=1){int e=SSL_get_error(server,r);if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE) rejected=1;}
        if(SSL_is_init_finished(server)) break;
    }
    assert(rejected && SSL_get_verify_result(server)!=X509_V_OK);ERR_clear_error();SSL_free(client);SSL_free(server);
}
static void pending_and_reload_failures(const char *base)
{
    const char *pending="66666666-6666-4666-8666-666666666666";
    struct json_object *r;struct ac_pki *before=NULL,*after=NULL;
    assert(ac_pki_init(&before)==0);char generation[37];snprintf(generation,sizeof(generation),"%s",ac_pki_generation(before));ac_pki_free(before);
    setenv("AC_PKI_TEST_INTERRUPT_AFTER","server-key",1);
    r=request("submit",pending,"server_renew","");json_object_put(r);unsetenv("AC_PKI_TEST_INTERRUPT_AFTER");expect_state(pending,"queued");
    char path[4096];snprintf(path,sizeof(path),"%s/ac/gen-%s/server.ed25519",base,pending);
    int fd=open(path,O_WRONLY|O_TRUNC|O_NOFOLLOW);assert(fd>=0&&write(fd,"bad",3)==3);close(fd);
    r=request("retry",pending,"","");json_object_put(r);expect_state(pending,"queued");
    assert(ac_pki_generation_activate(pending)!=0);assert(ac_pki_init(&after)==0&&!strcmp(ac_pki_generation(after),generation));ac_pki_free(after);
    r=request("cancel",pending,"","");json_object_put(r);expect_state(pending,"cancelled");
    const char *reload="77777777-7777-4777-8777-777777777777";
    fail_reload=1;r=request("submit",reload,"server_renew","");json_object_put(r);expect_state(reload,"activating");
    assert(ac_pki_init(&after)==0&&!strcmp(ac_pki_generation(after),generation));ac_pki_free(after);
    fail_reload=0;r=request("retry",reload,"","");json_object_put(r);expect_state(reload,"confirming");r=request("rollback",reload,"","");json_object_put(r);expect_state(reload,"rolled_back");
}
static void invalid_time_is_not_published(void)
{
    select_ap(0);struct apd_enrollment_metadata metadata;assert(apd_credentials_validate_startup(&metadata)==0);
    unsigned char *der=NULL,*pem=NULL;size_t length=0,pem_len=0;char path[4096],before[4096];snprintf(before,sizeof(before),"%s",apd_credentials_pki_dir());
    assert(apd_credentials_path(path,sizeof(path),before,APD_CREDENTIALS_CERT_FILE)==0&&apd_credentials_read_binary_secure(path,65536,&der,&length)==0);
    const unsigned char *cursor=der;X509 *cert=d2i_X509(NULL,&cursor,(long)length);free(der);assert(cert);assert(X509_gmtime_adj(X509_getm_notBefore(cert),86400));
    struct ac_pki *pki=NULL;assert(ac_pki_init(&pki)==0);
    const char *generation=ac_pki_generation(pki),*pkiroot=getenv("DREAMINGWRT_AC_PKI_DIR");
    char keypath[4096];snprintf(keypath,sizeof(keypath),"%s/gen-%s/ca.ed25519",pkiroot,generation);
    unsigned char *raw=NULL;size_t rawlen=0;assert(apd_credentials_read_binary_secure(keypath,32,&raw,&rawlen)==0&&rawlen==32);
    EVP_PKEY *signer=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,raw,rawlen);OPENSSL_cleanse(raw,rawlen);free(raw);assert(signer&&X509_sign(cert,signer,NULL)>0);ac_pki_free(pki);
    length=(size_t)i2d_X509(cert,NULL);der=malloc(length);unsigned char *out=der;assert(i2d_X509(cert,&out)==(int)length);X509_free(cert);
    assert(apd_credentials_read_secure(metadata.ca_cert_pem_path,65536,&pem,&pem_len)==0);
    assert(apd_credentials_rotation_install("88888888-8888-4888-8888-888888888888","99999999-9999-4999-8999-999999999999",der,length,(const char *)pem,pem_len)!=0);
    assert(!strcmp(before,apd_credentials_pki_dir()));free(der);free(pem);
    char serverpath[4096],materialdir[4096];
    /* generation pointed into pki before free; derive the active marker again. */
    assert(ac_pki_init(&pki)==0);snprintf(materialdir,sizeof(materialdir),"%s/gen-%s",pkiroot,ac_pki_generation(pki));ac_pki_free(pki);
    assert(apd_credentials_path(serverpath,sizeof(serverpath),materialdir,"server.crt.der")==0);
    unsigned char *original=NULL;size_t original_len=0;assert(apd_credentials_read_binary_secure(serverpath,65536,&original,&original_len)==0);
    cursor=original;cert=d2i_X509(NULL,&cursor,(long)original_len);assert(cert&&X509_gmtime_adj(X509_getm_notBefore(cert),86400)&&X509_sign(cert,signer,NULL)>0);
    length=(size_t)i2d_X509(cert,NULL);der=malloc(length);out=der;assert(i2d_X509(cert,&out)==(int)length);X509_free(cert);EVP_PKEY_free(signer);
    assert(apd_credentials_atomic_write(materialdir,"server.crt.der",der,length)==0);free(der);
    struct json_object *status=request("status","","","");struct json_object *window=json_object_object_get(status,"server_certificate");
    assert(json_object_get_boolean(json_object_object_get(window,"clock_anomaly")));
    assert(!strcmp(json_object_get_string(json_object_object_get(window,"validity")),"not_yet_valid"));json_object_put(status);
    assert(apd_credentials_atomic_write(materialdir,"server.crt.der",original,original_len)==0);free(original);
}

int main(int argc,char **argv)
{
    setvbuf(stdout,NULL,_IONBF,0);
    assert(argc==2);char path[4096];assert(chmod(argv[1],0700)==0);
    snprintf(path,sizeof(path),"%s/ac",argv[1]);setenv("DREAMINGWRT_AC_PKI_DIR",path,1);setenv("DREAMINGWRT_AC_LISTEN_NAMES","ac.test",1);
    snprintf(db_path,sizeof(db_path),"%s/tasks.db",argv[1]);assert(sqlite3_open(db_path,&database)==SQLITE_OK);
    sql("CREATE TABLE ac_device_certificates(certificate_id TEXT PRIMARY KEY,ap_id TEXT,serial TEXT,key_id TEXT,not_before INTEGER,not_after INTEGER,state TEXT,revoked_at INTEGER DEFAULT 0,certificate_der BLOB,fingerprint_sha256 BLOB,issuer_key_id TEXT,issued_at INTEGER,activated_at INTEGER DEFAULT 0);CREATE TABLE ac_enrollments(enrollment_id TEXT PRIMARY KEY,ap_id TEXT,state TEXT,certificate_id TEXT,public_key BLOB,key_id TEXT,updated_at INTEGER);");
    assert(!ac_certificate_lifecycle_ready(NULL) && !ac_certificate_lifecycle_ready(database));
    assert(ac_certificate_lifecycle_init(database)==0);readiness_failures();struct ac_pki *pki=NULL;assert(ac_pki_init(&pki)==0);char controller[37];snprintf(controller,sizeof(controller),"%s",ac_pki_controller_id(pki));
    for(int a=0;a<2;a++){snprintf(directories[a],sizeof(directories[a]),"%s/ap%d",argv[1],a);prepare_ap(a,pki);}ac_pki_free(pki);assert(ac_transport_certificate_reload()==0);
    const char *server_task="11111111-1111-4111-8111-111111111111",*ap_task="22222222-2222-4222-8222-222222222222",*ca_task="33333333-3333-4333-8333-333333333333";
    SSL_CTX *oldctx=server_context;SSL_CTX_up_ref(oldctx);
    struct json_object *r=request("submit",server_task,"server_renew","");assert(json_object_get_boolean(json_object_object_get(r,"ok")));json_object_put(r);expect_state(server_task,"confirming");
    assert(poll_ap(0,oldctx,1)==1);expect_state(server_task,"confirming");assert(poll_ap(0,NULL,1)==0);expect_state(server_task,"confirming");assert(poll_ap(1,NULL,1)==0);expect_state(server_task,"completed");SSL_CTX_free(oldctx);
    puts("PASS server renew: real TLS old session retained; new-session proof; offline target blocks completion");
    r=request("submit",ap_task,"ap_renew",ap_ids[0]);json_object_put(r);
    rejected_poll(ap_task, 0);
    setenv("APD_CREDENTIALS_TEST_ROTATION_INTERRUPT","before-marker",1);assert(poll_ap(0,NULL,1)==1);unsetenv("APD_CREDENTIALS_TEST_ROTATION_INTERRUPT");
    assert(count("SELECT count(*) FROM ac_device_certificates")==3);
    rejected_poll(ap_task, 1);
    r=request("cancel",ap_task,"","");assert(!strcmp(json_object_get_string(json_object_object_get(r,"error")),"cancel_boundary_crossed"));json_object_put(r);
    assert(poll_ap(0,NULL,1)==1);assert(count("SELECT count(*) FROM ac_device_certificates")==3);assert(count("SELECT revoked_at FROM ac_device_certificates WHERE certificate_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'")==0);
    assert(poll_ap(0,NULL,1)==0);expect_state(ap_task,"completed");assert(count("SELECT revoked_at>0 FROM ac_device_certificates WHERE certificate_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'")==1);
    select_ap(0);struct apd_enrollment_metadata m;assert(apd_credentials_validate_startup(&m)==0 && !strcmp(m.ap_id,ap_ids[0]));
    r=request("submit",ap_task,"ap_renew",ap_ids[0]);assert(json_object_get_boolean(json_object_object_get(r,"ok")));json_object_put(r);
    r=request("submit",ap_task,"ca_rotate","");assert(!strcmp(json_object_get_string(json_object_object_get(r,"error")),"idempotency_conflict"));json_object_put(r);
    puts("PASS AP renew: local CSR; atomic public credential slot; identity preserved; old certificate revoked only after new mTLS; idempotency");
    r=request("submit",ca_task,"ca_rotate","");json_object_put(r);expect_state(ca_task,"distributing");assert(!ac_certificate_lifecycle_enrollment_allowed(database));
    assert(poll_ap(0,NULL,1)==1);assert(poll_ap(0,NULL,1)==0);expect_state(ca_task,"distributing");
    assert(sqlite3_close(database)==SQLITE_OK);assert(sqlite3_open(db_path,&database)==SQLITE_OK);assert(ac_certificate_lifecycle_init(database)==0&&ac_transport_certificate_reload()==0&&ac_certificate_lifecycle_tick(database)==0);expect_state(ca_task,"distributing");
    assert(poll_ap(1,NULL,1)==1);assert(poll_ap(1,NULL,1)==1);expect_state(ca_task,"confirming");
    assert(ac_pki_init(&pki)==0&&!strcmp(controller,ac_pki_controller_id(pki)));X509 *alt=ac_pki_alternate_ca_dup(pki);assert(alt);X509_free(alt);ac_pki_free(pki);
    assert(poll_ap(0,NULL,1)==0);expect_state(ca_task,"confirming");assert(poll_ap(1,NULL,1)==1);expect_state(ca_task,"retiring");assert(poll_ap(0,NULL,1)==1);assert(poll_ap(0,NULL,1)==0);expect_state(ca_task,"retiring");assert(poll_ap(1,NULL,1)==0);expect_state(ca_task,"completed");
    assert(ac_pki_init(&pki)==0&&!strcmp(controller,ac_pki_controller_id(pki)));assert(!ac_pki_alternate_ca_dup(pki));ac_pki_free(pki);assert(ac_certificate_lifecycle_enrollment_allowed(database));
    puts("PASS CA rotate: dual trust; both AP client proofs; stable controller ID; restart recovery; old CA retained until all new server proofs; both trust retire acks");
    const char *rollback="44444444-4444-4444-8444-444444444444";
    r=request("submit",rollback,"server_renew","");json_object_put(r);expect_state(rollback,"confirming");r=request("rollback",rollback,"","");json_object_put(r);expect_state(rollback,"rolled_back");assert(poll_ap(0,NULL,1)==0);
    const char *cancel="55555555-5555-4555-8555-555555555555";
    r=request("submit",cancel,"ap_renew",ap_ids[0]);json_object_put(r);r=request("cancel",cancel,"","");json_object_put(r);expect_state(cancel,"cancelled");
    puts("PASS explicit server rollback and pre-activation cancellation");
    tls_retired_ca_rejected();pending_and_reload_failures(argv[1]);invalid_time_is_not_published();
    puts("PASS TLS rejects retired CA; incomplete/corrupt pending generation never activates; failed reload preserves old server; explicit retry; future AP certificate never publishes");
    struct json_object *foreign=json_object_new_object();
    json_object_object_add(foreign,"action",json_object_new_string("submit"));json_object_object_add(foreign,"request_id",json_object_new_string(ap_task));json_object_object_add(foreign,"operation",json_object_new_string("ap_renew"));json_object_object_add(foreign,"ap_id",json_object_new_string(ap_ids[0]));json_object_object_add(foreign,"actor",json_object_new_string("other-operator"));json_object_object_add(foreign,"reason",json_object_new_string("certificate fixture"));json_object_object_add(foreign,"confirmed",json_object_new_boolean(1));
    r=ac_certificate_lifecycle_request(database,foreign);assert(!strcmp(json_object_get_string(json_object_object_get(r,"error")),"idempotency_conflict"));json_object_put(r);json_object_put(foreign);
    puts("PASS request id cannot be reused across actors; AP interrupted preparation replays same certificate; cancellation refused after issuance");
    puts("PASS malformed CSR, mismatched task identity and false mTLS proof preserve old certificate and issue no extra rows");
    explicit_revocation();
    SSL_CTX_free(server_context);sqlite3_close(database);for(int a=0;a<2;a++)EVP_PKEY_free(keys[a]);return 0;
}
