/* SPDX-License-Identifier: GPL-2.0-or-later */
#define APD_TRANSPORT_TEST_STANDALONE
#define AP_LOG_TEST_RPC
#include "../src/apd/apd_audit_forward.h"
#include "../src/apd/apd_transport.c"
#include <assert.h>
static int acknowledgements;
struct json_object *ap_log_rpc(const char *method, struct json_object *body)
{
    if (!strcmp(method,"ap_log_ack")) {
        assert(ap_log_batch_valid(json_object_object_get(body,"events")));
        acknowledgements++;
        return ap_log_result(1,NULL);
    }
    assert(!strcmp(method,"ap_log_peek"));
    return json_tokener_parse("{\"events\":[{\"id\":\"1234567890abcdef1234567890abcdef\",\"ts\":1790930000,\"severity\":\"warning\",\"category\":\"system\",\"event\":\"probe\",\"source\":\"fixture\",\"title\":\"ack binding\",\"detail_json\":\"{}\"}]}");
}
int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    struct sockaddr_in addr={0};
    struct apd_enrollment_metadata metadata={0};
    char epoch[65];
    assert(argc==3);
    ctx=SSL_CTX_new(TLS_client_method());assert(ctx);
    assert(SSL_CTX_load_verify_locations(ctx,argv[2],NULL)==1);
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);
    addr.sin_family=AF_INET;addr.sin_port=htons(atoi(argv[1]));addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(connect(fd,(struct sockaddr*)&addr,sizeof(addr))==0);
    ssl=SSL_new(ctx);assert(ssl);assert(SSL_set_fd(ssl,fd)==1);assert(SSL_connect(ssl)==1);
    snprintf(metadata.ap_id,sizeof(metadata.ap_id),"11111111-1111-4111-8111-111111111111");
    memset(epoch,'a',64);epoch[64]=0;
    g_apd_wire_protocol = AP_CONTROL_PROTOCOL_V3;
    int flags=fcntl(fd,F_GETFL,0);assert(flags>=0);assert(fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0);
    int rc=apd_session_logs(ssl,&metadata,epoch);
    printf("rc=%d acked=%d\n",rc,acknowledgements);
    SSL_free(ssl);SSL_CTX_free(ctx);close(fd);
    return 0;
}
