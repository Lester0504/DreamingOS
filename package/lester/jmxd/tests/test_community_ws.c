// Isolated auth boundary. The community WS loop, proof, storage and framing are production code.
#define _POSIX_C_SOURCE 200809L
#include "../src/webd/webd_community.h"
#include "../src/webd/api/webd_http_req.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
sqlite3 *g_config_db;
static char identity[96];
int webd_identity_is_user(const char *value){return !strncmp(value,"test:",5);}
const char *webd_identity_username(const char *value){return value+5;}
char *jmx_app_validate_token_mode(const char *token,int *state,int activity){(void)state;(void)activity;return !strcmp(token,identity+5)?strdup(identity):NULL;}
int main(int argc,char **argv){
 if(argc!=5)return 2;
 signal(SIGPIPE,SIG_IGN);curl_global_init(CURL_GLOBAL_DEFAULT);
 if(sqlite3_open(argv[1],&g_config_db)!=SQLITE_OK)return 3;
 snprintf(identity,sizeof(identity),"test:%s",argv[2]);
 struct http_req req={0};req.websocket=1;
 snprintf(req.auth_token,sizeof(req.auth_token),"%s",argv[2]);
 snprintf(req.ws_key,sizeof(req.ws_key),"%s",argv[3]);
 snprintf(req.query,sizeof(req.query),"%s",argv[4]);
 fcntl(3,F_SETFL,fcntl(3,F_GETFL)&~O_NONBLOCK);
 community_ws_session(3,&req,identity);close(3);sqlite3_close(g_config_db);curl_global_cleanup();return 0;
}
