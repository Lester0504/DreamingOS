// SPDX-License-Identifier: GPL-2.0-or-later
#include "tm.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

J *tm_get(J *j,const char *k) { J *v=NULL; if(j) json_object_object_get_ex(j,k,&v); return v; }
const char *tm_str(J *j,const char *k,const char *d) { J *v=tm_get(j,k);return v&&json_object_is_type(v,json_type_string)?json_object_get_string(v):d; }
int64_t tm_int(J *j,const char *k,int64_t d) { J *v=tm_get(j,k);return v&&json_object_is_type(v,json_type_int)?json_object_get_int64(v):d; }
int tm_bool(J *j,const char *k,int d) { J *v=tm_get(j,k);return v&&json_object_is_type(v,json_type_boolean)?json_object_get_boolean(v):d; }
J *tm_copy(J *j) { return j?json_tokener_parse(json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN)):json_object_new_object(); }
void tm_string(J *j,const char *k,const char *v) { json_object_object_add(j,k,v?json_object_new_string(v):NULL); }
void tm_number(J *j,const char *k,int64_t v) { json_object_object_add(j,k,json_object_new_int64(v)); }
void tm_boolean(J *j,const char *k,int v) { json_object_object_add(j,k,json_object_new_boolean(v)); }
J *tm_error(int *status,int code,const char *reason,const char *message) { J *j=json_object_new_object();*status=code;tm_boolean(j,"ok",0);tm_string(j,"error",reason);tm_string(j,"message",message);tm_boolean(j,"retryable",code==503||code==504);return j; }
int64_t tm_now(void) { return time(NULL); }
void tm_uuid(char out[33]) { unsigned char b[16];if(RAND_bytes(b,sizeof(b))!=1)abort();for(size_t i=0;i<16;i++)snprintf(out+i*2,3,"%02x",b[i]); }
void tm_scrub(J *j) { if(!j)return;if(json_object_is_type(j,json_type_string)){char *s=(char *)json_object_get_string(j);OPENSSL_cleanse(s,json_object_get_string_len(j));}else if(json_object_is_type(j,json_type_object)){json_object_object_foreach(j,k,v){(void)k;tm_scrub(v);}} }
int tm_write_all(int fd,const void *p,size_t n) { const char *s=p;while(n){ssize_t r=send(fd,s,n,MSG_NOSIGNAL);if(r<0&&errno==EINTR)continue;if(r<=0)return -1;s+=r;n-=r;}return 0; }
int tm_read_all(int fd,void *p,size_t n) { char *s=p;while(n){ssize_t r=recv(fd,s,n,0);if(r<0&&errno==EINTR)continue;if(r<=0)return -1;s+=r;n-=r;}return 0; }
int tm_send_json(int fd,J *j) { const char *s=json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN);size_t n=strlen(s);uint32_t len=htonl(n);return n>TM_FRAME_MAX?-1:(tm_write_all(fd,&len,4)||tm_write_all(fd,s,n)?-1:0); }
J *tm_receive_json(int fd) { uint32_t len;if(tm_read_all(fd,&len,4))return NULL;size_t n=ntohl(len);if(!n||n>TM_FRAME_MAX)return NULL;char *s=calloc(1,n+1);if(!s)return NULL;J *j=NULL;if(!tm_read_all(fd,s,n))j=json_tokener_parse(s);OPENSSL_cleanse(s,n);free(s);return j; }
char *tm_base64(const void *p,size_t n) { char *s=malloc(4*((n+2)/3)+1);if(s)EVP_EncodeBlock((unsigned char *)s,p,n);return s; }
unsigned char *tm_unbase64(const char *s,size_t *n) { size_t len=strlen(s);if(!len||len%4||len>TM_FRAME_MAX)return NULL;unsigned char *p=malloc(len/4*3+1);if(!p)return NULL;int z=EVP_DecodeBlock(p,(const unsigned char *)s,len);if(z<0){free(p);return NULL;}if(s[len-1]=='=')z--;if(s[len-2]=='=')z--;*n=z;return p; }
