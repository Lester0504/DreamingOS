// SPDX-License-Identifier: GPL-2.0-or-later
/* Test-only host boundaries: never execute a network apply or mount a real ISO. */
#include "netboot/netboot_internal.h"
#include "storage/storage_files.h"
#include "jmx_exec.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static sqlite3 *authority;
static int authority_write_rc=-1,authority_in_transaction;
sqlite3 *jmx_netconfig_db_write_connection(void)
{
    if(!authority && sqlite3_open(NB_DB_PATH,&authority)!=SQLITE_OK)return NULL;
    return authority;
}
int storage_files_open_stream(const char *r,const char *p,struct storage_files_stream *out,const char **why)
{
    (void)r;
#ifdef NB_TEST_SOURCE_ROOT
    /* Only the separately compiled mount-namespace test opens disposable ISOs. */
    if(!strncmp(p,NB_TEST_SOURCE_ROOT "/",strlen(NB_TEST_SOURCE_ROOT)+1)) {
        memset(out,0,sizeof *out);out->fd=open(p,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(out->fd>=0){snprintf(out->root_id,sizeof out->root_id,"fixture");snprintf(out->display_path,sizeof out->display_path,"%s",p);snprintf(out->basename,sizeof out->basename,"%s",strrchr(p,'/')+1);return 0;}
    }
#else
    (void)p;(void)out;
#endif
    *why="fixture_source_unavailable";return -1;
}
int jmx_dhcp_service_apply(const char *id)
{
    (void)id;
    /* Exercise a real DHCP-side authority write while Netboot holds its txn.
     * Runtime execution remains a failing boundary, forcing the rollback path. */
    int rc=sqlite3_exec(jmx_netconfig_db_write_connection(),
        "UPDATE dhcp_scope SET pool_start='101' WHERE id='scope'",NULL,NULL,NULL);
    authority_write_rc=rc;authority_in_transaction=!sqlite3_get_autocommit(authority);
    return -1;
}
int jmx_exec_wait(const char *p,char *const a[],int t,struct jmx_exec_result *r)
{(void)p;(void)a;(void)t;memset(r,0,sizeof *r);r->exit_code=1;return 0;}
void jmx_exec_result_free(struct jmx_exec_result *r){free(r->output);}
int main(void)
{
    char *line=NULL;size_t n=0;
    while(getline(&line,&n,stdin)>0) {
        struct json_object *in=json_tokener_parse(line),*out=NULL,*body=nb_value(in,"body");
        const char *op=nb_string(in,"op");
        if(!strcmp(op,"authority-result")){out=nb_reply(json_object_new_object());nb_int(nb_value(out,"data"),"rc",authority_write_rc);nb_flag(nb_value(out,"data"),"in_transaction",authority_in_transaction);}
        else if(!strcmp(op,"observe")){nb_observe_client(nb_string(body,"mac"),"127.0.0.1","x86_64","efi");out=nb_reply(json_object_new_object());}
        else if(!strcmp(op,"http")) {
            nb_http_stop();nb_config_publish(body);int rc=nb_http_start(body,nb_value(in,"interface"));
            out=nb_reply(json_object_new_object());nb_int(nb_value(out,"data"),"rc",rc);nb_int(nb_value(out,"data"),"errno",errno);
        } else if(!strcmp(op,"publish")){nb_config_publish(body);out=nb_reply(json_object_new_object());}
        else if(!strcmp(op,"stop")){nb_http_stop();out=nb_reply(json_object_new_object());}
        else if(!strcmp(op,"render")){char *block=nb_dhcp_block(body,nb_value(in,"interface"));out=nb_reply(json_object_new_object());nb_text(nb_value(out,"data"),"block",block);free(block);}
        else if(!strcmp(op,"detect")){
            int fd=open(nb_string(in,"path"),O_DIRECTORY|O_RDONLY);struct json_object *im=json_object_new_object();
            nb_image_detect_at(im,fd);close(fd);out=nb_reply(im);
        } else out=jmx_netboot_request(nb_string(in,"method"),nb_string(in,"resource"),nb_string(in,"id"),nb_string(in,"action"),body);
        puts(json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN));fflush(stdout);
        json_object_put(out);json_object_put(in);
    }
    nb_http_stop();if(authority)sqlite3_close(authority);free(line);return 0;
}
