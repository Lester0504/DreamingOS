/* Test transport only. Compile file_services.c with explicit /tmp path overrides. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "storage/file_services.h"
int main(int argc,char **argv) {
    if(argc==3 && !strcmp(argv[1],"--file-share-ftp"))return jmx_file_service_ftp_runtime(argv[2]);
    if(argc==2 && !strcmp(argv[1],"--file-share-bindings"))return jmx_file_service_bindings_watch();
    char *line = NULL; size_t cap = 0;
    while (getline(&line, &cap, stdin) > 0) {
        struct json_object *request = json_tokener_parse(line), *op, *args, *id, *service;
        if (!request) return 2;
        json_object_object_get_ex(request,"op",&op);
        json_object_object_get_ex(request,"args",&args);
        json_object_object_get_ex(request,"id",&id);
        json_object_object_get_ex(request,"service",&service);
        const char *name=json_object_get_string(op), *key=json_object_get_string(id);
        struct json_object *result;
        if (!strncmp(name,"ftp-",4)) result=jmx_ftp_share_request(name+4,key,args);
        else if (!strncmp(name,"webdav-",7)) result=jmx_webdav_share_request(name+7,key,args);
        else if (!strncmp(name,"operation-",10)) result=jmx_file_share_operation_request(name+10,key,args);
        else if (!strncmp(name,"account-",8)) result=jmx_file_service_accounts_request(name+8,key,args);
        else if (!strcmp(name,"get")) result=jmx_file_service_get(json_object_get_string(service));
        else if (!strcmp(name,"action")) result=jmx_file_service_action(json_object_get_string(service),args);
        else if (!strcmp(name,"settings")) result=!strcmp(json_object_get_string(service),"ftp")?jmx_ftp_settings_set(args):!strcmp(json_object_get_string(service),"nfs")?jmx_nfs_defaults_set(args):jmx_samba_settings_set(args);
        else if (!strcmp(name,"samba")) result=jmx_samba_share_upsert(key,args);
        else if (!strcmp(name,"samba-delete")) result=jmx_samba_share_delete(key,args);
        else if (!strcmp(name,"nfs")) result=jmx_nfs_export_upsert(key,args);
        else if (!strcmp(name,"nfs-delete")) result=jmx_nfs_export_delete(key,args);
        else result=jmx_file_services_get();
        puts(json_object_to_json_string_ext(result,JSON_C_TO_STRING_PLAIN));fflush(stdout);
        json_object_put(result);json_object_put(request);
    }
    free(line);return 0;
}
