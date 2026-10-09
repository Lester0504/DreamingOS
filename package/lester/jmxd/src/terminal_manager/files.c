// SPDX-License-Identifier: GPL-2.0-or-later
#include "tm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tm_path_valid(const char *p) { return p&&p[0]=='/'&&strlen(p)<4096; }

static J *sftp_error(struct tm_session *s,int *status) {
    unsigned long code=libssh2_sftp_last_error(s->sftp);int http=502;const char *reason="sftp_failed",*message="远端文件操作失败";
    if(code==LIBSSH2_FX_NO_SUCH_FILE){http=404;reason="file_not_found";message="路径不存在";}
    else if(code==LIBSSH2_FX_PERMISSION_DENIED){http=403;reason="remote_permission_denied";message="远端目录或文件无权限";}
    else if(code==LIBSSH2_FX_FILE_ALREADY_EXISTS){http=409;reason="file_conflict";message="目标已存在";}
    else if(code==LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM){http=507;reason="remote_no_space";message="远端空间不足";}
    else if(code==LIBSSH2_FX_WRITE_PROTECT){http=422;reason="remote_readonly";message="远端文件系统只读";}
    J *j=tm_error(status,http,reason,message);tm_number(j,"sftp_status",code);return j;
}

static J *attributes(const char *name,LIBSSH2_SFTP_ATTRIBUTES *a) {
    J *j=json_object_new_object();tm_string(j,"name",name);
    const char *type=!(a->flags&LIBSSH2_SFTP_ATTR_PERMISSIONS)?"unknown":LIBSSH2_SFTP_S_ISDIR(a->permissions)?"directory":LIBSSH2_SFTP_S_ISLNK(a->permissions)?"symlink":LIBSSH2_SFTP_S_ISREG(a->permissions)?"file":"other";tm_string(j,"type",type);
    if(a->flags&LIBSSH2_SFTP_ATTR_SIZE)tm_number(j,"size",a->filesize);else json_object_object_add(j,"size",NULL);
    if(a->flags&LIBSSH2_SFTP_ATTR_ACMODTIME)tm_number(j,"mtime",a->mtime);else json_object_object_add(j,"mtime",NULL);
    if(a->flags&LIBSSH2_SFTP_ATTR_PERMISSIONS)tm_number(j,"permissions",a->permissions&07777);else json_object_object_add(j,"permissions",NULL);
    if(a->flags&LIBSSH2_SFTP_ATTR_UIDGID){tm_number(j,"uid",a->uid);tm_number(j,"gid",a->gid);}else {json_object_object_add(j,"uid",NULL);json_object_object_add(j,"gid",NULL);}return j;
}

static int delete_path(LIBSSH2_SFTP *sftp,const char *path,int recursive,int depth,int *budget) {
    if(depth>16||--*budget<0)return -2;LIBSSH2_SFTP_ATTRIBUTES a={0};if(libssh2_sftp_lstat(sftp,path,&a))return -1;
    if(!LIBSSH2_SFTP_S_ISDIR(a.permissions))return libssh2_sftp_unlink(sftp,path);
    if(recursive){LIBSSH2_SFTP_HANDLE *h=libssh2_sftp_opendir(sftp,path);if(!h)return -1;int rc=0,n;char name[4096];
        while((n=libssh2_sftp_readdir(h,name,sizeof(name)-1,&a))>0){name[n]=0;if(!strcmp(name,".")||!strcmp(name,".."))continue;char child[4096];if(snprintf(child,sizeof(child),"%s/%s",path,name)>=(int)sizeof(child)){rc=-2;break;}rc=delete_path(sftp,child,1,depth+1,budget);if(rc)break;}
        libssh2_sftp_closedir(h);if(rc||n<0)return rc?rc:-1;
    }return libssh2_sftp_rmdir(sftp,path);
}

J *tm_files_route(struct tm_session *s,const char *operation,J *body,int *status) {
    if(!s->sftp)return tm_error(status,422,"sftp_unavailable","此会话没有可用的 SSH/SFTP 文件通道");
    const char *path=tm_str(body,"path",s->cwd);if(!tm_path_valid(path))return tm_error(status,422,"absolute_path_required","请明确指定绝对路径");
    libssh2_session_set_blocking(s->ssh,1);libssh2_session_set_timeout(s->ssh,5000);
    J *r=NULL;int rc=0;
    if(!strcmp(operation,"files")) {
        LIBSSH2_SFTP_HANDLE *dir=libssh2_sftp_opendir(s->sftp,path);if(!dir){r=sftp_error(s,status);goto done;}
        J *items=json_object_new_array();char name[4096];LIBSSH2_SFTP_ATTRIBUTES a;int n=0;int limit=2000;size_t response_bytes=1024;int truncated=0;
        while(limit--&&(n=libssh2_sftp_readdir(dir,name,sizeof(name)-1,&a))>0){name[n]=0;if(!strcmp(name,".")||!strcmp(name,"..")||(!tm_bool(body,"show_hidden",0)&&name[0]=='.'))continue;J *item=attributes(name,&a);
            if(LIBSSH2_SFTP_S_ISLNK(a.permissions)){char linkpath[4096],target[4096];int z=snprintf(linkpath,sizeof(linkpath),"%s/%s",path,name);if(z<(int)sizeof(linkpath)){z=libssh2_sftp_readlink(s->sftp,linkpath,target,sizeof(target)-1);if(z>0){target[z]=0;tm_string(item,"link_target",target);}}}response_bytes+=strlen(json_object_to_json_string_ext(item,JSON_C_TO_STRING_PLAIN))+1;if(response_bytes>TM_FRAME_MAX-4096){json_object_put(item);truncated=1;break;}json_object_array_add(items,item);
        }libssh2_sftp_closedir(dir);
        if(n<0){json_object_put(items);r=sftp_error(s,status);goto done;}
        r=json_object_new_object();json_object_object_add(r,"items",items);char canonical[4096];n=libssh2_sftp_realpath(s->sftp,path,canonical,sizeof(canonical)-1);if(n>0){canonical[n]=0;tm_string(r,"path",canonical);}else tm_string(r,"path",path);tm_boolean(r,"truncated",truncated||limit<0);tm_number(r,"limit",2000);
    }else if(!strcmp(operation,"files/mkdir"))rc=libssh2_sftp_mkdir(s->sftp,path,0755);
    else if(!strcmp(operation,"files/chmod")){int64_t mode=tm_int(body,"permissions",-1);if(mode<0||mode>07777){r=tm_error(status,422,"invalid_permissions","权限必须是 0000–7777 范围的八进制值");goto done;}LIBSSH2_SFTP_ATTRIBUTES a={.flags=LIBSSH2_SFTP_ATTR_PERMISSIONS,.permissions=mode};rc=libssh2_sftp_setstat(s->sftp,path,&a);}
    else if(!strcmp(operation,"files/rename")){const char *target=tm_str(body,"target","");if(!tm_path_valid(target)){r=tm_error(status,422,"absolute_path_required","请明确指定目标绝对路径");goto done;}LIBSSH2_SFTP_ATTRIBUTES a;int exists=libssh2_sftp_lstat(s->sftp,target,&a)==0;if(exists&&!tm_bool(body,"replace",0)){r=tm_error(status,409,"file_conflict","目标已存在，请选择替换或改名");goto done;}rc=libssh2_sftp_rename_ex(s->sftp,path,strlen(path),target,strlen(target),LIBSSH2_SFTP_RENAME_ATOMIC|(tm_bool(body,"replace",0)?LIBSSH2_SFTP_RENAME_OVERWRITE:0));}
    else if(!strcmp(operation,"files/delete")){if(!strcmp(path,"/")||!tm_bool(body,"confirmed",0)){r=tm_error(status,422,"delete_confirmation_required","删除需要明确确认目标路径");goto done;}int budget=2000;rc=delete_path(s->sftp,path,tm_bool(body,"recursive",0),0,&budget);if(rc==-2){r=tm_error(status,422,"recursive_delete_limit","递归删除达到 2000 项或16层限制，可能已有部分项目删除；请刷新目录");goto done;}}
    else {r=tm_error(status,404,"not_found","文件操作不存在");goto done;}
    if(rc)r=sftp_error(s,status);
    if(!r){r=json_object_new_object();tm_boolean(r,"ok",1);tm_string(r,"path",path);if(strcmp(operation,"files/delete")&&strcmp(operation,"files/rename")){LIBSSH2_SFTP_ATTRIBUTES a;if(!libssh2_sftp_lstat(s->sftp,path,&a))json_object_object_add(r,"attributes",attributes(path,&a));}}
done:
    libssh2_session_set_blocking(s->ssh,0);return r;
}
