// SPDX-License-Identifier: GPL-2.0-or-later
/* ISO ownership is a readonly loop mount, never a user supplied mount target. */
#include "netboot_internal.h"
#include "storage/storage_files.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int nb_id_valid(const char *id)
{
    if (!id || !*id || strlen(id)>64) return 0;
    for (const char *p=id; *p; p++) if (!isalnum((unsigned char)*p) && *p!='-' && *p!='_') return 0;
    return 1;
}
static int image_fail(struct json_object *image, const char *state, const char *reason)
{ nb_text(image,"image_status",state); nb_text(image,"error",reason); return -1; }
static void target_path(const char *id, char path[PATH_MAX])
{ snprintf(path,PATH_MAX,NB_RUN_DIR "/images/%s",id); }

/* Walk descriptors: a symlink in an ISO must never escape the mounted image. */
static int open_below(int root, const char *relative)
{
    if (!relative || !*relative || relative[0]=='/' || strlen(relative)>=PATH_MAX) { errno=EINVAL; return -1; }
    char path[PATH_MAX], *save=NULL; snprintf(path,sizeof path,"%s",relative);
    int fd=dup(root);
    for (char *part=strtok_r(path,"/",&save); part; part=strtok_r(NULL,"/",&save)) {
        if (!strcmp(part,".") || !strcmp(part,"..")) { close(fd); errno=EPERM; return -1; }
        int next=openat(fd,part,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        close(fd); if (next<0) return -1; fd=next;
    }
    struct stat st;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode)) { close(fd); errno=EINVAL; return -1; }
    return fd;
}
static int mounted_root(struct json_object *image)
{
    char path[PATH_MAX]; target_path(nb_string(image,"id"),path);
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
    if (fd<0) return -1;
    struct stat st; struct loop_info64 loop={0};
    if (fstat(fd,&st)) { close(fd); return -1; }
    char loop_path[64]; snprintf(loop_path,sizeof loop_path,"/dev/block/%u:%u",major(st.st_dev),minor(st.st_dev));
    int lfd=open(loop_path,O_RDONLY|O_CLOEXEC);
    if (lfd<0) { snprintf(loop_path,sizeof loop_path,"/dev/loop%u",minor(st.st_dev)); lfd=open(loop_path,O_RDONLY|O_CLOEXEC); }
    int valid=lfd>=0 && major(st.st_dev)==7 && ioctl(lfd,LOOP_GET_STATUS64,&loop)==0 &&
        (loop.lo_flags&LO_FLAGS_READ_ONLY) &&
        loop.lo_inode==(uint64_t)nb_number(image,"source_inode") &&
        loop.lo_device==(uint64_t)nb_number(image,"source_device");
    if (lfd>=0) close(lfd);
    if (!valid) { close(fd); errno=ESTALE; return -1; }
    return fd;
}
static int source_open(struct json_object *image, int remember)
{
    struct storage_files_stream source; const char *reason=NULL; struct stat st;
    if (storage_files_open_stream(nb_string(image,"root_id"),nb_string(image,"path"),&source,&reason)) {
        image_fail(image,"missing",reason ? reason : "image_missing"); return -1;
    }
    if (fstat(source.fd,&st) || st.st_size<32768 || strcasecmp(strrchr(source.basename,'.') ?: "", ".iso")) {
        close(source.fd); image_fail(image,"unsupported","invalid_iso_file"); return -1;
    }
    if (remember) {
        nb_text(image,"path",source.display_path); nb_text(image,"root_id",source.root_id);
        nb_int(image,"source_inode",st.st_ino); nb_int(image,"source_device",st.st_dev);
        nb_int(image,"size_bytes",st.st_size); nb_int(image,"source_mtime",st.st_mtime);
        nb_int(image,"source_ctime",st.st_ctime);
    } else if ((uint64_t)nb_number(image,"source_inode")!=(uint64_t)st.st_ino ||
        (uint64_t)nb_number(image,"source_device")!=(uint64_t)st.st_dev ||
        nb_number(image,"size_bytes")!=st.st_size || nb_number(image,"source_mtime")!=st.st_mtime ||
        nb_number(image,"source_ctime")!=st.st_ctime) {
        close(source.fd); image_fail(image,"missing","source_changed"); return -1;
    }
    return source.fd;
}
int nb_image_register(struct json_object *image)
{ int fd=source_open(image,1); if(fd<0)return -1; close(fd); nb_text(image,"image_status","unmounted"); return 0; }

static char *strip(char *s)
{
    while(isspace((unsigned char)*s))s++;
    char *end=s+strlen(s); while(end>s && isspace((unsigned char)end[-1]))*--end=0;
    return s;
}
int nb_image_detect_at(struct json_object *image, int rootfd)
{
    nb_flag(image,"boot_verified",0);
    nb_text(image,"method",""); nb_text(image,"kernel",""); nb_text(image,"initrd","");
    nb_text(image,"os",""); nb_text(image,"version",""); nb_text(image,"arch","");
    int fd=open_below(rootfd,".treeinfo");
    if(fd<0)return image_fail(image,"unsupported","template_not_supported");
    char text[65537]; ssize_t len=read(fd,text,sizeof text-1); close(fd);
    if(len<=0 || len==(ssize_t)sizeof(text)-1)return image_fail(image,"unsupported","treeinfo_invalid");
    text[len]=0;
    char section[80]="",family[100]="",version[64]="",arch[32]="", *save=NULL;
    for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        char *s=strip(line);
        if(*s=='[') { char *end=strchr(s,']'); if(end){*end=0;snprintf(section,sizeof section,"%s",s+1);}continue; }
        char *eq=strchr(s,'='); if(!eq || strcmp(section,"general"))continue;
        *eq=0;char *key=strip(s), *value=strip(eq+1);
        if(!strcmp(key,"family"))snprintf(family,sizeof family,"%s",value);
        if(!strcmp(key,"version"))snprintf(version,sizeof version,"%s",value);
        if(!strcmp(key,"arch"))snprintf(arch,sizeof arch,"%s",value);
    }
    nb_text(image,"os",family);nb_text(image,"version",version);nb_text(image,"arch",arch);
    if((strcmp(family,"Rocky Linux") && strcmp(family,"AlmaLinux") && strcmp(family,"Red Hat Enterprise Linux") && strcmp(family,"CentOS Stream")) ||
       (strcmp(version,"9") && strncmp(version,"9.",2)) || strcmp(arch,"x86_64"))
        return image_fail(image,"unsupported","template_not_supported");
    const char *required[]={"images/pxeboot/vmlinuz","images/pxeboot/initrd.img","images/install.img",NULL};
    for(int i=0;required[i];i++) {
        fd=open_below(rootfd,required[i]);
        if(fd<0)return image_fail(image,"unsupported","template_file_missing");
        struct stat st; int ok=!fstat(fd,&st)&&st.st_size>0;close(fd);
        if(!ok)return image_fail(image,"unsupported","template_file_empty");
    }
    nb_text(image,"method","rhel9-http");nb_text(image,"kernel",required[0]);nb_text(image,"initrd",required[1]);
    nb_text(image,"args","ip=dhcp");nb_text(image,"image_status","ready");nb_text(image,"error","");
    struct json_object *resources=nb_resources();int ready=1;
    for(size_t i=0;i<json_object_array_length(resources);i++)ready&=nb_bool(json_object_array_get_idx(resources,i),"ready");
    json_object_put(resources);
    return ready?0:image_fail(image,"dependency_missing","boot_resources_unavailable");
}
static int unmount_owned(const char *id,struct json_object *image)
{
    if(!nb_id_valid(id)){errno=EINVAL;return -1;}
    if(nb_http_busy(id)){errno=EBUSY;return -1;}
    char path[PATH_MAX];target_path(id,path);
    struct stat st,parent;
    if(lstat(path,&st)){return errno==ENOENT?0:-1;}
    if(!S_ISDIR(st.st_mode)||stat(NB_RUN_DIR "/images",&parent)){errno=ESTALE;return -1;}
    if(st.st_dev!=parent.st_dev) {
        int root=image?mounted_root(image):-1;
        if(root<0){errno=ESTALE;return -1;}close(root);
    }
    if(umount2(path,0) && errno!=EINVAL && errno!=ENOENT)return -1;
    if(rmdir(path) && errno!=ENOENT)return -1;
    return 0;
}
int nb_image_unmount_known(struct json_object *image)
{ return unmount_owned(nb_string(image,"id"),image); }
int nb_image_unmount(const char *id)
{
    struct json_object *cfg=nb_config_snapshot();
    int rc=unmount_owned(id,nb_find(nb_value(cfg,"images"),id));
    if(cfg)json_object_put(cfg);return rc;
}
int nb_image_probe(struct json_object *image,int remount,int overwrite)
{
    (void)overwrite; /* Manual templates are not enabled in v1. */
    const char *id=nb_string(image,"id"); if(!nb_id_valid(id))return -1;
    if(nb_http_busy(id))return image_fail(image,"busy","image_busy");
    int root=mounted_root(image);
    if(root>=0 && !remount) {int source=source_open(image,0); if(source<0){close(root);return -1;} close(source);int rc=nb_image_detect_at(image,root);close(root);return rc;}
    if(root>=0)close(root);
    if(remount && nb_image_unmount_known(image))return image_fail(image,"mount_failed","unmount_failed");
    int source=source_open(image,remount || !nb_number(image,"source_inode"));if(source<0)return -1;
    mkdir("/run/dreamingwrt",0755);mkdir(NB_RUN_DIR,0700);mkdir(NB_RUN_DIR "/images",0700);
    char path[PATH_MAX];target_path(id,path);
    if(mkdir(path,0700) && errno!=EEXIST){close(source);return image_fail(image,"mount_failed","mount_directory_failed");}
    struct stat before,parent;
    if(lstat(path,&before) || !S_ISDIR(before.st_mode) || stat(NB_RUN_DIR "/images",&parent) || before.st_dev!=parent.st_dev) {
        close(source);return image_fail(image,"mount_failed","mount_target_busy");
    }
    int control=open("/dev/loop-control",O_RDWR|O_CLOEXEC);
    int number=control>=0?ioctl(control,LOOP_CTL_GET_FREE):-1;if(control>=0)close(control);
    if(number<0){close(source);return image_fail(image,"mount_failed","loop_unavailable");}
    char dev[64];snprintf(dev,sizeof dev,"/dev/loop%d",number);
    int loop=open(dev,O_RDWR|O_CLOEXEC);struct loop_info64 info={0};
    info.lo_flags=LO_FLAGS_READ_ONLY|LO_FLAGS_AUTOCLEAR;
    int attached=loop>=0 && ioctl(loop,LOOP_SET_FD,source)==0;
    if(!attached || ioctl(loop,LOOP_SET_STATUS64,&info)) {
        /* LOOP_CTL_GET_FREE is advisory: do not clear a loop claimed by another service. */
        if(attached)ioctl(loop,LOOP_CLR_FD,0);
        if(loop>=0)close(loop);close(source);
        return image_fail(image,"mount_failed","loop_attach_failed");
    }
    int rc=mount(dev,path,"iso9660",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL);
    if(rc)rc=mount(dev,path,"udf",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL);
    close(source);close(loop);
    if(rc)return image_fail(image,"mount_failed","iso_mount_failed");
    root=mounted_root(image);
    if(root<0)return image_fail(image,"mount_failed","mount_identity_failed");
    rc=nb_image_detect_at(image,root);close(root);return rc;
}
void nb_image_observe(struct json_object *image)
{
    if(!nb_id_valid(nb_string(image,"id")))return;
    int fd=source_open(image,0);if(fd<0)return;close(fd);
    fd=mounted_root(image);
    if(fd<0){image_fail(image,"unmounted","image_unmounted");return;}
    nb_image_detect_at(image,fd);close(fd);
}
int nb_image_open(struct json_object *image,const char *relative)
{
    int source=source_open(image,0);if(source<0)return -1;close(source);
    int root=mounted_root(image);if(root<0)return -1;
    int fd=open_below(root,relative);close(root);return fd;
}
