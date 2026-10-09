#define _GNU_SOURCE
#define _DARWIN_C_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include "ac/ac_secrets.h"
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include "storage/storage_files.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#else
#define PR_SET_NAME 15
static int prctl(int option, ...)
{
    (void)option;
    return 0;
}
#endif

#include "container_service_runtime_defs.inc"

static int64_t nc_now_s(void)
{
    return (int64_t)time(NULL);
}

static int nc_json_bool_def(struct json_object *object, const char *key, int fallback)
{
    struct json_object *value = NULL;

    if (!object || !json_object_object_get_ex(object, key, &value) ||
        !json_object_is_type(value, json_type_boolean))
        return fallback;
    return json_object_get_boolean(value) ? 1 : 0;
}

static const char *nc_json_str_def(struct json_object *o,const char *key,const char *fallback) {
    struct json_object *v=NULL;
    return o && json_object_object_get_ex(o,key,&v) && json_object_is_type(v,json_type_string)?json_object_get_string(v):fallback;
}
static int nc_json_int_def(struct json_object *o,const char *key,int fallback) {
    struct json_object *v=NULL;
    return o && json_object_object_get_ex(o,key,&v)?json_object_get_int(v):fallback;
}
/* Only the explicitly created test directory is admitted by this fixture. */
int storage_files_open_dir(const char *root,const char *path,int writing,char *canonical,size_t size,const char **reason) {
    (void)root;(void)writing;
    const char *test_root=getenv("DOCKER_WORKFLOW_TEST_ROOT");char resolved[PATH_MAX];struct stat st;
    if(!test_root||!realpath(path,resolved)||strncmp(resolved,test_root,strlen(test_root))||
       (resolved[strlen(test_root)]&&resolved[strlen(test_root)]!='/')){*reason="outside_test_root";return -1;}
    int fd=open(resolved,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY);
    if(fd<0||fstat(fd,&st)||!S_ISDIR(st.st_mode)){if(fd>=0)close(fd);*reason="test_directory_unavailable";return -1;}
    if(snprintf(canonical,size,"%s",resolved)>=(int)size){close(fd);*reason="path_too_long";return -1;}
    return fd;
}

/* Restricted to an explicit test root; this does not replace production
 * storage-files admission, which is covered by the storage test suite. */
int storage_files_open_stream(const char *root,const char *path,struct storage_files_stream *stream,const char **reason) {
    (void)root;
    const char *test_root=getenv("DOCKER_WORKFLOW_TEST_ROOT");
    struct stat st;
    if(!test_root||strncmp(path,test_root,strlen(test_root))||path[strlen(test_root)]!='/') {*reason="outside_test_root";return -1;}
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)){if(fd>=0)close(fd);*reason="test_file_unavailable";return -1;}
    memset(stream,0,sizeof(*stream));stream->fd=fd;stream->size_bytes=st.st_size;stream->inode=st.st_ino;stream->modified_unix=st.st_mtime;
    snprintf(stream->basename,sizeof(stream->basename),"%s",strrchr(path,'/')+1);return 0;
}
#define API_CODE_SUCCESS 2000
#define API_CODE_ERROR 5000
static struct json_object *jmx_gen_api_response_data(int code,struct json_object *data) {
    struct json_object *response=json_object_new_object();
    json_object_object_add(response,"code",json_object_new_int(code));json_object_object_add(response,"data",data);return response;
}
struct nc_docker_http_buffer { char *data; size_t len; };
struct nc_docker_compose_file { char dir[128]; char path[160]; };

struct nc_exec_result {
    char *output;
    int rc;
    int timed_out;
    int truncated;
};

struct nc_container_label {
    const char *key;
    const char *value;
    size_t value_len;
};

static int nc_container_job_id_valid(const char *id);
static pthread_mutex_t g_container_job_workers_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t g_container_job_workers[NC_CONTAINER_JOB_ACTIVE_MAX];

#ifdef DOCKER_MIGRATION_TESTING
static int nc_docker_migration_guard(void);
static int nc_docker_migration_pending(void);
static struct json_object *nc_docker_migration_plan(struct json_object *);
static int nc_docker_migration_submit(struct json_object *,struct json_object *);
static int nc_docker_migration_execute(sqlite3 *,const char *,struct json_object *,struct json_object *);
#else
static int nc_docker_migration_guard(void){return -2;}
static int nc_docker_migration_pending(void){return 0;}
static struct json_object *nc_docker_migration_plan(struct json_object *cfg){(void)cfg;return json_object_new_object();}
static int nc_docker_migration_submit(struct json_object *cfg,struct json_object *out){(void)cfg;(void)out;return -1;}
static int nc_docker_migration_execute(sqlite3 *db,const char *job,struct json_object *cfg,struct json_object *out){(void)db;(void)job;(void)cfg;(void)out;return 125;}
#endif
#ifdef DOCKER_SETTINGS_TESTING
static int nc_docker_settings_submit(struct json_object *,struct json_object *);
static int nc_docker_settings_execute(const char *,struct json_object *,struct json_object *);
#else
static int nc_docker_settings_submit(struct json_object *cfg,struct json_object *out) {(void)cfg;(void)out;return -1;}
static int nc_docker_settings_execute(const char *job,struct json_object *cfg,struct json_object *out) {(void)job;(void)cfg;(void)out;return 125;}
#endif
#include "container_service_runtime_impl.inc"

#ifdef LXC_BOOT_TESTING
/* Drive the real boot scheduler with a small test event loop. Timings stay real. */
struct uloop_timeout { void (*cb)(struct uloop_timeout *); int pending; };
static int64_t lxc_boot_test_due;
static void uloop_timeout_set(struct uloop_timeout *timer,int ms) {timer->pending=1;lxc_boot_test_due=nc_container_monotonic_ms()+ms;}
static void uloop_timeout_cancel(struct uloop_timeout *timer) {timer->pending=0;}
#define LOG_WARN(...) fprintf(stderr,__VA_ARGS__)
#include "netconfig/033_nc_lxc_autostart.inc"
#endif
#ifdef DOCKER_SETTINGS_TESTING
#include "netconfig/033_nc_docker_settings.inc"
#endif
#ifdef DOCKER_MIGRATION_TESTING
#include "netconfig/033_nc_docker_migration.inc"
#include "docker_migration_provider_fixture.inc"
#endif

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static void print_json(struct json_object *object)
{
    puts(json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN));
}

int main(int argc, char **argv)
{
#ifdef LXC_BOOT_TESTING
    if(argc==2&&!strcmp(argv[1],"lxc-boot")){
        jmx_lxc_autostart_start();
        int64_t until=nc_container_monotonic_ms()+60000;
        while(nc_lxc_boot_timer.pending&&nc_container_monotonic_ms()<until){
            if(nc_container_monotonic_ms()>=lxc_boot_test_due){nc_lxc_boot_timer.pending=0;nc_lxc_boot_timer.cb(&nc_lxc_boot_timer);}
            else {struct timespec pause={.tv_nsec=10000000};nanosleep(&pause,NULL);}
        }
        printf("{\"ok\":%s}\n",nc_lxc_boot_timer.pending?"false":"true");
        jmx_lxc_autostart_stop();return 0;
    }
    if(argc==2&&!strcmp(argv[1],"lxc-boot-candidates")){
        struct json_object *items=nc_lxc_boot_candidates();print_json(items);json_object_put(items);return 0;
    }
#endif
    sqlite3 *db = NULL;

    if(argc==2&&!strcmp(argv[1],"lxc-templates")){
        struct json_object *out=jmx_lxc_templates_get();print_json(out);json_object_put(out);return 0;
    }
    if(argc==2&&!strcmp(argv[1],"lxc-settings")){
        struct json_object *out=jmx_lxc_config_get();print_json(out);json_object_put(out);return 0;
    }
    if(argc==3&&!strcmp(argv[1],"lxc-settings-save")){
        struct json_object *cfg=json_tokener_parse(argv[2]),*out=json_object_new_object();
        int rc=jmx_lxc_settings_save(cfg,out);print_json(out);json_object_put(out);json_object_put(cfg);return rc?1:0;
    }
    if (argc == 3 && !strcmp(argv[1],"lxc-config")) {
        struct json_object *out=jmx_lxc_config_document_get(argv[2]);
        print_json(out);json_object_put(out);return 0;
    }
    if (argc == 5 && !strcmp(argv[1],"lxc-action")) {
        struct json_object *cfg=json_tokener_parse(argv[4]),*out=json_object_new_object();
        int rc=jmx_lxc_container_action(argv[2],argv[3],cfg,out);
        print_json(out);json_object_put(out);if(cfg)json_object_put(cfg);return rc?1:0;
    }
    if (argc == 3 && (!strcmp(argv[1],"lxc-get")||!strcmp(argv[1],"docker-get"))) {
        struct json_object *out=!strcmp(argv[1],"lxc-get")?jmx_lxc_job_get(argv[2]):jmx_docker_job_get(argv[2]);
        print_json(out);json_object_put(out);return 0;
    }
    if (argc == 2 && (!strcmp(argv[1],"lxc-list")||!strcmp(argv[1],"docker-list"))) {
        struct json_object *out=!strcmp(argv[1],"lxc-list")?jmx_lxc_jobs_list(NULL):jmx_docker_jobs_list(NULL);
        print_json(out);json_object_put(out);return 0;
    }
    if (argc == 3 && !strcmp(argv[1],"lxc-cancel")) {
        struct json_object *cfg=json_tokener_parse("{\"confirm\":true}"),*out=json_object_new_object();
        int rc=jmx_lxc_job_cancel(argv[2],cfg,out);print_json(out);json_object_put(out);json_object_put(cfg);return rc?1:0;
    }
    if (argc == 3 && !strcmp(argv[1], "--container-job-worker"))
        return jmx_docker_job_worker(argv[2]);
    if (argc == 2 && !strcmp(argv[1], "migrate")) {
        CHECK(nc_container_job_db_open(&db) == 0);
        CHECK(sqlite3_close(db) == SQLITE_OK);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "normalize")) {
        struct json_object *request = json_tokener_parse(argv[2]);
        struct json_object *error = json_object_new_object();
        char *canonical = NULL;
        char target[256] = "", name[129] = "";
        int rc;

        CHECK(request != NULL && error != NULL);
        rc = nc_docker_create_normalize(request, &canonical, target,
                                        sizeof(target), name, sizeof(name), error);
        if (rc == 0)
            puts(canonical);
        else
            print_json(error);
        free(canonical);
        json_object_put(error);
        json_object_put(request);
        return rc == 0 ? 0 : 1;
    }
    if (argc == 3 && (!strcmp(argv[1], "workflow-read")||!strcmp(argv[1], "workflow-write"))) {
        struct json_object *request=json_tokener_parse(argv[2]),*out=NULL;int rc=0;
        CHECK(request!=NULL);
        if(!strcmp(argv[1],"workflow-read"))out=jmx_docker_workbench_read(request);
        else {out=json_object_new_object();rc=jmx_docker_workbench_write(request,out);}
        print_json(out);json_object_put(out);json_object_put(request);return rc?1:0;
    }
#ifdef DOCKER_SETTINGS_TESTING
    if (argc == 2 && !strcmp(argv[1], "config-get")) {
        struct json_object *out=jmx_docker_config_get();print_json(out);json_object_put(out);return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "config-set")) {
        struct json_object *cfg=json_tokener_parse(argv[2]),*out=json_object_new_object();
        int rc=jmx_docker_config_set(cfg,out);print_json(out);json_object_put(out);json_object_put(cfg);return rc?1:0;
    }
#endif
    if (argc == 3 && !strcmp(argv[1], "network-create")) {
        struct json_object *request=json_tokener_parse(argv[2]), *out=json_object_new_object();
        int rc=jmx_docker_network_create(request,out);
        print_json(out); json_object_put(out); json_object_put(request); return rc ? 1 : 0;
    }
    if (argc == 3 && (!strcmp(argv[1], "create") || !strcmp(argv[1], "pull"))) {
        struct json_object *request = json_tokener_parse(argv[2]);
        struct json_object *out = json_object_new_object();
        int rc;

        CHECK(request != NULL && out != NULL);
        rc = !strcmp(argv[1], "pull") ? jmx_docker_image_pull(request, out) : jmx_docker_container_create(request, out);
        print_json(out);
        json_object_put(out);
        json_object_put(request);
        return rc == 0 ? 0 : 1;
    }
    if (argc == 3 && !strcmp(argv[1], "worker"))
        return jmx_docker_job_worker(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "cancel")) {
        struct json_object *request = json_tokener_parse("{\"confirm\":true}");
        struct json_object *out = json_object_new_object();
        int rc;

        CHECK(request != NULL && out != NULL);
        rc = jmx_docker_job_cancel(argv[2], request, out);
        print_json(out);
        json_object_put(out);
        json_object_put(request);
        return rc == 0 ? 0 : 1;
    }
    if (argc == 2 && !strcmp(argv[1], "reconcile")) {
        int rc;

        CHECK(nc_container_job_db_open(&db) == 0);
        rc = nc_container_jobs_reconcile(db);
        CHECK(sqlite3_close(db) == SQLITE_OK);
        return rc == 0 ? 0 : 1;
    }
    fprintf(stderr, "usage: %s migrate|normalize JSON|create JSON|worker ID|cancel ID|reconcile\n",
            argv[0]);
    return 2;
}
