#define _GNU_SOURCE

#include <ctype.h>
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

#include "container_service_runtime_impl.inc"

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
    sqlite3 *db = NULL;

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
    if (argc == 3 && !strcmp(argv[1], "create")) {
        struct json_object *request = json_tokener_parse(argv[2]);
        struct json_object *out = json_object_new_object();
        int rc;

        CHECK(request != NULL && out != NULL);
        rc = jmx_docker_container_create(request, out);
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
