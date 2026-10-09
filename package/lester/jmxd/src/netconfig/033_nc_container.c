        if (!ifname[0] || strlen(ifname) > 32) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("invalid_ifname"));
            return -1;
        }
        /* Reject traversal and separators before building a sysfs path. */
        for (i = 0; ifname[i]; i++) {
            if (!isalnum((unsigned char)ifname[i]) &&
                ifname[i] != '-' && ifname[i] != '_' && ifname[i] != '.') {
                json_object_object_add(out, "ok", json_object_new_boolean(0));
                json_object_object_add(out, "error",
                                       json_object_new_string("invalid_ifname"));
                return -1;
            }
        }
        if (queue < 0 || queue > 4095) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("invalid_rx_queue"));
            return -1;
        }
        if (!nc_net_tune_mask_valid(rps)) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("invalid_rps_mask"));
            json_object_object_add(out, "message",
                                   json_object_new_string("rps_cpus must be a hex CPU mask, optionally comma grouped"));
            return -1;
        }
        snprintf(path, sizeof(path), "/sys/class/net/%s/queues/rx-%d/rps_cpus",
                 ifname, queue);
        json_object_object_add(out, "path", json_object_new_string(path));
        if (nc_irq_read_text(path, readback, sizeof(readback)) != 0) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("rps_queue_absent"));
            return -1;
        }
        json_object_object_add(out, "previous", json_object_new_string(readback));
        if (!nc_net_tune_path_writable(path)) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("rps_read_only"));
            return -1;
        }
        if (nc_net_tune_write_path(path, rps, out) != 0)
            return -1;
        readback[0] = 0;
        if (nc_irq_read_text(path, readback, sizeof(readback)) != 0) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("readback_failed"));
            return -1;
        }
        json_object_object_add(out, "readback", json_object_new_string(readback));
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
        return 0;
    }

    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("missing_target"));
    json_object_object_add(out, "message",
                           json_object_new_string("send knob+value or ifname+rx_queue+rps_cpus"));
    return -1;
}

int jmx_system_cpu_interrupt_set(struct json_object *cfg, struct json_object *out)
{
    if (!cfg || !out) return -1;
    if (nc_json_str_def(cfg, "operation", "")[0])
        return nc_cpu_steering_batch_irq_set(cfg, out);
    const char *irq_str = nc_json_str_def(cfg, "irq", "");
    const char *affinity = nc_json_str_def(cfg, "smp_affinity", "");
    int irq = atoi(irq_str);
    if (irq <= 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_irq"));
        return -1;
    }
    if (!affinity[0] || strlen(affinity) > 255) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("missing_smp_affinity"));
        return -1;
    }
    /* Linux also accepts comma-separated 32-bit groups on large CPU sets. */
    int has_nonzero = 0;
    for (const char *p = affinity; *p; p++) {
        char c = *p;
        if (c != ',' && !isxdigit((unsigned char)c)) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error", json_object_new_string("invalid_affinity_format"));
            json_object_object_add(out, "message", json_object_new_string("smp_affinity must be a hex CPU mask, optionally comma grouped"));
            return -1;
        }
        if (c >= '1' && c <= '9') has_nonzero = 1;
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) has_nonzero = 1;
    }
    if (!has_nonzero || affinity[0] == ',' || affinity[strlen(affinity) - 1] == ',' || strstr(affinity, ",,")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_affinity_mask"));
        return -1;
    }
    char path[128];
    snprintf(path, sizeof(path), "/proc/irq/%d/smp_affinity", irq);
    if (!nc_irq_affinity_path_writable(path)) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("irq_affinity_read_only"));
        json_object_object_add(out, "reason",
                               json_object_new_string("kernel_managed_affinity_or_read_only"));
        json_object_object_add(out, "irq", json_object_new_int(irq));
        json_object_object_add(out, "persistent", json_object_new_boolean(0));
        return -1;
    }
    FILE *fp = fopen(path, "w");
    if (!fp) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("write_failed"));
        char msg[256];
        snprintf(msg, sizeof(msg), "cannot write %s: %s", path, strerror(errno));
        json_object_object_add(out, "message", json_object_new_string(msg));
        return -1;
    }
    errno = 0;
    {
        int write_rc = fprintf(fp, "%s\n", affinity);
        int flush_rc = write_rc < 0 ? -1 : fflush(fp);
        int saved_errno = errno;
        int close_rc = fclose(fp);
        char msg[256];

        if (write_rc >= 0 && flush_rc == 0 && close_rc == 0)
            goto affinity_written;
        if (!saved_errno)
            saved_errno = errno;
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("write_failed"));
        snprintf(msg, sizeof(msg), "cannot write %s: %s", path,
                 saved_errno ? strerror(saved_errno) : "kernel rejected affinity");
        json_object_object_add(out, "message", json_object_new_string(msg));
        return -1;
    }
affinity_written: ;
    /* Verify */
    char readback[512] = "";
    fp = fopen(path, "r");
    if (!fp || !fgets(readback, sizeof(readback), fp)) {
        if (fp) fclose(fp);
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("readback_failed"));
        return -1;
    }
    fclose(fp);
    readback[strcspn(readback, "\r\n")] = 0;
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "irq", json_object_new_int(irq));
    json_object_object_add(out, "smp_affinity", json_object_new_string(affinity));
    json_object_object_add(out, "readback", json_object_new_string(readback));
    json_object_object_add(out, "persistent", json_object_new_boolean(0));
    json_object_object_add(out, "semantic", json_object_new_string("irq_smp_affinity"));
    json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
    return 0;
}

/* ═══ SSH Idle Timeout ═══ */
int jmx_system_ssh_idle_timeout_set(struct json_object *cfg, struct json_object *out)
{
    const char *provider = nc_sys_ssh_provider();
    int timeout_min;
    int rc;
    struct json_object *ssh;

    if (!cfg || !out) return -1;
    timeout_min = nc_json_int_def(cfg, "idle_timeout_min", 0);
    if (timeout_min < 0) timeout_min = 0;
    if (timeout_min > 1440) timeout_min = 1440;  /* max 24h */
    ssh = json_object_new_object();
    if (!ssh)
        return -1;
    json_object_object_add(ssh, "idle_timeout_min", json_object_new_int(timeout_min));
    rc = nc_sys_ssh_settings_apply(ssh);
    json_object_put(ssh);
    json_object_object_add(out, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "provider", json_object_new_string(provider));
    json_object_object_add(out, "idle_timeout_min", json_object_new_int(timeout_min));
    json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
    if (rc != 0) {
        json_object_object_add(out, "error", json_object_new_string("apply_failed"));
    }
    return rc == 0 ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════════
 *  Container Service — Docker + LXC
 * ═══════════════════════════════════════════════════════════════ */

/* ── Helpers ── */

int nc_cmd_exists(const char *cmd)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "command -v %s >/dev/null 2>&1", cmd);
    return system(buf) == 0;
}

char *nc_cmd_output(const char *cmd, int max_len)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    char *buf = calloc(1, max_len + 1);
    if (!buf) { pclose(fp); return NULL; }
    size_t n = fread(buf, 1, max_len, fp);
    pclose(fp);
    buf[n] = 0;
    return buf;
}

#define NC_CONTAINER_OUTPUT_MAX (64U * 1024U)
#ifndef NC_CONTAINER_JOB_DB_PATH
#define NC_CONTAINER_JOB_DB_PATH jmx_dataset_path("core")
#endif
#ifndef NC_CONTAINER_JOB_EXEC_PATH
#define NC_CONTAINER_JOB_EXEC_PATH "/usr/bin/dreamingwrt-core"
#endif
#ifndef NC_CONTAINER_SECRET_KEY_PATH
#define NC_CONTAINER_SECRET_KEY_PATH "/etc/dreamingwrt/container-secrets.key"
#endif
#define NC_CONTAINER_JOB_ID_LEN 36
#define NC_CONTAINER_JOB_RETENTION_SEC (7 * 86400)
#define NC_CONTAINER_JOB_MAX_ROWS 1000
#define NC_CONTAINER_JOB_ACTIVE_MAX 2
#define NC_CONTAINER_JOB_WORKER_COMM "dwrt-docker-job"
#define NC_CONTAINER_CREATE_COMMAND_MAX 64
#define NC_CONTAINER_CREATE_COMMAND_ITEM_MAX 1024
#define NC_CONTAINER_CREATE_COMMAND_TOTAL_MAX 8192
#define NC_CONTAINER_CREATE_LABEL_MAX 64
#define NC_CONTAINER_CREATE_LABEL_KEY_MAX 128
#define NC_CONTAINER_CREATE_LABEL_VALUE_MAX 512
#define NC_CONTAINER_CREATE_ARGV_MAX 512
#define NC_CONTAINER_CREATE_JSON_MAX (128U * 1024U)

static int nc_container_job_id_valid(const char *id);
static int nc_lxc_jobs_conflict(sqlite3 *db,const char *request);
static int nc_lxc_job_kind(const char *kind);
static int nc_docker_compose_available(void);
static int nc_docker_workflow_kind(const char *kind);
static int nc_docker_migration_guard(void);
static int nc_docker_migration_pending(void);
static int nc_docker_compose_build_available(void);
static int nc_docker_network_ipam_available(void);
static int nc_docker_network_driver_available(struct json_object *info, const char *driver);
static pthread_mutex_t g_container_job_workers_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t g_container_job_workers[NC_CONTAINER_JOB_ACTIVE_MAX];

static void nc_container_job_register_worker(pid_t pid)
{
    int i;

    if (pid <= 1)
        return;
    pthread_mutex_lock(&g_container_job_workers_lock);
    for (i = 0; i < NC_CONTAINER_JOB_ACTIVE_MAX; i++) {
        if (g_container_job_workers[i] <= 1) {
            g_container_job_workers[i] = pid;
            break;
        }
    }
    pthread_mutex_unlock(&g_container_job_workers_lock);
}

void jmx_docker_jobs_reap_workers(void)
{
    int i, status;

    pthread_mutex_lock(&g_container_job_workers_lock);
    for (i = 0; i < NC_CONTAINER_JOB_ACTIVE_MAX; i++) {
        pid_t pid = g_container_job_workers[i];
        pid_t reaped;

        if (pid <= 1)
            continue;
        reaped = waitpid(pid, &status, WNOHANG);
        if (reaped == pid || (reaped < 0 && errno == ECHILD))
            g_container_job_workers[i] = 0;
    }
    pthread_mutex_unlock(&g_container_job_workers_lock);
}

struct nc_exec_result {
    char *output;
    int rc;
    int timed_out;
    int truncated;
};

static int64_t nc_container_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void nc_exec_result_free(struct nc_exec_result *result)
{
    if (!result)
        return;
    free(result->output);
    memset(result, 0, sizeof(*result));
}

static void nc_exec_trim_output(char *output)
{
    size_t len;

    if (!output)
        return;
    len = strlen(output);
    while (len > 0 && (output[len - 1] == '\n' || output[len - 1] == '\r'))
        output[--len] = '\0';
}

static int nc_exec_argv_capture_ex(const char *const argv[], int timeout_s,
                                   size_t max_output, struct nc_exec_result *result,
                                   int isolate_process_group)
{
    int pipefd[2] = {-1, -1};
    pid_t pid;
    int status = 0;
    int child_done = 0;
    int pipe_eof = 0;
    int flags;
    int64_t deadline;
    size_t used = 0;

    if (!argv || !argv[0] || !result || timeout_s < 1)
        return -1;
    memset(result, 0, sizeof(*result));
    int migration_guard = !strcmp(argv[0], "docker") ? nc_docker_migration_guard() : -2;
    if (migration_guard == -1) { result->rc=125; result->output=strdup("docker_migration_busy_or_recovery_required"); return 125; }
    if (max_output > NC_CONTAINER_OUTPUT_MAX)
        max_output = NC_CONTAINER_OUTPUT_MAX;
    result->output = calloc(1, max_output + 1);
    if (!result->output) { if(migration_guard>=0)close(migration_guard); return -1; }
    if (pipe(pipefd) != 0)
        goto fail;

    pid = fork();
    if (pid < 0)
        goto fail;
    if (pid == 0) {
        if (isolate_process_group)
            (void)setpgid(0, 0);
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(126);
        close(pipefd[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    close(pipefd[1]);
    pipefd[1] = -1;
    if (isolate_process_group)
        (void)setpgid(pid, pid);
    flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags < 0 || fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        if (isolate_process_group)
            (void)kill(-pid, SIGKILL);
        (void)kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        goto fail;
    }
    deadline = nc_container_monotonic_ms() + (int64_t)timeout_s * 1000;

    while (!child_done || !pipe_eof) {
        char chunk[2048];
        ssize_t n;
        pid_t waited;

        do {
            n = read(pipefd[0], chunk, sizeof(chunk));
            if (n > 0) {
                size_t copy = (size_t)n;
                if (copy > max_output - used)
                    copy = max_output - used;
                if (copy > 0) {
                    memcpy(result->output + used, chunk, copy);
                    used += copy;
                    result->output[used] = '\0';
                }
                if (copy < (size_t)n)
                    result->truncated = 1;
            }
        } while (n > 0);
        if (n == 0)
            pipe_eof = 1;
        else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            pipe_eof = 1;

        if (!child_done) {
            waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid)
                child_done = 1;
            else if (waited < 0 && errno != EINTR) {
                status = 127 << 8;
                child_done = 1;
            }
        }
        if (!child_done && nc_container_monotonic_ms() >= deadline) {
            result->timed_out = 1;
            if (isolate_process_group)
                (void)kill(-pid, SIGTERM);
            (void)kill(pid, SIGTERM);
            usleep(200000);
            if (isolate_process_group)
                (void)kill(-pid, SIGKILL);
            (void)kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            child_done = 1;
        }
        if (!child_done || !pipe_eof) {
            struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN | POLLHUP};
            (void)poll(&pfd, 1, 50);
        }
        if (child_done && !pipe_eof) {
            struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN | POLLHUP};
            if (poll(&pfd, 1, 0) == 0)
                pipe_eof = 1;
        }
    }

    close(pipefd[0]);
    nc_exec_trim_output(result->output);
    if (result->timed_out)
        result->rc = 124;
    else if (WIFEXITED(status))
        result->rc = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        result->rc = 128 + WTERMSIG(status);
    else
        result->rc = 127;
    if(migration_guard>=0)close(migration_guard);
    return result->rc;

fail:
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    nc_exec_result_free(result);
    if(migration_guard>=0)close(migration_guard);
    return -1;
}

static int nc_exec_argv_capture(const char *const argv[], int timeout_s,
                                size_t max_output, struct nc_exec_result *result)
{
    return nc_exec_argv_capture_ex(argv, timeout_s, max_output, result, 1);
}

static int nc_exec_argv_json(const char *const argv[], int timeout_s,
                             size_t max_output, struct json_object *out)
{
    struct nc_exec_result result;
    int rc;

    if (!out)
        return -1;
    rc = nc_exec_argv_capture(argv, timeout_s, max_output, &result);
    if (rc < 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("exec_failed"));
        json_object_object_add(out, "rc", json_object_new_int(-1));
        return -1;
    }
    json_object_object_add(out, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(out, "rc", json_object_new_int(rc));
    json_object_object_add(out, "output", json_object_new_string(result.output));
    json_object_object_add(out, "timed_out", json_object_new_boolean(result.timed_out));
    json_object_object_add(out, "output_truncated", json_object_new_boolean(result.truncated));
    nc_exec_result_free(&result);
    return rc;
}

/* Parse a tab/table output line into json fields */
#include "033_nc_docker_read.inc"

struct json_object *jmx_container_docker_get(void)
{
    return nc_docker_workbench_get();
}


/* ── LXC GET ── */

#include "033_nc_lxc_read.inc"

/* ── Container Service Summary ── */

struct json_object *jmx_container_service_get(void)
{
    struct json_object *d = json_object_new_object();
    struct json_object *cap = json_object_new_object();
    int has_docker = nc_cmd_exists("docker");
    json_object_object_add(d, "contract_version", json_object_new_string("container-service.v1"));
    json_object_object_add(cap, "read", json_object_new_boolean(1));
    json_object_object_add(cap, "docker_actions", json_object_new_boolean(has_docker));
    json_object_object_add(cap, "lxc_actions", json_object_new_boolean(0));
    json_object_object_add(d, "capabilities", cap);

    /* embed docker + lxc sub-responses */
    struct json_object *docker = NULL, *lxc = NULL;
    struct json_object *docker_resp = jmx_container_docker_get();
    struct json_object *lxc_resp = jmx_container_lxc_get();
    json_object_object_get_ex(docker_resp, "data", &docker);
    json_object_object_get_ex(lxc_resp, "data", &lxc);
    if (docker) json_object_object_add(d, "docker", json_object_get(docker));
    if (lxc) json_object_object_add(d, "lxc", json_object_get(lxc));
    json_object_put(docker_resp);
    json_object_put(lxc_resp);

    json_object_object_add(d, "source", json_object_new_string("jmxd-container-service"));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}


/* ═══ Docker Operations ═══ */

static int nc_docker_name_valid(const char *name)
{
    size_t len;

    if (!name || !name[0]) return 0;
    len = strlen(name);
    if (len > 128 || !isalnum((unsigned char)name[0])) return 0;
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int nc_docker_resource_id_valid(const char *id)
{
    size_t len;

    if (!id || !id[0]) return 0;
    len = strlen(id);
    if (len > 255 || !isalnum((unsigned char)id[0])) return 0;
    for (const char *p = id; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int nc_docker_image_id_valid(const char *id)
{
    size_t len;

    if (!id || !id[0]) return 0;
    len = strlen(id);
    if (len > 255 || !isalnum((unsigned char)id[0])) return 0;
    for (const char *p = id; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' ||
              c == '/' || c == '@' || c == '+'))
            return 0;
    }
    return 1;
}

static int nc_docker_driver_valid(const char *driver)
{
    size_t len;

    if (!driver || !driver[0]) return 0;
    len = strlen(driver);
    if (len > 64 || !isalnum((unsigned char)driver[0])) return 0;
    for (const char *p = driver; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int nc_docker_hostname_valid(const char *hostname)
{
    size_t len, label_len = 0;
    int label_start = 1;

    if (!hostname || !hostname[0])
        return 0;
    len = strlen(hostname);
    if (len > 253)
        return 0;
    for (const unsigned char *p = (const unsigned char *)hostname; *p; p++) {
        if (*p == '.') {
            if (label_start || p[-1] == '-')
                return 0;
            label_start = 1;
            label_len = 0;
            continue;
        }
        if (!(isalnum(*p) || (*p == '-' && !label_start)) || ++label_len > 63)
            return 0;
        label_start = 0;
    }
    return !label_start && hostname[len - 1] != '-';
}

static int nc_docker_label_key_valid(const char *key)
{
    size_t len;

    if (!key || !key[0])
        return 0;
    len = strlen(key);
    if (len > NC_CONTAINER_CREATE_LABEL_KEY_MAX ||
        !isalnum((unsigned char)key[0]))
        return 0;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++)
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    return 1;
}

static int nc_docker_label_value_valid(const char *value, size_t len)
{
    size_t i;

    if (!value || len > NC_CONTAINER_CREATE_LABEL_VALUE_MAX || strlen(value) != len)
        return 0;
    for (i = 0; i < len; i++)
        if ((unsigned char)value[i] < 0x20 || (unsigned char)value[i] > 0x7e)
            return 0;
    return 1;
}

static int nc_docker_restart_policy_valid(const char *policy)
{
    const char *retry;
    char *end = NULL;
    long value;

    if (!policy || !policy[0] || strlen(policy) > 32)
        return 0;
    if (!strcmp(policy, "no") || !strcmp(policy, "always") ||
        !strcmp(policy, "unless-stopped") || !strcmp(policy, "on-failure"))
        return 1;
    if (strncmp(policy, "on-failure:", 11))
        return 0;
    retry = policy + 11;
    if (!retry[0] || (retry[0] == '0' && retry[1]))
        return 0;
    errno = 0;
    value = strtol(retry, &end, 10);
    return errno == 0 && end && !*end && value >= 1 && value <= 100;
}

static int nc_docker_container_id_from_output(const char *output,
                                              char *id, size_t id_len)
{
    const char *line, *end;
    size_t len, i;

    if (!output || !output[0] || !id || id_len < 65)
        return -1;
    line = strrchr(output, '\n');
    line = line ? line + 1 : output;
    while (*line && isspace((unsigned char)*line))
        line++;
    end = line + strlen(line);
    while (end > line && isspace((unsigned char)end[-1]))
        end--;
    len = (size_t)(end - line);
    if (len != 64)
        return -1;
    for (i = 0; i < len; i++)
        if (!isxdigit((unsigned char)line[i]))
            return -1;
    memcpy(id, line, len);
    id[len] = '\0';
    return 0;
}

static int nc_docker_create_error(struct json_object *out, const char *error,
                                  const char *field, const char *reason)
{
    if (!out)
        return -1;
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string(error));
    if (field)
        json_object_object_add(out, "field", json_object_new_string(field));
    if (reason)
        json_object_object_add(out, "reason", json_object_new_string(reason));
    return -1;
}

static int nc_docker_create_field_supported(const char *key)
{
    static const char *const fields[] = {
        "image", "name", "hostname", "restart_policy", "network",
        "command", "labels", "ports", "mounts", "env", "resources",
        "start_after_create", "id", "action", "confirm", NULL
    };
    int i;

    for (i = 0; fields[i]; i++)
        if (!strcmp(key, fields[i]))
            return 1;
    return 0;
}

struct nc_container_label {
    const char *key;
    const char *value;
    size_t value_len;
};

static int nc_container_label_compare(const void *left, const void *right)
{
    const struct nc_container_label *a = left;
    const struct nc_container_label *b = right;

    return strcmp(a->key, b->key);
}

#include "033_nc_docker_create.inc"

static int nc_docker_create_normalize(struct json_object *cfg, char **canonical_out,
                                      char *target, size_t target_len,
                                      char *requested_name, size_t requested_name_len,
                                      struct json_object *out)
{
    struct json_object *canonical = NULL, *value = NULL;
    struct nc_container_label labels[NC_CONTAINER_CREATE_LABEL_MAX];
    const char *image;
    size_t label_count = 0, command_total = 0, i;
    char *canonical_text = NULL;

    if (canonical_out)
        *canonical_out = NULL;
    if (target && target_len)
        target[0] = '\0';
    if (requested_name && requested_name_len)
        requested_name[0] = '\0';
    if (!cfg || !json_object_is_type(cfg, json_type_object))
        return nc_docker_create_error(out, "invalid_container_create_request",
                                      NULL, "object_required");
    json_object_object_foreach(cfg, key, ignored) {
        (void)ignored;
        if (!nc_docker_create_field_supported(key))
            return nc_docker_create_error(out, "unsupported_container_create_field",
                                          key, "field_not_in_container_create_schema");
    }
    if (!json_object_object_get_ex(cfg, "image", &value))
        return nc_docker_create_error(out, "invalid_container_create_request",
                                      "image", "image_required");
    if (!json_object_is_type(value, json_type_string) ||
        json_object_get_string_len(value) != (int)strlen(json_object_get_string(value)) ||
        !nc_docker_image_id_valid(json_object_get_string(value)))
        return nc_docker_create_error(out, "invalid_container_create_request",
                                      "image", "invalid_image_reference");
    image = json_object_get_string(value);
    canonical = json_object_new_object();
    if (!canonical)
        return nc_docker_create_error(out, "container_job_storage_failed", NULL,
                                      "out_of_memory");
    json_object_object_add(canonical, "image", json_object_new_string(image));
    if (target && target_len)
        snprintf(target, target_len, "%s", image);

#define NC_CREATE_OPTIONAL_STRING(field_name, validator, destination, destination_len) do { \
    if (json_object_object_get_ex(cfg, (field_name), &value)) { \
        const char *text_value; \
        if (!json_object_is_type(value, json_type_string)) { \
            json_object_put(canonical); \
            return nc_docker_create_error(out, "invalid_container_create_request", \
                                          (field_name), "string_required"); \
        } \
        text_value = json_object_get_string(value); \
        if (json_object_get_string_len(value) != (int)strlen(text_value) || !(validator)(text_value)) { \
            json_object_put(canonical); \
            return nc_docker_create_error(out, "invalid_container_create_request", \
                                          (field_name), "invalid_value"); \
        } \
        json_object_object_add(canonical, (field_name), json_object_new_string(text_value)); \
        if ((destination) && (destination_len)) \
            snprintf((destination), (destination_len), "%s", text_value); \
    } \
} while (0)

    NC_CREATE_OPTIONAL_STRING("name", nc_docker_name_valid,
                              requested_name, requested_name_len);
    NC_CREATE_OPTIONAL_STRING("hostname", nc_docker_hostname_valid, NULL, 0);
    NC_CREATE_OPTIONAL_STRING("restart_policy", nc_docker_restart_policy_valid, NULL, 0);
    if (json_object_object_get_ex(cfg, "network", &value)) {
        const char *network;
        if (!json_object_is_type(value, json_type_string)) {
            json_object_put(canonical);
            return nc_docker_create_error(out, "invalid_container_create_request",
                                          "network", "string_required");
        }
        network = json_object_get_string(value);
        if (json_object_get_string_len(value) != (int)strlen(network) ||
            !nc_docker_name_valid(network)) {
            json_object_put(canonical);
            return nc_docker_create_error(out, "invalid_container_create_request",
                                          "network", "invalid_safe_resource_name");
        }
        if (!strcmp(network, "host")) {
            json_object_put(canonical);
            return nc_docker_create_error(out, "unsupported_container_create_field",
                                          "network", "host_network_unsupported");
        }
        json_object_object_add(canonical, "network", json_object_new_string(network));
    }
    if (json_object_object_get_ex(cfg, "command", &value)) {
        struct json_object *command;
        size_t count;

        if (!json_object_is_type(value, json_type_array)) {
            json_object_put(canonical);
            return nc_docker_create_error(out, "invalid_container_create_request",
                                          "command", "string_array_required");
        }
        count = json_object_array_length(value);
        if (count > NC_CONTAINER_CREATE_COMMAND_MAX) {
            json_object_put(canonical);
            return nc_docker_create_error(out, "invalid_container_create_request",
                                          "command", "too_many_items");
        }
        command = json_object_new_array();
        for (i = 0; i < count; i++) {
            struct json_object *item = json_object_array_get_idx(value, i);
            const char *text;
            size_t len;

            if (!item || !json_object_is_type(item, json_type_string)) {
                json_object_put(command);
                json_object_put(canonical);
                return nc_docker_create_error(out, "invalid_container_create_request",
                                              "command", "string_array_required");
            }
            text = json_object_get_string(item);
            len = (size_t)json_object_get_string_len(item);
            if (strlen(text) != len || len > NC_CONTAINER_CREATE_COMMAND_ITEM_MAX ||
                command_total + len > NC_CONTAINER_CREATE_COMMAND_TOTAL_MAX) {
                json_object_put(command);
                json_object_put(canonical);
                return nc_docker_create_error(out, "invalid_container_create_request",
                                              "command", "command_size_limit_exceeded");
            }
            command_total += len;
            json_object_array_add(command, json_object_new_string_len(text, (int)len));
        }
        json_object_object_add(canonical, "command", command);
    }
    if (json_object_object_get_ex(cfg, "labels", &value)) {
        struct json_object *label_object;

        if (!json_object_is_type(value, json_type_object)) {
            json_object_put(canonical);
            return nc_docker_create_error(out, "invalid_container_create_request",
                                          "labels", "object_required");
        }
        json_object_object_foreach(value, key, label_value) {
            const char *text;
            size_t len;

            if (label_count >= NC_CONTAINER_CREATE_LABEL_MAX ||
                !nc_docker_label_key_valid(key) ||
                !json_object_is_type(label_value, json_type_string)) {
                json_object_put(canonical);
                return nc_docker_create_error(out, "invalid_container_create_request",
                                              "labels", label_count >= NC_CONTAINER_CREATE_LABEL_MAX ?
                                              "too_many_labels" : "invalid_label");
            }
            text = json_object_get_string(label_value);
            len = (size_t)json_object_get_string_len(label_value);
            if (!nc_docker_label_value_valid(text, len)) {
                json_object_put(canonical);
                return nc_docker_create_error(out, "invalid_container_create_request",
                                              "labels", "invalid_label_value");
            }
            labels[label_count].key = key;
            labels[label_count].value = text;
            labels[label_count].value_len = len;
            label_count++;
        }
        qsort(labels, label_count, sizeof(labels[0]), nc_container_label_compare);
        label_object = json_object_new_object();
        for (i = 0; i < label_count; i++)
            json_object_object_add(label_object, labels[i].key,
                json_object_new_string_len(labels[i].value, (int)labels[i].value_len));
        json_object_object_add(canonical, "labels", label_object);
    }
#undef NC_CREATE_OPTIONAL_STRING
    if (nc_docker_create_extended(cfg, canonical, out) != 0) {
        json_object_put(canonical); return -1;
    }

    canonical_text = strdup(json_object_to_json_string_ext(canonical, JSON_C_TO_STRING_PLAIN));
    json_object_put(canonical);
    if (!canonical_text)
        return nc_docker_create_error(out, "container_job_storage_failed", NULL,
                                      "out_of_memory");
    if (canonical_out)
        *canonical_out = canonical_text;
    else
        free(canonical_text);
    return 0;
}

static int nc_docker_bounded_int(struct json_object *cfg, const char *key,
                                 int def, int min, int max, int *value,
                                 struct json_object *out)
{
    int candidate = cfg ? nc_json_int_def(cfg, key, def) : def;

    if (candidate < min || candidate > max) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_argument"));
        json_object_object_add(out, "field", json_object_new_string(key));
        json_object_object_add(out, "min", json_object_new_int(min));
        json_object_object_add(out, "max", json_object_new_int(max));
        return -1;
    }
    *value = candidate;
    return 0;
}

static int nc_docker_confirmation_required(struct json_object *cfg,
                                           struct json_object *out)
{
    if (cfg && nc_json_bool_def(cfg, "confirm", 0))
        return 0;
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("confirmation_required"));
    json_object_object_add(out, "message", json_object_new_string("confirm=true is required"));
    return -1;
}

static int nc_docker_invalid(struct json_object *out, const char *error)
{
    if (!out)
        return -1;
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string(error));
    return -1;
}

static int nc_docker_capability_disabled(struct json_object *cfg,
                                         struct json_object *out,
                                         const char *reason)
{
    if (nc_docker_confirmation_required(cfg, out) != 0)
        return -1;
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(out, "reason", json_object_new_string(reason));
    return -1;
}

static int nc_container_job_db_open(sqlite3 **out)
{
    sqlite3 *db = NULL;
    char *err = NULL;
    const struct {
        const char *name;
        const char *definition;
    } migrations[] = {
        {"request_json", "TEXT NOT NULL DEFAULT ''"},
        {"result_id", "TEXT NOT NULL DEFAULT ''"},
        {"result_name", "TEXT NOT NULL DEFAULT ''"},
        {"output_truncated", "INTEGER NOT NULL DEFAULT 0"},
        {"result_json", "TEXT NOT NULL DEFAULT '{}'"},
    };
    size_t i;

    if (!out)
        return -1;
    *out = NULL;
    if (sqlite3_open_v2(NC_CONTAINER_JOB_DB_PATH, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    if (sqlite3_busy_timeout(db, 5000) != SQLITE_OK)
        goto failed;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK)
        goto failed;
    sqlite3_free(err); err = NULL;
    if (sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS container_job ("
        " id TEXT PRIMARY KEY,kind TEXT NOT NULL,target TEXT NOT NULL,state TEXT NOT NULL,"
        " progress INTEGER NOT NULL DEFAULT 0,worker_pid INTEGER NOT NULL DEFAULT 0,"
        " rc INTEGER NOT NULL DEFAULT -1,output TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,started_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL,completed_at INTEGER NOT NULL DEFAULT 0,"
        " request_json TEXT NOT NULL DEFAULT '',result_id TEXT NOT NULL DEFAULT '',"
        " result_name TEXT NOT NULL DEFAULT '',output_truncated INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_container_job_state_updated "
        "ON container_job(state,updated_at DESC);", NULL, NULL, &err) != SQLITE_OK)
        goto rollback;
    sqlite3_free(err); err = NULL;
    for (i = 0; i < sizeof(migrations) / sizeof(migrations[0]); i++) {
        sqlite3_stmt *st = NULL;
        int found = 0, step_rc;
        char sql[256];

        if (sqlite3_prepare_v2(db, "PRAGMA table_info(container_job)",
                              -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(st, 1);
            if (name && !strcmp(name, migrations[i].name)) {
                found = 1;
                break;
            }
        }
        if (step_rc != SQLITE_ROW && step_rc != SQLITE_DONE) {
            sqlite3_finalize(st);
            goto rollback;
        }
        if (sqlite3_finalize(st) != SQLITE_OK)
            goto rollback;
        if (found)
            continue;
        if (snprintf(sql, sizeof(sql), "ALTER TABLE container_job ADD COLUMN %s %s",
                     migrations[i].name, migrations[i].definition) >= (int)sizeof(sql))
            goto rollback;
        if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK)
            goto rollback;
        sqlite3_free(err); err = NULL;
    }
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
        goto rollback;
    sqlite3_free(err); err = NULL;
    *out = db;
    return 0;

rollback:
    sqlite3_free(err); err = NULL;
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
failed:
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
}

static int nc_container_job_worker_matches(pid_t pid, const char *job_id)
{
    char path[64], comm[32] = "", cmdline[256];
    FILE *fp;
    size_t used, offset = 0;
    int arg_index = 0, worker_arg = 0, id_arg = 0;

    if (pid <= 1 || !nc_container_job_id_valid(job_id))
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    fp = fopen(path, "r");
    if (!fp)
        return 0;
    if (fgets(comm, sizeof(comm), fp))
        comm[strcspn(comm, "\r\n")] = 0;
    fclose(fp);
    if (strcmp(comm, NC_CONTAINER_JOB_WORKER_COMM))
        return 0;
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    fp = fopen(path, "rb");
    if (!fp)
        return 0;
    used = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    if (ferror(fp) || fclose(fp) != 0 || used == 0 || used >= sizeof(cmdline) - 1)
        return 0;
    cmdline[used] = '\0';
    while (offset < used) {
        size_t len = strnlen(cmdline + offset, used - offset);

        if (len == used - offset)
            return 0;
        if (arg_index == 1)
            worker_arg = !strcmp(cmdline + offset, "--container-job-worker");
        else if (arg_index == 2)
            id_arg = !strcmp(cmdline + offset, job_id);
        arg_index++;
        offset += len + 1;
    }
    return arg_index >= 3 && worker_arg && id_arg;
}

static int nc_container_jobs_reconcile(sqlite3 *db)
{
    sqlite3_stmt *read_st = NULL, *write_st = NULL;
    struct { char id[NC_CONTAINER_JOB_ID_LEN + 1]; } stale[NC_CONTAINER_JOB_ACTIVE_MAX * 4];
    int count = 0, i;
    int64_t now = nc_now_s();

    if (!db || sqlite3_prepare_v2(db,
        "SELECT id,worker_pid,state,updated_at FROM container_job WHERE state IN ('queued','running')",
        -1, &read_st, NULL) != SQLITE_OK)
        return -1;
    for (;;) {
        int step_rc = sqlite3_step(read_st);

        if (step_rc == SQLITE_DONE)
            break;
        if (step_rc != SQLITE_ROW ||
            count >= (int)(sizeof(stale) / sizeof(stale[0]))) {
            sqlite3_finalize(read_st);
            return -1;
        }
        pid_t pid = (pid_t)sqlite3_column_int64(read_st, 1);
        const char *state = (const char *)sqlite3_column_text(read_st, 2);
        int64_t updated_at = sqlite3_column_int64(read_st, 3);
        const char *job_id = (const char *)sqlite3_column_text(read_st, 0);
        if (!nc_container_job_worker_matches(pid, job_id) &&
            (strcmp(state ? state : "", "queued") || now - updated_at > 5))
            snprintf(stale[count++].id, sizeof(stale[0].id), "%s",
                     job_id ? job_id : "");
    }
    if (sqlite3_finalize(read_st) != SQLITE_OK)
        return -1;
    if (sqlite3_prepare_v2(db,
        "UPDATE container_job SET state='failed',progress=100,worker_pid=0,rc=125,"
        "error='worker_interrupted',updated_at=?1,completed_at=?1 "
        "WHERE id=?2 AND state IN ('queued','running')", -1, &write_st, NULL) != SQLITE_OK)
        return -1;
    for (i = 0; i < count; i++) {
        if (sqlite3_reset(write_st) != SQLITE_OK ||
            sqlite3_clear_bindings(write_st) != SQLITE_OK ||
            sqlite3_bind_int64(write_st, 1, now) != SQLITE_OK ||
            sqlite3_bind_text(write_st, 2, stale[i].id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_step(write_st) != SQLITE_DONE) {
            sqlite3_finalize(write_st);
            return -1;
        }
    }
    return sqlite3_finalize(write_st) == SQLITE_OK ? 0 : -1;
}

#include "033_nc_docker_inspect.inc"

/* ── Container lifecycle ── */

int jmx_docker_container_start(const char *id, struct json_object *out)
{
    const char *const argv[] = {"docker", "start", id, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    return nc_exec_argv_json(argv, 60, 4096, out);
}

int jmx_docker_container_stop(const char *id, struct json_object *cfg, struct json_object *out)
{
    int timeout;
    char timeout_buf[16];
    const char *argv[] = {"docker", "stop", "-t", timeout_buf, id, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    if (nc_docker_bounded_int(cfg, "timeout", 10, 1, 600, &timeout, out) != 0)
        return -1;
    snprintf(timeout_buf, sizeof(timeout_buf), "%d", timeout);
    return nc_exec_argv_json(argv, timeout + 30, 4096, out);
}

int jmx_docker_container_restart(const char *id, struct json_object *cfg, struct json_object *out)
{
    int timeout;
    char timeout_buf[16];
    const char *argv[] = {"docker", "restart", "-t", timeout_buf, id, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    if (nc_docker_bounded_int(cfg, "timeout", 10, 1, 600, &timeout, out) != 0)
        return -1;
    snprintf(timeout_buf, sizeof(timeout_buf), "%d", timeout);
    return nc_exec_argv_json(argv, timeout + 30, 4096, out);
}

int jmx_docker_container_pause(const char *id, struct json_object *out)
{
    const char *const argv[] = {"docker", "pause", id, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    return nc_exec_argv_json(argv, 60, 4096, out);
}

int jmx_docker_container_unpause(const char *id, struct json_object *out)
{
    const char *const argv[] = {"docker", "unpause", id, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    return nc_exec_argv_json(argv, 60, 4096, out);
}

int jmx_docker_container_remove(const char *id, struct json_object *cfg, struct json_object *out)
{
    const char *argv[7] = {"docker", "rm", NULL, NULL, NULL, NULL, NULL};
    size_t argc = 2;

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    if (nc_docker_confirmation_required(cfg, out) != 0) return -1;
    int force = cfg ? nc_json_bool_def(cfg, "force", 0) : 0;
    int volumes = cfg ? nc_json_bool_def(cfg, "remove_volumes", 0) : 0;
    if (force) argv[argc++] = "-f";
    if (volumes) argv[argc++] = "-v";
    argv[argc++] = id;
    argv[argc] = NULL;
    return nc_exec_argv_json(argv, 120, 4096, out);
}

int jmx_docker_container_rename(const char *id, struct json_object *cfg, struct json_object *out)
{
    const char *argv[] = {"docker", "rename", id, NULL, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    if (!cfg) return nc_docker_invalid(out, "missing_payload");
    const char *new_name = nc_json_str_def(cfg, "name", "");
    if (!nc_docker_name_valid(new_name)) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_name"));
        return -1;
    }
    argv[3] = new_name;
    return nc_exec_argv_json(argv, 60, 4096, out);
}

int jmx_docker_container_restart_policy(const char *id, struct json_object *cfg, struct json_object *out)
{
    int max_retry;
    char restart_arg[96];
    const char *argv[] = {"docker", "update", restart_arg, id, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    if (!cfg) return nc_docker_invalid(out, "missing_payload");
    const char *policy = nc_json_str_def(cfg, "restart_policy", "no");
    /* validate: no, always, on-failure, unless-stopped */
    if (strcmp(policy, "no") && strcmp(policy, "always") && strcmp(policy, "on-failure") && strcmp(policy, "unless-stopped")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_policy"));
        json_object_object_add(out, "message", json_object_new_string("policy must be: no, always, on-failure, unless-stopped"));
        return -1;
    }
    if (nc_docker_bounded_int(cfg, "max_retry", 0, 0, 100, &max_retry, out) != 0)
        return -1;
    if (strcmp(policy, "on-failure") && max_retry != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_max_retry"));
        json_object_object_add(out, "message", json_object_new_string("max_retry is only valid for on-failure"));
        return -1;
    }
    if (!strcmp(policy, "on-failure") && max_retry > 0)
        snprintf(restart_arg, sizeof(restart_arg), "--restart=%s:%d", policy, max_retry);
    else
        snprintf(restart_arg, sizeof(restart_arg), "--restart=%s", policy);
    return nc_exec_argv_json(argv, 60, 4096, out);
}

struct json_object *jmx_docker_container_logs(const char *id, struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    struct nc_exec_result result;
    int tail;
    int rc;
    char tail_buf[16], since_buf[32];
    const char *argv[10] = {"docker", "logs"};
    size_t argc = 2;

    if (!nc_docker_resource_id_valid(id)) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("invalid_id"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    if (nc_docker_bounded_int(cfg, "tail", 100, 1, 10000, &tail, d) != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    int timestamps = cfg ? nc_json_bool_def(cfg, "timestamps", 0) : 0;
    snprintf(tail_buf, sizeof(tail_buf), "%d", tail);
    struct json_object *since = nc_docker_member(cfg,"since");
    if (since) {
        if (!nc_docker_integer(since,0,INT64_MAX)) {
            nc_docker_invalid(d,"invalid_since"); return jmx_gen_api_response_data(API_CODE_ERROR,d);
        }
        snprintf(since_buf,sizeof(since_buf),"%lld",(long long)json_object_get_int64(since));
        argv[argc++]="--since";argv[argc++]=since_buf;
    }
    if (timestamps) argv[argc++] = "--timestamps";
    argv[argc++] = "--tail";
    argv[argc++] = tail_buf;
    argv[argc++] = id;
    argv[argc] = NULL;
    rc = nc_exec_argv_capture(argv, 30, NC_CONTAINER_OUTPUT_MAX, &result);
    if (rc < 0) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("exec_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    json_object_object_add(d, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(d, "rc", json_object_new_int(rc));
    json_object_object_add(d, "logs", json_object_new_string(result.output));
    json_object_object_add(d, "tail", json_object_new_int(tail));
    json_object_object_add(d, "timed_out", json_object_new_boolean(result.timed_out));
    json_object_object_add(d, "output_truncated", json_object_new_boolean(result.truncated));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    nc_exec_result_free(&result);
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

#include "033_nc_docker_stats.inc"

struct json_object *jmx_docker_container_stats(const char *id)
{
    return jmx_docker_stats_get(id);
}

static int nc_container_job_spawn(const char *id)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int null_fd;

        (void)setpgid(0, 0);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDIN_FILENO);
            (void)dup2(null_fd, STDOUT_FILENO);
            (void)dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) close(null_fd);
        }
        execl(NC_CONTAINER_JOB_EXEC_PATH, "dreamingwrt-core",
              "--container-job-worker", id, (char *)NULL);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    nc_container_job_register_worker(pid);
    return 0;
}

static int nc_container_job_submit(const char *kind, const char *target,
                                   const char *request_json,
                                   struct json_object *out)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    unsigned char random[16];
    static const char hex[] = "0123456789abcdef";
    char id[NC_CONTAINER_JOB_ID_LEN + 1] = "job-";
    int i, active = 0, step_rc;
    int64_t now = nc_now_s();
    struct ac_secrets *vault = NULL;
    char secret_ref[128] = "", secret_id[80] = "";
    struct json_object *sensitive = json_tokener_parse(request_json ? request_json : "{}");
    struct json_object *environment = nc_docker_member(sensitive, "env");
    int protect = (environment && json_object_object_length(environment) > 0) ||
        (kind && (!strcmp(kind,"container_clone") || !strcmp(kind,"container_recreate") || !strcmp(kind,"container_recover") || !strcmp(kind,"network_recreate") || !strcmp(kind,"network_recover")));
    if (sensitive) json_object_put(sensitive);

    if (!out || !kind || (strcmp(kind, "image_pull") && strcmp(kind, "container_create") && !nc_docker_workflow_kind(kind) && !nc_lxc_job_kind(kind)) ||
        !target || !target[0] || !request_json)
        return nc_docker_invalid(out, "invalid_container_job_request");
    if (!nc_lxc_job_kind(kind) && nc_docker_migration_pending() && strcmp(kind,"docker_migration"))
        return nc_docker_invalid(out,"docker_migration_recovery_required");
    if (nc_container_job_db_open(&db) != 0)
        goto storage_failed;
    if (protect && (ac_secrets_schema_init(db) != AC_SECRETS_OK ||
        ac_secrets_open_or_create(db, NC_CONTAINER_SECRET_KEY_PATH, &vault) != AC_SECRETS_OK))
        goto storage_failed;
    if (nc_container_jobs_reconcile(db) != 0)
        goto storage_failed;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        goto storage_failed;
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM container_job WHERE state IN ('queued','running')",
        -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    step_rc = sqlite3_step(st);
    if (step_rc != SQLITE_ROW)
        goto rollback;
    active = sqlite3_column_int(st, 0);
    if (sqlite3_finalize(st) != SQLITE_OK) {
        st = NULL;
        goto rollback;
    }
    st = NULL;
    if(sqlite3_prepare_v2(db,"SELECT 1 FROM container_job WHERE kind='docker_migration' AND state IN ('queued','running') LIMIT 1",-1,&st,NULL)!=SQLITE_OK)goto rollback;
    step_rc=sqlite3_step(st);sqlite3_finalize(st);st=NULL;
    if(!nc_lxc_job_kind(kind) && (step_rc==SQLITE_ROW||(!strcmp(kind,"docker_migration")&&active))){
        sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);ac_secrets_close(vault);sqlite3_close(db);
        return nc_docker_invalid(out,"docker_migration_jobs_busy");
    }
    if(step_rc!=SQLITE_DONE)goto rollback;
    if (active >= NC_CONTAINER_JOB_ACTIVE_MAX) {
        if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            goto storage_failed;
        ac_secrets_close(vault);
        sqlite3_close(db);
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("container_job_busy"));
        json_object_object_add(out, "active_jobs", json_object_new_int(active));
        return -1;
    }
    if(nc_lxc_job_kind(kind)){
        int conflict=nc_lxc_jobs_conflict(db,request_json);
        if(conflict<0)goto rollback;
        if(conflict){
            sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);ac_secrets_close(vault);sqlite3_close(db);
            return nc_docker_invalid(out,"container_operation_busy");
        }
    }
    if (nc_lxc_job_kind(kind) || !strcmp(kind,"docker_config") || !strcmp(kind,"compose_action") || !strcmp(kind,"container_clone") || !strcmp(kind,"container_recreate") || !strcmp(kind,"container_recover") || !strcmp(kind,"network_recreate") || !strcmp(kind,"network_recover")) {
        if(sqlite3_prepare_v2(db,"SELECT 1 FROM container_job WHERE target=?1 AND (substr(kind,1,4)='lxc_')=?2 AND state IN ('queued','running') LIMIT 1",-1,&st,NULL)!=SQLITE_OK ||
           sqlite3_bind_text(st,1,target,-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
           sqlite3_bind_int(st,2,nc_lxc_job_kind(kind))!=SQLITE_OK)goto rollback;
        step_rc=sqlite3_step(st);sqlite3_finalize(st);st=NULL;
        if(step_rc==SQLITE_ROW) {
            sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);ac_secrets_close(vault);sqlite3_close(db);
            return nc_docker_invalid(out,!strcmp(kind,"compose_action")?"compose_project_busy":"container_operation_busy");
        }
        if(step_rc!=SQLITE_DONE)goto rollback;
    }
    {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        ssize_t got = fd >= 0 ? read(fd, random, sizeof(random)) : -1;
        if (fd >= 0 && close(fd) != 0)
            goto rollback;
        if (got != (ssize_t)sizeof(random))
            goto rollback;
    }
    for (i = 0; i < (int)sizeof(random); i++) {
        id[4 + i * 2] = hex[random[i] >> 4];
        id[5 + i * 2] = hex[random[i] & 15];
    }
    id[NC_CONTAINER_JOB_ID_LEN] = '\0';
    if (protect) {
        snprintf(secret_id,sizeof(secret_id),"docker-%s",id);
        if (ac_secrets_put(vault, secret_id, 1, (const unsigned char *)request_json, strlen(request_json)) != AC_SECRETS_OK)
            goto rollback;
        snprintf(secret_ref, sizeof(secret_ref), "{\"secret_ref\":\"%s\"}", id);
        request_json = secret_ref;
    }
    if (sqlite3_prepare_v2(db,
        "INSERT INTO container_job(id,kind,target,state,progress,request_json,created_at,updated_at,result_json) "
        "VALUES(?1,?2,?3,'queued',0,?4,?5,?5,?6)", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 2, kind, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(st, 3, target, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 4, request_json, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int64(st, 5, now) != SQLITE_OK ||
        sqlite3_bind_text(st,6,nc_lxc_job_kind(kind)?request_json:"{}",-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    if (sqlite3_finalize(st) != SQLITE_OK) {
        st = NULL;
        goto rollback;
    }
    st = NULL;
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback;
    ac_secrets_close(vault); vault = NULL;
    sqlite3_close(db); db = NULL;

    if (nc_container_job_spawn(id) != 0)
        goto worker_failed;
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "job_id", json_object_new_string(id));
    json_object_object_add(out, "kind", json_object_new_string(kind));
    json_object_object_add(out, "target", json_object_new_string(target));
    json_object_object_add(out, "state", json_object_new_string("queued"));
    json_object_object_add(out, "progress", json_object_new_int(0));
    {
        char endpoint[160];
        snprintf(endpoint, sizeof(endpoint),
                 "/api/v1/container_service/%s/jobs/%s", nc_lxc_job_kind(kind)?"lxc":"docker", id);
        nc_lxc_string(out,"engine",nc_lxc_job_kind(kind)?"lxc":"docker");
        json_object_object_add(out, "status_endpoint", json_object_new_string(endpoint));
    }
    return 0;

worker_failed:
    if (nc_container_job_db_open(&db) == 0) {
        if (sqlite3_prepare_v2(db,
            "UPDATE container_job SET state='failed',progress=100,rc=125,"
            "error='worker_start_failed',updated_at=?1,completed_at=?1 WHERE id=?2",
            -1, &st, NULL) != SQLITE_OK ||
            sqlite3_bind_int64(st, 1, nc_now_s()) != SQLITE_OK ||
            sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_DONE)
            json_object_object_add(out, "worker_failure_persisted", json_object_new_boolean(0));
        if (st) sqlite3_finalize(st);
        sqlite3_close(db);
    }
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("worker_start_failed"));
    return -1;

rollback:
    if (st) { sqlite3_finalize(st); st = NULL; }
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
storage_failed:
    ac_secrets_close(vault);
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("container_job_storage_failed"));
    return -1;
}

int jmx_docker_container_create(struct json_object *cfg, struct json_object *out)
{
    char *canonical = NULL;
    char image[256] = "", name[129] = "";
    int rc;

    if (!out)
        return -1;
    if (nc_docker_confirmation_required(cfg, out) != 0)
        return -1;
    if (!nc_cmd_exists("docker"))
        return nc_docker_invalid(out, "docker_command_not_found");
    if (nc_docker_create_normalize(cfg, &canonical, image, sizeof(image),
                                   name, sizeof(name), out) != 0)
        return -1;
    if (nc_docker_create_preflight(cfg, out) != 0) { free(canonical); return -1; }
    rc = nc_container_job_submit("container_create", image, canonical, out);
    free(canonical);
    return rc;
}

/* ── Image operations ── */

int jmx_docker_image_pull(struct json_object *cfg, struct json_object *out)
{
    const char *image;
    struct json_object *credential = NULL;
    char request_json[300];

    if (!out)
        return -1;
    if (nc_docker_confirmation_required(cfg, out) != 0)
        return -1;
    image = nc_json_str_def(cfg, "image", "");
    if (!nc_docker_image_id_valid(image))
        return nc_docker_invalid(out, "invalid_image_reference");
    if (json_object_object_get_ex(cfg, "username", &credential) ||
        json_object_object_get_ex(cfg, "password", &credential) ||
        json_object_object_get_ex(cfg, "registry_auth", &credential)) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error",
                               json_object_new_string("registry_credentials_unsupported"));
        json_object_object_add(out, "reason",
                               json_object_new_string("credential_broker_pending"));
        return -1;
    }
    if (!nc_cmd_exists("docker"))
        return nc_docker_invalid(out, "docker_command_not_found");
    if (snprintf(request_json, sizeof(request_json), "{\"image\":\"%s\"}", image) >=
        (int)sizeof(request_json))
        return nc_docker_invalid(out, "invalid_image_reference");
    return nc_container_job_submit("image_pull", image, request_json, out);
}

#include "033_nc_docker_recreate.inc"
#include "033_nc_docker_network.inc"
#include "033_nc_docker_network_rebuild.inc"
#include "033_nc_docker_settings.inc"
#include "033_nc_docker_migration.inc"
#include "033_nc_docker_workflows.inc"
#include "033_nc_docker_pull.inc"
#include "033_nc_lxc_jobs.inc"
#include "033_nc_lxc_autostart.inc"

int jmx_docker_job_worker(const char *id)
{
    struct nc_exec_result result = {0};
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *request = NULL;
    struct json_object *workflow_result = json_object_new_object();
    char kind[32] = "", target[256] = "";
    char *request_json = NULL;
    char result_id[256] = "", result_name[129] = "";
    const char *job_error = "container_job_worker_failed";
    int rc = 125, claimed = 0;
    int64_t started = nc_now_s();

    if (!nc_container_job_id_valid(id) || nc_container_job_db_open(&db) != 0) {
        json_object_put(workflow_result);
        return 125;
    }
    (void)setpgid(0, 0);
    (void)prctl(PR_SET_NAME, NC_CONTAINER_JOB_WORKER_COMM, 0, 0, 0);
    if (sqlite3_prepare_v2(db,
        "SELECT kind,target,request_json FROM container_job WHERE id=?1 AND state='queued'",
        -1, &st, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK)
        goto done;
    if (sqlite3_step(st) != SQLITE_ROW)
        goto done;
    {
        const char *kind_db = (const char *)sqlite3_column_text(st, 0);
        const char *target_db = (const char *)sqlite3_column_text(st, 1);
        const char *request_db = (const char *)sqlite3_column_text(st, 2);
        int request_len = sqlite3_column_bytes(st, 2);

        if (!kind_db || !target_db || !request_db || request_len <= 0 ||
            (size_t)request_len > NC_CONTAINER_CREATE_JSON_MAX ||
            snprintf(kind, sizeof(kind), "%s", kind_db) >=
            (int)sizeof(kind) ||
            snprintf(target, sizeof(target), "%s", target_db) >= (int)sizeof(target))
            goto done;
        request_json = malloc((size_t)request_len + 1);
        if (!request_json)
            goto done;
        memcpy(request_json, request_db, (size_t)request_len);
        request_json[request_len] = '\0';
        if (strlen(request_json) != (size_t)request_len)
            goto done;
    }
    if (sqlite3_finalize(st) != SQLITE_OK) {
        st = NULL;
        goto done;
    }
    st = NULL;
    if (sqlite3_prepare_v2(db,
        "UPDATE container_job SET state='running',progress=10,worker_pid=?1,"
        "started_at=?2,updated_at=?2 WHERE id=?3 AND state='queued'",
        -1, &st, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_bind_int64(st, 1, (sqlite3_int64)getpid()) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, started) != SQLITE_OK ||
        sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT) != SQLITE_OK)
        goto done;
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1)
        claimed = 1;
    if (sqlite3_finalize(st) != SQLITE_OK) {
        st = NULL;
        goto done;
    }
    st = NULL;
    if (!claimed) {
        rc = 0;
        goto done;
    }
    {
        struct json_object *stored = json_tokener_parse(request_json);
        struct json_object *ref = nc_docker_member(stored, "secret_ref");
        if (ref) {
            struct ac_secrets *vault = NULL;
            unsigned char *clear = NULL; size_t clear_len = 0;
            int opened = !strcmp(json_object_get_string(ref), id) &&
                ac_secrets_open(db, NC_CONTAINER_SECRET_KEY_PATH, &vault) == AC_SECRETS_OK;
            char secret_id[80]; snprintf(secret_id,sizeof(secret_id),"docker-%s",id);
            int loaded = opened && ac_secrets_get(vault, secret_id, 1, &clear, &clear_len) == AC_SECRETS_OK;
            ac_secrets_close(vault);
            if (!loaded || clear_len > NC_CONTAINER_CREATE_JSON_MAX) {
                ac_secrets_clear(clear, clear_len); json_object_put(stored);
                job_error = "container_secret_unavailable"; goto complete;
            }
            free(request_json); request_json = strndup((const char *)clear, clear_len);
            ac_secrets_clear(clear, clear_len);
            if (!request_json) { json_object_put(stored); goto complete; }
        }
        if (stored) json_object_put(stored);
    }
    if (nc_lxc_job_kind(kind)) {
        request=json_tokener_parse(request_json);
        if(!request || !json_object_is_type(request,json_type_object)){job_error="invalid_persisted_request";goto complete;}
        rc=nc_lxc_job_execute(db,id,kind,target,request,&result,workflow_result);
        job_error=rc?nc_json_str_def(workflow_result,"error","lxc_action_failed"):"";
        goto complete;
    }
    if (nc_docker_workflow_kind(kind)) {
        request=json_tokener_parse(request_json);
        if(!request||!json_object_is_type(request,json_type_object)) {
            job_error="invalid_persisted_request";goto complete;
        }
        rc=nc_docker_workflow_execute(db,id,kind,target,request,&result,workflow_result);
        job_error=rc?nc_json_str_def(workflow_result,"error","docker_workflow_failed"):"";
        goto complete;
    }
    if ((strcmp(kind, "image_pull") && strcmp(kind, "container_create")) ||
        !nc_docker_image_id_valid(target) || !request_json[0]) {
        job_error = "invalid_persisted_request";
        goto complete;
    }
    if (!strcmp(kind, "image_pull")) {
        struct json_object *image_value = NULL;
        const char *image;

        request = json_tokener_parse(request_json);
        if (!request || !json_object_is_type(request, json_type_object) ||
            !json_object_object_get_ex(request, "image", &image_value) ||
            !json_object_is_type(image_value, json_type_string)) {
            job_error = "invalid_persisted_request";
            goto complete;
        }
        image = json_object_get_string(image_value);
        if (json_object_get_string_len(image_value) != (int)strlen(image) ||
            !nc_docker_image_id_valid(image) || strcmp(image, target)) {
            job_error = "invalid_persisted_request";
            goto complete;
        }
        {
            rc = nc_docker_pull_execute(db, id, image, &result, workflow_result);
        }
        job_error = rc == 0 ? "" :
                    (rc == 124 ? "pull_timeout" : "docker_pull_failed");
    } else {
        char *canonical = NULL;
        char canonical_target[256] = "", requested_name[129] = "";
        const char *argv[NC_CONTAINER_CREATE_ARGV_MAX];
        char *label_args[NC_CONTAINER_CREATE_LABEL_MAX] = {0};
        char *extra_args[68] = {0}; size_t extra_count = 0;
        struct json_object *environment = NULL;
        int env_fd = -1; char env_path[64] = "";
        size_t argc = 0, label_arg_count = 0, i;
        struct json_object *value = NULL;
        struct json_object *validation_error = json_object_new_object();

        request = json_tokener_parse(request_json);
        if (!request || !validation_error ||
            nc_docker_create_normalize(request, &canonical, canonical_target,
                                       sizeof(canonical_target), requested_name,
                                       sizeof(requested_name), validation_error) != 0 ||
            !canonical || strcmp(canonical, request_json) ||
            strcmp(canonical_target, target)) {
            free(canonical);
            if (validation_error) json_object_put(validation_error);
            job_error = "invalid_persisted_request";
            goto complete;
        }
        if (nc_docker_create_preflight(request, validation_error) != 0) {
            result.output = strdup(json_object_to_json_string_ext(validation_error, JSON_C_TO_STRING_PLAIN));
            job_error = "container_preflight_failed";
            json_object_put(validation_error); free(canonical); goto complete;
        }
        json_object_put(validation_error);
        free(canonical);

#define NC_CREATE_ARG(arg_value) do { \
    if (argc + 1 >= NC_CONTAINER_CREATE_ARGV_MAX) { \
        job_error = "container_create_argv_limit_exceeded"; \
        goto create_cleanup; \
    } \
    argv[argc++] = (arg_value); \
} while (0)

        NC_CREATE_ARG("docker");
        NC_CREATE_ARG("create");
        if (json_object_object_get_ex(request, "name", &value)) {
            NC_CREATE_ARG("--name");
            NC_CREATE_ARG(json_object_get_string(value));
        }
        if (json_object_object_get_ex(request, "hostname", &value)) {
            NC_CREATE_ARG("--hostname");
            NC_CREATE_ARG(json_object_get_string(value));
        }
        if (json_object_object_get_ex(request, "restart_policy", &value)) {
            NC_CREATE_ARG("--restart");
            NC_CREATE_ARG(json_object_get_string(value));
        }
        if (json_object_object_get_ex(request, "network", &value)) {
            NC_CREATE_ARG("--network");
            NC_CREATE_ARG(json_object_get_string(value));
        }
        if (json_object_object_get_ex(request, "labels", &value)) {
            json_object_object_foreach(value, key, label_value) {
                const char *label_text = json_object_get_string(label_value);
                size_t needed = strlen(key) + 1 + strlen(label_text) + 1;

                if (label_arg_count >= NC_CONTAINER_CREATE_LABEL_MAX ||
                    !(label_args[label_arg_count] = malloc(needed))) {
                    job_error = "container_create_argv_allocation_failed";
                    goto create_cleanup;
                }
                snprintf(label_args[label_arg_count], needed, "%s=%s", key, label_text);
                NC_CREATE_ARG("--label");
                NC_CREATE_ARG(label_args[label_arg_count]);
                label_arg_count++;
            }
        }
        if (json_object_object_get_ex(request, "ports", &value)) {
            for (i=0;i<json_object_array_length(value);i++) {
                struct json_object *p=json_object_array_get_idx(value,i);
                char binding[128]; const char *ip=nc_json_str_def(p,"host_ip","");
                if (strchr(ip,':')) snprintf(binding,sizeof(binding),"[%s]:%d:%d/%s",ip,nc_json_int_def(p,"host_port",0),nc_json_int_def(p,"container_port",0),nc_json_str_def(p,"protocol","tcp"));
                else snprintf(binding,sizeof(binding),"%s%s%d:%d/%s",ip,*ip?":":"",nc_json_int_def(p,"host_port",0),nc_json_int_def(p,"container_port",0),nc_json_str_def(p,"protocol","tcp"));
                extra_args[extra_count]=strdup(binding);
                if (!extra_args[extra_count]) goto create_cleanup;
                NC_CREATE_ARG("--publish"); NC_CREATE_ARG(extra_args[extra_count++]);
            }
        }
        if (json_object_object_get_ex(request, "mounts", &value)) {
            for (i=0;i<json_object_array_length(value);i++) {
                struct json_object *m=json_object_array_get_idx(value,i);
                char mount[PATH_MAX*2+80];
                snprintf(mount,sizeof(mount),"type=%s,source=%s,target=%s%s",nc_json_str_def(m,"type",""),nc_json_str_def(m,"source",""),nc_json_str_def(m,"target",""),nc_json_bool_def(m,"read_only",0)?",readonly":"");
                extra_args[extra_count]=strdup(mount);
                if (!extra_args[extra_count]) goto create_cleanup;
                NC_CREATE_ARG("--mount"); NC_CREATE_ARG(extra_args[extra_count++]);
            }
        }
        environment=nc_docker_member(request,"env");
        if (environment && json_object_object_length(environment)) {
            char temporary[]="/tmp/dwrt-docker-env-XXXXXX";
            env_fd=mkstemp(temporary);
            if (env_fd<0) { job_error="environment_setup_failed"; goto create_cleanup; }
            unlink(temporary);
            /* Unlinked 0600 file, inherited only by Docker; no values in argv or
             * client environment (PATH/DOCKER_HOST/LD_PRELOAD are user env too). */
            json_object_object_foreach(environment,key,v) {
                if (dprintf(env_fd,"%s=%s\n",key,json_object_get_string(v))<0) { job_error="environment_setup_failed"; goto create_cleanup; }
            }
            if (lseek(env_fd,0,SEEK_SET)<0) { job_error="environment_setup_failed"; goto create_cleanup; }
            snprintf(env_path,sizeof(env_path),"/proc/self/fd/%d",env_fd);
            NC_CREATE_ARG("--env-file"); NC_CREATE_ARG(env_path);
        }
        if (json_object_object_get_ex(request,"resources",&value)) {
            const char *keys[]={"memory_bytes","cpu_shares"};
            const char *flags[]={"--memory","--cpu-shares"};
            for (int k=0;k<2;k++) {
                struct json_object *v=nc_docker_member(value,keys[k]);
                if (!v) continue;
                char number[32]; snprintf(number,sizeof(number),"%lld",(long long)json_object_get_int64(v));
                extra_args[extra_count]=strdup(number);
                if (!extra_args[extra_count]) goto create_cleanup;
                NC_CREATE_ARG(flags[k]); NC_CREATE_ARG(extra_args[extra_count++]);
            }
        }
        NC_CREATE_ARG(target);
        if (json_object_object_get_ex(request, "command", &value)) {
            for (i = 0; i < json_object_array_length(value); i++)
                NC_CREATE_ARG(json_object_get_string(json_object_array_get_idx(value, i)));
        }
        argv[argc] = NULL;
        /* Keep Docker in the worker's process group so cancellation is atomic. */
        rc = nc_exec_argv_capture_ex(argv, 300, NC_CONTAINER_OUTPUT_MAX,
                                     &result, 0);
        job_error = rc == 0 ? "" :
                    (rc == 124 ? "container_create_timeout" : "docker_create_failed");
        if (rc == 0 && result.output &&
            nc_docker_container_id_from_output(result.output, result_id,
                                               sizeof(result_id)) == 0) {
            struct nc_exec_result inspect_result = {0};
            const char *inspect_argv[] = {
                "docker", "inspect", "--format", "{{.Name}}", result_id, NULL
            };

            if (requested_name[0]) {
                snprintf(result_name, sizeof(result_name), "%s", requested_name);
            } else if (nc_exec_argv_capture_ex(inspect_argv, 30, 1024,
                                               &inspect_result, 0) == 0 &&
                       inspect_result.output) {
                const char *actual_name = inspect_result.output[0] == '/' ?
                                          inspect_result.output + 1 : inspect_result.output;
                if (nc_docker_name_valid(actual_name))
                    snprintf(result_name, sizeof(result_name), "%s", actual_name);
            }
            if (inspect_result.output)
                nc_exec_result_free(&inspect_result);
        } else if (rc == 0) {
            rc = 125;
            job_error = "container_create_result_invalid";
        }

        if (rc==0 && result_id[0]) {
            /* Record the created object before starting it, including for cancellation. */
            if (sqlite3_prepare_v2(db,"UPDATE container_job SET result_id=?1,result_name=?2 WHERE id=?3 AND state='running'",-1,&st,NULL)!=SQLITE_OK ||
                sqlite3_bind_text(st,1,result_id,-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
                sqlite3_bind_text(st,2,result_name,-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
                sqlite3_bind_text(st,3,id,-1,SQLITE_TRANSIENT)!=SQLITE_OK || sqlite3_step(st)!=SQLITE_DONE || sqlite3_changes(db)!=1) {
                if(st){sqlite3_finalize(st);st=NULL;}rc=125;job_error="created_object_record_failed";goto create_cleanup;
            }
            sqlite3_finalize(st);st=NULL;
        }
        if (rc==0 && nc_json_bool_def(request,"start_after_create",0)) {
            const char *const start_argv[]={"docker","start",result_id,NULL};
            nc_exec_result_free(&result);
            rc=nc_exec_argv_capture_ex(start_argv,120,NC_CONTAINER_OUTPUT_MAX,&result,0);
            job_error=rc==0?"":"container_start_failed";
            if(rc==0) {
                struct nc_exec_result verify={0};
                const char *const verify_argv[]={"docker","inspect","--format","{{.State.Running}}",result_id,NULL};
                int read_rc=nc_exec_argv_capture_ex(verify_argv,12,1024,&verify,0);
                if(read_rc||!verify.output||strcmp(verify.output,"true")) {rc=125;job_error="container_start_not_running";}
                nc_exec_result_free(&verify);
            }
        }

create_cleanup:
        if (env_fd>=0) close(env_fd);
        if (environment) {
            /* Docker failure output can quote an environment value. */
            if (json_object_object_length(environment) && result.output) {
                nc_exec_result_free(&result);
                result.output=strdup(rc==0?"container_created":"container_operation_failed_output_redacted");
            }
        }
        for (i=0;i<extra_count;i++) free(extra_args[i]);
        for (i = 0; i < label_arg_count; i++)
            free(label_args[i]);
#undef NC_CREATE_ARG
    }

complete:
    if (sqlite3_prepare_v2(db,
        "UPDATE container_job SET state=?1,progress=100,worker_pid=0,rc=?2,"
        "output=?3,error=?4,result_id=?5,result_name=?6,output_truncated=?7,"
        "updated_at=?8,completed_at=?8,result_json=?10 WHERE id=?9 AND state='running'",
        -1, &st, NULL) != SQLITE_OK ||
        sqlite3_bind_text(st, 1, rc == 0 ? "success" : "failed", -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(st, 2, rc) != SQLITE_OK ||
        sqlite3_bind_text(st, 3, result.output ? result.output : "", -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 4, job_error, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 5, result_id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 6, result_name, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int(st, 7, result.truncated) != SQLITE_OK ||
        sqlite3_bind_int64(st, 8, nc_now_s()) != SQLITE_OK ||
        sqlite3_bind_text(st, 9, id, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(st, 10, json_object_to_json_string_ext(workflow_result,JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(db) != 1) {
        if (st) { sqlite3_finalize(st); st = NULL; }
        rc = 125;
        goto done;
    }
    if (sqlite3_finalize(st) != SQLITE_OK) {
        st = NULL;
        rc = 125;
        goto done;
    }
    st = NULL;
    if (result.output)
        nc_exec_result_free(&result);
done:
    if (st) sqlite3_finalize(st);
    if (request) json_object_put(request);
    json_object_put(workflow_result);
    free(request_json);
    if (result.output) nc_exec_result_free(&result);
    sqlite3_close(db);
    return rc == 0 ? 0 : 1;
}

static int nc_container_job_id_valid(const char *id)
{
    int i;
    if (!id || strlen(id) != NC_CONTAINER_JOB_ID_LEN || strncmp(id, "job-", 4))
        return 0;
    for (i = 4; i < NC_CONTAINER_JOB_ID_LEN; i++)
        if (!isxdigit((unsigned char)id[i]))
            return 0;
    return 1;
}

static struct json_object *nc_container_job_row(sqlite3_stmt *st,
                                                int list_output_truncated)
{
    struct json_object *o = json_object_new_object();
    nc_lxc_string(o,"engine",nc_lxc_job_kind((const char *)sqlite3_column_text(st,1))?"lxc":"docker");
    const char *saved_result = sqlite3_column_count(st)>15?(const char *)sqlite3_column_text(st,sqlite3_column_count(st)>16?16:15):NULL;
    struct json_object *result = saved_result?json_tokener_parse(saved_result):NULL;
    if(!result)result=json_object_new_object();
    const char *result_id = (const char *)sqlite3_column_text(st, 12);
    const char *result_name = (const char *)sqlite3_column_text(st, 13);
    int output_truncated = sqlite3_column_int(st, 14) || list_output_truncated;

    if(nc_lxc_job_kind((const char *)sqlite3_column_text(st,1))){
        const char *state=(const char *)sqlite3_column_text(st,3);
        const char *lxc_kind=(const char *)sqlite3_column_text(st,1);
        if(state && (!strcmp(state,"failed")||!strcmp(state,"cancelled"))){
            char identity[80],actual[24]="",directory[PATH_MAX],resolved[PATH_MAX];struct stat st;
            struct json_object *observed=json_object_new_object();
            const char *name=nc_json_str_def(result,"name",""),*root=nc_json_str_def(result,"lxcpath","");
            nc_lxc_bool(result,"readback_required",1);
            if(!nc_lxc_name_valid(name)||!realpath(root,resolved)||strcmp(root,resolved)||
               snprintf(directory,sizeof(directory),"%s/%s",root,name)>=(int)sizeof(directory)){
                nc_lxc_string(result,"readback_error","lxc_storage_unavailable");
            }else if(lstat(directory,&st)){
                if(errno==ENOENT)nc_lxc_bool(result,"remaining_object",0);
                else nc_lxc_string(result,"readback_error","container_directory_unreadable");
            }else{
                nc_lxc_bool(result,"remaining_object",1);
                nc_lxc_string(result,"remaining_path",directory);
                snprintf(identity,sizeof(identity),"%llu:%llu",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);
                int unfinished_create=!strcmp(lxc_kind,"lxc_create")&&!nc_json_str_def(result,"identity","")[0];
                if(unfinished_create&&S_ISDIR(st.st_mode)){
                    nc_lxc_string(result,"observed_identity",identity);
                    nc_lxc_string(result,"readback_error","lxc_creation_interrupted");
                    nc_lxc_bool(result,"ownership_verified",0);
                    if(!nc_lxc_state(root,name,actual,sizeof(actual),observed))nc_lxc_string(result,"state",actual);
                }
                else if(!S_ISDIR(st.st_mode)||strcmp(identity,nc_json_str_def(result,"identity","")))nc_lxc_string(result,"readback_error","container_identity_changed");
                else if(!nc_lxc_state(root,name,actual,sizeof(actual),observed)){
                    nc_lxc_string(result,"state",actual);nc_lxc_bool(result,"readback_required",0);
                }else nc_lxc_string(result,"readback_error",nc_json_str_def(observed,"error","lxc_read_failed"));
            }
            if(realpath(root,resolved)&&!strcmp(root,resolved)){
                const char *copy=nc_json_str_def(result,"new_name","");
                if(!strcmp(lxc_kind,"lxc_clone")&&nc_lxc_name_valid(copy)&&
                   snprintf(directory,sizeof(directory),"%s/%s",root,copy)<(int)sizeof(directory)){
                    nc_lxc_string(result,"remaining_copy_path",directory);
                    if(!lstat(directory,&st)){
                        nc_lxc_bool(result,"remaining_copy",1);
                        snprintf(identity,sizeof(identity),"%llu:%llu",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);
                        nc_lxc_string(result,"observed_copy_identity",identity);
                        nc_lxc_bool(result,"copy_ownership_verified",0);
                    }else if(errno==ENOENT)nc_lxc_bool(result,"remaining_copy",0);
                }
            }
            json_object_put(observed);
        }
        json_object_object_del(result,"confirm");json_object_object_del(result,"force_confirm");
    }
    json_object_object_add(o, "job_id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
    json_object_object_add(o, "kind", json_object_new_string((const char *)sqlite3_column_text(st, 1)));
    json_object_object_add(o, "target", json_object_new_string((const char *)sqlite3_column_text(st, 2)));
    json_object_object_add(o, "state", json_object_new_string((const char *)sqlite3_column_text(st, 3)));
    json_object_object_add(o, "progress", json_object_new_int(sqlite3_column_int(st, 4)));
    json_object_object_add(o, "rc", json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(o, "output", json_object_new_string((const char *)sqlite3_column_text(st, 6)));
    json_object_object_add(o, "output_truncated",
                           json_object_new_boolean(output_truncated));
    json_object_object_add(o, "error", json_object_new_string((const char *)sqlite3_column_text(st, 7)));
    json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_object_add(o, "started_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(o, "completed_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
    if (result_id && result_id[0])
        json_object_object_add(result, "container_id", json_object_new_string(result_id));
    if (result_name && result_name[0])
        json_object_object_add(result, "container_name", json_object_new_string(result_name));
    json_object_object_add(o, "result", result);
    json_object_object_add(o, "ok", json_object_new_boolean(1));
    json_object_object_add(o, "contract_version", json_object_new_string("container-job.v1"));
    return o;
}

static struct json_object *nc_container_job_get_engine(const char *id,int lxc)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *data;
    int found = 0;

    if (!nc_container_job_id_valid(id)) {
        data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("container_job_not_found"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_container_job_db_open(&db) != 0)
        goto failed;
    if (nc_container_jobs_reconcile(db) != 0)
        goto failed;
    if (sqlite3_prepare_v2(db,
        "SELECT id,kind,target,state,progress,rc,output,error,created_at,started_at,updated_at,completed_at,"
        "result_id,result_name,output_truncated,result_json "
        "FROM container_job WHERE id=?1 AND (substr(kind,1,4)='lxc_')=?2", -1, &st, NULL) != SQLITE_OK)
        goto failed;
    if (sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK || sqlite3_bind_int(st,2,lxc)!=SQLITE_OK)
        goto failed;
    {
        int step_rc = sqlite3_step(st);
        if (step_rc == SQLITE_ROW) {
        data = nc_container_job_row(st, 0);
        found = 1;
        } else if (step_rc == SQLITE_DONE) {
            data = json_object_new_object();
            json_object_object_add(data, "ok", json_object_new_boolean(0));
            json_object_object_add(data, "error", json_object_new_string("container_job_not_found"));
        } else {
            goto failed;
        }
    }
    if (sqlite3_finalize(st) != SQLITE_OK) {
        st = NULL;
        if (found) json_object_put(data);
        goto failed;
    }
    st = NULL;
    if (sqlite3_close(db) != SQLITE_OK) {
        db = NULL;
        if (found) json_object_put(data);
        goto failed;
    }
    db = NULL;
    return jmx_gen_api_response_data(found ? API_CODE_SUCCESS : API_CODE_ERROR, data);
failed:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string("container_job_storage_failed"));
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static struct json_object *nc_container_jobs_list_engine(struct json_object *cfg,int lxc)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *items = json_object_new_array();
    int limit = cfg ? nc_json_int_def(cfg, "limit", 50) : 50;
    int rows = 0, step_rc;

    if (limit < 1 || limit > 200) limit = 50;
    if (nc_container_job_db_open(&db) != 0)
        goto failed;
    if (nc_container_jobs_reconcile(db) != 0)
        goto failed;
    if (sqlite3_prepare_v2(db,
        "SELECT id,kind,target,state,progress,rc,"
        "CASE WHEN length(output)>2048 THEN substr(output,-2048) ELSE output END,"
        "error,created_at,started_at,updated_at,completed_at,"
        "result_id,result_name,output_truncated,length(output)>2048,result_json "
        "FROM container_job WHERE (substr(kind,1,4)='lxc_')=?2 ORDER BY created_at DESC LIMIT ?1", -1, &st, NULL) != SQLITE_OK)
        goto failed;
    if (sqlite3_bind_int(st, 1, limit) != SQLITE_OK || sqlite3_bind_int(st,2,lxc)!=SQLITE_OK)
        goto failed;
    while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) {
        json_object_array_add(items, nc_container_job_row(st, sqlite3_column_int(st, 15)));
        rows++;
    }
    if (step_rc != SQLITE_DONE || sqlite3_finalize(st) != SQLITE_OK) {
        st = NULL;
        goto failed;
    }
    st = NULL;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM container_job WHERE state IN ('success','failed','cancelled') "
        "AND completed_at<?1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, nc_now_s() - NC_CONTAINER_JOB_RETENTION_SEC);
        (void)sqlite3_step(st);
        sqlite3_finalize(st); st = NULL;
    }
    if (sqlite3_prepare_v2(db,
        "DELETE FROM container_job WHERE state IN ('success','failed','cancelled') AND id IN (SELECT id FROM container_job "
        "ORDER BY created_at DESC LIMIT -1 OFFSET ?1)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, NC_CONTAINER_JOB_MAX_ROWS);
        (void)sqlite3_step(st);
        sqlite3_finalize(st); st = NULL;
    }
    /* Container secrets follow the same retention as their owning jobs. */
    (void)sqlite3_exec(db,"DELETE FROM ac_secrets WHERE secret_id LIKE 'docker-job-%' "
                         "AND substr(secret_id,8) NOT IN (SELECT id FROM container_job)",NULL,NULL,NULL);
    sqlite3_close(db);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "total_returned", json_object_new_int(rows));
    json_object_object_add(data, "limit", json_object_new_int(limit));
    json_object_object_add(data, "contract_version", json_object_new_string("container-job.v1"));
    json_object_object_add(data, "source", json_object_new_string("dreamingwrt.db:container_job"));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
failed:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    json_object_put(items);
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error", json_object_new_string("container_job_storage_failed"));
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static int nc_container_job_cancel_engine(const char *id, struct json_object *cfg,
                          struct json_object *out,int lxc)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    pid_t pid = 0;
    char state[32] = "";
    char path[128], children[1024] = "";
    FILE *fp;
    int64_t now = nc_now_s();

    if (!out || nc_docker_confirmation_required(cfg, out) != 0)
        return -1;
    if (!nc_container_job_id_valid(id))
        return nc_docker_invalid(out, "container_job_not_found");
    if (nc_container_job_db_open(&db) != 0)
        goto storage_failed_cancel;
    if (nc_container_jobs_reconcile(db) != 0)
        goto storage_failed_cancel;
    if (sqlite3_prepare_v2(db,
        "SELECT state,worker_pid FROM container_job WHERE id=?1 AND (substr(kind,1,4)='lxc_')=?2", -1, &st, NULL) != SQLITE_OK)
        goto storage_failed_cancel;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st,2,lxc);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st); sqlite3_close(db);
        return nc_docker_invalid(out, "container_job_not_found");
    }
    snprintf(state, sizeof(state), "%s", (const char *)sqlite3_column_text(st, 0));
    pid = (pid_t)sqlite3_column_int64(st, 1);
    sqlite3_finalize(st); st = NULL;
    if (strcmp(state, "queued") && strcmp(state, "running")) {
        sqlite3_close(db);
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("container_job_not_cancellable"));
        json_object_object_add(out, "state", json_object_new_string(state));
        return -1;
    }
    if (sqlite3_prepare_v2(db,
        "UPDATE container_job SET state='cancelled',progress=100,worker_pid=0,rc=130,"
        "error='cancelled_by_user',updated_at=?1,completed_at=?1 "
        "WHERE id=?2 AND state IN ('queued','running')",
        -1, &st, NULL) != SQLITE_OK)
        goto storage_failed_cancel;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(db) != 1)
        goto storage_failed_cancel;
    sqlite3_finalize(st); st = NULL;
    sqlite3_close(db); db = NULL;
    if (pid > 1) {
        if (nc_container_job_worker_matches(pid, id)) {
            char *cursor, *end;
            snprintf(path, sizeof(path), "/proc/%ld/task/%ld/children", (long)pid, (long)pid);
            fp = fopen(path, "r");
            if (fp) {
                /*
                 * An empty children file is normal (the worker may have no
                 * descendants), so leave the buffer as the empty string the
                 * caller already initialised and let the parse loop below find
                 * nothing.
                 */
                if (!fgets(children, sizeof(children), fp))
                    children[0] = '\0';
                fclose(fp);
            }
            cursor = children;
            while (cursor && *cursor) {
                long child = strtol(cursor, &end, 10);
                if (end == cursor) break;
                if (child > 1) { (void)kill(-(pid_t)child, SIGTERM); (void)kill((pid_t)child, SIGTERM); }
                cursor = end;
            }
            (void)kill(-pid, SIGTERM); (void)kill(pid, SIGTERM);
            usleep(250000);
            cursor = children;
            while (cursor && *cursor) {
                long child = strtol(cursor, &end, 10);
                if (end == cursor) break;
                if (child > 1) { (void)kill(-(pid_t)child, SIGKILL); (void)kill((pid_t)child, SIGKILL); }
                cursor = end;
            }
            (void)kill(-pid, SIGKILL); (void)kill(pid, SIGKILL);
        }
    }
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "job_id", json_object_new_string(id));
    json_object_object_add(out, "state", json_object_new_string("cancelled"));
    json_object_object_add(out, "completed_at", json_object_new_int64(now));
    return 0;
storage_failed_cancel:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("container_job_storage_failed"));
    return -1;
}

struct json_object *jmx_docker_job_get(const char *id){return nc_container_job_get_engine(id,0);}
struct json_object *jmx_lxc_job_get(const char *id){return nc_container_job_get_engine(id,1);}
struct json_object *jmx_docker_jobs_list(struct json_object *cfg){return nc_container_jobs_list_engine(cfg,0);}
struct json_object *jmx_lxc_jobs_list(struct json_object *cfg){return nc_container_jobs_list_engine(cfg,1);}
int jmx_docker_job_cancel(const char *id,struct json_object *cfg,struct json_object *out){return nc_container_job_cancel_engine(id,cfg,out,0);}
int jmx_lxc_job_cancel(const char *id,struct json_object *cfg,struct json_object *out){return nc_container_job_cancel_engine(id,cfg,out,1);}

int jmx_docker_image_remove(const char *id, struct json_object *cfg, struct json_object *out)
{
    const char *argv[6] = {"docker", "image", "rm", NULL, NULL, NULL};
    size_t argc = 3;

    if (!nc_docker_image_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    if (nc_docker_confirmation_required(cfg, out) != 0) return -1;
    int force = cfg ? nc_json_bool_def(cfg, "force", 0) : 0;
    if (force) argv[argc++] = "--force";
    argv[argc++] = id;
    argv[argc] = NULL;
    return nc_exec_argv_json(argv, 120, 4096, out);
}

struct json_object *jmx_docker_image_prune(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    nc_docker_capability_disabled(cfg, d, "image_prune_preview_pending");
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

/* ── Network operations ── */

int jmx_docker_network_remove(const char *id, struct json_object *cfg, struct json_object *out)
{
    const char *const argv[] = {"docker", "network", "rm", id, NULL};

    if (!nc_docker_resource_id_valid(id)) return nc_docker_invalid(out, "invalid_id");
    if (nc_docker_confirmation_required(cfg, out) != 0) return -1;
    return nc_exec_argv_json(argv, 60, 4096, out);
}

struct json_object *jmx_docker_network_prune(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    nc_docker_capability_disabled(cfg, d, "network_prune_preview_pending");
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

/* ── Volume operations ── */

int jmx_docker_volume_create(struct json_object *cfg, struct json_object *out)
{
    const char *argv[] = {"docker", "volume", "create", "--driver", NULL, NULL, NULL};

    if (!cfg || !out) return -1;
    const char *name = nc_json_str_def(cfg, "name", "");
    const char *driver = nc_json_str_def(cfg, "driver", "local");
    if (!nc_docker_name_valid(name)) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_name"));
        return -1;
    }
    if (!nc_docker_driver_valid(driver)) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_driver"));
        return -1;
    }
    argv[4] = driver;
    argv[5] = name;
    return nc_exec_argv_json(argv, 60, 4096, out);
}

int jmx_docker_volume_remove(const char *name, struct json_object *cfg, struct json_object *out)
{
    const char *const argv[] = {"docker", "volume", "rm", name, NULL};

    if (!nc_docker_name_valid(name)) return nc_docker_invalid(out, "invalid_name");
    if (nc_docker_confirmation_required(cfg, out) != 0) return -1;
    return nc_exec_argv_json(argv, 60, 4096, out);
}

struct json_object *jmx_docker_volume_prune(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    nc_docker_capability_disabled(cfg, d, "volume_prune_preview_pending");
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

/* ── Service operations ── */

struct json_object *jmx_docker_service_status(void)
{
    struct json_object *d = json_object_new_object();
    int running = system("/etc/init.d/dockerd running >/dev/null 2>&1") == 0;
    int enabled = system("/etc/init.d/dockerd enabled >/dev/null 2>&1") == 0;
    json_object_object_add(d, "running", json_object_new_boolean(running));
    json_object_object_add(d, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

int jmx_docker_service_action(const char *action, struct json_object *out)
{
    const char *argv[] = {"/etc/init.d/dockerd", action, NULL};

    if (!action || !out) return -1;
    /* validate: start, stop, restart, reload */
    if (strcmp(action, "start") && strcmp(action, "stop") && strcmp(action, "restart") && strcmp(action, "reload")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_action"));
        json_object_object_add(out, "message", json_object_new_string("action must be: start, stop, restart, reload"));
        return -1;
    }
    return nc_exec_argv_json(argv, 120, 4096, out);
}

/* ── Config ── */

/* ═══ LXC Operations ═══ */

static int nc_lxc_write_disabled(struct json_object *out, const char *reason)
{
    if (!out)
        return -1;
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(out, "reason", json_object_new_string(
        reason ? reason : "lxc_write_pipeline_pending"));
    json_object_object_add(out, "persisted", json_object_new_boolean(0));
    json_object_object_add(out, "applied", json_object_new_boolean(0));
    return -1;
}

int jmx_lxc_container_start(const char *name, struct json_object *out)
{
    (void)name;
    return nc_lxc_write_disabled(out,
        "lxc_runtime_job_validate_readback_rollback_pending");
}

int jmx_lxc_container_stop(const char *name, struct json_object *cfg, struct json_object *out)
{
    (void)name;
    (void)cfg;
    return nc_lxc_write_disabled(out,
        "lxc_runtime_job_validate_readback_rollback_pending");
}

int jmx_lxc_container_restart(const char *name, struct json_object *cfg, struct json_object *out)
{
    (void)name;
    (void)cfg;
    return nc_lxc_write_disabled(out,
        "lxc_runtime_job_validate_readback_rollback_pending");
}

int jmx_lxc_container_destroy(const char *name, struct json_object *cfg, struct json_object *out)
{
    (void)name;
    (void)cfg;
    return nc_lxc_write_disabled(out,
        "lxc_runtime_job_validate_readback_rollback_pending");
}

int jmx_lxc_container_create(struct json_object *cfg, struct json_object *out)
{
    (void)cfg;
    return nc_lxc_write_disabled(out,
        "lxc_create_trusted_template_async_job_pending");
}

int jmx_lxc_container_clone(const char *name, struct json_object *cfg, struct json_object *out)
{
    (void)name;
    (void)cfg;
    return nc_lxc_write_disabled(out,
        "lxc_clone_async_job_validate_readback_rollback_pending");
}

int jmx_lxc_container_snapshot(const char *name, struct json_object *cfg, struct json_object *out)
{
    (void)name;
    (void)cfg;
