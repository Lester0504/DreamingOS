// SPDX-License-Identifier: GPL-2.0-or-later
/* Container-only TTY engine. No host shell, saved credential, or remote endpoint. */
#include "tm.h"
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef TM_DOCKER_SOCKET
#define TM_DOCKER_SOCKET "/var/run/docker.sock"
#endif

#ifndef TM_DOCKER_MIGRATION_LOCK
#define TM_DOCKER_MIGRATION_LOCK "/var/run/dwrt-docker-migration.lock"
#endif
#ifndef TM_DOCKER_CONFIG_DB
#define TM_DOCKER_CONFIG_DB "/etc/dreamingwrt/config.db"
#endif
static int docker_migration_guard(void)
{
    int fd=open(TM_DOCKER_MIGRATION_LOCK,O_RDWR|O_CREAT|O_CLOEXEC,0600);
    if(fd<0)return -1;
    if(flock(fd,LOCK_SH|LOCK_NB)){close(fd);return -1;}
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;int pending=0;
    if(sqlite3_open_v2(TM_DOCKER_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK &&
       sqlite3_prepare_v2(db,"SELECT state FROM docker_engine_settings WHERE id=1",-1,&st,NULL)==SQLITE_OK &&
       sqlite3_step(st)==SQLITE_ROW){
        const char *state=(const char *)sqlite3_column_text(st,0);
        pending=state&&!strncmp(state,"migration_",10);
    }
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    if(pending){close(fd);return -1;}
    return fd;
}

static pthread_once_t docker_curl_once = PTHREAD_ONCE_INIT;
static void docker_curl_init(void) { curl_global_init(CURL_GLOBAL_DEFAULT); }

struct docker_response { char *data; size_t used; };
static size_t docker_collect(char *p, size_t size, size_t count, void *arg)
{
    struct docker_response *r = arg;
    size_t n = size * count;
    if (n > 1024 * 1024 - r->used) return 0;
    char *next = realloc(r->data, r->used + n + 1);
    if (!next) return 0;
    r->data = next; memcpy(next + r->used, p, n); r->used += n;
    next[r->used] = 0; return n;
}

static J *docker_request(const char *method, const char *path, J *body, long *status)
{
    pthread_once(&docker_curl_once, docker_curl_init);
    CURL *curl = curl_easy_init(); struct docker_response response = {0};
    *status = 0;
    if (!curl) return NULL;
    char url[512]; snprintf(url, sizeof(url), "http://localhost%s", path);
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, TM_DOCKER_SOCKET);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, docker_collect);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN));
    if (curl_easy_perform(curl) == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    J *result = response.data ? json_tokener_parse(response.data) : NULL;
    free(response.data); curl_slist_free_all(headers); curl_easy_cleanup(curl);
    return result;
}

static int docker_id(const char *id)
{
    if (strlen(id) != 64) return 0;
    for (const char *p = id; *p; p++) if (!isxdigit((unsigned char)*p)) return 0;
    return 1;
}

const char *tm_docker_validate(J *host)
{
    if (!docker_id(tm_str(host, "container_id", ""))) return "container_id";
    const char *shell = tm_str(host, "shell", "/bin/sh");
    if (strcmp(shell, "/bin/sh") && strcmp(shell, "/bin/bash") && strcmp(shell, "/bin/ash")) return "shell";
    tm_string(host, "shell", shell); return NULL;
}

static int docker_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
    return syscall(SYS_pidfd_open, pid, 0);
#else
    (void)pid; errno = ENOSYS; return -1;
#endif
}

static int docker_signal(int fd, int signal)
{
#ifdef SYS_pidfd_send_signal
    return syscall(SYS_pidfd_send_signal, fd, signal, NULL, 0);
#else
    (void)fd; (void)signal; errno = ENOSYS; return -1;
#endif
}

J *tm_docker_capabilities(int manage)
{
    int probe = docker_pidfd(getpid());
    int cleanup = probe >= 0 && !docker_signal(probe, 0);
    if (probe >= 0) close(probe);
#ifndef TM_TESTING
    cleanup = cleanup && geteuid() == 0;
#endif
    long status = 0; J *version = docker_request("GET", "/version", NULL, &status);
    int available = cleanup && status == 200 && version;
    J *r = json_object_new_object(); tm_boolean(r, "terminal", available);
    tm_boolean(r, "connect", available && manage);
    tm_string(r, "reason", !cleanup ? "docker_exec_cleanup_unavailable" : status != 200 ? "docker_engine_unavailable" : !manage ? "owner_or_admin_required" : "");
    tm_number(r, "authorization_lease_seconds", TM_LEASE_SECONDS);
    json_object_object_add(r, "shells", json_tokener_parse("[\"/bin/sh\",\"/bin/bash\",\"/bin/ash\"]"));
    json_object_put(version); return r;
}

static J *docker_exec_info(struct tm_session *s, long *status)
{
    char path[128]; snprintf(path, sizeof(path), "/exec/%s/json", s->docker_exec);
    return docker_request("GET", path, NULL, status);
}

/* Pin the Engine's actual exec process, then confirm its identity again. A pidfd
 * cannot signal an unrelated process after a PID is recycled. */
static int docker_pin(struct tm_session *s)
{
    for (int attempt = 0; attempt < 20; attempt++) {
        long status; J *info = docker_exec_info(s, &status);
        pid_t pid = tm_int(info, "Pid", 0);
        int running = status == 200 && tm_bool(info, "Running", 0) && pid > 0 &&
            !strcmp(tm_str(info, "ContainerID", ""), tm_str(s->host, "container_id", ""));
        int exited = status == 200 && !tm_bool(info, "Running", 0) && tm_int(info, "ExitCode", 0) != 0;
        json_object_put(info);
        if (exited) return -2;
        if (running) {
            int fd = docker_pidfd(pid);
            if (fd < 0) return -1;
            info = docker_exec_info(s, &status);
            int valid = status == 200 && tm_bool(info, "Running", 0) && tm_int(info, "Pid", 0) == pid &&
                !strcmp(tm_str(info, "ContainerID", ""), tm_str(s->host, "container_id", ""));
            json_object_put(info);
            if (!valid) { close(fd); return -1; }
            s->docker_pidfd = fd;
            return docker_signal(fd, 0);
        }
        usleep(10000);
    }
    return -1;
}

static int docker_open(struct tm_session *s)
{
    J *caps = tm_docker_capabilities(1);
    if (!tm_bool(caps, "terminal", 0)) {
        tm_state(s, "failed", tm_str(caps, "reason", "docker_engine_unavailable"));
        json_object_put(caps); return -1;
    }
    json_object_put(caps);
    char path[256]; long status;
    snprintf(path, sizeof(path), "/containers/%s/json", tm_str(s->host, "container_id", ""));
    J *container = docker_request("GET", path, NULL, &status), *state = tm_get(container, "State");
    int running = status == 200 && tm_bool(state, "Running", 0) && !tm_bool(state, "Paused", 0) && !tm_bool(state, "Restarting", 0);
    json_object_put(container);
    if (!running) { tm_state(s, "failed", status == 404 ? "docker_container_not_found" : status != 200 ? "docker_engine_unavailable" : "docker_container_not_running"); return -1; }
    J *body = json_tokener_parse("{\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true}");
    J *cmd = json_object_new_array(); json_object_array_add(cmd, json_object_new_string(tm_str(s->host, "shell", "/bin/sh")));
    json_object_array_add(cmd, json_object_new_string("-i")); json_object_object_add(body, "Cmd", cmd);
    json_object_object_add(body, "Env", json_tokener_parse("[\"TERM=xterm-256color\"]"));
    snprintf(path, sizeof(path), "/containers/%s/exec", tm_str(s->host, "container_id", ""));
    J *created = docker_request("POST", path, body, &status); json_object_put(body);
    if (status != 201 || !docker_id(tm_str(created, "Id", ""))) {
        json_object_put(created); tm_state(s, "failed", "docker_exec_create_failed"); return -1;
    }
    snprintf(s->docker_exec, sizeof(s->docker_exec), "%s", tm_str(created, "Id", "")); json_object_put(created);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX}; snprintf(address.sun_path, sizeof(address.sun_path), "%s", TM_DOCKER_SOCKET);
    struct timeval timeout = {5, 0};
    if (fd < 0) goto unavailable;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) { close(fd); goto unavailable; }
    s->stream = fd;
    const char *start = "{\"Detach\":false,\"Tty\":true}";
    char request[512]; int length = snprintf(request, sizeof(request), "POST /exec/%s/start HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", s->docker_exec, strlen(start), start);
    if (tm_write_all(fd, request, length)) goto unavailable;
    char header[8192] = {0}; size_t used = 0;
    while (used < sizeof(header) - 1) {
        if (read(fd, header + used, 1) != 1) goto unavailable;
        header[++used] = 0;
        if (used >= 4 && !strcmp(header + used - 4, "\r\n\r\n")) break;
    }
    int code = 0; sscanf(header, "HTTP/%*s %d", &code);
    if (used == sizeof(header) - 1 || (code != 101 && code != 200)) {
        tm_state(s, "failed", "docker_shell_unavailable"); return -1;
    }
    int pinned = docker_pin(s);
    if (pinned) { tm_state(s, "failed", pinned == -2 ? "docker_shell_unavailable" : "docker_exec_cleanup_unavailable"); return -1; }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    tm_docker_resize(s, s->cols, s->rows); return s->stop ? -1 : 0;
unavailable:
    tm_state(s, "failed", "docker_engine_unavailable"); return -1;
}

int tm_docker_open(struct tm_session *s)
{
    int guard=docker_migration_guard();
    if(guard<0){tm_state(s,"failed","docker_migration_busy_or_recovery_required");return -1;}
    int rc=docker_open(s);close(guard);return rc;
}

void tm_docker_resize(struct tm_session *s, int cols, int rows)
{
    char path[160]; long status;
    snprintf(path, sizeof(path), "/exec/%s/resize?h=%d&w=%d", s->docker_exec, rows, cols);
    J *r = docker_request("POST", path, NULL, &status); json_object_put(r);
    if (status != 200 && status != 201) { s->stop = 1; tm_state(s, "failed", "docker_resize_failed"); }
}

void tm_docker_close(struct tm_session *s)
{
    if (!s->docker_exec[0]) return;
    /* A dropped start response may still have started the process. */
    if (s->docker_pidfd < 0) docker_pin(s);
    if (s->docker_pidfd >= 0) {
        docker_signal(s->docker_pidfd, SIGHUP);
        struct pollfd p = {s->docker_pidfd, POLLIN, 0};
        if (poll(&p, 1, 200) <= 0) {
            docker_signal(s->docker_pidfd, SIGKILL);
            if (poll(&p, 1, 1000) <= 0) tm_state(s, "failed", "docker_exec_cleanup_failed");
        }
        close(s->docker_pidfd); s->docker_pidfd = -1;
    }
}
