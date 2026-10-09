#define _GNU_SOURCE
#include "jmx_exec.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define JMX_EXEC_KILL_GRACE_MS 200
#define JMX_EXEC_MAX_OUTPUT JMX_EXEC_OUTPUT_LIMIT_MAX

/* closefrom spawn actions are available in the glibc toolchains used by both
 * x86 and ARM. Other libc versions retain the existing fork/exec contract. */
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 34) && !defined(JMX_EXEC_FORCE_FORK)
#define JMX_EXEC_SPAWN_CLOSEFROM 1
#endif
#endif

static int64_t jmx_exec_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void jmx_exec_result_free(struct jmx_exec_result *result)
{
    if (!result)
        return;
    free(result->output);
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
}

static int jmx_exec_valid(const char *path, char *const argv[],
                          size_t output_limit, int timeout_ms)
{
    size_t i;
    if (!path || path[0] != '/' || !argv || !argv[0] ||
        strcmp(path, argv[0]) || timeout_ms < 1 ||
        output_limit > JMX_EXEC_MAX_OUTPUT)
        return 0;
    for (i = 0; argv[i]; i++) {
        if (i >= 64 || strlen(argv[i]) > 4096)
            return 0;
    }
    return i > 0;
}

#ifndef JMX_EXEC_SPAWN_CLOSEFROM
static void jmx_exec_close_extra_fds(void)
{
    long maxfd;
    int fd;

#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0)
        return;
#endif
    maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536)
        maxfd = 65536;
    for (fd = 3; fd < maxfd; fd++)
        close(fd);
}
#endif

#ifdef JMX_EXEC_SPAWN_CLOSEFROM
static int jmx_exec_spawn(pid_t *pid, const char *path, char *const argv[],
                           char *const env[], int output_fd)
{
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    int rc = posix_spawn_file_actions_init(&actions);

    if (rc != 0)
        return rc;
    rc = posix_spawnattr_init(&attr);
    if (rc != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return rc;
    }
    rc = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
                                          O_RDWR | O_NOFOLLOW, 0);
    if (!rc)
        rc = posix_spawn_file_actions_adddup2(&actions,
                    output_fd >= 0 ? output_fd : STDIN_FILENO, STDOUT_FILENO);
    if (!rc)
        rc = posix_spawn_file_actions_adddup2(&actions,
                    output_fd >= 0 ? output_fd : STDIN_FILENO, STDERR_FILENO);
    if (!rc)
        rc = posix_spawn_file_actions_addclosefrom_np(&actions, 3);
    if (!rc)
        rc = posix_spawnattr_setpgroup(&attr, 0);
    if (!rc)
        rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    if (!rc)
        rc = posix_spawn(pid, path, &actions, &attr, argv, env);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    return rc;
}
#endif

int jmx_exec_capture(const char *path, char *const argv[], size_t output_limit,
                     int timeout_ms, struct jmx_exec_result *result)
{
    static char *const clean_env[] = {
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", NULL
    };
    int pipefd[2] = { -1, -1 };
    int status = 0, child_done = 0, term_sent = 0;
    int64_t deadline;
    pid_t pid;

    if (!result || !jmx_exec_valid(path, argv, output_limit, timeout_ms))
        return -1;
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    if (output_limit) {
        result->output = calloc(output_limit + 1, 1);
        if (!result->output || pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0)
            goto failed;
    }
#ifdef JMX_EXEC_SPAWN_CLOSEFROM
    {
        int spawn_rc = jmx_exec_spawn(&pid, path, argv, clean_env,
                                      output_limit ? pipefd[1] : -1);
        if (spawn_rc != 0) {
            if (pipefd[0] >= 0) close(pipefd[0]);
            if (pipefd[1] >= 0) close(pipefd[1]);
            /* Preserve the old child's exec failure result. */
            result->exit_code = spawn_rc == ENOENT ? 127 : 126;
            return 0;
        }
    }
#else
    pid = fork();
    if (pid < 0)
        goto failed;
    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (nullfd < 0)
            _exit(126);
        if (dup2(nullfd, STDIN_FILENO) < 0)
            _exit(126);
        if (output_limit) {
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
                dup2(pipefd[1], STDERR_FILENO) < 0)
                _exit(126);
            close(pipefd[1]);
        } else {
            if (dup2(nullfd, STDOUT_FILENO) < 0 || dup2(nullfd, STDERR_FILENO) < 0)
                _exit(126);
        }
        if (nullfd > STDERR_FILENO)
            close(nullfd);
        (void)setpgid(0, 0);
        jmx_exec_close_extra_fds();
        execve(path, argv, clean_env);
        _exit(errno == ENOENT ? 127 : 126);
    }
    (void)setpgid(pid, pid);
#endif
    if (output_limit) {
        close(pipefd[1]);
        pipefd[1] = -1;
    }
    deadline = jmx_exec_now_ms();
    if (deadline < 0)
        goto kill_failed;
    deadline += timeout_ms;
    while (!child_done || pipefd[0] >= 0) {
        int64_t now = jmx_exec_now_ms();
        int wait_ms = now >= 0 && now < deadline ? (int)(deadline - now) : 0;
        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN | POLLHUP };
        if (wait_ms > 50)
            wait_ms = 50;
        if (pipefd[0] >= 0 && poll(&pfd, 1, wait_ms) > 0 &&
            (pfd.revents & (POLLIN | POLLHUP))) {
            for (;;) {
                char buf[4096];
                ssize_t n = read(pipefd[0], buf, sizeof(buf));
                if (n > 0) {
                    size_t room = output_limit - result->output_len;
                    size_t take = (size_t)n < room ? (size_t)n : room;
                    if (take) {
                        memcpy(result->output + result->output_len, buf, take);
                        result->output_len += take;
                        result->output[result->output_len] = '\0';
                    }
                    if (take < (size_t)n)
                        result->truncated = 1;
                } else if (n == 0) {
                    close(pipefd[0]);
                    pipefd[0] = -1;
                    break;
                } else if (errno != EINTR && errno != EAGAIN) {
                    close(pipefd[0]);
                    pipefd[0] = -1;
                    break;
                } else {
                    break;
                }
            }
        } else if (pipefd[0] < 0 && wait_ms > 0) {
            usleep((useconds_t)(wait_ms > 10 ? 10 : wait_ms) * 1000);
        }
        if (!child_done) {
            pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid)
                child_done = 1;
            else if (waited < 0 && errno != EINTR)
                goto kill_failed;
        }
        now = jmx_exec_now_ms();
        if (child_done && pipefd[0] >= 0 && (now < 0 || now >= deadline)) {
            kill(-pid, SIGKILL);
            close(pipefd[0]);
            pipefd[0] = -1;
            result->truncated = 1;
        }
        if (!child_done && (now < 0 || now >= deadline)) {
            if (!term_sent) {
                kill(-pid, SIGTERM);
                result->timed_out = 1;
                term_sent = 1;
                deadline = (now < 0 ? 0 : now) + JMX_EXEC_KILL_GRACE_MS;
            } else {
                kill(-pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
                child_done = 1;
            }
        }
        if (child_done && pipefd[0] < 0)
            break;
    }
    if (WIFEXITED(status))
        result->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) {
        result->term_signal = WTERMSIG(status);
        result->exit_code = 128 + result->term_signal;
    }
    return 0;

kill_failed:
    kill(-pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
failed:
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    jmx_exec_result_free(result);
    return -1;
}

int jmx_exec_wait(const char *path, char *const argv[], int timeout_ms,
                  struct jmx_exec_result *result)
{
    return jmx_exec_capture(path, argv, 0, timeout_ms, result);
}
