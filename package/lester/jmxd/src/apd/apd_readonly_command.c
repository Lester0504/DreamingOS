// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_readonly_command.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef APD_COMMAND_LIMIT
#define APD_COMMAND_LIMIT (256U * 1024U)
#endif
#ifndef APD_COMMAND_STDERR_LIMIT
#define APD_COMMAND_STDERR_LIMIT (8U * 1024U)
#endif

static int64_t apd_command_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int apd_child_wait(pid_t child, int *status, int options,
                          int *status_valid)
{
    pid_t waited;

    do {
        waited = waitpid(child, status, options);
    } while (waited < 0 && errno == EINTR);
    if (waited == child) {
        if (status_valid)
            *status_valid = 1;
        return 1;
    }
    if (waited == 0)
        return 0;
    if (waited < 0 && errno == ECHILD)
        return 1;
    return -1;
}

int apd_readonly_command_bounded(const char *path, char *const argv[],
                                 int timeout_ms, size_t output_limit,
                                 struct apd_command_result *result)
{
    int stdout_pipe[2] = { -1, -1 };
    int stderr_pipe[2] = { -1, -1 };
    pid_t child;
    int flags;
    int status = 0;
    int status_valid = 0;
    int child_done = 0;
    int stdout_eof = 0;
    int stderr_eof = 0;
    int io_failed = 0;
    int64_t deadline;
    size_t stdout_capacity = 4096;
    size_t stderr_capacity = 1024;

    if (!path || !argv || !result || timeout_ms <= 0 || output_limit == 0 ||
        access(path, X_OK) != 0)
        return -1;
    memset(result, 0, sizeof(*result));
    result->exit_status = -1;
    result->path = path;
    result->text = calloc(1, stdout_capacity);
    result->stderr_text = calloc(1, stderr_capacity);
    if (!result->text || !result->stderr_text || pipe(stdout_pipe) != 0 ||
        pipe(stderr_pipe) != 0)
        goto fail;
    child = fork();
    if (child < 0)
        goto fail;
    if (child == 0) {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(stderr_pipe[1], STDERR_FILENO) < 0)
            _exit(126);
        if (stdout_pipe[1] != STDOUT_FILENO)
            close(stdout_pipe[1]);
        if (stderr_pipe[1] != STDERR_FILENO)
            close(stderr_pipe[1]);
        execv(path, argv);
        _exit(127);
    }

    close(stdout_pipe[1]);
    stdout_pipe[1] = -1;
    close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
    flags = fcntl(stdout_pipe[0], F_GETFL, 0);
    if (flags >= 0)
        fcntl(stdout_pipe[0], F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(stderr_pipe[0], F_GETFL, 0);
    if (flags >= 0)
        fcntl(stderr_pipe[0], F_SETFL, flags | O_NONBLOCK);
    deadline = apd_command_monotonic_ms() + timeout_ms;
    while (!stdout_eof || !stderr_eof || !child_done) {
        struct pollfd pfds[2];
        nfds_t nfds = 0;
        int64_t remaining = deadline - apd_command_monotonic_ms();
        int wait_ms = remaining > 100 ? 100 :
                      (remaining > 0 ? (int)remaining : 0);
        int poll_rc;

        if (!stdout_eof) {
            pfds[nfds].fd = stdout_pipe[0];
            pfds[nfds].events = POLLIN | POLLHUP;
            pfds[nfds].revents = 0;
            nfds++;
        }
        if (!stderr_eof) {
            pfds[nfds].fd = stderr_pipe[0];
            pfds[nfds].events = POLLIN | POLLHUP;
            pfds[nfds].revents = 0;
            nfds++;
        }

        if (remaining <= 0) {
            result->timed_out = 1;
            if (!child_done) {
                if (kill(child, SIGKILL) != 0 && errno != ESRCH)
                    io_failed = 1;
                if (apd_child_wait(child, &status, 0, &status_valid) < 0)
                    io_failed = 1;
                child_done = 1;
            }
            break;
        }
        poll_rc = nfds ? poll(pfds, nfds, wait_ms) : 0;
        if (poll_rc < 0 && errno != EINTR) {
            io_failed = 1;
            stdout_eof = 1;
            stderr_eof = 1;
        }
        for (nfds_t i = 0; poll_rc > 0 && i < nfds; i++) {
            int is_stderr = pfds[i].fd == stderr_pipe[0];
            int *eof = is_stderr ? &stderr_eof : &stdout_eof;

            if (pfds[i].revents & (POLLERR | POLLNVAL)) {
                io_failed = 1;
                *eof = 1;
                continue;
            }
            if (!(pfds[i].revents & (POLLIN | POLLHUP)))
                continue;
            for (;;) {
                char chunk[2048];
                ssize_t got = read(pfds[i].fd, chunk, sizeof(chunk));

                if (got > 0 && is_stderr) {
                    size_t copy = (size_t)got;
                    size_t available = result->stderr_length < APD_COMMAND_STDERR_LIMIT ?
                        APD_COMMAND_STDERR_LIMIT - result->stderr_length : 0;
                    size_t needed;

                    if (copy > available) {
                        copy = available;
                        result->stderr_limited = 1;
                    }
                    needed = result->stderr_length + copy + 1;
                    if (needed > stderr_capacity) {
                        char *expanded;

                        while (stderr_capacity < needed)
                            stderr_capacity *= 2;
                        expanded = realloc(result->stderr_text, stderr_capacity);
                        if (!expanded) {
                            kill(child, SIGKILL);
                            goto parent_fail;
                        }
                        result->stderr_text = expanded;
                    }
                    if (copy) {
                        memcpy(result->stderr_text + result->stderr_length,
                               chunk, copy);
                        result->stderr_length += copy;
                        result->stderr_text[result->stderr_length] = '\0';
                    }
                    continue;
                }
                if (got > 0) {
                    size_t needed;

                    if (result->length >= output_limit ||
                        (size_t)got > output_limit - result->length) {
                        result->output_limited = 1;
                        if (kill(child, SIGKILL) != 0 && errno != ESRCH)
                            io_failed = 1;
                        *eof = 1;
                        break;
                    }
                    needed = result->length + (size_t)got + 1;
                    if (needed > stdout_capacity) {
                        char *expanded;

                        while (stdout_capacity < needed)
                            stdout_capacity *= 2;
                        expanded = realloc(result->text, stdout_capacity);
                        if (!expanded) {
                            kill(child, SIGKILL);
                            goto parent_fail;
                        }
                        result->text = expanded;
                    }
                    memcpy(result->text + result->length, chunk, (size_t)got);
                    result->length += (size_t)got;
                    result->text[result->length] = '\0';
                    continue;
                }
                if (got == 0)
                    *eof = 1;
                else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                         errno != EINTR)
                    *eof = 1;
                break;
            }
        }
        if (!child_done) {
            int wait_state = apd_child_wait(child, &status, WNOHANG,
                                            &status_valid);

            if (wait_state != 0) {
                child_done = 1;
                if (wait_state < 0)
                    io_failed = 1;
            }
        }
        if (result->timed_out || result->output_limited) {
            if (!child_done) {
                if (kill(child, SIGKILL) != 0 && errno != ESRCH)
                    io_failed = 1;
                if (apd_child_wait(child, &status, 0, &status_valid) < 0)
                    io_failed = 1;
                child_done = 1;
            }
            break;
        }
    }
    close(stdout_pipe[0]);
    stdout_pipe[0] = -1;
    close(stderr_pipe[0]);
    stderr_pipe[0] = -1;
    if (status_valid && WIFEXITED(status))
        result->exit_status = WEXITSTATUS(status);
    else if (status_valid && WIFSIGNALED(status))
        result->exit_status = 128 + WTERMSIG(status);
    return result->timed_out || result->output_limited || io_failed ||
           result->exit_status != 0 ? -1 : 0;

parent_fail:
    (void)apd_child_wait(child, &status, 0, &status_valid);
fail:
    if (stdout_pipe[0] >= 0)
        close(stdout_pipe[0]);
    if (stdout_pipe[1] >= 0)
        close(stdout_pipe[1]);
    if (stderr_pipe[0] >= 0)
        close(stderr_pipe[0]);
    if (stderr_pipe[1] >= 0)
        close(stderr_pipe[1]);
    free(result ? result->text : NULL);
    free(result ? result->stderr_text : NULL);
    if (result)
        memset(result, 0, sizeof(*result));
    return -1;
}

int apd_readonly_command(const char *path, char *const argv[],
                         struct apd_command_result *result)
{
    return apd_readonly_command_bounded(path, argv,
                                        APD_READONLY_COMMAND_TIMEOUT_MS,
                                        APD_COMMAND_LIMIT, result);
}

void apd_command_result_free(struct apd_command_result *result)
{
    if (!result)
        return;
    free(result->text);
    free(result->stderr_text);
    memset(result, 0, sizeof(*result));
}
