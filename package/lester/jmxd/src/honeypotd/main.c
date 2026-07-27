// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt low-interaction honeypot data plane. */
#include "honeypotd_internal.h"

static volatile sig_atomic_t hp_stopping;

enum hp_poll_kind {
    HP_POLL_LISTENER = 1,
    HP_POLL_SESSION = 2,
};

struct hp_poll_ref {
    enum hp_poll_kind kind;
    size_t index;
};

static void hp_signal_handler(int signo)
{
    (void)signo;
    hp_stopping = 1;
}

static int hp_set_nonblocking_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

static int hp_apply_resource_limits(const struct hp_runtime *runtime)
{
    struct rlimit limit;
    rlim_t nofile = (rlim_t)runtime->limits.max_sessions +
                    (rlim_t)runtime->listener_count + 64;

    limit.rlim_cur = limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limit) != 0)
        return -1;
    limit.rlim_cur = limit.rlim_max = nofile;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
        return -1;
#ifdef RLIMIT_AS
    limit.rlim_cur = limit.rlim_max = 64U * 1024U * 1024U;
    if (setrlimit(RLIMIT_AS, &limit) != 0)
        return -1;
#endif
    return 0;
}

static int hp_drop_privileges(void)
{
    struct passwd *password;
    gid_t gid = 65534;
    uid_t uid = 65534;

    if (geteuid() != 0)
        return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    password = getpwnam("nobody");
    if (password) {
        uid = password->pw_uid;
        gid = password->pw_gid;
    }
    if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
        return -1;
    if (setuid(0) == 0)
        return -1;
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

static void hp_sockaddr_source(const struct sockaddr_storage *address, char *host,
                               size_t host_size, uint16_t *port)
{
    host[0] = '\0';
    *port = 0;
    if (address->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)address;

        (void)inet_ntop(AF_INET, &sin->sin_addr, host, host_size);
        *port = ntohs(sin->sin_port);
    } else if (address->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)address;

        (void)inet_ntop(AF_INET6, &sin6->sin6_addr, host, host_size);
        *port = ntohs(sin6->sin6_port);
    }
}

bool hp_source_rate_allow(struct hp_state *state, const char *source_ip, uint64_t now_ms)
{
    struct hp_source_rate *free_entry = NULL;
    struct hp_source_rate *oldest = NULL;

    for (size_t i = 0; i < HP_MAX_SOURCE_RATES; i++) {
        struct hp_source_rate *entry = &state->source_rates[i];

        if (entry->used && !strcmp(entry->address, source_ip)) {
            if (now_ms - entry->window_started_ms >= 60000U) {
                entry->window_started_ms = now_ms;
                entry->accepted = 0;
            }
            entry->last_seen_ms = now_ms;
            if (entry->accepted >= state->runtime.limits.source_rate_per_minute)
                return false;
            entry->accepted++;
            return true;
        }
        if (!entry->used && !free_entry)
            free_entry = entry;
        if (entry->used && (!oldest || entry->last_seen_ms < oldest->last_seen_ms))
            oldest = entry;
    }
    struct hp_source_rate *entry = free_entry ? free_entry : oldest;
    if (!entry)
        return false;
    memset(entry, 0, sizeof(*entry));
    entry->used = true;
    snprintf(entry->address, sizeof(entry->address), "%s", source_ip);
    entry->window_started_ms = now_ms;
    entry->last_seen_ms = now_ms;
    entry->accepted = 1;
    return true;
}

static unsigned int hp_source_active_count(const struct hp_state *state, const char *source_ip)
{
    unsigned int count = 0;

    for (size_t i = 0; i < state->runtime.limits.max_sessions; i++) {
        if (state->sessions[i].active &&
            !strcmp(state->sessions[i].source_ip, source_ip))
            count++;
    }
    return count;
}

static struct hp_session *hp_session_allocate(struct hp_state *state, size_t *index)
{
    for (size_t i = 0; i < state->runtime.limits.max_sessions; i++) {
        if (!state->sessions[i].active) {
            *index = i;
            return &state->sessions[i];
        }
    }
    return NULL;
}

static void hp_session_close(struct hp_state *state, size_t index)
{
    struct hp_session *session = &state->sessions[index];

    if (!session->active)
        return;
    close(session->fd);
    memset(session, 0, sizeof(*session));
    session->fd = -1;
    if (state->active_sessions)
        state->active_sessions--;
}

static void hp_accept_ready(struct hp_state *state, size_t listener_index)
{
    const struct hp_listener *listener = &state->runtime.listeners[listener_index];

    for (unsigned int accepted = 0; accepted < 32; accepted++) {
        struct sockaddr_storage source;
        socklen_t source_len = sizeof(source);
        char source_ip[INET6_ADDRSTRLEN];
        uint16_t source_port;
        struct hp_session *session;
        struct sockaddr_in original;
        socklen_t original_len = sizeof(original);
        ssize_t mapping_index;
        size_t session_index;
        uint64_t now_ms;
        int fd;

        fd = accept(listener->fd, (struct sockaddr *)&source, &source_len);
        if (fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (fd < 0 && errno == EINTR)
            continue;
        if (fd < 0)
            return;
        if (hp_set_nonblocking_cloexec(fd) != 0) {
            close(fd);
            continue;
        }
        memset(&original, 0, sizeof(original));
        if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &original, &original_len) != 0 ||
            original_len < sizeof(original)) {
            close(fd);
            continue;
        }
        mapping_index = hp_runtime_mapping_for_original(&state->runtime,
                                                        listener_index, &original);
        if (mapping_index < 0) {
            close(fd);
            continue;
        }
        hp_sockaddr_source(&source, source_ip, sizeof(source_ip), &source_port);
        now_ms = hp_monotonic_ms();
        if (!source_ip[0] || state->active_sessions >= state->runtime.limits.max_sessions ||
            hp_source_active_count(state, source_ip) >= state->runtime.limits.max_per_source ||
            !hp_source_rate_allow(state, source_ip, now_ms)) {
            close(fd);
            continue;
        }
        session = hp_session_allocate(state, &session_index);
        if (!session) {
            close(fd);
            continue;
        }
        memset(session, 0, sizeof(*session));
        session->active = true;
        session->fd = fd;
        session->listener_index = (size_t)mapping_index;
        session->started_ms = now_ms;
        session->last_activity_ms = now_ms;
        session->source_port = source_port;
        snprintf(session->source_ip, sizeof(session->source_ip), "%s", source_ip);
        state->active_sessions++;
        hp_protocol_on_accept(state, session);
    }
}

static bool hp_session_read(struct hp_state *state, size_t index, uint64_t now_ms)
{
    struct hp_session *session = &state->sessions[index];
    size_t limit = state->runtime.limits.capture_limit;

    while (session->input_len < limit) {
        size_t available = limit - session->input_len;
        ssize_t got = recv(session->fd, session->input + session->input_len,
                           available, MSG_DONTWAIT);

        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        if (got <= 0)
            return false;
        session->input_len += (size_t)got;
        session->captured += (size_t)got;
        session->last_activity_ms = now_ms;
        hp_protocol_on_data(state, session);
        if (session->close_after_write)
            break;
    }
    if (session->input_len >= limit && !session->close_after_write)
        session->close_after_write = true;
    return true;
}

static bool hp_session_write(struct hp_session *session, uint64_t now_ms)
{
    while (session->output_offset < session->output_len) {
        ssize_t sent = send(session->fd, session->output + session->output_offset,
                            session->output_len - session->output_offset,
                            MSG_DONTWAIT | MSG_NOSIGNAL);

        if (sent < 0 && errno == EINTR)
            continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return true;
        if (sent <= 0)
            return false;
        session->output_offset += (size_t)sent;
        session->last_activity_ms = now_ms;
    }
    session->output_offset = 0;
    session->output_len = 0;
    return !session->close_after_write;
}

static void hp_expire_sessions(struct hp_state *state, uint64_t now_ms)
{
    uint64_t idle_limit = (uint64_t)state->runtime.limits.idle_timeout_seconds * 1000U;
    uint64_t total_limit = (uint64_t)state->runtime.limits.session_timeout_seconds * 1000U;

    for (size_t i = 0; i < state->runtime.limits.max_sessions; i++) {
        struct hp_session *session = &state->sessions[i];

        if (!session->active)
            continue;
        if (now_ms - session->last_activity_ms >= idle_limit ||
            now_ms - session->started_ms >= total_limit)
            hp_session_close(state, i);
    }
}

static nfds_t hp_build_pollfds(struct hp_state *state, struct pollfd *pollfds,
                               struct hp_poll_ref *refs)
{
    nfds_t count = 0;

    for (size_t i = 0; i < state->runtime.listener_count; i++) {
        if (state->runtime.listeners[i].fd < 0)
            continue;
        pollfds[count].fd = state->runtime.listeners[i].fd;
        pollfds[count].events = POLLIN;
        pollfds[count].revents = 0;
        refs[count].kind = HP_POLL_LISTENER;
        refs[count].index = i;
        count++;
    }
    for (size_t i = 0; i < state->runtime.limits.max_sessions; i++) {
        struct hp_session *session = &state->sessions[i];

        if (!session->active)
            continue;
        pollfds[count].fd = session->fd;
        pollfds[count].events = POLLIN;
        if (session->output_offset < session->output_len)
            pollfds[count].events |= POLLOUT;
        pollfds[count].revents = 0;
        refs[count].kind = HP_POLL_SESSION;
        refs[count].index = i;
        count++;
    }
    return count;
}

static void hp_handle_poll(struct hp_state *state, const struct pollfd *pollfd,
                           const struct hp_poll_ref *ref, uint64_t now_ms)
{
    if (ref->kind == HP_POLL_LISTENER) {
        const struct hp_listener *listener = &state->runtime.listeners[ref->index];

        if (!(pollfd->revents & POLLIN))
            return;
        if (listener->transport == HP_TRANSPORT_UDP)
            hp_protocol_handle_dns(state, ref->index);
        else
            hp_accept_ready(state, ref->index);
        return;
    }
    struct hp_session *session = &state->sessions[ref->index];
    if (!session->active)
        return;
    if (pollfd->revents & (POLLERR | POLLNVAL)) {
        hp_session_close(state, ref->index);
        return;
    }
    if ((pollfd->revents & POLLIN) && !hp_session_read(state, ref->index, now_ms)) {
        hp_session_close(state, ref->index);
        return;
    }
    session = &state->sessions[ref->index];
    if (!session->active)
        return;
    if (session->close_after_write && session->output_offset == session->output_len) {
        hp_session_close(state, ref->index);
        return;
    }
    if ((pollfd->revents & POLLOUT) && !hp_session_write(session, now_ms)) {
        hp_session_close(state, ref->index);
        return;
    }
    if ((pollfd->revents & POLLHUP) && session->output_len == session->output_offset)
        hp_session_close(state, ref->index);
}

static int hp_run(struct hp_state *state)
{
    struct pollfd pollfds[HP_MAX_LISTENERS + HP_MAX_SESSIONS];
    struct hp_poll_ref refs[HP_MAX_LISTENERS + HP_MAX_SESSIONS];

    while (!hp_stopping) {
        uint64_t now_ms = hp_monotonic_ms();
        nfds_t count;
        int timeout_ms;
        int rc;

        hp_expire_sessions(state, now_ms);
        hp_events_flush(&state->events, now_ms);
        count = hp_build_pollfds(state, pollfds, refs);
        if (state->events.count && state->events.next_retry_ms <= now_ms)
            timeout_ms = 10;
        else if (state->events.count && state->events.next_retry_ms > now_ms) {
            uint64_t wait_ms = state->events.next_retry_ms - now_ms;
            timeout_ms = wait_ms < 250U ? (int)wait_ms : 250;
        } else
            timeout_ms = 250;
        rc = poll(pollfds, count, timeout_ms);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0)
            return -1;
        now_ms = hp_monotonic_ms();
        for (nfds_t i = 0; i < count && rc > 0; i++) {
            if (!pollfds[i].revents)
                continue;
            hp_handle_poll(state, &pollfds[i], &refs[i], now_ms);
            rc--;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct hp_state state;
    int load_rc;
    int result = EXIT_FAILURE;

    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "usage: dreamingwrt-honeypotd\n");
        return EXIT_FAILURE;
    }
    memset(&state, 0, sizeof(state));
    for (size_t i = 0; i < HP_MAX_SESSIONS; i++)
        state.sessions[i].fd = -1;
    signal(SIGINT, hp_signal_handler);
    signal(SIGTERM, hp_signal_handler);
    signal(SIGPIPE, SIG_IGN);

    load_rc = hp_runtime_load(&state.runtime, HP_RUNTIME_PATH);
    if (load_rc != 0) {
        fprintf(stderr, "dreamingwrt-honeypotd: invalid runtime configuration\n");
        return EXIT_FAILURE;
    }
    if (!state.runtime.enabled || state.runtime.listener_count == 0)
        return EXIT_SUCCESS;
    if (hp_apply_resource_limits(&state.runtime) != 0 ||
        hp_runtime_open_listeners(&state.runtime) != 0) {
        fprintf(stderr, "dreamingwrt-honeypotd: listener initialization failed\n");
        goto out_runtime;
    }
    if (hp_drop_privileges() != 0) {
        fprintf(stderr, "dreamingwrt-honeypotd: privilege drop failed\n");
        goto out_runtime;
    }
    if (hp_events_init(&state.events) != 0) {
        fprintf(stderr, "dreamingwrt-honeypotd: Aegis event channel unavailable\n");
        goto out_runtime;
    }
    result = hp_run(&state) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    for (size_t i = 0; i < state.runtime.limits.max_sessions; i++)
        hp_session_close(&state, i);
    for (unsigned int i = 0; i < 4 && state.events.count; i++)
        hp_events_flush(&state.events, hp_monotonic_ms());

    hp_events_close(&state.events);
out_runtime:
    hp_runtime_close(&state.runtime);
    return result;
}
