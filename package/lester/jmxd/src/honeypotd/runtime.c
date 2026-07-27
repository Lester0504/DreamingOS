// SPDX-License-Identifier: GPL-2.0-or-later
#include "honeypotd_internal.h"

static void hp_runtime_defaults(struct hp_runtime *runtime)
{
    memset(runtime, 0, sizeof(*runtime));
    runtime->limits.max_sessions = HP_MAX_SESSIONS;
    runtime->limits.max_per_source = HP_MAX_PER_SOURCE_HARD;
    runtime->limits.source_rate_per_minute = 20;
    runtime->limits.idle_timeout_seconds = 20;
    runtime->limits.session_timeout_seconds = 60;
    runtime->limits.capture_limit = HP_CAPTURE_HARD_LIMIT;
    for (size_t i = 0; i < HP_MAX_LISTENERS; i++)
        runtime->listeners[i].fd = -1;
}

uint64_t hp_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

uint64_t hp_realtime_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

const char *hp_service_name(enum hp_service service)
{
    switch (service) {
    case HP_SERVICE_SSH: return "ssh";
    case HP_SERVICE_TELNET: return "telnet";
    case HP_SERVICE_HTTP: return "http";
    case HP_SERVICE_FTP: return "ftp";
    case HP_SERVICE_DNS: return "dns";
    default: return "unknown";
    }
}

static enum hp_service hp_service_parse(const char *value)
{
    if (!value)
        return 0;
    if (!strcasecmp(value, "ssh")) return HP_SERVICE_SSH;
    if (!strcasecmp(value, "telnet")) return HP_SERVICE_TELNET;
    if (!strcasecmp(value, "http")) return HP_SERVICE_HTTP;
    if (!strcasecmp(value, "ftp")) return HP_SERVICE_FTP;
    if (!strcasecmp(value, "dns")) return HP_SERVICE_DNS;
    return 0;
}

static const char *hp_json_string(struct json_object *obj, const char *name)
{
    struct json_object *value = NULL;

    if (!obj || !json_object_object_get_ex(obj, name, &value) ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static int hp_json_bool_strict(struct json_object *obj, const char *name,
                               bool fallback, bool *out)
{
    struct json_object *value = NULL;

    if (!json_object_object_get_ex(obj, name, &value)) {
        *out = fallback;
        return 0;
    }
    if (!json_object_is_type(value, json_type_boolean))
        return -1;
    *out = json_object_get_boolean(value);
    return 0;
}

static int hp_json_uint(struct json_object *obj, const char *name, unsigned int fallback,
                        unsigned int minimum, unsigned int maximum, unsigned int *out)
{
    struct json_object *value = NULL;
    int64_t number;

    if (!json_object_object_get_ex(obj, name, &value)) {
        *out = fallback;
        return 0;
    }
    if (!json_object_is_type(value, json_type_int))
        return -1;
    number = json_object_get_int64(value);
    if (number < minimum || number > maximum)
        return -1;
    *out = (unsigned int)number;
    return 0;
}

static int hp_read_runtime_file(const char *path, char **out)
{
    struct stat st;
    char *buffer;
    size_t offset = 0;
    int fd;

    *out = NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return errno == ENOENT ? 1 : -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > HP_RUNTIME_FILE_LIMIT) {
        close(fd);
        return -1;
    }
    buffer = calloc(1, (size_t)st.st_size + 1);
    if (!buffer) {
        close(fd);
        return -1;
    }
    while (offset < (size_t)st.st_size) {
        ssize_t got = read(fd, buffer + offset, (size_t)st.st_size - offset);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            free(buffer);
            close(fd);
            return -1;
        }
        offset += (size_t)got;
    }
    close(fd);
    buffer[offset] = '\0';
    *out = buffer;
    return 0;
}

static int hp_parse_ipv4_destination(const char *value, char *out, size_t out_size)
{
    struct in_addr address;
    uint32_t host;

    if (!value || !value[0] || inet_pton(AF_INET, value, &address) != 1)
        return -1;
    host = ntohl(address.s_addr);
    if (host == 0 || host == 0xffffffffU || (host & 0xf0000000U) == 0xe0000000U)
        return -1;
    if (!inet_ntop(AF_INET, &address, out, out_size))
        return -1;
    return 0;
}

static int hp_copy_string(char *output, size_t output_size, const char *value,
                          bool required)
{
    size_t length;

    if (!value || !value[0]) {
        if (required)
            return -1;
        output[0] = '\0';
        return 0;
    }
    length = strlen(value);
    if (length >= output_size)
        return -1;
    memcpy(output, value, length + 1);
    return 0;
}

static int hp_parse_ingest_token(struct hp_runtime *runtime, const char *value)
{
    if (!value || strlen(value) != 64)
        return -1;
    for (size_t i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return -1;
        runtime->ingest_token[i] = (char)c;
    }
    runtime->ingest_token[64] = '\0';
    return 0;
}

static int hp_listener_parse_service(struct hp_runtime *runtime,
                                     struct json_object *honeypot,
                                     struct json_object *service_item)
{
    struct hp_listener *listener;
    struct json_object *value = NULL;
    const char *service_value;
    const char *transport_value;
    const char *address;
    const char *honeypot_id;
    const char *profile;
    const char *ifname;
    unsigned int listen_port;
    unsigned int external_port;

    if (!json_object_is_type(honeypot, json_type_object) ||
        !json_object_is_type(service_item, json_type_object) ||
        runtime->listener_count >= HP_MAX_LISTENERS)
        return -1;
    listener = &runtime->listeners[runtime->listener_count];
    service_value = hp_json_string(service_item, "name");
    listener->service = hp_service_parse(service_value);
    if (!listener->service)
        return -1;
    transport_value = hp_json_string(service_item, "transport");
    listener->transport = listener->service == HP_SERVICE_DNS ?
        HP_TRANSPORT_UDP : HP_TRANSPORT_TCP;
    if (!transport_value)
        return -1;
    enum hp_transport requested = !strcasecmp(transport_value, "udp") ?
        HP_TRANSPORT_UDP : !strcasecmp(transport_value, "tcp") ? HP_TRANSPORT_TCP : 0;
    if (!requested || requested != listener->transport)
        return -1;
    if (hp_json_uint(service_item, "listen_port", 0, 1024, 65535, &listen_port) != 0 ||
        listen_port == 0 ||
        hp_json_uint(service_item, "external_port", 0, 1, 65535, &external_port) != 0 ||
        external_port == 0)
        return -1;
    honeypot_id = hp_json_string(honeypot, "id");
    address = hp_json_string(honeypot, "address");
    if (hp_copy_string(listener->honeypot_id, sizeof(listener->honeypot_id),
                       honeypot_id, true) != 0 ||
        hp_parse_ipv4_destination(address, listener->address,
                                  sizeof(listener->address)) != 0)
        return -1;
    profile = hp_json_string(honeypot, "profile");
    ifname = hp_json_string(honeypot, "interface");
    if (hp_copy_string(listener->profile, sizeof(listener->profile), profile, true) != 0 ||
        hp_copy_string(listener->ifname, sizeof(listener->ifname), ifname, true) != 0)
        return -1;
    listener->listen_port = (uint16_t)listen_port;
    listener->external_port = (uint16_t)external_port;
    listener->dns_rcode = 5;
    if (listener->service == HP_SERVICE_DNS &&
        json_object_object_get_ex(service_item, "dns_response", &value)) {
        const char *response;

        if (!json_object_is_type(value, json_type_string))
            return -1;
        response = json_object_get_string(value);
        if (!strcasecmp(response, "nxdomain"))
            listener->dns_rcode = 3;
        else if (strcasecmp(response, "refused"))
            return -1;
    }
    for (size_t i = 0; i < runtime->listener_count; i++) {
        const struct hp_listener *existing = &runtime->listeners[i];

        if (existing->transport != listener->transport ||
            existing->listen_port != listener->listen_port)
            continue;
        if (existing->service != listener->service)
            return -1;
        if (existing->external_port == listener->external_port &&
            !strcmp(existing->address, listener->address))
            return -1;
    }
    runtime->listener_count++;
    return 0;
}

static int hp_parse_honeypots(struct hp_runtime *runtime, struct json_object *honeypots)
{
    size_t honeypot_count;

    if (!json_object_is_type(honeypots, json_type_array))
        return -1;
    honeypot_count = json_object_array_length(honeypots);
    if (honeypot_count == 0 || honeypot_count > HP_MAX_LISTENERS)
        return -1;
    for (size_t i = 0; i < honeypot_count; i++) {
        struct json_object *honeypot = json_object_array_get_idx(honeypots, i);
        struct json_object *services = NULL;
        size_t service_count;

        if (!json_object_is_type(honeypot, json_type_object) ||
            !json_object_object_get_ex(honeypot, "services", &services) ||
            !json_object_is_type(services, json_type_array))
            return -1;
        service_count = json_object_array_length(services);
        if (service_count == 0 || service_count > HP_MAX_LISTENERS - runtime->listener_count)
            return -1;
        for (size_t j = 0; j < service_count; j++) {
            if (hp_listener_parse_service(runtime, honeypot,
                                          json_object_array_get_idx(services, j)) != 0)
                return -1;
        }
    }
    return runtime->listener_count ? 0 : -1;
}

int hp_runtime_load(struct hp_runtime *runtime, const char *path)
{
    struct json_object *root = NULL;
    struct json_object *limits = NULL;
    struct json_object *honeypots = NULL;
    char *raw = NULL;
    int read_rc;

    hp_runtime_defaults(runtime);
    read_rc = hp_read_runtime_file(path, &raw);
    if (read_rc == 1)
        return 0;
    if (read_rc != 0)
        return -1;
    root = json_tokener_parse(raw);
    free(raw);
    if (!root || !json_object_is_type(root, json_type_object))
        goto invalid;
    if (hp_json_bool_strict(root, "enabled", false, &runtime->enabled) != 0)
        goto invalid;
    if (!runtime->enabled) {
        json_object_put(root);
        return 0;
    }
    if (hp_parse_ingest_token(runtime, hp_json_string(root, "ingest_token")) != 0)
        goto invalid;
    if (json_object_object_get_ex(root, "limits", &limits) &&
        !json_object_is_type(limits, json_type_object))
        goto invalid;
    if (!limits)
        limits = root;
    if (hp_json_uint(limits, "max_sessions", HP_MAX_SESSIONS, 1, HP_MAX_SESSIONS,
                     &runtime->limits.max_sessions) != 0 ||
        hp_json_uint(limits, "max_per_source", HP_MAX_PER_SOURCE_HARD, 1,
                     HP_MAX_PER_SOURCE_HARD, &runtime->limits.max_per_source) != 0 ||
        hp_json_uint(limits, "source_rate_per_minute", 20, 1, 120,
                     &runtime->limits.source_rate_per_minute) != 0 ||
        hp_json_uint(limits, "idle_timeout_seconds", 20, 1, 30,
                     &runtime->limits.idle_timeout_seconds) != 0 ||
        hp_json_uint(limits, "session_timeout_seconds", 60, 1, 60,
                     &runtime->limits.session_timeout_seconds) != 0 ||
        hp_json_uint(limits, "capture_limit", HP_CAPTURE_HARD_LIMIT, 1,
                     HP_CAPTURE_HARD_LIMIT, &runtime->limits.capture_limit) != 0)
        goto invalid;
    if (runtime->limits.max_per_source > runtime->limits.max_sessions)
        goto invalid;
    if (!json_object_object_get_ex(root, "honeypots", &honeypots) ||
        hp_parse_honeypots(runtime, honeypots) != 0)
        goto invalid;
    json_object_put(root);
    return 0;

invalid:
    if (root)
        json_object_put(root);
    hp_runtime_close(runtime);
    hp_runtime_defaults(runtime);
    return -1;
}

static int hp_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

int hp_runtime_open_listeners(struct hp_runtime *runtime)
{
    for (size_t i = 0; i < runtime->listener_count; i++) {
        struct hp_listener *listener = &runtime->listeners[i];
        struct sockaddr_in bind_address;
        int type = listener->transport == HP_TRANSPORT_UDP ? SOCK_DGRAM : SOCK_STREAM;
        int one = 1;

        for (size_t j = 0; listener->transport == HP_TRANSPORT_TCP && j < i; j++) {
            const struct hp_listener *existing = &runtime->listeners[j];

            if (existing->fd >= 0 && existing->transport == listener->transport &&
                existing->service == listener->service &&
                existing->listen_port == listener->listen_port) {
                listener->fd = -1;
                goto next_listener;
            }
        }

        listener->fd = socket(AF_INET, type, 0);
        if (listener->fd < 0 || hp_socket_nonblocking(listener->fd) != 0)
            goto fail;
        if (listener->transport == HP_TRANSPORT_TCP &&
            setsockopt(listener->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
            goto fail;
        memset(&bind_address, 0, sizeof(bind_address));
        bind_address.sin_family = AF_INET;
        if (listener->transport == HP_TRANSPORT_UDP) {
            if (inet_pton(AF_INET, listener->address, &bind_address.sin_addr) != 1)
                goto fail;
        } else {
            bind_address.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        bind_address.sin_port = htons(listener->listen_port);
        memcpy(&listener->bind_addr, &bind_address, sizeof(bind_address));
        listener->bind_len = sizeof(bind_address);

        /*
         * Wildcard bind is intentional: nft prerouting redirect targets the ingress
         * interface's local address, not loopback.  The Aegis chain must accept only
         * packets whose ct original daddr is this listener's configured honeypot IP
         * and must drop direct access to every internal port.
         */
        if (bind(listener->fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) != 0)
            goto fail;
        if (listener->transport == HP_TRANSPORT_TCP &&
            listen(listener->fd, (int)runtime->limits.max_sessions) != 0)
            goto fail;
next_listener:
        ;
    }
    return 0;

fail:
    hp_runtime_close(runtime);
    return -1;
}

ssize_t hp_runtime_mapping_for_original(const struct hp_runtime *runtime,
                                        size_t socket_index,
                                        const struct sockaddr_in *original)
{
    const struct hp_listener *socket_listener;
    char address[INET_ADDRSTRLEN];
    uint16_t external_port;
    ssize_t match = -1;

    if (!runtime || !original || socket_index >= runtime->listener_count ||
        original->sin_family != AF_INET ||
        !inet_ntop(AF_INET, &original->sin_addr, address, sizeof(address)))
        return -1;
    socket_listener = &runtime->listeners[socket_index];
    external_port = ntohs(original->sin_port);
    for (size_t i = 0; i < runtime->listener_count; i++) {
        const struct hp_listener *candidate = &runtime->listeners[i];

        if (candidate->transport != socket_listener->transport ||
            candidate->service != socket_listener->service ||
            candidate->listen_port != socket_listener->listen_port ||
            candidate->external_port != external_port ||
            strcmp(candidate->address, address))
            continue;
        if (match >= 0)
            return -1;
        match = (ssize_t)i;
    }
    return match;
}

void hp_runtime_close(struct hp_runtime *runtime)
{
    for (size_t i = 0; i < HP_MAX_LISTENERS; i++) {
        if (runtime->listeners[i].fd >= 0) {
            close(runtime->listeners[i].fd);
            runtime->listeners[i].fd = -1;
        }
    }
    runtime->listener_count = 0;
    memset(runtime->ingest_token, 0, sizeof(runtime->ingest_token));
}
