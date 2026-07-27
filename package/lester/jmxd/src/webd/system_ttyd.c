// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "system_ttyd.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <json-c/json.h>
#include <limits.h>
#include <net/if.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <uci.h>
#include <unistd.h>

#ifndef SYSTEM_TTYD_CONFIG_PATH
#define SYSTEM_TTYD_CONFIG_PATH "/etc/config/ttyd"
#endif
#ifndef SYSTEM_TTYD_LOCK_PATH
#define SYSTEM_TTYD_LOCK_PATH "/var/lock/dreamingwrt-system-ttyd.lock"
#endif
#ifndef SYSTEM_TTYD_BACKUP_DIR
#define SYSTEM_TTYD_BACKUP_DIR "/etc/dreamingwrt/backups/ttyd"
#endif
#ifndef SYSTEM_TTYD_INIT_PATH
#define SYSTEM_TTYD_INIT_PATH "/etc/init.d/ttyd"
#endif
#ifndef SYSTEM_TTYD_BINARY_PATH
#define SYSTEM_TTYD_BINARY_PATH "/usr/bin/ttyd"
#endif
#ifndef SYSTEM_TTYD_UBUS_PATH
#define SYSTEM_TTYD_UBUS_PATH "/bin/ubus"
#endif
#ifndef SYSTEM_TTYD_SS_PATH
#define SYSTEM_TTYD_SS_PATH "/usr/sbin/ss"
#endif

#define TTYD_MAX_INSTANCES 32
#define TTYD_MAX_CLIENT_OPTIONS 64
#define TTYD_MAX_ID 64
#define TTYD_MAX_INTERFACE 107
#define TTYD_MAX_CREDENTIAL 256
#define TTYD_MAX_PATH 512
#define TTYD_MAX_COMMAND 1024
#define TTYD_MAX_URL 2048
#define TTYD_MAX_OPTION 256
#define TTYD_MAX_CONFIG (1024U * 1024U)
#define TTYD_COMMAND_OUTPUT 65536U
#define TTYD_EXEC_TIMEOUT_MS 8000
#define TTYD_RUNTIME_RETRIES 20
#define TTYD_BACKUPS_RETAIN 32

struct ttyd_snapshot {
    char *data;
    size_t len;
    mode_t mode;
    int existed;
};

struct ttyd_exec_result {
    int exit_code;
    int timed_out;
    int output_truncated;
};

struct ttyd_instance {
    char id[TTYD_MAX_ID + 1];
    int enable;
    int unix_sock;
    int port;
    char interface[TTYD_MAX_INTERFACE + 1];
    char credential[TTYD_MAX_CREDENTIAL + 1];
    int credential_configured;
    char uid[24];
    char gid[24];
    int signal;
    int url_arg;
    int readonly;
    char client_option[TTYD_MAX_CLIENT_OPTIONS][TTYD_MAX_OPTION + 1];
    size_t client_option_count;
    char terminal_type[64];
    int check_origin;
    int max_clients;
    int once;
    char index[TTYD_MAX_PATH + 1];
    int ipv6;
    int ssl;
    char ssl_cert[TTYD_MAX_PATH + 1];
    char ssl_key[TTYD_MAX_PATH + 1];
    char ssl_ca[TTYD_MAX_PATH + 1];
    int debug;
    char command[TTYD_MAX_COMMAND + 1];
    char url_override[TTYD_MAX_URL + 1];
    int running;
    int pid;
    char listen[TTYD_MAX_PATH + 1];
};

struct ttyd_config {
    struct ttyd_instance instances[TTYD_MAX_INSTANCES];
    size_t count;
    char revision[65];
};

struct ttyd_buffer {
    char *data;
    size_t len;
    size_t cap;
};

static int64_t ttyd_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void ttyd_set_status(int *status, int value)
{
    if (status)
        *status = value;
}

static struct json_object *ttyd_error(const char *code, const char *message,
                                      const char *field, const char *instance_id,
                                      int status, int *http_status)
{
    struct json_object *root = json_object_new_object();
    struct json_object *error = json_object_new_object();
    struct json_object *details = json_object_new_object();

    ttyd_set_status(http_status, status);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(error, "code",
                           json_object_new_string(code ? code : "internal_error"));
    json_object_object_add(error, "message",
                           json_object_new_string(message ? message : "internal error"));
    if (field && field[0])
        json_object_object_add(details, "field", json_object_new_string(field));
    if (instance_id && instance_id[0])
        json_object_object_add(details, "instance_id",
                               json_object_new_string(instance_id));
    json_object_object_add(error, "details", details);
    json_object_object_add(root, "error", error);
    return root;
}

static int ttyd_copy(char *out, size_t out_len, const char *value)
{
    size_t len;

    if (!out || !out_len || !value || (len = strlen(value)) >= out_len)
        return -1;
    memcpy(out, value, len + 1);
    return 0;
}

static int ttyd_text_safe(const char *value, size_t max_len, int required)
{
    size_t i, len;

    if (!value || !(len = strlen(value)))
        return !required;
    if (len > max_len)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static int ttyd_id_ok(const char *id)
{
    size_t i, len;

    if (!id || !(len = strlen(id)) || len > TTYD_MAX_ID ||
        !(isalnum((unsigned char)id[0]) || id[0] == '_'))
        return 0;
    for (i = 1; i < len; i++)
        if (!(isalnum((unsigned char)id[i]) || id[i] == '_' ||
              id[i] == '-' || id[i] == '.'))
            return 0;
    return 1;
}

static int ttyd_bool_text(const char *value, int fallback)
{
    if (!value || !value[0])
        return fallback;
    if (!strcasecmp(value, "1") || !strcasecmp(value, "true") ||
        !strcasecmp(value, "yes") || !strcasecmp(value, "on"))
        return 1;
    if (!strcasecmp(value, "0") || !strcasecmp(value, "false") ||
        !strcasecmp(value, "no") || !strcasecmp(value, "off"))
        return 0;
    return fallback;
}

static int ttyd_decimal(const char *text, uint64_t max, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;
    const unsigned char *p;

    if (!text || !text[0])
        return -1;
    for (p = (const unsigned char *)text; *p; p++)
        if (!isdigit(*p))
            return -1;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno || !end || *end || value > max)
        return -1;
    *out = value;
    return 0;
}

static const char *ttyd_uci_string(struct uci_context *ctx,
                                   struct uci_section *section,
                                   const char *name, const char *fallback)
{
    const char *value = uci_lookup_option_string(ctx, section, name);

    return value ? value : fallback;
}

static int ttyd_instance_id_used(const struct ttyd_config *config,
                                 const char *id)
{
    size_t i;

    for (i = 0; config && i < config->count; i++)
        if (!strcmp(config->instances[i].id, id))
            return 1;
    return 0;
}

static int ttyd_section_id(const struct ttyd_config *config,
                           const struct uci_section *section,
                           char *out, size_t out_len)
{
    unsigned int suffix;

    if (!section->anonymous)
        return ttyd_id_ok(section->e.name) ?
            ttyd_copy(out, out_len, section->e.name) : -1;
    if (!ttyd_instance_id_used(config, "ttyd"))
        return ttyd_copy(out, out_len, "ttyd");
    for (suffix = 2; suffix <= TTYD_MAX_INSTANCES + 1; suffix++) {
        snprintf(out, out_len, "ttyd-%u", suffix);
        if (!ttyd_instance_id_used(config, out))
            return 0;
    }
    return -1;
}

static int ttyd_file_read(const char *path, struct ttyd_snapshot *snapshot)
{
    struct stat st;
    int fd;
    size_t used = 0;

    memset(snapshot, 0, sizeof(*snapshot));
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > TTYD_MAX_CONFIG)
        return -1;
    snapshot->data = malloc((size_t)st.st_size + 1);
    if (!snapshot->data)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        goto failed;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, snapshot->data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            close(fd);
            goto failed;
        }
        used += (size_t)got;
    }
    close(fd);
    snapshot->data[used] = '\0';
    snapshot->len = used;
    snapshot->mode = st.st_mode & 0777;
    snapshot->existed = 1;
    return 0;
failed:
    free(snapshot->data);
    memset(snapshot, 0, sizeof(*snapshot));
    return -1;
}

static void ttyd_snapshot_free(struct ttyd_snapshot *snapshot)
{
    if (snapshot) {
        free(snapshot->data);
        memset(snapshot, 0, sizeof(*snapshot));
    }
}

static int ttyd_hash_bytes(const void *data, size_t len, char out[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    size_t i;

    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data ? data : "", len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    for (i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    return 0;
}

static int ttyd_revision_read(char out[65])
{
    struct ttyd_snapshot snapshot;
    int rc;

    if (ttyd_file_read(SYSTEM_TTYD_CONFIG_PATH, &snapshot) != 0)
        return -1;
    rc = ttyd_hash_bytes(snapshot.data, snapshot.len, out);
    ttyd_snapshot_free(&snapshot);
    return rc;
}

static void ttyd_path_parts(char *directory, size_t directory_len,
                            char *package, size_t package_len)
{
    const char *slash = strrchr(SYSTEM_TTYD_CONFIG_PATH, '/');

    if (!slash) {
        ttyd_copy(directory, directory_len, ".");
        ttyd_copy(package, package_len, SYSTEM_TTYD_CONFIG_PATH);
        return;
    }
    snprintf(directory, directory_len, "%.*s", (int)(slash - SYSTEM_TTYD_CONFIG_PATH),
             SYSTEM_TTYD_CONFIG_PATH);
    ttyd_copy(package, package_len, slash + 1);
}

static int ttyd_config_read(struct ttyd_config *config)
{
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    struct uci_element *element;
    char directory[PATH_MAX], package_name[64];
    char revision_after[65];
    int rc = -1;

    memset(config, 0, sizeof(*config));
    if (ttyd_revision_read(config->revision) != 0)
        return -1;
    ttyd_path_parts(directory, sizeof(directory), package_name, sizeof(package_name));
    ctx = uci_alloc_context();
    if (!ctx || uci_set_confdir(ctx, directory) != UCI_OK)
        goto out;
    if (uci_load(ctx, package_name, &package) != UCI_OK) {
        if (access(SYSTEM_TTYD_CONFIG_PATH, F_OK) != 0 && errno == ENOENT) {
            rc = 0;
            goto out;
        }
        goto out;
    }
    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        struct ttyd_instance *instance;
        struct uci_option *option;
        const char *value;
        uint64_t number;

        if (strcmp(section->type, "ttyd"))
            continue;
        if (config->count >= TTYD_MAX_INSTANCES)
            goto out;
        instance = &config->instances[config->count++];
        memset(instance, 0, sizeof(*instance));
        if (ttyd_section_id(config, section, instance->id,
                            sizeof(instance->id)) != 0)
            goto out;
        instance->enable = ttyd_bool_text(
            ttyd_uci_string(ctx, section, "enable", "1"), 1);
        instance->unix_sock = ttyd_bool_text(
            ttyd_uci_string(ctx, section, "unix_sock", "0"), 0);
        value = ttyd_uci_string(ctx, section, "port", "7681");
        instance->port = ttyd_decimal(value, 65535, &number) == 0 ? (int)number : -1;
        if (ttyd_copy(instance->interface, sizeof(instance->interface),
                      ttyd_uci_string(ctx, section, "interface", "")) != 0 ||
            ttyd_copy(instance->credential, sizeof(instance->credential),
                      ttyd_uci_string(ctx, section, "credential", "")) != 0 ||
            ttyd_copy(instance->uid, sizeof(instance->uid),
                      ttyd_uci_string(ctx, section, "uid", "")) != 0 ||
            ttyd_copy(instance->gid, sizeof(instance->gid),
                      ttyd_uci_string(ctx, section, "gid", "")) != 0)
            goto out;
        instance->credential_configured = instance->credential[0] != '\0';
        value = ttyd_uci_string(ctx, section, "signal", "1");
        instance->signal = ttyd_decimal(value, INT_MAX, &number) == 0 ? (int)number : -1;
        instance->url_arg = ttyd_bool_text(ttyd_uci_string(ctx, section, "url_arg", "0"), 0);
        instance->readonly = ttyd_bool_text(ttyd_uci_string(ctx, section, "readonly", "0"), 0);
        instance->check_origin = ttyd_bool_text(ttyd_uci_string(ctx, section, "check_origin", "0"), 0);
        value = ttyd_uci_string(ctx, section, "max_clients", "0");
        instance->max_clients = ttyd_decimal(value, INT_MAX, &number) == 0 ? (int)number : -1;
        instance->once = ttyd_bool_text(ttyd_uci_string(ctx, section, "once", "0"), 0);
        instance->ipv6 = ttyd_bool_text(ttyd_uci_string(ctx, section, "ipv6", "0"), 0);
        instance->ssl = ttyd_bool_text(ttyd_uci_string(ctx, section, "ssl", "0"), 0);
        value = ttyd_uci_string(ctx, section, "debug", "7");
        instance->debug = ttyd_decimal(value, INT_MAX, &number) == 0 ? (int)number : -1;
        if (ttyd_copy(instance->terminal_type, sizeof(instance->terminal_type),
                      ttyd_uci_string(ctx, section, "terminal_type", "xterm-256color")) != 0 ||
            ttyd_copy(instance->index, sizeof(instance->index),
                      ttyd_uci_string(ctx, section, "index", "")) != 0 ||
            ttyd_copy(instance->ssl_cert, sizeof(instance->ssl_cert),
                      ttyd_uci_string(ctx, section, "ssl_cert", "")) != 0 ||
            ttyd_copy(instance->ssl_key, sizeof(instance->ssl_key),
                      ttyd_uci_string(ctx, section, "ssl_key", "")) != 0 ||
            ttyd_copy(instance->ssl_ca, sizeof(instance->ssl_ca),
                      ttyd_uci_string(ctx, section, "ssl_ca", "")) != 0 ||
            ttyd_copy(instance->command, sizeof(instance->command),
                      ttyd_uci_string(ctx, section, "command", "")) != 0 ||
            ttyd_copy(instance->url_override, sizeof(instance->url_override),
                      ttyd_uci_string(ctx, section, "url_override", "")) != 0)
            goto out;
        option = uci_lookup_option(ctx, section, "client_option");
        if (option) {
            if (option->type == UCI_TYPE_LIST) {
                struct uci_element *item;
                uci_foreach_element(&option->v.list, item) {
                    if (instance->client_option_count >= TTYD_MAX_CLIENT_OPTIONS ||
                        ttyd_copy(instance->client_option[instance->client_option_count],
                                  sizeof(instance->client_option[0]), item->name) != 0)
                        goto out;
                    instance->client_option_count++;
                }
            } else if (option->type == UCI_TYPE_STRING && option->v.string) {
                if (ttyd_copy(instance->client_option[0],
                              sizeof(instance->client_option[0]), option->v.string) != 0)
                    goto out;
                instance->client_option_count = 1;
            }
        }
        if (!instance->unix_sock && instance->interface[0] == '/')
            instance->unix_sock = 1;
    }
    if (ttyd_revision_read(revision_after) != 0 ||
        strcmp(config->revision, revision_after))
        goto out;
    rc = 0;
out:
    if (package)
        uci_unload(ctx, package);
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

static int ttyd_buffer_reserve(struct ttyd_buffer *buffer, size_t extra)
{
    size_t need, cap;
    char *next;

    if (extra > SIZE_MAX - buffer->len - 1)
        return -1;
    need = buffer->len + extra + 1;
    if (need <= buffer->cap)
        return 0;
    cap = buffer->cap ? buffer->cap : 1024;
    while (cap < need) {
        if (cap > SIZE_MAX / 2)
            return -1;
        cap *= 2;
    }
    next = realloc(buffer->data, cap);
    if (!next)
        return -1;
    buffer->data = next;
    buffer->cap = cap;
    return 0;
}

static int ttyd_buffer_append_n(struct ttyd_buffer *buffer,
                                const char *text, size_t len)
{
    if (ttyd_buffer_reserve(buffer, len) != 0)
        return -1;
    memcpy(buffer->data + buffer->len, text, len);
    buffer->len += len;
    buffer->data[buffer->len] = '\0';
    return 0;
}

static int ttyd_buffer_append(struct ttyd_buffer *buffer, const char *text)
{
    return ttyd_buffer_append_n(buffer, text, strlen(text));
}

static int ttyd_buffer_printf(struct ttyd_buffer *buffer, const char *format, ...)
{
    va_list args, copy;
    int needed;

    va_start(args, format);
    va_copy(copy, args);
    needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0 || ttyd_buffer_reserve(buffer, (size_t)needed) != 0) {
        va_end(args);
        return -1;
    }
    vsnprintf(buffer->data + buffer->len, buffer->cap - buffer->len, format, args);
    va_end(args);
    buffer->len += (size_t)needed;
    return 0;
}

static int ttyd_buffer_uci_value(struct ttyd_buffer *buffer, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");

    if (ttyd_buffer_append(buffer, "'") != 0)
        return -1;
    for (; *p; p++) {
        if (*p == '\'') {
            if (ttyd_buffer_append(buffer, "'\\''") != 0)
                return -1;
        } else if (*p < 0x20 || *p == 0x7f ||
                   ttyd_buffer_append_n(buffer, (const char *)p, 1) != 0) {
            return -1;
        }
    }
    return ttyd_buffer_append(buffer, "'");
}

static int ttyd_render_option(struct ttyd_buffer *buffer, const char *name,
                              const char *value)
{
    return ttyd_buffer_printf(buffer, "\toption %s ", name) == 0 &&
           ttyd_buffer_uci_value(buffer, value) == 0 &&
           ttyd_buffer_append(buffer, "\n") == 0 ? 0 : -1;
}

static int ttyd_render_bool(struct ttyd_buffer *buffer, const char *name, int value)
{
    return ttyd_render_option(buffer, name, value ? "1" : "0");
}

static int ttyd_config_render(const struct ttyd_config *config,
                              struct ttyd_buffer *buffer)
{
    size_t i, j;
    char number[32];

    memset(buffer, 0, sizeof(*buffer));
    for (i = 0; i < config->count; i++) {
        const struct ttyd_instance *instance = &config->instances[i];
        if (ttyd_buffer_append(buffer, "config ttyd ") != 0 ||
            ttyd_buffer_uci_value(buffer, instance->id) != 0 ||
            ttyd_buffer_append(buffer, "\n") != 0 ||
            ttyd_render_bool(buffer, "enable", instance->enable) != 0 ||
            ttyd_render_bool(buffer, "unix_sock", instance->unix_sock) != 0)
            goto failed;
        snprintf(number, sizeof(number), "%d", instance->port);
        if (ttyd_render_option(buffer, "port", number) != 0 ||
            ttyd_render_option(buffer, "interface", instance->interface) != 0)
            goto failed;
        if (instance->credential_configured &&
            ttyd_render_option(buffer, "credential", instance->credential) != 0)
            goto failed;
        if (instance->uid[0] && ttyd_render_option(buffer, "uid", instance->uid) != 0)
            goto failed;
        if (instance->gid[0] && ttyd_render_option(buffer, "gid", instance->gid) != 0)
            goto failed;
        snprintf(number, sizeof(number), "%d", instance->signal);
        if (ttyd_render_option(buffer, "signal", number) != 0 ||
            ttyd_render_bool(buffer, "url_arg", instance->url_arg) != 0 ||
            ttyd_render_bool(buffer, "readonly", instance->readonly) != 0)
            goto failed;
        for (j = 0; j < instance->client_option_count; j++)
            if (ttyd_buffer_append(buffer, "\tlist client_option ") != 0 ||
                ttyd_buffer_uci_value(buffer, instance->client_option[j]) != 0 ||
                ttyd_buffer_append(buffer, "\n") != 0)
                goto failed;
        if (ttyd_render_option(buffer, "terminal_type", instance->terminal_type) != 0 ||
            ttyd_render_bool(buffer, "check_origin", instance->check_origin) != 0)
            goto failed;
        snprintf(number, sizeof(number), "%d", instance->max_clients);
        if (ttyd_render_option(buffer, "max_clients", number) != 0 ||
            ttyd_render_bool(buffer, "once", instance->once) != 0)
            goto failed;
        if (instance->index[0] && ttyd_render_option(buffer, "index", instance->index) != 0)
            goto failed;
        if (ttyd_render_bool(buffer, "ipv6", instance->ipv6) != 0 ||
            ttyd_render_bool(buffer, "ssl", instance->ssl) != 0)
            goto failed;
        if (instance->ssl_cert[0] &&
            ttyd_render_option(buffer, "ssl_cert", instance->ssl_cert) != 0)
            goto failed;
        if (instance->ssl_key[0] &&
            ttyd_render_option(buffer, "ssl_key", instance->ssl_key) != 0)
            goto failed;
        if (instance->ssl_ca[0] &&
            ttyd_render_option(buffer, "ssl_ca", instance->ssl_ca) != 0)
            goto failed;
        snprintf(number, sizeof(number), "%d", instance->debug);
        if (ttyd_render_option(buffer, "debug", number) != 0 ||
            ttyd_render_option(buffer, "command", instance->command) != 0)
            goto failed;
        if (instance->url_override[0] &&
            ttyd_render_option(buffer, "url_override", instance->url_override) != 0)
            goto failed;
        if (ttyd_buffer_append(buffer, "\n") != 0)
            goto failed;
    }
    if (!buffer->data && ttyd_buffer_append(buffer, "") != 0)
        goto failed;
    return 0;
failed:
    free(buffer->data);
    memset(buffer, 0, sizeof(*buffer));
    return -1;
}

static int ttyd_uci_canonicalize(const struct ttyd_buffer *rendered,
                                 struct ttyd_buffer *canonical)
{
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    FILE *input = NULL, *output = NULL;
    char *data = NULL;
    size_t len = 0;
    int rc = -1;

    memset(canonical, 0, sizeof(*canonical));
    if (!rendered->len) {
        canonical->data = calloc(1, 1);
        if (!canonical->data)
            return -1;
        canonical->cap = 1;
        return 0;
    }
    input = fmemopen(rendered->data, rendered->len, "r");
    ctx = uci_alloc_context();
    if (!input || !ctx ||
        uci_import(ctx, input, "ttyd", &package, true) != UCI_OK || !package)
        goto out;
    output = open_memstream(&data, &len);
    if (!output || uci_export(ctx, output, package, false) != UCI_OK ||
        fflush(output) != 0 || fclose(output) != 0) {
        output = NULL;
        goto out;
    }
    output = NULL;
    canonical->data = data;
    canonical->len = len;
    canonical->cap = len + 1;
    data = NULL;
    rc = 0;
out:
    if (output)
        fclose(output);
    if (input)
        fclose(input);
    if (package)
        uci_unload(ctx, package);
    if (ctx)
        uci_free_context(ctx);
    free(data);
    return rc;
}

static void ttyd_buffer_free(struct ttyd_buffer *buffer)
{
    if (buffer) {
        free(buffer->data);
        memset(buffer, 0, sizeof(*buffer));
    }
}

static int ttyd_json_bool(struct json_object *object, const char *key,
                          int fallback, int *out, int *present)
{
    struct json_object *value = NULL;

    *present = object && json_object_object_get_ex(object, key, &value);
    if (!*present) {
        *out = fallback;
        return 0;
    }
    if (!value || !json_object_is_type(value, json_type_boolean))
        return -1;
    *out = json_object_get_boolean(value);
    return 0;
}

static int ttyd_json_string(struct json_object *object, const char *key,
                            const char *fallback, char *out, size_t out_len,
                            int *present)
{
    struct json_object *value = NULL;
    const char *text;

    *present = object && json_object_object_get_ex(object, key, &value);
    if (!*present)
        text = fallback ? fallback : "";
    else if (!value || !json_object_is_type(value, json_type_string))
        return -1;
    else
        text = json_object_get_string(value);
    return text && ttyd_copy(out, out_len, text) == 0 ? 0 : -1;
}

static int ttyd_json_integer(struct json_object *object, const char *key,
                             int fallback, int64_t min, int64_t max,
                             int *out, int *present)
{
    struct json_object *value = NULL;
    int64_t number;
    uint64_t parsed;

    *present = object && json_object_object_get_ex(object, key, &value);
    if (!*present) {
        *out = fallback;
        return 0;
    }
    if (!value)
        return -1;
    if (json_object_is_type(value, json_type_int)) {
        number = json_object_get_int64(value);
    } else if (json_object_is_type(value, json_type_string) &&
               ttyd_decimal(json_object_get_string(value), INT64_MAX, &parsed) == 0) {
        number = (int64_t)parsed;
    } else {
        return -1;
    }
    if (number < min || number > max)
        return -1;
    *out = (int)number;
    return 0;
}

static int ttyd_json_uint_string(struct json_object *object, const char *key,
                                 char *out, size_t out_len, int *present)
{
    struct json_object *value = NULL;
    const char *text;
    uint64_t number;

    *present = object && json_object_object_get_ex(object, key, &value);
    if (!*present) {
        out[0] = '\0';
        return 0;
    }
    if (!value)
        return -1;
    if (json_object_is_type(value, json_type_int)) {
        int64_t signed_value = json_object_get_int64(value);
        if (signed_value < 0 || (uint64_t)signed_value > UINT32_MAX)
            return -1;
        snprintf(out, out_len, "%lld", (long long)signed_value);
        return 0;
    }
    if (!json_object_is_type(value, json_type_string))
        return -1;
    text = json_object_get_string(value);
    if (!text || !text[0]) {
        out[0] = '\0';
        return 0;
    }
    if (ttyd_decimal(text, UINT32_MAX, &number) != 0)
        return -1;
    snprintf(out, out_len, "%llu", (unsigned long long)number);
    return 0;
}

static struct json_object *ttyd_payload(struct json_object *request)
{
    struct json_object *data = NULL;

    if (request && json_object_is_type(request, json_type_object) &&
        json_object_object_get_ex(request, "data", &data) && data &&
        json_object_is_type(data, json_type_object))
        return data;
    return request;
}

static int ttyd_port_available(int port, const struct ttyd_instance *old);
static int ttyd_listen_matches(const struct ttyd_instance *instance);

static const struct ttyd_instance *ttyd_find_instance(
    const struct ttyd_config *config, const char *id)
{
    size_t i;

    for (i = 0; config && i < config->count; i++)
        if (!strcmp(config->instances[i].id, id))
            return &config->instances[i];
    return NULL;
}

static int ttyd_path_has_dotdot(const char *path)
{
    const char *p = path;

    while (p && *p) {
        while (*p == '/')
            p++;
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
            return 1;
        p = strchr(p, '/');
    }
    return 0;
}

static int ttyd_path_prefix(const char *path, const char *prefix)
{
    size_t len = strlen(prefix);

    return !strncmp(path, prefix, len) &&
           (path[len] == '\0' || path[len] == '/');
}

static int ttyd_unix_path_ok(const char *path)
{
    return path && path[0] == '/' && strlen(path) <= TTYD_MAX_INTERFACE &&
           ttyd_text_safe(path, TTYD_MAX_INTERFACE, 1) &&
           !ttyd_path_has_dotdot(path) &&
           (ttyd_path_prefix(path, "/run") ||
            ttyd_path_prefix(path, "/var/run") ||
            ttyd_path_prefix(path, "/tmp/ttyd")) &&
           strcmp(path, "/run") && strcmp(path, "/var/run") &&
           strcmp(path, "/tmp/ttyd");
}

static int ttyd_unix_endpoint_available(const char *path,
                                        const struct ttyd_instance *old)
{
    struct stat st;

    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    return old && old->enable && old->unix_sock &&
           !strcmp(old->interface, path) && S_ISSOCK(st.st_mode);
}

static int ttyd_network_section_exists(const char *name)
{
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    struct uci_element *element;
    int found = 0;

    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "network", &package) != UCI_OK)
        goto out;
    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        if (!strcmp(section->e.name, name) && !strcmp(section->type, "interface")) {
            found = 1;
            break;
        }
    }
out:
    if (package)
        uci_unload(ctx, package);
    if (ctx)
        uci_free_context(ctx);
    return found;
}

static int ttyd_interface_exists(const char *interface)
{
    struct ifaddrs *all = NULL, *entry;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    int family = 0, found = 0;

    if (!interface || !interface[0])
        return 1;
    if (interface[0] == '@')
        return ttyd_id_ok(interface + 1) &&
               ttyd_network_section_exists(interface + 1);
    if (if_nametoindex(interface) != 0)
        return 1;
    if (inet_pton(AF_INET, interface, &ipv4) == 1)
        family = AF_INET;
    else if (inet_pton(AF_INET6, interface, &ipv6) == 1)
        family = AF_INET6;
    else
        return 0;
    if ((!strcmp(interface, "0.0.0.0") || !strcmp(interface, "::")))
        return 1;
    if (getifaddrs(&all) != 0)
        return 0;
    for (entry = all; entry; entry = entry->ifa_next) {
        char address[INET6_ADDRSTRLEN];
        void *source;
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != family)
            continue;
        source = family == AF_INET ?
            (void *)&((struct sockaddr_in *)entry->ifa_addr)->sin_addr :
            (void *)&((struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr;
        if (inet_ntop(family, source, address, sizeof(address)) &&
            !strcmp(address, interface)) {
            found = 1;
            break;
        }
    }
    freeifaddrs(all);
    return found;
}

static int ttyd_regular_file(const char *path, int executable)
{
    struct stat st;

    return path && path[0] == '/' && !ttyd_path_has_dotdot(path) &&
           stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           access(path, executable ? X_OK : R_OK) == 0;
}

static int ttyd_command_ok(const char *command)
{
    char executable[TTYD_MAX_PATH + 1];
    size_t i = 0;

    if (!ttyd_text_safe(command, TTYD_MAX_COMMAND, 1) || command[0] != '/')
        return 0;
    while (command[i] && !isspace((unsigned char)command[i])) {
        if (strchr("'\"`$;&|<>*?[]{}()\\", command[i]) ||
            i >= sizeof(executable) - 1)
            return 0;
        executable[i] = command[i];
        i++;
    }
    executable[i] = '\0';
    for (; command[i]; i++)
        if (strchr("'\"`$;&|<>*?[]{}()\\", command[i]))
            return 0;
    return ttyd_regular_file(executable, 1);
}

static int ttyd_client_option_ok(const char *option)
{
    const char *equal;
    size_t i, key_len;

    if (!ttyd_text_safe(option, TTYD_MAX_OPTION, 1) ||
        !(equal = strchr(option, '=')) || equal == option || !equal[1])
        return 0;
    key_len = (size_t)(equal - option);
    if (key_len > 64)
        return 0;
    for (i = 0; i < key_len; i++)
        if (!(isalnum((unsigned char)option[i]) || option[i] == '_' ||
              option[i] == '-' || option[i] == '.'))
            return 0;
    return 1;
}

static int ttyd_url_ok(const char *url)
{
    const char *authority, *end;
    size_t i;

    if (!url || !url[0])
        return 1;
    if (!ttyd_text_safe(url, TTYD_MAX_URL, 1) ||
        (strncmp(url, "http://", 7) && strncmp(url, "https://", 8)) ||
        strchr(url, '\\') || strchr(url, '@'))
        return 0;
    authority = strstr(url, "://") + 3;
    end = strpbrk(authority, "/?#");
    if (!end)
        end = authority + strlen(authority);
    if (end == authority || memchr(authority, ' ', (size_t)(end - authority)))
        return 0;
    for (i = 0; url[i]; i++)
        if (isspace((unsigned char)url[i]))
            return 0;
    return 1;
}

static int ttyd_credential_ok(const char *credential)
{
    const char *colon;
    size_t i;

    if (!ttyd_text_safe(credential, TTYD_MAX_CREDENTIAL, 1) ||
        !(colon = strchr(credential, ':')) || colon == credential || !colon[1])
        return 0;
    for (i = 0; credential[i]; i++)
        if (isspace((unsigned char)credential[i]))
            return 0;
    return 1;
}

static int ttyd_terminal_type_ok(const char *terminal_type)
{
    size_t i;

    if (!ttyd_text_safe(terminal_type, 63, 1))
        return 0;
    for (i = 0; terminal_type[i]; i++)
        if (!(isalnum((unsigned char)terminal_type[i]) ||
              terminal_type[i] == '-' || terminal_type[i] == '_' ||
              terminal_type[i] == '.'))
            return 0;
    return 1;
}

static int ttyd_known_instance_key(const char *key)
{
    static const char *const keys[] = {
        "id", "name", "enable", "unix_sock", "port", "interface",
        "unix_sock_path", "_unix_sock_path",
        "credential", "credential_configured", "preserve_credential",
        "clear_credential", "uid", "gid", "signal", "url_arg",
        "readonly", "client_option", "terminal_type", "check_origin",
        "max_clients", "once", "index", "ipv6", "ssl", "ssl_cert",
        "ssl_key", "ssl_ca", "debug", "command", "url_override",
        "running", "listen", "terminal_url"
    };
    size_t i;

    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (!strcmp(key, keys[i]))
            return 1;
    return 0;
}

static int ttyd_known_request_key(const char *key)
{
    return !strcmp(key, "revision") || !strcmp(key, "instances") ||
           !strcmp(key, "confirm") || !strcmp(key, "reload");
}

static struct json_object *ttyd_parse_request(struct json_object *request,
                                              const struct ttyd_config *current,
                                              struct ttyd_config *desired,
                                              int require_revision,
                                              int *http_status)
{
    struct json_object *payload = ttyd_payload(request), *items = NULL;
    const char *revision = NULL;
    int present, reload, i;
    size_t j;

    memset(desired, 0, sizeof(*desired));
    if (!payload || !json_object_is_type(payload, json_type_object))
        return ttyd_error("invalid_request", "request body must be an object",
                          "body", NULL, 400, http_status);
    {
        json_object_object_foreach(payload, key, value) {
            (void)value;
            if (!ttyd_known_request_key(key))
                return ttyd_error("unknown_field", "unknown ttyd request field",
                                  key, NULL, 400, http_status);
        }
    }
    {
        struct json_object *value = NULL;
        if (json_object_object_get_ex(payload, "revision", &value)) {
            if (!value || !json_object_is_type(value, json_type_string))
                return ttyd_error("invalid_revision", "revision must be a string",
                                  "revision", NULL, 400, http_status);
            revision = json_object_get_string(value);
        }
    }
    {
        struct json_object *value = NULL;
        if (json_object_object_get_ex(payload, "confirm", &value) &&
            (!value || !json_object_is_type(value, json_type_boolean)))
            return ttyd_error("invalid_type", "confirm must be a boolean",
                              "confirm", NULL, 400, http_status);
    }
    if (require_revision && (!revision || !revision[0]))
        return ttyd_error("revision_required", "revision is required",
                          "revision", NULL, 428, http_status);
    if (revision && strcmp(revision, current->revision)) {
        struct json_object *root = ttyd_error(
            "revision_conflict", "ttyd configuration changed; reload and retry",
            "revision", NULL, 409, http_status);
        struct json_object *error = NULL, *details = NULL;
        json_object_object_get_ex(root, "error", &error);
        json_object_object_get_ex(error, "details", &details);
        json_object_object_add(details, "current_revision",
                               json_object_new_string(current->revision));
        return root;
    }
    if (ttyd_json_bool(payload, "reload", 1, &reload, &present) != 0)
        return ttyd_error("invalid_type", "reload must be a boolean",
                          "reload", NULL, 400, http_status);
    if (present && !reload)
        return ttyd_error("reload_required", "runtime readback requires reload=true",
                          "reload", NULL, 422, http_status);
    if (!json_object_object_get_ex(payload, "instances", &items) || !items ||
        !json_object_is_type(items, json_type_array))
        return ttyd_error("instances_required", "instances must be an array",
                          "instances", NULL, 400, http_status);
    if (json_object_array_length(items) > TTYD_MAX_INSTANCES)
        return ttyd_error("too_many_instances", "too many ttyd instances",
                          "instances", NULL, 422, http_status);

    for (i = 0; i < (int)json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, (size_t)i);
        struct ttyd_instance *instance = &desired->instances[desired->count];
        const struct ttyd_instance *old;
        char id[TTYD_MAX_ID + 1];
        int preserve = 0, clear = 0, credential_present = 0;

        if (!item || !json_object_is_type(item, json_type_object))
            return ttyd_error("invalid_instance", "each instance must be an object",
                              "instances", NULL, 400, http_status);
        {
            json_object_object_foreach(item, key, value) {
                (void)value;
                if (!ttyd_known_instance_key(key))
                    return ttyd_error("unknown_field", "unknown ttyd instance field",
                                      key, NULL, 400, http_status);
            }
        }
        if (ttyd_json_string(item, "id", "", id, sizeof(id), &present) != 0 ||
            !present || !ttyd_id_ok(id))
            return ttyd_error("invalid_instance_id", "invalid ttyd section id",
                              "id", id, 422, http_status);
        for (j = 0; j < desired->count; j++)
            if (!strcmp(desired->instances[j].id, id))
                return ttyd_error("duplicate_instance", "duplicate ttyd section id",
                                  "id", id, 409, http_status);
        memset(instance, 0, sizeof(*instance));
        ttyd_copy(instance->id, sizeof(instance->id), id);
        old = ttyd_find_instance(current, id);
        if (ttyd_json_bool(item, "enable", 1, &instance->enable, &present) != 0)
            return ttyd_error("invalid_type", "enable must be a boolean",
                              "enable", id, 400, http_status);
        if (ttyd_json_bool(item, "unix_sock", 0, &instance->unix_sock, &present) != 0)
            return ttyd_error("invalid_type", "unix_sock must be a boolean",
                              "unix_sock", id, 400, http_status);
        if (ttyd_json_integer(item, "port", 7681, 0, 65535,
                              &instance->port, &present) != 0)
            return ttyd_error("invalid_port", "port must be an integer from 1 to 65535",
                              "port", id, 422, http_status);
        if (!instance->unix_sock && instance->port == 0)
            return ttyd_error("random_port_unsupported",
                              "random port 0 cannot be verified after apply",
                              "port", id, 422, http_status);
        if (instance->enable && !instance->unix_sock &&
            !ttyd_port_available(instance->port, old))
            return ttyd_error("port_in_use", "listen port is already used by another service",
                              "port", id, 409, http_status);
        if (ttyd_json_string(item, "interface", "", instance->interface,
                             sizeof(instance->interface), &present) != 0)
            return ttyd_error("invalid_interface", "interface is too long or invalid",
                              "interface", id, 422, http_status);
        if (instance->unix_sock) {
            char socket_path[TTYD_MAX_INTERFACE + 1] = "";
            char legacy_socket_path[TTYD_MAX_INTERFACE + 1] = "";
            int socket_path_present = 0, legacy_socket_path_present = 0;

            if (ttyd_json_string(item, "unix_sock_path", "", socket_path,
                                 sizeof(socket_path), &socket_path_present) != 0 ||
                ttyd_json_string(item, "_unix_sock_path", "", legacy_socket_path,
                                 sizeof(legacy_socket_path), &legacy_socket_path_present) != 0)
                return ttyd_error("invalid_unix_socket", "UNIX socket path is invalid or too long",
                                  "unix_sock_path", id, 422, http_status);
            if (socket_path_present && legacy_socket_path_present &&
                socket_path[0] && legacy_socket_path[0] &&
                strcmp(socket_path, legacy_socket_path))
                return ttyd_error("ambiguous_unix_socket", "UNIX socket path aliases disagree",
                                  "unix_sock_path", id, 422, http_status);
            if (socket_path[0])
                ttyd_copy(instance->interface, sizeof(instance->interface), socket_path);
            else if (legacy_socket_path[0])
                ttyd_copy(instance->interface, sizeof(instance->interface), legacy_socket_path);
            if (!ttyd_unix_path_ok(instance->interface))
                return ttyd_error("invalid_unix_socket", "UNIX socket path is outside allowed runtime directories",
                                  "interface", id, 422, http_status);
            if (instance->enable &&
                !ttyd_unix_endpoint_available(instance->interface, old))
                return ttyd_error("unix_socket_in_use",
                                  "UNIX socket path already exists",
                                  "interface", id, 409, http_status);
        } else if (!ttyd_interface_exists(instance->interface)) {
            return ttyd_error("interface_not_found", "interface does not exist",
                              "interface", id, 422, http_status);
        }
        if (ttyd_json_string(item, "credential", "", instance->credential,
                             sizeof(instance->credential), &credential_present) != 0 ||
            ttyd_json_bool(item, "preserve_credential", 0, &preserve, &present) != 0 ||
            ttyd_json_bool(item, "clear_credential", 0, &clear, &present) != 0)
            return ttyd_error("invalid_credential_operation", "invalid credential operation",
                              "credential", id, 400, http_status);
        if ((preserve && clear) || (credential_present && instance->credential[0] && (preserve || clear)))
            return ttyd_error("ambiguous_credential_operation", "credential operation is ambiguous",
                              "credential", id, 422, http_status);
        if (credential_present && instance->credential[0]) {
            if (!ttyd_credential_ok(instance->credential))
                return ttyd_error("invalid_credential", "credential must use username:password format",
                                  "credential", id, 422, http_status);
            instance->credential_configured = 1;
        } else if (preserve) {
            if (!old || !old->credential_configured)
                return ttyd_error("credential_not_available", "there is no credential to preserve",
                                  "preserve_credential", id, 422, http_status);
            ttyd_copy(instance->credential, sizeof(instance->credential), old->credential);
            instance->credential_configured = 1;
        } else if (old && old->credential_configured && !clear) {
            return ttyd_error("credential_action_required",
                              "set preserve_credential=true or clear_credential=true",
                              "credential", id, 422, http_status);
        } else if (credential_present && !instance->credential[0] && !clear) {
            return ttyd_error("ambiguous_empty_credential",
                              "empty credential does not clear a stored credential",
                              "credential", id, 422, http_status);
        }
        if (ttyd_json_uint_string(item, "uid", instance->uid,
                                  sizeof(instance->uid), &present) != 0 ||
            ttyd_json_uint_string(item, "gid", instance->gid,
                                  sizeof(instance->gid), &present) != 0)
            return ttyd_error("invalid_identity", "uid and gid must be unsigned 32-bit integers",
                              "uid", id, 422, http_status);
        if (ttyd_json_integer(item, "signal", 1, 1, 64,
                              &instance->signal, &present) != 0)
            return ttyd_error("invalid_signal", "signal must be from 1 to 64",
                              "signal", id, 422, http_status);
        if (ttyd_json_bool(item, "url_arg", 0, &instance->url_arg, &present) != 0 ||
            ttyd_json_bool(item, "readonly", 0, &instance->readonly, &present) != 0 ||
            ttyd_json_bool(item, "check_origin", 0, &instance->check_origin, &present) != 0 ||
            ttyd_json_bool(item, "once", 0, &instance->once, &present) != 0 ||
            ttyd_json_bool(item, "ipv6", 0, &instance->ipv6, &present) != 0 ||
            ttyd_json_bool(item, "ssl", 0, &instance->ssl, &present) != 0)
            return ttyd_error("invalid_type", "ttyd flag fields must be booleans",
                              "instances", id, 400, http_status);
        if (ttyd_json_integer(item, "max_clients", 0, 0, 4096,
                              &instance->max_clients, &present) != 0)
            return ttyd_error("invalid_max_clients", "max_clients must be from 0 to 4096",
                              "max_clients", id, 422, http_status);
        if (ttyd_json_integer(item, "debug", 7, 1, 15,
                              &instance->debug, &present) != 0 ||
            (instance->debug != 1 && instance->debug != 3 &&
             instance->debug != 7 && instance->debug != 15))
            return ttyd_error("invalid_debug", "debug must be one of 1, 3, 7, 15",
                              "debug", id, 422, http_status);
        if (ttyd_json_string(item, "terminal_type", "xterm-256color",
                             instance->terminal_type, sizeof(instance->terminal_type),
                             &present) != 0 ||
            !ttyd_terminal_type_ok(instance->terminal_type))
            return ttyd_error("invalid_terminal_type", "invalid terminal type",
                              "terminal_type", id, 422, http_status);
        if (ttyd_json_string(item, "index", "", instance->index,
                             sizeof(instance->index), &present) != 0 ||
            ttyd_json_string(item, "ssl_cert", "", instance->ssl_cert,
                             sizeof(instance->ssl_cert), &present) != 0 ||
            ttyd_json_string(item, "ssl_key", "", instance->ssl_key,
                             sizeof(instance->ssl_key), &present) != 0 ||
            ttyd_json_string(item, "ssl_ca", "", instance->ssl_ca,
                             sizeof(instance->ssl_ca), &present) != 0 ||
            ttyd_json_string(item, "command", "", instance->command,
                             sizeof(instance->command), &present) != 0 ||
            ttyd_json_string(item, "url_override", "", instance->url_override,
                             sizeof(instance->url_override), &present) != 0)
            return ttyd_error("invalid_string", "ttyd string field is invalid or too long",
                              "instances", id, 422, http_status);
        if (!ttyd_command_ok(instance->command))
            return ttyd_error("invalid_command", "command executable does not exist or contains unsafe syntax",
                              "command", id, 422, http_status);
        if (instance->index[0] && !ttyd_regular_file(instance->index, 0))
            return ttyd_error("invalid_index", "custom index must be a readable regular file",
                              "index", id, 422, http_status);
        if ((instance->ssl_cert[0] &&
             !ttyd_regular_file(instance->ssl_cert, 0)) ||
            (instance->ssl_key[0] &&
             !ttyd_regular_file(instance->ssl_key, 0)) ||
            (instance->ssl &&
             (!instance->ssl_cert[0] || !instance->ssl_key[0])))
            return ttyd_error("invalid_tls_files", "SSL certificate and key must be readable regular files",
                              "ssl", id, 422, http_status);
        if (instance->ssl_ca[0] && !ttyd_regular_file(instance->ssl_ca, 0))
            return ttyd_error("invalid_ssl_ca", "SSL CA must be a readable regular file",
                              "ssl_ca", id, 422, http_status);
        if (!ttyd_url_ok(instance->url_override))
            return ttyd_error("invalid_url_override", "URL override must be a safe HTTP(S) URL",
                              "url_override", id, 422, http_status);
        {
            struct json_object *options = NULL;
            if (json_object_object_get_ex(item, "client_option", &options)) {
                if (!options || !json_object_is_type(options, json_type_array) ||
                    json_object_array_length(options) > TTYD_MAX_CLIENT_OPTIONS)
                    return ttyd_error("invalid_client_option", "client_option must be a bounded array",
                                      "client_option", id, 422, http_status);
                for (j = 0; j < json_object_array_length(options); j++) {
                    struct json_object *option = json_object_array_get_idx(options, j);
                    const char *text;
                    size_t k;
                    if (!option || !json_object_is_type(option, json_type_string) ||
                        !(text = json_object_get_string(option)) ||
                        !ttyd_client_option_ok(text) ||
                        ttyd_copy(instance->client_option[instance->client_option_count],
                                  sizeof(instance->client_option[0]), text) != 0)
                        return ttyd_error("invalid_client_option", "client_option must use key=value format",
                                          "client_option", id, 422, http_status);
                    for (k = 0; k < instance->client_option_count; k++)
                        if (!strcmp(instance->client_option[k], text))
                            return ttyd_error("duplicate_client_option", "duplicate client option",
                                              "client_option", id, 409, http_status);
                    instance->client_option_count++;
                }
            }
        }
        for (j = 0; j < desired->count; j++) {
            const struct ttyd_instance *other = &desired->instances[j];
            if (!instance->enable || !other->enable)
                continue;
            if (instance->unix_sock && other->unix_sock &&
                !strcmp(instance->interface, other->interface))
                return ttyd_error("endpoint_conflict", "duplicate UNIX socket path",
                                  "interface", id, 409, http_status);
            if (!instance->unix_sock && !other->unix_sock &&
                instance->port == other->port)
                return ttyd_error("port_conflict", "duplicate ttyd listen port",
                                  "port", id, 409, http_status);
        }
        desired->count++;
    }
    return NULL;
}

static struct json_object *ttyd_instance_json(const struct ttyd_instance *instance)
{
    struct json_object *item = json_object_new_object();
    struct json_object *options = json_object_new_array();
    size_t i;

    json_object_object_add(item, "id", json_object_new_string(instance->id));
    json_object_object_add(item, "name", json_object_new_string(instance->id));
    json_object_object_add(item, "enable", json_object_new_boolean(instance->enable));
    json_object_object_add(item, "unix_sock", json_object_new_boolean(instance->unix_sock));
    json_object_object_add(item, "port", json_object_new_int(instance->port));
    json_object_object_add(item, "interface", json_object_new_string(instance->interface));
    json_object_object_add(item, "unix_sock_path",
                           json_object_new_string(instance->unix_sock ? instance->interface : ""));
    json_object_object_add(item, "credential_configured",
                           json_object_new_boolean(instance->credential_configured));
    json_object_object_add(item, "uid", json_object_new_string(instance->uid));
    json_object_object_add(item, "gid", json_object_new_string(instance->gid));
    json_object_object_add(item, "signal", json_object_new_int(instance->signal));
    json_object_object_add(item, "url_arg", json_object_new_boolean(instance->url_arg));
    json_object_object_add(item, "readonly", json_object_new_boolean(instance->readonly));
    for (i = 0; i < instance->client_option_count; i++)
        json_object_array_add(options, json_object_new_string(instance->client_option[i]));
    json_object_object_add(item, "client_option", options);
    json_object_object_add(item, "terminal_type", json_object_new_string(instance->terminal_type));
    json_object_object_add(item, "check_origin", json_object_new_boolean(instance->check_origin));
    json_object_object_add(item, "max_clients", json_object_new_int(instance->max_clients));
    json_object_object_add(item, "once", json_object_new_boolean(instance->once));
    json_object_object_add(item, "index", json_object_new_string(instance->index));
    json_object_object_add(item, "ipv6", json_object_new_boolean(instance->ipv6));
    json_object_object_add(item, "ssl", json_object_new_boolean(instance->ssl));
    json_object_object_add(item, "ssl_cert", json_object_new_string(instance->ssl_cert));
    json_object_object_add(item, "ssl_key", json_object_new_string(instance->ssl_key));
    json_object_object_add(item, "ssl_ca", json_object_new_string(instance->ssl_ca));
    json_object_object_add(item, "debug", json_object_new_int(instance->debug));
    json_object_object_add(item, "command", json_object_new_string(instance->command));
    json_object_object_add(item, "url_override", json_object_new_string(instance->url_override));
    json_object_object_add(item, "running", json_object_new_boolean(instance->running));
    json_object_object_add(item, "listen", json_object_new_string(instance->listen));
    return item;
}

static int ttyd_wait_child(pid_t pid, int pipe_fd, int timeout_ms,
                           char *output, size_t output_len,
                           struct ttyd_exec_result *result)
{
    int status = 0, done = 0;
    int64_t deadline = ttyd_monotonic_ms() + timeout_ms;
    size_t used = 0;

    memset(result, 0, sizeof(*result));
    result->exit_code = 128;
    while (!done) {
        struct pollfd pfd = { .fd = pipe_fd, .events = POLLIN | POLLHUP };
        int64_t now = ttyd_monotonic_ms();
        ssize_t got;
        if (now < 0 || now >= deadline) {
            result->timed_out = 1;
            kill(pid, SIGTERM);
            usleep(200000);
            if (waitpid(pid, &status, WNOHANG) == 0)
                kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        (void)poll(&pfd, 1, 50);
        while ((got = read(pipe_fd,
                           output && used + 1 < output_len ? output + used :
                           (char [512]){0},
                           output && used + 1 < output_len ?
                           output_len - used - 1 : 512)) > 0) {
            if (output && used + 1 < output_len)
                used += (size_t)got;
            else
                result->output_truncated = 1;
        }
        if (waitpid(pid, &status, WNOHANG) == pid)
            done = 1;
    }
    while (!result->timed_out) {
        char discard[512];
        char *destination = output && used + 1 < output_len ? output + used : discard;
        size_t room = destination == discard ? sizeof(discard) : output_len - used - 1;
        ssize_t got = read(pipe_fd, destination, room);
        if (got <= 0)
            break;
        if (destination == discard)
            result->output_truncated = 1;
        else
            used += (size_t)got;
    }
    if (output && output_len)
        output[used] = '\0';
    if (result->timed_out) {
        result->exit_code = 124;
        return -1;
    }
    if (WIFEXITED(status))
        result->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        result->exit_code = 128 + WTERMSIG(status);
    return result->exit_code == 0 ? 0 : -1;
}

static int ttyd_exec(char *const argv[], int timeout_ms, char *output,
                     size_t output_len, struct ttyd_exec_result *result)
{
    int pipes[2], flags, rc;
    pid_t pid;

    if (!argv || !argv[0] || argv[0][0] != '/' || pipe(pipes) != 0)
        return -1;
    if (fcntl(pipes[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pipes[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(pipes[0]);
        close(pipes[1]);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(pipes[0]);
        close(pipes[1]);
        return -1;
    }
    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (nullfd >= 0) {
            dup2(nullfd, STDIN_FILENO);
            close(nullfd);
        }
        dup2(pipes[1], STDOUT_FILENO);
        dup2(pipes[1], STDERR_FILENO);
        close(pipes[0]);
        close(pipes[1]);
        clearenv();
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        setenv("LANG", "C", 1);
        setenv("LC_ALL", "C", 1);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipes[1]);
    flags = fcntl(pipes[0], F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(pipes[0], F_SETFL, flags | O_NONBLOCK);
    rc = ttyd_wait_child(pid, pipes[0], timeout_ms, output, output_len, result);
    close(pipes[0]);
    return rc;
}

static int ttyd_capture(char *const argv[], char **output,
                        struct ttyd_exec_result *result)
{
    *output = calloc(1, TTYD_COMMAND_OUTPUT);
    if (!*output)
        return -1;
    return ttyd_exec(argv, TTYD_EXEC_TIMEOUT_MS, *output,
                     TTYD_COMMAND_OUTPUT, result);
}

static int ttyd_port_available(int port, const struct ttyd_instance *old)
{
    char *output = NULL, *line, *save = NULL;
    char suffix[24];
    char *argv[] = { (char *)SYSTEM_TTYD_SS_PATH, (char *)"-H",
                     (char *)"-lntp", NULL };
    struct ttyd_exec_result result;
    int available = 1;

    if (access(SYSTEM_TTYD_SS_PATH, X_OK) != 0)
        return 0;
    if (ttyd_capture(argv, &output, &result) != 0)
        return 0;
    snprintf(suffix, sizeof(suffix), ":%d", port);
    for (line = strtok_r(output, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char copy[2048], *token, *token_save = NULL;
        int column = 0;
        snprintf(copy, sizeof(copy), "%s", line);
        for (token = strtok_r(copy, " \t", &token_save); token;
             token = strtok_r(NULL, " \t", &token_save), column++) {
            size_t token_len = strlen(token), suffix_len = strlen(suffix);
            if (column == 3 && token_len >= suffix_len &&
                !strcmp(token + token_len - suffix_len, suffix)) {
                if (!strstr(line, "\"ttyd\"") || !old || !old->enable ||
                    old->unix_sock || old->port != port) {
                    available = 0;
                    goto out;
                }
            }
        }
    }
out:
    free(output);
    return available;
}

struct ttyd_runtime_entry {
    char name[64];
    int running;
    int pid;
};

static int ttyd_runtime_entries(struct ttyd_runtime_entry *entries,
                                size_t *count)
{
    char *output = NULL;
    char *argv[] = { (char *)SYSTEM_TTYD_UBUS_PATH, (char *)"call",
                     (char *)"service", (char *)"list",
                     (char *)"{\"name\":\"ttyd\"}", NULL };
    struct ttyd_exec_result result;
    struct json_object *root = NULL, *service = NULL, *instances = NULL;

    *count = 0;
    if (access(SYSTEM_TTYD_UBUS_PATH, X_OK) != 0 ||
        ttyd_capture(argv, &output, &result) != 0)
        goto failed;
    root = json_tokener_parse(output);
    if (!root || !json_object_object_get_ex(root, "ttyd", &service) ||
        !service || !json_object_object_get_ex(service, "instances", &instances) ||
        !instances || !json_object_is_type(instances, json_type_object)) {
        if (root && json_object_object_length(root) == 0) {
            json_object_put(root);
            free(output);
            return 0;
        }
        goto failed;
    }
    json_object_object_foreach(instances, name, value) {
        struct json_object *running = NULL, *pid = NULL;
        if (*count >= TTYD_MAX_INSTANCES)
            goto failed;
        memset(&entries[*count], 0, sizeof(entries[*count]));
        ttyd_copy(entries[*count].name, sizeof(entries[*count].name), name);
        if (value && json_object_is_type(value, json_type_object)) {
            if (json_object_object_get_ex(value, "running", &running))
                entries[*count].running = json_object_get_boolean(running);
            if (json_object_object_get_ex(value, "pid", &pid) &&
                json_object_is_type(pid, json_type_int))
                entries[*count].pid = json_object_get_int(pid);
        }
        (*count)++;
    }
    json_object_put(root);
    free(output);
    return 0;
failed:
    if (root)
        json_object_put(root);
    free(output);
    return -1;
}

static int ttyd_endpoint_for_pid(int pid, int unix_sock,
                                 char *out, size_t out_len)
{
    char pid_marker[48], *output = NULL, *line, *save = NULL;
    char *tcp_argv[] = { (char *)SYSTEM_TTYD_SS_PATH, (char *)"-H",
                         (char *)"-lntp", NULL };
    char *unix_argv[] = { (char *)SYSTEM_TTYD_SS_PATH, (char *)"-H",
                          (char *)"-lxnp", NULL };
    struct ttyd_exec_result result;
    int rc = -1;

    out[0] = '\0';
    if (pid <= 0 || access(SYSTEM_TTYD_SS_PATH, X_OK) != 0)
        return -1;
    snprintf(pid_marker, sizeof(pid_marker), "pid=%d,", pid);
    if (ttyd_capture(unix_sock ? unix_argv : tcp_argv, &output, &result) != 0)
        goto out;
    for (line = strtok_r(output, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char copy[2048], *token, *token_save = NULL;
        int column = 0;
        if (!strstr(line, pid_marker))
            continue;
        snprintf(copy, sizeof(copy), "%s", line);
        for (token = strtok_r(copy, " \t", &token_save); token;
             token = strtok_r(NULL, " \t", &token_save), column++) {
            if ((!unix_sock && column == 3) ||
                (unix_sock && token[0] == '/')) {
                rc = ttyd_copy(out, out_len, token);
                goto out;
            }
        }
    }
out:
    free(output);
    return rc;
}

static int ttyd_runtime_read(struct ttyd_config *config)
{
    struct ttyd_runtime_entry entries[TTYD_MAX_INSTANCES];
    int used[TTYD_MAX_INSTANCES] = {0};
    size_t count = 0, i, j;

    if (ttyd_runtime_entries(entries, &count) != 0)
        return -1;
    for (i = 0; i < config->count; i++) {
        struct ttyd_instance *instance = &config->instances[i];
        instance->running = 0;
        instance->pid = 0;
        instance->listen[0] = '\0';
        if (!instance->enable)
            continue;
        for (j = 0; j < count; j++) {
            char endpoint[TTYD_MAX_PATH + 1];
            struct ttyd_instance candidate = *instance;

            if (used[j] || !entries[j].running ||
                ttyd_endpoint_for_pid(entries[j].pid, instance->unix_sock,
                                      endpoint, sizeof(endpoint)) != 0)
                continue;
            candidate.running = 1;
            ttyd_copy(candidate.listen, sizeof(candidate.listen), endpoint);
            if (!ttyd_listen_matches(&candidate))
                continue;
            instance->running = 1;
            instance->pid = entries[j].pid;
            ttyd_copy(instance->listen, sizeof(instance->listen), endpoint);
            used[j] = 1;
            break;
        }
    }
    return 0;
}

static int ttyd_listen_matches(const struct ttyd_instance *instance)
{
    char suffix[24];
    size_t listen_len, suffix_len;

    if (!instance->enable)
        return !instance->running;
    if (!instance->running || !instance->listen[0])
        return 0;
    if (instance->unix_sock)
        return !strcmp(instance->listen, instance->interface);
    snprintf(suffix, sizeof(suffix), ":%d", instance->port);
    listen_len = strlen(instance->listen);
    suffix_len = strlen(suffix);
    return listen_len >= suffix_len &&
           !strcmp(instance->listen + listen_len - suffix_len, suffix);
}

static int ttyd_runtime_verified(struct ttyd_config *config)
{
    struct ttyd_runtime_entry entries[TTYD_MAX_INSTANCES];
    size_t i, runtime_count = 0, running_count = 0, enabled_count = 0;

    if (ttyd_runtime_read(config) != 0)
        return 0;
    if (ttyd_runtime_entries(entries, &runtime_count) != 0)
        return 0;
    for (i = 0; i < runtime_count; i++)
        if (entries[i].running)
            running_count++;
    for (i = 0; i < config->count; i++) {
        if (config->instances[i].enable)
            enabled_count++;
        if (!ttyd_listen_matches(&config->instances[i]))
            return 0;
    }
    return running_count == enabled_count;
}

static int ttyd_service_action(const char *action,
                               struct ttyd_exec_result *result)
{
    char output[8192];
    char *argv[] = { (char *)SYSTEM_TTYD_INIT_PATH, (char *)action, NULL };

    if (access(SYSTEM_TTYD_INIT_PATH, X_OK) != 0)
        return -1;
    return ttyd_exec(argv, TTYD_EXEC_TIMEOUT_MS, output, sizeof(output), result);
}

static int ttyd_service_apply(struct ttyd_config *config,
                              const char **action,
                              struct ttyd_exec_result *result)
{
    int i;

    *action = "reload";
    if (ttyd_service_action("reload", result) == 0) {
        for (i = 0; i < TTYD_RUNTIME_RETRIES; i++) {
            if (ttyd_runtime_verified(config))
                return 0;
            usleep(100000);
        }
    }
    *action = "restart";
    if (ttyd_service_action("restart", result) != 0)
        return -1;
    for (i = 0; i < TTYD_RUNTIME_RETRIES; i++) {
        if (ttyd_runtime_verified(config))
            return 0;
        usleep(100000);
    }
    return -1;
}

static int ttyd_write_all(int fd, const void *data, size_t len)
{
    const unsigned char *cursor = data;

    while (len) {
        ssize_t written = write(fd, cursor, len);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        cursor += written;
        len -= (size_t)written;
    }
    return 0;
}

static int ttyd_parent_fsync(const char *path)
{
    char parent[PATH_MAX], *slash;
    int fd, rc;

    if (!path || strlen(path) >= sizeof(parent))
        return -1;
    snprintf(parent, sizeof(parent), "%s", path);
    slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    if (slash == parent)
        parent[1] = '\0';
    else
        *slash = '\0';
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    rc = fsync(fd);
    close(fd);
    return rc;
}

static int ttyd_atomic_write(const char *path, const void *data, size_t len,
                             mode_t mode)
{
    char temporary[PATH_MAX];
    int fd = -1, rc = -1;

    if (!path || !data || strlen(path) + 48 >= sizeof(temporary))
        return -1;
    snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%lld", path,
             (long)getpid(), (long long)time(NULL));
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
              mode);
    if (fd < 0)
        return -1;
    if (ttyd_write_all(fd, data, len) != 0 || fsync(fd) != 0 || close(fd) != 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (rename(temporary, path) != 0 || ttyd_parent_fsync(path) != 0)
        goto out;
    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(temporary);
    return rc;
}

static int ttyd_snapshot_restore(const struct ttyd_snapshot *snapshot)
{
    if (snapshot->existed)
        return ttyd_atomic_write(SYSTEM_TTYD_CONFIG_PATH, snapshot->data,
                                 snapshot->len,
                                 snapshot->mode ? snapshot->mode : 0600);
    if (unlink(SYSTEM_TTYD_CONFIG_PATH) != 0 && errno != ENOENT)
        return -1;
    return ttyd_parent_fsync(SYSTEM_TTYD_CONFIG_PATH);
}

static int ttyd_mkdir(const char *path, mode_t mode)
{
    char copy[PATH_MAX], *cursor;

    if (!path || path[0] != '/' || strlen(path) >= sizeof(copy))
        return -1;
    snprintf(copy, sizeof(copy), "%s", path);
    for (cursor = copy + 1; *cursor; cursor++) {
        if (*cursor != '/')
            continue;
        *cursor = '\0';
        if (mkdir(copy, mode) != 0 && errno != EEXIST)
            return -1;
        *cursor = '/';
    }
    return mkdir(copy, mode) == 0 || errno == EEXIST ? 0 : -1;
}

static int ttyd_backup_write(const struct ttyd_snapshot *snapshot,
                             char *path, size_t path_len)
{
    struct timespec now;

    if (ttyd_mkdir(SYSTEM_TTYD_BACKUP_DIR, 0700) != 0)
        return -1;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        return -1;
    snprintf(path, path_len, "%s/ttyd.%lld.%09ld.%ld.bak",
             SYSTEM_TTYD_BACKUP_DIR, (long long)now.tv_sec, now.tv_nsec,
             (long)getpid());
    return ttyd_atomic_write(path, snapshot->data ? snapshot->data : "",
                             snapshot->len, 0600);
}

static int ttyd_name_compare(const void *left, const void *right)
{
    const char *const *a = left, *const *b = right;
    return strcmp(*a, *b);
}

static void ttyd_backups_prune(void)
{
    DIR *directory = opendir(SYSTEM_TTYD_BACKUP_DIR);
    struct dirent *entry;
    char **names = NULL;
    size_t count = 0, capacity = 0, i;

    if (!directory)
        return;
    while ((entry = readdir(directory)) != NULL) {
        char **next;
        if (strncmp(entry->d_name, "ttyd.", 5) ||
            !strstr(entry->d_name, ".bak"))
            continue;
        if (count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 64;
            next = realloc(names, next_capacity * sizeof(*names));
            if (!next)
                break;
            names = next;
            capacity = next_capacity;
        }
        names[count] = strdup(entry->d_name);
        if (!names[count])
            break;
        count++;
    }
    closedir(directory);
    if (count > TTYD_BACKUPS_RETAIN) {
        qsort(names, count, sizeof(*names), ttyd_name_compare);
        for (i = 0; i < count - TTYD_BACKUPS_RETAIN; i++) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", SYSTEM_TTYD_BACKUP_DIR,
                     names[i]);
            (void)unlink(path);
        }
    }
    for (i = 0; i < count; i++)
        free(names[i]);
    free(names);
}

static void ttyd_add_runtime_result(struct json_object *root,
                                    struct ttyd_config *config)
{
    struct json_object *instances = json_object_new_array();
    size_t i;

    (void)ttyd_runtime_read(config);
    json_object_object_add(root, "revision",
                           json_object_new_string(config->revision));
    json_object_object_add(root, "terminal_url", json_object_new_string("/terminal/"));
    for (i = 0; i < config->count; i++)
        json_object_array_add(instances,
                              ttyd_instance_json(&config->instances[i]));
    json_object_object_add(root, "instances", instances);
}

static struct json_object *ttyd_config_json(struct ttyd_config *config,
                                            int include_capabilities)
{
    struct json_object *root = json_object_new_object();
    struct json_object *instances = json_object_new_array();
    size_t i;

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "revision", json_object_new_string(config->revision));
    json_object_object_add(root, "terminal_url", json_object_new_string("/terminal/"));
    json_object_object_add(root, "proxy_available", json_object_new_boolean(1));
    for (i = 0; i < config->count; i++)
        json_object_array_add(instances, ttyd_instance_json(&config->instances[i]));
    json_object_object_add(root, "instances", instances);
    if (include_capabilities) {
        struct json_object *capabilities = json_object_new_object();
        json_object_object_add(capabilities, "system_ttyd_read",
                               json_object_new_boolean(1));
        json_object_object_add(capabilities, "system_ttyd_write",
                               json_object_new_boolean(1));
        json_object_object_add(capabilities, "system_ttyd_multi_instance",
                               json_object_new_boolean(1));
        json_object_object_add(capabilities, "system_ttyd_proxy",
                               json_object_new_boolean(1));
        json_object_object_add(root, "capabilities", capabilities);
    }
    return root;
}

static int ttyd_configs_changed(const struct ttyd_config *desired,
                                const struct ttyd_config *current,
                                struct ttyd_buffer *canonical)
{
    struct ttyd_buffer rendered = {0}, current_rendered = {0};
    struct ttyd_buffer current_canonical = {0};
    int changed = -1;

    if (ttyd_config_render(desired, &rendered) != 0 ||
        ttyd_uci_canonicalize(&rendered, canonical) != 0 ||
        ttyd_config_render(current, &current_rendered) != 0 ||
        ttyd_uci_canonicalize(&current_rendered, &current_canonical) != 0)
        goto out;
    changed = current_canonical.len != canonical->len ||
              memcmp(current_canonical.data, canonical->data, canonical->len);
out:
    ttyd_buffer_free(&rendered);
    ttyd_buffer_free(&current_rendered);
    ttyd_buffer_free(&current_canonical);
    return changed;
}

struct json_object *system_ttyd_get(int *http_status)
{
    struct ttyd_config config;

    if (ttyd_config_read(&config) != 0)
        return ttyd_error("ttyd_config_read_failed",
                          "failed to read /etc/config/ttyd through libuci",
                          NULL, NULL, 500, http_status);
    if (ttyd_runtime_read(&config) != 0)
        return ttyd_error("ttyd_runtime_read_failed",
                          "failed to read ttyd procd and listen state",
                          NULL, NULL, 503, http_status);
    ttyd_set_status(http_status, 200);
    return ttyd_config_json(&config, 1);
}

struct json_object *system_ttyd_validate(struct json_object *request,
                                         int *http_status)
{
    struct ttyd_config current, desired;
    struct ttyd_buffer canonical = {0};
    struct json_object *error, *root, *plan;
    int changed;

    if (ttyd_config_read(&current) != 0)
        return ttyd_error("ttyd_config_read_failed", "failed to read ttyd UCI configuration",
                          NULL, NULL, 500, http_status);
    error = ttyd_parse_request(request, &current, &desired, 0, http_status);
    if (error)
        return error;
    changed = ttyd_configs_changed(&desired, &current, &canonical);
    ttyd_buffer_free(&canonical);
    if (changed < 0)
        return ttyd_error("ttyd_config_render_failed", "failed to render valid UCI configuration",
                          NULL, NULL, 500, http_status);
    root = json_object_new_object();
    plan = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "valid", json_object_new_boolean(1));
    json_object_object_add(root, "changed", json_object_new_boolean(changed));
    json_object_object_add(root, "revision", json_object_new_string(current.revision));
    json_object_object_add(root, "confirm_required", json_object_new_boolean(changed));
    json_object_object_add(plan, "authority", json_object_new_string("uci:/etc/config/ttyd"));
    json_object_object_add(plan, "lock", json_object_new_string(SYSTEM_TTYD_LOCK_PATH));
    json_object_object_add(plan, "backup", json_object_new_boolean(changed));
    json_object_object_add(plan, "service_action",
                           json_object_new_string(changed ? "reload_or_restart" : "none"));
    json_object_object_add(plan, "runtime_readback", json_object_new_boolean(changed));
    json_object_object_add(root, "plan", plan);
    ttyd_set_status(http_status, 200);
    return root;
}

struct json_object *system_ttyd_apply(struct json_object *request,
                                      int *http_status)
{
    struct ttyd_config current, desired, readback;
    struct ttyd_buffer canonical = {0};
    struct ttyd_snapshot snapshot = {0};
    struct ttyd_exec_result apply_result = {0}, rollback_result = {0};
    struct json_object *payload = ttyd_payload(request), *confirm = NULL;
    struct json_object *error = NULL, *root = NULL;
    const char *action = "none", *rollback_action = "none";
    char backup_path[PATH_MAX] = "";
    int lock_fd = -1, changed, rollback_ok = 1;

    if (ttyd_config_read(&current) != 0)
        return ttyd_error("ttyd_config_read_failed", "failed to read ttyd UCI configuration",
                          NULL, NULL, 500, http_status);
    error = ttyd_parse_request(request, &current, &desired, 1, http_status);
    if (error)
        return error;
    changed = ttyd_configs_changed(&desired, &current, &canonical);
    if (changed < 0) {
        ttyd_buffer_free(&canonical);
        return ttyd_error("ttyd_config_render_failed", "failed to render valid UCI configuration",
                          NULL, NULL, 500, http_status);
    }
    if (!payload || !json_object_object_get_ex(payload, "confirm", &confirm) ||
        !confirm || !json_object_is_type(confirm, json_type_boolean) ||
        !json_object_get_boolean(confirm)) {
        ttyd_buffer_free(&canonical);
        return ttyd_error("confirm_required", "confirm=true is required to change ttyd",
                          "confirm", NULL, 428, http_status);
    }
    lock_fd = open(SYSTEM_TTYD_LOCK_PATH,
                   O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0)
            close(lock_fd);
        ttyd_buffer_free(&canonical);
        return ttyd_error("ttyd_lock_failed", "failed to acquire ttyd configuration lock",
                          NULL, NULL, 503, http_status);
    }
    /* Recheck under the lock so validation cannot race another writer. */
    if (ttyd_config_read(&current) != 0) {
        error = ttyd_error("ttyd_config_read_failed", "failed to re-read ttyd configuration",
                           NULL, NULL, 500, http_status);
        goto out;
    }
    {
        struct json_object *revision_object = NULL;
        const char *expected = NULL;
        if (payload && json_object_object_get_ex(payload, "revision", &revision_object) &&
            revision_object && json_object_is_type(revision_object, json_type_string))
            expected = json_object_get_string(revision_object);
        if (!expected || strcmp(expected, current.revision)) {
            error = ttyd_error("revision_conflict", "ttyd configuration changed while waiting for lock",
                               "revision", NULL, 409, http_status);
            goto out;
        }
    }
    ttyd_buffer_free(&canonical);
    error = ttyd_parse_request(request, &current, &desired, 1, http_status);
    if (error)
        goto out;
    changed = ttyd_configs_changed(&desired, &current, &canonical);
    if (changed < 0) {
        error = ttyd_error("ttyd_config_render_failed",
                           "failed to render valid UCI configuration under lock",
                           NULL, NULL, 500, http_status);
        goto out;
    }
    if (!changed) {
        readback = current;
        if (ttyd_service_apply(&readback, &action, &apply_result) != 0) {
            error = ttyd_error(
                "ttyd_runtime_apply_failed",
                "ttyd reload/restart or runtime readback failed; configuration was unchanged",
                NULL, NULL, 502, http_status);
            json_object_object_add(error, "changed", json_object_new_boolean(0));
            json_object_object_add(error, "reload_ok", json_object_new_boolean(0));
            json_object_object_add(error, "rollback_ok", json_object_new_boolean(1));
            json_object_object_add(error, "service_action",
                                   json_object_new_string(action));
            json_object_object_add(error, "service_exit_code",
                                   json_object_new_int(apply_result.exit_code));
            json_object_object_add(error, "service_timed_out",
                                   json_object_new_boolean(apply_result.timed_out));
            ttyd_add_runtime_result(error, &readback);
            goto out;
        }
        root = ttyd_config_json(&readback, 0);
        json_object_object_add(root, "changed", json_object_new_boolean(0));
        json_object_object_add(root, "reload_ok", json_object_new_boolean(1));
        json_object_object_add(root, "rollback_ok", json_object_new_boolean(1));
        json_object_object_add(root, "service_action", json_object_new_string(action));
        ttyd_set_status(http_status, 200);
        goto out;
    }
    if (ttyd_file_read(SYSTEM_TTYD_CONFIG_PATH, &snapshot) != 0) {
        error = ttyd_error("ttyd_backup_read_failed", "failed to snapshot ttyd configuration",
                           NULL, NULL, 500, http_status);
        goto out;
    }
    if (ttyd_backup_write(&snapshot, backup_path, sizeof(backup_path)) != 0) {
        error = ttyd_error("ttyd_backup_failed", "failed to create ttyd configuration backup",
                           NULL, NULL, 500, http_status);
        goto out;
    }
    if (ttyd_atomic_write(SYSTEM_TTYD_CONFIG_PATH, canonical.data, canonical.len,
                          0600) != 0) {
        action = "config_write_failed";
        goto rollback;
    }
    if (ttyd_config_read(&readback) != 0) {
        action = "readback_failed";
        goto rollback;
    }
    if (access(SYSTEM_TTYD_BINARY_PATH, X_OK) != 0 ||
        ttyd_service_apply(&readback, &action, &apply_result) != 0)
        goto rollback;
    root = ttyd_config_json(&readback, 0);
    json_object_object_add(root, "changed", json_object_new_boolean(1));
    json_object_object_add(root, "reload_ok", json_object_new_boolean(1));
    json_object_object_add(root, "rollback_ok", json_object_new_boolean(1));
    json_object_object_add(root, "service_action", json_object_new_string(action));
    json_object_object_add(root, "backup_path", json_object_new_string(backup_path));
    ttyd_backups_prune();
    ttyd_set_status(http_status, 200);
    goto out;

rollback:
    rollback_ok = ttyd_snapshot_restore(&snapshot) == 0;
    if (rollback_ok && ttyd_config_read(&readback) == 0)
        rollback_ok = ttyd_service_apply(&readback, &rollback_action,
                                         &rollback_result) == 0;
    else
        rollback_ok = 0;
    error = ttyd_error("ttyd_runtime_apply_failed",
                       "ttyd reload/restart or runtime readback failed; previous configuration restored",
                       NULL, NULL, rollback_ok ? 502 : 500, http_status);
    json_object_object_add(error, "changed", json_object_new_boolean(0));
    json_object_object_add(error, "reload_ok", json_object_new_boolean(0));
    json_object_object_add(error, "rollback_ok", json_object_new_boolean(rollback_ok));
    json_object_object_add(error, "service_action", json_object_new_string(action));
    json_object_object_add(error, "rollback_action", json_object_new_string(rollback_action));
    json_object_object_add(error, "backup_path", json_object_new_string(backup_path));
    json_object_object_add(error, "service_exit_code",
                           json_object_new_int(apply_result.exit_code));
    json_object_object_add(error, "service_timed_out",
                           json_object_new_boolean(apply_result.timed_out));
    if (ttyd_config_read(&readback) == 0)
        ttyd_add_runtime_result(error, &readback);

out:
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    ttyd_snapshot_free(&snapshot);
    ttyd_buffer_free(&canonical);
    if (error)
        return error;
    return root;
}
