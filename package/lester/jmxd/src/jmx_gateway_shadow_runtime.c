// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_gateway_shadow_runtime.c - fail-closed VRRP/conntrackd runtime helpers
 */
#include "jmx_gateway_shadow_runtime.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define GS_KEEPALIVED_NAME "keepalived.conf"
#define GS_CONNTRACKD_NAME "conntrackd.conf"
#define GS_LOCK_NAME ".gateway-shadow-runtime.lock"
#define GS_CONFIG_BUFFER_SIZE 8192
#define GS_KEEPALIVED_PID "/var/run/dreamingwrt-gateway-shadow-keepalived.pid"
#define GS_KEEPALIVED_VRRP_PID \
    "/var/run/dreamingwrt-gateway-shadow-keepalived-vrrp.pid"

struct gs_staged_file {
    const char *final_name;
    char temporary_name[96];
    char backup_name[96];
    int had_original;
    int committed;
};

static void gs_result_reset(struct jmx_gateway_shadow_runtime_result *result)
{
    if (!result) return;
    memset(result, 0, sizeof(*result));
    result->child_exit_status = -1;
}

static int gs_fail(struct jmx_gateway_shadow_runtime_result *result, int code,
                   int system_errno, const char *format, ...)
{
    va_list arguments;

    if (result) {
        result->code = code;
        result->system_errno = system_errno;
        if (format) {
            va_start(arguments, format);
            vsnprintf(result->message, sizeof(result->message), format, arguments);
            va_end(arguments);
        }
    }
    return code;
}

static int gs_success(struct jmx_gateway_shadow_runtime_result *result,
                      const char *message)
{
    if (result) {
        result->code = JMX_GS_RUNTIME_OK;
        result->system_errno = 0;
        result->child_exit_status = 0;
        snprintf(result->message, sizeof(result->message), "%s",
                 message ? message : "ok");
    }
    return JMX_GS_RUNTIME_OK;
}

static int gs_safe_interface(const char *name)
{
    size_t index, length;

    if (!name || !(length = strlen(name)) || length >= IFNAMSIZ) return 0;
    if (name[0] == '.' || name[length - 1] == '.') return 0;
    for (index = 0; index < length; index++) {
        unsigned char character = (unsigned char)name[index];
        if (!isalnum(character) && character != '_' && character != '-' &&
            character != '.') return 0;
    }
    return 1;
}

static int gs_ipv4_parse(const char *text, struct in_addr *address)
{
    return text && address && inet_pton(AF_INET, text, address) == 1;
}

static int gs_heartbeat_ipv4(const char *text, struct in_addr *address)
{
    uint32_t host;

    if (!gs_ipv4_parse(text, address)) return 0;
    host = ntohl(address->s_addr);
    /* Dedicated, non-routed IPv4 link-local range, excluding network/broadcast. */
    return (host & 0xffff0000U) == 0xa9fe0000U &&
           (host & 0x0000ffffU) != 0 && (host & 0x0000ffffU) != 0xffffU;
}

static int gs_virtual_ipv4(const char *text, struct in_addr *address,
                           unsigned int *prefix)
{
    char copy[64];
    char *slash, *end = NULL;
    unsigned long parsed_prefix;
    uint32_t host;

    if (!text || strlen(text) >= sizeof(copy)) return 0;
    snprintf(copy, sizeof(copy), "%s", text);
    slash = strrchr(copy, '/');
    if (!slash || slash == copy || !slash[1]) return 0;
    *slash++ = '\0';
    errno = 0;
    parsed_prefix = strtoul(slash, &end, 10);
    if (errno || !end || *end || parsed_prefix < 1 || parsed_prefix > 32 ||
        !gs_ipv4_parse(copy, address)) return 0;
    host = ntohl(address->s_addr);
    if (host == 0 || (host & 0xff000000U) == 0x7f000000U ||
        (host & 0xf0000000U) == 0xe0000000U || host == 0xffffffffU) return 0;
    if (prefix) *prefix = (unsigned int)parsed_prefix;
    return 1;
}

int jmx_gateway_shadow_runtime_validate(
    const struct jmx_gateway_shadow_runtime_config *config,
    struct jmx_gateway_shadow_runtime_result *result)
{
    struct in_addr local, peer, virtual_address;
    unsigned int prefix = 0;

    gs_result_reset(result);
    if (!config)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, EINVAL,
                       "configuration is required");
    if (!config->role || (strcmp(config->role, "primary") != 0 &&
                          strcmp(config->role, "secondary") != 0))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ROLE, EINVAL,
                       "role must be primary or secondary");
    if (!gs_safe_interface(config->lan_interface))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_INTERFACE, EINVAL,
                       "lan_interface is invalid");
    if (!gs_safe_interface(config->heartbeat_interface))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_INTERFACE, EINVAL,
                       "heartbeat_interface is invalid");
    if (strcmp(config->lan_interface, config->heartbeat_interface) == 0)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_INTERFACE, EINVAL,
                       "heartbeat_interface must be dedicated");
    if (!gs_heartbeat_ipv4(config->heartbeat_local_ip, &local))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_HEARTBEAT_ADDRESS, EINVAL,
                       "heartbeat_local_ip must be a usable 169.254/16 address");
    if (!gs_heartbeat_ipv4(config->heartbeat_peer_ip, &peer))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_HEARTBEAT_ADDRESS, EINVAL,
                       "heartbeat_peer_ip must be a usable 169.254/16 address");
    if (local.s_addr == peer.s_addr)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_HEARTBEAT_ADDRESS, EINVAL,
                       "local and peer heartbeat addresses must differ");
    if (!gs_virtual_ipv4(config->virtual_ipv4, &virtual_address, &prefix))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_VIRTUAL_ADDRESS, EINVAL,
                       "virtual_ipv4 must be a usable IPv4 CIDR");
    if (virtual_address.s_addr == local.s_addr || virtual_address.s_addr == peer.s_addr)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_VIRTUAL_ADDRESS, EINVAL,
                       "virtual_ipv4 must differ from heartbeat addresses");
    if (config->virtual_router_id < 1 || config->virtual_router_id > 255)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_VRRP, EINVAL,
                       "virtual_router_id must be between 1 and 255");
    if (config->priority < 1 || config->priority > 254)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_VRRP, EINVAL,
                       "priority must be between 1 and 254");
    if (config->advert_interval_seconds < 1 ||
        config->advert_interval_seconds > 60)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_VRRP, EINVAL,
                       "advert interval must be between 1 and 60 seconds");
    if (config->preempt)
        return gs_fail(result, JMX_GS_RUNTIME_PREEMPT_UNSUPPORTED, ENOTSUP,
                       "preempt is disabled in phase one; nopreempt is required");
    if (config->connection_sync != 0 && config->connection_sync != 1)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, EINVAL,
                       "connection_sync must be 0 or 1");
    return gs_success(result, "configuration is valid");
}

static int gs_render_keepalived(
    const struct jmx_gateway_shadow_runtime_config *config,
    char *buffer, size_t size)
{
    int written = snprintf(
        buffer, size,
        "# Generated by DreamingWrt Gateway Shadow. Do not edit.\n"
        "global_defs {\n"
        "    router_id DREAMINGWRT_GATEWAY_SHADOW\n"
        "}\n\n"
        "vrrp_instance DREAMINGWRT_GATEWAY_SHADOW {\n"
        "    state BACKUP\n"
        "    interface %s\n"
        "    virtual_router_id %u\n"
        "    priority %u\n"
        "    advert_int %u\n"
        "    nopreempt\n"
        "    unicast_src_ip %s\n"
        "    unicast_peer {\n"
        "        %s\n"
        "    }\n"
        "    virtual_ipaddress {\n"
        "        %s dev %s\n"
        "    }\n"
        "}\n",
        config->heartbeat_interface, config->virtual_router_id, config->priority,
        config->advert_interval_seconds, config->heartbeat_local_ip,
        config->heartbeat_peer_ip, config->virtual_ipv4, config->lan_interface);

    return written >= 0 && (size_t)written < size ? written : -1;
}

static int gs_render_conntrackd(
    const struct jmx_gateway_shadow_runtime_config *config,
    char *buffer, size_t size)
{
    int written = snprintf(
        buffer, size,
        "# Generated by DreamingWrt Gateway Shadow. Do not edit.\n"
        "# connection_sync=%s; lifecycle control must honor this flag.\n"
        "Sync {\n"
        "    Mode FTFW {\n"
        "        DisableExternalCache Off\n"
        "        StartupResync On\n"
        "    }\n"
        "    UDP {\n"
        "        IPv4_address %s\n"
        "        IPv4_Destination_Address %s\n"
        "        Port 3780\n"
        "        Interface %s\n"
        "        SndSocketBuffer 1249280\n"
        "        RcvSocketBuffer 1249280\n"
        "        Checksum On\n"
        "    }\n"
        "    Options {\n"
        "        TCPWindowTracking On\n"
        "    }\n"
        "}\n\n"
        "General {\n"
        "    HashSize 32768\n"
        "    HashLimit 131072\n"
        "    LogFile Off\n"
        "    Syslog daemon\n"
        "    LockFile /var/run/dreamingwrt-gateway-shadow-conntrackd.lock\n"
        "    UNIX {\n"
        "        Path /var/run/dreamingwrt-gateway-shadow-conntrackd.ctl\n"
        "        Backlog 20\n"
        "    }\n"
        "    NetlinkBufferSize 2097152\n"
        "    NetlinkBufferSizeMaxGrowth 8388608\n"
        "}\n",
        config->connection_sync ? "enabled" : "disabled",
        config->heartbeat_local_ip, config->heartbeat_peer_ip,
        config->heartbeat_interface);

    return written >= 0 && (size_t)written < size ? written : -1;
}

static int gs_write_all(int descriptor, const char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = write(descriptor, data + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int gs_stage_file(int directory_fd, struct gs_staged_file *file,
                         const char *contents, size_t length,
                         struct jmx_gateway_shadow_runtime_result *result)
{
    unsigned int attempt;
    int descriptor = -1;

    for (attempt = 0; attempt < 64; attempt++) {
        snprintf(file->temporary_name, sizeof(file->temporary_name),
                 ".%s.tmp.%ld.%p.%u", file->final_name, (long)getpid(),
                 (void *)file, attempt);
        descriptor = openat(directory_fd, file->temporary_name,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                            0600);
        if (descriptor >= 0 || errno != EEXIST) break;
    }
    if (descriptor < 0)
        return gs_fail(result, JMX_GS_RUNTIME_WRITE_ERROR, errno,
                       "cannot stage %s: %s", file->final_name, strerror(errno));
    if (fchmod(descriptor, 0600) != 0 ||
        gs_write_all(descriptor, contents, length) != 0 || fsync(descriptor) != 0) {
        int saved_errno = errno ? errno : EIO;
        close(descriptor);
        unlinkat(directory_fd, file->temporary_name, 0);
        file->temporary_name[0] = '\0';
        return gs_fail(result, JMX_GS_RUNTIME_WRITE_ERROR, saved_errno,
                       "cannot write %s: %s", file->final_name,
                       strerror(saved_errno));
    }
    if (close(descriptor) != 0) {
        int saved_errno = errno;
        unlinkat(directory_fd, file->temporary_name, 0);
        file->temporary_name[0] = '\0';
        return gs_fail(result, JMX_GS_RUNTIME_WRITE_ERROR, saved_errno,
                       "cannot close staged %s: %s", file->final_name,
                       strerror(saved_errno));
    }
    return 0;
}

static void gs_cleanup_stage(int directory_fd, struct gs_staged_file *files,
                             size_t count)
{
    size_t index;
    for (index = 0; index < count; index++) {
        if (files[index].temporary_name[0])
            unlinkat(directory_fd, files[index].temporary_name, 0);
    }
}

static void gs_restore_transaction(int directory_fd,
                                   struct gs_staged_file *files, size_t count)
{
    size_t index;

    for (index = 0; index < count; index++) {
        if (files[index].committed)
            unlinkat(directory_fd, files[index].final_name, 0);
    }
    for (index = 0; index < count; index++) {
        if (files[index].had_original)
            renameat(directory_fd, files[index].backup_name,
                     directory_fd, files[index].final_name);
    }
    fsync(directory_fd);
}

static int gs_commit_transaction(int directory_fd,
                                 struct gs_staged_file *files, size_t count,
                                 struct jmx_gateway_shadow_runtime_result *result)
{
    size_t index;
    struct stat status;

    for (index = 0; index < count; index++) {
        snprintf(files[index].backup_name, sizeof(files[index].backup_name),
                 ".%s.rollback.%ld", files[index].final_name, (long)getpid());
        unlinkat(directory_fd, files[index].backup_name, 0);
        if (fstatat(directory_fd, files[index].final_name, &status,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            if (!S_ISREG(status.st_mode)) {
                gs_restore_transaction(directory_fd, files, index);
                return gs_fail(result, JMX_GS_RUNTIME_COMMIT_ERROR, EINVAL,
                               "existing %s is not a regular file",
                               files[index].final_name);
            }
            if (renameat(directory_fd, files[index].final_name, directory_fd,
                         files[index].backup_name) != 0) {
                int saved_errno = errno;
                gs_restore_transaction(directory_fd, files, index);
                return gs_fail(result, JMX_GS_RUNTIME_COMMIT_ERROR, saved_errno,
                               "cannot stage rollback for %s: %s",
                               files[index].final_name, strerror(saved_errno));
            }
            files[index].had_original = 1;
        } else if (errno != ENOENT) {
            int saved_errno = errno;
            gs_restore_transaction(directory_fd, files, index);
            return gs_fail(result, JMX_GS_RUNTIME_COMMIT_ERROR, saved_errno,
                           "cannot inspect %s: %s", files[index].final_name,
                           strerror(saved_errno));
        }
    }
    if (fsync(directory_fd) != 0) {
        int saved_errno = errno;
        gs_restore_transaction(directory_fd, files, count);
        return gs_fail(result, JMX_GS_RUNTIME_COMMIT_ERROR, saved_errno,
                       "cannot fsync rollback stage: %s",
                       strerror(saved_errno));
    }

    for (index = 0; index < count; index++) {
        if (renameat(directory_fd, files[index].temporary_name, directory_fd,
                     files[index].final_name) != 0) {
            int saved_errno = errno;
            gs_restore_transaction(directory_fd, files, count);
            return gs_fail(result, JMX_GS_RUNTIME_COMMIT_ERROR, saved_errno,
                           "cannot commit %s: %s", files[index].final_name,
                           strerror(saved_errno));
        }
        files[index].temporary_name[0] = '\0';
        files[index].committed = 1;
    }
    if (fsync(directory_fd) != 0) {
        int saved_errno = errno;
        gs_restore_transaction(directory_fd, files, count);
        return gs_fail(result, JMX_GS_RUNTIME_COMMIT_ERROR, saved_errno,
                       "cannot fsync configuration directory: %s",
                       strerror(saved_errno));
    }
    for (index = 0; index < count; index++) {
        if (files[index].had_original)
            unlinkat(directory_fd, files[index].backup_name, 0);
    }
    if (fsync(directory_fd) != 0)
        return gs_fail(result, JMX_GS_RUNTIME_COMMIT_ERROR, errno,
                       "configuration committed but directory cleanup fsync failed: %s",
                       strerror(errno));
    return 0;
}

static int gs_lock_directory(int directory_fd,
                             struct jmx_gateway_shadow_runtime_result *result)
{
    int lock_descriptor;
    struct stat status;

    lock_descriptor = openat(directory_fd, GS_LOCK_NAME,
                             O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_descriptor < 0)
        return gs_fail(result, JMX_GS_RUNTIME_DIRECTORY_ERROR, errno,
                       "cannot open runtime lock: %s", strerror(errno));
    if (fstat(lock_descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || (status.st_mode & 0022) != 0) {
        int saved_errno = errno ? errno : EPERM;
        close(lock_descriptor);
        return gs_fail(result, JMX_GS_RUNTIME_DIRECTORY_ERROR, saved_errno,
                       "runtime lock is not a trusted regular file");
    }
    if (fchmod(lock_descriptor, 0600) != 0 ||
        flock(lock_descriptor, LOCK_EX) != 0) {
        int saved_errno = errno;
        close(lock_descriptor);
        return gs_fail(result, JMX_GS_RUNTIME_DIRECTORY_ERROR, saved_errno,
                       "cannot lock runtime directory: %s",
                       strerror(saved_errno));
    }
    return lock_descriptor;
}

int jmx_gateway_shadow_runtime_render(
    const struct jmx_gateway_shadow_runtime_config *config,
    const char *output_directory,
    struct jmx_gateway_shadow_runtime_result *result)
{
    char keepalived[GS_CONFIG_BUFFER_SIZE];
    char conntrackd[GS_CONFIG_BUFFER_SIZE];
    int keepalived_length, conntrackd_length, directory_fd, lock_fd, rc;
    struct stat directory_status;
    struct gs_staged_file files[2] = {
        { .final_name = GS_KEEPALIVED_NAME },
        { .final_name = GS_CONNTRACKD_NAME }
    };

    gs_result_reset(result);
    rc = jmx_gateway_shadow_runtime_validate(config, result);
    if (rc != JMX_GS_RUNTIME_OK) return rc;
    if (!output_directory || !output_directory[0])
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, EINVAL,
                       "output_directory is required");
    if (strlen(output_directory) + 1 + strlen(GS_CONNTRACKD_NAME) >= PATH_MAX)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, ENAMETOOLONG,
                       "output directory path is too long");
    keepalived_length = gs_render_keepalived(config, keepalived, sizeof(keepalived));
    conntrackd_length = gs_render_conntrackd(config, conntrackd, sizeof(conntrackd));
    if (keepalived_length < 0 || conntrackd_length < 0)
        return gs_fail(result, JMX_GS_RUNTIME_WRITE_ERROR, EOVERFLOW,
                       "rendered configuration exceeds the internal limit");

    directory_fd = open(output_directory,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0)
        return gs_fail(result, JMX_GS_RUNTIME_DIRECTORY_ERROR, errno,
                       "cannot open output directory: %s", strerror(errno));
    if (fstat(directory_fd, &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode)) {
        int saved_errno = errno ? errno : ENOTDIR;
        close(directory_fd);
        return gs_fail(result, JMX_GS_RUNTIME_DIRECTORY_ERROR, saved_errno,
                       "output path is not a directory");
    }
    lock_fd = gs_lock_directory(directory_fd, result);
    if (lock_fd < 0) {
        close(directory_fd);
        return result ? result->code : JMX_GS_RUNTIME_DIRECTORY_ERROR;
    }

    rc = gs_stage_file(directory_fd, &files[0], keepalived,
                       (size_t)keepalived_length, result);
    if (rc == 0)
        rc = gs_stage_file(directory_fd, &files[1], conntrackd,
                           (size_t)conntrackd_length, result);
    if (rc == 0 && fsync(directory_fd) != 0)
        rc = gs_fail(result, JMX_GS_RUNTIME_WRITE_ERROR, errno,
                     "cannot fsync staged runtime files: %s", strerror(errno));
    if (rc == 0) rc = gs_commit_transaction(directory_fd, files, 2, result);
    if (rc != 0) gs_cleanup_stage(directory_fd, files, 2);
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    close(directory_fd);
    if (rc != 0) return rc;

    if (result) {
        snprintf(result->keepalived_path, sizeof(result->keepalived_path),
                 "%s/%s", output_directory, GS_KEEPALIVED_NAME);
        snprintf(result->conntrackd_path, sizeof(result->conntrackd_path),
                 "%s/%s", output_directory, GS_CONNTRACKD_NAME);
    }
    return gs_success(result, "runtime configuration rendered");
}

static int gs_absolute_executable(const char *path)
{
    struct stat status;
    return path && path[0] == '/' && stat(path, &status) == 0 &&
           S_ISREG(status.st_mode) && access(path, X_OK) == 0;
}

static int gs_absolute_regular_file(const char *path)
{
    struct stat status;
    return path && path[0] == '/' && lstat(path, &status) == 0 &&
           S_ISREG(status.st_mode);
}

static int gs_exec_capture(const char *path, char *const arguments[],
                           struct jmx_gateway_shadow_runtime_result *result)
{
    int descriptors[2];
    pid_t child;
    size_t stored = 0;
    int status = 0;

    if (pipe(descriptors) != 0)
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, errno,
                       "cannot create child output pipe: %s", strerror(errno));
    child = fork();
    if (child < 0) {
        int saved_errno = errno;
        close(descriptors[0]); close(descriptors[1]);
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, saved_errno,
                       "cannot fork: %s", strerror(saved_errno));
    }
    if (child == 0) {
        int null_descriptor;
        close(descriptors[0]);
        if (dup2(descriptors[1], STDOUT_FILENO) < 0 ||
            dup2(descriptors[1], STDERR_FILENO) < 0) _exit(126);
        if (descriptors[1] != STDOUT_FILENO && descriptors[1] != STDERR_FILENO)
            close(descriptors[1]);
        null_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null_descriptor >= 0) {
            dup2(null_descriptor, STDIN_FILENO);
            if (null_descriptor != STDIN_FILENO) close(null_descriptor);
        }
        execv(path, arguments);
        _exit(errno == ENOENT ? 127 : 126);
    }

    close(descriptors[1]);
    for (;;) {
        char buffer[256];
        ssize_t count = read(descriptors[0], buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        if (result && stored < sizeof(result->child_output) - 1) {
            size_t available = sizeof(result->child_output) - 1 - stored;
            size_t copy = (size_t)count < available ? (size_t)count : available;
            memcpy(result->child_output + stored, buffer, copy);
            stored += copy;
            result->child_output[stored] = '\0';
        }
    }
    close(descriptors[0]);
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, errno,
                       "cannot wait for child process: %s", strerror(errno));
    }
    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (result) result->child_exit_status = exit_status;
        if (exit_status == 0) return gs_success(result, "child command succeeded");
        return gs_fail(result, JMX_GS_RUNTIME_CHILD_FAILED, 0,
                       "child command exited with status %d", exit_status);
    }
    if (WIFSIGNALED(status)) {
        int signal_number = WTERMSIG(status);
        if (result) result->child_exit_status = 128 + signal_number;
        return gs_fail(result, JMX_GS_RUNTIME_CHILD_FAILED, 0,
                       "child command terminated by signal %d", signal_number);
    }
    return gs_fail(result, JMX_GS_RUNTIME_CHILD_FAILED, 0,
                   "child command ended in an unknown state");
}

static int gs_read_owned_pid(const char *pid_path, const char *binary_path,
                             pid_t *process_id,
                             struct jmx_gateway_shadow_runtime_result *result)
{
    char buffer[64];
    char *end = NULL;
    long parsed;
    int descriptor;
    ssize_t count;
    struct stat pid_status, binary_status, process_status;
    char process_executable[64];

    descriptor = open(pid_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, errno,
                       "cannot open Shadow pidfile %s: %s", pid_path,
                       strerror(errno));
    if (fstat(descriptor, &pid_status) != 0 || !S_ISREG(pid_status.st_mode) ||
        pid_status.st_uid != geteuid() || (pid_status.st_mode & 0022) != 0) {
        int saved_errno = errno ? errno : EPERM;
        close(descriptor);
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, saved_errno,
                       "Shadow pidfile is not a trusted regular file");
    }
    count = read(descriptor, buffer, sizeof(buffer) - 1);
    close(descriptor);
    if (count <= 0)
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, EINVAL,
                       "Shadow pidfile is empty or unreadable");
    buffer[count] = '\0';
    errno = 0;
    parsed = strtol(buffer, &end, 10);
    while (end && isspace((unsigned char)*end)) end++;
    if (errno || !end || *end || parsed <= 1 || parsed > INT_MAX)
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, EINVAL,
                       "Shadow pidfile contains an invalid process id");

    /* Never signal an unrelated process after pid reuse or pidfile tampering. */
    snprintf(process_executable, sizeof(process_executable),
             "/proc/%ld/exe", parsed);
    if (stat(binary_path, &binary_status) != 0 ||
        stat(process_executable, &process_status) != 0 ||
        binary_status.st_dev != process_status.st_dev ||
        binary_status.st_ino != process_status.st_ino)
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, ESRCH,
                       "Shadow pidfile does not identify the requested daemon");
    *process_id = (pid_t)parsed;
    return JMX_GS_RUNTIME_OK;
}

static int gs_keepalived_signal(enum jmx_gateway_shadow_daemon_action action,
                                const char *binary_path,
                                struct jmx_gateway_shadow_runtime_result *result)
{
    pid_t process_id;
    int signal_number = action == JMX_GS_DAEMON_RELOAD ? SIGHUP : SIGTERM;
    int rc = gs_read_owned_pid(GS_KEEPALIVED_PID, binary_path, &process_id, result);

    if (rc != JMX_GS_RUNTIME_OK) return rc;
    if (kill(process_id, signal_number) != 0)
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, errno,
                       "cannot signal Shadow keepalived process: %s",
                       strerror(errno));
    return gs_success(result, action == JMX_GS_DAEMON_RELOAD ?
                              "Shadow keepalived reload requested" :
                              "Shadow keepalived stop requested");
}

int jmx_gateway_shadow_runtime_config_test(
    enum jmx_gateway_shadow_daemon daemon,
    const char *binary_path,
    const char *config_path,
    struct jmx_gateway_shadow_runtime_result *result)
{
    char *arguments[5];

    gs_result_reset(result);
    if (daemon == JMX_GS_DAEMON_CONNTRACKD)
        return gs_fail(result, JMX_GS_RUNTIME_UNSUPPORTED, ENOTSUP,
                       "conntrackd has no safe non-starting config-test mode");
    if (daemon != JMX_GS_DAEMON_KEEPALIVED)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, EINVAL,
                       "unknown daemon");
    if (!gs_absolute_executable(binary_path))
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, errno ? errno : EACCES,
                       "keepalived binary must be an absolute executable file");
    if (!gs_absolute_regular_file(config_path))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, errno ? errno : EINVAL,
                       "config path must be an absolute regular file");
    arguments[0] = (char *)binary_path;
    arguments[1] = (char *)"-t";
    arguments[2] = (char *)"-f";
    arguments[3] = (char *)config_path;
    arguments[4] = NULL;
    return gs_exec_capture(binary_path, arguments, result);
}

int jmx_gateway_shadow_runtime_daemon_control(
    enum jmx_gateway_shadow_daemon daemon,
    enum jmx_gateway_shadow_daemon_action action,
    const char *binary_path,
    const char *config_path,
    struct jmx_gateway_shadow_runtime_result *result)
{
    char *arguments[10];

    gs_result_reset(result);
    if (daemon != JMX_GS_DAEMON_KEEPALIVED &&
        daemon != JMX_GS_DAEMON_CONNTRACKD)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, EINVAL,
                       "unknown daemon");
    if (action != JMX_GS_DAEMON_START && action != JMX_GS_DAEMON_RELOAD &&
        action != JMX_GS_DAEMON_STOP)
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, EINVAL,
                       "daemon action must be start, reload, or stop");
    if (!gs_absolute_executable(binary_path))
        return gs_fail(result, JMX_GS_RUNTIME_EXEC_ERROR, errno ? errno : EACCES,
                       "daemon path must be an absolute executable file");
    if (!gs_absolute_regular_file(config_path))
        return gs_fail(result, JMX_GS_RUNTIME_INVALID_ARGUMENT, errno ? errno : EINVAL,
                       "config path must be an absolute regular file");

    if (daemon == JMX_GS_DAEMON_KEEPALIVED) {
        if (action != JMX_GS_DAEMON_START)
            return gs_keepalived_signal(action, binary_path, result);
        arguments[0] = (char *)binary_path;
        arguments[1] = (char *)"-f";
        arguments[2] = (char *)config_path;
        arguments[3] = (char *)"-p";
        arguments[4] = (char *)GS_KEEPALIVED_PID;
        arguments[5] = (char *)"-r";
        arguments[6] = (char *)GS_KEEPALIVED_VRRP_PID;
        arguments[7] = NULL;
        return gs_exec_capture(binary_path, arguments, result);
    }

    if (action == JMX_GS_DAEMON_RELOAD)
        return gs_fail(result, JMX_GS_RUNTIME_UNSUPPORTED, ENOTSUP,
                       "conntrackd has no atomic reload; use a controlled stop/start");
    arguments[0] = (char *)binary_path;
    arguments[1] = action == JMX_GS_DAEMON_START ? (char *)"-d" : (char *)"-k";
    arguments[2] = (char *)"-C";
    arguments[3] = (char *)config_path;
    arguments[4] = NULL;
    return gs_exec_capture(binary_path, arguments, result);
}
