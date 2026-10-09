        } while (got < 0 && errno == EINTR);
        close(release_gate[0]);
        if (got != 1 || release != '1')
            _exit(125);
        fexecve(self_fd, worker_argv, clean_envp);
        _exit(127);
    }
    close(release_gate[0]); release_gate[0] = -1;
    close(handshake[1]); handshake[1] = -1;
    close(reset_exec.fd); reset_exec.fd = -1;
    close(reboot_exec.fd); reboot_exec.fd = -1;
    close(self_fd); self_fd = -1;
    pfd.fd = handshake[0];
    pfd.events = POLLIN | POLLHUP;
    if (poll(&pfd, 1, NC_FACTORY_RESET_HANDSHAKE_TIMEOUT_MS) <= 0)
        goto parent_fail;
    do {
        got = read(handshake[0], &detached, sizeof(detached));
    } while (got < 0 && errno == EINTR);
    close(handshake[0]); handshake[0] = -1;
    do {
        waited = waitpid(dispatcher, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (got != (ssize_t)sizeof(detached) || detached <= 0 ||
        waited != dispatcher ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto parent_fail;
    result->executor_pid = detached;
    result->release_fd = release_gate[1];
    result->lock_fd = lockfd;
    return 0;
parent_fail:
    if (handshake[0] >= 0)
        close(handshake[0]);
    if (release_gate[1] >= 0)
        close(release_gate[1]);
    if (lockfd >= 0)
        close(lockfd);
    if (dispatcher > 0) {
        (void)kill(dispatcher, SIGKILL);
        while (waitpid(dispatcher, &status, 0) < 0 && errno == EINTR) {}
    }
    return -1;
fail:
    if (reset_exec.fd >= 0) close(reset_exec.fd);
    if (reboot_exec.fd >= 0) close(reboot_exec.fd);
    if (self_fd >= 0) close(self_fd);
    if (lockfd >= 0) close(lockfd);
    if (handshake[0] >= 0) close(handshake[0]);
    if (handshake[1] >= 0) close(handshake[1]);
    if (release_gate[0] >= 0) close(release_gate[0]);
    if (release_gate[1] >= 0) close(release_gate[1]);
    return -1;
}

static int nc_factory_reset_release(struct nc_factory_reset_dispatch_result *result)
{
    char release = '1';
    ssize_t written;

    if (!result || result->release_fd < 0)
        return -1;
    do {
        written = send(result->release_fd, &release, 1, MSG_NOSIGNAL);
    } while (written < 0 && errno == EINTR);
    close(result->release_fd);
    result->release_fd = -1;
    if (result->lock_fd >= 0) {
        close(result->lock_fd);
        result->lock_fd = -1;
    }
    return written == 1 ? 0 : -1;
}

static void nc_factory_reset_cancel(struct nc_factory_reset_dispatch_result *result)
{
    if (result && result->release_fd >= 0) {
        close(result->release_fd);
        result->release_fd = -1;
    }
    if (result && result->lock_fd >= 0) {
        close(result->lock_fd);
        result->lock_fd = -1;
    }
}

struct json_object *jmx_flash_factory_reset(struct json_object *cfg) {
    struct nc_factory_reset_dispatch_result dispatch;
    struct json_object *confirm = NULL;
    struct json_object *d = json_object_new_object();
    int confirmed = 0;

    if (cfg && json_object_object_get_ex(cfg, "confirm", &confirm) &&
        json_object_is_type(confirm, json_type_boolean))
        confirmed = json_object_get_boolean(confirm);
    if (!confirmed) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("confirmation_required"));
        json_object_object_add(d, "reason", json_object_new_string("confirm_true_boolean_required"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    {
        int dispatch_rc;
        if ((dispatch_rc = nc_factory_reset_dispatch(&dispatch)) != 0) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "accepted", json_object_new_boolean(0));
        json_object_object_add(d, "dispatched", json_object_new_boolean(0));
        json_object_object_add(d, "error",
            json_object_new_string(dispatch_rc == -2 ? "factory_reset_in_progress" :
                                                      "dispatch_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
        }
    }
    if (nc_factory_reset_status_write("accepted", "dispatch", "accepted",
                                      dispatch.executor_pid) != 0) {
        nc_factory_reset_cancel(&dispatch);
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "accepted", json_object_new_boolean(0));
        json_object_object_add(d, "dispatched", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("status_publish_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    if (nc_factory_reset_release(&dispatch) != 0) {
        (void)nc_factory_reset_status_write("failed", "dispatch", "release_failed",
                                            dispatch.executor_pid);
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "accepted", json_object_new_boolean(0));
        json_object_object_add(d, "dispatched", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("release_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    LOG_ERROR("flash_factory_reset: accepted detached reset executor pid=%ld\n",
              (long)dispatch.executor_pid);
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "accepted", json_object_new_boolean(1));
    json_object_object_add(d, "dispatched", json_object_new_boolean(1));
    json_object_object_add(d, "state", json_object_new_string("dispatched"));
    json_object_object_add(d, "executor_pid", json_object_new_int((int)dispatch.executor_pid));
    json_object_object_add(d, "dispatch_delay_seconds",
                           json_object_new_int(NC_FACTORY_RESET_DISPATCH_DELAY_SECONDS));
    json_object_object_add(d, "message", json_object_new_string("factory reset dispatched; completion is not yet known"));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

#define NC_PRESERVE_CONF_PATH "/etc/sysupgrade.conf"

struct json_object *jmx_flash_preserve_config_get(struct json_object *cfg) {
    (void)cfg;
    struct json_object *d = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    FILE *fp = fopen(NC_PRESERVE_CONF_PATH, "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0] && line[0] != '#')
                json_object_array_add(arr, json_object_new_string(line));
        }
        fclose(fp);
    }
    json_object_object_add(d, "items", arr);
    json_object_object_add(d, "path", json_object_new_string(NC_PRESERVE_CONF_PATH));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_flash_preserve_config_set(struct json_object *cfg) {
    struct json_object *d = json_object_new_object();
    struct json_object *arr = NULL;
    if (!cfg || !json_object_object_get_ex(cfg, "items", &arr) || !json_object_is_type(arr, json_type_array)) {
        json_object_object_add(d, "error", json_object_new_string("missing items array"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    FILE *fp = fopen(NC_PRESERVE_CONF_PATH, "w");
    if (!fp) {
        json_object_object_add(d, "error", json_object_new_string("cannot write sysupgrade.conf"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    fprintf(fp, "# Managed by DreamingWrt\n");
    int n = json_object_array_length(arr);
    for (int i = 0; i < n; i++) {
        const char *entry = json_object_get_string(json_object_array_get_idx(arr, i));
        if (entry && entry[0] && entry[0] != '/') continue;
        if (entry && entry[0]) fprintf(fp, "%s\n", entry);
    }
    fclose(fp);
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "count", json_object_new_int(n));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

/* ═══ System Kernel Restore Defaults ═══ */
#define NC_KERNEL_RESTORE_SYSCTL_TIMEOUT_MS 3000
#define NC_KERNEL_RESTORE_SYSCTL_OUTPUT_MAX 4096
#define NC_KERNEL_RESTORE_VALUE_MAX 127

struct nc_kernel_restore_item {
    const char *key;
    const char *value;
    char old_value[NC_KERNEL_RESTORE_VALUE_MAX + 1];
    int old_captured;
    int applied;
};

struct nc_kernel_restore_uci_snapshot {
    char section[96];
    char value[64];
    int present;
};

struct nc_kernel_restore_file_snapshot {
    char *data;
    size_t len;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    int existed;
};

static int nc_kernel_restore_exec_ok(int rc,
                                     const struct jmx_exec_result *result)
{
    if (rc != 0 || !result || result->timed_out || result->truncated ||
        result->term_signal != 0 || result->exit_code != 0)
        return -1;
    return 0;
}

static int nc_kernel_restore_value_ok(const char *value)
{
    const unsigned char *p;
    size_t len;

    if (!value || !value[0])
        return 0;
    len = strlen(value);
    if (len > NC_KERNEL_RESTORE_VALUE_MAX)
        return 0;
    for (p = (const unsigned char *)value; *p; p++) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

static int nc_kernel_restore_sysctl_read(const char *key,
                                         char *value, size_t value_len)
{
    struct jmx_exec_result result;
    char *argv[] = { "/sbin/sysctl", "-n", (char *)key, NULL };
    char *start;
    char *end;
    int rc;

    if (!key || !value || value_len < 2)
        return -1;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = jmx_exec_capture("/sbin/sysctl", argv,
                          NC_KERNEL_RESTORE_SYSCTL_OUTPUT_MAX,
                          NC_KERNEL_RESTORE_SYSCTL_TIMEOUT_MS, &result);
    if (nc_kernel_restore_exec_ok(rc, &result) != 0 || !result.output)
        goto failed;
    start = result.output;
    while (*start && isspace((unsigned char)*start))
        start++;
    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
        *--end = '\0';
    if (!nc_kernel_restore_value_ok(start) || strlen(start) >= value_len)
        goto failed;
    snprintf(value, value_len, "%s", start);
    jmx_exec_result_free(&result);
    return 0;

failed:
    jmx_exec_result_free(&result);
    return -1;
}

static int nc_kernel_restore_sysctl_write(const char *key,
                                          const char *value)
{
    struct jmx_exec_result result;
    char assignment[256];
    char observed[NC_KERNEL_RESTORE_VALUE_MAX + 1];
    char *argv[] = { "/sbin/sysctl", "-w", assignment, NULL };
    int n;
    int rc;

    if (!key || !key[0] || !nc_kernel_restore_value_ok(value))
        return -1;
    n = snprintf(assignment, sizeof(assignment), "%s=%s", key, value);
    if (n < 0 || (size_t)n >= sizeof(assignment))
        return -1;
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = jmx_exec_wait("/sbin/sysctl", argv,
                       NC_KERNEL_RESTORE_SYSCTL_TIMEOUT_MS, &result);
    if (nc_kernel_restore_exec_ok(rc, &result) != 0)
        return -1;
    if (nc_kernel_restore_sysctl_read(key, observed, sizeof(observed)) != 0)
        return -1;
    return strcmp(observed, value) == 0 ? 0 : -1;
}

static int nc_kernel_restore_sysctl_rollback(struct nc_kernel_restore_item *items,
                                             int count)
{
    int i;
    int ok = 1;

    if (!items || count < 0)
        return -1;
    for (i = count - 1; i >= 0; i--) {
        if (!items[i].applied || !items[i].old_captured)
            continue;
        if (nc_kernel_restore_sysctl_write(items[i].key,
                                           items[i].old_value) != 0)
            ok = 0;
        else
            items[i].applied = 0;
    }
    return ok ? 0 : -1;
}

static struct uci_section *nc_kernel_restore_uci_system_section(
    struct uci_package *pkg, const char *name)
{
    struct uci_element *element;

    if (!pkg)
        return NULL;
    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *section = uci_to_section(element);

        if (!section || strcmp(section->type, "system"))
            continue;
        if (!name || (section->e.name && !strcmp(section->e.name, name)))
            return section;
    }
    return NULL;
}

static int nc_kernel_restore_uci_snapshot(
    struct nc_kernel_restore_uci_snapshot *snapshot)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *section;
    const char *value;
    int rc = -1;

    if (!snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "system", &pkg) != UCI_OK || !pkg)
        goto done;
    section = nc_kernel_restore_uci_system_section(pkg, NULL);
    if (!section || !section->e.name)
        goto done;
    snprintf(snapshot->section, sizeof(snapshot->section), "%s",
             section->e.name);
    value = uci_lookup_option_string(ctx, section, "packet_steering");
    if (value) {
        if (strlen(value) >= sizeof(snapshot->value))
            goto done;
        snprintf(snapshot->value, sizeof(snapshot->value), "%s", value);
        snapshot->present = 1;
    }
    rc = 0;

done:
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

static int nc_kernel_restore_uci_verify(
    const struct nc_kernel_restore_uci_snapshot *snapshot,
    const char *expected, int expected_present)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *section;
    const char *value;
    int matched = 0;

    if (!snapshot || !snapshot->section[0])
        return -1;
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "system", &pkg) != UCI_OK || !pkg)
        goto done;
    section = nc_kernel_restore_uci_system_section(pkg, snapshot->section);
    if (!section)
        goto done;
    value = uci_lookup_option_string(ctx, section, "packet_steering");
    matched = expected_present ? (value && expected && !strcmp(value, expected))
                               : (value == NULL);

done:
    if (ctx)
        uci_free_context(ctx);
    return matched ? 0 : -1;
}

static int nc_kernel_restore_uci_apply(
    const struct nc_kernel_restore_uci_snapshot *snapshot)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *section;
    int rc = -1;

    if (!snapshot || !snapshot->section[0])
        return -1;
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "system", &pkg) != UCI_OK || !pkg)
        goto done;
    section = nc_kernel_restore_uci_system_section(pkg, snapshot->section);
    if (!section || nc_uci_set_pkg(ctx, "system", section->e.name,
                                   "packet_steering", "1") != UCI_OK ||
        jmx_uci_commit(ctx, "system") != UCI_OK)
        goto done;
    rc = nc_kernel_restore_uci_verify(snapshot, "1", 1);

done:
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

static int nc_kernel_restore_uci_rollback(
    const struct nc_kernel_restore_uci_snapshot *snapshot)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *section;
    int rc = -1;

    if (!snapshot || !snapshot->section[0])
        return -1;
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, "system", &pkg) != UCI_OK || !pkg)
        goto done;
    section = nc_kernel_restore_uci_system_section(pkg, snapshot->section);
    if (!section)
        goto done;
    if (snapshot->present) {
        if (nc_uci_set_pkg(ctx, "system", section->e.name,
                           "packet_steering", snapshot->value) != UCI_OK)
            goto done;
    } else if (nc_uci_delete_pkg(ctx, "system", section->e.name,
                                 "packet_steering") != UCI_OK) {
        goto done;
    }
    if (jmx_uci_commit(ctx, "system") != UCI_OK)
        goto done;
    rc = nc_kernel_restore_uci_verify(snapshot, snapshot->value,
                                      snapshot->present);

done:
    if (ctx)
        uci_free_context(ctx);
    return rc;
}

static void nc_kernel_restore_file_snapshot_free(
    struct nc_kernel_restore_file_snapshot *snapshot)
{
    if (!snapshot)
        return;
    free(snapshot->data);
    memset(snapshot, 0, sizeof(*snapshot));
}

static int nc_kernel_restore_tuning_snapshot(
    struct nc_kernel_restore_file_snapshot *snapshot)
{
    const char *path = "/etc/sysctl.d/99-dreamingwrt-tuning.conf";
    struct stat before;
    struct stat opened;
    ssize_t got;
    size_t offset = 0;
    int fd = -1;

    if (!snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    if (lstat(path, &before) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(before.st_mode) || before.st_size < 0 ||
        before.st_size > 65536)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &opened) != 0 ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino ||
        !S_ISREG(opened.st_mode))
        goto failed;
    snapshot->data = calloc(1, (size_t)opened.st_size + 1);
    if (!snapshot->data)
        goto failed;
    while (offset < (size_t)opened.st_size) {
        got = read(fd, snapshot->data + offset,
                   (size_t)opened.st_size - offset);
        if (got > 0) {
            offset += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        goto failed;
    }
    snapshot->len = offset;
    snapshot->mode = opened.st_mode & 07777;
    snapshot->uid = opened.st_uid;
    snapshot->gid = opened.st_gid;
    snapshot->existed = 1;
    close(fd);
    return 0;

failed:
    if (fd >= 0)
        close(fd);
    nc_kernel_restore_file_snapshot_free(snapshot);
    return -1;
}

static int nc_kernel_restore_tuning_remove(int *removed_out)
{
    int dirfd;

    if (removed_out)
        *removed_out = 0;
    if (unlink("/etc/sysctl.d/99-dreamingwrt-tuning.conf") != 0)
        return errno == ENOENT ? 0 : -1;
    if (removed_out)
        *removed_out = 1;
    dirfd = open("/etc/sysctl.d", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                   O_NOFOLLOW);
    if (dirfd < 0)
        return -1;
    if (fsync(dirfd) == 0) {
        close(dirfd);
        return 0;
    }
    close(dirfd);
    return -1;
}

static int nc_kernel_restore_tuning_write(const char *data, size_t len,
                                          mode_t mode, uid_t uid, gid_t gid)
{
    char temporary[128];
    ssize_t written;
    size_t offset = 0;
    int fd = -1;
    int dirfd = -1;
    int attempt;

    if ((!data && len) || len > 65536)
        return -1;
    dirfd = open("/etc/sysctl.d", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                   O_NOFOLLOW);
    if (dirfd < 0)
        return -1;
    for (attempt = 0; attempt < 16; attempt++) {
        snprintf(temporary, sizeof(temporary),
                 ".99-dreamingwrt-tuning.conf.restore-%ld-%d",
                 (long)getpid(), attempt);
        fd = openat(dirfd, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
        if (fd >= 0 || errno != EEXIST)
            break;
    }
    if (fd < 0)
        goto failed;
    while (offset < len) {
        written = write(fd, data + offset, len - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        goto failed;
    }
    if (fchmod(fd, mode) != 0 || fchown(fd, uid, gid) != 0 || fsync(fd) != 0)
        goto failed;
    if (close(fd) != 0) {
        fd = -1;
        goto failed_closed;
    }
    fd = -1;
    if (renameat(dirfd, temporary, dirfd,
                 "99-dreamingwrt-tuning.conf") != 0 || fsync(dirfd) != 0)
        goto failed_closed;
    close(dirfd);
    return 0;

failed:
    if (fd >= 0)
        close(fd);
failed_closed:
    if (temporary[0])
        unlinkat(dirfd, temporary, 0);
    close(dirfd);
    return -1;
}

static int nc_kernel_restore_tuning_verify(const char *expected,
                                           size_t expected_len)
{
    const char *path = "/etc/sysctl.d/99-dreamingwrt-tuning.conf";
    struct stat st;
    char *actual;
    int matched;

    if ((!expected && expected_len) || lstat(path, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        st.st_size < 0 || (size_t)st.st_size != expected_len)
        return -1;
    actual = nc_sys_read_file_alloc(path, 65536, NULL);
    if (!actual)
        return -1;
    matched = !memcmp(actual, expected, expected_len) &&
              actual[expected_len] == '\0';
    free(actual);
    return matched ? 0 : -1;
}

static int nc_kernel_restore_tuning_publish(
    const struct nc_kernel_restore_item *items, int count)
{
    char *content;
    size_t capacity;
    size_t length = 0;
    int i;
    int n;
    int rc = -1;

    if (!items || count < 1 || count > 64)
        return -1;
    capacity = 256 + (size_t)count * 256;
    content = calloc(1, capacity);
    if (!content)
        return -1;
    n = snprintf(content, capacity,
                 "# Managed by DreamingWrt kernel restore-defaults; "
                 "do not edit by hand\n");
    if (n < 0 || (size_t)n >= capacity)
        goto done;
    length = (size_t)n;
    for (i = 0; i < count; i++) {
        if (!items[i].key || !items[i].key[0] ||
            !nc_kernel_restore_value_ok(items[i].value))
            goto done;
        n = snprintf(content + length, capacity - length, "%s=%s\n",
                     items[i].key, items[i].value);
        if (n < 0 || (size_t)n >= capacity - length)
            goto done;
        length += (size_t)n;
    }
    if (nc_kernel_restore_tuning_write(content, length, 0644, 0, 0) != 0 ||
        nc_kernel_restore_tuning_verify(content, length) != 0)
        goto done;
    rc = 0;

done:
    free(content);
    return rc;
}

static int nc_kernel_restore_tuning_rollback(
    const struct nc_kernel_restore_file_snapshot *snapshot)
{
    if (!snapshot)
        return -1;
    if (!snapshot->existed)
        return nc_kernel_restore_tuning_remove(NULL);
    if (nc_kernel_restore_tuning_write(snapshot->data, snapshot->len,
                                       snapshot->mode, snapshot->uid,
                                       snapshot->gid) != 0)
        return -1;
    return nc_kernel_restore_tuning_verify(snapshot->data, snapshot->len);
}

static int nc_kernel_restore_db_commit(void)
{
    sqlite3_stmt *statement = NULL;
    char *error = NULL;
    int transaction_started = 0;
    int rc = -1;

    if (jmx_netconfig_db_init() != 0)
        return -1;
    nc_sys_settings_db_init();
    if (sqlite3_exec(g_netconfig_db, "BEGIN IMMEDIATE", NULL, NULL,
                     &error) != SQLITE_OK)
        goto done;
    transaction_started = 1;
    if (nc_prepare(&statement,
        "UPDATE system_settings SET packet_steering=1,updated_at=?1 "
        "WHERE id=1") != 0)
        goto rollback;
    sqlite3_bind_int64(statement, 1, nc_now_s());
    if (nc_step_done(statement) != 0 || sqlite3_changes(g_netconfig_db) != 1)
        goto rollback;
    sqlite3_finalize(statement);
    statement = NULL;
    if (sqlite3_exec(g_netconfig_db, "COMMIT", NULL, NULL,
                     &error) != SQLITE_OK)
        goto rollback;
    transaction_started = 0;
    rc = 0;
    goto done;

rollback:
    if (statement) {
        sqlite3_finalize(statement);
        statement = NULL;
    }
    if (transaction_started)
        (void)sqlite3_exec(g_netconfig_db, "ROLLBACK", NULL, NULL, NULL);
done:
    if (statement)
