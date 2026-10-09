    sqlite3_stmt *st = NULL;
    struct nc_client_control_rule_row *rows = NULL;
    int count = 0;
    int cap = 0;
    int i;
    int rc = 0;
    time_t now_t;
    int64_t now;
    struct tm lt;

    if (jmx_netconfig_db_init() != 0)
        return -1;

    now_t = time(NULL);
    now = (int64_t)now_t;
    localtime_r(&now_t, &lt);

    if (nc_prepare(&st,
        "SELECT id,mac,enabled,control_type,schedule_mode,days_json,days_text,start_time,end_time,"
        "limit_mode,up_limit,up_unit,down_limit,down_unit,line,protocol,note,updated_at,last_runtime_enabled,"
        "last_runtime_apply_at,apply_state "
        "FROM client_control_rules ORDER BY mac,updated_at DESC,id DESC") != 0)
        return -1;

    while (sqlite3_step(st) == SQLITE_ROW) {
        struct nc_client_control_rule_row *r;
        const char *v;
        if (count >= cap) {
            int new_cap = cap ? cap * 2 : 32;
            struct nc_client_control_rule_row *nr =
                realloc(rows, (size_t)new_cap * sizeof(*rows));
            if (!nr) {
                rc = -1;
                break;
            }
            rows = nr;
            memset(rows + cap, 0, (size_t)(new_cap - cap) * sizeof(*rows));
            cap = new_cap;
        }
        r = &rows[count++];
        v = nc_sql_text(st, 0); snprintf(r->id, sizeof(r->id), "%s", v);
        v = nc_sql_text(st, 1); snprintf(r->mac, sizeof(r->mac), "%s", v);
        r->enabled = sqlite3_column_int(st, 2) ? 1 : 0;
        v = nc_sql_text(st, 3); snprintf(r->control_type, sizeof(r->control_type), "%s", v[0] ? v : "IP限速");
        v = nc_sql_text(st, 4); snprintf(r->schedule_mode, sizeof(r->schedule_mode), "%s", v);
        v = nc_sql_text(st, 5); snprintf(r->days_json, sizeof(r->days_json), "%s", v);
        v = nc_sql_text(st, 6); snprintf(r->days_text, sizeof(r->days_text), "%s", v);
        v = nc_sql_text(st, 7); snprintf(r->start_time, sizeof(r->start_time), "%s", v[0] ? v : "00:00");
        v = nc_sql_text(st, 8); snprintf(r->end_time, sizeof(r->end_time), "%s", v[0] ? v : "23:59");
        v = nc_sql_text(st, 9); snprintf(r->limit_mode, sizeof(r->limit_mode), "%s", v[0] ? v : "独立限速");
        r->up_limit = sqlite3_column_int(st, 10);
        v = nc_sql_text(st, 11); snprintf(r->up_unit, sizeof(r->up_unit), "%s", v[0] ? v : "KB/s");
        r->down_limit = sqlite3_column_int(st, 12);
        v = nc_sql_text(st, 13); snprintf(r->down_unit, sizeof(r->down_unit), "%s", v[0] ? v : "KB/s");
        v = nc_sql_text(st, 14); snprintf(r->line, sizeof(r->line), "%s", v);
        v = nc_sql_text(st, 15); snprintf(r->protocol, sizeof(r->protocol), "%s", v[0] ? v : "任意");
        v = nc_sql_text(st, 16); snprintf(r->note, sizeof(r->note), "%s", v);
        r->updated_at = sqlite3_column_int64(st, 17);
        r->last_runtime_enabled = sqlite3_column_int(st, 18);
        r->last_runtime_apply_at = sqlite3_column_int64(st, 19);
        v = nc_sql_text(st, 20); snprintf(r->prev_apply_state, sizeof(r->prev_apply_state), "%s", v);
        r->desired_active = nc_control_rule_should_be_active(r, &lt);
        r->up_kbps = nc_control_limit_to_kbps(r->up_limit, r->up_unit);
        r->down_kbps = nc_control_limit_to_kbps(r->down_limit, r->down_unit);
        r->runtime_supported = !strcmp(r->control_type, "IP限速") &&
            (!r->line[0] || !strcmp(r->line, "任意") || !strcmp(r->line, "全部") ||
             !strcasecmp(r->line, "any") || !strcasecmp(r->line, "all") || !strcmp(r->line, "*")) &&
            (!strcmp(r->limit_mode, "独立限速") || !strcasecmp(r->limit_mode, "independent")) &&
            nc_rate_limit_protocol_id(r->protocol) >= 0;
        snprintf(r->apply_state, sizeof(r->apply_state), "%s", "pending");
        r->apply_reason[0] = 0;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (rc != 0) {
        free(rows);
        return rc;
    }

    /* Pick exactly one active IP限速 rule per MAC.  Multiple active rows are
     * deterministic: latest updated row wins; inactive rows never delete a
     * newer active row for the same client. */
    for (i = 0; i < count; i++) {
        int j;
        if (!rows[i].desired_active || !rows[i].runtime_supported)
            continue;
        for (j = 0; j < i; j++) {
            if (!strcmp(rows[j].mac, rows[i].mac) && rows[j].selected)
                break;
        }
        if (j == i)
            rows[i].selected = 1;
    }

    for (i = 0; i < count; i++) {
        struct nc_client_control_rule_row *r = &rows[i];
        int desired_runtime_enabled = 0;
        int apply_rc = 0;

        if (!r->enabled) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "disabled");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "disabled_by_rule");
            r->runtime_apply = 1;
            desired_runtime_enabled = 0;
        } else if (!r->desired_active) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "scheduled_inactive");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "outside_schedule");
            r->runtime_apply = 1;
            desired_runtime_enabled = 0;
        } else if (strcmp(r->control_type, "IP限速")) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "unsupported");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "unsupported_control_type");
            r->runtime_apply = 0;
            desired_runtime_enabled = 0;
        } else if (r->line[0] && strcmp(r->line, "任意") && strcmp(r->line, "全部") &&
                   strcasecmp(r->line, "any") && strcasecmp(r->line, "all") && strcmp(r->line, "*")) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "unsupported");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "line_scoped_client_rate_limit_not_implemented");
            r->runtime_apply = 0;
            desired_runtime_enabled = 0;
        } else if (strcmp(r->limit_mode, "独立限速") && strcasecmp(r->limit_mode, "independent")) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "unsupported");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "shared_rate_limit_dataplane_not_implemented");
            r->runtime_apply = 0;
            desired_runtime_enabled = 0;
        } else if (nc_rate_limit_protocol_id(r->protocol) < 0) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "unsupported");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "unsupported_l4_protocol");
            r->runtime_apply = 0;
            desired_runtime_enabled = 0;
        } else if (!r->selected) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "shadowed");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "shadowed_by_newer_active_rule");
            r->runtime_apply = 0;
            desired_runtime_enabled = 0;
        } else if (r->up_kbps <= 0 && r->down_kbps <= 0) {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "applied");
            snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "zero_limit_means_unlimited");
            r->runtime_apply = 1;
            desired_runtime_enabled = 1;
        } else {
            snprintf(r->apply_state, sizeof(r->apply_state), "%s", "applied");
            if (r->protocol[0] && strcmp(r->protocol, "任意") && strcmp(r->protocol, "全部") &&
                     strcasecmp(r->protocol, "any") && strcasecmp(r->protocol, "all"))
                snprintf(r->apply_reason, sizeof(r->apply_reason), "%s",
                         "protocol_runtime_applied");
            else
                snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "");
            r->runtime_apply = 1;
            desired_runtime_enabled = 1;
        }

        if (nc_control_rule_needs_apply(r, desired_runtime_enabled, now)) {
            if (r->selected && !strcmp(r->control_type, "IP限速") &&
                (r->up_kbps > 0 || r->down_kbps > 0)) {
                apply_rc = nc_client_rate_limit_set_ex(r->mac, "", r->up_kbps, r->down_kbps,
                                                       r->protocol,
                                                       r->note[0] ? r->note : "client control schedule");
                if (apply_rc != 0) {
                    snprintf(r->apply_state, sizeof(r->apply_state), "%s", "failed");
                    snprintf(r->apply_reason, sizeof(r->apply_reason), "%s", "client_rate_limit_set_failed");
                    r->runtime_apply = 0;
                    rc = -1;
                }
            } else {
                int has_selected_for_mac = 0;
                int j;
                for (j = 0; j < count; j++) {
                    if (rows[j].selected && !strcmp(rows[j].mac, r->mac)) {
                        has_selected_for_mac = 1;
                        break;
                    }
                }
                if (!has_selected_for_mac || (r->selected && r->up_kbps <= 0 && r->down_kbps <= 0)) {
                    apply_rc = nc_client_rate_limit_delete(r->mac);
                    if (apply_rc != 0) {
                        snprintf(r->apply_state, sizeof(r->apply_state), "%s", "failed");
                        snprintf(r->apply_reason, sizeof(r->apply_reason), "%s",
                                 "client_rate_limit_delete_failed");
                        r->runtime_apply = 0;
                        rc = -1;
                    }
                }
            }
        }
        if (nc_control_update_rule_runtime(r, desired_runtime_enabled, now) != 0)
            rc = -1;
    }

    free(rows);
    return rc;
}

/* ═══ Flash / Firmware Operations ═══ */

#define NC_FACTORY_RESET_PATH "/sbin/factoryreset"
#define NC_FACTORY_RESET_REBOOT_PATH "/sbin/reboot"
#define NC_FACTORY_RESET_STATUS_NAME "factory-reset-status.json"
#define NC_FACTORY_RESET_DISPATCH_DELAY_SECONDS 2
#define NC_FACTORY_RESET_HANDSHAKE_TIMEOUT_MS 2000

struct nc_factory_reset_executable {
    int fd;
    dev_t device;
    ino_t inode;
};

struct nc_factory_reset_dispatch_result {
    pid_t executor_pid;
    int release_fd;
    int lock_fd;
};

static int nc_factory_reset_status_write(const char *state, const char *stage,
                                         const char *reason, pid_t executor_pid)
{
    const char *stage_key = "stage";
    const char *reason_key = "reason";
    const char *timestamp_key = "timestamp";
    char temporary[96] = "";
    char payload[768];
    struct stat dir_st;
    int dirfd = -1, fd = -1, rc = -1;
    size_t length, offset = 0;
    ssize_t written;

    if (!state || !stage || !reason)
        return -1;
    if (mkdir("/etc/dreamingwrt/", 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open("/etc/dreamingwrt/",
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0)
        return -1;
    if (fstat(dirfd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
        dir_st.st_uid != 0 || (dir_st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;
    if (fchmod(dirfd, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0)
        goto out;
    if (snprintf(temporary, sizeof(temporary), ".factory-reset-status.%ld.%lld.tmp",
                 (long)getpid(), (long long)nc_now_s()) >= (int)sizeof(temporary))
        goto out;
    fd = openat(dirfd, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        goto out;
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0 || fchown(fd, 0, 0) != 0)
        goto out;
    if (snprintf(payload, sizeof(payload),
                 "{\"state\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\","
                 "\"%s\":%lld,\"executor_pid\":%ld}\n",
                 state, stage_key, stage, reason_key, reason, timestamp_key,
                 (long long)nc_now_s(),
                 (long)executor_pid) >= (int)sizeof(payload))
        goto out;
    length = strlen(payload);
    while (offset < length) {
        written = write(fd, payload + offset, length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            goto out;
        offset += (size_t)written;
    }
    if (fsync(fd) != 0 || close(fd) != 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (renameat(dirfd, temporary, dirfd, NC_FACTORY_RESET_STATUS_NAME) != 0 ||
        fsync(dirfd) != 0)
        goto out;
    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    if (rc != 0 && temporary[0])
        (void)unlinkat(dirfd, temporary, 0);
    close(dirfd);
    return rc;
}

static int nc_factory_reset_validate_executable(
    const char *path, struct nc_factory_reset_executable *trusted)
{
    char resolved[PATH_MAX];
    struct stat link_st, path_st, fd_st;
    int fd = -1;

    if (!path || !trusted || path[0] != '/')
        return -1;
    memset(trusted, 0, sizeof(*trusted));
    trusted->fd = -1;
    if (lstat(path, &link_st) != 0 || link_st.st_uid != 0)
        return -1;
    if (S_ISLNK(link_st.st_mode)) {
        if (!realpath(path, resolved) || resolved[0] != '/')
            return -1;
        fd = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    } else {
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (fd < 0 || fstat(fd, &fd_st) != 0 || stat(path, &path_st) != 0)
        goto fail;
    if (!S_ISREG(fd_st.st_mode) || fd_st.st_uid != 0 ||
        (fd_st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (fd_st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 ||
        path_st.st_dev != fd_st.st_dev || path_st.st_ino != fd_st.st_ino)
        goto fail;
    trusted->fd = fd;
    trusted->device = fd_st.st_dev;
    trusted->inode = fd_st.st_ino;
    return 0;
fail:
    if (fd >= 0)
        close(fd);
    return -1;
}

static int nc_factory_reset_revalidate_executable(
    const char *path, const struct nc_factory_reset_executable *trusted)
{
    struct stat path_st, fd_st;

    if (!path || !trusted || trusted->fd < 0 ||
        fstat(trusted->fd, &fd_st) != 0 || stat(path, &path_st) != 0)
        return -1;
    if (!S_ISREG(fd_st.st_mode) || fd_st.st_uid != 0 ||
        (fd_st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (fd_st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 ||
        fd_st.st_dev != trusted->device || fd_st.st_ino != trusted->inode ||
        path_st.st_dev != trusted->device || path_st.st_ino != trusted->inode)
        return -1;
    return 0;
}

static int64_t nc_factory_reset_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void nc_factory_reset_record_failure(const char *stage,
                                            const char *reason,
                                            pid_t executor_pid)
{
    char message[384];
    int fd;
    int length;

    if (nc_factory_reset_status_write("failed", stage, reason, executor_pid) == 0)
        return;
    length = snprintf(message, sizeof(message),
                      "dreamingwrt factory reset failure: stage=%s reason=%s pid=%ld\n",
                      stage ? stage : "unknown", reason ? reason : "unknown",
                      (long)executor_pid);
    if (length <= 0)
        return;
    if (length >= (int)sizeof(message))
        length = (int)sizeof(message) - 1;
    fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        /*
         * Breadcrumb for post-mortem log reading only. If /dev/kmsg refuses the
         * write there is nothing useful to do about it here, and the factory
         * reset must not be derailed by a failed log line.
         */
        (void)!write(fd, message, (size_t)length);
        close(fd);
    }
}

static int nc_factory_reset_exec_wait_fd(int executable_fd,
                                         char *const argv[], int timeout_ms,
                                         int *status_out)
{
    static char *const clean_envp[] = {
        (char *)"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        (char *)"HOME=/root", (char *)"LANG=C", (char *)"LC_ALL=C", NULL
    };
    struct timespec pause_time = { .tv_sec = 0, .tv_nsec = 20000000L };
    pid_t child;
    int64_t deadline;
    int status = 0;

    if (executable_fd < 0 || !argv || !argv[0] || timeout_ms < 1 || !status_out)
        return -1;
    child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        sigset_t empty;
        int nullfd;
        int fd;

        (void)setpgid(0, 0);
        sigemptyset(&empty);
        (void)sigprocmask(SIG_SETMASK, &empty, NULL);
        nullfd = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0 ||
            dup2(nullfd, STDOUT_FILENO) < 0 || dup2(nullfd, STDERR_FILENO) < 0)
            _exit(126);
        if (nullfd > STDERR_FILENO)
            close(nullfd);
        for (fd = 3; fd < 65536; fd++)
            if (fd != executable_fd)
                close(fd);
        fexecve(executable_fd, argv, clean_envp);
        _exit(127);
    }
    (void)setpgid(child, child);
    deadline = nc_factory_reset_now_ms();
    if (deadline < 0)
        goto kill_child;
    deadline += timeout_ms;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        int64_t now;

        if (waited == child) {
            *status_out = status;
            return 0;
        }
        if (waited < 0 && errno != EINTR)
            goto kill_child;
        now = nc_factory_reset_now_ms();
        if (now < 0 || now >= deadline)
            break;
        while (nanosleep(&pause_time, &pause_time) != 0 && errno == EINTR) {}
        pause_time.tv_sec = 0;
        pause_time.tv_nsec = 20000000L;
    }
    (void)kill(-child, SIGTERM);
    pause_time.tv_sec = 0;
    pause_time.tv_nsec = 200000000L;
    while (nanosleep(&pause_time, &pause_time) != 0 && errno == EINTR) {}
kill_child:
    (void)kill(-child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    *status_out = status;
    return -2;
}

static int nc_factory_reset_worker(void)
{
    struct nc_factory_reset_executable reset_exec = { .fd = -1 };
    struct nc_factory_reset_executable reboot_exec = { .fd = -1 };
    char *reset_argv[] = { (char *)"/sbin/factoryreset", (char *)"-y", NULL };
    char *reboot_argv[] = { (char *)"/sbin/reboot", NULL };
    pid_t executor_pid = getpid();
    int status = 0;
    int rc = 1;

    {
        sigset_t empty;
        sigemptyset(&empty);
        (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    }
    umask(077);
    sleep(NC_FACTORY_RESET_DISPATCH_DELAY_SECONDS);

    if (nc_factory_reset_validate_executable(NC_FACTORY_RESET_PATH, &reset_exec) != 0 ||
        nc_factory_reset_validate_executable(NC_FACTORY_RESET_REBOOT_PATH,
                                              &reboot_exec) != 0) {
        nc_factory_reset_record_failure("dispatch", "trusted_executable_invalid",
                                        executor_pid);
        goto out;
    }
    if (nc_factory_reset_status_write("running", "factoryreset", "started",
                                      executor_pid) != 0) {
        nc_factory_reset_record_failure("factoryreset", "status_publish_failed",
                                        executor_pid);
        goto out;
    }
    if (nc_factory_reset_revalidate_executable(NC_FACTORY_RESET_PATH,
                                                &reset_exec) != 0) {
        nc_factory_reset_record_failure("factoryreset", "trusted_executable_changed",
                                        executor_pid);
        goto out;
    }
    if (nc_factory_reset_exec_wait_fd(reset_exec.fd, reset_argv, 120000,
                                      &status) != 0) {
        nc_factory_reset_record_failure("factoryreset", "timeout_or_wait_failed",
                                        executor_pid);
        goto out;
    }
    if (WIFSIGNALED(status)) {
        nc_factory_reset_record_failure("factoryreset", "terminated_by_signal",
                                        executor_pid);
        goto out;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        nc_factory_reset_record_failure("factoryreset", "nonzero_exit", executor_pid);
        goto out;
    }
    if (nc_factory_reset_revalidate_executable(NC_FACTORY_RESET_REBOOT_PATH,
                                                &reboot_exec) != 0) {
        nc_factory_reset_record_failure("reboot", "trusted_executable_changed",
                                        executor_pid);
        goto out;
    }
    if (nc_factory_reset_exec_wait_fd(reboot_exec.fd, reboot_argv, 30000,
                                      &status) != 0) {
        nc_factory_reset_record_failure("reboot", "timeout_or_wait_failed",
                                        executor_pid);
        goto out;
    }
    if (WIFSIGNALED(status)) {
        nc_factory_reset_record_failure("reboot", "terminated_by_signal", executor_pid);
        goto out;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        nc_factory_reset_record_failure("reboot", "nonzero_exit", executor_pid);
        goto out;
    }
    sleep(30);
    nc_factory_reset_record_failure("reboot", "returned_without_system_restart",
                                    executor_pid);
out:
    if (reset_exec.fd >= 0)
        close(reset_exec.fd);
    if (reboot_exec.fd >= 0)
        close(reboot_exec.fd);
    return rc;
}

int jmx_flash_factory_reset_worker_main(void)
{
    return nc_factory_reset_worker();
}

static int nc_factory_reset_lock_open(void)
{
    struct stat dir_st;
    int dirfd = -1, lockfd = -1;

    if (mkdir("/run/dreamingwrt", 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open("/run/dreamingwrt",
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
        dir_st.st_uid != 0 || (dir_st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;
    lockfd = openat(dirfd, "factory-reset.lock",
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || fchmod(lockfd, 0600) != 0 || fchown(lockfd, 0, 0) != 0)
        goto out;
    if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        int busy = errno == EWOULDBLOCK || errno == EAGAIN;
        close(lockfd);
        close(dirfd);
        return busy ? -2 : -1;
    }
    close(dirfd);
    return lockfd;
out:
    if (lockfd >= 0)
        close(lockfd);
    if (dirfd >= 0)
        close(dirfd);
    return -1;
}

static int nc_factory_reset_open_self(void)
{
    struct stat st;
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);

    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static int nc_factory_reset_dispatch(struct nc_factory_reset_dispatch_result *result)
{
    struct nc_factory_reset_executable reset_exec = { .fd = -1 };
    struct nc_factory_reset_executable reboot_exec = { .fd = -1 };
    static char *const clean_envp[] = {
        (char *)"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        (char *)"HOME=/root", (char *)"LANG=C", (char *)"LC_ALL=C", NULL
    };
    char *worker_argv[] = {
        (char *)"/usr/bin/dreamingwrt-core", (char *)"--factory-reset-worker", NULL
    };
    int handshake[2] = {-1, -1};
    int release_gate[2] = {-1, -1};
    int lockfd = -1, self_fd = -1;
    long open_max;
    pid_t parent_pid, dispatcher = -1, detached = -1;
    struct pollfd pfd;
    ssize_t got;
    pid_t waited;
    int status = 0;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    result->release_fd = -1;
    result->lock_fd = -1;
    lockfd = nc_factory_reset_lock_open();
    if (lockfd < 0)
        return lockfd;
    if (nc_factory_reset_validate_executable(NC_FACTORY_RESET_PATH, &reset_exec) != 0 ||
        nc_factory_reset_validate_executable(NC_FACTORY_RESET_REBOOT_PATH, &reboot_exec) != 0)
        goto fail;
    self_fd = nc_factory_reset_open_self();
    if (self_fd < 0)
        goto fail;
    open_max = sysconf(_SC_OPEN_MAX);
    if (open_max < 0 || open_max > 65536)
        open_max = 65536;
    if (pipe(handshake) != 0 ||
        fcntl(handshake[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(handshake[1], F_SETFD, FD_CLOEXEC) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, release_gate) != 0)
        goto fail;
    parent_pid = getpid();
    dispatcher = fork();
    if (dispatcher < 0)
        goto fail;
    if (dispatcher == 0) {
        int fd;
        char release = '\0';

        (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent_pid)
            _exit(126);

        close(handshake[0]);
        close(release_gate[1]);
        if (setsid() < 0) {
            detached = -1;
            /*
             * The parent treats a closed pipe as failure too, so if this
             * handshake write cannot land, _exit() below still reports the
             * failure by closing the descriptor.
             */
            (void)!write(handshake[1], &detached, sizeof(detached));
            _exit(126);
        }
        detached = fork();
        if (detached != 0) {
            close(release_gate[0]);
            close(reset_exec.fd);
            close(reboot_exec.fd);
            close(self_fd);
            close(lockfd);
            (void)!write(handshake[1], &detached, sizeof(detached));
            _exit(detached > 0 ? 0 : 126);
        }
        close(handshake[1]);
        for (fd = 3; fd < open_max; fd++)
            if (fd != release_gate[0] && fd != self_fd && fd != lockfd)
                close(fd);
        if (fcntl(lockfd, F_SETFD, 0) != 0)
            _exit(126);
        do {
            got = read(release_gate[0], &release, 1);
