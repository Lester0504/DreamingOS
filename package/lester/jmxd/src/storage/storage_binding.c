// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "storage_binding.h"

#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const g_uses[] = { "audit", "aegis", "log", "snapshots", "core", "metrics", "apid", "notify", "flow", "wan_sla", "aegis_work" };
static pthread_mutex_t g_binding_lock = PTHREAD_MUTEX_INITIALIZER;

const char *jmx_storage_binding_use(size_t index)
{
    return index < sizeof(g_uses) / sizeof(g_uses[0]) ? g_uses[index] : NULL;
}

const char *jmx_storage_binding_default_path(const char *use)
{
    if (!use)
        return "";
    if (!strcmp(use, "audit"))
        return "/opt/dreamingwrt/audit";
    if (!strcmp(use, "aegis"))
        return "/etc/dreamingwrt/aegis.db";
    if (!strcmp(use, "log"))
        return "/etc/dreamingwrt/log.db";
    if (!strcmp(use, "snapshots"))
        return "/data/persist/dreamingwrt-ota-snapshots";
    if (!strcmp(use, "core"))
        return "/etc/dreamingwrt/dreamingwrt.db";
    if (!strcmp(use, "metrics"))
        return "/etc/dreamingwrt/metrics.db";
    if (!strcmp(use, "apid"))
        return "/etc/dreamingwrt/apid.db";
    if (!strcmp(use, "notify"))
        return "/etc/dreamingwrt/notify.db";
    if (!strcmp(use, "flow"))
        return "/etc/dreamingwrt/flow.db";
    if (!strcmp(use, "wan_sla"))
        return "/etc/dreamingwrt/wan-sla.db";
    if (!strcmp(use, "aegis_work"))
        return "/opt/dreamingwrt/aegis";
    return "";
}

int jmx_storage_binding_path_ready(const char *path, int expect_dir)
{
    struct stat st;

    if (!path || path[0] != '/' || stat(path, &st) != 0)
        return 0;
    if (expect_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))
        return 0;
#ifndef JMX_STORAGE_TEST_MOUNT
    struct stat system;
    if (stat("/", &system) != 0 || st.st_dev == system.st_dev)
        return 0;
    if (stat("/overlay", &system) == 0 && st.st_dev == system.st_dev)
        return 0;
#endif
    return access(path, R_OK | W_OK) == 0;
}

static int valid_use(const char *use)
{
    size_t i;

    if (!use)
        return 0;
    for (i = 0; i < sizeof(g_uses) / sizeof(g_uses[0]); i++)
        if (!strcmp(use, g_uses[i]))
            return 1;
    return 0;
}

static void copy_text(char *dst, size_t len, const char *src)
{
    if (!dst || !len)
        return;
    snprintf(dst, len, "%s", src ? src : "");
}

static struct json_object *load_root(void)
{
    FILE *fp;
    char buf[32768];
    size_t n;
    struct json_object *root;

    fp = fopen(JMX_STORAGE_ASSIGNMENTS_PATH, "re");
    if (!fp)
        return errno == ENOENT ? json_object_new_object() : NULL;
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    if (ferror(fp) || !feof(fp)) {
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    buf[n] = '\0';
    root = json_tokener_parse(buf);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root)
            json_object_put(root);
        return NULL;
    }
    return root;
}

static int fsync_parent(void)
{
    int fd = open(JMX_STORAGE_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int rc;

    if (fd < 0)
        return -1;
    rc = fsync(fd);
    if (close(fd) != 0 && rc == 0)
        rc = -1;
    return rc;
}

int jmx_storage_binding_read(const char *use, char *provider_id, size_t provider_len,
                             char *active_path, size_t path_len,
                             char *state, size_t state_len,
                             char *reason, size_t reason_len)
{
    struct json_object *root = NULL, *item = NULL, *value = NULL;

    if (!valid_use(use))
        return -1;
    if (provider_id && provider_len) provider_id[0] = '\0';
    if (active_path && path_len) active_path[0] = '\0';
    if (state && state_len) copy_text(state, state_len, "local_default");
    if (reason && reason_len) copy_text(reason, reason_len, "no_external_provider_selected");
    root = load_root();
    if (!root)
        return -1;
    if (json_object_object_get_ex(root, use, &item)) {
        if (!item || !json_object_is_type(item, json_type_object)) {
            json_object_put(root);
            return -1;
        }
        static const char *const strings[] = {
            "active_provider", "active_path", "state", "reason"
        };
        size_t i;
        for (i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
            if (json_object_object_get_ex(item, strings[i], &value) &&
                (!value || !json_object_is_type(value, json_type_string))) {
                json_object_put(root);
                return -1;
            }
        }
        if (json_object_object_get_ex(item, "active_path", &value)) {
            const char *p = json_object_get_string(value);
            if ((p[0] && p[0] != '/') ||
                (active_path && strlen(p) >= path_len)) {
                json_object_put(root);
                return -1;
            }
        }
        if (provider_id && provider_len &&
            json_object_object_get_ex(item, "active_provider", &value))
            copy_text(provider_id, provider_len, json_object_get_string(value));
        if (active_path && path_len &&
            json_object_object_get_ex(item, "active_path", &value))
            copy_text(active_path, path_len, json_object_get_string(value));
        if (state && state_len &&
            json_object_object_get_ex(item, "state", &value))
            copy_text(state, state_len, json_object_get_string(value));
        if (reason && reason_len &&
            json_object_object_get_ex(item, "reason", &value))
            copy_text(reason, reason_len, json_object_get_string(value));
    }
    json_object_put(root);
    return 0;
}

int jmx_storage_binding_commit(const char *use, const char *expected_provider,
                               const char *expected_path, const char *provider_id,
                               const char *active_path, const char *state,
                               const char *reason, int rollback_available)
{
    struct json_object *root = NULL, *item = NULL;
    const char *serialized;
    char tmp[PATH_MAX] = "";
    int fd = -1;
    int lock_fd = -1;
    FILE *fp = NULL;
    int rc = -1;

    if (!valid_use(use) || !active_path ||
        (active_path[0] && active_path[0] != '/'))
        return -1;
    if (mkdir(JMX_STORAGE_PARENT_DIR, 0750) != 0 && errno != EEXIST)
        return -1;
    if (mkdir(JMX_STORAGE_DIR, 0750) != 0 && errno != EEXIST)
        return -1;
    pthread_mutex_lock(&g_binding_lock);
    lock_fd = open(JMX_STORAGE_DIR "/assignments.lock",
                   O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd < 0)
        goto done;
    {
        struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
        if (fcntl(lock_fd, F_SETLK, &lock) != 0)
            goto done;
    }
    if (expected_path) {
        char current_provider[128] = "", current_path[PATH_MAX] = "";
        if (jmx_storage_binding_read(use, current_provider, sizeof(current_provider),
                                     current_path, sizeof(current_path),
                                     NULL, 0, NULL, 0) != 0 ||
            strcmp(current_path, expected_path) ||
            (expected_provider && strcmp(current_provider, expected_provider)))
            goto done;
    }
    root = load_root();
    if (!root)
        goto done;
    /* Preserve metadata owned by the policy/migration producer. */
    if (json_object_object_get_ex(root, use, &item)) {
        if (!item || !json_object_is_type(item, json_type_object)) {
            item = NULL;
            goto done;
        }
        json_object_get(item);
    } else {
        item = json_object_new_object();
    }
    if (!item)
        goto done;
    json_object_object_add(item, "requested_provider",
                           json_object_new_string(active_path[0] && provider_id ? provider_id : ""));
    json_object_object_add(item, "active_provider",
                           json_object_new_string(active_path[0] && provider_id ? provider_id : "local"));
    json_object_object_add(item, "active_path", json_object_new_string(active_path));
    json_object_object_add(item, "state",
                           json_object_new_string(active_path[0] && state && state[0] ? state : "local_default"));
    json_object_object_add(item, "reason",
                           json_object_new_string(active_path[0] && reason ? reason : "no_external_provider_selected"));
    json_object_object_add(item, "rollback_available",
                           json_object_new_boolean(rollback_available));
    if (expected_path) {
        json_object_object_add(item, "old_path", json_object_new_string(
            expected_path[0] ? expected_path : jmx_storage_binding_default_path(use)));
        json_object_object_add(item, "new_path", json_object_new_string(active_path));
        json_object_object_add(item, "phase", json_object_new_string("committed"));
    }
    json_object_object_add(root, "version", json_object_new_int(JMX_STORAGE_BINDING_VERSION));
    json_object_object_add(root, use, item);
    item = NULL;
    serialized = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", JMX_STORAGE_ASSIGNMENTS_PATH, (long)getpid());
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        goto done;
    fp = fdopen(fd, "w");
    if (!fp)
        goto done;
    fd = -1;
    if (fprintf(fp, "%s\n", serialized ? serialized : "{}") < 0 ||
        fflush(fp) != 0 || fsync(fileno(fp)) != 0)
        goto done;
    int close_rc = fclose(fp);
    fp = NULL;
    if (close_rc != 0)
        goto done;
    if (rename(tmp, JMX_STORAGE_ASSIGNMENTS_PATH) != 0 || fsync_parent() != 0)
        goto done;
    rc = 0;
done:
    if (fp) fclose(fp);
    if (fd >= 0) close(fd);
    if (rc != 0 && tmp[0]) unlink(tmp);
    if (item) json_object_put(item);
    if (root) json_object_put(root);
    if (lock_fd >= 0) close(lock_fd);
    pthread_mutex_unlock(&g_binding_lock);
    return rc;
}

int jmx_storage_binding_write(const char *use, const char *provider_id,
                              const char *active_path, const char *state,
                              const char *reason, int rollback_available)
{
    return jmx_storage_binding_commit(use, NULL, NULL, provider_id, active_path,
                                      state, reason, rollback_available);
}
