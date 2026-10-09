// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "storage_supervisor.h"
#include "storage_migration.h"
#include "storage_binding.h"

#include <libubus.h>
#include <errno.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STORAGE_SUPERVISOR_TIMEOUT_MS 5000
#define STORAGE_SNAPSHOT_STATE_PATH "/etc/dreamingwrt/storage/snapshots-runtime.state"
#define STORAGE_SNAPSHOT_STATE_DIR "/etc/dreamingwrt/storage"

struct storage_supervisor_call {
    struct json_object *response;
};

static struct ubus_context *g_supervisor_ctx;
static int g_snapshot_frozen;

/* A migration callback is invoked once for the new path and, when the
 * consumer rejects it, once more for the restored old path.  Keep the
 * pre-migration binding so the rollback callback cannot accidentally persist
 * the requested provider (or the local default) as the active assignment. */
struct storage_supervisor_binding_backup {
    int valid;
    char use[32];
    char old_path[PATH_MAX];
    char new_path[PATH_MAX];
    char provider_id[128];
    char active_path[PATH_MAX];
    char state[32];
    char reason[96];
};

static struct storage_supervisor_binding_backup g_binding_backup;

static int storage_supervisor_write_snapshot_state(const char *active_path,
                                                   int frozen);

static int storage_supervisor_assignment_read(const char *use,
                                              char *provider_id,
                                              size_t provider_len,
                                              char *active_path,
                                              size_t path_len)
{
    char state[32] = "";
    char reason[96] = "";

    return jmx_storage_binding_read(use, provider_id, provider_len,
                                    active_path, path_len, state,
                                    sizeof(state), reason, sizeof(reason));
}

static int storage_supervisor_capture_binding(const char *use,
                                              const char *old_path,
                                              const char *new_path)
{
    struct storage_supervisor_binding_backup backup = {0};

    if (!use || !old_path || !new_path ||
        strlen(use) >= sizeof(backup.use) ||
        strlen(old_path) >= sizeof(backup.old_path) ||
        strlen(new_path) >= sizeof(backup.new_path))
        return -1;
    if (jmx_storage_binding_read(use, backup.provider_id,
                                 sizeof(backup.provider_id),
                                 backup.active_path,
                                 sizeof(backup.active_path),
                                 backup.state, sizeof(backup.state),
                                 backup.reason, sizeof(backup.reason)) != 0)
        return -1;
    snprintf(backup.use, sizeof(backup.use), "%s", use);
    snprintf(backup.old_path, sizeof(backup.old_path), "%s", old_path);
    snprintf(backup.new_path, sizeof(backup.new_path), "%s", new_path);
    backup.valid = 1;
    g_binding_backup = backup;
    return 0;
}

static int storage_supervisor_is_rollback(const char *use,
                                          const char *old_path,
                                          const char *new_path)
{
    return g_binding_backup.valid && use && old_path && new_path &&
           !strcmp(g_binding_backup.use, use) &&
           !strcmp(g_binding_backup.old_path, new_path) &&
           !strcmp(g_binding_backup.new_path, old_path);
}

static int storage_supervisor_restore_binding(const char *use)
{
    int rc;

    if (!g_binding_backup.valid || !use || strcmp(g_binding_backup.use, use))
        return -1;
    rc = jmx_storage_binding_write(use, g_binding_backup.provider_id,
                                   g_binding_backup.active_path,
                                   g_binding_backup.state,
                                   g_binding_backup.reason,
                                   g_binding_backup.active_path[0] ? 1 : 0);
    if (rc == 0 && !strcmp(use, "snapshots"))
        rc = storage_supervisor_write_snapshot_state(
            g_binding_backup.active_path, 1);
    if (rc == 0)
        g_binding_backup.valid = 0;
    return rc;
}

static int storage_supervisor_fsync_dir(const char *path)
{
    int fd;
    int rc;

    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    rc = fsync(fd);
    if (close(fd) != 0 && rc == 0)
        rc = -1;
    return rc;
}

static int storage_supervisor_write_snapshot_state(const char *active_path,
                                                   int frozen)
{
    char tmp[PATH_MAX];
    int fd = -1;
    int n;
    int rc = -1;

    if (!active_path)
        active_path = "";
    if (mkdir("/etc/dreamingwrt", 0750) != 0 && errno != EEXIST)
        return -1;
    if (mkdir(STORAGE_SNAPSHOT_STATE_DIR, 0750) != 0 && errno != EEXIST)
        return -1;
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", STORAGE_SNAPSHOT_STATE_PATH,
                 (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp))
        return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    n = dprintf(fd, "active_path=%s\nfrozen=%d\n", active_path, frozen ? 1 : 0);
    if (n < 0 || fsync(fd) != 0)
        goto done;
    if (close(fd) != 0)
        goto done;
    fd = -1;
    if (rename(tmp, STORAGE_SNAPSHOT_STATE_PATH) != 0 ||
        storage_supervisor_fsync_dir(STORAGE_SNAPSHOT_STATE_DIR) != 0)
        goto done;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(tmp);
    return rc;
}

static int storage_supervisor_snapshot_state_read(char *active_path,
                                                  size_t path_len)
{
    FILE *fp;
    char line[PATH_MAX];

    if (active_path && path_len)
        active_path[0] = '\0';
    fp = fopen(STORAGE_SNAPSHOT_STATE_PATH, "re");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strncmp(line, "active_path=", 12) && active_path && path_len) {
            char *value = line + 12;
            value[strcspn(value, "\r\n")] = '\0';
            if (value[0] == '/')
                snprintf(active_path, path_len, "%s", value);
        }
    }
    fclose(fp);
    return 0;
}

static void storage_supervisor_reply_cb(struct ubus_request *req, int type,
                                        struct blob_attr *msg)
{
    struct storage_supervisor_call *call = req ? req->priv : NULL;
    char *text;

    (void)type;
    if (!call || !msg)
        return;
    text = blobmsg_format_json(msg, true);
    if (!text)
        return;
    if (call->response)
        json_object_put(call->response);
    call->response = json_tokener_parse(text);
    free(text);
}

static int storage_supervisor_response_ok(struct json_object *response,
                                          const char *use,
                                          const char *phase,
                                          const char *expected_path)
{
    struct json_object *value = NULL;

    if (!response || !json_object_is_type(response, json_type_object))
        return 0;
    if (!json_object_object_get_ex(response, "ok", &value) ||
        !value || !json_object_get_boolean(value))
        return 0;
    if (!use || !json_object_object_get_ex(response, "use", &value) || !value ||
        strcmp(json_object_get_string(value), use) != 0)
        return 0;
    if (!phase || !json_object_object_get_ex(response, "phase", &value) || !value ||
        strcmp(json_object_get_string(value), phase) != 0)
        return 0;
    if (expected_path && expected_path[0]) {
        if (!json_object_object_get_ex(response, "active_path", &value) || !value ||
            strcmp(json_object_get_string(value), expected_path) != 0)
            return 0;
    }
    return 1;
}

static int storage_supervisor_call(const char *object, const char *method,
                                   struct json_object *params,
                                   const char *use, const char *phase)
{
    struct storage_supervisor_call call = {0};
    struct blob_buf request = {};
    uint32_t object_id = 0;
    const char *payload;
    const char *expected_path = NULL;
    struct json_object *expected_path_obj = NULL;
    int rc;

    if (!g_supervisor_ctx || !object || !method || !use || !phase)
        return -1;
    if ((!strcmp(method, "storage_reopen") ||
         !strcmp(method, "storage_lifecycle_status")) && params &&
        json_object_object_get_ex(params, "new_path", &expected_path_obj) &&
        expected_path_obj)
        expected_path = json_object_get_string(expected_path_obj);
    rc = ubus_lookup_id(g_supervisor_ctx, object, &object_id);
    if (rc != UBUS_STATUS_OK)
        return -1;
    blob_buf_init(&request, 0);
    payload = params ? json_object_to_json_string_ext(params,
                                                       JSON_C_TO_STRING_PLAIN) : "{}";
    if (!blobmsg_add_json_from_string(&request, payload)) {
        blob_buf_free(&request);
        return -1;
    }
    rc = ubus_invoke(g_supervisor_ctx, object_id, method, request.head,
                     storage_supervisor_reply_cb, &call,
                     STORAGE_SUPERVISOR_TIMEOUT_MS);
    blob_buf_free(&request);
    if (rc != UBUS_STATUS_OK ||
        !storage_supervisor_response_ok(call.response, use, phase, expected_path))
        rc = -1;
    else
        rc = 0;
    if (call.response)
        json_object_put(call.response);
    return rc;
}

static const char *storage_supervisor_object(const char *use)
{
    if (!strcmp(use, "audit"))
        return "jmx_audit";
    if (!strcmp(use, "aegis"))
        return "dreamingwrt.aegis";
    if (!strcmp(use, "log"))
        return "dreamingwrt.logd";
    return NULL;
}

static struct json_object *storage_supervisor_request(const char *use,
                                                      const char *old_path,
                                                      const char *new_path)
{
    struct json_object *request = json_object_new_object();

    if (!request)
        return NULL;
    json_object_object_add(request, "use", json_object_new_string(use ? use : ""));
    if (old_path)
        json_object_object_add(request, "old_path", json_object_new_string(old_path));
    if (new_path)
        json_object_object_add(request, "new_path", json_object_new_string(new_path));
    return request;
}

static int storage_supervisor_freeze(const char *use, void *arg)
{
    const char *object;
    struct json_object *request;
    int rc;

    (void)arg;
    if (!use)
        return -1;
    if (!strcmp(use, "snapshots")) {
        if (g_snapshot_frozen)
            return -1;
        {
            char active_path[PATH_MAX] = "";
            storage_supervisor_snapshot_state_read(active_path, sizeof(active_path));
            if (storage_supervisor_write_snapshot_state(active_path, 1) != 0)
                return -1;
        }
        g_snapshot_frozen = 1;
        return 0;
    }
    object = storage_supervisor_object(use);
    request = storage_supervisor_request(use, NULL, NULL);
    rc = object && request ? storage_supervisor_call(object, "storage_freeze",
                                                       request, use, "freeze") : -1;
    if (request)
        json_object_put(request);
    return rc;
}

static int storage_supervisor_unfreeze(const char *use, void *arg)
{
    const char *object;
    struct json_object *request;
    int rc;

    (void)arg;
    if (!use)
        return -1;
    if (!strcmp(use, "snapshots")) {
        if (!g_snapshot_frozen)
            return -1;
        {
            char active_path[PATH_MAX] = "";
            storage_supervisor_snapshot_state_read(active_path, sizeof(active_path));
            if (storage_supervisor_write_snapshot_state(active_path, 0) != 0)
                return -1;
        }
        g_snapshot_frozen = 0;
        g_binding_backup.valid = 0;
        return 0;
    }
    object = storage_supervisor_object(use);
    request = storage_supervisor_request(use, NULL, NULL);
    rc = object && request ? storage_supervisor_call(object, "storage_unfreeze",
                                                       request, use, "unfreeze") : -1;
    if (request)
        json_object_put(request);
    if (rc == 0)
        g_binding_backup.valid = 0;
    return rc;
}

static int storage_supervisor_reopen(const char *use, const char *old_path,
                                     const char *new_path, void *arg)
{
    const char *object;
    struct json_object *request;
    int rc;

    (void)arg;
    if (!use || !old_path || !new_path)
        return -1;
    {
        int rollback = storage_supervisor_is_rollback(use, old_path, new_path);
        const char *provider = jmx_storage_migration_current_provider();
        int external = !rollback && provider && provider[0] &&
                       strcmp(provider, "local");
        const char *persist_path = external ? new_path : "";
        const char *persist_provider = external ? provider : "";
        const char *persist_state = external ? "external" : "local_default";
        const char *persist_reason = external ? "migrated" : "rollback_to_local";

        if (!rollback && !g_binding_backup.valid &&
            storage_supervisor_capture_binding(use, old_path, new_path) != 0)
            return -1;

        if (!strcmp(use, "snapshots")) {
            if (!g_snapshot_frozen)
                return -1;
            if (rollback)
                return storage_supervisor_restore_binding(use);
            if (storage_supervisor_write_snapshot_state(persist_path, 1) != 0)
                return -1;
            rc = jmx_storage_binding_write(use, persist_provider, persist_path,
                                           persist_state, persist_reason, external);
            if (rc != 0)
                return -1;
            return 0;
        }
        object = storage_supervisor_object(use);
        request = storage_supervisor_request(use, old_path, new_path);
        rc = object && request ? storage_supervisor_call(object, "storage_reopen",
                                                           request, use, "reopen") : -1;
        if (request)
            json_object_put(request);
        if (rc == 0 && rollback)
            rc = storage_supervisor_restore_binding(use);
        else if (rc == 0)
            rc = jmx_storage_binding_write(use, persist_provider, persist_path,
                                           persist_state, persist_reason, external);
        return rc;
    }
}

int jmx_storage_supervisor_bind(struct ubus_context *ctx)
{
    if (!ctx)
        return -1;
    {
        char active_path[PATH_MAX] = "";
        char provider_id[128] = "";
        if (storage_supervisor_assignment_read("snapshots", provider_id,
                                               sizeof(provider_id), active_path,
                                               sizeof(active_path)) != 0)
            return -1;
        if (!active_path[0])
            storage_supervisor_snapshot_state_read(active_path, sizeof(active_path));
        if (storage_supervisor_write_snapshot_state(active_path, 0) != 0)
            return -1;
    }
    g_supervisor_ctx = ctx;
    g_snapshot_frozen = 0;
    jmx_storage_migration_set_consumer_reopen_hook(storage_supervisor_reopen, NULL);
    jmx_storage_migration_set_consumer_freeze_hooks(storage_supervisor_freeze,
                                                    storage_supervisor_unfreeze,
                                                    NULL);
    return 0;
}

void jmx_storage_supervisor_unbind(void)
{
    g_supervisor_ctx = NULL;
    g_snapshot_frozen = 0;
    {
        char active_path[PATH_MAX] = "";
        storage_supervisor_snapshot_state_read(active_path, sizeof(active_path));
        (void)storage_supervisor_write_snapshot_state(active_path, 0);
    }
    jmx_storage_migration_set_consumer_reopen_hook(NULL, NULL);
    jmx_storage_migration_set_consumer_freeze_hooks(NULL, NULL, NULL);
}

int jmx_storage_supervisor_ready(void)
{
    static const char *const objects[] = {
        "jmx_audit", "dreamingwrt.aegis", "dreamingwrt.logd"
    };
    size_t i;
    uint32_t id;
    struct json_object *request;

    if (!g_supervisor_ctx)
        return 0;
    {
        FILE *state = fopen(STORAGE_SNAPSHOT_STATE_PATH, "re");
        char line[256];

        if (state) {
            while (fgets(line, sizeof(line), state)) {
                if (!strncmp(line, "frozen=1", 8)) {
                    fclose(state);
                    return 0;
                }
            }
            fclose(state);
        }
    }
    {
        static const char *const uses[] = { "audit", "aegis", "log", "snapshots" };
        size_t u;
        for (u = 0; u < sizeof(uses) / sizeof(uses[0]); u++) {
            char provider_id[128] = "";
            char active_path[PATH_MAX] = "";
            if (storage_supervisor_assignment_read(uses[u], provider_id,
                                                   sizeof(provider_id), active_path,
                                                   sizeof(active_path)) != 0)
                return 0;
            if (active_path[0]) {
                struct stat st;
                if (stat(active_path, &st) != 0 ||
                    ( (!strcmp(uses[u], "audit") || !strcmp(uses[u], "snapshots"))
                      ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) ||
                    access(active_path, R_OK | W_OK) != 0)
                    return 0;
            }
        }
    }
    {
        static const char *const uses[] = { "audit", "aegis", "log" };
        static const char *const objects[] = {
            "jmx_audit", "dreamingwrt.aegis", "dreamingwrt.logd"
        };
        size_t i;
        uint32_t id;
        struct json_object *request;
        for (i = 0; i < sizeof(objects) / sizeof(objects[0]); i++) {
            char provider_id[128] = "";
            char active_path[PATH_MAX] = "";
            if (storage_supervisor_assignment_read(uses[i], provider_id,
                                                   sizeof(provider_id), active_path,
                                                   sizeof(active_path)) != 0)
                return 0;
            id = 0;
            if (ubus_lookup_id(g_supervisor_ctx, objects[i], &id) != UBUS_STATUS_OK)
                return 0;
            request = storage_supervisor_request(uses[i], NULL,
                                                 active_path[0] ? active_path : NULL);
            if (!request || storage_supervisor_call(objects[i],
                                                    "storage_lifecycle_status",
                                                    request, uses[i], "status") != 0) {
                if (request)
                    json_object_put(request);
                return 0;
            }
            json_object_put(request);
        }
        return 1;
    }
}
