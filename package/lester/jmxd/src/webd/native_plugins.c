// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "native_plugins.h"
#include "webd_http.h"

#define NATIVE_PLUGIN_ROOT "/usr/share/dreamingwrt/native-plugins"
#define NATIVE_MANIFEST_MAX (64 * 1024)
#define NATIVE_PROXY_BODY_MAX (1024 * 1024)
#define NATIVE_PROXY_RESPONSE_MAX (4 * 1024 * 1024)
#define NATIVE_PROXY_CONNECT_MS 1000
#define NATIVE_PROXY_IO_MS 15000

static int safe_token(const char *value, size_t max_len)
{
    const unsigned char *p;

    if (!value || !value[0] || strlen(value) > max_len)
        return 0;
    for (p = (const unsigned char *)value; *p; p++) {
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-'))
            return 0;
    }
    return 1;
}

static int safe_text(const char *value, size_t max_len)
{
    const unsigned char *p;

    if (!value || !value[0] || strlen(value) > max_len)
        return 0;
    for (p = (const unsigned char *)value; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

static int safe_resource(const char *value, const char *prefix, const char *suffix)
{
    size_t len;
    const unsigned char *p;

    if (!value || !prefix || !suffix || strncmp(value, prefix, strlen(prefix)) ||
        strstr(value, "..") || strchr(value, '\\') || strchr(value, '?') || strchr(value, '#'))
        return 0;
    len = strlen(value);
    if (len <= strlen(prefix) + strlen(suffix) || len > 256 ||
        strcmp(value + len - strlen(suffix), suffix))
        return 0;
    for (p = (const unsigned char *)value; *p; p++) {
        if (!(isalnum(*p) || *p == '/' || *p == '.' || *p == '_' || *p == '-' || *p == '~'))
            return 0;
    }
    return 1;
}

static int safe_query(const char *query)
{
    const unsigned char *p;

    if (!query || !query[0])
        return 1;
    if (strlen(query) > 512)
        return 0;
    for (p = (const unsigned char *)query; *p; p++)
        if (*p < 0x21 || *p == 0x7f)
            return 0;
    return 1;
}

static int safe_header_value(const char *value, size_t max_len)
{
    const unsigned char *p;

    if (!value || strlen(value) > max_len)
        return 0;
    for (p = (const unsigned char *)value; *p; p++)
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    return 1;
}

static int safe_proxy_method(const char *method)
{
    return method && (!strcmp(method, "GET") || !strcmp(method, "HEAD") ||
                      !strcmp(method, "POST") || !strcmp(method, "PUT") ||
                      !strcmp(method, "PATCH") || !strcmp(method, "DELETE"));
}

static int safe_proxy_suffix(const char *suffix)
{
    const unsigned char *p;

    if (!suffix || suffix[0] != '/' || strlen(suffix) > 512 ||
        strstr(suffix, "..") || strchr(suffix, '\\') ||
        strchr(suffix, '?') || strchr(suffix, '#'))
        return 0;
    for (p = (const unsigned char *)suffix; *p; p++)
        if (*p < 0x21 || *p == 0x7f)
            return 0;
    return 1;
}

static int path_has_segment(const char *path, const char *segment)
{
    size_t len;
    const char *p;

    if (!path || !segment || !(len = strlen(segment)))
        return 0;
    for (p = path; (p = strchr(p, '/')) != NULL; p++) {
        p++;
        if (!strncmp(p, segment, len) && (!p[len] || p[len] == '/'))
            return 1;
        if (!*p)
            break;
    }
    return 0;
}

/*
 * Prefix/exact helpers for the permission gate.
 *
 * These deliberately work on the plugin-relative suffix rather than the full
 * request path, because that is what the daemon's requiredPermission() sees.
 * Matching the full path would also match the plugin id itself: a plugin
 * literally named "nodes" would otherwise make every one of its routes look
 * node-scoped.
 */
static int native_path_equals(const char *suffix, const char *want)
{
    if (!suffix || !want)
        return 0;
    return !strcmp(suffix, want);
}

static int native_path_has_prefix(const char *suffix, const char *prefix)
{
    size_t len;

    if (!suffix || !prefix || !(len = strlen(prefix)))
        return 0;
    return !strncmp(suffix, prefix, len);
}

static int native_path_has_suffix(const char *suffix, const char *tail)
{
    size_t sl, tl;

    if (!suffix || !tail)
        return 0;
    sl = strlen(suffix);
    tl = strlen(tail);
    return sl >= tl && !strcmp(suffix + sl - tl, tail);
}

/* GET /nodes/... exposes node credentials; the daemon grades it secrets. */
static int native_path_is_node_scoped(const char *suffix)
{
    return native_path_has_prefix(suffix, "/nodes/");
}

/* The cached subscription payload contains node credentials. */
static int native_path_is_subscription_raw(const char *suffix)
{
    return native_path_has_prefix(suffix, "/subscriptions/") &&
           native_path_has_suffix(suffix, "/raw");
}

/* Any write under /data-plane/ swaps the running configuration. */
static int native_path_is_data_plane(const char *suffix)
{
    return native_path_has_prefix(suffix, "/data-plane/");
}

/*
 * A restore replaces the encrypted secret store together with the structured
 * state. Mirrors backupRestorePath() on the daemon side.
 */
/*
 * The shape is POST /backups/{id}/restore — exactly three segments, with a
 * resource id in the middle that may not contain a slash. Matching a looser
 * pattern such as "any path containing restore" would be wrong in both
 * directions: it would pull the operate-tier "restore" routes up into secrets,
 * and it would still miss nothing, since this is the only restore the daemon
 * grades as credential access.
 */
static int native_path_is_backup_restore(const char *method, const char *suffix)
{
    const char *id, *rest;
    size_t id_len;

    if (!method || strcmp(method, "POST") || !suffix)
        return 0;
    if (!native_path_has_prefix(suffix, "/backups/"))
        return 0;
    id = suffix + strlen("/backups/");
    rest = strchr(id, '/');
    if (!rest)
        return 0;
    id_len = (size_t)(rest - id);
    if (!id_len)
        return 0;
    return !strcmp(rest, "/restore");
}

/*
 * Writes under /nodes/ are credential access, except the probe family and
 * wan-policy, which the daemon lets the operate tier handle. Keeping the
 * exception list here rather than relying on segment order matters: "probe"
 * also appears in the operate list, and without this carve-out a node probe
 * would be graded secrets and refused for an operator.
 */
static int native_path_is_node_write_secret(const char *suffix)
{
    if (!native_path_has_prefix(suffix, "/nodes/"))
        return 0;
    if (native_path_has_suffix(suffix, "/probe") ||
        native_path_has_suffix(suffix, "/service-probe") ||
        native_path_has_suffix(suffix, "/profile-probe") ||
        native_path_has_suffix(suffix, "/ip-quality-probe") ||
        native_path_has_suffix(suffix, "/wan-policy"))
        return 0;
    return 1;
}

/*
 * Split "/api/v1/plugins/native/<id>[/<suffix>]" into the plugin id and the
 * remaining suffix. Returns 0 on success, -1 when the path does not name a
 * plugin.
 *
 * Both the permission gate and the proxy used to hardcode
 *   static const char prefix[] = WEBD_NATIVE_API_PREFIX "dreamingproxy";
 * and then derive the suffix as path + sizeof(prefix) - 1. That offset is a
 * compile-time constant tied to the length of "dreamingproxy" (13), so any
 * plugin with a different id length (adguardhome is 11) would have had its
 * suffix start two bytes past the right place. This helper exists so the two
 * call sites cannot disagree about where the id ends: if one accepted a path
 * and the other rejected it, the failure would surface as a confusing 502
 * rather than a clean 404.
 *
 * id_out is bounded and validated with safe_token(), which rejects '/' and any
 * character outside [A-Za-z0-9._-]. A caller therefore cannot smuggle a path
 * separator into the id and reach a socket or manifest outside the plugin root.
 * ".." alone would satisfy safe_token(), so it is rejected explicitly: the id is
 * interpolated into both a manifest path and a socket path.
 */
static int native_split_path(const char *path, char *id_out, size_t id_len,
                             const char **suffix_out)
{
    static const char api_prefix[] = WEBD_NATIVE_API_PREFIX;
    const size_t api_len = sizeof(api_prefix) - 1;
    const char *id_start;
    const char *end;
    size_t n;

    if (!path || !id_out || !id_len || !suffix_out)
        return -1;
    if (strncmp(path, api_prefix, api_len))
        return -1;
    id_start = path + api_len;
    end = strchr(id_start, '/');
    n = end ? (size_t)(end - id_start) : strlen(id_start);
    if (!n || n >= id_len)
        return -1;
    memcpy(id_out, id_start, n);
    id_out[n] = '\0';
    if (!safe_token(id_out, 64) || !strcmp(id_out, "..") || !strcmp(id_out, "."))
        return -1;
    *suffix_out = end ? end : "";
    return 0;
}


static const char *obj_string(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    if (!obj || !json_object_object_get_ex(obj, key, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static int manifest_valid(struct json_object *manifest, const char *directory_id)
{
    struct json_object *permissions = NULL;
    const char *id = obj_string(manifest, "id");
    const char *label = obj_string(manifest, "label");
    const char *path = obj_string(manifest, "path");
    const char *module = obj_string(manifest, "module");
    const char *style = obj_string(manifest, "style");
    const char *api_prefix = obj_string(manifest, "api_prefix");
    char expected_path[256];
    char expected_api[256];
    int i;

    if (!json_object_is_type(manifest, json_type_object) ||
        !safe_token(id, 64) || strcmp(id, directory_id) || !safe_text(label, 128) ||
        snprintf(expected_path, sizeof(expected_path), "/app/#/plugins/native/%s", id) >= (int)sizeof(expected_path) ||
        !path || strcmp(path, expected_path) ||
        !safe_resource(module, "native/", ".js") ||
        !safe_resource(style, "/static/css/", ".css") ||
        snprintf(expected_api, sizeof(expected_api), WEBD_NATIVE_API_PREFIX "%s", id) >= (int)sizeof(expected_api) ||
        !api_prefix || strcmp(api_prefix, expected_api))
        return 0;
    if (!json_object_object_get_ex(manifest, "permissions", &permissions) || !permissions ||
        !json_object_is_type(permissions, json_type_array) ||
        json_object_array_length(permissions) == 0 || json_object_array_length(permissions) > 16)
        return 0;
    for (i = 0; i < (int)json_object_array_length(permissions); i++) {
        const char *permission = json_object_get_string(json_object_array_get_idx(permissions, i));
        if (!permission || strncmp(permission, id, strlen(id)) || permission[strlen(id)] != '.' ||
            !safe_token(permission, 96))
            return 0;
    }
    return 1;
}

static struct json_object *read_manifest(const char *directory_id)
{
    char path[512];
    int fd;
    struct stat st;
    char *buf;
    ssize_t got;
    struct json_object *manifest;

    if (!safe_token(directory_id, 64) ||
        snprintf(path, sizeof(path), NATIVE_PLUGIN_ROOT "/%s/manifest.json", directory_id) >= (int)sizeof(path))
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > NATIVE_MANIFEST_MAX) {
        close(fd);
        return NULL;
    }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    got = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (got != st.st_size) {
        free(buf);
        return NULL;
    }
    buf[got] = '\0';
    manifest = json_tokener_parse(buf);
    free(buf);
    if (!manifest || !manifest_valid(manifest, directory_id)) {
        if (manifest)
            json_object_put(manifest);
        return NULL;
    }
    json_object_object_add(manifest, "installed", json_object_new_boolean(1));
    json_object_object_add(manifest, "enabled", json_object_new_boolean(1));
    json_object_object_add(manifest, "api_mode", json_object_new_string("native_unix_http"));
    json_object_object_add(manifest, "source", json_object_new_string("native_plugin_manifest"));
    {
        struct json_object *capabilities = json_object_new_object();
        json_object_object_add(capabilities, "json_proxy", json_object_new_boolean(1));
        json_object_object_add(capabilities, "sse_proxy", json_object_new_boolean(0));
        json_object_object_add(capabilities, "websocket_proxy", json_object_new_boolean(0));
        json_object_object_add(capabilities, "file_upload", json_object_new_boolean(0));
        json_object_object_add(capabilities, "stream_download", json_object_new_boolean(0));
        json_object_object_add(manifest, "capabilities", capabilities);
    }
    return manifest;
}

/*
 * A path only names a plugin if that plugin is actually installed with a valid
 * manifest. Without this check the permission gate would accept any well-formed
 * id and the proxy would then try to connect to /var/run/<id>/<id>.sock, turning
 * a typo or a probe into a 502 instead of a clean 404.
 */
static int native_plugin_installed(const char *plugin_id)
{
    struct json_object *manifest;

    if (!plugin_id || !plugin_id[0])
        return 0;
    manifest = read_manifest(plugin_id);
    if (!manifest)
        return 0;
    json_object_put(manifest);
    return 1;
}

struct json_object *webd_native_plugins_scan(void)
{
    struct json_object *plugins = json_object_new_array();
    DIR *dir = opendir(NATIVE_PLUGIN_ROOT);
    struct dirent *entry;

    if (!dir)
        return plugins;
    while ((entry = readdir(dir)) != NULL) {
        struct json_object *manifest;

        if (entry->d_name[0] == '.')
            continue;
        manifest = read_manifest(entry->d_name);
        if (manifest)
            json_object_array_add(plugins, manifest);
    }
    closedir(dir);
    return plugins;
}

static struct json_object *find_menu_group(struct json_object *items, const char *id)
{
    int i;

    if (!items || !json_object_is_type(items, json_type_array))
        return NULL;
    for (i = 0; i < (int)json_object_array_length(items); i++) {
        struct json_object *item = json_object_array_get_idx(items, i);
        struct json_object *children = NULL;
        const char *item_id = obj_string(item, "id");
        struct json_object *found;

        if (item_id && !strcmp(item_id, id))
            return item;
        if (json_object_object_get_ex(item, "children", &children)) {
            found = find_menu_group(children, id);
            if (found)
                return found;
        }
    }
    return NULL;
}

static int menu_has_id(struct json_object *items, const char *id)
{
    int i;

    if (!items || !id || !json_object_is_type(items, json_type_array))
        return 0;
    for (i = 0; i < (int)json_object_array_length(items); i++) {
        const char *old_id = obj_string(json_object_array_get_idx(items, i), "id");
        if (old_id && !strcmp(old_id, id))
            return 1;
    }
    return 0;
}

void webd_native_plugins_merge_menu(struct json_object *menu)
{
    struct json_object *items = NULL;
    struct json_object *group;
    struct json_object *children = NULL;
    struct json_object *plugins;
    int i;

    if (!menu || !json_object_object_get_ex(menu, "items", &items))
        return;
    group = find_menu_group(items, "native-plugins");
    if (!group)
        return;
    if (!json_object_object_get_ex(group, "children", &children) ||
        !json_object_is_type(children, json_type_array)) {
        children = json_object_new_array();
        json_object_object_add(group, "children", children);
    }
    plugins = webd_native_plugins_scan();
    for (i = 0; i < (int)json_object_array_length(plugins); i++) {
        struct json_object *manifest = json_object_array_get_idx(plugins, i);
        const char *id = obj_string(manifest, "id");
        const char *icon = obj_string(manifest, "icon");
        const char *module_version = obj_string(manifest, "module_version");
        const char *style_version = obj_string(manifest, "style_version");
        struct json_object *item;
        struct json_object *permissions = NULL;

        if (!id || menu_has_id(children, id))
            continue;
        item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_string(id));
        json_object_object_add(item, "func_name", json_object_new_string(id));
        json_object_object_add(item, "label", json_object_new_string(obj_string(manifest, "label")));
        json_object_object_add(item, "path", json_object_new_string(obj_string(manifest, "path")));
        json_object_object_add(item, "module", json_object_new_string(obj_string(manifest, "module")));
        json_object_object_add(item, "style", json_object_new_string(obj_string(manifest, "style")));
        json_object_object_add(item, "icon", json_object_new_string(icon ? icon : "plugin"));
        json_object_object_add(item, "module_version", json_object_new_string(module_version ? module_version : "1"));
        json_object_object_add(item, "style_version", json_object_new_string(style_version ? style_version : "1"));
        json_object_object_add(item, "plugin", json_object_get(manifest));
        if (json_object_object_get_ex(manifest, "permissions", &permissions) &&
            json_object_array_length(permissions) > 0)
            json_object_object_add(item, "permission",
                                   json_object_get(json_object_array_get_idx(permissions, 0)));
        json_object_array_add(children, item);
    }
    json_object_put(plugins);
}

const char *webd_native_required_permission(const char *method, const char *path)
{
    static __thread char permission[128];
    char plugin_id[80];
    const char *suffix = NULL;
    const char *action;

    /*
     * Previously this matched only the compiled-in "dreamingproxy" prefix and
     * returned NULL for every other plugin. The caller in jmx_app_api.c treats
     * NULL as "not a plugin route" and skips the proxy entirely, so a correctly
     * installed plugin such as adguardhome fell through to the plugin-detail
     * lookup and was reported as "native plugin is not registered" — a
     * misleading 404, since the plugin was registered and merely could not
     * obtain a required permission.
     */
    if (!method || native_split_path(path, plugin_id, sizeof(plugin_id), &suffix))
        return NULL;
    if (!native_plugin_installed(plugin_id))
        return NULL;

    /* Action classification is intentionally identical to the previous
     * dreamingproxy-only ordering, so existing permission grants keep their
     * exact meaning: secrets outrank apply, apply outranks operate, and
     * anything else that writes is "configure". */
    /*
     * The classification below mirrors requiredPermission() in
     * dreamingproxy/internal/api/api.go. The daemon is the authority; webd is
     * a pre-filter in front of it, so webd must never be stricter than the
     * daemon or a request the daemon would allow dies at 403 before reaching
     * it — and never looser in a way that turns a daemon refusal into a
     * confusing error class.
     *
     * That is exactly what had happened: webd's operate list held 5 segments
     * where the daemon's holds 17, so POST .../service/restart and
     * .../overview/egress/refresh were graded "configure". An App device is an
     * operator, operator does not carry configure, and every one of those
     * operations was refused by webd without the daemon ever seeing it.
     * restart was the worst of them: start and stop passed, restart did not.
     *
     * Keep the two lists in step. jmxd/tests/native_plugin_permission_parity_fixture.c
     * reads both files and fails when they diverge.
     */
    if (!strcmp(method, "GET") || !strcmp(method, "HEAD")) {
        /*
         * Credential-bearing reads. The daemon grades these "secrets"; webd
         * used to grade them "read", so it forwarded a request the daemon then
         * refused. Fail-closed either way, but the caller saw
         * permission_denied instead of plugin_permission_denied and the audit
         * record carried the wrong required_permission.
         */
        if (native_path_is_node_scoped(suffix) ||
            native_path_equals(suffix, "/data-plane/candidate") ||
            native_path_equals(suffix, "/data-plane/last-known-good") ||
            native_path_is_subscription_raw(suffix))
            action = "secrets";
        else
            action = (path_has_segment(path, "audit-events") ||
                      path_has_segment(path, "diagnostics")) ? "audit" : "read";
    } else if (native_path_is_data_plane(suffix)) {
        /* Any write below /data-plane/ swaps the running configuration. */
        action = "apply";
    } else if (native_path_is_backup_restore(method, suffix)) {
        /*
         * A full restore replaces the encrypted secret store along with the
         * structured state, so it is credential access rather than routine
         * maintenance. Ordered before the operate list on purpose: "restore"
         * appears in both, and the daemon resolves it as secrets.
         */
        action = "secrets";
    } else if (native_path_is_node_write_secret(suffix)) {
        /* Writes under /nodes/ carry node credentials, except the probe
         * variants and wan-policy which the daemon lets operate handle. */
        action = "secrets";
    } else if (path_has_segment(path, "secret") ||
               path_has_segment(path, "secrets") ||
               path_has_segment(path, "credentials")) {
        action = "secrets";
    } else if (path_has_segment(path, "apply") ||
               path_has_segment(path, "rollback")) {
        action = "apply";
    } else if (path_has_segment(path, "simulate")) {
        /* Simulation only explains the compiled rule order; it mutates
         * nothing, and the daemon grades it read. */
        action = "read";
    } else if (path_has_segment(path, "probe") ||
               path_has_segment(path, "service-probe") ||
               path_has_segment(path, "profile-probe") ||
               path_has_segment(path, "probe-profile-batch") ||
               path_has_segment(path, "ip-quality-probe") ||
               path_has_segment(path, "failover-preflight") ||
               path_has_segment(path, "select") ||
               path_has_segment(path, "probe-jobs") ||
               path_has_segment(path, "ip-quality-probe-jobs") ||
               path_has_segment(path, "refresh") ||
               path_has_segment(path, "restore") ||
               path_has_segment(path, "connections") ||
               path_has_segment(path, "connection-history") ||
               path_has_segment(path, "start") ||
               path_has_segment(path, "stop") ||
               path_has_segment(path, "restart") ||
               path_has_segment(path, "update")) {
        action = "operate";
    } else {
        action = "configure";
    }
    if (snprintf(permission, sizeof(permission), "%s.%s", plugin_id, action) >=
        (int)sizeof(permission))
        return NULL;
    return permission;
}

/*
 * True when a permission names a read-only action. Used for audit risk grading
 * so it follows the action suffix rather than any particular plugin name.
 */
int webd_native_permission_is_readonly(const char *permission)
{
    const char *dot;

    if (!permission || !permission[0])
        return 0;
    dot = strrchr(permission, '.');
    if (!dot || !dot[1])
        return 0;
    return !strcmp(dot + 1, "read");
}

/*
 * Best-effort socket path for the plugin named by a request path, so an error
 * response can point at the file that actually failed to answer.
 */
int webd_native_socket_hint(const char *path, char *out, size_t out_len)
{
    char plugin_id[80];
    const char *suffix = NULL;

    if (!out || !out_len)
        return -1;
    if (native_split_path(path, plugin_id, sizeof(plugin_id), &suffix))
        return -1;
    if (snprintf(out, out_len, "/var/run/%s/%s.sock", plugin_id, plugin_id) >=
        (int)out_len)
        return -1;
    return 0;
}

static int wait_fd(int fd, short events, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = events };
    int rc;

    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    return rc > 0 && (pfd.revents & events) ? 0 : -1;
}

static int wait_fd_read(int fd, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc;

    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0 || (pfd.revents & (POLLERR | POLLNVAL)))
        return -1;
    return (pfd.revents & (POLLIN | POLLHUP)) ? 0 : -1;
}

static int connect_unix(const char *socket_path)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    int rc;

    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path) >= (int)sizeof(addr.sun_path)) {
        close(fd);
        return -1;
    }
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc && wait_fd(fd, POLLOUT, NATIVE_PROXY_CONNECT_MS)) {
        close(fd);
        return -1;
    }
    if (rc) {
        int socket_error = 0;
        socklen_t socket_error_len = sizeof(socket_error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len) || socket_error) {
            close(fd);
            return -1;
        }
    }
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int write_all_timeout(int fd, const void *data, size_t len)
{
    const char *p = data;
    size_t off = 0;

    while (off < len) {
        ssize_t n;
        if (wait_fd(fd, POLLOUT, NATIVE_PROXY_IO_MS))
            return -1;
        n = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static int append_permissions(char *out, size_t out_len, struct json_object *permissions)
{
    size_t used = 0;
    int i;

    if (!out || !out_len)
        return -1;
    out[0] = '\0';
    if (!permissions || !json_object_is_type(permissions, json_type_array))
        return 0;
    for (i = 0; i < (int)json_object_array_length(permissions); i++) {
        const char *permission = json_object_get_string(json_object_array_get_idx(permissions, i));
        int n;
        if (!permission || !safe_token(permission, 96))
            continue;
        n = snprintf(out + used, out_len - used, "%s%s", used ? "," : "", permission);
        if (n < 0 || (size_t)n >= out_len - used)
            return -1;
        used += (size_t)n;
    }
    return 0;
}

static int decode_chunked(const char *src, size_t src_len, char **out, size_t *out_len)
{
    size_t pos = 0, used = 0;
    char *decoded = malloc(src_len + 1);

    if (!decoded)
        return -1;
    while (pos < src_len) {
        char *end = NULL;
        unsigned long chunk;
        const char *line_end = memchr(src + pos, '\n', src_len - pos);
        char size_buf[32];
        size_t line_len;

        if (!line_end || line_end == src + pos || line_end[-1] != '\r')
            goto fail;
        line_len = (size_t)(line_end - (src + pos) - 1);
        if (!line_len || line_len >= sizeof(size_buf))
            goto fail;
        memcpy(size_buf, src + pos, line_len);
        size_buf[line_len] = '\0';
        if (!isxdigit((unsigned char)size_buf[0]))
            goto fail;
        errno = 0;
        chunk = strtoul(size_buf, &end, 16);
        if (errno || !end || (*end && *end != ';'))
            goto fail;
        pos = (size_t)(line_end - src) + 1;
        if (chunk == 0) {
            for (;;) {
                const char *trailer_end = memchr(src + pos, '\n', src_len - pos);
                const char *p;

                if (!trailer_end || trailer_end == src + pos || trailer_end[-1] != '\r')
                    goto fail;
                line_len = (size_t)(trailer_end - (src + pos) - 1);
                if (!line_len) {
                    pos = (size_t)(trailer_end - src) + 1;
                    if (pos != src_len)
                        goto fail;
                    decoded[used] = '\0';
                    *out = decoded;
                    *out_len = used;
                    return 0;
                }
                if (!memchr(src + pos, ':', line_len))
                    goto fail;
                for (p = src + pos; p < trailer_end - 1; p++)
                    if (((unsigned char)*p < 0x20 && *p != '\t') || *p == 0x7f)
                        goto fail;
                pos = (size_t)(trailer_end - src) + 1;
            }
        }
        if (chunk > src_len - pos || used + chunk > NATIVE_PROXY_RESPONSE_MAX)
            goto fail;
        memcpy(decoded + used, src + pos, chunk);
        used += chunk;
        pos += chunk;
        if (pos + 2 > src_len || src[pos] != '\r' || src[pos + 1] != '\n')
            goto fail;
        pos += 2;
    }
fail:
    free(decoded);
    return -1;
}

static int json_content_type(const char *content_type)
{
    static const char json[] = "application/json";
    static const char problem[] = "application/problem+json";
    size_t len;

    if (!content_type)
        return 0;
    len = strlen(json);
    if (!strncasecmp(content_type, json, len) &&
        (!content_type[len] || content_type[len] == ';'))
        return 1;
    len = strlen(problem);
    return !strncasecmp(content_type, problem, len) &&
           (!content_type[len] || content_type[len] == ';');
}

static int valid_json_body(const char *body, size_t body_len)
{
    struct json_tokener *tok;
    struct json_object *parsed;
    enum json_tokener_error error;
    size_t parsed_len;

    if (!body || !body_len || body_len > INT_MAX)
        return 0;
    tok = json_tokener_new();
    if (!tok)
        return 0;
    parsed = json_tokener_parse_ex(tok, body, (int)body_len);
    error = json_tokener_get_error(tok);
    parsed_len = json_tokener_get_parse_end(tok);
    while (parsed_len < body_len && isspace((unsigned char)body[parsed_len]))
        parsed_len++;
    json_tokener_free(tok);
    if (parsed)
        json_object_put(parsed);
    return parsed && error == json_tokener_success && parsed_len == body_len;
}

static int relay_response(int client_fd, const char *method, char *response, size_t response_len)
{
    char *headers_end = response_len ? strstr(response, "\r\n\r\n") : NULL;
    char content_type[128] = "application/json; charset=utf-8";
    int status = 502;
    int chunked = 0;
    int have_transfer_encoding = 0;
    int have_content_type = 0;
    int have_content_length = 0;
    unsigned long long content_length = 0;
    char *body;
    size_t body_len;
    char *decoded = NULL;
    char *line;

    if (!headers_end || sscanf(response, "HTTP/%*s %d", &status) != 1 || status < 200 || status > 599)
        return -1;
    *headers_end = '\0';
    for (line = strstr(response, "\r\n"); line; ) {
        char *next = strstr(line + 2, "\r\n");
        char *value;
        line += 2;
        if (!*line)
            break;
        if (!strncasecmp(line, "Content-Type:", 13)) {
            size_t len;
            value = line + 13;
            while (*value == ' ' || *value == '\t') value++;
            len = next ? (size_t)(next - value) : strlen(value);
            if (have_content_type || len >= sizeof(content_type))
                return -1;
            memcpy(content_type, value, len);
            content_type[len] = '\0';
            have_content_type = 1;
        } else if (!strncasecmp(line, "Transfer-Encoding:", 18)) {
            char transfer_encoding[32];
            size_t len;

            value = line + 18;
            while (*value == ' ' || *value == '\t') value++;
            len = next ? (size_t)(next - value) : strlen(value);
            while (len && (value[len - 1] == ' ' || value[len - 1] == '\t')) len--;
            if (have_transfer_encoding || !len || len >= sizeof(transfer_encoding))
                return -1;
            memcpy(transfer_encoding, value, len);
            transfer_encoding[len] = '\0';
            if (strcasecmp(transfer_encoding, "chunked"))
                return -1;
            have_transfer_encoding = 1;
            chunked = 1;
        } else if (!strncasecmp(line, "Content-Length:", 15)) {
            char *end = NULL;
            char *field_end = next ? next : line + strlen(line);
            unsigned long long parsed_length;

            value = line + 15;
            while (*value == ' ' || *value == '\t') value++;
            errno = 0;
            parsed_length = strtoull(value, &end, 10);
            while (end < field_end && (*end == ' ' || *end == '\t')) end++;
            if (errno || end == value || end != field_end ||
                parsed_length > NATIVE_PROXY_RESPONSE_MAX ||
                (have_content_length && parsed_length != content_length))
                return -1;
            content_length = parsed_length;
            have_content_length = 1;
        }
        line = next;
    }
    body = headers_end + 4;
    body_len = response_len - (size_t)(body - response);
    if ((!strcmp(method, "HEAD") && body_len) ||
        (status == 204 && (body_len || chunked || (have_content_length && content_length))))
        return -1;
    if (chunked && have_content_length)
        return -1;
    if (chunked) {
        if (decode_chunked(body, body_len, &decoded, &body_len))
            return -1;
        body = decoded;
    } else if (have_content_length && strcmp(method, "HEAD") && status != 204 &&
               content_length != body_len) {
        return -1;
    }
    if ((status != 204 && (!have_content_type || !json_content_type(content_type))) ||
        (strcmp(method, "HEAD") && status != 204 && !valid_json_body(body, body_len))) {
        free(decoded);
        return -1;
    }
    if (!strcmp(method, "HEAD") || status == 204)
        body_len = 0;
    status = http_send_raw(client_fd, status, content_type, body, body_len, "no-store");
    free(decoded);
    return status;
}

int webd_native_proxy_json(int client_fd,
                           const char *method,
                           const char *path,
                           const char *query,
                           const void *body,
                           size_t body_len,
                           const char *actor,
                           const char *client_ip,
                           const char *request_id,
                           struct json_object *permissions)
{
    char plugin_id[80];
    const char *suffix = NULL;
    char socket_path[256];
    char upstream_path[768];
    char permission_header[1024];
    char header[3072];
    char *response = NULL;
    size_t response_len = 0, capacity = 0;
    int fd = -1;
    int hlen;
    int rc = -1;

    /*
     * The id is parsed from the path instead of being compiled in. Deriving the
     * suffix from the parsed id length is the whole point: the old code used
     * sizeof(prefix) - 1, a constant sized for "dreamingproxy", so a shorter id
     * such as "adguardhome" would have started the suffix two bytes late and
     * silently returned -1, which the caller reports as a 502.
     */
    if (!safe_proxy_method(method) || !path || body_len > NATIVE_PROXY_BODY_MAX ||
        (body_len && (!body || !valid_json_body(body, body_len))) ||
        native_split_path(path, plugin_id, sizeof(plugin_id), &suffix) ||
        !native_plugin_installed(plugin_id))
        return -1;
    if (*suffix && *suffix != '/')
        return -1;
    if (!*suffix)
        suffix = "/";
    if (!safe_proxy_suffix(suffix) || !safe_query(query) ||
        !safe_header_value(actor ? actor : "", 256) ||
        !safe_header_value(client_ip ? client_ip : "", 64) ||
        !safe_header_value(request_id ? request_id : "", 64) ||
        snprintf(socket_path, sizeof(socket_path), "/var/run/%s/%s.sock", plugin_id, plugin_id) >= (int)sizeof(socket_path) ||
        snprintf(upstream_path, sizeof(upstream_path), WEBD_NATIVE_API_PREFIX "%s%s%s%s",
                 plugin_id, suffix, query && query[0] ? "?" : "", query && query[0] ? query : "") >= (int)sizeof(upstream_path) ||
        append_permissions(permission_header, sizeof(permission_header), permissions))
        return -1;
    fd = connect_unix(socket_path);
    if (fd < 0)
        return -2;
    hlen = snprintf(header, sizeof(header),
                    "%s %s HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Content-Type: application/json\r\n"
                    "Accept: application/json\r\n"
                    "Content-Length: %llu\r\n"
                    "Connection: close\r\n"
                    "X-Request-ID: %s\r\n"
                    "X-DreamingWrt-Actor: %s\r\n"
                    "X-DreamingWrt-Permissions: %s\r\n"
                    "X-Forwarded-For: %s\r\n\r\n",
                    method, upstream_path, (unsigned long long)body_len,
                    request_id ? request_id : "", actor ? actor : "",
                    permission_header, client_ip ? client_ip : "");
    if (hlen <= 0 || hlen >= (int)sizeof(header) ||
        write_all_timeout(fd, header, (size_t)hlen) ||
        (body_len && write_all_timeout(fd, body, body_len)))
        goto done;
    for (;;) {
        ssize_t n;
        if (wait_fd_read(fd, NATIVE_PROXY_IO_MS))
            goto done;
        if (capacity - response_len < 8192) {
            size_t next = capacity ? capacity * 2 : 16384;
            char *grown;
            if (next > NATIVE_PROXY_RESPONSE_MAX + 1)
                next = NATIVE_PROXY_RESPONSE_MAX + 1;
            if (next <= capacity)
                goto done;
            grown = realloc(response, next);
            if (!grown)
                goto done;
            response = grown;
            capacity = next;
        }
        n = read(fd, response + response_len, capacity - response_len - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            goto done;
        if (n == 0)
            break;
        response_len += (size_t)n;
        if (response_len > NATIVE_PROXY_RESPONSE_MAX)
            goto done;
    }
    if (!response)
        goto done;
    response[response_len] = '\0';
    rc = relay_response(client_fd, method, response, response_len);
done:
    if (fd >= 0)
        close(fd);
    free(response);
    return rc;
}
