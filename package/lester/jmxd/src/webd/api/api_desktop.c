// SPDX-License-Identifier: GPL-2.0-or-later
/* Installed application projection. Never infers installation from a menu,
 * contacts a catalog, starts a daemon or reads application config into output. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "api_desktop.h"
#include "../native_plugins.h"

#ifndef DESKTOP_PUBLIC_ROOT
#define DESKTOP_PUBLIC_ROOT "/www/dreamingwrt"
#endif
#ifndef DESKTOP_APPSTORE_REGISTRY
#define DESKTOP_APPSTORE_REGISTRY "/etc/dreamingwrt/appstore/registry"
#endif
#ifndef DESKTOP_APPSTORE_APPS
#define DESKTOP_APPSTORE_APPS "/overlay/dreamingos-appstore/apps"
#endif
#define DESKTOP_REGISTRY_MAX (256 * 1024)

static const char *desktop_string(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) &&
        json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
}
static struct json_object *desktop_object(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) &&
        json_object_is_type(v, json_type_object) ? v : NULL;
}
static void desktop_text(struct json_object *o, const char *key, const char *text)
{
    json_object_object_add(o, key, text ? json_object_new_string(text) : NULL);
}
static int desktop_file(const char *path, int executable)
{
    struct stat st;
    return !stat(path, &st) && S_ISREG(st.st_mode) &&
        access(path, executable ? X_OK : R_OK) == 0;
}
static int desktop_token(const char *s, size_t max)
{
    if (!s[0] || strlen(s) > max || strstr(s, "..")) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.') return 0;
    return 1;
}
static int desktop_relative(const char *s)
{
    if (!s[0] || s[0] == '/' || strlen(s) > 256 || strstr(s, "..") || strstr(s, "//")) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (!isalnum(*p) && *p != '/' && *p != '-' && *p != '_' && *p != '.') return 0;
    return 1;
}
static struct json_object *desktop_app(const char *id, const char *name,
    const char *source, const char *entry, const char *icon, int core,
    int installed, int launch, int read, const char *reason)
{
    struct json_object *o = json_object_new_object();
    struct json_object *cap = json_object_new_object(), *perm = json_object_new_object();
    desktop_text(o, "id", id);
    desktop_text(o, "name", name);
    desktop_text(o, "source", source);
    desktop_text(o, "entry", entry);
    desktop_text(o, "icon", icon);
    json_object_object_add(o, "core", json_object_new_boolean(core));
    json_object_object_add(o, "installed", json_object_new_boolean(installed));
    json_object_object_add(cap, "launch", json_object_new_boolean(launch));
    if (!launch) desktop_text(cap, "reason", reason);
    json_object_object_add(perm, "read", json_object_new_boolean(read));
    if (!read) desktop_text(perm, "reason", "read_permission_not_declared");
    json_object_object_add(o, "capabilities", cap);
    json_object_object_add(o, "permissions", perm);
    json_object_object_add(o, "entitlement", NULL);
    return o;
}
/* No per-application entitlement verifier is registered on the device yet.
 * Package metadata is a declaration, never evidence of a valid license.
 * Optional future licensed apps are explicit unavailable; core never calls this. */
static void desktop_entitlement(struct json_object *app, struct json_object *manifest)
{
    struct json_object *declared = NULL;
    if (!json_object_object_get_ex(manifest, "entitlement", &declared) || !declared) return;
    struct json_object *e = json_object_new_object();
    json_object_object_add(e, "required", json_object_new_boolean(1));
    desktop_text(e, "state", "unavailable");
    desktop_text(e, "reason", "entitlement_source_unavailable");
    json_object_object_add(app, "entitlement", e);
    struct json_object *cap = desktop_object(app, "capabilities");
    json_object_object_add(cap, "launch", json_object_new_boolean(0));
    desktop_text(cap, "reason", "entitlement_source_unavailable");
}
static void desktop_native_apps(struct json_object *apps, int *errors)
{
    struct json_object *plugins = webd_native_plugins_scan_checked(errors);
    for (size_t i = 0; i < json_object_array_length(plugins); i++) {
        struct json_object *m = json_object_array_get_idx(plugins, i), *p = NULL;
        const char *id = desktop_string(m, "id");
        char app_id[80], path[768], permission[96];
        snprintf(app_id, sizeof(app_id), "native.%s", id);
        snprintf(permission, sizeof(permission), "%s.read", id);
        int read = 0;
        json_object_object_get_ex(m, "permissions", &p);
        for (size_t n = 0; n < json_object_array_length(p); n++)
            if (!strcmp(json_object_get_string(json_object_array_get_idx(p, n)), permission)) read = 1;
        /* Native read is granted to every authenticated role by
         * webd_native_permissions; writes remain independently authorized. */
        snprintf(path, sizeof(path), "%s/app/index.html", DESKTOP_PUBLIC_ROOT);
        int ready = desktop_file(path, 0);
        snprintf(path, sizeof(path), "%s/plugins/%s", DESKTOP_PUBLIC_ROOT, desktop_string(m, "module"));
        ready = ready && desktop_file(path, 0);
        snprintf(path, sizeof(path), "%s%s", DESKTOP_PUBLIC_ROOT, desktop_string(m, "style"));
        ready = ready && desktop_file(path, 0);
        const char *icon = desktop_string(m, "icon");
        struct json_object *app = desktop_app(app_id, desktop_string(m, "label"),
            "native_plugin_manifest", desktop_string(m, "path"), icon[0] ? icon : "plugin",
            0, 1, ready, read, "entry_assets_missing");
        desktop_text(app, "source_id", id);
        desktop_entitlement(app, m);
        json_object_array_add(apps, app);
    }
    json_object_put(plugins);
}
static struct json_object *desktop_registry_read(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > DESKTOP_REGISTRY_MAX) {
        close(fd); return NULL;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    size_t n = 0;
    while (n < (size_t)st.st_size) {
        ssize_t got = read(fd, buf+n, (size_t)st.st_size-n);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        n += (size_t)got;
    }
    close(fd);
    buf[n] = 0;
    struct json_tokener *tok = json_tokener_new();
    struct json_object *o = n == (size_t)st.st_size ? json_tokener_parse_ex(tok, buf, (int)n) : NULL;
    size_t end = json_tokener_get_parse_end(tok);
    while (end < n && isspace((unsigned char)buf[end])) end++;
    if (json_tokener_get_error(tok) != json_tokener_success || end != n ||
        !json_object_is_type(o, json_type_object)) { json_object_put(o); o = NULL; }
    json_tokener_free(tok);
    free(buf);
    return o;
}
static int desktop_appstore_payload(struct json_object *reg, struct json_object *manifest, const char *id)
{
    const char *version = desktop_string(reg, "activeVersionDir");
    const char *exe = desktop_string(desktop_object(manifest, "service"), "executable");
    char path[1024], target[128];
    if (!desktop_token(version, 120) || !desktop_relative(exe)) return 0;
    snprintf(path, sizeof(path), "%s/%s/current", DESKTOP_APPSTORE_APPS, id);
    ssize_t n = readlink(path, target, sizeof(target)-1);
    if (n < 0) return 0;
    target[n] = 0;
    if (strcmp(target, version)) return 0;
    snprintf(path, sizeof(path), "%s/%s/current/%s", DESKTOP_APPSTORE_APPS, id, exe);
    return desktop_file(path, 1);
}
/* Static /app files are the currently registered desktop surface. A daemon
 * port, external URL or API gateway is not an /app iframe entry. Directory
 * manifests normalize to their concrete index.html, which webd actually serves. */
static const char *desktop_appstore_entry(struct json_object *manifest, char *entry, size_t len)
{
    struct json_object *launch = desktop_object(manifest, "launch");
    const char *route = desktop_string(launch, "route");
    char path[768];
    if (strcmp(desktop_string(launch, "kind"), "web")) return "no_web_entry";
    if (strncmp(route, "/app/", 5) || !desktop_relative(route+5)) return "entry_not_registered";
    snprintf(entry, len, "%s%s", route, route[strlen(route)-1] == '/' ? "index.html" : "");
    snprintf(path, sizeof(path), "%s%s", DESKTOP_PUBLIC_ROOT, entry);
    return desktop_file(path, 0) ? NULL : "entry_assets_missing";
}
static void desktop_appstore_apps(struct json_object *apps, int *errors)
{
    DIR *dir = opendir(DESKTOP_APPSTORE_REGISTRY);
    if (!dir) { if (errno != ENOENT) (*errors)++; return; }
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) { if (errno) (*errors)++; break; }
        size_t len = strlen(de->d_name);
        if (de->d_name[0] == '.' || len < 6 || strcmp(de->d_name+len-5, ".json")) continue;
        char id[65], path[768], app_id[80], entry[320] = "";
        if (len-5 >= sizeof(id)) { (*errors)++; continue; }
        memcpy(id, de->d_name, len-5); id[len-5] = 0;
        int valid_id = 1;
        for (const char *p = id; *p; p++) if (!(*p >= 'a' && *p <= 'z') && !isdigit((unsigned char)*p) && *p != '-') valid_id = 0;
        if (!valid_id) { (*errors)++; continue; }
        snprintf(path, sizeof(path), "%s/%s", DESKTOP_APPSTORE_REGISTRY, de->d_name);
        struct json_object *reg = desktop_registry_read(path);
        struct json_object *manifest = desktop_object(reg, "manifest");
        if (!reg || strcmp(desktop_string(reg, "schema"), "dreamingos-appstore-registry/1") ||
            strcmp(desktop_string(reg, "appId"), id) || strcmp(desktop_string(reg, "installStatus"), "installed") ||
            !manifest || strcmp(desktop_string(manifest, "schema"), "dreamingos-app/1") ||
            strcmp(desktop_string(manifest, "id"), id)) {
            (*errors)++; json_object_put(reg); continue;
        }
        int installed = desktop_appstore_payload(reg, manifest, id);
        const char *reason = desktop_appstore_entry(manifest, entry, sizeof(entry));
        int launch = installed && !reason;
        if (!installed) reason = "package_files_missing";
        const char *name = desktop_string(manifest, "name"), *icon = desktop_string(manifest, "icon");
        snprintf(app_id, sizeof(app_id), "appstore.%s", id);
        struct json_object *app = desktop_app(app_id, name[0] ? name : id, "appstore_worker_registry",
            entry[0] ? entry : NULL, icon[0] ? icon : "plugin", 0, installed, launch, 1, reason);
        desktop_text(app, "source_id", id);
        desktop_text(app, "version", desktop_string(reg, "version"));
        desktop_entitlement(app, manifest);
        json_object_array_add(apps, app);
        json_object_put(reg);
    }
    closedir(dir);
}
static struct json_object *desktop_error(const char *code, const char *message)
{
    struct json_object *e = json_object_new_object();
    desktop_text(e, "code", code);
    desktop_text(e, "message", message);
    desktop_text(e, "source", "webd.desktop");
    return e;
}
static struct json_object *desktop_apps(struct jmx_api_ctx *ctx)
{
    struct json_object *response = json_object_new_object();
    desktop_text(response, "contract", "product-plane.v1");
    desktop_text(response, "resource", "desktop.apps");
    if (!ctx->device_id || !ctx->device_id[0] || ctx->role < JMX_ROLE_VIEWER || ctx->role > JMX_ROLE_AI_AGENT) {
        int authenticated = ctx->device_id && ctx->device_id[0];
        ctx->status = authenticated ? 403 : 401;
        json_object_object_add(response, "ok", json_object_new_boolean(0));
        json_object_object_add(response, "error", desktop_error(authenticated ? "permission_denied" : "authentication_required", authenticated ? "Desktop read permission denied" : "Authentication required"));
        return response;
    }
    struct json_object *data = json_object_new_object(), *apps = json_object_new_array();
    struct json_object *meta = json_object_new_object();
    /* Independent of package registries, license state and user preferences. */
    json_object_array_add(apps, desktop_app("router", "路由管理", "platform_core",
        "/app/?desktop=router#/dashboard", "network_config", 1, 1, 1, 1, NULL));
    int native_errors = 0, store_errors = 0;
    desktop_native_apps(apps, &native_errors);
    desktop_appstore_apps(apps, &store_errors);
    int failed = native_errors || store_errors;
    desktop_text(data, "schema", "desktop.apps.v1");
    json_object_object_add(data, "apps", apps);
    json_object_object_add(response, "data", data);
    json_object_object_add(response, "ok", json_object_new_boolean(!failed));
    struct json_object *capabilities = json_object_new_object(), *permissions = json_object_new_object();
    json_object_object_add(capabilities, "read", json_object_new_boolean(1));
    json_object_object_add(permissions, "read", json_object_new_boolean(1));
    json_object_object_add(response, "capabilities", capabilities);
    json_object_object_add(response, "permissions", permissions);
    json_object_object_add(response, "entitlement", NULL);
    desktop_text(meta, "source", "device_installed_registries");
    json_object_object_add(meta, "observed_at", json_object_new_int64(time(NULL)));
    json_object_object_add(meta, "stale", json_object_new_boolean(0));
    json_object_object_add(meta, "partial", json_object_new_boolean(failed));
    json_object_object_add(meta, "native_registry_errors", json_object_new_int(native_errors));
    json_object_object_add(meta, "appstore_registry_errors", json_object_new_int(store_errors));
    json_object_object_add(response, "meta", meta);
    if (failed) json_object_object_add(response, "error", desktop_error("desktop_registry_unavailable", "Installed application registry is incomplete; core router remains available"));
    ctx->status = failed ? 503 : 200;
    return response;
}
const struct jmx_api_route desktop_api_routes[] = {
    JMX_API_ROUTE(9613, "/api/v1/desktop/apps", "GET", JMX_API_EXACT, desktop_apps),
    JMX_API_ROUTE_END,
};
