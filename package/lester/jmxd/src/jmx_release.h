/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef JMX_RELEASE_H
#define JMX_RELEASE_H
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifndef DW_RELEASE_PATH
#define DW_RELEASE_PATH "/etc/dreamingos-release.json"
#endif
#ifndef DW_RELEASE_LEGACY_PATH
#define DW_RELEASE_LEGACY_PATH "/etc/dreamingwrt-release.json"
#endif
/* A present canonical file owns identity. Invalid canonical metadata must not
 * silently fall back to an older version from another file. */
static inline struct json_object *dw_release_read_paths(const char *primary,
        const char *legacy, const char **source)
{
    struct stat st;
    struct json_object *release;
    const char *path = primary;
    if (stat(path, &st) != 0) {
        path = legacy;
        if (stat(path, &st) != 0) { if (source) *source = primary; return NULL; }
    }
    if (source) *source = path;
    if (!S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 1024 * 1024)
        return NULL;
    release = json_object_from_file(path);
    if (release && !json_object_is_type(release, json_type_object)) {
        json_object_put(release); release = NULL;
    }
    return release;
}
static inline struct json_object *dw_release_read(const char **source)
{
    return dw_release_read_paths(DW_RELEASE_PATH, DW_RELEASE_LEGACY_PATH, source);
}
static inline const char *dw_release_string(struct json_object *release, const char *key)
{
    struct json_object *value = NULL;
    if (release && json_object_object_get_ex(release, key, &value) && value &&
        json_object_is_type(value, json_type_string)) return json_object_get_string(value);
    return "";
}
static inline const char *dw_release_version(struct json_object *release)
{
    const char *version = dw_release_string(release, "version");
    return version[0] ? version : dw_release_string(release, "dreamingwrt_version");
}
static inline int dw_release_display(struct json_object *release, char *out, size_t size)
{
    const char *version = dw_release_version(release);
    const char *model = dw_release_string(release, "model");
    const char *build = dw_release_string(release, "build_id");
    if (!out || !size) return 0;
    if (version[0] && model[0] && build[0])
        snprintf(out, size, "DreamingOS_%s_%s_%s", model, version, build);
    else snprintf(out, size, "%s", version);
    return out[0] != 0;
}
#endif
