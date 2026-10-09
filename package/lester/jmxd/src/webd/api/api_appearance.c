// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * api_appearance.c - Appearance/branding config + public media BFF builders.
 *
 * Extracted verbatim from webd/jmx_app_api.c (Phase 7S) with no behavioral
 * change. Routes are unchanged and still dispatched from handle_client() in
 * the main TU; only the function definitions moved here.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <zlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <sqlite3.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <uci.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "../jmx_strbuf.h"
#include "../jmx_app_api.h"
#include "../jmx_app_perms.h"
#include "../webd_system_web_access.h"
#include "../jmx_app_cache.h"
#include "../jmx_system_data_path.h"
#include "../../storage/storage_files.h"
#include "../webd_http.h"
#include "../webd_static.h"
#include "../webd_mmdb.h"
#include "../webd_wifi_aggregate.h"
#include "../webd_upload_staging.h"
#include "../webd_backup_store.h"
#include "../webd_init_control.h"
#include "../native_plugins.h"
#include "../terminal_groups.h"
#include "../system_ttyd.h"
#include "../system_ttyd_proxy.h"
#include "../webd_session_idle.h"
#include "../webd_passkey.h"
#include "../webd_admin_transaction.h"
#include "../webd_vpn_aggregate.h"
#include "../webd_api_keys.h"
#include "../webd_ac_secret_rpc.h"
#include "../../ap_control_wire.h"
#include "../../ap_radio_id.h"
#include "../../safeops/port_snapshot.h"
#include "../../safeops/rollback_claim.h"
#include "../../safeops/revision_sequence.h"
#include "../../ac/ac_secrets.h"
#include "../../safeops/config_snapshot_codec.h"
#include "../ai_runtime.h"
#include "../ai_local_rpc.h"
#include "../ai_oauth.h"
#include "../jmx_auth_contract.h"
#include "../jmx_wifi_contract.h"
#include "api_router.h"
#include "api_request.h"
#include "api_toolkit.h"
#include "api_dashboard.h"
#include "api_topology.h"
#include "api_util.h"
#include "api_json.h"
#include "api_error.h"
#include "api_ubus.h"
#include "api_shared_json.h"
#include "api_runtime_cache.h"
#include "api_clients_list.h"
#include "api_client_control.h"
#include "api_client_connections.h"
#include "api_client_profile.h"
#include "api_policy_read.h"
#include "api_policy_objects.h"
#include "api_policy_paths.h"
#include "api_insights_internal.h"  /* struct webd_jmx_features + webd_jmx_features_read() used by webd_kernel_runtime_data */
#include "../../jmx_config_schema.h"
#include "../../proc_path.h"
#include "../../terminal_policy/terminal_policy.h"
#include "../../client_connections_snapshot.h"
#include "api_bootstrap_internal.h"
#define WEBD_MONITOR_TTL_SEC 2
#define WEBD_MONITOR_STALE_SEC 30
#define WEBD_MONITOR_TIMEOUT_MS 3000
#include "api_appearance_internal.h"

static void webd_appearance_column_get(const char *column, const char *def,
                                       char *out, size_t out_len)
{
    static const char *allowed[] = {
        "accent_color", "wallpaper_directory", "login_enabled", "login_image", "login_opacity",
        "login_mode", "login_interval", "glass_blur", "glass_opacity",
        "glass_highlight", "glass_border_width", "glass_border_color",
        "glass_neutral_color", "glass_preserve_center", "menu_glass_mode",
        "menu_glass_displacement_scale", "glass_saturate",
        "menu_glass_aberration_intensity", "menu_glass_highlight_angle",
        "theme_family", NULL
    };
    sqlite3_stmt *st = NULL;
    char sql[160];
    int valid = 0;

    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%s", def ? def : "");
    if (!g_config_db || !column || !column[0])
        return;
    for (int i = 0; allowed[i]; i++)
        if (!strcmp(column, allowed[i])) { valid = 1; break; }
    if (!valid || snprintf(sql, sizeof(sql),
        "SELECT %s FROM appearance_settings WHERE id=1", column) >= (int)sizeof(sql))
        return;
    if (sqlite3_prepare_v2(g_config_db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0))
        snprintf(out, out_len, "%s", (const char *)sqlite3_column_text(st, 0));
    if (st) sqlite3_finalize(st);
}

static int webd_truthy(const char *s, int def)
{
    if (!s || !s[0])
        return def;
    return !strcmp(s, "1") || !strcasecmp(s, "true") || !strcasecmp(s, "yes") || !strcasecmp(s, "on");
}

static double webd_clamp_double(double v, double min, double max)
{
    if (v < min) return min;
    if (v > max) return max;
    return v;
}

static int webd_media_file_name_ok(const char *name)
{
    const unsigned char *p;

    if (!name || !name[0] || name[0] == '.' || strchr(name, '/') || strchr(name, '\\'))
        return 0;
    if (strstr(name, ".."))
        return 0;
    for (p = (const unsigned char *)name; *p; p++) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

static const char *webd_media_kind(const char *name)
{
    const char *ext = name ? strrchr(name, '.') : NULL;

    if (!ext) return NULL;
    ext++;
    if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg") || !strcasecmp(ext, "png") ||
        !strcasecmp(ext, "gif") || !strcasecmp(ext, "webp"))
        return "image";
    if (!strcasecmp(ext, "mp4") || !strcasecmp(ext, "webm"))
        return "video";
    return NULL;
}

static const char *webd_media_mime(const char *name)
{
    const char *ext = name ? strrchr(name, '.') : NULL;

    if (!ext) return "";
    ext++;
    if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg")) return "image/jpeg";
    if (!strcasecmp(ext, "png")) return "image/png";
    if (!strcasecmp(ext, "gif")) return "image/gif";
    if (!strcasecmp(ext, "webp")) return "image/webp";
    if (!strcasecmp(ext, "mp4")) return "video/mp4";
    if (!strcasecmp(ext, "webm")) return "video/webm";
    return "";
}

static void webd_public_dir_url(const char *path, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (path && !strcmp(path, "/www/dreamingwrt/static/background"))
        snprintf(out, out_len, "%s", "/static/background/");
}

static struct json_object *webd_media_object(const char *url, const char *name)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "url", json_object_new_string(url ? url : ""));
    json_object_object_add(o, "name", json_object_new_string(name ? name : ""));
    json_object_object_add(o, "type", json_object_new_string(webd_media_kind(name) ? webd_media_kind(name) : ""));
    json_object_object_add(o, "mime", json_object_new_string(webd_media_mime(name)));
    return o;
}

static int webd_appearance_row_available(void)
{
    sqlite3_stmt *st = NULL;
    int available = 0;

    if (g_config_db && sqlite3_prepare_v2(g_config_db,
        "SELECT 1 FROM appearance_settings WHERE id=1", -1, &st, NULL) == SQLITE_OK)
        available = sqlite3_step(st) == SQLITE_ROW;
    if (st) sqlite3_finalize(st);
    return available;
}

struct json_object *webd_public_appearance_data(void)
{
    char directory[256], image[128], mode[32], interval[32], opacity_s[32], enabled_s[16];
    char accent_color[32];
    char glass_blur_s[32], glass_opacity_s[32], glass_highlight_s[32];
    char glass_corner_s[32], glass_refraction_offset_s[32], glass_refraction_height_s[32];
    char glass_dispersion_s[32], glass_border_width_s[32], glass_border_color[32];
    char glass_neutral_color[32], glass_preserve_center_s[16];
    char glass_edge_intensity_s[32], glass_rim_intensity_s[32], glass_base_intensity_s[32];
    char glass_edge_distance_s[32], glass_rim_distance_s[32], glass_base_distance_s[32];
    char glass_corner_boost_s[32], glass_ripple_effect_s[32], glass_tint_opacity_s[32], glass_warp_s[16];
    char menu_glass_mode[16], menu_glass_displacement_s[32], menu_glass_blur_s[32];
    char menu_glass_saturation_s[32], menu_glass_aberration_s[32], menu_glass_corner_s[32];
    char menu_glass_over_light_s[16], menu_glass_highlight_angle_s[32];
    char theme_family_s[24];
    char public_dir[256];
    struct json_object *data = json_object_new_object();
    struct json_object *material_glass = json_object_new_object();
    struct json_object *glass = json_object_new_object();
    struct json_object *menu_glass = json_object_new_object();
    struct json_object *media = json_object_new_array();
    struct json_object *images = json_object_new_array();
    struct json_object *selected = NULL;
    double opacity;
    int interval_ms = 6000;
    int enabled;
    DIR *dir;

    if (!webd_appearance_row_available()) {
        json_object_object_add(data, "available", json_object_new_boolean(0));
        json_object_object_add(data, "reason", json_object_new_string("config_db_appearance_unavailable"));
        json_object_object_add(data, "source", json_object_new_string("config.db:appearance_settings"));
        return data;
    }

    webd_appearance_column_get("wallpaper_directory", "/www/dreamingwrt/static/background", directory, sizeof(directory));
    webd_appearance_column_get("accent_color", "violet", accent_color, sizeof(accent_color));
    webd_appearance_column_get("login_enabled", "1", enabled_s, sizeof(enabled_s));
    webd_appearance_column_get("login_image", "", image, sizeof(image));
    webd_appearance_column_get("login_opacity", "1", opacity_s, sizeof(opacity_s));
    webd_appearance_column_get("login_mode", "argon", mode, sizeof(mode));
    webd_appearance_column_get("login_interval", "medium", interval, sizeof(interval));
    webd_appearance_column_get("glass_blur", "3.2", glass_blur_s, sizeof(glass_blur_s));
    webd_appearance_column_get("glass_opacity", "0.06", glass_opacity_s, sizeof(glass_opacity_s));
    webd_appearance_column_get("glass_highlight", "0.28", glass_highlight_s, sizeof(glass_highlight_s));
    snprintf(glass_corner_s, sizeof(glass_corner_s), "%s", "25");
    snprintf(glass_refraction_offset_s, sizeof(glass_refraction_offset_s), "%s", "120");
    snprintf(glass_refraction_height_s, sizeof(glass_refraction_height_s), "%s", "12");
    snprintf(glass_dispersion_s, sizeof(glass_dispersion_s), "%s", "0");
    webd_appearance_column_get("glass_border_width", "1", glass_border_width_s, sizeof(glass_border_width_s));
    webd_appearance_column_get("glass_border_color", "#25FFFFFF", glass_border_color, sizeof(glass_border_color));
    webd_appearance_column_get("glass_neutral_color", "10 16 25", glass_neutral_color, sizeof(glass_neutral_color));
    webd_appearance_column_get("glass_preserve_center", "1", glass_preserve_center_s, sizeof(glass_preserve_center_s));
    snprintf(glass_edge_intensity_s, sizeof(glass_edge_intensity_s), "%s", "0.012");
    snprintf(glass_rim_intensity_s, sizeof(glass_rim_intensity_s), "%s", "0.060");
    snprintf(glass_base_intensity_s, sizeof(glass_base_intensity_s), "%s", "0.010");
    snprintf(glass_edge_distance_s, sizeof(glass_edge_distance_s), "%s", "0.15");
    snprintf(glass_rim_distance_s, sizeof(glass_rim_distance_s), "%s", "0.80");
    snprintf(glass_base_distance_s, sizeof(glass_base_distance_s), "%s", "0.10");
    snprintf(glass_corner_boost_s, sizeof(glass_corner_boost_s), "%s", "0.020");
    snprintf(glass_ripple_effect_s, sizeof(glass_ripple_effect_s), "%s", "0.100");
    snprintf(glass_tint_opacity_s, sizeof(glass_tint_opacity_s), "%s", "0");
    snprintf(glass_warp_s, sizeof(glass_warp_s), "%s", "0");
    webd_appearance_column_get("menu_glass_mode", "shader", menu_glass_mode, sizeof(menu_glass_mode));
    webd_appearance_column_get("menu_glass_displacement_scale", "80", menu_glass_displacement_s, sizeof(menu_glass_displacement_s));
    snprintf(menu_glass_blur_s, sizeof(menu_glass_blur_s), "%s", "0");
    webd_appearance_column_get("glass_saturate", "140", menu_glass_saturation_s, sizeof(menu_glass_saturation_s));
    webd_appearance_column_get("menu_glass_aberration_intensity", "2", menu_glass_aberration_s, sizeof(menu_glass_aberration_s));
    snprintf(menu_glass_corner_s, sizeof(menu_glass_corner_s), "%s", "0");
    snprintf(menu_glass_over_light_s, sizeof(menu_glass_over_light_s), "%s", "0");
    webd_appearance_column_get("menu_glass_highlight_angle", "135", menu_glass_highlight_angle_s, sizeof(menu_glass_highlight_angle_s));
    webd_appearance_column_get("theme_family", "liquid-glass", theme_family_s, sizeof(theme_family_s));
    /* Missing column (pre-migration core) or a corrupt value falls back to
     * liquid-glass so the front end never receives an unknown family. */
    if (strcmp(theme_family_s, "liquid-glass") &&
        strcmp(theme_family_s, "frosted-glass") &&
        strcmp(theme_family_s, "traditional"))
        snprintf(theme_family_s, sizeof(theme_family_s), "%s", "liquid-glass");

    enabled = webd_truthy(enabled_s, 1);
    opacity = webd_clamp_double(atof(opacity_s), 0.0, 1.0);
    if (!strcmp(interval, "slow")) interval_ms = 15000;
    else if (!strcmp(interval, "relaxed")) interval_ms = 30000;
    else if (!strcmp(interval, "long")) interval_ms = 60000;
    webd_public_dir_url(directory, public_dir, sizeof(public_dir));

    if (enabled && public_dir[0] && !strcmp(mode, "fixed") && webd_media_file_name_ok(image) && webd_media_kind(image)) {
        char full[512];
        struct stat st;

        if (snprintf(full, sizeof(full), "%s/%s", directory, image) < (int)sizeof(full) &&
            stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
            char url[512];
            snprintf(url, sizeof(url), "%s%s", public_dir, image);
            selected = webd_media_object(url, image);
        }
    }

    dir = enabled && public_dir[0] ? opendir(directory) : NULL;
    if (dir) {
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            char full[512];
            char url[512];
            struct json_object *item;
            const char *kind;
            struct stat st;

            if (!webd_media_file_name_ok(de->d_name))
                continue;
            kind = webd_media_kind(de->d_name);
            if (!kind)
                continue;
            if (snprintf(full, sizeof(full), "%s/%s", directory, de->d_name) >= (int)sizeof(full) ||
                lstat(full, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))
                continue;
            snprintf(url, sizeof(url), "%s%s", public_dir, de->d_name);
            item = webd_media_object(url, de->d_name);
            if (!selected)
                selected = json_object_get(item);
            if (!strcmp(kind, "image"))
                json_object_array_add(images, json_object_new_string(url));
            json_object_array_add(media, item);
        }
        closedir(dir);
    }

    json_object_object_add(data, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(data, "available", json_object_new_boolean(1));
    json_object_object_add(data, "public_dir", json_object_new_string(public_dir));
    json_object_object_add(data, "mode", json_object_new_string(mode));
    json_object_object_add(data, "interval", json_object_new_string(interval));
    json_object_object_add(data, "interval_ms", json_object_new_int(interval_ms));
    json_object_object_add(data, "opacity", json_object_new_double(opacity));
    json_object_object_add(data, "image", json_object_new_string(image));
    json_object_object_add(data, "accent_color", json_object_new_string(accent_color));

    json_object_object_add(material_glass, "version", json_object_new_int(1));
    json_object_object_add(material_glass, "mode", json_object_new_string(menu_glass_mode));
    json_object_object_add(material_glass, "base_blur", json_object_new_double(webd_clamp_double(atof(glass_blur_s), 0.0, 16.0)));
    json_object_object_add(material_glass, "neutral_density", json_object_new_double(webd_clamp_double(atof(glass_opacity_s), 0.025, 0.18)));
    json_object_object_add(material_glass, "neutral_color", json_object_new_string(glass_neutral_color));
    json_object_object_add(material_glass, "saturation", json_object_new_int((int)webd_clamp_double(atof(menu_glass_saturation_s), 70.0, 220.0)));
    json_object_object_add(material_glass, "displacement_scale", json_object_new_double(webd_clamp_double(atof(menu_glass_displacement_s), 0.0, 180.0)));
    json_object_object_add(material_glass, "aberration_intensity", json_object_new_double(webd_clamp_double(atof(menu_glass_aberration_s), 0.0, 8.0)));
    json_object_object_add(material_glass, "border_width", json_object_new_double(webd_clamp_double(atof(glass_border_width_s), 0.0, 2.0)));
    json_object_object_add(material_glass, "border_color", json_object_new_string(glass_border_color));
    json_object_object_add(material_glass, "highlight", json_object_new_double(webd_clamp_double(atof(glass_highlight_s), 0.0, 0.65)));
    json_object_object_add(material_glass, "highlight_angle", json_object_new_double(webd_clamp_double(atof(menu_glass_highlight_angle_s), 0.0, 360.0)));
    json_object_object_add(material_glass, "preserve_center", json_object_new_boolean(webd_truthy(glass_preserve_center_s, 1)));
    json_object_object_add(material_glass, "renderer", json_object_new_string("host-tiered"));
    json_object_object_add(material_glass, "theme_family", json_object_new_string(theme_family_s));
    json_object_object_add(material_glass, "source", json_object_new_string("config.db:appearance_settings"));
    json_object_object_add(data, "material_glass", material_glass);

    /* Compatibility fields retain their old semantics during rolling updates. */
    json_object_object_add(data, "login_glass_blur", json_object_new_double(6.0));
    json_object_object_add(data, "login_glass_opacity", json_object_new_double(webd_clamp_double((atof(glass_opacity_s) - 0.025) / 0.035, 0.0, 1.0)));
    json_object_object_add(data, "login_glass_highlight", json_object_new_double(webd_clamp_double(atof(glass_highlight_s), 0.0, 1.0)));
    json_object_object_add(data, "login_glass_corner_radius", json_object_new_double(atof(glass_corner_s)));
    json_object_object_add(data, "login_glass_refraction_offset", json_object_new_double(atof(glass_refraction_offset_s)));
    json_object_object_add(data, "login_glass_refraction_height", json_object_new_double(atof(glass_refraction_height_s)));
    json_object_object_add(data, "login_glass_dispersion", json_object_new_double(atof(glass_dispersion_s)));
    json_object_object_add(data, "login_glass_border_width", json_object_new_double(atof(glass_border_width_s)));
    json_object_object_add(data, "login_glass_border_color", json_object_new_string(glass_border_color));
    json_object_object_add(data, "login_glass_edge_intensity", json_object_new_double(webd_clamp_double(atof(glass_edge_intensity_s), 0.0, 0.2)));
    json_object_object_add(data, "login_glass_rim_intensity", json_object_new_double(webd_clamp_double(atof(glass_rim_intensity_s), 0.0, 0.4)));
    json_object_object_add(data, "login_glass_base_intensity", json_object_new_double(webd_clamp_double(atof(glass_base_intensity_s), 0.0, 0.08)));
    json_object_object_add(data, "login_glass_edge_distance", json_object_new_double(webd_clamp_double(atof(glass_edge_distance_s), 0.02, 0.8)));
    json_object_object_add(data, "login_glass_rim_distance", json_object_new_double(webd_clamp_double(atof(glass_rim_distance_s), 0.05, 2.0)));
    json_object_object_add(data, "login_glass_base_distance", json_object_new_double(webd_clamp_double(atof(glass_base_distance_s), 0.02, 0.5)));
    json_object_object_add(data, "login_glass_corner_boost", json_object_new_double(webd_clamp_double(atof(glass_corner_boost_s), 0.0, 0.12)));
    json_object_object_add(data, "login_glass_ripple_effect", json_object_new_double(webd_clamp_double(atof(glass_ripple_effect_s), 0.0, 0.5)));
    json_object_object_add(data, "login_glass_tint_opacity", json_object_new_double(webd_clamp_double(atof(glass_tint_opacity_s), 0.0, 1.0)));
    json_object_object_add(data, "login_glass_warp", json_object_new_boolean(webd_truthy(glass_warp_s, 0)));
    json_object_object_add(glass, "corner_radius", json_object_new_double(atof(glass_corner_s)));
    json_object_object_add(glass, "blur_radius", json_object_new_double(6.0));
    json_object_object_add(glass, "refraction_offset", json_object_new_double(atof(glass_refraction_offset_s)));
    json_object_object_add(glass, "refraction_height", json_object_new_double(atof(glass_refraction_height_s)));
    json_object_object_add(glass, "dispersion", json_object_new_double(atof(glass_dispersion_s)));
    json_object_object_add(glass, "border_width", json_object_new_double(atof(glass_border_width_s)));
    json_object_object_add(glass, "border_color", json_object_new_string(glass_border_color));
    json_object_object_add(glass, "opacity", json_object_new_double(webd_clamp_double((atof(glass_opacity_s) - 0.025) / 0.035, 0.0, 1.0)));
    json_object_object_add(glass, "highlight", json_object_new_double(webd_clamp_double(atof(glass_highlight_s), 0.0, 1.0)));
    json_object_object_add(glass, "edge_intensity", json_object_new_double(webd_clamp_double(atof(glass_edge_intensity_s), 0.0, 0.2)));
    json_object_object_add(glass, "rim_intensity", json_object_new_double(webd_clamp_double(atof(glass_rim_intensity_s), 0.0, 0.4)));
    json_object_object_add(glass, "base_intensity", json_object_new_double(webd_clamp_double(atof(glass_base_intensity_s), 0.0, 0.08)));
    json_object_object_add(glass, "edge_distance", json_object_new_double(webd_clamp_double(atof(glass_edge_distance_s), 0.02, 0.8)));
    json_object_object_add(glass, "rim_distance", json_object_new_double(webd_clamp_double(atof(glass_rim_distance_s), 0.05, 2.0)));
    json_object_object_add(glass, "base_distance", json_object_new_double(webd_clamp_double(atof(glass_base_distance_s), 0.02, 0.5)));
    json_object_object_add(glass, "corner_boost", json_object_new_double(webd_clamp_double(atof(glass_corner_boost_s), 0.0, 0.12)));
    json_object_object_add(glass, "ripple_effect", json_object_new_double(webd_clamp_double(atof(glass_ripple_effect_s), 0.0, 0.5)));
    json_object_object_add(glass, "tint_opacity", json_object_new_double(webd_clamp_double(atof(glass_tint_opacity_s), 0.0, 1.0)));
    json_object_object_add(glass, "warp", json_object_new_boolean(webd_truthy(glass_warp_s, 0)));
    json_object_object_add(glass, "source", json_object_new_string("config.db:appearance_settings"));
    json_object_object_add(data, "liquid_glass", glass);
    json_object_object_add(menu_glass, "mode", json_object_new_string(menu_glass_mode));
    json_object_object_add(menu_glass, "displacement_scale", json_object_new_double(webd_clamp_double(atof(menu_glass_displacement_s), 0.0, 180.0)));
    json_object_object_add(menu_glass, "blur_amount", json_object_new_double(webd_clamp_double(atof(menu_glass_blur_s), 0.0, 1.0)));
    json_object_object_add(menu_glass, "saturation", json_object_new_int((int)webd_clamp_double(atof(menu_glass_saturation_s), 70.0, 220.0)));
    json_object_object_add(menu_glass, "aberration_intensity", json_object_new_double(webd_clamp_double(atof(menu_glass_aberration_s), 0.0, 8.0)));
    json_object_object_add(menu_glass, "corner_radius", json_object_new_double(webd_clamp_double(atof(menu_glass_corner_s), 0.0, 80.0)));
    json_object_object_add(menu_glass, "over_light", json_object_new_boolean(webd_truthy(menu_glass_over_light_s, 0)));
    json_object_object_add(menu_glass, "highlight_angle", json_object_new_double(webd_clamp_double(atof(menu_glass_highlight_angle_s), 0.0, 360.0)));
    json_object_object_add(menu_glass, "preserve_center", json_object_new_boolean(webd_truthy(glass_preserve_center_s, 1)));
    json_object_object_add(menu_glass, "renderer", json_object_new_string("svg-explicit-sampling"));
    json_object_object_add(menu_glass, "source", json_object_new_string("config.db:appearance_settings"));
    json_object_object_add(data, "menu_liquid_glass", menu_glass);

    json_object_object_add(data, "selected", selected ? selected : json_object_new_object());
    json_object_object_add(data, "images", images);
    json_object_object_add(data, "media", media);
    json_object_object_add(data, "source", json_object_new_string("config.db:appearance_settings"));
    return data;
}

struct json_object *webd_appearance_defaults(void)
{
    struct json_object *cached = jmx_cache_get("webd_appearance_defaults");
    struct json_object *appearance;
    struct json_object *login;
    struct json_object *selected = NULL;
    struct json_object *url = NULL;

    if (cached)
        return cached;
    appearance = json_object_new_object();
    login = webd_public_appearance_data();
    if (!app_nc_json_bool(login, "available", 0)) {
        json_object_object_add(appearance, "available", json_object_new_boolean(0));
        json_object_object_add(appearance, "reason", json_object_new_string(
            app_nc_json_str(login, "reason", "config_db_appearance_unavailable")));
        json_object_object_add(appearance, "source", json_object_new_string(
            "config.db:appearance_settings"));
        json_object_object_add(appearance, "login", login);
        jmx_cache_put("webd_appearance_defaults", appearance, 5);
        return appearance;
    }
    json_object_object_add(appearance, "available", json_object_new_boolean(1));
    json_object_object_add(appearance, "mode", json_object_new_string("auto"));
    json_object_object_add(appearance, "glass_opacity", json_object_new_double(0.16));
    json_object_object_add(appearance, "blur_radius", json_object_new_int(24));
    json_object_object_add(appearance, "highlight_strength", json_object_new_double(0.6));
    if (json_object_object_get_ex(login, "selected", &selected) && selected &&
        json_object_object_get_ex(selected, "url", &url) && url)
        json_object_object_add(appearance, "wallpaper", json_object_new_string(json_object_get_string(url)));
    else
        json_object_object_add(appearance, "wallpaper", json_object_new_string(""));
    json_object_object_add(appearance, "login", login);
    jmx_cache_put("webd_appearance_defaults", appearance, 30);
    return appearance;
}
