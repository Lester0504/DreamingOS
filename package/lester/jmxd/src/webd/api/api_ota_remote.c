// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Remote OTA fetch (T3 of the zero-key OTA program).
 *
 * Two POST routes that let a device pull a release from the cloud distributor
 * (dreamingos-dist) and hand it to the EXISTING on-device verify/apply path:
 *
 *   POST /api/v1/system/ota/check     read-only. Reads the running firmware's
 *                                     identity, asks the distributor whether a
 *                                     newer artifact exists, returns metadata.
 *   POST /api/v1/system/ota/download  webd curls the artifact into upload-staging
 *                                     and returns an upload_id. That upload_id is
 *                                     exactly what /api/v1/system/ota/verify and
 *                                     .../apply already consume — so this module
 *                                     adds the "where do the bytes come from"
 *                                     step and reuses everything downstream.
 *
 * Trust boundary, deliberately: this module NEVER verifies a signature and NEVER
 * touches otad's trust logic. The distributor is verify-on-publish (public keys
 * only) and the device's otad_trust.c is the final authority; a downloaded blob
 * still has to pass /ota/verify before /ota/apply will write a slot. otad itself
 * never makes an outbound request (its `download` ubus method is deliberately
 * disabled); webd is the only component that reaches the network here.
 *
 * SSRF posture: the client never supplies a URL. /download takes a bare filename
 * (from the check response) plus track/sha256/size, and webd builds the full URL
 * from the operator-provisioned distributor base in /etc/config/relay. An
 * unconfigured device fetches from nobody.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <uci.h>

#include "api_ota_remote.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../webd_upload_staging.h"

/*
 * The distributor base URL and channel live in the same UCI package the cloud
 * enrollment BFF uses (/etc/config/relay), in a dedicated `ota` section so the
 * two concerns never alias each other's options. Reading only; the section is
 * provisioned by the operator or the enrollment flow, not by this module.
 */
#define OTA_REMOTE_UCI_PACKAGE "relay"
#define OTA_REMOTE_UCI_SECTION "ota"
#define OTA_REMOTE_DEFAULT_CHANNEL "stable"

/* A firmware image is tens of MB and a slow link is legitimate; abort a transfer
 * only when it stalls below this rate for this long, rather than on a hard total
 * deadline that would kill an honest large download. */
#define OTA_REMOTE_LOW_SPEED_BYTES 1024L
#define OTA_REMOTE_LOW_SPEED_SECS  60L
#define OTA_REMOTE_CONNECT_TIMEOUT_MS 10000L
/* The check request is a small JSON round-trip; a hard total timeout is fine. */
#define OTA_REMOTE_CHECK_TIMEOUT_MS 15000L
/* Raising the notification-center event is best-effort and off the response
 * path; keep it short so a slow/absent notifyd never stalls a check. */
#define OTA_REMOTE_NOTIFY_TIMEOUT_MS 3000

struct ota_remote_config {
    char dist_url[512];
    char channel[64];
    char ca_path[256];
};

/*
 * Read the distributor config out of UCI. Returns 0 on a usable config (dist_url
 * present), -1 otherwise. dist_url being empty is the "not configured" state and
 * is reported to the caller as a distinct, actionable error — never silently
 * defaulted to some built-in host, because a device must not fetch firmware from
 * a URL nobody provisioned.
 */
static int ota_remote_read_config(struct ota_remote_config *out)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_section *section;
    const char *v;

    memset(out, 0, sizeof(*out));
    snprintf(out->channel, sizeof(out->channel), "%s", OTA_REMOTE_DEFAULT_CHANNEL);

    ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    if (uci_load(ctx, OTA_REMOTE_UCI_PACKAGE, &pkg) != UCI_OK || !pkg) {
        uci_free_context(ctx);
        return -1;
    }
    section = uci_lookup_section(ctx, pkg, OTA_REMOTE_UCI_SECTION);
    if (!section) {
        uci_free_context(ctx);
        return -1;
    }
    v = uci_lookup_option_string(ctx, section, "dist_url");
    if (v && v[0])
        snprintf(out->dist_url, sizeof(out->dist_url), "%s", v);
    v = uci_lookup_option_string(ctx, section, "channel");
    if (v && v[0])
        snprintf(out->channel, sizeof(out->channel), "%s", v);
    v = uci_lookup_option_string(ctx, section, "ca_path");
    if (v && v[0])
        snprintf(out->ca_path, sizeof(out->ca_path), "%s", v);
    uci_free_context(ctx);

    return out->dist_url[0] ? 0 : -1;
}

/*
 * The machine's architecture as the release manifest names it. Replicated from
 * otad_trust.c (amd64 -> x86_64) rather than called: otad_trust.c is the signing
 * trust kernel and is off-limits, and this is only a hint for the check request —
 * the authoritative arch gate still runs inside otad on apply.
 */
static void ota_remote_arch(char *buf, size_t buf_len)
{
    struct utsname uts;

    if (uname(&uts) != 0) {
        snprintf(buf, buf_len, "%s", "");
        return;
    }
    snprintf(buf, buf_len, "%s",
             !strcmp(uts.machine, "amd64") ? "x86_64" : uts.machine);
}

/*
 * The board (machine model) as OpenWrt records it in /tmp/sysinfo/board_name -
 * e.g. "bananapi,bpi-r4" or "gemtek,w1700k-ubi". Same identity source
 * otad_trust.c reads; replicated here (not called) for the same off-limits
 * reason as ota_remote_arch(). The distributor keys releases by board so two
 * boards of one architecture never receive each other's firmware. Best-effort:
 * on any read failure the buffer is left empty and the caller omits the
 * parameter, which makes the distributor serve only "generic" releases.
 */
static void ota_remote_board(char *buf, size_t buf_len)
{
    FILE *f;
    size_t n;

    buf[0] = '\0';
    f = fopen("/tmp/sysinfo/board_name", "re");
    if (!f)
        return;
    if (fgets(buf, buf_len, f)) {
        n = strlen(buf);
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                         buf[n - 1] == ' '  || buf[n - 1] == '\t'))
            buf[--n] = '\0';
    }
    fclose(f);
}

/*
 * Pull the running firmware's version and build_id out of otad's status. The
 * current slot letter comes from slot_status.current_slot; the version/build_id
 * for that letter come from the slots[] array. Best-effort: if otad is not
 * answering, the caller proceeds with empty identity (the distributor then treats
 * everything as newer, and the device's own epoch gate is the real guard). The
 * top-level status "version" is the daemon status-format version, not firmware,
 * and is deliberately not used.
 */
static void ota_remote_local_identity(char *version, size_t version_len,
                                      char *build_id, size_t build_id_len,
                                      char *current_slot, size_t slot_len)
{
    struct json_object *status;
    struct json_object *slot_status = NULL;
    struct json_object *slots = NULL;
    const char *slot = "";
    size_t i;

    version[0] = build_id[0] = current_slot[0] = '\0';

    status = app_ubus_invoke_object_timeout("dreamingwrt.otad", "status", NULL, 5000);
    if (!status)
        return;

    if (json_object_object_get_ex(status, "slot_status", &slot_status) && slot_status)
        slot = app_nc_json_str(slot_status, "current_slot", "");
    snprintf(current_slot, slot_len, "%s", slot);

    if (slot[0] &&
        json_object_object_get_ex(status, "slots", &slots) &&
        json_object_is_type(slots, json_type_array)) {
        for (i = 0; i < json_object_array_length(slots); i++) {
            struct json_object *row = json_object_array_get_idx(slots, i);

            if (!row)
                continue;
            if (!strcmp(app_nc_json_str(row, "slot_name", ""), slot)) {
                snprintf(version, version_len, "%s",
                         app_nc_json_str(row, "version", ""));
                snprintf(build_id, build_id_len, "%s",
                         app_nc_json_str(row, "build_id", ""));
                break;
            }
        }
    }
    json_object_put(status);
}

/* A "track" selects which distributor surface answers and which upload type the
 * staged bytes are recorded as. Only two are offered: full firmware and the
 * signature database. Anything else is rejected up front. */
static int ota_remote_track_ok(const char *track)
{
    return track && (!strcmp(track, "firmware") || !strcmp(track, "signature"));
}

static const char *ota_remote_track_check_path(const char *track)
{
    return !strcmp(track, "firmware") ? "/v1/updates/check" : "/v1/files/check";
}

static const char *ota_remote_track_download_path(const char *track)
{
    return !strcmp(track, "firmware") ? "/v1/updates/packages/"
                                      : "/v1/files/download/";
}

/* A filename that came back from the distributor is echoed straight into a URL
 * path, so it must be a bare leaf: no separators, no traversal, non-empty, and
 * short enough that the assembled URL cannot overrun. */
static int ota_remote_filename_ok(const char *name)
{
    size_t len;

    if (!name || !name[0])
        return 0;
    len = strlen(name);
    if (len > 200)
        return 0;
    if (strchr(name, '/') || strchr(name, '\\'))
        return 0;
    if (strstr(name, ".."))
        return 0;
    return 1;
}

static int ota_remote_sha256_ok(const char *hex)
{
    size_t i;

    if (!hex || strlen(hex) != WEBD_UPLOAD_SHA256_HEX_LEN)
        return 0;
    for (i = 0; i < WEBD_UPLOAD_SHA256_HEX_LEN; i++) {
        char c = hex[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/*
 * A small growable buffer for the check response body. The check reply is a
 * short JSON document; cap it so a misbehaving endpoint cannot make webd
 * allocate without bound.
 */
#define OTA_REMOTE_CHECK_MAX (256 * 1024)

struct ota_remote_buf {
    char  *data;
    size_t len;
};

static size_t ota_remote_collect(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    struct ota_remote_buf *b = opaque;
    size_t n = size * nmemb;
    char *next;

    if (n > OTA_REMOTE_CHECK_MAX - b->len)
        return 0;
    next = realloc(b->data, b->len + n + 1);
    if (!next)
        return 0;
    b->data = next;
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

/* ── firmware-available notification (best-effort) ────────────────────────── */

/*
 * Raise a notifyd event when the distributor reports a newer firmware, so the
 * update surfaces in the notification center (and any routed channel) and not
 * only inside this API response. This is deliberately best-effort: any failure
 * here is swallowed so it can never turn a successful check into an error.
 *
 * Anti-spam: the notifyd route table carries no dedupe window, so an unguarded
 * enqueue on every poll would pile up identical rows. We remember the
 * last-announced version in a per-track /tmp marker and enqueue only when the
 * available version changes — a device that polls hourly then notifies once per
 * new release, and re-announces the moment a genuinely newer version appears.
 */
static void ota_remote_notify_available(const char *track, const char *channel,
                                        const char *board, struct json_object *remote)
{
    struct json_object *rdata = NULL, *latest = NULL, *body, *resp;
    const char *version;
    char marker[128];
    char seen[128] = "";
    char title[256], dedupe[192];
    int ok = 0;
    FILE *fp;

    /* Only a firmware image warrants a user-facing "new version" prompt; the
     * signature track is an internal sub-artifact. */
    if (strcmp(track, "firmware") != 0)
        return;
    if (!remote || !json_object_object_get_ex(remote, "data", &rdata) || !rdata)
        return;
    if (!app_nc_json_bool(rdata, "update_available", 0))
        return;
    if (!json_object_object_get_ex(rdata, "latest", &latest) || !latest)
        return;
    version = app_nc_json_str(latest, "version", "");
    if (!version[0])
        return;

    /* track is validated to "firmware"/"signature" before we get here, so it is
     * safe to splice into the path without further sanitisation. */
    snprintf(marker, sizeof(marker), "/tmp/webd-ota-notified.%s", track);
    fp = fopen(marker, "r");
    if (fp) {
        if (fgets(seen, sizeof(seen), fp))
            seen[strcspn(seen, "\r\n")] = '\0';
        fclose(fp);
        if (strcmp(seen, version) == 0)
            return; /* already announced this exact version */
    }

    if (board && board[0])
        snprintf(title, sizeof(title), "发现新固件版本 %s（%s）", version, board);
    else
        snprintf(title, sizeof(title), "发现新固件版本 %s", version);
    snprintf(dedupe, sizeof(dedupe), "firmware-update:%s:%s",
             channel ? channel : "", version);

    body = json_object_new_object();
    json_object_object_add(body, "event", json_object_new_string("FIRMWARE_UPDATE_AVAILABLE"));
    json_object_object_add(body, "category", json_object_new_string("SYSTEM"));
    json_object_object_add(body, "severity", json_object_new_string("warning"));
    json_object_object_add(body, "source", json_object_new_string("ota_check"));
    json_object_object_add(body, "browser_interrupt", json_object_new_boolean(0));
    json_object_object_add(body, "title", json_object_new_string(title));
    json_object_object_add(body, "dedupe_key", json_object_new_string(dedupe));
    json_object_object_add(body, "message",
                           json_object_new_string("可在系统设置的固件更新中查看并升级。"));

    resp = app_ubus_invoke_object_timeout("dreamingwrt.notifyd", "enqueue", body,
                                          OTA_REMOTE_NOTIFY_TIMEOUT_MS);
    json_object_put(body);
    if (resp) {
        ok = app_nc_json_bool(resp, "ok", 0);
        json_object_put(resp);
    }

    /* Persist the marker only on a clean enqueue: a transient notifyd failure
     * then retries on the next poll instead of silently swallowing this
     * version's one and only announcement. */
    if (ok) {
        fp = fopen(marker, "w");
        if (fp) {
            fputs(version, fp);
            fputc('\n', fp);
            fclose(fp);
        }
    }
}

/* ── /api/v1/system/ota/check ─────────────────────────────────────────────── */

static struct json_object *ota_remote_check(struct jmx_api_ctx *ctx)
{
    struct ota_remote_config cfg;
    struct json_object *body = ctx->body;
    const char *track;
    const char *channel;
    char version[128], build_id[128], slot[8], board[64];
    char arch[sizeof(((struct utsname *)0)->machine)];
    char url[1024];
    CURL *curl;
    CURLcode cc;
    long http_code = 0;
    struct ota_remote_buf buf = {0};
    struct json_object *remote = NULL;
    struct json_object *data;
    struct curl_slist *headers = NULL;

    track = app_nc_json_str(body, "track", "firmware");
    if (!ota_remote_track_ok(track)) {
        ctx->status = 400;
        return webd_error("ota_track_invalid",
                          "track must be \"firmware\" or \"signature\"",
                          "track", "webd.ota");
    }

    if (ota_remote_read_config(&cfg) != 0) {
        ctx->status = 409;
        return webd_error("ota_dist_not_configured",
                          "no OTA distributor is configured; set dist_url in the "
                          "[ota] section of /etc/config/relay",
                          "dist_url", "webd.ota");
    }

    /* A channel in the request overrides the configured default, so an operator
     * can point one device at a canary channel without reprovisioning. */
    channel = app_nc_json_str(body, "channel", cfg.channel);

    ota_remote_arch(arch, sizeof(arch));
    ota_remote_local_identity(version, sizeof(version), build_id, sizeof(build_id),
                              slot, sizeof(slot));
    ota_remote_board(board, sizeof(board));

    curl = curl_easy_init();
    if (!curl) {
        ctx->status = 500;
        return webd_error("ota_curl_init_failed",
                          "the HTTP client could not be initialized", "",
                          "webd.ota");
    }

    {
        char *e_arch = curl_easy_escape(curl, arch, 0);
        char *e_chan = curl_easy_escape(curl, channel, 0);
        char *e_ver  = curl_easy_escape(curl, version, 0);
        char board_q[128] = "";

        /* board is optional: send it only when we could read one. Omitting it
         * (rather than sending empty) makes the distributor fall back to
         * generic-only, so an unidentifiable device can never pull another
         * board's firmware. */
        if (board[0]) {
            char *e_board = curl_easy_escape(curl, board, 0);
            if (e_board) {
                snprintf(board_q, sizeof(board_q), "&board=%s", e_board);
                curl_free(e_board);
            }
        }

        snprintf(url, sizeof(url),
                 "%s%s?arch=%s&channel=%s&current_version=%s%s",
                 cfg.dist_url, ota_remote_track_check_path(track),
                 e_arch ? e_arch : "", e_chan ? e_chan : "",
                 e_ver ? e_ver : "", board_q);
        curl_free(e_arch);
        curl_free(e_chan);
        curl_free(e_ver);
    }

    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, OTA_REMOTE_CONNECT_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, OTA_REMOTE_CHECK_TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dreamingwrt-webd/1.0 ota-check");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (cfg.ca_path[0])
        curl_easy_setopt(curl, CURLOPT_CAINFO, cfg.ca_path);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ota_remote_collect);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

    cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (cc != CURLE_OK) {
        free(buf.data);
        ctx->status = 502;
        return webd_error("ota_dist_unreachable",
                          curl_easy_strerror(cc), "", "webd.ota");
    }
    if (http_code < 200 || http_code >= 300) {
        free(buf.data);
        ctx->status = 502;
        return webd_error("ota_dist_http_error",
                          "the distributor returned a non-success status", "",
                          "webd.ota");
    }
    if (buf.data)
        remote = json_tokener_parse(buf.data);
    free(buf.data);
    if (!remote || !json_object_is_type(remote, json_type_object)) {
        if (remote)
            json_object_put(remote);
        ctx->status = 502;
        return webd_error("ota_dist_response_malformed",
                          "the distributor response was not a JSON object", "",
                          "webd.ota");
    }

    /* Best-effort: surface a "new firmware" event to the notification center
     * before we hand ownership of `remote` to the response. Never fails the
     * check. */
    ota_remote_notify_available(track, channel, board, remote);

    /* Enrich the distributor's answer with what the device knows about itself so
     * the UI can render "current -> available" without a second round-trip. The
     * distributor's own up_to_date/version/file fields pass through unchanged. */
    data = json_object_new_object();
    json_object_object_add(data, "track", json_object_new_string(track));
    json_object_object_add(data, "channel", json_object_new_string(channel));
    json_object_object_add(data, "current_version", json_object_new_string(version));
    json_object_object_add(data, "current_build_id", json_object_new_string(build_id));
    json_object_object_add(data, "current_slot", json_object_new_string(slot));
    json_object_object_add(data, "architecture", json_object_new_string(arch));
    json_object_object_add(data, "board", json_object_new_string(board));
    json_object_object_add(data, "distributor", remote); /* ownership transferred */

    ctx->status = 200;
    return webd_envelope(data, "webd.ota");
}

/* ── /api/v1/system/ota/download ──────────────────────────────────────────── */

/*
 * Streams the download straight into upload-staging. The write callback appends
 * each chunk at the running offset; a single append failure latches `failed` so
 * the rest of the transfer is discarded and curl is told to stop (return 0).
 */
struct ota_remote_sink {
    const char *owner_id;
    const char *upload_id;
    uint64_t    offset;
    int         failed;
    char        err[160];
};

static size_t ota_remote_sink_write(char *ptr, size_t size, size_t nmemb, void *opaque)
{
    struct ota_remote_sink *sink = opaque;
    size_t n = size * nmemb;
    struct webd_upload_meta meta;

    if (sink->failed)
        return 0;
    if (n == 0)
        return 0;
    if (webd_upload_append(sink->owner_id, sink->upload_id, sink->offset,
                           ptr, n, &meta, sink->err, sizeof(sink->err)) != 0) {
        sink->failed = 1;
        return 0;
    }
    sink->offset += n;
    return n;
}

static struct json_object *ota_remote_download(struct jmx_api_ctx *ctx)
{
    struct ota_remote_config cfg;
    struct json_object *body = ctx->body;
    const char *owner_id = ctx->device_id ? ctx->device_id : "";
    const char *track;
    const char *filename;
    const char *sha256;
    const char *upload_type;
    int64_t expected_size;
    uint64_t max_size;
    char url[1024];
    struct webd_upload_meta begin_meta;
    struct webd_upload_meta final_meta;
    struct ota_remote_sink sink;
    char err[160] = "";
    CURL *curl;
    CURLcode cc;
    long http_code = 0;
    struct curl_slist *headers = NULL;
    struct json_object *data;

    if (!owner_id[0]) {
        ctx->status = 401;
        return webd_error("ota_owner_required",
                          "a device session is required to download firmware", "",
                          "webd.ota");
    }

    track = app_nc_json_str(body, "track", "firmware");
    if (!ota_remote_track_ok(track)) {
        ctx->status = 400;
        return webd_error("ota_track_invalid",
                          "track must be \"firmware\" or \"signature\"",
                          "track", "webd.ota");
    }
    filename = app_nc_json_str(body, "filename", "");
    if (!ota_remote_filename_ok(filename)) {
        ctx->status = 400;
        return webd_error("ota_filename_invalid",
                          "filename must be a bare name from the check response",
                          "filename", "webd.ota");
    }
    sha256 = app_nc_json_str(body, "sha256", "");
    if (!ota_remote_sha256_ok(sha256)) {
        ctx->status = 400;
        return webd_error("ota_sha256_invalid",
                          "sha256 must be a 64-character hex digest",
                          "sha256", "webd.ota");
    }
    expected_size = app_nc_json_int64(body, "size", 0);
    if (expected_size <= 0) {
        ctx->status = 400;
        return webd_error("ota_size_invalid",
                          "size (bytes) from the check response is required",
                          "size", "webd.ota");
    }

    if (ota_remote_read_config(&cfg) != 0) {
        ctx->status = 409;
        return webd_error("ota_dist_not_configured",
                          "no OTA distributor is configured; set dist_url in the "
                          "[ota] section of /etc/config/relay",
                          "dist_url", "webd.ota");
    }

    /* A firmware image is staged as type "firmware"; the signature database as
     * "signature". Both are consumed by the same downstream verify/apply path. */
    upload_type = !strcmp(track, "firmware") ? "firmware" : "signature";
    max_size = webd_upload_type_default_max(upload_type);
    if (max_size && (uint64_t)expected_size > max_size) {
        ctx->status = 413;
        return webd_error("ota_size_too_large",
                          "the advertised artifact size exceeds the staging limit",
                          "size", "webd.ota");
    }

    if (webd_upload_begin(owner_id, "ota-remote", upload_type, filename,
                          (uint64_t)expected_size, max_size,
                          WEBD_UPLOAD_DEFAULT_TTL_SECONDS, &begin_meta,
                          err, sizeof(err)) != 0) {
        ctx->status = 500;
        return webd_error("ota_staging_begin_failed", err, "", "webd.ota");
    }

    snprintf(url, sizeof(url), "%s%s%s", cfg.dist_url,
             ota_remote_track_download_path(track), filename);

    memset(&sink, 0, sizeof(sink));
    sink.owner_id = owner_id;
    sink.upload_id = begin_meta.upload_id;

    curl = curl_easy_init();
    if (!curl) {
        webd_upload_delete(owner_id, begin_meta.upload_id, err, sizeof(err));
        ctx->status = 500;
        return webd_error("ota_curl_init_failed",
                          "the HTTP client could not be initialized", "",
                          "webd.ota");
    }
    headers = curl_slist_append(headers, "Accept: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, OTA_REMOTE_CONNECT_TIMEOUT_MS);
    /* No hard total timeout: a large image on a slow link is legitimate. Abort
     * only a stalled transfer via the low-speed guard. */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, OTA_REMOTE_LOW_SPEED_BYTES);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, OTA_REMOTE_LOW_SPEED_SECS);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dreamingwrt-webd/1.0 ota-download");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (cfg.ca_path[0])
        curl_easy_setopt(curl, CURLOPT_CAINFO, cfg.ca_path);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ota_remote_sink_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);

    cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (cc != CURLE_OK || sink.failed) {
        const char *why = sink.failed ? (sink.err[0] ? sink.err : "staging append failed")
                                       : curl_easy_strerror(cc);
        webd_upload_delete(owner_id, begin_meta.upload_id, err, sizeof(err));
        ctx->status = sink.failed ? 500 : 502;
        return webd_error(sink.failed ? "ota_staging_write_failed"
                                      : "ota_download_failed",
                          why, "", "webd.ota");
    }
    if (http_code < 200 || http_code >= 300) {
        webd_upload_delete(owner_id, begin_meta.upload_id, err, sizeof(err));
        ctx->status = 502;
        return webd_error("ota_dist_http_error",
                          "the distributor returned a non-success status for the "
                          "download", "", "webd.ota");
    }

    /* Finalize with the advertised sha256. This catches a truncated or corrupted
     * transfer cheaply; it is NOT the authenticity check — otad's signature gate
     * on /ota/verify is. A finalize mismatch discards the staged bytes. */
    if (webd_upload_finalize(owner_id, begin_meta.upload_id, sha256, &final_meta,
                             err, sizeof(err)) != 0) {
        char discard_err[160] = "";

        /* Discard the mismatched bytes. A separate scratch buffer keeps the
         * finalize error (`err`) intact for the response. */
        webd_upload_delete(owner_id, begin_meta.upload_id,
                           discard_err, sizeof(discard_err));
        ctx->status = 422;
        return webd_error("ota_staging_finalize_failed", err, "", "webd.ota");
    }

    data = json_object_new_object();
    json_object_object_add(data, "upload_id",
                           json_object_new_string(final_meta.upload_id));
    json_object_object_add(data, "upload_type",
                           json_object_new_string(final_meta.upload_type));
    json_object_object_add(data, "track", json_object_new_string(track));
    json_object_object_add(data, "filename", json_object_new_string(filename));
    json_object_object_add(data, "size_bytes",
                           json_object_new_int64((int64_t)final_meta.size_bytes));
    json_object_object_add(data, "sha256",
                           json_object_new_string(final_meta.sha256));
    /* The next step, spelled out so the UI does not have to hardcode it: hand
     * this upload_id to /api/v1/system/ota/verify, then .../apply. */
    json_object_object_add(data, "next",
                           json_object_new_string("/api/v1/system/ota/verify"));

    ctx->status = 200;
    return webd_envelope(data, "webd.ota");
}

static struct json_object *ota_remote_authorize(struct jmx_api_ctx *ctx)
{
    struct json_object *data = json_object_new_object();
    ctx->status = 200;
    json_object_object_add(data, "authorized", json_object_new_boolean(1));
    return webd_envelope(data, "webd.ota");
}

const struct jmx_api_route ota_remote_api_routes[] = {
    JMX_API_ROUTE(923, "/api/v1/system/ota/authorize", "POST", JMX_API_EXACT, ota_remote_authorize),
    JMX_API_ROUTE(921, "/api/v1/system/ota/check",    "POST", JMX_API_EXACT, ota_remote_check),
    JMX_API_ROUTE(922, "/api/v1/system/ota/download", "POST", JMX_API_EXACT, ota_remote_download),
    JMX_API_ROUTE_END,
};
