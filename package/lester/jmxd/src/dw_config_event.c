// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Shared configuration-commit failure reporter -- see dw_config_event.h.
 *
 * Modeled byte-for-byte on ac/ac_ubus.c's ac_report_device_event(), which is
 * the logd->notifyd path already verified end-to-end (event_add -> logd ->
 * default-warning route -> outbox). The only differences here are a
 * per-subsystem source daemon name and the ADMIN category / CONFIG_COMMIT_FAILED
 * event, plus a consistency->severity mapping.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "dw_config_event.h"

#define DW_CFG_EVENT_ID       "CONFIG_COMMIT_FAILED"
#define DW_CFG_EVENT_CATEGORY "ADMIN"
#define DW_CFG_LOGD_OBJECT    "dreamingwrt.logd"
#define DW_CFG_INVOKE_TIMEOUT 500

/*
 * Which daemon a subsystem lives in, for the event's "source". Kept here so
 * call sites pass only their stable subsystem slug and cannot disagree about
 * the source string. An unknown/NULL slug is sourced as core (the common case).
 */
static const char *dw_config_source_for(const char *subsystem)
{
    if (subsystem) {
        if (!strcmp(subsystem, "gateway_ports"))
            return "dreamingwrt-routed";
        if (!strcmp(subsystem, "flowd_nft_revision"))
            return "dreamingwrt-flowd";
    }
    return "dreamingwrt-core";
}

int dw_report_config_commit_failed(const char *subsystem, const char *target,
                                   const char *reason, int consistent)
{
    struct json_object *event = NULL;
    struct json_object *detail = NULL;
    struct blob_buf blob = {};
    struct ubus_context *ctx = NULL;
    uint32_t object_id = 0;
    const char *sub = (subsystem && subsystem[0]) ? subsystem : "config";
    const char *tgt = (target && target[0]) ? target : "-";
    const char *severity = consistent ? "error" : "critical";
    char stable_id[128];
    char dedupe_key[224];
    int blob_ready = 0;
    int rc = 0;

    /*
     * A private ephemeral ubus context, never a shared/global one: this helper
     * links into three daemons and can be called from any thread; a libubus
     * context is not safe to share across threads. A connect/free per call is
     * irrelevant since this only fires on a (deduped) commit failure. Mirrors
     * ac_report_device_event and otad_db.c's temporary_ctx.
     */
    ctx = ubus_connect(NULL);
    if (!ctx ||
        ubus_lookup_id(ctx, DW_CFG_LOGD_OBJECT, &object_id) != UBUS_STATUS_OK)
        goto done;

    event = json_object_new_object();
    detail = json_object_new_object();
    if (!event || !detail)
        goto done;

    snprintf(stable_id, sizeof(stable_id), "cfg-%s-%s", sub, tgt);
    /* dedupe on subsystem+target so a retried failing apply collapses to one
     * live alert per (surface, object). */
    snprintf(dedupe_key, sizeof(dedupe_key), "admin:config_commit_failed:%s:%s",
             sub, tgt);

    json_object_object_add(detail, "subsystem", json_object_new_string(sub));
    json_object_object_add(detail, "target",
        json_object_new_string((target && target[0]) ? target : ""));
    json_object_object_add(detail, "reason",
        json_object_new_string((reason && reason[0]) ? reason : ""));
    json_object_object_add(detail, "config_consistent",
        json_object_new_boolean(consistent ? 1 : 0));
    json_object_object_add(detail, "producer_source",
        json_object_new_string(dw_config_source_for(subsystem)));

    json_object_object_add(event, "id", json_object_new_string(stable_id));
    json_object_object_add(event, "severity", json_object_new_string(severity));
    json_object_object_add(event, "category",
                           json_object_new_string(DW_CFG_EVENT_CATEGORY));
    json_object_object_add(event, "event",
                           json_object_new_string(DW_CFG_EVENT_ID));
    json_object_object_add(event, "source",
                           json_object_new_string(dw_config_source_for(subsystem)));
    json_object_object_add(event, "title",
                           json_object_new_string("Configuration commit failed"));
    json_object_object_add(event, "target",
        json_object_new_string((target && target[0]) ? target : ""));
    json_object_object_add(event, "state", json_object_new_string("active"));
    json_object_object_add(event, "dedupe_key",
                           json_object_new_string(dedupe_key));
    json_object_object_add(event, "ts", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(event, "detail_json", detail);
    detail = NULL;

    blob_buf_init(&blob, 0);
    blob_ready = 1;
    if (!blobmsg_add_json_from_string(
            &blob, json_object_to_json_string_ext(event, JSON_C_TO_STRING_PLAIN)))
        goto done;
    rc = (ubus_invoke(ctx, object_id, "event_add", blob.head,
                      NULL, NULL, DW_CFG_INVOKE_TIMEOUT) == UBUS_STATUS_OK) ? 1 : 0;
done:
    if (blob_ready)
        blob_buf_free(&blob);
    if (detail)
        json_object_put(detail);
    if (event)
        json_object_put(event);
    if (ctx)
        ubus_free(ctx);
    return rc;
}
