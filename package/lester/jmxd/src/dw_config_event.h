// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Shared configuration-commit failure reporter. WS4 of the 2026-09-19
 * audit/error-observability handoff: "operation failed & needs user action ->
 * alert". This is the config-apply half of that (the AC/AP and PKI halves
 * already ship in ac_report_device_event).
 *
 * A single leaf helper linked into every daemon that owns a config-commit
 * path (dreamingwrt-core, dreamingwrt-routed, dreamingwrt-flowd). It emits a
 * structured CONFIG_COMMIT_FAILED event to dreamingwrt.logd via event_add;
 * logd's existing logd->notifyd bridge escalates it to the alert stream
 * (severity error/critical, both >= the default-warning route's threshold).
 *
 * Self-contained on purpose: it depends only on libubus / libubox / json-c
 * (all three binaries already link them) and never on any daemon's internals,
 * so the same object links unchanged into each. It uses a private ephemeral
 * ubus context (ubus_connect(NULL) ... ubus_free), exactly like
 * ac_report_device_event, so it is safe to call from any thread and from a
 * binary whose main context is owned by a different uloop.
 */
#ifndef DREAMINGWRT_DW_CONFIG_EVENT_H
#define DREAMINGWRT_DW_CONFIG_EVENT_H

/*
 * Report a configuration-commit failure to the log center.
 *
 * Fire-and-forget: never blocks the caller's control flow, never touches the
 * caller's response object, and silently no-ops (returns 0) if logd is not
 * reachable. Only ever call it on a genuine apply/commit-stage failure -- not
 * on a pure input-validation rejection (nothing was applied, nothing to
 * alert on), matching UniFi's DEVICE_COMMIT_ERROR semantics.
 *
 *   subsystem   stable slug for the apply surface -- one of "route_config",
 *               "system_service", "dhcp", "ipam_reservation",
 *               "gateway_ports", "flowd_nft_revision". Selects the reported
 *               source daemon name and is part of the dedupe key. A NULL or
 *               unknown slug still reports, sourced as dreamingwrt-core.
 *   target      the object the commit was for (WAN policy id, service name,
 *               lan_id, ...). May be NULL/"" when the site has none; it also
 *               joins the dedupe key so distinct targets alert separately.
 *   reason      machine reason string (failure_stage / failure_reason / error
 *               code). May be NULL/"".
 *   consistent  non-zero if the running configuration is in a known-good state
 *               after the failure (request rejected before apply, or the
 *               previous config was cleanly restored) -> severity "error";
 *               zero if a rollback itself failed and the runtime may be
 *               inconsistent -> severity "critical".
 *
 * Returns 1 if the event_add invoke succeeded, 0 otherwise.
 */
int dw_report_config_commit_failed(const char *subsystem, const char *target,
                                   const char *reason, int consistent);

#endif /* DREAMINGWRT_DW_CONFIG_EVENT_H */
