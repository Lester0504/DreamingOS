// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_RUNTIME_CACHE_H
#define WEBD_API_RUNTIME_CACHE_H

#define WEBD_CLIENTS_UPSTREAM_TIMEOUT_MS 1500
#define WEBD_CLIENTS_SHARED_CACHE_PATH "/tmp/dreamingwrt/clients-inventory.json"
#define WEBD_CLIENTS_SHARED_LOCK_PATH "/tmp/dreamingwrt/clients-inventory.lock"
#define WEBD_CLIENTS_SHARED_FRESH_MS 2000
#define WEBD_CLIENTS_SHARED_STALE_MS (5 * 60 * 1000)
#define WEBD_CLIENTS_SHARED_MAX_BYTES (1024U * 1024U)
#define WEBD_DASHBOARD_LIVE_SHARED_CACHE_PATH "/tmp/dreamingwrt/dashboard-live.json"
#define WEBD_DASHBOARD_LIVE_SHARED_LOCK_PATH "/tmp/dreamingwrt/dashboard-live.lock"
#define WEBD_DASHBOARD_LIVE_SHARED_FRESH_MS 2000
#define WEBD_DASHBOARD_LIVE_SHARED_STALE_MS 60000
#define WEBD_DASHBOARD_LIVE_SHARED_MAX_BYTES (768U * 1024U)

#endif
