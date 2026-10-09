/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DREAMINGWRT_OTAD_BOOT_CONTRACT_H
#define DREAMINGWRT_OTAD_BOOT_CONTRACT_H

/* Keep dreamingwrt-init and OTAD readiness validation on one schema list. */
#define OTAD_REQUIRED_DATABASES(X) \
    X("config", "/etc/dreamingwrt/config.db", "web_users") \
    X("apid", "/etc/dreamingwrt/apid.db", "web_sessions") \
    X("core", "/etc/dreamingwrt/dreamingwrt.db", "clients") \
    X("metrics", "/etc/dreamingwrt/metrics.db", "metric_bucket") \
    X("logd", "/etc/dreamingwrt/log.db", "log_events") \
    X("notifyd", "/etc/dreamingwrt/notify.db", "notify_outbox")

#define OTAD_REQUIRED_DATABASE_COUNT 6U
#define OTAD_REQUIRED_DATABASE_MASK ((1U << OTAD_REQUIRED_DATABASE_COUNT) - 1U)

#endif
