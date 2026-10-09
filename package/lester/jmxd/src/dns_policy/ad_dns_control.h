/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DWRT_AD_DNS_CONTROL_H
#define DWRT_AD_DNS_CONTROL_H
#include <json-c/json.h>
#include <sqlite3.h>
#include <stdint.h>
struct ad_dns_environment {
    sqlite3 *db;
    const char *directory;
    const char *leases;
    int64_t now;
    unsigned dns_port;
    /* Return a concrete conflict for a rule blocked outside the DNS layer. */
    struct json_object *(*conflicts)(struct json_object *request);
};
int ad_dns_init(const struct ad_dns_environment *e);
struct json_object *ad_dns_canonical(const struct ad_dns_environment *,struct json_object *,int deleting);
int ad_dns_reconcile(const struct ad_dns_environment *e, int restart);
struct json_object *ad_dns_handle(const struct ad_dns_environment *e, const char *operation,
                                 struct json_object *request);
#endif
