// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_WAN_PROBE_H
#define DREAMINGWRT_WAN_PROBE_H

#include <stdint.h>

struct wan_probe_request {
    const char *ifname, *method, *target;
    const char *dns_servers, *body_marker;
    const int *expected_status;
    unsigned expected_status_count;
    int timeout_ms;
};

struct wan_probe_result {
    int ok, valid, address_family, http_status;
    int64_t started_at, finished_at;
    double latency_ms, dns_ms, tcp_ms, tls_ms;
    char source_ifname[16], source_address[64];
    char error_class[48];
};

/* No shell, default-interface fallback, proxy or unbound DNS lookup. */
int wan_probe_validate(const struct wan_probe_request *request);
int wan_probe_run(const struct wan_probe_request *request,
                   struct wan_probe_result *result);

#endif
