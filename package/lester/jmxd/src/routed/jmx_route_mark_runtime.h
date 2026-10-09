/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_ROUTE_MARK_RUNTIME_H__
#define __JMX_ROUTE_MARK_RUNTIME_H__

#include <stdint.h>
#include <time.h>

#define JMX_ROUTE_MARK_MAX_RULE_PRIOS 64

/*
 * Live conntrack fwmark snapshot for route_status.  The runtime subscribes to
 * ctnetlink NEW/UPDATE/DESTROY on a dedicated thread and keeps a compact
 * id -> mark table so the uloop thread never scans /proc/net/nf_conntrack.
 */
struct jmx_route_mark_counts {
    int64_t total;          /* conntrack entries examined */
    int64_t explicit_steer; /* matched an explicit (carrier) policy rule */
    int64_t load_balance;   /* matched the default load-balance rule */
    int64_t unsteered;      /* mark=0, no policy applied */
    int64_t unknown;        /* marked, but not attributable to a known rule */
    int prio[JMX_ROUTE_MARK_MAX_RULE_PRIOS];
    int64_t per_prio[JMX_ROUTE_MARK_MAX_RULE_PRIOS];
    int prio_n;
};

struct jmx_route_mark_runtime_status {
    int thread_started;
    int active;
    int supported;
    int dumping;
    int resync_needed;
    int overflow;
    int missing_id;
    int last_errno;
    uint64_t events_upsert;
    uint64_t events_destroy;
    uint64_t events_error;
    uint64_t enobufs;
    uint64_t dumps;
    uint64_t dump_entries;
    time_t last_full_sync;
    time_t dump_deadline;
    time_t updated_at;
};

int jmx_route_mark_runtime_start(void);
void jmx_route_mark_runtime_stop(void);
int jmx_route_mark_runtime_sample(const int *rule_prios,
                                  const int *rule_carriers,
                                  int rule_n,
                                  const int *wan_ids,
                                  int wan_n,
                                  struct jmx_route_mark_counts *out);
int jmx_route_mark_runtime_status(struct jmx_route_mark_runtime_status *out);

#endif
