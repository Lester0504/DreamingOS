/* Drives the real jmx_db_client_online_verdict() extracted from src/jmx_db.c.
 * Each case is printed as one line so the Python harness can compare it with
 * the behaviour Acceptance observed on the live router. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

struct json_object;

#include "verdict_under_test.h"

struct scenario {
    const char *name;
    struct jmx_db_client_evidence ev;
};

static void set_states(struct jmx_db_client_evidence *ev, const char *shared,
                       const char *v4, const char *v6)
{
    snprintf(ev->neigh_state, sizeof(ev->neigh_state), "%s", shared ? shared : "");
    snprintf(ev->neigh_state_v4, sizeof(ev->neigh_state_v4), "%s", v4 ? v4 : "");
    snprintf(ev->neigh_state_v6, sizeof(ev->neigh_state_v6), "%s", v6 ? v6 : "");
}

int main(void)
{
    struct scenario cases[16];
    size_t n = 0;
    size_t i;

    memset(cases, 0, sizeof(cases));

    /* 1. The reported ghost: 30.222/30.199. DB still says online, an IPv6 STALE
     *    entry lingers, IPv4 has gone FAILED, no traffic, not in the bridge FDB
     *    and the runtime node still claims "arp". Must end up offline. */
    cases[n].name = "ghost_v6_stale_v4_failed";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.sample_age_ms = 5000;
    cases[n].ev.last_seen_age = 4000;
    cases[n].ev.bridge_fdb_present = 0;
    cases[n].ev.runtime_online_source = "arp";
    set_states(&cases[n].ev, "STALE", "FAILED", "STALE");
    n++;

    /* 2. Same but the bridge could not be read: FAILED IPv4 alone must still
     *    win, because that is negative evidence on its own. */
    cases[n].name = "ghost_v4_failed_fdb_unreadable";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.sample_age_ms = 5000;
    cases[n].ev.last_seen_age = 10;
    cases[n].ev.bridge_fdb_present = -1;
    cases[n].ev.runtime_online_source = "arp";
    set_states(&cases[n].ev, "STALE", "FAILED", "STALE");
    n++;

    /* 3. IPv6-only client, genuinely reachable over v6, absent v4 evidence.
     *    Must stay online: the fix must not exclude IPv6-only devices. */
    cases[n].name = "ipv6_only_reachable";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.sample_age_ms = 3000;
    cases[n].ev.last_seen_age = 5;
    cases[n].ev.bridge_fdb_present = 1;
    cases[n].ev.runtime_online_source = "neigh";
    set_states(&cases[n].ev, "REACHABLE", "", "REACHABLE");
    n++;

    /* 4. Real device 192.168.30.2: REACHABLE and in the FDB. Regression guard. */
    cases[n].name = "real_device_reachable_in_fdb";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.sample_age_ms = 2000;
    cases[n].ev.last_seen_age = 3;
    cases[n].ev.bridge_fdb_present = 1;
    cases[n].ev.runtime_online_source = "arp";
    set_states(&cases[n].ev, "REACHABLE", "REACHABLE", "STALE");
    n++;

    /* 5. Idle but present: no traffic, in the FDB, REACHABLE on v4. A quiet
     *    laptop must not be declared offline. */
    cases[n].name = "idle_reachable_no_traffic";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 0;
    cases[n].ev.sample_age_ms = 1000;
    cases[n].ev.last_seen_age = 30;
    cases[n].ev.bridge_fdb_present = 1;
    cases[n].ev.runtime_online_source = "arp";
    set_states(&cases[n].ev, "REACHABLE", "REACHABLE", "");
    n++;

    /* 6. Traffic beats FDB absence: a client bridged behind an AP may not
     *    appear in this router's FDB while clearly moving bytes. */
    cases[n].name = "traffic_overrides_fdb_absence";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.tx_rate = 4096;
    cases[n].ev.rx_rate = 8192;
    cases[n].ev.sample_age_ms = 1500;
    cases[n].ev.last_seen_age = 1;
    cases[n].ev.bridge_fdb_present = 0;
    cases[n].ev.runtime_online_source = "traffic";
    set_states(&cases[n].ev, "STALE", "STALE", "STALE");
    n++;

    /* 7. Conntrack beats FDB absence too. */
    cases[n].name = "conntrack_overrides_fdb_absence";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.connections = 7;
    cases[n].ev.sample_age_ms = 1500;
    cases[n].ev.last_seen_age = 2;
    cases[n].ev.bridge_fdb_present = 0;
    cases[n].ev.runtime_online_source = "conntrack";
    set_states(&cases[n].ev, "STALE", "STALE", "STALE");
    n++;

    /* 8. STALE only, no FDB entry, nothing else: the vanished-VM shape without
     *    an explicit FAILED. Must be offline via the FDB cross-check. */
    cases[n].name = "stale_only_absent_from_fdb";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.sample_age_ms = 5000;
    cases[n].ev.last_seen_age = 20;
    cases[n].ev.bridge_fdb_present = 0;
    cases[n].ev.runtime_online_source = "arp";
    set_states(&cases[n].ev, "STALE", "STALE", "STALE");
    n++;

    /* 9. STALE only but present in the FDB: the bridge has seen a frame, so
     *    this stays online. Guards against over-reaching. */
    cases[n].name = "stale_only_present_in_fdb";
    cases[n].ev.db_online = 1;
    cases[n].ev.runtime_online = 1;
    cases[n].ev.sample_age_ms = 5000;
    cases[n].ev.last_seen_age = 20;
    cases[n].ev.bridge_fdb_present = 1;
    cases[n].ev.runtime_online_source = "arp";
    set_states(&cases[n].ev, "STALE", "STALE", "STALE");
    n++;

    /* 10. Offline in the DB stays offline and must not claim a live source. */
    cases[n].name = "db_offline_stays_offline";
    cases[n].ev.db_online = 0;
    cases[n].ev.runtime_online = 0;
    cases[n].ev.sample_age_ms = -1;
    cases[n].ev.last_seen_age = -1;
    cases[n].ev.bridge_fdb_present = -1;
    cases[n].ev.runtime_online_source = "arp";
    set_states(&cases[n].ev, "", "", "");
    n++;

    for (i = 0; i < n; i++) {
        struct jmx_db_client_verdict v;

        memset(&v, 0, sizeof(v));
        jmx_db_client_online_verdict(&cases[i].ev, &v);
        printf("%s online=%d neigh_failed=%d neigh_reachable=%d "
               "sample_valid=%d online_source=%s zero_reason=%s\n",
               cases[i].name, v.online, v.neigh_failed, v.neigh_reachable,
               v.sample_valid,
               v.online_source && v.online_source[0] ? v.online_source : "-",
               v.zero_reason && v.zero_reason[0] ? v.zero_reason : "-");
    }
    return 0;
}
