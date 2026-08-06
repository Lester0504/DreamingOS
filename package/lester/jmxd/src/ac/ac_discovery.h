// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AC_DISCOVERY_H
#define DREAMINGWRT_AC_DISCOVERY_H

#include <stdint.h>

#include <json-c/json.h>

/*
 * Controller-side discovery of not-yet-adopted APs.
 *
 * Direction matters here. The obvious design -- controller sweeps the
 * network and probes each host -- does not work in the deployment we
 * actually have: 30.1 has no route to 192.168.31.0/24, so it cannot reach
 * 31.31 at all, yet 31.31 is adopted because the *AP* dials in over
 * ap-control.v2. Discovery therefore follows the same direction as the
 * existing transport: APs announce themselves, the controller listens and
 * records candidates.
 *
 * A candidate is an unauthenticated claim. Nothing here grants trust:
 * adoption still requires the operator to confirm the fingerprint or supply
 * a pairing token, and the records below are explicitly not credentials.
 */

#define AC_DISCOVERY_BEACON_PORT 21517
#define AC_DISCOVERY_BEACON_MAGIC "DWRT-AP-BEACON/1"
#define AC_DISCOVERY_PAYLOAD_MAX 1024
/* Candidates older than this stop being offered; an AP that stopped
 * announcing is probably gone or already adopted elsewhere. */
#define AC_DISCOVERY_CANDIDATE_TTL_SECONDS 900
#define AC_DISCOVERY_MAX_CANDIDATES 256

struct ac_discovery_candidate {
    char ap_id[37];
    char key_id[72];
    char mac[18];
    char model[128];
    char board_name[64];
    char mgmt_ip[46];       /* observed source address, not a claimed one */
    char claimed_ip[46];    /* what the AP said, kept separate on purpose */
    uint16_t mgmt_port;
    int64_t first_seen;
    int64_t last_seen;
    int adopted_elsewhere;  /* AP reports an existing controller binding */
    char adopted_controller_id[37];
};

/* Starts/stops the passive beacon listener. Safe to call when the socket
 * cannot be bound; discovery then reports itself unavailable with a reason
 * rather than preventing ac from starting. */
int ac_discovery_start(void);
void ac_discovery_stop(void);

int ac_discovery_available(void);
const char *ac_discovery_reason(void);

/*
 * Records a beacon. Exposed so the ap-control session path can also feed
 * candidates: an AP that connects but is not adopted is a discovery signal
 * just as much as a UDP beacon, and it is a more trustworthy one because
 * the connection proves reachability.
 */
int ac_discovery_record(const struct ac_discovery_candidate *candidate);

/* Parses a beacon payload. Returns 0 on success. observed_ip is the real
 * source address and always wins over any address inside the payload. */
int ac_discovery_parse_beacon(const char *payload, size_t payload_len,
                              const char *observed_ip,
                              struct ac_discovery_candidate *out);

/* discovery_list ubus response: candidates seen but not adopted. */
struct json_object *ac_discovery_list_json(void);

/* Drops candidates that have aged past the TTL. */
void ac_discovery_expire(int64_t now);

#endif
