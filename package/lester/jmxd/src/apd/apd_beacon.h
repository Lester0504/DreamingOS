// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_BEACON_H
#define DREAMINGWRT_APD_BEACON_H

/*
 * AP-side discovery beacon.
 *
 * While the AP is not adopted it broadcasts a small identity announcement so
 * a controller on the segment can list it as a candidate. The beacon stops
 * once the AP is adopted -- an adopted AP is inventory and keeps talking to
 * its controller over the established session instead.
 *
 * The payload is identity and connection information only. It carries no
 * key, token, or anything else that would let a listener adopt this AP, on
 * the same reasoning as the pasteable pairing code: broadcast traffic is
 * readable by everyone on the segment.
 */

#define APD_BEACON_PORT 21517
#define APD_BEACON_MAGIC "DWRT-AP-BEACON/1"
#define APD_BEACON_INTERVAL_SECONDS 30

int apd_beacon_start(void);
void apd_beacon_stop(void);
int apd_beacon_active(void);
const char *apd_beacon_reason(void);

#endif
