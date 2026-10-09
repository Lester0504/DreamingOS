// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_TXPOWER_MODE_H
#define DREAMINGWRT_APD_TXPOWER_MODE_H

#include <json-c/json.h>

/*
 * 6 GHz transmit ceiling mode.
 *
 * "calibrated" is the driver default and the only safe mode on arbitrary
 * hardware: mt7996 clamps every channel to the EEPROM calibrated target.
 * "regulatory" drops that clamp and lets the regulatory database ceiling
 * stand on its own, which drives the PA above its factory calibration.
 *
 * The second mode is destructive on hardware that was not built for it, so
 * four independent gates must all pass before it can be selected:
 *
 *   1. the board is on the hardware allowlist below,
 *   2. the running mt7996e exposes the opt-in module parameter,
 *   3. the running regdb exposes the qualified 35 dBm ceiling,
 *   4. the caller passes confirm=true.
 *
 * apd never selects "regulatory" on its own: there is no default or
 * migration. Once the operator explicitly enables a mode, the selected mode
 * is persisted. Startup leaves existing wireless interfaces alone; applying
 * a different mode to them requires a confirmed operation in either direction.
 * A change quiesces and restarts the complete shared PHY; selecting an
 * already-applied ceiling does not restart wireless. A failed apply may roll
 * back to calibrated once, without repeated radio cycling.
 * Successful selections also update the APD-owned kmodloader option so a
 * subsequent boot establishes the ceiling before creating wireless interfaces.
 */
#define APD_TXPOWER_MODE_CALIBRATED "calibrated"
#define APD_TXPOWER_MODE_REGULATORY "regulatory"

/* W1700K high-power mode is only real when regdb exposes at least 35 dBm. */
#define APD_TXPOWER_REQUIRED_REG_CEILING_X10 350

#define APD_TXPOWER_MODE_MAX 31
#define APD_TXPOWER_REASON_MAX 127
#define APD_TXPOWER_BOARD_MAX 127
#define APD_TXPOWER_PHY_MAX 31
#define APD_TXPOWER_RADIO_MAX 63
#define APD_TXPOWER_ACTIVE_IFACE_MAX 8
#define APD_TXPOWER_IFACE_NAME_MAX 63

/* Volatile driver knob added by mt76 patch 042. */
#ifndef APD_TXPOWER_PARAM_PATH
#define APD_TXPOWER_PARAM_PATH \
    "/sys/module/mt7996e/parameters/txpower_from_regdb"
#endif

#ifndef APD_TXPOWER_PERSIST_PATH
#define APD_TXPOWER_PERSIST_PATH \
    "/etc/dreamingwrt/txpower_mode"
#endif

struct apd_txpower_mode_state {
    char mode[APD_TXPOWER_MODE_MAX + 1];
    char persisted_mode[APD_TXPOWER_MODE_MAX + 1];
    char restore_reason[APD_TXPOWER_REASON_MAX + 1];
    char board_name[APD_TXPOWER_BOARD_MAX + 1];
    char reason[APD_TXPOWER_REASON_MAX + 1];
    char phy[APD_TXPOWER_PHY_MAX + 1];
    char radio[APD_TXPOWER_RADIO_MAX + 1];
    char active_6ghz_interfaces[APD_TXPOWER_ACTIVE_IFACE_MAX]
                               [APD_TXPOWER_IFACE_NAME_MAX + 1];
    int active_6ghz_txpower_dbm_x10[APD_TXPOWER_ACTIVE_IFACE_MAX];
    int board_allowed;
    int param_present;
    int regdb_ready;
    int supported;
    int active_6ghz_interface_count;
    int active_6ghz_interface_overflow;
    int active_6ghz_readback_ok;
    int wireless_inventory_ok;
    int wireless_interfaces_present;
    int radio_reload_performed;
    int radio_reload_ok;
    int rollback_performed;
    int rollback_ok;
    int restore_pending;
    int restore_attempts;
    /* Highest 6 GHz ceiling iw reports, tenths of a dBm, -1 when unknown. */
    int ceiling_dbm_x10;
    /* Current regulatory-domain 6 GHz EIRP ceiling, -1 when unavailable. */
    int regulatory_ceiling_dbm_x10;
};

int apd_txpower_mode_state_collect(struct apd_txpower_mode_state *out);

/* Read-only. Always returns an object; never mutates driver state. */
struct json_object *apd_txpower_mode_json(void);

/*
 * Write path. Refuses with capability_disabled unless every gate passes.
 * On success the driver ceiling has been recomputed and read back, and the
 * observed 6 GHz ceiling is reported as evidence.
 */
struct json_object *apd_txpower_mode_set_json(const char *mode, int confirmed);

/*
 * Restore a persisted ceiling without cycling existing wireless interfaces.
 * Returns 0 if satisfied, -1 for read-only readiness retry, 1 if explicit
 * application is required, or 2 after a terminal failure.
 */
int apd_txpower_mode_restore_persisted(void);

/* Retry readiness only; an apply failure or existing interface is terminal. */
int apd_txpower_mode_restore_start(void);
void apd_txpower_mode_restore_stop(void);

#endif
