// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AUTHORITY_DIAGNOSTICS_H
#define DREAMINGWRT_AUTHORITY_DIAGNOSTICS_H

#include <json-c/json.h>

#define JMX_AUTHORITY_DIAGNOSTICS_CONTRACT "authority-diagnostics.v1"

/* Read-only authority inventory.  This module never renames, removes, or
 * writes a database. */
struct json_object *jmx_authority_diagnostics_json(void);

#endif
