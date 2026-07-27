/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_SIGNATURE_DB_H__
#define __JMX_SIGNATURE_DB_H__

#include "jmx_rule.h"

#define JMX_SIGNATURE_DB_DEFAULT "/etc/dreamingwrt/dreamingwrt_signatures.db"
#define JMX_SIGNATURE_DB_SHARE   "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db"

int jmx_load_signature_db(const char *path, jmx_rule_set_t *rs);

/* Load legacy and optional schema-v2 chain records from one read-only SQLite
 * snapshot.  The function returns failure only when the legacy load fails.
 * chain_status receives 0 for a valid/absent v3 schema and -1 when v3 was
 * structurally rejected, allowing v2 to continue with the old v3 generation. */
int jmx_load_signature_db_with_chain(const char *path,
				     jmx_rule_set_t *legacy,
				     jmx_chain_rule_set_t *chain,
				     uint32_t engine_capabilities,
				     int *chain_status);

#endif
