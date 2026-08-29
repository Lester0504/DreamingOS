/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_SIGNATURE_DB_H__
#define __JMX_SIGNATURE_DB_H__

#include "jmx_rule.h"
#include <sqlite3.h>

#ifndef JMX_SIGNATURE_DB_HOT
#define JMX_SIGNATURE_DB_HOT     "/tmp/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SIGNATURE_DB_DEFAULT
#define JMX_SIGNATURE_DB_DEFAULT "/etc/dreamingwrt/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SIGNATURE_DB_NEW_SHARE
#define JMX_SIGNATURE_DB_NEW_SHARE "/usr/share/dreamingos/system-db/dreamingwrt_signatures.db"
#endif
#ifndef JMX_SIGNATURE_DB_SHARE
#define JMX_SIGNATURE_DB_SHARE   "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db"
#endif
#define JMX_SIGNATURE_CONTAINER_DEFAULT "/etc/dreamingwrt/dreamingwrt_signatures.dwsig"
#define JMX_SIGNATURE_CONTAINER_SHARE   "/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.dwsig"

int jmx_load_signature_db(const char *path, jmx_rule_set_t *rs);

/* Offline/test loader for a source SQLite database before sealing. */
int jmx_load_signature_db_plaintext_path(const char *path, jmx_rule_set_t *rs);

/* Production entry point. Route B accepts plaintext SQLite only at the four
 * exact managed authority paths above. A .dwsig path still uses the sealed
 * fail-closed parser so future Route A artifacts cannot be mistaken for DBs. */
int jmx_signature_db_open_path(const char *path, sqlite3 **db);
int jmx_signature_db_close_path(sqlite3 *db);
const char *jmx_signature_db_last_error(void);

/* Offline/build-time compatibility for tools that inspect a source SQLite DB.
 * Never use this entry point for a runtime signature authority. */
int jmx_signature_db_open_plaintext_path(const char *path, sqlite3 **db);

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
