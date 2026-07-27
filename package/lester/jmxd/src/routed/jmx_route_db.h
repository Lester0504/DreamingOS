/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_ROUTE_DB_H__
#define __JMX_ROUTE_DB_H__

#include <stddef.h>
#include <json-c/json.h>

#define JMX_ROUTE_DB_PATH "/etc/dreamingwrt/config.db"
#define JMX_ROUTE_UCI_MIGRATION "jmx_route_uci_v1"

struct jmx_route_db_tx;

int jmx_route_db_config_get(struct json_object **config);
int jmx_route_db_replace_begin(struct json_object *request,
                               struct jmx_route_db_tx **tx,
                               struct json_object **previous,
                               struct json_object **readback,
                               char *error, size_t error_len);
int jmx_route_db_replace_commit(struct jmx_route_db_tx *tx);
void jmx_route_db_replace_rollback(struct jmx_route_db_tx *tx);

#endif
