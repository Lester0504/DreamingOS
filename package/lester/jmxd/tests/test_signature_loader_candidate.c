/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "jmx_signature_db.h"

int main(int argc, char **argv)
{
	jmx_rule_set_t legacy;
	jmx_chain_rule_set_t chain;
	int chain_status = -1;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s SIGNATURE_DB\n", argv[0]);
		return 2;
	}
	rc = jmx_load_signature_db_with_chain(
		argv[1], &legacy, &chain, JMX_V3_CAP_PHASE1_MASK, &chain_status);
	assert(rc == 0);
	assert(chain_status == 0);
	assert(legacy.app_info_count == 5873);
	assert(legacy.total_rules > 0);
	assert(legacy.total_rules == legacy.fast_rules + legacy.slow_rules);
	assert(chain.schema_v2_present == 1);
	assert(chain.stats.chain_db_rules == 6191);
	assert(chain.stats.chain_unresolved_rules == 6191);
	assert(chain.rule_count == 0);
	assert(chain.step_count == 0);
	assert(chain.port_count == 0);
	assert(chain.stats.chain_ready_rules == 0);
	assert(chain.stats.rejected_records == 0);
	printf(
		"ok apps=%u legacy=%u fast=%u slow=%u chain_db=%u chain_active=%zu\n",
		legacy.app_info_count, legacy.total_rules, legacy.fast_rules,
		legacy.slow_rules, chain.stats.chain_db_rules, chain.rule_count);
	jmx_rule_set_free(&legacy);
	jmx_chain_rule_set_free(&chain);
	return 0;
}
