#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "jmx_client_accounting.h"

int main(void)
{
	struct jmx_client_byte_counters counters = {0};

	assert(jmx_account_client_packet(
		&counters, JMX_CLIENT_PACKET_DIRECTION_UPLOAD, 100, false));
	assert(counters.in_bytes == 0);
	assert(counters.out_bytes == 100);
	assert(counters.total_bytes == 100);

	assert(jmx_account_client_packet(
		&counters, JMX_CLIENT_PACKET_DIRECTION_DOWNLOAD, 250, false));
	assert(counters.in_bytes == 250);
	assert(counters.out_bytes == 100);
	assert(counters.total_bytes == 350);

	assert(!jmx_account_client_packet(
		&counters, JMX_CLIENT_PACKET_DIRECTION_UPLOAD, 400, true));
	assert(!jmx_account_client_packet(
		&counters, JMX_CLIENT_PACKET_DIRECTION_UNKNOWN, 500, false));
	assert(!jmx_account_client_packet(
		&counters, JMX_CLIENT_PACKET_DIRECTION_DOWNLOAD, 0, false));
	assert(counters.in_bytes == 250);
	assert(counters.out_bytes == 100);
	assert(counters.total_bytes == 350);

	puts("ok: client app byte accounting fixture passed");
	return 0;
}
