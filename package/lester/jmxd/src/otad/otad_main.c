// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt OTA daemon. Slot writes are restricted to verified inactive A/B slots. */
#include "otad_internal.h"

static void otad_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
	int rc;

	signal(SIGINT, otad_handle_signal);
	signal(SIGTERM, otad_handle_signal);

	if (otad_db_init() != 0)
		return 1;
	if (argc == 3 && !strcmp(argv[1], "--operation-worker")) {
		rc = otad_operation_worker(argv[2]);
		otad_db_close();
		return rc;
	}
	if (argc != 1) {
		fprintf(stderr, "Usage: dreamingwrt-otad [--operation-worker <operation-id>]\n");
		otad_db_close();
		return 2;
	}
	uloop_init();
    if (otad_ubus_start() != 0) {
        uloop_done();
        otad_db_close();
        return 1;
    }

    otad_reconcile_boot_state();
    otad_confirm_timer_start();

    fprintf(stderr, "[dreamingwrt-otad] started config=%s inventory=%s ab_apply=guarded\n",
            OTAD_CONFIG_DB_PATH, OTAD_INVENTORY_DB_PATH);
    uloop_run();

    otad_ubus_stop();
    uloop_done();
    otad_db_close();
    return 0;
}
