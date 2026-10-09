// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dreamingos-vm entry point.
 *
 * Startup is deliberately tolerant: the store and ubus object must come up, but
 * the libvirt connection is opened lazily (vm_conn) so a host where libvirtd is
 * not yet running, or where KVM is absent, still gets a live daemon that reports
 * its degraded state through status/capabilities instead of exiting.
 */
#include "vm_internal.h"

int64_t g_vm_started_at;

int64_t vm_now_s(void)
{
    return (int64_t)time(NULL);
}

static void vm_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

static void vm_usage(FILE *out)
{
    fprintf(out,
        "Usage: " VM_SERVICE_NAME " [--version|--help]\n"
        "  (no arguments)  run the VM management daemon\n"
        "  --version       print the contract version and exit\n");
}

int main(int argc, char **argv)
{
    int rc = 1;

    if (argc > 2) {
        vm_usage(stderr);
        return 2;
    }
    if (argc == 2) {
        if (!strcmp(argv[1], "--version")) {
            printf("%s %s (libvirt %u.%u.%u)\n", VM_SERVICE_NAME, VM_SCHEMA,
                   LIBVIR_VERSION_NUMBER / 1000000,
                   (LIBVIR_VERSION_NUMBER / 1000) % 1000,
                   LIBVIR_VERSION_NUMBER % 1000);
            return 0;
        }
        vm_usage(!strcmp(argv[1], "--help") ? stdout : stderr);
        return strcmp(argv[1], "--help") ? 2 : 0;
    }

    /* SIGPIPE would otherwise kill the process if a libvirt stream or ubus peer
     * hangs up mid-write. */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, vm_handle_signal);
    signal(SIGTERM, vm_handle_signal);
    g_vm_started_at = vm_now_s();

    /* libvirt's default error handler prints to stderr; route it away so a
     * missing connection does not spam the log. Errors are surfaced through the
     * contract instead. */
    virSetErrorFunc(NULL, NULL);

    if (vm_store_open() != 0) {
        fprintf(stderr, "[%s] startup failed stage=store\n", VM_SERVICE_NAME);
        return 1;
    }

    /* Workers reap their own children; uloop's waitpid(-1) would otherwise
     * steal a helper's exit status. */
    uloop_handle_sigchld = false;
    if (uloop_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=uloop_init\n", VM_SERVICE_NAME);
        goto fail_store;
    }
    if (vm_task_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=task_init\n", VM_SERVICE_NAME);
        goto fail_uloop;
    }
    if (vm_ubus_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=ubus_start\n", VM_SERVICE_NAME);
        goto fail_task;
    }

    fprintf(stderr, "[%s] started service_state=%s\n", VM_SERVICE_NAME,
            vm_service_state());
    uloop_run();
    rc = 0;

    vm_ubus_stop();
fail_task:
    vm_task_shutdown();
fail_uloop:
    uloop_done();
fail_store:
    vm_conn_close();
    vm_store_close();
    return rc;
}
