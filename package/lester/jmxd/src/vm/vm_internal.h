// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dreamingos-vm: the optional VM management daemon for DreamingWrt.
 *
 * It owns the libvirt/QEMU control plane behind the frozen vm.v1 contract
 * (todo/2026-09-23/Handoff/Backend-to-Front-dreamingos-vm.md). webd's api_vm.c
 * is a thin gateway that forwards the /api/v1/vm/ subtree to the `dreamingos.vm` ubus
 * object this daemon registers; the daemon holds the persistent truth.
 *
 * Optionality (PM handoff §2): this whole binary is compiled ONLY when
 * CONFIG_PACKAGE_dreamingos-vm is selected. A lean build never links libvirt.
 * The gateway is always present, so a router without this package still answers
 * /api/v1/vm/status with installed:false rather than a 404.
 *
 * libvirt or KVM being absent is a normal, explainable state — not a failure.
 * The daemon stays up serving status/capabilities so an operator can see why VM
 * creation is unavailable instead of finding a dead process.
 */
#ifndef DREAMINGOS_VM_INTERNAL_H
#define DREAMINGOS_VM_INTERNAL_H

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <sqlite3.h>

#define VM_SERVICE_NAME "dreamingos-vm"
#define VM_SCHEMA "vm.v1"
#define VM_SOURCE "webd.vm"

/* libvirt URI. qemu:///system is the host-wide privileged connection; the
 * daemon runs as the supervised system service, so this is the right scope. */
#ifndef VM_LIBVIRT_URI
#define VM_LIBVIRT_URI "qemu:///system"
#endif

/* Overridable at compile time so a test can exercise the real store against a
 * temporary directory instead of the live one. */
#ifndef VM_STATE_DIR
#define VM_STATE_DIR "/etc/dreamingwrt/vm"
#endif
#define VM_STORE_PATH VM_STATE_DIR "/vm.db"

/* Firmware descriptors installed by package/lester/ovmf; probed for the
 * capabilities firmware list. */
#ifndef VM_OVMF_DIR
#define VM_OVMF_DIR "/usr/share/OVMF"
#endif
#ifndef VM_QEMU_FW_DIR
#define VM_QEMU_FW_DIR "/usr/share/qemu/firmware"
#endif

/* ── shared globals (vm_main.c) ─────────────────────────────────────── */
extern int64_t g_vm_started_at;
int64_t vm_now_s(void);

/* ── connection management (vm_libvirt.c) ───────────────────────────────
 * vm_conn() lazily opens VM_LIBVIRT_URI and caches it, reconnecting if the
 * previous handle went stale. It returns NULL when libvirt is unreachable
 * (daemon not running, package missing) — callers must treat NULL as the
 * "service degraded" state, never as fatal.
 */
virConnectPtr vm_conn(void);
void vm_conn_close(void);
/* "ready" once libvirt answers, "degraded" when it cannot be reached. The
 * daemon itself being up means it is never "not_installed"/"stopped" here;
 * those states are the gateway's to report when this object is absent. */
const char *vm_service_state(void);
/* dependency_state members, each "ok"|"missing"|"unknown". */
void vm_dependency_state(const char **libvirt, const char **qemu,
                         const char **kvm);

/* ── capabilities + status + overview (vm_capabilities.c) ────────────── */
struct json_object *vm_status_json(void);        /* §3 data object */
struct json_object *vm_capabilities_json(void);   /* §5 data object */
struct json_object *vm_overview_json(void);       /* §4 overview data */
bool vm_kvm_present(void);                         /* /dev/kvm usable */
const char *vm_host_arch(void);                    /* uname machine */

/* ── instances: read (vm_libvirt.c) ─────────────────────────────────────
 * All return a heap json_object (data portion of the envelope) or NULL on OOM,
 * and set *http_status. A NULL libvirt connection yields 503 service_unavailable
 * shaped data==NULL so the ubus layer can emit the error envelope.
 */
struct json_object *vm_instance_list_json(int page, int page_size,
                                          const char *q, const char *state,
                                          int *http_status);
struct json_object *vm_instance_get_json(const char *id, int *http_status);

struct json_object *vm_pool_list_json(int page, int page_size, const char *q,
                                      const char *state, int *http_status);
struct json_object *vm_network_list_json(int page, int page_size, const char *q,
                                         const char *state, int *http_status);

/* ── instances: write ───────────────────────────────────────────────────
 * validate is synchronous (no reservation). create/delete are tasks: they
 * return a queued task_id via the task engine. action is synchronous for the
 * quick libvirt lifecycle verbs. Each sets *http_status; on the error path they
 * return a fully-formed error object (webd_error-compatible shape) so the ubus
 * layer forwards it verbatim.
 */
struct json_object *vm_instance_validate(struct json_object *config,
                                         int *http_status);
struct json_object *vm_instance_action(const char *id, struct json_object *body,
                                       int *http_status);
/* Task-worker entry points (called by vm_task.c). Return 0 on success and fill
 * *result_out (a data object: vm_id + canonical config/revision, or deleted
 * targets); return -1 and fill *error_out with a vm_error_obj on failure. The
 * caller owns both out objects. */
int vm_create_domain(struct json_object *config, struct json_object **result_out,
                     struct json_object **error_out);
int vm_delete_domain(const char *id, bool delete_owned_disks,
                     struct json_object **result_out,
                     struct json_object **error_out);

/* ── config <-> libvirt domain XML (vm_config.c) ─────────────────────────
 * vm_config_validate fills *field_errors (a json array, caller owns) and
 * returns 0 when the config is acceptable, -1 otherwise. vm_config_to_xml
 * renders a libvirt domain definition; the returned string is heap-owned.
 */
int vm_config_validate(struct json_object *config,
                       struct json_object **field_errors);
/* Append a { field, code, message } entry to a json array (field_errors or
 * warnings). Shared by vm_config.c and the validate path in vm_libvirt.c. */
void vm_fe_add(struct json_object *arr, const char *field,
               const char *code, const char *message);
char *vm_config_to_xml(struct json_object *config, const char *uuid,
                       char **err_out);
struct json_object *vm_domain_canonical_config(virConnectPtr conn,
                                               virDomainPtr dom);
const char *vm_domain_state_str(int state);
struct json_object *vm_domain_allowed_actions(int state);
/* True when `action` is valid from the given virDomainState; keeps the action
 * guard and the advertised allowed_actions in lockstep. */
bool vm_action_permitted(int state, const char *action);

/* ── persistent store: sqlite (vm_store.c) ───────────────────────────────
 * Holds the revision counter and request_id idempotency map, keyed by VM uuid.
 * libvirt is the source of truth for domain existence/state; the store only
 * carries what libvirt cannot (monotonic revision, client request_id -> task).
 */
int vm_store_open(void);
void vm_store_close(void);
sqlite3 *vm_store_db(void);
int64_t vm_store_revision_get(const char *uuid);
int64_t vm_store_revision_bump(const char *uuid);

/* ── task engine (vm_task.c) ─────────────────────────────────────────────
 * A minimal persisted async engine for create/delete/import/export. Quick
 * lifecycle actions do NOT go through it. Tasks survive a daemon restart via
 * the store and are reconciled to `interrupted` if they cannot resume.
 */
int vm_task_init(void);
void vm_task_shutdown(void);
/* kind is a stable string ("instance_create","instance_delete",...). payload is
 * borrowed for the duration of the call. Fills task_id (>=37 bytes) and returns
 * the queued task json (data portion). */
struct json_object *vm_task_submit(const char *kind, const char *object_id,
                                   struct json_object *payload,
                                   int *http_status);
struct json_object *vm_task_get_json(const char *task_id, int *http_status);
struct json_object *vm_task_list_json(int *http_status);
struct json_object *vm_task_cancel(const char *task_id, int *http_status);

/* ── ubus object (vm_ubus.c) ─────────────────────────────────────────── */
int vm_ubus_start(void);
void vm_ubus_stop(void);

/* ── small shared helpers (vm_model.c) ───────────────────────────────────
 * vm_error_obj builds the { ok:false, error:{code,message,details} } shape the
 * gateway forwards; details may be NULL. vm_data_obj wraps a data payload as
 * { ok:true, data:{...} }. Both add schema/source; meta is added by the gateway.
 */
struct json_object *vm_error_obj(const char *code, const char *message,
                                 struct json_object *details);
struct json_object *vm_data_obj(struct json_object *data);
bool vm_uuid_valid(const char *s);
void vm_uuid_generate(char *out /* >=37 */);

#endif /* DREAMINGOS_VM_INTERNAL_H */
