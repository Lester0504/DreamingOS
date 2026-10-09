#include "../dw_business_event.h"
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * libvirt control plane for dreamingos-vm: connection caching, instance reads
 * (§4 list/get), the synchronous validate (§6) and lifecycle actions (§4), and
 * the create/delete task workers (§7) driven by vm_task.c.
 *
 * Return conventions (frozen with the ubus layer):
 *   - reads (list/get) return the INNER data object or NULL; on NULL the caller
 *     builds the error envelope from *http_status.
 *   - validate/action return the FULL { ok, data|error } body (vm_data_obj /
 *     vm_error_obj); the ubus layer forwards them verbatim.
 *   - the task workers return 0 (+*result_out data) or -1 (+*error_out error obj).
 *
 * libvirt is the source of truth for domain existence and state; the sqlite
 * store only carries the monotonic revision (§10).
 */
#include "vm_internal.h"
#include <ctype.h>
#include <limits.h>

static virConnectPtr g_conn;

/* Lazily open VM_LIBVIRT_URI and cache it; reopen if the cached handle went
 * stale (libvirtd restarted). NULL means libvirt is unreachable — every caller
 * treats that as the "service degraded"/503 state, never as fatal. */
virConnectPtr vm_conn(void)
{
    if (g_conn) {
        if (virConnectIsAlive(g_conn) == 1)
            return g_conn;
        virConnectClose(g_conn);
        g_conn = NULL;
    }
    g_conn = virConnectOpen(VM_LIBVIRT_URI);
    return g_conn;
}

void vm_conn_close(void)
{
    if (g_conn) {
        virConnectClose(g_conn);
        g_conn = NULL;
    }
}

static const char *vm_last_err_msg(void)
{
    const char *m = virGetLastErrorMessage();
    return (m && *m) ? m : "unknown libvirt error";
}
const char *vm_service_state(void)
{
    return vm_conn() ? "ready" : "degraded";
}

void vm_dependency_state(const char **libvirt, const char **qemu, const char **kvm)
{
    virConnectPtr c = vm_conn();

    *libvirt = c ? "ok" : "missing";
    /* Without a live connection we cannot honestly probe the qemu driver. */
    *qemu = c ? "ok" : "unknown";
    *kvm = vm_kvm_present() ? "ok" : "missing";
}

/* Only libvirt-defined directory pools and networks are selectable references.
 * Host paths are not part of these read contracts. */
static int vm_xml_attribute(const char *xml, const char *tag, const char *attribute,
                             char *out, size_t size)
{
    char prefix[64];
    const char *start, *end, *p;
    out[0] = '\0';
    if (!xml || !size) return 0;
    snprintf(prefix, sizeof(prefix), "<%s", tag);
    start = xml;
    while ((start = strstr(start, prefix)) != NULL) {
        char next = start[strlen(prefix)];
        if (isspace((unsigned char)next) || next == '>' || next == '/') break;
        start += strlen(prefix);
    }
    if (!start || !(end = strchr(start, '>'))) return 0;
    p = start + strlen(prefix);
    while (p < end) {
        const char *name, *value;
        size_t name_len, value_len;
        char quote;
        while (p < end && isspace((unsigned char)*p)) p++;
        name = p;
        while (p < end && (isalnum((unsigned char)*p) || *p == '_' || *p == '-')) p++;
        name_len = (size_t)(p - name);
        if (!name_len) break;
        while (p < end && isspace((unsigned char)*p)) p++;
        if (p >= end || *p++ != '=') break;
        while (p < end && isspace((unsigned char)*p)) p++;
        if (p >= end || (*p != '\'' && *p != '"')) break;
        quote = *p++; value = p;
        while (p < end && *p != quote) p++;
        value_len = (size_t)(p - value);
        if (p >= end) break;
        if (name_len == strlen(attribute) && !strncmp(name, attribute, name_len)) {
            if (value_len >= size) return 0;
            memcpy(out, value, value_len); out[value_len] = '\0'; return 1;
        }
        p++;
    }
    return 0;
}
static struct json_object *vm_reference_list_data(struct json_object *items,
                                                  int page, int page_size, int total)
{
    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "schema", json_object_new_string(VM_SCHEMA));
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "page", json_object_new_int(page));
    json_object_object_add(data, "page_size", json_object_new_int(page_size));
    json_object_object_add(data, "total", json_object_new_int(total));
    return data;
}
static int vm_reference_page(int *page, int *page_size)
{
    if (*page < 1) *page = 1;
    if (*page_size < 1) *page_size = 20;
    if (*page_size > 200) *page_size = 200;
    return *page <= INT_MAX / *page_size;
}
struct json_object *vm_pool_list_json(int page, int page_size, const char *q,
                                      const char *state, int *http_status)
{
    virConnectPtr conn = vm_conn();
    virStoragePoolPtr *pools = NULL;
    struct json_object *items = json_object_new_array();
    int count, matched = 0;
    if (!conn) { *http_status = 503; json_object_put(items); return NULL; }
    if (!vm_reference_page(&page, &page_size)) { *http_status = 400; json_object_put(items); return NULL; }
    count = virConnectListAllStoragePools(conn, &pools, VIR_CONNECT_LIST_STORAGE_POOLS_DIR);
    if (count < 0) { *http_status = 503; json_object_put(items); return NULL; }
    for (int i = 0; i < count; ++i) {
        const char *name = virStoragePoolGetName(pools[i]);
        const char *pool_state;
        int active = virStoragePoolIsActive(pools[i]);
        virStoragePoolInfo info;
        char uuid[VIR_UUID_STRING_BUFLEN] = {0};
        if (active < 0 || virStoragePoolGetUUIDString(pools[i], uuid) < 0 ||
            virStoragePoolGetInfo(pools[i], &info) < 0) goto fail;
        pool_state = active ? "active" : "inactive";
        if (q && *q && (!name || !strstr(name, q))) continue;
        if (state && *state && strcmp(state, pool_state)) continue;
        if (matched++ < (page - 1) * page_size || matched > page * page_size) continue;
        struct json_object *item = json_object_new_object();
        struct json_object *volumes = json_object_new_array();
        virStorageVolPtr *vols = NULL;
        int nvols = active ? virStoragePoolListAllVolumes(pools[i], &vols, 0) : 0;
        if (nvols < 0) { json_object_put(item); json_object_put(volumes); goto fail; }
        for (int v = 0; v < nvols; ++v) {
            virStorageVolInfo vi;
            const char *vname = virStorageVolGetName(vols[v]);
            if (virStorageVolGetInfo(vols[v], &vi) == 0 && vname) {
                struct json_object *volume = json_object_new_object();
                json_object_object_add(volume, "name", json_object_new_string(vname));
                json_object_object_add(volume, "capacity_bytes", json_object_new_int64((int64_t)vi.capacity));
                json_object_object_add(volume, "allocation_bytes", json_object_new_int64((int64_t)vi.allocation));
                json_object_array_add(volumes, volume);
            }
            virStorageVolFree(vols[v]);
        }
        free(vols);
        json_object_object_add(item, "id", json_object_new_string(uuid));
        json_object_object_add(item, "name", json_object_new_string(name ? name : ""));
        json_object_object_add(item, "type", json_object_new_string("dir"));
        json_object_object_add(item, "state", json_object_new_string(pool_state));
        json_object_object_add(item, "active", json_object_new_boolean(active));
        json_object_object_add(item, "capacity_bytes", json_object_new_int64((int64_t)info.capacity));
        json_object_object_add(item, "allocation_bytes", json_object_new_int64((int64_t)info.allocation));
        json_object_object_add(item, "available_bytes", json_object_new_int64((int64_t)info.available));
        json_object_object_add(item, "volumes", volumes);
        json_object_array_add(items, item);
    }
    for (int i = 0; i < count; i++) virStoragePoolFree(pools[i]);
    free(pools); *http_status = 200;
    return vm_reference_list_data(items, page, page_size, matched);
fail:
    for (int i = 0; i < count; i++) virStoragePoolFree(pools[i]);
    free(pools); json_object_put(items); *http_status = 503; return NULL;
}
struct json_object *vm_network_list_json(int page, int page_size, const char *q,
                                         const char *state, int *http_status)
{
    virConnectPtr conn = vm_conn();
    virNetworkPtr *nets = NULL;
    struct json_object *items = json_object_new_array();
    int count, matched = 0;
    if (!conn) { *http_status = 503; json_object_put(items); return NULL; }
    if (!vm_reference_page(&page, &page_size)) { *http_status = 400; json_object_put(items); return NULL; }
    count = virConnectListAllNetworks(conn, &nets, 0);
    if (count < 0) { *http_status = 503; json_object_put(items); return NULL; }
    for (int i = 0; i < count; ++i) {
        const char *name = virNetworkGetName(nets[i]);
        int active = virNetworkIsActive(nets[i]);
        const char *net_state = active ? "active" : "inactive";
        char uuid[VIR_UUID_STRING_BUFLEN] = {0}, mode[32] = "", virtualport[32] = "";
        char *xml;
        if (active < 0 || virNetworkGetUUIDString(nets[i], uuid) < 0) goto fail;
        if (q && *q && (!name || !strstr(name, q))) continue;
        if (state && *state && strcmp(state, net_state)) continue;
        if (matched++ < (page - 1) * page_size || matched > page * page_size) continue;
        xml = virNetworkGetXMLDesc(nets[i], 0);
        if (!xml) goto fail;
        vm_xml_attribute(xml, "forward", "mode", mode, sizeof(mode));
        vm_xml_attribute(xml, "virtualport", "type", virtualport, sizeof(virtualport));
        struct json_object *item = json_object_new_object();
        const char *kind = !strcmp(virtualport, "openvswitch") ? "ovs" : mode[0] ? mode : "isolated";
        json_object_object_add(item, "id", json_object_new_string(uuid));
        json_object_object_add(item, "name", json_object_new_string(name ? name : ""));
        json_object_object_add(item, "mode", json_object_new_string(kind));
        json_object_object_add(item, "state", json_object_new_string(net_state));
        json_object_object_add(item, "active", json_object_new_boolean(active));
        json_object_array_add(items, item);
        free(xml);
    }
    for (int i = 0; i < count; i++) virNetworkFree(nets[i]);
    free(nets); *http_status = 200;
    return vm_reference_list_data(items, page, page_size, matched);
fail:
    for (int i = 0; i < count; i++) virNetworkFree(nets[i]);
    free(nets); json_object_put(items); *http_status = 503; return NULL;
}

/* Case-sensitive substring; kept dependency-free (no strcasestr) so the cross
 * toolchain need not define _GNU_SOURCE. */
struct json_object *vm_instance_list_json(int page, int page_size, const char *q,
                                          const char *state, int *http_status)
{
    virConnectPtr conn = vm_conn();
    virDomainPtr *doms = NULL;
    int ndoms, i, matched = 0, from, to;
    struct json_object *d, *items;

    if (!conn) { *http_status = 503; return NULL; }
    if (page < 1) page = 1;
    if (page_size < 1) page_size = 20;
    if (page_size > 200) page_size = 200;

    ndoms = virConnectListAllDomains(conn, &doms, 0);
    if (ndoms < 0) { *http_status = 503; return NULL; }

    from = (page - 1) * page_size;
    to = from + page_size;
    d = json_object_new_object();
    items = json_object_new_array();

    for (i = 0; i < ndoms; i++) {
        const char *name = virDomainGetName(doms[i]);
        char uuid[VIR_UUID_STRING_BUFLEN] = { 0 };
        int st = VIR_DOMAIN_NOSTATE;

        if (virDomainGetState(doms[i], &st, NULL, 0) < 0)
            st = VIR_DOMAIN_NOSTATE;
        if (q && *q && (!name || !strstr(name, q)))
            goto next;
        if (state && *state && strcmp(vm_domain_state_str(st), state))
            goto next;
        if (matched >= from && matched < to) {
            struct json_object *it = json_object_new_object();

            virDomainGetUUIDString(doms[i], uuid);
            json_object_object_add(it, "id", json_object_new_string(uuid));
            json_object_object_add(it, "name", json_object_new_string(name ? name : ""));
            json_object_object_add(it, "state", json_object_new_string(vm_domain_state_str(st)));
            json_object_object_add(it, "revision", json_object_new_int64(vm_store_revision_get(uuid)));
            json_object_object_add(it, "allowed_actions", vm_domain_allowed_actions(st));
            json_object_array_add(items, it);
        }
        matched++;
    next:
        virDomainFree(doms[i]);
    }
    free(doms);

    json_object_object_add(d, "items", items);
    json_object_object_add(d, "page", json_object_new_int(page));
    json_object_object_add(d, "page_size", json_object_new_int(page_size));
    json_object_object_add(d, "total", json_object_new_int(matched));
    *http_status = 200;
    return d;
}
struct json_object *vm_instance_get_json(const char *id, int *http_status)
{
    virConnectPtr conn = vm_conn();
    virDomainPtr dom;
    char uuid[VIR_UUID_STRING_BUFLEN] = { 0 };
    int st = VIR_DOMAIN_NOSTATE;
    struct json_object *d;

    if (!conn) { *http_status = 503; return NULL; }
    if (!id || !vm_uuid_valid(id)) { *http_status = 404; return NULL; }
    dom = virDomainLookupByUUIDString(conn, id);
    if (!dom) { *http_status = 404; return NULL; }

    virDomainGetUUIDString(dom, uuid);
    if (virDomainGetState(dom, &st, NULL, 0) < 0)
        st = VIR_DOMAIN_NOSTATE;

    d = json_object_new_object();
    json_object_object_add(d, "id", json_object_new_string(uuid));
    json_object_object_add(d, "state", json_object_new_string(vm_domain_state_str(st)));
    json_object_object_add(d, "revision", json_object_new_int64(vm_store_revision_get(uuid)));
    json_object_object_add(d, "allowed_actions", vm_domain_allowed_actions(st));
    json_object_object_add(d, "config", vm_domain_canonical_config(conn, dom));
    virDomainFree(dom);
    *http_status = 200;
    return d;
}
/* §6 pre-check. Returns 200 with { valid, field_errors[], warnings[] } as data —
 * validate reports problems as payload, it does not itself fail with 422; the
 * create POST is where invalid_config/422 happens. Accepts either the raw create
 * config or a { "config": {...} } wrapper so the gateway need not unwrap. */
struct json_object *vm_instance_validate(struct json_object *config, int *http_status)
{
    struct json_object *cfg = config, *inner, *v;
    struct json_object *field_errors = NULL, *warnings, *data;
    const char *accel = "auto", *fw = "bios";
    bool kvm = vm_kvm_present();

    if (config && json_object_object_get_ex(config, "config", &inner) &&
        json_object_is_type(inner, json_type_object))
        cfg = inner;

    vm_config_validate(cfg, &field_errors);   /* always allocates field_errors */
    warnings = json_object_new_array();

    if (cfg && json_object_object_get_ex(cfg, "accelerator", &v))
        accel = json_object_get_string(v);
    if (cfg && json_object_object_get_ex(cfg, "firmware", &v))
        fw = json_object_get_string(v);

    /* Honest capability gating (§11): what will hard-fail at create becomes a
     * blocking field_error now; a silent-but-degraded choice becomes a warning. */
    if (!strcmp(accel, "kvm") && !kvm)
        vm_fe_add(field_errors, "accelerator", "capability_disabled",
                  "no /dev/kvm on this host; use tcg or auto");
    else if (!strcmp(accel, "auto") && !kvm)
        vm_fe_add(warnings, "accelerator", "kvm_device_absent",
                  "no KVM; will run under TCG (software, slow)");

    if (!strcmp(fw, "uefi_secureboot") &&
        access(VM_OVMF_DIR "/OVMF_CODE.secboot.fd", F_OK) != 0 &&
        access(VM_OVMF_DIR "/OVMF_CODE_4M.secboot.fd", F_OK) != 0)
        vm_fe_add(field_errors, "firmware", "capability_disabled",
                  "no secure-boot OVMF firmware present");

    if (cfg && json_object_object_get_ex(cfg, "tpm", &v) && json_object_get_boolean(v) &&
        access("/usr/bin/swtpm", F_OK) != 0)
        vm_fe_add(field_errors, "tpm", "dependency_missing", "swtpm not installed");

    data = json_object_new_object();
    json_object_object_add(data, "valid",
                           json_object_new_boolean(json_object_array_length(field_errors) == 0));
    json_object_object_add(data, "field_errors", field_errors);
    json_object_object_add(data, "warnings", warnings);
    *http_status = 200;
    return vm_data_obj(data);
}
static struct json_object *vm_instance_action_execute(const char *id, struct json_object *body,
                                       int *http_status)
{
    virConnectPtr conn = vm_conn();
    virDomainPtr dom;
    struct json_object *v, *det;
    const char *action = NULL;
    char uuid[VIR_UUID_STRING_BUFLEN] = { 0 };
    int st = VIR_DOMAIN_NOSTATE, rc = -1, nst;
    int64_t want_rev = -1, cur_rev, nrev;
    bool confirm = false;

    if (!conn) { *http_status = 503;
        return vm_error_obj("service_unavailable", "libvirt unreachable", NULL); }
    if (!id || !vm_uuid_valid(id)) { *http_status = 404;
        return vm_error_obj("not_found", "no such vm", NULL); }
    if (body && json_object_object_get_ex(body, "action", &v))
        action = json_object_get_string(v);
    if (!action || !*action) { *http_status = 400;
        return vm_error_obj("bad_request", "action is required", NULL); }
    if (body && json_object_object_get_ex(body, "confirm", &v))
        confirm = json_object_get_boolean(v);
    if (body && json_object_object_get_ex(body, "revision", &v))
        want_rev = json_object_get_int64(v);

    dom = virDomainLookupByUUIDString(conn, id);
    if (!dom) { *http_status = 404;
        return vm_error_obj("not_found", "no such vm", NULL); }
    virDomainGetUUIDString(dom, uuid);
    if (virDomainGetState(dom, &st, NULL, 0) < 0)
        st = VIR_DOMAIN_NOSTATE;

    cur_rev = vm_store_revision_get(uuid);
    if (want_rev >= 0 && want_rev != cur_rev) {
        det = json_object_new_object();
        json_object_object_add(det, "current_revision", json_object_new_int64(cur_rev));
        virDomainFree(dom);
        *http_status = 409;
        return vm_error_obj("revision_conflict", "stale revision", det);
    }
    /* Hard, data-risky verbs need explicit confirm:true (§4). */
    if ((!strcmp(action, "force_stop") || !strcmp(action, "reset")) && !confirm) {
        det = json_object_new_object();
        json_object_object_add(det, "impact",
            json_object_new_string("abrupt power action may lose unsaved guest state"));
        virDomainFree(dom);
        *http_status = 409;
        return vm_error_obj("requires_confirm", "this action requires confirm:true", det);
    }
    /* allowed_actions is the single source of truth for what a state accepts. */
    if (!vm_action_permitted(st, action)) {
        det = json_object_new_object();
        json_object_object_add(det, "state", json_object_new_string(vm_domain_state_str(st)));
        json_object_object_add(det, "allowed_actions", vm_domain_allowed_actions(st));
        virDomainFree(dom);
        *http_status = 409;
        return vm_error_obj("invalid_state", "action not allowed in current state", det);
    }
    if (!strcmp(action, "start"))           rc = virDomainCreate(dom);
    else if (!strcmp(action, "shutdown"))   rc = virDomainShutdown(dom);
    else if (!strcmp(action, "reboot"))     rc = virDomainReboot(dom, 0);
    else if (!strcmp(action, "reset"))      rc = virDomainReset(dom, 0);
    else if (!strcmp(action, "pause"))      rc = virDomainSuspend(dom);
    else if (!strcmp(action, "resume"))     rc = virDomainResume(dom);
    else if (!strcmp(action, "force_stop")) rc = virDomainDestroy(dom);

    if (rc < 0) {
        /* Action was permitted for the state but libvirt still refused it —
         * almost always a race with another in-flight operation on the domain. */
        det = json_object_new_object();
        json_object_object_add(det, "libvirt", json_object_new_string(vm_last_err_msg()));
        virDomainFree(dom);
        *http_status = 409;
        return vm_error_obj("vm_busy", "hypervisor rejected the action", det);
    }

    nrev = vm_store_revision_bump(uuid);
    nst = VIR_DOMAIN_NOSTATE;
    if (virDomainGetState(dom, &nst, NULL, 0) < 0)
        nst = st;
    det = json_object_new_object();
    json_object_object_add(det, "id", json_object_new_string(uuid));
    json_object_object_add(det, "action", json_object_new_string(action));
    json_object_object_add(det, "result", json_object_new_string(
        !strcmp(action, "shutdown") || !strcmp(action, "reboot") ? "accepted" : "success"));
    json_object_object_add(det, "state", json_object_new_string(vm_domain_state_str(nst)));
    json_object_object_add(det, "revision", json_object_new_int64(nrev < 0 ? cur_rev : nrev));
    json_object_object_add(det, "allowed_actions", vm_domain_allowed_actions(nst));
    virDomainFree(dom);
    *http_status = 200;
    return vm_data_obj(det);
}
struct json_object *vm_instance_action(const char *id, struct json_object *body,
                                       int *http_status)
{
    struct json_object *reply = vm_instance_action_execute(id, body, http_status);
    struct json_object *detail = json_object_new_object(), *v = NULL, *data = NULL, *context = NULL;
    int ok = reply && json_object_object_get_ex(reply, "ok", &v) && json_object_get_boolean(v);
    json_object_object_add(detail, "object_id", json_object_new_string(id ? id : ""));
    json_object_object_add(detail, "engine", json_object_new_string("libvirt"));
    if (body && json_object_object_get_ex(body, "action", &v)) json_object_object_add(detail, "action", json_object_get(v));
    if (body && json_object_object_get_ex(body, "request_id", &v)) json_object_object_add(detail, "request_id", json_object_get(v));
    if (body && json_object_object_get_ex(body, "_log_context", &context)) {
        if (json_object_object_get_ex(context, "actor", &v)) json_object_object_add(detail, "actor", json_object_get(v));
        if (json_object_object_get_ex(context, "source_ip", &v)) json_object_object_add(detail, "source_ip", json_object_get(v));
    }
    json_object_object_add(detail, "result", json_object_new_string(ok ? "success" : "failed"));
    if (ok && json_object_object_get_ex(reply, "data", &data) && json_object_object_get_ex(data, "result", &v))
        json_object_object_add(detail, "result", json_object_get(v));
    if (!ok && reply && json_object_object_get_ex(reply, "error", &data) && json_object_object_get_ex(data, "code", &v))
        json_object_object_add(detail, "failure_reason", json_object_get(v));
    dw_business_event("vm", "VM_ACTION_RESULT", detail);
    json_object_put(detail);
    return reply;
}

/* Create the backing volume for one "new" disk and stamp its host path into the
 * disk object as _path (consumed by vm_config_to_xml). Returns the created vol
 * (the caller tracks it for rollback) or NULL with *err set to a classified
 * token ("__pool_required"/"__pool_missing") or a raw libvirt message. */
static virStorageVolPtr vm_disk_provision(virConnectPtr conn, const char *vmname,
                                          int idx, struct json_object *disk,
                                          char **err)
{
    struct json_object *x;
    const char *pool_id = NULL, *fmt = "qcow2";
    int64_t cap = 0;
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char *volxml = NULL, *path;
    size_t sz;
    FILE *f;
    char volname[160];

    if (json_object_object_get_ex(disk, "pool_id", &x)) pool_id = json_object_get_string(x);
    if (json_object_object_get_ex(disk, "format", &x)) fmt = json_object_get_string(x);
    if (json_object_object_get_ex(disk, "capacity_bytes", &x)) cap = json_object_get_int64(x);
    if (!pool_id || !*pool_id) { *err = strdup("__pool_required"); return NULL; }

    pool = virStoragePoolLookupByUUIDString(conn, pool_id);
    if (!pool) { *err = strdup("__pool_missing"); return NULL; }

    /* vmname is validated to [A-Za-z0-9._-] so it is XML- and path-safe. */
    snprintf(volname, sizeof volname, "%s-%d.%s", vmname, idx,
             !strcmp(fmt, "raw") ? "img" : "qcow2");
    f = open_memstream(&volxml, &sz);
    if (!f) { virStoragePoolFree(pool); *err = strdup("oom"); return NULL; }
    fprintf(f, "<volume>\n  <name>%s</name>\n", volname);
    fprintf(f, "  <capacity unit='bytes'>%lld</capacity>\n", (long long)cap);
    fputs("  <allocation unit='bytes'>0</allocation>\n", f);
    fprintf(f, "  <target><format type='%s'/></target>\n</volume>\n",
            !strcmp(fmt, "raw") ? "raw" : "qcow2");
    fclose(f);

    vol = virStorageVolCreateXML(pool, volxml, 0);
    free(volxml);
    virStoragePoolFree(pool);
    if (!vol) { *err = strdup(vm_last_err_msg()); return NULL; }

    path = virStorageVolGetPath(vol);
    if (path) {
        json_object_object_add(disk, "_path", json_object_new_string(path));
        free(path);
    }
    return vol;
}

/* Map a vm_disk_provision failure to a frozen §8 error. Pool problems are field
 * errors (invalid_config/422); an out-of-space libvirt message is
 * insufficient_space (409); anything else is reported verbatim rather than
 * dressed up as a condition we did not actually detect. */
static struct json_object *vm_disk_err(int idx, const char *tok)
{
    struct json_object *det, *fe;
    char field[48];

    snprintf(field, sizeof field, "disks[%d].pool_id", idx);
    if (tok && (!strcmp(tok, "__pool_required") || !strcmp(tok, "__pool_missing"))) {
        fe = json_object_new_array();
        if (!strcmp(tok, "__pool_required"))
            vm_fe_add(fe, field, "required", "pool_id is required for a new disk");
        else
            vm_fe_add(fe, field, "not_found", "no storage pool with this id");
        det = json_object_new_object();
        json_object_object_add(det, "field_errors", fe);
        return vm_error_obj("invalid_config", "config validation failed", det);
    }
    det = json_object_new_object();
    json_object_object_add(det, "detail",
                           json_object_new_string(tok ? tok : "disk provisioning failed"));
    if (tok && strstr(tok, "space"))
        return vm_error_obj("insufficient_space", "not enough space in the pool", det);
    return vm_error_obj("bad_request", "could not create backing volume", det);
}

int vm_create_domain(struct json_object *config, struct json_object **result_out,
                     struct json_object **error_out)
{
    virConnectPtr conn = vm_conn();
    struct json_object *fe = NULL, *disks, *nics, *v, *data;
    const char *name = NULL;
    char uuid[37];
    char *xml = NULL, *xerr = NULL;
    virDomainPtr dom, ex;
    virStorageVolPtr vols[32];
    int nvols = 0, nd, nn, i;
    bool start_after = false;

    *result_out = NULL;
    *error_out = NULL;
    if (!conn) {
        *error_out = vm_error_obj("service_unavailable", "libvirt unreachable", NULL);
        return -1;
    }
    if (vm_config_validate(config, &fe) != 0) {
        struct json_object *det = json_object_new_object();
        json_object_object_add(det, "field_errors", fe);
        *error_out = vm_error_obj("invalid_config", "config validation failed", det);
        return -1;
    }
    json_object_put(fe);   /* empty array on success */

    json_object_object_get_ex(config, "name", &v);
    name = json_object_get_string(v);
    ex = virDomainLookupByName(conn, name);   /* §6: conflict check before disks */
    if (ex) {
        virDomainFree(ex);
        *error_out = vm_error_obj("name_conflict", "a vm with this name already exists", NULL);
        return -1;
    }
    vm_uuid_generate(uuid);

    if (json_object_object_get_ex(config, "disks", &disks) &&
        json_object_is_type(disks, json_type_array)) {
        nd = json_object_array_length(disks);
        if (nd > 32) {
            *error_out = vm_error_obj("invalid_config", "too many disks", NULL);
            return -1;
        }
        for (i = 0; i < nd; i++) {
            struct json_object *disk = json_object_array_get_idx(disks, i);
            char *derr = NULL;
            virStorageVolPtr vol = vm_disk_provision(conn, name, i, disk, &derr);

            if (!vol) {
                *error_out = vm_disk_err(i, derr);
                free(derr);
                goto rollback;
            }
            vols[nvols++] = vol;
        }
    }

    if (json_object_object_get_ex(config, "nics", &nics) &&
        json_object_is_type(nics, json_type_array)) {
        nn = json_object_array_length(nics);
        for (i = 0; i < nn; i++) {
            struct json_object *nic = json_object_array_get_idx(nics, i);
            const char *netid = NULL;

            if (json_object_object_get_ex(nic, "network_id", &v))
                netid = json_object_get_string(v);
            if (netid && *netid) {
                virNetworkPtr net = virNetworkLookupByUUIDString(conn, netid);

                if (net) {
                    const char *nm = virNetworkGetName(net);
                    if (nm)
                        json_object_object_add(nic, "_network_name",
                                               json_object_new_string(nm));
                    virNetworkFree(net);
                }
            }
        }
    }
    xml = vm_config_to_xml(config, uuid, &xerr);
    if (!xml) {
        struct json_object *det = json_object_new_object();

        if (xerr && !strcmp(xerr, "kvm_unavailable")) {
            json_object_object_add(det, "missing", json_object_new_string("kvm"));
            *error_out = vm_error_obj("capability_disabled",
                                      "explicit kvm requested but /dev/kvm is absent", det);
        } else {
            json_object_object_add(det, "detail",
                                   json_object_new_string(xerr ? xerr : "xml render failed"));
            *error_out = vm_error_obj("invalid_config", "cannot render domain", det);
        }
        free(xerr);
        goto rollback;
    }
    dom = virDomainDefineXML(conn, xml);
    free(xml);
    if (!dom) {
        struct json_object *det = json_object_new_object();

        json_object_object_add(det, "libvirt", json_object_new_string(vm_last_err_msg()));
        *error_out = vm_error_obj("bad_request",
                                  "libvirt rejected the domain definition", det);
        goto rollback;
    }
    /* The volumes now belong to the defined domain; release our client-side
     * tracking handles (this frees the handles, not the underlying storage). */
    for (i = 0; i < nvols; i++)
        virStorageVolFree(vols[i]);

    /* The domain is defined; from here failures are reported honestly rather
     * than rolled back — the VM exists, it just may not have auto-started. */
    data = json_object_new_object();
    json_object_object_add(data, "vm_id", json_object_new_string(uuid));

    if (json_object_object_get_ex(config, "autostart", &v) && json_object_get_boolean(v))
        virDomainSetAutostart(dom, 1);
    if (json_object_object_get_ex(config, "start_after_create", &v))
        start_after = json_object_get_boolean(v);
    if (start_after && virDomainCreate(dom) < 0) {
        /* Defined but would not boot: say so instead of claiming it is running. */
        json_object_object_add(data, "started", json_object_new_boolean(0));
        json_object_object_add(data, "start_error",
                               json_object_new_string(vm_last_err_msg()));
    } else {
        json_object_object_add(data, "started", json_object_new_boolean(start_after));
    }

    /* Seed the revision counter (§10) so the first read-back carries revision 1. */
    vm_store_revision_bump(uuid);
    json_object_object_add(data, "config", vm_domain_canonical_config(conn, dom));
    json_object_object_add(data, "revision",
                           json_object_new_int64(vm_store_revision_get(uuid)));
    virDomainFree(dom);
    *result_out = data;
    return 0;

rollback:
    /* Reached only before the domain is defined: drop every volume we created so
     * a failed create leaves no orphan backing files (§7). */
    for (i = 0; i < nvols; i++) {
        virStorageVolDelete(vols[i], 0);
        virStorageVolFree(vols[i]);
    }
    return -1;
}
/* Delete the backing-file volumes owned by a domain being removed. Scans the
 * domain XML for <disk device='disk'> source paths (the parked cdrom has no
 * source and is skipped), resolves each to a managed storage volume and deletes
 * it, recording the outcome per path. A path libvirt does not own as a volume is
 * reported skipped rather than force-unlinked — we remove only what we manage. */
static void vm_delete_owned_volumes(virConnectPtr conn, const char *xml,
                                    struct json_object *targets)
{
    const char *p = xml;

    while (xml && (p = strstr(p, "<disk ")) != NULL) {
        const char *end = strstr(p, "</disk>");
        const char *dev, *src, *q;
        char path[1024];
        virStorageVolPtr vol;
        struct json_object *t;
        size_t len;

        if (!end)
            break;
        /* Only data disks own their volumes; skip the readonly cdrom drive. */
        dev = strstr(p, "device='disk'");
        if (!dev || dev > end) { p = end + 7; continue; }
        src = strstr(p, "<source file='");
        if (!src || src > end) { p = end + 7; continue; }
        src += sizeof("<source file='") - 1;
        q = strchr(src, '\'');
        if (!q || q > end) { p = end + 7; continue; }
        len = (size_t)(q - src);
        if (len == 0 || len >= sizeof path) { p = end + 7; continue; }
        memcpy(path, src, len);
        path[len] = '\0';

        t = json_object_new_object();
        json_object_object_add(t, "path", json_object_new_string(path));
        vol = virStorageVolLookupByPath(conn, path);
        if (vol) {
            bool ok = virStorageVolDelete(vol, 0) == 0;
            json_object_object_add(t, "deleted", json_object_new_boolean(ok));
            if (!ok)
                json_object_object_add(t, "detail",
                                       json_object_new_string(vm_last_err_msg()));
            virStorageVolFree(vol);
        } else {
            json_object_object_add(t, "deleted", json_object_new_boolean(0));
            json_object_object_add(t, "detail",
                                   json_object_new_string("not a managed volume"));
        }
        json_object_array_add(targets, t);
        p = end + 7;
    }
}
int vm_delete_domain(const char *id, bool delete_owned_disks,
                     struct json_object **result_out, struct json_object **error_out)
{
    virConnectPtr conn = vm_conn();
    virDomainPtr dom;
    char uuid[VIR_UUID_STRING_BUFLEN] = { 0 };
    int st = VIR_DOMAIN_NOSTATE;
    struct json_object *data, *targets;
    unsigned int uflags = VIR_DOMAIN_UNDEFINE_MANAGED_SAVE |
                          VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA |
                          VIR_DOMAIN_UNDEFINE_NVRAM;

    *result_out = NULL;
    *error_out = NULL;
    if (!conn) {
        *error_out = vm_error_obj("service_unavailable", "libvirt unreachable", NULL);
        return -1;
    }
    if (!id || !vm_uuid_valid(id)) {
        *error_out = vm_error_obj("not_found", "no such vm", NULL);
        return -1;
    }
    dom = virDomainLookupByUUIDString(conn, id);
    if (!dom) {
        *error_out = vm_error_obj("not_found", "no such vm", NULL);
        return -1;
    }
    virDomainGetUUIDString(dom, uuid);
    if (virDomainGetState(dom, &st, NULL, 0) < 0)
        st = VIR_DOMAIN_NOSTATE;
    /* §4: a live domain must be shut down first — we never yank storage out from
     * under a running guest. crashed/shutoff are both safe to remove. */
    if (st != VIR_DOMAIN_SHUTOFF && st != VIR_DOMAIN_CRASHED) {
        virDomainFree(dom);
        *error_out = vm_error_obj("vm_must_be_stopped",
                                  "stop the vm before deleting it", NULL);
        return -1;
    }
    /* Disks are kept unless the caller explicitly opts in (§4 delete_owned_disks
     * defaults false); read the XML while the domain still exists, then drop the
     * definition. targets[] is always present so the client can see what went. */
    targets = json_object_new_array();
    if (delete_owned_disks) {
        char *xml = virDomainGetXMLDesc(dom, 0);

        if (xml) {
            vm_delete_owned_volumes(conn, xml, targets);
            free(xml);
        }
    }

    if (virDomainUndefineFlags(dom, uflags) < 0) {
        struct json_object *det = json_object_new_object();

        json_object_object_add(det, "libvirt", json_object_new_string(vm_last_err_msg()));
        json_object_put(targets);
        virDomainFree(dom);
        *error_out = vm_error_obj("bad_request",
                                  "libvirt refused to undefine the domain", det);
        return -1;
    }
    virDomainFree(dom);

    /* The revision row (§10) is intentionally left in place: it is keyed by uuid
     * and libvirt will never re-issue this one, so a stale row is harmless and a
     * new domain with a fresh uuid always starts clean. */
    data = json_object_new_object();
    json_object_object_add(data, "id", json_object_new_string(uuid));
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    json_object_object_add(data, "deleted_disks", targets);
    *result_out = data;
    return 0;
}
