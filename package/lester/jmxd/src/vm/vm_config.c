// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Config <-> libvirt domain XML for dreamingos-vm.
 *
 * vm_config_validate does the synchronous field pre-check (§6/§8 field_errors),
 * vm_config_to_xml renders a libvirt domain definition, and
 * vm_domain_canonical_config reads a defined domain back into the vm.v1 config
 * shape. State/allowed-action mapping lives here because both the read and the
 * write paths need the same table.
 */
#include "vm_internal.h"
#include <ctype.h>

const char *vm_domain_state_str(int state)
{
    switch (state) {
    case VIR_DOMAIN_RUNNING:
    case VIR_DOMAIN_BLOCKED:      return "running";
    case VIR_DOMAIN_PAUSED:       return "paused";
    case VIR_DOMAIN_SHUTDOWN:     return "shutting_down";
    case VIR_DOMAIN_SHUTOFF:      return "stopped";
    case VIR_DOMAIN_CRASHED:      return "crashed";
    case VIR_DOMAIN_PMSUSPENDED:  return "suspended";
    default:                      return "unknown";
    }
}

/* The single source of truth for which verbs a state accepts. Both the JSON
 * builder and the action guard consult it so the advertised allowed_actions can
 * never drift from what vm_instance_action will actually permit. */
static const char *const *vm_state_actions(int state, int *n)
{
    static const char *running[] = { "shutdown", "reboot", "force_stop", "reset", "pause" };
    static const char *paused[]  = { "resume", "force_stop" };
    static const char *stopped[] = { "start" };
    static const char *crashed[] = { "start", "force_stop" };
    static const char *none[]    = { NULL };

    switch (state) {
    case VIR_DOMAIN_RUNNING:
    case VIR_DOMAIN_BLOCKED:     *n = 5; return running;
    case VIR_DOMAIN_PAUSED:
    case VIR_DOMAIN_PMSUSPENDED: *n = 2; return paused;
    case VIR_DOMAIN_SHUTOFF:     *n = 1; return stopped;
    case VIR_DOMAIN_CRASHED:     *n = 2; return crashed;
    default:                     *n = 0; return none;
    }
}
struct json_object *vm_domain_allowed_actions(int state)
{
    struct json_object *arr = json_object_new_array();
    const char *const *acts;
    int n, i;

    if (!arr)
        return NULL;
    acts = vm_state_actions(state, &n);
    for (i = 0; i < n; i++)
        json_object_array_add(arr, json_object_new_string(acts[i]));
    return arr;
}

static bool vm_action_allowed(int state, const char *action)
{
    const char *const *acts;
    int n, i;

    acts = vm_state_actions(state, &n);
    for (i = 0; i < n; i++)
        if (!strcmp(acts[i], action))
            return true;
    return false;
}

bool vm_action_permitted(int state, const char *action)
{
    return vm_action_allowed(state, action);
}

/* Public so vm_libvirt.c's validate can append the same {field,code,message}
 * shape for capability/dependency gating. */
void vm_fe_add(struct json_object *arr, const char *field,
               const char *code, const char *message)
{
    struct json_object *e = json_object_new_object();

    if (!e)
        return;
    json_object_object_add(e, "field", json_object_new_string(field));
    json_object_object_add(e, "code", json_object_new_string(code));
    json_object_object_add(e, "message", json_object_new_string(message));
    json_object_array_add(arr, e);
}
int vm_config_validate(struct json_object *config, struct json_object **field_errors)
{
    struct json_object *fe = json_object_new_array();
    struct json_object *v, *cpu, *disks;

    *field_errors = fe;
    if (!config || !json_object_is_type(config, json_type_object)) {
        vm_fe_add(fe, "config", "required", "config object is required");
        return -1;
    }

    if (!json_object_object_get_ex(config, "name", &v) ||
        !json_object_is_type(v, json_type_string) ||
        !*json_object_get_string(v)) {
        vm_fe_add(fe, "name", "required", "name is required");
    } else {
        const char *nm = json_object_get_string(v);
        const char *p;

        if (strlen(nm) > 64)
            vm_fe_add(fe, "name", "too_long", "name must be <= 64 characters");
        else
            for (p = nm; *p; p++)
                if (!(isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == '.')) {
                    vm_fe_add(fe, "name", "invalid_chars",
                              "only letters, digits, '.', '_', '-' allowed");
                    break;
                }
    }

    if (!json_object_object_get_ex(config, "memory_bytes", &v) ||
        !json_object_is_type(v, json_type_int))
        vm_fe_add(fe, "memory_bytes", "required", "memory_bytes is required");
    else if (json_object_get_int64(v) < 128LL * 1024 * 1024)
        vm_fe_add(fe, "memory_bytes", "out_of_range", "minimum is 128 MiB");

    if (json_object_object_get_ex(config, "cpu", &cpu) &&
        json_object_is_type(cpu, json_type_object)) {
        int64_t s = 1, c = 1, t = 1;
        struct json_object *x;

        if (json_object_object_get_ex(cpu, "sockets", &x)) s = json_object_get_int64(x);
        if (json_object_object_get_ex(cpu, "cores", &x))   c = json_object_get_int64(x);
        if (json_object_object_get_ex(cpu, "threads", &x)) t = json_object_get_int64(x);
        if (s < 1 || c < 1 || t < 1)
            vm_fe_add(fe, "cpu", "out_of_range", "sockets/cores/threads must be >= 1");
        else if (s * c * t > 255)
            vm_fe_add(fe, "cpu", "out_of_range", "total vcpus must be <= 255");
    } else {
        vm_fe_add(fe, "cpu", "required", "cpu topology is required");
    }
    if (json_object_object_get_ex(config, "firmware", &v) &&
        json_object_is_type(v, json_type_string)) {
        const char *fw = json_object_get_string(v);

        if (strcmp(fw, "bios") && strcmp(fw, "uefi") && strcmp(fw, "uefi_secureboot"))
            vm_fe_add(fe, "firmware", "unsupported", "bios|uefi|uefi_secureboot");
        if (!strcmp(fw, "uefi_secureboot")) {
            const char *machine = "q35";
            struct json_object *m;

            if (json_object_object_get_ex(config, "machine", &m) &&
                json_object_is_type(m, json_type_string))
                machine = json_object_get_string(m);
            if (strcmp(machine, "q35"))
                vm_fe_add(fe, "machine", "requires_q35", "secure boot requires machine q35");
        }
    }

    if (json_object_object_get_ex(config, "accelerator", &v) &&
        json_object_is_type(v, json_type_string)) {
        const char *a = json_object_get_string(v);

        if (strcmp(a, "kvm") && strcmp(a, "tcg") && strcmp(a, "auto"))
            vm_fe_add(fe, "accelerator", "unsupported", "kvm|tcg|auto");
    }

    if (json_object_object_get_ex(config, "disks", &disks) &&
        json_object_is_type(disks, json_type_array)) {
        int nd = json_object_array_length(disks), i;

        for (i = 0; i < nd; i++) {
            struct json_object *d = json_object_array_get_idx(disks, i), *x;
            const char *src = "new";
            char fld[40];

            if (json_object_object_get_ex(d, "source", &x))
                src = json_object_get_string(x);
            if (strcmp(src, "new")) {
                snprintf(fld, sizeof fld, "disks[%d].source", i);
                vm_fe_add(fe, fld, "unsupported", "only source=new is supported this release");
                continue;
            }
            if (!json_object_object_get_ex(d, "pool_id", &x) ||
                !json_object_is_type(x, json_type_string)) {
                snprintf(fld, sizeof fld, "disks[%d].pool_id", i);
                vm_fe_add(fe, fld, "required", "pool_id is required for a new disk");
            }
            if (!json_object_object_get_ex(d, "capacity_bytes", &x) ||
                json_object_get_int64(x) < 1LL * 1024 * 1024) {
                snprintf(fld, sizeof fld, "disks[%d].capacity_bytes", i);
                vm_fe_add(fe, fld, "out_of_range", "minimum is 1 MiB");
            }
            if (json_object_object_get_ex(d, "format", &x)) {
                const char *f = json_object_get_string(x);

                if (strcmp(f, "qcow2") && strcmp(f, "raw")) {
                    snprintf(fld, sizeof fld, "disks[%d].format", i);
                    vm_fe_add(fe, fld, "unsupported", "qcow2|raw");
                }
            }
        }
    }

    return json_object_array_length(fe) ? -1 : 0;
}
static void xml_esc(FILE *f, const char *s)
{
    if (!s)
        return;
    for (; *s; s++)
        switch (*s) {
        case '&':  fputs("&amp;", f);  break;
        case '<':  fputs("&lt;", f);   break;
        case '>':  fputs("&gt;", f);   break;
        case '"':  fputs("&quot;", f); break;
        case '\'': fputs("&apos;", f); break;
        default:   fputc(*s, f);       break;
        }
}

char *vm_config_to_xml(struct json_object *config, const char *uuid, char **err_out)
{
    char *buf = NULL;
    size_t sz = 0;
    FILE *f;
    struct json_object *v, *cpu, *disks, *nics;
    const char *name = "vm", *arch, *machine = "q35", *fw = "bios", *accel = "auto";
    const char *domtype;
    int64_t membytes = 0, sockets = 1, cores = 1, threads = 1;
    bool kvm;

    if (err_out)
        *err_out = NULL;
    if (!config) {
        if (err_out) *err_out = strdup("null config");
        return NULL;
    }
    arch = vm_host_arch();
    if (json_object_object_get_ex(config, "name", &v)) name = json_object_get_string(v);
    if (json_object_object_get_ex(config, "guest_arch", &v) && json_object_is_type(v, json_type_string))
        arch = json_object_get_string(v);
    if (json_object_object_get_ex(config, "machine", &v) && json_object_is_type(v, json_type_string))
        machine = json_object_get_string(v);
    if (json_object_object_get_ex(config, "firmware", &v) && json_object_is_type(v, json_type_string))
        fw = json_object_get_string(v);
    if (json_object_object_get_ex(config, "accelerator", &v) && json_object_is_type(v, json_type_string))
        accel = json_object_get_string(v);
    if (json_object_object_get_ex(config, "memory_bytes", &v)) membytes = json_object_get_int64(v);
    if (json_object_object_get_ex(config, "cpu", &cpu) && json_object_is_type(cpu, json_type_object)) {
        if (json_object_object_get_ex(cpu, "sockets", &v)) sockets = json_object_get_int64(v);
        if (json_object_object_get_ex(cpu, "cores", &v))   cores = json_object_get_int64(v);
        if (json_object_object_get_ex(cpu, "threads", &v)) threads = json_object_get_int64(v);
    }

    /* Resolve the accelerator honestly: an explicit kvm request on a host with
     * no /dev/kvm is refused (the caller maps this to capability_disabled);
     * "auto" silently lands on TCG and the canonical read-back will say so. */
    kvm = vm_kvm_present();
    if (!strcmp(accel, "kvm")) {
        if (!kvm) { if (err_out) *err_out = strdup("kvm_unavailable"); return NULL; }
        domtype = "kvm";
    } else if (!strcmp(accel, "tcg")) {
        domtype = "qemu";
    } else {
        domtype = kvm ? "kvm" : "qemu";
    }

    f = open_memstream(&buf, &sz);
    if (!f) { if (err_out) *err_out = strdup("oom"); return NULL; }
    fprintf(f, "<domain type='%s'>\n", domtype);
    fputs("  <name>", f); xml_esc(f, name); fputs("</name>\n", f);
    fprintf(f, "  <uuid>%s</uuid>\n", uuid);
    fprintf(f, "  <memory unit='bytes'>%lld</memory>\n", (long long)membytes);
    fprintf(f, "  <currentMemory unit='bytes'>%lld</currentMemory>\n", (long long)membytes);
    fprintf(f, "  <vcpu placement='static'>%lld</vcpu>\n",
            (long long)(sockets * cores * threads));

    if (!strcmp(fw, "uefi") || !strcmp(fw, "uefi_secureboot")) {
        fputs("  <os firmware='efi'>\n", f);
        fprintf(f, "    <type arch='%s' machine='%s'>hvm</type>\n", arch, machine);
        fputs("    <firmware>\n", f);
        if (!strcmp(fw, "uefi_secureboot")) {
            fputs("      <feature enabled='yes' name='secure-boot'/>\n", f);
            fputs("      <feature enabled='yes' name='enrolled-keys'/>\n", f);
        } else {
            fputs("      <feature enabled='no' name='secure-boot'/>\n", f);
        }
        fputs("    </firmware>\n", f);
        fputs("    <boot dev='hd'/>\n    <boot dev='cdrom'/>\n  </os>\n", f);
    } else {
        fputs("  <os>\n", f);
        fprintf(f, "    <type arch='%s' machine='%s'>hvm</type>\n", arch, machine);
        fputs("    <boot dev='hd'/>\n    <boot dev='cdrom'/>\n  </os>\n", f);
    }

    fputs("  <features>\n    <acpi/>\n    <apic/>\n", f);
    if (!strcmp(fw, "uefi_secureboot"))
        fputs("    <smm state='on'/>\n", f);
    fputs("  </features>\n", f);

    fprintf(f, "  <cpu%s>\n    <topology sockets='%lld' cores='%lld' threads='%lld'/>\n  </cpu>\n",
            strcmp(domtype, "kvm") ? "" : " mode='host-passthrough'",
            (long long)sockets, (long long)cores, (long long)threads);
    fputs("  <clock offset='utc'/>\n", f);
    fputs("  <on_poweroff>destroy</on_poweroff>\n", f);
    fputs("  <on_reboot>restart</on_reboot>\n", f);
    fputs("  <on_crash>destroy</on_crash>\n", f);
    fputs("  <devices>\n", f);
    if (json_object_object_get_ex(config, "disks", &disks) &&
        json_object_is_type(disks, json_type_array)) {
        int nd = json_object_array_length(disks), i;

        for (i = 0; i < nd; i++) {
            struct json_object *d = json_object_array_get_idx(disks, i), *x;
            const char *path = NULL, *fmt = "qcow2", *bus = "virtio", *pfx;
            char dev[8];

            /* vm_create_domain resolves each "new" disk to a host path before
             * calling us; an unresolved disk is skipped rather than guessed. */
            if (json_object_object_get_ex(d, "_path", &x)) path = json_object_get_string(x);
            if (json_object_object_get_ex(d, "format", &x)) fmt = json_object_get_string(x);
            if (json_object_object_get_ex(d, "bus", &x)) bus = json_object_get_string(x);
            if (!path)
                continue;
            pfx = !strcmp(bus, "virtio") ? "vd" : (!strcmp(bus, "ide") ? "hd" : "sd");
            snprintf(dev, sizeof dev, "%s%c", pfx, 'a' + (i % 20));
            fputs("    <disk type='file' device='disk'>\n", f);
            fprintf(f, "      <driver name='qemu' type='%s'/>\n", fmt);
            fputs("      <source file='", f); xml_esc(f, path); fputs("'/>\n", f);
            fprintf(f, "      <target dev='%s' bus='%s'/>\n", dev, bus);
            fputs("    </disk>\n", f);
        }
    }

    /* An empty CDROM drive so media can be attached later; the image store that
     * resolves cdroms[].image_id to a path is a later phase. Parked at sdz so it
     * cannot collide with a sata/scsi data disk. */
    fputs("    <disk type='file' device='cdrom'>\n", f);
    fputs("      <driver name='qemu' type='raw'/>\n", f);
    fputs("      <target dev='sdz' bus='sata'/>\n      <readonly/>\n    </disk>\n", f);

    if (json_object_object_get_ex(config, "nics", &nics) &&
        json_object_is_type(nics, json_type_array)) {
        int nn = json_object_array_length(nics), i;

        for (i = 0; i < nn; i++) {
            struct json_object *nic = json_object_array_get_idx(nics, i), *x;
            const char *net = NULL, *model = "virtio", *mac = NULL;

            if (json_object_object_get_ex(nic, "_network_name", &x)) net = json_object_get_string(x);
            if (json_object_object_get_ex(nic, "model", &x)) model = json_object_get_string(x);
            if (json_object_object_get_ex(nic, "mac", &x)) {
                const char *m = json_object_get_string(x);
                if (strcmp(m, "auto")) mac = m;
            }
            if (!net)
                continue;
            fputs("    <interface type='network'>\n", f);
            fputs("      <source network='", f); xml_esc(f, net); fputs("'/>\n", f);
            fprintf(f, "      <model type='%s'/>\n", model);
            if (mac) { fputs("      <mac address='", f); xml_esc(f, mac); fputs("'/>\n", f); }
            fputs("    </interface>\n", f);
        }
    }

    if (json_object_object_get_ex(config, "tpm", &v) && json_object_get_boolean(v)) {
        fputs("    <tpm model='tpm-crb'>\n", f);
        fputs("      <backend type='emulator' version='2.0'/>\n    </tpm>\n", f);
    }
    fputs("    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n", f);
    fputs("    <video>\n      <model type='virtio'/>\n    </video>\n", f);
    fputs("    <serial type='pty'/>\n    <console type='pty'/>\n", f);
    fputs("    <memballoon model='virtio'/>\n", f);
    fputs("  </devices>\n</domain>\n", f);
    fclose(f);
    return buf;
}
struct json_object *vm_domain_canonical_config(virConnectPtr conn, virDomainPtr dom)
{
    struct json_object *cfg = json_object_new_object();
    char uuid[VIR_UUID_STRING_BUFLEN] = { 0 };
    const char *name;
    unsigned long maxmem;
    int vcpus;
    char *xml;

    (void)conn;
    if (!cfg)
        return NULL;
    virDomainGetUUIDString(dom, uuid);
    name = virDomainGetName(dom);
    json_object_object_add(cfg, "name", json_object_new_string(name ? name : ""));
    json_object_object_add(cfg, "uuid", json_object_new_string(uuid));
    maxmem = virDomainGetMaxMemory(dom);      /* KiB, 0 on error */
    json_object_object_add(cfg, "memory_bytes", json_object_new_int64((int64_t)maxmem * 1024));
    vcpus = virDomainGetMaxVcpus(dom);
    if (vcpus > 0) {
        struct json_object *c = json_object_new_object();

        /* libvirt exposes the flat maximum here; the sockets/cores/threads split
         * is only recoverable by parsing <topology>, which is a later refinement.
         * Reporting it as cores keeps the vcpu total truthful. */
        json_object_object_add(c, "sockets", json_object_new_int(1));
        json_object_object_add(c, "cores", json_object_new_int(vcpus));
        json_object_object_add(c, "threads", json_object_new_int(1));
        json_object_object_add(cfg, "cpu", c);
    }

    xml = virDomainGetXMLDesc(dom, 0);
    if (xml) {
        const char *accel = strstr(xml, "<domain type='kvm'") ? "kvm"
                          : (strstr(xml, "<domain type='qemu'") ? "tcg" : "unknown");

        json_object_object_add(cfg, "accelerator", json_object_new_string(accel));
        if (strstr(xml, "enabled='yes' name='secure-boot'"))
            json_object_object_add(cfg, "firmware", json_object_new_string("uefi_secureboot"));
        else if (strstr(xml, "firmware='efi'"))
            json_object_object_add(cfg, "firmware", json_object_new_string("uefi"));
        else
            json_object_object_add(cfg, "firmware", json_object_new_string("bios"));
        free(xml);
    }
    return cfg;
}
