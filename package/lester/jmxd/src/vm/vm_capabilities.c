// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * status (§3), capabilities (§5) and overview (§4) for dreamingos-vm.
 *
 * These are the routes the contract guarantees answer even when virtualisation
 * is unavailable, so they lean on cheap host probes (/dev/kvm, the OVMF/qemu
 * firmware descriptors, /sys IOMMU groups) rather than requiring a live libvirt
 * connection. Every advertised false capability carries a stable reason string.
 */
#include "vm_internal.h"
#include <sys/utsname.h>
#include <dirent.h>

bool vm_kvm_present(void)
{
    return access("/dev/kvm", R_OK | W_OK) == 0;
}

const char *vm_host_arch(void)
{
    static char m[65];
    struct utsname u;

    if (!m[0]) {
        if (uname(&u) == 0)
            snprintf(m, sizeof m, "%s", u.machine);
        else
            snprintf(m, sizeof m, "unknown");
    }
    return m;
}

static bool file_exists(const char *p)
{
    return access(p, F_OK) == 0;
}

static bool vm_uefi_available(void)
{
    return file_exists(VM_OVMF_DIR "/OVMF_CODE_4M.fd") ||
           file_exists(VM_OVMF_DIR "/OVMF_CODE.fd") ||
           file_exists(VM_OVMF_DIR "/OVMF_CODE.secboot.fd") ||
           file_exists(VM_OVMF_DIR "/OVMF_CODE_4M.secboot.fd");
}

static bool vm_secureboot_available(void)
{
    return file_exists(VM_OVMF_DIR "/OVMF_CODE.secboot.fd") ||
           file_exists(VM_OVMF_DIR "/OVMF_CODE_4M.secboot.fd");
}

static bool vm_iommu_present(void)
{
    DIR *d = opendir("/sys/kernel/iommu_groups");
    struct dirent *e;
    bool any = false;

    if (!d)
        return false;
    while ((e = readdir(d)))
        if (e->d_name[0] != '.') { any = true; break; }
    closedir(d);
    return any;
}
struct json_object *vm_status_json(void)
{
    const char *lv, *qe, *kv;
    struct json_object *d = json_object_new_object();
    struct json_object *dep = json_object_new_object();
    const char *state = vm_service_state();

    vm_dependency_state(&lv, &qe, &kv);
    json_object_object_add(d, "installed", json_object_new_boolean(1));
    json_object_object_add(d, "enabled", json_object_new_boolean(1));
    json_object_object_add(d, "service_state", json_object_new_string(state));
    json_object_object_add(dep, "libvirt", json_object_new_string(lv));
    json_object_object_add(dep, "qemu", json_object_new_string(qe));
    json_object_object_add(dep, "kvm", json_object_new_string(kv));
    json_object_object_add(d, "dependency_state", dep);
    if (!strcmp(state, "degraded"))
        json_object_object_add(d, "reason", json_object_new_string("libvirt_unreachable"));
    return d;
}

static void vm_machines_for_arch(struct json_object *arr, const char *arch)
{
    if (!strcmp(arch, "x86_64") || !strcmp(arch, "i686")) {
        json_object_array_add(arr, json_object_new_string("q35"));
        json_object_array_add(arr, json_object_new_string("pc"));
    } else if (!strcmp(arch, "aarch64") || !strcmp(arch, "armv7l")) {
        json_object_array_add(arr, json_object_new_string("virt"));
    } else {
        json_object_array_add(arr, json_object_new_string("virt"));
    }
}
struct json_object *vm_capabilities_json(void)
{
    struct json_object *d = json_object_new_object();
    struct json_object *caps = json_object_new_object();
    struct json_object *fw = json_object_new_array();
    struct json_object *machines = json_object_new_array();
    struct json_object *guests = json_object_new_array();
    struct json_object *limits = json_object_new_object();
    struct json_object *reasons = json_object_new_object();
    const char *arch = vm_host_arch();
    bool kvm = vm_kvm_present();
    bool uefi = vm_uefi_available();
    bool secboot = vm_secureboot_available();
    bool tpm = file_exists("/usr/bin/swtpm");
    bool iommu = vm_iommu_present();
    bool ovs = file_exists("/usr/bin/ovs-vsctl");

    json_object_object_add(d, "installed", json_object_new_boolean(1));
    json_object_object_add(d, "enabled", json_object_new_boolean(1));
    json_object_object_add(d, "service_state", json_object_new_string(vm_service_state()));
    json_object_object_add(d, "host_arch", json_object_new_string(arch));
    json_object_array_add(guests, json_object_new_string(arch));
    json_object_object_add(d, "guest_arches", guests);

    json_object_array_add(fw, json_object_new_string("bios"));
    if (uefi) json_object_array_add(fw, json_object_new_string("uefi"));
    if (secboot) json_object_array_add(fw, json_object_new_string("uefi_secureboot"));
    vm_machines_for_arch(machines, arch);

    json_object_object_add(caps, "create", json_object_new_boolean(1));
    json_object_object_add(caps, "kvm", json_object_new_boolean(kvm));
    json_object_object_add(caps, "tcg", json_object_new_boolean(1));
    json_object_object_add(caps, "firmware", fw);
    json_object_object_add(caps, "machines", machines);
    json_object_object_add(caps, "tpm", json_object_new_boolean(tpm));
    json_object_object_add(caps, "secure_boot", json_object_new_boolean(secboot));
    json_object_object_add(caps, "snapshot_disk", json_object_new_boolean(1));
    json_object_object_add(caps, "snapshot_memory", json_object_new_boolean(0));
    json_object_object_add(caps, "clone", json_object_new_boolean(1));
    json_object_object_add(caps, "import_ova", json_object_new_boolean(1));
    json_object_object_add(caps, "import_roceos_tar", json_object_new_boolean(1));
    json_object_object_add(caps, "export", json_object_new_boolean(1));
    json_object_object_add(caps, "pci_passthrough", json_object_new_boolean(iommu));
    json_object_object_add(caps, "usb_passthrough", json_object_new_boolean(1));
    json_object_object_add(caps, "ovs", json_object_new_boolean(ovs));
    json_object_object_add(caps, "sriov", json_object_new_boolean(0));
    json_object_object_add(d, "capabilities", caps);

    /* 0 == "server decides against the measured host ceiling at validate time"
     * (§5). max_disks/max_nics are the frozen static caps. */
    json_object_object_add(limits, "max_vcpus", json_object_new_int(0));
    json_object_object_add(limits, "max_memory_bytes", json_object_new_int64(0));
    json_object_object_add(limits, "max_disks", json_object_new_int(8));
    json_object_object_add(limits, "max_nics", json_object_new_int(8));
    json_object_object_add(d, "limits", limits);

    /* §5/§11: every advertised false capability carries a frozen reason token so
     * the frontend greys it out with a stable message instead of guessing. The
     * two unconditional-false capabilities (snapshot_memory, sriov) always carry
     * theirs; the host-probed ones only when actually false. */
    if (!kvm)
        json_object_object_add(reasons, "kvm", json_object_new_string("kvm_device_absent"));
    if (!tpm)
        json_object_object_add(reasons, "tpm", json_object_new_string("dependency_missing"));
    if (!secboot)
        json_object_object_add(reasons, "secure_boot", json_object_new_string("firmware_missing"));
    json_object_object_add(reasons, "snapshot_memory",
                           json_object_new_string("requires_stopped_or_unsupported_for_uefi_nvram"));
    if (!iommu)
        json_object_object_add(reasons, "pci_passthrough", json_object_new_string("iommu_disabled"));
    if (!ovs)
        json_object_object_add(reasons, "ovs", json_object_new_string("dependency_missing"));
    json_object_object_add(reasons, "sriov", json_object_new_string("not_implemented"));
    json_object_object_add(d, "capability_reasons", reasons);
    return d;
}
struct json_object *vm_overview_json(void)
{
    virConnectPtr conn = vm_conn();
    virDomainPtr *doms = NULL;
    int ndoms, i;
    int total = 0, running = 0, stopped = 0, paused = 0, other = 0;
    int64_t alloc_vcpus = 0, alloc_mem = 0;
    struct json_object *d, *counts, *host;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    long pages = sysconf(_SC_PHYS_PAGES);
    long pgsz = sysconf(_SC_PAGE_SIZE);

    /* Overview is the one "live" route in this file: it needs the domain list,
     * so a NULL connection is 503 (degraded), not an empty overview. */
    if (!conn)
        return NULL;
    ndoms = virConnectListAllDomains(conn, &doms, 0);
    if (ndoms < 0)
        return NULL;

    for (i = 0; i < ndoms; i++) {
        virDomainInfo info;
        int st = VIR_DOMAIN_NOSTATE;

        total++;
        if (virDomainGetState(doms[i], &st, NULL, 0) < 0)
            st = VIR_DOMAIN_NOSTATE;
        switch (st) {
        case VIR_DOMAIN_RUNNING:
        case VIR_DOMAIN_BLOCKED:      running++; break;
        case VIR_DOMAIN_SHUTOFF:      stopped++; break;
        case VIR_DOMAIN_PAUSED:
        case VIR_DOMAIN_PMSUSPENDED:  paused++;  break;
        default:                      other++;   break;
        }
        /* Committed against the host only by domains that are live. maxMem is the
         * configured ceiling (KiB); the balloon current would understate reserve. */
        if ((st == VIR_DOMAIN_RUNNING || st == VIR_DOMAIN_BLOCKED ||
             st == VIR_DOMAIN_PAUSED || st == VIR_DOMAIN_PMSUSPENDED) &&
            virDomainGetInfo(doms[i], &info) == 0) {
            alloc_vcpus += info.nrVirtCpu;
            alloc_mem   += (int64_t)info.maxMem * 1024;
        }
        virDomainFree(doms[i]);
    }
    free(doms);

    d = json_object_new_object();
    counts = json_object_new_object();
    host = json_object_new_object();
    json_object_object_add(counts, "total", json_object_new_int(total));
    json_object_object_add(counts, "running", json_object_new_int(running));
    json_object_object_add(counts, "stopped", json_object_new_int(stopped));
    json_object_object_add(counts, "paused", json_object_new_int(paused));
    json_object_object_add(counts, "other", json_object_new_int(other));
    json_object_object_add(d, "counts", counts);

    json_object_object_add(host, "cpus", json_object_new_int(cpus > 0 ? (int)cpus : 0));
    json_object_object_add(host, "memory_bytes",
                           json_object_new_int64(pages > 0 && pgsz > 0 ? (int64_t)pages * pgsz : 0));
    json_object_object_add(host, "allocated_vcpus", json_object_new_int64(alloc_vcpus));
    json_object_object_add(host, "allocated_memory_bytes", json_object_new_int64(alloc_mem));
    json_object_object_add(d, "host", host);

    json_object_object_add(d, "sampled_at", json_object_new_int64(vm_now_s()));
    return d;
}
