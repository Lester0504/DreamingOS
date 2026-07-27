// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/otad/otad_internal.h"

const char *otad_json_str(struct json_object *o, const char *key,
                          const char *def)
{
    struct json_object *value = NULL;

    if (!o || !json_object_object_get_ex(o, key, &value) ||
        !json_object_is_type(value, json_type_string))
        return def;
    return json_object_get_string(value);
}

int otad_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *value = NULL;

    if (!o || !json_object_object_get_ex(o, key, &value))
        return def;
    return json_object_get_boolean(value) ? 1 : 0;
}

void otad_json_add_string(struct json_object *o, const char *key,
                          const char *value)
{
    json_object_object_add(o, key,
                           json_object_new_string(value ? value : ""));
}

#include "../src/otad/otad_topology.c"

int main(void)
{
    struct otad_ab_topology topology;
    struct otad_ab_topology verified_topology;
    struct json_object *result = json_object_new_object();
    struct json_object *evidence = json_object_new_array();
    char reason[128] = "";
    char boot_state_reason[128] = "";
    int topology_verified;
    int boot_state_verified = 0;
    int inactive_bootable_verified = 0;
    int supported;

    topology_verified = otad_ab_topology_readonly_probe(
        &topology, reason, sizeof(reason)) == 0;
    if (topology_verified &&
        otad_ab_topology_discover(&verified_topology, boot_state_reason,
                                  sizeof(boot_state_reason)) == 0 &&
        otad_ab_boot_state_readonly_verify(&verified_topology,
                                           boot_state_reason,
                                           sizeof(boot_state_reason)) == 0) {
        topology = verified_topology;
        boot_state_verified = 1;
        inactive_bootable_verified =
            topology.inactive_slot_bootable_verified;
    }
    supported = topology_verified && boot_state_verified;
    json_object_object_add(result, "ok", json_object_new_boolean(1));
    json_object_object_add(result, "supported",
                           json_object_new_boolean(supported));
    json_object_object_add(result, "read_only",
                           json_object_new_boolean(1));
    json_object_object_add(result, "topology_readonly_verified",
                           json_object_new_boolean(topology_verified));
    json_object_object_add(result, "inactive_slot_write_target_verified",
                           json_object_new_boolean(topology_verified));
    json_object_object_add(result, "boot_state_readonly_verified",
                           json_object_new_boolean(boot_state_verified));
    json_object_object_add(result, "inactive_slot_bootable_verified",
                           json_object_new_boolean(
                               inactive_bootable_verified));
    otad_json_add_string(result, "reason", supported ? "" :
                         (topology_verified ? boot_state_reason : reason));
    json_object_array_add(evidence,
                          json_object_new_string("/sys/class/block"));
    json_object_array_add(evidence,
                          json_object_new_string("/proc/self/mountinfo"));
    json_object_array_add(evidence,
                          json_object_new_string("/proc/cmdline"));
    json_object_array_add(evidence,
                          json_object_new_string("blkid:PARTUUID,TYPE"));
    json_object_array_add(evidence,
                          json_object_new_string(
                              "DWRT_BOOT:boot/grub/grubenv,grub.cfg"));
    json_object_object_add(result, "evidence", evidence);
    if (topology_verified)
        json_object_object_add(result, "topology",
                               otad_ab_topology_json(&topology));
    puts(json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
    json_object_put(result);
    return supported ? 0 : 2;
}
