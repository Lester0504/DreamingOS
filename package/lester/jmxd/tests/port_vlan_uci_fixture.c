#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uci.h>
#include <json-c/json.h>

static int webd_port_vlan_id_ok(int id, int allow_zero)
{
    return id >= (allow_zero ? 0 : 1) && id <= 4094;
}
static int webd_json_array_contains_int_value(struct json_object *values, int id)
{
    for (size_t i = 0; i < json_object_array_length(values); i++)
        if (json_object_get_int(json_object_array_get_idx(values, i)) == id) return 1;
    return 0;
}
#include "port_vlan_uci.inc"

static void check(struct uci_context *ctx, const char *dir, const char *text,
                  const char *expected_reason, int native, size_t tag_count)
{
    char path[256], after[4096] = "";
    struct json_object *config = json_object_new_object();
    const char *reason;
    FILE *fp;
    snprintf(path, sizeof(path), "%s/network", dir);
    fp = fopen(path, "w");
    assert(fp && fputs(text, fp) >= 0 && fclose(fp) == 0);
    reason = webd_port_vlan_read_config(ctx, "lan1", "br-lan", config);
    assert(!strcmp(reason, expected_reason));
    assert(json_object_get_int(json_object_object_get(config, "native_vlan")) == native);
    assert(json_object_array_length(json_object_object_get(config, "tagged_vlans")) == tag_count);
    fp = fopen(path, "r");
    assert(fp);
    assert(fread(after, 1, sizeof(after) - 1, fp) == strlen(text));
    fclose(fp);
    assert(!strcmp(text, after));
    json_object_put(config);
}

#define BRIDGE "config device 'br'\n option name 'br-lan'\n option type 'bridge'\n option vlan_filtering '1'\n"
#define NATIVE "config bridge-vlan\n option device 'br-lan'\n option vlan '1'\n list ports 'lan1:u*'\n list ports 'lan2:u*'\n"
#define TAGGED "config bridge-vlan\n option device 'br-lan'\n option vlan '20'\n list ports 'lan1:t'\n list ports 'lan3:t'\n"
int main(void)
{
    char dir[] = "/tmp/f17-vlan-uci-XXXXXX", path[256];
    struct uci_context *ctx = uci_alloc_context();
    assert(ctx && mkdtemp(dir));
    assert(uci_set_confdir(ctx, dir) == UCI_OK && uci_set_savedir(ctx, dir) == UCI_OK);
    check(ctx, dir, BRIDGE NATIVE TAGGED, "", 1, 1);
    check(ctx, dir, BRIDGE TAGGED, "", 0, 1);
    check(ctx, dir, NATIVE TAGGED, "bridge_vlan_filtering_not_enabled", 1, 1);
    check(ctx, dir, BRIDGE NATIVE
        "config bridge-vlan\n option device 'br-lan'\n option vlan '2'\n list ports 'lan1:u*'\n",
        "multiple_native_vlans_unsupported", 2, 0);
    check(ctx, dir, BRIDGE NATIVE
        "config bridge-vlan\n option device 'br-lan'\n option vlan '2'\n list ports 'lan1:u'\n",
        "vlan_membership_flags_unsupported", 1, 0);
    check(ctx, dir, BRIDGE NATIVE
        "config bridge-vlan\n option device 'br-other'\n option vlan '2'\n list ports 'lan1:t'\n",
        "", 1, 0);
    snprintf(path, sizeof(path), "%s/network", dir);
    uci_free_context(ctx);
    unlink(path);
    rmdir(dir);
    puts("six real UCI VLAN canonical cases passed; input files unchanged");
    return 0;
}
