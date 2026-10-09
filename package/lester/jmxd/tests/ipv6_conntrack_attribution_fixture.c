#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dw_conntrack_attribution.h"

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void target_init(struct dw_ct_target *target, int id,
                        const char *iface, const char *addr)
{
    memset(target, 0, sizeof(*target));
    target->kernel_wan_id = id;
    snprintf(target->ifaces[target->iface_count++], DW_CT_IFACE_LEN, "%s", iface);
    snprintf(target->addrs[target->addr_count++], DW_CT_ADDR_LEN, "%s", addr);
}

int main(void)
{
    struct dw_ct_target targets[4];
    struct dw_ct_match match;
    int counts[4] = {0};
    int i;

    target_init(&targets[0], 1, "pppoe-wan", "2001:db8:1::1");
    target_init(&targets[1], 2, "pppoe-wan2", "2001:db8:2::1");
    target_init(&targets[2], 3, "pppoe-wan3", "2001:db8:3::1");
    target_init(&targets[3], 4, "pppoe-wan4", "2001:db8:4::1");

    for (i = 0; i < 4; i++) {
        char line[256];

        snprintf(line, sizeof(line),
                 "ipv6 10 tcp 6 src=fd00::10 dst=2001:4860::1 mark=0x%x\n",
                 (7U << 16) | (unsigned int)(i + 1));
        match = dw_ct_classify_line(line, targets, 4);
        require(match.kind == DW_CT_MARK, "ctmark was not primary");
        require(match.target_index == i, "ctmark mapped to the wrong WAN");
        counts[match.target_index]++;
    }
    for (i = 0; i < 4; i++)
        require(counts[i] == 1, "a marked row was copied across WANs");

    match = dw_ct_classify_line(
        "ipv6 10 tcp 6 src=fd00::10 dst=2001:4860::1 oif=pppoe-wan2 mark=0x70063\n",
        targets, 4);
    require(match.kind == DW_CT_INTERFACE && match.target_index == 1,
            "unknown mark did not use interface fallback");

    match = dw_ct_classify_line(
        "ipv6 10 udp 17 src=fd00::10 dst=2001:db8:3::1 mark=0x70063\n",
        targets, 4);
    require(match.kind == DW_CT_ADDRESS && match.target_index == 2,
            "unknown mark did not use address fallback");

    match = dw_ct_classify_line(
        "ipv6 10 tcp 6 src=2001:db8:4::1 dst=2001:4860::1 mark=0x70001\n",
        targets, 4);
    require(match.kind == DW_CT_LOCAL_SOURCE,
            "router-originated IPv6 source was not excluded");

    match = dw_ct_classify_line(
        "ipv6 10 tcp 6 src=fd00::10 dst=2001:4860::1 mark=0x70063\n",
        targets, 4);
    require(match.kind == DW_CT_UNMAPPED && match.target_index == -1,
            "unattributed IPv6 row did not remain unmapped");

    match.kind = DW_CT_UNMAPPED;
    if (!strncmp("ipv4 2 tcp 6 src=192.0.2.10 mark=0x70001", "ipv6 ", 5))
        match = dw_ct_classify_line("ipv4 2 tcp 6 src=192.0.2.10 mark=0x70001",
                                    targets, 4);
    require(match.kind == DW_CT_UNMAPPED,
            "IPv6 caller failed to filter an IPv4 conntrack row");

    puts("ok: shared conntrack attribution runtime fixture");
    return 0;
}
