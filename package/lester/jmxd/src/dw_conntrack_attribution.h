/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DW_CONNTRACK_ATTRIBUTION_H
#define DW_CONNTRACK_ATTRIBUTION_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DW_CT_TARGET_IFACES 3
#define DW_CT_TARGET_ADDRS 18
#define DW_CT_IFACE_LEN 64
#define DW_CT_ADDR_LEN 64

struct dw_ct_target {
    int kernel_wan_id;
    char ifaces[DW_CT_TARGET_IFACES][DW_CT_IFACE_LEN];
    size_t iface_count;
    char addrs[DW_CT_TARGET_ADDRS][DW_CT_ADDR_LEN];
    size_t addr_count;
};

enum dw_ct_match_kind {
    DW_CT_UNMAPPED = 0,
    DW_CT_LOCAL_SOURCE,
    DW_CT_MARK,
    DW_CT_INTERFACE,
    DW_CT_ADDRESS,
};

struct dw_ct_match {
    enum dw_ct_match_kind kind;
    int target_index;
};

static int dw_ct_copy_token(char *out, size_t out_len, const char *value)
{
    size_t len;

    if (!out || out_len < 2 || !value || !value[0])
        return -1;
    len = strcspn(value, " \t\r\n");
    if (!len || len >= out_len)
        return -1;
    memcpy(out, value, len);
    out[len] = '\0';
    return 0;
}

static int dw_ct_original_source(const char *line, char *out, size_t out_len)
{
    const char *source;

    if (!line)
        return -1;
    source = strstr(line, "src=");
    return source ? dw_ct_copy_token(out, out_len, source + 4) : -1;
}

static int dw_ct_mark_wan_id(const char *line)
{
    const char *value;
    char *end = NULL;
    unsigned long mark;
    unsigned int rule_prio;
    unsigned int wan_id;

    if (!line || !(value = strstr(line, "mark=")))
        return 0;
    errno = 0;
    mark = strtoul(value + 5, &end, 0);
    if (errno || end == value + 5 || mark > UINT32_MAX)
        return 0;
    rule_prio = ((unsigned int)mark) >> 16;
    wan_id = ((unsigned int)mark) & 0xffffU;
    return rule_prio && wan_id ? (int)wan_id : 0;
}

static int dw_ct_line_has_token(const char *line, const char *prefix,
                                const char *value)
{
    char needle[DW_CT_ADDR_LEN + 16];
    const char *cursor;
    size_t len;

    if (!line || !prefix || !value || !value[0] ||
        snprintf(needle, sizeof(needle), "%s%s", prefix, value) >=
            (int)sizeof(needle))
        return 0;
    len = strlen(needle);
    cursor = strstr(line, needle);
    while (cursor) {
        char tail = cursor[len];

        if (!tail || tail == ' ' || tail == '\t' || tail == '\r' || tail == '\n')
            return 1;
        cursor = strstr(cursor + 1, needle);
    }
    return 0;
}

static int dw_ct_target_for_mark(const struct dw_ct_target *targets,
                                 size_t count, int wan_id)
{
    size_t i;

    if (!targets || wan_id <= 0)
        return -1;
    for (i = 0; i < count; i++)
        if (targets[i].kernel_wan_id == wan_id)
            return (int)i;
    return -1;
}

static int dw_ct_target_for_local_source(const char *line,
                                         const struct dw_ct_target *targets,
                                         size_t count)
{
    char source[DW_CT_ADDR_LEN];
    size_t i, j;

    if (dw_ct_original_source(line, source, sizeof(source)) != 0)
        return -1;
    for (i = 0; i < count; i++)
        for (j = 0; j < targets[i].addr_count; j++)
            if (!strcmp(source, targets[i].addrs[j]))
                return (int)i;
    return -1;
}

static int dw_ct_unique_interface_target(const char *line,
                                         const struct dw_ct_target *targets,
                                         size_t count)
{
    int match = -1;
    size_t i, j;

    for (i = 0; i < count; i++) {
        int target_matches = 0;

        for (j = 0; j < targets[i].iface_count; j++) {
            const char *iface = targets[i].ifaces[j];

            if (dw_ct_line_has_token(line, "iif=", iface) ||
                dw_ct_line_has_token(line, "oif=", iface) ||
                dw_ct_line_has_token(line, "dev=", iface)) {
                target_matches = 1;
                break;
            }
        }
        if (!target_matches)
            continue;
        if (match >= 0)
            return -1;
        match = (int)i;
    }
    return match;
}

static int dw_ct_unique_address_target(const char *line,
                                       const struct dw_ct_target *targets,
                                       size_t count)
{
    int match = -1;
    size_t i, j;

    for (i = 0; i < count; i++) {
        int target_matches = 0;

        for (j = 0; j < targets[i].addr_count; j++) {
            const char *addr = targets[i].addrs[j];

            if (dw_ct_line_has_token(line, "src=", addr) ||
                dw_ct_line_has_token(line, "dst=", addr)) {
                target_matches = 1;
                break;
            }
        }
        if (!target_matches)
            continue;
        if (match >= 0)
            return -1;
        match = (int)i;
    }
    return match;
}

static struct dw_ct_match dw_ct_classify_line(
    const char *line, const struct dw_ct_target *targets, size_t count)
{
    struct dw_ct_match match = { DW_CT_UNMAPPED, -1 };
    int mark_target;
    int local_target;

    if (!line || !targets || !count)
        return match;
    mark_target = dw_ct_target_for_mark(targets, count,
                                        dw_ct_mark_wan_id(line));
    local_target = dw_ct_target_for_local_source(line, targets, count);
    if (local_target >= 0) {
        match.kind = DW_CT_LOCAL_SOURCE;
        match.target_index = mark_target >= 0 ? mark_target : local_target;
        return match;
    }
    if (mark_target >= 0) {
        match.kind = DW_CT_MARK;
        match.target_index = mark_target;
        return match;
    }
    match.target_index = dw_ct_unique_interface_target(line, targets, count);
    if (match.target_index >= 0) {
        match.kind = DW_CT_INTERFACE;
        return match;
    }
    match.target_index = dw_ct_unique_address_target(line, targets, count);
    if (match.target_index >= 0)
        match.kind = DW_CT_ADDRESS;
    return match;
}

#endif
