// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AP_RADIO_ID_H
#define DREAMINGWRT_AP_RADIO_ID_H

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static inline int dreamingwrt_ap_radio_id_component(
    const char *text, const char **end_out, unsigned int *value_out)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !text[0] || !end_out || !value_out ||
        (text[0] == '0' && isdigit((unsigned char)text[1])))
        return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno == ERANGE || !end || end == text || value > UINT_MAX)
        return -1;
    *end_out = end;
    *value_out = (unsigned int)value;
    return 0;
}

/* Legacy phyN means one radio per wiphy. phyNrM selects radio M within
 * wiphy N on mac80211 hardware that exposes several radios through one phy. */
static inline int dreamingwrt_ap_radio_id_parse(
    const char *radio_id, unsigned int *wiphy_index,
    unsigned int *radio_index, int *has_radio_index)
{
    const char *end;

    if (!radio_id || strncmp(radio_id, "phy", 3) || !radio_id[3] ||
        strlen(radio_id) > 31 || !wiphy_index || !radio_index ||
        !has_radio_index || dreamingwrt_ap_radio_id_component(
            radio_id + 3, &end, wiphy_index) != 0)
        return -1;
    *radio_index = 0;
    *has_radio_index = 0;
    if (!*end)
        return 0;
    if (*end != 'r' || !end[1] || dreamingwrt_ap_radio_id_component(
            end + 1, &end, radio_index) != 0 || *end)
        return -1;
    *has_radio_index = 1;
    return 0;
}

static inline int dreamingwrt_ap_radio_id_valid(const char *radio_id)
{
    unsigned int wiphy_index;
    unsigned int radio_index;
    int has_radio_index;

    return dreamingwrt_ap_radio_id_parse(radio_id, &wiphy_index,
        &radio_index, &has_radio_index) == 0;
}

#endif
