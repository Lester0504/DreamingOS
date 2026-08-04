// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * `wlanconfig <interface> list chan` parsing.
 *
 * Sample of the format this handles (31.31, ath11):
 *
 *   Channel  36 : 5180    Mhz 11na C CU V VU V80- 42 V160- 50
 *   Channel  52 : 5260 *~ Mhz 11na C CU V VU V80- 58 V160- 50
 *
 * The `*~` between frequency and unit marks DFS. `V80-`/`V160-` are followed by
 * the center channel for that width. Absence of a marker means the width is not
 * advertised, and it is left unset rather than assumed: the AC validate path
 * refuses widths without evidence, so under-claiming is safe and over-claiming
 * is not.
 */
#include "apd_vendor_chanlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int chan_parse_int(const char *token, int low, int high, int *out)
{
    char *end = NULL;
    long value;

    if (!token || !*token)
        return -1;
    value = strtol(token, &end, 10);
    if (!end || *end || value < low || value > high)
        return -1;
    *out = (int)value;
    return 0;
}

/*
 * Reads one `Channel N : FREQ [flags] Mhz MODE caps...` line.
 *
 * Returns 0 when the line yielded a channel. The leading "Channel" keyword and
 * the colon are required, which is what keeps the tool's trailing prose notes
 * from being mistaken for data.
 */
static int chan_parse_line(const char *line, struct apd_vendor_channel *out)
{
    char buffer[512];
    char *tokens[48];
    size_t count = 0;
    char *cursor;
    char *saved = NULL;
    size_t i;
    size_t colon = 0;
    int have_colon = 0;

    if (!line || !out)
        return -1;
    if (snprintf(buffer, sizeof(buffer), "%s", line) >= (int)sizeof(buffer))
        return -1;
    cursor = strtok_r(buffer, " \t\r\n", &saved);
    while (cursor && count < sizeof(tokens) / sizeof(tokens[0])) {
        tokens[count++] = cursor;
        cursor = strtok_r(NULL, " \t\r\n", &saved);
    }
    /* Channel <n> : <freq> ... needs at least four tokens. */
    if (count < 4 || strcmp(tokens[0], "Channel"))
        return -1;
    for (i = 1; i < count; i++) {
        if (!strcmp(tokens[i], ":")) {
            colon = i;
            have_colon = 1;
            break;
        }
    }
    if (!have_colon || colon < 2 || colon + 1 >= count)
        return -1;

    memset(out, 0, sizeof(*out));
    if (chan_parse_int(tokens[colon - 1], 1, 233, &out->channel) != 0)
        return -1;
    if (chan_parse_int(tokens[colon + 1], 2000, 8000, &out->freq_mhz) != 0)
        return -1;

    for (i = colon + 2; i < count; i++) {
        const char *token = tokens[i];

        /*
         * DFS marker. It appears as a standalone token between the frequency and
         * "Mhz"; both `*~` and a bare `*` are accepted because builds differ in
         * whether the tilde is emitted.
         */
        if (token[0] == '*') {
            out->dfs = 1;
            continue;
        }
        if (!strcasecmp(token, "Mhz"))
            continue;
        if (!strncmp(token, "11", 2) && !out->mode[0]) {
            snprintf(out->mode, sizeof(out->mode), "%s", token);
            continue;
        }
        if (!strcmp(token, "V80-")) {
            out->width_80 = 1;
            /* The next token is the 80 MHz center channel when present. */
            if (i + 1 < count &&
                chan_parse_int(tokens[i + 1], 1, 233, &out->center_80) == 0)
                i++;
            continue;
        }
        if (!strcmp(token, "V160-")) {
            out->width_160 = 1;
            if (i + 1 < count &&
                chan_parse_int(tokens[i + 1], 1, 233, &out->center_160) == 0)
                i++;
            continue;
        }
    }

    /*
     * 20 MHz is implied by the channel existing at all. 40 MHz is implied by an
     * 80 MHz capability, since 80 is built from two 40s; it is not invented for
     * channels that only advertise 20.
     */
    out->width_20 = 1;
    if (out->width_80 || out->width_160)
        out->width_40 = 1;
    return 0;
}

int apd_vendor_chanlist_parse(const char *text, struct apd_vendor_chan_set *set)
{
    const char *cursor;

    if (!set)
        return -1;
    memset(set, 0, sizeof(*set));
    if (!text || !*text) {
        snprintf(set->reason, sizeof(set->reason), "%s", "no_output");
        return -1;
    }

    for (cursor = text; *cursor;) {
        const char *newline = strchr(cursor, '\n');
        size_t length = newline ? (size_t)(newline - cursor) : strlen(cursor);
        char line[512];
        struct apd_vendor_channel channel;

        if (length < sizeof(line)) {
            memcpy(line, cursor, length);
            line[length] = '\0';
            if (chan_parse_line(line, &channel) == 0) {
                if (set->count >= APD_VENDOR_CHAN_LIMIT) {
                    set->truncated = 1;
                    break;
                }
                set->items[set->count++] = channel;
            }
        }
        if (!newline)
            break;
        cursor = newline + 1;
    }

    if (!set->count) {
        snprintf(set->reason, sizeof(set->reason), "%s", "no_channels_listed");
        return -1;
    }
    return 0;
}
