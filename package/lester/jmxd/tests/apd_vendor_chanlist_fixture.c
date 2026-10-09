// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * `wlanconfig list chan` parsing, driven against the output shape 31.31 emits.
 *
 * The point of these checks is that DFS and the 80/160 MHz capabilities survive
 * parsing. Taking only the channel number would satisfy "we have a catalogue"
 * while still leaving the channel AI view without its inputs.
 */
#include "apd_vendor_chanlist.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Verbatim shape from `wlanconfig ath11 list chan`, including the trailing
 * prose line the tool prints after the table. */
static const char *sample(void)
{
    return
        "Channel  36 : 5180    Mhz 11na C CU V VU V80- 42 V160- 50\n"
        "Channel  40 : 5200    Mhz 11na C CU V VU V80- 42 V160- 50\n"
        "Channel  52 : 5260 *~ Mhz 11na C CU V VU V80- 58 V160- 50\n"
        "Channel  56 : 5280 *~ Mhz 11na C CU V VU V80- 58 V160- 50\n"
        "Channel 149 : 5745    Mhz 11na C CU V VU V80- 155\n"
        "Channel   1 : 2412    Mhz 11ng C CU\n";
}

static const struct apd_vendor_channel *find(const struct apd_vendor_chan_set *set,
                                             int channel)
{
    size_t i;

    for (i = 0; i < set->count; i++) {
        if (set->items[i].channel == channel)
            return &set->items[i];
    }
    return NULL;
}

int main(void)
{
    struct apd_vendor_chan_set set;
    const struct apd_vendor_channel *c;

    /* 1. A real table parses, and only the channel rows become channels: the
     *    trailing note line must not turn into a bogus entry. */
    assert(apd_vendor_chanlist_parse(sample(), &set) == 0);
    assert(set.count == 6);
    assert(!set.truncated);
    assert(set.reason[0] == '\0');

    /* 2. Non-DFS channel: frequency, mode and 80/160 capability with centers. */
    c = find(&set, 36);
    assert(c);
    assert(c->freq_mhz == 5180);
    assert(!c->dfs);
    assert(c->width_20 && c->width_40 && c->width_80 && c->width_160);
    assert(c->center_80 == 42);
    assert(c->center_160 == 50);
    assert(!strcmp(c->mode, "11na"));

    /* 3. DFS is taken from the `*~` marker, which sits between the frequency
     *    and the unit rather than at a fixed column. */
    c = find(&set, 52);
    assert(c);
    assert(c->freq_mhz == 5260);
    assert(c->dfs);
    assert(c->center_80 == 58);

    c = find(&set, 56);
    assert(c && c->dfs);

    /* 4. A channel advertising 80 but not 160 must not be credited with 160. */
    c = find(&set, 149);
    assert(c);
    assert(c->width_80 && !c->width_160);
    assert(c->center_80 == 155);
    assert(c->center_160 == 0);

    /* 5. A 2.4 GHz channel with no width markers claims only 20 MHz. This is the
     *    case that must not be widened: vendor VHT is advertised on 2.4 GHz
     *    where no 80 MHz channel exists. */
    c = find(&set, 1);
    assert(c);
    assert(c->freq_mhz == 2412);
    assert(c->width_20);
    assert(!c->width_40 && !c->width_80 && !c->width_160);
    assert(!c->dfs);

    /* 6. Empty and non-table input are refused with distinguishable reasons,
     *    so "tool missing" never reads the same as "no channels". */
    assert(apd_vendor_chanlist_parse("", &set) == -1);
    assert(!strcmp(set.reason, "no_output"));
    assert(apd_vendor_chanlist_parse(NULL, &set) == -1);
    assert(!strcmp(set.reason, "no_output"));
    assert(apd_vendor_chanlist_parse("wlanconfig: command not found\n", &set) == -1);
    assert(!strcmp(set.reason, "no_channels_listed"));
    assert(set.count == 0);

    /* 7. Malformed rows are skipped, not fatal, and do not shift later rows. */
    assert(apd_vendor_chanlist_parse(
        "Channel  xx : 5180    Mhz 11na\n"
        "Channel  36 : 5180    Mhz 11na C CU V VU V80- 42\n"
        "Channel     : garbage\n", &set) == 0);
    assert(set.count == 1);
    assert(set.items[0].channel == 36);

    /* 8. An out-of-range frequency is rejected rather than stored. */
    assert(apd_vendor_chanlist_parse("Channel  36 : 99999 Mhz 11na\n", &set) == -1);

    printf("apd_vendor_chanlist_fixture: all checks passed\n");
    return 0;
}
