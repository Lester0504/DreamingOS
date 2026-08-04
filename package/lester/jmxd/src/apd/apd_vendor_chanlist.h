/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Parser for `wlanconfig <interface> list chan`.
 *
 * QCA driver builds answer `iw phy` without a channel list and answer
 * `iw dev <if> survey dump` with nothing at all, while still reporting a full
 * channel catalogue through this vendor command. Treating the empty `iw` output
 * as "the driver cannot do it" was the wrong conclusion: the data is available,
 * the probe was not.
 *
 * This lives in its own translation unit rather than in apd_backend_openwrt.c
 * so the catalogue fallback can be developed and tested independently of the
 * station and airtime collectors in that file.
 */
#ifndef APD_VENDOR_CHANLIST_H
#define APD_VENDOR_CHANLIST_H

#include <stddef.h>

#define APD_VENDOR_CHAN_LIMIT 128

/*
 * One channel as reported by the vendor tool.
 *
 * `dfs` marks a radar-detection channel: the tool prints `*~` (or `*`) after the
 * frequency. The width flags come from the `V80-`/`V160-` capability tokens on
 * the same line, so a channel that cannot do 80 MHz is not claimed to.
 */
struct apd_vendor_channel {
    int channel;
    int freq_mhz;
    int dfs;
    int width_20;
    int width_40;
    int width_80;
    int width_160;
    /* Center channel advertised alongside V80-/V160-, 0 when absent. */
    int center_80;
    int center_160;
    char mode[24];
};

struct apd_vendor_chan_set {
    struct apd_vendor_channel items[APD_VENDOR_CHAN_LIMIT];
    size_t count;
    int truncated;
    /* Empty when channels were parsed; otherwise why nothing was produced. */
    char reason[48];
};

/*
 * Parses the tool's stdout. Returns 0 when at least one channel was recognised,
 * -1 otherwise with `reason` set. Unparsable lines are skipped rather than
 * aborting the parse: the tool appends human-readable notes to real output.
 */
int apd_vendor_chanlist_parse(const char *text, struct apd_vendor_chan_set *set);

#endif /* APD_VENDOR_CHANLIST_H */
