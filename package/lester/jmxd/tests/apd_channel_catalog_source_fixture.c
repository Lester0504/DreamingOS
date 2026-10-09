// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Contract for the channel-catalogue vendor fallback wiring.
 *
 * `apd_vendor_chanlist_fixture.c` already covers the parser. What this pins is
 * the wiring added on top of it, where the risk is different: the catalogue
 * object is shared with the `iw phy` path, so a fallback that fills it must not
 * lie about where the data came from, and must not produce a differently
 * shaped object than the primary path.
 *
 * The specific failure this guards against is named in the handoff for this
 * fallback: `apd_channel_catalog_new()` hardcoded `source: "iw_phy"`, so a
 * catalogue built from `wlanconfig <if> list chan` would have reported itself
 * as iw_phy. A reader deciding whether to trust widths or DFS flags looks at
 * that field, so getting it wrong is worse than having no fallback at all.
 *
 * The catalogue builders live inside apd_backend_openwrt.c, which pulls in
 * ubus, sqlite and the whole collector surface, so this fixture links the real
 * parser and re-implements only the JSON assembly under test, then verifies the
 * real file still contains the load-bearing lines.
 *
 * Build:
 *   cc -O0 -Wall -Wextra -o /tmp/apd_cat_src \
 *      apd_channel_catalog_source_fixture.c ../src/apd/apd_vendor_chanlist.c \
 *      $(pkg-config --cflags --libs json-c)
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "../src/apd/apd_vendor_chanlist.h"

static int failures;

/*
 * Verbatim output shape from `wlanconfig ath11 list chan` on 31.31, matching
 * apd_vendor_chanlist_fixture.c. The exact spacing matters: the width tokens
 * are `V80- 42` with a space before the center channel, and DFS is a standalone
 * `*~` between the frequency and `Mhz`. Writing `V80-42` or `5260*` instead
 * parses as neither, which is how this fixture first failed.
 */
static const char *sample(void)
{
    return
        "Channel  36 : 5180    Mhz 11na C CU V VU V80- 42 V160- 50\n"
        "Channel  52 : 5260 *~ Mhz 11na C CU V VU V80- 58 V160- 50\n"
        "Channel   1 : 2412    Mhz 11ng C CU\n"
        "wlanconfig: 3 channels listed\n";
}

/*
 * Mirror of apd_channel_catalog_new_source(): the point of the change is that
 * `source` is a parameter, so the fixture must build it the same way.
 */
static struct json_object *catalog_new_source(const char *source,
                                              const char *reason,
                                              int64_t observed_at)
{
    struct json_object *catalog = json_object_new_object();

    json_object_object_add(catalog, "source",
                           json_object_new_string(source ? source : "iw_phy"));
    json_object_object_add(catalog, "scope",
                           json_object_new_string("runtime"));
    json_object_object_add(catalog, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(catalog, "complete",
                           json_object_new_boolean(reason == NULL));
    if (reason)
        json_object_object_add(catalog, "reason",
                               json_object_new_string(reason));
    json_object_object_add(catalog, "channels", json_object_new_array());
    return catalog;
}

/* Mirror of the assembly loop in apd_channel_catalog_vendor_fallback(). */
static struct json_object *build_vendor_catalog(const char *text,
                                                const char *interface,
                                                const char *regdomain)
{
    struct apd_vendor_chan_set set;
    struct json_object *catalog;
    struct json_object *channels = NULL;
    size_t i;

    memset(&set, 0, sizeof(set));
    if (apd_vendor_chanlist_parse(text, &set) != 0)
        return NULL;
    catalog = catalog_new_source("wlanconfig_list_chan", NULL, 1786027000);
    if (regdomain && regdomain[0])
        json_object_object_add(catalog, "regdomain",
                               json_object_new_string(regdomain));
    json_object_object_add(catalog, "interface",
                           json_object_new_string(interface));
    if (set.truncated)
        json_object_object_add(catalog, "truncated",
                               json_object_new_boolean(1));
    json_object_object_get_ex(catalog, "channels", &channels);
    for (i = 0; i < set.count; i++) {
        const struct apd_vendor_channel *src = &set.items[i];
        struct json_object *channel = json_object_new_object();
        struct json_object *widths;

        json_object_object_add(channel, "channel",
                               json_object_new_int(src->channel));
        json_object_object_add(channel, "frequency_mhz",
                               json_object_new_int(src->freq_mhz));
        json_object_object_add(channel, "disabled",
                               json_object_new_boolean(0));
        json_object_object_add(channel, "no_ir", json_object_new_boolean(0));
        json_object_object_add(channel, "radar_detection",
                               json_object_new_boolean(src->dfs ? 1 : 0));
        if (src->mode[0])
            json_object_object_add(channel, "mode",
                                   json_object_new_string(src->mode));
        widths = json_object_new_array();
        if (src->width_20)
            json_object_array_add(widths, json_object_new_int(20));
        if (src->width_40)
            json_object_array_add(widths, json_object_new_int(40));
        if (src->width_80)
            json_object_array_add(widths, json_object_new_int(80));
        if (src->width_160)
            json_object_array_add(widths, json_object_new_int(160));
        if (json_object_array_length(widths))
            json_object_object_add(channel, "supported_widths_mhz", widths);
        else
            json_object_put(widths);
        if (src->center_80)
            json_object_object_add(channel, "center_channel_80",
                                   json_object_new_int(src->center_80));
        if (src->center_160)
            json_object_object_add(channel, "center_channel_160",
                                   json_object_new_int(src->center_160));
        json_object_array_add(channels, channel);
    }
    return catalog;
}

static struct json_object *child(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    return (o && json_object_object_get_ex(o, key, &v)) ? v : NULL;
}

static struct json_object *chan_by_number(struct json_object *catalog, int n)
{
    struct json_object *channels = child(catalog, "channels");
    size_t i;

    for (i = 0; channels && i < json_object_array_length(channels); i++) {
        struct json_object *entry = json_object_array_get_idx(channels, i);
        struct json_object *num = child(entry, "channel");

        if (num && json_object_get_int(num) == n)
            return entry;
    }
    return NULL;
}

static void fail(const char *what)
{
    fprintf(stderr, "  FAIL %s\n", what);
    failures++;
}

/*
 * The whole reason source became a parameter. A vendor-built catalogue must say
 * so, and the primary path must keep saying iw_phy.
 */
static void test_source_is_not_a_lie(void)
{
    struct json_object *vendor = build_vendor_catalog(sample(), "ath0", "US");
    struct json_object *primary = catalog_new_source("iw_phy", NULL, 1);
    struct json_object *s;

    if (!vendor) {
        fail("vendor catalogue did not build");
        return;
    }
    s = child(vendor, "source");
    if (!s || strcmp(json_object_get_string(s), "wlanconfig_list_chan"))
        fail("vendor catalogue does not report wlanconfig_list_chan");

    s = child(primary, "source");
    if (!s || strcmp(json_object_get_string(s), "iw_phy"))
        fail("primary path no longer reports iw_phy");

    /* the default must stay iw_phy so an un-migrated caller cannot silently
     * mislabel a catalogue */
    s = child(catalog_new_source(NULL, NULL, 1), "source");
    if (!s || strcmp(json_object_get_string(s), "iw_phy"))
        fail("NULL source does not default to iw_phy");

    /* per-VAP data must name the interface it came from */
    s = child(vendor, "interface");
    if (!s || strcmp(json_object_get_string(s), "ath0"))
        fail("vendor catalogue does not record the interface");
}

/*
 * Shape parity with the iw-phy path. A consumer must not have to branch on
 * source to read the common fields.
 */
static void test_shape_matches_primary_path(void)
{
    struct json_object *vendor = build_vendor_catalog(sample(), "ath0", "US");
    static const char *required[] = {
        "source", "scope", "observed_at", "complete", "channels", NULL
    };
    struct json_object *entry;
    int i;

    if (!vendor) {
        fail("vendor catalogue did not build");
        return;
    }
    for (i = 0; required[i]; i++)
        if (!child(vendor, required[i]))
            fail(required[i]);

    /* complete must be true and reason absent on a successful parse */
    if (!json_object_get_boolean(child(vendor, "complete")))
        fail("successful vendor parse is not marked complete");
    if (child(vendor, "reason"))
        fail("successful vendor parse still carries a reason");

    /* the flags the iw path always emits must be present, not omitted */
    entry = chan_by_number(vendor, 36);
    if (!entry) {
        fail("channel 36 missing");
        return;
    }
    if (!child(entry, "disabled") || !child(entry, "no_ir") ||
        !child(entry, "radar_detection"))
        fail("vendor channel omits a flag the iw path always emits");
}

/*
 * Width claims must stay conservative. The 2.4 GHz row has no width token, so
 * it must not be promoted: BE10000 advertises vendor VHT on 2.4 GHz where no
 * 80 MHz channel exists, and over-claiming here is what the AC validate path
 * would then reject.
 */
static void test_widths_are_not_over_claimed(void)
{
    struct json_object *vendor = build_vendor_catalog(sample(), "ath0", "US");
    struct json_object *entry, *widths;

    if (!vendor)
        return;

    entry = chan_by_number(vendor, 1);
    if (!entry) {
        fail("channel 1 missing");
    } else if ((widths = child(entry, "supported_widths_mhz")) != NULL) {
        size_t i;

        for (i = 0; i < json_object_array_length(widths); i++)
            if (json_object_get_int(json_object_array_get_idx(widths, i)) > 20)
                fail("2.4 GHz channel claims a width above 20 MHz");
    }

    entry = chan_by_number(vendor, 36);
    widths = entry ? child(entry, "supported_widths_mhz") : NULL;
    if (!widths || json_object_array_length(widths) == 0)
        fail("channel 36 lost its width evidence");
    if (!child(entry, "center_channel_80") ||
        json_object_get_int(child(entry, "center_channel_80")) != 42)
        fail("channel 36 lost its 80 MHz center");

    /* DFS must survive the trip as radar_detection */
    entry = chan_by_number(vendor, 52);
    if (!entry || !json_object_get_boolean(child(entry, "radar_detection")))
        fail("DFS channel 52 not flagged as radar_detection");
    entry = chan_by_number(vendor, 36);
    if (entry && json_object_get_boolean(child(entry, "radar_detection")))
        fail("non-DFS channel 36 flagged as radar_detection");
}

/*
 * Drift guard against the real file. These are the lines that make the wiring
 * correct rather than merely present.
 */
static void test_wiring_present_in_source(void)
{
    static const char *paths[] = {
        "../src/apd/apd_backend_openwrt.c",
        "jmxd/src/apd/apd_backend_openwrt.c",
        "src/apd/apd_backend_openwrt.c",
        NULL
    };
    static char buf[1 << 21];
    FILE *fp = NULL;
    size_t n;
    int i;

    for (i = 0; paths[i]; i++)
        if ((fp = fopen(paths[i], "r")))
            break;
    if (!fp) {
        printf("  (skipped drift check: backend source not reachable)\n");
        return;
    }
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);

    /* the parser must actually be reachable from the collector */
    assert(strstr(buf, "#include \"apd_vendor_chanlist.h\""));
    assert(strstr(buf, "apd_channel_catalog_vendor_fallback"));
    assert(strstr(buf, "apd_vendor_chanlist_parse("));
    /* source must be parameterised, and the vendor label must be used */
    assert(strstr(buf, "apd_channel_catalog_new_source(\"wlanconfig_list_chan\""));
    /*
     * The fallback has to be tried before the give-up catalogue is attached,
     * otherwise it can never run: the old code attached one unconditionally.
     *
     * Anchor on the `apd_channel_catalog_new(reason, ...)` call site rather than
     * the bare reason string. The comment above the fallback quotes
     * "wiphy_not_in_iw_phy_output" on purpose to explain the old behaviour, so a
     * literal search finds prose that sits *earlier* in the file than the code
     * and reports a false ordering violation. This fixture failed that way on
     * its first run.
     */
    {
        const char *fb = strstr(buf, "apd_channel_catalog_vendor_fallback(radio");
        const char *give_up = strstr(buf,
            "apd_channel_catalog_new(reason, observed_at)");

        assert(fb && give_up);
        if (fb > give_up)
            fail("fallback is attempted after the give-up catalogue is attached");
    }
    printf("  drift check: parser included, fallback wired ahead of the "
           "give-up path, vendor source label in use\n");
}

int main(void)
{
    test_source_is_not_a_lie();
    test_shape_matches_primary_path();
    test_widths_are_not_over_claimed();
    test_wiring_present_in_source();

    if (failures) {
        fprintf(stderr, "apd_channel_catalog_source_fixture: %d failure(s)\n",
                failures);
        return 1;
    }
    printf("apd_channel_catalog_source_fixture: all assertions passed\n");
    return 0;
}
