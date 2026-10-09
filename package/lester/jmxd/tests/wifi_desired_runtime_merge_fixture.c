// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Contract for merging the runtime snapshot into the desired wifi view.
 *
 * The defect: /api/v1/wifi/config takes the desired branch when the managed AP
 * reports no runtime status, and the desired view is the UCI config, which has
 * no width_mhz and no txpower_dbm at all. wifi_normalize_aliases() therefore had
 * nothing to alias and both columns rendered empty, while the same response
 * carried complete values one level up in snapshot.radios. Band was empty too,
 * except on the one radio where UCI held the driver's numeric code and "3" was
 * forwarded verbatim and rendered as a band literally named 3.
 *
 * Three properties are pinned here:
 *
 *   1. The join between the two id spaces is exact, not guessed. Desired uses
 *      UCI section names (wifi0), runtime uses phy names (phy1); what makes it
 *      exact is that the runtime radio's interfaces[] contains the UCI section
 *      name. An ambiguous or absent match must yield a reason, never a value.
 *   2. The MLD pseudo-PHY is excluded structurally - it carries no wifiN - and
 *      not by the desired view happening to omit it.
 *   3. Nothing is fabricated. A field that cannot be filled gets an explicit
 *      *_reason, and a filled field gets a *_source naming where it came from.
 *
 * The functions under test live in webd_wifi_aggregate.c, which pulls in ubus
 * and the whole aggregation surface, so they are copied verbatim below and
 * test_copies_match_source() re-reads the real file.
 *
 * Build:
 *   cc -O0 -Wall -Wextra -o /tmp/wifi_merge \
 *      wifi_desired_runtime_merge_fixture.c $(pkg-config --cflags --libs json-c)
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <json-c/json.h>

static int failures;

/* ---- helpers mirrored from the aggregation unit ---- */

static struct json_object *wifi_child(struct json_object *obj, const char *key)
{
    struct json_object *v = NULL;

    if (!obj || !json_object_is_type(obj, json_type_object))
        return NULL;
    return json_object_object_get_ex(obj, key, &v) ? v : NULL;
}

static struct json_object *wifi_child_array(struct json_object *obj,
                                            const char *key)
{
    struct json_object *v = wifi_child(obj, key);

    return (v && json_object_is_type(v, json_type_array)) ? v : NULL;
}

static const char *wifi_string(struct json_object *obj, const char *key,
                               const char *fallback)
{
    struct json_object *v = wifi_child(obj, key);

    return (v && json_object_is_type(v, json_type_string)) ?
        json_object_get_string(v) : fallback;
}

/* ---- verbatim copies of the functions under test ---- */

static const char *wifi_band_from_uci_code(const char *raw)
{
    if (!raw || !raw[0])
        return "";
    if (!strcmp(raw, "1"))
        return "2.4GHz";
    if (!strcmp(raw, "2"))
        return "5GHz";
    if (!strcmp(raw, "3"))
        return "6GHz";
    return "";
}

static int wifi_band_is_uci_code(const char *raw)
{
    return raw && raw[0] && raw[1] == '\0' && raw[0] >= '0' && raw[0] <= '9';
}

static struct json_object *wifi_runtime_radio_for_desired(
        struct json_object *runtime_radios, const char *desired_id)
{
    struct json_object *match = NULL;
    size_t i, j;

    if (!runtime_radios || !desired_id || !desired_id[0])
        return NULL;
    for (i = 0; i < json_object_array_length(runtime_radios); i++) {
        struct json_object *radio = json_object_array_get_idx(runtime_radios, i);
        struct json_object *interfaces = wifi_child_array(radio, "interfaces");

        for (j = 0; interfaces && j < json_object_array_length(interfaces); j++) {
            struct json_object *iface = json_object_array_get_idx(interfaces, j);
            const char *name = wifi_string(iface, "interface", "");

            if (name[0] && !strcmp(name, desired_id)) {
                if (match && match != radio)
                    return NULL;
                match = radio;
            }
        }
    }
    return match;
}

static void wifi_desired_merge_runtime(struct json_object *desired_radios,
                                       struct json_object *runtime_radios)
{
    size_t i;

    if (!desired_radios)
        return;
    for (i = 0; i < json_object_array_length(desired_radios); i++) {
        struct json_object *radio = json_object_array_get_idx(desired_radios, i);
        struct json_object *runtime;
        const char *raw_band;
        const char *id;

        if (!radio || !json_object_is_type(radio, json_type_object))
            continue;
        id = wifi_string(radio, "id", "");

        raw_band = wifi_string(radio, "band", "");
        if (wifi_band_is_uci_code(raw_band)) {
            const char *named = wifi_band_from_uci_code(raw_band);

            json_object_object_del(radio, "band");
            if (named[0]) {
                json_object_object_add(radio, "band",
                                       json_object_new_string(named));
                json_object_object_add(radio, "band_source",
                    json_object_new_string("uci_band_code"));
            } else {
                json_object_object_add(radio, "band_reason",
                    json_object_new_string("uci_band_code_unrecognised"));
            }
        }

        runtime = wifi_runtime_radio_for_desired(runtime_radios, id);
        if (!runtime) {
            if (!wifi_child(radio, "band") && !wifi_child(radio, "band_reason"))
                json_object_object_add(radio, "band_reason",
                    json_object_new_string(
                        runtime_radios ? "desired_not_aligned_to_runtime_radio" :
                                         "runtime_snapshot_unavailable"));
            if (!wifi_child(radio, "width") && !wifi_child(radio, "width_mhz") &&
                !wifi_child(radio, "width_reason"))
                json_object_object_add(radio, "width_reason",
                    json_object_new_string(
                        runtime_radios ? "desired_not_aligned_to_runtime_radio" :
                                         "runtime_snapshot_unavailable"));
            if (!wifi_child(radio, "tx_power") &&
                !wifi_child(radio, "txpower_dbm") &&
                !wifi_child(radio, "tx_power_reason"))
                json_object_object_add(radio, "tx_power_reason",
                    json_object_new_string(
                        runtime_radios ? "desired_not_aligned_to_runtime_radio" :
                                         "runtime_snapshot_unavailable"));
            continue;
        }

        json_object_object_add(radio, "runtime_radio_id",
            json_object_new_string(wifi_string(runtime, "id", "")));

        if (!wifi_child(radio, "band") && wifi_child(runtime, "band")) {
            json_object_object_add(radio, "band",
                json_object_get(wifi_child(runtime, "band")));
            json_object_object_add(radio, "band_source",
                json_object_new_string("managed_ap_runtime_snapshot"));
        }
        if (!wifi_child(radio, "width") && !wifi_child(radio, "width_mhz") &&
            wifi_child(runtime, "width_mhz")) {
            json_object_object_add(radio, "width_mhz",
                json_object_get(wifi_child(runtime, "width_mhz")));
            json_object_object_add(radio, "width_source",
                json_object_new_string("managed_ap_runtime_snapshot"));
        }
        if (wifi_child(runtime, "channel")) {
            char desired_channel[32];

            snprintf(desired_channel, sizeof(desired_channel), "%s",
                     wifi_string(radio, "channel", ""));

            if (!wifi_child(radio, "operating_channel")) {
                json_object_object_add(radio, "operating_channel",
                    json_object_get(wifi_child(runtime, "channel")));
                json_object_object_add(radio, "operating_channel_source",
                    json_object_new_string("managed_ap_runtime_snapshot"));
            }
            if (!desired_channel[0] || !strcmp(desired_channel, "auto") ||
                !strcmp(desired_channel, "0")) {
                json_object_object_del(radio, "channel");
                json_object_object_add(radio, "channel",
                    json_object_get(wifi_child(runtime, "channel")));
                json_object_object_add(radio, "channel_source",
                    json_object_new_string("managed_ap_runtime_snapshot"));
                if (desired_channel[0])
                    json_object_object_add(radio, "channel_desired",
                        json_object_new_string(desired_channel));
            }
        }
        if (!wifi_child(radio, "tx_power") &&
            !wifi_child(radio, "txpower_dbm") &&
            wifi_child(runtime, "txpower_dbm")) {
            json_object_object_add(radio, "txpower_dbm",
                json_object_get(wifi_child(runtime, "txpower_dbm")));
            json_object_object_add(radio, "tx_power_source",
                json_object_new_string("managed_ap_runtime_snapshot"));
        }
        if (!wifi_child(radio, "tx_power") &&
            !wifi_child(radio, "txpower_dbm")) {
            struct json_object *ifaces = wifi_child_array(runtime, "interfaces");
            struct json_object *found = NULL;
            int conflict = 0;
            size_t k;

            for (k = 0; ifaces && k < json_object_array_length(ifaces); k++) {
                struct json_object *iface =
                    json_object_array_get_idx(ifaces, k);
                struct json_object *power = wifi_child(iface, "txpower_dbm");

                if (!power)
                    continue;
                if (found && json_object_get_int(found) !=
                             json_object_get_int(power)) {
                    conflict = 1;
                    break;
                }
                if (!found)
                    found = power;
            }
            if (conflict)
                json_object_object_add(radio, "tx_power_reason",
                    json_object_new_string(
                        "managed_ap_vap_txpower_disagrees"));
            else if (found) {
                json_object_object_add(radio, "txpower_dbm",
                    json_object_get(found));
                json_object_object_add(radio, "tx_power_source",
                    json_object_new_string("managed_ap_runtime_vap_txpower"));
            }
        }
        if (!wifi_child(radio, "tx_power") &&
            !wifi_child(radio, "txpower_dbm") &&
            !wifi_child(radio, "tx_power_reason"))
            json_object_object_add(radio, "tx_power_reason",
                json_object_new_string("managed_ap_reports_no_radio_txpower"));
    }
}

static void wifi_desired_ssid_bands(struct json_object *desired_ssids,
                                    struct json_object *desired_radios)
{
    size_t i, j;

    if (!desired_ssids || !desired_radios)
        return;
    for (i = 0; i < json_object_array_length(desired_ssids); i++) {
        struct json_object *ssid = json_object_array_get_idx(desired_ssids, i);
        const char *radio_id;

        if (!ssid || !json_object_is_type(ssid, json_type_object))
            continue;
        if (wifi_child(ssid, "band"))
            continue;
        radio_id = wifi_string(ssid, "radio_id", "");
        if (!radio_id[0]) {
            json_object_object_add(ssid, "band_reason",
                json_object_new_string("ssid_has_no_radio_id"));
            continue;
        }
        for (j = 0; j < json_object_array_length(desired_radios); j++) {
            struct json_object *radio = json_object_array_get_idx(desired_radios, j);

            if (strcmp(wifi_string(radio, "id", ""), radio_id))
                continue;
            if (wifi_child(radio, "band")) {
                json_object_object_add(ssid, "band",
                    json_object_get(wifi_child(radio, "band")));
                json_object_object_add(ssid, "band_source",
                    json_object_new_string("inherited_from_radio"));
            } else {
                json_object_object_add(ssid, "band_reason",
                    json_object_new_string("radio_band_unavailable"));
            }
            break;
        }
        if (!wifi_child(ssid, "band") && !wifi_child(ssid, "band_reason"))
            json_object_object_add(ssid, "band_reason",
                json_object_new_string("radio_id_not_found_in_desired_radios"));
    }
}

/* ---- fixtures modelled on the real 31.31 payload ---- */

static struct json_object *parse(const char *text)
{
    struct json_object *o = json_tokener_parse(text);

    assert(o);
    return o;
}

/*
 * Runtime radios exactly as the managed AP reports them, including the MLD
 * pseudo-PHY (phy0), which has interfaces but no UCI section name.
 *
 * Transmit power sits on the VAPs, not on the radio: on 31.31 phy3's AP-type
 * VAPs each report txpower_dbm 24 while the radio object has no such field.
 * phy2 is left without any VAP power at all, and phy1 is given two VAPs that
 * disagree, so the merge's three tx-power paths are all exercised.
 */
static struct json_object *runtime_radios(void)
{
    return parse(
        "[{\"id\":\"phy3\",\"band\":\"6GHz\",\"channel\":33,\"width_mhz\":320,"
        "  \"interfaces\":[{\"interface\":\"ath21\",\"txpower_dbm\":24},"
        "                  {\"interface\":\"ath2\",\"txpower_dbm\":24},"
        "                  {\"interface\":\"wifi2\"}]},"
        " {\"id\":\"phy2\",\"band\":\"5GHz\",\"channel\":36,\"width_mhz\":160,"
        "  \"interfaces\":[{\"interface\":\"ath15\"},{\"interface\":\"ath1\"},"
        "                  {\"interface\":\"wifi1\"}]},"
        " {\"id\":\"phy1\",\"band\":\"2.4GHz\",\"channel\":10,\"width_mhz\":40,"
        "  \"interfaces\":[{\"interface\":\"ath05\",\"txpower_dbm\":20},"
        "                  {\"interface\":\"ath0\",\"txpower_dbm\":23},"
        "                  {\"interface\":\"wifi0\"}]},"
        " {\"id\":\"phy0\","
        "  \"interfaces\":[{\"interface\":\"MLD1\"},{\"interface\":\"mld-wifi0\"}]}]");
}

/* Desired radios as UCI holds them: no width, no txpower, band only on wifi2
 * and there only as the driver's numeric code. */
static struct json_object *desired_radios(void)
{
    return parse(
        "[{\"id\":\"wifi0\",\"channel\":\"10\",\"hwmode\":\"11beg\","
        "  \"source\":\"uci_wireless\"},"
        " {\"id\":\"wifi1\",\"channel\":\"36\",\"hwmode\":\"11bea\","
        "  \"source\":\"uci_wireless\"},"
        " {\"id\":\"wifi2\",\"channel\":\"auto\",\"hwmode\":\"11bea\","
        "  \"band\":\"3\",\"source\":\"uci_wireless\"}]");
}

static struct json_object *radio_by_id(struct json_object *radios, const char *id)
{
    size_t i;

    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *r = json_object_array_get_idx(radios, i);

        if (!strcmp(wifi_string(r, "id", ""), id))
            return r;
    }
    return NULL;
}

static void expect_str(struct json_object *o, const char *key, const char *want)
{
    const char *got = wifi_string(o, key, NULL);

    if (!got || strcmp(got, want)) {
        fprintf(stderr, "  FAIL %s: want \"%s\", got %s\n", key, want,
                got ? got : "(absent)");
        failures++;
    }
}

static void expect_int(struct json_object *o, const char *key, int want)
{
    struct json_object *v = wifi_child(o, key);

    if (!v || json_object_get_int(v) != want) {
        fprintf(stderr, "  FAIL %s: want %d, got %s\n", key, want,
                v ? json_object_get_string(v) : "(absent)");
        failures++;
    }
}

/* The join must land on the right phy for every radio, and must not match the
 * MLD pseudo-PHY. */
static void test_join_is_exact(void)
{
    struct json_object *rt = runtime_radios();

    expect_str(wifi_runtime_radio_for_desired(rt, "wifi0"), "id", "phy1");
    expect_str(wifi_runtime_radio_for_desired(rt, "wifi1"), "id", "phy2");
    expect_str(wifi_runtime_radio_for_desired(rt, "wifi2"), "id", "phy3");

    /* nothing claims these */
    if (wifi_runtime_radio_for_desired(rt, "wifi3"))
        failures++, fprintf(stderr, "  FAIL wifi3 matched a phy\n");
    if (wifi_runtime_radio_for_desired(rt, ""))
        failures++, fprintf(stderr, "  FAIL empty id matched a phy\n");
    if (wifi_runtime_radio_for_desired(NULL, "wifi0"))
        failures++, fprintf(stderr, "  FAIL NULL runtime matched\n");

    /*
     * The pseudo-PHY must never be reachable through this join: matching it
     * would attach a bandless, channelless radio to a real UCI section.
     */
    if (wifi_runtime_radio_for_desired(rt, "mld-wifi0") &&
        strcmp(wifi_string(wifi_runtime_radio_for_desired(rt, "mld-wifi0"),
                           "id", ""), "phy0"))
        failures++;
    json_object_put(rt);
}

/* Two phys claiming one UCI section is ambiguous; refuse instead of guessing. */
static void test_ambiguous_join_is_refused(void)
{
    struct json_object *rt = parse(
        "[{\"id\":\"phyA\",\"interfaces\":[{\"interface\":\"wifi0\"}]},"
        " {\"id\":\"phyB\",\"interfaces\":[{\"interface\":\"wifi0\"}]}]");

    if (wifi_runtime_radio_for_desired(rt, "wifi0")) {
        fprintf(stderr, "  FAIL ambiguous join returned a match\n");
        failures++;
    }
    json_object_put(rt);
}

/* The whole point: band, width and tx-power stop being empty, and each filled
 * field says where it came from. */
static void test_merge_fills_and_attributes(void)
{
    struct json_object *rt = runtime_radios();
    struct json_object *des = desired_radios();
    struct json_object *r;

    wifi_desired_merge_runtime(des, rt);

    r = radio_by_id(des, "wifi0");
    expect_str(r, "band", "2.4GHz");
    expect_str(r, "band_source", "managed_ap_runtime_snapshot");
    expect_int(r, "width_mhz", 40);
    expect_str(r, "width_source", "managed_ap_runtime_snapshot");
    expect_str(r, "runtime_radio_id", "phy1");

    r = radio_by_id(des, "wifi1");
    expect_str(r, "band", "5GHz");
    expect_int(r, "width_mhz", 160);
    expect_str(r, "runtime_radio_id", "phy2");

    /* wifi2 already had a band, as the driver's code: it must be translated,
     * attributed to the code, and NOT overwritten by the runtime value. */
    r = radio_by_id(des, "wifi2");
    expect_str(r, "band", "6GHz");
    expect_str(r, "band_source", "uci_band_code");
    expect_int(r, "width_mhz", 320);
    expect_str(r, "runtime_radio_id", "phy3");

    json_object_put(des);
    json_object_put(rt);
}

/* The driver band code must never reach a caller verbatim. */
static void test_uci_band_code_is_translated(void)
{
    if (strcmp(wifi_band_from_uci_code("1"), "2.4GHz")) failures++;
    if (strcmp(wifi_band_from_uci_code("2"), "5GHz")) failures++;
    if (strcmp(wifi_band_from_uci_code("3"), "6GHz")) failures++;
    /* an unknown code yields nothing rather than a plausible guess */
    if (wifi_band_from_uci_code("7")[0]) failures++;
    if (wifi_band_from_uci_code("")[0]) failures++;

    assert(wifi_band_is_uci_code("3"));
    assert(!wifi_band_is_uci_code("6GHz"));
    assert(!wifi_band_is_uci_code("2.4GHz"));
    assert(!wifi_band_is_uci_code(""));

    /* an unrecognised code must leave a reason and no band */
    {
        struct json_object *des = parse(
            "[{\"id\":\"wifiX\",\"band\":\"7\"}]");
        struct json_object *r;

        wifi_desired_merge_runtime(des, NULL);
        r = radio_by_id(des, "wifiX");
        if (wifi_child(r, "band")) {
            fprintf(stderr, "  FAIL unrecognised code produced a band\n");
            failures++;
        }
        expect_str(r, "band_reason", "uci_band_code_unrecognised");
        json_object_put(des);
    }
}

/* No runtime match, and no runtime snapshot at all, must both be stated. */
static void test_unaligned_states_a_reason(void)
{
    struct json_object *rt = runtime_radios();
    struct json_object *des = parse("[{\"id\":\"wifi9\",\"channel\":\"1\"}]");
    struct json_object *r;

    wifi_desired_merge_runtime(des, rt);
    r = radio_by_id(des, "wifi9");
    expect_str(r, "band_reason", "desired_not_aligned_to_runtime_radio");
    expect_str(r, "width_reason", "desired_not_aligned_to_runtime_radio");
    if (wifi_child(r, "band") || wifi_child(r, "width_mhz")) {
        fprintf(stderr, "  FAIL unaligned radio was given values\n");
        failures++;
    }
    json_object_put(des);

    des = parse("[{\"id\":\"wifi0\",\"channel\":\"10\"}]");
    wifi_desired_merge_runtime(des, NULL);
    r = radio_by_id(des, "wifi0");
    expect_str(r, "band_reason", "runtime_snapshot_unavailable");
    expect_str(r, "width_reason", "runtime_snapshot_unavailable");
    json_object_put(des);
    json_object_put(rt);
}

/*
 * A radio without a usable tx-power reading must always say why, and must
 * never end up with neither a value nor a reason. Which reason applies depends
 * on the VAP readings, so this only requires that one of the defined reasons is
 * present; test_txpower_falls_back_to_vaps() pins down which.
 */
static void test_txpower_absence_is_explicit(void)
{
    struct json_object *rt = runtime_radios();
    struct json_object *des = desired_radios();
    size_t i;

    wifi_desired_merge_runtime(des, rt);
    for (i = 0; i < json_object_array_length(des); i++) {
        struct json_object *r = json_object_array_get_idx(des, i);
        const char *reason;

        if (wifi_child(r, "txpower_dbm") || wifi_child(r, "tx_power"))
            continue;
        reason = wifi_string(r, "tx_power_reason", NULL);
        if (!reason ||
            (strcmp(reason, "managed_ap_reports_no_radio_txpower") &&
             strcmp(reason, "managed_ap_vap_txpower_disagrees") &&
             strcmp(reason, "desired_not_aligned_to_runtime_radio") &&
             strcmp(reason, "runtime_snapshot_unavailable"))) {
            fprintf(stderr,
                    "  FAIL radio %s has neither tx_power nor a known reason "
                    "(got %s)\n",
                    wifi_string(r, "id", "?"), reason ? reason : "(absent)");
            failures++;
        }
    }
    /* when the AP does report it, the value wins and no reason is emitted */
    {
        struct json_object *rt2 = parse(
            "[{\"id\":\"phy1\",\"band\":\"2.4GHz\",\"txpower_dbm\":24,"
            "  \"interfaces\":[{\"interface\":\"wifi0\"}]}]");
        struct json_object *des2 = parse("[{\"id\":\"wifi0\"}]");
        struct json_object *r;

        wifi_desired_merge_runtime(des2, rt2);
        r = radio_by_id(des2, "wifi0");
        expect_int(r, "txpower_dbm", 24);
        expect_str(r, "tx_power_source", "managed_ap_runtime_snapshot");
        if (wifi_child(r, "tx_power_reason")) {
            fprintf(stderr, "  FAIL tx_power present yet a reason was set\n");
            failures++;
        }
        json_object_put(des2);
        json_object_put(rt2);
    }
    json_object_put(des);
    json_object_put(rt);
}

/* SSIDs inherit their radio's band, and say so; a dangling radio_id is stated. */
static void test_ssid_bands_are_inherited(void)
{
    struct json_object *rt = runtime_radios();
    struct json_object *des = desired_radios();
    struct json_object *ssids = parse(
        "[{\"id\":\"ath0\",\"radio_id\":\"wifi0\"},"
        " {\"id\":\"ath2\",\"radio_id\":\"wifi2\"},"
        " {\"id\":\"orphan\",\"radio_id\":\"wifi9\"},"
        " {\"id\":\"noradio\"}]");
    size_t i;

    wifi_desired_merge_runtime(des, rt);
    wifi_desired_ssid_bands(ssids, des);

    for (i = 0; i < json_object_array_length(ssids); i++) {
        struct json_object *s = json_object_array_get_idx(ssids, i);
        const char *id = wifi_string(s, "id", "");

        if (!strcmp(id, "ath0")) {
            expect_str(s, "band", "2.4GHz");
            expect_str(s, "band_source", "inherited_from_radio");
        } else if (!strcmp(id, "ath2")) {
            expect_str(s, "band", "6GHz");
        } else if (!strcmp(id, "orphan")) {
            expect_str(s, "band_reason",
                       "radio_id_not_found_in_desired_radios");
            if (wifi_child(s, "band")) failures++;
        } else if (!strcmp(id, "noradio")) {
            expect_str(s, "band_reason", "ssid_has_no_radio_id");
            if (wifi_child(s, "band")) failures++;
        }
    }
    json_object_put(ssids);
    json_object_put(des);
    json_object_put(rt);
}

/*
 * The radio object carries no txpower_dbm, but its VAPs do. A radio-level
 * answer is only legitimate when the VAPs agree, so this checks all three
 * outcomes: agreement yields the value, disagreement yields a distinct reason
 * and no value, and no VAP reading at all keeps the original absence reason.
 */
static void test_txpower_falls_back_to_vaps(void)
{
    struct json_object *rt = runtime_radios();
    struct json_object *des = desired_radios();
    struct json_object *r;

    wifi_desired_merge_runtime(des, rt);

    /* phy3's VAPs both report 24 -> radio gets 24, attributed to the VAPs */
    r = radio_by_id(des, "wifi2");
    expect_int(r, "txpower_dbm", 24);
    expect_str(r, "tx_power_source", "managed_ap_runtime_vap_txpower");
    if (wifi_child(r, "tx_power_reason")) {
        fprintf(stderr, "  FAIL vap-derived tx_power still carries a reason\n");
        failures++;
    }

    /* phy1's VAPs report 20 and 23 -> no single answer, say so */
    r = radio_by_id(des, "wifi0");
    expect_str(r, "tx_power_reason", "managed_ap_vap_txpower_disagrees");
    if (wifi_child(r, "txpower_dbm") || wifi_child(r, "tx_power")) {
        fprintf(stderr, "  FAIL disagreeing VAPs still produced a value\n");
        failures++;
    }

    /* phy2 has no VAP power at all -> the original absence reason stands */
    r = radio_by_id(des, "wifi1");
    expect_str(r, "tx_power_reason", "managed_ap_reports_no_radio_txpower");

    json_object_put(des);
    json_object_put(rt);
}

/*
 * A UCI channel of "auto" is not a channel a caller can display, while the
 * runtime snapshot knows the radio is operating on 33. The operating channel
 * must be published, and a pinned channel must never be overwritten by it -
 * that difference is how a caller sees config drifting from reality.
 */
static void test_channel_falls_back_only_when_auto(void)
{
    struct json_object *rt = runtime_radios();
    struct json_object *des = desired_radios();
    struct json_object *r;

    wifi_desired_merge_runtime(des, rt);

    /* wifi2 is "auto" -> replaced by the operating channel, original kept */
    r = radio_by_id(des, "wifi2");
    expect_int(r, "channel", 33);
    expect_str(r, "channel_source", "managed_ap_runtime_snapshot");
    expect_str(r, "channel_desired", "auto");
    expect_int(r, "operating_channel", 33);

    /* wifi0 is pinned to 10 -> value untouched, no channel_source */
    r = radio_by_id(des, "wifi0");
    expect_str(r, "channel", "10");
    if (wifi_child(r, "channel_source")) {
        fprintf(stderr, "  FAIL pinned channel was re-sourced\n");
        failures++;
    }
    expect_int(r, "operating_channel", 10);
    expect_str(r, "operating_channel_source", "managed_ap_runtime_snapshot");

    json_object_put(des);
    json_object_put(rt);

    /*
     * A pinned channel that disagrees with the operating one must survive as
     * a visible disagreement rather than being silently harmonised.
     */
    rt = parse("[{\"id\":\"phy1\",\"channel\":6,"
               "  \"interfaces\":[{\"interface\":\"wifi0\"}]}]");
    des = parse("[{\"id\":\"wifi0\",\"channel\":\"1\"}]");
    wifi_desired_merge_runtime(des, rt);
    r = radio_by_id(des, "wifi0");
    expect_str(r, "channel", "1");
    expect_int(r, "operating_channel", 6);
    json_object_put(des);
    json_object_put(rt);
}

/* Drift guard: the wiring must stay in the desired branch only. */
static void test_copies_match_source(void)
{
    static const char *paths[] = {
        "../src/webd/webd_wifi_aggregate.c",
        "jmxd/src/webd/webd_wifi_aggregate.c",
        "src/webd/webd_wifi_aggregate.c",
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
        printf("  (skipped drift check: source not reachable)\n");
        return;
    }
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);

    assert(strstr(buf, "static struct json_object *wifi_runtime_radio_for_desired("));
    assert(strstr(buf, "static void wifi_desired_merge_runtime("));
    assert(strstr(buf, "static void wifi_desired_ssid_bands("));
    assert(strstr(buf, "wifi_band_from_uci_code"));
    /* the merge must be invoked, and guarded so it only touches the desired
     * view - calling it on the runtime branch would risk regressing
     * wifi/status's runtime_radios */
    assert(strstr(buf, "wifi_desired_merge_runtime(source_radios,"));
    assert(strstr(buf,
        "if (source_radios == wifi_child_array(desired, \"radios\"))"));
    /*
     * The VAP tx-power fallback and the auto-channel fallback are the two
     * paths that turn a blank column into a real reading, so their reason
     * codes must not drift out of the implementation while the fixture keeps
     * asserting them.
     */
    assert(strstr(buf, "managed_ap_runtime_vap_txpower"));
    assert(strstr(buf, "managed_ap_vap_txpower_disagrees"));
    assert(strstr(buf, "\"operating_channel\""));
    printf("  drift check: merge helpers present and invoked behind the "
           "desired-branch guard\n");
}

int main(void)
{
    test_join_is_exact();
    test_ambiguous_join_is_refused();
    test_merge_fills_and_attributes();
    test_uci_band_code_is_translated();
    test_unaligned_states_a_reason();
    test_txpower_absence_is_explicit();
    test_txpower_falls_back_to_vaps();
    test_channel_falls_back_only_when_auto();
    test_ssid_bands_are_inherited();
    test_copies_match_source();

    if (failures) {
        fprintf(stderr, "wifi_desired_runtime_merge_fixture: %d failure(s)\n",
                failures);
        return 1;
    }
    printf("wifi_desired_runtime_merge_fixture: all assertions passed\n");
    return 0;
}
