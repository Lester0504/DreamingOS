// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Contract tests for controller-side AP discovery.
 *
 * The parser reads unauthenticated broadcast traffic from anyone on the
 * segment, so most of what follows is about rejecting hostile input rather
 * than parsing happy paths.
 */
#include <stdio.h>
#include <string.h>

#include "ac_discovery.h"

static int g_failures;
static int g_checks;

static void check(int condition, const char *what)
{
    g_checks++;
    if (!condition) {
        g_failures++;
        printf("FAIL %s\n", what);
    }
}

static void check_str(const char *got, const char *want, const char *what)
{
    g_checks++;
    if (!got || !want || strcmp(got, want) != 0) {
        g_failures++;
        printf("FAIL %s: got '%s' want '%s'\n", what, got ? got : "(null)",
               want ? want : "(null)");
    }
}

#define GOOD_AP_ID "d2315132-7131-5124-b77a-a567cedc175c"

static void test_valid_beacon(void)
{
    struct ac_discovery_candidate c;
    const char *payload =
        "{\"magic\":\"DWRT-AP-BEACON/1\","
        "\"ap_id\":\"" GOOD_AP_ID "\","
        "\"key_id\":\"sha256:3b440fd2b882d101\","
        "\"mac\":\"AA:BB:CC:DD:EE:FF\","
        "\"model\":\"Xiaomi Router BE10000\","
        "\"board_name\":\"xiaomi,be10000\","
        "\"mgmt_ip\":\"192.168.31.31\",\"mgmt_port\":22}";

    check(ac_discovery_parse_beacon(payload, strlen(payload),
                                    "192.168.31.31", &c) == 0,
          "valid beacon parses");
    check_str(c.ap_id, GOOD_AP_ID, "ap_id parsed");
    check_str(c.model, "Xiaomi Router BE10000", "model parsed");
    check_str(c.mac, "AA:BB:CC:DD:EE:FF", "mac parsed");
    check(c.mgmt_port == 22, "port parsed");
    check(c.adopted_elsewhere == 0, "not adopted elsewhere by default");
}

/*
 * The observed source address is evidence; a claimed address is a assertion.
 * They must not be conflated, or a beacon could point the operator at an
 * address the sender does not own.
 */
static void test_observed_ip_wins(void)
{
    struct ac_discovery_candidate c;
    const char *lying =
        "{\"magic\":\"DWRT-AP-BEACON/1\","
        "\"ap_id\":\"" GOOD_AP_ID "\","
        "\"mgmt_ip\":\"10.0.0.1\"}";

    check(ac_discovery_parse_beacon(lying, strlen(lying),
                                    "192.168.31.31", &c) == 0,
          "beacon with mismatched address still parses");
    check_str(c.mgmt_ip, "192.168.31.31",
              "observed address is recorded as mgmt_ip");
    check_str(c.claimed_ip, "10.0.0.1",
              "claimed address is kept separately, not merged");
}

static void test_rejects_malformed(void)
{
    struct ac_discovery_candidate c;
    const char *cases[] = {
        "",
        "not json",
        "[]",
        "{}",
        "{\"magic\":\"WRONG\",\"ap_id\":\"" GOOD_AP_ID "\"}",
        "{\"magic\":\"DWRT-AP-BEACON/1\"}",                     /* no ap_id */
        "{\"magic\":\"DWRT-AP-BEACON/1\",\"ap_id\":\"short\"}",
        "{\"magic\":\"DWRT-AP-BEACON/1\",\"ap_id\":123}",
        "{\"magic\":123,\"ap_id\":\"" GOOD_AP_ID "\"}",
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char label[128];

        snprintf(label, sizeof(label), "malformed beacon rejected: %.40s",
                 cases[i]);
        check(ac_discovery_parse_beacon(cases[i], strlen(cases[i]),
                                        "192.168.31.31", &c) != 0, label);
    }
}

/* A beacon must not be able to smuggle control characters into logs or the
 * admin UI through the descriptive fields. */
static void test_rejects_control_characters(void)
{
    struct ac_discovery_candidate c;
    const char *payload =
        "{\"magic\":\"DWRT-AP-BEACON/1\","
        "\"ap_id\":\"" GOOD_AP_ID "\","
        "\"model\":\"evil\\u001b[2Jclear\"}";

    if (ac_discovery_parse_beacon(payload, strlen(payload),
                                  "192.168.31.31", &c) == 0) {
        size_t i;
        int clean = 1;

        for (i = 0; c.model[i]; i++)
            if ((unsigned char)c.model[i] < 0x20)
                clean = 0;
        check(clean, "control characters never reach the model field");
    } else {
        check(1, "beacon with control characters rejected outright");
    }
}

static void test_oversized_rejected(void)
{
    struct ac_discovery_candidate c;
    char big[AC_DISCOVERY_PAYLOAD_MAX + 64];

    memset(big, 'A', sizeof(big));
    big[sizeof(big) - 1] = '\0';
    check(ac_discovery_parse_beacon(big, strlen(big), "192.168.31.31", &c) != 0,
          "oversized payload rejected");
}

static void test_adopted_elsewhere(void)
{
    struct ac_discovery_candidate c;
    const char *payload =
        "{\"magic\":\"DWRT-AP-BEACON/1\","
        "\"ap_id\":\"" GOOD_AP_ID "\","
        "\"adopted_controller_id\":\"11111111-2222-4333-8444-555555555555\"}";

    check(ac_discovery_parse_beacon(payload, strlen(payload),
                                    "192.168.31.31", &c) == 0,
          "beacon reporting another controller parses");
    check(c.adopted_elsewhere == 1, "adopted_elsewhere flagged");
    check_str(c.adopted_controller_id, "11111111-2222-4333-8444-555555555555",
              "other controller id retained for operator warning");
}

int main(void)
{
    test_valid_beacon();
    test_observed_ip_wins();
    test_rejects_malformed();
    test_rejects_control_characters();
    test_oversized_rejected();
    test_adopted_elsewhere();

    printf("%s: %d checks, %d failures\n",
           g_failures ? "FAILED" : "PASSED", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
