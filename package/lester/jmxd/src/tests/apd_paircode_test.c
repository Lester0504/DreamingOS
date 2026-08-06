// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Contract tests for the apd pairing code format.
 *
 * Build standalone:
 *   cc -DAPD_PAIRCODE_TEST_STANDALONE -I../apd -o t \
 *      apd_paircode_test.c ../apd/apd_paircode.c -lcrypto
 */
#include "apd_paircode.h"

#include <stdio.h>
#include <string.h>

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
        printf("FAIL %s: got %s want %s\n", what,
               got ? got : "(null)", want ? want : "(null)");
    }
}

static void fill_ap(struct apd_paircode_ap *ap)
{
    memset(ap, 0, sizeof(*ap));
    snprintf(ap->ap_id, sizeof(ap->ap_id),
             "d2315132-7131-5124-b77a-a567cedc175c");
    snprintf(ap->key_id, sizeof(ap->key_id),
             "sha256:3b440fd2b882d101aa11bb22cc33dd44ee55ff66"
             "0011223344556677889900aa");
    snprintf(ap->mac, sizeof(ap->mac), "AA:BB:CC:DD:EE:FF");
    snprintf(ap->model, sizeof(ap->model), "Xiaomi Router BE10000");
    snprintf(ap->board_name, sizeof(ap->board_name), "xiaomi,be10000");
    snprintf(ap->mgmt_ip, sizeof(ap->mgmt_ip), "192.168.31.31");
    ap->mgmt_port = 22;
}

static void test_ap_roundtrip(void)
{
    struct apd_paircode_ap in;
    struct apd_paircode_ap out;
    char code[APD_PAIRCODE_MAX];

    fill_ap(&in);
    check(apd_paircode_ap_encode(&in, code, sizeof(code)) == APD_PAIRCODE_OK,
          "ap encode succeeds");
    check(strncmp(code, "DWRTAP1.", 8) == 0, "ap code carries prefix");
    check(strchr(code, ' ') == NULL, "ap code has no spaces");

    check(apd_paircode_ap_decode(code, &out) == APD_PAIRCODE_OK,
          "ap decode succeeds");
    check_str(out.ap_id, in.ap_id, "ap_id round-trips");
    check_str(out.key_id, in.key_id, "key_id round-trips");
    check_str(out.mac, in.mac, "mac round-trips");
    check_str(out.model, in.model, "model round-trips");
    check_str(out.board_name, in.board_name, "board round-trips");
    check_str(out.mgmt_ip, in.mgmt_ip, "mgmt_ip round-trips");
    check(out.mgmt_port == in.mgmt_port, "mgmt_port round-trips");
}

/*
 * The handoff makes this a hard requirement: the AP-side code is pasted into
 * a browser and may land in clipboards and chat logs, so it must not carry
 * anything that by itself permits adoption.
 */
static void test_ap_code_carries_no_secret(void)
{
    struct apd_paircode_ap in;
    char code[APD_PAIRCODE_MAX];
    struct apd_paircode_controller decoded;

    fill_ap(&in);
    apd_paircode_ap_encode(&in, code, sizeof(code));

    /* An AP code must never satisfy the controller-bootstrap decoder, which
     * is the only path that yields a usable enrollment token. */
    check(apd_paircode_controller_decode(code, &decoded) ==
              APD_PAIRCODE_ERR_PREFIX,
          "ap code is not accepted as a controller bootstrap code");
    check(decoded.token[0] == '\0', "no token recovered from ap code");
}

static void test_controller_roundtrip(void)
{
    struct apd_paircode_controller in;
    struct apd_paircode_controller out;
    char code[APD_PAIRCODE_MAX];

    memset(&in, 0, sizeof(in));
    snprintf(in.controller_host, sizeof(in.controller_host), "192.168.30.1");
    in.controller_port = 8443;
    snprintf(in.controller_id, sizeof(in.controller_id),
             "d2315132-7131-5124-b77a-a567cedc175c");
    snprintf(in.token_id, sizeof(in.token_id),
             "11111111-2222-4333-8444-555555555555");
    snprintf(in.token, sizeof(in.token),
             "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_ABCDE");
    snprintf(in.site_id, sizeof(in.site_id), "default");

    check(apd_paircode_controller_encode(&in, code, sizeof(code)) ==
              APD_PAIRCODE_OK, "controller encode succeeds");
    check(strncmp(code, "DWRTCT1.", 8) == 0, "controller code carries prefix");
    check(apd_paircode_controller_decode(code, &out) == APD_PAIRCODE_OK,
          "controller decode succeeds");
    check_str(out.controller_host, in.controller_host, "host round-trips");
    check(out.controller_port == in.controller_port, "port round-trips");
    check_str(out.token, in.token, "token round-trips");
    check_str(out.token_id, in.token_id, "token_id round-trips");
    check_str(out.site_id, in.site_id, "site_id round-trips");

    /* Cross-decoding the other direction must fail too. */
    {
        struct apd_paircode_ap ap;

        check(apd_paircode_ap_decode(code, &ap) == APD_PAIRCODE_ERR_PREFIX,
              "controller code is not accepted as an ap code");
    }
}

/* A truncated paste must be caught by the checksum, not surface later as a
 * vague enrollment failure. */
static void test_truncation_detected(void)
{
    struct apd_paircode_ap in;
    struct apd_paircode_ap out;
    char code[APD_PAIRCODE_MAX];
    size_t len;
    size_t cut;
    int detected = 0;
    int total = 0;

    fill_ap(&in);
    apd_paircode_ap_encode(&in, code, sizeof(code));
    len = strlen(code);

    for (cut = 9; cut < len; cut++) {
        char damaged[APD_PAIRCODE_MAX];
        int rc;

        memcpy(damaged, code, cut);
        damaged[cut] = '\0';
        rc = apd_paircode_ap_decode(damaged, &out);
        total++;
        if (rc != APD_PAIRCODE_OK)
            detected++;
        else
            printf("FAIL truncation at %zu accepted\n", cut);
    }
    check(detected == total, "every truncation is rejected");

    /* single-character corruption in the body */
    {
        char damaged[APD_PAIRCODE_MAX];
        size_t i;
        int caught = 0;
        int tried = 0;

        for (i = 8; i < len - 8; i++) {
            snprintf(damaged, sizeof(damaged), "%s", code);
            damaged[i] = (damaged[i] == 'A') ? 'B' : 'A';
            tried++;
            if (apd_paircode_ap_decode(damaged, &out) != APD_PAIRCODE_OK)
                caught++;
        }
        check(caught == tried, "every single-char corruption is rejected");
    }
}

static void test_normalize(void)
{
    struct apd_paircode_ap in;
    struct apd_paircode_ap out;
    char code[APD_PAIRCODE_MAX];
    char pasted[APD_PAIRCODE_MAX + 32];

    fill_ap(&in);
    apd_paircode_ap_encode(&in, code, sizeof(code));

    /* what a terminal copy typically looks like */
    snprintf(pasted, sizeof(pasted), "  %s\r\n", code);
    apd_paircode_normalize(pasted);
    check_str(pasted, code, "normalize strips whitespace and newlines");

    /* lowercased by a helpful mail client */
    {
        size_t i;

        snprintf(pasted, sizeof(pasted), "%s", code);
        for (i = 0; pasted[i]; i++)
            if (pasted[i] >= 'A' && pasted[i] <= 'Z')
                pasted[i] = (char)(pasted[i] - 'A' + 'a');
        apd_paircode_normalize(pasted);
        check(apd_paircode_ap_decode(pasted, &out) == APD_PAIRCODE_OK,
              "normalize recovers a lowercased code");
    }
}

static void test_rejects_garbage(void)
{
    struct apd_paircode_ap out;

    check(apd_paircode_ap_decode("", &out) == APD_PAIRCODE_ERR_PREFIX,
          "empty string rejected");
    check(apd_paircode_ap_decode("hello", &out) == APD_PAIRCODE_ERR_PREFIX,
          "random text rejected");
    check(apd_paircode_ap_decode("DWRTAP1.", &out) != APD_PAIRCODE_OK,
          "prefix only rejected");
    check(apd_paircode_ap_decode("DWRTAP1.AAAA", &out) != APD_PAIRCODE_OK,
          "missing checksum rejected");
    check(apd_paircode_ap_decode("DWRTAP2.AAAA.BBBBBBB", &out) ==
              APD_PAIRCODE_ERR_PREFIX, "unknown prefix version rejected");
}

static void test_fingerprint(void)
{
    char out[32];

    apd_paircode_fingerprint_short(
        "sha256:3b440fd2b882d101aa11bb22cc33dd44", out, sizeof(out));
    check_str(out, "3B44-0FD2-B882-D101", "fingerprint groups hex digits");

    apd_paircode_fingerprint_short("", out, sizeof(out));
    check_str(out, "", "empty key_id yields empty fingerprint");

    /* must not overrun a short buffer */
    {
        char small[6];

        apd_paircode_fingerprint_short(
            "sha256:3b440fd2b882d101", small, sizeof(small));
        check(strlen(small) < sizeof(small), "short buffer stays terminated");
    }
}

static void test_optional_fields(void)
{
    struct apd_paircode_ap in;
    struct apd_paircode_ap out;
    char code[APD_PAIRCODE_MAX];

    /* Only ap_id present: still valid, absent fields decode empty. */
    memset(&in, 0, sizeof(in));
    snprintf(in.ap_id, sizeof(in.ap_id),
             "d2315132-7131-5124-b77a-a567cedc175c");
    check(apd_paircode_ap_encode(&in, code, sizeof(code)) == APD_PAIRCODE_OK,
          "minimal ap code encodes");
    check(apd_paircode_ap_decode(code, &out) == APD_PAIRCODE_OK,
          "minimal ap code decodes");
    check_str(out.ap_id, in.ap_id, "minimal ap_id round-trips");
    check(out.mgmt_ip[0] == '\0', "absent mgmt_ip decodes empty");
    check(out.mgmt_port == 0, "absent mgmt_port decodes zero");
}

/* The code has to survive being rendered as a QR, so it must stay inside the
 * QR alphanumeric charset: uppercase letters, digits, and '.'. */
static void test_charset_is_qr_safe(void)
{
    static const char allowed[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    struct apd_paircode_ap in;
    char code[APD_PAIRCODE_MAX];
    size_t i;
    int ok = 1;

    fill_ap(&in);
    apd_paircode_ap_encode(&in, code, sizeof(code));
    for (i = 0; code[i]; i++)
        if (!strchr(allowed, code[i]))
            ok = 0;
    check(ok, "ap code stays within the QR alphanumeric charset");
}

int main(void)
{
    test_ap_roundtrip();
    test_ap_code_carries_no_secret();
    test_controller_roundtrip();
    test_truncation_detected();
    test_normalize();
    test_rejects_garbage();
    test_fingerprint();
    test_optional_fields();
    test_charset_is_qr_safe();

    printf("%s: %d checks, %d failures\n",
           g_failures ? "FAILED" : "PASSED", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
