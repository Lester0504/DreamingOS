/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Contract fixture for the shared SafeOps snapshot codec
 * (safeops/config_snapshot_codec.h). Uses an in-memory STUB vault — no real
 * key file or sqlite handle — mirroring the safeops_rollback_fixture stubbing
 * style. Proves the create/restore round-trip, and every REFUSE path that
 * protects the live WAN config.
 *
 * Cases:
 *  (a) round-trip: a /etc/config/network with a PPPoE `option password
 *      'secret'` encodes to a body with NO plaintext 'secret' and a `@vault:`
 *      reference, decodes+reinjects byte-identical, sha256 matches.
 *  (b) tamper: flip a byte in the compressed body -> decode REFUSES (sha256
 *      mismatch), no plaintext emitted.
 *  (c) vault-miss: a `@vault:` ref the stub cannot resolve -> REFUSE, no write.
 *  (d) old raw (no magic) -> passthrough verbatim (DECODE_RAW).
 *  (e) stripped-but-not-reinjected (vault returns empty) -> REFUSE, never a
 *      silent blank password.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "safeops/config_snapshot_codec.h"

/* ---- in-memory stub vault ------------------------------------------------ */
#define STUB_MAX 32
struct stub_vault {
    char id[STUB_MAX][DWNETSNAP_SECRET_ID_MAX];
    unsigned char *val[STUB_MAX];
    size_t len[STUB_MAX];
    int n;
    int get_returns_empty; /* case (e): resolve to a 0-length secret */
    int get_forced_miss;   /* case (c): every resolve fails */
};

static int stub_put(void *ctx, const char *secret_id,
                    const unsigned char *plaintext, size_t len)
{
    struct stub_vault *v = ctx;
    int i;

    for (i = 0; i < v->n; i++)
        if (!strcmp(v->id[i], secret_id))
            break; /* overwrite */
    if (i == v->n) {
        if (v->n >= STUB_MAX)
            return -1;
        v->n++;
    }
    snprintf(v->id[i], sizeof(v->id[i]), "%s", secret_id);
    free(v->val[i]);
    v->val[i] = malloc(len ? len : 1);
    if (!v->val[i])
        return -1;
    memcpy(v->val[i], plaintext, len);
    v->len[i] = len;
    return 0;
}

static int stub_get(void *ctx, const char *secret_id,
                    unsigned char **out, size_t *out_len)
{
    struct stub_vault *v = ctx;
    int i;

    *out = NULL;
    *out_len = 0;
    if (v->get_forced_miss)
        return -1;
    for (i = 0; i < v->n; i++) {
        if (!strcmp(v->id[i], secret_id)) {
            size_t len = v->get_returns_empty ? 0 : v->len[i];
            unsigned char *buf = malloc(len ? len : 1);
            if (!buf)
                return -1;
            memcpy(buf, v->val[i], len);
            *out = buf;
            *out_len = len;
            return 0;
        }
    }
    return -1;
}

static void stub_free(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    (void)len;
    free(buf);
}

static void stub_del(void *ctx, const char *secret_id)
{
    struct stub_vault *v = ctx;
    int i;

    for (i = 0; i < v->n; i++) {
        if (!strcmp(v->id[i], secret_id)) {
            free(v->val[i]);
            v->val[i] = v->val[v->n - 1];
            v->len[i] = v->len[v->n - 1];
            memcpy(v->id[i], v->id[v->n - 1], sizeof(v->id[i]));
            v->n--;
            return;
        }
    }
}

static void stub_reset(struct stub_vault *v)
{
    int i;
    for (i = 0; i < v->n; i++)
        free(v->val[i]);
    memset(v, 0, sizeof(*v));
}

static struct dwnetsnap_vault mkvault(struct stub_vault *s)
{
    struct dwnetsnap_vault v;
    v.ctx = s;
    v.put = stub_put;
    v.get = stub_get;
    v.free_secret = stub_free;
    v.del = stub_del;
    return v;
}

/* A representative /etc/config/network: PPPoE WAN with a plaintext password,
 * plus a hybrid_line carrying a second password, plus non-secret sections. */
static const char SAMPLE[] =
    "config interface 'loopback'\n"
    "\toption device 'lo'\n"
    "\toption proto 'static'\n"
    "\toption ipaddr '127.0.0.1'\n"
    "\n"
    "config interface 'wan'\n"
    "\toption proto 'pppoe'\n"
    "\toption username 'user@isp'\n"
    "\toption password 'sup3r-Secret!'\n"
    "\toption ipv6 'auto'\n"
    "\n"
    "config interface 'hybrid_line'\n"
    "\toption proto 'pppoe'\n"
    "\toption username 'line2'\n"
    "\toption password 'second_PW_42'\n";

static const char *PLAINTEXT_SECRETS[] = { "sup3r-Secret!", "second_PW_42" };

static int contains(const unsigned char *hay, size_t hay_len, const char *needle)
{
    return dwnetsnap_memfind(hay, hay_len, needle, strlen(needle)) != NULL;
}

static void test_round_trip(void)
{
    struct stub_vault sv = {0};
    struct dwnetsnap_vault vault;
    unsigned char *snap = NULL, *back = NULL;
    size_t snap_len = 0, back_len = 0;
    const unsigned char *body;
    size_t body_off, body_len, i;
    int enc, dec;

    stub_reset(&sv);
    vault = mkvault(&sv);

    enc = dwnetsnap_encode((const unsigned char *)SAMPLE, strlen(SAMPLE),
                           "network.123.456.bak", &vault, &snap, &snap_len);
    assert(enc == DWNETSNAP_ENCODE_OK);
    assert(snap && snap_len > 0);
    assert(sv.n == 2); /* two passwords vaulted */

    /* new-format magic + header present */
    assert(snap_len > DWNETSNAP_MAGIC_LEN);
    assert(!memcmp(snap, DWNETSNAP_MAGIC, DWNETSNAP_MAGIC_LEN));
    assert(contains(snap, snap_len, "orig_sha256:"));
    assert(contains(snap, snap_len, "enc:zlib"));

    /* Neither plaintext secret may survive anywhere in the snapshot bytes
     * (header + compressed body). Decompress the body and re-check there too. */
    for (i = 0; i < sizeof(PLAINTEXT_SECRETS) / sizeof(PLAINTEXT_SECRETS[0]); i++)
        assert(!contains(snap, snap_len, PLAINTEXT_SECRETS[i]));

    /* Locate + inflate the body to assert the reference is what replaced it. */
    body = dwnetsnap_memfind(snap, snap_len, "\n\n", 2);
    assert(body);
    body = body + 2;
    body_off = (size_t)(body - snap);
    body_len = snap_len - body_off;
    {
        uLongf out = 65536;
        unsigned char inflated[65536];
        assert(uncompress(inflated, &out, body, (uLong)body_len) == Z_OK);
        assert(contains(inflated, out, DWNETSNAP_REF));
        for (i = 0; i < sizeof(PLAINTEXT_SECRETS) / sizeof(PLAINTEXT_SECRETS[0]); i++)
            assert(!contains(inflated, out, PLAINTEXT_SECRETS[i]));
        /* Non-secret content survives verbatim in the body. */
        assert(contains(inflated, out, "option username 'user@isp'"));
        assert(contains(inflated, out, "config interface 'loopback'"));
    }

    /* Decode + reinject: byte-identical to the original plaintext. */
    dec = dwnetsnap_decode(snap, snap_len, &vault, &back, &back_len, NULL, 0);
    assert(dec == DWNETSNAP_DECODE_OK);
    assert(back_len == strlen(SAMPLE));
    assert(!memcmp(back, SAMPLE, back_len));

    free(snap);
    free(back);
    stub_reset(&sv);
}

static void test_tamper(void)
{
    struct stub_vault sv = {0};
    struct dwnetsnap_vault vault;
    unsigned char *snap = NULL, *back = NULL;
    size_t snap_len = 0, back_len = 0;
    char err[128] = "";
    const unsigned char *body;
    size_t body_off;
    int dec;

    stub_reset(&sv);
    vault = mkvault(&sv);
    assert(dwnetsnap_encode((const unsigned char *)SAMPLE, strlen(SAMPLE),
                            "network.9.9.bak", &vault, &snap, &snap_len) ==
           DWNETSNAP_ENCODE_OK);

    /* Flip a byte inside the compressed body. */
    body = dwnetsnap_memfind(snap, snap_len, "\n\n", 2);
    assert(body);
    body_off = (size_t)(body + 2 - snap);
    assert(body_off < snap_len);
    snap[body_off] ^= 0x5a;

    dec = dwnetsnap_decode(snap, snap_len, &vault, &back, &back_len,
                           err, sizeof(err));
    assert(dec == DWNETSNAP_DECODE_REFUSE);
    assert(back == NULL && back_len == 0);
    /* A corrupt body either fails to inflate or fails the sha256 gate; either
     * way it is a refusal, never a plaintext. */
    assert(err[0] != '\0');

    free(snap);
    stub_reset(&sv);
}

static void test_vault_miss(void)
{
    struct stub_vault sv = {0};
    struct dwnetsnap_vault vault;
    unsigned char *snap = NULL, *back = NULL;
    size_t snap_len = 0, back_len = 0;
    char err[128] = "";
    int dec;

    stub_reset(&sv);
    vault = mkvault(&sv);
    assert(dwnetsnap_encode((const unsigned char *)SAMPLE, strlen(SAMPLE),
                            "network.7.7.bak", &vault, &snap, &snap_len) ==
           DWNETSNAP_ENCODE_OK);

    /* The vault can no longer resolve any reference (key lost / wrong vault). */
    sv.get_forced_miss = 1;
    dec = dwnetsnap_decode(snap, snap_len, &vault, &back, &back_len,
                           err, sizeof(err));
    assert(dec == DWNETSNAP_DECODE_REFUSE);
    assert(back == NULL);
    assert(!strcmp(err, "snapshot_vault_resolve_failed"));

    /* A NULL vault (no capability at all) also refuses a new-format snapshot. */
    dec = dwnetsnap_decode(snap, snap_len, NULL, &back, &back_len, err, sizeof(err));
    assert(dec == DWNETSNAP_DECODE_REFUSE);
    assert(back == NULL);

    free(snap);
    stub_reset(&sv);
}

static void test_old_raw_passthrough(void)
{
    unsigned char *back = NULL;
    size_t back_len = 0;
    int dec;

    /* A raw UCI file (no magic) must report RAW so the caller copies verbatim. */
    dec = dwnetsnap_decode((const unsigned char *)SAMPLE, strlen(SAMPLE),
                           NULL, &back, &back_len, NULL, 0);
    assert(dec == DWNETSNAP_DECODE_RAW);
    assert(back == NULL && back_len == 0);

    /* Even a short/empty buffer without magic is RAW, never a false new-format. */
    dec = dwnetsnap_decode((const unsigned char *)"x", 1, NULL,
                           &back, &back_len, NULL, 0);
    assert(dec == DWNETSNAP_DECODE_RAW);
}

static void test_stripped_not_reinjected(void)
{
    struct stub_vault sv = {0};
    struct dwnetsnap_vault vault;
    unsigned char *snap = NULL, *back = NULL;
    size_t snap_len = 0, back_len = 0;
    char err[128] = "";
    int dec;

    stub_reset(&sv);
    vault = mkvault(&sv);
    assert(dwnetsnap_encode((const unsigned char *)SAMPLE, strlen(SAMPLE),
                            "network.5.5.bak", &vault, &snap, &snap_len) ==
           DWNETSNAP_ENCODE_OK);

    /* The reference exists but resolves to an EMPTY secret. Writing that would
     * blank the live PPPoE password, so decode MUST refuse — never silently
     * emit a config with an empty password. */
    sv.get_returns_empty = 1;
    dec = dwnetsnap_decode(snap, snap_len, &vault, &back, &back_len,
                           err, sizeof(err));
    assert(dec == DWNETSNAP_DECODE_REFUSE);
    assert(back == NULL && back_len == 0);
    assert(!strcmp(err, "snapshot_vault_resolve_failed"));

    free(snap);
    stub_reset(&sv);
}

static void test_no_secrets_falls_back(void)
{
    struct stub_vault sv = {0};
    struct dwnetsnap_vault vault;
    unsigned char *snap = NULL;
    size_t snap_len = 0;
    static const char plain[] =
        "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n";

    stub_reset(&sv);
    vault = mkvault(&sv);
    /* No secret option -> NO_SECRETS so the caller keeps the raw .bak path. */
    assert(dwnetsnap_encode((const unsigned char *)plain, strlen(plain),
                            "network.1.1.bak", &vault, &snap, &snap_len) ==
           DWNETSNAP_ENCODE_NO_SECRETS);
    assert(snap == NULL && snap_len == 0);
    assert(sv.n == 0);
    stub_reset(&sv);
}

int main(void)
{
    test_round_trip();
    test_tamper();
    test_vault_miss();
    test_old_raw_passthrough();
    test_stripped_not_reinjected();
    test_no_secrets_falls_back();
    puts("ok: SafeOps snapshot codec round-trip, tamper/vault-miss/empty refuse, raw passthrough");
    return 0;
}
