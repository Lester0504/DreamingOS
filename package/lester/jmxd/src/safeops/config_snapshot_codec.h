/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DREAMINGWRT_SAFEOPS_CONFIG_SNAPSHOT_CODEC_H
#define DREAMINGWRT_SAFEOPS_CONFIG_SNAPSHOT_CODEC_H

/*
 * SafeOps config-apply rollback snapshot codec (handoff §12 item 3, HARD half).
 *
 * ONE shared implementation, #included verbatim by BOTH the webd apply path
 * (webd/jmx_app_api.c) and the UNATTENDED auto-rollback writer in init
 * (init/dreamingwrt_init.c). Everything here is `static inline`, so the two
 * translation units link their own copy of BYTE-IDENTICAL logic — there is no
 * second, drifting restore path. Do NOT fork this file.
 *
 * What it does: a rollback snapshot of /etc/config/network is stored
 * secret-isolated (PPPoE `option password` and friends moved into the
 * AES-256-GCM vault, replaced inline by an `@vault:<secret_id>` reference),
 * zlib-compressed, and self-describing. On restore the body is decompressed,
 * every `@vault:` reference is resolved back to plaintext, and the
 * reconstruction is checked against the sha256 of the ORIGINAL plaintext that
 * was captured at create time.
 *
 * ===================== THE #1 SAFETY LAW =====================
 * Restore copies the snapshot back onto the LIVE /etc/config/network, and init
 * does it with no operator present. A wrong reconstruction (bad decompress /
 * bad vault resolve / a stripped-but-not-reinjected password) would BLANK the
 * live PPPoE password and drop the WAN. Therefore:
 *
 *   - dwnetsnap_decode() REFUSES on ANY failure — decompress error, a
 *     `@vault:` reference the vault cannot resolve, an empty resolved secret,
 *     a length mismatch, or a sha256 mismatch. On refusal it frees/wipes any
 *     partial buffer and returns DWNETSNAP_DECODE_REFUSE. Callers MUST NOT
 *     write /etc/config/network on refusal.
 *   - A snapshot with NO magic header is old raw `.bak`: restored VERBATIM
 *     (today's behaviour, unchanged) so in-flight snapshots still work.
 *   - Create (dwnetsnap_encode) falls back to the raw `.bak` whenever the
 *     vault is unavailable, no secret is found, or ANY step fails — it never
 *     writes a new-format snapshot it could not itself restore.
 *
 * The vault is injected as a small function-pointer interface so this header
 * has no link dependency on ac_secrets (the callers wire ac_secrets in; the
 * contract test wires an in-memory stub).
 */

#include <ctype.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <zlib.h>

/* --------------------------------------------------------------------------
 * Wire format constants and shared operational constants.
 * ------------------------------------------------------------------------ */

/* First bytes of a new-format snapshot. The trailing '\n' is part of the
 * magic so a raw UCI file (which starts with "config ...") can never collide. */
#define DWNETSNAP_MAGIC "DWNETSNAPv1\n"
#define DWNETSNAP_MAGIC_LEN (sizeof(DWNETSNAP_MAGIC) - 1)

/* Vault key + secret-id scheme + the create-time format enable sentinel.
 * Shared so webd and init cannot disagree on where the vault lives. */
#define DWNETSNAP_VAULT_KEY_PATH "/etc/dreamingwrt/netconfig-snapshot.key"
#define DWNETSNAP_ENABLE_SENTINEL "/etc/dreamingwrt/safeops-cas-snapshots.enabled"
#define DWNETSNAP_SECRET_ID_PREFIX "netcfg-snap:"
#define DWNETSNAP_SECRET_VERSION 1U

/* Hard cap on any single config we will read/reconstruct. /etc/config/network
 * is a few KiB; this is only a sanity bound against a corrupt header. */
#define DWNETSNAP_MAX_BYTES (4U * 1024U * 1024U)

/* The `@vault:` reference marker inserted in place of a stripped secret. */
#define DWNETSNAP_REF "@vault:"
#define DWNETSNAP_REF_LEN (sizeof(DWNETSNAP_REF) - 1)

/* Kept == ac_secrets' AC_SECRET_ID_MAX so a generated id always fits the vault
 * without coupling this header to <sqlite3.h> (needed for the stub test). */
#define DWNETSNAP_SECRET_ID_MAX 128U

/*
 * This header is #included by three TUs with different feature-test macros
 * (webd defines _GNU_SOURCE, init and the strict-POSIX contract test do not),
 * so it must not touch _GNU_SOURCE-gated libc (memmem) or rely on <strings.h>.
 * These tiny local helpers keep every build identical and warning-clean.
 */

/* Locate needle in hay; NULL if absent. Local, POSIX-clean memmem. */
static inline const unsigned char *dwnetsnap_memfind(const unsigned char *hay,
                                                     size_t hay_len,
                                                     const void *needle,
                                                     size_t needle_len)
{
    const unsigned char *n = (const unsigned char *)needle;

    if (needle_len == 0)
        return hay;
    if (needle_len > hay_len)
        return NULL;
    for (; hay_len >= needle_len; hay++, hay_len--) {
        if (hay[0] == n[0] && memcmp(hay, n, needle_len) == 0)
            return hay;
    }
    return NULL;
}

static inline unsigned char dwnetsnap_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

/* ASCII case-insensitive equality of (a,alen) against C-string b. */
static inline int dwnetsnap_ci_equal_n(const char *a, size_t alen,
                                       const char *b)
{
    size_t i;

    if (strlen(b) != alen)
        return 0;
    for (i = 0; i < alen; i++)
        if (dwnetsnap_lower((unsigned char)a[i]) !=
            dwnetsnap_lower((unsigned char)b[i]))
            return 0;
    return 1;
}

/* ASCII case-insensitive equality of two C-strings. */
static inline int dwnetsnap_ci_streq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (dwnetsnap_lower((unsigned char)*a) !=
            dwnetsnap_lower((unsigned char)*b))
            return 0;
    return *a == *b;
}

enum dwnetsnap_encode_result {
    DWNETSNAP_ENCODE_OK = 0,       /* new-format bytes produced in *out */
    DWNETSNAP_ENCODE_NO_SECRETS = 1, /* nothing to isolate -> caller uses raw .bak */
    DWNETSNAP_ENCODE_ERROR = -1,   /* any failure -> caller MUST use raw .bak */
};

enum dwnetsnap_decode_result {
    DWNETSNAP_DECODE_OK = 0,       /* reconstructed + integrity-verified in *out */
    DWNETSNAP_DECODE_RAW = 1,      /* no magic: copy input verbatim (old .bak) */
    DWNETSNAP_DECODE_REFUSE = -1,  /* MUST NOT write /etc/config/network */
};

/*
 * Vault interface. put/del are only needed by create (encode); restore
 * (decode) needs only get. Any pointer may be NULL; a decode that needs a
 * missing capability REFUSES rather than guessing.
 *
 *  put:  store `len` plaintext bytes under secret_id. return 0 on success.
 *  get:  resolve secret_id -> freshly allocated *out (len in *out_len).
 *        return 0 on success. The buffer is released via `free_secret`.
 *  free_secret: release a buffer returned by get (may be NULL if get uses
 *        plain malloc — then the codec free()s directly).
 *  del:  best-effort delete of secret_id (cleanup). return value ignored.
 */
struct dwnetsnap_vault {
    void *ctx;
    int (*put)(void *ctx, const char *secret_id,
               const unsigned char *plaintext, size_t len);
    int (*get)(void *ctx, const char *secret_id,
               unsigned char **out, size_t *out_len);
    void (*free_secret)(void *ctx, unsigned char *buf, size_t len);
    void (*del)(void *ctx, const char *secret_id);
};

/* --------------------------------------------------------------------------
 * Small growable byte buffer (private).
 * ------------------------------------------------------------------------ */
struct dwnetsnap_buf {
    unsigned char *data;
    size_t len;
    size_t cap;
};

static inline void dwnetsnap_buf_init(struct dwnetsnap_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static inline void dwnetsnap_buf_free(struct dwnetsnap_buf *b)
{
    if (b->data) {
        /* May carry plaintext during reconstruction; wipe before release. */
        if (b->cap)
            memset(b->data, 0, b->cap);
        free(b->data);
    }
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static inline int dwnetsnap_buf_reserve(struct dwnetsnap_buf *b, size_t extra)
{
    size_t need;
    size_t ncap;
    unsigned char *nd;

    if (extra > DWNETSNAP_MAX_BYTES || b->len > DWNETSNAP_MAX_BYTES)
        return -1;
    need = b->len + extra;
    if (need < b->len) /* overflow */
        return -1;
    if (need <= b->cap)
        return 0;
    ncap = b->cap ? b->cap : 256;
    while (ncap < need) {
        size_t d = ncap * 2;
        if (d < ncap)
            return -1;
        ncap = d;
    }
    nd = (unsigned char *)malloc(ncap);
    if (!nd)
        return -1;
    if (b->data) {
        memcpy(nd, b->data, b->len);
        if (b->cap)
            memset(b->data, 0, b->cap);
        free(b->data);
    }
    b->data = nd;
    b->cap = ncap;
    return 0;
}

static inline int dwnetsnap_buf_append(struct dwnetsnap_buf *b,
                                       const void *src, size_t n)
{
    if (n == 0)
        return 0;
    if (dwnetsnap_buf_reserve(b, n) != 0)
        return -1;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

/* --------------------------------------------------------------------------
 * Helpers: sha256 hex, secret-key classification, id sanitisation.
 * ------------------------------------------------------------------------ */

/* Lowercase hex sha256 of buf -> out[65] (64 hex chars + NUL). 0 on success. */
static inline int dwnetsnap_sha256_hex(const unsigned char *buf, size_t len,
                                       char out[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    static const char hex[] = "0123456789abcdef";
    unsigned int i;

    if (!out)
        return -1;
    out[0] = '\0';
    if (EVP_Digest(buf ? (const void *)buf : (const void *)"", buf ? len : 0,
                   digest, &dlen, EVP_sha256(), NULL) != 1 || dlen != 32)
        return -1;
    for (i = 0; i < 32; i++) {
        out[i * 2] = hex[(digest[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[digest[i] & 0xf];
    }
    out[64] = '\0';
    return 0;
}

/* Is `key` (a UCI option name) one that carries a plaintext credential?
 * WHOLE-name, case-insensitive. Deliberately small: only keys that actually
 * appear in /etc/config/network as a raw secret. */
static inline int dwnetsnap_secret_option_key(const char *key, size_t len)
{
    static const char *const keys[] = {
        "password", "key", "psk", "wpa_psk"
    };
    size_t i;

    if (!key || len == 0)
        return 0;
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (dwnetsnap_ci_equal_n(key, len, keys[i]))
            return 1;
    return 0;
}

/* Characters allowed inside a `@vault:<secret_id>` reference. Excludes the
 * quote/space that terminate a UCI value, so reinjection reads a maximal run
 * and stops exactly at the closing quote. Matches ac_secrets' id charset use. */
static inline int dwnetsnap_id_char(unsigned char c)
{
    return isalnum(c) || c == '.' || c == '_' || c == '-' || c == ':';
}

/* Build "netcfg-snap:<sanitised-basename>:<seq>" into out. 0 on success. */
static inline int dwnetsnap_secret_id(const char *basename, unsigned seq,
                                      char *out, size_t out_len)
{
    size_t i;
    int n;

    if (!basename || !basename[0] || !out)
        return -1;
    n = snprintf(out, out_len, "%s%s:%u", DWNETSNAP_SECRET_ID_PREFIX,
                 basename, seq);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    /* The fixed prefix/colon/digits are all valid id chars; only the caller's
     * basename could carry a stray byte, so sanitising the whole string is
     * safe and simplest. */
    for (i = 0; out[i]; i++) {
        unsigned char c = (unsigned char)out[i];
        if (!dwnetsnap_id_char(c))
            out[i] = '_';
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * ENCODE — strip secrets into the vault, compress, emit new-format bytes.
 *
 * On DWNETSNAP_ENCODE_OK: out/out_len hold malloc'd new-format bytes.
 * On NO_SECRETS or ERROR: nothing is emitted and every secret this call put
 * into the vault is rolled back (best-effort del), so the caller can safely
 * fall back to a raw copy without leaking orphan vault rows.
 * ------------------------------------------------------------------------ */
static inline int dwnetsnap_encode(const unsigned char *plain, size_t plain_len,
                                   const char *basename,
                                   struct dwnetsnap_vault *vault,
                                   unsigned char **out, size_t *out_len)
{
    struct dwnetsnap_buf body;   /* secret-stripped body */
    struct dwnetsnap_buf result; /* header + compressed body */
    char orig_hex[65];
    char put_ids[64][DWNETSNAP_SECRET_ID_MAX];
    unsigned put_n = 0;
    unsigned seq = 0;
    const unsigned char *p;
    const unsigned char *end;
    uLongf clen;
    uLong bound;
    unsigned char *comp = NULL;
    char header[256];
    int hn;
    int rc = DWNETSNAP_ENCODE_ERROR;

    if (out)
        *out = NULL;
    if (out_len)
        *out_len = 0;
    if (!plain || plain_len == 0 || plain_len > DWNETSNAP_MAX_BYTES ||
        !basename || !basename[0] || !vault || !vault->put || !out || !out_len)
        return DWNETSNAP_ENCODE_ERROR;

    /* A literal "@vault:" already present in the plaintext would be
     * misread as a reference on decode. Real network configs never contain
     * it; if one does, refuse the new format and let the caller use raw. */
    if (plain_len >= DWNETSNAP_REF_LEN &&
        dwnetsnap_memfind(plain, plain_len, DWNETSNAP_REF, DWNETSNAP_REF_LEN))
        return DWNETSNAP_ENCODE_ERROR;

    dwnetsnap_buf_init(&body);
    dwnetsnap_buf_init(&result);

    p = plain;
    end = plain + plain_len;
    while (p < end) {
        const unsigned char *nl = (const unsigned char *)memchr(p, '\n',
                                                                (size_t)(end - p));
        const unsigned char *line_end = nl ? nl : end;
        const unsigned char *q = p;
        const unsigned char *key;
        size_t key_len;
        const unsigned char *val;
        const unsigned char *val_end;
        unsigned char quote;

        /* Parse a UCI "\toption <key> '<value>'" line; anything else copies
         * through verbatim. */
        while (q < line_end && (*q == ' ' || *q == '\t'))
            q++;
        if ((size_t)(line_end - q) < 7 || memcmp(q, "option ", 7) != 0)
            goto copy_line;
        q += 7;
        while (q < line_end && (*q == ' ' || *q == '\t'))
            q++;
        key = q;
        while (q < line_end && *q != ' ' && *q != '\t')
            q++;
        key_len = (size_t)(q - key);
        if (!dwnetsnap_secret_option_key((const char *)key, key_len))
            goto copy_line;
        while (q < line_end && (*q == ' ' || *q == '\t'))
            q++;
        if (q >= line_end || (*q != '\'' && *q != '"'))
            goto copy_line;
        quote = *q;
        val = q + 1;
        val_end = val;
        while (val_end < line_end && *val_end != quote)
            val_end++;
        if (val_end >= line_end) /* unterminated quote: copy through */
            goto copy_line;
        if (val_end == val) /* empty secret: nothing to isolate */
            goto copy_line;

        /* Vault the value, splice in "@vault:<id>". Prefix up to and
         * including the opening quote is preserved byte-for-byte. */
        {
            char sid[DWNETSNAP_SECRET_ID_MAX];
            char ref[DWNETSNAP_SECRET_ID_MAX + 8];
            int rn;

            if (put_n >= sizeof(put_ids) / sizeof(put_ids[0]))
                goto fail; /* implausibly many secrets */
            if (dwnetsnap_secret_id(basename, seq++, sid, sizeof(sid)) != 0)
                goto fail;
            if (vault->put(vault->ctx, sid, val,
                           (size_t)(val_end - val)) != 0)
                goto fail;
            snprintf(put_ids[put_n], sizeof(put_ids[0]), "%s", sid);
            put_n++;
            if (dwnetsnap_buf_append(&body, p, (size_t)(val - p)) != 0)
                goto fail;
            rn = snprintf(ref, sizeof(ref), "%s%s", DWNETSNAP_REF, sid);
            if (rn < 0 || (size_t)rn >= sizeof(ref))
                goto fail;
            if (dwnetsnap_buf_append(&body, ref, (size_t)rn) != 0)
                goto fail;
            if (dwnetsnap_buf_append(&body, val_end,
                                     (size_t)(line_end - val_end)) != 0)
                goto fail;
        }
        if (nl && dwnetsnap_buf_append(&body, "\n", 1) != 0)
            goto fail;
        p = nl ? nl + 1 : end;
        continue;

copy_line:
        if (dwnetsnap_buf_append(&body, p, (size_t)(line_end - p)) != 0)
            goto fail;
        if (nl && dwnetsnap_buf_append(&body, "\n", 1) != 0)
            goto fail;
        p = nl ? nl + 1 : end;
    }

    if (put_n == 0) {
        rc = DWNETSNAP_ENCODE_NO_SECRETS; /* behaviour-neutral: use raw .bak */
        goto out;
    }

    if (dwnetsnap_sha256_hex(plain, plain_len, orig_hex) != 0)
        goto fail;

    bound = compressBound((uLong)body.len);
    comp = (unsigned char *)malloc(bound ? (size_t)bound : 1U);
    if (!comp)
        goto fail;
    clen = bound;
    if (compress2(comp, &clen, body.data ? (const Bytef *)body.data
                                         : (const Bytef *)"",
                  (uLong)body.len, 6) != Z_OK)
        goto fail;

    hn = snprintf(header, sizeof(header),
                  DWNETSNAP_MAGIC
                  "orig_sha256:%s\norig_len:%zu\nbody_len:%zu\nenc:zlib\n\n",
                  orig_hex, plain_len, body.len);
    if (hn < 0 || (size_t)hn >= sizeof(header))
        goto fail;
    if (dwnetsnap_buf_append(&result, header, (size_t)hn) != 0)
        goto fail;
    if (dwnetsnap_buf_append(&result, comp, (size_t)clen) != 0)
        goto fail;

    *out = result.data;
    *out_len = result.len;
    result.data = NULL; /* ownership handed to caller */
    result.cap = 0;
    rc = DWNETSNAP_ENCODE_OK;
    goto out;

fail:
    rc = DWNETSNAP_ENCODE_ERROR;
    /* Roll back every secret we stored this call so no orphan rows survive a
     * fallback to the raw .bak. */
    if (vault->del) {
        unsigned i;
        for (i = 0; i < put_n; i++)
            vault->del(vault->ctx, put_ids[i]);
    }
out:
    if (comp) {
        free(comp);
        comp = NULL;
    }
    dwnetsnap_buf_free(&body);
    dwnetsnap_buf_free(&result);
    memset(put_ids, 0, sizeof(put_ids));
    return rc;
}

/* --------------------------------------------------------------------------
 * DECODE — reconstruct + integrity-verify, or REFUSE. See THE #1 SAFETY LAW.
 *
 * DWNETSNAP_DECODE_RAW: no magic; caller copies the snapshot verbatim.
 * DWNETSNAP_DECODE_OK: out/out_len hold malloc'd reconstructed plaintext;
 *   caller writes it, then frees with free() (already sha256-verified).
 * DWNETSNAP_DECODE_REFUSE: caller MUST NOT touch /etc/config/network.
 * ------------------------------------------------------------------------ */
static inline int dwnetsnap_decode(const unsigned char *snap, size_t snap_len,
                                   struct dwnetsnap_vault *vault,
                                   unsigned char **out, size_t *out_len,
                                   char *err, size_t err_len)
{
    const unsigned char *hdr;
    const unsigned char *hdr_end;
    const unsigned char *comp;
    size_t comp_len;
    const unsigned char *line;
    char orig_hex[65] = "";
    unsigned long long orig_len_hdr = 0;
    unsigned long long body_len_hdr = 0;
    int have_sha = 0, have_orig = 0, have_body = 0, have_enc = 0;
    unsigned char *body = NULL;
    uLongf ulen;
    struct dwnetsnap_buf rebuilt;
    const unsigned char *bp;
    const unsigned char *bend;
    char got_hex[65];
    int rc = DWNETSNAP_DECODE_REFUSE;

    if (out)
        *out = NULL;
    if (out_len)
        *out_len = 0;
    if (err && err_len)
        err[0] = '\0';
    if (!snap || !out || !out_len)
        return DWNETSNAP_DECODE_REFUSE;

    /* No magic -> old raw .bak: verbatim restore (today's path). */
    if (snap_len < DWNETSNAP_MAGIC_LEN ||
        memcmp(snap, DWNETSNAP_MAGIC, DWNETSNAP_MAGIC_LEN) != 0)
        return DWNETSNAP_DECODE_RAW;

    dwnetsnap_buf_init(&rebuilt);

    /* Text header runs from after the magic to the first blank line. The
     * compressed body (binary, may contain '\n') begins after "\n\n". */
    hdr = snap + DWNETSNAP_MAGIC_LEN;
    hdr_end = dwnetsnap_memfind(hdr, snap_len - DWNETSNAP_MAGIC_LEN, "\n\n", 2);
    if (!hdr_end) {
        if (err && err_len) snprintf(err, err_len, "snapshot_header_unterminated");
        return DWNETSNAP_DECODE_REFUSE;
    }
    comp = hdr_end + 2;
    comp_len = (size_t)(snap + snap_len - comp);

    for (line = hdr; line < hdr_end; ) {
        const unsigned char *le = (const unsigned char *)memchr(
            line, '\n', (size_t)(hdr_end - line));
        const unsigned char *colon;
        size_t klen;
        const char *v;

        if (!le)
            le = hdr_end;
        colon = (const unsigned char *)memchr(line, ':', (size_t)(le - line));
        if (!colon) {
            line = le + 1;
            continue;
        }
        klen = (size_t)(colon - line);
        v = (const char *)colon + 1;
        if (klen == 11 && !memcmp(line, "orig_sha256", 11)) {
            if ((size_t)(le - (colon + 1)) == 64) {
                memcpy(orig_hex, v, 64);
                orig_hex[64] = '\0';
                have_sha = 1;
            }
        } else if (klen == 8 && !memcmp(line, "orig_len", 8)) {
            orig_len_hdr = strtoull(v, NULL, 10);
            have_orig = 1;
        } else if (klen == 8 && !memcmp(line, "body_len", 8)) {
            body_len_hdr = strtoull(v, NULL, 10);
            have_body = 1;
        } else if (klen == 3 && !memcmp(line, "enc", 3)) {
            if ((size_t)(le - (colon + 1)) == 4 && !memcmp(v, "zlib", 4))
                have_enc = 1;
        }
        line = le + 1;
    }

    if (!have_sha || !have_orig || !have_body || !have_enc ||
        orig_len_hdr == 0 || orig_len_hdr > DWNETSNAP_MAX_BYTES ||
        body_len_hdr == 0 || body_len_hdr > DWNETSNAP_MAX_BYTES ||
        comp_len == 0) {
        if (err && err_len) snprintf(err, err_len, "snapshot_header_invalid");
        return DWNETSNAP_DECODE_REFUSE;
    }

    /* Decompress the secret-stripped body. */
    body = (unsigned char *)malloc((size_t)body_len_hdr + 1U);
    if (!body) {
        if (err && err_len) snprintf(err, err_len, "snapshot_oom");
        return DWNETSNAP_DECODE_REFUSE;
    }
    ulen = (uLongf)body_len_hdr;
    if (uncompress(body, &ulen, comp, (uLong)comp_len) != Z_OK ||
        ulen != (uLongf)body_len_hdr) {
        if (err && err_len) snprintf(err, err_len, "snapshot_decompress_failed");
        goto refuse;
    }
    body[ulen] = '\0';

    /* Reconstruct: copy the body, resolving every "@vault:<id>" via the
     * vault. A missing/failed/empty resolve REFUSES — never a blank secret. */
    bp = body;
    bend = body + (size_t)ulen;
    while (bp < bend) {
        const unsigned char *ref = dwnetsnap_memfind(
            bp, (size_t)(bend - bp), DWNETSNAP_REF, DWNETSNAP_REF_LEN);
        const unsigned char *idp;
        const unsigned char *ide;
        char sid[DWNETSNAP_SECRET_ID_MAX];
        size_t idlen;
        unsigned char *secret = NULL;
        size_t secret_len = 0;

        if (!ref) {
            if (dwnetsnap_buf_append(&rebuilt, bp, (size_t)(bend - bp)) != 0)
                goto refuse;
            break;
        }
        if (dwnetsnap_buf_append(&rebuilt, bp, (size_t)(ref - bp)) != 0)
            goto refuse;
        idp = ref + DWNETSNAP_REF_LEN;
        ide = idp;
        while (ide < bend && dwnetsnap_id_char(*ide))
            ide++;
        idlen = (size_t)(ide - idp);
        if (idlen == 0 || idlen >= sizeof(sid)) {
            if (err && err_len) snprintf(err, err_len, "snapshot_ref_malformed");
            goto refuse;
        }
        memcpy(sid, idp, idlen);
        sid[idlen] = '\0';
        if (!vault || !vault->get ||
            vault->get(vault->ctx, sid, &secret, &secret_len) != 0 ||
            !secret || secret_len == 0) {
            /* Cannot resolve, or resolved empty: refusing keeps the WAN up. */
            if (secret) {
                if (vault && vault->free_secret)
                    vault->free_secret(vault->ctx, secret, secret_len);
                else
                    free(secret);
            }
            if (err && err_len) snprintf(err, err_len, "snapshot_vault_resolve_failed");
            goto refuse;
        }
        if (dwnetsnap_buf_append(&rebuilt, secret, secret_len) != 0) {
            if (vault->free_secret)
                vault->free_secret(vault->ctx, secret, secret_len);
            else
                free(secret);
            goto refuse;
        }
        if (vault->free_secret)
            vault->free_secret(vault->ctx, secret, secret_len);
        else
            free(secret);
        bp = ide;
    }

    /* Integrity gate: length then sha256 of the reconstruction vs the header's
     * ORIGINAL-plaintext sha256. ANY mismatch REFUSES. */
    if (rebuilt.len != (size_t)orig_len_hdr) {
        if (err && err_len) snprintf(err, err_len, "snapshot_length_mismatch");
        goto refuse;
    }
    if (dwnetsnap_sha256_hex(rebuilt.data, rebuilt.len, got_hex) != 0) {
        if (err && err_len) snprintf(err, err_len, "snapshot_sha256_failed");
        goto refuse;
    }
    if (!dwnetsnap_ci_streq(got_hex, orig_hex)) {
        if (err && err_len) snprintf(err, err_len, "snapshot_sha256_mismatch");
        goto refuse;
    }

    *out = rebuilt.data;
    *out_len = rebuilt.len;
    rebuilt.data = NULL; /* ownership handed to caller (already verified) */
    rebuilt.cap = 0;
    rc = DWNETSNAP_DECODE_OK;
    goto done;

refuse:
    rc = DWNETSNAP_DECODE_REFUSE;
done:
    if (body) {
        memset(body, 0, (size_t)body_len_hdr + 1U);
        free(body);
    }
    dwnetsnap_buf_free(&rebuilt);
    return rc;
}

/* --------------------------------------------------------------------------
 * Shared file I/O so webd and init read/write snapshots identically.
 * ------------------------------------------------------------------------ */

/* Read up to DWNETSNAP_MAX_BYTES of `path` into a malloc'd buffer. 0 on ok. */
static inline int dwnetsnap_read_file(const char *path, unsigned char **out,
                                      size_t *out_len)
{
    int fd;
    struct dwnetsnap_buf b;
    unsigned char tmp[8192];
    ssize_t n;

    if (out)
        *out = NULL;
    if (out_len)
        *out_len = 0;
    if (!path || !out || !out_len)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    dwnetsnap_buf_init(&b);
    while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
        if (dwnetsnap_buf_append(&b, tmp, (size_t)n) != 0) {
            close(fd);
            dwnetsnap_buf_free(&b);
            return -1;
        }
    }
    close(fd);
    if (n < 0) {
        dwnetsnap_buf_free(&b);
        return -1;
    }
    *out = b.data;
    *out_len = b.len;
    return 0;
}

/* Write `len` bytes to `path` (0600, fsync'd). 0 on success. */
static inline int dwnetsnap_write_file(const char *path,
                                       const unsigned char *data, size_t len)
{
    int fd;
    const unsigned char *p = data;
    size_t left = len;

    if (!path || (!data && len))
        return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            close(fd);
            return -1;
        }
        p += w;
        left -= (size_t)w;
    }
    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/*
 * The single restore primitive shared by webd_network_config_restore and
 * init's restore_network_snapshot. Reads `snapshot_path`, decodes it (raw or
 * new-format), and — ONLY when the result is safe — writes the bytes to
 * `target_path`. On REFUSE it writes nothing and returns -1.
 *
 * `err` receives a stable machine token on failure. Callers keep their own
 * forensic pre-copy + prefix guards + sync() around this.
 */
static inline int dwnetsnap_restore_to_target(const char *snapshot_path,
                                              const char *target_path,
                                              struct dwnetsnap_vault *vault,
                                              char *err, size_t err_len)
{
    unsigned char *snap = NULL;
    size_t snap_len = 0;
    unsigned char *plain = NULL;
    size_t plain_len = 0;
    int dec;
    int rc = -1;

    if (err && err_len)
        err[0] = '\0';
    if (!snapshot_path || !target_path) {
        if (err && err_len) snprintf(err, err_len, "invalid_path");
        return -1;
    }
    if (dwnetsnap_read_file(snapshot_path, &snap, &snap_len) != 0 ||
        snap_len == 0) {
        if (err && err_len) snprintf(err, err_len, "snapshot_read_failed");
        free(snap);
        return -1;
    }

    dec = dwnetsnap_decode(snap, snap_len, vault, &plain, &plain_len,
                           err, err_len);
    if (dec == DWNETSNAP_DECODE_RAW) {
        /* Old raw .bak — restore verbatim, exactly as before. */
        if (dwnetsnap_write_file(target_path, snap, snap_len) != 0) {
            if (err && err_len) snprintf(err, err_len, "restore_write_failed");
            goto out;
        }
        rc = 0;
    } else if (dec == DWNETSNAP_DECODE_OK) {
        if (dwnetsnap_write_file(target_path, plain, plain_len) != 0) {
            if (err && err_len) snprintf(err, err_len, "restore_write_failed");
            goto out;
        }
        rc = 0;
    } else {
        /* REFUSE: err already set by dwnetsnap_decode. Write nothing. */
        rc = -1;
    }

out:
    if (plain) {
        memset(plain, 0, plain_len);
        free(plain);
    }
    if (snap) {
        memset(snap, 0, snap_len);
        free(snap);
    }
    return rc;
}

#endif /* DREAMINGWRT_SAFEOPS_CONFIG_SNAPSHOT_CODEC_H */
