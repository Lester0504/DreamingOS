// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Minimal QR Code encoder (ISO/IEC 18004), alphanumeric mode, ECC level M.
 *
 * Only what apdctl needs to print a scannable pairing code in an ssh
 * session: alphanumeric input, versions 1-10, level M, all 8 mask patterns
 * evaluated by the standard penalty rules.
 */
#include "apd_qr.h"

#include <string.h>

/* Data codewords and EC block layout for level M, versions 1-10. */
struct apd_qr_spec {
    short total_codewords;   /* data + ecc */
    short data_codewords;    /* level M */
    unsigned char ec_per_block;
    unsigned char group1_blocks;
    unsigned char group1_data;
    unsigned char group2_blocks;
    unsigned char group2_data;
};

static const struct apd_qr_spec apd_qr_specs[APD_QR_MAX_VERSION + 1] = {
    {0, 0, 0, 0, 0, 0, 0},           /* unused */
    {26, 16, 10, 1, 16, 0, 0},       /* v1-M */
    {44, 28, 16, 1, 28, 0, 0},       /* v2-M */
    {70, 44, 26, 1, 44, 0, 0},       /* v3-M */
    {100, 64, 18, 2, 32, 0, 0},      /* v4-M */
    {134, 86, 24, 2, 43, 0, 0},      /* v5-M */
    {172, 108, 16, 4, 27, 0, 0},     /* v6-M */
    {196, 124, 18, 4, 31, 0, 0},     /* v7-M */
    {242, 154, 22, 2, 38, 2, 39},    /* v8-M */
    {292, 182, 22, 3, 36, 2, 37},    /* v9-M */
    {346, 216, 26, 4, 43, 1, 44},    /* v10-M */
};

/* Alignment pattern centre coordinates, versions 1-10. */
static const unsigned char apd_qr_align[APD_QR_MAX_VERSION + 1][3] = {
    {0, 0, 0},
    {0, 0, 0},          /* v1 has none */
    {6, 18, 0},
    {6, 22, 0},
    {6, 26, 0},
    {6, 30, 0},
    {6, 34, 0},
    {6, 22, 38},
    {6, 24, 42},
    {6, 26, 46},
    {6, 28, 50},
};

/* Level M format information, indexed by mask 0-7 (ISO 18004 Table C.1). */
static const unsigned short apd_qr_format_m[8] = {
    0x5412, 0x5125, 0x5E7C, 0x5B4B,
    0x45F9, 0x40CE, 0x4F97, 0x4AA0,
};

/* Version information for v7+, indexed by version (Table D.1). */
static const unsigned int apd_qr_version_info[APD_QR_MAX_VERSION + 1] = {
    0, 0, 0, 0, 0, 0, 0,
    0x07C94, 0x085BC, 0x09A99, 0x0A4D3,
};

/* --- GF(256) arithmetic, primitive polynomial 0x11d --- */

static unsigned char apd_qr_exp[512];
static unsigned char apd_qr_log[256];
static int apd_qr_gf_ready;

static void apd_qr_gf_init(void)
{
    int i;
    unsigned int x = 1;

    if (apd_qr_gf_ready)
        return;
    for (i = 0; i < 255; i++) {
        apd_qr_exp[i] = (unsigned char)x;
        apd_qr_log[x] = (unsigned char)i;
        x <<= 1;
        if (x & 0x100)
            x ^= 0x11d;
    }
    for (i = 255; i < 512; i++)
        apd_qr_exp[i] = apd_qr_exp[i - 255];
    apd_qr_gf_ready = 1;
}

static unsigned char apd_qr_gf_mul(unsigned char a, unsigned char b)
{
    if (!a || !b)
        return 0;
    return apd_qr_exp[apd_qr_log[a] + apd_qr_log[b]];
}

/*
 * Generator polynomial for the given ECC degree, as the product of
 * (x - alpha^i). Coefficients come out constant-term first: out[0] is the
 * constant and out[degree] is the leading 1.
 */
static void apd_qr_rs_generator(int degree, unsigned char *out)
{
    int i, j;

    memset(out, 0, (size_t)degree + 1);
    out[0] = 1;
    for (i = 0; i < degree; i++) {
        /*
         * Multiply the current polynomial by (x - alpha^i). Walking down
         * from the new leading term keeps each read ahead of its write.
         */
        for (j = i + 1; j > 0; j--)
            out[j] = (unsigned char)(apd_qr_gf_mul(out[j], apd_qr_exp[i]) ^
                                     out[j - 1]);
        out[0] = apd_qr_gf_mul(out[0], apd_qr_exp[i]);
    }
}

/* Remainder of data * x^ec_len divided by the generator polynomial. */
static void apd_qr_rs_encode(const unsigned char *data, int data_len,
                             int ec_len, unsigned char *ecc)
{
    unsigned char generator[31];
    int i, j;

    apd_qr_rs_generator(ec_len, generator);
    memset(ecc, 0, (size_t)ec_len);
    for (i = 0; i < data_len; i++) {
        unsigned char factor = (unsigned char)(data[i] ^ ecc[0]);

        memmove(ecc, ecc + 1, (size_t)ec_len - 1);
        ecc[ec_len - 1] = 0;
        /*
         * generator[ec_len] is the leading 1, consumed by the shift above.
         * ecc[] runs highest-order first, so it pairs with the generator
         * coefficients in descending order.
         */
        for (j = 0; j < ec_len; j++)
            ecc[j] = (unsigned char)(ecc[j] ^
                                     apd_qr_gf_mul(generator[ec_len - 1 - j],
                                                   factor));
    }
}

/* --- alphanumeric mode --- */

static int apd_qr_alnum_value(char c)
{
    static const char table[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    const char *p = strchr(table, c);

    if (!c || !p)
        return -1;
    return (int)(p - table);
}

int apd_qr_alnum_compatible(const char *text)
{
    size_t i;

    if (!text || !text[0])
        return 0;
    for (i = 0; text[i]; i++)
        if (apd_qr_alnum_value(text[i]) < 0)
            return 0;
    return 1;
}

/* Character count indicator width for alphanumeric mode. */
static int apd_qr_count_bits(int version)
{
    if (version <= 9)
        return 9;
    return 11;
}

struct apd_qr_bits {
    unsigned char *data;
    size_t capacity;   /* bytes */
    size_t length;     /* bits written */
};

static void apd_qr_put_bit(struct apd_qr_bits *bits, int bit)
{
    size_t index = bits->length >> 3;

    if (index >= bits->capacity)
        return;
    if (bit)
        bits->data[index] |= (unsigned char)(0x80 >> (bits->length & 7));
    bits->length++;
}

static void apd_qr_put_bits(struct apd_qr_bits *bits, unsigned int value,
                            int count)
{
    int i;

    for (i = count - 1; i >= 0; i--)
        apd_qr_put_bit(bits, (int)((value >> i) & 1u));
}

/* --- matrix construction --- */

static void apd_qr_set(struct apd_qr *qr, unsigned char *reserved,
                       int x, int y, int dark)
{
    if (x < 0 || y < 0 || x >= qr->size || y >= qr->size)
        return;
    qr->module[y][x] = (unsigned char)(dark ? 1 : 0);
    if (reserved)
        reserved[y * APD_QR_MAX_SIZE + x] = 1;
}

static void apd_qr_place_finder(struct apd_qr *qr, unsigned char *reserved,
                                int ox, int oy)
{
    int dx, dy;

    for (dy = -1; dy <= 7; dy++) {
        for (dx = -1; dx <= 7; dx++) {
            int x = ox + dx;
            int y = oy + dy;
            int rx, ry, ring;

            if (x < 0 || y < 0 || x >= qr->size || y >= qr->size)
                continue;
            if (dx < 0 || dy < 0 || dx > 6 || dy > 6) {
                /* separator */
                apd_qr_set(qr, reserved, x, y, 0);
                continue;
            }
            /*
             * Chebyshev distance from the 7x7 centre: ring 3 (outer border)
             * and rings 0-1 (the 3x3 core) are dark, ring 2 is the light
             * separator ring between them.
             */
            rx = dx - 3;
            ry = dy - 3;
            if (rx < 0) rx = -rx;
            if (ry < 0) ry = -ry;
            ring = rx > ry ? rx : ry;
            apd_qr_set(qr, reserved, x, y, ring != 2);
        }
    }
}

static void apd_qr_place_alignment(struct apd_qr *qr, unsigned char *reserved)
{
    const unsigned char *centers = apd_qr_align[qr->version];
    int count = 0;
    int i, j;

    while (count < 3 && centers[count])
        count++;
    for (i = 0; i < count; i++) {
        for (j = 0; j < count; j++) {
            int cx = centers[i];
            int cy = centers[j];
            int dx, dy;

            /*
             * Alignment patterns are omitted only where they would collide
             * with a finder, i.e. when *both* coordinates sit on the first
             * or last centre. For v2-v6 the sole centre pair is
             * (6, size-7), whose diagonal position is legitimate, so the
             * test has to consider the pair rather than either axis alone.
             */
            {
                int first = 6;
                int last = (int)centers[count - 1];

                if ((cx == first && cy == first) ||
                    (cx == first && cy == last) ||
                    (cx == last && cy == first))
                    continue;
            }
            for (dy = -2; dy <= 2; dy++) {
                for (dx = -2; dx <= 2; dx++) {
                    int adx = dx < 0 ? -dx : dx;
                    int ady = dy < 0 ? -dy : dy;
                    int ring = adx > ady ? adx : ady;

                    /* 5x5: dark outer ring and dark centre, light ring 1. */
                    apd_qr_set(qr, reserved, cx + dx, cy + dy, ring != 1);
                }
            }
        }
    }
}

static void apd_qr_place_timing(struct apd_qr *qr, unsigned char *reserved)
{
    int i;

    for (i = 8; i < qr->size - 8; i++) {
        int dark = (i % 2) == 0;

        apd_qr_set(qr, reserved, i, 6, dark);
        apd_qr_set(qr, reserved, 6, i, dark);
    }
}

static void apd_qr_reserve_format(struct apd_qr *qr, unsigned char *reserved)
{
    int i;

    /*
     * Format info runs along row 8 and column 8, but index 6 is where the
     * timing patterns cross. Reserving it here would overwrite a timing
     * module that place_timing already set.
     */
    for (i = 0; i < 9; i++) {
        if (i == 6)
            continue;
        apd_qr_set(qr, reserved, i, 8, 0);
        apd_qr_set(qr, reserved, 8, i, 0);
    }
    for (i = 0; i < 8; i++) {
        apd_qr_set(qr, reserved, qr->size - 1 - i, 8, 0);
        apd_qr_set(qr, reserved, 8, qr->size - 1 - i, 0);
    }
    /* Dark module. */
    apd_qr_set(qr, reserved, 8, qr->size - 8, 1);

    if (qr->version >= 7) {
        for (i = 0; i < 18; i++) {
            int a = i / 3;
            int b = i % 3;

            apd_qr_set(qr, reserved, a, qr->size - 11 + b, 0);
            apd_qr_set(qr, reserved, qr->size - 11 + b, a, 0);
        }
    }
}

static void apd_qr_write_format(struct apd_qr *qr, int mask)
{
    unsigned int format = apd_qr_format_m[mask];
    int i;

    for (i = 0; i < 15; i++) {
        int dark = (int)((format >> i) & 1u);
        int pos;

        /*
         * i is the LSB-first index; the spec numbers these bits MSB-first,
         * so bit i lands where spec bit (14 - i) is drawn.
         *
         * Copy 1 runs up column 8 then left along row 8 around the
         * top-left finder.
         */
        if (i < 6)
            qr->module[i][8] = (unsigned char)dark;
        else if (i == 6)
            qr->module[7][8] = (unsigned char)dark;
        else if (i == 7)
            qr->module[8][8] = (unsigned char)dark;
        else if (i == 8)
            qr->module[8][7] = (unsigned char)dark;
        else
            qr->module[8][14 - i] = (unsigned char)dark;

        /* Copy 2: row 8 on the top-right, column 8 on the bottom-left. */
        if (i < 8) {
            pos = qr->size - 1 - i;
            qr->module[8][pos] = (unsigned char)dark;
        } else {
            pos = qr->size - 15 + i;
            qr->module[pos][8] = (unsigned char)dark;
        }
    }
}

static void apd_qr_write_version(struct apd_qr *qr)
{
    unsigned int info;
    int i;

    if (qr->version < 7)
        return;
    info = apd_qr_version_info[qr->version];
    for (i = 0; i < 18; i++) {
        int dark = (int)((info >> i) & 1u);
        int a = i / 3;
        int b = i % 3;

        qr->module[qr->size - 11 + b][a] = (unsigned char)dark;
        qr->module[a][qr->size - 11 + b] = (unsigned char)dark;
    }
}

static int apd_qr_mask_bit(int mask, int x, int y)
{
    switch (mask) {
    case 0: return ((x + y) % 2) == 0;
    case 1: return (y % 2) == 0;
    case 2: return (x % 3) == 0;
    case 3: return ((x + y) % 3) == 0;
    case 4: return (((y / 2) + (x / 3)) % 2) == 0;
    case 5: return ((x * y) % 2 + (x * y) % 3) == 0;
    case 6: return (((x * y) % 2 + (x * y) % 3) % 2) == 0;
    default: return (((x + y) % 2 + (x * y) % 3) % 2) == 0;
    }
}

static void apd_qr_place_data(struct apd_qr *qr, const unsigned char *reserved,
                              const unsigned char *codewords, size_t length)
{
    int x = qr->size - 1;
    int y = qr->size - 1;
    int upward = 1;
    size_t bit = 0;
    size_t total = length * 8;

    while (x > 0) {
        if (x == 6)
            x--;      /* skip the vertical timing column */
        for (;;) {
            int i;

            for (i = 0; i < 2; i++) {
                int cx = x - i;

                if (reserved[y * APD_QR_MAX_SIZE + cx])
                    continue;
                if (bit < total) {
                    int dark = (codewords[bit >> 3] >>
                                (7 - (bit & 7))) & 1;
                    qr->module[y][cx] = (unsigned char)dark;
                    bit++;
                } else {
                    qr->module[y][cx] = 0;   /* remainder bits are light */
                }
            }
            if (upward) {
                if (y == 0)
                    break;
                y--;
            } else {
                if (y == qr->size - 1)
                    break;
                y++;
            }
        }
        upward = !upward;
        x -= 2;
    }
}

/* --- mask penalty scoring (ISO 18004 section 8.8.2) --- */

static int apd_qr_penalty_run(const struct apd_qr *qr)
{
    int penalty = 0;
    int i, j;

    for (i = 0; i < qr->size; i++) {
        int run_h = 1, run_v = 1;

        for (j = 1; j < qr->size; j++) {
            if (qr->module[i][j] == qr->module[i][j - 1]) {
                run_h++;
            } else {
                if (run_h >= 5)
                    penalty += 3 + (run_h - 5);
                run_h = 1;
            }
            if (qr->module[j][i] == qr->module[j - 1][i]) {
                run_v++;
            } else {
                if (run_v >= 5)
                    penalty += 3 + (run_v - 5);
                run_v = 1;
            }
        }
        if (run_h >= 5)
            penalty += 3 + (run_h - 5);
        if (run_v >= 5)
            penalty += 3 + (run_v - 5);
    }
    return penalty;
}

static int apd_qr_penalty_block(const struct apd_qr *qr)
{
    int penalty = 0;
    int i, j;

    for (i = 0; i < qr->size - 1; i++)
        for (j = 0; j < qr->size - 1; j++) {
            unsigned char v = qr->module[i][j];

            if (v == qr->module[i][j + 1] &&
                v == qr->module[i + 1][j] &&
                v == qr->module[i + 1][j + 1])
                penalty += 3;
        }
    return penalty;
}

/*
 * Anything outside the symbol counts as light, because the quiet zone is
 * light. Treating out-of-bounds as non-light made edge occurrences look
 * harmless and could pick a mask that real decoders mistake for a finder.
 */
static int apd_qr_line_light(const struct apd_qr *qr, int i, int from, int to,
                             int horizontal)
{
    int k;

    for (k = from; k < to; k++) {
        if (k < 0 || k >= qr->size)
            continue;
        if (horizontal ? qr->module[i][k] : qr->module[k][i])
            return 0;
    }
    return 1;
}

/* Rule 3: the 1:1:3:1:1 finder-like pattern with four light modules on
 * either side. */
static int apd_qr_penalty_finder(const struct apd_qr *qr)
{
    static const unsigned char pattern[7] = {1, 0, 1, 1, 1, 0, 1};
    int penalty = 0;
    int i, j, k;

    for (i = 0; i < qr->size; i++) {
        for (j = 0; j + 6 < qr->size; j++) {
            int match_h = 1, match_v = 1;

            for (k = 0; k < 7; k++) {
                if (qr->module[i][j + k] != pattern[k])
                    match_h = 0;
                if (qr->module[j + k][i] != pattern[k])
                    match_v = 0;
            }
            if (match_h) {
                if (apd_qr_line_light(qr, i, j - 4, j, 1))
                    penalty += 40;
                if (apd_qr_line_light(qr, i, j + 7, j + 11, 1))
                    penalty += 40;
            }
            if (match_v) {
                if (apd_qr_line_light(qr, i, j - 4, j, 0))
                    penalty += 40;
                if (apd_qr_line_light(qr, i, j + 7, j + 11, 0))
                    penalty += 40;
            }
        }
    }
    return penalty;
}

static int apd_qr_penalty_balance(const struct apd_qr *qr)
{
    int dark = 0;
    int i, j;
    int total = qr->size * qr->size;
    int percent, deviation;

    for (i = 0; i < qr->size; i++)
        for (j = 0; j < qr->size; j++)
            if (qr->module[i][j])
                dark++;
    percent = dark * 100 / total;
    deviation = percent - 50;
    if (deviation < 0)
        deviation = -deviation;
    return (deviation / 5) * 10;
}

static int apd_qr_penalty(const struct apd_qr *qr)
{
    return apd_qr_penalty_run(qr) + apd_qr_penalty_block(qr) +
           apd_qr_penalty_finder(qr) + apd_qr_penalty_balance(qr);
}

/* --- top level --- */

static int apd_qr_pick_version(size_t text_len, int *out_version)
{
    int version;

    for (version = APD_QR_MIN_VERSION; version <= APD_QR_MAX_VERSION;
         version++) {
        const struct apd_qr_spec *spec = &apd_qr_specs[version];
        size_t bits = 4;    /* mode indicator */

        bits += (size_t)apd_qr_count_bits(version);
        bits += (text_len / 2) * 11;
        if (text_len & 1)
            bits += 6;
        if (bits <= (size_t)spec->data_codewords * 8) {
            *out_version = version;
            return APD_QR_OK;
        }
    }
    return APD_QR_ERR_TOO_LONG;
}

int apd_qr_encode_alnum(const char *text, struct apd_qr *out)
{
    unsigned char payload[216];      /* v10-M data codewords, the maximum */
    unsigned char interleaved[346];
    unsigned char ecc_blocks[8][30];
    struct apd_qr_bits bits;
    const struct apd_qr_spec *spec;
    unsigned char reserved[APD_QR_MAX_SIZE * APD_QR_MAX_SIZE];
    struct apd_qr best;
    size_t text_len;
    size_t i;
    int version = 0;
    int rc;
    int blocks, block, mask, best_mask = 0, best_penalty = 0;
    int data_offset;
    size_t out_index;
    int max_data;

    if (!text || !out)
        return APD_QR_ERR_ARG;
    if (!apd_qr_alnum_compatible(text))
        return APD_QR_ERR_CHARSET;
    apd_qr_gf_init();
    text_len = strlen(text);
    rc = apd_qr_pick_version(text_len, &version);
    if (rc != APD_QR_OK)
        return rc;
    spec = &apd_qr_specs[version];

    /* 1. Encode the bitstream. */
    memset(payload, 0, sizeof(payload));
    bits.data = payload;
    bits.capacity = (size_t)spec->data_codewords;
    bits.length = 0;
    apd_qr_put_bits(&bits, 2, 4);                            /* alphanumeric */
    apd_qr_put_bits(&bits, (unsigned int)text_len,
                    apd_qr_count_bits(version));
    for (i = 0; i + 1 < text_len; i += 2) {
        int pair = apd_qr_alnum_value(text[i]) * 45 +
                   apd_qr_alnum_value(text[i + 1]);

        apd_qr_put_bits(&bits, (unsigned int)pair, 11);
    }
    if (text_len & 1)
        apd_qr_put_bits(&bits, (unsigned int)apd_qr_alnum_value(text[text_len - 1]), 6);

    /* 2. Terminator, byte alignment, then the 0xEC/0x11 pad cycle. */
    {
        size_t capacity_bits = (size_t)spec->data_codewords * 8;
        int terminator = 4;
        size_t pad_index = 0;

        if (bits.length + 4 > capacity_bits)
            terminator = (int)(capacity_bits - bits.length);
        apd_qr_put_bits(&bits, 0, terminator);
        while (bits.length % 8)
            apd_qr_put_bit(&bits, 0);
        while (bits.length < capacity_bits) {
            apd_qr_put_bits(&bits, (pad_index & 1) ? 0x11 : 0xEC, 8);
            pad_index++;
        }
    }

    /* 3. Split into blocks, compute ECC, interleave. */
    blocks = spec->group1_blocks + spec->group2_blocks;
    data_offset = 0;
    for (block = 0; block < blocks; block++) {
        int block_data = block < spec->group1_blocks ?
            spec->group1_data : spec->group2_data;

        apd_qr_rs_encode(payload + data_offset, block_data,
                         spec->ec_per_block, ecc_blocks[block]);
        data_offset += block_data;
    }

    memset(interleaved, 0, sizeof(interleaved));
    out_index = 0;
    max_data = spec->group2_blocks ? spec->group2_data : spec->group1_data;
    for (i = 0; i < (size_t)max_data; i++) {
        int offset = 0;

        for (block = 0; block < blocks; block++) {
            int block_data = block < spec->group1_blocks ?
                spec->group1_data : spec->group2_data;

            if ((int)i < block_data)
                interleaved[out_index++] = payload[offset + i];
            offset += block_data;
        }
    }
    for (i = 0; i < spec->ec_per_block; i++)
        for (block = 0; block < blocks; block++)
            interleaved[out_index++] = ecc_blocks[block][i];

    /* 4. Lay out the matrix, then pick the lowest-penalty mask. */
    memset(out, 0, sizeof(*out));
    out->version = version;
    out->size = version * 4 + 17;
    memset(reserved, 0, sizeof(reserved));
    apd_qr_place_finder(out, reserved, 0, 0);
    apd_qr_place_finder(out, reserved, out->size - 7, 0);
    apd_qr_place_finder(out, reserved, 0, out->size - 7);
    apd_qr_place_alignment(out, reserved);
    apd_qr_place_timing(out, reserved);
    apd_qr_reserve_format(out, reserved);
    apd_qr_place_data(out, reserved, interleaved, out_index);

    best = *out;
    for (mask = 0; mask < 8; mask++) {
        struct apd_qr candidate = *out;
        int penalty;
        int x, y;

        for (y = 0; y < candidate.size; y++)
            for (x = 0; x < candidate.size; x++)
                if (!reserved[y * APD_QR_MAX_SIZE + x] &&
                    apd_qr_mask_bit(mask, x, y))
                    candidate.module[y][x] ^= 1;
        candidate.mask = mask;
        apd_qr_write_format(&candidate, mask);
        apd_qr_write_version(&candidate);
        penalty = apd_qr_penalty(&candidate);
        if (mask == 0 || penalty < best_penalty) {
            best_penalty = penalty;
            best_mask = mask;
            best = candidate;
        }
    }
    best.mask = best_mask;
    *out = best;
    return APD_QR_OK;
}

int apd_qr_render_columns(const struct apd_qr *qr, int quiet)
{
    if (!qr)
        return 0;
    if (quiet < 0)
        quiet = 0;
    return qr->size + quiet * 2;
}

int apd_qr_render_rows(const struct apd_qr *qr, int quiet)
{
    int rows;

    if (!qr)
        return 0;
    if (quiet < 0)
        quiet = 0;
    rows = qr->size + quiet * 2;
    return (rows + 1) / 2;
}

/*
 * Two module rows share one text line via half blocks. QR polarity is dark
 * modules on light, so the block glyph must render the *dark* module: with
 * ANSI we paint a white background and black foreground, which keeps the
 * code scannable on dark-themed terminals too.
 */
void apd_qr_render_halfblock(const struct apd_qr *qr, int quiet, int color,
                             FILE *out)
{
    int total, y, x;

    if (!qr || !out)
        return;
    if (quiet < 0)
        quiet = 0;
    total = qr->size + quiet * 2;

    for (y = 0; y < total; y += 2) {
        if (color)
            fputs("\033[47m\033[30m", out);
        for (x = 0; x < total; x++) {
            int mx = x - quiet;
            int top_y = y - quiet;
            int bottom_y = y + 1 - quiet;
            int top = 0;
            int bottom = 0;

            if (mx >= 0 && mx < qr->size) {
                if (top_y >= 0 && top_y < qr->size)
                    top = qr->module[top_y][mx];
                if (bottom_y >= 0 && bottom_y < qr->size)
                    bottom = qr->module[bottom_y][mx];
            }
            if (top && bottom)
                fputs("\xe2\x96\x88", out);        /* full block */
            else if (top)
                fputs("\xe2\x96\x80", out);        /* upper half */
            else if (bottom)
                fputs("\xe2\x96\x84", out);        /* lower half */
            else
                fputc(' ', out);
        }
        if (color)
            fputs("\033[0m", out);
        fputc('\n', out);
    }
}
