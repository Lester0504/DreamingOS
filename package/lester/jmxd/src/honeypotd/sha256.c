// SPDX-License-Identifier: GPL-2.0-or-later
#include "honeypotd_internal.h"

struct hp_sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_len;
};

static const uint32_t hp_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t hp_rotr32(uint32_t value, unsigned int bits)
{
    return (value >> bits) | (value << (32U - bits));
}

static void hp_sha256_transform(struct hp_sha256_ctx *ctx, const unsigned char block[64])
{
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (size_t i = 0; i < 16; i++) {
        words[i] = ((uint32_t)block[i * 4] << 24) |
                   ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) |
                   (uint32_t)block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = hp_rotr32(words[i - 15], 7) ^ hp_rotr32(words[i - 15], 18) ^
                      (words[i - 15] >> 3);
        uint32_t s1 = hp_rotr32(words[i - 2], 17) ^ hp_rotr32(words[i - 2], 19) ^
                      (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t sum1 = hp_rotr32(e, 6) ^ hp_rotr32(e, 11) ^ hp_rotr32(e, 25);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choose + hp_sha256_k[i] + words[i];
        uint32_t sum0 = hp_rotr32(a, 2) ^ hp_rotr32(a, 13) ^ hp_rotr32(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void hp_sha256_init(struct hp_sha256_ctx *ctx)
{
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->state, initial, sizeof(initial));
}

static void hp_sha256_update(struct hp_sha256_ctx *ctx, const unsigned char *data, size_t length)
{
    if (!data || length == 0)
        return;
    ctx->bit_count += (uint64_t)length * 8U;
    while (length) {
        size_t copy = sizeof(ctx->block) - ctx->block_len;

        if (copy > length)
            copy = length;
        memcpy(ctx->block + ctx->block_len, data, copy);
        ctx->block_len += copy;
        data += copy;
        length -= copy;
        if (ctx->block_len == sizeof(ctx->block)) {
            hp_sha256_transform(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void hp_sha256_final(struct hp_sha256_ctx *ctx, unsigned char digest[32])
{
    uint64_t bits = ctx->bit_count;

    ctx->block[ctx->block_len++] = 0x80;
    if (ctx->block_len > 56) {
        memset(ctx->block + ctx->block_len, 0, sizeof(ctx->block) - ctx->block_len);
        hp_sha256_transform(ctx, ctx->block);
        ctx->block_len = 0;
    }
    memset(ctx->block + ctx->block_len, 0, 56 - ctx->block_len);
    for (size_t i = 0; i < 8; i++)
        ctx->block[63 - i] = (unsigned char)(bits >> (i * 8));
    hp_sha256_transform(ctx, ctx->block);
    for (size_t i = 0; i < 8; i++) {
        digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)ctx->state[i];
    }
    memset(ctx, 0, sizeof(*ctx));
}

void hp_payload_add_password_digest(struct json_object *payload,
                                    const unsigned char *password, size_t length,
                                    bool present)
{
    static const char hex[] = "0123456789abcdef";
    struct hp_sha256_ctx ctx;
    unsigned char digest[32];
    char encoded[65];

    json_object_object_add(payload, "password_present", json_object_new_boolean(present));
    json_object_object_add(payload, "password_length", json_object_new_int64((int64_t)length));
    if (!present || (!password && length != 0))
        return;
    hp_sha256_init(&ctx);
    hp_sha256_update(&ctx, password, length);
    hp_sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        encoded[i * 2] = hex[digest[i] >> 4];
        encoded[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    encoded[64] = '\0';
    json_object_object_add(payload, "password_sha256", json_object_new_string(encoded));
    memset(digest, 0, sizeof(digest));
    memset(encoded, 0, sizeof(encoded));
}
