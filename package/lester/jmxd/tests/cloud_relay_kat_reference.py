#!/usr/bin/env python3
"""Independent reference vectors for the relay end-to-end encryption chain.

The router side (cloud_envelope.c) is built on OpenSSL. Checking it with
OpenSSL would only prove OpenSSL agrees with itself, so every primitive here is
implemented from the RFC text with nothing but hashlib/hmac: X25519 (RFC 7748),
HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 (RFC 8439) and Ed25519 (RFC 8032).

Each primitive is checked against its RFC test vector before any DreamingOS
vector is emitted, so a bug in this file fails loudly instead of silently
"agreeing" with a matching bug on the C side.

Run with --selftest to only verify the primitives, or with no arguments to
write the generated C header to stdout.
"""
import hashlib
import hmac
import json
import struct
import sys

# ── X25519 (RFC 7748) ────────────────────────────────────────────────

_P = 2 ** 255 - 19
_A24 = 121665


def _cswap(swap, x2, x3):
    dummy = swap * ((x2 - x3) % _P)
    return (x2 - dummy) % _P, (x3 + dummy) % _P


def x25519(scalar, u):
    k = int.from_bytes(scalar, "little")
    k &= ~7
    k &= ~(128 << (8 * 31))
    k |= 64 << (8 * 31)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = x1 * pow((da - cb) % _P, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * ((aa + _A24 * e) % _P) % _P
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def x25519_base(scalar):
    return x25519(scalar, (9).to_bytes(32, "little"))


# ── HKDF-SHA256 (RFC 5869) ───────────────────────────────────────────


def hkdf_sha256(secret, salt, info, length):
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


# ── ChaCha20-Poly1305 (RFC 8439) ─────────────────────────────────────


def _rotl32(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha20_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state = constants + list(struct.unpack("<8I", key)) + [counter] + \
        list(struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20(key, counter, nonce, data):
    stream = b""
    blocks = (len(data) + 63) // 64
    for i in range(blocks):
        stream += _chacha20_block(key, counter + i, nonce)
    return bytes(a ^ b for a, b in zip(data, stream))


def poly1305(key, message):
    prime = (1 << 130) - 5
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset:offset + 16]
        accumulator += int.from_bytes(chunk + b"\x01", "little")
        accumulator = accumulator * r % prime
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _poly1305_key(key, nonce):
    return _chacha20_block(key, 0, nonce)[:32]


def _aead_mac_data(aad, ciphertext):
    def pad16(data):
        return b"\x00" * (-len(data) % 16)

    return (aad + pad16(aad) + ciphertext + pad16(ciphertext) +
            struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext)))


def chacha20poly1305_seal(key, nonce, plaintext, aad=b""):
    ciphertext = chacha20(key, 1, nonce, plaintext)
    tag = poly1305(_poly1305_key(key, nonce),
                   _aead_mac_data(aad, ciphertext))
    return ciphertext, tag


def chacha20poly1305_open(key, nonce, ciphertext, tag, aad=b""):
    expected = poly1305(_poly1305_key(key, nonce),
                        _aead_mac_data(aad, ciphertext))
    if not hmac.compare_digest(expected, tag):
        raise ValueError("tag mismatch")
    return chacha20(key, 1, nonce, ciphertext)


# ── Ed25519 (RFC 8032) ───────────────────────────────────────────────

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P


def _ed_point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_scalar_mult(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _ed_point_add(result, point)
        point = _ed_point_add(point, point)
        scalar >>= 1
    return result


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P


def _ed_recover_x(y, sign):
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if x * x % _ED_P != x2:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    if x * x % _ED_P != x2:
        return None
    if x & 1 != sign:
        x = _ED_P - x
    return x


_ED_G = (_ed_recover_x(_ED_GY, 0), _ED_GY, 1,
         _ed_recover_x(_ED_GY, 0) * _ED_GY % _ED_P)


def _ed_compress(point):
    x, y, z = point[0], point[1], point[2]
    inverse = pow(z, _ED_P - 2, _ED_P)
    x, y = x * inverse % _ED_P, y * inverse % _ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_secret_expand(secret):
    digest = hashlib.sha512(secret).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= ~7
    scalar &= ~(128 << (8 * 31))
    scalar |= 64 << (8 * 31)
    return scalar, digest[32:]


def ed25519_public(secret):
    scalar, _ = _ed_secret_expand(secret)
    return _ed_compress(_ed_scalar_mult(scalar, _ED_G))


def ed25519_sign(secret, message):
    scalar, prefix = _ed_secret_expand(secret)
    public = _ed_compress(_ed_scalar_mult(scalar, _ED_G))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(),
                       "little") % _ED_L
    big_r = _ed_compress(_ed_scalar_mult(r, _ED_G))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(),
                       "little") % _ED_L
    s = (r + k * scalar) % _ED_L
    return big_r + s.to_bytes(32, "little")


# ── primitive self-tests against the RFC vectors ─────────────────────


def selftest():
    # RFC 7748 section 6.1
    alice_secret = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_secret = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_public = bytes.fromhex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_public = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert x25519_base(alice_secret) == alice_public, "X25519 base(alice)"
    assert x25519_base(bob_secret) == bob_public, "X25519 base(bob)"
    assert x25519(alice_secret, bob_public) == shared, "X25519 shared a*B"
    assert x25519(bob_secret, alice_public) == shared, "X25519 shared b*A"

    # RFC 5869 test case 1
    okm = hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                      bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm == bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"), "HKDF-SHA256 RFC 5869 case 1"

    # RFC 8439 section 2.8.2
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer "
                 b"you only one tip for the future, sunscreen would be it.")
    ciphertext, tag = chacha20poly1305_seal(key, nonce, plaintext, aad)
    assert ciphertext.hex().startswith("d31a8d34648e60db7b86afbc53ef7ec2"), \
        "ChaCha20-Poly1305 ciphertext"
    assert tag == bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691"), \
        "ChaCha20-Poly1305 tag"
    assert chacha20poly1305_open(key, nonce, ciphertext, tag, aad) == plaintext, \
        "ChaCha20-Poly1305 open"

    # RFC 8032 section 7.1 test 2
    secret = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    assert ed25519_public(secret) == bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), \
        "Ed25519 public key"
    assert ed25519_sign(secret, b"\x72") == bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"), \
        "Ed25519 signature"
    return "all RFC primitive vectors match"


# ── DreamingOS relay vectors ─────────────────────────────────────────

CONTEXT = b"dreamingos-relay-e2ee-v1"

ROUTER_STATIC_PRIVATE = bytes(range(0x40, 0x60))
APP_EPHEMERAL_PRIVATE = bytes(range(0x01, 0x21))
APP_SIGNING_SECRET = bytes(range(0x80, 0xA0))
ROUTER_ID = "DR-KAT-0001"
REQUEST_ID = "8f14e45f-ea4e-4b30-9b1e-2c1d3f4a5b6c"
NONCE = bytes.fromhex("aabbccdd0011223344556677")


def build_vectors():
    router_public = x25519_base(ROUTER_STATIC_PRIVATE)
    ephemeral_public = x25519_base(APP_EPHEMERAL_PRIVATE)
    signing_public = ed25519_public(APP_SIGNING_SECRET)

    # The App computes the shared secret from its ephemeral private key and the
    # router's registered static public key; the router mirrors it the other
    # way round. Both must land on the same bytes.
    shared_app = x25519(APP_EPHEMERAL_PRIVATE, router_public)
    shared_router = x25519(ROUTER_STATIC_PRIVATE, ephemeral_public)
    assert shared_app == shared_router, "X25519 agreement is not symmetric"

    salt = hashlib.sha256(REQUEST_ID.encode()).digest()
    info = CONTEXT + ephemeral_public + router_public
    traffic = hkdf_sha256(shared_app, salt, info, 32)

    inner = json.dumps({
        "method": "GET",
        "path": "/api/v1/status",
        "request_id": REQUEST_ID,
        "issued_at": 1767225600,
        "access_token": "kat-access-token",
        "body": "",
    }, separators=(",", ":"), sort_keys=True).encode()

    body, tag = chacha20poly1305_seal(traffic, NONCE, inner)
    combined = NONCE + body + tag

    transcript = (CONTEXT + ROUTER_ID.encode() + REQUEST_ID.encode() +
                  ephemeral_public + combined)
    signature = ed25519_sign(APP_SIGNING_SECRET, transcript)

    response_plain = json.dumps({
        "status": 200,
        "request_id": REQUEST_ID,
        "body": "",
    }, separators=(",", ":"), sort_keys=True).encode()
    response_body, response_tag = chacha20poly1305_seal(traffic, NONCE,
                                                       response_plain)

    return {
        "router_private": ROUTER_STATIC_PRIVATE,
        "router_public": router_public,
        "ephemeral_public": ephemeral_public,
        "signing_public": signing_public,
        "traffic_key": traffic,
        "inner_plaintext": inner,
        "ciphertext": combined,
        "signature": signature,
        "response_ciphertext": NONCE + response_body + response_tag,
        "response_plaintext": response_plain,
    }


def c_bytes(name, data):
    lines = [f"static const unsigned char {name}[] = {{"]
    for offset in range(0, len(data), 12):
        chunk = data[offset:offset + 12]
        lines.append("    " + " ".join(f"0x{b:02x}," for b in chunk))
    lines.append("};")
    return "\n".join(lines)


def emit_header():
    vectors = build_vectors()
    out = [
        "/* SPDX-License-Identifier: GPL-2.0-or-later */",
        "/*",
        " * Generated by tests/cloud_relay_kat_reference.py. Do not edit by hand.",
        " *",
        " * Every value below comes from a from-scratch RFC implementation that is",
        " * self-checked against the RFC 7748 / 5869 / 8439 / 8032 vectors, so a",
        " * match here means the OpenSSL-based router code agrees with an outside",
        " * implementation of the same contract the iOS App ships.",
        " */",
        "#ifndef CLOUD_RELAY_KAT_VECTORS_H",
        "#define CLOUD_RELAY_KAT_VECTORS_H",
        "",
        f'#define KAT_ROUTER_ID "{ROUTER_ID}"',
        f'#define KAT_REQUEST_ID "{REQUEST_ID}"',
        "",
    ]
    for name in ("router_private", "router_public", "ephemeral_public",
                 "signing_public", "traffic_key", "ciphertext", "signature",
                 "response_ciphertext"):
        out.append(c_bytes("kat_" + name, vectors[name]))
        out.append("")
    out.append(c_bytes("kat_inner_plaintext", vectors["inner_plaintext"]))
    out.append("")
    out.append(c_bytes("kat_response_plaintext", vectors["response_plaintext"]))
    out.append("")
    out.append("#endif /* CLOUD_RELAY_KAT_VECTORS_H */")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    message = selftest()
    if "--selftest" in sys.argv:
        print("ok: " + message)
    else:
        sys.stdout.write(emit_header())
