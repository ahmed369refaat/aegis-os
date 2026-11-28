#!/usr/bin/env python3
"""K27: generate the ChaCha20 / Poly1305 / AEAD / HKDF test vectors —
the RFC 8439 §2.4.2, §2.5.2 and §2.8.2 vectors computed by literal
Python implementations (straight from the RFC text), cross-checked
against the `cryptography` library. Print the exact expected bytes
for the Rust suite."""

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hmac, hashlib, os


def rotl(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl(s[b] ^ s[c], 7)


def chacha_block(key, counter, nonce):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += [int.from_bytes(key[4 * i : 4 * i + 4], "little") for i in range(8)]
    s.append(counter)
    s += [int.from_bytes(nonce[4 * i : 4 * i + 4], "little") for i in range(3)]
    w = s[:]
    for _ in range(10):
        qr(w, 0, 4, 8, 12)
        qr(w, 1, 5, 9, 13)
        qr(w, 2, 6, 10, 14)
        qr(w, 3, 7, 11, 15)
        qr(w, 0, 5, 10, 15)
        qr(w, 1, 6, 11, 12)
        qr(w, 2, 7, 8, 13)
        qr(w, 3, 4, 9, 14)
    return b"".join(
        ((w[i] + s[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16)
    )


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i : i + 16]
        n = int.from_bytes(blk + b"\x01", "little")
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def chacha_keystream(key, start_ctr, nonce, n):
    out = b""
    c = start_ctr
    while len(out) < n:
        out += chacha_block(key, c, nonce)
        c += 1
    return out[:n]


def aead_tag(key, nonce, ct, aad):
    # RFC 8439 §2.6: the poly key is block 0's first 32 bytes
    pk = chacha_block(key, 0, nonce)[:32]
    pad_aad = (-len(aad)) % 16
    pad_ct = (-len(ct)) % 16
    mac = aad + b"\x00" * pad_aad + ct + b"\x00" * pad_ct
    mac += len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    return poly1305(pk, mac)


def aead_seal(key, nonce, pt, aad):
    ct = bytes(a ^ b for a, b in zip(pt, chacha_keystream(key, 1, nonce, len(pt))))
    return ct + aead_tag(key, nonce, ct, aad)


# ── RFC 8439 §2.4.2: the block test ──
key = bytes(range(32))
nonce = bytes.fromhex("000000090000004a00000000")
b1 = chacha_block(key, 1, nonce)
print("§2.4.2 block:", b1.hex())
two = ChaCha20Poly1305(key).encrypt(nonce, b"\x00" * 128, b"")[:-16]
print("block1 == lib[0:64]:", two[:64] == b1)
print("block2 == lib[64:128]:", two[64:128] == chacha_block(key, 2, nonce))

# ── RFC 8439 §2.5.2: the poly1305 test ──
pkey = bytes.fromhex(
    "85d6be7857556d337f4452fe42d506a8010380af560fb2fd4abff6af4149f51b"
)
msg = b"Cryptographic Forum Research Group"
print("§2.5.2 tag:", poly1305(pkey, msg).hex())

# ── RFC 8439 §2.8.2: the AEAD test ──
akey = bytes(range(32))
anonce = bytes.fromhex("070000004041424344454647")
pt = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you "
    b"only one tip for the future, sunscreen would be it."
)
aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
sealed = aead_seal(akey, anonce, pt, aad)
ct, tag = sealed[:-16], sealed[-16:]
print("§2.8.2 ct[:32]:", ct[:32].hex())
print("§2.8.2 ct tail:", ct[-16:].hex())
print("§2.8.2 tag:", tag.hex())
lib = ChaCha20Poly1305(akey).encrypt(anonce, pt, aad)
print("library == mine:", lib == sealed)

# ── randomized AEAD pairs for embedding ──
print("\n# embedded random AEAD pairs:")
for _ in range(3):
    k = os.urandom(32)
    n = os.urandom(12)
    m = os.urandom(64)
    a = os.urandom(13)
    mine = aead_seal(k, n, m, a)
    lc = ChaCha20Poly1305(k).encrypt(n, m, a)
    ok = lc == mine
    print(
        f'  ("{k.hex()}", "{n.hex()}", "{m.hex()}", "{a.hex()}", '
        f'"{mine[:-16].hex()}", "{mine[-16:].hex()}"),  # lib agrees: {ok}'
    )

# ── HKDF: RFC 5869 test cases 1-3 ──
print("\n# HKDF RFC 5869:")


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, l):
    t = b""
    okm = b""
    i = 1
    while len(okm) < l:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:l]


tc = [
    (
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    ),
    (
        bytes.fromhex(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        ),
        bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e"
            "3f404142434445464748494a4b4c4d4e4f"
        ),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        82,
    ),
    (b"", bytes.fromhex("0b" * 22), b"", 42),
]
for idx, (salt, ikm, info, l) in enumerate(tc):
    prk = hkdf_extract(salt, ikm)
    okm = hkdf_expand(prk, info, l)
    print(f"case{idx + 1} prk: {prk.hex()}")
    print(f"case{idx + 1} okm: {okm.hex()}")
