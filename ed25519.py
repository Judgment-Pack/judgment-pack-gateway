"""Ed25519 signing and verification, following the reference construction in
RFC 8032 section 6.

Why this file exists at all: the gateway is standard-library-only by design, and
Python's standard library has no asymmetric signature primitive. Verification is
the property this whole repo exists to provide, so the choice was between adding
a dependency and carrying a small, auditable implementation of a well-specified
algorithm. This is the second.

    !! NOT CONSTANT TIME. NOT FOR A REAL KEY. !!

This is arithmetic on Python integers. It leaks timing, it is slow, and it must
not hold a signing key that matters. It exists so the reference can demonstrate
and specify signed receipts, and so the corpus can carry signed vectors. A
deployment signs with a vetted implementation -- Go's standard library has
`crypto/ed25519`, which is one more reason the deployable belongs in Go.

Correctness is not taken on faith: `test_ed25519.py` checks this against RFC 8032
section 7.1's published vectors AND cross-checks signing and verification against
the `cryptography` package when it is installed, which it is not at runtime.

Ed25519 is chosen over ECDSA specifically because its signatures are
deterministic: there is no per-signature nonce, so there is no nonce-reuse
failure mode, which is the way hand-rolled ECDSA usually loses the key.
"""

import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493  # group order

SIGNATURE_BYTES = 64
PUBLIC_KEY_BYTES = 32
SEED_BYTES = 32


class SignatureError(Exception):
    """A signature does not verify, or a key or signature is malformed."""


def _modp_inv(x):
    return pow(x, P - 2, P)


_D = -121665 * _modp_inv(121666) % P
_MODP_SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _MODP_SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_G_Y = 4 * _modp_inv(5) % P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % P)


# Points are (X, Y, Z, T) in extended coordinates, so the scalar ladder needs no
# modular inversion -- only the final compression does.
def _point_add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * _D % P
    dd = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(scalar, point):
    result = (0, 1, 1, 0)  # the neutral element
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(p1, p2):
    if (p1[0] * p2[2] - p2[0] * p1[2]) % P != 0:
        return False
    return (p1[1] * p2[2] - p2[1] * p1[2]) % P == 0


def _point_compress(point):
    inv_z = _modp_inv(point[2])
    x = point[0] * inv_z % P
    y = point[1] * inv_z % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(data):
    if len(data) != 32:
        raise SignatureError("a compressed point is 32 bytes")
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        raise SignatureError("point is not on the curve")
    return (x, y, 1, x * y % P)


def _sha512_int(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand_seed(seed):
    if len(seed) != SEED_BYTES:
        raise SignatureError("an Ed25519 seed is %d bytes" % SEED_BYTES)
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8      # clear the low 3 bits
    scalar |= 1 << 254            # set bit 254
    return scalar, digest[32:]


def public_key(seed):
    """The 32-byte public key for a 32-byte seed."""
    scalar, _prefix = _expand_seed(seed)
    return _point_compress(_point_mul(scalar, _G))


def sign(seed, message):
    """A 64-byte detached signature. Deterministic: same seed and message always
    produce the same signature, so there is no nonce to reuse."""
    scalar, prefix = _expand_seed(seed)
    encoded_public = _point_compress(_point_mul(scalar, _G))
    r = _sha512_int(prefix + message) % L
    encoded_r = _point_compress(_point_mul(r, _G))
    k = _sha512_int(encoded_r + encoded_public + message) % L
    s = (r + k * scalar) % L
    return encoded_r + int.to_bytes(s, 32, "little")


def verify(public, message, signature):
    """True if `signature` is a valid Ed25519 signature. Never raises for an
    ordinary bad signature -- a forgery attempt is an expected input, not an
    error -- but does raise SignatureError for a malformed key or signature."""
    if len(public) != PUBLIC_KEY_BYTES:
        raise SignatureError("an Ed25519 public key is %d bytes" % PUBLIC_KEY_BYTES)
    if len(signature) != SIGNATURE_BYTES:
        raise SignatureError("an Ed25519 signature is %d bytes" % SIGNATURE_BYTES)
    try:
        point_a = _point_decompress(public)
        point_r = _point_decompress(signature[:32])
    except SignatureError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False  # non-canonical S; reject rather than let it be malleable
    k = _sha512_int(signature[:32] + public + message) % L
    return _point_equal(_point_mul(s, _G),
                        _point_add(point_r, _point_mul(k, point_a)))
