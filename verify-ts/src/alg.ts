// The two signature algorithms (ADR-0053): Ed25519, every record's since
// the first release, and ECDSA over P-256 with SHA-256, "ES256". A record
// names its algorithm in its alg member exactly when a P-256 key signs it,
// inside what is signed, and a record without the member is Ed25519. A
// verifier takes the algorithm from the record, never from a key's length,
// and verifies only under a key it was given with that algorithm: the pin,
// a rotation's nextAlg or previousAlg (verifyByAlg).

import * as crypto from "node:crypto";

import { member } from "./json.ts";
import type { ObjectValue } from "./json.ts";

// Alg is Ed25519's, the member absent, or ES256's.
export type Alg = "" | "ES256";
export const es256 = "ES256";

// The pin of a P-256 key: its 66 lowercase hexadecimal characters, beside
// the 32 raw bytes an Ed25519 key is pinned by.
export type Pin = { readonly alg: "ES256"; readonly key: string };

// A key with the algorithm it was given with; key is null for a key that
// does not hold its algorithm's key rule, under which nothing verifies.
export type HeldKey = { readonly alg: Alg; readonly key: crypto.KeyObject | null };

// P-256's field prime, curve constant b and group order n (FIPS 186-5).
const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
// (n - 1)/2, n odd: the low-S bound
const halfN = (n - 1n) / 2n;
// SubjectPublicKeyInfo of id-ecPublicKey on prime256v1, before a 33-byte
// compressed point
const spkiPrefix = Buffer.from("3039301306072a8648ce3d020106082a8648ce3d030107032200", "hex");

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  base %= m;
  for (; exp > 0n; exp >>= 1n) {
    if (exp & 1n) {
      r = (r * base) % m;
    }
    base = (base * base) % m;
  }
  return r;
}

// recordAlg is the algorithm a record's member names: Ed25519 where it is
// absent, ES256 where it is the string "ES256", and null for any other
// value, which is refused wherever the member sits (ADR-0053 §1).
export function recordAlg(v: ObjectValue, name: string): Alg | null {
  const m = member(v, name);
  if (m === undefined) {
    return "";
  }
  return m.type === "string" && m.value === es256 ? es256 : null;
}

// p256KeySound is §4's key rule: 33 bytes, the first 02 or 03, x below p,
// and x³ − 3x + b a square modulo p, so the point exists. The uncompressed
// form and every other length are refused.
export function p256KeySound(raw: Uint8Array): boolean {
  if (raw.length !== 33 || (raw[0] !== 2 && raw[0] !== 3)) {
    return false;
  }
  const x = BigInt("0x" + Buffer.from(raw.subarray(1)).toString("hex"));
  if (x >= p) {
    return false;
  }
  const rhs = (((((x * x) % p) * x - 3n * x + b) % p) + p) % p;
  return rhs === 0n || modPow(rhs, (p - 1n) / 2n, p) === 1n;
}

// keyObject is the key raw is under alg, or null where it does not hold
// the key rule of P-256; an Ed25519 key is held to its length alone here,
// as it always was.
export function keyObject(alg: Alg, raw: Uint8Array): crypto.KeyObject | null {
  try {
    if (alg === es256) {
      return p256KeySound(raw) ? crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, raw]), format: "der", type: "spki" }) : null;
    }
    return raw.length === 32 ? crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" }) : null;
  } catch {
    return null;
  }
}

// verifyByAlg is every signature check of the gateway's records: the
// signature, in hex, is alg's over message under key, which holds only
// where key was given with alg and its KeyObject is of alg's type (ed25519,
// or ec on prime256v1). An ES256 signature is r||s in 128 lowercase
// hexadecimal characters with 1 ≤ r ≤ n − 1 and 1 ≤ s ≤ (n − 1)/2,
// low-S, checked here since crypto.verify does not, and verified over
// SHA-256 of message, named, in IEEE P1363 form; a DER one and a high-S one
// do not verify. An Ed25519 signature's hex is of either case, as each
// caller's own form check leaves it.
export function verifyByAlg(alg: Alg, key: HeldKey, message: Uint8Array, signatureHex: string): boolean {
  if (key.alg !== alg || key.key === null) {
    return false;
  }
  if (alg === es256) {
    if (key.key.asymmetricKeyType !== "ec" || key.key.asymmetricKeyDetails?.namedCurve !== "prime256v1" || !/^[0-9a-f]{128}$/.test(signatureHex)) {
      return false;
    }
    const r = BigInt("0x" + signatureHex.slice(0, 64));
    const s = BigInt("0x" + signatureHex.slice(64));
    if (r < 1n || r > n - 1n || s < 1n || s > halfN) {
      return false;
    }
    return crypto.verify("sha256", message, { key: key.key, dsaEncoding: "ieee-p1363" }, Buffer.from(signatureHex, "hex"));
  }
  if (key.key.asymmetricKeyType !== "ed25519" || !/^(?:[0-9a-fA-F]{2}){64}$/.test(signatureHex)) {
    return false;
  }
  return crypto.verify(null, message, key.key, Buffer.from(signatureHex, "hex"));
}
