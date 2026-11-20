// Key rotation (SPEC.md §3b): the walk of a registry's lines from the key
// pinned, following each rotation -- a key-rotation the current key signed,
// naming the next key, and on the line after it a key-continuation the next
// key signed -- and stopping at the first statement that is not so, with
// its finding. A line that is not a rotation statement is a seal, or
// nothing, under the key current at it.

import * as crypto from "node:crypto";

import { keyObject, p256KeySound, recordAlg, verifyByAlg } from "./alg.ts";
import type { Alg } from "./alg.ts";
import { canonical } from "./canon.ts";
import { hasDuplicate, member, parse } from "./json.ts";
import type { ObjectValue, Value } from "./json.ts";
import { keyRefusal } from "./witness.ts";

export type RotationStatus = "rotation-break" | "rotation-forged" | "rotation-order" | "rotation-key-refused";

// A key the walk reached: the key pinned first, then each key a followed
// rotation rotated to, each with the algorithm it was reached with: the pin's, or
// its rotation's nextAlg (ADR-0053 §7).
export type ReachedKey = { readonly raw: Uint8Array; readonly keyId: string; readonly alg: Alg; readonly key: crypto.KeyObject | null };

const prefix = "judgment-pack-gateway/rotation/1:";
const maxRotation = 2n ** 53n - 2n;
const timeForm = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const hexOf = (n: number) => new RegExp(`^[0-9a-f]{${n}}$`);
const hex32 = hexOf(32);
const hex64 = hexOf(64);
const hex66 = hexOf(66);
const hex128 = hexOf(128);

const members: Record<string, readonly string[]> = {
  "key-rotation": ["kind", "rotationVersion", "rotation", "rotatedAt", "keyId", "next", "nextKeyId", "signature"],
  "key-continuation": ["kind", "rotationVersion", "rotation", "rotatedAt", "keyId", "previous", "previousKeyId", "signature"],
};
// The members a statement holds where a P-256 key signs it (alg) or is the
// key it names (nextAlg, previousAlg), each then "ES256" (ADR-0053 §1, §7).
const optional: Record<string, readonly string[]> = {
  "key-rotation": ["alg", "nextAlg"],
  "key-continuation": ["alg", "previousAlg"],
};

export function reached(raw: Uint8Array, alg: Alg = ""): ReachedKey {
  return { raw, keyId: crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32), alg, key: keyObject(alg, raw) };
}

// keySound is the key rule of alg: Ed25519's of SPEC.md §8.4, or a
// compressed P-256 point that exists.
function keySound(alg: Alg, raw: Uint8Array): boolean {
  return alg === "" ? keyRefusal(raw) === null : p256KeySound(raw);
}

// A rotation statement that holds its form.
type Statement = {
  readonly kind: string;
  readonly rotation: bigint;
  readonly rotatedAt: string;
  readonly keyId: string;
  // alg is the statement's signer's algorithm, and namedAlg the named key's.
  readonly alg: Alg;
  readonly namedAlg: Alg;
  // named is the key the statement names: next, or previous.
  readonly named: Uint8Array;
  readonly namedId: string;
  readonly signature: string;
  readonly value: ObjectValue;
};

// rotationKind is the kind of a line that is a rotation statement -- one
// JSON object in the canonical domain, no name given twice, whose kind is
// one of the two -- with its value; null for any other line.
export function rotationKind(v: Value | null): { readonly kind: string; readonly value: ObjectValue } | null {
  if (v === null || v.type !== "object" || hasDuplicate(v) || canonical(v) === null) {
    return null;
  }
  const kind = member(v, "kind");
  if (kind?.type !== "string" || members[kind.value] === undefined) {
    return null;
  }
  return { kind: kind.value, value: v };
}

function str(v: Value | undefined, form: RegExp): string | null {
  return v?.type === "string" && form.test(v.value) ? v.value : null;
}

// statementOf holds a rotation statement to its form: exactly the members
// of its kind, each of its form, the key id beside the key it names that
// key's id.
function statementOf(kind: string, v: ObjectValue): Statement | null {
  const names = members[kind]!;
  const extra = optional[kind]!;
  if (!names.every((name) => member(v, name) !== undefined) || !v.members.every((m) => names.includes(m.name) || extra.includes(m.name))) {
    return null;
  }
  const [named, namedIdName, namedAlgName] = kind === "key-rotation" ? ["next", "nextKeyId", "nextAlg"] : ["previous", "previousKeyId", "previousAlg"];
  const alg = recordAlg(v, "alg");
  const namedAlg = recordAlg(v, namedAlgName!);
  const rotation = member(v, "rotation");
  const rotatedAt = str(member(v, "rotatedAt"), timeForm);
  const keyId = str(member(v, "keyId"), hex32);
  const namedHex = str(member(v, named!), namedAlg === "ES256" ? hex66 : hex64);
  const namedId = str(member(v, namedIdName!), hex32);
  const signature = str(member(v, "signature"), hex128);
  if (
    alg === null ||
    namedAlg === null ||
    str(member(v, "rotationVersion"), /^1$/) === null ||
    rotation?.type !== "number" ||
    rotation.integer === null ||
    rotation.integer < 1n ||
    rotation.integer > maxRotation ||
    rotatedAt === null ||
    keyId === null ||
    namedHex === null ||
    namedId === null ||
    signature === null
  ) {
    return null;
  }
  const raw = Buffer.from(namedHex, "hex");
  if (crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32) !== namedId) {
    return null;
  }
  return { kind, rotation: rotation.integer, rotatedAt, keyId, alg, namedAlg, named: raw, namedId, signature, value: v };
}

// signedBy is whether the statement's signature verifies under the key by
// the algorithm the statement's alg names, which the key must be of, over
// the prefix and the canonical form of everything but the signature.
function signedBy(st: Statement, key: ReachedKey): boolean {
  const body = canonical({ type: "object", members: st.value.members.filter((m) => m.name !== "signature") });
  if (body === null) {
    return false;
  }
  return verifyByAlg(st.alg, key, Buffer.concat([Buffer.from(prefix, "utf8"), body]), st.signature);
}

// RegistryWalk takes the registry's lines in order. A line it does not take
// is the caller's to read as a seal, under current().
export class RegistryWalk {
  readonly keys: ReachedKey[];
  finding: { readonly status: RotationStatus; readonly rotation: number } | null = null;
  // pending is a key-rotation that passed checks 1 to 4, waiting for the
  // line after it.
  private pending: Statement | null = null;
  private readonly onKey: (k: ReachedKey) => void;

  constructor(pinned: Uint8Array, pinnedAlg: Alg, onKey: (k: ReachedKey) => void) {
    this.keys = [reached(pinned, pinnedAlg)];
    this.onKey = onKey;
  }

  current(): ReachedKey {
    return this.keys[this.keys.length - 1]!;
  }

  followed(): number {
    return this.keys.length - 1;
  }

  private stop(status: RotationStatus): void {
    this.finding = { status, rotation: this.followed() + 1 };
  }

  // take is whether the walk takes a line -- a rotation statement, or the
  // continuation of a rotation -- given the line's value, or null for a
  // line that is no JSON value. A line it does not take is no rotation
  // statement.
  take(v: Value | null): boolean {
    const statement = rotationKind(v);
    if (this.pending !== null) {
      const forward = this.pending;
      this.pending = null;
      const reverse = statement?.kind === "key-continuation" ? statementOf(statement.kind, statement.value) : null;
      const from = this.current();
      if (
        reverse !== null &&
        reverse.rotation === forward.rotation &&
        reverse.rotatedAt === forward.rotatedAt &&
        // the pair (check 5): the continuation's alg is the rotation's
        // nextAlg, its previous and previousAlg the current key's bytes and
        // algorithm, and it verifies under next by that algorithm
        reverse.alg === forward.namedAlg &&
        reverse.namedAlg === from.alg &&
        Buffer.from(reverse.named).equals(Buffer.from(from.raw)) &&
        reverse.keyId === forward.namedId &&
        signedBy(reverse, reached(forward.named, forward.namedAlg))
      ) {
        const k = reached(forward.named, forward.namedAlg);
        this.onKey(k);
        this.keys.push(k);
        return true;
      }
      this.stop("rotation-break");
    }
    if (statement === null) {
      return false;
    }
    if (this.finding !== null) {
      // past a finding nothing is followed, and a rotation statement is
      // never a seal
      return true;
    }
    if (statement.kind === "key-continuation") {
      this.stop("rotation-forged");
      return true;
    }
    const st = statementOf(statement.kind, statement.value);
    if (st === null) {
      this.stop("rotation-break");
      return true;
    }
    const current = this.current();
    // the signer's algorithm is the current key's, and its signature
    // verifies by it (check 2)
    if (st.keyId !== current.keyId || st.alg !== current.alg || !signedBy(st, current)) {
      this.stop("rotation-forged");
      return true;
    }
    if (st.rotation !== BigInt(this.followed() + 1)) {
      this.stop("rotation-order");
      return true;
    }
    // the key named holds nextAlg's key rule, and its key id is none of a
    // key reached, of either algorithm (check 4)
    if (!keySound(st.namedAlg, st.named) || this.keys.some((k) => k.keyId === st.namedId)) {
      this.stop("rotation-key-refused");
      return true;
    }
    this.pending = st;
    return true;
  }

  // end is the registry's end: a rotation waiting for its continuation
  // has none.
  end(): void {
    if (this.pending !== null) {
      this.pending = null;
      this.stop("rotation-break");
    }
  }
}
