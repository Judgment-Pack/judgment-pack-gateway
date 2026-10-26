// Key rotation (SPEC.md §3b): the walk of a registry's lines from the key
// pinned, following each rotation -- a key-rotation the current key signed,
// naming the next key, and on the line after it a key-continuation the next
// key signed -- and stopping at the first statement that is not so, with
// its finding. A line that is not a rotation statement is a seal, or
// nothing, under the key current at it.

import * as crypto from "node:crypto";

import { canonical } from "./canon.ts";
import { hasDuplicate, member, parse } from "./json.ts";
import type { ObjectValue, Value } from "./json.ts";
import { keyRefusal } from "./witness.ts";

export type RotationStatus = "rotation-break" | "rotation-forged" | "rotation-order" | "rotation-key-refused";

// A key the walk reached: the key pinned first, then each key a followed
// rotation rotated to.
export type ReachedKey = { readonly raw: Uint8Array; readonly keyId: string; readonly key: crypto.KeyObject };

const prefix = "judgment-pack-gateway/rotation/1:";
const maxRotation = 2n ** 53n - 2n;
const timeForm = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const hexOf = (n: number) => new RegExp(`^[0-9a-f]{${n}}$`);
const hex32 = hexOf(32);
const hex64 = hexOf(64);
const hex128 = hexOf(128);

const members: Record<string, readonly string[]> = {
  "key-rotation": ["kind", "rotationVersion", "rotation", "rotatedAt", "keyId", "next", "nextKeyId", "signature"],
  "key-continuation": ["kind", "rotationVersion", "rotation", "rotatedAt", "keyId", "previous", "previousKeyId", "signature"],
};

export function reached(raw: Uint8Array): ReachedKey {
  return {
    raw,
    keyId: crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32),
    key: crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" }),
  };
}

// A rotation statement that holds its form.
type Statement = {
  readonly kind: string;
  readonly rotation: bigint;
  readonly rotatedAt: string;
  readonly keyId: string;
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
  if (v.members.length !== names.length || !v.members.every((m) => names.includes(m.name))) {
    return null;
  }
  const [named, namedIdName] = kind === "key-rotation" ? ["next", "nextKeyId"] : ["previous", "previousKeyId"];
  const rotation = member(v, "rotation");
  const rotatedAt = str(member(v, "rotatedAt"), timeForm);
  const keyId = str(member(v, "keyId"), hex32);
  const namedHex = str(member(v, named!), hex64);
  const namedId = str(member(v, namedIdName!), hex32);
  const signature = str(member(v, "signature"), hex128);
  if (
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
  return { kind, rotation: rotation.integer, rotatedAt, keyId, named: raw, namedId, signature, value: v };
}

// signedBy is whether the statement's signature verifies under the key,
// over the prefix and the canonical form of everything but the signature.
function signedBy(st: Statement, key: crypto.KeyObject): boolean {
  const body = canonical({ type: "object", members: st.value.members.filter((m) => m.name !== "signature") });
  if (body === null) {
    return false;
  }
  return crypto.verify(null, Buffer.concat([Buffer.from(prefix, "utf8"), body]), key, Buffer.from(st.signature, "hex"));
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

  constructor(pinned: Uint8Array, onKey: (k: ReachedKey) => void) {
    this.keys = [reached(pinned)];
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
        Buffer.from(reverse.named).equals(Buffer.from(from.raw)) &&
        reverse.keyId === forward.namedId &&
        signedBy(reverse, reached(forward.named).key)
      ) {
        const k = reached(forward.named);
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
    if (st.keyId !== current.keyId || !signedBy(st, current.key)) {
      this.stop("rotation-forged");
      return true;
    }
    if (st.rotation !== BigInt(this.followed() + 1)) {
      this.stop("rotation-order");
      return true;
    }
    if (keyRefusal(st.named) !== null || this.keys.some((k) => k.keyId === st.namedId)) {
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
