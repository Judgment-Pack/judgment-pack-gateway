// The checkpoint witness's statement, and the reading of a chain of them
// (SPEC.md §8): the statement's form, the runtime's public-key rule and its
// one equation, and the chain rule, within the bounds of one reading. A
// witness signs the runtime's audit checkpoints and chains its statements
// per trail; a reader is given the keys it trusts, the statements, and,
// when it has fetched one, the witness's head.

import * as crypto from "node:crypto";

import { canonical } from "./canon.ts";
import { NoVerdict, code, readDocument, withRegular } from "./inputs.ts";
import { TooLarge, count, hasDuplicate, member, parse } from "./json.ts";
import type { ObjectValue, Value } from "./json.ts";

const prefix = "judgment-pack-gateway/witness/1:";

// The bounds of one reading (§8.7).
export const witnessBounds = { keys: 16, bytes: 64 << 20, statements: 110000 };

// A statement holds thirteen values; a line holding more is no statement,
// and is not parsed past them.
const statementValues = 64;

// The largest index or sequence a statement holds, 2^53 - 2.
const maxInteger = 2n ** 53n - 2n;

export type Refusal = "keys-over-bound" | "key-not-canonical" | "key-small-order" | "key-not-on-curve" | "bytes-over-bound" | "statements-over-bound";

export type Finding =
  | "witness-malformed"
  | "witness-signature-invalid"
  | "witness-trail-mismatch"
  | "witness-equivocation"
  | "witness-chain-broken"
  | "witness-head-unreached";

// An answer: a refusal, or findings, or what a chain with none says.
export type Answer =
  | { readonly refused: Refusal }
  | { readonly ok: false; readonly findings: Finding[] }
  | {
      readonly ok: true;
      readonly findings: [];
      readonly reading: "current" | "historical";
      readonly headIndex: number | null;
      readonly highestIndex: number;
      readonly latestCheckpoint: { readonly index: number; readonly sequence: number; readonly witnessedAt: string };
      readonly conflicts: number[];
      readonly retired: boolean;
    };

// --- the key rule (§8.4) ----------------------------------------------------

const p = 2n ** 255n - 19n;

function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  base %= p;
  while (exponent > 0n) {
    if (exponent & 1n) {
      result = (result * base) % p;
    }
    base = (base * base) % p;
    exponent >>= 1n;
  }
  return result;
}

const d = (((-121665n * power(121666n, p - 2n)) % p) + p) % p;

// The eight points whose order divides 8, by their canonical encodings.
const smallOrder = new Set([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]);

// keyRefusal is why a reader may not trust 32 bytes as a witness key, or
// null: they must be the canonical encoding of a point of the curve whose
// order does not divide 8, read as written -- y the low 255 bits,
// little-endian, the top bit the sign of x -- and held, in order, to being
// canonical, to not being of small order, and to being a point.
export function keyRefusal(key: Uint8Array): Refusal | null {
  if (key.length !== 32) {
    return "key-not-on-curve";
  }
  let encoded = 0n;
  for (let i = 31; i >= 0; i--) {
    encoded = (encoded << 8n) | BigInt(key[i]!);
  }
  const sign = encoded >> 255n;
  const y = encoded & ((1n << 255n) - 1n);
  if (y >= p) {
    return "key-not-canonical";
  }
  const numerator = (((y * y - 1n) % p) + p) % p;
  if (numerator === 0n && sign === 1n) {
    return "key-not-canonical";
  }
  if (smallOrder.has(Buffer.from(key).toString("hex"))) {
    return "key-small-order";
  }
  // x² = (y² - 1) / (d·y² + 1) has a root exactly when it is 0 or its
  // Legendre symbol is 1.
  const xx = (numerator * power((d * y * y + 1n) % p, p - 2n)) % p;
  if (xx !== 0n && power(xx, (p - 1n) / 2n) !== 1n) {
    return "key-not-on-curve";
  }
  return null;
}

// --- the statement (§8.2, §8.3) ---------------------------------------------

type Statement = {
  readonly kind: "checkpoint" | "conflict" | "retirement";
  readonly trail: string;
  readonly sequence: bigint;
  // checkpoint is its canonical bytes, the checkpoint line without its
  // newline; whole, the statement's, by which two copies are one.
  readonly checkpoint: string;
  readonly index: bigint;
  readonly prev: string | null;
  readonly witnessedAt: string;
  readonly keyId: string;
  readonly signature: string;
  readonly whole: string;
  readonly signed: Buffer;
};

const statementMembers = ["checkpoint", "index", "keyId", "kind", "prevSignature", "signature", "witnessVersion", "witnessedAt"];
const checkpointMembers = ["checkpointVersion", "recordDigest", "sequence", "trail"];
const timeForm = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;

function exactly(o: ObjectValue, names: string[]): boolean {
  return o.members.length === names.length && names.every((n) => count(o, n) === 1);
}

function text(v: Value | undefined, form: RegExp): string | null {
  return v?.type === "string" && form.test(v.value) ? v.value : null;
}

// integer is a member spelled in digits alone, no sign, fraction or
// exponent, from least to 2^53 - 2.
function integer(v: Value | undefined, least: bigint): bigint | null {
  if (v?.type !== "number" || !/^[0-9]+$/.test(v.text) || v.integer === null || v.integer < least || v.integer > maxInteger) {
    return null;
  }
  return v.integer;
}

const hex = (n: number) => new RegExp(`^[0-9a-f]{${n}}$`);
const hex32 = hex(32);
const hex128 = hex(128);
const digestForm = /^sha256:[0-9a-f]{64}$/;

// statementOf reads one line by its JSON value and holds it to the form of
// §8.2, or is null for a line that is malformed.
function statementOf(line: Uint8Array): Statement | null {
  let v: Value | null;
  try {
    v = parse(line, statementValues);
  } catch (e) {
    if (e instanceof TooLarge) {
      return null;
    }
    throw e;
  }
  if (v === null || v.type !== "object" || hasDuplicate(v) || !exactly(v, statementMembers)) {
    return null;
  }
  const kind = text(member(v, "kind"), /^(?:checkpoint|conflict|retirement)$/) as Statement["kind"] | null;
  const witnessedAt = text(member(v, "witnessedAt"), timeForm);
  const keyId = text(member(v, "keyId"), hex32);
  const signature = text(member(v, "signature"), hex128);
  const index = integer(member(v, "index"), 0n);
  const prevV = member(v, "prevSignature");
  const prev = prevV?.type === "null" ? null : text(prevV, hex128);
  const cp = member(v, "checkpoint");
  if (
    text(member(v, "witnessVersion"), /^1$/) === null ||
    kind === null ||
    witnessedAt === null ||
    keyId === null ||
    signature === null ||
    index === null ||
    (prevV?.type !== "null" && prev === null) ||
    cp?.type !== "object" ||
    !exactly(cp, checkpointMembers)
  ) {
    return null;
  }
  const trail = text(member(cp, "trail"), hex32);
  const sequence = integer(member(cp, "sequence"), 1n);
  if (text(member(cp, "checkpointVersion"), /^1$/) === null || trail === null || sequence === null || text(member(cp, "recordDigest"), digestForm) === null) {
    return null;
  }
  const whole = canonical(v);
  const checkpoint = canonical(cp);
  const unsigned = canonical({ type: "object", members: v.members.filter((m) => m.name !== "signature") });
  if (whole === null || checkpoint === null || unsigned === null) {
    return null;
  }
  return {
    kind,
    trail,
    sequence,
    checkpoint: Buffer.from(checkpoint).toString("latin1"),
    index,
    prev,
    witnessedAt,
    keyId,
    signature,
    whole: Buffer.from(whole).toString("latin1"),
    signed: Buffer.concat([Buffer.from(prefix, "ascii"), unsigned]),
  };
}

// keyIdOf is §1.2's: the first 32 hex characters of the SHA-256 of the key.
function keyIdOf(key: Uint8Array): string {
  return crypto.createHash("sha256").update(key).digest("hex").slice(0, 32);
}

// verifies is the equation of §8.4 under a key that passed the key rule:
// S below L, and the canonical encoding of [S]B - [h]A equal to R byte for
// byte. Node's Ed25519, OpenSSL's, verifies exactly so: it refuses S of L
// or more and compares the encoding of the point it computes with R, with
// no cofactor (the corpus's signature vectors hold it to that).
function verifies(key: crypto.KeyObject, st: Statement): boolean {
  return crypto.verify(null, st.signed, key, Buffer.from(st.signature, "hex"));
}

// Collected is the statement lines of a reading's files, or, past the
// bound, how many lines were counted before the split stopped.
export type Collected =
  | { readonly within: true; readonly lines: Uint8Array[]; readonly headLines: Uint8Array[] }
  | { readonly within: false; readonly counted: number };

// collectLines splits the statements files, in order, and then the head
// file into statement lines -- up to each 0x0A, the piece after the last one
// included, less those that are empty or hold only spaces, tabs and
// carriage returns -- counting them as it splits. At the line past limit it
// stops: it keeps no more lines and splits nothing further, so a file of
// many short lines costs no more than limit statements do (§8.7).
export function collectLines(files: Uint8Array[], head: Uint8Array | null, limit: number): Collected {
  let counted = 0;
  const take = (file: Uint8Array, into: Uint8Array[]): boolean => {
    let start = 0;
    let blank = true;
    for (let i = 0; i <= file.length; i++) {
      const b = i < file.length ? file[i] : 0x0a;
      if (b === 0x0a) {
        if (!blank) {
          if (++counted > limit) {
            return false;
          }
          into.push(file.subarray(start, i));
        }
        start = i + 1;
        blank = true;
      } else if (b !== 0x20 && b !== 0x09 && b !== 0x0d) {
        blank = false;
      }
    }
    return true;
  };
  const lines: Uint8Array[] = [];
  const headLines: Uint8Array[] = [];
  for (const file of files) {
    if (!take(file, lines)) {
      return { within: false, counted };
    }
  }
  if (head !== null && !take(head, headLines)) {
    return { within: false, counted };
  }
  return { within: true, lines, headLines };
}

// --- the reading (§8.6) -----------------------------------------------------

export type Reading = {
  readonly trail: string;
  readonly keys: Uint8Array[];
  readonly files: Uint8Array[];
  readonly head: Uint8Array | null;
};

// readWitness reads one chain within the bounds of §8.7.
export function readWitness(r: Reading): Answer {
  if (r.keys.length > witnessBounds.keys) {
    return { refused: "keys-over-bound" };
  }
  const keys = new Map<string, crypto.KeyObject>();
  for (const key of r.keys) {
    const refusal = keyRefusal(key);
    if (refusal !== null) {
      return { refused: refusal };
    }
    keys.set(keyIdOf(key), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key).toString("base64url") }, format: "jwk" }));
  }
  let bytes = r.head?.length ?? 0;
  for (const f of r.files) {
    bytes += f.length;
  }
  if (bytes > witnessBounds.bytes) {
    return { refused: "bytes-over-bound" };
  }
  const collected = collectLines(r.files, r.head, witnessBounds.statements);
  if (!collected.within) {
    return { refused: "statements-over-bound" };
  }
  const supplied = collected.lines;
  const headLines = collected.headLines;

  // Step 1: the set, each statement once by its canonical bytes, held to
  // its form, its signature and its trail, the first failure its one
  // finding.
  const findings = new Set<Finding>();
  const byWhole = new Map<string, Statement>();
  const byLine = new Map<string, Statement | null>();
  const add = (line: Uint8Array): Statement | null => {
    const raw = Buffer.from(line).toString("latin1");
    let st = byLine.get(raw);
    if (st === undefined) {
      st = statementOf(line);
      if (st !== null) {
        st = byWhole.get(st.whole) ?? st;
        byWhole.set(st.whole, st);
      }
      byLine.set(raw, st);
    }
    if (st === null) {
      findings.add("witness-malformed");
    }
    return st;
  };
  for (const line of supplied) {
    add(line);
  }
  let head: Statement | null = null;
  if (r.head !== null) {
    if (headLines.length !== 1) {
      findings.add("witness-malformed");
    } else {
      head = add(headLines[0]!);
    }
  }
  const passing: Statement[] = [];
  for (const st of byWhole.values()) {
    const key = keys.get(st.keyId);
    if (key === undefined || !verifies(key, st)) {
      findings.add("witness-signature-invalid");
    } else if (st.trail !== r.trail) {
      findings.add("witness-trail-mismatch");
    } else {
      passing.push(st);
    }
  }
  // Step 2: two that passed, of one index, that differ.
  const indexes = new Set<bigint>();
  for (const st of passing) {
    if (indexes.has(st.index)) {
      findings.add("witness-equivocation");
    }
    indexes.add(st.index);
  }
  if (findings.size > 0) {
    return { ok: false, findings: [...findings].sort() };
  }

  // Step 3: the chain, less a head more than one index past every other
  // statement, walked in index order.
  let highestOther = -1n;
  for (const st of passing) {
    if (st !== head && st.index > highestOther) {
      highestOther = st.index;
    }
  }
  const unreached = head !== null && head.index > highestOther + 1n;
  const chain = passing.filter((st) => !(unreached && st === head)).sort((a, b) => (a.index < b.index ? -1 : 1));
  let latest: Statement | null = null;
  const conflicts: number[] = [];
  let broken = chain.length === 0;
  for (let i = 0; i < chain.length; i++) {
    const st = chain[i]!;
    const before = chain[i - 1];
    if (before === undefined) {
      broken ||= st.index !== 0n || st.prev !== null;
    } else {
      broken ||= st.index !== before.index + 1n || st.prev !== before.signature;
    }
    if (st.kind === "checkpoint") {
      broken ||= latest !== null && st.sequence <= latest.sequence;
      latest = st;
    } else if (st.kind === "conflict") {
      broken ||= latest === null || st.sequence > latest.sequence;
      conflicts.push(Number(st.sequence));
    } else {
      broken ||= latest === null || st.checkpoint !== latest.checkpoint || i !== chain.length - 1;
    }
  }
  if (broken) {
    findings.add("witness-chain-broken");
  }
  // Step 4: a head left out is a head the chain supplied does not reach.
  if (unreached) {
    findings.add("witness-head-unreached");
  }
  const last = chain[chain.length - 1];
  const found: Statement | null = latest;
  if (findings.size > 0 || last === undefined || found === null) {
    return { ok: false, findings: [...findings].sort() };
  }
  return {
    ok: true,
    findings: [],
    reading: head === null ? "historical" : "current",
    headIndex: head === null ? null : Number(head.index),
    highestIndex: Number(last.index),
    latestCheckpoint: { index: Number(found.index), sequence: Number(found.sequence), witnessedAt: found.witnessedAt },
    conflicts,
    retired: last.kind === "retirement",
  };
}

// sizeOf is a regular file's size; a file that cannot be opened, or is not
// one regular file, is no answer.
function sizeOf(path: string): number {
  try {
    return withRegular(path, "a witness file", (_fd, size) => size);
  } catch (e) {
    if (e instanceof NoVerdict) {
      throw e;
    }
    throw new NoVerdict(`a witness file ${JSON.stringify(path)} cannot be read: ${code(e) ?? String(e)}`);
  }
}

// readWitnessFiles reads a chain from files, as the process contract's
// `witness` command names them: a key file holds 64 hexadecimal characters,
// whitespace around them allowed; the statements files' and the head file's
// sizes are held to the byte bound before any of them is read. A file that
// cannot be read is no answer (NoVerdict).
export function readWitnessFiles(trail: string, keyPaths: string[], statementPaths: string[], headPath: string | null): Answer {
  if (keyPaths.length > witnessBounds.keys) {
    return { refused: "keys-over-bound" };
  }
  const keys = keyPaths.map((k) => {
    const t = Buffer.from(readDocument(k, "the witness key")).toString("latin1").trim();
    if (!/^[0-9a-fA-F]{64}$/.test(t)) {
      throw new NoVerdict(`the witness key ${JSON.stringify(k)} is not 64 hexadecimal characters`);
    }
    return Buffer.from(t, "hex");
  });
  for (const key of keys) {
    const refusal = keyRefusal(key);
    if (refusal !== null) {
      return { refused: refusal };
    }
  }
  const paths = headPath === null ? statementPaths : [...statementPaths, headPath];
  let total = 0;
  for (const path of paths) {
    total += sizeOf(path);
  }
  if (total > witnessBounds.bytes) {
    return { refused: "bytes-over-bound" };
  }
  const read = paths.map((path) => readDocument(path, "a witness file"));
  return readWitness({
    trail,
    keys,
    files: headPath === null ? read : read.slice(0, -1),
    head: headPath === null ? null : read[read.length - 1]!,
  });
}
