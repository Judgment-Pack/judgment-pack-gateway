// The key history's consumer check (SPEC.md §3e; ADR-0052, ADR-0055): an
// answer of /publickey/history held, from the key pinned, to version 1's
// check or to version 2's, which marks each store continuation, so that a
// rotation given twice or passed over is refused from the history alone.
// A refusal names one of the classes the Go check names (ADR-0055 §9),
// which the corpus compares.

import * as crypto from "node:crypto";
import { recordAlg } from "./alg.ts";
import type { Alg } from "./alg.ts";
import { canonical } from "./canon.ts";
import { continuationOf, isContinuation } from "./continuation.ts";
import { hasDuplicate, member, parse } from "./json.ts";
import type { ObjectValue, Value } from "./json.ts";
import { keySound, reached, rotationKind, signedBy, statementOf } from "./rotation.ts";

export type KeyHistoryClass = "version" | "form" | "key" | "rotation" | "ordinal" | "time" | "continuation" | "carried";

// One key of a history; the key at a store rotation is one entry, its
// validTo its last.
export type KeyHistoryEntry = {
  readonly keyId: string;
  readonly alg: Alg;
  readonly raw: Uint8Array;
  readonly validFrom: string;
  validTo: string;
  readonly forward: string;
  readonly reverse: string;
};

export type KeyHistoryPin = { readonly alg: Alg; readonly key: Uint8Array };

export type KeyHistoryAnswer =
  | { readonly accepted: true; readonly version: "1" | "2"; readonly entries: KeyHistoryEntry[] }
  | { readonly accepted: false; readonly class: KeyHistoryClass; readonly reason: string };

class Refused extends Error {
  readonly cls: KeyHistoryClass;
  constructor(cls: KeyHistoryClass, reason: string) {
    super(reason);
    this.cls = cls;
  }
}

const timeForm = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const entryMembers = ["alg", "keyId", "publicKey", "validFrom", "validTo", "keyRotation", "keyContinuation"];
const keyIdOf = (raw: Uint8Array): string => crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32);
const same = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));
const only = (v: ObjectValue, names: readonly string[]): boolean => v.members.every((m) => names.includes(m.name));
const str = (s: string): Value => ({ type: "string", value: s });

// What a check carries from entry to entry, and across base and the
// stores: every keyId before, the last rotatedAt, and the latest of every
// rotatedAt and continuedAt.
type State = { seen: Set<string>; lastRotatedAt: string; latest: string };

// checkKeyHistory holds the answer's bytes to §3e's check from the key
// pinned (null to take the first entry's), its keyHistoryVersion read
// first; with requireVersion "2" an answer of version "1" is refused.
export function checkKeyHistory(bytes: Uint8Array, pin: KeyHistoryPin | null, options: { readonly requireVersion?: string } = {}): KeyHistoryAnswer {
  try {
    const require = options.requireVersion;
    if (require !== undefined && require !== "2") {
      throw new Refused("version", 'requireVersion is "2", or absent');
    }
    const v = parse(bytes);
    if (v === null || hasDuplicate(v)) {
      throw new Refused("form", "not one JSON object");
    }
    if (v.type !== "object") {
      throw new Refused("form", "not an object of keyHistoryVersion and keys");
    }
    const s: State = { seen: new Set(), lastRotatedAt: "", latest: "" };
    const version = member(v, "keyHistoryVersion");
    if (version?.type === "string" && version.value === "2") {
      return { accepted: true, version: "2", entries: version2(v, pin, s) };
    }
    if (version?.type !== "string" || version.value !== "1") {
      throw new Refused("version", 'keyHistoryVersion is not "1" or "2"');
    }
    if (require === "2") {
      throw new Refused("version", 'keyHistoryVersion is "1", and version "2" is required');
    }
    return { accepted: true, version: "1", entries: version1(v, pin, s) };
  } catch (e) {
    if (e instanceof Refused) {
      return { accepted: false, class: e.cls, reason: e.message };
    }
    throw e;
  }
}

function version1(v: ObjectValue, pin: KeyHistoryPin | null, s: State): KeyHistoryEntry[] {
  if (!only(v, ["keyHistoryVersion", "keys"])) {
    throw new Refused("form", "not an object of keyHistoryVersion and keys");
  }
  const keys = member(v, "keys");
  if (keys?.type !== "array" || keys.items.length === 0) {
    throw new Refused("form", "keys is not an array of at least one entry");
  }
  return keysHold(s, keys.items, (e) => pinnedFirst(e, pin), false, false);
}

function pinnedFirst(e: KeyHistoryEntry, pin: KeyHistoryPin | null): void {
  if (pin !== null && (e.alg !== pin.alg || !same(e.raw, pin.key))) {
    throw new Refused("key", `entry 0: key ${e.keyId} is not the key pinned`);
  }
}

// version2 is ADR-0055 §2: base, where present, of version 1's check; then
// each store, its first entry the key pinned or the last before it, its
// ordinals their places, and its continuation signed by its first key over
// the history before it, in time.
function version2(v: ObjectValue, pin: KeyHistoryPin | null, s: State): KeyHistoryEntry[] {
  if (!only(v, ["keyHistoryVersion", "stores", "base"])) {
    throw new Refused("form", "not an object of keyHistoryVersion, stores and base");
  }
  const stores = member(v, "stores");
  if (stores?.type !== "array" || stores.items.length === 0) {
    throw new Refused("form", "stores is not an array of at least one store");
  }
  const base = member(v, "base");
  let entries: KeyHistoryEntry[] = [];
  if (base !== undefined) {
    const version = base.type === "object" ? member(base, "keyHistoryVersion") : undefined;
    if (base.type !== "object" || version?.type !== "string" || version.value !== "1") {
      throw new Refused("form", 'base is not a history of version "1"');
    }
    entries = version1(base, pin, s);
  }
  stores.items.forEach((store, j) => {
    if (store.type !== "object" || !only(store, ["keys", "continuation"])) {
      throw new Refused("form", `store ${j}: not an object of keys and continuation`);
    }
    const joined = j > 0 || base !== undefined;
    const line = member(store, "continuation");
    if ((line !== undefined) !== joined || (line !== undefined && line.type !== "string")) {
      throw new Refused("form", `store ${j}: a continuation, a string, is held by every store but the first, and by the first where base is present, and by no other`);
    }
    const keys = member(store, "keys");
    if (keys?.type !== "array" || keys.items.length === 0) {
      throw new Refused("form", `store ${j}: keys is not an array of at least one entry`);
    }
    const first = (e: KeyHistoryEntry): void => {
      if (!joined) {
        pinnedFirst(e, pin);
        return;
      }
      const prev = entries[entries.length - 1]!;
      if (e.keyId !== prev.keyId || e.alg !== prev.alg || !same(e.raw, prev.raw)) {
        throw new Refused("key", `entry 0: key ${e.keyId} is not key ${prev.keyId}, the last before it`);
      }
      continuationHolds(s, line?.type === "string" ? line.value : "", e, historyBefore(base, stores.items.slice(0, j)));
    };
    const held = keysHold(s, keys.items, first, joined, true);
    if (joined) {
      entries[entries.length - 1]!.validTo = held[0]!.validTo;
      held.shift();
    }
    entries = [...entries, ...held];
  });
  return entries;
}

// historyBefore is the bytes of the history before a store: base, for the
// first, and otherwise canon of {base, keyHistoryVersion, stores}.
function historyBefore(base: Value | undefined, stores: Value[]): Uint8Array | null {
  if (stores.length === 0) {
    return base === undefined ? null : canonical(base);
  }
  const members = [...(base === undefined ? [] : [{ name: "base", value: base }]), { name: "keyHistoryVersion", value: str("2") }, { name: "stores", value: { type: "array" as const, items: stores } }];
  return canonical({ type: "object", members });
}

function continuationHolds(s: State, line: string, e: KeyHistoryEntry, before: Uint8Array | null): void {
  const v = parse(Buffer.from(line, "utf8"));
  if (v === null || !isContinuation(v)) {
    throw new Refused("continuation", "continuation is not a store continuation");
  }
  const c = continuationOf(v, reached(e.raw, e.alg));
  if (c === null) {
    throw new Refused("continuation", "continuation does not hold §3d's form, or is not of and signed by the store's first key");
  }
  const digest = before === null ? "" : crypto.createHash("sha256").update(before).digest("hex");
  if (digest !== c.history) {
    throw new Refused("carried", `continuation names the key history ${c.history}, not ${digest}, the history before it`);
  }
  if (c.at < s.latest) {
    throw new Refused("time", `continuation's continuedAt ${c.at} is before ${s.latest}, a rotatedAt or continuedAt before it`);
  }
  if (e.validTo !== "" && c.at > e.validTo) {
    throw new Refused("time", `continuation's continuedAt ${c.at} is after ${e.validTo}, the validTo of the store's first key`);
  }
  s.latest = c.at;
}

// keysHold is version 1's check of one list of entries; joined, its first
// entry is the key at a store rotation, already seen; with ordinals, each
// later entry's rotation is its place.
function keysHold(s: State, keys: Value[], first: (e: KeyHistoryEntry) => void, joined: boolean, ordinals: boolean): KeyHistoryEntry[] {
  const entries: KeyHistoryEntry[] = [];
  keys.forEach((kv, i) => {
    const e = entryOf(kv, i);
    if (i > 0 || !joined) {
      if (s.seen.has(e.keyId)) {
        throw new Refused("key", `entry ${i}: key ${e.keyId} is an earlier entry's`);
      }
      s.seen.add(e.keyId);
    }
    if (i === 0) {
      first(e);
      if (e.validFrom !== "" || e.forward !== "" || e.reverse !== "") {
        throw new Refused("form", "entry 0: the first key carries no validFrom and no rotation");
      }
    } else {
      const before = entries[i - 1]!;
      const { ordinal, at } = pairOf(before, e, i);
      if (ordinals && ordinal !== BigInt(i)) {
        throw new Refused("ordinal", `entry ${i}: the rotation's ordinal is ${ordinal}, not ${i}, its place in its store`);
      }
      if (e.validFrom !== at || before.validTo !== at) {
        throw new Refused("time", `entry ${i}: validFrom, and the validTo before it, are not the rotation's rotatedAt ${at}`);
      }
      if (s.lastRotatedAt !== "" && at < s.lastRotatedAt) {
        throw new Refused("time", `entry ${i}: the rotation's rotatedAt is before the rotatedAt of the rotation before it`);
      }
      s.lastRotatedAt = at;
      if (at > s.latest) {
        s.latest = at;
      }
    }
    if ((e.validTo === "") !== (i === keys.length - 1)) {
      throw new Refused("form", `entry ${i}: only the last entry, the key in force, has no validTo`);
    }
    entries.push(e);
  });
  return entries;
}

// entryOf holds one entry to its form (SPEC.md §3e's table; ADR-0053 §8).
function entryOf(v: Value, i: number): KeyHistoryEntry {
  if (v.type !== "object" || !only(v, entryMembers)) {
    throw new Refused("form", `entry ${i}: not an object of the entry's members`);
  }
  const alg = recordAlg(v, "alg");
  if (alg === null) {
    throw new Refused("form", `entry ${i}: alg is not "ES256"`);
  }
  const keyHex = member(v, "publicKey");
  const keyId = member(v, "keyId");
  const form = alg === "ES256" ? /^[0-9a-f]{66}$/ : /^[0-9a-f]{64}$/;
  if (keyHex?.type !== "string" || !form.test(keyHex.value) || keyId?.type !== "string") {
    throw new Refused("form", `entry ${i}: publicKey is not of its algorithm's form, or keyId is missing`);
  }
  const raw = Buffer.from(keyHex.value, "hex");
  if (keyIdOf(raw) !== keyId.value) {
    throw new Refused("key", `entry ${i}: keyId is not the key id of publicKey`);
  }
  if (!keySound(alg, raw)) {
    throw new Refused("key", `entry ${i}: publicKey is a key §8.4's rule refuses`);
  }
  const text = (name: string, time: boolean): string => {
    const m = member(v, name);
    if (m === undefined) {
      return "";
    }
    if (m.type !== "string" || m.value === "" || (time && !timeForm.test(m.value))) {
      throw new Refused("form", `entry ${i}: ${name} is not of its form`);
    }
    return m.value;
  };
  const e = { keyId: keyId.value, alg, raw, validFrom: text("validFrom", true), validTo: text("validTo", true), forward: text("keyRotation", false), reverse: text("keyContinuation", false) };
  if ((e.forward === "") !== (e.reverse === "")) {
    throw new Refused("form", `entry ${i}: keyRotation and keyContinuation are given together`);
  }
  return e;
}

// pairOf holds an entry's two statements to a rotation of §3b's form from
// the entry before it to it, the ordinal's place aside.
function pairOf(before: KeyHistoryEntry, e: KeyHistoryEntry, i: number): { readonly ordinal: bigint; readonly at: string } {
  const refused = (why: string): Refused => new Refused("rotation", `entry ${i}: ${why}`);
  const fwd = rotationKind(parse(Buffer.from(e.forward, "utf8")));
  const st = fwd?.kind === "key-rotation" ? statementOf(fwd.kind, fwd.value) : null;
  if (st === null) {
    throw refused("keyRotation is not a key-rotation statement of its form");
  }
  if (st.keyId !== before.keyId || st.alg !== before.alg || !signedBy(st, reached(before.raw, before.alg))) {
    throw refused("keyRotation is not signed by the key before it");
  }
  if (st.namedAlg !== e.alg || !same(st.named, e.raw)) {
    throw refused("keyRotation does not name this entry's key");
  }
  const rev = rotationKind(parse(Buffer.from(e.reverse, "utf8")));
  const r = rev?.kind === "key-continuation" ? statementOf(rev.kind, rev.value) : null;
  if (
    r === null ||
    r.rotation !== st.rotation ||
    r.rotatedAt !== st.rotatedAt ||
    r.alg !== e.alg ||
    r.namedAlg !== before.alg ||
    !same(r.named, before.raw) ||
    r.keyId !== e.keyId ||
    !signedBy(r, reached(e.raw, e.alg))
  ) {
    throw refused("keyContinuation is not the key-continuation of keyRotation, signed by this entry's key");
  }
  return { ordinal: st.rotation, at: st.rotatedAt };
}
