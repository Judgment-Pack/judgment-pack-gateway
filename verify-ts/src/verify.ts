// Registry-anchored verification of a store (SPEC.md §1.4, §4): each
// receipt by the ladder, each session's sequence and chain, each session
// against its seal, a version 3 action's citations and decision record, a
// decision record's own citations, and what an action claims of the
// runtime evaluation record it names.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import { canonical } from "./canon.ts";
import { continuationOf, isContinuation } from "./continuation.ts";
import { citations } from "./citations.ts";
import type { Citation } from "./citations.ts";
import {
  Budget,
  NoVerdict,
  checkSpellings,
  code,
  digestArtifact,
  digestSupplied,
  documentBound,
  eachDecisionRecord,
  eachEntry,
  eachRemovalLine,
  endsWith,
  entryCost,
  eachRegistryLine,
  locateDecisionRecords,
  locateRegistry,
  nameOf,
  nothingAt,
  readDocument,
  refuseUnsupportedPlatform,
  suppliedDirectory,
} from "./inputs.ts";
import { TooLarge, count, hasDuplicate, integerDigits, maxValues, member, parse } from "./json.ts";
import type { NumberValue, ObjectValue, Value } from "./json.ts";
import { p256KeySound, recordAlg, verifyByAlg } from "./alg.ts";
import type { Alg, Pin } from "./alg.ts";
import { RegistryWalk, rotationKind } from "./rotation.ts";
import type { ReachedKey, RotationStatus } from "./rotation.ts";
import { isScopeIdentifier, structureV2, structureV3 } from "./structure.ts";
import { descriptorStatus } from "./descriptors.ts";

export type Status =
  | "ok"
  | "malformed"
  | "unsupported-version"
  | "key-mismatch"
  | "signature-mismatch"
  | "misfiled"
  | "authority-mismatch"
  | "artifact-missing"
  | "artifact-mismatch"
  | "descriptor-provenance-missing"
  | "descriptor-provenance-mismatch";

// A finding, its members in the order written. A bigint is written as the
// integer it is.
export type Finding = ReadonlyArray<readonly [string, string | number | bigint | null]>;

// A verdict's findings are made again each time they are read, from what
// verification kept, so none is held for the verdict to be written; so are
// its observations (§4, "Observations"), which are no part of ok.
// Its witnesses are the distinct witnesses named by the receipts that
// passed the ladder (§4, ADR-0014), no part of ok either.
// Its rotations are those the walk of the registry followed from the key
// pinned (§3b), null when it followed none, no part of ok either.
export type Verdict = {
  readonly ok: boolean;
  readonly findings: Iterable<Finding>;
  readonly observations: Iterable<Finding>;
  readonly witnesses: Iterable<Witness>;
  readonly rotations: { readonly count: number; readonly keyId: string } | null;
  // A verdict by scope's cut (§4, "A verdict by scope"): the scope
  // identifier, the sessions of it, and those it could attribute to none,
  // each sorted; absent from a verdict of the whole store.
  readonly cut?: Cut;
};

// A cut by one scope identifier, as a verdict reports it.
export type Cut = { readonly scope: string; readonly sessions: readonly string[]; readonly unattributed: readonly string[] };

// A witness a receipt names: the trail it is named for, where it serves,
// and its key's identifier.
export type Witness = { readonly trail: string; readonly origin: string; readonly keyId: string };

// A receipt file as the ladder judged it, kept as no more than the rest of
// verification reads of it, each kept string its own and none long, so no
// receipt's size stays in memory past its turn.
type Delivery = { key: string; contract: string; outcome: string; identity: string; source: string; shape: string };
type Reconciliation = Delivery & { action: Citation };
type Judged = {
  readonly delivery?: Delivery;
  readonly reconciliation?: Reconciliation;
  readonly file: string;
  readonly status: Status;
  // Past order 1: the receipt's index, for its finding.
  readonly callIndex?: bigint;
  // For a receipt that passed with no bytes re-digested: what the artifact
  // step says of it (§1.3a), artifact-not-retained or artifact-removed.
  readonly observation?: string;
  // For a receipt past the signed orders (§1.4, orders 1 to 6): its
  // top-level scope, absent for none, which a seal naming a scope is held
  // to where the receipt passed (ADR-0036), and its scopeSalt, which one of
  // version 3 is taken over (ADR-0042); and signed, which a verdict by scope
  // attributes the session by (§4, "A verdict by scope").
  readonly signed?: true;
  readonly scope?: string;
  readonly scopeSalt?: string;
  // For a receipt that passed: what the chain walk reads of it, its key's
  // place among the keys the registry's walk reached among it (§3b).
  readonly chain?: { readonly version: string; readonly signature: string; readonly prev: Prev; readonly keyPos: number };
  // For a version 3 action that passed: the record it names, and its
  // bytes' SHA-256, by which its citations are read again once the
  // enumeration is whole; and what §4 step 8 compares with the record, the
  // pack it names and its citations as a set (citesKey).
  // exact is decision.recordBytes "exact": the record is found by a line's
  // exact bytes (§4 step 6).
  // witnessTrail is the trail an action's witness member names, which
  // the record found is held to (§4 step 8).
  readonly action?: {
    // approvals: action.approvals, for §4's approval-cited-again
    readonly approvals?: ReadonlyArray<{ readonly kind: string; readonly id: string; readonly digest: string }>;
    readonly recordDigest: string;
    readonly bytes: string;
    readonly packDigest: string;
    readonly citesKey: string;
    readonly exact: boolean;
    readonly witnessTrail?: string;
  };
  // For a version 3 receipt that passed and names a witness: the witness.
  readonly witness?: Witness;
};

// Claims is what §4 step 8 reads of a record an action names, when it is a
// runtime evaluation record: the pack digest it states, and its citations
// as a set -- null when its cites is not of the shape, which matches no set.
// Its trail is the record's trail member, null when it has none that is a
// string.
type Claims = { readonly packDigest: string; readonly citesKey: string | null; readonly trail: string | null };

// citesKey names a set of citations: the SHA-256 of each distinct one's
// three members, a line each, the lines sorted. No member holds a line
// break, so two sets have one key only when they are one set.
function citesKey(cites: Citation[]): string {
  const lines = [...new Set(cites.map((c) => `${c.sessionId}\n${c.callIndex}\n${c.signature}`))].sort();
  return sha256Hex(Buffer.from(lines.join("\n"), "utf8"));
}

// Prev is a prevSignature as the chain walk compares it: null, a string
// short enough to be a signature, or neither.
type Prev = { readonly kind: "null" } | { readonly kind: "string"; readonly value: string } | { readonly kind: "other" };

// own is a copy of a string held by nothing else: a string read out of a
// document can otherwise keep the whole document's text alive. The copy is
// made through a buffer, at the cost of its bytes whatever its length --
// Latin-1 when every code unit fits, so a one-byte string stays one, and
// UTF-16 otherwise, which keeps every code unit as it is.
function own(s: string): string {
  return /^[\u0000-\u00ff]*$/.test(s) ? Buffer.from(s, "latin1").toString("latin1") : Buffer.from(s, "utf16le").toString("utf16le");
}

// size is what a kept string is charged: two bytes a character, the most
// one takes.
function size(s: string): number {
  return 2 * s.length;
}

// limits.retainedBytes is what verification may keep, 256 MiB, charged to
// a Budget as it is kept: a store needing more is no verdict, refused as
// the charge that passes it is made. Only a test lowers it.
export const limits = { retainedBytes: 256 << 20 };

// sessionCost is what a session is charged beside its name: what is kept
// for it, empty or not -- its list of receipt files, its receipts as
// judged, its index of stems, and its entry in the map of each.
export const sessionCost = 4 * entryCost;

// receiptCost is what a receipt file is charged beside its name. What is
// kept of a receipt but its name is bounded: a status and an index; for
// one that passed, its version, its signature and a previous one of at
// most 128 characters; for an action, the record it names, its bytes'
// digest, the pack it names and the key of its citations; in the index,
// its signature when of a citation's form -- 655 characters at most,
// beside a few objects and their entries in maps and sets. A receipt file is charged all of it when it is met, and its name
// twice, in its session's list and as its stem, so a store is refused for
// its size before any receipt is read.
const receiptCost = 8 * entryCost;

const receiptPrefix: Record<string, string> = {
  "2": "judgment-pack-gateway/receipt/2:",
  "3": "judgment-pack-gateway/receipt/3:",
};
const sealPrefix = "judgment-pack-gateway/seal/2:";
// §3c: a seal made after an interruption, its own kind and its own domain.
const interruptionKind = "seal-after-interruption";
const interruptionPrefix = "judgment-pack-gateway/seal-after-interruption/1:";
const interruptionMembers = ["finalCount", "headSignature", "keyId", "kind", "sealedAt", "sealedVia", "sessionId", "signature"];
// A seal of version 2 (§3, "A seal of version 2"; ADR-0036): the seal of a
// session of a scope identifier, naming it under the signature by its
// digest in the session, never by the identifier, of either kind.
// sealVersion selects the form, and each is signed under a prefix of its
// own, so no form is read as another.
const scopedSealPrefix = "judgment-pack-gateway/seal-version/2:";
const interruptionPrefix2 = "judgment-pack-gateway/seal-after-interruption/2:";
const sealScopeDigestPrefix = "judgment-pack-gateway/seal-scope/1:";
const scopedSealMembers = ["finalCount", "keyId", "scopeDigest", "sealVersion", "sealedAt", "sessionId", "signature"];
const digestForm = /^sha256:[0-9a-f]{64}$/;
// A seal of version 3 (§3, "A seal of version 3"; ADR-0042): version 2's
// form, of either kind, whose scopeDigest is taken over the session's scope
// salt beside the identifier and the session's id. The salt is in every
// receipt of the session (scopeSalt) and in no registry line, so the registry
// alone tests no guessed identifier against the seal.
const saltedSealPrefix = "judgment-pack-gateway/seal-version/3:";
const interruptionPrefix3 = "judgment-pack-gateway/seal-after-interruption/3:";
const sealScopeSaltedDigestPrefix = "judgment-pack-gateway/seal-scope/2:";
const scopeSaltForm = /^[0-9a-f]{64}$/;

// saltedScopeDigest is what a seal of version 3 names a session's scope by:
// "sha256:" and the lowercase hex of SHA-256 over the prefix and the
// canonical form of {"salt", "scope", "sessionId"}.
function saltedScopeDigest(sessionId: string, scope: string, salt: string): string {
  const named: ObjectValue = {
    type: "object",
    members: [
      { name: "salt", value: { type: "string", value: salt } },
      { name: "scope", value: { type: "string", value: scope } },
      { name: "sessionId", value: { type: "string", value: sessionId } },
    ],
  };
  const body = canonical(named);
  if (body === null) {
    return "";
  }
  return "sha256:" + sha256Hex(Buffer.concat([Buffer.from(sealScopeSaltedDigestPrefix, "utf8"), body]));
}

// namesScope is whether a seal names the scope identifier scope, carried with
// the scope salt salt (undefined for none): a seal of version 3 by the digest
// over the salt, which must be there and of its form; one of version 2 by
// the digest in the session, whatever salt is carried; a seal of a form that
// names no scope names none.
function namesScope(seal: Seal, sessionId: string, scope: string, salt: string | undefined): boolean {
  if (seal.scopeDigest === undefined) {
    return false;
  }
  if (seal.salted === true) {
    return salt !== undefined && scopeSaltForm.test(salt) && saltedScopeDigest(sessionId, scope, salt) === seal.scopeDigest;
  }
  return sealScopeDigest(sessionId, scope) === seal.scopeDigest;
}

// sealScopeDigest is what a seal of version 2 names a session's scope by:
// "sha256:" and the lowercase hex of SHA-256 over the prefix and the
// canonical form of {"scope", "sessionId"} (§3, "A seal of version 2").
function sealScopeDigest(sessionId: string, scope: string): string {
  const named: ObjectValue = {
    type: "object",
    members: [
      { name: "scope", value: { type: "string", value: scope } },
      { name: "sessionId", value: { type: "string", value: sessionId } },
    ],
  };
  const body = canonical(named);
  if (body === null) {
    return "";
  }
  return "sha256:" + sha256Hex(Buffer.concat([Buffer.from(sealScopeDigestPrefix, "utf8"), body]));
}

// A key id: SHA-256 of the 32 raw bytes of the public key, in hex, its
// first 32 characters.
export function keyIdOf(publicKey: Uint8Array): string {
  return crypto.createHash("sha256").update(publicKey).digest("hex").slice(0, 32);
}

// signed is whether the signature verifies by alg under the key, which must
// be of alg, over the prefix and the canonical form of the value: an
// Ed25519 one in hex of either case, an ES256 one in 128 lowercase
// hexadecimal characters, low-S (verifyByAlg).
function signed(key: ReachedKey, alg: Alg, prefix: string, v: Value, signatureHex: string): boolean {
  const body = canonical(v);
  if (body === null) {
    return false;
  }
  return verifyByAlg(alg, key, Buffer.concat([Buffer.from(prefix, "utf8"), body]), signatureHex);
}

function sha256Hex(bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

// testHooks lets a test look at memory between one document and the
// next; nothing sets it but a test.
export const testHooks: { sample?: (where: string) => void } = {};

// parseOr is the document parsed, and a document past maxValues is
// answered by tooLarge: a receipt is no verdict; a registry line or a
// decision record that opens an object could be a seal or a record that
// cites, and is no verdict, and one that does not is not read.
function parseOr(bytes: Uint8Array, tooLarge: () => Value | null): Value | null {
  try {
    return parse(bytes);
  } catch (e) {
    if (e instanceof TooLarge) {
      return tooLarge();
    }
    throw e;
  }
}

function opensObject(bytes: Uint8Array): boolean {
  const at = bytes.findIndex((b) => b !== 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d);
  return at !== -1 && bytes[at] === 0x7b;
}

function str(v: Value | undefined): string | undefined {
  return v?.type === "string" ? v.value : undefined;
}

// under is a path below root as its spelling says, never normalized: a
// ".." in root steps back from where the platform finds root's last
// component, as it would for any path, not from the component as written.
function under(root: string, ...names: string[]): string {
  return [root, ...names].join(path.sep);
}

// sessionFiles is the store's sessions -- each directory under receipts/,
// not a link to one -- and each one's .json entries that are not
// directories, each charged to the budget as it is met. A store root or
// receipts directory not there holds no session; one there that cannot be
// read as a directory is no verdict. The sessions, and each one's files,
// are in the order of their names' bytes, as the reference reader lists
// them (go/verify.go; corpus/README.md, "Findings order is not
// normative"), never in the order a listing returns them, which no
// filesystem fixes: everything read from the list then sees one order.
function sessionFiles(root: string, budget: Budget): Map<string, string[]> {
  return byName(listedSessionFiles(root, budget));
}

function byName(sessions: Map<string, string[]>): Map<string, string[]> {
  const order = (a: string, b: string): number => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  return new Map([...sessions].sort(([a], [b]) => order(a, b)).map(([session, files]) => [session, files.sort(order)]));
}

function listedSessionFiles(root: string, budget: Budget): Map<string, string[]> {
  const sessions = new Map<string, string[]>();
  const receipts = under(root, "receipts");
  // Names are read as the bytes they are: a name that is not UTF-8 is no
  // verdict (nameOf), rather than decoded into one that could be taken for
  // another entry's.
  const eachSession = (name: Buffer, entry: fs.Dirent) => {
    if (!entry.isDirectory()) {
      return;
    }
    const session = nameOf(name, "a session directory");
    budget.charge(sessionCost + size(session), "the store's sessions");
    const files: string[] = [];
    sessions.set(session, files);
    const what = `session ${JSON.stringify(session)}`;
    try {
      eachEntry(under(receipts, session), what, (n, e) => {
        if (endsWith(n, ".json") && !e.isDirectory()) {
          const file = nameOf(n, `in ${what}, a receipt file`);
          budget.charge(receiptCost + 2 * size(file), "the store's receipt files");
          files.push(file);
        }
      });
    } catch (e) {
      throw e instanceof NoVerdict ? e : new NoVerdict(`${what} cannot be read: ${code(e) ?? e}`);
    }
  };
  try {
    eachEntry(receipts, "the receipts directory", eachSession);
  } catch (e) {
    if (e instanceof NoVerdict) {
      throw e;
    }
    if (code(e) === "ENOENT") {
      return sessions;
    }
    throw new NoVerdict(`the receipts directory ${JSON.stringify(receipts)} cannot be read: ${code(e) ?? e}`);
  }
  return sessions;
}

// citedSignature is what §4 steps 5 and 7 read of a cited file: its one
// top-level signature member, when the file is one JSON object giving that
// name once and the member is a string. Nothing else in it matters.
function citedSignature(v: Value | null): string | undefined {
  const signature = v?.type === "object" && count(v, "signature") === 1 ? str(member(v, "signature")) : undefined;
  // Only a version 3 signature's form can match a citation's; nothing
  // longer is kept.
  return signature !== undefined && /^[0-9a-f]{128}$/.test(signature) ? own(signature) : undefined;
}

// A removal record that loaded (§1.3a): of its form, under a key the walk
// reached, its signature verifying; kept by the receipt signature it names.
type Removal = { readonly sessionId: string; readonly callIndex: bigint; readonly resultDigest: string; readonly keyPos: number };
const removalPrefix = "judgment-pack-gateway/artifact-removal/1:";
const removalMembers = ["callIndex", "keyId", "kind", "receiptSignature", "removedAt", "removedBy", "resultDigest", "sessionId", "signature"];

// What the artifact step reads beside the store's own bytes (§1.3a): the
// removal records that loaded, and the directory of bytes a reader
// supplied, undefined when none was.
type Retention = { readonly removals: ReadonlyMap<string, readonly Removal[]>; readonly supplied: string | undefined };

// A session-removal record that loaded (§1.3a, "A removed session"): it
// names a sealed session by its id, its seal's signature and its seal's
// count; kept by the session it names.
// scope is the scope identifier the record names, which a seal of version 2
// or 3 is held to (§1.3a, "A removed session"), and scopeSalt the scope salt
// a record of a session sealed with a seal of version 3 carries.
type SessionRemoval = { readonly sealSignature: string; readonly finalCount: bigint; readonly scope: string; readonly scopeSalt?: string; readonly keyPos: number };
const sessionRemovalPrefix = "judgment-pack-gateway/session-removal/1:";
const sessionRemovalMembers = ["finalCount", "keyId", "kind", "removedAt", "removedBy", "scope", "sealSignature", "sessionId", "signature"];
const sessionRemovalSaltedMembers = [...sessionRemovalMembers, "scopeSalt"];

// removalOf is a line of the removal file, read, as a record when it holds
// exactly its nine members, no name twice, each of its form, its key id
// names a key the walk reached and its signature verifies under that key,
// over the prefix and the canonical form of everything but the signature;
// any other line is no record.
function removalOf(v: Value | null, keys: readonly ReachedKey[]): (Removal & { readonly receiptSignature: string }) | null {
  if (v === null || v.type !== "object" || hasDuplicate(v)) {
    return null;
  }
  // alg among them on a record a P-256 key signs (ADR-0053 §2)
  const names = member(v, "alg") !== undefined ? [...removalMembers, "alg"] : removalMembers;
  const alg = recordAlg(v, "alg");
  if (alg === null || v.members.length !== names.length || !v.members.every((m) => names.includes(m.name))) {
    return null;
  }
  const of = (name: string, form: RegExp): string | undefined => {
    const s = str(member(v, name));
    return s !== undefined && form.test(s) ? s : undefined;
  };
  const kind = of("kind", /^artifact-removal$/);
  const sessionId = of("sessionId", /^[A-Za-z0-9._-]{1,128}$/);
  const callIndex = member(v, "callIndex");
  const receiptSignature = of("receiptSignature", /^[0-9a-f]{128}$/);
  const resultDigest = of("resultDigest", /^sha256:[0-9a-f]{64}$/);
  const removedAt = str(member(v, "removedAt"));
  const removedBy = str(member(v, "removedBy"));
  const keyId = of("keyId", /^[0-9a-f]{32}$/);
  const signature = of("signature", /^[0-9a-f]{128}$/);
  if (
    kind === undefined ||
    sessionId === undefined ||
    sessionId === "." ||
    sessionId === ".." ||
    callIndex?.type !== "number" ||
    callIndex.integer === null ||
    callIndex.integer < 0n ||
    callIndex.integer > 2n ** 53n - 1n ||
    receiptSignature === undefined ||
    resultDigest === undefined ||
    removedAt === undefined ||
    !isRemovalTime(removedAt) ||
    removedBy === undefined ||
    !isScopeIdentifier(removedBy) ||
    keyId === undefined ||
    signature === undefined
  ) {
    return null;
  }
  const keyPos = keys.findIndex((k) => k.keyId === keyId);
  if (keyPos < 0 || keys[keyPos]!.alg !== alg) {
    return null;
  }
  const payload: ObjectValue = { type: "object", members: v.members.filter((m) => m.name !== "signature") };
  if (!signed(keys[keyPos]!, alg, removalPrefix, payload, signature)) {
    return null;
  }
  return { sessionId: own(sessionId), callIndex: callIndex.integer, resultDigest: own(resultDigest), keyPos, receiptSignature: own(receiptSignature) };
}

// sessionRemovalOf is a line of the removal file, read, as a
// session-removal record when it holds exactly its nine members, no name
// twice, each of its form, its key id names a key the walk reached and its
// signature verifies under that key, over its own prefix and the canonical
// form of everything but the signature; any other line is no such record.
function sessionRemovalOf(v: Value | null, keys: readonly ReachedKey[]): (SessionRemoval & { readonly sessionId: string }) | null {
  if (v === null || v.type !== "object" || hasDuplicate(v)) {
    return null;
  }
  // the nine members, or the ten of a record of a session sealed with a
  // seal of version 3, its scope salt among them (ADR-0042)
  const salted = member(v, "scopeSalt") !== undefined;
  const members = [...(salted ? sessionRemovalSaltedMembers : sessionRemovalMembers), ...(member(v, "alg") !== undefined ? ["alg"] : [])];
  const alg = recordAlg(v, "alg");
  if (alg === null || v.members.length !== members.length || !v.members.every((m) => members.includes(m.name))) {
    return null;
  }
  const of = (name: string, form: RegExp): string | undefined => {
    const s = str(member(v, name));
    return s !== undefined && form.test(s) ? s : undefined;
  };
  const scopeSalt = salted ? of("scopeSalt", scopeSaltForm) : undefined;
  if (salted && scopeSalt === undefined) {
    return null;
  }
  const kind = of("kind", /^session-removal$/);
  const sessionId = of("sessionId", /^[A-Za-z0-9._-]{1,128}$/);
  const finalCount = member(v, "finalCount");
  const sealSignature = of("sealSignature", /^[0-9a-f]{128}$/);
  const scope = str(member(v, "scope"));
  const removedAt = str(member(v, "removedAt"));
  const removedBy = str(member(v, "removedBy"));
  const keyId = of("keyId", /^[0-9a-f]{32}$/);
  const signature = of("signature", /^[0-9a-f]{128}$/);
  if (
    kind === undefined ||
    sessionId === undefined ||
    sessionId === "." ||
    sessionId === ".." ||
    finalCount?.type !== "number" ||
    finalCount.integer === null ||
    sealSignature === undefined ||
    scope === undefined ||
    !isScopeIdentifier(scope) ||
    removedAt === undefined ||
    !isRemovalTime(removedAt) ||
    removedBy === undefined ||
    !isScopeIdentifier(removedBy) ||
    keyId === undefined ||
    signature === undefined
  ) {
    return null;
  }
  const keyPos = keys.findIndex((k) => k.keyId === keyId);
  if (keyPos < 0) {
    return null;
  }
  const payload: ObjectValue = { type: "object", members: v.members.filter((m) => m.name !== "signature") };
  if (keys[keyPos]!.alg !== alg || !signed(keys[keyPos]!, alg, sessionRemovalPrefix, payload, signature)) {
    return null;
  }
  return { sessionId: own(sessionId), sealSignature: own(sealSignature), finalCount: finalCount.integer, scope: own(scope), ...(scopeSalt !== undefined && { scopeSalt: own(scopeSalt) }), keyPos };
}

// loadRemovals is the store's removal records (§1.3a, "Loading"; §4.1),
// read a line at a time (eachRemovalLine): nothing at the path loads none,
// and nor does anything there that is not a regular file, which is not
// read; a regular file that cannot be read is no verdict. A record that
// names the receipt by the same session, index and digest as one kept
// replaces it only where its key was reached later, which is all the
// artifact step reads of either; so what is kept, and charged, grows with
// the receipts the records name, not with the lines that repeat them.
function loadRemovals(root: string, keys: readonly ReachedKey[], budget: Budget): { removals: Map<string, Removal[]>; sessions: Map<string, SessionRemoval[]> } {
  const removals = new Map<string, Removal[]>();
  const sessions = new Map<string, SessionRemoval[]>();
  eachRemovalLine(under(root, "artifact-removals.jsonl"), (line) => {
    const parsed = parseOr(line, () => null);
    // A session-removal record is kept once for the seal it names, as an
    // artifact-removal is for its receipt; a scope-removal record is read
    // by no step of §4 and is not kept.
    const removed = sessionRemovalOf(parsed, keys);
    if (removed !== null) {
      const named = sessions.get(removed.sessionId);
      const at = named?.findIndex((k) => k.sealSignature === removed.sealSignature && k.finalCount === removed.finalCount && k.scope === removed.scope) ?? -1;
      if (at >= 0) {
        if (removed.keyPos > named![at]!.keyPos) {
          named![at] = removed;
        }
        return;
      }
      budget.charge(entryCost + size(removed.sessionId) + size(removed.sealSignature) + size(removed.scope), "the removal records");
      if (named === undefined) {
        sessions.set(removed.sessionId, [removed]);
      } else {
        named.push(removed);
      }
      return;
    }
    const rec = removalOf(parsed, keys);
    if (rec === null) {
      return;
    }
    const named = removals.get(rec.receiptSignature);
    const at = named?.findIndex((k) => k.sessionId === rec.sessionId && k.callIndex === rec.callIndex && k.resultDigest === rec.resultDigest) ?? -1;
    if (at >= 0) {
      if (rec.keyPos > named![at]!.keyPos) {
        named![at] = rec;
      }
      return;
    }
    budget.charge(entryCost + size(rec.receiptSignature) + size(rec.sessionId) + size(rec.resultDigest), "the removal records");
    if (named === undefined) {
      removals.set(rec.receiptSignature, [rec]);
    } else {
      named.push(rec);
    }
  });
  return { removals, sessions };
}

// isRemovalTime is a removedAt of its form that names an instant (§1.3a):
// a date the calendar holds, and an hour, minute and second of a day.
function isRemovalTime(s: string): boolean {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/.exec(s);
  if (m === null) {
    return false;
  }
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  // setUTCFullYear, not Date.UTC, which reads a year below 100 as 19xx
  const t = new Date(0);
  t.setUTCFullYear(y, mo - 1, d);
  t.setUTCHours(h, mi, se, 0);
  return (
    t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d &&
    t.getUTCHours() === h && t.getUTCMinutes() === mi && t.getUTCSeconds() === se
  );
}

// judge is the ladder of §1.4 for one receipt: at most one status, the
// first failure in order.
function judge(parsed: Value | null, bytesDigest: string, root: string, session: string, file: string, keys: readonly ReachedKey[], authority: string, retention: Retention): Judged {
  // 1. malformed: unparseable, a name twice, or a structural violation of
  // the receipt's version.
  if (parsed === null || parsed.type !== "object" || hasDuplicate(parsed)) {
    return { file, status: "malformed" };
  }
  const receipt = parsed;
  const version = str(member(receipt, "receiptVersion"));
  if (!(version === "3" ? structureV3(receipt) : structureV2(receipt))) {
    return { file, status: "malformed" };
  }
  // alg (ADR-0053 §1): a version 3 receipt a P-256 key signs carries
  // "ES256" and no other value; a version 2 receipt, Ed25519 alone,
  // carries none, of any value, and is never verified as ES256.
  const alg = version === "3" ? recordAlg(receipt, "alg") : "";
  if (alg === null || (version === "2" && member(receipt, "alg") !== undefined)) {
    return { file, status: "malformed" };
  }
  // An index whose value is not read -- more than integerDigits digits --
  // cannot verify (the canonical domain ends at sixteen), and is no
  // verdict rather than a finding of unbounded size.
  const index = member(receipt, "callIndex") as NumberValue;
  if (index.integer === null) {
    throw new NoVerdict(`receipt ${session}/${file} has a callIndex of more than ${integerDigits} digits`);
  }
  const callIndex = index.integer;
  const signature = str(member(receipt, "signature"))!;
  const judged = (status: Status): Judged => ({ file, status, callIndex });
  // 2. unsupported-version
  if (version !== "2" && version !== "3") {
    return judged("unsupported-version");
  }
  // 3. key-mismatch: the key id of no key the registry's walk reached
  // (§3b), the key pinned first.
  const receiptKeyId = str(member(receipt, "keyId"));
  const keyPos = keys.findIndex((k) => k.keyId === receiptKeyId);
  // The key the key id names verifies a receipt of its own algorithm
  // alone: alg names it, and a key of the other algorithm is the key
  // failure, with no signature tried.
  if (keyPos < 0 || keys[keyPos]!.alg !== alg) {
    return judged("key-mismatch");
  }
  // 4. signature-mismatch: over everything but the receipt's own
  // top-level signature, under its version's prefix, under the key its
  // key id names.
  const unsigned: ObjectValue = { type: "object", members: receipt.members.filter((m) => m.name !== "signature") };
  if (!signed(keys[keyPos]!, alg, receiptPrefix[version]!, unsigned, signature)) {
    return judged("signature-mismatch");
  }
  // 5. misfiled: the file's stem is its callIndex, and the directory its
  // sessionId.
  if (file.slice(0, -".json".length) !== callIndex.toString() || str(member(receipt, "sessionId")) !== session) {
    return judged("misfiled");
  }
  // 6. authority-mismatch
  if (str(member(receipt, "authority")) !== authority) {
    return judged("authority-mismatch");
  }
  // Past the signed orders, what the receipt carries is the gateway's, its
  // scope and scope salt among them, whatever the steps after find.
  const scope = str(member(receipt, "scope"));
  const scopeSalt = str(member(receipt, "scopeSalt"));
  const carried = {
    signed: true as const,
    ...(scope !== undefined && { scope: own(scope) }),
    ...(scopeSalt !== undefined && { scopeSalt: own(scopeSalt) }),
  };
  const judgedSigned = (status: Status): Judged => ({ file, status, callIndex, ...carried });
  // 7. artifact-missing, and 8. artifact-mismatch: the artifact at the
  // result digest's hex, re-digested; where nothing at all is there, a
  // receipt that says its call kept no payload, or that a removal record
  // names, passes order 7, and bytes a reader supplied for it are
  // re-digested in its stead (§1.3a).
  const hex = str(member(receipt, "resultDigest"))!.slice("sha256:".length);
  const at = under(root, "artifacts", hex);
  const digest = digestArtifact(at);
  let observation: string | undefined;
  if (digest === null) {
    if (!nothingAt(at)) {
      return judgedSigned("artifact-missing");
    }
    if (version === "3" && member(receipt, "artifact") !== undefined) {
      observation = "artifact-not-retained";
    } else if (
      (retention.removals.get(signature) ?? []).some(
        (r) => r.sessionId === session && r.callIndex === callIndex && r.resultDigest === str(member(receipt, "resultDigest")) && r.keyPos >= keyPos,
      )
    ) {
      observation = "artifact-removed";
    } else {
      return judgedSigned("artifact-missing");
    }
    if (retention.supplied !== undefined) {
      const supplied = digestSupplied(under(retention.supplied, hex));
      if (supplied !== null) {
        if (supplied !== hex) {
          return judgedSigned("artifact-mismatch");
        }
        observation = undefined;
      }
    }
  } else if (digest !== hex) {
    return judgedSigned("artifact-mismatch");
  }
  if (version === "3") {
    const status = descriptorStatus(root,receipt,keys.slice(0,keyPos+1));
    if (status !== "ok") return judgedSigned(status);
  }
  const prevValue = member(receipt, "prevSignature");
  const prev: Prev =
    prevValue?.type === "null"
      ? { kind: "null" }
      : prevValue?.type === "string" && prevValue.value.length <= 128
        ? { kind: "string", value: own(prevValue.value) }
        : { kind: "other" };
  const named = version === "3" ? member(receipt, "witness") : undefined;
  const witness: Witness | undefined =
    named?.type === "object"
      ? { trail: own(str(member(named, "trail"))!), origin: own(str(member(named, "origin"))!), keyId: own(str(member(named, "keyId"))!) }
      : undefined;
  let action: Judged["action"];
  if (version === "3" && str(member(receipt, "kind")) === "action") {
    const act = member(receipt, "action") as ObjectValue;
    const decision = member(act, "decision") as ObjectValue;
    action = {
      recordDigest: own(str(member(decision, "recordDigest"))!),
      bytes: bytesDigest,
      packDigest: own(str(member(decision, "packDigest"))!),
      citesKey: citesKey(citations(member(act, "cites")!)!),
      exact: member(decision, "recordBytes") !== undefined,
      ...(member(act, "approvals")?.type === "array" && {
        approvals: (member(act, "approvals") as { readonly items: Value[] }).items.map((e) => ({
          kind: own(str(member(e as ObjectValue, "kind"))!),
          id: own(str(member(e as ObjectValue, "id"))!),
          digest: own(str(member(e as ObjectValue, "digest"))!),
        })),
      }),
      ...(witness && { witnessTrail: witness.trail }),
    };
  }
  // Keep only bounded correlation fields, never whole receipt objects.
  const identity = (v: Value | undefined): string => {
    if (v?.type !== "object") return "";
    return sha256Hex(canonical({type:"array",items:[member(v,"issuer")!,member(v,"subject")!]})!);
  };
  const detail = member(receipt,action ? "action" : "acquisition");
  const d = detail?.type === "object" ? member(detail,action ? "delivery" : "reconciliation") : undefined;
  let delivery: Delivery | undefined;
  let reconciliation: Reconciliation | undefined;
  if (version === "3" && d?.type === "object" && detail?.type === "object") {
    const fields: Delivery = {key:own(str(member(d,"key"))!),contract:own(str(member(d,"contract"))!),outcome:own(str(member(d,"outcome"))!),identity:identity(action ? member(detail,"requester") : member(receipt,"caller")),source:own(str(member(receipt,"source")) ?? ""),shape:action ? "" : own(str(member(detail,"shape")) ?? "")};
    if (action) delivery=fields;
    else {
      const c=citations({type:"array",items:[member(d,"action")!]})![0]!;
      reconciliation={...fields,action:{sessionId:own(c.sessionId),callIndex:own(c.callIndex),signature:own(c.signature)}};
    }
  }
  return {
    file,
    status: "ok",
    callIndex,
    ...(observation !== undefined && { observation }),
    ...carried,
    chain: { version: own(version), signature: own(signature), prev, keyPos },
    ...(action && { action }),
    ...(delivery && {delivery}),
    ...(reconciliation && {reconciliation}),
    ...(witness && { witness }),
  };
}

// A seal that loaded. head is, for a seal made after an interruption
// (§3c), the signature of the last receipt it seals; undefined for one of
// §3's form.
// signature is the seal's signature, its bytes in lowercase hex, and keyPos
// the place among the keys the walk reached of the key it loaded under:
// what a session-removal record names it by (§1.3a).
// scopeDigest is the digest of the scope identifier a seal of version 2
// names (sealScopeDigest), or one of version 3 over the session's scope salt
// (saltedScopeDigest, salted true); undefined for a seal of a form that
// names none.
type Seal = { readonly sessionId: string; readonly finalCount: bigint; readonly head?: string; readonly signature: string; readonly keyPos: number; readonly scopeDigest?: string; readonly salted?: boolean };

// sealOf is a registry line, read, as a seal, when it is one whose key id
// is the current key's at its line (§3b, §4 step 2) and whose signature
// verifies under that key; any other line is no seal and is dropped.
function sealOf(seal: Value | null, current: ReachedKey, keyPos: number): Seal | null {
  if (seal === null || seal.type !== "object" || hasDuplicate(seal)) {
    return null;
  }
  const sessionId = member(seal, "sessionId");
  const finalCount = member(seal, "finalCount");
  const sealedAt = member(seal, "sealedAt");
  const sealKeyId = member(seal, "keyId");
  const signature = str(member(seal, "signature"));
  if (
    sessionId?.type !== "string" ||
    finalCount?.type !== "number" ||
    finalCount.integer === null ||
    sealedAt?.type !== "string" ||
    sealKeyId?.type !== "string" ||
    signature === undefined
  ) {
    return null;
  }
  // alg (ADR-0053 §1): absent, Ed25519, whose signature's hex stays
  // lenient of case; "ES256", whose signature is 128 lowercase hexadecimal
  // characters (verifyByAlg), and whose signing input names five members,
  // alg among them; any other value loads nothing
  const alg = recordAlg(seal, "alg");
  if (alg === null || sealKeyId.value !== current.keyId || alg !== current.alg) {
    return null;
  }
  const payload: ObjectValue = {
    type: "object",
    members: [
      ...(alg === "ES256" ? [{ name: "alg", value: member(seal, "alg")! }] : []),
      { name: "sessionId", value: sessionId },
      { name: "finalCount", value: finalCount },
      { name: "sealedAt", value: sealedAt },
      { name: "keyId", value: sealKeyId },
    ],
  };
  if (!signed(current, alg, sealPrefix, payload, signature)) {
    return null;
  }
  return { sessionId: own(sessionId.value), finalCount: finalCount.integer, signature: signature.toLowerCase(), keyPos };
}

// isVersioned is whether a registry line is to be read as a seal of the
// version it names, and as nothing else: one JSON object holding sealVersion
// and no kind (ADR-0036).
function isVersioned(v: Value | null): v is ObjectValue {
  return v !== null && v.type === "object" && member(v, "sealVersion") !== undefined && member(v, "kind") === undefined;
}

// scopedSealOf is such a line, read, as a seal of version 2 or 3 when it holds its
// form -- exactly its members, no name given twice, each of its form -- its
// key id is the current key's at its line and its signature verifies under
// that key, over the prefix and the canonical form of everything but the
// signature; any other such line is no seal.
function scopedSealOf(v: ObjectValue, current: ReachedKey, keyPos: number): Seal | null {
  // alg among them on a seal a P-256 key signs (ADR-0053 §2)
  const alg = recordAlg(v, "alg");
  const allowed = member(v, "alg") !== undefined ? [...scopedSealMembers, "alg"] : scopedSealMembers;
  if (alg === null || hasDuplicate(v) || !v.members.every((m) => allowed.includes(m.name))) {
    return null;
  }
  const of = (name: string, form: RegExp): string | undefined => {
    const s = str(member(v, name));
    return s !== undefined && form.test(s) ? s : undefined;
  };
  const sessionId = of("sessionId", /^[A-Za-z0-9._-]{1,128}$/);
  const finalCount = member(v, "finalCount");
  const sealKeyId = of("keyId", /^[0-9a-f]{32}$/);
  const sealedAt = of("sealedAt", /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
  const signature = of("signature", /^[0-9a-f]{128}$/);
  const scopeDigest = of("scopeDigest", digestForm);
  const version = str(member(v, "sealVersion"));
  if (
    (version !== "2" && version !== "3") ||
    sessionId === undefined ||
    sessionId === "." ||
    sessionId === ".." ||
    finalCount?.type !== "number" ||
    finalCount.integer === null ||
    finalCount.integer < 0n ||
    sealKeyId === undefined ||
    sealedAt === undefined ||
    signature === undefined ||
    scopeDigest === undefined
  ) {
    return null;
  }
  if (sealKeyId !== current.keyId || alg !== current.alg) {
    return null;
  }
  const payload: ObjectValue = { type: "object", members: v.members.filter((m) => m.name !== "signature") };
  if (!signed(current, alg, version === "3" ? saltedSealPrefix : scopedSealPrefix, payload, signature)) {
    return null;
  }
  return { sessionId: own(sessionId), finalCount: finalCount.integer, signature: own(signature), keyPos, scopeDigest: own(scopeDigest), ...(version === "3" && { salted: true }) };
}

// isInterruption is whether a registry line is to be read as a seal made
// after an interruption (§3c), and as nothing else: one JSON object whose
// kind is that seal's.
function isInterruption(v: Value | null): v is ObjectValue {
  return v !== null && v.type === "object" && str(member(v, "kind")) === interruptionKind;
}

// interruptionSealOf is such a line, read, as a seal when it holds its form
// -- exactly its members, no name given twice, each of its form, and a count
// §1.1's domain holds, which the signature's canonical form asks -- its key
// id is the current key's at its line and its signature verifies under that
// key, over the prefix and the canonical form of everything but the
// signature; any other such line is no seal of either kind.
function interruptionSealOf(v: ObjectValue, current: ReachedKey, keyPos: number): Seal | null {
  // one of version 2 or 3 holds sealVersion "2" or "3" and a scopeDigest
  // beside its own members, and is signed under a prefix of its own
  // (ADR-0036, ADR-0042)
  const versioned = member(v, "sealVersion") !== undefined;
  // and alg on a seal a P-256 key signs (ADR-0053 §2)
  const alg = recordAlg(v, "alg");
  const allowed = [...(versioned ? [...interruptionMembers, "scopeDigest", "sealVersion"] : interruptionMembers), ...(member(v, "alg") !== undefined ? ["alg"] : [])];
  if (alg === null || hasDuplicate(v) || !v.members.every((m) => allowed.includes(m.name))) {
    return null;
  }
  const scopeDigest = versioned ? str(member(v, "scopeDigest")) : undefined;
  const version = versioned ? str(member(v, "sealVersion")) : undefined;
  if (versioned && ((version !== "2" && version !== "3") || scopeDigest === undefined || !digestForm.test(scopeDigest))) {
    return null;
  }
  const of = (name: string, form: RegExp): string | undefined => {
    const s = str(member(v, name));
    return s !== undefined && form.test(s) ? s : undefined;
  };
  const sessionId = of("sessionId", /^[A-Za-z0-9._-]{1,128}$/);
  const finalCount = member(v, "finalCount");
  const head = of("headSignature", /^[0-9a-f]{128}$/);
  const sealKeyId = of("keyId", /^[0-9a-f]{32}$/);
  const sealedAt = of("sealedAt", /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
  const sealedVia = of("sealedVia", /^(?:command|start)$/);
  const signature = of("signature", /^[0-9a-f]{128}$/);
  if (
    sessionId === undefined ||
    sessionId === "." ||
    sessionId === ".." ||
    finalCount?.type !== "number" ||
    finalCount.integer === null ||
    finalCount.integer < 1n ||
    head === undefined ||
    sealKeyId === undefined ||
    sealedAt === undefined ||
    sealedVia === undefined ||
    signature === undefined
  ) {
    return null;
  }
  if (sealKeyId !== current.keyId || alg !== current.alg) {
    return null;
  }
  const payload: ObjectValue = { type: "object", members: v.members.filter((m) => m.name !== "signature") };
  if (!signed(current, alg, version === "3" ? interruptionPrefix3 : versioned ? interruptionPrefix2 : interruptionPrefix, payload, signature)) {
    return null;
  }
  return { sessionId: own(sessionId), finalCount: finalCount.integer, head: own(head), signature: own(signature), keyPos, ...(scopeDigest !== undefined && { scopeDigest: own(scopeDigest) }), ...(version === "3" && { salted: true }) };
}

// A session's receipt files as a verdict by scope reads them (§4, "A
// verdict by scope"): the scope and scope salt of each past the signed
// orders, once each pair; whether one of them holds no scope; whether every
// file is past them, at the places 0 to count-1; and the signature the file
// at count-1 gives, undefined for none.
type Holding = {
  readonly scopes: ReadonlyArray<{ readonly scope: string; readonly salt: string | undefined }>;
  readonly noScope: boolean;
  readonly signedAll: boolean;
  readonly count: bigint;
  readonly last: string | undefined;
};

function holdingOf(judged: readonly Judged[], stems: ReadonlyMap<string, string | undefined> | undefined): Holding {
  const scopes = new Map<string, { readonly scope: string; readonly salt: string | undefined }>();
  const indexes = new Set<bigint>();
  let noScope = false;
  let signedAll = true;
  for (const j of judged) {
    if (j.signed !== true) {
      signedAll = false;
      continue;
    }
    indexes.add(j.callIndex!);
    if (j.scope === undefined) {
      noScope = true;
    } else {
      scopes.set(JSON.stringify([j.scope, j.scopeSalt ?? ""]), { scope: j.scope, salt: j.scopeSalt });
    }
  }
  const count = BigInt(judged.length);
  for (let i = 0n; i < count && signedAll; i++) {
    signedAll = indexes.has(i);
  }
  return { scopes: [...scopes.values()], noScope, signedAll, count, last: count > 0n ? stems?.get(String(count - 1n)) : undefined };
}

type Attribution = "of-another" | "of-the-scope" | "unattributed";

// attribute is the attribution of the session sessionId to scope (§4, "A
// verdict by scope"): seal its first seal that loaded, undefined for none;
// holding its receipts', undefined for a sealed session the store does not
// hold; removal the session-removal record naming a sealed session.
//
// Held in the store, a session is of the scope where a receipt past the
// signed orders carries it, whatever its seal says. Otherwise a seal of
// version 2 attributes it by the scope its digest names; one of version 3 to
// another where a receipt's scope and salt are its digest's, and to none
// where none is; a seal naming no scope to another where every receipt it
// counts is held and past the signed orders, its head the last for one after
// an interruption, and to none otherwise; and with no seal, it is of another
// where a receipt is past the signed orders and each that is carries another
// scope with a scope salt, and of none otherwise.
// A sealed session the store does not hold is of the scope a record naming
// it states, of the scope a seal of version 2 names, and otherwise of none.
function attribute(scope: string, sessionId: string, seal: Seal | undefined, holding: Holding | undefined, removal: SessionRemoval | undefined): Attribution {
  if (holding === undefined) {
    if (removal !== undefined) {
      return removal.scope === scope ? "of-the-scope" : "of-another";
    }
    if (seal !== undefined && seal.scopeDigest !== undefined && seal.salted !== true) {
      return namesScope(seal, sessionId, scope, undefined) ? "of-the-scope" : "of-another";
    }
    return "unattributed";
  }
  if (holding.scopes.some((h) => h.scope === scope)) {
    return "of-the-scope";
  }
  if (seal !== undefined && seal.scopeDigest !== undefined && seal.salted !== true) {
    return namesScope(seal, sessionId, scope, undefined) ? "of-the-scope" : "of-another";
  }
  if (seal !== undefined && seal.scopeDigest !== undefined) {
    return holding.scopes.some((h) => namesScope(seal, sessionId, h.scope, h.salt)) ? "of-another" : "unattributed";
  }
  if (seal !== undefined) {
    return holding.signedAll && holding.count === seal.finalCount && (seal.head === undefined || holding.last === seal.head) ? "of-another" : "unattributed";
  }
  if (holding.scopes.length === 0 || holding.noScope || holding.scopes.some((h) => h.salt === undefined)) {
    return "unattributed";
  }
  return "of-another";
}

// verifyStore is the verdict of §4 over the store at root, against the
// registry at registryPath, under the public key. With ordinarySealsOnly,
// a session a seal made after an interruption anchors is a finding, not an
// observation (§4 step 3). With scope, it is a verdict by scope (§4, "A
// verdict by scope"), which reads no decision records.
export function verifyStore(
  root: string,
  registryPath: string,
  authority: string,
  decisionRecordsPath: string | undefined,
  publicKey: Uint8Array | Pin,
  options: { readonly ordinarySealsOnly?: boolean; readonly artifacts?: string; readonly scope?: string; readonly previous?: string; readonly requireJournal?: readonly string[] } = {},
): Verdict {
  const ordinarySealsOnly = options.ordinarySealsOnly === true;
  // A verdict by scope names a scope identifier of its form, and reads no
  // decision record: an action receipt carries no scope, and a session of a
  // scope identifier is refused one.
  if (options.scope !== undefined && !isScopeIdentifier(options.scope)) {
    throw new NoVerdict("the scope is not a scope identifier");
  }
  if (options.scope !== undefined && decisionRecordsPath !== undefined) {
    throw new NoVerdict("a verdict by scope reads no decision records");
  }
  refuseUnsupportedPlatform();
  // The key pinned, with its algorithm (ADR-0053 §11): 32 raw bytes of an
  // Ed25519 key, or {alg: "ES256", key} with the 66 lowercase hexadecimal
  // characters of a P-256 point that holds the key rule.
  let pinned: { readonly raw: Uint8Array; readonly alg: Alg };
  if (publicKey instanceof Uint8Array) {
    if (publicKey.length !== 32) {
      throw new NoVerdict(`the public key is ${publicKey.length} bytes, not 32`);
    }
    pinned = { raw: publicKey, alg: "" };
  } else {
    if (publicKey.alg !== "ES256" || !/^[0-9a-f]{66}$/.test(publicKey.key) || !p256KeySound(Buffer.from(publicKey.key, "hex"))) {
      throw new NoVerdict('the pin is {alg: "ES256", key: <the 66 lowercase hexadecimal characters of a P-256 compressed point>}');
    }
    pinned = { raw: Buffer.from(publicKey.key, "hex"), alg: "ES256" };
  }
  // A spelling §4.1 refuses is refused before anything is read, and each
  // anchor is judged absent or present before the store is read.
  checkSpellings(registryPath, decisionRecordsPath);
  if (options.artifacts !== undefined) {
    suppliedDirectory(options.artifacts);
  }
  const registry = locateRegistry(registryPath);
  const records = locateDecisionRecords(decisionRecordsPath);

  // What verification keeps, charged as it is kept.
  const budget = new Budget(limits.retainedBytes);

  // Each receipt, read once: judged, and indexed by stem for the
  // citations of §4 steps 5 and 7. Every receipt file is met, and charged
  // for what is kept of it, before any is read.
  const sessions = new Map<string, Judged[]>();
  const signatures = new Map<string, Map<string, string | undefined>>();
  const store = sessionFiles(root, budget);

  // §4 step 2, walked from the key pinned (§3b) before any receipt is
  // judged, since a receipt may be under any key the walk reached: each
  // rotation followed, and the first loadable seal of each session under
  // the key current at its line. A line past the bound that opens an
  // object could be a seal or a rotation statement, so it is no verdict;
  // any other line past it is not one JSON object, and neither.
  const seals = new Map<string, Seal>();
  // §3c: the sessions for which more than one seal loads, one of them at
  // least a seal made after an interruption; the first still anchors.
  const conflicted = new Set<string>();
  const walk = new RegistryWalk(pinned.raw, pinned.alg, (k) => budget.charge(entryCost + size(k.keyId) + 64, "the keys the registry's rotations reached"));
  // §3d: the store continuation, which loads only as the registry's first
  // line, and is never a seal or a rotation statement.
  let lineAt = -1;
  let continuation: { readonly keyId: string; readonly lines: bigint; readonly digest: string } | null = null;
  let continuationFinding: string | null = null;
  eachRegistryLine(registry, (line) => {
    lineAt++;
    if (line.bytes === null) {
      if (line.opensObject) {
        throw new NoVerdict(`a registry line of more than ${documentBound} bytes cannot be read for a seal`);
      }
      walk.take(null);
      return;
    }
    const bytes = line.bytes;
    const read = parseOr(bytes, () => {
      if (opensObject(bytes)) {
        throw new NoVerdict(`a registry line of more than ${maxValues} values cannot be read for a seal`);
      }
      return null;
    });
    if (isContinuation(read)) {
      // the line after a key-rotation that is no continuation of it
      walk.take(null);
      if (lineAt > 0) {
        continuationFinding ??= "continuation-misplaced";
      } else {
        continuation = continuationOf(read!, walk.current());
        if (continuation === null) {
          continuationFinding = "continuation-forged";
        }
      }
      return;
    }
    if (walk.take(read)) {
      return;
    }
    const current = walk.current();
    const at = walk.keys.length - 1;
    const seal = isInterruption(read)
      ? interruptionSealOf(read, current, at)
      : isVersioned(read)
        ? scopedSealOf(read, current, at)
        : sealOf(read, current, at);
    if (seal === null) {
      return;
    }
    const first = seals.get(seal.sessionId);
    if (first === undefined) {
      budget.charge(entryCost + size(seal.sessionId) + size(seal.signature) + (seal.head === undefined ? 0 : size(seal.head)) + (seal.scopeDigest === undefined ? 0 : size(seal.scopeDigest)), "the registry's seals");
      seals.set(seal.sessionId, seal);
    } else if ((first.head !== undefined || seal.head !== undefined) && !conflicted.has(seal.sessionId)) {
      budget.charge(entryCost, "the registry's seals");
      conflicted.add(seal.sessionId);
    }
  });
  walk.end();
  // §3d: under --previous, the link to the registry before this one.
  let linkFinding: string | null = null;
  if (options.previous !== undefined) {
    let before: Buffer;
    try {
      before = fs.readFileSync(options.previous);
    } catch (e) {
      throw new NoVerdict(`the previous registry cannot be read: ${options.previous}`);
    }
    const link = registryLink(before);
    const c = continuation as { readonly keyId: string; readonly lines: bigint; readonly digest: string } | null;
    if (c === null) {
      linkFinding = continuationFinding === null ? "continuation-missing" : null;
    } else if (c.lines !== link.lines) {
      linkFinding = "continuation-count-mismatch";
    } else if (c.digest !== link.digest) {
      linkFinding = "continuation-digest-mismatch";
    } else if (lastKeyOf(options.previous, pinned) !== c.keyId) {
      linkFinding = "continuation-key-mismatch";
    }
  }
  testHooks.sample?.("registry");
  const keys = walk.keys;
  // §1.3a: the removal records, under the keys the walk reached.
  const loaded = loadRemovals(root, keys, budget);
  // §4 step 9: the store's journals (ADR-0056 §6), and --require-journal.
  const journals = judgeJournals(root, registryPath, keys, continuation !== null, options.requireJournal ?? []);
  const retention: Retention = { removals: loaded.removals, supplied: options.artifacts };
  // §4 step 4: a sealed session a session-removal record names, by its id,
  // its seal's signature and count, under the seal's key or one the walk
  // reached after it, and, for a seal of version 2 or 3, by the scope it
  // names: the record's scope digested in the session -- over the record's
  // scope salt, for version 3 -- is the seal's scopeDigest.
  const removalOf = (sessionId: string): SessionRemoval | undefined => {
    const seal = seals.get(sessionId)!;
    return (loaded.sessions.get(sessionId) ?? []).find(
      (r) =>
        r.sealSignature === seal.signature &&
        r.finalCount === seal.finalCount &&
        r.keyPos >= seal.keyPos &&
        (seal.scopeDigest === undefined || namesScope(seal, sessionId, r.scope, r.scopeSalt)),
    );
  };
  const removedSession = (sessionId: string): boolean => removalOf(sessionId) !== undefined;

  for (const [session, files] of store) {
    const judged: Judged[] = [];
    const stems = new Map<string, string | undefined>();
    for (const file of files) {
      const bytes = readDocument(under(root, "receipts", session, file), "the receipt");
      const parsed = parseOr(bytes, () => {
        throw new NoVerdict(`receipt ${session}/${file} holds more than ${maxValues} values`);
      });
      stems.set(file.slice(0, -".json".length), citedSignature(parsed));
      const j = judge(parsed, sha256Hex(bytes), root, session, file, keys, authority, retention);
      // A witness named is kept beside the bound receiptCost covers: its
      // origin may be 2048 characters.
      if (j.witness !== undefined) {
        budget.charge(entryCost + size(j.witness.origin) + size(j.witness.trail) + size(j.witness.keyId), "the witnesses the receipts name");
      }
      if (j.delivery || j.reconciliation) budget.charge(2048,"action correlation fields");
      judged.push(j);
      testHooks.sample?.("receipt");
    }
    sessions.set(session, judged);
    signatures.set(session, stems);
  }
  // A verdict by scope attributes every session the store holds, and every
  // sealed one it does not, before anything is reported: it reports those of
  // the scope and those it could attribute to none (kept), and is ok only
  // where it attributed every one.
  let cut: Cut | undefined;
  const kept = new Set<string>();
  if (options.scope !== undefined) {
    const scope = options.scope;
    const of: string[] = [];
    const none: string[] = [];
    const take = (sessionId: string, a: Attribution): void => {
      if (a === "of-another") {
        return;
      }
      (a === "of-the-scope" ? of : none).push(sessionId);
      kept.add(sessionId);
    };
    for (const [session, judged] of sessions) {
      take(session, attribute(scope, session, seals.get(session), holdingOf(judged, signatures.get(session)), undefined));
    }
    for (const [sessionId, seal] of seals) {
      if (!sessions.has(sessionId)) {
        take(sessionId, attribute(scope, sessionId, seal, undefined, removalOf(sessionId)));
      }
    }
    const order = (a: string, b: string): number => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
    cut = { scope, sessions: of.sort(order), unattributed: none.sort(order) };
  }
  // keeps is whether a verdict reports a finding or an observation: every
  // one of a verdict of the whole store; of a verdict by scope, one naming a
  // session it keeps, and one naming none.
  const keeps = (f: Finding): boolean => {
    if (cut === undefined) {
      return true;
    }
    const named = f.find(([name]) => name === "sessionId");
    return named === undefined || kept.has(named[1] as string);
  };
  const reconciliationTargets = new Map<string,Judged>();
  for (const [session,judged] of sessions) for (const j of judged) if (j.delivery) reconciliationTargets.set(session+"\0"+j.file,j);
  const reconciliationUnresolved = new Set<Judged>();
  // §1.2b: what the store establishes of each uncertain action, beside ok. A
  // mismatched read-back outranks a committed one, which outranks none.
  const deliveryRank = ["action-uncertain","action-committed","action-mismatch"];
  const deliveryState = new Map<Judged,string>();
  for (const target of reconciliationTargets.values()) if (target.delivery?.outcome === "uncertain") deliveryState.set(target,"action-uncertain");
  const raise = (target: Judged, to: string): void => {
    const from = deliveryState.get(target);
    if (from !== undefined && deliveryRank.indexOf(to) > deliveryRank.indexOf(from)) deliveryState.set(target,to);
  };
  for (const judged of sessions.values()) for (const j of judged) {
    const r=j.reconciliation; if (!r) continue;
    const target=reconciliationTargets.get(r.action.sessionId+"\0"+r.action.callIndex+".json");
    const d=target?.delivery;
    // The read-back is the action's platform's live operation, over MCP.
    const live = d !== undefined && d.source.endsWith("/write") && d.source.length > "/write".length ? d.source.slice(0,-"/write".length)+"/live" : undefined;
    const matched = !(!d || target?.chain?.signature !== r.action.signature || d.key !== r.key || d.contract !== r.contract || d.outcome !== "uncertain" || d.identity !== r.identity || r.identity === "" || live === undefined || r.source !== live || r.shape !== "mcp" || target?.scope !== j.scope);
    if (!matched) reconciliationUnresolved.add(j);
    if (target !== undefined) raise(target, !matched ? "action-mismatch" : r.outcome === "committed" ? "action-committed" : "action-uncertain");
  }
  const resolves = (c: Citation): boolean => signatures.get(c.sessionId)?.get(c.callIndex) === c.signature;
  // headOf is the signature the receipt file at a seal's last index gives,
  // as a citation reads it (§3c).
  const headOf = (session: string, seal: Seal): string | undefined => signatures.get(session)?.get(String(seal.finalCount - 1n));

  // §4 step 5, now that the enumeration is whole: each action that passed
  // is read again for its citations, and must be the bytes it was.
  const unresolved = new Set<Judged>();
  for (const [session, judged] of sessions) {
    for (const j of judged) {
      if (j.action === undefined) {
        continue;
      }
      const bytes = readDocument(under(root, "receipts", session, j.file), "the receipt");
      if (sha256Hex(bytes) !== j.action.bytes) {
        throw new NoVerdict(`receipt ${session}/${j.file} changed while it was verified`);
      }
      const receipt = parse(bytes) as ObjectValue;
      if (!citations(member(member(receipt, "action") as ObjectValue, "cites")!)!.every(resolves)) {
        unresolved.add(j);
      }
    }
  }

  // §4 step 6's candidates, matched against the records the actions that
  // passed name, and step 7's findings, from one walk: each record named
  // is marked once a candidate is found to be it.
  // Each under the reading its receipt names: step 6's, or, for a receipt
  // whose decision.recordBytes is "exact", a line's exact bytes.
  const named = new Map<string, boolean>();
  const namedExact = new Map<string, boolean>();
  for (const judged of sessions.values()) {
    for (const j of judged) {
      if (j.action !== undefined) {
        (j.action.exact ? namedExact : named).set(j.action.recordDigest, false);
      }
    }
  }
  const recordFindings = new RecordFindings(budget);
  // §4 step 8's reading of each record named and found: a record, read,
  // that is a runtime evaluation record has its claims kept; a record found
  // and not kept here is not compared.
  const claims = new Map<string, Claims>();
  const claimsExact = new Map<string, Claims>();
  eachDecisionRecord(records, budget, (candidate) => {
    testHooks.sample?.("candidate");
    const digest = "sha256:" + candidate.digest;
    const exactDigest = "sha256:" + (candidate.exact?.digest ?? candidate.digest);
    // A step 6 candidate is one that is not empty under its reading; a
    // line of a carriage return alone is a candidate under the exact
    // reading only.
    const stepSix = candidate.bytes === null || candidate.bytes.length > 0 || candidate.exact === undefined;
    if (stepSix && named.has(digest)) {
      named.set(digest, true);
    }
    if (namedExact.has(exactDigest)) {
      namedExact.set(exactDigest, true);
    }
    if (candidate.bytes === null) {
      // Past the bound: a candidate that does not open an object is not
      // one JSON object, and one that does cannot be read for its cites.
      // A .jsonl file whole comes here too, and is read for nothing.
      if (candidate.opensObject) {
        throw new NoVerdict(`a decision record of more than ${documentBound} bytes cannot be read for its citations`);
      }
      return;
    }
    if (!stepSix) {
      // a carriage return alone: no record, and nothing for step 7
      return;
    }
    const bytes = candidate.bytes;
    const record = parseOr(bytes, () => {
      if (opensObject(bytes)) {
        throw new NoVerdict(`a decision record of more than ${maxValues} values cannot be read for its citations`);
      }
      return null;
    });
    const status = recordCitations(record, resolves);
    if (status !== null) {
      recordFindings.add(candidate.digest, status);
    }
    // The claims of a record named and found, under each reading: under
    // the exact one the record's bytes are the line's and its carriage
    // return, which is whitespace to JSON, so they are read the same.
    for (const [key, wanted, kept] of [
      [digest, named, claims],
      [exactDigest, namedExact, claimsExact],
    ] as const) {
      if (wanted.has(key) && !kept.has(key)) {
        const read = recordClaims(record);
        if (read !== null) {
          budget.charge(entryCost + size(key) + size(read.packDigest) + size(read.citesKey ?? "") + size(read.trail ?? ""), "the claims of the decision records named");
          kept.set(key, read);
        }
      }
    }
  });
  testHooks.sample?.("decision records");

  // The findings, made from what was kept, each time they are read.
  function* everyFinding(): Generator<Finding> {
    yield* journals.findings;
    for (const [session, judged] of sessions) {
      for (const j of judged) {
        if (j.status === "malformed") {
          yield [
            ["sessionId", session],
            ["file", j.file],
            ["status", "malformed"],
          ];
        } else {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", j.status],
          ];
        }
      }
      // The sequence and the chain, over the receipts that passed.
      const broken = sessionBreak(judged);
      if (broken !== null) {
        yield [
          ["sessionId", session],
          ["callIndex", null],
          ["status", broken],
        ];
      }
      // §4 step 3: the session's count is its .json files, whether or not
      // each verified.
      const seal = seals.get(session);
      const have = BigInt(judged.length);
      if (seal === undefined) {
        yield [
          ["sessionId", session],
          ["status", "unregistered-session"],
        ];
      } else if (have !== seal.finalCount) {
        yield [
          ["sessionId", session],
          ["status", have < seal.finalCount ? "tail-rollback" : "count-exceeds-seal"],
          ["have", have],
          ["sealed", seal.finalCount],
        ];
      } else if (seal.head !== undefined && headOf(session, seal) !== seal.head) {
        // §3c: the receipt file at the last index it seals gives another
        // signature than the one it names.
        yield [
          ["sessionId", session],
          ["status", "seal-head-mismatch"],
        ];
      } else if (seal.head !== undefined && ordinarySealsOnly) {
        yield [
          ["sessionId", session],
          ["status", "sealed-after-interruption"],
        ];
      }
      // ADR-0036: a seal naming a scope identifier says every receipt it
      // counts is of that scope -- for a seal of version 3, under the salt
      // it is taken over (ADR-0042); an accepted receipt of another, or of
      // none, is found once, beside whatever else the session finds.
      if (seal?.scopeDigest !== undefined && judged.some((j) => j.status === "ok" && (j.scope === undefined || !namesScope(seal, session, j.scope, j.scopeSalt)))) {
        yield [
          ["sessionId", session],
          ["status", "seal-scope-mismatch"],
        ];
      }
      for (const j of judged) if (reconciliationUnresolved.has(j)) yield [["sessionId",session],["callIndex",j.callIndex!],["status","action-reconciliation-unresolved"]];
      // §4 steps 5 and 6, for each version 3 action receipt that passed.
      for (const j of judged) {
        if (j.action === undefined) {
          continue;
        }
        if (unresolved.has(j)) {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", "citation-unresolved"],
          ];
        }
        const [found, compared] = j.action.exact ? [namedExact, claimsExact] : [named, claims];
        if (found.get(j.action.recordDigest) !== true) {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", "decision-record-mismatch"],
          ];
          continue;
        }
        // §4 step 8: the record found, when it is a runtime evaluation
        // record, bears out the pack and the citations the action claims.
        const c = compared.get(j.action.recordDigest);
        if (c === undefined) {
          continue;
        }
        if (c.packDigest !== j.action.packDigest) {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", "decision-pack-mismatch"],
          ];
        }
        if (c.citesKey !== j.action.citesKey) {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", "decision-cites-mismatch"],
          ];
        }
        // ADR-0014: a witness named on an action is named for the trail of
        // the record it was minted on.
        if (j.action.witnessTrail !== undefined && c.trail !== j.action.witnessTrail) {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", "decision-trail-mismatch"],
          ];
        }
      }
    }
    // §4 step 4: each sealed session the store does not hold, unless a
    // session-removal record names it, which is observed instead.
    for (const sessionId of seals.keys()) {
      if (!sessions.has(sessionId) && !removedSession(sessionId)) {
        yield [
          ["sessionId", sessionId],
          ["status", "sealed-session-missing"],
        ];
      }
    }
    // §3c: two answers to how a session closed, found once, whether or
    // not the store holds it.
    for (const sessionId of seals.keys()) {
      if (conflicted.has(sessionId)) {
        yield [
          ["sessionId", sessionId],
          ["status", "seal-conflict"],
        ];
      }
    }
    yield* recordFindings.findings();
    // §3b: the walk's finding, naming the rotation it could not take.
    if (walk.finding !== null) {
      const status: RotationStatus = walk.finding.status;
      yield [
        ["status", status],
        ["rotation", walk.finding.rotation],
      ];
    }
    // §3d: a store continuation that does not load where it stands, and
    // under --previous a link that does not hold.
    if (continuationFinding !== null) {
      yield [["status", continuationFinding]];
    }
    if (linkFinding !== null) {
      yield [["status", linkFinding]];
    }
  }
  // The observations, in the order the reference reports them: §1.2b's of
  // each uncertain action; §4 step 3's of each open session; and §4 step
  // 8's of each action whose record was found and is not a runtime
  // evaluation record, which is not compared.
  function* everyObservation(): Generator<Finding> {
    yield* journals.observations;
    // §3d's, of a registry whose first line is a store continuation that
    // loads.
    const c = continuation as { readonly keyId: string; readonly lines: bigint; readonly digest: string } | null;
    if (c !== null) {
      yield [["observation", "continues-from"], ["previousLines", c.lines], ["previousDigest", c.digest]];
    }
    // §1.3a's, of each receipt that passed with no bytes re-digested.
    for (const [session, judged] of sessions) {
      for (const j of judged) {
        if (j.status === "ok" && j.observation !== undefined) yield [["sessionId", session],["callIndex", j.callIndex!],["observation", j.observation]];
      }
    }
    for (const [session, judged] of sessions) {
      for (const j of judged) {
        const delivery = deliveryState.get(j);
        if (delivery !== undefined) yield [["sessionId", session],["callIndex", j.callIndex!],["observation", delivery]];
      }
    }
    // §4's approval-cited-again: an action that passed and cites a single
    // record whose id and digest another action of the store also cites.
    const citing = new Map<string, number>();
    for (const judged of sessions.values()) for (const j of judged) if (j.status === "ok") for (const a of j.action?.approvals ?? []) citing.set(a.id + "\0" + a.digest, (citing.get(a.id + "\0" + a.digest) ?? 0) + 1);
    for (const [session, judged] of sessions) {
      for (const j of judged) {
        if (j.status === "ok" && (j.action?.approvals ?? []).some((a) => a.kind === "single" && (citing.get(a.id + "\0" + a.digest) ?? 0) > 1)) yield [["sessionId", session],["callIndex", j.callIndex!],["observation", "approval-cited-again"]];
      }
    }
    // §4 step 3's observation: a session no seal closes, holding receipts
    // every one of which passed, in sequence and chained, is open, on its
    // last receipt; its unregistered-session finding stands beside it.
    // A session a seal made after an interruption anchors, whose count
    // and last receipt hold it, is observed sealed so on that receipt
    // (§3c), unless the verdict takes only ordinary seals, where it is a
    // finding instead.
    for (const [session, judged] of sessions) {
      const seal = seals.get(session);
      if (seal === undefined && judged.length > 0 && judged.every((j) => j.status === "ok") && sessionBreak(judged) === null) {
        yield [
          ["sessionId", session],
          ["callIndex", BigInt(judged.length) - 1n],
          ["observation", "session-open"],
        ];
      } else if (seal?.head !== undefined && !ordinarySealsOnly && BigInt(judged.length) === seal.finalCount && headOf(session, seal) === seal.head) {
        yield [
          ["sessionId", session],
          ["callIndex", seal.finalCount - 1n],
          ["observation", "sealed-after-interruption"],
        ];
      }
    }
    // §4 step 4's: a sealed session the store does not hold that a
    // session-removal record names, of the session and not of a receipt.
    for (const sessionId of seals.keys()) {
      if (!sessions.has(sessionId) && removedSession(sessionId)) {
        yield [
          ["sessionId", sessionId],
          ["observation", "session-removed"],
        ];
      }
    }
    for (const [session, judged] of sessions) {
      for (const j of judged) {
        if (j.action === undefined) {
          continue;
        }
        const [found, compared] = j.action.exact ? [namedExact, claimsExact] : [named, claims];
        if (found.get(j.action.recordDigest) === true && !compared.has(j.action.recordDigest)) {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["observation", "decision-record-not-compared"],
          ];
        }
      }
    }
  }
  function* findings(): Generator<Finding> {
    for (const f of everyFinding()) {
      if (keeps(f)) {
        yield f;
      }
    }
  }
  function* observations(): Generator<Finding> {
    for (const o of everyObservation()) {
      if (keeps(o)) {
        yield o;
      }
    }
  }
  // The witnesses the receipts that passed name, each once (ADR-0014); of
  // a verdict by scope, those of the sessions it keeps.
  function* witnesses(): Generator<Witness> {
    const seen = new Set<string>();
    for (const [session, judged] of sessions) {
      if (cut !== undefined && !kept.has(session)) {
        continue;
      }
      for (const j of judged) {
        if (j.witness === undefined) {
          continue;
        }
        const key = `${j.witness.trail}\n${j.witness.origin}\n${j.witness.keyId}`;
        if (!seen.has(key)) {
          seen.add(key);
          yield j.witness;
        }
      }
    }
  }
  // The verdict is ok when every finding's status is; an observation is no
  // part of it, and neither is a witness named.
  let ok = cut === undefined || cut.unattributed.length === 0;
  for (const f of findings()) {
    ok &&= f.some(([name, value]) => name === "status" && value === "ok");
  }
  return {
    ok,
    ...(cut !== undefined && { cut }),
    findings: { [Symbol.iterator]: findings },
    observations: { [Symbol.iterator]: observations },
    witnesses: { [Symbol.iterator]: witnesses },
    rotations: walk.followed() > 0 ? { count: walk.followed(), keyId: walk.current().keyId } : null,
  };
}

// sessionBreak is what the sequence and the chain of a session's receipts
// that passed say of it (§1.4): sequence-broken when their indices are
// not 0 to n-1, chain-broken at the first receipt that does not link to the
// one before it, is of another version than the first, or is under a key
// the walk of the registry reached before the key of the one before it
// (§3b); null when they hold.
function sessionBreak(judged: readonly Judged[]): "sequence-broken" | "chain-broken" | null {
  const passing = judged.filter((j) => j.status === "ok").sort((a, b) => (a.callIndex! < b.callIndex! ? -1 : 1));
  if (passing.some((j, i) => j.callIndex !== BigInt(i))) {
    return "sequence-broken";
  }
  const head = passing[0]?.chain!.version;
  for (let i = 0; i < passing.length; i++) {
    const { version, prev, keyPos } = passing[i]!.chain!;
    const expected = i === 0 ? null : passing[i - 1]!.chain!.signature;
    const linked = expected === null ? prev.kind === "null" : prev.kind === "string" && prev.value === expected;
    // A session runs forward through a rotation and never back (§3b).
    const back = i > 0 && keyPos < passing[i - 1]!.chain!.keyPos;
    if (!linked || version !== head || back) {
      return "chain-broken";
    }
  }
  return null;
}

// recordClaims is §4 step 8's reading of a record: its claims when it is a
// runtime evaluation record -- one JSON object, no name given twice at any
// depth and no surrogate alone in any string, whose recordVersion is "1",
// whose kind is "evaluation" and whose pack's digest is a digest -- and
// null when it is not one. A number of any form is admitted, as the
// runtime writes its facts.
function recordClaims(record: Value | null): Claims | null {
  if (record === null || record.type !== "object" || hasDuplicate(record) || hasLoneSurrogate(record)) {
    return null;
  }
  const pack = member(record, "pack");
  const packDigest = pack?.type === "object" ? str(member(pack, "digest")) : undefined;
  if (str(member(record, "recordVersion")) !== "1" || str(member(record, "kind")) !== "evaluation" || packDigest === undefined || !/^sha256:[0-9a-f]{64}$/.test(packDigest)) {
    return null;
  }
  const cites = member(record, "cites");
  let key: string | null = citesKey([]);
  if (cites !== undefined) {
    const cited = canonical(cites) !== null ? citations(cites) : null;
    key = cited === null ? null : citesKey(cited);
  }
  const trail = str(member(record, "trail"));
  return { packDigest: own(packDigest), citesKey: key, trail: trail === undefined || trail.length > 64 ? null : own(trail) };
}

// hasLoneSurrogate is whether any string in the value, a member's name
// included, holds a surrogate that is not one of a pair.
function hasLoneSurrogate(v: Value): boolean {
  const work: Value[] = [v];
  for (let w = work.pop(); w !== undefined; w = work.pop()) {
    if (w.type === "string" && !w.value.isWellFormed()) {
      return true;
    }
    if (w.type === "array") {
      // one at a time: an array's items spread as arguments would pass the
      // engine's limit on arguments for a wide array
      for (const item of w.items) {
        work.push(item);
      }
    } else if (w.type === "object") {
      for (const m of w.members) {
        if (!m.name.isWellFormed()) {
          return true;
        }
        work.push(m.value);
      }
    }
  }
  return false;
}

// RecordFindings is §4 step 7's findings, kept as 33 bytes each -- a
// record's digest and its status -- in a buffer charged to the budget as
// it grows.
class RecordFindings {
  private buffer = Buffer.alloc(0);
  private n = 0;
  private readonly budget: Budget;

  constructor(budget: Budget) {
    this.budget = budget;
  }

  add(digestHex: string, status: "record-citation-malformed" | "record-citation-unresolved"): void {
    if ((this.n + 1) * 33 > this.buffer.length) {
      const grown = Math.max(33 * 16, this.buffer.length * 2);
      this.budget.charge(grown - this.buffer.length, "the decision records' findings");
      const buffer = Buffer.alloc(grown);
      this.buffer.copy(buffer);
      this.buffer = buffer;
    }
    this.buffer.write(digestHex, this.n * 33, "hex");
    this.buffer[this.n * 33 + 32] = status === "record-citation-malformed" ? 0 : 1;
    this.n++;
  }

  *findings(): Generator<Finding> {
    for (let i = 0; i < this.n; i++) {
      yield [
        ["recordDigest", "sha256:" + this.buffer.toString("hex", i * 33, i * 33 + 32)],
        ["status", this.buffer[i * 33 + 32] === 0 ? "record-citation-malformed" : "record-citation-unresolved"],
      ];
    }
  }
}

// recordCitations is §4 step 7's finding for a candidate it reads, or
// null: one that is one JSON object with a top-level cites member is a
// record that cites, its cites held to the canonical domain and to the
// shape of action.cites, and each entry resolved.
function recordCitations(record: Value | null, resolves: (c: Citation) => boolean): "record-citation-malformed" | "record-citation-unresolved" | null {
  if (record === null || record.type !== "object") {
    return null;
  }
  const n = count(record, "cites");
  if (n === 0) {
    return null;
  }
  const cites = member(record, "cites")!;
  const cited = n === 1 && canonical(cites) !== null ? citations(cites) : null;
  if (cited === null) {
    return "record-citation-malformed";
  }
  return cited.every(resolves) ? null : "record-citation-unresolved";
}

// writeVerdict writes the verdict as the process contract does, a finding
// at a time: no more of it is handed to write at once than one finding.
// Observations follow the findings, when there are any.
export function writeVerdict(v: Verdict, write: (text: string) => void): void {
  const entry = (f: Finding) =>
    "{" + f.map(([name, value]) => JSON.stringify(name) + ":" + (typeof value === "bigint" ? value.toString() : JSON.stringify(value))).join(",") + "}";
  write(`{"ok":${v.ok},"findings":[`);
  let first = true;
  for (const f of v.findings) {
    write((first ? "" : ",") + entry(f));
    first = false;
  }
  // The findings' close is written with the first observation, so a
  // verdict with none is written as it always was; so are the witnesses.
  let observed = false;
  for (const o of v.observations) {
    write((observed ? "," : `],"observations":[`) + entry(o));
    observed = true;
  }
  let named = false;
  for (const w of v.witnesses) {
    write((named ? "," : `],"witnesses":[`) + JSON.stringify({ trail: w.trail, origin: w.origin, keyId: w.keyId }));
    named = true;
  }
  // The rotations followed close the verdict, with the last array.
  const rotations = v.rotations === null ? "" : `,"rotations":${JSON.stringify({ count: v.rotations.count, keyId: v.rotations.keyId })}`;
  const cut = v.cut === undefined ? "" : `,"cut":${JSON.stringify({ scope: v.cut.scope, sessions: v.cut.sessions, unattributed: v.cut.unattributed })}`;
  write(`]${rotations}${cut}}\n`);
}

// registryLink is what a store continuation names of a registry (§3d): its
// line count, an empty piece after the last line feed no line, and the
// SHA-256 of its bytes, whole.
function registryLink(data: Buffer): { readonly lines: bigint; readonly digest: string } {
  const digest = crypto.createHash("sha256").update(data).digest("hex");
  if (data.length === 0) {
    return { lines: 0n, digest };
  }
  const end = data[data.length - 1] === 0x0a ? data.length - 1 : data.length;
  let count = 1n;
  for (let i = 0; i < end; i++) {
    if (data[i] === 0x0a) {
      count++;
    }
  }
  return { lines: count, digest };
}

// lastKeyOf is the key id the registry at previous's rotations end at (§3d, under
// --previous), walked as a gateway walks its own (§3b): from the previous key
// its first key-continuation names, where it has one, and from the key pinned
// otherwise; null where the walk finds a rotation finding, or where the
// keyId its last seal states is not the key in force at that seal's line, so
// that a registry that never rotated is held to the key its seals name. A
// registry holding no seal is held by its walk's last key alone.
function lastKeyOf(previous: string, pinned: { readonly raw: Uint8Array; readonly alg: Alg }): string | null {
  const values: (Value | null)[] = [];
  eachRegistryLine({ absent: false, path: previous }, (line) => {
    if (line.bytes === null) {
      if (line.opensObject) {
        throw new NoVerdict(`a line of the previous registry of more than ${documentBound} bytes cannot be read`);
      }
      values.push(null);
      return;
    }
    const bytes = line.bytes;
    values.push(
      parseOr(bytes, () => {
        if (opensObject(bytes)) {
          throw new NoVerdict(`a line of the previous registry of more than ${maxValues} values cannot be read`);
        }
        return null;
      }),
    );
  });
  let start = pinned;
  for (const v of values) {
    const statement = rotationKind(v);
    if (statement?.kind !== "key-continuation") {
      continue;
    }
    // with its previousAlg (ADR-0053 §7, "The gateway's own reading")
    const previous = member(statement.value, "previous");
    const alg = recordAlg(statement.value, "previousAlg");
    if (alg !== null && previous?.type === "string" && new RegExp(`^[0-9a-fA-F]{${alg === "ES256" ? 66 : 64}}$`).test(previous.value)) {
      start = { raw: Buffer.from(previous.value, "hex"), alg };
    }
    break;
  }
  const walk = new RegistryWalk(start.raw, start.alg, () => {});
  // the last seal: the keyId it states, and the key in force at its line
  let lastSeal: { readonly stated: string; readonly inForce: string } | null = null;
  for (const v of values) {
    if (walk.take(isContinuation(v) ? null : v) || isContinuation(v) || rotationKind(v) !== null || v === null || v.type !== "object") {
      continue;
    }
    const keyId = member(v, "keyId");
    const session = member(v, "sessionId");
    if (keyId?.type === "string" && session?.type === "string") {
      lastSeal = { stated: keyId.value, inForce: walk.current().keyId };
    }
  }
  walk.end();
  const seal = lastSeal as { readonly stated: string; readonly inForce: string } | null;
  if (walk.finding !== null || (seal !== null && seal.stated !== seal.inForce)) {
    return null;
  }
  return walk.current().keyId;
}

// --- §3f and §4 step 9: the journals (ADR-0056) -----------------------------

const journalPrefix = "judgment-pack-gateway/journal-entry/1:";
const journalLineBound = 4096;
const removalLineBound = 4096;
const journalEnvelope = ["journal", "journalVersion", "ordinal", "previous", "at", "keyId", "alg", "body", "signature"];
// The operator journal's body kinds, each with exactly its members beside
// kind, registryFrom and removalFrom: true where the member is required.
const operatorBodies: ReadonlyMap<string, ReadonlyMap<string, boolean>> = new Map([
  ["retain", new Map([["by", true], ["scope", false], ["acknowledgments", true], ["acknowledgedBy", true], ["sessions", true], ["removalBytes", true], ["removalDigest", true]])],
  ["remove-scope", new Map([["by", true], ["scope", true], ["removalBytes", true], ["removalDigest", true]])],
  ["remove-artifact", new Map([["by", true], ["removalBytes", true], ["removalDigest", true]])],
  ["seal-open", new Map([["seals", true], ["sealDigest", true], ["delivered", true]])],
  ["store-rotate", new Map([["seals", true], ["sealDigest", true], ["delivered", true]])],
  ["store-continued", new Map([["continuation", true], ["previousJournalBytes", true], ["previousJournalDigest", true]])],
]);

interface JournalEntry {
  readonly ordinal: number;
  readonly previous: string | undefined;
  readonly keyPos: number;
  readonly kind: string;
  readonly registryFrom: number;
  readonly removalFrom: number;
  readonly removal: boolean;
  readonly removalBytes: number;
  readonly removalDigest: string;
  readonly sealing: boolean;
  readonly seals: number;
  readonly sealDigest: string;
  readonly continuation: string;
}

function countOf(v: Value | undefined): number | null {
  if (v === undefined || v.type !== "number" || v.integer === null || v.integer < 0n || v.integer > 2n ** 53n - 1n) {
    return null;
  }
  return Number(v.integer);
}

function hexOf(v: Value | undefined, n: number): string | undefined {
  return v?.type === "string" && v.value.length === n && /^[0-9a-f]*$/.test(v.value) ? v.value : undefined;
}

function isEntryInstant(at: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(at)) {
    return false;
  }
  const d = new Date(at);
  return !Number.isNaN(d.getTime()) && d.toISOString() === at.replace("Z", ".000Z");
}

function journalBodyOf(body: ObjectValue): Omit<JournalEntry, "ordinal" | "previous" | "keyPos"> | null {
  const kind = str(member(body, "kind"));
  const members = kind === undefined ? undefined : operatorBodies.get(kind);
  if (kind === undefined || members === undefined) {
    return null;
  }
  const allowed = new Set(["kind", "registryFrom", "removalFrom", ...members.keys()]);
  for (const [name, required] of members) {
    if (required && member(body, name) === undefined) {
      return null;
    }
  }
  if (!body.members.every((m) => allowed.has(m.name))) {
    return null;
  }
  const registryFrom = countOf(member(body, "registryFrom"));
  const removalFrom = countOf(member(body, "removalFrom"));
  if (registryFrom === null || removalFrom === null) {
    return null;
  }
  const e = { kind, registryFrom, removalFrom, removal: false, removalBytes: 0, removalDigest: "", sealing: false, seals: 0, sealDigest: "", continuation: "" };
  for (const name of members.keys()) {
    const m = member(body, name);
    if (m === undefined) {
      continue;
    }
    let holds = false;
    switch (name) {
      case "by":
      case "scope":
        holds = m.type === "string" && isScopeIdentifier(m.value);
        break;
      case "acknowledgments":
      case "previousJournalDigest":
        holds = hexOf(m, 64) !== undefined;
        break;
      case "removalDigest":
        e.removalDigest = hexOf(m, 64) ?? "";
        holds = e.removalDigest !== "";
        break;
      case "sealDigest":
        e.sealDigest = hexOf(m, 64) ?? "";
        holds = e.sealDigest !== "";
        break;
      case "continuation":
        e.continuation = hexOf(m, 64) ?? "";
        holds = e.continuation !== "";
        break;
      case "acknowledgedBy":
        holds = m.type === "array" && m.items.length >= 1 && m.items.length <= 4 && m.items.every((id) => hexOf(id, 32) !== undefined);
        break;
      case "sessions":
      case "previousJournalBytes":
        holds = countOf(m) !== null;
        break;
      case "removalBytes": {
        const n = countOf(m);
        holds = n !== null;
        e.removalBytes = n ?? 0;
        e.removal = holds;
        break;
      }
      case "seals": {
        const n = countOf(m);
        holds = n !== null;
        e.seals = n ?? 0;
        e.sealing = holds;
        break;
      }
      case "delivered":
        holds = m.type === "boolean";
        break;
    }
    if (!holds) {
      return null;
    }
  }
  return e;
}

// journalEntryOf is a complete line of a journal as an entry that loads
// (ADR-0056 §6, journal-entry-forged); null for one that does not.
function journalEntryOf(line: Buffer, journal: string, keys: readonly ReachedKey[]): JournalEntry | null {
  if (line.length > journalLineBound) {
    return null;
  }
  const v = parseOr(line, () => null);
  if (v === null || v.type !== "object" || hasDuplicate(v)) {
    return null;
  }
  const canon = canonical(v);
  if (canon === null || !Buffer.from(canon).equals(line) || !v.members.every((m) => journalEnvelope.includes(m.name))) {
    return null;
  }
  if (str(member(v, "journal")) !== journal || str(member(v, "journalVersion")) !== "1") {
    return null;
  }
  const ordinal = countOf(member(v, "ordinal"));
  const hasPrevious = member(v, "previous") !== undefined;
  const previous = hexOf(member(v, "previous"), 64);
  const at = str(member(v, "at"));
  const keyId = hexOf(member(v, "keyId"), 32);
  const signature = hexOf(member(v, "signature"), 128);
  const body = member(v, "body");
  if (ordinal === null || (hasPrevious && previous === undefined) || at === undefined || !isEntryInstant(at) || keyId === undefined || signature === undefined || body?.type !== "object") {
    return null;
  }
  const e = journalBodyOf(body);
  if (e === null) {
    return null;
  }
  const keyPos = keys.findIndex((k) => k.keyId === keyId);
  const alg = recordAlg(v, "alg");
  if (keyPos < 0 || alg === null || keys[keyPos]!.alg !== alg) {
    return null;
  }
  const payload: ObjectValue = { type: "object", members: v.members.filter((m) => m.name !== "signature") };
  if (!signed(keys[keyPos]!, alg, journalPrefix, payload, signature)) {
    return null;
  }
  return { ...e, ordinal, previous, keyPos };
}

const scopeRemovalPrefix = "judgment-pack-gateway/scope-removal/1:";
const scopeRemovalMembers = ["keyId", "kind", "openSessions", "payloads", "receipts", "removedAt", "removedBy", "scope", "sealedSessions", "signature"];

// scopeRemovalLoads is whether a line of the removal file is a scope-removal
// record that loads (§1.3a): read by no step of §4 but this one's torn tail.
function scopeRemovalLoads(v: Value | null, keys: readonly ReachedKey[]): boolean {
  if (v === null || v.type !== "object" || hasDuplicate(v)) {
    return false;
  }
  const names = member(v, "alg") !== undefined ? [...scopeRemovalMembers, "alg"] : scopeRemovalMembers;
  const alg = recordAlg(v, "alg");
  if (alg === null || !v.members.every((m) => names.includes(m.name))) {
    return false;
  }
  const scope = str(member(v, "scope"));
  const removedAt = str(member(v, "removedAt"));
  const removedBy = str(member(v, "removedBy"));
  const keyId = hexOf(member(v, "keyId"), 32);
  const signature = hexOf(member(v, "signature"), 128);
  if (
    str(member(v, "kind")) !== "scope-removal" ||
    scope === undefined || !isScopeIdentifier(scope) ||
    ["sealedSessions", "openSessions", "receipts", "payloads"].some((n) => countOf(member(v, n)) === null) ||
    removedAt === undefined || !isRemovalTime(removedAt) ||
    removedBy === undefined || !isScopeIdentifier(removedBy) ||
    keyId === undefined || signature === undefined
  ) {
    return false;
  }
  const keyPos = keys.findIndex((k) => k.keyId === keyId);
  if (keyPos < 0 || keys[keyPos]!.alg !== alg) {
    return false;
  }
  const payload: ObjectValue = { type: "object", members: v.members.filter((m) => m.name !== "signature") };
  return signed(keys[keyPos]!, alg, scopeRemovalPrefix, payload, signature);
}

// pieceLoads is whether a torn piece of the removal file, read as a line,
// loads as a removal record of any kind (ADR-0056, Amendment B).
function pieceLoads(piece: Buffer, keys: readonly ReachedKey[]): boolean {
  if (piece.length === 0 || piece.length > removalLineBound) {
    return false;
  }
  const v = parseOr(piece, () => null);
  if (v === null || v.type !== "object") {
    return false;
  }
  switch (str(member(v, "kind"))) {
    case "artifact-removal":
      return removalOf(v, keys) !== null;
    case "session-removal":
      return sessionRemovalOf(v, keys) !== null;
    case "scope-removal":
      return scopeRemovalLoads(v, keys);
  }
  return false;
}

function splitLines(data: Buffer): { lines: Buffer[]; torn: number } {
  const lines: Buffer[] = [];
  let at = 0;
  for (let i = data.indexOf(0x0a, at); i >= 0; i = data.indexOf(0x0a, at)) {
    lines.push(data.subarray(at, i));
    at = i + 1;
  }
  return { lines, torn: data.length - at };
}

// commandSealsOf is each registry line §1.1's parser reads as one JSON
// object of kind seal-after-interruption and sealedVia command, whether or
// not it loads: where it starts, and its bytes with its 0x0A.
function commandSealsOf(registry: Buffer): { readonly at: number; readonly line: Buffer }[] {
  const out: { at: number; line: Buffer }[] = [];
  let at = 0;
  for (let i = registry.indexOf(0x0a, at); i >= 0; i = registry.indexOf(0x0a, at)) {
    const v = parseOr(registry.subarray(at, i), () => null);
    if (v !== null && v.type === "object" && !hasDuplicate(v) && str(member(v, "kind")) === "seal-after-interruption" && str(member(v, "sealedVia")) === "command") {
      out.push({ at, line: registry.subarray(at, i + 1) });
    }
    at = i + 1;
  }
  return out;
}

function journalFinding(status: string, journal: string, ordinal: number): Finding {
  return [["status", status], ["journal", journal], ["ordinal", BigInt(ordinal)]];
}

// judgeOperatorJournal is §4 step 9 for the operator journal: at most one
// finding, the first of journal-entry-forged, journal-order,
// journal-entry-mismatch and journal-entry-missing.
function judgeOperatorJournal(data: Buffer, pending: boolean, keys: readonly ReachedKey[], registry: Buffer, removal: Buffer, continued: boolean) {
  const name = "operator";
  const entries: JournalEntry[] = [];
  const { lines } = splitLines(data);
  for (const [i, line] of lines.entries()) {
    const e = journalEntryOf(line, name, keys);
    if (e === null) {
      return { entries, finding: journalFinding("journal-entry-forged", name, i), tornAt: 0, torn: 0 };
    }
    entries.push(e);
  }
  for (const [i, e] of entries.entries()) {
    if (e.ordinal !== i || (i === 0 && e.previous !== undefined) || (i > 0 && (e.previous === undefined || e.previous !== sha256Hex(lines[i - 1]!))) || (i > 0 && e.keyPos < entries[i - 1]!.keyPos)) {
      return { entries, finding: journalFinding("journal-order", name, i), tornAt: 0, torn: 0 };
    }
  }
  const seals = commandSealsOf(registry);
  let gap = false;
  let tornAt = 0;
  let torn = 0;
  let unnamed = 0;
  if (entries.length > 0) {
    const first = entries[0]!;
    let cursor = first.removalFrom;
    let taken = 0;
    let registryAt = 0;
    while (taken < seals.length && seals[taken]!.at < first.registryFrom) {
      taken++;
    }
    for (const [i, e] of entries.entries()) {
      let mismatch = e.removalFrom < cursor || e.removalFrom > removal.length || e.registryFrom > registry.length || e.registryFrom < registryAt;
      registryAt = e.registryFrom;
      if (!mismatch && e.removal) {
        const end = e.removalFrom + e.removalBytes;
        if (end > removal.length || sha256Hex(removal.subarray(e.removalFrom, end)) !== e.removalDigest) {
          mismatch = true;
        } else {
          gap ||= e.removalFrom > cursor;
          cursor = end;
        }
      } else if (!mismatch && e.sealing) {
        if (seals.length - taken < e.seals || sha256Hex(Buffer.concat(seals.slice(taken, taken + e.seals).map((s) => s.line))) !== e.sealDigest) {
          mismatch = true;
        } else {
          taken += e.seals;
        }
      } else if (!mismatch && e.kind === "store-continued") {
        const nl = registry.indexOf(0x0a);
        const firstLine = nl < 0 ? registry : registry.subarray(0, nl);
        mismatch = i !== 0 || !continued || sha256Hex(firstLine) !== e.continuation;
      }
      if (mismatch) {
        return { entries, finding: journalFinding("journal-entry-mismatch", name, i), tornAt: 0, torn: 0 };
      }
    }
    // the one uncovered piece that is no finding (Amendment B)
    const start = removal.lastIndexOf(0x0a) + 1;
    const piece = removal.subarray(start);
    if (!gap && !pending && piece.length > 0 && cursor === start && !pieceLoads(piece, keys)) {
      tornAt = start;
      torn = piece.length;
    } else {
      gap ||= cursor < removal.length;
    }
    unnamed = seals.length - taken;
  }
  if (pending || gap || unnamed > 0) {
    return { entries, finding: journalFinding("journal-entry-missing", name, entries.length), tornAt: 0, torn: 0 };
  }
  return { entries, finding: undefined, tornAt, torn };
}

// readUnder is the bytes of a regular file under root, following no link,
// and whether one is there: "other" for something there that is not one.
function readUnder(root: string, ...names: string[]): Buffer | "absent" | "other" {
  let at = root;
  for (const [i, name] of names.entries()) {
    at = path.join(at, name);
    let info: fs.Stats;
    try {
      info = fs.lstatSync(at);
    } catch {
      return "absent";
    }
    if (i < names.length - 1 ? !info.isDirectory() : !info.isFile()) {
      return i < names.length - 1 ? "absent" : "other";
    }
  }
  return fs.readFileSync(at);
}

// judgeJournals is §4 step 9 on a store's root, and --require-journal: the
// findings and observations it adds to the verdict.
function judgeJournals(root: string, registryPath: string, keys: readonly ReachedKey[], continued: boolean, required: readonly string[]): { findings: Finding[]; observations: Finding[] } {
  const findings: Finding[] = [];
  const observations: Finding[] = [];
  // any file of journals/ but the operator journal's two is journal-unknown,
  // by its name, in name order: a journal this verifier cannot judge is never
  // passed over as though it held
  const dir = path.join(root, "journals");
  let entries: fs.Dirent[] = [];
  try {
    if (fs.lstatSync(dir).isDirectory()) {
      entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT" && (err as NodeJS.ErrnoException).code !== "ENOTDIR") {
      throw err;
    }
  }
  // a known name that is not a regular file (a link, a directory, a pipe)
  // is not read either, and is named with the rest rather than read as no
  // journal
  for (const e of entries) {
    if ((e.name !== "operator.jsonl" && e.name !== "operator.pending") || !e.isFile()) {
      findings.push([["status", "journal-unknown"], ["file", e.name]]);
    }
  }
  const read = readUnder(root, "journals", "operator.jsonl");
  const data = typeof read === "string" ? Buffer.alloc(0) : read;
  const pending = readUnder(root, "journals", "operator.pending") !== "absent";
  const removalRead = readUnder(root, "artifact-removals.jsonl");
  const removal = typeof removalRead === "string" ? Buffer.alloc(0) : removalRead;
  let registry: Buffer;
  try {
    registry = fs.readFileSync(registryPath);
  } catch {
    registry = Buffer.alloc(0);
  }
  const evidence = removal.includes(0x0a) || commandSealsOf(registry).length > 0;
  const held = new Set<string>();
  if (splitLines(data).lines.length > 0 || pending) {
    held.add("operator");
    const j = judgeOperatorJournal(data, pending, keys, registry, removal, continued);
    if (j.finding !== undefined) {
      findings.push(j.finding);
    } else {
      const first = j.entries[0]!;
      observations.push([["observation", "journal-from"], ["journal", "operator"], ["registryFrom", BigInt(first.registryFrom)], ["removalFrom", BigInt(first.removalFrom)]]);
      if (j.torn > 0) {
        observations.push([["observation", "journal-torn-tail"], ["journal", "operator"], ["removalFrom", BigInt(j.tornAt)], ["bytes", BigInt(j.torn)]]);
      }
    }
  }
  for (const name of required) {
    if (!held.has(name) && evidence) {
      findings.push([["status", "journal-missing"], ["journal", name]]);
    }
  }
  return { findings, observations };
}

// The key history's consumer check (SPEC.md §3e, both versions; ADR-0055),
// beside the store verifier.
export { checkKeyHistory } from "./key-history.ts";
export type { KeyHistoryAnswer, KeyHistoryClass, KeyHistoryEntry, KeyHistoryPin } from "./key-history.ts";
