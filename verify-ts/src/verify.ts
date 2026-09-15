// Registry-anchored verification of a store (SPEC.md §1.4, §4): each
// receipt by the ladder, each session's sequence and chain, each session
// against its seal, a version 3 action's citations and decision record,
// and a decision record's own citations.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import { canonical } from "./canon.ts";
import { citations } from "./citations.ts";
import type { Citation } from "./citations.ts";
import {
  Budget,
  NoVerdict,
  checkSpellings,
  code,
  digestArtifact,
  documentBound,
  eachDecisionRecord,
  eachEntry,
  endsWith,
  entryCost,
  eachRegistryLine,
  locateDecisionRecords,
  locateRegistry,
  nameOf,
  readDocument,
  refuseUnsupportedPlatform,
} from "./inputs.ts";
import { TooLarge, count, hasDuplicate, integerDigits, maxValues, member, parse } from "./json.ts";
import type { NumberValue, ObjectValue, Value } from "./json.ts";
import { structureV2, structureV3 } from "./structure.ts";

export type Status =
  | "ok"
  | "malformed"
  | "unsupported-version"
  | "key-mismatch"
  | "signature-mismatch"
  | "misfiled"
  | "authority-mismatch"
  | "artifact-missing"
  | "artifact-mismatch";

// A finding, its members in the order written. A bigint is written as the
// integer it is.
export type Finding = ReadonlyArray<readonly [string, string | number | bigint | null]>;

// A verdict's findings are made again each time they are read, from what
// verification kept, so none is held for the verdict to be written.
export type Verdict = { readonly ok: boolean; readonly findings: Iterable<Finding> };

// A receipt file as the ladder judged it, kept as no more than the rest of
// verification reads of it, each kept string its own and none long, so no
// receipt's size stays in memory past its turn.
type Judged = {
  readonly file: string;
  readonly status: Status;
  // Past order 1: the receipt's index, for its finding.
  readonly callIndex?: bigint;
  // For a receipt that passed: what the chain walk reads of it.
  readonly chain?: { readonly version: string; readonly signature: string; readonly prev: Prev };
  // For a version 3 action that passed: the record it names, and its
  // bytes' SHA-256, by which its citations are read again once the
  // enumeration is whole.
  readonly action?: { readonly recordDigest: string; readonly bytes: string };
};

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
// most 128 characters; for an action, the record it names and its bytes'
// digest; in the index, its signature when of a citation's form -- 520
// characters at most, beside a few objects and their entries in maps and
// sets. A receipt file is charged all of it when it is met, and its name
// twice, in its session's list and as its stem, so a store is refused for
// its size before any receipt is read.
const receiptCost = 8 * entryCost;

const receiptPrefix: Record<string, string> = {
  "2": "judgment-pack-gateway/receipt/2:",
  "3": "judgment-pack-gateway/receipt/3:",
};
const sealPrefix = "judgment-pack-gateway/seal/2:";

// A key id: SHA-256 of the 32 raw bytes of the public key, in hex, its
// first 32 characters.
export function keyIdOf(publicKey: Uint8Array): string {
  return crypto.createHash("sha256").update(publicKey).digest("hex").slice(0, 32);
}

function publicKeyObject(publicKey: Uint8Array): crypto.KeyObject {
  return crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey).toString("base64url") },
    format: "jwk",
  });
}

// signed is whether the signature, in hex of either case, verifies over
// the prefix and the canonical form of the value.
function signed(key: crypto.KeyObject, prefix: string, v: Value, signatureHex: string): boolean {
  const body = canonical(v);
  if (body === null || !/^(?:[0-9a-fA-F]{2}){64}$/.test(signatureHex)) {
    return false;
  }
  const message = Buffer.concat([Buffer.from(prefix, "utf8"), body]);
  return crypto.verify(null, message, key, Buffer.from(signatureHex, "hex"));
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
// read as a directory is no verdict.
function sessionFiles(root: string, budget: Budget): Map<string, string[]> {
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

// judge is the ladder of §1.4 for one receipt: at most one status, the
// first failure in order.
function judge(parsed: Value | null, bytesDigest: string, root: string, session: string, file: string, key: crypto.KeyObject, keyId: string, authority: string): Judged {
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
  // 3. key-mismatch
  if (str(member(receipt, "keyId")) !== keyId) {
    return judged("key-mismatch");
  }
  // 4. signature-mismatch: over everything but the receipt's own
  // top-level signature, under its version's prefix.
  const unsigned: ObjectValue = { type: "object", members: receipt.members.filter((m) => m.name !== "signature") };
  if (!signed(key, receiptPrefix[version]!, unsigned, signature)) {
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
  // 7. artifact-missing, and 8. artifact-mismatch: the artifact at the
  // result digest's hex, re-digested.
  const hex = str(member(receipt, "resultDigest"))!.slice("sha256:".length);
  const digest = digestArtifact(under(root, "artifacts", hex));
  if (digest === null) {
    return judged("artifact-missing");
  }
  if (digest !== hex) {
    return judged("artifact-mismatch");
  }
  const prevValue = member(receipt, "prevSignature");
  const prev: Prev =
    prevValue?.type === "null"
      ? { kind: "null" }
      : prevValue?.type === "string" && prevValue.value.length <= 128
        ? { kind: "string", value: own(prevValue.value) }
        : { kind: "other" };
  let action: Judged["action"];
  if (version === "3" && str(member(receipt, "kind")) === "action") {
    const decision = member(member(receipt, "action") as ObjectValue, "decision") as ObjectValue;
    action = { recordDigest: own(str(member(decision, "recordDigest"))!), bytes: bytesDigest };
  }
  return { file, status: "ok", callIndex, chain: { version: own(version), signature: own(signature), prev }, ...(action && { action }) };
}

type Seal = { readonly sessionId: string; readonly finalCount: bigint };

// sealOf is a registry line as a seal, when it is one whose key id is the
// verifier's own and whose signature verifies under its key; any other
// line is no seal and is dropped.
function sealOf(line: Uint8Array | null, key: crypto.KeyObject, keyId: string): Seal | null {
  const seal =
    line === null
      ? null
      : parseOr(line, () => {
          if (opensObject(line)) {
            throw new NoVerdict(`a registry line of more than ${maxValues} values cannot be read for a seal`);
          }
          return null;
        });
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
  if (sealKeyId.value !== keyId) {
    return null;
  }
  const payload: ObjectValue = {
    type: "object",
    members: [
      { name: "sessionId", value: sessionId },
      { name: "finalCount", value: finalCount },
      { name: "sealedAt", value: sealedAt },
      { name: "keyId", value: sealKeyId },
    ],
  };
  if (!signed(key, sealPrefix, payload, signature)) {
    return null;
  }
  return { sessionId: own(sessionId.value), finalCount: finalCount.integer };
}

// verifyStore is the verdict of §4 over the store at root, against the
// registry at registryPath, under the public key.
export function verifyStore(
  root: string,
  registryPath: string,
  authority: string,
  decisionRecordsPath: string | undefined,
  publicKey: Uint8Array,
): Verdict {
  refuseUnsupportedPlatform();
  if (publicKey.length !== 32) {
    throw new NoVerdict(`the public key is ${publicKey.length} bytes, not 32`);
  }
  // A spelling §4.1 refuses is refused before anything is read, and each
  // anchor is judged absent or present before the store is read.
  checkSpellings(registryPath, decisionRecordsPath);
  const registry = locateRegistry(registryPath);
  const records = locateDecisionRecords(decisionRecordsPath);
  const key = publicKeyObject(publicKey);
  const keyId = keyIdOf(publicKey);

  // What verification keeps, charged as it is kept.
  const budget = new Budget(limits.retainedBytes);

  // Each receipt, read once: judged, and indexed by stem for the
  // citations of §4 steps 5 and 7. Every receipt file is met, and charged
  // for what is kept of it, before any is read.
  const sessions = new Map<string, Judged[]>();
  const signatures = new Map<string, Map<string, string | undefined>>();
  const store = sessionFiles(root, budget);
  for (const [session, files] of store) {
    const judged: Judged[] = [];
    const stems = new Map<string, string | undefined>();
    for (const file of files) {
      const bytes = readDocument(under(root, "receipts", session, file), "the receipt");
      const parsed = parseOr(bytes, () => {
        throw new NoVerdict(`receipt ${session}/${file} holds more than ${maxValues} values`);
      });
      stems.set(file.slice(0, -".json".length), citedSignature(parsed));
      judged.push(judge(parsed, sha256Hex(bytes), root, session, file, key, keyId, authority));
      testHooks.sample?.("receipt");
    }
    sessions.set(session, judged);
    signatures.set(session, stems);
  }
  const resolves = (c: Citation): boolean => signatures.get(c.sessionId)?.get(c.callIndex) === c.signature;

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

  // §4 step 2: the first loadable seal of each session. A line past the
  // bound that opens an object could be one, and the first, so it is no
  // verdict; any other line past it is not one JSON object, and no seal.
  const seals = new Map<string, Seal>();
  eachRegistryLine(registry, (line) => {
    if (line.bytes === null) {
      if (line.opensObject) {
        throw new NoVerdict(`a registry line of more than ${documentBound} bytes cannot be read for a seal`);
      }
      return;
    }
    const seal = sealOf(line.bytes, key, keyId);
    if (seal !== null && !seals.has(seal.sessionId)) {
      budget.charge(entryCost + size(seal.sessionId), "the registry's seals");
      seals.set(seal.sessionId, seal);
    }
  });
  testHooks.sample?.("registry");

  // §4 step 6's candidates, matched against the records the actions that
  // passed name, and step 7's findings, from one walk: each record named
  // is marked once a candidate is found to be it.
  const named = new Map<string, boolean>();
  for (const judged of sessions.values()) {
    for (const j of judged) {
      if (j.action !== undefined) {
        named.set(j.action.recordDigest, false);
      }
    }
  }
  const recordFindings = new RecordFindings(budget);
  eachDecisionRecord(records, budget, (candidate) => {
    testHooks.sample?.("candidate");
    const digest = "sha256:" + candidate.digest;
    if (named.has(digest)) {
      named.set(digest, true);
    }
    if (candidate.bytes === null) {
      // Past the bound: a candidate that does not open an object is not
      // one JSON object, and one that does cannot be read for its cites.
      if (candidate.opensObject) {
        throw new NoVerdict(`a decision record of more than ${documentBound} bytes cannot be read for its citations`);
      }
      return;
    }
    const status = recordCitations(candidate.bytes, resolves);
    if (status !== null) {
      recordFindings.add(candidate.digest, status);
    }
  });
  testHooks.sample?.("decision records");

  // The findings, made from what was kept, each time they are read.
  function* findings(): Generator<Finding> {
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
      const passing = judged.filter((j) => j.status === "ok").sort((a, b) => (a.callIndex! < b.callIndex! ? -1 : 1));
      if (passing.some((j, i) => j.callIndex !== BigInt(i))) {
        yield [
          ["sessionId", session],
          ["callIndex", null],
          ["status", "sequence-broken"],
        ];
      } else {
        const head = passing[0]?.chain!.version;
        for (let i = 0; i < passing.length; i++) {
          const { version, prev } = passing[i]!.chain!;
          const expected = i === 0 ? null : passing[i - 1]!.chain!.signature;
          const linked = expected === null ? prev.kind === "null" : prev.kind === "string" && prev.value === expected;
          if (!linked || version !== head) {
            yield [
              ["sessionId", session],
              ["callIndex", null],
              ["status", "chain-broken"],
            ];
            break;
          }
        }
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
      }
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
        if (named.get(j.action.recordDigest) !== true) {
          yield [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", "decision-record-mismatch"],
          ];
        }
      }
    }
    // §4 step 4: each sealed session the store does not hold.
    for (const sessionId of seals.keys()) {
      if (!sessions.has(sessionId)) {
        yield [
          ["sessionId", sessionId],
          ["status", "sealed-session-missing"],
        ];
      }
    }
    yield* recordFindings.findings();
  }
  // The verdict is ok when every finding's status is.
  let ok = true;
  for (const f of findings()) {
    ok &&= f.some(([name, value]) => name === "status" && value === "ok");
  }
  return { ok, findings: { [Symbol.iterator]: findings } };
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
function recordCitations(bytes: Uint8Array, resolves: (c: Citation) => boolean): "record-citation-malformed" | "record-citation-unresolved" | null {
  const record = parseOr(bytes, () => {
    if (opensObject(bytes)) {
      throw new NoVerdict(`a decision record of more than ${maxValues} values cannot be read for its citations`);
    }
    return null;
  });
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
export function writeVerdict(v: Verdict, write: (text: string) => void): void {
  write(`{"ok":${v.ok},"findings":[`);
  let first = true;
  for (const f of v.findings) {
    write(
      (first ? "{" : ",{") +
        f.map(([name, value]) => JSON.stringify(name) + ":" + (typeof value === "bigint" ? value.toString() : JSON.stringify(value))).join(",") +
        "}",
    );
    first = false;
  }
  write("]}\n");
}
