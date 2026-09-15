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
  NoVerdict,
  checkSpellings,
  code,
  digestArtifact,
  documentBound,
  eachDecisionRecord,
  eachRegistryLine,
  locateDecisionRecords,
  locateRegistry,
  readDocument,
  refuseUnsupportedPlatform,
} from "./inputs.ts";
import { TooLarge, count, hasDuplicate, maxValues, member, parse } from "./json.ts";
import type { ObjectValue, Value } from "./json.ts";
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

export type Verdict = { readonly ok: boolean; readonly findings: Finding[] };

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

// own is a copy of a short string held by nothing else: a string read out
// of a document can otherwise keep the whole document's text alive.
function own(s: string): string {
  return s.split("").join("");
}

// The longest callIndex, in digits, this verifier carries into a finding;
// one longer cannot verify (the canonical domain ends at sixteen), and is
// no verdict rather than a finding of unbounded size.
const maxIndexDigits = 64;

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

// testHooks lets a test look at the heap between one document and the
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

// sessionFiles is the store's sessions -- each directory under receipts/,
// not a link to one -- and each one's .json entries that are not
// directories. A store root or receipts directory not there holds no
// session; one there that cannot be read as a directory is no verdict.
function sessionFiles(root: string): Map<string, string[]> {
  const sessions = new Map<string, string[]>();
  const receipts = path.join(root, "receipts");
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(receipts, { withFileTypes: true });
  } catch (e) {
    if (code(e) === "ENOENT") {
      return sessions;
    }
    throw new NoVerdict(`the receipts directory ${JSON.stringify(receipts)} cannot be read: ${code(e) ?? e}`);
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    let names: fs.Dirent[];
    try {
      names = fs.readdirSync(path.join(receipts, entry.name), { withFileTypes: true });
    } catch (e) {
      throw new NoVerdict(`session ${JSON.stringify(entry.name)} cannot be read: ${code(e) ?? e}`);
    }
    sessions.set(
      entry.name,
      names.filter((n) => n.name.endsWith(".json") && !n.isDirectory()).map((n) => n.name),
    );
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
  const index = member(receipt, "callIndex") as Extract<Value, { type: "number" }>;
  if (index.text.replace("-", "").length > maxIndexDigits) {
    throw new NoVerdict(`receipt ${session}/${file} has a callIndex of more than ${maxIndexDigits} digits`);
  }
  const callIndex = index.integer!;
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
  const digest = digestArtifact(path.join(root, "artifacts", hex));
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

  // Each receipt, read once: judged, and indexed by stem for the
  // citations of §4 steps 5 and 7.
  const sessions = new Map<string, Judged[]>();
  const signatures = new Map<string, Map<string, string | undefined>>();
  for (const [session, files] of sessionFiles(root)) {
    const judged: Judged[] = [];
    const stems = new Map<string, string | undefined>();
    for (const file of files) {
      const bytes = readDocument(path.join(root, "receipts", session, file), "the receipt");
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
  const resolves = (c: Citation): boolean => signatures.get(c.sessionId)?.get(c.callIndex.toString()) === c.signature;

  // §4 step 5, now that the enumeration is whole: each action that passed
  // is read again for its citations, and must be the bytes it was.
  const unresolved = new Set<Judged>();
  for (const [session, judged] of sessions) {
    for (const j of judged) {
      if (j.action === undefined) {
        continue;
      }
      const bytes = readDocument(path.join(root, "receipts", session, j.file), "the receipt");
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
      seals.set(seal.sessionId, seal);
    }
  });
  testHooks.sample?.("registry");

  // §4 step 6's candidates, matched against the records the actions that
  // passed name, and step 7's findings, from one walk.
  const named = new Set<string>();
  for (const judged of sessions.values()) {
    for (const j of judged) {
      if (j.action !== undefined) {
        named.add(j.action.recordDigest);
      }
    }
  }
  const found = new Set<string>();
  const recordFindings: Finding[] = [];
  eachDecisionRecord(records, (candidate) => {
    const digest = "sha256:" + candidate.digest;
    if (named.has(digest)) {
      found.add(digest);
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
      recordFindings.push([
        ["recordDigest", digest],
        ["status", status],
      ]);
    }
  });
  testHooks.sample?.("decision records");

  const findings: Finding[] = [];
  let ok = true;
  const add = (f: Finding, passing = false) => {
    findings.push(f);
    ok &&= passing;
  };
  for (const [session, judged] of sessions) {
    for (const j of judged) {
      if (j.status === "malformed") {
        add([
          ["sessionId", session],
          ["file", j.file],
          ["status", "malformed"],
        ]);
      } else {
        add(
          [
            ["sessionId", session],
            ["callIndex", j.callIndex!],
            ["status", j.status],
          ],
          j.status === "ok",
        );
      }
    }
    // The sequence and the chain, over the receipts that passed.
    const passing = judged.filter((j) => j.status === "ok").sort((a, b) => (a.callIndex! < b.callIndex! ? -1 : 1));
    if (passing.some((j, i) => j.callIndex !== BigInt(i))) {
      add([
        ["sessionId", session],
        ["callIndex", null],
        ["status", "sequence-broken"],
      ]);
    } else {
      const head = passing[0]?.chain!.version;
      for (let i = 0; i < passing.length; i++) {
        const { version, prev } = passing[i]!.chain!;
        const expected = i === 0 ? null : passing[i - 1]!.chain!.signature;
        const linked = expected === null ? prev.kind === "null" : prev.kind === "string" && prev.value === expected;
        if (!linked || version !== head) {
          add([
            ["sessionId", session],
            ["callIndex", null],
            ["status", "chain-broken"],
          ]);
          break;
        }
      }
    }
    // §4 step 3: the session's count is its .json files, whether or not
    // each verified.
    const seal = seals.get(session);
    const have = BigInt(judged.length);
    if (seal === undefined) {
      add([
        ["sessionId", session],
        ["status", "unregistered-session"],
      ]);
    } else if (have !== seal.finalCount) {
      add([
        ["sessionId", session],
        ["status", have < seal.finalCount ? "tail-rollback" : "count-exceeds-seal"],
        ["have", have],
        ["sealed", seal.finalCount],
      ]);
    }
    // §4 steps 5 and 6, for each version 3 action receipt that passed.
    for (const j of judged) {
      if (j.action === undefined) {
        continue;
      }
      if (unresolved.has(j)) {
        add([
          ["sessionId", session],
          ["callIndex", j.callIndex!],
          ["status", "citation-unresolved"],
        ]);
      }
      if (!found.has(j.action.recordDigest)) {
        add([
          ["sessionId", session],
          ["callIndex", j.callIndex!],
          ["status", "decision-record-mismatch"],
        ]);
      }
    }
  }
  // §4 step 4: each sealed session the store does not hold.
  for (const sessionId of seals.keys()) {
    if (!sessions.has(sessionId)) {
      add([
        ["sessionId", sessionId],
        ["status", "sealed-session-missing"],
      ]);
    }
  }
  for (const f of recordFindings) {
    add(f);
  }
  return { ok, findings };
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

// writeVerdict is the verdict as the process contract writes it.
export function writeVerdict(v: Verdict): string {
  const findings = v.findings.map(
    (f) =>
      "{" +
      f.map(([name, value]) => JSON.stringify(name) + ":" + (typeof value === "bigint" ? value.toString() : JSON.stringify(value))).join(",") +
      "}",
  );
  return `{"ok":${v.ok},"findings":[${findings.join(",")}]}\n`;
}
