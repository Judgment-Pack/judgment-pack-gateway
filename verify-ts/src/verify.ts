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
import { count, hasDuplicate, member, parse } from "./json.ts";
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
// verification reads of it.
type Judged = {
  readonly file: string;
  readonly status: Status;
  // Past order 1: what the receipt says of its place and its chain.
  readonly callIndex?: bigint;
  readonly version?: string | undefined;
  readonly signature?: string;
  readonly prevSignature?: Value | undefined;
  // For a version 3 action: what it cites, and the record it names.
  readonly action?: { readonly cites: Citation[]; readonly recordDigest: string } | undefined;
};

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
  return v?.type === "object" && count(v, "signature") === 1 ? str(member(v, "signature")) : undefined;
}

// judge is the ladder of §1.4 for one receipt: at most one status, the
// first failure in order.
function judge(parsed: Value | null, root: string, session: string, file: string, key: crypto.KeyObject, keyId: string, authority: string): Judged {
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
  const callIndex = (member(receipt, "callIndex") as Extract<Value, { type: "number" }>).integer!;
  const signature = str(member(receipt, "signature"))!;
  let action: Judged["action"];
  if (version === "3" && str(member(receipt, "kind")) === "action") {
    const a = member(receipt, "action") as ObjectValue;
    const decision = member(a, "decision") as ObjectValue;
    action = { cites: citations(member(a, "cites")!)!, recordDigest: str(member(decision, "recordDigest"))! };
  }
  const judged = (status: Status): Judged => ({
    file,
    status,
    callIndex,
    version,
    signature,
    prevSignature: member(receipt, "prevSignature"),
    action,
  });
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
  return judged("ok");
}

type Seal = { readonly sessionId: string; readonly finalCount: bigint };

// sealOf is a registry line as a seal, when it is one whose key id is the
// verifier's own and whose signature verifies under its key; any other
// line is no seal and is dropped.
function sealOf(line: Uint8Array | null, key: crypto.KeyObject, keyId: string): Seal | null {
  const seal = line === null ? null : parse(line);
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
  return { sessionId: sessionId.value, finalCount: finalCount.integer };
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
      const parsed = parse(readDocument(path.join(root, "receipts", session, file), "the receipt"));
      stems.set(file.slice(0, -".json".length), citedSignature(parsed));
      judged.push(judge(parsed, root, session, file, key, keyId, authority));
    }
    sessions.set(session, judged);
    signatures.set(session, stems);
  }
  const resolves = (c: Citation): boolean => signatures.get(c.sessionId)?.get(c.callIndex.toString()) === c.signature;

  // §4 step 2: the first loadable seal of each session.
  const seals = new Map<string, Seal>();
  eachRegistryLine(registry, (line) => {
    const seal = sealOf(line.bytes, key, keyId);
    if (seal !== null && !seals.has(seal.sessionId)) {
      seals.set(seal.sessionId, seal);
    }
  });

  // §4 step 6's candidates by digest, and step 7's findings, from one walk.
  const recordDigests = new Set<string>();
  const recordFindings: Finding[] = [];
  eachDecisionRecord(records, (candidate) => {
    recordDigests.add("sha256:" + candidate.digest);
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
        ["recordDigest", "sha256:" + candidate.digest],
        ["status", status],
      ]);
    }
  });

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
      const head = passing[0]?.version;
      for (let i = 0; i < passing.length; i++) {
        const prev = passing[i]!.prevSignature;
        const expected = i === 0 ? null : passing[i - 1]!.signature!;
        const linked = expected === null ? prev?.type === "null" : prev?.type === "string" && prev.value === expected;
        if (!linked || passing[i]!.version !== head) {
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
      if (j.status !== "ok" || j.action === undefined) {
        continue;
      }
      if (!j.action.cites.every(resolves)) {
        add([
          ["sessionId", session],
          ["callIndex", j.callIndex!],
          ["status", "citation-unresolved"],
        ]);
      }
      if (!recordDigests.has(j.action.recordDigest)) {
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
  const record = parse(bytes);
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
