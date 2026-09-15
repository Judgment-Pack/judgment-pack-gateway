// Registry-anchored verification of a store (SPEC.md §1.4, §4): each
// receipt by the ladder, each session's sequence and chain, each session
// against its seal, and a version 3 action's citations and decision record,
// and a decision record's own citations.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import { canonical } from "./canon.ts";
import { count, hasDuplicate, member, parse } from "./json.ts";
import type { ObjectValue, Value } from "./json.ts";
import { NoVerdict, readDecisionRecords, readRegistry, refuseUnsupportedPlatform } from "./inputs.ts";
import type { Candidate } from "./inputs.ts";
import { citations } from "./citations.ts";
import type { Citation } from "./citations.ts";
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

// A receipt file as the ladder judged it.
type Judged = {
  readonly file: string;
  readonly status: Status;
  // Present past order 1: what the receipt says.
  readonly receipt?: ObjectValue;
  readonly callIndex?: bigint;
};

type Session = {
  readonly name: string;
  // Every .json file in the session directory, by name.
  readonly files: Map<string, Uint8Array>;
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

function sha256Hex(bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

// readStore is the store's sessions: each directory under receipts/, with
// its .json files. A store root or receipts directory that is not there
// holds no session; one that is there and cannot be read as a directory --
// a file among them -- is no verdict.
function readStore(root: string): Session[] {
  const sessions: Session[] = [];
  const receipts = path.join(root, "receipts");
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(receipts, { withFileTypes: true });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      return sessions;
    }
    throw new NoVerdict(`the receipts directory ${JSON.stringify(receipts)} cannot be read: ${(e as NodeJS.ErrnoException).code ?? e}`);
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const dir = path.join(receipts, entry.name);
    const files = new Map<string, Uint8Array>();
    let names: fs.Dirent[];
    try {
      names = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      throw new NoVerdict(`session ${JSON.stringify(entry.name)} cannot be read: ${(e as NodeJS.ErrnoException).code ?? e}`);
    }
    for (const name of names) {
      if (!name.name.endsWith(".json") || name.isDirectory()) {
        continue;
      }
      try {
        files.set(name.name, fs.readFileSync(path.join(dir, name.name)));
      } catch (e) {
        throw new NoVerdict(`receipt ${entry.name}/${name.name} cannot be read: ${(e as NodeJS.ErrnoException).code ?? e}`);
      }
    }
    sessions.push({ name: entry.name, files });
  }
  return sessions;
}

// judge is the ladder of §1.4 for one receipt file: at most one status,
// the first failure in order.
function judge(
  root: string,
  session: string,
  file: string,
  bytes: Uint8Array,
  key: crypto.KeyObject,
  keyId: string,
  authority: string,
): Judged {
  // 1. malformed: unparseable, a name twice, or a structural violation of
  // the receipt's version.
  const parsed = parse(bytes);
  if (parsed === null || parsed.type !== "object" || hasDuplicate(parsed)) {
    return { file, status: "malformed" };
  }
  const receipt = parsed;
  const version = str(member(receipt, "receiptVersion"));
  if (!(version === "3" ? structureV3(receipt) : structureV2(receipt))) {
    return { file, status: "malformed" };
  }
  const index = member(receipt, "callIndex") as Extract<Value, { type: "number" }>;
  const callIndex = index.integer!;
  const judged = (status: Status): Judged => ({ file, status, receipt, callIndex });
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
  if (!signed(key, receiptPrefix[version]!, unsigned, str(member(receipt, "signature"))!)) {
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
  let artifact: Uint8Array;
  try {
    artifact = fs.readFileSync(path.join(root, "artifacts", hex));
  } catch (e) {
    const c = (e as NodeJS.ErrnoException).code;
    if (c === "ENOENT" || c === "ENOTDIR" || c === "EISDIR") {
      return judged("artifact-missing");
    }
    throw new NoVerdict(`the artifact ${hex} cannot be read: ${c ?? e}`);
  }
  if (sha256Hex(artifact) !== hex) {
    return judged("artifact-mismatch");
  }
  return judged("ok");
}

type Seal = { readonly finalCount: bigint };

// loadSeals is the registry's seals by session: each line a seal whose key
// id is the verifier's own and whose signature verifies under its key, the
// first such seal of a session winning; any other line is dropped.
function loadSeals(registry: Uint8Array | null, key: crypto.KeyObject, keyId: string): Map<string, Seal> {
  const seals = new Map<string, Seal>();
  if (registry === null) {
    return seals;
  }
  let start = 0;
  for (let i = 0; i <= registry.length; i++) {
    if (i < registry.length && registry[i] !== 0x0a) {
      continue;
    }
    const line = registry.subarray(start, i);
    start = i + 1;
    const seal = parse(line);
    if (seal === null || seal.type !== "object" || hasDuplicate(seal)) {
      continue;
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
      continue;
    }
    if (sealKeyId.value !== keyId) {
      continue;
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
      continue;
    }
    if (!seals.has(sessionId.value)) {
      seals.set(sessionId.value, { finalCount: finalCount.integer });
    }
  }
  return seals;
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
  const key = publicKeyObject(publicKey);
  const keyId = keyIdOf(publicKey);
  const sessions = readStore(root);
  const registry = readRegistry(registryPath);
  const records = readDecisionRecords(decisionRecordsPath);

  const findings: Finding[] = [];
  let ok = true;
  const add = (f: Finding, passing = false) => {
    findings.push(f);
    ok &&= passing;
  };

  // The enumeration §4 steps 5 and 7 resolve citations against: each
  // session directory's receipt files by stem, with each file's signature
  // member where the file is one JSON object giving no name twice.
  const signatures = new Map<string, Map<string, string | undefined>>();
  for (const s of sessions) {
    const stems = new Map<string, string | undefined>();
    for (const [file, bytes] of s.files) {
      const v = parse(bytes);
      const signature = v !== null && v.type === "object" && !hasDuplicate(v) ? str(member(v, "signature")) : undefined;
      stems.set(file.slice(0, -".json".length), signature);
    }
    signatures.set(s.name, stems);
  }
  const resolves = (c: Citation): boolean => signatures.get(c.sessionId)?.get(c.callIndex.toString()) === c.signature;

  const recordDigests = new Set<string>();
  for (const c of records ?? []) {
    recordDigests.add("sha256:" + sha256Hex(c.bytes));
  }

  const seals = loadSeals(registry, key, keyId);
  for (const s of sessions) {
    const judged: Judged[] = [];
    for (const [file, bytes] of s.files) {
      judged.push(judge(root, s.name, file, bytes, key, keyId, authority));
    }
    for (const j of judged) {
      if (j.status === "malformed") {
        add([
          ["sessionId", s.name],
          ["file", j.file],
          ["status", "malformed"],
        ]);
      } else {
        add(
          [
            ["sessionId", s.name],
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
        ["sessionId", s.name],
        ["callIndex", null],
        ["status", "sequence-broken"],
      ]);
    } else {
      const head = passing[0] === undefined ? undefined : str(member(passing[0].receipt!, "receiptVersion"));
      for (let i = 0; i < passing.length; i++) {
        const r = passing[i]!.receipt!;
        const prev = member(r, "prevSignature");
        const expected = i === 0 ? null : str(member(passing[i - 1]!.receipt!, "signature"))!;
        const linked = expected === null ? prev?.type === "null" : prev?.type === "string" && prev.value === expected;
        if (!linked || str(member(r, "receiptVersion")) !== head) {
          add([
            ["sessionId", s.name],
            ["callIndex", null],
            ["status", "chain-broken"],
          ]);
          break;
        }
      }
    }
    // §4 step 3: the session's count is its .json files, whether or not
    // each verified.
    const seal = seals.get(s.name);
    const have = BigInt(s.files.size);
    if (seal === undefined) {
      add([
        ["sessionId", s.name],
        ["status", "unregistered-session"],
      ]);
    } else if (have !== seal.finalCount) {
      add([
        ["sessionId", s.name],
        ["status", have < seal.finalCount ? "tail-rollback" : "count-exceeds-seal"],
        ["have", have],
        ["sealed", seal.finalCount],
      ]);
    }
    // §4 steps 5 and 6, for each version 3 action receipt that passed.
    for (const j of judged) {
      const r = j.receipt;
      if (j.status !== "ok" || str(member(r!, "receiptVersion")) !== "3" || str(member(r!, "kind")) !== "action") {
        continue;
      }
      const action = member(r!, "action") as ObjectValue;
      const cited = citations(member(action, "cites")!)!;
      if (!cited.every(resolves)) {
        add([
          ["sessionId", s.name],
          ["callIndex", j.callIndex!],
          ["status", "citation-unresolved"],
        ]);
      }
      const decision = member(action, "decision") as ObjectValue;
      if (!recordDigests.has(str(member(decision, "recordDigest"))!)) {
        add([
          ["sessionId", s.name],
          ["callIndex", j.callIndex!],
          ["status", "decision-record-mismatch"],
        ]);
      }
    }
  }
  // §4 step 4: each sealed session the store does not hold.
  const held = new Set(sessions.map((s) => s.name));
  for (const sessionId of seals.keys()) {
    if (!held.has(sessionId)) {
      add([
        ["sessionId", sessionId],
        ["status", "sealed-session-missing"],
      ]);
    }
  }
  // §4 step 7: each decision record that cites.
  for (const c of records ?? []) {
    const status = recordCitations(c, resolves);
    if (status !== null) {
      add([
        ["recordDigest", "sha256:" + sha256Hex(c.bytes)],
        ["status", status],
      ]);
    }
  }
  return { ok, findings };
}

// recordCitations is §4 step 7's finding for a candidate, or null: a
// candidate step 7 reads that is one JSON object with a top-level cites
// member is a record that cites, its cites held to the canonical domain
// and to the shape of action.cites, and each entry resolved.
function recordCitations(c: Candidate, resolves: (c: Citation) => boolean): "record-citation-malformed" | "record-citation-unresolved" | null {
  if (!c.record) {
    return null;
  }
  const record = parse(c.bytes);
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
