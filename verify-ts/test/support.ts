// What the tests share: the corpus, its key, a vector materialized as the
// process contract hands it over, and findings as a multiset.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { canonical } from "../src/canon.ts";
import { parse } from "../src/json.ts";
import type { Value } from "../src/json.ts";
import { writeVerdict } from "../src/verify.ts";
import type { Verdict } from "../src/verify.ts";

// tempDir is a fresh directory under the platform's temporary one, taken
// away, with everything in it, when the test process ends.
const made: string[] = [];
process.on("exit", () => {
  for (const dir of made) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
export function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-ts-"));
  made.push(dir);
  return dir;
}

export const corpus = path.join(import.meta.dirname, "..", "..", "corpus");
export const publicKey = Buffer.from(fs.readFileSync(path.join(corpus, "TEST-PUBLIC-KEY"), "utf8").trim(), "hex");

export type StoreVector = {
  name: string;
  authority: string;
  files: Record<string, string>;
  registry: string;
  absentRegistry?: boolean;
  emptySessions?: string[];
  decisionRecords?: Record<string, string>;
  ordinarySealsOnly?: boolean;
  expected: {
    ok: boolean;
    findings: Record<string, unknown>[];
    observations?: Record<string, unknown>[];
    witnesses?: Record<string, unknown>[];
  };
};

// readVector is a corpus file read as gateway conform reads one (SPEC.md
// §7, corpus/README.md): exactly one JSON value, in which no object gives a
// member twice, its members read by their exact names. A file that is not
// one value, or gives a member twice, refuses the read: of two members,
// neither is the vector's.
export function readVector(file: string): unknown {
  const bytes = fs.readFileSync(file);
  const value = parse(bytes);
  if (value === null) {
    throw new Error(`${file}: not exactly one JSON value`);
  }
  const twice = givenTwice(value);
  if (twice !== undefined) {
    throw new Error(`${file}: the member ${JSON.stringify(twice)} is given twice in one object`);
  }
  return JSON.parse(bytes.toString("utf8"));
}

// givenTwice is the first name, in the order written, that an object in the
// value gives a second time.
function givenTwice(v: Value): string | undefined {
  type Frame = { readonly values: readonly Value[]; readonly names: readonly string[] | null; at: number; readonly seen: Set<string> };
  const stack: Frame[] = [];
  const enter = (w: Value) => {
    if (w.type === "array") {
      stack.push({ values: w.items, names: null, at: 0, seen: new Set() });
    } else if (w.type === "object") {
      stack.push({ values: w.members.map((m) => m.value), names: w.members.map((m) => m.name), at: 0, seen: new Set() });
    }
  };
  enter(v);
  for (let top = stack.at(-1); top !== undefined; top = stack.at(-1)) {
    if (top.at === top.values.length) {
      stack.pop();
      continue;
    }
    const i = top.at++;
    if (top.names !== null) {
      const name = top.names[i]!;
      if (top.seen.has(name)) {
        return name;
      }
      top.seen.add(name);
    }
    enter(top.values[i]!);
  }
  return undefined;
}

// only refuses a member of an object the runner reads strictly that is none
// of the names it reads there: a name in another case is such a member, as
// it is to gateway conform (SPEC.md §7). What is not an object is left to
// the reader of the member.
function only(file: string, o: unknown, ...names: string[]): void {
  if (typeof o !== "object" || o === null || Array.isArray(o)) {
    return;
  }
  for (const name of Object.keys(o)) {
    if (!names.includes(name)) {
      throw new Error(`${file}: unknown member ${JSON.stringify(name)}`);
    }
  }
}

// readStoreVector is one store vector, refusing a member the runner does
// not read, at the top or in expected.
export function readStoreVector(file: string): StoreVector {
  const v = readVector(file) as StoreVector;
  only(file, v, "name", "note", "authority", "files", "registry", "decisionRecords", "absentRegistry", "emptySessions", "ordinarySealsOnly", "expected");
  only(file, v.expected, "ok", "findings", "witnesses", "rotations", "observations");
  return v;
}

export function storeVectors(): StoreVector[] {
  const vectors: StoreVector[] = [];
  for (const dir of [path.join(corpus, "stores"), path.join(corpus, "v3", "stores")]) {
    for (const name of fs.readdirSync(dir).sort()) {
      vectors.push(readStoreVector(path.join(dir, name)));
    }
  }
  return vectors;
}

// materialize writes a vector as the runner would, and is the arguments
// verify takes.
export function materialize(v: StoreVector): { root: string; registry: string; decisionRecords: string | undefined } {
  const at = tempDir();
  const root = path.join(at, "store");
  for (const [file, text] of Object.entries(v.files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  }
  for (const s of v.emptySessions ?? []) {
    fs.mkdirSync(path.join(root, "receipts", s), { recursive: true });
  }
  const registry = path.join(at, "registry");
  if (!v.absentRegistry) {
    fs.writeFileSync(registry, v.registry);
  }
  let decisionRecords: string | undefined;
  if (v.decisionRecords !== undefined) {
    decisionRecords = path.join(at, "decision-records");
    fs.mkdirSync(decisionRecords);
    for (const [file, text] of Object.entries(v.decisionRecords)) {
      fs.mkdirSync(path.dirname(path.join(decisionRecords, file)), { recursive: true });
      fs.writeFileSync(path.join(decisionRecords, file), text);
    }
  }
  return { root, registry, decisionRecords };
}

// verdictText is the verdict as the process contract writes it.
export function verdictText(v: Verdict): string {
  const parts: string[] = [];
  writeVerdict(v, (text) => parts.push(text));
  return parts.join("");
}

// multiset is the findings, each in a canonical spelling, sorted.
export function multiset(findings: Record<string, unknown>[]): string[] {
  return findings.map((f) => JSON.stringify(Object.fromEntries(Object.entries(f).sort(([a], [b]) => (a < b ? -1 : 1))))).sort();
}

// Receipts of the tests' own, signed under the corpus's published test
// seed, which exists so that vectors can be made deliberately
// (corpus/README.md); a verifier reads only the public key.
const seed = Buffer.from(fs.readFileSync(path.join(corpus, "TEST-SEED"), "utf8").trim(), "hex");
const privateKey = crypto.createPrivateKey({
  key: { kty: "OKP", crv: "Ed25519", d: seed.toString("base64url"), x: publicKey.toString("base64url") },
  format: "jwk",
});
export const keyId = crypto.createHash("sha256").update(publicKey).digest("hex").slice(0, 32);
export const authority = "gateway:test";
export const artifact = Buffer.from('{"n":0}');
export const resultDigest = "sha256:" + crypto.createHash("sha256").update(artifact).digest("hex");
const digest = (c: string) => "sha256:" + c.repeat(64);

// sign is the hex signature over the prefix and the canonical form of a
// JSON value.
export function sign(prefix: string, value: unknown): string {
  const body = canonical(parse(Buffer.from(JSON.stringify(value), "utf8"))!);
  if (body === null) {
    throw new Error("outside the canonical domain");
  }
  return crypto.sign(null, Buffer.concat([Buffer.from(prefix, "utf8"), body]), privateKey).toString("hex");
}

export type Receipt = Record<string, unknown>;

// signed is the receipt with its signature, under its version's prefix.
export function signed(r: Receipt): Receipt {
  return { ...r, signature: sign(`judgment-pack-gateway/receipt/${r["receiptVersion"]}:`, r) };
}

// acquisitionV3 is a version 3 acquisition receipt, every member present,
// before its signature.
export function acquisitionV3(callIndex = 0, prevSignature: string | null = null, sessionId = "s1"): Receipt {
  return {
    receiptVersion: "3",
    sessionId,
    callIndex,
    prevSignature,
    source: "src",
    resultDigest,
    servedAt: "2026-09-15T00:00:00Z",
    authority,
    keyId,
    kind: "acquisition",
    argumentsCommitment: digest("0"),
    caller: null,
    acquisition: {
      adapter: { name: "adapter-mcp", version: "1", digest: digest("1") },
      shape: "mcp",
      endpoint: null,
      statement: null,
      snapshot: null,
      peerIdentity: null,
      schema: null,
      upstreamToken: null,
      observedAt: "2026-09-15T00:00:00Z",
    },
  };
}

// actionV3 is a version 3 action receipt citing the receipts given and the
// decision record by its digest, before its signature.
export function actionV3(callIndex: number, prevSignature: string | null, cites: unknown[], recordDigest: string, sessionId = "s1"): Receipt {
  const { acquisition: _, ...base } = acquisitionV3(callIndex, prevSignature, sessionId);
  return {
    ...base,
    kind: "action",
    action: {
      requester: { issuer: "https://issuer.test", subject: "person", tokenDigest: digest("2") },
      decision: { recordDigest, packDigest: digest("3") },
      cites,
      tool: { shape: "mcp", endpoint: null, name: "tickets.close" },
      request: digest("4"),
      adapter: { name: "adapter-mcp", version: "1", digest: digest("1") },
      observedAt: "2026-09-15T00:00:01Z",
    },
  };
}

// receiptV2 is a version 2 receipt, before its signature.
export function receiptV2(callIndex = 0, prevSignature: string | null = null): Receipt {
  return {
    receiptVersion: "2",
    sessionId: "s1",
    callIndex,
    prevSignature,
    source: "src",
    argumentsDigest: "hmac-sha256:" + "0".repeat(64),
    resultDigest,
    servedAt: "2026-09-15T00:00:00Z",
    authority,
    keyId,
  };
}

// sealLine is a registry line sealing the session at its count, signed by
// the test key over the key id it names.
export function sealLine(sessionId: string, finalCount: number, sealedAt = "2026-09-15T00:00:02Z", sealKeyId = keyId): string {
  const payload = { sessionId, finalCount, sealedAt, keyId: sealKeyId };
  return JSON.stringify({ ...payload, signature: sign("judgment-pack-gateway/seal/2:", payload) });
}

export type Store = { readonly root: string; readonly registry: string; readonly decisionRecords: string };

// newStore is an empty store's paths: its root holding the artifact, a
// registry path and a decision-record directory path, neither made.
export function newStore(): Store {
  const at = tempDir();
  const root = path.join(at, "store");
  fs.mkdirSync(path.join(root, "artifacts"), { recursive: true });
  fs.writeFileSync(path.join(root, "artifacts", resultDigest.slice("sha256:".length)), artifact);
  return { root, registry: path.join(at, "registry"), decisionRecords: path.join(at, "decision-records") };
}

// put writes a receipt file's text into the store.
export function put(store: Store, session: string, file: string, text: string): void {
  fs.mkdirSync(path.join(store.root, "receipts", session), { recursive: true });
  fs.writeFileSync(path.join(store.root, "receipts", session, file), text);
}

// A witness vector (corpus/README.md, "Witness vectors"): a file is its
// text, or parts each repeated a number of times.
export type WitnessFile = string | { parts: { text: string; times: number }[] };
export type WitnessVector = {
  name: string;
  family: string;
  trail: string;
  keys: string[];
  witness: WitnessFile[];
  head?: WitnessFile;
  expected: Record<string, unknown>;
};

// readWitnessVector is one witness vector, refusing a member the runner
// does not read: at the top, in a file's parts form, and in the expected
// answer, whose members are those of its form (corpus/README.md).
export function readWitnessVector(file: string): WitnessVector {
  const v = readVector(file) as WitnessVector;
  only(file, v, "name", "family", "note", "trail", "keys", "witness", "head", "expected");
  for (const f of [...(Array.isArray(v.witness) ? v.witness : []), v.head]) {
    only(file, f, "parts");
    if (typeof f === "object" && f !== null && Array.isArray(f.parts)) {
      for (const part of f.parts) {
        only(file, part, "text", "times");
      }
    }
  }
  const e = v.expected;
  if (typeof e === "object" && e !== null && "refused" in e) {
    only(file, e, "refused");
  } else if (e?.["ok"] === true) {
    only(file, e, "ok", "findings", "reading", "headIndex", "highestIndex", "latestCheckpoint", "conflicts", "retired");
    only(file, e["latestCheckpoint"], "index", "sequence", "witnessedAt");
  } else {
    only(file, e, "ok", "findings");
  }
  return v;
}

export function witnessVectors(): WitnessVector[] {
  const dir = path.join(corpus, "witness");
  return fs
    .readdirSync(dir)
    .sort()
    .map((name) => readWitnessVector(path.join(dir, name)));
}

function writeWitnessFile(at: string, file: WitnessFile): void {
  const fd = fs.openSync(at, "wx");
  try {
    for (const { text, times } of typeof file === "string" ? [{ text: file, times: 1 }] : file.parts) {
      const chunk = Buffer.from(text, "utf8");
      const perWrite = Math.max(1, Math.floor((1 << 20) / Math.max(chunk.length, 1)));
      for (let left = times; left > 0; left -= perWrite) {
        fs.writeSync(fd, Buffer.alloc(chunk.length * Math.min(left, perWrite), chunk));
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}

// materializeWitness writes a witness vector as the runner hands it over:
// a key file per key, a file per statements file, and the head file.
export function materializeWitness(v: WitnessVector): { keys: string[]; files: string[]; head: string | null } {
  const at = tempDir();
  const keys = v.keys.map((key, i) => {
    const p = path.join(at, `key-${i}`);
    fs.writeFileSync(p, key + "\n");
    return p;
  });
  const files = v.witness.map((file, i) => {
    const p = path.join(at, `statements-${i}.jsonl`);
    writeWitnessFile(p, file);
    return p;
  });
  let head: string | null = null;
  if (v.head !== undefined) {
    head = path.join(at, "head.jsonl");
    writeWitnessFile(head, v.head);
  }
  return { keys, files, head };
}

// sameWitnessAnswer is whether an answer is the one a vector expects, as
// the runner compares them: a refusal whole, findings as a set, and every
// member of a reading with none.
export function sameWitnessAnswer(expected: Record<string, unknown>, produced: Record<string, unknown>): boolean {
  const set = (v: unknown) => [...new Set(v as string[])].sort();
  if ("refused" in expected || "refused" in produced) {
    return JSON.stringify(expected) === JSON.stringify(produced);
  }
  if (expected["ok"] !== produced["ok"] || JSON.stringify(set(expected["findings"])) !== JSON.stringify(set(produced["findings"]))) {
    return false;
  }
  if (expected["ok"] !== true) {
    return true;
  }
  return ["reading", "headIndex", "highestIndex", "latestCheckpoint", "conflicts", "retired"].every(
    (name) => JSON.stringify(expected[name]) === JSON.stringify(produced[name]),
  );
}
