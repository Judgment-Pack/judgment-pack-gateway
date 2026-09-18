// What the tests share: the corpus, its key, a vector materialized as the
// process contract hands it over, and findings as a multiset.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { canonical } from "../src/canon.ts";
import { parse } from "../src/json.ts";
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
  expected: { ok: boolean; findings: Record<string, unknown>[] };
};

export function storeVectors(): StoreVector[] {
  const vectors: StoreVector[] = [];
  for (const dir of [path.join(corpus, "stores"), path.join(corpus, "v3", "stores")]) {
    for (const name of fs.readdirSync(dir).sort()) {
      vectors.push(JSON.parse(fs.readFileSync(path.join(dir, name), "utf8")));
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
