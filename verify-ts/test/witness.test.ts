// The witness reader (SPEC.md §8): every corpus vector, through the files
// the process contract hands an implementation; and statements of the
// tests' own, signed under the corpus's test seed, each departing from a
// valid chain in one respect, so that every refusal and finding is reached
// at least once here as well as in the corpus.

import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { collectLines, keyRefusal, readWitness, readWitnessFiles, witnessBounds } from "../src/witness.ts";
import type { Answer } from "../src/witness.ts";
import { keyId, materializeWitness, publicKey, sameWitnessAnswer, sign, tempDir, witnessVectors } from "./support.ts";

const main = path.join(import.meta.dirname, "..", "src", "main.ts");
const trail = "3c5e1a7f9b2d4c6e8a0f1b3d5c7e9a2b";
const prefix = "judgment-pack-gateway/witness/1:";

test("every witness vector", () => {
  const vectors = witnessVectors();
  assert.ok(vectors.length >= 50);
  for (const v of vectors) {
    const { keys, files, head } = materializeWitness(v);
    const answer = readWitnessFiles(v.trail, keys, files, head);
    assert.ok(sameWitnessAnswer(v.expected, answer as unknown as Record<string, unknown>), `${v.name}: ${JSON.stringify(answer)}`);
  }
});

type Statement = Record<string, unknown>;

function checkpoint(sequence: number, other = false, of = trail): Statement {
  const record = Buffer.from(`witness test ${other ? "other " : ""}record at ${sequence}`).toString("hex").padEnd(64, "0").slice(0, 64);
  return { checkpointVersion: "1", recordDigest: "sha256:" + record, sequence, trail: of };
}

function statement(index: number, prev: string | null, cp: Statement, kind = "checkpoint", extra: Statement = {}): Statement {
  const body: Statement = { checkpoint: cp, index, keyId, kind, prevSignature: prev, witnessVersion: "1", witnessedAt: `2026-10-05T12:${String(index % 60).padStart(2, "0")}:00Z`, ...extra };
  return { ...body, signature: sign(prefix, body) };
}

// chain is checkpoint statements at the sequences given, linked from 0.
function chain(...sequences: number[]): Statement[] {
  const out: Statement[] = [];
  for (const [i, sequence] of sequences.entries()) {
    out.push(statement(i, i === 0 ? null : (out[i - 1]!["signature"] as string), checkpoint(sequence)));
  }
  return out;
}

const lines = (...statements: (Statement | string)[]) => Buffer.from(statements.map((s) => (typeof s === "string" ? s : JSON.stringify(s)) + "\n").join(""));

function read(files: Buffer[], head: Buffer | null = null, keys: Uint8Array[] = [publicKey]): Answer {
  return readWitness({ trail, keys, files, head });
}

function findings(a: Answer): string[] | string {
  return "refused" in a ? `refused ${a.refused}` : a.findings;
}

test("a chain read from index 0 to a head is current, and coverage stays at the latest checkpoint", () => {
  const c = chain(100, 200);
  const x = statement(2, c[1]!["signature"] as string, checkpoint(100, true), "conflict");
  assert.deepEqual(read([lines(...c, x)], lines(x)), {
    ok: true,
    findings: [],
    reading: "current",
    headIndex: 2,
    highestIndex: 2,
    latestCheckpoint: { index: 1, sequence: 200, witnessedAt: "2026-10-05T12:01:00Z" },
    conflicts: [100],
    retired: false,
  });
  const r = statement(3, x["signature"] as string, c[1]!["checkpoint"] as Statement, "retirement");
  const retired = read([lines(...c, x, r)]);
  assert.ok("ok" in retired && retired.ok && retired.retired && retired.reading === "historical" && retired.headIndex === null);
});

test("every refusal is made before any statement is read", () => {
  const ok = lines(...chain(1));
  const many = Array.from({ length: 16 }, (_, k) => publicKeyOf(Buffer.alloc(32, k + 1)));
  assert.deepEqual(findings(read([ok], null, [...many.slice(0, 15), publicKey])), []);
  assert.equal(findings(read([ok], null, [...many, publicKey])), "refused keys-over-bound");
  for (const [key, refusal] of [
    ["edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "key-not-canonical"],
    ["0100000000000000000000000000000000000000000000000000000000000080", "key-not-canonical"],
    ["ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "key-not-canonical"],
    ["0000000000000000000000000000000000000000000000000000000000000080", "key-small-order"],
    ["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "key-small-order"],
    ["0200000000000000000000000000000000000000000000000000000000000000", "key-not-on-curve"],
  ] as const) {
    assert.equal(keyRefusal(Buffer.from(key, "hex")), refusal, key);
    assert.equal(findings(read([ok], null, [publicKey, Buffer.from(key, "hex")])), `refused ${refusal}`, key);
  }
  const pad = Buffer.alloc(witnessBounds.bytes - 2 * ok.length, "\n");
  assert.deepEqual(findings(read([Buffer.concat([ok, pad])], ok)), []);
  assert.equal(findings(read([Buffer.concat([ok, pad, Buffer.from("\n")])], ok)), "refused bytes-over-bound");
  assert.deepEqual(findings(read([Buffer.concat(Array(witnessBounds.statements - 1).fill(ok))], ok)), []);
  assert.equal(findings(read([Buffer.from("not a statement\n".repeat(witnessBounds.statements))], ok)), "refused statements-over-bound");
});

// publicKeyOf is the public key of a seed: a key the rule accepts.
function publicKeyOf(seed: Buffer): Buffer {
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const key = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return Buffer.from(crypto.createPublicKey(key).export({ format: "jwk" }).x!, "base64url");
}

test("each finding, by the statement or set that makes it, and only it", () => {
  const c = chain(10, 20, 30, 40);
  const sig = (s: Statement) => s["signature"] as string;
  const other1 = statement(1, sig(c[0]!), checkpoint(25));
  const altered = { ...c[1]!, checkpoint: { ...(c[1]!["checkpoint"] as Statement), sequence: 21 } };
  const text0 = JSON.stringify(c[0]);
  for (const [what, files, head, want] of [
    ["a member the format does not define", [lines(statement(0, null, checkpoint(10), "checkpoint", { note: "x" }))], null, ["witness-malformed"]],
    ["another witnessVersion", [lines(statement(0, null, checkpoint(10), "checkpoint", { witnessVersion: "2" }))], null, ["witness-malformed"]],
    ["a fifth checkpoint member", [lines(statement(0, null, { ...checkpoint(10), note: "x" }))], null, ["witness-malformed"]],
    ["index -0", [lines(text0.replace('"index":0,', '"index":-0,'))], null, ["witness-malformed"]],
    ["index 0.0", [lines(text0.replace('"index":0,', '"index":0.0,'))], null, ["witness-malformed"]],
    ["a signature in upper case", [lines(text0.replace(sig(c[0]!), sig(c[0]!).toUpperCase()))], null, ["witness-malformed"]],
    ["a name given twice", [lines(text0.replace('{"checkpoint"', '{"index":0,"checkpoint"'))], null, ["witness-malformed"]],
    ["a head file of two statements", [lines(c[0]!, c[1]!)], lines(c[0]!, c[1]!), ["witness-malformed"]],
    ["a statement altered after signing", [lines(c[0]!, altered)], null, ["witness-signature-invalid"]],
    ["a keyId that names no key", [lines(c[0]!, { ...c[1]!, keyId: "0".repeat(32) })], null, ["witness-signature-invalid"]],
    ["a statement of another trail", [lines(c[0]!, statement(0, null, checkpoint(5, false, "d0c1b2a3948576a7b8c9d0e1f2031425")))], null, ["witness-trail-mismatch"]],
    ["two statements at one index", [lines(c[0]!, c[1]!, other1)], null, ["witness-equivocation"]],
    ["a head that differs at an index held", [lines(...c)], lines(other1), ["witness-equivocation"]],
    ["beginning late", [lines(...c.slice(1))], null, ["witness-chain-broken"]],
    ["nothing supplied", [Buffer.alloc(0)], null, ["witness-chain-broken"]],
    ["a hole", [lines(c[0]!, c[1]!, c[3]!)], null, ["witness-chain-broken"]],
    ["a previous signature not the one before", [lines(c[0]!, c[1]!, statement(2, sig(c[0]!), checkpoint(30)))], null, ["witness-chain-broken"]],
    ["index 1 naming none", [lines(c[0]!, statement(1, null, checkpoint(20)))], null, ["witness-chain-broken"]],
    ["a sequence not increasing", [lines(c[0]!, statement(1, sig(c[0]!), checkpoint(10, true)))], null, ["witness-chain-broken"]],
    ["a conflict above the latest checkpoint", [lines(c[0]!, statement(1, sig(c[0]!), checkpoint(11, true), "conflict"))], null, ["witness-chain-broken"]],
    ["a retirement repeating an earlier checkpoint", [lines(c[0]!, c[1]!, statement(2, sig(c[1]!), c[0]!["checkpoint"] as Statement, "retirement"))], null, ["witness-chain-broken"]],
    ["a head more than one past", [lines(c[0]!, c[1]!)], lines(c[3]!), ["witness-head-unreached"]],
    ["a head alone, past index 0", [], lines(c[2]!), ["witness-chain-broken", "witness-head-unreached"]],
  ] as [string, Buffer[], Buffer | null, string[]][]) {
    assert.deepEqual(findings(read(files, head)), want, what);
  }
  for (const [what, files, head] of [
    ["a head one past, linked", [lines(c[0]!, c[1]!)], lines(c[2]!)],
    ["a chain past its head", [lines(...c)], lines(c[1]!)],
    ["a statement respelled", [lines(c[0]!), Buffer.from(" \r\n" + text0.replaceAll(",", " ,\t").replace('"kind"', '"k\\u0069nd"') + "\r\n")], null],
  ] as [string, Buffer[], Buffer | null][]) {
    assert.deepEqual(findings(read(files, head)), [], what);
  }
});

test("statements are counted as the files are split, and the split stops at the line past the bound", () => {
  const short = Buffer.from("x\n".repeat(1 << 22)); // 8 MiB, 4194304 lines
  // Compared as a sentence, not as the object: a reader that kept every line
  // would otherwise fail here by printing four million of them.
  const stopped = (r: ReturnType<typeof collectLines>) => (r.within ? `kept ${r.lines.length} lines` : `stopped at line ${r.counted}`);
  const past = `stopped at line ${witnessBounds.statements + 1}`;
  assert.equal(stopped(collectLines([short], null, witnessBounds.statements)), past);
  assert.equal(findings(read([short])), "refused statements-over-bound");
  // The head file is counted after the statements files.
  const one = lines(...chain(1));
  assert.equal(stopped(collectLines([Buffer.concat(Array(witnessBounds.statements).fill(one))], one, witnessBounds.statements)), past);
});

test("a chain begins with a checkpoint statement", () => {
  const conflict = statement(0, null, checkpoint(10, true), "conflict");
  const retirement = statement(0, null, checkpoint(10), "retirement");
  for (const [what, files] of [
    ["no statements file", []],
    ["an empty statements file", [Buffer.alloc(0)]],
    ["blank lines only", [Buffer.from("\n \r\n\t\n")]],
    ["a conflict with no checkpoint before it", [lines(conflict)]],
    ["a retirement with no checkpoint before it", [lines(retirement)]],
  ] as [string, Buffer[]][]) {
    assert.deepEqual(findings(read(files)), ["witness-chain-broken"], what);
  }
});

test("the process contract's witness command", () => {
  const at = tempDir();
  const key = path.join(at, "key");
  fs.writeFileSync(key, publicKey.toString("hex") + "\n");
  const statements = path.join(at, "statements");
  fs.writeFileSync(statements, lines(...chain(1)));
  const run = (...args: string[]) => spawnSync(process.execPath, [main, "witness", ...args]);
  const current = run("--trail", trail, "--witness-key", key, "--witness", statements, "--witness-head", statements);
  assert.equal(current.status, 0, current.stderr.toString());
  assert.equal(JSON.parse(current.stdout.toString()).reading, "current");
  const small = path.join(at, "small");
  fs.writeFileSync(small, "0".repeat(64));
  const refused = run("--trail", trail, "--witness-key", small, "--witness", statements);
  assert.equal(refused.status, 0);
  assert.equal(refused.stdout.toString(), '{"refused":"key-small-order"}');
  const short = path.join(at, "short");
  fs.writeFileSync(short, "abc");
  assert.equal(run("--trail", trail, "--witness-key", short, "--witness", statements).status, 2);
  assert.equal(run("--trail", trail, "--witness-key", key, "--witness", path.join(at, "absent")).status, 2);
  assert.equal(run("--trail", trail, "--witness", statements).status, 64);
});
