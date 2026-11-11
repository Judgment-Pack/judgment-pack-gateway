// The seal made after an interruption (SPEC.md §3c; gateway #395): what a
// line must be to load as one, and what verification says of the session
// it anchors -- sealed, observed sealed-after-interruption, and a finding
// only with --ordinary-seals-only. The rows of
// testdata/interruption-seal/cases.json are shared with the Go reader.

import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { verifyStore } from "../src/verify.ts";
import { corpus, materialize, publicKey, verdictText } from "./support.ts";
import type { StoreVector } from "./support.ts";

type Row = {
  name: string;
  vector: string;
  registry?: string;
  remove?: string[];
  tear?: string[];
  ordinarySealsOnly?: boolean;
  ok: boolean;
  findings: string[];
  observations: string[];
};

const main = path.join(import.meta.dirname, "..", "src", "main.ts");

function vector(name: string): StoreVector {
  return JSON.parse(fs.readFileSync(path.join(corpus, ...name.split("/")), "utf8"));
}

// lines is a verdict's findings, a line each and sorted, as the Go reader's
// test writes them, and its session-open and sealed-after-interruption
// observations, in the order given.
function lines(text: string): { ok: boolean; findings: string[]; observations: string[] } {
  const verdict = JSON.parse(text);
  const at = (f: Record<string, unknown>) => (f["file"] !== undefined ? f["file"] : f["callIndex"] ?? "<nil>");
  const findings = (verdict.findings as Record<string, unknown>[]).map((f) => `${f["sessionId"] ?? "<nil>"}/${at(f)}/${f["status"]}`).sort();
  const observations = ((verdict.observations ?? []) as Record<string, unknown>[])
    .filter((o) => o["observation"] === "session-open" || o["observation"] === "sealed-after-interruption")
    .map((o) => `${o["sessionId"]}/${o["callIndex"]}/${o["observation"]}`);
  return { ok: verdict.ok, findings, observations };
}

test("the shared rows: what a seal after an interruption anchors, plain and with ordinary seals only", () => {
  const rows: Row[] = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "..", "..", "testdata", "interruption-seal", "cases.json"), "utf8"));
  assert.ok(rows.length > 0);
  for (const row of rows) {
    const v = vector(row.vector);
    if (row.registry !== undefined) {
      v.registry = row.registry;
    }
    for (const file of row.remove ?? []) {
      assert.ok(file in v.files, `${row.name}: the vector holds no ${file}`);
      delete v.files[file];
    }
    for (const file of row.tear ?? []) {
      const text = v.files[file];
      assert.ok(text !== undefined && /^[\x00-\x7f]*$/.test(text), `${row.name}: ${file}`);
      v.files[file] = text.slice(0, Math.floor(text.length / 2));
    }
    const { root, registry, decisionRecords } = materialize(v);
    const got = lines(verdictText(verifyStore(root, registry, v.authority, decisionRecords, publicKey, { ordinarySealsOnly: row.ordinarySealsOnly === true })));
    assert.deepEqual(got, { ok: row.ok, findings: [...row.findings].sort(), observations: row.observations }, row.name);
  }
});

// The test key, from the published TEST-SEED, and a key that is not it.
function keyFrom(seed: Buffer): crypto.KeyObject {
  return crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
}
const testKey = keyFrom(Buffer.from(fs.readFileSync(path.join(corpus, "TEST-SEED"), "utf8").trim(), "hex"));
const otherKey = keyFrom(crypto.createHash("sha256").update("not the test key").digest());
const testKeyId = crypto.createHash("sha256").update(publicKey).digest("hex").slice(0, 32);

// sealed is a seal after an interruption written by hand: the body as
// given, its members in code-point order, then the signature over §3c's
// prefix and that body.
function sealed(body: string, key: crypto.KeyObject = testKey): string {
  const signature = crypto.sign(null, Buffer.from("judgment-pack-gateway/seal-after-interruption/1:" + body, "utf8"), key).toString("hex");
  return body.slice(0, -1) + `,"signature":"${signature}"}`;
}

test("a line loads as a seal after an interruption only when it holds the form, and the gateway's key signed it", () => {
  const base = vector("stores/interruption-seal.json");
  const head = JSON.parse(base.files["receipts/s1/2.json"]!).signature as string;
  const body = (o: { count?: string; head?: string; keyId?: string; at?: string; via?: string; session?: string; extra?: string } = {}) =>
    `{${o.extra ?? ""}"finalCount":${o.count ?? "3"},"headSignature":"${o.head ?? head}","keyId":"${o.keyId ?? testKeyId}","kind":"seal-after-interruption","sealedAt":"${o.at ?? "2026-11-10T00:00:01Z"}","sealedVia":"${o.via ?? "command"}","sessionId":"${o.session ?? "s1"}"}`;
  const good = sealed(body());
  const signatureAt = good.indexOf('"signature":"') + 13;
  const sealedOk = { ok: true, findings: ["s1/0/ok", "s1/1/ok", "s1/2/ok"], observations: ["s1/2/sealed-after-interruption"] };
  const unsealed = { ok: false, findings: ["s1/0/ok", "s1/1/ok", "s1/2/ok", "s1/<nil>/unregistered-session"], observations: ["s1/2/session-open"] };
  const rows: [string, string, typeof sealedOk][] = [
    ["the seal", good, sealedOk],
    ["sealed by the start", sealed(body({ via: "start" })), sealedOk],
    ["signed by another key", sealed(body(), otherKey), unsealed],
    ["naming another key's id", sealed(body({ keyId: "0".repeat(32) })), unsealed],
    ["its signature altered", good.slice(0, -3) + (good.at(-3) === "0" ? "1" : "0") + '"}', unsealed],
    ["its signature in uppercase", good.slice(0, signatureAt) + good.slice(signatureAt, -2).toUpperCase() + '"}', unsealed],
    ["a member more", sealed(body({ extra: '"extra":1,' })), unsealed],
    ["sealedVia missing", sealed(body().replace(',"sealedVia":"command"', "")), unsealed],
    ["sealedVia of no kind", sealed(body({ via: "operator" })), unsealed],
    ["finalCount zero", sealed(body({ count: "0", head })), unsealed],
    ["finalCount a string", sealed(body({ count: '"3"' })), unsealed],
    ["finalCount past 2^53-1", sealed(body({ count: "9007199254740992" })), unsealed],
    ["headSignature in uppercase", sealed(body({ head: head.toUpperCase() })), unsealed],
    ["headSignature short", sealed(body({ head: head.slice(0, 126) })), unsealed],
    ["keyId in uppercase", sealed(body({ keyId: testKeyId.toUpperCase() })), unsealed],
    ["sealedAt of another form", sealed(body({ at: "2026-11-10 00:00:01Z" })), unsealed],
    ["a session id §3a refuses", sealed(body({ session: "s1/.." })), unsealed],
    ["the session id ..", sealed(body({ session: ".." })), unsealed],
  ];
  for (const [name, line, want] of rows) {
    const v = { ...base, registry: line + "\n" };
    const { root, registry, decisionRecords } = materialize(v);
    assert.deepEqual(lines(verdictText(verifyStore(root, registry, v.authority, decisionRecords, publicKey))), want, name);
  }
});

test("main.ts verify takes --ordinary-seals-only first or not at all, and the verdict it writes is the strict one", () => {
  const v = vector("stores/interruption-seal.json");
  const { root, registry } = materialize(v);
  const run = (...args: string[]) => spawnSync(process.execPath, [main, "verify", ...args], { input: publicKey });
  const strict = run("--ordinary-seals-only", root, registry, v.authority);
  assert.equal(strict.status, 0, strict.stderr.toString());
  assert.equal(
    strict.stdout.toString(),
    '{"ok":false,"findings":[{"sessionId":"s1","callIndex":0,"status":"ok"},{"sessionId":"s1","callIndex":1,"status":"ok"},{"sessionId":"s1","callIndex":2,"status":"ok"},{"sessionId":"s1","status":"sealed-after-interruption"}]}\n',
  );
  const plain = run(root, registry, v.authority);
  assert.equal(plain.status, 0, plain.stderr.toString());
  assert.equal(
    plain.stdout.toString(),
    '{"ok":true,"findings":[{"sessionId":"s1","callIndex":0,"status":"ok"},{"sessionId":"s1","callIndex":1,"status":"ok"},{"sessionId":"s1","callIndex":2,"status":"ok"}],"observations":[{"sessionId":"s1","callIndex":2,"observation":"sealed-after-interruption"}]}\n',
  );
  assert.equal(run("--ordinary-seals-only", root, registry).status, 64);
  const usage =
    "usage: main.ts canon | main.ts verify [--ordinary-seals-only] <store-root> <registry-path> <authority> [<decision-records-dir>] | main.ts witness --trail <hex> --witness-key <file>... [--witness <file>]... [--witness-head <file>]\n";
  const notFirst = "verify: --ordinary-seals-only goes first, before the store root; a directory so named is given as ./--ordinary-seals-only\n" + usage;
  const misplaced: [string, string[]][] = [
    ["a fourth argument", [root, registry, v.authority, "--ordinary-seals-only"]],
    ["second, after a store root", [root, "--ordinary-seals-only", registry, v.authority]],
    ["first and again", ["--ordinary-seals-only", "--ordinary-seals-only", root, registry, v.authority]],
    ["first and as a fourth argument", ["--ordinary-seals-only", root, registry, v.authority, "--ordinary-seals-only"]],
  ];
  for (const [name, args] of misplaced) {
    const r = run(...args);
    assert.equal(r.status, 64, name);
    assert.equal(r.stdout.toString(), "", name);
    assert.equal(r.stderr.toString(), notFirst, name);
  }
  const dir = run(root, registry, v.authority, "./--ordinary-seals-only");
  assert.equal(dir.status, 0, dir.stderr.toString());
  assert.equal(dir.stdout.toString(), plain.stdout.toString());
});
