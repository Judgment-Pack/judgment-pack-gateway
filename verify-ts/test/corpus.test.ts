// The frozen corpus, read here as the process contract hands it to any
// implementation: every canon vector, and every store vector materialized
// as a store, a registry and a decision-record directory, with findings
// compared as a multiset. `gateway conform --impl` holds the process to
// the same corpus in CI; this holds the module to it without the gateway.

import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { canonical } from "../src/canon.ts";
import { maxValues, parse } from "../src/json.ts";
import { verifyStore, writeVerdict } from "../src/verify.ts";
import { corpus, materialize, multiset, newStore, publicKey, sealLine, storeVectors } from "./support.ts";

const main = path.join(import.meta.dirname, "..", "src", "main.ts");

test("every canon vector", () => {
  const vectors = JSON.parse(fs.readFileSync(path.join(corpus, "canon.json"), "utf8")).vectors;
  assert.ok(vectors.length >= 30);
  for (const v of vectors) {
    const value = parse(Buffer.from(v.inputJson, "utf8"));
    const bytes = value === null ? null : canonical(value);
    if (v.reject) {
      assert.equal(bytes, null, v.note);
    } else {
      assert.notEqual(bytes, null, v.note);
      assert.equal(Buffer.from(bytes!).toString("hex"), v.expectedHex, v.note);
    }
  }
});

test("every Ed25519 vector, and none of them altered", () => {
  const vectors = JSON.parse(fs.readFileSync(path.join(corpus, "ed25519-vectors.json"), "utf8")).vectors;
  assert.ok(vectors.length > 0);
  for (const v of vectors) {
    const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(v.publicKey, "hex").toString("base64url") }, format: "jwk" });
    const message = Buffer.from(v.message, "hex");
    const signature = Buffer.from(v.signature, "hex");
    assert.ok(crypto.verify(null, message, key, signature), v.message);
    signature[0]! ^= 1;
    assert.ok(!crypto.verify(null, message, key, signature), v.message);
  }
});

test("every store vector", () => {
  const vectors = storeVectors();
  assert.ok(vectors.length >= 39);
  for (const v of vectors) {
    const { root, registry, decisionRecords } = materialize(v);
    const verdict = JSON.parse(writeVerdict(verifyStore(root, registry, v.authority, decisionRecords, publicKey)));
    assert.equal(verdict.ok, v.expected.ok, v.name);
    assert.deepEqual(multiset(verdict.findings), multiset(v.expected.findings), v.name);
  }
});

test("the process contract, end to end", () => {
  const canon = spawnSync(process.execPath, [main, "canon"], { input: '{"b":1,"a":"caf\\u00e9"}' });
  assert.equal(canon.status, 0);
  assert.equal(canon.stdout.toString("utf8"), '{"a":"café","b":1}');
  const refused = spawnSync(process.execPath, [main, "canon"], { input: '{"n":1.0}' });
  assert.notEqual(refused.status, 0);
  assert.equal(refused.stdout.length, 0);

  const v = storeVectors().find((s) => s.name === "v3-action-valid")!;
  const { root, registry, decisionRecords } = materialize(v);
  const verified = spawnSync(process.execPath, [main, "verify", root, registry, v.authority, decisionRecords!], { input: publicKey });
  assert.equal(verified.status, 0, verified.stderr.toString());
  const verdict = JSON.parse(verified.stdout.toString("utf8"));
  assert.equal(verdict.ok, true);
  assert.deepEqual(multiset(verdict.findings), multiset(v.expected.findings));

  // A failing verdict is still a verdict: exit 0.
  const failing = spawnSync(process.execPath, [main, "verify", root, registry, v.authority], { input: publicKey });
  assert.equal(failing.status, 0);
  assert.equal(JSON.parse(failing.stdout.toString("utf8")).ok, false);

  // Standard input past its bound: a key of 33 bytes, and input with no
  // end, each refused having read no more than a byte past the bound.
  const longKey = spawnSync(process.execPath, [main, "verify", root, registry, v.authority], { input: Buffer.concat([publicKey, Buffer.from([0])]) });
  assert.equal(longKey.status, 2);
  const endless = fs.openSync("/dev/zero", "r");
  try {
    const endlessKey = spawnSync(process.execPath, [main, "verify", root, registry, v.authority], { stdio: [endless, "pipe", "pipe"], timeout: 20000 });
    assert.equal(endlessKey.status, 2);
    const endlessDocument = spawnSync(process.execPath, [main, "canon"], { stdio: [endless, "pipe", "pipe"], timeout: 20000 });
    assert.equal(endlessDocument.status, 2);
  } finally {
    fs.closeSync(endless);
  }

  // A document past the values this implementation reads is not refused
  // as outside the domain: exit 2.
  const tooMany = spawnSync(process.execPath, [main, "canon"], { input: "[" + "0,".repeat(maxValues) + "0]" });
  assert.equal(tooMany.status, 2);

  // No verdict: the store root is a file.
  const file = path.join(root, "receipts", "s2", "0.json");
  const none = spawnSync(process.execPath, [main, "verify", file, registry, v.authority], { input: publicKey });
  assert.equal(none.status, 2);
  assert.equal(none.stdout.length, 0);
});

// A string of millions of escapes, one value and within every bound, is
// read and written at the cost of its bytes: in a process held to a small
// heap, canonicalized whole, and verified inside a receipt.
test("a string of millions of escapes fits a small heap", () => {
  const heap = "--max-old-space-size=384";
  const escapes = '"' + "\\n".repeat(33554430) + '"';
  const canon = spawnSync(process.execPath, [heap, main, "canon"], { input: escapes, maxBuffer: 80 << 20 });
  assert.equal(canon.status, 0, canon.stderr.toString().slice(0, 400));
  assert.equal(canon.stdout.length, Buffer.byteLength(escapes));
  assert.ok(canon.stdout.equals(Buffer.from(escapes)));

  const v = storeVectors().find((s) => s.name === "valid-sealed")!;
  const { root, registry } = materialize(v);
  const receipt = path.join(root, "receipts", "s1", "0.json");
  // The receipt, with the rest of it, still within the 64 MiB a receipt may take.
  const within = '"' + "\\n".repeat(33000000) + '"';
  fs.writeFileSync(receipt, fs.readFileSync(receipt, "utf8").replace("{", '{"later":' + within + ","));
  const verified = spawnSync(process.execPath, [heap, main, "verify", root, registry, v.authority], { input: publicKey, maxBuffer: 1 << 20 });
  assert.equal(verified.status, 0, verified.stderr.toString().slice(0, 400));
  assert.ok(JSON.parse(verified.stdout.toString()).findings.some((f: { status: string }) => f.status === "signature-mismatch"));
});

// A validly signed seal naming a session of 60 MiB is loaded, and its
// finding written, in a process held to a small heap.
test("a seal of a very long session id fits a small heap", () => {
  const store = newStore();
  const long = "s".repeat(60 << 20);
  fs.writeFileSync(store.registry, sealLine(long, 0) + "\n");
  const verified = spawnSync(process.execPath, ["--max-old-space-size=384", main, "verify", store.root, store.registry, "gateway:test"], {
    input: publicKey,
    maxBuffer: 80 << 20,
  });
  assert.equal(verified.status, 0, verified.stderr.toString().slice(0, 400));
  const verdict = JSON.parse(verified.stdout.toString());
  assert.deepEqual(verdict.findings.map((f: { status: string }) => f.status), ["sealed-session-missing"]);
  assert.equal(verdict.findings[0].sessionId.length, long.length);
});

// Decision records failing in their millions are refused at the verdict's
// limit, cleanly, in a process held to a small heap.
test("a million failing decision records fit a small heap", () => {
  const v = storeVectors().find((s) => s.name === "valid-sealed")!;
  const { root, registry } = materialize(v);
  const records = path.join(path.dirname(root), "records");
  fs.mkdirSync(records);
  fs.writeFileSync(path.join(records, "log.jsonl"), '{"cites":null}\n'.repeat(1200000));
  const verified = spawnSync(process.execPath, ["--max-old-space-size=384", main, "verify", root, registry, v.authority, records], { input: publicKey });
  assert.equal(verified.status, 2, verified.stderr.toString().slice(0, 400));
  assert.match(verified.stderr.toString(), /findings a verdict here may hold/);
});

// An argument's bytes are its path. A path ending in 0xff arrives, decoded
// with replacement, as the path ending in U+FFFD -- which here names a
// store, a registry and a directory that would verify -- and is no
// verdict rather than read as that other path. (Linux shows a process its
// arguments' bytes.)
test("an argument that is not UTF-8 is no verdict, and never another path", { skip: process.platform !== "linux" }, () => {
  const v = storeVectors().find((s) => s.name === "valid-sealed")!;
  const good = materialize(v);
  const at = path.dirname(good.root);
  const byName = (name: string, last: number[]) => Buffer.concat([Buffer.from(path.join(at, name)), Buffer.from(last)]);
  // Each 0xff path beside its U+FFFD twin, the twin the one that verifies.
  fs.renameSync(good.root, byName("st", [0xef, 0xbf, 0xbd]));
  fs.mkdirSync(byName("st", [0xff]));
  fs.copyFileSync(good.registry, byName("reg", [0xef, 0xbf, 0xbd]));
  fs.writeFileSync(byName("reg", [0xff]), "");
  fs.mkdirSync(byName("dr", [0xef, 0xbf, 0xbd]));
  fs.mkdirSync(byName("dr", [0xff]));
  fs.writeFileSync(Buffer.concat([byName("dr", [0xff]), Buffer.from("/r.json")]), '{"cites":null}');
  const run = (script: string) =>
    spawnSync("/bin/sh", ["-c", script], {
      input: publicKey,
      env: { ...process.env, NODE: process.execPath, MAIN: main, AT: at + path.sep, TWIN_ROOT: byName("st", [0xef, 0xbf, 0xbd]).toString() },
    });
  const ff = (name: string) => `"$(printf '%s%s\\377' "$AT" ${name})"`;
  const twin = (name: string) => `"$AT${name}\u{fffd}"`;
  // The twins, named as they are, verify.
  const twins = run(`exec "$NODE" "$MAIN" verify ${twin("st")} ${twin("reg")} ${v.authority} ${twin("dr")}`);
  assert.equal(twins.status, 0, twins.stderr.toString());
  for (const [what, script] of [
    ["the store root", `exec "$NODE" "$MAIN" verify ${ff("st")} ${twin("reg")} ${v.authority}`],
    ["the registry", `exec "$NODE" "$MAIN" verify ${twin("st")} ${ff("reg")} ${v.authority}`],
    ["the decision-record directory", `exec "$NODE" "$MAIN" verify ${twin("st")} ${twin("reg")} ${v.authority} ${ff("dr")}`],
  ] as const) {
    const r = run(script);
    assert.equal(r.status, 2, `${what}: ${r.stdout} ${r.stderr}`);
    assert.match(r.stderr.toString(), /not UTF-8/, what);
  }
});
