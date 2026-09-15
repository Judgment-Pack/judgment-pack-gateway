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
import { parse } from "../src/json.ts";
import { verifyStore, writeVerdict } from "../src/verify.ts";
import { corpus, materialize, multiset, publicKey, storeVectors } from "./support.ts";

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
    assert.equal(endlessDocument.status, 1);
  } finally {
    fs.closeSync(endless);
  }

  // No verdict: the store root is a file.
  const file = path.join(root, "receipts", "s2", "0.json");
  const none = spawnSync(process.execPath, [main, "verify", file, registry, v.authority], { input: publicKey });
  assert.equal(none.status, 2);
  assert.equal(none.stdout.length, 0);
});
