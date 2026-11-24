// The frozen corpus, read here as the process contract hands it to any
// implementation: every canon vector, and every store vector materialized
// as a store, a registry and a decision-record directory, with findings
// compared as a multiset, and observations too where a vector states them. `gateway conform --impl` holds the process to
// the same corpus in CI; this holds the module to it without the gateway.

import * as assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { canonical } from "../src/canon.ts";
import { maxValues, parse } from "../src/json.ts";
import { verifyByAlg } from "../src/alg.ts";
import { reached } from "../src/rotation.ts";
import { checkKeyHistory, verifyStore } from "../src/verify.ts";
import {
  corpus,
  materialize,
  multiset,
  newStore,
  p256Pin,
  publicKey,
  readStoreVector,
  readVector,
  readWitnessVector,
  sealLine,
  storeVectors,
  tempDir,
  verdictText,
} from "./support.ts";

const main = path.join(import.meta.dirname, "..", "src", "main.ts");

// escapes is a JSON string of n two-character escapes, as bytes. Built as a
// Buffer, outside the V8 heap: under an address-space cap (ulimit -v) the
// test process's own heap is small, and a string of tens of millions of
// characters, concatenated and flattened, aborts it.
const escapes = (n: number): Buffer => Buffer.concat([Buffer.from('"'), Buffer.alloc(2 * n, "\\n"), Buffer.from('"')]);

test("every canon vector", () => {
  // read as gateway conform reads it, a member by its exact name; a member
  // no reader reads is passed over (SPEC.md §7)
  const vectors = (readVector(path.join(corpus, "canon.json")) as { vectors: { note: string; inputJson: string; expectedHex?: string; reject?: boolean }[] }).vectors;
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

test("every P-256 vector, its high-S twin refused, and none of them altered", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(corpus, "p256-vectors.json"), "utf8"));
  assert.ok(doc.vectors.length > 0);
  for (const v of doc.vectors) {
    assert.equal(v.publicKey, p256Pin.key);
    const key = reached(Buffer.from(v.publicKey, "hex"), "ES256");
    assert.equal(key.keyId, "dbdb99c64b3d511f72c88fb6c054da73");
    const message = Buffer.from(v.message, "hex");
    assert.ok(verifyByAlg("ES256", key, message, v.signature), v.message);
    assert.ok(!verifyByAlg("ES256", key, message, v.highS), v.message);
    assert.ok(!verifyByAlg("", key, message, v.signature), v.message);
    assert.ok(!verifyByAlg("ES256", key, message, v.signature.toUpperCase()), v.message);
    const altered = Buffer.from(v.signature, "hex");
    altered[10]! ^= 1;
    assert.ok(!verifyByAlg("ES256", key, message, altered.toString("hex")), v.message);
  }
});

test("main.ts verify takes --public-key-alg ES256 first, and the 66 hexadecimal characters on standard input", () => {
  const v = storeVectors().find((s) => s.name === "p256-pinned-from-first-receipt")!;
  const { root, registry } = materialize(v);
  const run = (args: string[], input: string | Buffer) => spawnSync(process.execPath, [main, "verify", ...args, root, registry, v.authority], { input });
  const pinned = run(["--public-key-alg", "ES256"], p256Pin.key);
  assert.equal(pinned.status, 0, pinned.stderr.toString());
  assert.equal(JSON.parse(pinned.stdout.toString("utf8")).ok, true);
  // the Ed25519 pin finds the P-256 receipt's key id among no key reached
  const plain = run([], publicKey);
  assert.equal(plain.status, 0);
  assert.equal(JSON.parse(plain.stdout.toString("utf8")).ok, false);
  for (const input of [p256Pin.key + "\n", p256Pin.key.toUpperCase(), publicKey]) {
    assert.equal(run(["--public-key-alg", "ES256"], input).status, 2);
  }
  // off the curve: x = 1 has no point
  assert.equal(run(["--public-key-alg", "ES256"], "02" + "00".repeat(31) + "01").status, 2);
  assert.equal(run(["--public-key-alg", "ES384"], p256Pin.key).status, 64);
  assert.equal(run(["--scope", "scope-a", "--public-key-alg", "ES256"], p256Pin.key).status, 64);
});

test("every store vector", () => {
  const vectors = storeVectors();
  assert.ok(vectors.length >= 39);
  for (const v of vectors) {
    const { root, registry, decisionRecords, artifacts, previous } = materialize(v);
    const options = { ordinarySealsOnly: v.ordinarySealsOnly === true, ...(artifacts !== undefined && { artifacts }), ...(v.scope !== undefined && { scope: v.scope }), ...(previous !== undefined && { previous }), ...(v.requireJournal !== undefined && { requireJournal: v.requireJournal }) };
    assert.ok(v.publicKeyAlg === undefined || v.publicKeyAlg === "ES256", v.name);
    const pin = v.publicKeyAlg === "ES256" ? p256Pin : publicKey;
    const verdict = JSON.parse(verdictText(verifyStore(root, registry, v.authority, decisionRecords, pin, options)));
    assert.equal(verdict.ok, v.expected.ok, v.name);
    assert.deepEqual(multiset(verdict.findings), multiset(v.expected.findings), v.name);
    // the observations, as a multiset, only where the vector states them
    // (SPEC.md §7); left out of a verdict is none
    if (v.expected.observations !== undefined) {
      assert.deepEqual(multiset(verdict.observations ?? []), multiset(v.expected.observations), v.name);
    }
    // the witnesses the receipts name, as a set (ADR-0014); absent is none
    assert.deepEqual([...new Set(multiset(verdict.witnesses ?? []))], [...new Set(multiset(v.expected.witnesses ?? []))], v.name);
    // a verdict by scope's cut, whole (§4, "A verdict by scope"); absent is
    // a verdict of the whole store
    assert.deepEqual(verdict.cut, v.expected.cut, v.name);
  }
});

// A vector's members are read by their exact names, as gateway conform
// reads them (SPEC.md §7): in a store vector and a witness vector, a member
// under another case is one the runner does not read, and refuses the
// read, at the top, in expected and in a file's parts form; canon.json's
// vectors pass it over. A member given twice refuses any vector file, as
// does a file that is not one JSON value.
test("a vector's members are read by their exact names", () => {
  const at = tempDir();
  const edited = (rel: string, from: string, to: string): string => {
    const text = fs.readFileSync(path.join(corpus, ...rel.split("/")), "utf8");
    assert.ok(text.includes(from), `${rel}: no ${from}`);
    const file = path.join(at, `${rel.replaceAll("/", "-")}-${crypto.randomUUID()}.json`);
    fs.writeFileSync(file, text.replace(from, to));
    return file;
  };
  for (const [rel, from, to, read, refused] of [
    ["stores/valid-sealed.json", '"authority": ', '"Authority": ', readStoreVector, 'unknown member "Authority"'],
    ["stores/valid-sealed.json", '"authority": ', '"OrdinarySealsOnly": true, "authority": ', readStoreVector, 'unknown member "OrdinarySealsOnly"'],
    ["stores/valid-sealed.json", '"ok": true,', '"ok": true, "OK": false,', readStoreVector, 'unknown member "OK"'],
    ["v3/stores/v3-action-valid.json", '"decisionRecords": {', '"DecisionRecords": {', readStoreVector, 'unknown member "DecisionRecords"'],
    ["stores/valid-sealed.json", '"ok": true,', '"ok": true, "ok": true,', readStoreVector, 'the member "ok" is given twice in one object'],
    ["stores/valid-sealed.json", '"ok": true,', '"ok": true, "findings": [{"status": "ok", "status": "ok"}],', readStoreVector, 'the member "status" is given twice in one object'],
    ["witness/valid-one-statement.json", '"trail": ', '"Trail": ', readWitnessVector, 'unknown member "Trail"'],
    ["witness/bound-statements-at-limit.json", '"times": ', '"Times": ', readWitnessVector, 'unknown member "Times"'],
    ["witness/valid-one-statement.json", '"reading": ', '"Reading": "", "reading": ', readWitnessVector, 'unknown member "Reading"'],
    ["witness/valid-one-statement.json", '"latestCheckpoint": {', '"latestCheckpoint": {"Index": 0, ', readWitnessVector, 'unknown member "Index"'],
    ["witness/valid-one-statement.json", '"trail": ', '"keys": [], "trail": ', readWitnessVector, 'the member "keys" is given twice in one object'],
    ["canon.json", '"inputJson": "{}",', '"inputJson": "{}" "x",', readVector, "not exactly one JSON value"],
    ["canon.json", '"inputJson": "{}",', '"inputJson": "{}", "note": "",', readVector, 'the member "note" is given twice in one object'],
  ] as const) {
    const file = edited(rel, from, to);
    assert.throws(() => read(file), { message: `${file}: ${refused}` }, `${rel}: ${to}`);
  }
  // in document order: a member twice inside a member's value, before
  // that member is given again
  const nested = edited("stores/valid-sealed.json", '"ok": true,', '"ok": {"a": 1, "a": 1}, "ok": true,');
  assert.throws(() => readStoreVector(nested), { message: `${nested}: the member "a" is given twice in one object` });
  const canon = readVector(edited("canon.json", '"inputJson": "{}",', '"inputJson": "{}", "InputJson": "[]", "Reject": true,')) as {
    vectors: Record<string, unknown>[];
  };
  assert.equal(canon.vectors[0]!["inputJson"], "{}");
  assert.equal(canon.vectors[0]!["reject"], undefined);
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
  assert.match(longKey.stderr.toString(), /standard input is more than 32 bytes/);
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

// A key of 33 bytes on a pipe left open is refused on its 33rd byte, the
// verifier waiting for nothing more.
test("a key past its bound is refused without waiting for the end", async () => {
  const v = storeVectors().find((s) => s.name === "valid-sealed")!;
  const { root, registry } = materialize(v);
  const child = spawn(process.execPath, [main, "verify", root, registry, v.authority], { stdio: ["pipe", "ignore", "ignore"] });
  child.stdin.write(Buffer.concat([publicKey, Buffer.from([0])]));
  const status = await new Promise<number | null>((resolve) => {
    const timer = setTimeout(() => {
      child.kill();
      resolve(null);
    }, 10000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
  child.stdin.destroy();
  assert.equal(status, 2);
});

// Standard input read a byte at a time -- a pipe returns what its writer
// wrote -- is held as the document's bytes, not a buffer a read: a
// document of 512 KiB so read is canonicalized in a process held to a heap
// too small for half a million buffers. The platform's module is rebound
// before the verifier loads.
test("standard input read a byte at a time fits a small heap", () => {
  const preload =
    "data:text/javascript," +
    encodeURIComponent(
      'import fs from "node:fs"; import { syncBuiltinESMExports } from "node:module";' +
        " const readSync = fs.readSync;" +
        " fs.readSync = (fd, buffer, offset, length, position) => readSync(fd, buffer, offset, Math.min(length, 1), position);" +
        " syncBuiltinESMExports();",
    );
  const document = '"' + "a".repeat(512 << 10) + '"';
  const r = spawnSync(process.execPath, ["--max-old-space-size=16", "--import", preload, main, "canon"], { input: document, maxBuffer: 2 << 20 });
  assert.equal(r.status, 0, r.stderr.toString().slice(0, 400));
  assert.equal(r.stdout.toString(), document);
});

// A string of millions of escapes, one value and within every bound, is
// read and written at the cost of its bytes: in a process held to a small
// heap, canonicalized whole, and verified inside a receipt.
test("a string of millions of escapes fits a small heap", () => {
  const heap = "--max-old-space-size=384";
  const document = escapes(33554430);
  const canon = spawnSync(process.execPath, [heap, main, "canon"], { input: document, maxBuffer: 80 << 20 });
  assert.equal(canon.status, 0, canon.stderr.toString().slice(0, 400));
  assert.ok(canon.stdout.equals(document));

  const v = storeVectors().find((s) => s.name === "valid-sealed")!;
  const { root, registry } = materialize(v);
  const receipt = path.join(root, "receipts", "s1", "0.json");
  // The receipt, with the rest of it, still within the 64 MiB a receipt may take.
  const text = fs.readFileSync(receipt);
  const open = text.indexOf("{");
  fs.writeFileSync(receipt, Buffer.concat([text.subarray(0, open + 1), Buffer.from('"later":'), escapes(33000000), Buffer.from(","), text.subarray(open + 1)]));
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

// Decision records failing in their millions are verified in a process
// held to a heap smaller than their findings written out: each failure is
// kept as 33 bytes, and the verdict is written as it is made, no finding
// held for it.
test("a million failing decision records fit a small heap", () => {
  const v = storeVectors().find((s) => s.name === "valid-sealed")!;
  const { root, registry } = materialize(v);
  const at = path.dirname(root);
  const records = path.join(at, "records");
  fs.mkdirSync(records);
  const n = 1200000;
  fs.writeFileSync(path.join(records, "log.jsonl"), '{"cites":null}\n'.repeat(n));
  const out = fs.openSync(path.join(at, "verdict"), "w");
  let verified: ReturnType<typeof spawnSync>;
  try {
    verified = spawnSync(process.execPath, ["--max-old-space-size=128", main, "verify", root, registry, v.authority, records], {
      input: publicKey,
      stdio: ["pipe", out, "pipe"],
    });
  } finally {
    fs.closeSync(out);
  }
  assert.equal(verified.status, 0, String(verified.stderr).slice(0, 400));
  const verdict = fs.readFileSync(path.join(at, "verdict"));
  const failure = Buffer.from('{"recordDigest":"sha256:');
  let failures = 0;
  for (let i = verdict.indexOf(failure); i !== -1; i = verdict.indexOf(failure, i + failure.length)) {
    failures++;
  }
  assert.equal(failures, n);
  assert.equal(verdict.subarray(0, 24).toString(), '{"ok":false,"findings":[');
  assert.equal(verdict.subarray(-3).toString(), "]}\n");
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

// The key-history family (ADR-0055 §9), held on the verdict and on the
// class of each refusal, which is part of the corpus contract; gateway
// conform runs the same vectors through the Go check.
test("every key-history vector, on its verdict and its class", () => {
  const dir = path.join(corpus, "key-history");
  const names = fs.readdirSync(dir).filter((n) => n.endsWith(".json")).sort();
  assert.equal(names.length, 29);
  for (const name of names) {
    const v = readVector(path.join(dir, name)) as {
      name: string;
      pin: string | { alg: "ES256"; key: string };
      requireVersion?: string;
      history: string;
      expected: { accepted?: { keys: number; inForce: string }; refused?: string };
    };
    const pin =
      typeof v.pin === "string"
        ? { alg: "" as const, key: Buffer.from(fs.readFileSync(path.join(corpus, v.pin), "utf8").trim(), "hex") }
        : { alg: "ES256" as const, key: Buffer.from(v.pin.key, "hex") };
    const got = checkKeyHistory(Buffer.from(v.history, "utf8"), pin, v.requireVersion === undefined ? {} : { requireVersion: v.requireVersion });
    if (v.expected.accepted !== undefined) {
      assert.ok(got.accepted, `${v.name}: refused ${got.accepted ? "" : `${got.class}: ${got.reason}`}`);
      assert.equal(got.entries.length, v.expected.accepted.keys, v.name);
      assert.equal(got.entries[got.entries.length - 1]!.keyId, v.expected.accepted.inForce, v.name);
    } else {
      assert.ok(!got.accepted, `${v.name}: accepted`);
      assert.equal(got.class, v.expected.refused, `${v.name}: ${got.reason}`);
    }
  }
});

// The operator journal's own name, held by a link or a directory, is not
// read as no journal: it is journal-unknown, by its name, as in Go.
test("an operator journal that is not a regular file is journal-unknown", () => {
  const v = storeVectors().find((s) => s.name === "v3-journal-unknown")!;
  for (const make of ["directory", "link"]) {
    const { root, registry, decisionRecords } = materialize(v);
    const file = path.join(root, "journals", "operator.jsonl");
    fs.rmSync(file);
    if (make === "directory") {
      fs.mkdirSync(file);
    } else {
      fs.writeFileSync(path.join(root, "journals", "elsewhere"), "");
      fs.symlinkSync("elsewhere", file);
    }
    const verdict = JSON.parse(verdictText(verifyStore(root, registry, v.authority, decisionRecords, publicKey)));
    assert.equal(verdict.ok, false, make);
    assert.ok(verdict.findings.some((f: Record<string, unknown>) => f.status === "journal-unknown" && f.file === "operator.jsonl"), make);
  }
});

// Only a refusal journal's exact name, with .jsonl, .key, .forwarded or a
// cursor's staging form, is a file this verifier knows; each near miss is
// journal-unknown, by its name, as in Go, and a known file is never read.
test("a near miss of a refusal journal's name is journal-unknown", () => {
  const v = storeVectors().find((s) => s.name === "v3-journal-refusal-holds")!;
  const { root, registry, decisionRecords } = materialize(v);
  const dir = path.join(root, "journals");
  const name = fs.readdirSync(dir).find((f) => /^refusal-[a-p]{24}\.jsonl$/.test(f))!.slice(0, -".jsonl".length);
  const stem = name.slice("refusal-".length);
  fs.writeFileSync(path.join(dir, name + ".key"), "ab".repeat(32) + "\n");
  fs.writeFileSync(path.join(dir, name + ".forwarded"), "not a cursor");
  fs.writeFileSync(path.join(dir, name + ".forwarded.4242.0123456789ab.tmp"), "not a cursor");
  const misses = [
    "refusal-" + stem.slice(0, 23) + ".jsonl",
    "refusal-" + stem + "a.jsonl",
    "refusal-" + "q".repeat(24) + ".jsonl",
    "refusal-" + stem.toUpperCase() + ".jsonl",
    name + ".jsonl.bak",
    name + ".KEY",
    name + ".pending",
    name,
    "refusal-anything.jsonl",
    "refusal-.jsonl",
    "refusal-" + stem.slice(0, 23) + ".forwarded.4242.0123456789ab.tmp",
    name + ".forwarded.4242.0123456789AB.tmp",
    name + ".forwarded.4242.0123456789a.tmp",
    name + ".forwarded.4242.0123456789abc.tmp",
    name + ".forwarded.12345678901.0123456789ab.tmp",
    name + ".forwarded..0123456789ab.tmp",
    name + ".forwarded.0123456789ab.tmp",
    name + ".forwarded.4242.0123456789ab",
    name + ".forwarded.4242.0123456789ab.tmp.x",
    name + ".key.4242.0123456789ab.tmp",
    name + ".forwarded.bak",
  ];
  for (const m of misses) {
    fs.writeFileSync(path.join(dir, m), "{}\n");
  }
  const verdict = JSON.parse(verdictText(verifyStore(root, registry, v.authority, decisionRecords, publicKey)));
  const unknown = verdict.findings.filter((f: Record<string, unknown>) => f.status === "journal-unknown").map((f: Record<string, unknown>) => f.file).sort();
  assert.deepEqual(unknown, [...misses].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
  assert.equal(verdict.ok, false);
});
