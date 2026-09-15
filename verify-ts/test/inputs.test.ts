// Absent and unreadable inputs (SPEC.md §4.1): what is confirmed not there
// is absent and fails closed; what is there and cannot be read is no
// verdict; and a path is taken by its spelling.

import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import * as v8 from "node:v8";
import * as vm from "node:vm";

import { NoVerdict, documentBound } from "../src/inputs.ts";
import { maxValues } from "../src/json.ts";
import { testHooks, verifyStore } from "../src/verify.ts";
import { acquisitionV3, actionV3, authority, newStore, publicKey, put, receiptV2, resultDigest, sealLine, signed, tempDir } from "./support.ts";

// A store of one session, s1, holding one valid receipt.
function oneSession() {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  return store;
}

function statuses(root: string, registry: string, decisionRecords?: string): string[] {
  return verifyStore(root, registry, authority, decisionRecords, publicKey)
    .findings.map((f) => String(new Map(f).get("status")))
    .sort();
}

function refused(root: string, registry: string, decisionRecords?: string): boolean {
  try {
    verifyStore(root, registry, authority, decisionRecords, publicKey);
    return false;
  } catch (e) {
    if (e instanceof NoVerdict) {
      return true;
    }
    throw e;
  }
}

const asRoot = process.getuid?.() === 0;

test("a registry confirmed not there loads no seals, and fails closed", () => {
  const store = oneSession();
  assert.deepEqual(statuses(store.root, store.registry), ["ok", "unregistered-session"]);
  // Under a directory confirmed missing, nothing below it is looked at.
  assert.deepEqual(statuses(store.root, path.join(path.dirname(store.registry), "gone", "deeper", "registry")), ["ok", "unregistered-session"]);
});

test("a registry that is there and cannot be read is no verdict", () => {
  const store = oneSession();
  const at = path.dirname(store.registry);
  const file = path.join(at, "file");
  fs.writeFileSync(file, "");
  assert.ok(refused(store.root, path.join(file, "registry")), "a component above that is not a directory");
  fs.symlinkSync(path.join(at, "nowhere"), path.join(at, "dangling"));
  assert.ok(refused(store.root, path.join(at, "dangling")), "a link that leads nowhere");
  assert.ok(refused(store.root, path.join(at, "dangling", "registry")), "a directory above that leads nowhere");
  fs.mkdirSync(path.join(at, "dir"));
  assert.ok(refused(store.root, path.join(at, "dir")), "a directory");
  if (!asRoot) {
    fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n", { mode: 0o000 });
    assert.ok(refused(store.root, store.registry), "unreadable");
    fs.chmodSync(store.registry, 0o644);
  }
});

test("a registry path is taken by its spelling", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const at = path.dirname(store.registry);
  fs.mkdirSync(path.join(at, "named"));
  assert.ok(refused(store.root, ""), "empty");
  assert.ok(refused(store.root, store.registry + path.sep), "a trailing separator");
  assert.ok(refused(store.root, path.join(at, "missing") + path.sep), "a trailing separator on a name that is not there");
  assert.ok(refused(store.root, path.join(at, "named") + path.sep + ".." + path.sep + "registry"), "a .. after a named component");
  // A leading .., a . and a repeated separator name the same file either
  // way, and are taken.
  const relative = path.relative(process.cwd(), store.registry);
  assert.ok(relative.startsWith(".."), relative);
  assert.deepEqual(statuses(store.root, relative), ["ok"]);
  assert.deepEqual(statuses(store.root, "." + path.sep + relative), ["ok"]);
  assert.deepEqual(statuses(store.root, at + path.sep + "." + path.sep + path.sep + "registry"), ["ok"]);
});

test("a store root or receipts directory not there holds no session; one that is not a directory is no verdict", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  assert.deepEqual(statuses(path.join(store.root, "nowhere"), store.registry), ["sealed-session-missing"]);
  const empty = newStore();
  assert.deepEqual(statuses(empty.root, store.registry), ["sealed-session-missing"]);
  fs.writeFileSync(path.join(empty.root, "receipts"), "");
  assert.ok(refused(empty.root, store.registry), "receipts a file");
  if (!asRoot) {
    fs.chmodSync(path.join(store.root, "receipts", "s1"), 0o000);
    try {
      assert.ok(refused(store.root, store.registry), "a session that cannot be read");
    } finally {
      fs.chmodSync(path.join(store.root, "receipts", "s1"), 0o755);
    }
  }
});

test("a decision-record directory not there is absent; one there and unreadable is no verdict", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  assert.deepEqual(statuses(store.root, store.registry, store.decisionRecords), ["ok"]);
  fs.writeFileSync(store.decisionRecords, "");
  assert.ok(refused(store.root, store.registry, store.decisionRecords), "a file");
  fs.rmSync(store.decisionRecords);
  fs.mkdirSync(path.join(store.decisionRecords, "named"), { recursive: true });
  assert.ok(refused(store.root, store.registry, path.join(store.decisionRecords, "named") + path.sep + ".."), "a .. after a named component");
  if (!asRoot) {
    fs.chmodSync(path.join(store.decisionRecords, "named"), 0o000);
    try {
      assert.ok(refused(store.root, store.registry, store.decisionRecords), "a directory under it that cannot be read");
    } finally {
      fs.chmodSync(path.join(store.decisionRecords, "named"), 0o755);
    }
  }
});

test("a receipt file that cannot be read is no verdict", { skip: asRoot }, () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  fs.chmodSync(path.join(store.root, "receipts", "s1", "0.json"), 0o000);
  assert.ok(refused(store.root, store.registry));
});

test("a public key of another length is no verdict", () => {
  const store = oneSession();
  assert.throws(() => verifyStore(store.root, store.registry, authority, undefined, publicKey.subarray(1)), NoVerdict);
});

// A FIFO no writer holds open, or a device, is present and not a regular
// file: no verdict, and no wait.
test("what is not a regular file is no verdict, and nothing waits on it", { skip: process.platform === "win32" }, () => {
  const fifo = (p: string) => {
    const made = spawnSync("mkfifo", [p]);
    assert.equal(made.status, 0, String(made.stderr));
  };
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  fifo(path.join(store.root, "receipts", "s1", "1.json"));
  assert.ok(refused(store.root, store.registry), "a receipt that is a FIFO");
  fs.rmSync(path.join(store.root, "receipts", "s1", "1.json"));
  fs.symlinkSync("/dev/zero", path.join(store.root, "receipts", "s1", "1.json"));
  assert.ok(refused(store.root, store.registry), "a receipt that leads to a device");
  fs.rmSync(path.join(store.root, "receipts", "s1", "1.json"));
  const registry = path.join(path.dirname(store.registry), "zero");
  fs.symlinkSync("/dev/zero", registry);
  assert.ok(refused(store.root, registry), "a registry that leads to a device");
  const artifact = path.join(store.root, "artifacts", fs.readdirSync(path.join(store.root, "artifacts"))[0]!);
  fs.rmSync(artifact);
  fifo(artifact);
  assert.ok(refused(store.root, store.registry), "an artifact that is a FIFO");
});

test("a spelling §4.1 refuses is refused before anything is read", { skip: asRoot }, () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  fs.chmodSync(path.join(store.root, "receipts"), 0o000);
  try {
    const at = path.dirname(store.registry);
    fs.mkdirSync(path.join(at, "named"));
    const steppedBack = path.join(at, "named") + path.sep + ".." + path.sep;
    for (const [registry, records] of [
      [steppedBack + "registry", undefined],
      [store.registry, steppedBack + "records"],
    ] as const) {
      assert.throws(() => verifyStore(store.root, registry, authority, records, publicKey), /steps back after a named component/);
    }
  } finally {
    fs.chmodSync(path.join(store.root, "receipts"), 0o755);
  }
});

test("a document past the bound: a receipt is no verdict, a seal line no seal, a record read only as far as its first byte", () => {
  const past = (p: string, first: string) => {
    fs.writeFileSync(p, first);
    fs.truncateSync(p, documentBound + 2);
  };
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  past(path.join(store.root, "receipts", "s1", "9.json"), "{");
  assert.ok(refused(store.root, store.registry), "a receipt");
  fs.rmSync(path.join(store.root, "receipts", "s1", "9.json"));
  // A registry line past the bound that opens no object is no seal, and
  // the next line is read; one that opens an object could be the first
  // seal of its session, so it is no verdict -- here a valid seal for two,
  // behind whitespace, before a seal for one that would otherwise win.
  const registry = path.join(path.dirname(store.registry), "long");
  past(registry, "x");
  fs.appendFileSync(registry, "\n" + sealLine("s1", 1) + "\n");
  assert.deepEqual(statuses(store.root, registry), ["ok"], "a line past the bound that opens no object");
  const padded = path.join(path.dirname(store.registry), "padded");
  const fd = fs.openSync(padded, "w");
  const spaces = Buffer.alloc(1 << 20, 0x20);
  for (let written = 0; written <= documentBound; written += spaces.length) {
    fs.writeSync(fd, spaces);
  }
  fs.writeSync(fd, sealLine("s1", 2) + "\n" + sealLine("s1", 1) + "\n");
  fs.closeSync(fd);
  assert.ok(refused(store.root, padded), "a line past the bound that could be the first seal");
  const records = tempDir();
  past(path.join(records, "big.bin"), " x");
  assert.deepEqual(statuses(store.root, store.registry, records), ["ok"], "a file that opens no object is not read");
  past(path.join(records, "big.json"), " {");
  assert.ok(refused(store.root, store.registry, records), "a file that opens an object");
  fs.rmSync(path.join(records, "big.json"));
  past(path.join(records, "log.jsonl"), '{"cites":');
  assert.ok(refused(store.root, store.registry, records), "a line that opens an object");
});

// The heap, looked at between documents: what verification keeps of each
// receipt and each decision record is small, whatever they hold.
function heapPeak(run: () => void, where: string): number {
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc") as () => void;
  gc();
  const base = process.memoryUsage().heapUsed;
  let peak = 0;
  testHooks.sample = (at) => {
    if (at === where) {
      gc();
      peak = Math.max(peak, process.memoryUsage().heapUsed - base);
    }
  };
  try {
    run();
  } finally {
    delete testHooks.sample;
  }
  return peak;
}

test("what is kept of a receipt does not grow with it", () => {
  const store = newStore();
  const big = "b".repeat(2 << 20);
  // Receipts of 2 MiB, six of each: failing at the key, with a large
  // member of their own; passing, each naming a large previous value, an
  // object or a string; and failing at the signature, whose own is 2 MiB
  // of hex.
  for (let i = 0; i < 6; i++) {
    put(store, "s1", `${i}.json`, JSON.stringify({ ...acquisitionV3(i), keyId: "0".repeat(32), later: big, signature: "a".repeat(128) }));
    put(store, "s2", `${i}.json`, JSON.stringify(signed({ ...receiptV2(i, null), sessionId: "s2", prevSignature: { bulk: big } })));
    put(store, "s3", `${i}.json`, JSON.stringify(signed({ ...receiptV2(i, null), sessionId: "s3", prevSignature: big })));
    put(store, "s4", `${i}.json`, JSON.stringify({ ...receiptV2(i, null), sessionId: "s4", signature: "ab".repeat(1 << 20) }));
  }
  fs.writeFileSync(store.registry, "");
  const peak = heapPeak(() => verifyStore(store.root, store.registry, authority, undefined, publicKey), "receipt");
  assert.ok(peak < 4 << 20, `${peak >> 20} MiB held between receipts of 2 MiB`);
});

test("what is kept of the decision records does not grow with their number", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const records = tempDir();
  fs.writeFileSync(path.join(records, "log.jsonl"), Array.from({ length: 200000 }, (_, i) => String(i)).join("\n") + "\n");
  const peak = heapPeak(() => verifyStore(store.root, store.registry, authority, records, publicKey), "decision records");
  assert.ok(peak < 8 << 20, `${peak >> 20} MiB held after 200,000 candidates no action names`);
});

test("a receipt that changes while it is verified is no verdict", () => {
  const store = newStore();
  const head = signed(acquisitionV3());
  put(store, "s1", "0.json", JSON.stringify(head));
  const action = signed(actionV3(1, head["signature"] as string, [{ sessionId: "s1", callIndex: 0, signature: head["signature"] }], resultDigest));
  put(store, "s1", "1.json", JSON.stringify(action));
  fs.writeFileSync(store.registry, sealLine("s1", 2) + "\n");
  let judged = 0;
  testHooks.sample = (at) => {
    if (at === "receipt" && ++judged === 2) {
      // Both read and judged: the action's citations are read again next.
      put(store, "s1", "1.json", JSON.stringify(action) + " ");
    }
  };
  try {
    assert.throws(() => verifyStore(store.root, store.registry, authority, undefined, publicKey), /changed while it was verified/);
  } finally {
    delete testHooks.sample;
  }
});

test("an index of more than 64 digits is no verdict", () => {
  const store = newStore();
  const text = JSON.stringify(signed(receiptV2()));
  put(store, "s1", "0.json", text.replace('"callIndex":0', '"callIndex":' + "9".repeat(64)));
  fs.writeFileSync(store.registry, "");
  assert.deepEqual(statuses(store.root, store.registry), ["signature-mismatch", "unregistered-session"]);
  put(store, "s1", "0.json", text.replace('"callIndex":0', '"callIndex":' + "9".repeat(65)));
  assert.ok(refused(store.root, store.registry));
});

test("a document of more values than are read: a receipt is no verdict, a seal line or record read only if it could not be one", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const many = "0,".repeat(maxValues) + "0";
  // Flat, within the byte bound, and millions of values: the case that
  // would take gigabytes parsed whole.
  put(store, "s1", "1.json", "[" + "1,".repeat(31 * 2 ** 20 - 1) + "1]");
  assert.ok(refused(store.root, store.registry), "a receipt");
  fs.rmSync(path.join(store.root, "receipts", "s1", "1.json"));
  const registry = path.join(path.dirname(store.registry), "many");
  fs.writeFileSync(registry, `[${many}]\n` + sealLine("s1", 1) + "\n");
  assert.deepEqual(statuses(store.root, registry), ["ok"], "a registry line that opens no object");
  fs.writeFileSync(registry, `{"x":[${many}]}\n` + sealLine("s1", 1) + "\n");
  assert.ok(refused(store.root, registry), "a registry line that opens an object");
  const records = tempDir();
  fs.writeFileSync(path.join(records, "a.json"), `[${many}]`);
  assert.deepEqual(statuses(store.root, store.registry, records), ["ok"], "a record that opens no object");
  fs.writeFileSync(path.join(records, "b.jsonl"), `{"cites":[],"x":[${many}]}\n`);
  assert.ok(refused(store.root, store.registry, records), "a record that opens an object");
});

// Names are the bytes they are. Two decision records whose names decode
// alike -- 0xff and U+FFFD's own bytes -- are two candidates; a session or
// a receipt named in bytes that are not UTF-8 has no string to be found
// under, and is no verdict. (Linux takes such names; not every platform
// does.)
test("names that are not UTF-8 are read as their bytes, and none is taken for another", { skip: process.platform !== "linux" }, () => {
  const named = (dir: string, name: number[]) => Buffer.concat([Buffer.from(dir + path.sep), Buffer.from(name)]);
  const json = [0x2e, 0x6a, 0x73, 0x6f, 0x6e];
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const records = tempDir();
  fs.writeFileSync(named(records, [0xff, ...json]), '{"cites":null}');
  fs.writeFileSync(named(records, [0xef, 0xbf, 0xbd, ...json]), "{}");
  const verdict = verifyStore(store.root, store.registry, authority, records, publicKey);
  const record = "sha256:" + crypto.createHash("sha256").update('{"cites":null}').digest("hex");
  assert.ok(
    verdict.findings.some((f) => new Map(f).get("recordDigest") === record && new Map(f).get("status") === "record-citation-malformed"),
    JSON.stringify(verdict.findings, (_, v) => (typeof v === "bigint" ? String(v) : v)),
  );

  // Beside a session whose name decodes alike, which a reader decoding with
  // replacement would read for it.
  const other = named(path.join(store.root, "receipts"), [0x73, 0xff]);
  const alike = named(path.join(store.root, "receipts"), [0x73, 0xef, 0xbf, 0xbd]);
  fs.mkdirSync(other);
  fs.mkdirSync(alike);
  assert.ok(refused(store.root, store.registry), "a session so named");
  fs.rmdirSync(other);
  fs.rmdirSync(alike);
  const receipt = named(path.join(store.root, "receipts", "s1"), [0xff, ...json]);
  fs.writeFileSync(receipt, "{}");
  assert.ok(refused(store.root, store.registry), "a receipt so named");
  fs.rmSync(receipt);
  // A name not ending .json is not a receipt, whatever its bytes.
  fs.writeFileSync(named(path.join(store.root, "receipts", "s1"), [0xff]), "{}");
  assert.deepEqual(statuses(store.root, store.registry), ["ok"]);
});
