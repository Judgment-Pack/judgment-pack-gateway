// Absent and unreadable inputs (SPEC.md §4.1): what is confirmed not there
// is absent and fails closed; what is there and cannot be read is no
// verdict; and a path is taken by its spelling.

import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { test } from "node:test";

import * as v8 from "node:v8";
import * as vm from "node:vm";

import { Bytes, NoVerdict, documentBound, entryCost, readChunk } from "../src/inputs.ts";
import { maxValues } from "../src/json.ts";
import { limits, sessionCost, testHooks, verifyStore, writeVerdict } from "../src/verify.ts";
import { acquisitionV3, actionV3, authority, newStore, publicKey, put, receiptV2, resultDigest, sealLine, signed, tempDir, verdictText } from "./support.ts";

// A store of one session, s1, holding one valid receipt.
function oneSession() {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  return store;
}

function statuses(root: string, registry: string, decisionRecords?: string): string[] {
  return [...verifyStore(root, registry, authority, decisionRecords, publicKey).findings].map((f) => String(new Map(f).get("status"))).sort();
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

// A gauge of memory: the heap, and what is held outside it -- a buffer's
// bytes, and a long string, which the platform may keep outside the heap
// -- from when the gauge is made. Each look follows a collection that
// finishes before it returns, a buffer's bytes released with it: otherwise
// a buffer no longer held can still be counted after it.
function memoryGauge(): { look: () => void; peak: () => number } {
  v8.setFlagsFromString("--expose-gc");
  const collect = vm.runInNewContext("gc") as (options: object) => void;
  const used = () => {
    collect({ type: "major", execution: "sync", flavor: "last-resort" });
    const m = process.memoryUsage();
    return m.heapUsed + m.external;
  };
  const base = used();
  let peak = 0;
  return {
    look: () => {
      peak = Math.max(peak, used() - base);
    },
    peak: () => peak,
  };
}

// memoryPeak is the most memory held, looked at every every'th time
// verification passes where: what verification keeps of each receipt and
// each decision record is small, whatever they hold.
function memoryPeak(run: () => void, where: string, every = 1): number {
  const gauge = memoryGauge();
  let passed = 0;
  testHooks.sample = (at) => {
    if (at === where && ++passed % every === 0) {
      gauge.look();
    }
  };
  try {
    run();
  } finally {
    delete testHooks.sample;
  }
  return gauge.peak();
}

// shortReadPeak is the most memory held while verification runs with each
// read returning at most most bytes, looked at every every'th read. The
// platform's own module is what verification reads through, rebound for
// the run.
const nodeFs = createRequire(import.meta.url)("node:fs") as typeof fs;
function shortReadPeak(most: number, every: number, run: () => void): number {
  const gauge = memoryGauge();
  const readSync = nodeFs.readSync;
  let reads = 0;
  const short = (fd: number, buffer: NodeJS.ArrayBufferView, offset: number, length: number, position: fs.ReadPosition | null) => {
    if (++reads % every === 0) {
      gauge.look();
    }
    return readSync(fd, buffer, offset, Math.min(length, most), position);
  };
  nodeFs.readSync = short as typeof nodeFs.readSync;
  syncBuiltinESMExports();
  try {
    run();
  } finally {
    nodeFs.readSync = readSync;
    syncBuiltinESMExports();
  }
  assert.ok(reads > every, "the reads were made through the rebound module");
  return gauge.peak();
}

// Bytes grow by doubling: read a byte at a time, a document is copied a
// few times over, not once for each byte.
test("bytes grow by doubling", () => {
  const alloc = Buffer.alloc;
  let allocations = 0;
  Buffer.alloc = ((...args: Parameters<typeof Buffer.alloc>) => {
    allocations++;
    return alloc(...args);
  }) as typeof Buffer.alloc;
  const bytes = new Bytes();
  try {
    for (let i = 0; i < 100000; i++) {
      bytes.add(Uint8Array.of(0x61));
    }
  } finally {
    Buffer.alloc = alloc;
  }
  assert.equal(Buffer.from(bytes.take()).toString(), "a".repeat(100000));
  assert.ok(allocations < 40, `${allocations} buffers made for 100,000 bytes`);
});

// A read may return fewer bytes than were asked for, however many remain:
// a file under /proc returns a page at a time. What reading a document
// holds is at most twice the document, however few bytes each read
// returns.
test("short reads hold no more than twice the document", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify({ ...acquisitionV3(), later: "x".repeat(128 << 10) }));
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const receipt = shortReadPeak(512, 16, () => verifyStore(store.root, store.registry, authority, undefined, publicKey));
  assert.ok(receipt < 4 << 20, `${receipt} bytes held reading a receipt of 128 KiB 512 bytes at a time`);

  const small = oneSession();
  fs.writeFileSync(small.registry, sealLine("s1", 1) + "\n");
  const records = tempDir();
  fs.writeFileSync(path.join(records, "a.json"), JSON.stringify({ n: "y".repeat(64 << 10) }));
  fs.writeFileSync(path.join(records, "b.jsonl"), JSON.stringify({ n: "z".repeat(64 << 10) }) + "\n");
  const record = shortReadPeak(1, 4096, () => verifyStore(small.root, small.registry, authority, records, publicKey));
  assert.ok(record < 4 << 20, `${record} bytes held reading decision records of 64 KiB a byte at a time`);
});

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
  const peak = memoryPeak(() => verifyStore(store.root, store.registry, authority, undefined, publicKey), "receipt");
  assert.ok(peak < 4 << 20, `${peak >> 20} MiB held between receipts of 2 MiB`);
});

test("what is kept of a session, empty or not, is within its charge", () => {
  const store = newStore();
  fs.writeFileSync(store.registry, "");
  const n = 50000;
  for (let i = 0; i < n; i++) {
    fs.mkdirSync(path.join(store.root, "receipts", `e${i}`), { recursive: true });
  }
  // Verification run once on a small store first, so what the heap holds
  // of its code is there before the heap is measured.
  const small = oneSession();
  fs.writeFileSync(small.registry, "");
  verifyStore(small.root, small.registry, authority, undefined, publicKey);
  const peak = memoryPeak(() => verifyStore(store.root, store.registry, authority, undefined, publicKey), "decision records");
  // Each name charged at two bytes a character, as the budget does.
  const charged = n * sessionCost + 2 * Array.from({ length: n }, (_, i) => `e${i}`.length).reduce((a, b) => a + b);
  assert.ok(peak < charged, `${peak} bytes kept for ${n} empty sessions, charged ${charged}`);
});

// A small buffer is cut from a pool shared with others, and one kept keeps
// its pool. Were each directory waiting to be walked kept as such a buffer,
// then with something taking from the pool between one directory and the
// next, each would keep a pool of its own: many times what it is charged.
// Here each file read between them takes 4,000 bytes from the pool, by the
// test's own hand, so the test does not rest on what reading happens to
// take.
test("a directory waiting to be walked keeps no more than it is charged", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const records = tempDir();
  const n = 2000;
  let charged = 0;
  for (let i = 0; i < n; i++) {
    fs.mkdirSync(path.join(records, `d${i}`));
    fs.writeFileSync(path.join(records, `f${i}.json`), "{}");
    charged += entryCost + 2 * Buffer.byteLength(path.join(records, `d${i}`));
  }
  const gauge = memoryGauge();
  let candidates = 0;
  testHooks.sample = (at) => {
    if (at === "candidate") {
      Buffer.allocUnsafe(4000).fill(0);
      if (++candidates % 50 === 0) {
        gauge.look();
      }
    }
  };
  try {
    verifyStore(store.root, store.registry, authority, records, publicKey);
  } finally {
    delete testHooks.sample;
  }
  // Beside what one document's reading holds: a chunk, and the document.
  const reading = 2 * readChunk;
  assert.ok(gauge.peak() < charged + reading, `${gauge.peak()} bytes held with ${n} directories waiting, charged ${charged}`);
});

test("what is kept of the decision records does not grow with their number", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const records = tempDir();
  fs.writeFileSync(path.join(records, "log.jsonl"), Array.from({ length: 200000 }, (_, i) => String(i)).join("\n") + "\n");
  const peak = memoryPeak(() => verifyStore(store.root, store.registry, authority, records, publicKey), "decision records");
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
  // Version 3 likewise; and a long index below zero is malformed, as any
  // index below zero is.
  const v3 = JSON.stringify(signed(acquisitionV3()));
  put(store, "s1", "0.json", v3.replace('"callIndex":0', '"callIndex":' + "9".repeat(65)));
  assert.ok(refused(store.root, store.registry), "version 3");
  put(store, "s1", "0.json", v3.replace('"callIndex":0', '"callIndex":-' + "9".repeat(65)));
  assert.deepEqual(statuses(store.root, store.registry), ["malformed", "unregistered-session"]);
});

// An integer's value is read to 64 digits and no further: nothing needs a
// longer one's, and converting one costs time out of proportion to its
// bytes. A receipt, a decision record and a line each holding an integer
// of a million digits are verified without it being converted.
test("a long integer is never converted", () => {
  const long = "9".repeat(1 << 20);
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  put(store, "s1", "1.json", JSON.stringify(signed(acquisitionV3(1))).replace("{", `{"later":${long},`));
  const records = tempDir();
  fs.writeFileSync(path.join(records, "a.json"), `{"cites":[],"fact":${long}}`);
  fs.writeFileSync(path.join(records, "b.jsonl"), `{"cites":[],"fact":-${long}}\n`);
  const real = globalThis.BigInt;
  let longest = 0;
  globalThis.BigInt = Object.assign((v: string | number | bigint | boolean) => {
    longest = Math.max(longest, String(v).length);
    return real(v);
  }, real) as BigIntConstructor;
  let found: string[];
  try {
    found = statuses(store.root, store.registry, records);
  } finally {
    globalThis.BigInt = real;
  }
  assert.ok(longest <= 65, `an integer of ${longest} characters converted`);
  assert.deepEqual(found, ["count-exceeds-seal", "ok", "signature-mismatch"]);
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
  const findings = [...verifyStore(store.root, store.registry, authority, records, publicKey).findings];
  const record = "sha256:" + crypto.createHash("sha256").update('{"cites":null}').digest("hex");
  assert.ok(
    findings.some((f) => new Map(f).get("recordDigest") === record && new Map(f).get("status") === "record-citation-malformed"),
    JSON.stringify(findings, (_, v) => (typeof v === "bigint" ? String(v) : v)),
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
  // Beside a receipt whose name decodes alike, which a reader decoding
  // with replacement would read for it.
  const receipt = named(path.join(store.root, "receipts", "s1"), [0xff, ...json]);
  const alikeReceipt = named(path.join(store.root, "receipts", "s1"), [0xef, 0xbf, 0xbd, ...json]);
  fs.writeFileSync(receipt, "{}");
  fs.writeFileSync(alikeReceipt, "{}");
  assert.ok(refused(store.root, store.registry), "a receipt so named");
  fs.rmSync(receipt);
  fs.rmSync(alikeReceipt);
  // A name not ending .json is not a receipt, whatever its bytes.
  fs.writeFileSync(named(path.join(store.root, "receipts", "s1"), [0xff]), "{}");
  assert.deepEqual(statuses(store.root, store.registry), ["ok"]);
});

// What verification keeps is charged to a budget as it is kept, each
// test here lowering it to 16 KiB: within it a store is verified, and past
// it there is no verdict, refused as the charge that passes it is made.
const budget = 16 << 10;

function withBudget<T>(run: () => T): T {
  const saved = limits.retainedBytes;
  limits.retainedBytes = budget;
  try {
    return run();
  } finally {
    limits.retainedBytes = saved;
  }
}

// A regular expression is matched against the error as a string, its
// name before its message.
const pastBudget = (what: string) => new RegExp(`: ${what}: more than the ${budget} bytes this verifier keeps$`);

test("sessions are charged as they are met, empty ones too", () => {
  const store = newStore();
  fs.writeFileSync(store.registry, "");
  const session = (i: number) => fs.mkdirSync(path.join(store.root, "receipts", `e${i}`), { recursive: true });
  for (let i = 0; i < 10; i++) {
    session(i);
  }
  assert.equal(withBudget(() => statuses(store.root, store.registry)).length, 10);
  for (let i = 10; i < 100; i++) {
    session(i);
  }
  assert.throws(() => withBudget(() => verifyStore(store.root, store.registry, authority, undefined, publicKey)), pastBudget("the store's sessions"));
});

test("a receipt file is charged for what is kept of it when it is met, before any is read", () => {
  // Every receipt file here is a link that leads nowhere, which a read
  // finds unreadable: past the budget, none is read.
  const store = newStore();
  fs.writeFileSync(store.registry, "");
  fs.mkdirSync(path.join(store.root, "receipts", "s1"), { recursive: true });
  const link = (i: number) => fs.symlinkSync(path.join(store.root, "nowhere"), path.join(store.root, "receipts", "s1", `${i}.json`));
  for (let i = 0; i < 4; i++) {
    link(i);
  }
  assert.throws(() => withBudget(() => verifyStore(store.root, store.registry, authority, undefined, publicKey)), /cannot be read: ENOENT/);
  for (let i = 4; i < 8; i++) {
    link(i);
  }
  assert.throws(() => withBudget(() => verifyStore(store.root, store.registry, authority, undefined, publicKey)), pastBudget("the store's receipt files"));
});

test("a seal is charged as it is kept, before the registry is read further", () => {
  const store = oneSession();
  const seals = Array.from({ length: 100 }, (_, i) => sealLine(`sealed-${i}`, 1));
  fs.writeFileSync(store.registry, [sealLine("s1", 1), ...seals.slice(0, 5)].join("\n") + "\n");
  assert.deepEqual(withBudget(() => statuses(store.root, store.registry)), ["ok", ...Array(5).fill("sealed-session-missing")]);
  // After them, a line that opens an object and holds more values than are
  // read, which would be no verdict of its own.
  fs.writeFileSync(store.registry, [sealLine("s1", 1), ...seals, `{"x":[${"0,".repeat(maxValues)}0]}`].join("\n") + "\n");
  assert.throws(() => withBudget(() => verifyStore(store.root, store.registry, authority, undefined, publicKey)), pastBudget("the registry's seals"));
  // A seal's session id at two bytes a character: one of 6,000 fits, two
  // do not.
  const long = (c: string) => sealLine(c.repeat(6000), 1);
  fs.writeFileSync(store.registry, [sealLine("s1", 1), long("x")].join("\n") + "\n");
  assert.deepEqual(withBudget(() => statuses(store.root, store.registry)), ["ok", "sealed-session-missing"]);
  fs.writeFileSync(store.registry, [sealLine("s1", 1), long("x"), long("y")].join("\n") + "\n");
  assert.throws(() => withBudget(() => verifyStore(store.root, store.registry, authority, undefined, publicKey)), pastBudget("the registry's seals"));
});

test("a directory under the decision records is charged until it is walked", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  // Sixty directories each inside the last: one waits at a time.
  const deep = tempDir();
  fs.mkdirSync(path.join(deep, ...Array(60).fill("d")), { recursive: true });
  assert.deepEqual(withBudget(() => statuses(store.root, store.registry, deep)), ["ok"]);
  // A hundred side by side: all wait at once.
  const wide = tempDir();
  for (let i = 0; i < 100; i++) {
    fs.mkdirSync(path.join(wide, `w${i}`));
  }
  assert.throws(
    () => withBudget(() => verifyStore(store.root, store.registry, authority, wide, publicKey)),
    pastBudget("the decision-record directories still to walk"),
  );
});

test("the decision records' findings are charged as their buffer grows", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  const records = tempDir();
  fs.writeFileSync(path.join(records, "log.jsonl"), '{"cites":1}\n'.repeat(10));
  assert.deepEqual(withBudget(() => statuses(store.root, store.registry, records)), ["ok", ...Array(10).fill("record-citation-malformed")]);
  fs.writeFileSync(path.join(records, "log.jsonl"), '{"cites":1}\n'.repeat(2000));
  assert.throws(() => withBudget(() => verifyStore(store.root, store.registry, authority, records, publicKey)), pastBudget("the decision records' findings"));
});

test("the verdict is written a finding at a time, as often as it is read", () => {
  const store = newStore();
  fs.writeFileSync(store.registry, "");
  for (let i = 0; i < 20; i++) {
    fs.mkdirSync(path.join(store.root, "receipts", `e${i}`), { recursive: true });
  }
  const verdict = verifyStore(store.root, store.registry, authority, undefined, publicKey);
  const chunks: string[] = [];
  writeVerdict(verdict, (text) => chunks.push(text));
  assert.equal(chunks.length, 22, "the opening, each finding, and the close");
  assert.equal(JSON.parse(chunks.join("")).findings.length, 20);
  assert.equal(verdictText(verdict), chunks.join(""));
});

test("the store root is taken as spelled, never normalized", () => {
  const store = oneSession();
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  // A file beside the receipts directory: file/.. would name the store
  // were the path normalized, but the platform steps back from a file
  // that is no directory, and finds nothing.
  const file = path.join(store.root, "file");
  fs.writeFileSync(file, "");
  assert.ok(refused(file + path.sep + "..", store.registry));
});
