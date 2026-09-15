// Absent and unreadable inputs (SPEC.md §4.1): what is confirmed not there
// is absent and fails closed; what is there and cannot be read is no
// verdict; and a path is taken by its spelling.

import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { NoVerdict } from "../src/inputs.ts";
import { verifyStore } from "../src/verify.ts";
import { acquisitionV3, authority, newStore, publicKey, put, sealLine, signed } from "./support.ts";

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
