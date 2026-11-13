// Payload retention (SPEC.md §1.3a; ADR-0028): what the artifact step reads
// beside the store's own bytes -- the removal file and a directory of bytes a
// reader supplied -- where the corpus cannot hold it: an entry that is not a
// regular file, a link at the artifact's path, and main.ts's --artifacts.
// The corpus holds the verdicts themselves (v3-artifact-*).

import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { test } from "node:test";

import { NoVerdict, readChunk, removalLineBound } from "../src/inputs.ts";
import { limits, verifyStore } from "../src/verify.ts";
import { acquisitionV3, authority, keyId, newStore, publicKey, put, resultDigest, sealLine, sign, signed, tempDir, verdictText } from "./support.ts";
import type { Receipt, Store } from "./support.ts";

const main = path.join(import.meta.dirname, "..", "src", "main.ts");
const hex = resultDigest.slice("sha256:".length);

// one is a store of one sealed session holding the receipt given, signed,
// with its artifact in the store unless the receipt kept none.
function one(receipt: Receipt, keep = true): { store: Store; r: Receipt } {
  const store = newStore();
  if (!keep) {
    fs.unlinkSync(path.join(store.root, "artifacts", hex));
  }
  const r = signed(receipt);
  put(store, "s1", "0.json", JSON.stringify(r));
  fs.writeFileSync(store.registry, sealLine("s1", 1) + "\n");
  return { store, r };
}

const notRetained = (): Receipt => ({ ...acquisitionV3(), artifact: "not-retained" });

function verdict(store: Store, artifacts?: string): { ok: boolean; findings: { status: string }[]; observations?: { observation: string }[] } {
  return JSON.parse(verdictText(verifyStore(store.root, store.registry, authority, undefined, publicKey, artifacts === undefined ? {} : { artifacts })));
}

function supplied(entries: Record<string, string | null>): string {
  const dir = path.join(tempDir(), "supplied");
  fs.mkdirSync(dir);
  for (const [name, text] of Object.entries(entries)) {
    if (text === null) {
      fs.mkdirSync(path.join(dir, name));
    } else {
      fs.writeFileSync(path.join(dir, name), text);
    }
  }
  return dir;
}

// recordFor is the removal record for r, signed, as a line of the file
// without its line feed; removedAt as given.
function recordFor(r: Receipt, removedAt = "2026-09-16T00:00:00Z"): string {
  const record = {
    callIndex: 0,
    keyId,
    kind: "artifact-removal",
    receiptSignature: r["signature"],
    removedAt,
    removedBy: "retention-job",
    resultDigest,
    sessionId: "s1",
  };
  return JSON.stringify({ ...record, signature: sign("judgment-pack-gateway/artifact-removal/1:", record) });
}

test("anything at the removal file's path that is not a regular file is not read, a link to the records included; one that cannot be read is no verdict", () => {
  for (const [name, make] of [
    ["a directory", (file: string) => fs.mkdirSync(file)],
    ["a link to the records", (file: string, records: string) => fs.symlinkSync(records, file)],
    ["a link that leads nowhere", (file: string, records: string) => fs.symlinkSync(records + ".nowhere", file)],
  ] as const) {
    const { store, r } = one(acquisitionV3(), false);
    const file = path.join(store.root, "artifact-removals.jsonl");
    const records = path.join(tempDir(), "records.jsonl");
    fs.writeFileSync(records, recordFor(r) + "\n");
    fs.copyFileSync(records, file);
    assert.equal(verdict(store).findings[0]!.status, "ok", name);
    fs.unlinkSync(file);
    assert.equal(verdict(store).findings[0]!.status, "artifact-missing", name);
    make(file, records);
    assert.equal(verdict(store).findings[0]!.status, "artifact-missing", name);
  }
  if (process.getuid?.() !== 0) {
    const { store, r } = one(acquisitionV3(), false);
    const file = path.join(store.root, "artifact-removals.jsonl");
    fs.writeFileSync(file, recordFor(r) + "\n");
    fs.chmodSync(file, 0);
    assert.throws(() => verifyStore(store.root, store.registry, authority, undefined, publicKey), NoVerdict);
  }
});

test("a socket at the removal file's path is not read, and nothing waits on it", async (t) => {
  const { store, r } = one(acquisitionV3(), false);
  const file = path.join(store.root, "artifact-removals.jsonl");
  if (Buffer.byteLength(file) > 100) {
    t.skip("a socket's path is held to about a hundred bytes");
    return;
  }
  const records = path.join(tempDir(), "records.jsonl");
  fs.writeFileSync(records, recordFor(r) + "\n");
  const server = net.createServer();
  await new Promise<void>((done) => server.listen(file, done));
  try {
    assert.equal(fs.lstatSync(file).isSocket(), true);
    assert.equal(verdict(store).findings[0]!.status, "artifact-missing");
  } finally {
    await new Promise<void>((done) => server.close(() => done()));
  }
});

test("the removal file is read a line at a time: a line over the bound loads nothing and swallows nothing, and a record repeated keeps one", () => {
  const { store, r } = one(acquisitionV3(), false);
  const file = path.join(store.root, "artifact-removals.jsonl");
  const record = recordFor(r);
  const padded = (n: number) => "{" + " ".repeat(n - record.length) + record.slice(1);
  for (const [name, text, status] of [
    ["at the bound", padded(removalLineBound) + "\n", "ok"],
    ["one byte over", padded(removalLineBound + 1) + "\n", "artifact-missing"],
    ["over, then the record", "x".repeat(3 * removalLineBound + 7) + "\n" + record + "\n", "ok"],
    ["over across a read", "x".repeat(readChunk + 5) + "\n" + record + "\n", "ok"],
    ["blank lines and the record twice", "\n\n" + record + "\n\n" + record + "\n" + padded(record.length + 3) + "\n", "ok"],
    ["over and torn", padded(removalLineBound + 1), "artifact-missing"],
  ] as const) {
    fs.writeFileSync(file, text);
    assert.equal(verdict(store).findings[0]!.status, status, name);
  }
});

test("a record repeated is kept, and charged, once: a file of copies fits a budget one record fits", () => {
  const { store, r } = one(acquisitionV3(), false);
  const record = recordFor(r);
  const saved = limits.retainedBytes;
  limits.retainedBytes = 64 << 10;
  try {
    fs.writeFileSync(path.join(store.root, "artifact-removals.jsonl"), (record + "\n").repeat(1000));
    assert.equal(verdict(store).findings[0]!.status, "ok");
  } finally {
    limits.retainedBytes = saved;
  }
});

test("a removal record's removedAt is an instant: of its form and of the calendar", () => {
  const { store, r } = one(acquisitionV3(), false);
  const file = path.join(store.root, "artifact-removals.jsonl");
  for (const at of ["2028-02-29T23:59:59Z", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59Z"]) {
    fs.writeFileSync(file, recordFor(r, at) + "\n");
    assert.equal(verdict(store).findings[0]!.status, "ok", at);
  }
  for (const at of ["2026-13-45T99:99:99Z", "2026-13-01T00:00:00Z", "2028-02-30T00:00:00Z", "2026-02-29T00:00:00Z", "2026-11-00T00:00:00Z", "2026-11-13T24:00:00Z", "2026-11-13T00:60:00Z", "2026-11-13T23:59:60Z", "2026-11-13 00:00:00Z"]) {
    fs.writeFileSync(file, recordFor(r, at) + "\n");
    assert.equal(verdict(store).findings[0]!.status, "artifact-missing", at);
  }
});

test("a removal record names the receipt it was made for, and a line after the last line feed is none", () => {
  const { store, r } = one(acquisitionV3(), false);
  const text = recordFor(r);
  fs.writeFileSync(path.join(store.root, "artifact-removals.jsonl"), text);
  assert.equal(verdict(store).findings[0]!.status, "artifact-missing", "torn");
  fs.writeFileSync(path.join(store.root, "artifact-removals.jsonl"), text + "\n");
  const v = verdict(store);
  assert.equal(v.findings[0]!.status, "ok");
  assert.deepEqual(v.observations?.map((o) => o.observation), ["artifact-removed"]);
});

test("something at an artifact's path that yields no bytes is artifact-missing, whatever the receipt carries", () => {
  for (const make of [
    (p: string) => fs.mkdirSync(p),
    (p: string) => fs.symlinkSync(path.join(path.dirname(p), "nowhere"), p),
  ]) {
    const { store } = one(notRetained(), false);
    make(path.join(store.root, "artifacts", hex));
    assert.equal(verdict(store).findings[0]!.status, "artifact-missing");
  }
});

test("a supplied entry is read only for a receipt that passed with no bytes in the store, and one not a regular file is then no verdict", () => {
  const unreadable = supplied({ [hex]: null });
  // never kept, nothing in the store: the entry is read, and is a directory
  const never = one(notRetained(), false).store;
  assert.throws(() => verifyStore(never.root, never.registry, authority, undefined, publicKey, { artifacts: unreadable }), NoVerdict);
  // kept, its bytes there: re-digested in the store, the entry never read
  assert.equal(verdict(one(acquisitionV3()).store, unreadable).findings[0]!.status, "ok");
  // kept, gone, no record: artifact-missing, the entry never read
  assert.equal(verdict(one(acquisitionV3(), false).store, unreadable).findings[0]!.status, "artifact-missing");
  // never kept, its bytes there too: those are re-digested, and the entry never read
  assert.equal(verdict(one(notRetained()).store, unreadable).findings[0]!.status, "ok");
});

test("a supplied directory that is not a directory is no verdict", () => {
  const { store } = one(notRetained(), false);
  const file = path.join(tempDir(), "file");
  fs.writeFileSync(file, "");
  for (const artifacts of [file, path.join(tempDir(), "absent")]) {
    assert.throws(() => verifyStore(store.root, store.registry, authority, undefined, publicKey, { artifacts }), NoVerdict, artifacts);
  }
});

test("main.ts verify takes --artifacts <dir> after --ordinary-seals-only and before the store root, or not at all", () => {
  const { store } = one(notRetained(), false);
  const bytes = fs.readFileSync(path.join(newStore().root, "artifacts", hex));
  const dir = supplied({ [hex]: bytes.toString("utf8") });
  const run = (...args: string[]) => spawnSync(process.execPath, [main, "verify", ...args], { input: publicKey });
  const ok = (r: ReturnType<typeof run>) => {
    assert.equal(r.status, 0, r.stderr.toString());
    return JSON.parse(r.stdout.toString()) as { ok: boolean; observations?: unknown[] };
  };
  // the bytes supplied are re-digested: ok, no observation
  const checked = ok(run("--artifacts", dir, store.root, store.registry, authority));
  assert.equal(checked.ok, true);
  assert.equal(checked.observations, undefined);
  assert.equal(ok(run("--ordinary-seals-only", "--artifacts", dir, store.root, store.registry, authority)).ok, true);
  // none supplied: ok, with the observation
  assert.equal(ok(run(store.root, store.registry, authority)).observations?.length, 1);
  const misplaced = "verify: --artifacts <dir> goes before the store root, after --ordinary-seals-only; a directory so named is given as ./--artifacts\n";
  for (const [name, args, message] of [
    ["after the store root", [store.root, "--artifacts", dir, store.registry, authority], misplaced],
    ["as the fourth argument", [store.root, store.registry, authority, "--artifacts"], misplaced],
    ["given twice", ["--artifacts", dir, "--artifacts", dir, store.root, store.registry, authority], misplaced],
    ["with no directory", ["--artifacts"], misplaced],
    ["with an empty directory name", ["--artifacts", "", store.root, store.registry, authority], misplaced],
    ["before --ordinary-seals-only", ["--artifacts", dir, "--ordinary-seals-only", store.root, store.registry, authority], "verify: --ordinary-seals-only goes first"],
  ] as const) {
    const r = run(...args);
    assert.equal(r.status, 64, name);
    assert.equal(r.stdout.length, 0, name);
    assert.ok(r.stderr.toString().startsWith(message), `${name}: ${r.stderr.toString()}`);
  }
  // a directory so named, given as ./--artifacts, is a directory
  const named = path.join(tempDir(), "--artifacts");
  fs.mkdirSync(named);
  const relative = spawnSync(process.execPath, [main, "verify", store.root, store.registry, authority, "./--artifacts"], { input: publicKey, cwd: path.dirname(named) });
  assert.equal(relative.status, 0, relative.stderr.toString());
  // a supplied directory that is not there is no verdict: exit 2
  const absent = run("--artifacts", path.join(tempDir(), "absent"), store.root, store.registry, authority);
  assert.equal(absent.status, 2);
  assert.equal(absent.stdout.length, 0);
});
