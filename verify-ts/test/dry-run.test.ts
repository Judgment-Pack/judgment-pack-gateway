// corpus/dry-run: verifyDryRun, and verifyStore's reading of the same bytes
// held as a store's receipts/s1/0.json (SPEC.md §1.2c).
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";

import { verifyDryRun } from "../src/dry-run.ts";
import { verifyStore, writeVerdict } from "../src/verify.ts";

const corpus = path.join(import.meta.dirname, "..", "..", "corpus");
const publicKey = Buffer.from(fs.readFileSync(path.join(corpus, "TEST-PUBLIC-KEY"), "utf8").trim(), "hex");
const p256Pin = { alg: "ES256", key: fs.readFileSync(path.join(corpus, "TEST-P256-PUBLIC-KEY"), "utf8").trim() } as const;

test("every dry-run vector", () => {
  const names = fs.readdirSync(path.join(corpus, "dry-run")).filter((n) => n.endsWith(".json")).sort();
  assert.equal(names.length, 8);
  for (const name of names) {
    const v = JSON.parse(fs.readFileSync(path.join(corpus, "dry-run", name), "utf8"));
    const pin = v.publicKeyAlg === "ES256" ? p256Pin : publicKey;
    const report = verifyDryRun(Buffer.from(v.receipt, "utf8"), pin);
    assert.equal(report.dryRun, true, v.name);
    assert.equal(report.ok, v.expected.ok, v.name);
    assert.deepEqual(report.findings.map((f) => f.status), v.expected.findings.map((f: { status: string }) => f.status), v.name);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "dry-run-"));
    try {
      fs.mkdirSync(path.join(root, "store", "receipts", "s1"), { recursive: true });
      fs.writeFileSync(path.join(root, "store", "receipts", "s1", "0.json"), v.receipt);
      fs.writeFileSync(path.join(root, "registry.jsonl"), "");
      let out = "";
      writeVerdict(verifyStore(path.join(root, "store"), path.join(root, "registry.jsonl"), "gateway:corpus", undefined, pin), (t) => { out += t; });
      const found = JSON.parse(out).findings.find((f: { sessionId?: string; file?: string; callIndex?: number }) => f.sessionId === "s1" && (f.file === "0.json" || f.callIndex !== undefined));
      assert.equal(found?.status, v.asReceipt, v.name);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});
