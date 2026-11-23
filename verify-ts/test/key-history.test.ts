// The key history's consumer check (SPEC.md §3e; ADR-0055), beyond the
// corpus family that test/corpus.test.ts runs: the version read first, the
// consumer's requireVersion, and the key at a store rotation one entry.

import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { checkKeyHistory } from "../src/key-history.ts";
import { corpus, publicKey } from "./support.ts";

const history = (name: string): Buffer => Buffer.from((JSON.parse(fs.readFileSync(path.join(corpus, "key-history", name + ".json"), "utf8")) as { history: string }).history, "utf8");
const pin = { alg: "" as const, key: publicKey };

test("version 1 is accepted, and refused by version where version 2 is required", () => {
  const one = history("kh-v1-one-key");
  const got = checkKeyHistory(one, pin);
  assert.ok(got.accepted && got.version === "1" && got.entries.length === 1);
  const required = checkKeyHistory(one, pin, { requireVersion: "2" });
  assert.ok(!required.accepted && required.class === "version");
  const unknown = checkKeyHistory(one, pin, { requireVersion: "1" });
  assert.ok(!unknown.accepted && unknown.class === "version", "requireVersion is \"2\" or absent");
});

test("the key at a store rotation is one entry, whose validTo is its last", () => {
  const got = checkKeyHistory(history("kh-v2-across-store"), null, { requireVersion: "2" });
  assert.ok(got.accepted && got.version === "2");
  assert.equal(got.entries.length, 3);
  assert.equal(got.entries[1]!.validFrom, "2026-08-01T01:00:00Z");
  assert.equal(got.entries[1]!.validTo, "2026-08-01T03:00:00Z");
  assert.equal(got.entries[2]!.validTo, "");
});

test("bytes that are not one object, or that give a member twice, are refused by form", () => {
  for (const bytes of ["", "[]", '{"keyHistoryVersion":"1","keys":[],"keys":[]}']) {
    const got = checkKeyHistory(Buffer.from(bytes, "utf8"), pin);
    assert.ok(!got.accepted && got.class === "form", bytes);
  }
});

test("a pin of another algorithm is refused by key", () => {
  const got = checkKeyHistory(history("kh-v1-one-key"), { alg: "ES256", key: publicKey });
  assert.ok(!got.accepted && got.class === "key");
});
