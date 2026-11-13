// The scope member of a version 3 receipt (§1.2a, ADR-0026): its form, held
// case by case, and the display policy table it reads, held to the
// reference's and to what Node's own Unicode tables can say of it. The corpus
// holds the member in receipts (v3-scope-*).

import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { displayRefused } from "../src/display-policy-table.ts";
import { isScopeIdentifier } from "../src/structure.ts";

test("a scope identifier of its form, and strings out of it", () => {
  for (const s of [
    "a",
    "scope-a",
    "équipe 北",
    " leading and trailing ",
    "\u{1F600}".repeat(4) + "é".repeat(56), // 128 bytes
    "a".repeat(128),
    "\u2028", // a line separator is not a policy 1 class
  ]) {
    assert.equal(isScopeIdentifier(s), true, JSON.stringify(s));
  }
  for (const s of [
    "",
    "a".repeat(129),
    "a".repeat(127) + "é", // 129 bytes, 128 code points
    "\u{1F600}".repeat(32) + "a", // 129 bytes, 33 code points
    "scope\ta",
    "scope\na",
    "scope\ra",
    "scope\u0000a",
    "scope\u007fa",
    "scope\u0085a",
    "scope\u00ada",
    "scope\u200ba",
    "scope\u200da",
    "scope\u202ea",
    "scope\u2066a",
    "scope\ufeffa",
    "scope\ue000a",
    "scope\u{F0000}a",
    "scope\u2ffca", // unassigned in 15.0.0, assigned in 15.1
    "scope\u0378a",
    "scope\ufdd0a",
    "scope\uffffa",
    "scope\u{E0001}a",
    "scope\ud800a", // a surrogate alone
    "scope\udc00",
  ]) {
    assert.equal(isScopeIdentifier(s), false, JSON.stringify(s));
  }
});

test("the table is the reference's, range for range", () => {
  const source = readFileSync(new URL("../../go/policy_table.go", import.meta.url), "utf8");
  const ranges = [...source.matchAll(/\{0x([0-9A-F]+), 0x([0-9A-F]+)\}/g)].map(
    (m) => [Number.parseInt(m[1]!, 16), Number.parseInt(m[2]!, 16)] as const,
  );
  assert.equal(ranges.length, 717);
  assert.deepEqual(displayRefused, ranges);
  for (let i = 1; i < displayRefused.length; i++) {
    const [, previous] = displayRefused[i - 1]!;
    const [first, last] = displayRefused[i]!;
    assert.ok(first <= last && first > previous + 1, `range ${i} is not sorted, disjoint and apart`);
  }
});

test("every code point Node puts in a class policy 1 names is refused", () => {
  // Node's tables are of a later Unicode version than 15.0.0. A code point
  // once assigned stays assigned, and these properties do not move off a
  // code point, so each class as Node reads it lies inside the table; the
  // table holding more -- what a later version assigned -- is as it must be.
  const classes = [
    /\p{Cc}/u,
    /\p{Bidi_Control}/u,
    /\p{Default_Ignorable_Code_Point}/u,
    /\p{Co}/u,
    /\p{Cn}/u,
    /\p{Noncharacter_Code_Point}/u,
  ];
  const refused = new Uint8Array(0x110000);
  for (const [first, last] of displayRefused) {
    refused.fill(1, first, last + 1);
  }
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) {
      continue;
    }
    if (cp === 0x09 || cp === 0x0a) {
      assert.equal(refused[cp], 0);
      continue;
    }
    const ch = String.fromCodePoint(cp);
    if (classes.some((c) => c.test(ch))) {
      assert.equal(refused[cp], 1, `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
    }
  }
});
