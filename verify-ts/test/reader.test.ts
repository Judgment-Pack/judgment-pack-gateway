// The reader and the canonical form at their edges: depth, encoding,
// number spellings and names.

import * as assert from "node:assert/strict";
import { test } from "node:test";

import { canonical } from "../src/canon.ts";
import { hasDuplicate, maxDepth, parse } from "../src/json.ts";

const text = (s: string) => parse(Buffer.from(s, "utf8"));
const canon = (s: string) => {
  const v = text(s);
  const bytes = v === null ? null : canonical(v);
  return bytes === null ? null : Buffer.from(bytes).toString("utf8");
};

test("nesting to the reference's bound is read, and past it is not", () => {
  const nested = (n: number) => "[".repeat(n) + "]".repeat(n);
  assert.equal(canon(nested(maxDepth)), nested(maxDepth));
  assert.equal(text(nested(maxDepth + 1)), null);
  const objects = (n: number) => '{"a":'.repeat(n - 1) + "{}" + "}".repeat(n - 1);
  assert.equal(canon(objects(maxDepth)), objects(maxDepth));
  assert.equal(text(objects(maxDepth + 1)), null);
});

test("only UTF-8 holding one JSON value, whitespace around it, is read", () => {
  assert.equal(canon(' \t\r\n{"a" : [ 1 , 2 ] }\n'), '{"a":[1,2]}');
  assert.equal(parse(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), null, "a byte order mark");
  assert.equal(parse(Buffer.from([0x22, 0xff, 0x22])), null, "not UTF-8");
  assert.equal(parse(Buffer.from([0x22, 0xed, 0xa0, 0x80, 0x22])), null, "a surrogate encoded in UTF-8");
  assert.equal(parse(Buffer.from([0x22, 0x01, 0x22])), null, "a control character unescaped");
  for (const bad of ["", "{} {}", "[1,]", '{"a":1,}', "01", "1.", "1e", "-", "+1", "'a'", "tru", "nul", '{"a" 1}', "[1 2]", '"\\x"', '"\\u00"', '"\\u00zz"']) {
    assert.equal(text(bad), null, JSON.stringify(bad));
  }
});

test("numbers keep their spelling", () => {
  assert.equal(canon("-0"), "0");
  assert.equal(canon("[0,-1,10]"), "[0,-1,10]");
  for (const float of ["0.0", "1E2", "-0.5", "1e-2"]) {
    assert.notEqual(text(float), null, float);
    assert.equal(canon(float), null, float);
  }
});

test("names are strings the canonical form holds to its own rules", () => {
  assert.equal(canon('{"\\ud800":1}'), null, "a lone surrogate in a name");
  assert.equal(canon('{"\\u00e9":1,"e":2,"\\ud83d\\ude00":3,"\\uffff":4}'), '{"e":2,"\u00e9":1,"\uffff":4,"\u{1f600}":3}');
  const twice = text('{"a":[{"b":1,"b":2}]}');
  assert.ok(twice !== null && hasDuplicate(twice));
  assert.equal(canonical(twice), null);
  assert.equal(canon('"\\/"'), '"/"');
  // A name before another it begins.
  assert.equal(canon('{"requester":1,"request":2,"":3}'), '{"":3,"request":2,"requester":1}');
});
