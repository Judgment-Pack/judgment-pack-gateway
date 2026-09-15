// Receipts, seals and records of the tests' own, signed under the test
// seed: each departs from a valid one in one respect the corpus does not
// exercise, and the verdict says the status §1.4 or §4 gives it.

import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { readChunk } from "../src/inputs.ts";
import { verifyStore } from "../src/verify.ts";
import { acquisitionV3, actionV3, authority, multiset, newStore, publicKey, put, receiptV2, resultDigest, sealLine, signed, tempDir, verdictText } from "./support.ts";
import type { Receipt, Store } from "./support.ts";

function verdict(store: Store, seals: string[], decisionRecords?: string): { ok: boolean; findings: Record<string, unknown>[] } {
  fs.writeFileSync(store.registry, seals.map((line) => line + "\n").join(""));
  return JSON.parse(verdictText(verifyStore(store.root, store.registry, authority, decisionRecords, publicKey)));
}

// alone is the findings for a store whose one session, sealed at one,
// holds one receipt file.
function alone(text: string): string[] {
  const store = newStore();
  put(store, "s1", "0.json", text);
  return multiset(verdict(store, [sealLine("s1", 1)]).findings);
}

const passes = multiset([{ sessionId: "s1", callIndex: 0, status: "ok" }]);
const malformed = multiset([{ sessionId: "s1", file: "0.json", status: "malformed" }]);
const status = (s: string) => multiset([{ sessionId: "s1", callIndex: 0, status: s }]);

// edited is the receipt changed by edit, then signed.
function edited(r: Receipt, edit: (r: any) => void): string {
  const copy = structuredClone(r);
  edit(copy);
  return JSON.stringify(signed(copy));
}

test("a version 3 receipt departing from §1.2a in one respect is malformed", () => {
  assert.deepEqual(alone(JSON.stringify(signed(acquisitionV3()))), passes);
  const cases: [string, (r: any) => void][] = [
    ["callIndex negative", (r) => (r.callIndex = -1)],
    ["a nullable member absent", (r) => delete r.acquisition.snapshot],
    ["shape outside its values", (r) => (r.acquisition.shape = "ftp")],
    ["statement a digest in uppercase", (r) => (r.acquisition.statement = "sha256:" + "A".repeat(64))],
    ["schema another prefix", (r) => (r.acquisition.schema = "sha512:" + "0".repeat(64))],
    ["pageItems not digests", (r) => (r.acquisition.pageItems = ["x"])],
    ["pageItems not an array", (r) => (r.acquisition.pageItems = resultDigest)],
    ["caller without tokenDigest", (r) => (r.caller = { issuer: "i", subject: "s" })],
    ["caller a string", (r) => (r.caller = "someone")],
    ["prevSignature a number", (r) => (r.prevSignature = 7)],
    ["adapter without its digest", (r) => delete r.acquisition.adapter.digest],
    ["observedAt absent", (r) => delete r.acquisition.observedAt],
    ["acquisition absent", (r) => delete r.acquisition],
    ["the sibling present", (r) => (r.action = {})],
    ["kind action over an acquisition", (r) => (r.kind = "action")],
    ["argumentsCommitment absent", (r) => delete r.argumentsCommitment],
    ["argumentsDigest present", (r) => (r.argumentsDigest = "hmac-sha256:" + "0".repeat(64))],
    ["keyId a number", (r) => (r.keyId = 1)],
    ["keyId not hex", (r) => (r.keyId = "not-hex")],
    ["keyId of another length", (r) => (r.keyId = r.keyId + "00")],
    ["servedAt null", (r) => (r.servedAt = null)],
    ["source absent", (r) => delete r.source],
    ["authority a number", (r) => (r.authority = 1)],
    ["resultDigest not a digest", (r) => (r.resultDigest = "sha256:0")],
    ["endpoint absent", (r) => delete r.acquisition.endpoint],
    ["peerIdentity a number", (r) => (r.peerIdentity = 1, r.acquisition.peerIdentity = 1)],
    ["upstreamToken absent", (r) => delete r.acquisition.upstreamToken],
    ["adapter's name absent", (r) => delete r.acquisition.adapter.name],
    ["adapter's version a number", (r) => (r.acquisition.adapter.version = 1)],
    ["adapter absent", (r) => delete r.acquisition.adapter],
    ["acquisition not an object", (r) => (r.acquisition = [])],
    ["caller's issuer absent", (r) => (r.caller = { subject: "s", tokenDigest: resultDigest })],
    ["caller's subject a number", (r) => (r.caller = { issuer: "i", subject: 1, tokenDigest: resultDigest })],
    ["caller absent", (r) => delete r.caller],
    ["kind absent", (r) => delete r.kind],
    ["sessionId a number", (r) => (r.sessionId = 1)],
  ];
  for (const [name, edit] of cases) {
    assert.deepEqual(alone(edited(acquisitionV3(), edit)), malformed, name);
  }
});

test("a version 3 receipt tolerates members it does not name, at any depth", () => {
  const text = edited(acquisitionV3(), (r) => {
    r.later = { anything: [1, "two"] };
    r.acquisition.alsoLater = true;
    r.acquisition.adapter.build = "x";
    r.acquisition.pageItems = [resultDigest];
    r.caller = { issuer: "i", subject: "s", tokenDigest: resultDigest, claims: {} };
  });
  assert.deepEqual(alone(text), passes);
});

test("a version 3 signature is 128 lowercase hex characters", () => {
  const r = signed(acquisitionV3());
  assert.deepEqual(alone(JSON.stringify({ ...r, signature: (r["signature"] as string).toUpperCase() })), malformed);
  assert.deepEqual(alone(JSON.stringify({ ...r, signature: (r["signature"] as string).slice(2) })), malformed);
});

test("an action receipt departing from §1.2a in one respect is malformed", () => {
  const cite = { sessionId: "s1", callIndex: 0, signature: "a".repeat(128) };
  const action = () => actionV3(0, null, [cite], resultDigest);
  const valid = multiset([
    { sessionId: "s1", callIndex: 0, status: "ok" },
    { sessionId: "s1", callIndex: 0, status: "citation-unresolved" },
    { sessionId: "s1", callIndex: 0, status: "decision-record-mismatch" },
  ]);
  assert.deepEqual(alone(JSON.stringify(signed(action()))), valid, "the action as it stands");
  const cases: [string, (r: any) => void][] = [
    ["requester absent", (r) => delete r.action.requester],
    ["a citation's callIndex negative", (r) => (r.action.cites[0].callIndex = -1)],
    ["a citation's session not a flat token", (r) => (r.action.cites[0].sessionId = "a/b")],
    ["a citation not an object", (r) => (r.action.cites = ["s1/0"])],
    ["cites absent", (r) => delete r.action.cites],
    ["tool's endpoint absent", (r) => delete r.action.tool.endpoint],
    ["decision without packDigest", (r) => delete r.action.decision.packDigest],
    ["request not a digest", (r) => (r.action.request = "request")],
    ["requester's tokenDigest absent", (r) => delete r.action.requester.tokenDigest],
    ["decision absent", (r) => delete r.action.decision],
    ["decision's recordDigest not a digest", (r) => (r.action.decision.recordDigest = "record")],
    ["tool absent", (r) => delete r.action.tool],
    ["tool's name absent", (r) => delete r.action.tool.name],
    ["tool's shape a number", (r) => (r.action.tool.shape = 1)],
    ["the executor's adapter absent", (r) => delete r.action.adapter],
    ["observedAt absent", (r) => delete r.action.observedAt],
    ["the sibling present", (r) => (r.acquisition = {})],
    ["action not an object", (r) => (r.action = "close")],
  ];
  for (const [name, edit] of cases) {
    assert.deepEqual(alone(edited(action(), edit)), malformed, name);
  }
});

test("a version 2 receipt is held to §1.4 order 1's list, and its signature's case is open", () => {
  const r = signed(receiptV2());
  assert.deepEqual(alone(JSON.stringify(r)), passes);
  assert.deepEqual(alone(JSON.stringify({ ...r, signature: (r["signature"] as string).toUpperCase() })), passes);
  assert.deepEqual(alone(JSON.stringify({ ...r, signature: (r["signature"] as string).slice(1) })), malformed, "odd-length hex");
  assert.deepEqual(alone(JSON.stringify({ ...r, signature: (r["signature"] as string).slice(4) })), status("signature-mismatch"), "another length");
  const { signature: _, ...unsigned } = r;
  assert.deepEqual(alone(JSON.stringify(unsigned)), malformed, "no signature");
  assert.deepEqual(alone(edited(receiptV2(), (x) => (x.callIndex = "0"))), malformed, "callIndex a string");
  assert.deepEqual(alone(JSON.stringify(r).replace('"callIndex":0', '"callIndex":0.0')), malformed, "callIndex a float");
  assert.deepEqual(alone(edited(receiptV2(), (x) => (x.resultDigest = x.resultDigest.toUpperCase()))), malformed, "resultDigest uppercase");
  assert.deepEqual(alone(edited(receiptV2(), (x) => delete x.receiptVersion)), status("unsupported-version"));
  // A member the canonical form refuses leaves the signing input undefined:
  // the signature cannot verify over it.
  assert.deepEqual(alone(JSON.stringify(r).replace("{", '{"later":1.5,')), status("signature-mismatch"));
  // A name given twice is malformed at any depth.
  assert.deepEqual(alone(JSON.stringify(r).replace("{", '{"x":{"y":1,"y":1},')), malformed);
});

test("a version 3 prevSignature is any string, and one naming nothing breaks the chain", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3(0, "x"))));
  assert.deepEqual(
    multiset(verdict(store, [sealLine("s1", 1)]).findings),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s1", callIndex: null, status: "chain-broken" },
    ]),
  );
});

test("the head of a chain names no previous receipt", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3(0, "b".repeat(128)))));
  assert.deepEqual(
    multiset(verdict(store, [sealLine("s1", 1)]).findings),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s1", callIndex: null, status: "chain-broken" },
    ]),
  );
});

test("seals load by line, the first of a session winning, and any other line is dropped", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  const at = (seals: string[]) => multiset(verdict(store, seals).findings);
  const unregistered = multiset([
    { sessionId: "s1", callIndex: 0, status: "ok" },
    { sessionId: "s1", status: "unregistered-session" },
  ]);
  assert.deepEqual(at([sealLine("s1", 1) + "\r"]), passes, "a line ending in a carriage return");
  assert.deepEqual(at([sealLine("s1", 1), sealLine("s1", 5)]), passes, "the first seal wins");
  assert.deepEqual(
    at([sealLine("s1", 5), sealLine("s1", 1)]),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s1", status: "tail-rollback", have: 1, sealed: 5 },
    ]),
  );
  assert.deepEqual(at(["{not json", "", sealLine("s1", 1)]), passes, "lines that are no seal are dropped");
  assert.deepEqual(at([sealLine("s1", 1).replace('"finalCount":1', '"finalCount":1.0')]), unregistered, "a float count");
  assert.deepEqual(at([sealLine("s1", 1).replace(/"keyId":"[0-9a-f]+"/, (k) => k.toUpperCase().replace("KEYID", "keyId"))]), unregistered, "another key id");
  // The signed value first: a reader taking the first of a name twice
  // would load it.
  assert.deepEqual(at([sealLine("s1", 1).replace(/("sealedAt":"[^"]*")/, '$1,"sealedAt":"x"')]), unregistered, "a name given twice");
  fs.writeFileSync(store.registry, sealLine("s1", 1));
  assert.deepEqual(
    multiset(JSON.parse(verdictText(verifyStore(store.root, store.registry, authority, undefined, publicKey))).findings),
    passes,
    "a last line with no line feed",
  );
});

// recordStore is a sealed session s1 of an acquisition and an action
// citing it, the action naming a decision record by digest.
function recordStore(record: string, cite?: object): { store: Store; seals: string[] } {
  const store = newStore();
  const head = signed(acquisitionV3());
  const citing = cite ?? { sessionId: "s1", callIndex: 0, signature: head["signature"] };
  const recordDigest = "sha256:" + crypto.createHash("sha256").update(record).digest("hex");
  put(store, "s1", "0.json", JSON.stringify(head));
  put(store, "s1", "1.json", JSON.stringify(signed(actionV3(1, head["signature"] as string, [citing], recordDigest))));
  return { store, seals: [sealLine("s1", 2)] };
}

const bothPass = multiset([
  { sessionId: "s1", callIndex: 0, status: "ok" },
  { sessionId: "s1", callIndex: 1, status: "ok" },
]);

function withRecords(files: Record<string, string>): string {
  const dir = tempDir();
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), text);
  }
  return dir;
}

test("an action's citations resolve by the enumeration's own strings", () => {
  const record = '{"run":"r"}';
  const { store, seals } = recordStore(record);
  assert.deepEqual(multiset(verdict(store, seals, withRecords({ "r.json": record })).findings), bothPass);

  const unresolved = multiset([
    { sessionId: "s1", callIndex: 0, status: "ok" },
    { sessionId: "s1", callIndex: 1, status: "ok" },
    { sessionId: "s1", callIndex: 1, status: "citation-unresolved" },
  ]);
  const sig = "c".repeat(128);
  for (const [name, cite] of [
    ["a session the store does not hold", { sessionId: "s9", callIndex: 0, signature: sig }],
    ["an index with no receipt", { sessionId: "s1", callIndex: 7, signature: sig }],
  ] as const) {
    const { store, seals } = recordStore(record, cite);
    assert.deepEqual(multiset(verdict(store, seals, withRecords({ "r.json": record })).findings), unresolved, name);
  }
  // A cited file that is not JSON has no signature to match.
  const bad = recordStore(record, { sessionId: "s2", callIndex: 0, signature: sig });
  put(bad.store, "s2", "0.json", "{not json");
  assert.deepEqual(
    multiset(verdict(bad.store, [...bad.seals, sealLine("s2", 1)], withRecords({ "r.json": record })).findings),
    multiset([...unresolved.map((f) => JSON.parse(f)), { sessionId: "s2", file: "0.json", status: "malformed" }]),
  );
  // The index is the stem as written: 00.json is not 0.
  const padded = recordStore(record, { sessionId: "s2", callIndex: 0, signature: sig });
  put(padded.store, "s2", "00.json", JSON.stringify({ ...signed(acquisitionV3(0, null, "s2")), signature: sig }));
  const findings = multiset(verdict(padded.store, [...padded.seals, sealLine("s2", 1)], withRecords({ "r.json": record })).findings);
  assert.ok(findings.includes(JSON.stringify({ callIndex: 1, sessionId: "s1", status: "citation-unresolved" })), findings.join("\n"));
});

// -0 is 0: a citation's index written -0 names the receipt 0.json, in an
// action's cites and in a record's.
test("a citation's index of -0 names the receipt 0.json", () => {
  const headSignature = signed(acquisitionV3())["signature"] as string;
  const record = `{"cites":[{"sessionId":"s1","callIndex":-0,"signature":"${headSignature}"}]}`;
  const { store, seals } = recordStore(record);
  // The action's own citation rewritten -0: its signature is over the
  // canonical form, which writes 0.
  const action = path.join(store.root, "receipts", "s1", "1.json");
  const text = fs.readFileSync(action, "utf8");
  assert.equal(text.split('"callIndex":0,"signature"').length, 2);
  fs.writeFileSync(action, text.replace('"callIndex":0,"signature"', '"callIndex":-0,"signature"'));
  assert.deepEqual(multiset(verdict(store, seals, withRecords({ "r.json": record })).findings), bothPass);
});

// A citation's index past 64 digits is an integer still: the action is of
// its shape, and fails at its signature, which the canonical form cannot
// hold -- not as malformed.
test("an action citing an index of more than 64 digits fails at its signature", () => {
  const { store, seals } = recordStore('{"run":"r"}');
  const action = path.join(store.root, "receipts", "s1", "1.json");
  const text = fs.readFileSync(action, "utf8");
  fs.writeFileSync(action, text.replace('"callIndex":0,"signature"', '"callIndex":' + "9".repeat(65) + ',"signature"'));
  assert.deepEqual(
    multiset(verdict(store, seals).findings),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s1", callIndex: 1, status: "signature-mismatch" },
    ]),
  );
});

test("decision records are the directory's files whole and each .jsonl line", () => {
  const line = '{"run":"a"}';
  // A line ends before its carriage return and line feed; blank lines are
  // no candidates; the last line needs no line feed.
  const lines = "\r\n\n" + line + "\r\n" + '{"run":"b"}';
  const { store, seals } = recordStore(line);
  assert.deepEqual(multiset(verdict(store, seals, withRecords({ "audit/e.jsonl": lines })).findings), bothPass);
  // The .jsonl file whole is a candidate too.
  const whole = recordStore(lines);
  assert.deepEqual(multiset(verdict(whole.store, whole.seals, withRecords({ "audit/e.jsonl": lines })).findings), bothPass);
  // A link under the directory is not followed.
  const linked = recordStore(line);
  const dir = withRecords({});
  const outside = withRecords({ "r.json": line });
  fs.symlinkSync(path.join(outside, "r.json"), path.join(dir, "r.json"));
  assert.deepEqual(
    multiset(verdict(linked.store, linked.seals, dir).findings),
    multiset([...bothPass.map((f) => JSON.parse(f)), { sessionId: "s1", callIndex: 1, status: "decision-record-mismatch" }]),
  );
  // Named without a trailing separator, a directory that is a link is a
  // link, and the walk stops at it; with one, the platform resolves it.
  const via = path.join(withRecords({}), "via");
  fs.symlinkSync(outside, via);
  assert.deepEqual(
    multiset(verdict(linked.store, linked.seals, via).findings),
    multiset([...bothPass.map((f) => JSON.parse(f)), { sessionId: "s1", callIndex: 1, status: "decision-record-mismatch" }]),
  );
  assert.deepEqual(multiset(verdict(linked.store, linked.seals, via + path.sep).findings), bothPass);
});

test("a decision record's citations are read from its cites member alone", () => {
  const store = newStore();
  const head = signed(acquisitionV3());
  put(store, "s1", "0.json", JSON.stringify(head));
  const seals = [sealLine("s1", 1)];
  const cite = { sessionId: "s1", callIndex: 0, signature: head["signature"] };
  const sha = (s: string) => "sha256:" + crypto.createHash("sha256").update(s).digest("hex");
  const findings = (files: Record<string, string>) => multiset(verdict(store, seals, withRecords(files)).findings);
  const one = (record: string, s: string) => multiset([{ sessionId: "s1", callIndex: 0, status: "ok" }, { recordDigest: sha(record), status: s }]);

  const resolving = JSON.stringify({ facts: { amount: 1.5 }, run: "r", cites: [{ ...cite, note: "extra" }] });
  assert.deepEqual(findings({ "r.json": resolving }), passes, "floats elsewhere, and a member a citation does not name");
  assert.deepEqual(findings({ "r.json": resolving.replace('"run":"r"', '"run":"r","run":"s"') }), passes, "a name twice outside cites");
  const float = JSON.stringify({ cites: [cite] }).replace('"callIndex":0', '"callIndex":0.0');
  assert.deepEqual(findings({ "r.json": float }), one(float, "record-citation-malformed"), "a float inside cites");
  const twice = JSON.stringify({ cites: [cite] }).replace('"callIndex":0', '"callIndex":0,"callIndex":0');
  assert.deepEqual(findings({ "r.json": twice }), one(twice, "record-citation-malformed"), "a name twice inside cites");
  const notArray = '{"cites":{}}';
  assert.deepEqual(findings({ "r.json": notArray }), one(notArray, "record-citation-malformed"), "cites not an array");
  // A .jsonl file is read for citations line by line, never whole.
  const line = '{"cites":[1]}';
  assert.deepEqual(findings({ "e.jsonl": line + "\n" }), one(line, "record-citation-malformed"));
  // A candidate that is not one JSON object is not read.
  assert.deepEqual(findings({ "a.json": '[{"cites":1}]', "b.json": '{"cites":1} {}', "c.bin": "\xff" }), passes);
});

// The readings AMBIGUITIES.md records, each held here.
test("bytes that are not UTF-8 are unparseable, and a lone surrogate leaves nothing to sign", () => {
  const text = JSON.stringify(signed(receiptV2()));
  assert.deepEqual(alone(text.replace('"source":"src"', '"source":"\\ud800"')), status("signature-mismatch"));
  assert.deepEqual(alone(JSON.stringify(signed(acquisitionV3())).replace('"source":"src"', '"source":"\\ud800"')), status("signature-mismatch"));
  const store = newStore();
  put(store, "s1", "0.json", "");
  fs.writeFileSync(path.join(store.root, "receipts", "s1", "0.json"), Buffer.concat([Buffer.from(text.slice(0, -1)), Buffer.from([0xff, 0x7d])]));
  assert.deepEqual(multiset(verdict(store, [sealLine("s1", 1)]).findings), malformed);
});

test("what a session is, and what it counts", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  // A directory named like a receipt is not counted; a link named like one
  // is, and is read through; a link to a session directory is no session.
  fs.mkdirSync(path.join(store.root, "receipts", "s1", "9.json"));
  fs.symlinkSync(path.join(store.root, "receipts", "s1", "0.json"), path.join(store.root, "receipts", "s1", "1.json"));
  fs.symlinkSync(path.join(store.root, "receipts", "s1"), path.join(store.root, "receipts", "s2"));
  assert.deepEqual(
    multiset(verdict(store, [sealLine("s1", 2)]).findings),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s1", callIndex: 0, status: "misfiled" },
    ]),
  );
});

test("an artifact path that is a directory holds no artifact", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  const at = path.join(store.root, "artifacts", resultDigest.slice("sha256:".length));
  fs.rmSync(at);
  fs.mkdirSync(at);
  assert.deepEqual(multiset(verdict(store, [sealLine("s1", 1)]).findings), status("artifact-missing"));
  fs.rmSync(path.join(store.root, "artifacts"), { recursive: true });
  fs.writeFileSync(path.join(store.root, "artifacts"), "");
  assert.deepEqual(multiset(verdict(store, [sealLine("s1", 1)]).findings), status("artifact-missing"));
});

test("a seal's members beyond the four its signature covers are not read", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  assert.deepEqual(multiset(verdict(store, [sealLine("s1", 1).replace("{", '{"note":[1.5],')]).findings), passes);
});

test("a citation reads the cited file's one signature, and nothing else in it", () => {
  const record = '{"run":"r"}';
  const head = signed(acquisitionV3(0, null, "s2"));
  const unresolved = JSON.stringify({ callIndex: 1, sessionId: "s1", status: "citation-unresolved" });
  const findings = (text: string) => {
    const { store, seals } = recordStore(record, { sessionId: "s2", callIndex: 0, signature: head["signature"] });
    put(store, "s2", "0.json", text);
    return multiset(verdict(store, [...seals, sealLine("s2", 1)], withRecords({ "r.json": record })).findings);
  };
  // A name twice elsewhere makes the cited receipt malformed, its own
  // finding, and leaves its signature to be read.
  const twiceElsewhere = findings(JSON.stringify(head).replace("{", '{"source":"x",'));
  assert.ok(!twiceElsewhere.includes(unresolved), twiceElsewhere.join("\n"));
  assert.ok(twiceElsewhere.includes(JSON.stringify({ file: "0.json", sessionId: "s2", status: "malformed" })));
  // The signature given twice is no one signature.
  // The signed one first: a reader taking the first of a name twice would
  // resolve against it.
  assert.ok(findings(JSON.stringify(head).replace(/("signature":"[0-9a-f]+")/, '$1,"signature":"' + "e".repeat(128) + '"')).includes(unresolved));
});

test("the same record in two candidates reports twice", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  const record = '{"cites":{}}';
  const digest = "sha256:" + crypto.createHash("sha256").update(record).digest("hex");
  const findings = verdict(store, [sealLine("s1", 1)], withRecords({ "a.json": record, "b.jsonl": record + "\n" })).findings;
  assert.equal(findings.filter((f) => f["recordDigest"] === digest).length, 2);
});

test("a receipt in another session's directory is misfiled there", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  put(store, "s2", "0.json", JSON.stringify(signed(acquisitionV3())));
  assert.deepEqual(
    multiset(verdict(store, [sealLine("s1", 1), sealLine("s2", 1)]).findings),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s2", callIndex: 0, status: "misfiled" },
    ]),
  );
});

// §3 makes finalCount an integer, and nothing more: a validly signed seal
// counting below zero is loadable, the first for its session, and any
// count of files exceeds it (§4 step 3).
test("a seal counting below zero is loaded, and any count exceeds it", () => {
  const store = newStore();
  put(store, "s1", "0.json", JSON.stringify(signed(acquisitionV3())));
  assert.deepEqual(
    multiset(verdict(store, [sealLine("s1", -1), sealLine("s1", 1)]).findings),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s1", status: "count-exceeds-seal", have: 1, sealed: -1 },
    ]),
  );
});

test("a record's citations are held to the canonical domain, members they do not name included", () => {
  const store = newStore();
  const head = signed(acquisitionV3());
  put(store, "s1", "0.json", JSON.stringify(head));
  const cite = JSON.stringify({ sessionId: "s1", callIndex: 0, signature: head["signature"] });
  for (const record of [
    `{"cites":[${cite.replace("{", '{"note":1.5,')}]}`,
    `{"cites":[${cite.replace('"callIndex":0', '"callIndex":9007199254740992')}]}`,
    `{"cites":[${cite.replace("{", '{"note":"\\udc00",')}]}`,
  ]) {
    const findings = verdict(store, [sealLine("s1", 1)], withRecords({ "r.json": record })).findings;
    assert.ok(findings.some((f) => f["status"] === "record-citation-malformed"), record);
  }
});

test("a blank line is no candidate, though an empty file is one", () => {
  const empty = "sha256:" + crypto.createHash("sha256").update("").digest("hex");
  const store = newStore();
  const head = signed(acquisitionV3());
  put(store, "s1", "0.json", JSON.stringify(head));
  put(store, "s1", "1.json", JSON.stringify(signed(actionV3(1, head["signature"] as string, [], empty))));
  const mismatch = { sessionId: "s1", callIndex: 1, status: "decision-record-mismatch" };
  assert.ok(verdict(store, [sealLine("s1", 2)], withRecords({ "e.jsonl": "\n\r\n\n" })).findings.some((f) => JSON.stringify(f) === JSON.stringify(mismatch)));
  assert.ok(!verdict(store, [sealLine("s1", 2)], withRecords({ "e.jsonl": "" })).findings.some((f) => f["status"] === "decision-record-mismatch"));
});

test("a session id is a flat token of at most 128 characters", () => {
  for (const [length, found] of [
    [128, "ok"],
    [129, "malformed"],
  ] as const) {
    const id = "s".repeat(length);
    const store = newStore();
    put(store, id, "0.json", JSON.stringify(signed(acquisitionV3(0, null, id))));
    const findings = verdict(store, [sealLine(id, 1)]).findings;
    assert.equal(findings.length, 1, JSON.stringify(findings));
    assert.equal(findings[0]!["status"], found, String(length));
  }
});

test("a version 3 key id of either case is of its form, and not the verifier's in uppercase", () => {
  assert.deepEqual(alone(edited(acquisitionV3(), (r) => (r.keyId = r.keyId.toUpperCase()))), status("key-mismatch"));
});

test("an action that fails the ladder is joined to nothing", () => {
  const store = newStore();
  const head = signed(acquisitionV3());
  put(store, "s1", "0.json", JSON.stringify(head));
  const action = signed(actionV3(1, head["signature"] as string, [{ sessionId: "s9", callIndex: 0, signature: "c".repeat(128) }], resultDigest));
  put(store, "s1", "1.json", JSON.stringify({ ...action, source: "altered" }));
  assert.deepEqual(
    multiset(verdict(store, [sealLine("s1", 2)]).findings),
    multiset([
      { sessionId: "s1", callIndex: 0, status: "ok" },
      { sessionId: "s1", callIndex: 1, status: "signature-mismatch" },
    ]),
  );
});

test("a .jsonl file's lines are its lines whatever the reads that find them", () => {
  const long = "a".repeat(readChunk - 1);
  for (const [name, text, line] of [
    ["the last line, with no line feed", '{"run":"a"}\n{"run":"last"}', '{"run":"last"}'],
    ["a carriage return at a read's end before its line feed", long + "\r\n" + '{"run":"b"}', long],
    ["a carriage return at a read's end before more of its line", long + "\rx\n", long + "\rx"],
    ["a line across a read's end", "b".repeat(readChunk + 7) + "\n", "b".repeat(readChunk + 7)],
  ] as const) {
    const { store, seals } = recordStore(line);
    assert.deepEqual(multiset(verdict(store, seals, withRecords({ "e.jsonl": text })).findings), bothPass, name);
  }
});

test("a session named beyond Latin-1 is sealed by its seal", () => {
  const name = "会话-\u{1f600}";
  const store = newStore();
  put(store, name, "0.json", JSON.stringify(signed({ ...receiptV2(), sessionId: name })));
  assert.deepEqual(multiset(verdict(store, [sealLine(name, 1)]).findings), multiset([{ sessionId: name, callIndex: 0, status: "ok" }]));
});
