// A verdict by scope (SPEC.md §4, "A verdict by scope") through main.ts:
// --scope <identifier> first or not at all, never with a decision-records
// directory, and the verdict it writes is the cut's, its cut member last.
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as path from "node:path";
import { test } from "node:test";

import { corpus, materialize, publicKey, readStoreVector } from "./support.ts";

const main = path.join(import.meta.dirname, "..", "src", "main.ts");

test("main.ts verify takes --scope first or not at all, and the verdict it writes is the cut's", () => {
  const v = readStoreVector(path.join(corpus, "v3", "stores", "v3-cut-two-scopes.json"));
  const { root, registry } = materialize(v);
  const run = (...args: string[]) => spawnSync(process.execPath, [main, "verify", ...args], { input: publicKey });
  const cut = run("--scope", "scope-a", root, registry, v.authority);
  assert.equal(cut.status, 0, cut.stderr.toString());
  assert.equal(
    cut.stdout.toString(),
    '{"ok":true,"findings":[{"sessionId":"s1","callIndex":0,"status":"ok"},{"sessionId":"s1","callIndex":1,"status":"ok"}],"cut":{"scope":"scope-a","sessions":["s1"],"unattributed":[]}}\n',
  );
  // the whole store's verdict gives no cut
  const whole = run(root, registry, v.authority);
  assert.equal(whole.status, 0, whole.stderr.toString());
  assert.ok(!whole.stdout.toString().includes('"cut"'), whole.stdout.toString());
  const usage =
    "usage: main.ts canon | main.ts verify [--public-key-alg ES256] [--scope <identifier>] [--ordinary-seals-only] [--artifacts <dir>] <store-root> <registry-path> <authority> [<decision-records-dir>] | main.ts witness --trail <hex> --witness-key <file>... [--witness <file>]... [--witness-head <file>]\n";
  const notFirst = "verify: --scope goes first, before every other option; a directory so named is given as ./--scope\n";
  for (const [name, args, said] of [
    ["after the store root", [root, "--scope", "scope-a", registry, v.authority], notFirst],
    ["after --ordinary-seals-only", ["--ordinary-seals-only", "--scope", "scope-a", root, registry, v.authority], notFirst],
    ["first and again", ["--scope", "scope-a", "--scope", "scope-a", root, registry, v.authority], notFirst],
    ["with a decision-records directory", ["--scope", "scope-a", root, registry, v.authority, root], "verify: a verdict by scope reads no decision records\n"],
    ["naming no scope identifier", ["--scope", "", root, registry, v.authority], "verify: --scope names a scope identifier\n"],
    ["naming nothing", ["--scope"], "verify: --scope names a scope identifier\n"],
  ] as [string, string[], string][]) {
    const r = run(...args);
    assert.equal(r.status, 64, name);
    assert.equal(r.stdout.toString(), "", name);
    assert.equal(r.stderr.toString(), said + usage, name);
  }
});
