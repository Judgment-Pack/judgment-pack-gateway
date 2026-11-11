// §4 step 3's observation (gateway #381): a session no seal closes, whose
// receipts are every one whole, in sequence and chained, is observed
// session-open on its last receipt. The rows are shared with the Go reader
// (testdata/session-open/cases.json): a corpus vector, edited as the row
// says, and the session-open observations its verdict carries.

import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { verifyStore } from "../src/verify.ts";
import { corpus, materialize, publicKey, readStoreVector, verdictText } from "./support.ts";
import type { StoreVector } from "./support.ts";

type Row = { name: string; vector: string; registry?: string; remove?: string[]; tear?: string[]; observations: string[] };

test("an open session is observed so, and only a whole one, by the shared rows", () => {
  const rows: Row[] = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "..", "..", "testdata", "session-open", "cases.json"), "utf8"));
  assert.ok(rows.length > 0);
  for (const row of rows) {
    const v: StoreVector = readStoreVector(path.join(corpus, ...row.vector.split("/")));
    if (row.registry !== undefined) {
      v.registry = row.registry;
    }
    for (const file of row.remove ?? []) {
      assert.ok(file in v.files, `${row.name}: the vector holds no ${file}`);
      delete v.files[file];
    }
    for (const file of row.tear ?? []) {
      const text = v.files[file];
      assert.ok(text !== undefined, `${row.name}: the vector holds no ${file}`);
      // a receipt's text is ASCII, so its first half by characters is the
      // Go reader's first half by bytes
      assert.ok(/^[\x00-\x7f]*$/.test(text), `${row.name}: ${file} is not ASCII`);
      v.files[file] = text.slice(0, Math.floor(text.length / 2));
    }
    const { root, registry, decisionRecords } = materialize(v);
    const verdict = JSON.parse(verdictText(verifyStore(root, registry, v.authority, decisionRecords, publicKey)));
    const open = (verdict.observations ?? [])
      .filter((o: Record<string, unknown>) => o["observation"] === "session-open")
      .map((o: Record<string, unknown>) => `${o["sessionId"]}/${o["callIndex"]}/${o["observation"]}`);
    assert.deepEqual(open, row.observations, row.name);
    if (open.length > 0) {
      assert.equal(verdict.ok, false, `${row.name}: an open session's store verified ok`);
    }
  }
});
