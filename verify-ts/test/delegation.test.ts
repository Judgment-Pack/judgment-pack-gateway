import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { parse } from "../src/json.ts";
import { structureV3 } from "../src/structure.ts";
import type { ObjectValue } from "../src/json.ts";

// The forms of the delegation and reconciler members, and the comparisons
// within one receipt (SPEC.md §11.7): the rows the Go reader reads too.
test("the delegation and reconciler members share structural rows with the Go reader", () => {
  const doc = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "../../testdata/delegation/receipt-members.json"), "utf8"));
  assert.ok(doc.rows.length >= 50);
  for (const row of doc.rows) {
    const receipt = structuredClone(doc.bases[row.base]);
    let target = receipt;
    for (const name of row.path.slice(0, -1)) {
      target = target[name];
    }
    const last = row.path[row.path.length - 1];
    if (row.remove) {
      delete target[last];
    } else {
      target[last] = row.value;
    }
    const parsed = parse(Buffer.from(JSON.stringify(receipt))) as ObjectValue;
    assert.equal(structureV3(parsed), row.valid, JSON.stringify(row));
  }
});
