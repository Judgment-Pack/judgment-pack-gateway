// The call reference (ADR-0060): a version 3 receipt's callRef is 64
// lowercase hexadecimal characters on either kind, and any other form is
// malformed; a reader that does not know it still verifies the signature,
// which is over every member.
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { canonical } from "../src/canon.ts";
import { parse } from "../src/json.ts";
import { structureV3 } from "../src/structure.ts";
import type { ObjectValue } from "../src/json.ts";
import { acquisitionV3, actionV3, publicKey, resultDigest, signed } from "./support.ts";

const ref = "0123456789abcdef".repeat(4);
const read = (r: unknown) => parse(Buffer.from(JSON.stringify(r))) as ObjectValue;
const cites = [{ sessionId: "read", callIndex: 0, signature: "ab".repeat(64) }];

test("callRef is 64 lowercase hex on either kind, and any other form is malformed", () => {
  assert.equal(structureV3(read(signed(acquisitionV3()))), true);
  assert.equal(structureV3(read(signed({ ...acquisitionV3(), callRef: ref }))), true);
  assert.equal(structureV3(read(signed({ ...actionV3(0, null, cites, resultDigest), callRef: ref }))), true);
  for (const bad of [ref.toUpperCase(), ref.slice(1), ref + "0", "", 7, null]) {
    assert.equal(structureV3(read(signed({ ...acquisitionV3(), callRef: bad }))), false, JSON.stringify(bad));
  }
});

test("a reader that does not know callRef verifies the signature over it", () => {
  const { signature, ...core } = signed({ ...acquisitionV3(), callRef: ref });
  const { callRef: _, ...withoutRef } = core;
  const key = crypto.createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]), format: "der", type: "spki" });
  const holds = (c: unknown) => crypto.verify(null, Buffer.concat([Buffer.from("judgment-pack-gateway/receipt/3:"), canonical(read(c))!]), key, Buffer.from(signature as string, "hex"));
  assert.equal(holds(core), true);
  assert.equal(holds(withoutRef), false);
});
