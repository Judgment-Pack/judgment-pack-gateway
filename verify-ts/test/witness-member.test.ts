// The witness member of a version 3 receipt (§1.2a, ADR-0014): its origin's
// form, held as the reference holds it. The corpus holds the member in a
// receipt; this holds the form case by case, an origin the corpus has no
// vector for included.

import * as assert from "node:assert/strict";
import { test } from "node:test";

import { isWitnessOrigin } from "../src/structure.ts";

test("an origin of its form, and origins out of it", () => {
  const port443 = (host: string) => `https://${host}:443`;
  for (const origin of [
    "https://witness.example:443",
    "https://w-1.witness.example:8443",
    "https://192.0.2.7:443",
    "https://[2001:db8::7]:443",
    "https://localhost:1",
    "https://a:65535",
    "http://127.0.0.1:8080",
    "http://127.255.0.9:80",
    "http://[::1]:8080",
    port443("a".repeat(2048 - "https://:443".length)),
  ]) {
    assert.equal(isWitnessOrigin(origin), true, origin.slice(0, 80));
  }
  for (const origin of [
    "",
    "https://witness.example",
    "https://witness.example:",
    "https://witness.example:0443",
    "https://witness.example:0",
    "https://witness.example:65536",
    "https://witness.example:443/",
    "https://witness.example:443/witness",
    "https://witness.example:443?x=1",
    "https://Witness.example:443",
    "https://witness..example:443",
    "https://.witness.example:443",
    "https://user@witness.example:443",
    "https://witness_example:443",
    "https://[2001:DB8::7]:443",
    "https://[2001:db8::7%25eth0]:443",
    "https://[::ffff:1.2.3.4]:443",
    "https://[1::2::3]:443",
    "https://2001:db8::7:443",
    "http://witness.example:80",
    "http://localhost:8080",
    "http://10.0.0.1:8080",
    "http://127.0.0.01:8080",
    "http://127.0.0.256:8080",
    "http://[0:0:0:0:0:0:0:1]:8080",
    "ftp://witness.example:21",
    "HTTPS://witness.example:443",
    " https://witness.example:443",
    "https://witness.example:443 ",
    "https://witness.example:443\n",
    port443("a".repeat(2049 - "https://:443".length)),
  ]) {
    assert.equal(isWitnessOrigin(origin), false, origin.slice(0, 80));
  }
});
