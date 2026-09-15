// The process contract of corpus/README.md: `canon` and `verify`, so the
// gateway's `conform --impl` can hold this implementation to the frozen
// corpus.
//
//   main.ts canon      stdin: one JSON document; stdout: its canonical
//                      bytes; exit 0 inside the domain, 1 refused, 2
//                      past what this implementation reads
//   main.ts verify <store-root> <registry-path> <authority> [<decision-records-dir>]
//                      stdin: the 32-byte Ed25519 public key; stdout:
//                      {"ok": bool, "findings": [...]}; exit 0 whenever a
//                      verdict was reached, 2 when none could be

import * as fs from "node:fs";

import { canonical } from "./canon.ts";
import { NoVerdict, code, documentBound } from "./inputs.ts";
import { TooLarge, maxValues, parse } from "./json.ts";
import type { Value } from "./json.ts";
import { verifyStore, writeVerdict } from "./verify.ts";

// readInput is standard input to its end, or null past limit bytes: no
// more than a byte past the limit is read.
function readInput(limit: number): Uint8Array | null {
  const parts: Buffer[] = [];
  const buffer = Buffer.alloc(1 << 16);
  let n = 0;
  for (;;) {
    let read: number;
    try {
      read = fs.readSync(0, buffer, 0, Math.min(buffer.length, limit + 1 - n), null);
    } catch (e) {
      if (code(e) === "EAGAIN") {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
        continue;
      }
      if (code(e) === "EOF") {
        break;
      }
      throw e;
    }
    if (read === 0) {
      break;
    }
    parts.push(Buffer.from(buffer.subarray(0, read)));
    n += read;
    if (n > limit) {
      return null;
    }
  }
  return Buffer.concat(parts, n);
}

function main(args: string[]): number {
  const [command, ...rest] = args;
  if (command === "canon" && rest.length === 0) {
    const input = readInput(documentBound);
    if (input === null) {
      process.stderr.write(`canon: the document is more than ${documentBound} bytes, more than this implementation reads\n`);
      return 2;
    }
    let value: Value | null;
    try {
      value = parse(input);
    } catch (e) {
      if (e instanceof TooLarge) {
        process.stderr.write(`canon: the document holds more than ${maxValues} values, more than this implementation reads\n`);
        return 2;
      }
      throw e;
    }
    const bytes = value === null ? null : canonical(value);
    if (bytes === null) {
      process.stderr.write("canon: outside the domain\n");
      return 1;
    }
    process.stdout.write(bytes);
    return 0;
  }
  if (command === "verify" && (rest.length === 3 || rest.length === 4)) {
    const [root, registry, authority, decisionRecords] = rest as [string, string, string, string | undefined];
    try {
      const key = readInput(32);
      if (key === null) {
        throw new NoVerdict("the public key on standard input is more than 32 bytes");
      }
      process.stdout.write(writeVerdict(verifyStore(root, registry, authority, decisionRecords, key)));
      return 0;
    } catch (e) {
      if (e instanceof NoVerdict) {
        process.stderr.write(`verify: no verdict: ${e.message}\n`);
        return 2;
      }
      throw e;
    }
  }
  process.stderr.write("usage: main.ts canon | main.ts verify <store-root> <registry-path> <authority> [<decision-records-dir>]\n");
  return 64;
}

process.exitCode = main(process.argv.slice(2));
