// The process contract of corpus/README.md: `canon` and `verify`, so the
// gateway's `conform --impl` can hold this implementation to the frozen
// corpus.
//
//   main.ts canon      stdin: one JSON document; stdout: its canonical
//                      bytes; exit 0 inside the domain, 1 refused
//   main.ts verify <store-root> <registry-path> <authority> [<decision-records-dir>]
//                      stdin: the 32-byte Ed25519 public key; stdout:
//                      {"ok": bool, "findings": [...]}; exit 0 whenever a
//                      verdict was reached, 2 when none could be

import * as fs from "node:fs";

import { canonical } from "./canon.ts";
import { NoVerdict } from "./inputs.ts";
import { parse } from "./json.ts";
import { verifyStore, writeVerdict } from "./verify.ts";

function main(args: string[]): number {
  const [command, ...rest] = args;
  if (command === "canon" && rest.length === 0) {
    const value = parse(fs.readFileSync(0));
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
      process.stdout.write(writeVerdict(verifyStore(root, registry, authority, decisionRecords, fs.readFileSync(0))));
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
