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
        wait();
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

// wait is a pause for a descriptor that is not ready.
function wait(): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
}

// Output is standard output written as it is made: text is held until
// there is a chunk of it, and a chunk is written whole before more is
// taken, so no more than a chunk and the text last handed over is held.
class Output {
  private parts: string[] = [];
  private held = 0;

  write(text: string): void {
    this.parts.push(text);
    this.held += text.length;
    if (this.held >= 1 << 16) {
      this.flush();
    }
  }

  flush(): void {
    let bytes = Buffer.from(this.parts.join(""));
    this.parts = [];
    this.held = 0;
    while (bytes.length > 0) {
      let n: number;
      try {
        n = fs.writeSync(1, bytes);
      } catch (e) {
        if (code(e) === "EAGAIN") {
          wait();
          continue;
        }
        throw e;
      }
      bytes = bytes.subarray(n);
    }
  }
}

const strictUTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// exactArguments is the arguments as the strings their bytes are. The
// platform hands a program its arguments decoded as UTF-8 with
// replacement, so a path holding a byte that is not UTF-8 would arrive as
// another path, one that may exist. Where the platform shows a process
// its own arguments' bytes (Linux, /proc/self/cmdline), each is decoded
// strictly and one that is not UTF-8 is no verdict; where it does not, an
// argument holding a replacement character cannot be told from one that
// was not UTF-8, and is no verdict.
function exactArguments(args: string[]): string[] {
  let raw: Buffer | undefined;
  try {
    raw = fs.readFileSync("/proc/self/cmdline");
  } catch {
    raw = undefined;
  }
  if (raw === undefined) {
    for (const a of args) {
      if (a.includes("\ufffd")) {
        throw new NoVerdict(`an argument holds U+FFFD, which here cannot be told from bytes that are not UTF-8: ${JSON.stringify(a)}`);
      }
    }
    return args;
  }
  // The arguments are the command line's last entries, each ended by a
  // NUL; the platform's and node's own come before them.
  const entries: Buffer[] = [];
  let start = 0;
  for (let i = raw.indexOf(0); i !== -1; i = raw.indexOf(0, start)) {
    entries.push(raw.subarray(start, i));
    start = i + 1;
  }
  const mine = entries.slice(entries.length - args.length - 1);
  return args.map((a, k) => {
    const bytes = mine[k + 1];
    let exact: string;
    try {
      exact = bytes === undefined ? a : strictUTF8.decode(bytes);
    } catch {
      throw new NoVerdict(`an argument is not UTF-8: ${JSON.stringify(a)}`);
    }
    if (exact !== a) {
      throw new NoVerdict(`an argument is not the string it was given as: ${JSON.stringify(a)}`);
    }
    return exact;
  });
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
    try {
      const [root, registry, authority, decisionRecords] = exactArguments(rest) as [string, string, string, string | undefined];
      const key = readInput(32);
      if (key === null) {
        throw new NoVerdict("the public key on standard input is more than 32 bytes");
      }
      const verdict = verifyStore(root, registry, authority, decisionRecords, key);
      const output = new Output();
      writeVerdict(verdict, (text) => output.write(text));
      output.flush();
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
