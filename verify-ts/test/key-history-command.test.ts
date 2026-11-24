// main.ts verify-key-history (SPEC.md §3e; ADR-0055, amendment of
// 2026-11-24): the consumer's check of a fetched key history, from a file or
// standard input, through the command line. The line it writes for each
// corpus vector is derived from the vector alone, as the gateway's own test
// derives it, so the two tools' outputs are held to one line, byte for byte.

import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";

import { keyHistoryInputBound } from "../src/key-history.ts";
import { corpus, publicKey, tempDir } from "./support.ts";

const main = path.join(import.meta.dirname, "..", "src", "main.ts");

type Vector = {
  name: string;
  pin: string | { alg: "ES256"; key: string };
  requireVersion?: string;
  history: string;
  expected: { accepted?: { keys: number; inForce: string }; refused?: string };
};

const readVector = (name: string): Vector => JSON.parse(fs.readFileSync(path.join(corpus, "key-history", name + ".json"), "utf8")) as Vector;

// lineOf is the line the command writes for a vector, from the vector alone;
// the version of an accepted history is the one its own keyHistoryVersion names.
function lineOf(v: Vector): string {
  if (v.expected.accepted === undefined) {
    return `{"accepted":false,"refused":"${v.expected.refused}"}\n`;
  }
  const version = (JSON.parse(v.history) as { keyHistoryVersion: string }).keyHistoryVersion;
  return `{"accepted":true,"version":"${version}","keys":${v.expected.accepted.keys},"inForce":"${v.expected.accepted.inForce}"}\n`;
}

// optionsOf is a vector's pin as the command takes it, and its requireVersion.
function optionsOf(v: Vector): string[] {
  const pin = typeof v.pin === "string" ? { alg: "", key: fs.readFileSync(path.join(corpus, v.pin), "utf8").trim() } : v.pin;
  return [
    "--public-key",
    pin.key,
    ...(pin.alg === "ES256" ? ["--public-key-alg", "ES256"] : []),
    ...(v.requireVersion === undefined ? [] : ["--require-version", v.requireVersion]),
  ];
}

const run = (args: string[], input: string | Buffer = "") => spawnSync(process.execPath, [main, "verify-key-history", ...args], { input });

const vectorNames = (): string[] =>
  fs
    .readdirSync(path.join(corpus, "key-history"))
    .filter((n) => n.endsWith(".json"))
    .map((n) => n.slice(0, -5))
    .sort();

test("every key-history vector, through the command: the exit code and the line, byte for byte", () => {
  const names = vectorNames();
  assert.equal(names.length, 29);
  const dir = tempDir();
  for (const name of names) {
    const v = readVector(name);
    const file = path.join(dir, name + ".json");
    fs.writeFileSync(file, v.history);
    const got = run([...optionsOf(v), file]);
    assert.equal(got.status, v.expected.accepted === undefined ? 1 : 0, `${name}: ${got.stderr}`);
    assert.equal(got.stdout.toString(), lineOf(v), name);
  }
});

test("standard input gives the line a file gives", () => {
  const dir = tempDir();
  for (const name of ["kh-v2-across-store", "kh-v1-version-2-required", "kh-v2-p256-continuation"]) {
    const v = readVector(name);
    const file = path.join(dir, name + ".json");
    fs.writeFileSync(file, v.history);
    const fromFile = run([...optionsOf(v), file]);
    const fromStdin = run([...optionsOf(v), "-"], v.history);
    assert.equal(fromStdin.status, fromFile.status, name);
    assert.equal(fromStdin.stdout.toString(), fromFile.stdout.toString(), name);
    assert.equal(fromStdin.stdout.toString(), lineOf(v), name);
  }
});

test("the pin is optional, a first key that is not the pin is refused, and --require-version 2 refuses version 1", () => {
  const dir = tempDir();
  const v = readVector("kh-v1-one-key");
  const file = path.join(dir, "one.json");
  fs.writeFileSync(file, v.history);
  const none = run([file]);
  assert.equal(none.status, 0, none.stderr.toString());
  assert.equal(none.stdout.toString(), lineOf(v));
  const p256 = fs.readFileSync(path.join(corpus, "TEST-P256-PUBLIC-KEY"), "utf8").trim();
  const other = run(["--public-key", p256, "--public-key-alg", "ES256", file]);
  assert.equal(other.status, 1);
  assert.equal(other.stdout.toString(), '{"accepted":false,"refused":"key"}\n');
  const required = run(["--require-version", "2", file]);
  assert.equal(required.status, 1);
  assert.equal(required.stdout.toString(), '{"accepted":false,"refused":"version"}\n');
});

test("a usage error, an input that cannot be read, is exit 64 and writes nothing on standard output", () => {
  const dir = tempDir();
  const v = readVector("kh-v1-one-key");
  const file = path.join(dir, "one.json");
  fs.writeFileSync(file, v.history);
  const ed = publicKey.toString("hex");
  const cases: [string, string[]][] = [
    ["a bad flag", ["--frobnicate", file]],
    ["a bad flag after the key", ["--public-key", ed, "--frobnicate", file]],
    ["no file", []],
    ["no file after the options", ["--public-key", ed, "--require-version", "2"]],
    ["two files", [file, file]],
    ["a file and standard input", [file, "-"]],
    ["--require-version 3", ["--require-version", "3", file]],
    ["--require-version 1", ["--require-version", "1", file]],
    ["--require-version without a value", ["--require-version"]],
    ["--public-key without a value", ["--public-key"]],
    ["an uppercase key", ["--public-key", ed.toUpperCase(), file]],
    ["a key of 63 characters", ["--public-key", ed.slice(1), file]],
    ["an algorithm of another name", ["--public-key", ed, "--public-key-alg", "ES384", file]],
    ["an algorithm without a value", ["--public-key", ed, "--public-key-alg"]],
    ["an Ed25519 key under ES256", ["--public-key", ed, "--public-key-alg", "ES256", file]],
    ["an algorithm without a key", ["--public-key-alg", "ES256", file]],
    ["the options in the other order", ["--require-version", "2", "--public-key", ed, file]],
    ["a file that is not there", [path.join(dir, "absent.json")]],
    ["a directory", [dir]],
  ];
  for (const [name, args] of cases) {
    const got = run(args);
    assert.equal(got.status, 64, `${name}: ${got.stdout} ${got.stderr}`);
    assert.equal(got.stdout.toString(), "", name);
    assert.notEqual(got.stderr.toString(), "", name);
  }
});

test("an input of the bound is read, and one byte over it is a usage-level refusal made before it is parsed", () => {
  assert.equal(keyHistoryInputBound, 16777216, "the bound is 16777216 bytes; docs and the gateway's command state it");
  const v = readVector("kh-v1-one-key");
  const dir = tempDir();
  const padded = (n: number): string => v.history + " ".repeat(n - v.history.length);
  const at = padded(keyHistoryInputBound);
  const over = padded(keyHistoryInputBound + 1);
  const atFile = path.join(dir, "at.json");
  const overFile = path.join(dir, "over.json");
  fs.writeFileSync(atFile, at);
  fs.writeFileSync(overFile, over);
  for (const what of ["a file", "standard input"]) {
    const read = what === "a file" ? run([...optionsOf(v), atFile]) : run([...optionsOf(v), "-"], at);
    // at the bound it is read: any verdict, and a line of it on standard output
    assert.ok(read.status === 0 || read.status === 1, `${what} at the bound: ${read.status} ${read.stderr}`);
    assert.ok(read.stdout.toString().startsWith('{"accepted":'), what);
    const refused = what === "a file" ? run([...optionsOf(v), overFile]) : run([...optionsOf(v), "-"], over);
    assert.equal(refused.status, 64, `${what} one byte over the bound: ${refused.stdout} ${refused.stderr}`);
    assert.equal(refused.stdout.toString(), "", what);
    assert.match(refused.stderr.toString(), /16777216/, what);
  }
});
