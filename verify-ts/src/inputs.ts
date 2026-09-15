// Absent and unreadable inputs (SPEC.md §4.1). An input is absent only
// when the platform confirms nothing is there; anything present that
// cannot be read is no verdict at all, never an absence.

import * as fs from "node:fs";
import * as path from "node:path";

// NoVerdict is an input present and unreadable: the verifier reaches no
// verdict and says why.
export class NoVerdict extends Error {}

function code(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException | undefined)?.code;
}

// The Windows spelling rules of §4.1 are not implemented here, so this
// verifier does not run there rather than read a path as spelled that
// Windows would resolve otherwise.
export function refuseUnsupportedPlatform(): void {
  if (process.platform === "win32") {
    throw new NoVerdict("this verifier does not implement SPEC.md §4.1's Windows spelling rules");
  }
}

// checkSpelling refuses a path the platform could resolve to another file
// than the one its spelling names: a ".." after a named component, which
// steps back from where that component leads, a link's target included.
function checkSpelling(p: string, what: string): void {
  let named = false;
  for (const component of p.split(path.sep)) {
    if (component === "..") {
      if (named) {
        throw new NoVerdict(`${what} ${JSON.stringify(p)} steps back after a named component`);
      }
    } else if (component !== "" && component !== ".") {
      named = true;
    }
  }
}

type Found = { readonly present: false } | { readonly present: true; readonly stat: fs.Stats };

// look is what is at p, following links, or confirmed absence: a stat that
// finds nothing, and a look at the path itself that finds nothing too. A
// link that leads nowhere, or any other failure, is present and unreadable.
function look(p: string, what: string): Found {
  try {
    return { present: true, stat: fs.statSync(p) };
  } catch (e) {
    if (code(e) !== "ENOENT") {
      throw new NoVerdict(`${what} ${JSON.stringify(p)} cannot be read: ${code(e) ?? e}`);
    }
  }
  try {
    fs.lstatSync(p);
  } catch (e) {
    if (code(e) === "ENOENT") {
      return { present: false };
    }
    throw new NoVerdict(`${what} ${JSON.stringify(p)} cannot be read: ${code(e) ?? e}`);
  }
  throw new NoVerdict(`${what} ${JSON.stringify(p)} is a link that leads nowhere`);
}

// locate walks the directories above p -- the prefixes of its spelling,
// each cut before a separator -- and then p itself: absent when any of them
// is confirmed missing, since nothing below a missing directory is looked
// at; present as what p is otherwise. A file above p is found by the look
// below it, which the platform answers ENOTDIR: present and unreadable.
function locate(p: string, what: string): Found {
  for (let at = p.indexOf(path.sep, 1); at !== -1; at = p.indexOf(path.sep, at + 1)) {
    const found = look(p.slice(0, at), what);
    if (!found.present) {
      return found;
    }
  }
  return look(p, what);
}

// readRegistry is the registry's bytes, or null when it is absent.
export function readRegistry(p: string): Uint8Array | null {
  if (p === "" || p.endsWith(path.sep)) {
    throw new NoVerdict(`the registry path ${JSON.stringify(p)} names no file`);
  }
  checkSpelling(p, "the registry");
  const found = locate(p, "the registry");
  if (!found.present) {
    return null;
  }
  try {
    return fs.readFileSync(p);
  } catch (e) {
    throw new NoVerdict(`the registry ${JSON.stringify(p)} cannot be read: ${code(e) ?? e}`);
  }
}

// A candidate for the decision records of §4 step 6: bytes to hash, and
// whether step 7 reads them for a record's citations -- a regular file
// whole, or each line of a .jsonl file but not that file whole.
export type Candidate = { readonly bytes: Uint8Array; readonly record: boolean };

// readDecisionRecords is every candidate under the directory, or null when
// it is absent or none was given.
export function readDecisionRecords(p: string | undefined): Candidate[] | null {
  if (p === undefined) {
    return null;
  }
  checkSpelling(p, "the decision-record directory");
  const found = locate(p, "the decision-record directory");
  if (!found.present) {
    return null;
  }
  if (!found.stat.isDirectory()) {
    throw new NoVerdict(`the decision-record directory ${JSON.stringify(p)} is not a directory`);
  }
  // The walk takes the directory as its path is spelled and follows no
  // link: named without a trailing separator, a link to a directory is a
  // link, and the walk stops at it; with one, the platform resolves it.
  const candidates: Candidate[] = [];
  let top: fs.Stats;
  try {
    top = fs.lstatSync(p);
  } catch (e) {
    throw new NoVerdict(`the decision-record directory ${JSON.stringify(p)} cannot be read: ${code(e) ?? e}`);
  }
  if (!top.isDirectory()) {
    return candidates;
  }
  const dirs = [p];
  for (let dir = dirs.pop(); dir !== undefined; dir = dirs.pop()) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      throw new NoVerdict(`under the decision-record directory, ${JSON.stringify(dir)} cannot be read: ${code(e) ?? e}`);
    }
    for (const entry of entries) {
      const at = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        dirs.push(at);
        continue;
      }
      if (!entry.isFile()) {
        continue; // a link is not followed, and nothing else is a file
      }
      let bytes: Uint8Array;
      try {
        bytes = fs.readFileSync(at);
      } catch (e) {
        throw new NoVerdict(`under the decision-record directory, ${JSON.stringify(at)} cannot be read: ${code(e) ?? e}`);
      }
      const lines = entry.name.endsWith(".jsonl");
      candidates.push({ bytes, record: !lines });
      if (lines) {
        for (const line of splitLines(bytes)) {
          candidates.push({ bytes: line, record: true });
        }
      }
    }
  }
  return candidates;
}

// splitLines is a .jsonl file's lines: its bytes split on each line feed,
// each piece without one trailing carriage return, and no empty piece.
export function splitLines(bytes: Uint8Array): Uint8Array[] {
  const lines: Uint8Array[] = [];
  let start = 0;
  for (let i = 0; i <= bytes.length; i++) {
    if (i < bytes.length && bytes[i] !== 0x0a) {
      continue;
    }
    let end = i;
    if (end > start && bytes[end - 1] === 0x0d) {
      end--;
    }
    if (end > start) {
      lines.push(bytes.subarray(start, end));
    }
    start = i + 1;
  }
  return lines;
}
