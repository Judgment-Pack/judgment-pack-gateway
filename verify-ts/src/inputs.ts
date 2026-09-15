// Absent and unreadable inputs (SPEC.md §4.1), and reading what is there
// within bounds. An input is absent only when the platform confirms
// nothing is there; anything present that cannot be read is no verdict at
// all, never an absence. Nothing is read but a regular file, opened
// without waiting on a writer, so a FIFO or a device in a store is no
// verdict rather than a hang; and nothing is held whole but one JSON
// document at a time.

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

// NoVerdict is an input present and unreadable: the verifier reaches no
// verdict and says why.
export class NoVerdict extends Error {}

// documentBound is the most a single JSON document the verifier reads --
// a receipt, a seal line, a decision record -- may take. SPEC.md sets no
// bound; this one keeps memory within reach whatever a store holds.
export const documentBound = 64 << 20;

// readChunk is how much of a file is read at a time.
export const readChunk = 1 << 20;
const chunk = readChunk;

export function code(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException | undefined)?.code;
}

// shown is a path as a message shows it; the bytes of a name that is not
// UTF-8 are shown with replacement characters, and read as they are.
function shown(p: fs.PathLike): string {
  return JSON.stringify(typeof p === "string" ? p : p.toString());
}

function unreadable(what: string, p: fs.PathLike, e: unknown): NoVerdict {
  return e instanceof NoVerdict ? e : new NoVerdict(`${what} ${shown(p)} cannot be read: ${code(e) ?? e}`);
}

const strictUTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// nameOf is a name read from a directory, as the string it is in UTF-8. A
// name that is not UTF-8 has no string to be in a finding, and decoded
// with replacement it could be taken for another entry's, so it is no
// verdict.
export function nameOf(bytes: Uint8Array, what: string): string {
  try {
    return strictUTF8.decode(bytes);
  } catch {
    throw new NoVerdict(`${what} ${JSON.stringify(Buffer.from(bytes).toString())} is named in bytes that are not UTF-8`);
  }
}

// endsWith is whether a name's bytes end with the ASCII suffix.
export function endsWith(name: Uint8Array, suffix: string): boolean {
  return name.length >= suffix.length && Buffer.from(name.subarray(name.length - suffix.length)).toString("latin1") === suffix;
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

// checkSpellings refuses, before anything is read, an anchor spelled so the
// platform could resolve it otherwise -- and, for the registry, which is a
// file, a path naming none.
export function checkSpellings(registry: string, decisionRecords: string | undefined): void {
  if (registry === "" || registry.endsWith(path.sep)) {
    throw new NoVerdict(`the registry path ${JSON.stringify(registry)} names no file`);
  }
  checkSpelling(registry, "the registry");
  if (decisionRecords !== undefined) {
    checkSpelling(decisionRecords, "the decision-record directory");
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
      throw unreadable(what, p, e);
    }
  }
  try {
    fs.lstatSync(p);
  } catch (e) {
    if (code(e) === "ENOENT") {
      return { present: false };
    }
    throw unreadable(what, p, e);
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

// An anchor as §4.1 classifies it: confirmed absent, or a path to read.
export type Anchor = { readonly absent: true } | { readonly absent: false; readonly path: string };

// locateRegistry classifies the registry; what is there is read only if
// it is a regular file (withRegular).
export function locateRegistry(p: string): Anchor {
  return locate(p, "the registry").present ? { absent: false, path: p } : { absent: true };
}

// locateDecisionRecords classifies the decision-record directory; one not
// given is absent.
export function locateDecisionRecords(p: string | undefined): Anchor {
  if (p === undefined) {
    return { absent: true };
  }
  const found = locate(p, "the decision-record directory");
  if (!found.present) {
    return { absent: true };
  }
  if (!found.stat.isDirectory()) {
    throw new NoVerdict(`the decision-record directory ${JSON.stringify(p)} is not a directory`);
  }
  return { absent: false, path: p };
}

// withRegular opens p, following a link, without waiting on a writer, and
// hands its descriptor and size to use when it is a regular file; anything
// else there is no verdict. A failure to open is thrown as it is, for the
// caller to read.
export function withRegular<T>(p: fs.PathLike, what: string, use: (fd: number, size: number) => T): T {
  const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  try {
    let stat: fs.Stats;
    try {
      stat = fs.fstatSync(fd);
    } catch (e) {
      throw unreadable(what, p, e);
    }
    if (!stat.isFile()) {
      throw new NoVerdict(`${what} ${shown(p)} is not a regular file`);
    }
    try {
      return use(fd, stat.size);
    } catch (e) {
      throw unreadable(what, p, e);
    }
  } finally {
    fs.closeSync(fd);
  }
}

// readDocument is a regular file's bytes, when within documentBound; a
// larger file, or one that cannot be read, is no verdict.
export function readDocument(p: string, what: string): Uint8Array {
  try {
    return withRegular(p, what, (fd) => {
      const bytes = readBounded(fd);
      if (bytes === null) {
        throw new NoVerdict(`${what} ${JSON.stringify(p)} is over ${documentBound} bytes`);
      }
      return bytes;
    });
  } catch (e) {
    throw unreadable(what, p, e);
  }
}

// readBounded is the open file's bytes to its end, or null past
// documentBound.
function readBounded(fd: number): Uint8Array | null {
  const parts: Buffer[] = [];
  let n = 0;
  for (;;) {
    const buffer = Buffer.alloc(chunk);
    const read = fs.readSync(fd, buffer, 0, buffer.length, null);
    if (read === 0) {
      return Buffer.concat(parts, n);
    }
    n += read;
    if (n > documentBound) {
      return null;
    }
    parts.push(buffer.subarray(0, read));
  }
}

// A candidate as read: its SHA-256, and either its bytes or, past
// documentBound, whether its first byte that is not JSON whitespace opens
// an object -- the one thing that could make it a record step 7 reads.
export type Read = { readonly digest: string; readonly bytes: Uint8Array | null; readonly opensObject: boolean };

const isSpace = (b: number) => b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d;

// Accumulating is a document read a chunk at a time: hashed throughout,
// kept while within documentBound, and past it only its first byte that is
// not whitespace remembered.
class Accumulating {
  private readonly hash = crypto.createHash("sha256");
  private parts: Buffer[] = [];
  private length = 0;
  private first = -1;
  private over = false;

  add(bytes: Uint8Array): void {
    if (bytes.length === 0) {
      return;
    }
    this.hash.update(bytes);
    if (this.first === -1) {
      const at = bytes.findIndex((b) => !isSpace(b));
      if (at !== -1) {
        this.first = bytes[at]!;
      }
    }
    if (this.over) {
      return;
    }
    if (this.length + bytes.length > documentBound) {
      this.over = true;
      this.parts = [];
      return;
    }
    this.parts.push(Buffer.from(bytes));
    this.length += bytes.length;
  }

  done(): Read {
    return {
      digest: this.hash.digest("hex"),
      bytes: this.over ? null : Buffer.concat(this.parts, this.length),
      opensObject: this.first === 0x7b,
    };
  }
}

// eachLine hands each line of the open file to visit, in order: its bytes
// split on each line feed, one trailing carriage return taken off, the
// empty ones included. The whole file's SHA-256 is the result.
function eachLine(fd: number, visit: (line: Read) => void): string {
  const whole = crypto.createHash("sha256");
  const buffer = Buffer.alloc(chunk);
  let line = new Accumulating();
  // A carriage return is taken off only at a line's end, so one is held
  // back until what follows it is known.
  let heldReturn = false;
  let any = false;
  const end = () => {
    visit(line.done());
    line = new Accumulating();
    any = false;
  };
  for (;;) {
    const read = fs.readSync(fd, buffer, 0, buffer.length, null);
    if (read === 0) {
      break;
    }
    const bytes = buffer.subarray(0, read);
    whole.update(bytes);
    let start = 0;
    for (;;) {
      const at = bytes.indexOf(0x0a, start);
      const piece = bytes.subarray(start, at === -1 ? bytes.length : at);
      if (piece.length > 0) {
        if (heldReturn) {
          line.add(Buffer.from([0x0d]));
        }
        heldReturn = piece[piece.length - 1] === 0x0d;
        line.add(heldReturn ? piece.subarray(0, piece.length - 1) : piece);
        any = true;
      }
      if (at === -1) {
        break;
      }
      heldReturn = false;
      end();
      start = at + 1;
    }
  }
  if (any) {
    // The last line, with no line feed after it, keeps no trailing
    // carriage return either.
    end();
  }
  return whole.digest("hex");
}

// eachRegistryLine hands each line of the registry to visit, in order.
export function eachRegistryLine(anchor: Anchor, visit: (line: Read) => void): void {
  if (anchor.absent) {
    return;
  }
  try {
    withRegular(anchor.path, "the registry", (fd) => eachLine(fd, visit));
  } catch (e) {
    throw unreadable("the registry", anchor.path, e);
  }
}

// digestArtifact is the SHA-256 of the artifact's bytes, read in chunks,
// or null when no artifact is at the path: nothing there, something above
// it that is not a directory, or a directory in its place.
export function digestArtifact(p: string): string | null {
  try {
    return withRegular(p, "the artifact", (fd) => {
      const hash = crypto.createHash("sha256");
      const buffer = Buffer.alloc(chunk);
      for (;;) {
        const read = fs.readSync(fd, buffer, 0, buffer.length, null);
        if (read === 0) {
          return hash.digest("hex");
        }
        hash.update(buffer.subarray(0, read));
      }
    });
  } catch (e) {
    const c = code(e);
    if (c === "ENOENT" || c === "ENOTDIR") {
      return null;
    }
    if (e instanceof NoVerdict && fs.statSync(p, { throwIfNoEntry: false })?.isDirectory()) {
      return null;
    }
    throw unreadable("the artifact", p, e);
  }
}

// eachDecisionRecord walks the directory (§4 step 6) and hands each
// candidate to visit: a regular file whole, and each line of a .jsonl file.
// Step 7 reads a candidate's bytes; a .jsonl file whole comes without
// them, since step 7 reads its lines and not the file. An empty line is no
// candidate.
export function eachDecisionRecord(anchor: Anchor, visit: (candidate: Read) => void): void {
  if (anchor.absent) {
    return;
  }
  const p = anchor.path;
  // The walk takes the directory as its path is spelled and follows no
  // link: named without a trailing separator, a link to a directory is a
  // link, and the walk stops at it; with one, the platform resolves it.
  let top: fs.Stats;
  try {
    top = fs.lstatSync(p);
  } catch (e) {
    throw unreadable("the decision-record directory", p, e);
  }
  if (!top.isDirectory()) {
    return;
  }
  // Names are read as the bytes they are, and paths made of them, so two
  // files whose names decode alike are two candidates.
  const separator = Buffer.from(path.sep);
  const dirs: Buffer[] = [Buffer.from(p)];
  for (let dir = dirs.pop(); dir !== undefined; dir = dirs.pop()) {
    let entries: fs.Dirent<Buffer>[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true, encoding: "buffer" });
    } catch (e) {
      throw unreadable("under the decision-record directory,", dir, e);
    }
    for (const entry of entries) {
      const at = Buffer.concat([dir, separator, entry.name]);
      if (entry.isDirectory()) {
        dirs.push(at);
        continue;
      }
      if (!entry.isFile()) {
        continue; // a link is not followed, and nothing else is a file
      }
      const what = "under the decision-record directory, the file";
      try {
        withRegular(at, what, (fd) => {
          if (endsWith(entry.name, ".jsonl")) {
            const whole = eachLine(fd, (line) => {
              if (line.bytes === null || line.bytes.length > 0) {
                visit(line);
              }
            });
            visit({ digest: whole, bytes: null, opensObject: false });
            return;
          }
          const file = new Accumulating();
          const buffer = Buffer.alloc(chunk);
          for (;;) {
            const read = fs.readSync(fd, buffer, 0, buffer.length, null);
            if (read === 0) {
              break;
            }
            file.add(buffer.subarray(0, read));
          }
          visit(file.done());
        });
      } catch (e) {
        throw unreadable(what, at, e);
      }
    }
  }
}
