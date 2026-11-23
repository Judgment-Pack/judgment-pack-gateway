// The store continuation (SPEC.md §3d; ADR-0048): its form and its
// signature, shared by the store verifier and the key-history check
// (ADR-0055 §11), which holds a version 2 history's continuation lines to it.

import { recordAlg, verifyByAlg } from "./alg.ts";
import { canonical } from "./canon.ts";
import { hasDuplicate, member } from "./json.ts";
import type { Value } from "./json.ts";
import type { ReachedKey } from "./rotation.ts";

// A store continuation that holds its form: its keyId, previousLines,
// previousDigest (digest), continuedAt (at) and keyHistoryDigest (history).
export type Continuation = {
  readonly keyId: string;
  readonly lines: bigint;
  readonly digest: string;
  readonly at: string;
  readonly history: string;
};

// §3d: a registry line is a store continuation when it is one JSON object,
// no name given twice, whose kind is store-continuation.
export function isContinuation(v: Value | null): boolean {
  if (v === null || v.type !== "object" || hasDuplicate(v)) {
    return false;
  }
  const kind = member(v, "kind");
  return kind?.type === "string" && kind.value === "store-continuation";
}

// keyHistoryDigest names the key history the rotation carried beside the
// new registry (§3e), by the SHA-256 of its bytes, of previousDigest's form;
// a verifier is not given that history, and holds the member to its form.
export const continuationMembers = ["kind", "continuationVersion", "continuedAt", "keyId", "previousLines", "previousDigest", "keyHistoryDigest", "signature"];

// continuationOf is a store continuation that holds its form and is signed
// by the key in force at its line, or null.
export function continuationOf(v: Value, key: ReachedKey): Continuation | null {
  if (v.type !== "object") {
    return null;
  }
  // alg among them on a continuation a P-256 key signs (ADR-0053 §2)
  const names = member(v, "alg") !== undefined ? [...continuationMembers, "alg"] : continuationMembers;
  const alg = recordAlg(v, "alg");
  if (alg === null || v.members.length !== names.length || !v.members.every((m) => names.includes(m.name))) {
    return null;
  }
  const s = (name: string, form: RegExp): string | null => {
    const m = member(v, name);
    return m?.type === "string" && form.test(m.value) ? m.value : null;
  };
  const version = s("continuationVersion", /^1$/);
  const at = s("continuedAt", /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
  const keyId = s("keyId", /^[0-9a-f]{32}$/);
  const last = s("previousDigest", /^[0-9a-f]{64}$/);
  const history = s("keyHistoryDigest", /^[0-9a-f]{64}$/);
  const signature = s("signature", /^[0-9a-f]{128}$/);
  const lines = member(v, "previousLines");
  if (version === null || at === null || keyId === null || last === null || history === null || signature === null || lines?.type !== "number" || !/^(0|[1-9][0-9]*)$/.test(lines.text)) {
    return null;
  }
  const body = canonical({ type: "object", members: v.members.filter((m) => m.name !== "signature") });
  if (keyId !== key.keyId || alg !== key.alg || body === null) {
    return null;
  }
  const signed = Buffer.concat([Buffer.from("judgment-pack-gateway/store-continuation/1:", "utf8"), body]);
  if (!verifyByAlg(alg, key, signed, signature)) {
    return null;
  }
  return { keyId, lines: BigInt(lines.text), digest: last, at, history };
}
