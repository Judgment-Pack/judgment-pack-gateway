// A citation of an acquisition receipt, of the shape §1.2a gives
// action.cites, and the flat token (§3a) its session is named by.

import { member } from "./json.ts";
import type { Value } from "./json.ts";

// A citation of the shape §1.2a gives action.cites.
export type Citation = { readonly sessionId: string; readonly callIndex: bigint; readonly signature: string };

// citations is the value as a list of citations, or null when it is not an
// array of objects of that shape.
export function citations(v: Value): Citation[] | null {
  if (v.type !== "array") {
    return null;
  }
  const out: Citation[] = [];
  for (const item of v.items) {
    if (item.type !== "object") {
      return null;
    }
    const sessionId = member(item, "sessionId");
    const callIndex = member(item, "callIndex");
    const signature = member(item, "signature");
    if (
      sessionId?.type !== "string" ||
      !isFlatToken(sessionId.value) ||
      callIndex?.type !== "number" ||
      callIndex.integer === null ||
      callIndex.integer < 0n ||
      signature?.type !== "string" ||
      !/^[0-9a-f]{128}$/.test(signature.value)
    ) {
      return null;
    }
    out.push({ sessionId: sessionId.value, callIndex: callIndex.integer, signature: signature.value });
  }
  return out;
}

// A flat token (§3a).
export function isFlatToken(s: string): boolean {
  return /^[A-Za-z0-9._-]{1,128}$/.test(s) && s !== "." && s !== "..";
}

