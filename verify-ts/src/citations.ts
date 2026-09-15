// A citation of an acquisition receipt, of the shape §1.2a gives
// action.cites, and the flat token (§3a) its session is named by.

import { member, negative } from "./json.ts";
import type { Value } from "./json.ts";

// A citation of the shape §1.2a gives action.cites, its index the decimal
// integer it is written as (-0 as 0): the spelling a receipt file's stem
// is compared to, whatever its length.
export type Citation = { readonly sessionId: string; readonly callIndex: string; readonly signature: string };

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
      !callIndex.integral ||
      negative(callIndex) ||
      signature?.type !== "string" ||
      !/^[0-9a-f]{128}$/.test(signature.value)
    ) {
      return null;
    }
    out.push({ sessionId: sessionId.value, callIndex: callIndex.text === "-0" ? "0" : callIndex.text, signature: signature.value });
  }
  return out;
}

// A flat token (§3a).
export function isFlatToken(s: string): boolean {
  return /^[A-Za-z0-9._-]{1,128}$/.test(s) && s !== "." && s !== "..";
}

