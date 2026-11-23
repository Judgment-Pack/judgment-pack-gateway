// The dry-run receipt (SPEC.md §1.2c; ADR-0054 decision 2): a signed form of
// its own, under its own prefix, with no receiptVersion. verifyStore finds
// it malformed wherever a store holds it; verifyDryRun checks it as itself
// and reads no store.

import { canonical } from "./canon.ts";
import { hasDuplicate, member, parse } from "./json.ts";
import type { ObjectValue } from "./json.ts";
import { es256, keyObject, recordAlg, verifyByAlg } from "./alg.ts";
import type { Pin } from "./alg.ts";
import { delegationHolds, isActionClaims, isScopeIdentifier } from "./structure.ts";
import { keyIdOf } from "./verify.ts";

export const dryRunPrefix = "judgment-pack-gateway/dry-run/1:";

// true where required
const dryRunMembers: Record<string, boolean> = { dryRunVersion: true, authority: true, keyId: true, servedAt: true, signature: true, source: true, action: true, scope: false, delegation: false, alg: false };
const actionMembers: Record<string, boolean> = { requester: true, decision: true, cites: true, tool: true, request: true, policy: false, approvals: false };

export type DryRunReport = { readonly ok: boolean; readonly findings: ReadonlyArray<{ readonly status: string }>; readonly dryRun: true };

// verifyDryRun: malformed for a form error, key-mismatch for a keyId or alg
// that is not the pinned key's, signature-mismatch otherwise; dryRun is true
// in every report.
export function verifyDryRun(bytes: Uint8Array, publicKey: Uint8Array | Pin): DryRunReport {
  const status = dryRunStatus(bytes, publicKey);
  return status === null ? { ok: true, findings: [], dryRun: true } : { ok: false, findings: [{ status }], dryRun: true };
}

function exactly(o: ObjectValue, members: Record<string, boolean>): boolean {
  const names = new Set(o.members.map((m) => m.name));
  return o.members.every((m) => Object.hasOwn(members, m.name)) && Object.entries(members).every(([name, required]) => !required || names.has(name));
}

function text(o: ObjectValue, name: string): string | undefined {
  const v = member(o, name);
  return v?.type === "string" ? v.value : undefined;
}

function dryRunStatus(bytes: Uint8Array, publicKey: Uint8Array | Pin): string | null {
  let parsed;
  try {
    parsed = parse(bytes);
  } catch {
    return "malformed";
  }
  if (parsed === null || parsed.type !== "object" || hasDuplicate(parsed) || !dryRunForm(parsed)) {
    return "malformed";
  }
  // canonical JSON before the key, as the Go verifier refuses a value
  // canonical JSON admits none of when it parses
  const body = canonical({ type: "object", members: parsed.members.filter((m) => m.name !== "signature") });
  if (body === null) {
    return "malformed";
  }
  const raw = publicKey instanceof Uint8Array ? publicKey : Buffer.from(publicKey.key, "hex");
  const pinAlg = publicKey instanceof Uint8Array ? "" : es256;
  const alg = recordAlg(parsed, "alg");
  if (text(parsed, "keyId") !== keyIdOf(raw) || alg !== pinAlg) {
    return "key-mismatch";
  }
  const message = Buffer.concat([Buffer.from(dryRunPrefix, "utf8"), body]);
  return verifyByAlg(alg, { alg: pinAlg, key: keyObject(pinAlg, raw) }, message, text(parsed, "signature")!) ? null : "signature-mismatch";
}

function dryRunForm(r: ObjectValue): boolean {
  if (!exactly(r, dryRunMembers) || text(r, "dryRunVersion") !== "1" || text(r, "authority") === undefined || text(r, "servedAt") === undefined) {
    return false;
  }
  const keyId = text(r, "keyId");
  const signature = text(r, "signature");
  const source = text(r, "source");
  const scope = member(r, "scope");
  if (keyId === undefined || !/^[0-9a-f]{32}$/.test(keyId) || signature === undefined || !/^[0-9a-f]{128}$/.test(signature) || recordAlg(r, "alg") === null) {
    return false;
  }
  if (source === undefined || !source.endsWith("/write") || source.length === "/write".length) {
    return false;
  }
  if (scope !== undefined && !(scope.type === "string" && isScopeIdentifier(scope.value))) {
    return false;
  }
  const action = member(r, "action");
  if (!isActionClaims(action) || !exactly(action, actionMembers)) {
    return false;
  }
  // §11.7's form, with the requester standing for the caller a dry-run
  // receipt does not carry.
  const delegation = member(r, "delegation");
  return delegation === undefined || delegationHolds({ type: "object", members: [{ name: "caller", value: member(action, "requester")! }, { name: "action", value: action }, { name: "delegation", value: delegation }] }, "action");
}
