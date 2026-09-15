// The structural conditions of §1.4 order 1, by the receipt's version.
// Each is a condition of form -- presence, type, enumeration, shape, the
// form of a string -- and none is relational: whether prevSignature names
// the previous receipt, whether a citation resolves, whether a digest
// matches bytes, is each checked at its own stage.

import { member } from "./json.ts";
import type { ObjectValue, Value } from "./json.ts";
import { citations, isFlatToken } from "./citations.ts";

const digestForm = /^sha256:[0-9a-f]{64}$/;
const signatureV3Form = /^[0-9a-f]{128}$/;

function isString(v: Value | undefined): v is Extract<Value, { type: "string" }> {
  return v?.type === "string";
}

function isDigest(v: Value | undefined): boolean {
  return isString(v) && digestForm.test(v.value);
}

function isInteger(v: Value | undefined): boolean {
  return v?.type === "number" && v.integer !== null;
}

// A nullable member is present, as null or as its stated shape.
function nullableString(v: Value | undefined): boolean {
  return v?.type === "null" || isString(v);
}

function nullableDigest(v: Value | undefined): boolean {
  return v?.type === "null" || isDigest(v);
}

// structureV2 is order 1 for a receipt that is not version 3 (§1.4): a
// signature present and hex, callIndex an integer, and resultDigest a
// digest. A version 2 signature's hex may be of either case; one of
// another length than an Ed25519 signature's fails at order 4.
export function structureV2(r: ObjectValue): boolean {
  const signature = member(r, "signature");
  return (
    isString(signature) &&
    /^(?:[0-9a-fA-F]{2})*$/.test(signature.value) &&
    isInteger(member(r, "callIndex")) &&
    isDigest(member(r, "resultDigest"))
  );
}

// An identity: the issuer and subject of a verified token, and the digest
// of its bytes.
function isIdentity(v: Value | undefined): boolean {
  return (
    v?.type === "object" &&
    isString(member(v, "issuer")) &&
    isString(member(v, "subject")) &&
    isDigest(member(v, "tokenDigest"))
  );
}

// An adapter: the program that fetched or performed, by name, version and
// digest.
function isAdapter(v: Value | undefined): boolean {
  return (
    v?.type === "object" &&
    isString(member(v, "name")) &&
    isString(member(v, "version")) &&
    isDigest(member(v, "digest"))
  );
}

const shapes = new Set(["airbyte", "mcp", "http", "command"]);

function isAcquisition(v: Value | undefined): boolean {
  if (v?.type !== "object") {
    return false;
  }
  const shape = member(v, "shape");
  const pageItems = member(v, "pageItems");
  return (
    isAdapter(member(v, "adapter")) &&
    isString(shape) &&
    shapes.has(shape.value) &&
    nullableString(member(v, "endpoint")) &&
    nullableDigest(member(v, "statement")) &&
    nullableString(member(v, "snapshot")) &&
    nullableString(member(v, "peerIdentity")) &&
    nullableDigest(member(v, "schema")) &&
    nullableString(member(v, "upstreamToken")) &&
    (pageItems === undefined || (pageItems.type === "array" && pageItems.items.every(isDigest))) &&
    isString(member(v, "observedAt"))
  );
}

function isAction(v: Value | undefined): boolean {
  if (v?.type !== "object") {
    return false;
  }
  const decision = member(v, "decision");
  const cites = member(v, "cites");
  const tool = member(v, "tool");
  return (
    isIdentity(member(v, "requester")) &&
    decision?.type === "object" &&
    isDigest(member(decision, "recordDigest")) &&
    isDigest(member(decision, "packDigest")) &&
    cites !== undefined &&
    citations(cites) !== null &&
    tool?.type === "object" &&
    isString(member(tool, "shape")) &&
    nullableString(member(tool, "endpoint")) &&
    isString(member(tool, "name")) &&
    isDigest(member(v, "request")) &&
    isAdapter(member(v, "adapter")) &&
    isString(member(v, "observedAt"))
  );
}

// structureV3 is order 1 for a version 3 receipt (§1.2a): every structural
// constraint it states. A member it does not name is tolerated at any
// depth, a signed one being the signer's own -- but for argumentsDigest,
// which it says does not exist in version 3.
export function structureV3(r: ObjectValue): boolean {
  const sessionId = member(r, "sessionId");
  const callIndex = member(r, "callIndex");
  const signature = member(r, "signature");
  const kind = member(r, "kind");
  const caller = member(r, "caller");
  const acquisition = member(r, "acquisition");
  const action = member(r, "action");
  if (
    !isString(sessionId) ||
    !isFlatToken(sessionId.value) ||
    callIndex?.type !== "number" ||
    callIndex.integer === null ||
    callIndex.integer < 0n ||
    !nullableString(member(r, "prevSignature")) ||
    !isString(member(r, "source")) ||
    !isDigest(member(r, "resultDigest")) ||
    !isString(member(r, "servedAt")) ||
    !isString(member(r, "authority")) ||
    !isString(member(r, "keyId")) ||
    !isString(signature) ||
    !signatureV3Form.test(signature.value) ||
    !isDigest(member(r, "argumentsCommitment")) ||
    !(caller?.type === "null" || isIdentity(caller)) ||
    member(r, "argumentsDigest") !== undefined ||
    !isString(kind)
  ) {
    return false;
  }
  switch (kind.value) {
    case "acquisition":
      return action === undefined && isAcquisition(acquisition);
    case "action":
      return acquisition === undefined && isAction(action);
    default:
      return false;
  }
}
