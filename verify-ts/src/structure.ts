// The structural conditions of §1.4 order 1, by the receipt's version.
// Each is a condition of form -- presence, type, enumeration, shape, the
// form of a string -- and none is relational: whether prevSignature names
// the previous receipt, whether a citation resolves, whether a digest
// matches bytes, is each checked at its own stage.

import { isIPv6 } from "node:net";

import { member, negative } from "./json.ts";
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

// A key id is §1.2's: the first 32 characters of a SHA-256 in hex, whose
// case §1.2 leaves unstated.
function isKeyId(v: Value | undefined): boolean {
  return isString(v) && /^[0-9a-fA-F]{32}$/.test(v.value);
}

function isInteger(v: Value | undefined): boolean {
  return v?.type === "number" && v.integral;
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

// isRemoteEndpoint is the form of a remote MCP server's endpoint (§1.2a,
// ADR-0015; testdata/remote-endpoints/cases.json is the table it is tested
// against): at most 2048 characters, each from U+0021 to U+007E; no "?"
// and no "#"; "https://" or "http://"; then an authority, a host and
// optionally ":" and a port; then nothing, or "/" and a path. The host is
// a name of letters, digits, "-", "." and "_", or "[", an IPv6 address, and
// "]", so no "@" is in the authority and no user is named;
// the port a decimal from 1 to 65535 with no leading zero; and every "%" in
// the path is followed by exactly two hexadecimal digits. An "@" in the
// path names no user, and is a path's character like any other. After "http://", the host is a loopback
// address written as one, an IPv4 address of 127.0.0.0/8 in dotted decimal
// or [::1]; a name is not one, localhost included.
export function isRemoteEndpoint(s: string): boolean {
  if (s.length > 2048 || !/^[\x21-\x7e]*$/.test(s) || /[?#]/.test(s)) {
    return false;
  }
  const scheme = /^(https?):\/\/(.*)$/s.exec(s);
  if (scheme === null) {
    return false;
  }
  const rest = scheme[2]!;
  const slash = rest.indexOf("/");
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? "" : rest.slice(slash + 1);
  const split = splitAuthority(authority);
  if (split === null || split.host === "") {
    return false;
  }
  if (!/^[A-Za-z0-9._-]+$/.test(split.host) && !/^\[[0-9A-Fa-f:.]+\]$/.test(split.host)) {
    return false;
  }
  if (split.host.startsWith("[") && !isIPv6Address(split.host.slice(1, -1))) {
    return false;
  }
  if (split.port !== null && (!/^[1-9][0-9]{0,4}$/.test(split.port) || Number(split.port) > 65535)) {
    return false;
  }
  if (/%(?![0-9A-Fa-f]{2})/.test(path)) {
    return false;
  }
  return scheme[1] === "https" || isLoopbackHost(split.host);
}

// isIPv6Address is an IPv6 address in the form RFC 3986 names IPv6address
// (§1.2a): eight groups of one to four hexadecimal digits separated by ":",
// "::" standing once for one or more groups of zeros, and the last two
// groups optionally an IPv4 address in dotted decimal, each part from 0 to
// 255 with no leading zero; no zone.
function isIPv6Address(s: string): boolean {
  let groups = s;
  let wanted = 8;
  if (s.includes(".")) {
    const colon = s.lastIndexOf(":");
    if (colon < 0 || colon > s.indexOf(".") || !isIPv4Dotted(s.slice(colon + 1))) {
      return false;
    }
    // The address's last two groups are the IPv4 address: what is before
    // it ends in ":", or in "::" when that stands for groups before it.
    groups = s.slice(0, colon + 1);
    groups = groups.endsWith("::") ? groups : groups.slice(0, -1);
    wanted = 6;
  }
  const halves = groups.split("::");
  if (halves.length > 2) {
    return false;
  }
  const written = halves.flatMap((half) => (half === "" ? [] : half.split(":")));
  if (!written.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group))) {
    return false;
  }
  return halves.length === 2 ? written.length < wanted : written.length === wanted;
}

// isIPv4Dotted is an IPv4 address in dotted decimal, each part from 0 to
// 255 with no leading zero.
function isIPv4Dotted(s: string): boolean {
  const octets = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(s);
  return octets !== null && octets.slice(1).every((o) => Number(o) <= 255);
}

// splitAuthority is an authority's host and its port, null when no ":"
// follows the host: a host in brackets runs to the first "]", any other to
// the first ":". It is null itself when the "]" is missing or anything
// but ":" follows it.
function splitAuthority(authority: string): { host: string; port: string | null } | null {
  if (!authority.startsWith("[")) {
    const colon = authority.indexOf(":");
    return colon < 0 ? { host: authority, port: null } : { host: authority.slice(0, colon), port: authority.slice(colon + 1) };
  }
  const end = authority.indexOf("]");
  if (end < 0) {
    return null;
  }
  const host = authority.slice(0, end + 1);
  const rest = authority.slice(end + 1);
  if (rest === "") {
    return { host, port: null };
  }
  return rest.startsWith(":") ? { host, port: rest.slice(1) } : null;
}

// isLoopbackHost is a loopback address written as one: [::1], or an IPv4
// address of 127.0.0.0/8 in dotted decimal, each part from 0 to 255 with
// no leading zero.
function isLoopbackHost(host: string): boolean {
  if (host === "[::1]") {
    return true;
  }
  const octets = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(host);
  return octets !== null && octets[1] === "127" && octets.slice(2).every((o) => Number(o) <= 255);
}

// remoteHolds is what a remote MCP server adds to an acquisition (§1.2a,
// ADR-0015), held to its form, or true when neither member is there:
// transport and server together, on shape mcp alone; transport "http";
// server an object of a string name and a string version, another member
// of it tolerated; the endpoint of a remote server's form; and the peer
// identity "tls:sha256:" and 64 lowercase hex after "https://", null after
// "http://".
function remoteHolds(v: ObjectValue): boolean {
  const transport = member(v, "transport");
  const server = member(v, "server");
  if (transport === undefined && server === undefined) {
    return true;
  }
  const shape = member(v, "shape");
  const endpoint = member(v, "endpoint");
  const peer = member(v, "peerIdentity");
  if (
    !isString(transport) ||
    transport.value !== "http" ||
    server?.type !== "object" ||
    !isString(member(server, "name")) ||
    !isString(member(server, "version")) ||
    !isString(shape) ||
    shape.value !== "mcp" ||
    !isString(endpoint) ||
    !isRemoteEndpoint(endpoint.value)
  ) {
    return false;
  }
  if (endpoint.value.startsWith("https://")) {
    return isString(peer) && /^tls:sha256:[0-9a-f]{64}$/.test(peer.value);
  }
  return peer?.type === "null";
}

export function isActionDelivery(v: Value): boolean {
  if (v.type !== "object" || v.members.length !== 3 || !v.members.every(m => ["key", "contract", "outcome"].includes(m.name))) return false;
  const key = member(v,"key"), outcome = member(v,"outcome");
  return isString(key) && /^[0-9a-f]{64}$/.test(key.value) && isDigest(member(v,"contract")) && isString(outcome) && ["response","uncertain"].includes(outcome.value);
}
export function isActionReconciliation(v: Value): boolean {
  if (v.type !== "object" || v.members.length !== 4 || !v.members.every(m => ["action","key", "contract", "outcome"].includes(m.name))) return false;
  const key = member(v,"key"), outcome = member(v,"outcome"), action = member(v,"action");
  if (action?.type !== "object" || action.members.length !== 3 || !action.members.every(m => ["sessionId","callIndex","signature"].includes(m.name))) return false;
  return isString(key) && /^[0-9a-f]{64}$/.test(key.value) && isDigest(member(v,"contract")) && isString(outcome) && ["committed","unknown"].includes(outcome.value) && citations({type:"array",items:[action]}) !== null;
}

function isAcquisition(v: Value | undefined): boolean {
  if (v?.type !== "object") {
    return false;
  }
  const shape = member(v, "shape");
  const pageItems = member(v, "pageItems");
  const provenance = member(v, "descriptorProvenance");
 const reconciliation=member(v,"reconciliation");
  return (
    (reconciliation===undefined || isActionReconciliation(reconciliation)) &&
 isAdapter(member(v, "adapter")) &&
    isString(shape) &&
    shapes.has(shape.value) &&
    (provenance === undefined || (shape.value === "mcp" && isDescriptorProvenance(provenance))) &&
    nullableString(member(v, "endpoint")) &&
    nullableDigest(member(v, "statement")) &&
    nullableString(member(v, "snapshot")) &&
    nullableString(member(v, "peerIdentity")) &&
    nullableDigest(member(v, "schema")) &&
    nullableString(member(v, "upstreamToken")) &&
    (pageItems === undefined || (pageItems.type === "array" && pageItems.items.every(isDigest))) &&
    isString(member(v, "observedAt")) &&
    remoteHolds(v)
  );
}

export function isBindingReference(s: string): boolean {
  const parts = s.split("@");
  return parts.length === 2 && parts[0] !== "" && parts[0] !== "." && parts[0] !== ".." && !/[\\/]/.test(parts[0]!) && /^sha256:[0-9a-f]{64}$/.test(parts[1]!);
}

function isDescriptorProvenance(v: Value): boolean {
  if (v.type !== "object" || v.members.length !== 3 || !v.members.every(m => ["snapshot", "statement", "binding"].includes(m.name))) return false;
  const binding = member(v, "binding");
  return isDigest(member(v, "snapshot")) && isDigest(member(v, "statement")) && isString(binding) && isBindingReference(binding.value);
}

// toolTransportHolds is what a write to a remote MCP server adds to an
// action's tool (§1.2a, #268), held to its form, or true when it adds
// nothing: transport, when present, is "http", on shape mcp alone, and the
// endpoint is then a string of a remote server's form. Without transport
// the endpoint is the platform's, a string or null, held to nothing more:
// it may even begin with "https://", so its spelling says nothing of the
// transport.
function toolTransportHolds(tool: ObjectValue): boolean {
  const transport = member(tool, "transport");
  if (transport === undefined) {
    return true;
  }
  const shape = member(tool, "shape");
  const endpoint = member(tool, "endpoint");
  return (
    isString(transport) &&
    transport.value === "http" &&
    isString(shape) &&
    shape.value === "mcp" &&
    isString(endpoint) &&
    isRemoteEndpoint(endpoint.value)
  );
}

function isAction(v: Value | undefined): boolean {
  if (v?.type !== "object") {
    return false;
  }
  const decision = member(v, "decision");
  const recordBytes = decision?.type === "object" ? member(decision, "recordBytes") : undefined;
  const cites = member(v, "cites");
  const tool = member(v, "tool");
  const policy = member(v, "policy");
 const delivery=member(v,"delivery");
  return (
    (delivery===undefined || isActionDelivery(delivery)) &&
 isIdentity(member(v, "requester")) &&
    decision?.type === "object" &&
    isDigest(member(decision, "recordDigest")) &&
    isDigest(member(decision, "packDigest")) &&
    // how the record was found: optional, and "exact" when present
    (recordBytes === undefined || (recordBytes.type === "string" && recordBytes.value === "exact")) &&
    cites !== undefined &&
    citations(cites) !== null &&
    tool?.type === "object" &&
    isString(member(tool, "shape")) &&
    nullableString(member(tool, "endpoint")) &&
    isString(member(tool, "name")) &&
    // a write to a remote server: its transport, and its endpoint of the form
    toolTransportHolds(tool) &&
    isDigest(member(v, "request")) &&
    // the policy the write was held to: optional, and a digest when present
    (policy === undefined || isDigest(policy)) &&
    isAdapter(member(v, "adapter")) &&
    isString(member(v, "observedAt"))
  );
}

// isWitnessOrigin is the form of a witness's origin (§1.2a, ADR-0014):
// "https://" or "http://", a host in lowercase, ":" and a port in decimal
// with no leading zero, from 1 to 65535, and nothing after; "http" only
// with a loopback address written as one -- an IPv4 address of
// 127.0.0.0/8 in dotted decimal, or [::1] -- and at most 2048 characters.
// A host is a name of lowercase letters, digits and hyphens in labels
// joined by single dots, or an IPv6 address of lowercase hexadecimal and
// colons in brackets.
export function isWitnessOrigin(s: string): boolean {
  if (s.length > 2048) {
    return false;
  }
  const scheme = /^(https?):\/\/(.*)$/s.exec(s);
  if (scheme === null) {
    return false;
  }
  const rest = scheme[2]!;
  const colon = rest.lastIndexOf(":");
  if (colon < 0) {
    return false;
  }
  const host = rest.slice(0, colon);
  const port = rest.slice(colon + 1);
  if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535) {
    return false;
  }
  if (scheme[1] === "http") {
    if (host === "[::1]") {
      return true;
    }
    const octets = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(host);
    return octets !== null && octets[1] === "127" && octets.slice(2).every((o) => Number(o) <= 255);
  }
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(host)) {
    return true;
  }
  return /^\[[0-9a-f:]+\]$/.test(host) && isIPv6(host.slice(1, -1));
}

// isWitness is the witness member's form (§1.2a): an object whose origin
// is a witness's origin and whose keyId and trail are each 32 lowercase
// hexadecimal characters. A member it does not name is tolerated.
function isWitness(v: Value | undefined): boolean {
  if (v?.type !== "object") {
    return false;
  }
  const origin = member(v, "origin");
  const keyId = member(v, "keyId");
  const trail = member(v, "trail");
  return (
    isString(origin) &&
    isWitnessOrigin(origin.value) &&
    isString(keyId) &&
    /^[0-9a-f]{32}$/.test(keyId.value) &&
    isString(trail) &&
    /^[0-9a-f]{32}$/.test(trail.value)
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
  const witness = member(r, "witness");
  if (
    !isString(sessionId) ||
    !isFlatToken(sessionId.value) ||
    callIndex?.type !== "number" ||
    !callIndex.integral ||
    negative(callIndex) ||
    !nullableString(member(r, "prevSignature")) ||
    !isString(member(r, "source")) ||
    !isDigest(member(r, "resultDigest")) ||
    !isString(member(r, "servedAt")) ||
    !isString(member(r, "authority")) ||
    !isKeyId(member(r, "keyId")) ||
    !isString(signature) ||
    !signatureV3Form.test(signature.value) ||
    !isDigest(member(r, "argumentsCommitment")) ||
    !(caller?.type === "null" || isIdentity(caller)) ||
    member(r, "argumentsDigest") !== undefined ||
    // the witness the receipt names: optional, of its form when present
    (witness !== undefined && !isWitness(witness)) ||
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
