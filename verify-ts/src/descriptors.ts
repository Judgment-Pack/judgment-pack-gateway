// SPEC.md §9: the optional, signed MCP descriptor reference. The snapshot is
// checked as exact bytes; this verifier does not interpret its tool schemas.
import * as crypto from "node:crypto";
import * as path from "node:path";
import { canonical } from "./canon.ts";
import { readDocument } from "./inputs.ts";
import { hasDuplicate, member, parse } from "./json.ts";
import type { ObjectValue } from "./json.ts";
import type { ReachedKey } from "./rotation.ts";
import { isRemoteEndpoint } from "./structure.ts";

export type DescriptorStatus = "ok" | "descriptor-provenance-missing" | "descriptor-provenance-mismatch";
const text = (o: ObjectValue, name: string): string | undefined => {
  const v = member(o, name); return v?.type === "string" ? v.value : undefined;
};
const digest = (raw: Uint8Array): string => "sha256:" + crypto.createHash("sha256").update(raw).digest("hex");

export function descriptorStatus(root: string, receipt: ObjectValue, keys: readonly ReachedKey[]): DescriptorStatus {
  const acquisition = member(receipt, "acquisition");
  if (acquisition?.type !== "object") return "ok";
  const p = member(acquisition, "descriptorProvenance");
  if (p?.type !== "object") return "ok"; // lexical validation already holds its form
  const snapshotPin = text(p,"snapshot")!, statementPin = text(p,"statement")!;
  let snapshot: Uint8Array, statement: Uint8Array;
  try {
    snapshot = readDocument(path.join(root,"artifacts",snapshotPin.slice(7)),"descriptor snapshot",327680);
    statement = readDocument(path.join(root,"artifacts",statementPin.slice(7)),"descriptor statement",16384);
  } catch { return "descriptor-provenance-missing"; }
  const fail = "descriptor-provenance-mismatch";
  if (digest(snapshot) !== snapshotPin || digest(statement) !== statementPin) return fail;
  const obj = parse(statement);
  if (obj?.type !== "object" || hasDuplicate(obj)) return fail;
  const bytes = canonical(obj);
  if (bytes === null || !Buffer.from(bytes).equals(Buffer.from(statement))) return fail;
  const names = ["statementVersion","authority","keyId","source","binding","snapshot","endpoint","capturedAt","signature"];
  if (obj.members.length !== names.length || !obj.members.every(m => names.includes(m.name) && m.value.type === "string")) return fail;
  if (text(obj,"statementVersion") !== "1" || text(obj,"authority") !== text(receipt,"authority") || text(obj,"source") !== text(receipt,"source") || text(obj,"binding") !== text(p,"binding") || text(obj,"snapshot") !== snapshotPin) return fail;
  const at = text(obj,"capturedAt")!, endpoint = text(obj,"endpoint")!, signature = text(obj,"signature")!, keyId = text(obj,"keyId")!;
  if (!/^[0-9a-f]{32}$/.test(keyId) || !/^[0-9a-f]{128}$/.test(signature) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(at)) return fail;
  const timestamp = Date.parse(at);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== at.replace("Z",".000Z")) return fail;
  // A remote acquisition (transport "http") is covered only by a statement
  // naming its same, nonempty endpoint; an empty one is a local capture.
  const remote = text(acquisition,"transport") === "http";
  if ((endpoint !== "" || remote) && (!isRemoteEndpoint(endpoint) || endpoint !== text(acquisition,"endpoint"))) return fail;
  const core: ObjectValue = {type:"object",members:obj.members.filter(m => m.name !== "signature")};
  const input = Buffer.concat([Buffer.from("judgment-pack-gateway/descriptor-statement/1:","utf8"),canonical(core)!]);
  const key = keys.find(k => k.keyId === keyId);
  return key !== undefined && crypto.verify(null,input,key.key,Buffer.from(signature,"hex")) ? "ok" : fail;
}
