import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import mutableFS from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { readDocument } from "../src/inputs.ts";
import { verifyStore } from "../src/verify.ts";
import { acquisitionV3, authority, keyId, newStore, publicKey, put, sealLine, sign, signed, verdictText } from "./support.ts";

const prefix = "judgment-pack-gateway/descriptor-statement/1:";
const mutations: Record<string,string> = JSON.parse(fs.readFileSync(new URL("../../testdata/descriptor-provenance/statement-mutations.json",import.meta.url),"utf8"));
const digest = (raw: string): string => "sha256:" + crypto.createHash("sha256").update(raw).digest("hex");
// All statement members are strings, so this handwritten fixture's canonical
// order can be spelled without the implementation's canonicalizer.
const canonicalText = (o: Record<string,string>): string => JSON.stringify(Object.fromEntries(Object.entries(o).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0)));

function fixture(change?: string, missing?: string, removeMember?: string) {
  const store = newStore();
  const snapshot = '{"tools":{}}';
  const snapshotPin = digest(snapshot);
  const binding = "customer@sha256:" + "1".repeat(64);
  const core: Record<string,string> = {statementVersion:"1",authority,keyId,source:"tickets/live",binding,snapshot:snapshotPin,endpoint:"",capturedAt:"2026-09-15T01:02:03Z"};
  if (change !== undefined && mutations[change] !== undefined) core[change] = mutations[change]!;
  if (removeMember !== undefined && removeMember !== "signature") delete core[removeMember];
  const statement: Record<string,string> = {...core,signature:sign(change === "domain" ? "judgment-pack-gateway/receipt/3:" : prefix,core)};
  if (change === "signature") statement["signature"] = "0".repeat(128);
  if (removeMember === "signature") delete statement["signature"];
  const statementBytes = canonicalText(statement), statementPin = digest(statementBytes);
  fs.writeFileSync(path.join(store.root,"artifacts",snapshotPin.slice(7)),missing === "changed-snapshot" ? "{}" : snapshot);
  fs.writeFileSync(path.join(store.root,"artifacts",statementPin.slice(7)),missing === "changed-statement" ? "{}" : statementBytes);
  if (missing === "snapshot" || missing === "statement") fs.unlinkSync(path.join(store.root,"artifacts",(missing === "snapshot" ? snapshotPin : statementPin).slice(7)));
  const receipt: any = acquisitionV3();
  receipt.source = "tickets/live";
  receipt.acquisition.shape = "mcp";
  receipt.acquisition.descriptorProvenance = {snapshot:snapshotPin,statement:statementPin,binding};
  put(store,"s1","0.json",JSON.stringify(signed(receipt)));
  fs.writeFileSync(store.registry,sealLine("s1",1)+"\n");
  return store;
}

function status(store: ReturnType<typeof fixture>): string {
  const verdict = JSON.parse(verdictText(verifyStore(store.root,store.registry,authority,undefined,publicKey)));
  return verdict.findings.find((f: any) => f.sessionId === "s1" && f.callIndex === 0).status;
}

test("descriptor provenance requires both exact retained artifacts", () => {
  assert.equal(status(fixture()),"ok");
  for (const missing of ["snapshot","statement"]) assert.equal(status(fixture(undefined,missing)),"descriptor-provenance-missing",missing);
  for (const changed of ["changed-snapshot","changed-statement"]) assert.equal(status(fixture(undefined,changed)),"descriptor-provenance-mismatch",changed);
});

test("descriptor artifact limits stop I/O at one byte past the bound", () => {
  const store = fixture();
  const target = path.join(store.root,"oversized");
  fs.writeFileSync(target,Buffer.alloc(1 << 20));
  const original = mutableFS.readSync;
  let readBytes = 0;
  // Observe real reads, without replacing the bounded reader under test.
  mutableFS.readSync = ((...args: any[]) => {
    const n = (original as any)(...args); readBytes += n; return n;
  }) as typeof original;
  syncBuiltinESMExports();
  try {
    for (const limit of [16384,327680]) {
      readBytes = 0;
      assert.throws(() => readDocument(target,"descriptor artifact",limit), /is over/);
      assert.equal(readBytes,limit + 1);
    }
  } finally {
    mutableFS.readSync = original;
    syncBuiltinESMExports();
  }
});

test("descriptor statement claims and signing domain cannot be spliced", () => {
  for (const name of [...Object.keys(mutations),"signature","domain"]) assert.equal(status(fixture(name)),"descriptor-provenance-mismatch",name);
  for (const name of ["statementVersion","authority","keyId","source","binding","snapshot","endpoint","capturedAt","signature"]) assert.equal(status(fixture(undefined,undefined,name)),"descriptor-provenance-mismatch","missing "+name);
});

test("a descriptor statement signed by a later reached key cannot cover an earlier receipt", () => {
  const store = fixture();
  const seed = Buffer.from(fs.readFileSync(new URL("../../corpus/TEST-SEED",import.meta.url),"utf8").trim(),"hex");
  seed[0]! ^= 1;
  const next = crypto.createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),seed]),format:"der",type:"pkcs8"});
  const nextPublic = Buffer.from(crypto.createPublicKey(next).export({format:"jwk"}).x!,"base64url");
  const nextId = crypto.createHash("sha256").update(nextPublic).digest("hex").slice(0,32);
  const nextSign = (domain:string,obj:Record<string,unknown>):string => crypto.sign(null,Buffer.from(domain+JSON.stringify(Object.fromEntries(Object.entries(obj).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0)))),next).toString("hex");
  const receipt: any = JSON.parse(fs.readFileSync(path.join(store.root,"receipts/s1/0.json"),"utf8"));
  const p = receipt.acquisition.descriptorProvenance;
  const st: Record<string,string> = JSON.parse(fs.readFileSync(path.join(store.root,"artifacts",p.statement.slice(7)),"utf8"));
  delete st.signature; st.keyId = nextId;
  st.signature = nextSign(prefix,st);
  const raw = canonicalText(st);p.statement = digest(raw);
  fs.writeFileSync(path.join(store.root,"artifacts",p.statement.slice(7)),raw);
  delete receipt.signature;put(store,"s1","0.json",JSON.stringify(signed(receipt)));
  const common = {rotationVersion:"1",rotation:1,rotatedAt:"2026-09-16T00:00:00Z"};
  const forward = {...common,kind:"key-rotation",keyId,next:nextPublic.toString("hex"),nextKeyId:nextId};
  const reverse = {...common,kind:"key-continuation",keyId:nextId,previous:publicKey.toString("hex"),previousKeyId:keyId};
  fs.appendFileSync(store.registry,JSON.stringify({...forward,signature:sign("judgment-pack-gateway/rotation/1:",forward)})+"\n"+JSON.stringify({...reverse,signature:nextSign("judgment-pack-gateway/rotation/1:",reverse)})+"\n");
  assert.equal(status(store),"descriptor-provenance-mismatch");
});
