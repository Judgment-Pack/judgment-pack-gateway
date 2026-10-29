import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { parse } from "../src/json.ts";
import { structureV3 } from "../src/structure.ts";
import type { ObjectValue } from "../src/json.ts";
import { acquisitionV3, actionV3, resultDigest, signed } from "./support.ts";

test("action delivery and reconciliation share exact structural mutation rows", () => {
  const rows=JSON.parse(fs.readFileSync(path.join(import.meta.dirname,"../../testdata/action-reconciliation/mutations.json"),"utf8"));
  for (const row of rows) {
    const extension: any={key:"a".repeat(64),contract:"sha256:"+"b".repeat(64),outcome:row.kind === "delivery" ? "uncertain" : "committed"};
    if (row.kind !== "delivery") extension.action={sessionId:"act",callIndex:0,signature:"ab".repeat(64)};
    const target=row.kind === "citation" ? extension.action : extension;
    if (row.remove) delete target[row.member]; else target[row.member]=row.value;
    const receipt: any=row.kind === "delivery" ? actionV3(0,null,[{sessionId:"read",callIndex:0,signature:"ab".repeat(64)}],resultDigest) : acquisitionV3();
    if (row.kind === "delivery") receipt.action.delivery=extension; else receipt.acquisition.reconciliation=extension;
    const parsed=parse(Buffer.from(JSON.stringify(signed(receipt)))) as ObjectValue;
    assert.equal(structureV3(parsed),row.valid,JSON.stringify(row));
  }
});

import * as crypto from "node:crypto";
import { verifyStore } from "../src/verify.ts";
import { authority, newStore, publicKey, put, sealLine, verdictText } from "./support.ts";

test("reconciliation resolves the exact uncertain action and authenticated identity", () => {
  for (const mutation of ["valid","key","contract","signature","session","index","identity","response","missing","tampered"]) {
    const store=newStore();
    const record="{}";
    const recordDigest="sha256:"+crypto.createHash("sha256").update(record).digest("hex");
    fs.mkdirSync(store.decisionRecords,{recursive:true});fs.writeFileSync(path.join(store.decisionRecords,"decision.json"),record);
    const read=signed(acquisitionV3());
    put(store,"s1","0.json",JSON.stringify(read));
    const action: any=actionV3(0,null,[{sessionId:"s1",callIndex:0,signature:read["signature"]}],recordDigest,"act");
    action.action.delivery={key:"a".repeat(64),contract:"sha256:"+"b".repeat(64),outcome:mutation === "response" ? "response" : "uncertain"};
    const signedAction=signed(action);
    if (mutation !== "missing") put(store,"act","0.json",JSON.stringify(mutation === "tampered" ? {...signedAction,source:"tampered"} : signedAction));
    const recon: any=acquisitionV3(0,null,"recon");recon.caller={...action.action.requester,tokenDigest:"sha256:"+"f".repeat(64)};
    const extension: any={key:"a".repeat(64),contract:"sha256:"+"b".repeat(64),outcome:"committed",action:{sessionId:"act",callIndex:0,signature:signedAction["signature"]}};
    if (mutation === "key") extension.key="c".repeat(64);
    if (mutation === "contract") extension.contract="sha256:"+"c".repeat(64);
    if (mutation === "signature") extension.action.signature="ab".repeat(64);
    if (mutation === "session") extension.action.sessionId="s1";
    if (mutation === "index") extension.action.callIndex=1;
    if (mutation === "identity") recon.caller.subject="other";
    recon.acquisition.reconciliation=extension;
    put(store,"recon","0.json",JSON.stringify(signed(recon)));
    fs.writeFileSync(store.registry,[sealLine("s1",1),sealLine("act",1),sealLine("recon",1)].join("\n")+"\n");
    const verdict=JSON.parse(verdictText(verifyStore(store.root,store.registry,authority,store.decisionRecords,publicKey)));
    assert.equal(verdict.findings.some((f:any)=>f.status==="action-reconciliation-unresolved"),mutation!=="valid",mutation);
    if (mutation === "valid") assert.equal(verdict.ok,true);
  }
});
