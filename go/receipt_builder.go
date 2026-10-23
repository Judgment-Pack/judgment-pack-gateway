package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// receiptInput separates path-specific preparation from the common signed
// members of SPEC.md §1.2 and §1.2a. Callers retain artifacts, draw salts and
// capture servedAt before constructing this input; building does no I/O.
// detail is the acquisition or action object named by kind in version 3.
// Version 2 uses argumentsSeed and omits every version 3 member.
type receiptInput struct {
	version, sessionID, prevSignature         string
	callIndex                                 int64
	source, resultDigest, servedAt, authority string
	arguments, argumentsSalt, argumentsSeed   []byte
	who                                       *caller
	witness                                   *vObject
	kind                                      string
	detail                                    *vObject
}

// buildReceipt assembles the unsigned core. keyId and signature remain the
// store's responsibility, alongside the existing atomic write and ownership
// checks; neither production path signs or stores through this builder.
func buildReceipt(in receiptInput) *vObject {
	core := newObject()
	core.set("receiptVersion", vString(in.version))
	core.set("sessionId", vString(in.sessionID))
	core.set("callIndex", vInt(in.callIndex))
	if in.prevSignature == "" {
		core.set("prevSignature", vNull{})
	} else {
		core.set("prevSignature", vString(in.prevSignature))
	}
	core.set("source", vString(in.source))
	core.set("resultDigest", vString(in.resultDigest))
	core.set("servedAt", vString(in.servedAt))
	core.set("authority", vString(in.authority))
	if in.version == receiptVersion3 {
		core.set("argumentsCommitment", vString(commitmentOver(in.argumentsSalt, "args:", in.arguments)))
		core.set("kind", vString(in.kind))
		if in.who == nil {
			core.set("caller", vNull{})
		} else {
			core.set("caller", identityObject(in.who))
		}
		if in.witness != nil {
			core.set("witness", in.witness)
		}
		core.set(in.kind, in.detail)
	} else {
		mac := hmac.New(sha256.New, argumentsKey(in.argumentsSeed))
		mac.Write(append([]byte("args:"), in.arguments...))
		core.set("argumentsDigest", vString("hmac-sha256:"+hex.EncodeToString(mac.Sum(nil))))
	}
	return core
}
