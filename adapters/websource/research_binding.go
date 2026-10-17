package websource

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"encoding/json"
)

// PageBindingDescriptor describes the installed page reader, not a profile,
// acquisition, permission or statement about a page's contents. The consumer
// supplies its reviewed endpoint rule and Gateway identity when making a profile.
type PageBindingDescriptor struct {
	Version  int                 `json:"version"`
	Shape    string              `json:"shape"`
	Adapter  attachment.Identity `json:"adapter"`
	Endpoint *string             `json:"endpoint"`
	Research struct {
		Capabilities []string `json:"capabilities"`
	} `json:"research"`
	FixedArguments map[string]string `json:"fixedArguments"`
	RequestSchema  json.RawMessage   `json:"requestSchema"`
	ResultRecord   string            `json:"resultRecord"`
}

// pageIdentity is shared by description, page reads and discovery. It reports
// the actual running executable and version; a consumer never reconstructs them.
func pageIdentity() (attachment.Identity, error) {
	identity, err := document.OwnIdentity()
	if err != nil {
		return attachment.Identity{}, ErrProcessing
	}
	identity.Name = "adapter-web"
	return identity, nil
}

// DescribeResearchBinding performs no acquisition, reads no request or private
// configuration, and makes no receipt. Endpoint is null because the reader has
// no fixed endpoint; this grants neither a wildcard nor any other endpoint rule.
func DescribeResearchBinding() ([]byte, error) {
	identity, err := pageIdentity()
	if err != nil {
		return nil, err
	}
	argument := func() map[string]any {
		return map[string]any{
			"type": "string", "minLength": 1, "maxLength": 4096,
			"description": "A public HTTPS URL, at most 4096 UTF-8 bytes. The adapter additionally checks URL form, public network addresses and access policy at acquisition.",
		}
	}
	schema, err := canon.EncodeJSON(map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object", "additionalProperties": false,
		"required":    []string{"url"},
		"properties":  map[string]any{"url": argument(), "site": argument()},
		"description": "One page-read request, at most 8192 UTF-8 JSON bytes. Optional site enables the existing same-origin robots-aware read; omitted site is a plain read. Operator redirect and document-processing settings are never request arguments.",
	})
	if err != nil {
		return nil, ErrProcessing
	}
	d := PageBindingDescriptor{Version: 1, Shape: "http", Adapter: identity,
		FixedArguments: map[string]string{}, RequestSchema: schema,
		ResultRecord: "attachment-v" + attachment.Version}
	d.Research.Capabilities = []string{"page"}
	return canon.EncodeJSON(d)
}
