package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"encoding/json"
)

// ResearchBindingDescriptor is installation metadata, never a portable profile,
// receipt, permission grant, or assertion about the truth of a source. The host
// supplies its Gateway key/authority and source name when registering a profile.
// Only the trusted adapter executable can report its own acquisition identity.
//
// Version 2 (ADR-0019) adds the request schema's version, and the result
// schema and its version; the members of version 1 keep their meaning, and
// the request schema is the one acquisition enforces, generated from the same
// table.
type ResearchBindingDescriptor struct {
	Version              int                 `json:"version"`
	Shape                string              `json:"shape"`
	Adapter              attachment.Identity `json:"adapter"`
	Endpoint             string              `json:"endpoint"`
	Research             Research            `json:"research"`
	FixedArguments       map[string]string   `json:"fixedArguments"`
	RequestSchema        json.RawMessage     `json:"requestSchema"`
	RequestSchemaVersion string              `json:"requestSchemaVersion"`
	ResultRecord         string              `json:"resultRecord"`
	ResultSchema         json.RawMessage     `json:"resultSchema"`
	ResultSchemaVersion  string              `json:"resultSchemaVersion"`
}

// ResearchBindingVersion is the version of the description
// --describe-research writes.
const ResearchBindingVersion = 2

// searchEndpoint is shared by acquisition and read-only binding discovery. Never
// reproduce provider URL construction in a consumer or infer it from a model name.
func searchEndpoint(c SearchConnection) string {
	if c.Provider == "tavily" {
		return "https://api.tavily.com/search"
	}
	host := "aiplatform.googleapis.com"
	if c.Location != "global" {
		host = c.Location + "-" + host
	}
	return "https://" + host + "/v1/projects/" + c.Project + "/locations/" + c.Location + "/publishers/google/models/" + c.Model + ":generateContent"
}

// DescribeSearchBinding reads the exact named revision without acquisition,
// credential output or request charging. A later read still checks the current
// revision, policy, setup and daily budget; discovery grants none of these.
func DescribeSearchBinding(s *Store, raw []byte) ([]byte, error) {
	var q struct {
		Connection string `json:"connection"`
		Revision   string `json:"revision"`
	}
	if decode(raw, &q) != nil || !searchID.MatchString(q.Connection) || !opaque.MatchString(q.Revision) {
		return nil, ErrRequest
	}
	var c SearchConnection
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Search == nil {
			return ErrConnect
		}
		for _, candidate := range v.Search.Connections {
			if candidate.ID != q.Connection {
				continue
			}
			if candidate.Revision != q.Revision {
				return ErrChanged
			}
			if !searchValid(candidate) {
				return ErrSetup
			}
			c = candidate
			return nil
		}
		return ErrConnect
	})
	if err != nil {
		return nil, err
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, ErrProvider
	}
	identity.Name = "adapter-sources"
	versions, known := searchSchemaVersions[c.Provider]
	request, err := canon.EncodeJSON(searchRequestSchema(c))
	if err != nil || !known {
		return nil, ErrProvider
	}
	result, err := canon.EncodeJSON(searchResultSchema(c))
	if err != nil {
		return nil, ErrProvider
	}
	return canon.EncodeJSON(ResearchBindingDescriptor{Version: ResearchBindingVersion, Shape: "http", Adapter: identity, Endpoint: searchEndpoint(c), Research: *searchResearch(c), FixedArguments: map[string]string{"connection": c.ID, "revision": c.Revision}, RequestSchema: request, RequestSchemaVersion: versions.request, ResultRecord: "web-search-v1", ResultSchema: result, ResultSchemaVersion: versions.result})
}
