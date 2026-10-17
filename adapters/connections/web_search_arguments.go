package connections

// The arguments of a search, held to one table (ADR-0019). The table is what
// acquisition enforces and what --describe-research describes: the request
// schema is generated from it, never written beside it, so the two cannot
// say different things. An argument the table does not give the connection's
// provider is refused by name, and so is a value out of its form, before
// anything is charged or sent.

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"adapters/internal/canon"
)

const (
	// searchQueryBytes bounds a query, and each search a grounded answer
	// names, in bytes of UTF-8.
	searchQueryBytes = 2000
	// searchResultsMax is the most hits a request may ask for and a result
	// holds.
	searchResultsMax = 10
	// searchDomainsMax is the most domains a list may name: fewer than any
	// provider that takes a list documents.
	searchDomainsMax = 20
	// searchDomainBytes is the longest name of a domain.
	searchDomainBytes = 253

	searchTitleBytes       = 512
	searchSnippetBytes     = 2000
	searchAnswerBytes      = 12000
	searchAttributionBytes = 32000
	searchQueriesMax       = 20
	searchURLBytes         = 4096
)

// searchDomainPattern is a domain name as a request may give one: two or
// more labels of lowercase letters, digits and hyphens, separated by dots,
// each label 1 to 63 characters that neither begin nor end with a hyphen.
// No scheme, path, port, wildcard, capital or final dot.
const searchDomainPattern = `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`

var searchDomain = regexp.MustCompile(searchDomainPattern)

// The kinds of form an argument may have.
const (
	formConnection = "connection" // a saved connection's name; the schema gives the connection's own
	formRevision   = "revision"   // a revision; the schema gives the connection's present one
	formText       = "text"       // min to max bytes of UTF-8, no control character
	formInteger    = "integer"    // an integer from min to max
	formChoice     = "choice"     // one of choices
	formDomains    = "domains"    // a list of min to max distinct domain names
)

type searchForm struct {
	kind     string
	min, max int
	choices  []string
}

// searchArgument is a row of the table: an argument by its name as a caller
// writes it, whether every request carries it, the providers whose
// connections take it, the member of Tavily's request it is sent as, as
// given ("" where it is not sent so), its form, and what the schema says of
// it beyond the form.
type searchArgument struct {
	name      string
	required  bool
	providers []string
	tavily    string
	form      searchForm
	about     string
}

var searchBothProviders = []string{"tavily", "google-grounding"}

// searchArguments is the table. Its order is the order in which a request's
// arguments are checked, and so which refusal a request with several faults
// is given. A Google connection is sent the query inside the adapter's own
// instruction, and maxResults bounds the links its answer keeps; neither is
// sent to Google as an argument of its own.
var searchArguments = []searchArgument{
	{"connection", true, searchBothProviders, "", searchForm{kind: formConnection}, ""},
	{"revision", true, searchBothProviders, "", searchForm{kind: formRevision}, ""},
	{"query", true, searchBothProviders, "query", searchForm{kind: formText, min: 1, max: searchQueryBytes}, ""},
	{"maxResults", true, searchBothProviders, "max_results", searchForm{kind: formInteger, min: 1, max: searchResultsMax}, ""},
	{"includeDomains", false, []string{"tavily"}, "include_domains", searchForm{kind: formDomains, min: 1, max: searchDomainsMax},
		"Only results from these domains: sent to Tavily as include_domains, as given, for Tavily to apply; the adapter does not hold the hits to it."},
	{"excludeDomains", false, []string{"tavily"}, "exclude_domains", searchForm{kind: formDomains, min: 1, max: searchDomainsMax},
		"No results from these domains: sent to Tavily as exclude_domains, as given, for Tavily to apply; the adapter does not hold the hits to it."},
	{"timeRange", false, []string{"tavily"}, "time_range", searchForm{kind: formChoice, choices: []string{"day", "week", "month", "year"}},
		"Only results from this span of time back from the request: sent to Tavily as time_range, as given, for Tavily to apply."},
}

// tavilyFixed is what the adapter asks of Tavily whatever the request: a
// basic search, no generated answer and no page content. No argument is
// sent as one of these members.
var tavilyFixed = map[string]any{"search_depth": "basic", "include_answer": false, "include_raw_content": false}

// The schema versions. A change of what searchRequestSchema or
// searchResultSchema writes for a provider is a new version of that schema;
// TestSearchSchemaVersionsNameOneSchemaEach holds each version to the digest
// of what it was when it was given.
var searchSchemaVersions = map[string]struct{ request, result string }{
	"tavily":           {"tavily-request-1", "tavily-result-1"},
	"google-grounding": {"google-grounding-request-1", "google-grounding-result-1"},
}

// searchOptions are the arguments of a request past the four every request
// carries, each by its name, as read.
type searchOptions map[string]any

func (a searchArgument) takes(provider string) bool { return slices.Contains(a.providers, provider) }

func searchArgumentNamed(name string) (searchArgument, bool) {
	for _, a := range searchArguments {
		if a.name == name {
			return a, true
		}
	}
	return searchArgument{}, false
}

// holds reports whether a value read from a request is in the form.
func (f searchForm) holds(v any) bool {
	switch f.kind {
	case formConnection:
		s, ok := v.(string)
		return ok && searchID.MatchString(s)
	case formRevision:
		s, ok := v.(string)
		return ok && opaque.MatchString(s)
	case formText:
		s, ok := v.(string)
		return ok && len(s) >= f.min && resourceText(s, f.max, false)
	case formInteger:
		n, ok := v.(int)
		return ok && n >= f.min && n <= f.max
	case formChoice:
		s, ok := v.(string)
		return ok && slices.Contains(f.choices, s)
	case formDomains:
		list, ok := v.([]string)
		if !ok || len(list) < f.min || len(list) > f.max {
			return false
		}
		seen := map[string]bool{}
		for _, d := range list {
			if len(d) > searchDomainBytes || !searchDomain.MatchString(d) || seen[d] {
				return false
			}
			seen[d] = true
		}
		return true
	}
	return false
}

// read takes a member's value as written: a string, an integer or a list of
// strings, as the form is. A value of another JSON type reads as nothing,
// which no form holds.
func (f searchForm) read(raw json.RawMessage) any {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	switch f.kind {
	case formInteger:
		n, err := strconv.ParseInt(string(raw), 10, 32)
		if err != nil {
			return nil
		}
		return int(n)
	case formDomains:
		if raw[0] != '[' {
			return nil
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return nil
		}
		list := make([]string, 0, len(items))
		for _, item := range items {
			s, ok := readString(item)
			if !ok {
				return nil
			}
			list = append(list, s)
		}
		return list
	default:
		if s, ok := readString(raw); ok {
			return s
		}
		return nil
	}
}

func readString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// says is the form in words, for a refusal.
func (f searchForm) says() string {
	switch f.kind {
	case formConnection:
		return "the name of a saved connection: a lowercase letter, then up to 47 lowercase letters, digits and hyphens"
	case formRevision:
		return "a revision: 64 lowercase hexadecimal characters"
	case formText:
		return "text of " + strconv.Itoa(f.min) + " to " + strconv.Itoa(f.max) + " bytes of UTF-8 with no control character"
	case formInteger:
		return "an integer from " + strconv.Itoa(f.min) + " to " + strconv.Itoa(f.max)
	case formChoice:
		quoted := make([]string, len(f.choices))
		for i, c := range f.choices {
			quoted[i] = `"` + c + `"`
		}
		return "one of " + strings.Join(quoted, ", ")
	case formDomains:
		return "a list of " + strconv.Itoa(f.min) + " to " + strconv.Itoa(f.max) + " distinct domain names, each of at most " + strconv.Itoa(searchDomainBytes) + " bytes in lowercase letters, digits, hyphens and dots"
	}
	return "in its form"
}

// plainName is a member name a refusal repeats: one that can hold no
// credential's form and needs no escape. Any other is described, not
// repeated.
var plainName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

func spellArgument(name string) string {
	if plainName.MatchString(name) {
		return `"` + name + `"`
	}
	return "a member whose name is not a plain name"
}

func searchArgumentUnsupported(name, provider string) error {
	if provider == "" {
		return Error("search-argument-unsupported: " + spellArgument(name) + " is not an argument of web-search; nothing was sent")
	}
	return Error("search-argument-unsupported: " + spellArgument(name) + " is not an argument a " + provider + " connection takes; nothing was sent")
}

func searchArgumentInvalid(a searchArgument) error {
	return Error("search-argument-invalid: " + spellArgument(a.name) + " must be " + a.form.says() + "; nothing was sent")
}

func searchArgumentMissing(a searchArgument) error {
	return Error("search-argument-invalid: " + spellArgument(a.name) + " is required; nothing was sent")
}

// readSearchArguments reads a request by the table: a JSON object in the
// canonical domain's text, each member an argument of the table, by its name
// as written, each value in its form, each required argument there. A member
// the table does not hold is refused by name first, in the order of names;
// then each argument, in the table's order. Whether the connection's
// provider takes each argument is known only once the connection is read
// (searchArgumentsTaken).
func readSearchArguments(raw []byte) (SearchRequest, searchOptions, error) {
	var q SearchRequest
	if len(raw) > 64<<10 {
		return q, nil, ErrRequest
	}
	// Numbers are carried here, not refused: a number out of an argument's
	// form is that argument's refusal, by name.
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil || !canon.IsObject(raw) {
		return q, nil, ErrRequest
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return q, nil, ErrRequest
	}
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := searchArgumentNamed(name); !ok {
			return q, nil, searchArgumentUnsupported(name, "")
		}
	}
	options := searchOptions{}
	for _, a := range searchArguments {
		value, present := members[a.name]
		if !present {
			if a.required {
				return SearchRequest{}, nil, searchArgumentMissing(a)
			}
			continue
		}
		v := a.form.read(value)
		if !a.form.holds(v) {
			return SearchRequest{}, nil, searchArgumentInvalid(a)
		}
		switch a.name {
		case "connection":
			q.Connection = v.(string)
		case "revision":
			q.Revision = v.(string)
		case "query":
			q.Query = v.(string)
		case "maxResults":
			q.MaxResults = v.(int)
		default:
			options[a.name] = v
		}
	}
	return q, options, nil
}

// searchRequestHeld reports whether the four arguments every request
// carries are in their forms, by the table.
func searchRequestHeld(q SearchRequest) bool {
	values := map[string]any{"connection": q.Connection, "revision": q.Revision, "query": q.Query, "maxResults": q.MaxResults}
	for _, a := range searchArguments {
		if v, ok := values[a.name]; ok && !a.form.holds(v) {
			return false
		}
	}
	return true
}

// searchArgumentsTaken refuses, by name, the first argument in the table's
// order that a request carries and the provider's connections do not take,
// and a value no longer in its form.
func searchArgumentsTaken(provider string, options searchOptions) error {
	for _, a := range searchArguments {
		v, present := options[a.name]
		if !present {
			continue
		}
		if !a.takes(provider) {
			return searchArgumentUnsupported(a.name, provider)
		}
		if !a.form.holds(v) {
			return searchArgumentInvalid(a)
		}
	}
	names := make([]string, 0, len(options))
	for name := range options {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := searchArgumentNamed(name); !ok {
			return searchArgumentUnsupported(name, provider)
		}
	}
	return nil
}

// tavilyRequest is what Tavily is asked: the fixed members, and each
// argument the table sends to Tavily, under its member there, as given.
func tavilyRequest(q SearchRequest, options searchOptions) map[string]any {
	body := map[string]any{}
	for name, v := range tavilyFixed {
		body[name] = v
	}
	values := map[string]any{"query": q.Query, "maxResults": q.MaxResults}
	for name, v := range options {
		values[name] = v
	}
	for _, a := range searchArguments {
		if v, ok := values[a.name]; ok && a.tavily != "" {
			body[a.tavily] = v
		}
	}
	return body
}

// searchRequestSchema is the request a connection takes, as a JSON Schema
// (2020-12) generated from the table: the arguments its provider takes, the
// connection and its present revision as constants. What a schema cannot
// state, a text's bound in bytes and its control characters, the query's
// description states; a pattern is ECMA-262's and RE2's alike.
func searchRequestSchema(c SearchConnection) map[string]any {
	properties := map[string]any{}
	required := []string{}
	for _, a := range searchArguments {
		if !a.takes(c.Provider) {
			continue
		}
		properties[a.name] = a.schema(c)
		if a.required {
			required = append(required, a.name)
		}
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"required": required, "properties": properties,
	}
}

func (a searchArgument) schema(c SearchConnection) map[string]any {
	var s map[string]any
	switch a.form.kind {
	case formConnection:
		s = map[string]any{"type": "string", "const": c.ID}
	case formRevision:
		s = map[string]any{"type": "string", "const": c.Revision}
	case formText:
		s = map[string]any{"type": "string", "minLength": a.form.min, "maxLength": a.form.max,
			"description": "At most " + strconv.Itoa(a.form.max) + " UTF-8 bytes, with no control characters; the adapter enforces these additional byte and text bounds."}
	case formInteger:
		s = map[string]any{"type": "integer", "minimum": a.form.min, "maximum": a.form.max}
	case formChoice:
		s = map[string]any{"type": "string", "enum": a.form.choices}
	case formDomains:
		s = map[string]any{"type": "array", "minItems": a.form.min, "maxItems": a.form.max, "uniqueItems": true,
			"items": map[string]any{"type": "string", "maxLength": searchDomainBytes, "pattern": searchDomainPattern}}
	}
	if a.about != "" {
		s["description"] = a.about
	}
	return s
}

// searchResultSchema is the result member a connection's acquisition
// answers with (web-search-v1), as a JSON Schema (2020-12), with the bounds
// normalizeSearch keeps it to.
func searchResultSchema(c SearchConnection) map[string]any {
	text := func(max int) map[string]any { return map[string]any{"type": "string", "maxLength": max} }
	hit := map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"title", "url", "snippet"},
		"properties": map[string]any{
			"title":   text(searchTitleBytes),
			"url":     map[string]any{"type": "string", "maxLength": searchURLBytes, "pattern": `^[Hh][Tt][Tt][Pp][Ss]://[^\r\n\x00]+$`},
			"snippet": text(searchSnippetBytes),
		},
	}
	hits := map[string]any{"type": "array", "maxItems": searchResultsMax, "items": hit,
		"description": "In the provider's order, no link twice, at most the request's maxResults."}
	properties := map[string]any{
		"version":     map[string]any{"type": "integer", "const": 1},
		"connection":  map[string]any{"type": "string", "const": c.ID},
		"revision":    map[string]any{"type": "string", "const": c.Revision},
		"provider":    map[string]any{"type": "string", "const": c.Provider},
		"query":       map[string]any{"type": "string", "minLength": 1, "maxLength": searchQueryBytes, "description": "The request's query, as given."},
		"retrievedAt": map[string]any{"type": "string", "pattern": `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`, "description": "When the answer had been read, to the second, in UTC."},
		"hits":        hits,
	}
	required := []string{"version", "connection", "revision", "provider", "query", "retrievedAt", "kind", "hits"}
	switch c.Provider {
	case "tavily":
		properties["kind"] = map[string]any{"type": "string", "const": "search-results"}
	case "google-grounding":
		properties["kind"] = map[string]any{"type": "string", "const": "grounded-answer"}
		hits["minItems"] = 1
		hit["properties"].(map[string]any)["snippet"] = map[string]any{"type": "string", "const": ""}
		properties["generatedAnswer"] = map[string]any{"type": "string", "minLength": 1, "maxLength": searchAnswerBytes, "description": "What the model wrote: generated text, not an excerpt of any page."}
		properties["attributionHtml"] = map[string]any{"type": "string", "minLength": 1, "maxLength": searchAttributionBytes, "description": "The provider's attribution markup, as given; markup the adapter neither wrote nor read."}
		properties["queries"] = map[string]any{"type": "array", "minItems": 1, "maxItems": searchQueriesMax, "items": text(searchQueryBytes), "description": "The searches the provider says it made."}
		required = append(required, "attributionHtml")
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"description": "The result member of what an acquisition of this connection answers, web-search-v1. A length is the adapter's bound in bytes of UTF-8, which a schema counts in characters, so the schema admits more than the adapter writes.",
		"required":    required, "properties": properties,
	}
}
