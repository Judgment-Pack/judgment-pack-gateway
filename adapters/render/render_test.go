package render

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
)

var testIdentity = attachment.Identity{Name: adapterName, Version: "0", Digest: "sha256:" + strings.Repeat("a", 64)}

// sampleDocument is a document that uses every block and every property of a
// run, with text in the scripts of the desk's locales and the characters XML
// reserves.
const sampleDocument = `{"title":"Refund decision","language":"en","blocks":[
 {"type":"heading","level":2,"runs":[{"text":"Refund decision"}]},
 {"type":"paragraph","runs":[{"text":"The refund of "},{"text":"149.50 CAD","bold":true},{"text":" is approved. See "},{"text":"the policy","link":"https://example.com/policy?a=1&b=2"},{"text":".\nSecond line\twith a tab, and <angle> & \"quotes\" &amp; 'apostrophes'."}]},
 {"type":"list","ordered":true,"items":[{"runs":[{"text":"First"}]},{"runs":[{"text":"Second","italic":true}]}]},
 {"type":"list","ordered":false,"items":[{"runs":[{"text":"日本語 (にほんご)"}]},{"runs":[{"text":"한국어"}]},{"runs":[{"text":"简体中文 繁體中文 粵語"}]},{"runs":[{"text":"español français português"}]}]},
 {"type":"list","ordered":true,"items":[{"runs":[{"text":"Again from one"}]}]},
 {"type":"table","header":[{"runs":[{"text":"Item"}]},{"runs":[{"text":"Amount"}]}],"rows":[[{"runs":[{"text":"Refund"}]},{"runs":[{"text":"149.50","code":true}]}],[{"runs":[{"text":"Fee"}]},{"runs":[{"text":"0.00","code":true},{"text":" see ","italic":true},{"text":"the policy","link":"https://example.com/policy?a=1&b=2"},{"text":" or ","bold":true,"italic":true,"code":true},{"text":"write","link":"mailto:refunds@example.com"}]}]]}
]}`

func arguments(format, document string) string {
	return `{"format":"` + format + `","document":` + document + `}`
}

func parse(t *testing.T, raw string, cfg Config) (Request, error) {
	t.Helper()
	return ParseRequest(context.Background(), strings.NewReader(raw), cfg, time.Now)
}

// render parses and renders, and returns the record and the file it holds.
func render(t *testing.T, raw string, cfg Config) (Record, []byte, []byte) {
	t.Helper()
	req, err := parse(t, raw, cfg)
	if err != nil {
		t.Fatalf("the request was refused: %v", err)
	}
	return renderRequest(t, req, cfg)
}

// unpacked is what the parts of a file hold, by the sizes the archive states
// for them, each held to what the part gives when it is read.
func unpacked(t *testing.T, file []byte) int64 {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatalf("the file is not a ZIP archive: %v", err)
	}
	var held int64
	for _, entry := range archive.File {
		if n := len(docxPart(t, file, entry.Name)); uint64(n) != entry.UncompressedSize64 {
			t.Fatalf("%s states %d bytes and holds %d", entry.Name, entry.UncompressedSize64, n)
		}
		held += int64(entry.UncompressedSize64)
	}
	return held
}

// renderRequest renders a request already admitted.
func renderRequest(t *testing.T, req Request, cfg Config) (Record, []byte, []byte) {
	t.Helper()
	out, err := Process(context.Background(), cfg, req, testIdentity, time.Now())
	if err != nil {
		t.Fatalf("the rendering was refused: %v", err)
	}
	var rec Record
	if err := json.Unmarshal(out, &rec); err != nil {
		t.Fatalf("the record does not decode: %v", err)
	}
	file, err := base64.StdEncoding.DecodeString(rec.File.Bytes)
	if err != nil {
		t.Fatalf("file.bytes does not decode: %v", err)
	}
	return rec, file, out
}

func codeOf(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	if err == nil {
		return "admitted"
	}
	return "not a refusal: " + err.Error()
}

// The structure is closed: a request that carries anything the contract does
// not define, or that gives a member a value of another kind, is refused and
// nothing is rendered. Each row is one departure from a request that is
// admitted, with the code it is refused under and what the reason says, so
// that a request refused for one rule is not taken for one refused for
// another.
func TestARequestOutsideTheContractIsRefused(t *testing.T) {
	paragraph := `{"type":"paragraph","runs":[{"text":"x"}]}`
	document := func(blocks string) string { return `{"title":"T","blocks":[` + blocks + `]}` }
	run := func(members string) string {
		return arguments("docx", document(`{"type":"paragraph","runs":[{`+members+`}]}`))
	}
	if _, err := parse(t, arguments("docx", document(paragraph)), DefaultConfig()); err != nil {
		t.Fatalf("the request the rows depart from is refused: %v", err)
	}
	const domain = "not JSON of the canonical domain"
	for name, c := range map[string]struct{ raw, code, says string }{
		"not JSON":      {`not json`, CodeArgumentsInvalid, domain},
		"nothing":       {``, CodeArgumentsInvalid, domain},
		"two documents": {arguments("docx", document(paragraph)) + `{}`, CodeArgumentsInvalid, domain},
		"not an object": {`[]`, CodeArgumentsInvalid, "arguments: not a JSON object"},
		// A run in a cell is as deep as the structure goes, and anything
		// deeper is refused for its depth before it is read for anything
		// else: a member the contract does not name, here, that holds an
		// array.
		"a value nested past the structure":   {arguments("docx", document(`{"type":"table","rows":[[{"runs":[{"text":"x","notes":[]}]}]]}`)), CodeArgumentsInvalid, "the arguments nest deeper than the structure does"},
		"arguments nested nine thousand deep": {strings.Repeat(`{"x":`, 9000) + `"` + strings.Repeat("a", 500000) + `"` + strings.Repeat(`}`, 9000), CodeArgumentsInvalid, "the arguments nest deeper than the structure does"},
		"null":                                {`null`, CodeArgumentsInvalid, "arguments: not a JSON object"},
		"a member the contract does not name": {`{"format":"docx","document":` + document(paragraph) + `,"save":"drive"}`, CodeArgumentsInvalid, "arguments: a member the contract does not define"},
		"format missing":                      {`{"document":` + document(paragraph) + `}`, CodeArgumentsInvalid, "arguments: member format is missing"},
		// Two members are missing, and the one named is the first of them
		// by name, every time.
		"format and document missing":         {`{}`, CodeArgumentsInvalid, "arguments: member document is missing"},
		"format given twice":                  {`{"format":"docx","format":"docx","document":` + document(paragraph) + `}`, CodeArgumentsInvalid, domain},
		"a format the contract does not name": {arguments("html", document(paragraph)), CodeArgumentsInvalid, "format must be"},
		"format of another case":              {arguments("DOCX", document(paragraph)), CodeArgumentsInvalid, "format must be"},
		"format that is null":                 {`{"format":null,"document":` + document(paragraph) + `}`, CodeArgumentsInvalid, "format must be"},
		"a number outside the domain":         {arguments("docx", `{"title":"T","blocks":[{"type":"heading","level":1.5,"runs":[]}]}`), CodeArgumentsInvalid, domain},
		"an unpaired surrogate":               {run(`"text":"\ud800"`), CodeArgumentsInvalid, domain},
		// A name given twice is outside the canonical domain, wherever in
		// the arguments it is, so it is refused before any block is read.
		"type given twice":                     {arguments("docx", document(`{"type":"paragraph","type":"heading","runs":[]}`)), CodeArgumentsInvalid, domain},
		"text given twice":                     {run(`"text":"a","text":"b"`), CodeArgumentsInvalid, domain},
		"document that is an array":            {`{"format":"docx","document":[]}`, CodeArgumentsInvalid, "document: not a JSON object"},
		"title missing":                        {arguments("docx", `{"blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document: member title is missing"},
		"blocks missing":                       {arguments("docx", `{"title":"T"}`), CodeArgumentsInvalid, "document: member blocks is missing"},
		"title empty":                          {arguments("docx", `{"title":"","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.title must be"},
		"title that is null":                   {arguments("docx", `{"title":null,"blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.title must be"},
		"title with a line feed":               {arguments("docx", `{"title":"a\nb","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.title must be"},
		"title with U+FFFE":                    {arguments("docx", `{"title":"a￾b","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.title must be"},
		"title with U+FFFF":                    {arguments("docx", `{"title":"a￿b","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.title must be"},
		"title past 255 bytes":                 {arguments("docx", `{"title":"`+strings.Repeat("t", 256)+`","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.title must be"},
		"language that is no tag":              {arguments("docx", `{"title":"T","language":"en us","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.language must be"},
		"language that is a number":            {arguments("docx", `{"title":"T","language":1,"blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.language must be"},
		"language that is empty":               {arguments("docx", `{"title":"T","language":"","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.language must be"},
		"language past 35 bytes":               {arguments("docx", `{"title":"T","language":"en-`+strings.Repeat("abcdefgh-", 3)+`abcdefgh","blocks":[`+paragraph+`]}`), CodeArgumentsInvalid, "document.language must be"},
		"blocks that is an object":             {arguments("docx", `{"title":"T","blocks":{}}`), CodeArgumentsInvalid, "document.blocks must be an array"},
		"blocks that is null":                  {arguments("docx", `{"title":"T","blocks":null}`), CodeArgumentsInvalid, "document.blocks must be an array"},
		"a member of document not named":       {arguments("docx", `{"title":"T","blocks":[`+paragraph+`],"author":"a"}`), CodeArgumentsInvalid, "document: a member the contract does not define"},
		"cites that is a string":               {`{"format":"docx","document":` + document(paragraph) + `,"cites":"x"}`, CodeArgumentsInvalid, "cites: not a JSON object"},
		"cites with no decision":               {`{"format":"docx","document":` + document(paragraph) + `,"cites":{}}`, CodeArgumentsInvalid, "cites: member decision is missing"},
		"cites.decision that is no digest":     {`{"format":"docx","document":` + document(paragraph) + `,"cites":{"decision":"sha256:abc"}}`, CodeArgumentsInvalid, "cites.decision must be"},
		"cites.decision in capitals":           {`{"format":"docx","document":` + document(paragraph) + `,"cites":{"decision":"sha256:` + strings.Repeat("A", 64) + `"}}`, CodeArgumentsInvalid, "cites.decision must be"},
		"cites with another member":            {`{"format":"docx","document":` + document(paragraph) + `,"cites":{"decision":"sha256:` + strings.Repeat("0", 64) + `","receipt":"x"}}`, CodeArgumentsInvalid, "cites: a member the contract does not define"},
		"no block":                             {arguments("docx", document(``)), CodeContentInvalid, "document.blocks holds no block"},
		"a block that is a string":             {arguments("docx", document(`"paragraph"`)), CodeContentInvalid, "block 1: a block is an object with a type"},
		"a block that is null":                 {arguments("docx", document(`null`)), CodeContentInvalid, "block 1: a block is an object with a type"},
		"a block with no type":                 {arguments("docx", document(`{"runs":[]}`)), CodeContentInvalid, "block 1: a block is an object with a type"},
		"a type that is a number":              {arguments("docx", document(`{"type":1,"runs":[]}`)), CodeContentInvalid, "block 1: a block's type is a string"},
		"a type the contract does not define":  {arguments("docx", document(`{"type":"image","runs":[]}`)), CodeContentInvalid, "block 1: a type the contract does not define"},
		"type under a name of another case":    {arguments("docx", document(`{"Type":"paragraph","runs":[]}`)), CodeContentInvalid, "block 1: a block is an object with a type"},
		"the second block, not the first":      {arguments("docx", document(paragraph+`,{"type":"image"}`)), CodeContentInvalid, "block 2: a type the contract does not define"},
		"a paragraph with a level":             {arguments("docx", document(`{"type":"paragraph","level":1,"runs":[]}`)), CodeContentInvalid, "block 1: a member the contract does not define"},
		"a paragraph with no runs":             {arguments("docx", document(`{"type":"paragraph"}`)), CodeContentInvalid, "block 1: member runs is missing"},
		"a heading with no level":              {arguments("docx", document(`{"type":"heading","runs":[]}`)), CodeContentInvalid, "block 1: member level is missing"},
		"a heading with items":                 {arguments("docx", document(`{"type":"heading","level":1,"runs":[],"items":[]}`)), CodeContentInvalid, "block 1: a member the contract does not define"},
		"a heading of level 0":                 {arguments("docx", document(`{"type":"heading","level":0,"runs":[]}`)), CodeContentInvalid, "a heading's level is an integer from 1 to 6"},
		"a heading of level 7":                 {arguments("docx", document(`{"type":"heading","level":7,"runs":[]}`)), CodeContentInvalid, "a heading's level is an integer from 1 to 6"},
		"a heading whose level is a string":    {arguments("docx", document(`{"type":"heading","level":"1","runs":[]}`)), CodeContentInvalid, "a heading's level is an integer from 1 to 6"},
		"a heading of level -1":                {arguments("docx", document(`{"type":"heading","level":-1,"runs":[]}`)), CodeContentInvalid, "a heading's level is an integer from 1 to 6"},
		"a heading of level 01":                {arguments("docx", document(`{"type":"heading","level":01,"runs":[]}`)), CodeArgumentsInvalid, domain},
		"a heading with a run that is not one": {arguments("docx", document(`{"type":"heading","level":1,"runs":[{"text":"a\rb"}]}`)), CodeContentInvalid, "block 1: a run's text holds a control character"},
		"runs that is an object":               {arguments("docx", document(`{"type":"paragraph","runs":{}}`)), CodeContentInvalid, "block 1: runs is an array"},
		"runs that is null":                    {arguments("docx", document(`{"type":"paragraph","runs":null}`)), CodeContentInvalid, "block 1: runs is an array"},
		"a run that is a string":               {arguments("docx", document(`{"type":"paragraph","runs":["x"]}`)), CodeContentInvalid, "block 1: not a JSON object"},
		"a run with no text":                   {run(`"bold":true`), CodeContentInvalid, "block 1: member text is missing"},
		"a run whose text is a number":         {run(`"text":1`), CodeContentInvalid, "a run's text is a string"},
		"a run whose text is null":             {run(`"text":null`), CodeContentInvalid, "a run's text is a string"},
		"a run whose bold is a string":         {run(`"text":"x","bold":"true"`), CodeContentInvalid, "a run's bold is true or false"},
		"a run whose italic is null":           {run(`"text":"x","italic":null`), CodeContentInvalid, "a run's italic is true or false"},
		"a run whose code is a number":         {run(`"text":"x","code":1`), CodeContentInvalid, "a run's code is true or false"},
		"a run with a member not defined":      {run(`"text":"x","color":"red"`), CodeContentInvalid, "block 1: a member the contract does not define"},
		"text with a carriage return":          {run(`"text":"a\rb"`), CodeContentInvalid, "a run's text holds a control character"},
		"text with a control character":        {run(`"text":"a\u0001b"`), CodeContentInvalid, "a run's text holds a control character"},
		"text with a null character":           {run(`"text":"a\u0000b"`), CodeContentInvalid, "a run's text holds a control character"},
		"text with a delete":                   {run(`"text":"a\u007fb"`), CodeContentInvalid, "a run's text holds a control character"},
		"text with U+FFFE":                     {run(`"text":"a￾b"`), CodeContentInvalid, "a code point a Word file cannot carry"},
		"text with U+FFFF":                     {run(`"text":"a￿b"`), CodeContentInvalid, "a code point a Word file cannot carry"},
		"a link that is a number":              {run(`"text":"x","link":1`), CodeContentInvalid, "a run's link is a string"},
		"a link that is null":                  {run(`"text":"x","link":null`), CodeContentInvalid, "a run's link is a string"},
		"a link with no scheme":                {run(`"text":"x","link":"example.com"`), CodeContentInvalid, "a scheme other than"},
		"a link to a file":                     {run(`"text":"x","link":"file:///etc/passwd"`), CodeContentInvalid, "a scheme other than"},
		"a link that is a script":              {run(`"text":"x","link":"javascript:alert(1)"`), CodeContentInvalid, "a scheme other than"},
		"a link that is data":                  {run(`"text":"x","link":"data:text/html,x"`), CodeContentInvalid, "a scheme other than"},
		"a link with no host":                  {run(`"text":"x","link":"https:///path"`), CodeContentInvalid, "names no host"},
		"a link over http with no host":        {run(`"text":"x","link":"http:"`), CodeContentInvalid, "names no host"},
		"a link to no address":                 {run(`"text":"x","link":"mailto:"`), CodeContentInvalid, "names no address"},
		"a link that is no URL":                {run(`"text":"x","link":"https://[::1"`), CodeContentInvalid, "is not a URL"},
		"a link to a port and no host":         {run(`"text":"x","link":"http://:80/"`), CodeContentInvalid, "names no host"},
		"a link to a user and no host":         {run(`"text":"x","link":"https://user@:443/"`), CodeContentInvalid, "names no host"},
		"a link to an address with no domain":  {run(`"text":"x","link":"mailto:someone@"`), CodeContentInvalid, "names no address"},
		"a link to an address with no name":    {run(`"text":"x","link":"mailto:@example.com"`), CodeContentInvalid, "names no address"},
		"a link to an address with no at sign": {run(`"text":"x","link":"mailto:example.com"`), CodeContentInvalid, "names no address"},
		"a link to two addresses":              {run(`"text":"x","link":"mailto:a@example.com,b@example.com"`), CodeContentInvalid, "names no address"},
		"a link to an address with two signs":  {run(`"text":"x","link":"mailto:a@b@example.com"`), CodeContentInvalid, "names no address"},
		"a link to a share as an address":      {run(`"text":"x","link":"mailto:\\\\server\\share@x"`), CodeContentInvalid, "names no address"},
		"a link to a script as an address":     {run(`"text":"x","link":"mailto:javascript:alert(1)@x"`), CodeContentInvalid, "names no address"},
		"a link to an address with a fragment": {run(`"text":"x","link":"mailto:a@example.com#@b@example.org"`), CodeContentInvalid, "an address with a fragment"},
		"a link to an address and a bare sign": {run(`"text":"x","link":"mailto:a@example.com#"`), CodeContentInvalid, "an address with a fragment"},
		"a link to two addresses by an escape": {run(`"text":"x","link":"mailto:a@example.com%2Cb%40example.org"`), CodeContentInvalid, "names no address"},
		"a link to an address with an escape":  {run(`"text":"x","link":"mailto:%zz@example.com"`), CodeContentInvalid, "names no address"},
		"a link with U+FFFE":                   {run(`"text":"x","link":"https://example.com/\ufffe"`), CodeContentInvalid, "a code point a Word file cannot carry"},
		"a link with U+FFFF":                   {run(`"text":"x","link":"https://example.com/\uffff"`), CodeContentInvalid, "a code point a Word file cannot carry"},
		"a link with a space":                  {run(`"text":"x","link":"https://example.com/a b"`), CodeContentInvalid, "a space or a control character"},
		"a link with a tab":                    {run(`"text":"x","link":"https://example.com/a\tb"`), CodeContentInvalid, "a space or a control character"},
		"a link with a delete":                 {run(`"text":"x","link":"https://example.com/a\u007fb"`), CodeContentInvalid, "a space or a control character"},
		"a link that is empty":                 {run(`"text":"x","link":""`), CodeContentInvalid, "a link's target is 1 to 2048 bytes"},
		"a link past its length":               {run(`"text":"x","link":"https://example.com/` + strings.Repeat("a", maxTargetBytes) + `"`), CodeContentInvalid, "a link's target is 1 to 2048 bytes"},
		"a list with no ordered":               {arguments("docx", document(`{"type":"list","items":[{"runs":[]}]}`)), CodeContentInvalid, "block 1: member ordered is missing"},
		"a list with no items":                 {arguments("docx", document(`{"type":"list","ordered":true}`)), CodeContentInvalid, "block 1: member items is missing"},
		"a list whose ordered is a number":     {arguments("docx", document(`{"type":"list","ordered":1,"items":[{"runs":[]}]}`)), CodeContentInvalid, "a list's ordered is true or false"},
		"a list whose items is an object":      {arguments("docx", document(`{"type":"list","ordered":false,"items":{}}`)), CodeContentInvalid, "items is an array"},
		"a list whose items is null":           {arguments("docx", document(`{"type":"list","ordered":false,"items":null}`)), CodeContentInvalid, "items is an array"},
		"a list with no item":                  {arguments("docx", document(`{"type":"list","ordered":false,"items":[]}`)), CodeContentInvalid, "items holds nothing"},
		"an item that is a string":             {arguments("docx", document(`{"type":"list","ordered":false,"items":["x"]}`)), CodeContentInvalid, "block 1: not a JSON object"},
		"an item with no runs":                 {arguments("docx", document(`{"type":"list","ordered":false,"items":[{}]}`)), CodeContentInvalid, "block 1: member runs is missing"},
		"a list within a list":                 {arguments("docx", document(`{"type":"list","ordered":false,"items":[{"runs":[],"items":[]}]}`)), CodeContentInvalid, "block 1: a member the contract does not define"},
		"an item with a run that is not one":   {arguments("docx", document(`{"type":"list","ordered":false,"items":[{"runs":[{"text":"x","link":"ftp://example.com"}]}]}`)), CodeContentInvalid, "a scheme other than"},
		"a table with a caption":               {arguments("docx", document(`{"type":"table","caption":"x","rows":[[{"runs":[]}]]}`)), CodeContentInvalid, "block 1: a member the contract does not define"},
		"a table with no rows":                 {arguments("docx", document(`{"type":"table"}`)), CodeContentInvalid, "block 1: member rows is missing"},
		"a table whose rows is an object":      {arguments("docx", document(`{"type":"table","rows":{}}`)), CodeContentInvalid, "a table's rows is an array"},
		"a table whose rows is null":           {arguments("docx", document(`{"type":"table","rows":null}`)), CodeContentInvalid, "a table's rows is an array"},
		"a table with no row":                  {arguments("docx", document(`{"type":"table","rows":[]}`)), CodeContentInvalid, "a table holds no row"},
		"a table whose row is an object":       {arguments("docx", document(`{"type":"table","rows":[{}]}`)), CodeContentInvalid, "row is an array"},
		"a table with an empty row":            {arguments("docx", document(`{"type":"table","rows":[[]]}`)), CodeContentInvalid, "row holds nothing"},
		"a table whose header is empty":        {arguments("docx", document(`{"type":"table","header":[],"rows":[[{"runs":[]}]]}`)), CodeContentInvalid, "header holds nothing"},
		"a table whose header is null":         {arguments("docx", document(`{"type":"table","header":null,"rows":[[{"runs":[]}]]}`)), CodeContentInvalid, "header is an array"},
		"a table whose rows differ in length":  {arguments("docx", document(`{"type":"table","rows":[[{"runs":[]}],[{"runs":[]},{"runs":[]}]]}`)), CodeContentInvalid, "a table's rows do not all hold 1 cells"},
		"a table whose header is another size": {arguments("docx", document(`{"type":"table","header":[{"runs":[]},{"runs":[]}],"rows":[[{"runs":[]}]]}`)), CodeContentInvalid, "a table's rows do not all hold 2 cells"},
		"a header with a run that is not one":  {arguments("docx", document(`{"type":"table","header":[{"runs":[{"text":"a\u0002"}]}],"rows":[[{"runs":[]}]]}`)), CodeContentInvalid, "a run's text holds a control character"},
		"a cell with a run that is not one":    {arguments("docx", document(`{"type":"table","rows":[[{"runs":[{"text":1}]}]]}`)), CodeContentInvalid, "a run's text is a string"},
		"a cell that holds a table":            {arguments("docx", document(`{"type":"table","rows":[[{"runs":[],"rows":[]}]]}`)), CodeContentInvalid, "block 1: a member the contract does not define"},
	} {
		_, err := parse(t, c.raw, DefaultConfig())
		var refusal *Refusal
		if !errors.As(err, &refusal) {
			t.Errorf("%s: %s, want %s", name, codeOf(err), c.code)
			continue
		}
		if refusal.Code != c.code || !strings.Contains(refusal.Reason, c.says) {
			t.Errorf("%s: refused as %q, want %s saying %q", name, refusal.Error(), c.code, c.says)
		}
	}
}

// What a request may hold and is admitted with, at the edges of each rule.
func TestWhatTheContractAdmits(t *testing.T) {
	document := func(blocks string) string { return `{"title":"T","blocks":[` + blocks + `]}` }
	for name, raw := range map[string]string{
		"a paragraph with no run":              arguments("docx", document(`{"type":"paragraph","runs":[]}`)),
		"text that is empty":                   arguments("docx", document(`{"type":"paragraph","runs":[{"text":""}]}`)),
		"text with a line feed and a tab":      arguments("docx", document(`{"type":"paragraph","runs":[{"text":"a\nb\tc"}]}`)),
		"text outside the basic plane":         arguments("docx", document(`{"type":"paragraph","runs":[{"text":"😀 𠮷"}]}`)),
		"text with the replacement character":  arguments("docx", document(`{"type":"paragraph","runs":[{"text":"a�b"}]}`)),
		"text that reads right to left":        arguments("docx", document(`{"type":"paragraph","runs":[{"text":"שלום ‏"}]}`)),
		"headings of level 1 and level 6":      arguments("docx", document(`{"type":"heading","level":1,"runs":[]},{"type":"heading","level":6,"runs":[]}`)),
		"a link over http":                     arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"http://example.com"}]}`)),
		"a link whose scheme is in capitals":   arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"HTTPS://example.com/"}]}`)),
		"a link to a host and a port":          arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"https://example.com:8443/a?b=c#d"}]}`)),
		"a link to an address of six":          arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"https://[2001:db8::1]:8443/"}]}`)),
		"a link outside ASCII":                 arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"https://example.com/日本語?q=é"}]}`)),
		"a link to an address with a subject":  arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"mailto:a.b+c@example.com?subject=Refund"}]}`)),
		"a link that is an address":            arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"mailto:a@example.com"}]}`)),
		"a link at its length":                 arguments("docx", document(`{"type":"paragraph","runs":[{"text":"x","link":"https://example.com/`+strings.Repeat("a", maxTargetBytes-len("https://example.com/"))+`"}]}`)),
		"a table with no header":               arguments("docx", document(`{"type":"table","rows":[[{"runs":[]}]]}`)),
		"a table at its columns":               arguments("docx", document(`{"type":"table","rows":[[`+strings.TrimSuffix(strings.Repeat(`{"runs":[]},`, maxTableColumns), ",")+`]]}`)),
		"a language with a script and region":  arguments("docx", `{"title":"T","language":"zh-Hant-HK","blocks":[{"type":"paragraph","runs":[]}]}`),
		"a title at 255 bytes":                 arguments("docx", `{"title":"`+strings.Repeat("t", 255)+`","blocks":[{"type":"paragraph","runs":[]}]}`),
		"a request for a PDF":                  arguments("pdf", document(`{"type":"paragraph","runs":[]}`)),
		"members in another order, and spaces": ` { "document" : { "blocks" : [ { "runs" : [ ] , "type" : "paragraph" } ] , "title" : "T" } , "format" : "docx" } `,
	} {
		if _, err := parse(t, raw, DefaultConfig()); err != nil {
			t.Errorf("%s: refused, %v", name, err)
		}
	}
}

// Each bound of the structure refuses the first request past it and admits
// the one at it.
func TestTheBoundsOfTheStructure(t *testing.T) {
	document := func(blocks string) string { return `{"title":"T","blocks":[` + blocks + `]}` }
	repeat := func(s string, n int) string { return strings.TrimSuffix(strings.Repeat(s+",", n), ",") }
	cfg := DefaultConfig()
	cfg.MaxRequest = 8 << 20
	small := cfg
	small.MaxBlocks = 3
	for name, c := range map[string]struct {
		cfg             Config
		raw, code, says string
	}{
		"blocks at the bound":     {small, arguments("docx", document(repeat(`{"type":"paragraph","runs":[]}`, 3))), "admitted", ""},
		"blocks past the bound":   {small, arguments("docx", document(repeat(`{"type":"paragraph","runs":[]}`, 4))), CodeContentOverBound, "the document holds 4 blocks, past --max-blocks 3"},
		"runs at the bound":       {cfg, arguments("docx", document(`{"type":"paragraph","runs":[`+repeat(`{"text":"x"}`, maxRuns)+`]}`)), "admitted", ""},
		"runs past the bound":     {cfg, arguments("docx", document(`{"type":"paragraph","runs":[`+repeat(`{"text":"x"}`, maxRuns+1)+`]}`)), CodeContentOverBound, "runs holds 513 entries, past 512"},
		"items at the bound":      {cfg, arguments("docx", document(`{"type":"list","ordered":false,"items":[`+repeat(`{"runs":[]}`, maxListItems)+`]}`)), "admitted", ""},
		"items past the bound":    {cfg, arguments("docx", document(`{"type":"list","ordered":false,"items":[`+repeat(`{"runs":[]}`, maxListItems+1)+`]}`)), CodeContentOverBound, "items holds 1001 entries, past 1000"},
		"columns past the bound":  {cfg, arguments("docx", document(`{"type":"table","rows":[[`+repeat(`{"runs":[]}`, maxTableColumns+1)+`]]}`)), CodeContentOverBound, "row holds 65 entries, past 64"},
		"a header past the bound": {cfg, arguments("docx", document(`{"type":"table","header":[`+repeat(`{"runs":[]}`, maxTableColumns+1)+`],"rows":[[{"runs":[]}]]}`)), CodeContentOverBound, "header holds 65 entries, past 64"},
		"rows at the bound":       {cfg, arguments("docx", document(`{"type":"table","rows":[`+repeat(`[{"runs":[]}]`, maxTableRows)+`]}`)), "admitted", ""},
		"rows past the bound":     {cfg, arguments("docx", document(`{"type":"table","rows":[`+repeat(`[{"runs":[]}]`, maxTableRows+1)+`]}`)), CodeContentOverBound, "a table holds 1001 rows, past 1000"},
	} {
		_, err := parse(t, c.raw, c.cfg)
		if codeOf(err) != c.code {
			t.Errorf("%s: %s, want %s", name, codeOf(err), c.code)
		}
		if err != nil && !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: refused as %q, want it to say %q", name, err, c.says)
		}
	}
}

// The read bound is the request's, the file bound the file's and the output
// bound the record's: each refuses by its own name, at the first byte past
// it, and admits what is at it.
func TestTheBoundsOfTheRequestTheFileAndTheRecord(t *testing.T) {
	raw := arguments("docx", sampleDocument)
	cfg := DefaultConfig()
	cfg.MaxRequest = int64(len(raw))
	if _, err := parse(t, raw, cfg); err != nil {
		t.Fatalf("a request at the read bound is refused: %v", err)
	}
	cfg.MaxRequest--
	if _, err := parse(t, raw, cfg); codeOf(err) != CodeRequestOverBound {
		t.Fatalf("a request a byte past the read bound: %s, want %s", codeOf(err), CodeRequestOverBound)
	}

	// The bound on the file is on what its parts hold, which is what a
	// reader of the file is given to read, and on the archive they are in.
	// The parts are the longer of the two, so they are what the bound meets:
	// a file whose parts are at the bound is written, and one whose parts
	// are a byte past it is refused, though the archive is well within it.
	cfg = DefaultConfig()
	_, file, out := render(t, raw, cfg)
	req, err := parse(t, raw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	within := func(cfg Config) error {
		_, err := Process(context.Background(), cfg, req, testIdentity, time.Now())
		return err
	}
	held := unpacked(t, file)
	if held <= int64(len(file)) {
		t.Fatalf("the parts hold %d bytes and the archive is %d: the test wants the parts to be the longer", held, len(file))
	}
	cfg.MaxFile = held
	if err := within(cfg); err != nil {
		t.Fatalf("a file whose parts are at the file bound is refused: %v", err)
	}
	cfg.MaxFile--
	if err := within(cfg); codeOf(err) != CodeFileOverBound || !strings.Contains(err.Error(), "the parts of the file hold more than --max-file") {
		t.Fatalf("a file whose parts are a byte past the file bound: %v, want %s", err, CodeFileOverBound)
	}
	// Text that says little at length: 900 kilobytes of request whose
	// document part is twelve megabytes and whose archive is under forty
	// kilobytes. It is refused for what its parts hold.
	long, err := parse(t, arguments("docx", `{"title":"T","blocks":[{"type":"paragraph","runs":[{"text":"`+strings.Repeat(`a\n`, 300000)+`"}]}]}`), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Process(context.Background(), DefaultConfig(), long, testIdentity, time.Now()); codeOf(err) != CodeFileOverBound {
		t.Fatalf("a file whose parts hold twelve megabytes: %s, want %s", codeOf(err), CodeFileOverBound)
	}
	roomy := DefaultConfig()
	roomy.MaxFile, roomy.MaxOutput = 16<<20, 16<<20
	if rec, archive, _ := renderRequest(t, long, roomy); unpacked(t, archive) < 12_000_000 || rec.File.Size > 64_000 {
		t.Fatalf("the parts hold %d bytes in an archive of %d", unpacked(t, archive), rec.File.Size)
	}
	// The document part stops being written at the first block that begins
	// past the bound: of a hundred lists, each past the bound by itself,
	// the writer comes to one.
	var lists []Block
	for range 100 {
		lists = append(lists, Block{Type: BlockList, Items: []Cell{{{Text: strings.Repeat("x", 2000)}}}})
	}
	stopped := &docxWriter{targets: map[string]int{}, most: 1000}
	if body := stopped.body(Document{Title: "T", Blocks: lists}); !stopped.over || body != "" || len(stopped.lists) != 1 {
		t.Fatalf("the writer came to %d lists and wrote %d bytes", len(stopped.lists), len(body))
	}
	// The targets of the links count towards it, since the file holds them
	// too, in a part of their own: of a hundred paragraphs that say nothing
	// and link to two thousand bytes each, the writer comes to one.
	var linked []Block
	for i := range 100 {
		linked = append(linked, Block{Type: BlockParagraph, Runs: []Run{{Link: fmt.Sprintf("https://example.com/%04d/%s", i, strings.Repeat("a", 2000))}}})
	}
	stopped = &docxWriter{targets: map[string]int{}, most: 1000}
	if body := stopped.body(Document{Title: "T", Blocks: linked}); !stopped.over || body != "" || len(stopped.order) != 1 {
		t.Fatalf("the writer came to %d targets and wrote %d bytes", len(stopped.order), len(body))
	}
	// A target met twice is held once, and counted once.
	for i := range linked {
		linked[i].Runs[0].Link = linked[0].Runs[0].Link
	}
	stopped = &docxWriter{targets: map[string]int{}, most: 4000}
	if body := stopped.body(Document{Title: "T", Blocks: linked[:10]}); stopped.over || body == "" || stopped.linked != int64(len(linked[0].Runs[0].Link)) {
		t.Fatalf("ten links to one target of %d bytes are counted as %d bytes", len(linked[0].Runs[0].Link), stopped.linked)
	}
	// The record states the output bound it was held to, and its duration,
	// so its length moves with both. The clock is held still, and the bound
	// is one of as many digits as the record's length has, so that the
	// record is the same length at the bound and a byte short of it.
	_ = out
	still := func() time.Time { return req.ReceivedAt }
	bounded := func(cfg Config) ([]byte, error) {
		return process(context.Background(), cfg, req, testIdentity, req.ReceivedAt, still)
	}
	cfg = DefaultConfig()
	cfg.MaxOutput = 9999
	record, err := bounded(cfg)
	if err != nil || len(record) < 1001 || len(record) > 9999 {
		t.Fatalf("the record is %d bytes, and the test wants one of four digits: %v", len(record), err)
	}
	cfg.MaxOutput = int64(len(record))
	if at, err := bounded(cfg); err != nil || len(at) != len(record) {
		t.Fatalf("a record at the output bound is refused, or is %d bytes and not %d: %v", len(at), len(record), err)
	}
	cfg.MaxOutput--
	if _, err := bounded(cfg); codeOf(err) != CodeRecordOverBound {
		t.Fatalf("a record a byte past the output bound: %s, want %s", codeOf(err), CodeRecordOverBound)
	}
}

// A request for a PDF is admitted as a request and refused as a rendering,
// by name: this adapter has no rendering program to be configured with. Its
// content is held to every rule first, so a request for a PDF whose content
// breaks one is refused for the content.
func TestAPDFIsRefusedByName(t *testing.T) {
	if _, err := parse(t, arguments("pdf", `{"title":"T","blocks":[{"type":"image"}]}`), DefaultConfig()); codeOf(err) != CodeContentInvalid {
		t.Fatalf("a request for a PDF whose content breaks a rule: %s, want %s", codeOf(err), CodeContentInvalid)
	}
	req, err := parse(t, arguments("pdf", sampleDocument), DefaultConfig())
	if err != nil {
		t.Fatalf("the request is refused: %v", err)
	}
	out, err := Process(context.Background(), DefaultConfig(), req, testIdentity, time.Now())
	if codeOf(err) != CodeRendererNotConfigured || out != nil {
		t.Fatalf("%s with %d bytes of record, want %s and none", codeOf(err), len(out), CodeRendererNotConfigured)
	}
}

// A deadline that has passed refuses the rendering, whether the context has
// caught up with the clock or not.
func TestADeadlinePassedRefusesTheRendering(t *testing.T) {
	req, err := parse(t, arguments("docx", sampleDocument), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Process(cancelled, DefaultConfig(), req, testIdentity, time.Now()); codeOf(err) != CodeTimeout {
		t.Errorf("a cancelled context: %s, want %s", codeOf(err), CodeTimeout)
	}
	// The context's own timer has not fired: its deadline is an hour away by
	// the runtime's clock, and passed by the clock the adapter reads.
	ahead, stop := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer stop()
	later := func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := process(ahead, DefaultConfig(), req, testIdentity, time.Now(), later); codeOf(err) != CodeTimeout {
		t.Errorf("a deadline the clock has reached: %s, want %s", codeOf(err), CodeTimeout)
	}
	if _, err := process(ahead, DefaultConfig(), req, testIdentity, time.Now(), time.Now); err != nil {
		t.Errorf("a deadline still to come: %v", err)
	}
	// The deadline is an instant, and at that instant it has passed.
	at, _ := ahead.Deadline()
	if _, err := process(ahead, DefaultConfig(), req, testIdentity, time.Now(), func() time.Time { return at }); codeOf(err) != CodeTimeout {
		t.Errorf("a deadline at the instant the clock reads: %s, want %s", codeOf(err), CodeTimeout)
	}
	if _, err := process(ahead, DefaultConfig(), req, testIdentity, time.Now(), func() time.Time { return at.Add(-time.Nanosecond) }); err != nil {
		t.Errorf("a deadline a nanosecond away: %v", err)
	}
	// A deadline that passes while the file is written refuses the rendering
	// too: the clock is read once before the file is written, and says the
	// deadline is still to come, and once after it, and says it has passed.
	readings := 0
	passing := func() time.Time {
		readings++
		if readings == 1 {
			return time.Now()
		}
		return time.Now().Add(2 * time.Hour)
	}
	if out, err := process(ahead, DefaultConfig(), req, testIdentity, time.Now(), passing); codeOf(err) != CodeTimeout || out != nil {
		t.Errorf("a deadline that passed while the file was written: %s, want %s", codeOf(err), CodeTimeout)
	}
	// Where the deadline passed while the file was written and the file is
	// past its bound as well, the rendering is refused for the deadline: the
	// order of the refusals is the contract's.
	tiny := DefaultConfig()
	tiny.MaxFile = 1
	readings = 0
	if _, err := process(ahead, tiny, req, testIdentity, time.Now(), passing); codeOf(err) != CodeTimeout || readings != 2 {
		t.Errorf("a deadline that passed and a file past its bound: %s after %d readings of the clock, want %s after 2", codeOf(err), readings, CodeTimeout)
	}
	if _, err := process(ahead, tiny, req, testIdentity, time.Now(), time.Now); codeOf(err) != CodeFileOverBound {
		t.Errorf("a file past its bound with time left: %s, want %s", codeOf(err), CodeFileOverBound)
	}
}

// docxPart reads one part of a Word file.
func docxPart(t *testing.T, file []byte, name string) []byte {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatalf("the file is not a ZIP archive: %v", err)
	}
	for _, entry := range archive.File {
		if entry.Name == name {
			r, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			data, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("%s does not read: %v", name, err)
			}
			return data
		}
	}
	t.Fatalf("the file holds no %s", name)
	return nil
}

// read is what a test reads out of a document part: its paragraphs in
// order, each as its style, its list and its text, with the properties of
// each run written around the run's text.
type paragraphRead struct {
	Style string
	List  string
	Text  string
	// Cell is "r,c" for a paragraph inside a table's cell, and Header
	// whether its row is a header row.
	Cell   string
	Header bool
}

func readBody(t *testing.T, body []byte) []paragraphRead {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(body))
	var out []paragraphRead
	var p *paragraphRead
	var run strings.Builder
	var link string
	var bold, italic, code, inText bool
	row, column, header, inTable := 0, 0, false, false
	attr := func(e xml.StartElement, name string) string {
		for _, a := range e.Attr {
			if a.Name.Local == name {
				return a.Value
			}
		}
		return ""
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("the document part is not well formed: %v", err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			switch e.Name.Local {
			case "tbl":
				inTable, row = true, 0
			case "tr":
				row, column, header = row+1, 0, false
			case "tblHeader":
				header = true
			case "tc":
				column++
			case "p":
				p = &paragraphRead{}
				if inTable {
					p.Cell, p.Header = fmt.Sprintf("%d,%d", row, column), header
				}
			case "pStyle":
				p.Style = attr(e, "val")
			case "numId":
				p.List = attr(e, "val")
			case "hyperlink":
				link = attr(e, "id")
			case "r":
				run.Reset()
				bold, italic, code = false, false, false
			case "b":
				bold = true
			case "i":
				italic = true
			case "rFonts":
				code = attr(e, "ascii") == codeFont
			case "t":
				inText = true
				if attr(e, "space") != "preserve" {
					t.Errorf("a run's text does not say its spaces are kept")
				}
			case "br":
				run.WriteString("\n")
			case "tab":
				run.WriteString("\t")
			}
		case xml.CharData:
			if inText {
				run.Write(e)
			}
		case xml.EndElement:
			switch e.Name.Local {
			case "t":
				inText = false
			case "tbl":
				inTable = false
			case "hyperlink":
				link = ""
			case "r":
				text := run.String()
				for _, mark := range []struct {
					on   bool
					with string
				}{{code, "`"}, {italic, "_"}, {bold, "*"}} {
					if mark.on {
						text = mark.with + text + mark.with
					}
				}
				if link != "" {
					text = "[" + text + "](" + link + ")"
				}
				p.Text += text
			case "p":
				out = append(out, *p)
			}
		}
	}
}

// A Word file holds the text and the structure the request gave: every block
// in order, as the paragraph, the list or the table it was, every run with
// the properties it had, and every character of its text, the ones XML
// reserves among them.
func TestAWordFileHoldsTheTextAndTheStructure(t *testing.T) {
	_, file, _ := render(t, arguments("docx", sampleDocument), DefaultConfig())
	got := readBody(t, docxPart(t, file, "word/document.xml"))
	want := []paragraphRead{
		{Style: "Heading2", Text: "Refund decision"},
		{Text: "The refund of *149.50 CAD* is approved. See [the policy](rId3).\nSecond line\twith a tab, and <angle> & \"quotes\" &amp; 'apostrophes'."},
		{Style: "ListParagraph", List: "1", Text: "First"},
		{Style: "ListParagraph", List: "1", Text: "_Second_"},
		{Style: "ListParagraph", List: "2", Text: "日本語 (にほんご)"},
		{Style: "ListParagraph", List: "2", Text: "한국어"},
		{Style: "ListParagraph", List: "2", Text: "简体中文 繁體中文 粵語"},
		{Style: "ListParagraph", List: "2", Text: "español français português"},
		{Style: "ListParagraph", List: "3", Text: "Again from one"},
		{Cell: "1,1", Header: true, Text: "*Item*"},
		{Cell: "1,2", Header: true, Text: "*Amount*"},
		{Cell: "2,1", Text: "Refund"},
		{Cell: "2,2", Text: "`149.50`"},
		{Cell: "3,1", Text: "Fee"},
		{Cell: "3,2", Text: "`0.00`_ see _[the policy](rId3)*_` or `_*[write](rId4)"},
		// The paragraph a table is followed by where nothing else follows it.
		{},
	}
	if len(got) != len(want) {
		t.Fatalf("the document holds %d paragraphs, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("paragraph %d is %+v, want %+v", i+1, got[i], want[i])
		}
	}

	// The targets of the links are relationships of the document part, one
	// for each distinct target, in the order the body met them, and each is
	// outside the file.
	var rels struct {
		Relationship []struct {
			ID     string `xml:"Id,attr"`
			Type   string `xml:"Type,attr"`
			Target string `xml:"Target,attr"`
			Mode   string `xml:"TargetMode,attr"`
		}
	}
	if err := xml.Unmarshal(docxPart(t, file, "word/_rels/document.xml.rels"), &rels); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{}
	for _, r := range rels.Relationship {
		if r.Type == relHyperlink {
			if r.Mode != "External" {
				t.Errorf("the link %s is not marked as outside the file", r.ID)
			}
			links[r.ID] = r.Target
		}
	}
	if len(links) != 2 || links["rId3"] != "https://example.com/policy?a=1&b=2" || links["rId4"] != "mailto:refunds@example.com" {
		t.Errorf("the links are %v", links)
	}

	// Each list is its own instance of a numbering definition, the numbered
	// ones of the numbered definition, and each begins at one.
	var numbering struct {
		Num []struct {
			ID       string `xml:"numId,attr"`
			Abstract struct {
				Val string `xml:"val,attr"`
			} `xml:"abstractNumId"`
			Override struct {
				Start struct {
					Val string `xml:"val,attr"`
				} `xml:"startOverride"`
			} `xml:"lvlOverride"`
		} `xml:"num"`
	}
	if err := xml.Unmarshal(docxPart(t, file, "word/numbering.xml"), &numbering); err != nil {
		t.Fatal(err)
	}
	var lists []string
	for _, n := range numbering.Num {
		lists = append(lists, n.ID+" of "+n.Abstract.Val+" from "+n.Override.Start.Val)
	}
	if got, want := strings.Join(lists, "; "), "1 of 1 from 1; 2 of 0 from 1; 3 of 1 from 1"; got != want {
		t.Errorf("the lists are %q, want %q", got, want)
	}

	// The title and the language are the file's properties, and it states
	// no time and no author. The language is the default language of the
	// text as well.
	core := string(docxPart(t, file, "docProps/core.xml"))
	for _, want := range []string{"<dc:title>Refund decision</dc:title>", "<dc:language>en</dc:language>"} {
		if !strings.Contains(core, want) {
			t.Errorf("the properties do not hold %s: %s", want, core)
		}
	}
	if styles := string(docxPart(t, file, "word/styles.xml")); !strings.Contains(styles, `<w:lang w:val="en" w:eastAsia="en" w:bidi="en"/>`) {
		t.Errorf("the styles do not state the language: %s", styles)
	}
	// A title is text as a run's is: the characters XML reserves are its
	// own, and a document with no language states none.
	_, titled, _ := render(t, arguments("docx", `{"title":"Refunds & <returns> \"2026\"","blocks":[{"type":"paragraph","runs":[]}]}`), DefaultConfig())
	var properties struct {
		Title    string  `xml:"title"`
		Language *string `xml:"language"`
	}
	if err := xml.Unmarshal(docxPart(t, titled, "docProps/core.xml"), &properties); err != nil || properties.Title != `Refunds & <returns> "2026"` || properties.Language != nil {
		t.Errorf("the properties are %+v: %v", properties, err)
	}
	if styles := string(docxPart(t, titled, "word/styles.xml")); strings.Contains(styles, "w:lang") {
		t.Errorf("the styles of a document with no language state one: %s", styles)
	}
	for _, none := range []string{"created", "modified", "creator", "lastModifiedBy"} {
		if strings.Contains(core, none) {
			t.Errorf("the properties state %s: %s", none, core)
		}
	}
}

// A table is followed by a paragraph where a reader needs one: where the
// table is the last of the document, and where another table follows it. It
// is followed by none where a paragraph or a list follows it already.
func TestATableIsFollowedByAParagraph(t *testing.T) {
	table := `{"type":"table","rows":[[{"runs":[{"text":"cell"}]}]]}`
	paragraph := `{"type":"paragraph","runs":[{"text":"after"}]}`
	for name, c := range map[string]struct{ blocks, want string }{
		"a table that is the last":         {paragraph + "," + table, "after|cell@1,1|"},
		"a table followed by a paragraph":  {table + "," + paragraph, "cell@1,1|after"},
		"a table followed by a table":      {table + "," + table + "," + paragraph, "cell@1,1||cell@1,1|after"},
		"two tables that are the last two": {table + "," + table, "cell@1,1||cell@1,1|"},
	} {
		_, file, _ := render(t, arguments("docx", `{"title":"T","blocks":[`+c.blocks+`]}`), DefaultConfig())
		var got []string
		for _, p := range readBody(t, docxPart(t, file, "word/document.xml")) {
			if p.Cell != "" {
				p.Text += "@" + p.Cell
			}
			got = append(got, p.Text)
		}
		if strings.Join(got, "|") != c.want {
			t.Errorf("%s: the paragraphs are %q, want %q", name, strings.Join(got, "|"), c.want)
		}
	}
}

// What the writer chooses, the contract states, and the file holds as stated:
// the sizes, the spacing, the indents and the colour the request did not give.
func TestTheWritersDefaultsAreTheContracts(t *testing.T) {
	_, file, _ := render(t, arguments("docx", sampleDocument), DefaultConfig())
	styles := string(docxPart(t, file, "word/styles.xml"))
	for what, want := range map[string]string{
		"text at 11 points":                                      `<w:rPrDefault><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/>`,
		"8 points after a paragraph, lines at 1.08":              `<w:pPrDefault><w:pPr><w:spacing w:after="160" w:line="259" w:lineRule="auto"/></w:pPr></w:pPrDefault>`,
		"3 points after an item of a list, and none between two": `w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="60"/><w:contextualSpacing/></w:pPr>`,
		"a link in blue, underlined":                             `w:styleId="Hyperlink"><w:name w:val="Hyperlink"/><w:basedOn w:val="DefaultParagraphFont"/><w:rPr><w:color w:val="0563C1"/><w:u w:val="single"/></w:rPr>`,
		"a table with cell margins":                              `<w:left w:w="108" w:type="dxa"/>`,
		"a table with single borders":                            `<w:insideV w:val="single" w:sz="4" w:space="0" w:color="auto"/>`,
	} {
		if !strings.Contains(styles, want) {
			t.Errorf("%s: the styles do not hold %s", what, want)
		}
	}
	// 12 points before a heading and 4 after it.
	for level, points := range []int{16, 13, 12, 11, 11, 11} {
		want := fmt.Sprintf(`w:styleId="Heading%d"><w:name w:val="heading %d"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="%d"/></w:pPr><w:rPr><w:b/><w:bCs/><w:sz w:val="%d"/>`, level+1, level+1, level, 2*points)
		if !strings.Contains(styles, want) {
			t.Errorf("a heading of level %d at %d points, in bold, kept with what follows: the styles do not hold %s", level+1, points, want)
		}
	}
	numbering := string(docxPart(t, file, "word/numbering.xml"))
	for what, want := range map[string]string{
		"a bullet of a dot, indented half an inch and hanging a quarter": `<w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr>`,
		"numbers as 1., indented the same":                               `<w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr>`,
	} {
		if !strings.Contains(numbering, want) {
			t.Errorf("%s: the numbering does not hold %s", what, want)
		}
	}
	// A table is given the whole width of the text, and its layout is not
	// fixed: the widths its columns state are preferred ones.
	body := string(docxPart(t, file, "word/document.xml"))
	if !strings.Contains(body, `<w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/></w:tblPr>`) || strings.Contains(body, "tblLayout") {
		t.Errorf("the table's properties are not the contract's: %s", body)
	}
}

// An address is held to its form character by character: each of the
// characters that would begin a path, a scheme or a list refuses the target
// by itself, in an address that is otherwise one.
func TestAnAddressHoldsNoneOfTheCharactersOfAList(t *testing.T) {
	for _, c := range []string{`/`, `\\`, `:`, `,`, `;`, `<`, `>`, `\"`} {
		for _, target := range []string{"mailto:a" + c + "b@example.com", "mailto:a@example.com" + c + "b"} {
			raw := arguments("docx", `{"title":"T","blocks":[{"type":"paragraph","runs":[{"text":"x","link":"`+target+`"}]}]}`)
			_, err := parse(t, raw, DefaultConfig())
			if codeOf(err) != CodeContentInvalid || !strings.Contains(err.Error(), "a link's target names no address") {
				t.Errorf("%s: %v", target, err)
			}
		}
	}
}

// A target the adapter admits is in the file as it was given: read back out
// of the relationships, it is the same string, whatever characters it holds.
func TestAnAdmittedTargetIsWrittenAsGiven(t *testing.T) {
	// Each is written here as the request's JSON spells it.
	targets := []string{
		`https://example.com/`,
		`HTTPS://EXAMPLE.COM/Path`,
		`http://example.com:8080/a?b=1&c=2#frag`,
		`https://example.com/?q=<tag>&x='y'`,
		`https://user:secret@example.com/`,
		`https://[2001:db8::1]:8443/`,
		`https://example.com/日本語/한국어?q=é`,
		`https://example.com/\ufeff\u0085\u2028\ufffd`,
		`https://example.com/\ud83d\ude00`,
		`https://example.com/%00%0a%ff`,
		`mailto:a.b+c@example.com`,
		`mailto:a@example.com?subject=Refund%20decision&body=x`,
		`MAILTO:A@EXAMPLE.COM`,
	}
	var runs []string
	for _, target := range targets {
		runs = append(runs, `{"text":"x","link":"`+target+`"}`)
	}
	_, file, _ := render(t, arguments("docx", `{"title":"T","blocks":[{"type":"paragraph","runs":[`+strings.Join(runs, ",")+`]}]}`), DefaultConfig())
	var rels struct {
		Relationship []struct {
			ID     string `xml:"Id,attr"`
			Target string `xml:"Target,attr"`
			Mode   string `xml:"TargetMode,attr"`
		}
	}
	if err := xml.Unmarshal(docxPart(t, file, "word/_rels/document.xml.rels"), &rels); err != nil {
		t.Fatal(err)
	}
	written := map[string]string{}
	for _, r := range rels.Relationship {
		if r.Mode == "External" {
			written[r.ID] = r.Target
		}
	}
	if len(written) != len(targets) {
		t.Fatalf("the file holds %d targets, want %d", len(written), len(targets))
	}
	for i, target := range targets {
		var given string
		if err := json.Unmarshal([]byte(`"`+target+`"`), &given); err != nil {
			t.Fatal(err)
		}
		if got := written[fmt.Sprintf("rId%d", firstLinkRelationship+i)]; got != given {
			t.Errorf("the target %q is in the file as %q", given, got)
		}
	}
}

// Every column of a table states its width, in the grid and in each cell. A
// grid of two or more columns with no widths is a file LibreOffice 6.4
// refuses to open, though it is one other readers accept.
func TestATablesColumnsStateTheirWidths(t *testing.T) {
	document := `{"title":"T","blocks":[{"type":"table","rows":[[{"runs":[]},{"runs":[]},{"runs":[]}],[{"runs":[]},{"runs":[]},{"runs":[]}]]}]}`
	_, file, _ := render(t, arguments("docx", document), DefaultConfig())
	dec := xml.NewDecoder(bytes.NewReader(docxPart(t, file, "word/document.xml")))
	widths := map[string][]string{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e, ok := tok.(xml.StartElement); ok && (e.Name.Local == "gridCol" || e.Name.Local == "tcW") {
			width := ""
			for _, a := range e.Attr {
				if a.Name.Local == "w" {
					width = a.Value
				}
			}
			widths[e.Name.Local] = append(widths[e.Name.Local], width)
		}
	}
	if got := strings.Join(widths["gridCol"], " "); got != "3000 3000 3000" {
		t.Errorf("the grid's columns are %q wide, want three of 3000", got)
	}
	if got := strings.Join(widths["tcW"], " "); got != "3000 3000 3000 3000 3000 3000" {
		t.Errorf("the cells are %q wide, want six of 3000", got)
	}
}

// The same request yields the same file, byte for byte, and so does a
// request that spells the same content another way. A request whose content
// differs by one character yields another file and another content digest.
func TestAWordFileIsReproducible(t *testing.T) {
	first, file, _ := render(t, arguments("docx", sampleDocument), DefaultConfig())
	again, fileAgain, _ := render(t, arguments("docx", sampleDocument), DefaultConfig())
	if !bytes.Equal(file, fileAgain) || first.File.SHA256 != again.File.SHA256 {
		t.Fatal("the same request rendered twice gave two files")
	}
	// The same content with its members in another order, its spaces
	// elsewhere, and its characters written as escapes.
	var value any
	if err := json.Unmarshal([]byte(sampleDocument), &value); err != nil {
		t.Fatal(err)
	}
	respelt, err := json.MarshalIndent(value, " ", "\t")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(respelt, []byte(sampleDocument)) {
		t.Fatal("the second spelling is the first")
	}
	other, fileOther, _ := render(t, `{"document":`+string(respelt)+`,"format":"docx"}`, DefaultConfig())
	if !bytes.Equal(file, fileOther) {
		t.Error("the same content spelt another way gave another file")
	}
	if first.Request.ContentDigest != other.Request.ContentDigest {
		t.Error("the same content spelt another way has another content digest")
	}
	changed, fileChanged, _ := render(t, arguments("docx", strings.Replace(sampleDocument, "149.50 CAD", "149.51 CAD", 1)), DefaultConfig())
	if bytes.Equal(file, fileChanged) || first.File.SHA256 == changed.File.SHA256 {
		t.Error("content that differs gave the same file")
	}
	if first.Request.ContentDigest == changed.Request.ContentDigest {
		t.Error("content that differs has the same content digest")
	}
}

// The archive is written from the document and from nothing else: its
// entries are these, in this order, each under the one date, each with its
// sizes and its checksum in its own header, and none with anything beside
// them. Every part is well-formed XML, and every part the content types name
// is there.
func TestTheArchiveCarriesNothingOfTheEnvironment(t *testing.T) {
	_, file, _ := render(t, arguments("docx", sampleDocument), DefaultConfig())
	archive, err := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"[Content_Types].xml", "_rels/.rels", "docProps/core.xml", "word/document.xml", "word/_rels/document.xml.rels", "word/styles.xml", "word/numbering.xml"}
	var got []string
	for _, entry := range archive.File {
		got = append(got, entry.Name)
		// The first of January 1980, at midnight, as the archive states it
		// and as a reader of the archive reads it.
		if entry.ModifiedDate != 0x21 || entry.ModifiedTime != 0 || !entry.Modified.Equal(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%s is dated %#x at %#x, which is %v", entry.Name, entry.ModifiedDate, entry.ModifiedTime, entry.Modified)
		}
		if entry.CreatorVersion != 20 || entry.ReaderVersion != 20 {
			t.Errorf("%s states the versions %d and %d, want 20, which a deflated entry needs", entry.Name, entry.CreatorVersion, entry.ReaderVersion)
		}
		if entry.Flags != 0 || len(entry.Extra) != 0 || entry.Comment != "" || entry.Method != zip.Deflate {
			t.Errorf("%s has flags %#x, %d bytes beside it, the comment %q and method %d", entry.Name, entry.Flags, len(entry.Extra), entry.Comment, entry.Method)
		}
		data := docxPart(t, file, entry.Name)
		dec := xml.NewDecoder(bytes.NewReader(data))
		for {
			if _, err := dec.Token(); err == io.EOF {
				break
			} else if err != nil {
				t.Errorf("%s is not well formed: %v", entry.Name, err)
				break
			}
		}
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the entries are %v, want %v", got, want)
	}
	// What the archive's directory says of an entry, the entry's own header
	// says before it: the headers are gone through from the first byte of
	// the file, each followed by its name and its data and by nothing else.
	at := 0
	for _, entry := range archive.File {
		header := file[at:]
		if len(header) < 30 || string(header[:4]) != "PK\x03\x04" {
			t.Fatalf("%s: no entry begins at byte %d", entry.Name, at)
		}
		field := func(offset int) uint16 { return uint16(header[offset]) | uint16(header[offset+1])<<8 }
		long := func(offset int) uint32 { return uint32(field(offset)) | uint32(field(offset+2))<<16 }
		if field(4) != 20 || field(6) != 0 || field(8) != zip.Deflate || field(10) != 0 || field(12) != 0x21 {
			t.Errorf("%s: its header states version %d, flags %#x, method %d, time %#x and date %#x", entry.Name, field(4), field(6), field(8), field(10), field(12))
		}
		if long(14) != entry.CRC32 || uint64(long(18)) != entry.CompressedSize64 || uint64(long(22)) != entry.UncompressedSize64 {
			t.Errorf("%s: its header states the checksum %#x and the sizes %d and %d", entry.Name, long(14), long(18), long(22))
		}
		if int(field(26)) != len(entry.Name) || field(28) != 0 || string(header[30:30+len(entry.Name)]) != entry.Name {
			t.Errorf("%s: its header names it in %d bytes with %d bytes beside", entry.Name, field(26), field(28))
		}
		at += 30 + len(entry.Name) + int(entry.CompressedSize64)
	}
	if string(file[at:at+4]) != "PK\x01\x02" {
		t.Errorf("the directory does not begin where the last entry ends, at byte %d", at)
	}
	if archive.Comment != "" {
		t.Errorf("the archive has the comment %q", archive.Comment)
	}
	types := string(docxPart(t, file, "[Content_Types].xml"))
	for _, name := range want[2:] {
		if strings.HasSuffix(name, ".rels") {
			continue
		}
		if !strings.Contains(types, `PartName="/`+name+`"`) {
			t.Errorf("the content types do not name /%s", name)
		}
	}
}

// The record says of the file what is true of it, names the content by its
// digest, carries what the caller cited as the caller gave it, and passes the
// reference check.
func TestTheRecordSaysWhatWasRendered(t *testing.T) {
	decision := "sha256:" + strings.Repeat("0123456789abcdef", 4)
	raw := `{"format":"docx","document":` + sampleDocument + `,"cites":{"decision":"` + decision + `"}}`
	rec, file, out := render(t, raw, DefaultConfig())
	if err := Check(out); err != nil {
		t.Fatalf("the record does not pass its check: %v", err)
	}
	if rec.RenderVersion != "1" || rec.Request.Format != "docx" || rec.Request.Title != "Refund decision" || rec.Request.Language == nil || *rec.Request.Language != "en" {
		t.Errorf("the record's request is %+v", rec.Request)
	}
	if rec.Request.Blocks != 6 || rec.Request.Cites == nil || rec.Request.Cites.Decision != decision {
		t.Errorf("the record's request is %+v", rec.Request)
	}
	if rec.File.MediaType != MediaTypeDocx || rec.File.Size != int64(len(file)) || rec.File.SHA256 != digestOf(file) || rec.File.Encoding != "base64" {
		t.Errorf("the record's file is %+v for a file of %d bytes", rec.File, len(file))
	}
	if rec.Rendering.Status != "complete" || rec.Rendering.Renderer != (Renderer{Kind: "module", Name: "adapter-render/docx/1"}) {
		t.Errorf("the record's rendering is %+v", rec.Rendering)
	}
	if want := (Bounds{MaxRequestBytes: 1 << 20, MaxBlocks: 2000, MaxFileBytes: 4 << 20, MaxOutputBytes: 1 << 20, TimeoutMs: 25000}); rec.Rendering.Bounds != want {
		t.Errorf("the record's bounds are %+v, want %+v", rec.Rendering.Bounds, want)
	}
	if rec.Provenance.Adapter != testIdentity {
		t.Errorf("the record's adapter is %+v", rec.Provenance.Adapter)
	}
	// textBytes is the bytes of every run's text, counted here apart from
	// the adapter.
	var document struct {
		Blocks []json.RawMessage
	}
	if err := json.Unmarshal([]byte(sampleDocument), &document); err != nil {
		t.Fatal(err)
	}
	texts := 0
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if text, ok := v["text"].(string); ok {
				texts += len(text)
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	for _, block := range document.Blocks {
		var v any
		if err := json.Unmarshal(block, &v); err != nil {
			t.Fatal(err)
		}
		walk(v)
	}
	if rec.Request.TextBytes != int64(texts) {
		t.Errorf("textBytes is %d, and the runs hold %d bytes of text", rec.Request.TextBytes, texts)
	}

	// observedAt is when the request had been read, in UTC whatever zone the
	// instant was taken in, and durationMs runs from when the reading of the
	// request began, not from when it ended.
	req, err := parse(t, raw, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	began := time.Date(2026, 9, 28, 23, 30, 0, 0, time.FixedZone("east", 9*3600))
	req.ReceivedAt = began.Add(time.Second)
	timed, err := process(context.Background(), DefaultConfig(), req, testIdentity, began, func() time.Time { return began.Add(1500 * time.Millisecond) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"observedAt":"2026-09-28T14:30:01Z"`, `"durationMs":1500,`} {
		if !bytes.Contains(timed, []byte(want)) {
			t.Errorf("the record does not hold %s: %s", want, timed)
		}
	}
	// A clock that went backwards gives a duration of nothing, not a
	// negative one.
	timed, err = process(context.Background(), DefaultConfig(), req, testIdentity, began, func() time.Time { return began.Add(-time.Second) })
	if err != nil || !bytes.Contains(timed, []byte(`"durationMs":0,`)) {
		t.Errorf("the record of a clock that went backwards: %v: %s", err, timed)
	}

	// The adapter holds the record it built to the check before it writes
	// it, and writes none that does not pass: an identity with no version is
	// one the check refuses.
	unversioned := testIdentity
	unversioned.Version = ""
	if out, err := Process(context.Background(), DefaultConfig(), req, unversioned, time.Now()); codeOf(err) != CodeAdapterFailed || out != nil || !strings.Contains(err.Error(), "does not pass its own check") {
		t.Errorf("a record the check refuses: %v, with %d bytes of record", err, len(out))
	}

	// A request that cites nothing, and names no language, says so with null.
	plain, _, plainOut := render(t, arguments("docx", `{"title":"T","blocks":[{"type":"paragraph","runs":[]}]}`), DefaultConfig())
	if plain.Request.Cites != nil || plain.Request.Language != nil || !bytes.Contains(plainOut, []byte(`"cites":null`)) || !bytes.Contains(plainOut, []byte(`"language":null`)) {
		t.Errorf("the record of a request that cites nothing is %s", plainOut)
	}
}

// The reference check refuses a record that says of its file what is not
// true of it, and one that departs from the record's form. Each row is one
// departure from a record the check passes, with what the check says of it.
func TestTheCheckRefusesARecordThatIsNotOne(t *testing.T) {
	_, file, out := render(t, `{"format":"docx","document":`+sampleDocument+`,"cites":{"decision":"sha256:`+strings.Repeat("0", 64)+`"}}`, DefaultConfig())
	var rec map[string]any
	decode := func() {
		rec = nil
		dec := json.NewDecoder(bytes.NewReader(out))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
	}
	member := func(path ...string) map[string]any {
		at := rec
		for _, name := range path {
			at = at[name].(map[string]any)
		}
		return at
	}
	other := append([]byte{}, file...)
	other[len(other)-1] ^= 1
	type change struct {
		make func()
		says string
	}
	for name, c := range map[string]change{
		"a version that is not 1":           {func() { rec["renderVersion"] = "2" }, `renderVersion is not "1"`},
		"a version that is a number":        {func() { rec["renderVersion"] = json.Number("1") }, `renderVersion is not "1"`},
		"a member the record does not have": {func() { rec["saved"] = true }, "record: a member the contract does not define"},
		"no provenance":                     {func() { delete(rec, "provenance") }, "record: member provenance is missing"},
		"a request that is a string":        {func() { rec["request"] = "docx" }, "request: not a JSON object"},
		"a request with another member":     {func() { member("request")["name"] = "x" }, "request: a member the contract does not define"},
		"request without cites":             {func() { delete(member("request"), "cites") }, "request: member cites is missing"},
		"a format that is not the file's":   {func() { member("request")["format"] = "pdf" }, `request.format is not "docx"`},
		"a title that is empty":             {func() { member("request")["title"] = "" }, "request.title is not a title"},
		"a title of 256 bytes":              {func() { member("request")["title"] = strings.Repeat("é", 128) }, "request.title is not a title"},
		"a language that is no tag":         {func() { member("request")["language"] = "en us" }, "request.language is neither null nor a language tag"},
		"a language that is a number":       {func() { member("request")["language"] = json.Number("1") }, "request.language is neither null nor a language tag"},
		"a language past 35 bytes":          {func() { member("request")["language"] = "en-" + strings.Repeat("abcdefgh-", 3) + "abcdefgh" }, "request.language is neither null nor a language tag"},
		"a content digest that is not one":  {func() { member("request")["contentDigest"] = "sha256:abc" }, "request.contentDigest is not a digest"},
		"no block":                          {func() { member("request")["blocks"] = json.Number("0") }, "request.blocks is not a positive integer"},
		"blocks that is a string":           {func() { member("request")["blocks"] = "1" }, "request.blocks is not a positive integer"},
		"textBytes that is a string":        {func() { member("request")["textBytes"] = "1" }, "request.textBytes is not a non-negative integer"},
		"textBytes that is negative":        {func() { member("request")["textBytes"] = json.Number("-1") }, "request.textBytes is not a non-negative integer"},
		// An integer is read as it is written: nothing written with a sign
		// is one, though what it comes to is nothing.
		"textBytes written as -0":         {func() { member("request")["textBytes"] = json.Number("-0") }, "request.textBytes is not a non-negative integer"},
		"a duration written as -0":        {func() { member("rendering")["durationMs"] = json.Number("-0") }, "rendering.durationMs is not a non-negative integer"},
		"cites that is a string":          {func() { member("request")["cites"] = "x" }, "request.cites: not a JSON object"},
		"cites with another member":       {func() { member("request", "cites")["receipt"] = "x" }, "request.cites: a member the contract does not define"},
		"cites that is not a digest":      {func() { member("request", "cites")["decision"] = "x" }, "request.cites.decision is not a digest"},
		"a file that is a string":         {func() { rec["file"] = "x" }, "file: not a JSON object"},
		"a file with a name":              {func() { member("file")["name"] = "a.docx" }, "file: a member the contract does not define"},
		"a media type of another format":  {func() { member("file")["mediaType"] = "application/pdf" }, "file.mediaType is not the media type of the format"},
		"a size that is not the file's":   {func() { member("file")["size"] = json.Number(fmt.Sprint(len(file) + 1)) }, "file.size is not the size of the file"},
		"a size that is a string":         {func() { member("file")["size"] = fmt.Sprint(len(file)) }, "file.size is not a positive integer"},
		"a digest that is not the file's": {func() { member("file")["sha256"] = "sha256:" + strings.Repeat("0", 64) }, "file.sha256 is not the digest of the file"},
		"a digest that is not one":        {func() { member("file")["sha256"] = "sha256:0" }, "file.sha256 is not a digest"},
		"bytes that are another file's":   {func() { member("file")["bytes"] = base64.StdEncoding.EncodeToString(other) }, "file.sha256 is not the digest of the file"},
		"bytes without their padding": {func() {
			member("file")["bytes"] = strings.TrimRight(base64.StdEncoding.EncodeToString(file[:len(file)-len(file)%3-1]), "=")
		}, "file.bytes is not the one standard padded base64 encoding"},
		"bytes with a line break":        {func() { member("file")["bytes"] = member("file")["bytes"].(string) + "\n" }, "file.bytes is not the one standard padded base64 encoding"},
		"bytes that are empty":           {func() { member("file")["bytes"] = "" }, "file.bytes is not the one standard padded base64 encoding"},
		"an encoding that is not base64": {func() { member("file")["encoding"] = "hex" }, `file.encoding is not "base64"`},
		"a rendering that is a string":   {func() { rec["rendering"] = "x" }, "rendering: not a JSON object"},
		"a rendering with errors":        {func() { member("rendering")["errors"] = []any{} }, "rendering: a member the contract does not define"},
		"a status that is not complete":  {func() { member("rendering")["status"] = "partial" }, `rendering.status is not "complete"`},
		"a renderer that is a string":    {func() { member("rendering")["renderer"] = "module" }, "rendering.renderer: not a JSON object"},
		"a renderer that is a program":   {func() { member("rendering", "renderer")["kind"] = "program" }, `rendering.renderer.kind is not "module"`},
		"a renderer of another name":     {func() { member("rendering", "renderer")["name"] = "adapter-render/docx/2" }, "rendering.renderer.name is not the renderer of the format"},
		"a renderer with a digest":       {func() { member("rendering", "renderer")["digest"] = "sha256:" + strings.Repeat("0", 64) }, "rendering.renderer: a member the contract does not define"},
		"bounds that are a string":       {func() { member("rendering")["bounds"] = "x" }, "rendering.bounds: not a JSON object"},
		"bounds without the file's":      {func() { delete(member("rendering", "bounds"), "maxFileBytes") }, "rendering.bounds: member maxFileBytes is missing"},
		"a bound on blocks that is zero": {func() { member("rendering", "bounds")["maxBlocks"] = json.Number("0") }, "rendering.bounds.maxBlocks is not a positive integer"},
		// A bound past the ceiling an adapter can be configured with is
		// one no adapter wrote.
		"a bound on the request past its ceiling": {func() { member("rendering", "bounds")["maxRequestBytes"] = json.Number("67108865") }, "rendering.bounds.maxRequestBytes is not a positive integer of at most 67108864"},
		"a bound on blocks past its ceiling":      {func() { member("rendering", "bounds")["maxBlocks"] = json.Number("100001") }, "rendering.bounds.maxBlocks is not a positive integer of at most 100000"},
		"a bound on the file past its ceiling":    {func() { member("rendering", "bounds")["maxFileBytes"] = json.Number("67108865") }, "rendering.bounds.maxFileBytes is not a positive integer of at most 67108864"},
		"a bound on the output past its ceiling":  {func() { member("rendering", "bounds")["maxOutputBytes"] = json.Number("1099511627777") }, "rendering.bounds.maxOutputBytes is not a positive integer of at most 1099511627776"},
		"a timeout past its ceiling":              {func() { member("rendering", "bounds")["timeoutMs"] = json.Number("600001") }, "rendering.bounds.timeoutMs is not a positive integer of at most 600000"},
		"a bound on the request that is zero":     {func() { member("rendering", "bounds")["maxRequestBytes"] = json.Number("0") }, "rendering.bounds.maxRequestBytes is not a positive integer"},
		"a bound on the file that is zero":        {func() { member("rendering", "bounds")["maxFileBytes"] = json.Number("0") }, "rendering.bounds.maxFileBytes is not a positive integer"},
		"a bound on the output that is zero":      {func() { member("rendering", "bounds")["maxOutputBytes"] = json.Number("0") }, "rendering.bounds.maxOutputBytes is not a positive integer"},
		"a timeout that is zero":                  {func() { member("rendering", "bounds")["timeoutMs"] = json.Number("0") }, "rendering.bounds.timeoutMs is not a positive integer"},
		"a file past the bound the record has":    {func() { member("rendering", "bounds")["maxFileBytes"] = json.Number(fmt.Sprint(len(file) - 1)) }, "file.size is past rendering.bounds.maxFileBytes"},
		"a duration that is negative":             {func() { member("rendering")["durationMs"] = json.Number("-1") }, "rendering.durationMs is not a non-negative integer"},
		"a duration with a fraction":              {func() { member("rendering")["durationMs"] = json.Number("1.5") }, "the record is not JSON of the canonical domain"},
		"a duration past the domain":              {func() { member("rendering")["durationMs"] = json.Number("9007199254740992") }, "the record is not JSON of the canonical domain"},
		"provenance that is a string":             {func() { rec["provenance"] = "x" }, "provenance: not a JSON object"},
		"provenance with a source":                {func() { member("provenance")["source"] = nil }, "provenance: a member the contract does not define"},
		"an adapter that is a string":             {func() { member("provenance")["adapter"] = "adapter-render" }, "provenance.adapter: not a JSON object"},
		"an adapter of another name":              {func() { member("provenance", "adapter")["name"] = "adapter-document" }, `provenance.adapter.name is not "adapter-render"`},
		"an adapter with no version":              {func() { member("provenance", "adapter")["version"] = "" }, "provenance.adapter.version is not a non-empty string"},
		"an adapter whose digest is not one":      {func() { member("provenance", "adapter")["digest"] = "abc" }, "provenance.adapter.digest is not a digest"},
		"an instant that is a number":             {func() { member("provenance")["observedAt"] = json.Number("0") }, "provenance.observedAt is not a string"},
		"an instant with a zone":                  {func() { member("provenance")["observedAt"] = "2026-09-28T12:00:00+02:00" }, "provenance.observedAt is not a UTC instant to the second"},
		"an instant to the millisecond":           {func() { member("provenance")["observedAt"] = "2026-09-28T12:00:00.000Z" }, "provenance.observedAt is not a UTC instant to the second"},
		"an instant that is no day":               {func() { member("provenance")["observedAt"] = "2026-02-30T12:00:00Z" }, "provenance.observedAt is not a UTC instant to the second"},
	} {
		decode()
		c.make()
		changed, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := Check(changed); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: the check says %v, want it to say %q", name, err, c.says)
		}
	}
	decode()
	same, _ := json.Marshal(rec)
	if err := Check(same); err != nil {
		t.Fatalf("the record the rows depart from does not pass: %v", err)
	}
	// A record that cites nothing and names no language passes as well.
	member("request")["cites"], member("request")["language"] = nil, nil
	plain, _ := json.Marshal(rec)
	if err := Check(plain); err != nil {
		t.Fatalf("a record that cites nothing does not pass: %v", err)
	}
	for name, c := range map[string]struct{ raw, says string }{
		"a member given twice": {`{"renderVersion":"1","renderVersion":"1"}`, "the record is not JSON of the canonical domain"},
		"not JSON":             {`record`, "the record is not JSON of the canonical domain"},
		"an array":             {`[]`, "record: not a JSON object"},
		"a record nested deep": {`{"request":{"cites":{"decision":["sha256"]}}}`, "the record nests deeper than a record does"},
	} {
		if err := Check([]byte(c.raw)); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: the check says %v, want it to say %q", name, err, c.says)
		}
	}
}

// stored is one part of an archive as a test lays it out: what the entry's
// own header says, what the directory says, and the bytes between them.
type stored struct {
	name                   string
	version, flags, method uint16
	time, date             uint16
	sum, packed, unpacked  uint32
	beside                 []byte
	data                   []byte
	// own is what the entry's own header says where that is to differ from
	// the directory, or nil.
	own *stored
	// at is where the directory says the entry's header is, where that is to
	// differ from where it is, or -1.
	at int64
}

// layout is an archive: data before it, its parts, how many the record that
// ends it says there are, a comment, and data after it.
type layout struct {
	before, comment, after []byte
	parts                  []stored
	count                  int
}

// laidOut reads a file the adapter wrote into the layout that writes it
// again, each part compressed as the writer compresses it.
func laidOut(t *testing.T, file []byte) layout {
	t.Helper()
	archive, err := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatal(err)
	}
	var l layout
	for _, entry := range archive.File {
		plain := docxPart(t, file, entry.Name)
		var packed bytes.Buffer
		deflate, err := flate.NewWriter(&packed, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		deflate.Write(plain)
		deflate.Close()
		l.parts = append(l.parts, stored{
			name: entry.Name, version: 20, method: zip.Deflate, date: 0x21,
			sum: crc32.ChecksumIEEE(plain), packed: uint32(packed.Len()), unpacked: uint32(len(plain)),
			data: packed.Bytes(), at: -1,
		})
	}
	l.count = len(l.parts)
	return l
}

// bytes writes the archive, byte by byte as the format has it.
func (l layout) bytes() []byte {
	var out bytes.Buffer
	short := func(b *bytes.Buffer, v uint16) { b.Write([]byte{byte(v), byte(v >> 8)}) }
	long := func(b *bytes.Buffer, v uint32) { short(b, uint16(v)); short(b, uint16(v>>16)) }
	out.Write(l.before)
	var directory bytes.Buffer
	for _, p := range l.parts {
		at := int64(out.Len())
		own := p
		if p.own != nil {
			own = *p.own
		}
		out.WriteString("PK\x03\x04")
		short(&out, own.version)
		short(&out, own.flags)
		short(&out, own.method)
		short(&out, own.time)
		short(&out, own.date)
		long(&out, own.sum)
		long(&out, own.packed)
		long(&out, own.unpacked)
		short(&out, uint16(len(own.name)))
		short(&out, uint16(len(own.beside)))
		out.WriteString(own.name)
		out.Write(own.beside)
		out.Write(p.data)
		if p.at >= 0 {
			at = p.at
		}
		directory.WriteString("PK\x01\x02")
		short(&directory, p.version)
		short(&directory, p.version)
		short(&directory, p.flags)
		short(&directory, p.method)
		short(&directory, p.time)
		short(&directory, p.date)
		long(&directory, p.sum)
		long(&directory, p.packed)
		long(&directory, p.unpacked)
		short(&directory, uint16(len(p.name)))
		short(&directory, uint16(len(p.beside)))
		short(&directory, 0)
		short(&directory, 0)
		short(&directory, 0)
		long(&directory, 0)
		long(&directory, uint32(at))
		directory.WriteString(p.name)
		directory.Write(p.beside)
	}
	begins := out.Len()
	out.Write(directory.Bytes())
	out.WriteString("PK\x05\x06")
	short(&out, 0)
	short(&out, 0)
	short(&out, uint16(l.count))
	short(&out, uint16(l.count))
	long(&out, uint32(directory.Len()))
	long(&out, uint32(begins))
	short(&out, uint16(len(l.comment)))
	out.Write(l.comment)
	out.Write(l.after)
	return out.Bytes()
}

// The archive is what the contract says the writer writes, and nothing the
// contract does not say: written again from its parts by the rules of the
// format, one part after another with the directory after the last, it is
// the file, byte for byte.
func TestTheArchiveIsLaidOutAsTheContractSays(t *testing.T) {
	_, file, _ := render(t, arguments("docx", sampleDocument), DefaultConfig())
	if again := laidOut(t, file).bytes(); !bytes.Equal(again, file) {
		t.Fatalf("the archive written again from its parts is %d bytes and the file is %d, or they differ", len(again), len(file))
	}
}

// The check holds the file to being the archive the writer writes and to the
// bound on what its parts hold. Each row is the writer's archive with one
// thing about it changed, and what the check says of it. A file cut short
// anywhere is refused as well, and the check reads nothing past its end.
func TestTheCheckHoldsTheFileToTheWritersArchive(t *testing.T) {
	_, file, out := render(t, arguments("docx", sampleDocument), DefaultConfig())
	held := unpacked(t, file)
	with := func(file []byte, maxFile int64) []byte {
		t.Helper()
		var rec map[string]any
		dec := json.NewDecoder(bytes.NewReader(out))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		of := rec["file"].(map[string]any)
		of["bytes"], of["size"], of["sha256"] = base64.StdEncoding.EncodeToString(file), json.Number(fmt.Sprint(len(file))), digestOf(file)
		rec["rendering"].(map[string]any)["bounds"].(map[string]any)["maxFileBytes"] = json.Number(fmt.Sprint(maxFile))
		changed, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	if err := Check(with(file, held)); err != nil {
		t.Fatalf("a file whose parts are at the bound: %v", err)
	}
	const (
		notTheWriters = "file.bytes is not an archive of the seven parts as the adapter writes one"
		overBound     = "the parts of the file hold more than rendering.bounds.maxFileBytes"
		notAsStated   = "a part of the file does not hold what the archive states of it"
	)
	within := func(bound int64, change func(l *layout)) []byte {
		l := laidOut(t, file)
		change(&l)
		return with(l.bytes(), bound)
	}
	changed := func(change func(l *layout)) []byte { return within(1<<20, change) }
	// Another part for the rows that need one: the document part, as it is.
	document := laidOut(t, file).parts[3]
	plain := docxPart(t, file, document.name)
	for cut := 0; cut < len(file); cut += 7 {
		if err := Check(with(file[:cut+1], 1<<20)); cut+1 < len(file) && (err == nil || !strings.Contains(err.Error(), notTheWriters)) {
			t.Fatalf("the file cut to %d bytes: the check says %v", cut+1, err)
		}
	}
	for name, c := range map[string]struct {
		record []byte
		says   string
	}{
		"parts a byte past the bound":   {with(file, held-1), overBound},
		"a bound that is the archive's": {with(file, int64(len(file))), overBound},
		"a file that is no archive":     {with([]byte("not an archive, and long enough to hold the record that would end one: "+strings.Repeat("x", 600)), 1<<20), notTheWriters},
		"a file too short to be one":    {with([]byte("PK\x05\x06"), 1<<20), notTheWriters},
		"six parts":                     {changed(func(l *layout) { l.parts, l.count = l.parts[:6], 6 }), notTheWriters},
		"eight parts":                   {changed(func(l *layout) { l.parts, l.count = append(l.parts, document), 8 }), notTheWriters},
		"eight parts, said to be seven": {changed(func(l *layout) { l.parts = append(l.parts, document) }), notTheWriters},
		// Four thousand entries over one stream, each said to hold nothing:
		// refused for their number, by the record that ends the archive,
		// before any of them is read.
		"four thousand parts over one stream": {within(64<<20, func(l *layout) {
			empty := document
			empty.unpacked, empty.at = 0, 0
			for len(l.parts) < 4000 {
				l.parts = append(l.parts, empty)
			}
			l.count = len(l.parts)
		}), notTheWriters},
		"parts in another order":    {changed(func(l *layout) { l.parts[5], l.parts[6] = l.parts[6], l.parts[5] }), notTheWriters},
		"a part under another name": {changed(func(l *layout) { l.parts[3].name = "word/document.XML" }), notTheWriters},
		"a part twice, for another": {changed(func(l *layout) { l.parts[4] = l.parts[3] }), notTheWriters},
		"a part that is not compressed": {changed(func(l *layout) {
			l.parts[3].method, l.parts[3].data, l.parts[3].packed = zip.Store, plain, uint32(len(plain))
		}), notTheWriters},
		"a part compressed another way":   {changed(func(l *layout) { l.parts[3].method = 99 }), notTheWriters},
		"a part with a flag":              {changed(func(l *layout) { l.parts[3].flags = 0x800 }), notTheWriters},
		"a part of another day":           {changed(func(l *layout) { l.parts[3].date = 0x5b3c }), notTheWriters},
		"a part of another hour":          {changed(func(l *layout) { l.parts[3].time = 0x6000 }), notTheWriters},
		"a part of another version":       {changed(func(l *layout) { l.parts[3].version = 45 }), notTheWriters},
		"a part with something beside it": {changed(func(l *layout) { l.parts[3].beside = []byte{0x99, 0x99, 0, 0} }), notTheWriters},
		"a comment on the archive":        {changed(func(l *layout) { l.comment = []byte("a comment") }), notTheWriters},
		"data before the archive":         {changed(func(l *layout) { l.before = []byte("before") }), notTheWriters},
		"data after the archive":          {changed(func(l *layout) { l.after = []byte("after") }), notTheWriters},
		"a header with another checksum": {changed(func(l *layout) {
			own := l.parts[3]
			own.sum++
			l.parts[3].own = &own
		}), notTheWriters},
		"a header with another size": {changed(func(l *layout) {
			own := l.parts[3]
			own.unpacked++
			l.parts[3].own = &own
		}), notTheWriters},
		"a header with another name": {changed(func(l *layout) {
			own := l.parts[3]
			own.name = "word/document.xmL"
			l.parts[3].own = &own
		}), notTheWriters},
		"a header with something beside the name": {changed(func(l *layout) {
			own := l.parts[3]
			own.beside = []byte{0x99, 0x99, 0, 0}
			l.parts[3].own = &own
		}), notTheWriters},
		// The directory says two parts begin where one does, so that the
		// bytes of one would be read for both.
		"two parts over the same bytes":    {changed(func(l *layout) { l.parts[4].at = 0 }), notTheWriters},
		"a part that holds more than said": {changed(func(l *layout) { l.parts[3].unpacked-- }), notAsStated},
		"a part that holds less than said": {changed(func(l *layout) { l.parts[3].unpacked++ }), notAsStated},
		"a part whose checksum is not its": {changed(func(l *layout) { l.parts[3].sum++ }), notAsStated},
		// A checksum of nothing is one the archive's reader does not
		// compare. The check compares it.
		"a part whose checksum is said to be nothing": {changed(func(l *layout) { l.parts[3].sum = 0 }), notAsStated},
		"a part that says it is past the bound":       {changed(func(l *layout) { l.parts[3].unpacked = 1<<20 + 1 }), overBound},
		// The largest a part can say it is, in the archive's 32 bits, under
		// the largest bound a record can state: refused for the bound,
		// before the archive is written again, which at that size would
		// state the part in another way than the writer does.
		"a part that says it is as long as can be said": {within(64<<20, func(l *layout) { l.parts[3].unpacked = 1<<32 - 1 }), overBound},
		// The archive is the writer's in every byte, and one part's data
		// holds three bytes after what it holds.
		"a part with bytes after what it holds": {changed(func(l *layout) {
			l.parts[3].data = append(append([]byte{}, l.parts[3].data...), 0, 0, 0)
			l.parts[3].packed += 3
		}), notAsStated},
		// The archive is the writer's in every byte, and one part's data is
		// all of what it holds with no end to it: a reader that stopped at
		// the length stated would not find that out.
		"a part whose data does not end": {changed(func(l *layout) {
			var open bytes.Buffer
			deflate, _ := flate.NewWriter(&open, flate.BestCompression)
			deflate.Write(plain)
			deflate.Flush()
			l.parts[3].data, l.parts[3].packed = open.Bytes(), uint32(open.Len())
		}), notAsStated},
		"a part said to be longer than the file": {changed(func(l *layout) {
			own := l.parts[0]
			own.packed = 1 << 30
			l.parts[0].own = &own
		}), notTheWriters},
		"a part said to be as long as can be said": {changed(func(l *layout) {
			own := l.parts[0]
			own.packed = 1<<32 - 1
			l.parts[0].own = &own
		}), notTheWriters},
	} {
		if err := Check(c.record); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: the check says %v, want it to say %q", name, err, c.says)
		}
	}
}

// A record whose bounds are each at its ceiling passes, and a part is read no
// further than it states and one byte: a reader that would give a mebibyte
// is asked for eleven bytes where the part states ten.
func TestTheCheckAtTheCeilingsAndTheReadOfAPart(t *testing.T) {
	_, _, out := render(t, arguments("docx", sampleDocument), Config{MaxRequest: 64 << 20, MaxBlocks: 100_000, MaxFile: 64 << 20, MaxOutput: 1 << 40, Timeout: 10 * time.Minute})
	if err := Check(out); err != nil {
		t.Fatalf("a record whose bounds are at their ceilings: %v", err)
	}
	source := &counted{left: 1 << 20}
	held, sum, err := readNoMoreThan(source, 11)
	if err != nil || held != 11 || source.given != 11 || sum != crc32.ChecksumIEEE(make([]byte, 11)) {
		t.Fatalf("a reader of a mebibyte was given %d bytes and asked for %d: %v", held, source.given, err)
	}
	source = &counted{left: 5}
	if held, sum, err := readNoMoreThan(source, 11); err != nil || held != 5 || source.given != 5 || sum != crc32.ChecksumIEEE(make([]byte, 5)) {
		t.Fatalf("a reader of five bytes was given %d bytes: %v", held, err)
	}
}

// counted is a reader of so many zero bytes that counts the bytes it gave.
type counted struct{ left, given int }

func (c *counted) Read(p []byte) (int, error) {
	if c.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), c.left)
	clear(p[:n])
	c.left -= n
	c.given += n
	return n, nil
}

// The readers of single values take a value of their own kind, written as
// the canonical domain writes it, and nothing else: null is no string, no
// array and no boolean, and an integer is digits.
func TestTheReadersOfSingleValues(t *testing.T) {
	for raw, want := range map[string]int64{"0": 0, "7": 7, " 12 ": 12, "9007199254740991": 9007199254740991} {
		if n, ok := integerOf(json.RawMessage(raw)); !ok || n != want {
			t.Errorf("integerOf(%q) is %d, %v", raw, n, ok)
		}
	}
	for _, raw := range []string{"", " ", "-1", "+1", "1.0", "1e3", "01", "00", `"1"`, "null", "true", "9007199254740992", "99999999999999999", "123456789012345678901234567890"} {
		if n, ok := integerOf(json.RawMessage(raw)); ok {
			t.Errorf("integerOf(%q) is %d", raw, n)
		}
	}
	var text string
	if !stringInto(json.RawMessage(` "aé" `), &text) || text != "aé" {
		t.Errorf("stringInto reads %q", text)
	}
	for _, raw := range []string{"", "null", "1", "true", `["a"]`, `{"a":"b"}`, `"unterminated`} {
		if stringInto(json.RawMessage(raw), &text) {
			t.Errorf("stringInto(%q) is a string", raw)
		}
	}
	var flag bool
	if !boolInto(json.RawMessage(" true "), &flag) || !flag || !boolInto(json.RawMessage("false"), &flag) || flag {
		t.Error("boolInto does not read true and false")
	}
	for _, raw := range []string{"", "null", "1", "0", `"true"`, "TRUE", "[true]"} {
		if boolInto(json.RawMessage(raw), &flag) {
			t.Errorf("boolInto(%q) is a boolean", raw)
		}
	}
	if values, ok := arrayOf(json.RawMessage(` [1, "a", {}] `)); !ok || len(values) != 3 {
		t.Errorf("arrayOf reads %d values, %v", len(values), ok)
	}
	if values, ok := arrayOf(json.RawMessage(`[]`)); !ok || len(values) != 0 {
		t.Errorf("arrayOf reads %d values of an empty array, %v", len(values), ok)
	}
	for _, raw := range []string{"", "null", "1", `"[]"`, `{}`, `[1,`} {
		if _, ok := arrayOf(json.RawMessage(raw)); ok {
			t.Errorf("arrayOf(%q) is an array", raw)
		}
	}
	if members, ok := membersOf(json.RawMessage(` {"a":1,"A":2} `)); !ok || len(members) != 2 || string(members["a"]) != "1" || string(members["A"]) != "2" {
		t.Errorf("membersOf reads %v, %v", members, ok)
	}
	for _, raw := range []string{"", "null", "1", `"{}"`, `[]`, `{"a":`} {
		if _, ok := membersOf(json.RawMessage(raw)); ok {
			t.Errorf("membersOf(%q) is an object", raw)
		}
	}
}

// The depth of a JSON text is the brackets that stand open outside its
// strings: a bracket inside a string is text, and so is one after a quotation
// mark that a backslash has made part of the string.
func TestTheDepthOfTheArguments(t *testing.T) {
	for raw, depth := range map[string]int{
		``:                        0,
		`"x"`:                     0,
		`{}`:                      1,
		`[[],[],[]]`:              2,
		`{"a":{"b":[1,{"c":2}]}}`: 4,
		`{"a":"[[[[{{{{"}`:        1,
		`{"a":"\"[[[["}`:          1,
		`{"a":"\\","b":[[]]}`:     3,
		`{"[[":{"]]":[]}}`:        3,
		// Text that is not JSON is counted as it stands, and refused for
		// what it is by what reads it next.
		`]]]]{[`: 2,
		`[[[[`:   4,
	} {
		if depth > 0 && nestedWithin([]byte(raw), depth-1) {
			t.Errorf("%s is within %d", raw, depth-1)
		}
		if !nestedWithin([]byte(raw), depth) {
			t.Errorf("%s is not within %d", raw, depth)
		}
	}
	// The deepest the contract admits is a run in a cell of a table, and
	// the sample holds one.
	if !nestedWithin([]byte(arguments("docx", sampleDocument)), maxNesting) || nestedWithin([]byte(arguments("docx", sampleDocument)), maxNesting-1) {
		t.Errorf("the sample does not nest exactly %d deep", maxNesting)
	}
}

// stalled is a request that never arrives: a read of it does not return
// until the test ends.
type stalled struct{ until chan struct{} }

func (s stalled) Read([]byte) (int, error) {
	<-s.until
	return 0, io.EOF
}

// broken is a request whose read fails.
type broken struct{}

func (broken) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// A request that cannot be read is a failure of the adapter, and the reason
// says which: one whose read failed, or one that had not arrived when the
// deadline had passed.
func TestARequestThatIsNotReadIsRefused(t *testing.T) {
	_, err := ParseRequest(context.Background(), broken{}, DefaultConfig(), time.Now)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != CodeAdapterFailed || refusal.Reason != "stdin could not be read" {
		t.Errorf("a read that failed: %v", err)
	}
	// The deadline is three seconds gone, so the wait for the request is at
	// its floor and the test does not wait the two seconds a fresh deadline
	// would allow.
	past, cancel := context.WithDeadline(context.Background(), time.Now().Add(-3*time.Second))
	defer cancel()
	never := stalled{until: make(chan struct{})}
	defer close(never.until)
	_, err = ParseRequest(past, never, DefaultConfig(), time.Now)
	if !errors.As(err, &refusal) || refusal.Code != CodeAdapterFailed || !strings.Contains(refusal.Reason, "the deadline passed and the request had not been read in full") {
		t.Errorf("a request that never arrived: %v", err)
	}
}

// The examples beside the contract are what the adapter writes: the record
// passes the check, the request yields the record's account of it, and the
// file the request yields holds the parts the example's file holds, each the
// same once it is read out of the archive. The archives themselves are not
// compared, since another build may compress the same parts to other bytes.
func TestTheExamplesAreWhatTheAdapterWrites(t *testing.T) {
	const examples = "../../testdata/rendering/examples/"
	request, err := os.ReadFile(examples + "refund-decision.request.json")
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(examples + "refund-decision.record.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(example); err != nil {
		t.Fatalf("the example record does not pass the check: %v", err)
	}
	var want Record
	if err := json.Unmarshal(example, &want); err != nil {
		t.Fatal(err)
	}
	got, file, _ := render(t, string(request), DefaultConfig())
	if !reflect.DeepEqual(got.Request, want.Request) {
		t.Errorf("the request is recorded as %+v, and the example has %+v", got.Request, want.Request)
	}
	if got.File.MediaType != want.File.MediaType || got.Rendering.Status != want.Rendering.Status || got.Rendering.Renderer != want.Rendering.Renderer || got.Rendering.Bounds != want.Rendering.Bounds {
		t.Errorf("the rendering is recorded as %+v, and the example has %+v", got.Rendering, want.Rendering)
	}
	exampleFile, err := base64.StdEncoding.DecodeString(want.File.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(exampleFile), int64(len(exampleFile)))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != 7 {
		t.Fatalf("the example's file holds %d parts", len(archive.File))
	}
	for _, entry := range archive.File {
		if !bytes.Equal(docxPart(t, file, entry.Name), docxPart(t, exampleFile, entry.Name)) {
			t.Errorf("%s is not the example's: the example is to be written again by the adapter", entry.Name)
		}
	}
}

// Where pandoc is installed, it reads the file and finds the text: a reader
// this repository did not write. The test says what it ran, and is skipped
// where the program is not there.
func TestAnotherReaderReadsTheFile(t *testing.T) {
	pandoc, err := exec.LookPath("pandoc")
	if err != nil {
		t.Skip("pandoc is not installed")
	}
	_, file, _ := render(t, arguments("docx", sampleDocument), DefaultConfig())
	cmd := exec.Command(pandoc, "--from", "docx", "--to", "plain", "--wrap", "none")
	cmd.Stdin = bytes.NewReader(file)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("pandoc does not read the file: %v", err)
	}
	for _, want := range []string{"The refund of 149.50 CAD is approved. See the policy.", `<angle> & "quotes" &amp; 'apostrophes'.`, "日本語 (にほんご)", "한국어", "简体中文 繁體中文 粵語", "español français português", "Again from one", "149.50"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("pandoc reads no %q in:\n%s", want, out)
		}
	}
}

func TestTheConfigurationIsHeldToItsCeilings(t *testing.T) {
	if err := DefaultConfig().Check(); err != nil {
		t.Fatalf("the default configuration is refused: %v", err)
	}
	for name, change := range map[string]func(*Config){
		"no request":               func(c *Config) { c.MaxRequest = 0 },
		"a request past 64 MiB":    func(c *Config) { c.MaxRequest = 64<<20 + 1 },
		"no block":                 func(c *Config) { c.MaxBlocks = 0 },
		"blocks past 100,000":      func(c *Config) { c.MaxBlocks = 100_001 },
		"no file":                  func(c *Config) { c.MaxFile = 0 },
		"a file past 64 MiB":       func(c *Config) { c.MaxFile = 64<<20 + 1 },
		"no output":                func(c *Config) { c.MaxOutput = 0 },
		"an output past its limit": func(c *Config) { c.MaxOutput = 1<<40 + 1 },
		"no time":                  func(c *Config) { c.Timeout = 0 },
		"a time past ten minutes":  func(c *Config) { c.Timeout = 10*time.Minute + time.Millisecond },
		"a time to the microsecond": func(c *Config) {
			c.Timeout = 1500 * time.Microsecond
		},
	} {
		cfg := DefaultConfig()
		change(&cfg)
		if err := cfg.Check(); err == nil {
			t.Errorf("%s: the configuration is admitted", name)
		}
	}
	for name, cfg := range map[string]Config{
		"every bound at its ceiling": {MaxRequest: 64 << 20, MaxBlocks: 100_000, MaxFile: 64 << 20, MaxOutput: 1 << 40, Timeout: 10 * time.Minute},
		"every bound at one":         {MaxRequest: 1, MaxBlocks: 1, MaxFile: 1, MaxOutput: 1, Timeout: time.Millisecond},
	} {
		if err := cfg.Check(); err != nil {
			t.Errorf("%s: refused, %v", name, err)
		}
	}
}

// A refusal is written as one line of ASCII, the code first, at most 160
// bytes: what the caller wrote is not echoed past that, nor as it was where
// it was not ASCII.
func TestARefusalIsOneBoundedLineOfASCII(t *testing.T) {
	line := (&Refusal{Code: CodeContentInvalid, Reason: "naïve\n" + strings.Repeat("x", 400)}).Line()
	if len(line) != 160 || !strings.HasPrefix(line, "content-invalid: na??ve?xxx") {
		t.Errorf("the line is %d bytes: %q", len(line), line)
	}
	for _, c := range []byte(line) {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("the line holds the byte %#x", c)
		}
	}
	// A refusal names the block it is about and no member the caller wrote.
	_, err := parse(t, arguments("docx", `{"title":"T","blocks":[{"type":"paragraph","runs":[]},{"type":"paragraph","runs":[],"secret-member":1}]}`), DefaultConfig())
	var refusal *Refusal
	if !errors.As(err, &refusal) || !strings.HasPrefix(refusal.Reason, "block 2: ") || strings.Contains(refusal.Reason, "secret") {
		t.Errorf("the refusal is %v", err)
	}
}
