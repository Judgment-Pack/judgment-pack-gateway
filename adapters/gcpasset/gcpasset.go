// Package gcpasset is the gateway's read-only Cloud Asset Inventory adapter
// (docs/adr/0039-a-read-only-asset-inventory-connection-for-configuration-drift.md,
// with its Amendment): one assets.list call per acquisition for one
// configured project, its page projected to an allow-list per asset type
// and returned in the envelope SPEC.md §6 states. It is read-only by check,
// not by assumption:
//
//   - it holds two tokens, each narrow to its use: one of the cloudasset
//     scope for the list call alone, one of the cloud-platform.read-only
//     scope for projects.testIamPermissions alone, and the scopes each token
//     was granted are read and held to the one requested (scope.go);
//   - each time it obtains a token -- at the gateway's start and at every
//     refresh -- it asks testIamPermissions on every configured project
//     whether the credential holds any of a fixed list of write
//     permissions, and refuses if it does or if the platform answers a
//     call with anything else; a check that could not finish -- the run's
//     time ended, a request timed out or the connection failed before the
//     platform answered -- seals and uses no token, and is no refusal
//     (writecheck.go);
//   - on every IAM_POLICY page it serves, it refuses a binding of its own
//     principal, or of allUsers or allAuthenticatedUsers, to a role outside
//     a fixed list of read-only predefined roles (project.go).
//
// It keeps no cursor: the platform's nextPageToken is returned as written,
// or null, and never followed. It imports nothing of the core module.
package gcpasset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"adapters/internal/canon"
	"adapters/internal/redact"
)

// Version is what the adapter reports of itself in the receipt's adapter
// member, beside the digest of its own executable, which is what pins it.
var Version = "0"

const (
	adapterName = "adapter-gcp-asset"
	stampLayout = "2006-01-02T15:04:05Z"

	// AssetScope is the one scope the list token is requested with; it
	// reaches the Cloud Asset API alone.
	AssetScope = "https://www.googleapis.com/auth/cloudasset"
	// CheckScope is the one scope the check token is requested with: it
	// reads every API the identity's roles allow and writes through none,
	// and it is used for projects.testIamPermissions and nothing else.
	CheckScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

	// The content types a configuration may serve.
	ContentResource  = "RESOURCE"
	ContentIAMPolicy = "IAM_POLICY"

	// MembersCountUsers is the one reduction a configuration may name.
	MembersCountUsers = "count-users"

	// The token sources this version takes (Amendment A3): the metadata
	// server of the platform's own compute, and a service-account key.
	TokenSourceMetadata = "metadata"
	TokenSourceKey      = "key"

	// DefaultMaxAnswer bounds the list call's answer as read, before it is
	// projected; maxAnswerCeiling is the largest --max-answer taken.
	DefaultMaxAnswer = 8 << 20
	maxAnswerCeiling = 64 << 20
	// maxOutputCeiling is the largest --max-output taken.
	maxOutputCeiling = 1 << 40
	// maxRequestBytes bounds what is read from stdin.
	maxRequestBytes = 64 << 10
	// maxPageToken bounds a page token a request names.
	maxPageToken = 8192
	// maxPageSize is the platform's own bound on a page.
	maxPageSize = 1000
	// maxParents and maxAssetTypes bound a configuration's lists.
	maxParents    = 64
	maxAssetTypes = 32
	// maxNesting bounds how deep an upstream answer may nest before it is
	// decoded at all: the deepest answer the projections read is under
	// twenty levels.
	maxNesting = 64
	// errorBodyBytes is how much of a refusing answer's body is read to
	// classify it.
	errorBodyBytes = 64 << 10
	maxHeaderBytes = 64 << 10
)

// requestTimeout bounds each upstream request inside the run's own time. A
// request it ends brings back no answer, so a read-only check it was part
// of is incomplete, not refused (errCheckIncomplete). A test of this
// package shortens it, and no build of the command can change it.
var requestTimeout = 15 * time.Second

// Exit statuses, beside 1 (a failure of any other kind) and 2 (usage). The
// token statuses are the token step's (adapters/httpsource), read by the
// gateway in the same way.
const (
	StatusNoCredential     = 3
	StatusTokenRefused     = 4
	StatusRejectedBySource = 5
	StatusSealUnusable     = 6
	// ReferenceExpiredStatus is an expired page token (SPEC.md §6).
	ReferenceExpiredStatus = 8
	// RefusedStatus is a read-only refusal: credential-scope-unknown,
	// credential-can-write or credential-bound-at-resource. The gateway
	// closes the source on it.
	RefusedStatus = 9
)

// SealedTokenVariable is the environment variable a sealed list token is
// handed to an acquisition in.
const SealedTokenVariable = "ADAPTER_GCP_ASSET_SEALED_TOKEN"

// Config is one invocation's configuration, from the command line the
// gateway spawned the adapter with.
type Config struct {
	// Parents are the projects a request may name, each
	// projects/<project-id>.
	Parents []string
	// AssetTypes are the asset types served, each with a projection.
	AssetTypes []string
	// ContentTypes are RESOURCE, IAM_POLICY or both.
	ContentTypes []string
	// Members is "" or MembersCountUsers.
	Members string
	// TokenSource is TokenSourceMetadata or TokenSourceKey.
	TokenSource string
	// Credentials is the platform's live credentials file: the service
	// account's key for TokenSourceKey; for TokenSourceMetadata, an object
	// of strings whose sealKey seals the list token between runs.
	Credentials string
	// MaxOutput bounds the envelope; MaxAnswer the list call's answer.
	MaxOutput, MaxAnswer int64
	// SealedToken is the list token an earlier --token-only run obtained,
	// checked and sealed; empty, an acquisition obtains and checks its own.
	SealedToken string
}

// Request is the canonical arguments the gateway hands the adapter on
// stdin.
type Request struct {
	Parent      string
	ContentType string
	AssetTypes  []string
	// PageToken is "" when the request sent none (absent or null).
	PageToken string
	// PageSize is 0 when the request named none.
	PageSize int
	// ReadTime is "" when the request named none.
	ReadTime string
}

var (
	// projectID is a project identifier: 6 to 30 lower-case letters, digits
	// and hyphens, from a letter, to no hyphen.
	projectID     = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	folderParent  = regexp.MustCompile(`^folders/[0-9]+$`)
	assetTypeForm = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z0-9-]+)*\.googleapis\.com/[A-Z][A-Za-z0-9]*$`)
	pageTokenForm = regexp.MustCompile(`^[\x21-\x7e]+$`)
	statusCode    = regexp.MustCompile(`^[A-Z_]{1,64}$`)
)

// ParentProblem holds a parent to the form this version reads,
// projects/<project-id> (Amendment A2). A folder is refused by name, since
// folders are not read in this version.
func ParentProblem(parent string) error {
	if folderParent.MatchString(parent) {
		return errors.New("is a folder, and this version reads projects only")
	}
	id, ok := strings.CutPrefix(parent, "projects/")
	if !ok || !projectID.MatchString(id) {
		return errors.New("is not projects/<project-id>")
	}
	return nil
}

// prepareConfig holds the configuration to its rules, before any credential
// is read or any connection made.
func prepareConfig(cfg Config) error {
	if len(cfg.Parents) == 0 || len(cfg.Parents) > maxParents {
		return fmt.Errorf("--parents must name 1 to %d projects", maxParents)
	}
	for i, p := range cfg.Parents {
		if err := ParentProblem(p); err != nil {
			return fmt.Errorf("--parents[%d] %v", i, err)
		}
		if contains(cfg.Parents[:i], p) {
			return fmt.Errorf("--parents[%d] repeats an earlier parent", i)
		}
	}
	if len(cfg.AssetTypes) == 0 || len(cfg.AssetTypes) > maxAssetTypes {
		return fmt.Errorf("--asset-types must name 1 to %d asset types", maxAssetTypes)
	}
	for i, t := range cfg.AssetTypes {
		if _, ok := resourceProjections[t]; !ok {
			return fmt.Errorf("--asset-types[%d] has no projection in this version; the asset types served are %s", i, strings.Join(ServedAssetTypes(), ", "))
		}
		if contains(cfg.AssetTypes[:i], t) {
			return fmt.Errorf("--asset-types[%d] repeats an earlier asset type", i)
		}
	}
	if len(cfg.ContentTypes) == 0 || len(cfg.ContentTypes) > 2 {
		return errors.New("--content-types must name RESOURCE, IAM_POLICY or both")
	}
	for i, c := range cfg.ContentTypes {
		if c != ContentResource && c != ContentIAMPolicy {
			return fmt.Errorf("--content-types[%d] is neither RESOURCE nor IAM_POLICY", i)
		}
		if contains(cfg.ContentTypes[:i], c) {
			return fmt.Errorf("--content-types[%d] repeats an earlier content type", i)
		}
	}
	if cfg.Members != "" && cfg.Members != MembersCountUsers {
		return errors.New(`--members is "count-users" or not given`)
	}
	if cfg.TokenSource != TokenSourceMetadata && cfg.TokenSource != TokenSourceKey {
		return errors.New(`--token-source is "metadata" or "key"`)
	}
	if cfg.Credentials == "" {
		return errors.New("--credentials names the platform's live credentials file")
	}
	if cfg.MaxOutput <= 0 || cfg.MaxOutput > maxOutputCeiling {
		return fmt.Errorf("--max-output must be between 1 and %d bytes", int64(maxOutputCeiling))
	}
	if cfg.MaxAnswer <= 0 || cfg.MaxAnswer > maxAnswerCeiling {
		return fmt.Errorf("--max-answer must be between 1 and %d bytes", int64(maxAnswerCeiling))
	}
	return nil
}

var requestMembers = map[string]bool{"parent": true, "contentType": true, "assetTypes": true, "pageToken": false, "pageSize": false, "readTime": false}

// ParseRequest reads the request strictly: one JSON object in the canonical
// domain, no member named twice, its members among parent, contentType and
// assetTypes (required) and pageToken, pageSize and readTime (optional); a
// pageToken of null is a request that sends none.
func ParseRequest(r io.Reader) (Request, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxRequestBytes+1))
	if err != nil {
		return Request{}, fmt.Errorf("the request could not be read: %v", err)
	}
	if len(raw) > maxRequestBytes {
		return Request{}, fmt.Errorf("the request exceeds %d bytes", maxRequestBytes)
	}
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return Request{}, fmt.Errorf("the request is not one JSON value in the canonical domain: %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return Request{}, errors.New("the request is not a JSON object")
	}
	for name := range members {
		if _, known := requestMembers[name]; !known {
			return Request{}, fmt.Errorf("the request names a member %q this source does not take", name)
		}
	}
	for name, required := range requestMembers {
		if _, present := members[name]; required && !present {
			return Request{}, fmt.Errorf("the request names no %s", name)
		}
	}
	var req Request
	if !stringMember(members["parent"], &req.Parent) {
		return Request{}, errors.New("parent must be a string")
	}
	if !stringMember(members["contentType"], &req.ContentType) {
		return Request{}, errors.New("contentType must be a string")
	}
	if json.Unmarshal(members["assetTypes"], &req.AssetTypes) != nil || len(req.AssetTypes) == 0 || len(req.AssetTypes) > maxAssetTypes {
		return Request{}, fmt.Errorf("assetTypes must be an array of 1 to %d strings", maxAssetTypes)
	}
	if raw, present := members["pageToken"]; present && string(bytes.TrimSpace(raw)) != "null" {
		if !stringMember(raw, &req.PageToken) || len(req.PageToken) > maxPageToken || !pageTokenForm.MatchString(req.PageToken) {
			return Request{}, fmt.Errorf("pageToken must be null or a string of 1 to %d printable ASCII characters without spaces", maxPageToken)
		}
	}
	if raw, present := members["pageSize"]; present {
		n, err := strconv.Atoi(string(bytes.TrimSpace(raw)))
		if err != nil || n < 1 || n > maxPageSize {
			return Request{}, fmt.Errorf("pageSize must be an integer from 1 to %d", maxPageSize)
		}
		req.PageSize = n
	}
	if raw, present := members["readTime"]; present {
		if !stringMember(raw, &req.ReadTime) || len(req.ReadTime) > 64 {
			return Request{}, errors.New("readTime must be an RFC 3339 timestamp")
		}
		if _, err := time.Parse(time.RFC3339Nano, req.ReadTime); err != nil {
			return Request{}, errors.New("readTime must be an RFC 3339 timestamp")
		}
	}
	return req, nil
}

// stringMember decodes raw into s when it is a JSON string.
func stringMember(raw json.RawMessage, s *string) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '"' && json.Unmarshal(trimmed, s) == nil
}

// ParentNotConfigured is the refusal of a request naming a parent outside
// the configured set. It names the parent the request gave, the caller's
// own text, and is raised before any credential is used.
type ParentNotConfigured struct{ Parent string }

func (e *ParentNotConfigured) Error() string {
	return fmt.Sprintf("parent-not-configured: %q is not a parent this source serves", e.Parent)
}

// Admits holds a request to the configuration: a configured parent, a
// configured content type, and asset types among the configured ones, each
// once. The parent is held first, as the decision orders it.
func Admits(cfg Config, req Request) error {
	if !contains(cfg.Parents, req.Parent) {
		return &ParentNotConfigured{Parent: req.Parent}
	}
	if !contains(cfg.ContentTypes, req.ContentType) {
		return errors.New("contentType is not one this source serves")
	}
	for i, t := range req.AssetTypes {
		if !contains(cfg.AssetTypes, t) {
			return fmt.Errorf("assetTypes[%d] is not one this source serves", i)
		}
		if contains(req.AssetTypes[:i], t) {
			return fmt.Errorf("assetTypes[%d] repeats an earlier asset type", i)
		}
	}
	return nil
}

// listURL is the list call's URL, and the endpoint the receipt names: the
// URL without its query.
func listURL(req Request) (full, endpoint string) {
	endpoint = endpoints.Asset + "/v1/" + req.Parent + "/assets"
	q := url.Values{}
	q["assetTypes"] = append([]string(nil), req.AssetTypes...)
	q.Set("contentType", req.ContentType)
	if req.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(req.PageSize))
	}
	if req.PageToken != "" {
		q.Set("pageToken", req.PageToken)
	}
	if req.ReadTime != "" {
		q.Set("readTime", req.ReadTime)
	}
	return endpoint + "?" + q.Encode(), endpoint
}

// Acquire is one acquisition: the request held to the configuration before
// any credential is used, the list token opened (or obtained and checked
// for this one use), one list call, and the page projected into the
// envelope.
func Acquire(ctx context.Context, cfg Config, req Request) ([]byte, error) {
	if err := prepareConfig(cfg); err != nil {
		return nil, err
	}
	if err := Admits(cfg, req); err != nil {
		return nil, err
	}
	s, err := newSource(cfg)
	if err != nil {
		return nil, err
	}
	out, err := s.acquire(ctx, req)
	if err != nil {
		return nil, s.redacted(err)
	}
	return out, nil
}

func (s *source) acquire(ctx context.Context, req Request) ([]byte, error) {
	token, principal, err := s.listToken(ctx)
	if err != nil {
		return nil, err
	}
	full, endpoint := listURL(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, errors.New("the list request could not be formed")
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "judgment-pack-"+adapterName+"/"+Version)
	resp, err := s.api.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("the list call did not answer in time")
		}
		if errors.Is(err, errRedirect) {
			return nil, errRedirect
		}
		return nil, errors.New("the list call could not be sent")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		head, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyBytes))
		return nil, listRefusal(resp.StatusCode, resp.Header.Get("Content-Type"), head, req)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxAnswer+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("the list call did not answer in time")
		}
		return nil, errors.New("the list call's answer could not be read whole")
	}
	observedAt := time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	if int64(len(body)) > s.cfg.MaxAnswer {
		return nil, fmt.Errorf("the list call's answer exceeds %d bytes", s.cfg.MaxAnswer)
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != "application/json" {
		return nil, errors.New("the list call's answer is not application/json")
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, errors.New("the list call's answer is content-encoded; this adapter asks for none")
	}
	// An answer that repeats the token would carry it into the result and
	// the receipt; it is refused, never rewritten.
	if bytes.Contains(body, []byte(token)) {
		return nil, errors.New("the list call's answer repeats the credential, so nothing of it is carried")
	}
	page, err := s.projectPage(body, req, principal)
	if err != nil {
		return nil, err
	}
	return s.envelope(req, endpoint, page, peerIdentityOf(resp), observedAt)
}

// listRefusal is a list call answered with a status other than 200: an
// expired page token (ReferenceExpired) where the form decision 2 names is
// answered to a request that sent one; the token refused, said by its kind
// so the gateway drops it; and otherwise the status and the platform's
// error status, nothing of its message, which may quote what was sent.
func listRefusal(status int, contentType string, head []byte, req Request) error {
	if status == http.StatusUnauthorized {
		return &TokenFailure{Kind: StatusRejectedBySource, text: "the list call refused the token (401); the request is not sent again"}
	}
	if req.PageToken != "" && expiredPageToken(status, contentType, head) {
		return &ReferenceExpired{}
	}
	return fmt.Errorf("the list call answered %d %s%s", status, http.StatusText(status), platformStatus(head))
}

// expiredPageToken is decision 2's one mapped form (unconfirmed, A4): 400,
// a JSON body whose error.status is INVALID_ARGUMENT, with a
// google.rpc.BadRequest detail whose field violation names the page token.
func expiredPageToken(status int, contentType string, head []byte) bool {
	if status != http.StatusBadRequest {
		return false
	}
	if mediaType, _, _ := mime.ParseMediaType(contentType); mediaType != "application/json" {
		return false
	}
	if _, err := canon.Canonicalize(head, canon.CarryNumbersAsText); err != nil {
		return false
	}
	answer, _ := object(head)
	e, _ := object(answer["error"])
	var code string
	if !stringMember(e["status"], &code) || code != "INVALID_ARGUMENT" {
		return false
	}
	details, _ := array(e["details"])
	for _, raw := range details {
		d, _ := object(raw)
		var kind string
		if !stringMember(d["@type"], &kind) || kind != "type.googleapis.com/google.rpc.BadRequest" {
			continue
		}
		violations, _ := array(d["fieldViolations"])
		for _, raw := range violations {
			v, _ := object(raw)
			var field string
			if stringMember(v["field"], &field) && (field == "page_token" || field == "pageToken") {
				return true
			}
		}
	}
	return false
}

// platformStatus is ": <error.status>" of a JSON error answer when that is
// an upper-case code, and "" otherwise.
func platformStatus(head []byte) string {
	answer, _ := object(head)
	e, _ := object(answer["error"])
	var status string
	if !stringMember(e["status"], &status) || !statusCode.MatchString(status) {
		return ""
	}
	return ": " + status
}

// ReferenceExpired is an expired page token: the command exits with
// ReferenceExpiredStatus and writes Report on stdout beside it.
type ReferenceExpired struct{}

func (e *ReferenceExpired) Error() string {
	return "the list call refused the page token the request sent as no longer honoured (400 INVALID_ARGUMENT, page token)"
}

// Report is {"referenceExpired": {"status": 410}}, as SPEC.md §6 defines it.
func (e *ReferenceExpired) Report() []byte {
	return []byte(`{"referenceExpired":{"status":410}}`)
}

type adapterIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type acquisition struct {
	Adapter       adapterIdentity `json:"adapter"`
	Endpoint      *string         `json:"endpoint"`
	Statement     *string         `json:"statement"`
	Snapshot      *string         `json:"snapshot"`
	PeerIdentity  *string         `json:"peerIdentity"`
	Schema        *string         `json:"schema"`
	UpstreamToken *string         `json:"upstreamToken"`
	ObservedAt    string          `json:"observedAt"`
}

type envelope struct {
	Acquisition acquisition     `json:"acquisition"`
	Result      json.RawMessage `json:"result"`
}

// statement is the request as the receipt commits to it, under a salt the
// gateway draws: the parent, the content type, the asset types and what of
// the page the request named.
type statement struct {
	Parent      string   `json:"parent"`
	ContentType string   `json:"contentType"`
	AssetTypes  []string `json:"assetTypes"`
	PageToken   string   `json:"pageToken,omitempty"`
	PageSize    int      `json:"pageSize,omitempty"`
	ReadTime    string   `json:"readTime,omitempty"`
}

// envelope is SPEC.md §6's envelope for one list call: the projected page
// as the result; this adapter, the list URL without its query, the request
// as the statement, the page's readTime as the snapshot and the TLS peer's
// certificate as the acquisition.
func (s *source) envelope(req Request, endpoint string, page *projectedPage, peer *string, observedAt string) ([]byte, error) {
	identity, err := ownIdentity()
	if err != nil {
		return nil, err
	}
	encoded, err := canon.EncodeJSON(statement{Parent: req.Parent, ContentType: req.ContentType, AssetTypes: req.AssetTypes, PageToken: req.PageToken, PageSize: req.PageSize, ReadTime: req.ReadTime})
	if err != nil {
		return nil, err
	}
	text, err := canon.Canonicalize(encoded, canon.RefuseNumbers)
	if err != nil {
		return nil, err
	}
	result, err := canon.EncodeJSON(page)
	if err != nil {
		return nil, err
	}
	if result, err = canon.Canonicalize(result, canon.CarryNumbersAsText); err != nil {
		return nil, err
	}
	out, err := canon.EncodeJSON(envelope{Acquisition: acquisition{
		Adapter: identity, Endpoint: ptr(endpoint), Statement: ptr(string(text)),
		Snapshot: page.ReadTime, PeerIdentity: peer, ObservedAt: observedAt,
	}, Result: result})
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > s.cfg.MaxOutput {
		return nil, fmt.Errorf("the envelope exceeds the output bound of %d bytes", s.cfg.MaxOutput)
	}
	return out, nil
}

// peerIdentityOf is the TLS peer's leaf certificate digest, or nil.
func peerIdentityOf(resp *http.Response) *string {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	sum := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	return ptr("tls:sha256:" + hex.EncodeToString(sum[:]))
}

// ownIdentity is this adapter as the receipt names the program that read:
// its name, its version and the digest of its own executable.
func ownIdentity() (adapterIdentity, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return adapterIdentity{}, errors.New("the adapter's own executable could not be located for its digest")
	}
	file, err := os.Open(exe)
	if err != nil {
		return adapterIdentity{}, errors.New("the adapter's own executable could not be read for its digest")
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return adapterIdentity{}, errors.New("the adapter's own executable could not be read for its digest")
	}
	return adapterIdentity{Name: adapterName, Version: Version, Digest: "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}

// checkReport is what Check writes: the list endpoint, the token source,
// and the write check's result. It is for the operator connecting the
// platform, and nothing is minted from it.
type checkReport struct {
	Status      string          `json:"status"`
	Adapter     adapterIdentity `json:"adapter"`
	Endpoint    string          `json:"endpoint"`
	TokenSource string          `json:"tokenSource"`
	WriteCheck  writeCheckDone  `json:"writeCheck"`
}

type writeCheckDone struct {
	List        string `json:"list"`
	Permissions int    `json:"permissions"`
	Parents     int    `json:"parents"`
}

// FailedCheck is the report of a check that did not succeed, beside the
// exit status.
func FailedCheck(reason string) []byte {
	out, _ := canon.EncodeJSON(map[string]any{"check": map[string]string{"status": "failed", "message": reason}})
	return out
}

// Check obtains both tokens, holds their scopes to the ones requested, and
// runs the write check on every configured project, as a start does; it
// lists nothing.
func Check(ctx context.Context, cfg Config) ([]byte, error) {
	if err := prepareConfig(cfg); err != nil {
		return nil, err
	}
	s, err := newSource(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := s.obtainChecked(ctx); err != nil {
		return nil, s.redacted(err)
	}
	identity, err := ownIdentity()
	if err != nil {
		return nil, err
	}
	return canon.EncodeJSON(map[string]any{"check": checkReport{Status: "succeeded", Adapter: identity, Endpoint: endpoints.Asset,
		TokenSource: cfg.TokenSource, WriteCheck: writeCheckDone{List: WriteListVersion, Permissions: len(writeList), Parents: len(cfg.Parents)}}})
}

// Secrets is every scalar of the credentials file, for redacting a
// diagnostic raised before an acquisition was prepared.
func Secrets(cfg Config) []string {
	if cfg.Credentials == "" {
		return nil
	}
	data, err := redact.ReadCredentials(cfg.Credentials)
	if err != nil {
		return nil
	}
	return redact.SecretsOf(data)
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func ptr(s string) *string { return &s }
