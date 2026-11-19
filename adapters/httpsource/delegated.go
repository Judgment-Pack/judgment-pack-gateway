package httpsource

// A token step whose JWT-bearer assertion names a delegated subject and is
// signed by the service account credentials API
// (docs/adr/0045-a-delegated-subject-token-signed-by-the-credentials-api.md):
// at each token request the adapter asks the platform's metadata server,
// at the address metadata.go has built in, for an access token of the
// compute's own identity; asks the credentials API, at the address built in
// here, to sign the claims iss the service account, sub the subject, scope
// the scopes and aud the token endpoint, all fixed by the configuration;
// and exchanges the signed JWT at the token endpoint by the JWT-bearer
// grant. No key is read: the service account's key stays with the
// credentials API. The metadata access token and the signed JWT are held
// in this process's memory for the one request, kept out of every
// diagnostic, and written nowhere. This file opens no file.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"adapters/internal/canon"
)

// credentialsAPIBase is the service account credentials API, built in: the
// metadata access token is the compute's bearer for every API its scopes
// reach, and no configuration, flag or environment variable sends it
// elsewhere. Only this package's tests set it, to a local stand-in.
var credentialsAPIBase = "https://iamcredentials.googleapis.com"

const (
	// metadataTokenPath is the metadata server's access token of the
	// compute's default identity, asked with no query.
	metadataTokenPath = "/computeMetadata/v1/instance/service-accounts/default/token"
	// maxSignedJWT bounds the signed JWT the credentials API answers.
	maxSignedJWT = 16 << 10
	// jwtBearerGrant is RFC 7523's grant type.
	jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

var (
	// serviceAccountForm is a service account's address under a project's
	// iam.gserviceaccount.com domain, as the engine holds it
	// (go/token_step.go); it refuses the default compute and App Engine
	// accounts. It is the one value that enters the credentials API's path,
	// and it admits no / % ? # or :.
	serviceAccountForm = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	// subjectForm is the delegated subject's address, at most 254 bytes.
	subjectForm = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

// delegatedScopes are the read-only Admin SDK scopes a step of this form
// may ask for, as the engine holds them; admin.directory.user.security is
// not among them, since it also deletes a user's tokens and signs a user
// out.
var delegatedScopes = map[string]bool{
	"https://www.googleapis.com/auth/admin.directory.user.readonly":           true,
	"https://www.googleapis.com/auth/admin.directory.group.readonly":          true,
	"https://www.googleapis.com/auth/admin.directory.group.member.readonly":   true,
	"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly": true,
	"https://www.googleapis.com/auth/admin.reports.audit.readonly":            true,
}

// holdDelegated holds a step of this form to its rules: no client
// identifier, the service account and the subject of their forms, and a
// scope of one or more of delegatedScopes, each once. A refusal repeats no
// value.
func holdDelegated(t *TokenStep) error {
	switch {
	case t.ClientID != "":
		return errors.New("--client-id is not given beside --signed-by-service-account: the JWT-bearer grant authenticates no client, and the assertion's iss is the service account")
	case !serviceAccountForm.MatchString(t.ServiceAccount):
		return errors.New("--signed-by-service-account is NAME@PROJECT.iam.gserviceaccount.com, NAME and PROJECT each 6 to 30 lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen")
	case len(t.Subject) > 254 || !subjectForm.MatchString(t.Subject):
		return errors.New("--token-subject is an address of at most 254 bytes: 1 to 64 letters, digits and . _ + -, an @, and a domain of dot-separated labels of letters, digits and hyphens")
	}
	seen := map[string]bool{}
	for _, scope := range strings.Split(t.Scope, " ") {
		if !delegatedScopes[scope] || seen[scope] {
			return errors.New("--token-scope is one or more of the Admin SDK's read-only scopes ADR-0045 lists, each once, separated by single spaces")
		}
		seen[scope] = true
	}
	return nil
}

// metadataAccessToken asks the metadata server, under every rule its
// identity token is asked under (metadata.go), for an access token of the
// compute's default identity: GET, no query, Metadata-Flavor: Google, the
// answer taken only with that header once, no redirect followed, at most
// 64 KiB read as a token endpoint's answer is. Every failure is
// TokenNoCredential, but a 429 or 503 with the header, which is the
// throttled answer.
func metadataAccessToken(ctx context.Context, now time.Time) (string, error) {
	refuse := func(why string) (string, error) {
		return "", tokenFailure(TokenNoCredential, "the token step's metadata server %s; no token was requested", why)
	}
	client, err := metadataClient()
	if err != nil {
		return refuse("could not be asked")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataBase+metadataTokenPath, nil)
	if err != nil {
		return refuse("could not be asked")
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return refuse("answered with a redirect, which is not followed")
		}
		return refuse("could not be reached in time")
	}
	defer resp.Body.Close()
	if flavor := resp.Header.Values("Metadata-Flavor"); len(flavor) != 1 || flavor[0] != "Google" {
		return refuse("answered without Metadata-Flavor: Google")
	}
	if throttles(resp.StatusCode) {
		return "", throttled(resp.StatusCode, resp.Header.Values("Retry-After"), now, fmt.Sprintf("the token step's metadata server refused the access token request (%d)", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK {
		return refuse(fmt.Sprintf("refused the access token request (%d)", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse+1))
	if err != nil {
		return refuse("answered with an access token that could not be read whole")
	}
	if len(raw) > maxTokenResponse {
		return refuse("answered with more than 64 KiB")
	}
	obtained, err := parseTokenAnswer(raw)
	if err != nil {
		return refuse("answered with no access token this adapter takes")
	}
	return obtained.value, nil
}

// delegatedClaims are the claims the credentials API is asked to sign, in
// this order: iss the service account, sub the subject, scope the scopes,
// aud the token endpoint, all as configured, and iat and exp the assertion
// lifetime apart.
type delegatedClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// signDelegated asks the credentials API to sign the step's claims as the
// service account, authenticated by the metadata access token: POST
// .../v1/projects/-/serviceAccounts/SA:signJwt, TLS 1.2 or later, no
// redirect followed, ten seconds. The answer is taken only as status 200,
// at most 64 KiB of application/json, no member named twice, keyId a
// string and signedJwt a compact JWS of at most 16 KiB whose payload's iss,
// sub, scope, aud and exp are the ones asked for. Every failure is
// TokenNoCredential, but a 429 or 503, which is the throttled answer; no
// token request follows either.
func signDelegated(ctx context.Context, t *TokenStep, access string, now time.Time) (string, error) {
	refuse := func(why string) (string, error) {
		return "", tokenFailure(TokenNoCredential, "the token step's credentials API %s; no token was requested", why)
	}
	claims := delegatedClaims{Iss: t.ServiceAccount, Sub: t.Subject, Scope: t.Scope, Aud: t.Endpoint, Iat: now.Unix(), Exp: now.Add(assertionLifetime).Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		return refuse("could not be asked")
	}
	body, err := json.Marshal(struct {
		Payload string `json:"payload"`
	}{string(payload)})
	if err != nil {
		return refuse("could not be asked")
	}
	// The service account is of serviceAccountForm (holdDelegated), so the
	// path is sent as written.
	target := credentialsAPIBase + "/v1/projects/-/serviceAccounts/" + t.ServiceAccount + ":signJwt"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return refuse("could not be asked")
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "judgment-pack-adapter-http/"+Version)
	resp, err := tokenClient().Do(req)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return refuse("answered with a redirect, which is not followed")
		}
		return refuse("could not be reached in time")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse+1))
	if err != nil {
		return refuse("answered with a signed JWT that could not be read whole")
	}
	if throttles(resp.StatusCode) {
		return "", throttled(resp.StatusCode, resp.Header.Values("Retry-After"), now, fmt.Sprintf("the token step's credentials API refused the signing request (%d)", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK {
		return refuse(fmt.Sprintf("refused the signing request (%d)", resp.StatusCode))
	}
	if len(raw) > maxTokenResponse {
		return refuse("answered with more than 64 KiB")
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != "application/json" {
		return refuse("answered with no signed JWT this adapter takes")
	}
	signed, ok := signedJWTOf(raw)
	if !ok {
		return refuse("answered with no signed JWT this adapter takes")
	}
	if !signedClaimsAre(signed, claims) {
		return refuse("answered with a signed JWT of other claims than were asked for")
	}
	return signed, nil
}

// signedJWTOf is the signedJwt of a credentials API answer: an object, no
// member named twice, of exactly keyId, a string, and signedJwt, a compact
// JWS of at most 16 KiB.
func signedJWTOf(raw []byte) (string, bool) {
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return "", false
	}
	members, err := exactMembers(raw)
	if err != nil || len(members) != 2 {
		return "", false
	}
	var keyID, signed string
	for name, into := range map[string]*string{"keyId": &keyID, "signedJwt": &signed} {
		text := bytes.TrimSpace(members[name])
		if len(text) == 0 || text[0] != '"' || json.Unmarshal(text, into) != nil {
			return "", false
		}
	}
	if signed == "" || len(signed) > maxSignedJWT || !compactJWS.MatchString(signed) {
		return "", false
	}
	return signed, true
}

// signedClaimsAre is whether the signed JWT's payload is exactly the iss,
// sub, scope, aud, iat and exp asked for: each member once, by its exact
// name, and no other. The signature is the token endpoint's to verify; the
// adapter reads the claims only so an assertion of other claims is not sent.
// The payload is read by exactMembers, since a decoder into a struct takes
// ISS for iss and keeps the last of two members of one name.
func signedClaimsAre(signed string, want delegatedClaims) bool {
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(signed, ".")[1])
	if err != nil {
		return false
	}
	members, err := exactMembers(payload)
	if err != nil || len(members) != 6 {
		return false
	}
	for _, name := range []string{"iss", "sub", "scope", "aud", "iat", "exp"} {
		if _, ok := members[name]; !ok {
			return false
		}
	}
	var got delegatedClaims
	if json.Unmarshal(payload, &got) != nil {
		return false
	}
	return got == want
}

// delegatedAssertion is the assertion of a step of this form: the metadata
// access token asked for, then the claims signed under it. Both are added
// to secrets for every diagnostic after.
func delegatedAssertion(ctx context.Context, t *TokenStep, secrets *[]string) (string, error) {
	access, err := metadataAccessToken(ctx, time.Now())
	if err != nil {
		return "", err
	}
	*secrets = append(*secrets, access)
	return signDelegated(ctx, t, access, time.Now())
}
