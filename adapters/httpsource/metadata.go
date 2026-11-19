package httpsource

// A federated token asked of the platform's metadata server (gateway #502,
// docs/adr/0043-a-federated-token-from-the-platforms-metadata-server.md):
// in place of a file, the identity token the token step presents as its
// client assertion is asked of the metadata server of the compute the
// adapter runs on, for the one audience the configuration names. The
// address is built in, as an IP literal: no configuration member, flag or
// environment variable names it, no resolver is asked where it is, no
// proxy carries the request, and the connection is dialed to it alone. The
// token is held in this process's memory for the one token request that
// presents it, and nothing writes it.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"adapters/internal/metadataclient"
)

// metadataBase is the metadata server: the platform's fixed link-local
// address, written as an IP literal so that no resolver is asked where it
// is. A test of this package points it at a stand-in; nothing a
// configuration, a flag or the environment holds changes it.
var metadataBase = metadataclient.Address

const (
	// metadataIdentityPath is the identity token's path on the metadata
	// server, of the compute's default service account.
	metadataIdentityPath = "/computeMetadata/v1/instance/service-accounts/default/identity"
	// metadataTimeout bounds the metadata request, inside the
	// acquisition's own time.
	metadataTimeout = 5 * time.Second
	// identityMargin is how long before its exp an identity token is no
	// longer presented, so the token request does not carry one that
	// lapses on the way.
	identityMargin = 60 * time.Second
	// sealKeyMember is the credentials member a metadata token step's
	// sealed token is sealed under, at least minSealKey bytes: the
	// identity token changes at the metadata server's will, and an
	// acquisition handed a sealed token asks it nothing.
	sealKeyMember = "sealKey"
	minSealKey    = 32
)

var (
	// audienceForm is the audience's closed form: 1 to 256 ASCII letters,
	// digits and . _ ~ : / @ -, so it can add no query member and names no
	// host of its own; it is percent-encoded besides.
	audienceForm = regexp.MustCompile(`^[A-Za-z0-9._~:/@-]{1,256}$`)
	// compactJWS is a JWT in the compact serialization: three base64url
	// parts.
	compactJWS = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
)

// metadataClient is the client the identity token is asked with, the one
// the adapters share (adapters/internal/metadataclient): no proxy, a
// connection dialed to metadataBase's address and port alone, no redirect
// followed -- one would be an answer from somewhere else -- and the request
// bounded in time.
func metadataClient() (*http.Client, error) {
	return metadataclient.New(metadataBase, metadataTimeout)
}

// metadataIdentityToken asks the metadata server for an identity token of
// the audience and reads the answer strictly: Metadata-Flavor: Google,
// exactly once, before anything else is read of it; status 200, or 429 or
// 503, which are a throttled answer (throttle.go); at most 16 KiB, a
// compact JWS whose payload's aud is the audience asked, as a string, and
// whose exp is an integer more than identityMargin after now. The claims
// are read, not verified: the token endpoint verifies the token. Any other
// answer, and none, is TokenNoCredential -- no token request is sent -- by
// a fixed sentence that quotes nothing of it.
func metadataIdentityToken(ctx context.Context, audience string, now time.Time) (string, error) {
	refuse := func(why string) (string, error) {
		return "", tokenFailure(TokenNoCredential, "the token step's metadata server %s; no token was requested", why)
	}
	if !audienceForm.MatchString(audience) {
		return refuse("was not asked, the audience being out of form")
	}
	client, err := metadataClient()
	if err != nil {
		return refuse("could not be asked")
	}
	query := url.Values{"audience": {audience}, "format": {"full"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataBase+metadataIdentityPath+"?"+query.Encode(), nil)
	if err != nil {
		return refuse("could not be asked")
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, metadataclient.ErrRedirect) {
			return refuse("answered with a redirect, which is not followed")
		}
		return refuse("could not be reached in time")
	}
	defer resp.Body.Close()
	if !metadataclient.Flavored(resp.Header) {
		return refuse("answered without Metadata-Flavor: Google")
	}
	if throttles(resp.StatusCode) {
		// Said by its own kind, as the token endpoint's throttled answer
		// is: no token was obtained.
		return "", throttled(resp.StatusCode, resp.Header.Values("Retry-After"), now, fmt.Sprintf("the token step's metadata server refused the identity token request (%d)", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK {
		return refuse(fmt.Sprintf("refused the identity token request (%d)", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFederatedToken+1))
	if err != nil {
		return refuse("answered with an identity token that could not be read whole")
	}
	if len(raw) > maxFederatedToken {
		return refuse("answered with more than 16 KiB")
	}
	token := strings.TrimSpace(string(raw))
	aud, exp, ok := identityClaims(token)
	switch {
	case !ok:
		return refuse("answered with no identity token this adapter takes")
	case aud != audience:
		return refuse("answered with an identity token of another audience")
	case !now.Add(identityMargin).Before(time.Unix(exp, 0)):
		return refuse("answered with an identity token that lapses within 60 seconds")
	}
	return token, nil
}

// identityClaims reads a compact JWS's payload for its aud, a string, and
// its exp, an integer; ok is false when the token is not of that form.
func identityClaims(token string) (aud string, exp int64, ok bool) {
	if !compactJWS.MatchString(token) {
		return "", 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		return "", 0, false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || claims == nil {
		return "", 0, false
	}
	if text := bytes.TrimSpace(claims["aud"]); len(text) == 0 || text[0] != '"' || json.Unmarshal(text, &aud) != nil {
		return "", 0, false
	}
	exp, err = strconv.ParseInt(string(bytes.TrimSpace(claims["exp"])), 10, 64)
	if err != nil || exp <= 0 {
		return "", 0, false
	}
	return aud, exp, true
}
