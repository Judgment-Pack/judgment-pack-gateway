package connections

import (
	"adapters/internal/canon"
	"encoding/json"
	"regexp"
	"strings"
)

var googleClientID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,220}\.apps\.googleusercontent\.com$`)

func validClient(c Client) bool {
	return googleClientID.MatchString(c.ID) && len(c.Secret) <= 4096 && !strings.ContainsAny(c.Secret, "\r\n\x00")
}

// ParseGoogleDesktopClient accepts Google's downloaded Desktop app registration.
// Registration metadata never selects endpoints, scopes or callback addresses.
// Errors deliberately carry none of the input, including the application secret.
func ParseGoogleDesktopClient(raw []byte) (Client, error) {
	if len(raw) > 16<<10 {
		return Client{}, ErrRequest
	}
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return Client{}, ErrRequest
	}
	var registration struct {
		Installed *struct {
			ID     string `json:"client_id"`
			Secret string `json:"client_secret"`
		} `json:"installed"`
		Web  json.RawMessage `json:"web"`
		Type json.RawMessage `json:"type"`
	}
	if json.Unmarshal(raw, &registration) != nil || registration.Installed == nil || registration.Web != nil || registration.Type != nil {
		return Client{}, ErrRequest
	}
	c := Client{registration.Installed.ID, registration.Installed.Secret}
	if !validClient(c) {
		return Client{}, ErrRequest
	}
	return c, nil
}

// EnsureClient installs a publisher default only into an unconfigured store.
// Existing registrations, consent, policy and in-flight authorization epochs are
// preserved. Changing an existing client still requires explicit configuration.
func (s *Store) EnsureClient(c Client) error {
	if !validClient(c) {
		return ErrRequest
	}
	return s.locked(func(v *state) error {
		if v.Client.ID != "" || v.Connection != nil {
			return nil
		}
		v.Client = c
		v.Epoch = randomID()
		return s.write("state.json", v)
	})
}
