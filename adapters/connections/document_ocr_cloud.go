package connections

import (
	"adapters/attachment"
	"adapters/internal/ocrrender"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"golang.org/x/oauth2"
	googleauth "golang.org/x/oauth2/google"
)

type textractCredential struct {
	AccessKey    string `json:"accessKeyId"`
	SecretKey    string `json:"secretAccessKey"`
	SessionToken string `json:"sessionToken,omitempty"`
}

// cloudImageBytes bounds one rendered page sent to a cloud processor.
const cloudImageBytes = 5 << 20

// RunCloudOCR implements the existing page-text program contract: its
// arguments are the page numbers alone. The connection and the custody
// revision come from the operator through the worker's environment, never
// from the document. No default credentials, ambient auth, custom endpoints,
// redirects or fallback to another connection.
func RunCloudOCR(ctx context.Context, connection, revision string, pages []string, input io.Reader, output io.Writer) error {
	if len(pages) < 1 || len(pages) > 500 || !searchID.MatchString(connection) || revision == "" {
		return ErrRequest
	}
	s, e := OpenProcessingStore(os.Getenv("JPACK_CONNECTIONS_DIR"), "desk-local")
	if e != nil {
		return e
	}
	defer s.Close()
	if e = s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		return nil
	}); e != nil {
		return e
	}
	c, rev, e := s.processingConfig()
	if e != nil {
		return e
	}
	if rev != revision {
		return Error("processing-changed")
	}
	var selected OCRConnection
	for _, p := range c.Connections {
		if p.ID == connection && p.Enabled && cloudOCR(p.Kind) {
			selected = p
		}
	}
	if selected.ID == "" {
		return Error("processing-unavailable")
	}
	numbers := []int{}
	seen := map[int]bool{}
	for _, v := range pages {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 500 || seen[n] {
			return ErrRequest
		}
		seen[n] = true
		numbers = append(numbers, n)
	}
	data, e := io.ReadAll(io.LimitReader(input, (16<<20)+1))
	if e != nil || len(data) == 0 || len(data) > 16<<20 {
		return ErrRequest
	}
	client := ocrHTTPClient()
	defer client.CloseIdleConnections()
	// Resolve auth once for the document; keep it in this process's memory only.
	token := ""
	if selected.Kind == "google-document-ai" {
		cfg, e := googleauth.JWTConfigFromJSON([]byte(selected.Credential), "https://www.googleapis.com/auth/cloud-platform")
		if e != nil {
			return ErrSetup
		}
		t, e := cfg.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, client)).Token()
		if e != nil {
			return Error("credentials-required")
		}
		token = t.AccessToken
	}
	// A page's text is held against every secret the settings hold, not
	// only the selected processor's.
	var held []string
	for _, p := range c.Connections {
		held = append(held, secretsOf(p)...)
	}
	type page struct {
		Number int    `json:"number"`
		Text   string `json:"text"`
	}
	result := struct {
		Pages []page `json:"pages"`
	}{Pages: []page{}}
	total := 0
	for _, number := range numbers {
		// A change during a long run prevents any further cloud calls.
		_, current, e := s.processingConfig()
		if e != nil || current != rev {
			return Error("processing-changed")
		}
		raster, e := ocrrender.Page(ctx, data, number, cloudImageBytes)
		if e != nil {
			return e
		}
		text, e := cloudOCRPage(ctx, client, selected, token, raster, held...)
		if e != nil {
			return e
		}
		total += len(text)
		if total > 8<<20 {
			return ErrLimit
		}
		result.Pages = append(result.Pages, page{number, text})
	}
	_, current, e := s.processingConfig()
	if e != nil || current != rev {
		return Error("processing-changed")
	}
	return json.NewEncoder(output).Encode(result)
}
func ocrHTTPClient() *http.Client {
	p := google()
	p.client.Timeout = 120 * time.Second
	p.client.Transport.(*http.Transport).ResponseHeaderTimeout = 0
	return p.client
}

// All errors intentionally discard provider response bodies and credentials.
// A body that holds a secret this request carried is refused, so a provider
// that echoes one cannot put it into a record.
func ocrResponse(client *http.Client, req *http.Request, want int, secrets ...string) ([]byte, http.Header, error) {
	resp, e := client.Do(req)
	if e != nil {
		return nil, nil, ErrProvider
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return nil, nil, Error("credentials-required")
		}
		return nil, nil, ErrProvider
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if e != nil || len(data) > 8<<20 {
		return nil, nil, ErrProvider
	}
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(data, []byte(secret)) {
			return nil, nil, ErrProvider
		}
	}
	return data, resp.Header, nil
}

// secretsOf are the secrets a processor's settings hold. A credential that
// cannot be read for them is held whole.
func secretsOf(c OCRConnection) []string {
	switch c.Kind {
	case "azure-document-intelligence":
		return []string{c.Credential}
	case "aws-textract":
		var cred textractCredential
		if decode([]byte(c.Credential), &cred) == nil {
			return []string{cred.SecretKey, cred.SessionToken}
		}
	case "google-document-ai":
		var key struct {
			PrivateKey string `json:"private_key"`
		}
		if json.Unmarshal([]byte(c.Credential), &key) == nil && key.PrivateKey != "" {
			var body []string
			for _, line := range strings.Split(key.PrivateKey, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), "-----") {
					body = append(body, line)
				}
			}
			return []string{strings.Join(body, "")}
		}
	}
	if c.Credential != "" {
		return []string{c.Credential}
	}
	return nil
}

// squeezed is text as a record would hold it (attachment.NormalizeText), with
// every space, control and format character then left out, so that a secret
// split across lines or blocks, or broken by a character the record drops,
// is found whole.
func squeezed(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, attachment.NormalizeText(s))
}

// holdsSecret reports whether text, as decoded, holds any of the secrets.
func holdsSecret(text string, secrets []string) bool {
	t := squeezed(text)
	for _, secret := range secrets {
		if k := squeezed(secret); k != "" && strings.Contains(t, k) {
			return true
		}
	}
	return false
}

// cloudOCRPage answers one page's text. The text is held, decoded and in the
// form a record would take, against the processor's own secrets, the token in
// use and the others given (every secret the settings hold): a reply that
// echoes one, escaped or split, is refused before any text is returned.
func cloudOCRPage(ctx context.Context, client *http.Client, c OCRConnection, token string, png []byte, others ...string) (string, error) {
	secrets := append(append(secretsOf(c), token), others...)
	text, err := cloudOCRText(ctx, client, c, token, png)
	if err != nil {
		return "", err
	}
	if holdsSecret(text, secrets) {
		return "", ErrProvider
	}
	return text, nil
}
func cloudOCRText(ctx context.Context, client *http.Client, c OCRConnection, token string, png []byte) (string, error) {
	if len(png) == 0 || len(png) > cloudImageBytes {
		return "", ErrLimit
	}
	image := base64.StdEncoding.EncodeToString(png)
	switch c.Kind {
	case "google-document-ai":
		body, _ := json.Marshal(map[string]any{"rawDocument": map[string]string{"content": image, "mimeType": "image/png"}, "fieldMask": "text", "skipHumanReview": true})
		endpoint := "https://" + c.Location + "-documentai.googleapis.com/v1/projects/" + c.Project + "/locations/" + c.Location + "/processors/" + c.Processor + ":process"
		if c.Location == "global" {
			endpoint = strings.Replace(endpoint, "global-documentai", "documentai", 1)
		}
		req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
		if e != nil {
			return "", ErrRequest
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		raw, _, e := ocrResponse(client, req, 200, token)
		if e != nil {
			return "", e
		}
		var out struct {
			Document *struct {
				Text *string `json:"text"`
			} `json:"document"`
		}
		if json.Unmarshal(raw, &out) != nil || out.Document == nil {
			return "", ErrProvider
		}
		if out.Document.Text == nil {
			return "", nil
		}
		return *out.Document.Text, nil
	case "azure-document-intelligence":
		endpoint := strings.TrimRight(c.Endpoint, "/") + "/documentintelligence/documentModels/prebuilt-read:analyze?api-version=2024-11-30"
		body, _ := json.Marshal(map[string]string{"base64Source": image})
		req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
		if e != nil {
			return "", ErrRequest
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Ocp-Apim-Subscription-Key", c.Credential)
		_, headers, e := ocrResponse(client, req, 202, c.Credential)
		if e != nil {
			return "", e
		}
		operation := headers.Get("Operation-Location")
		u, e := url.Parse(operation)
		base, _ := url.Parse(endpoint)
		if e != nil || u.Scheme != "https" || u.Host != base.Host || u.User != nil || u.Fragment != "" || !strings.HasPrefix(u.Path, "/documentintelligence/documentModels/prebuilt-read/analyzeResults/") {
			return "", ErrProvider
		}
		for {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ErrCanceled
			case <-timer.C:
			}
			req, e = http.NewRequestWithContext(ctx, "GET", operation, nil)
			if e != nil {
				return "", ErrProvider
			}
			req.Header.Set("Ocp-Apim-Subscription-Key", c.Credential)
			raw, _, e := ocrResponse(client, req, 200, c.Credential)
			if e != nil {
				return "", e
			}
			var out struct {
				Status string `json:"status"`
				Result *struct {
					Content string `json:"content"`
				} `json:"analyzeResult"`
			}
			if json.Unmarshal(raw, &out) != nil {
				return "", ErrProvider
			}
			switch out.Status {
			case "succeeded":
				if out.Result == nil {
					return "", ErrProvider
				}
				return out.Result.Content, nil
			case "running", "notStarted":
				continue
			default:
				return "", ErrProvider
			}
		}
	case "aws-textract":
		var cred textractCredential
		if decode([]byte(c.Credential), &cred) != nil {
			return "", ErrSetup
		}
		body, _ := json.Marshal(map[string]any{"Document": map[string]string{"Bytes": image}})
		req, e := http.NewRequestWithContext(ctx, "POST", "https://textract."+c.Region+".amazonaws.com/", bytes.NewReader(body))
		if e != nil {
			return "", ErrRequest
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "Textract.DetectDocumentText")
		hash := sha256.Sum256(body)
		if v4.NewSigner().SignHTTP(ctx, aws.Credentials{AccessKeyID: cred.AccessKey, SecretAccessKey: cred.SecretKey, SessionToken: cred.SessionToken}, req, hex.EncodeToString(hash[:]), "textract", c.Region, time.Now()) != nil {
			return "", ErrSetup
		}
		raw, _, e := ocrResponse(client, req, 200, cred.SecretKey, cred.SessionToken)
		if e != nil {
			return "", e
		}
		var out struct {
			Blocks []struct {
				Type string `json:"BlockType"`
				Text string `json:"Text"`
			} `json:"Blocks"`
		}
		if json.Unmarshal(raw, &out) != nil || out.Blocks == nil {
			return "", ErrProvider
		}
		lines := []string{}
		for _, b := range out.Blocks {
			if b.Type == "LINE" {
				lines = append(lines, b.Text)
			}
		}
		return strings.Join(lines, "\n"), nil
	}
	return "", ErrRequest
}
