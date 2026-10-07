package connections

// Document processing (OCR) settings are the gateway's: an operator chooses a
// processor once, and every document-producing adapter of the managed local
// plan resolves that choice before it extracts. A document never chooses the
// program, its arguments or its credentials. The settings are kept as the
// other providers' are, in the private store, under their own namespace.
import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/ocrrender"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	ProcessingMinTimeoutSeconds     = 10
	ProcessingMaxTimeoutSeconds     = 120
	ProcessingDefaultTimeoutSeconds = 120
	// ProcessingSourceSeconds is what the local plan gives a source launched
	// with --document-processing, and ProcessingAdapterTimeout is where such
	// an adapter stops: the processing deadline, its read and its report fit.
	ProcessingSourceSeconds  = 150
	ProcessingAdapterTimeout = 140 * time.Second
)

type processingKey struct{}

// WithDocumentProcessing marks a read as one whose adapter the plan launched
// with --document-processing. Only such a read resolves the settings.
func WithDocumentProcessing(ctx context.Context) context.Context {
	return context.WithValue(ctx, processingKey{}, true)
}
func documentProcessing(ctx context.Context) bool {
	v, _ := ctx.Value(processingKey{}).(bool)
	return v
}

// ProcessingConfigured reports whether the settings under dir name a
// processor, for the local plan. It creates, locks and writes nothing. No
// directory, namespace or settings file, or settings that are off: false.
// Settings that are there and cannot be read now: true, so the sources are
// launched to resolve them and each read stops with that error, rather than
// reading without the OCR the operator configured.
func ProcessingConfigured(dir string) bool {
	if dir == "" || !filepath.IsAbs(dir) {
		return false
	}
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil || !st.IsDir() || private(st, true) != nil {
		return true
	}
	s, err := peekStore(filepath.Join(dir, "document-processing"), "desk-local")
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	defer s.Close()
	c, _, err := s.processingConfig()
	return err != nil || c.Mode == "auto"
}

// peekStore opens a store that is already there, held to the same custody
// checks as OpenStore, creating nothing; os.ErrNotExist when the directory or
// the principal's namespace is not there.
func peekStore(dir, principal string) (*Store, error) {
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !st.IsDir() || private(st, true) != nil {
		return nil, ErrStorage
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrStorage
	}
	defer r.Close()
	sum := sha256.Sum256([]byte(principal))
	name := hex.EncodeToString(sum[:])
	st, err = r.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !st.IsDir() || private(st, true) != nil {
		return nil, ErrStorage
	}
	child, err := r.OpenRoot(name)
	if err != nil {
		return nil, ErrStorage
	}
	return &Store{child}, nil
}

type OCRConnection struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Program string `json:"program,omitempty"`
	Enabled bool   `json:"enabled"`
	// Ready is status only: the processor's programs were found usable when
	// status was read. False says that was not confirmed then, not that the
	// processor is absent. A saved configuration never carries it.
	Ready     bool   `json:"ready,omitempty"`
	Project   string `json:"project,omitempty"`
	Location  string `json:"location,omitempty"`
	Processor string `json:"processor,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	// Credential is written by configure and never read back: status blanks
	// it and says only whether one is held.
	Credential           string `json:"credential,omitempty"`
	CredentialConfigured bool   `json:"credentialConfigured,omitempty"`
}
type ProcessingConfig struct {
	Version        int             `json:"version"`
	Mode           string          `json:"mode"`
	Connection     string          `json:"connection"`
	Connections    []OCRConnection `json:"connections"`
	TimeoutSeconds int             `json:"timeoutSeconds,omitempty"`
}
type ProcessingStatus struct {
	ProcessingConfig
	SHA256 string `json:"sha256"`
	State  string `json:"state"`
}

func processingDescriptor() Descriptor {
	return Descriptor{"document-processing", "local-program", "form", "document-processing", false, []string{"status", "configure", "test"}}
}
func OpenProcessingStore(dir, principal string) (*Store, error) {
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "document-processing"), principal)
}
func NewProcessing(s *Store, disabled bool) *Broker {
	return &Broker{store: s, provider: provider{processing: true}, disabled: disabled}
}

// processingConfig reads the settings and holds them to the rules they were
// written under. Only a file that is not there reads as "off"; one that cannot
// be read, or does not hold to the rules, is an error.
func (s *Store) processingConfig() (ProcessingConfig, string, error) {
	raw, err := s.read("processing.json")
	if errors.Is(err, os.ErrNotExist) {
		c := ProcessingConfig{Version: 1, Mode: "off", Connections: []OCRConnection{}}
		raw, _ = json.Marshal(c)
		return c, digest(raw), nil
	}
	var c ProcessingConfig
	if err != nil || decode(raw, &c) != nil || !validProcessing(c) {
		return ProcessingConfig{}, "", ErrStorage
	}
	return c, digest(raw), nil
}
func validProcessing(c ProcessingConfig) bool {
	if (c.TimeoutSeconds != 0 && (c.TimeoutSeconds < ProcessingMinTimeoutSeconds || c.TimeoutSeconds > ProcessingMaxTimeoutSeconds)) || c.Version != 1 || (c.Mode != "off" && c.Mode != "auto") || c.Connections == nil || len(c.Connections) > 16 {
		return false
	}
	seen := map[string]bool{}
	chosen := c.Connection == ""
	for _, p := range c.Connections {
		if !searchID.MatchString(p.ID) || seen[p.ID] || !resourceText(p.Name, 80, false) || p.Ready || p.CredentialConfigured {
			return false
		}
		seen[p.ID] = true
		if !validOCRConnection(p) {
			return false
		}
		if p.ID == c.Connection && p.Enabled {
			chosen = true
		}
	}
	return chosen && (c.Mode == "off" || c.Connection != "")
}

// sameDestination reports whether two connections send a document, and their
// credential, to the same place. A credential left out of a configure is kept
// only then: one that would be sent somewhere else is entered again.
func sameDestination(a, b OCRConnection) bool {
	return a.ID == b.ID && a.Kind == b.Kind && a.Program == b.Program && a.Project == b.Project && a.Location == b.Location && a.Processor == b.Processor && a.Endpoint == b.Endpoint && a.Region == b.Region
}

// ocrWorkerDir is where the workers ocr-tesseract and ocr-cloud are: beside
// the running executable, in the same bundle. findTool names Poppler and
// Tesseract. Tests replace both.
var ocrWorkerDir = func() string {
	exe, err := os.Executable()
	if err != nil || !filepath.IsAbs(exe) {
		return ""
	}
	return filepath.Dir(exe)
}
var findTool = ocrrender.Find

func ocrProgram(c OCRConnection) string {
	if c.Kind == "program" {
		return c.Program
	}
	dir := ocrWorkerDir()
	if dir == "" {
		return ""
	}
	name := "ocr-tesseract"
	if cloudOCR(c.Kind) {
		name = "ocr-cloud"
	}
	return filepath.Join(dir, name)
}

// ErrProcessorMissing is a processor whose worker or tools are not installed
// where they are run from.
const ErrProcessorMissing Error = "processor-not-installed"

// processorInstalled reports whether what the processor runs is there now:
// for a program, its file in its allowed place; for tesseract and the cloud
// processors, the worker beside the executable (every symlink resolved, a
// regular executable file still there) and the tools it runs, Poppler for
// both and Tesseract for tesseract, as Find names them.
func processorInstalled(c OCRConnection) bool {
	if c.Kind == "program" {
		return programAllowed(c.Program)
	}
	dir, worker := ocrWorkerDir(), ocrProgram(c)
	if dir == "" || worker == "" {
		return false
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(worker)
	if err != nil || !inside(resolved, real) {
		return false
	}
	if st, err := os.Stat(resolved); err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return false
	}
	tools := []string{"pdftoppm"}
	if c.Kind == "tesseract" {
		tools = append(tools, "tesseract")
	}
	for _, name := range tools {
		if _, err := findTool(name); err != nil {
			return false
		}
	}
	return true
}

// ocrBundle and systemPrograms are the two places a program processor may
// run from. Tests replace ocrBundle.
var ocrBundle = ocrrender.BundleDir

const systemPrograms = "/usr/bin"

// ErrProgramPlace is a program processor outside the OCR tools bundle and
// /usr/bin.
const ErrProgramPlace Error = "program-not-allowed"

// programAllowed reports whether path names a program a processor may run:
// absolute and clean, inside the OCR tools bundle beside the executable or
// /usr/bin, and still inside it once every symlink is resolved, where it is a
// regular executable file. It is checked at configure and again before a run.
func programAllowed(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return false
	}
	for _, root := range []string{ocrBundle(), systemPrograms} {
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		real, err := filepath.EvalSymlinks(root)
		if err == nil && inside(path, filepath.Clean(root)) && inside(resolved, real) {
			return true
		}
	}
	return false
}

// inside reports whether path lies below dir.
func inside(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}
func ocrReady(ctx context.Context, c OCRConnection) bool {
	if !processorInstalled(c) {
		return false
	}
	if c.Kind != "tesseract" {
		return true
	}
	name := ocrProgram(c)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, "--check")
	cmd.WaitDelay = time.Second
	return cmd.Run() == nil
}

// previewPages and previewRunes bound what a test answers of the document.
const previewPages, previewRunes = 8, 400

func (b *Broker) processingOperation(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case "status":
		var empty struct{}
		if decode(raw, &empty) != nil {
			return nil, ErrRequest
		}
		c, sha, err := b.store.processingConfig()
		if err != nil {
			return nil, err
		}
		out := ProcessingStatus{ProcessingConfig: c, SHA256: sha, State: "ready"}
		for i := range out.Connections {
			out.Connections[i].Ready = ocrReady(ctx, out.Connections[i])
			out.Connections[i].CredentialConfigured = out.Connections[i].Credential != ""
			out.Connections[i].Credential = ""
		}
		return out, nil
	case "configure":
		var req struct {
			Config  ProcessingConfig `json:"config"`
			IfMatch string           `json:"ifMatch"`
		}
		if decode(raw, &req) != nil || req.IfMatch == "" {
			return nil, ErrRequest
		}
		err := b.store.locked(func(_ *state) error {
			old, sha, e := b.store.processingConfig()
			if e != nil {
				return e
			}
			if sha != req.IfMatch {
				return Error("processing-changed")
			}
			for _, p := range req.Config.Connections {
				if p.Kind == "program" && !programAllowed(p.Program) {
					return ErrProgramPlace
				}
			}
			for i := range req.Config.Connections {
				p := &req.Config.Connections[i]
				if p.Credential == "" {
					for _, prev := range old.Connections {
						if sameDestination(prev, *p) {
							p.Credential = prev.Credential
						}
					}
				}
			}
			if !validProcessing(req.Config) {
				return ErrRequest
			}
			encoded, _ := json.Marshal(req.Config)
			if len(encoded) > 64<<10 {
				return ErrRequest
			}
			return b.store.write("processing.json", req.Config)
		})
		if err != nil {
			return nil, err
		}
		return b.processingOperation(ctx, "status", json.RawMessage(`{}`))
	case "test":
		var req struct {
			Connection string `json:"connection"`
			Revision   string `json:"revision"`
			Document   struct {
				Name      string `json:"name"`
				MediaType string `json:"mediaType"`
				Bytes     string `json:"bytes"`
			} `json:"document"`
		}
		if len(raw) > StorageLineBytes || decodeStorage(raw, &req) != nil || req.Document.MediaType != "application/pdf" || !readableName(req.Document.Name) {
			return nil, ErrRequest
		}
		c, sha, err := b.store.processingConfig()
		if err != nil {
			return nil, err
		}
		if sha != req.Revision {
			return nil, Error("processing-changed")
		}
		var picked *OCRConnection
		for i := range c.Connections {
			if c.Connections[i].ID == req.Connection && c.Connections[i].Enabled {
				picked = &c.Connections[i]
			}
		}
		if picked == nil {
			return nil, Error("processing-unavailable")
		}
		if picked.Kind == "program" && !programAllowed(picked.Program) {
			return nil, ErrProgramPlace
		}
		if !processorInstalled(*picked) {
			return nil, ErrProcessorMissing
		}
		data, err := base64.StdEncoding.Strict().DecodeString(req.Document.Bytes)
		if err != nil || len(data) == 0 || len(data) > MaxFileBytes {
			return nil, ErrRequest
		}
		cfg := testRunConfig(*picked, sha, c)
		identity, err := document.OwnIdentity()
		if err != nil {
			return nil, Error("processing-failed")
		}
		started := time.Now()
		result, err := processDriveDocument(ctx, cfg, document.Request{Name: req.Document.Name, MediaType: "application/pdf", Bytes: data, SHA256: digest(data), OCR: "auto", ReceivedAt: started}, identity, started)
		if err != nil {
			return nil, Error("processing-failed")
		}
		// The test answers a bounded preview and stores nothing.
		var record attachment.Record
		if json.Unmarshal(result, &record) != nil {
			return nil, Error("processing-failed")
		}
		preview := []map[string]any{}
		for i, p := range record.Content.Pages {
			if i == previewPages {
				break
			}
			text := []rune(p.Text)
			if len(text) > previewRunes {
				text = text[:previewRunes]
			}
			preview = append(preview, map[string]any{"number": p.Number, "status": p.Status, "extraction": p.Extraction, "text": string(text)})
		}
		return map[string]any{"processing": record.Processing, "extraction": record.Content.Extraction, "pageCount": record.Content.PageCount, "pages": preview}, nil
	}
	return nil, ErrRequest
}

// testRunConfig is a test's configuration. The companion is a long-lived
// process that no gateway process group cleans up after, so its OCR program
// runs in a group of its own, ended whole, whatever the program started.
func testRunConfig(p OCRConnection, revision string, c ProcessingConfig) document.Config {
	cfg := document.DefaultConfig()
	configureOCR(&cfg, p, revision, c)
	cfg.MaxOutput = 8 << 20
	cfg.OCRGroup = true
	return cfg
}

// ApplyDocumentProcessing resolves the operator's processor once, before
// extraction, for a read whose adapter the plan launched with
// --document-processing (WithDocumentProcessing); any other read is left as
// it was. An OCR program given on the command line (--ocr) is the operator's
// own and is kept. Settings that cannot be read now (JPACK_CONNECTIONS_DIR
// missing among them), a store the operator blocked, and a chosen processor
// that is gone are errors, never "no OCR".
func ApplyDocumentProcessing(ctx context.Context, cfg *document.Config) error {
	if !documentProcessing(ctx) || cfg.OCR != "" {
		return nil
	}
	dir := os.Getenv("JPACK_CONNECTIONS_DIR")
	if dir == "" {
		return ErrStorage
	}
	s, err := OpenProcessingStore(dir, "desk-local")
	if err != nil {
		return err
	}
	defer s.Close()
	if err = s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		return nil
	}); err != nil {
		return err
	}
	c, sha, err := s.processingConfig()
	if err != nil {
		return err
	}
	if c.Mode == "off" {
		return nil
	}
	for _, p := range c.Connections {
		if p.ID == c.Connection && p.Enabled {
			if p.Kind == "program" && !programAllowed(p.Program) {
				return ErrProgramPlace
			}
			// A processor whose worker or tools are not installed stops the
			// read, rather than ending a scanned document as ocr-failed.
			if !processorInstalled(p) {
				return ErrProcessorMissing
			}
			configureOCR(cfg, p, sha, c)
			if cfg.OCR == "" {
				return Error("processing-unavailable")
			}
			return nil
		}
	}
	return Error("processing-unavailable")
}

// ocrKinds are the names a record gives each kind of processor.
var ocrKinds = map[string]string{"tesseract": "tesseract", "program": "program", "google-document-ai": "google", "azure-document-intelligence": "azure", "aws-textract": "aws"}

func cloudOCR(kind string) bool {
	return kind == "google-document-ai" || kind == "azure-document-intelligence" || kind == "aws-textract"
}

var ocrPart = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}$`)
var ocrLocation = regexp.MustCompile(`^[a-z][a-z0-9-]{0,49}$`)

// An Azure AI resource's own endpoint, https://<resource>.cognitiveservices.azure.com.
var azureHost = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.cognitiveservices\.azure\.com$`)

func validAzureEndpoint(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.User == nil && u.Port() == "" && azureHost.MatchString(u.Host) && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && (u.Path == "" || u.Path == "/")
}
func validOCRConnection(p OCRConnection) bool {
	switch p.Kind {
	case "tesseract":
		return p.Program == "" && p.Credential == "" && p.Project == "" && p.Endpoint == "" && p.Region == "" && p.Processor == "" && p.Location == ""
	case "program":
		return filepath.IsAbs(p.Program) && filepath.Clean(p.Program) == p.Program && len(p.Program) <= 1024 && !strings.ContainsAny(p.Program, "\t\r\n\x00") && p.Credential == "" && p.Project == "" && p.Endpoint == "" && p.Region == "" && p.Processor == "" && p.Location == ""
	case "google-document-ai":
		return p.Program == "" && p.Endpoint == "" && p.Region == "" && ocrPart.MatchString(p.Project) && ocrLocation.MatchString(p.Location) && ocrPart.MatchString(p.Processor) && len(p.Credential) <= 16<<10 && validateGoogleCredential(p.Credential) == nil
	case "azure-document-intelligence":
		return p.Program == "" && p.Project == "" && p.Region == "" && p.Processor == "" && p.Location == "" && validAzureEndpoint(p.Endpoint) && resourceText(p.Credential, 256, false) && !strings.ContainsAny(p.Credential, " \t\r\n")
	case "aws-textract":
		var c textractCredential
		return p.Program == "" && p.Project == "" && p.Endpoint == "" && p.Processor == "" && p.Location == "" && ocrLocation.MatchString(p.Region) && !strings.HasPrefix(p.Region, "cn-") && decode([]byte(p.Credential), &c) == nil && resourceText(c.AccessKey, 128, false) && resourceText(c.SecretKey, 256, false) && resourceText(c.SessionToken, 8192, true) && !strings.ContainsAny(c.AccessKey+c.SecretKey, " \t\r\n")
	}
	return false
}

// configureOCR points cfg at the processor. A cloud worker is given the
// connection's ID and the settings' revision in its environment, never as
// arguments (the revision is a digest over the file that holds the
// credentials), and refuses to run under any other revision.
func configureOCR(cfg *document.Config, p OCRConnection, revision string, c ProcessingConfig) {
	cfg.OCR = ocrProgram(p)
	if cfg.OCR != "" {
		// A record names the kind and the program's file name, and the
		// digest of the file as it ran; never the directory.
		cfg.OCRName = ocrKinds[p.Kind] + ":" + filepath.Base(cfg.OCR)
	}
	seconds := c.TimeoutSeconds
	if seconds == 0 {
		seconds = ProcessingDefaultTimeoutSeconds
	}
	cfg.Timeout = time.Duration(seconds) * time.Second
	if cloudOCR(p.Kind) {
		cfg.OCREnv = []string{"JPACK_OCR_CONNECTION=" + p.ID, "JPACK_OCR_REVISION=" + revision}
	}
}
