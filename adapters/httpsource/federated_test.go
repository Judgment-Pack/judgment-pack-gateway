package httpsource

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// rootLinks has the walk take the links a test makes as root's, as a
// mounted volume's are, for the rest of the test.
func rootLinks(t *testing.T) {
	t.Helper()
	orig := lstatFederated
	lstatFederated = func(path string) (federatedFacts, error) {
		facts, err := orig(path)
		if facts.link {
			facts.uid = 0
		}
		return facts, err
	}
	t.Cleanup(func() { lstatFederated = orig })
}

// A federated token projected into a volume is renewed by re-pointing a
// link: the configured name is a link to ..data/token, ..data a link to a
// timestamped directory, swapped to a new one and the old one removed.
// Each token request finds the file again, so the renewed token is the
// one sent. A link that leaves the directory -- absolute or by "..", to a
// file that would otherwise be taken -- a link not root's, a file of
// another owner, one others may read, a directory on the way others may
// write, or a directory in the file's place, is no credential, and no
// token request is sent.
func TestTokenStepFollowsAFederatedTokenRenewedByALinkSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("making a symbolic link needs a privilege on Windows that a test does not assume")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "projected")
	stub := newTokenStub(t, nil)
	current := "eyJhbGciOiJSUzI1NiJ9.first.federated-signature"
	stub.federated = func() string { return current }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	project := func(stamp string) {
		must(os.MkdirAll(filepath.Join(dir, stamp), 0o755))
		must(os.WriteFile(filepath.Join(dir, stamp, "token"), []byte(current+"\n"), 0o600))
	}
	repoint := func(target string) {
		must(os.Symlink(target, filepath.Join(dir, "..data_tmp")))
		must(os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")))
	}
	project("..2026_a")
	must(os.Symlink("..2026_a", filepath.Join(dir, "..data")))
	must(os.Symlink(filepath.Join("..data", "token"), filepath.Join(dir, "token")))
	cfg := Config{Endpoint: stub.source.URL, Paths: []string{"/read"}, Methods: []string{"GET"}, MaxOutput: 1 << 20,
		Token: &TokenStep{Endpoint: stub.token.URL + "/token", ClientID: stub.clientID, FederatedTokenFile: filepath.Join(dir, "token"), FederatedTokenDir: dir}}

	// Links a user other than root made are not followed.
	if _, err := ObtainSealed(context.Background(), cfg); failureKind(err) != TokenNoCredential {
		t.Fatalf("links of the test's own user: %v", err)
	}
	rootLinks(t)
	if _, err := ObtainSealed(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	current = "eyJhbGciOiJSUzI1NiJ9.renewed.federated-signature"
	project("..2026_b")
	repoint("..2026_b")
	must(os.RemoveAll(filepath.Join(dir, "..2026_a")))
	if _, err := ObtainSealed(context.Background(), cfg); err != nil {
		t.Fatalf("after the link was swapped: %v", err)
	}
	stub.check(t)
	if hits := stub.tokenHits.Load(); hits != 2 || stub.assertions[1] != current {
		t.Fatalf("the renewed token was not the one sent: %d token requests", hits)
	}

	outside := filepath.Join(root, "outside")
	must(os.MkdirAll(outside, 0o755))
	must(os.WriteFile(filepath.Join(outside, "token"), []byte(current+"\n"), 0o600))
	refused := func(what string) {
		t.Helper()
		if _, err := ObtainSealed(context.Background(), cfg); failureKind(err) != TokenNoCredential {
			t.Fatalf("%s: not TokenNoCredential: %v", what, err)
		}
		if hits := stub.tokenHits.Load(); hits != 2 {
			t.Fatalf("%s: a token request was sent", what)
		}
	}
	repoint(outside)
	refused("a link to a directory outside, absolute")
	repoint(filepath.Join("..", "outside"))
	refused("a link to a directory outside, by ..")
	repoint("..2026_b")
	must(os.Chmod(filepath.Join(dir, "..2026_b", "token"), 0o640))
	refused("a token others may read")
	must(os.Chmod(filepath.Join(dir, "..2026_b", "token"), 0o600))
	orig := statFederatedFile
	statFederatedFile = func(f *os.File) (federatedFacts, error) {
		facts, err := orig(f)
		facts.uid = ownUID() + 1
		return facts, err
	}
	refused("a token another user owns")
	statFederatedFile = orig
	must(os.Chmod(filepath.Join(dir, "..2026_b"), 0o777))
	refused("a directory on the way others may write")
	must(os.Chmod(filepath.Join(dir, "..2026_b"), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "..2026_c", "token"), 0o700))
	repoint("..2026_c")
	refused("a directory in the file's place")
	if _, err := ObtainSealed(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("a directory in the file's place is refused as not a regular file: %v", err)
	}
	repoint("..2026_b")
	if _, err := ObtainSealed(context.Background(), cfg); err != nil {
		t.Fatalf("held again: %v", err)
	}
}
