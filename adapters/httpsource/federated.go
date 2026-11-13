package httpsource

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// A federated token file is found again at each token request, not once:
// a platform that projects an identity token into a volume renews it by
// re-pointing a link (the configured name a link to ..data/NAME, ..data a
// link swapped to a new timestamped directory, the old one removed), and
// a path resolved once would name the removed file after the first
// renewal. What is fixed is the configured path and its directory,
// FederatedTokenDir: the walk starts there, follows the links it meets,
// and must not leave it, so a link cannot steer the read anywhere else.
// Each directory, link and file it meets is held as the engine holds the
// way to the file at start, and the file is opened once and judged by
// its open handle, so no check is made of one file and the read of
// another.

// maxFederatedLinks bounds the links followed on the way to the file,
// which also ends a loop.
const maxFederatedLinks = 32

// federatedFacts are what the walk reads of a path, not following a link
// at it, or of the open file: its kind, its permission bits, and its owner,
// -1 where the system reports none (ownerOf).
type federatedFacts struct {
	link, dir, regular, sticky bool
	perm                       fs.FileMode
	uid                        int
}

func factsOf(info fs.FileInfo) federatedFacts {
	m := info.Mode()
	return federatedFacts{link: m&fs.ModeSymlink != 0, dir: m.IsDir(), regular: m.IsRegular(),
		sticky: m&fs.ModeSticky != 0, perm: m.Perm(), uid: ownerOf(info)}
}

// lstatFederated and statFederatedFile read those facts of a path and of
// an open file. A test replaces them to stand in for a link only root
// could have made, or for a file another user owns.
var (
	lstatFederated = func(path string) (federatedFacts, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return federatedFacts{}, err
		}
		return factsOf(info), nil
	}
	statFederatedFile = func(f *os.File) (federatedFacts, error) {
		info, err := f.Stat()
		if err != nil {
			return federatedFacts{}, err
		}
		return factsOf(info), nil
	}
)

// federatedDir is the directory the step's federated token file is held
// under: FederatedTokenDir, or the file's own directory as written.
func federatedDir(t *TokenStep) string {
	if t.FederatedTokenDir != "" {
		return t.FederatedTokenDir
	}
	return filepath.Dir(t.FederatedTokenFile)
}

// within is whether path is dir or lies under it, both clean.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// openFederatedToken finds the federated token file for this token
// request and opens it: from its directory, through every link on the way
// -- each owned by root, as a mounted secret's are, its target walked as
// written and never out of the directory -- and every directory on the
// way -- owned by root or by the user the adapter runs as, writable by
// nobody else unless sticky, traversable by that user -- to a regular file
// that user owns and alone may read. Where the system reports no owner
// (not Unix, where the engine does not run) the owner and the bits are not
// held, and the rest is. Anything else is TokenNoCredential.
func openFederatedToken(t *TokenStep) (*os.File, error) {
	refuse := func(why string) (*os.File, error) {
		return nil, tokenFailure(TokenNoCredential, "the token step's federated token file %s", why)
	}
	own := ownUID()
	dir := filepath.Clean(federatedDir(t))
	current := dir
	remaining := []string{filepath.Base(t.FederatedTokenFile)}
	hops := 0
	for len(remaining) > 0 {
		name := remaining[0]
		remaining = remaining[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			if current = filepath.Dir(current); !within(dir, current) {
				return refuse("is reached through a link that leaves its directory")
			}
			continue
		}
		next := filepath.Join(current, name)
		facts, err := lstatFederated(next)
		if err != nil {
			return refuse("could not be read")
		}
		switch {
		case facts.link:
			if own >= 0 && facts.uid != 0 {
				return refuse("is reached through a symbolic link not owned by root, whose owner could retarget it")
			}
			if hops++; hops > maxFederatedLinks {
				return refuse("is reached through too many symbolic links")
			}
			target, err := os.Readlink(next)
			if err != nil || target == "" {
				return refuse("could not be read")
			}
			if filepath.IsAbs(target) {
				// An absolute target is taken as written and must name a
				// place under the directory, which is resolved: walked from
				// the directory, it is the same place.
				target = filepath.Clean(target)
				rel, err := filepath.Rel(dir, target)
				if err != nil || !within(dir, target) {
					return refuse("is reached through a link that leaves its directory")
				}
				current, target = dir, rel
			}
			remaining = append(strings.Split(filepath.ToSlash(target), "/"), remaining...)
		case len(remaining) > 0:
			if !facts.dir {
				return refuse("is reached through something that is not a directory")
			}
			if own >= 0 && !heldDirectory(facts, own) {
				return refuse("is reached through a directory another user could replace it in, or one the adapter's user cannot traverse")
			}
			current = next
		default:
			return openHeldFederated(next, own)
		}
	}
	return refuse("names no file")
}

// heldDirectory is the engine's rule for a directory on the way to a
// credential: owned by root or by uid, writable by nobody else unless the
// sticky bit keeps others from renaming what they do not own, and
// traversable by uid -- by the owner bits when it is uid's, the other bits
// when it is root's.
func heldDirectory(facts federatedFacts, uid int) bool {
	if facts.uid != 0 && facts.uid != uid {
		return false
	}
	if facts.perm&0o022 != 0 && !facts.sticky {
		return false
	}
	if facts.uid == uid {
		return facts.perm&0o100 != 0
	}
	return facts.perm&0o001 != 0
}

// openHeldFederated opens the file the walk arrived at, not following a
// link put there since, and holds the open handle: a regular file, owned
// by uid and readable by uid alone, where the owner is known.
func openHeldFederated(path string, uid int) (*os.File, error) {
	refuse := func(file *os.File, why string) (*os.File, error) {
		if file != nil {
			file.Close()
		}
		return nil, tokenFailure(TokenNoCredential, "the token step's federated token file %s", why)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|federatedOpenFlags, 0)
	if err != nil {
		return refuse(nil, "could not be read")
	}
	facts, err := statFederatedFile(file)
	switch {
	case err != nil:
		return refuse(file, "could not be read")
	case !facts.regular:
		return refuse(file, "is not a regular file")
	case uid >= 0 && facts.uid != uid:
		return refuse(file, "is not owned by the user the adapter runs as")
	case uid >= 0 && facts.perm&0o077 != 0:
		return refuse(file, "is readable beyond its owner")
	}
	return file, nil
}
