//go:build !linux

package descendants

// Native Windows sandbox jobs handle the complete tree. Other platforms do
// not claim orphan adoption; the calling gateway's process group is separate.
func Adopt() error { return nil }
func Kill() error  { return nil }
