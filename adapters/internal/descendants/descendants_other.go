//go:build !linux

package descendants

// Outside Linux there is no descendant adoption: Adopt and Kill do nothing,
// and a full-access Windows launch has no job containment. The calling
// gateway's process group is separate.
func Adopt() error { return nil }
func Kill() error  { return nil }
