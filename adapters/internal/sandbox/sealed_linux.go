//go:build linux && (amd64 || arm64)

package sandbox

import (
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

// memfd_create(2) and the file seals of fcntl(2).
const (
	mfdCloexec      = 0x1
	mfdAllowSealing = 0x2
	mfdExec         = 0x10 // Linux 6.3 and later; EINVAL before
	fAddSeals       = 1033
	fGetSeals       = 1034
	sealSeal        = 0x1
	sealShrink      = 0x2
	sealGrow        = 0x4
	sealWrite       = 0x8
	sealedAll       = sealSeal | sealShrink | sealGrow | sealWrite
)

// The standard library names memfd_create for arm64 but not for amd64.
var sysMemfdCreate = map[string]uintptr{"amd64": 319, "arm64": 279}[runtime.GOARCH]

// SealedCopy copies everything src holds, from its first byte, into an
// anonymous memory file, seals that file against every later write, growth
// and shrinking, and returns it opened read-only at its first byte. What is
// read from the copy, and what the kernel executes through it, are exactly
// the bytes copied: a writer of src, or of the path src was opened from, can
// no longer change them. The caller digests the copy, never src.
func SealedCopy(src *os.File, name string) (*os.File, error) {
	mem, err := memoryFile(name, true)
	if err != nil {
		return nil, err
	}
	defer mem.Close()
	if _, err := io.Copy(mem, io.NewSectionReader(src, 0, 1<<62)); err != nil {
		return nil, err
	}
	return sealAndReopen(mem)
}

// sealedData is data in a sealed anonymous memory file, opened read-only at
// its first byte: what a launcher reads from it never reaches a disk.
func sealedData(name string, data []byte) (*os.File, error) {
	mem, err := memoryFile(name, false)
	if err != nil {
		return nil, err
	}
	defer mem.Close()
	if _, err := mem.Write(data); err != nil {
		return nil, err
	}
	return sealAndReopen(mem)
}

// Sealed reports whether f is a file sealed against every change, as
// SealedCopy returns.
func Sealed(f *os.File) bool {
	if f == nil {
		return false
	}
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), fGetSeals, 0)
	return errno == 0 && seals&sealedAll == sealedAll
}

func memoryFile(name string, executable bool) (*os.File, error) {
	if sysMemfdCreate == 0 {
		return nil, errors.New("sandbox: no anonymous memory files on this architecture")
	}
	cname, err := syscall.BytePtrFromString("gateway-" + name)
	if err != nil {
		return nil, err
	}
	flags := uintptr(mfdCloexec | mfdAllowSealing)
	if executable {
		// A host that makes memory files non-executable by default
		// (vm.memfd_noexec) needs the request; a kernel older than the
		// flag refuses it, and executes memory files without it.
		fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(cname)), flags|mfdExec, 0)
		if errno == 0 {
			return os.NewFile(fd, "memfd:"+name), nil
		}
		if errno != syscall.EINVAL {
			return nil, errno
		}
	}
	fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(cname)), flags, 0)
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(fd, "memfd:"+name), nil
}

// sealAndReopen seals mem and returns a read-only descriptor on it. The
// writable descriptor is not handed on: the kernel refuses to execute a file
// that is open for writing, and nothing downstream needs to write.
func sealAndReopen(mem *os.File) (*os.File, error) {
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, mem.Fd(), fAddSeals, sealedAll); errno != 0 {
		return nil, errno
	}
	ro, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(mem.Fd())))
	if err != nil {
		return nil, err
	}
	if !Sealed(ro) {
		ro.Close()
		return nil, errors.New("sandbox: the memory file is not sealed")
	}
	return ro, nil
}
