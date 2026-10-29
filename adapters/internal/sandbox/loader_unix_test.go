//go:build !windows

package sandbox

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loaderELF is the smallest 64-bit little-endian ELF executable debug/elf
// reads with a PT_INTERP naming interp and, when runpath is not empty, a
// dynamic section whose DT_RUNPATH is runpath.
func loaderELF(interp, runpath string) []byte {
	le := binary.LittleEndian
	type section struct {
		name, kind, link uint32
		data             []byte
	}
	dynstr := append(append([]byte{0}, runpath...), 0)
	var dynamic bytes.Buffer
	for _, entry := range [][2]uint64{{uint64(elf.DT_RUNPATH), 1}, {uint64(elf.DT_NULL), 0}} {
		binary.Write(&dynamic, le, entry)
	}
	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")
	sections := []section{{}, {1, uint32(elf.SHT_STRTAB), 0, dynstr}, {9, uint32(elf.SHT_DYNAMIC), 1, dynamic.Bytes()}, {18, uint32(elf.SHT_STRTAB), 0, shstr}}
	if runpath == "" {
		sections = []section{{}, {1, uint32(elf.SHT_STRTAB), 0, []byte("\x00.shstrtab\x00")}}
	}
	phnum := 1
	if runpath != "" {
		phnum = 2
	}
	offset := uint64(64 + 56*phnum)
	var body bytes.Buffer
	interpAt := offset
	body.Write(append([]byte(interp), 0))
	at := make([]uint64, len(sections))
	for i, s := range sections[1:] {
		at[i+1] = offset + uint64(body.Len())
		body.Write(s.data)
	}
	for body.Len()%8 != 0 {
		body.WriteByte(0)
	}
	shoff := offset + uint64(body.Len())
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.Write(&b, le, uint16(elf.ET_EXEC))
	binary.Write(&b, le, uint16(elf.EM_X86_64))
	binary.Write(&b, le, uint32(1))
	binary.Write(&b, le, []uint64{0, 64, shoff})
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, []uint16{64, 56, uint16(phnum), 64, uint16(len(sections)), uint16(len(sections) - 1)})
	binary.Write(&b, le, []uint32{uint32(elf.PT_INTERP), 4})
	binary.Write(&b, le, []uint64{interpAt, 0, 0, uint64(len(interp) + 1), uint64(len(interp) + 1), 1})
	if runpath != "" {
		binary.Write(&b, le, []uint32{uint32(elf.PT_DYNAMIC), 6})
		binary.Write(&b, le, []uint64{at[2], 0, 0, uint64(dynamic.Len()), uint64(dynamic.Len()), 8})
	}
	b.Write(body.Bytes())
	for i, s := range sections {
		binary.Write(&b, le, []uint32{s.name, s.kind})
		binary.Write(&b, le, []uint64{0, 0, at[i], uint64(len(s.data))})
		binary.Write(&b, le, []uint32{s.link, 0})
		entsize := uint64(0)
		if s.kind == uint32(elf.SHT_DYNAMIC) {
			entsize = 16
		}
		binary.Write(&b, le, []uint64{1, entsize})
	}
	return b.Bytes()
}

// A launcher's loader runs code in it before anything is confined: its
// program interpreter, and each directory of its RPATH or RUNPATH, must be
// one only root can change.
func TestLauncherLoaderIsHeld(t *testing.T) {
	trusted := t.TempDir()
	held := func(p string) string {
		if p == trusted || strings.HasPrefix(p, trusted+string(filepath.Separator)) {
			return ""
		}
		return "is not owned by root along its path"
	}
	bin := filepath.Join(trusted, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	interp := filepath.Join(trusted, "ld.so")
	for _, c := range []struct {
		name, interp, runpath, want string
	}{
		{"held", interp, filepath.Join(trusted, "lib") + ":$ORIGIN/../lib", ""},
		{"held, no search path", interp, "", ""},
		{"interpreter elsewhere", "/elsewhere/ld.so", "", "program interpreter"},
		{"relative interpreter", "ld.so", "", "relative program interpreter"},
		{"search path elsewhere", interp, "/elsewhere/lib", "library search path directory"},
		{"origin outside", interp, "$ORIGIN/../../../elsewhere", "library search path directory"},
		{"relative search path", interp, "lib", "relative or empty"},
		{"empty search path entry", interp, filepath.Join(trusted, "lib") + ":", "relative or empty"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(bin, "bwrap")
			if err := os.WriteFile(path, loaderELF(c.interp, c.runpath), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := elf.Open(path); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			got := launcherLoader(path, held)
			if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
	// A system program root installed passes the real hold.
	for _, system := range []string{"/bin/sh", "/usr/bin/env"} {
		resolved, err := filepath.EvalSymlinks(system)
		if err != nil || rootHeldFile(resolved) != "" {
			continue
		}
		if got := launcherLoader(resolved, rootHeldFile); got != "" {
			t.Fatalf("%s: %s", system, got)
		}
	}
}
