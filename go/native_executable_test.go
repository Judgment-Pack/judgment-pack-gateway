package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// elfFile is the smallest ELF file of the given class, byte order, type and
// machine that debug/elf reads: a header, and a PT_INTERP naming interp when
// it is not empty.
func elfFile(class elf.Class, data elf.Data, etype elf.Type, machine elf.Machine, interp string) []byte {
	var order binary.ByteOrder = binary.LittleEndian
	if data == elf.ELFDATA2MSB {
		order = binary.BigEndian
	}
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', byte(class), byte(data), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	wide := class == elf.ELFCLASS64
	word := func(v uint64) {
		if wide {
			binary.Write(&b, order, v)
		} else {
			binary.Write(&b, order, uint32(v))
		}
	}
	header, phentsize := uint64(52), uint16(32)
	if wide {
		header, phentsize = 64, 56
	}
	phnum := uint16(0)
	phoff := uint64(0)
	if interp != "" {
		phnum, phoff = 1, header
	}
	binary.Write(&b, order, uint16(etype))
	binary.Write(&b, order, uint16(machine))
	binary.Write(&b, order, uint32(1))
	word(0)     // entry
	word(phoff) // phoff
	word(0)     // shoff
	binary.Write(&b, order, uint32(0))
	binary.Write(&b, order, uint16(header))
	binary.Write(&b, order, phentsize)
	binary.Write(&b, order, phnum)
	binary.Write(&b, order, uint16(40+24*boolInt(wide)))
	binary.Write(&b, order, uint16(0))
	binary.Write(&b, order, uint16(0))
	if interp != "" {
		offset := header + uint64(phentsize)
		size := uint64(len(interp) + 1)
		if wide {
			binary.Write(&b, order, uint32(elf.PT_INTERP))
			binary.Write(&b, order, uint32(4))
			for _, v := range []uint64{offset, 0, 0, size, size, 1} {
				binary.Write(&b, order, v)
			}
		} else {
			binary.Write(&b, order, uint32(elf.PT_INTERP))
			for _, v := range []uint32{uint32(offset), 0, 0, uint32(size), uint32(size), 4, 1} {
				binary.Write(&b, order, v)
			}
		}
		b.WriteString(interp)
		b.WriteByte(0)
	}
	return b.Bytes()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// machoFile is the smallest 64-bit Mach-O file of the given CPU and type
// that debug/macho reads, with an LC_LOAD_DYLINKER naming dylinker when it is
// not empty.
func machoFile(cpu macho.Cpu, filetype macho.Type, dylinker string) []byte {
	var cmds bytes.Buffer
	ncmds := uint32(0)
	if dylinker != "" {
		name := append([]byte(dylinker), 0)
		size := 12 + len(name)
		size += (8 - size%8) % 8
		binary.Write(&cmds, binary.LittleEndian, uint32(loadDylinker))
		binary.Write(&cmds, binary.LittleEndian, uint32(size))
		binary.Write(&cmds, binary.LittleEndian, uint32(12))
		cmds.Write(name)
		cmds.Write(make([]byte, size-12-len(name)))
		ncmds = 1
	}
	var b bytes.Buffer
	for _, v := range []uint32{macho.Magic64, uint32(cpu), 3, uint32(filetype), ncmds, uint32(cmds.Len()), 0, 0} {
		binary.Write(&b, binary.LittleEndian, v)
	}
	b.Write(cmds.Bytes())
	return b.Bytes()
}

// fatFile is a universal file of the slices given, each at a page.
func fatFile(slices map[macho.Cpu][]byte) []byte {
	var b bytes.Buffer
	cpus := []macho.Cpu{macho.CpuAmd64, macho.CpuArm64}
	present := []macho.Cpu{}
	for _, cpu := range cpus {
		if _, ok := slices[cpu]; ok {
			present = append(present, cpu)
		}
	}
	binary.Write(&b, binary.BigEndian, uint32(macho.MagicFat))
	binary.Write(&b, binary.BigEndian, uint32(len(present)))
	offset := uint32(4096)
	for _, cpu := range present {
		for _, v := range []uint32{uint32(cpu), 3, offset, uint32(len(slices[cpu])), 12} {
			binary.Write(&b, binary.BigEndian, v)
		}
		offset += 4096
	}
	for _, cpu := range present {
		b.Write(make([]byte, 4096-b.Len()%4096))
		b.Write(slices[cpu])
	}
	return b.Bytes()
}

// An adapter is held to the host's own executable format by Go's parsers,
// for the host's CPU, and never by its first bytes alone. Each platform's
// rule is tested here whatever the platform the test runs on.
func TestAnAdapterIsANativeExecutableOfThisHost(t *testing.T) {
	javaClass := append([]byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34}, make([]byte, 600)...)
	linux := func(data []byte) (string, error) { return nativeExecutable(bytes.NewReader(data), "linux", "amd64") }
	darwin := func(data []byte) (string, error) { return nativeExecutable(bytes.NewReader(data), "darwin", "arm64") }
	accepted := []struct {
		name   string
		check  func([]byte) (string, error)
		data   []byte
		loader string
	}{
		{"a static ELF executable", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_X86_64, ""), ""},
		{"a position-independent ELF executable", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_DYN, elf.EM_X86_64, ""), ""},
		{"a dynamic ELF executable", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2"), "/lib64/ld-linux-x86-64.so.2"},
		{"a thin Mach-O executable", darwin, machoFile(macho.CpuArm64, macho.TypeExec, ""), ""},
		{"a Mach-O executable naming dyld", darwin, machoFile(macho.CpuArm64, macho.TypeExec, "/usr/lib/dyld"), "/usr/lib/dyld"},
		{"a universal file with this host's slice", darwin, fatFile(map[macho.Cpu][]byte{macho.CpuAmd64: machoFile(macho.CpuAmd64, macho.TypeExec, ""), macho.CpuArm64: machoFile(macho.CpuArm64, macho.TypeExec, "/usr/lib/dyld")}), "/usr/lib/dyld"},
	}
	for _, c := range accepted {
		if loader, err := c.check(c.data); err != nil || loader != c.loader {
			t.Fatalf("%s: %q %v", c.name, loader, err)
		}
	}
	refused := []struct {
		name  string
		check func([]byte) (string, error)
		data  []byte
		want  string
	}{
		{"a script", linux, []byte("#!/bin/sh\n"), "is a script"},
		{"a script on macOS", darwin, []byte("#!/usr/bin/env sh\n"), "is a script"},
		{"an empty file", linux, nil, "is not an ELF executable this host runs"},
		{"a truncated ELF header", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_X86_64, "")[:20], "is not an ELF executable this host runs"},
		{"an ELF file for another CPU", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_AARCH64, ""), "not for this host's CPU"},
		{"an ELF file of another class", linux, elfFile(elf.ELFCLASS32, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_X86_64, ""), "not for this host's CPU"},
		{"an ELF file of another byte order", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2MSB, elf.ET_EXEC, elf.EM_X86_64, ""), "not for this host's CPU"},
		{"an ELF object", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_REL, elf.EM_X86_64, ""), "not an executable"},
		{"an ELF core file", linux, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_CORE, elf.EM_X86_64, ""), "not an executable"},
		{"a Mach-O executable on Linux", linux, machoFile(macho.CpuAmd64, macho.TypeExec, ""), "is not an ELF executable this host runs"},
		{"a Java class on Linux", linux, javaClass, "is not an ELF executable this host runs"},
		{"a PE file", linux, append([]byte("MZ"), make([]byte, 200)...), "is not an ELF executable this host runs"},
		{"a Java class on macOS", darwin, javaClass, "is not a universal file this host runs"},
		{"a truncated Mach-O header", darwin, machoFile(macho.CpuArm64, macho.TypeExec, "")[:16], "is not a Mach-O executable this host runs"},
		{"a Mach-O executable for another CPU", darwin, machoFile(macho.CpuAmd64, macho.TypeExec, ""), "not for this host's CPU"},
		{"a Mach-O object", darwin, machoFile(macho.CpuArm64, macho.TypeObj, ""), "not an executable"},
		{"a Mach-O dylib", darwin, machoFile(macho.CpuArm64, macho.TypeDylib, ""), "not an executable"},
		{"a universal file without this host's slice", darwin, fatFile(map[macho.Cpu][]byte{macho.CpuAmd64: machoFile(macho.CpuAmd64, macho.TypeExec, "")}), "no executable slice for this host's CPU"},
		{"a universal file whose host slice is a dylib", darwin, fatFile(map[macho.Cpu][]byte{macho.CpuArm64: machoFile(macho.CpuArm64, macho.TypeDylib, "")}), "no executable slice for this host's CPU"},
		{"a universal file in the other byte order", darwin, append([]byte{0xbe, 0xba, 0xfe, 0xca}, make([]byte, 64)...), "is not a Mach-O executable this host runs"},
		{"an ELF executable on macOS", darwin, elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_AARCH64, ""), "is not a Mach-O executable this host runs"},
	}
	for _, c := range refused {
		if _, err := c.check(c.data); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	if _, err := nativeExecutable(bytes.NewReader(elfFile(elf.ELFCLASS64, elf.ELFDATA2LSB, elf.ET_EXEC, elf.EM_X86_64, "")), "linux", "sparc64"); err == nil || !strings.Contains(err.Error(), "is not one the check knows") {
		t.Fatalf("a CPU the check does not know: %v", err)
	}
}

// A real binary Go built for this host, the test binary itself, is one.
func TestAGoBuiltBinaryOfThisHostIsANativeExecutable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the engine runs on Linux and macOS")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readNativeExecutable(self); err != nil {
		t.Fatalf("the test binary: %v", err)
	}
	// Held as an adapter on this host, its loader, if it names one, with it:
	// a copy, in a directory at the test's mode, since the go command makes
	// the directory the test binary is in with mode 0777 less the umask, and
	// under a umask that leaves the group write the engine refuses that
	// directory before it reaches the binary.
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(tempDirAt(t, 0o755))
	if err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(dir, "adapter")
	if err := os.WriteFile(adapter, data, 0o755); err != nil {
		t.Fatal(err)
	}
	host := osEngineHost()
	host.euid = os.Geteuid()
	sources := map[string]sourceSpec{"warehouse/live": {argv: []string{adapter}}}
	if err := holdAdapterSources(sources, host); err != nil {
		t.Fatalf("the test binary as an adapter: %v", err)
	}
}

// hostExecutable is the smallest static executable of this host's own
// format and CPU that the format check accepts.
func hostExecutable() []byte {
	if runtime.GOOS == "darwin" {
		return machoFile(machoCPUs[runtime.GOARCH], macho.TypeExec, "")
	}
	want := elfHosts[runtime.GOARCH]
	return elfFile(want.class, want.data, elf.ET_EXEC, want.machine, "")
}
