package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// An adapter must be an executable the kernel of this host runs itself
// (gateway #203): a script hands itself to an interpreter, and #!/usr/bin/env
// to whichever one a PATH holds, and neither is held. The file is read as the
// host's own format by Go's parsers, not by its first bytes alone: an ELF
// executable on Linux and the other ELF systems, a Mach-O one, or a universal
// file holding one, on macOS, each for the host's CPU.

// readNativeExecutable opens the file at path, the one the walk held, and
// holds it to nativeExecutable for this host, reading no more of it than its
// size.
func readNativeExecutable(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("could not be read to tell whether it is a native executable: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("could not be read to tell whether it is a native executable: %v", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("is not a regular file")
	}
	return nativeExecutable(io.NewSectionReader(file, 0, info.Size()), runtime.GOOS, runtime.GOARCH)
}

// errScript is an adapter that is a script.
var errScript = errors.New("is a script (it starts with #!), and the interpreter it names, or the one env would find, is not held; install the adapter's own binary")

// nativeExecutable says why the file r holds is not an executable the kernel
// of goos on goarch runs itself, or answers the loader it names, empty when
// it names none (a statically linked one):
//
//   - on macOS, a Mach-O file of type MH_EXECUTE for the host's CPU, or a
//     universal file whose architecture table parses and holds such a slice;
//     its loader is the one its LC_LOAD_DYLINKER names;
//   - elsewhere, an ELF file of type ET_EXEC or ET_DYN (Go builds either) for
//     the host's machine, class and byte order; its loader is the one its
//     PT_INTERP names.
//
// A file the parser refuses is refused, a truncated header among them.
func nativeExecutable(r io.ReaderAt, goos, goarch string) (string, error) {
	var head [2]byte
	if _, err := r.ReadAt(head[:], 0); err == nil && bytes.Equal(head[:], []byte("#!")) {
		return "", errScript
	}
	if goos == "darwin" {
		return machoExecutable(r, goarch)
	}
	return elfExecutable(r, goarch)
}

// elfHost is what an ELF executable for a Go architecture says it is for.
type elfHost struct {
	machine elf.Machine
	class   elf.Class
	data    elf.Data
}

var elfHosts = map[string]elfHost{
	"amd64":    {elf.EM_X86_64, elf.ELFCLASS64, elf.ELFDATA2LSB},
	"arm64":    {elf.EM_AARCH64, elf.ELFCLASS64, elf.ELFDATA2LSB},
	"386":      {elf.EM_386, elf.ELFCLASS32, elf.ELFDATA2LSB},
	"arm":      {elf.EM_ARM, elf.ELFCLASS32, elf.ELFDATA2LSB},
	"riscv64":  {elf.EM_RISCV, elf.ELFCLASS64, elf.ELFDATA2LSB},
	"ppc64":    {elf.EM_PPC64, elf.ELFCLASS64, elf.ELFDATA2MSB},
	"ppc64le":  {elf.EM_PPC64, elf.ELFCLASS64, elf.ELFDATA2LSB},
	"s390x":    {elf.EM_S390, elf.ELFCLASS64, elf.ELFDATA2MSB},
	"loong64":  {elf.EM_LOONGARCH, elf.ELFCLASS64, elf.ELFDATA2LSB},
	"mips":     {elf.EM_MIPS, elf.ELFCLASS32, elf.ELFDATA2MSB},
	"mipsle":   {elf.EM_MIPS, elf.ELFCLASS32, elf.ELFDATA2LSB},
	"mips64":   {elf.EM_MIPS, elf.ELFCLASS64, elf.ELFDATA2MSB},
	"mips64le": {elf.EM_MIPS, elf.ELFCLASS64, elf.ELFDATA2LSB},
}

// maxLoaderPath bounds the loader path a file names.
const maxLoaderPath = 4096

func elfExecutable(r io.ReaderAt, goarch string) (string, error) {
	want, known := elfHosts[goarch]
	if !known {
		return "", fmt.Errorf("cannot be held: this host's CPU (%s) is not one the check knows", goarch)
	}
	file, err := elf.NewFile(r)
	if err != nil {
		return "", fmt.Errorf("is not an ELF executable this host runs: %v", err)
	}
	switch {
	case file.Machine != want.machine || file.Class != want.class || file.Data != want.data:
		return "", fmt.Errorf("is an ELF file for %s (%s, %s), not for this host's CPU (%s)", file.Machine, file.Class, file.Data, goarch)
	case file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN:
		return "", fmt.Errorf("is an ELF file of type %s, not an executable", file.Type)
	}
	for _, prog := range file.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		if prog.Filesz == 0 || prog.Filesz > maxLoaderPath {
			return "", errors.New("names a loader of no length this check reads")
		}
		name := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(name, 0); err != nil {
			return "", fmt.Errorf("names a loader that could not be read: %v", err)
		}
		return string(bytes.TrimRight(name, "\x00")), nil
	}
	return "", nil
}

// machoCPUs is the Mach-O CPU a Go architecture runs.
var machoCPUs = map[string]macho.Cpu{"amd64": macho.CpuAmd64, "arm64": macho.CpuArm64}

// loadDylinker is LC_LOAD_DYLINKER, the load command naming the loader.
const loadDylinker = 0xe

func machoExecutable(r io.ReaderAt, goarch string) (string, error) {
	want, known := machoCPUs[goarch]
	if !known {
		return "", fmt.Errorf("cannot be held: this host's CPU (%s) is not one the check knows", goarch)
	}
	// A universal file is one whose first four bytes, big-endian, are the
	// fat magic; any other file is read as a thin Mach-O one.
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 0); err == nil && binary.BigEndian.Uint32(magic[:]) == macho.MagicFat {
		fat, err := macho.NewFatFile(r)
		if err != nil {
			return "", fmt.Errorf("is not a universal file this host runs: %v", err)
		}
		defer fat.Close()
		for _, arch := range fat.Arches {
			if arch.Cpu == want && arch.Type == macho.TypeExec {
				return machoLoader(arch.File)
			}
		}
		return "", fmt.Errorf("is a universal file with no executable slice for this host's CPU (%s)", goarch)
	}
	file, err := macho.NewFile(r)
	if err != nil {
		return "", fmt.Errorf("is not a Mach-O executable this host runs: %v", err)
	}
	defer file.Close()
	switch {
	case file.Cpu != want:
		return "", fmt.Errorf("is a Mach-O file for %s, not for this host's CPU (%s)", file.Cpu, goarch)
	case file.Type != macho.TypeExec:
		return "", fmt.Errorf("is a Mach-O file of type %s, not an executable", file.Type)
	}
	return machoLoader(file)
}

// machoLoader is the loader a Mach-O executable's LC_LOAD_DYLINKER names, or
// empty when it names none.
func machoLoader(file *macho.File) (string, error) {
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 12 || file.ByteOrder.Uint32(raw[0:4]) != loadDylinker {
			continue
		}
		offset := file.ByteOrder.Uint32(raw[8:12])
		if offset < 12 || int(offset) >= len(raw) || len(raw)-int(offset) > maxLoaderPath {
			return "", errors.New("names a loader this check cannot read")
		}
		return string(bytes.TrimRight(raw[offset:], "\x00")), nil
	}
	return "", nil
}
