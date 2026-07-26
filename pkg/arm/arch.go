package arm

import (
	"fmt"
	"sort"
	"strings"
)

// Arch is a target architecture. It names the instruction set the generated
// code encodes, and it names the generated artifact: a Rust crate or Go module
// generated for aarch64 is called "aarch64", so pointing -output at a tree like
// iasm/arch/aarch64 produces a crate that matches the directory it lands in.
type Arch string

const (
	// ArchAArch64 is the ARM A64 instruction set.
	ArchAArch64 Arch = "aarch64"
)

// archSpecIndex maps an architecture to the index file its spec tree must have.
// Adding an architecture means adding its spec parser and an entry here.
var archSpecIndex = map[Arch]string{
	ArchAArch64: "encodingindex.xml",
}

// SupportedArches lists the architectures this build can generate.
func SupportedArches() []Arch {
	out := make([]Arch, 0, len(archSpecIndex))
	for a := range archSpecIndex {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseArch validates an -arch value.
func ParseArch(s string) (Arch, error) {
	a := Arch(strings.ToLower(strings.TrimSpace(s)))
	if a == "" {
		return ArchAArch64, nil
	}
	// Accept the common spellings of the same target.
	switch a {
	case "arm64", "aarch64", "arm64e":
		a = ArchAArch64
	}
	if _, ok := archSpecIndex[a]; !ok {
		names := make([]string, 0, len(archSpecIndex))
		for _, x := range SupportedArches() {
			names = append(names, string(x))
		}
		return "", fmt.Errorf("unsupported -arch %q; this build generates: %s",
			s, strings.Join(names, ", "))
	}
	return a, nil
}

// SpecIndexFile is the index file the architecture's spec tree is rooted at.
func (a Arch) SpecIndexFile() string { return archSpecIndex[a] }

// ArtifactName is the Rust crate name and Go module name for this target.
func (a Arch) ArtifactName() string { return string(a) }
