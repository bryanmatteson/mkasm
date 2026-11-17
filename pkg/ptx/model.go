// Package ptx provides a lossless textual codec for NVIDIA's virtual ISA.
// Native GPU machine code is deliberately not represented as PTX bytes.
package ptx

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

type Source struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}
type Document struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Section      string   `json:"section"`
	Names        []string `json:"names"`
	Syntax       []string `json:"syntax"`
	Examples     []string `json:"examples"`
	Requirements []string `json:"requirements"`
	MinVersion   int      `json:"min_version"`
	MinTarget    int      `json:"min_target"`
}
type OperandDefinition struct {
	Name  string `json:"name"`
	Class string `json:"class_name"`
}
type LLVMRecord struct {
	ID          string              `json:"id"`
	Syntax      string              `json:"syntax"`
	Pseudo      bool                `json:"pseudo"`
	Namespace   string              `json:"namespace"`
	Features    []string            `json:"features"`
	Operands    []OperandDefinition `json:"operands"`
	Constraints string              `json:"constraints"`
	Locations   []string            `json:"locations"`
}
type Grammar struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}
type Feature struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Field       string   `json:"field"`
	Value       string   `json:"value"`
	Description string   `json:"description"`
	Condition   string   `json:"condition"`
	Implies     []string `json:"implies"`
}
type Catalog struct {
	Features       []Feature      `json:"features"`
	TargetVersions map[string]int `json:"target_versions"`
	Schema         string         `json:"schema"`
	Architecture   string         `json:"architecture"`
	ISAVersion     string         `json:"isa_version"`
	Sources        []Source       `json:"sources"`
	Documents      []Document     `json:"documents"`
	LLVM           []LLVMRecord   `json:"llvm"`
	Grammar        []Grammar      `json:"grammar"`
}

//go:embed testdata/registry.json
var assets embed.FS
var once sync.Once
var defaultCatalog *Catalog

func Default() *Catalog {
	once.Do(func() {
		r, _ := assets.Open("testdata/registry.json")
		defer r.Close()
		var e error
		defaultCatalog, e = Parse(r, "ptx")
		if e != nil {
			panic(e)
		}
	})
	return defaultCatalog
}
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "ptx" && architecture != "nvptx" && architecture != "nvptx64" && architecture != "nvptx32" {
		return nil, fmt.Errorf("unsupported PTX architecture %q", architecture)
	}
	var c Catalog
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return nil, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return nil, fmt.Errorf("trailing PTX registry data")
	}
	if c.Schema != "mkasm.ptx.registry.v1" || len(c.Documents) == 0 || len(c.LLVM) == 0 {
		return nil, fmt.Errorf("invalid/empty PTX registry")
	}
	seen := map[string]bool{}
	for _, v := range c.Documents {
		if v.ID == "" || seen[v.ID] || len(v.Syntax) == 0 {
			return nil, fmt.Errorf("invalid/duplicate PTX document %q", v.ID)
		}
		seen[v.ID] = true
	}
	seen = map[string]bool{}
	for _, v := range c.LLVM {
		if v.ID == "" || seen[v.ID] {
			return nil, fmt.Errorf("invalid/duplicate LLVM record")
		}
		seen[v.ID] = true
	}
	c.Architecture = "ptx"
	return &c, nil
}
func (c *Catalog) WriteJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(c)
}
func (c *Catalog) Lookup(opcode string) []Document {
	var out []Document
	max := 0
	for _, d := range c.Documents {
		if d.Kind != "instruction" {
			continue
		}
		for _, n := range d.Names {
			if matchesInstructionFamily(opcode, n) {
				if len(n) > max {
					out = nil
					max = len(n)
				}
				if len(n) == max {
					out = append(out, d)
				}
				break
			}
		}
	}
	return out
}

func matchesInstructionFamily(opcode, name string) bool {
	if opcode == name || strings.HasPrefix(opcode, name+".") || strings.HasPrefix(opcode, name+"::") {
		return true
	}
	// The primary document calls this family "match.sync", while its
	// mandatory operation selector occurs between those two name components.
	if name == "match.sync" {
		return strings.HasPrefix(opcode, "match.any.sync.") || strings.HasPrefix(opcode, "match.all.sync.")
	}
	return false
}

// Assemble parses PTX text and applies the source-scoped profile checks. For
// complete ISA legality, use ValidateWith and a pinned primary assembler.
func (c *Catalog) Assemble(source string, p Profile) (*Module, error) {
	m, e := Decode(source)
	if e != nil {
		return nil, e
	}
	if e = c.Check(m, p).Error(); e != nil {
		return nil, e
	}
	return m, nil
}
