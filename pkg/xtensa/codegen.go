package xtensa

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed runtime.rs.tmpl
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

//go:embed context.rs.tmpl
var rustContext string

//go:embed testdata/LICENSE-LLVM
var llvmLicense []byte

//go:embed testdata/LICENSE-GNU
var gnuLicense []byte

//go:embed testdata/LICENSE-GHIDRA
var ghidraLicense []byte

//go:embed README.md
var readme []byte

func (c *Catalog) GenerateRust(output string) error {
	combined := *c.Core
	combined.Encodings = append(append([]codec.Encoding{}, c.Core.Encodings...), c.Slots.Encodings...)
	if err := combined.GenerateRust(output); err != nil {
		return err
	}
	path := filepath.Join(output, "src/lib.rs")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	src := string(data)
	for _, pair := range [][2]string{{"Decoded", "DecodedField"}, {"Assembler", "FieldAssembler"}, {"Template", "FieldTemplate"}, {"decode", "decode_field"}, {"decode_with_features", "decode_field_with_features"}, {"assemble", "assemble_field"}, {"assemble_at", "assemble_field_at"}, {"assemble_with_features", "assemble_field_with_features"}, {"describe", "describe_field"}, {"describe_with_features", "describe_field_with_features"}} {
		src = regexp.MustCompile(`\b`+pair[0]+`\b`).ReplaceAllString(src, pair[1])
	}
	var b strings.Builder
	b.WriteString("\nstatic SLOT_META:&[SlotMeta]=&[\n")
	for _, e := range combined.Encodings {
		m, ok := c.Metadata[e.ID]
		if !ok {
			fmt.Fprintln(&b, "SlotMeta{slot:-1,format:0,mask:&[]},")
		} else {
			fmt.Fprintf(&b, "SlotMeta{slot:%d,format:%d,mask:&%v},\n", m.Slot, m.Format, m.Mask)
		}
	}
	b.WriteString("];\n")
	b.WriteString("static FORMAT_META:&[FormatMeta]=&[\n")
	for _, f := range c.Formats {
		fmt.Fprintf(&b, "FormatMeta{name:%q,length:%d,slots:&%v,mask:&%v,value:&%v,scalar:%t},\n", f.Name, f.Length, f.Slots, f.Mask, f.Value, f.Scalar)
	}
	b.WriteString("];\n")

	src += b.String() + rustRuntime + rustAnalysis + rustContext
	// Go's byte formatting uses spaces; normalize only byte array expressions.
	src = regexp.MustCompile(`(?:mask|value|slots):&\[([0-9 ]+)\]`).ReplaceAllStringFunc(src, func(v string) string { return strings.ReplaceAll(v, " ", ",") })
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "LICENSE-LLVM"), llvmLicense, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "LICENSE-GNU"), gnuLicense, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "LICENSE-GHIDRA"), ghidraLicense, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "README.md"), readme, 0644); err != nil {
		return err
	}
	data, err = json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "catalog.json"), data, 0644)
}
