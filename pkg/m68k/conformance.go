package m68k

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed testdata/gnu-vectors.json
var independentVectors []byte

// A generated project must carry executable corpus checks when consumed
// outside this repository, rather than relying on a Go test to install them.
func (c *Catalog) writeConformance(output string) error {
	var rows strings.Builder
	profiles := []string{"68000", "68010", "68020", "68030", "68040", "68060", "68881", "68851", "cpu32", "fido"}
	if c.Architecture == "coldfire" {
		profiles = []string{"coldfire-all"}
	}
	for j := range c.Opcodes {
		o := &c.Opcodes[j]
		for _, profile := range profiles {
			if Profiles[profile]&o.Features == 0 {
				continue
			}
			selected, err := c.WithCPU(profile)
			if err != nil {
				return err
			}
			values, err := sampleOpcode(selected, o)
			if err != nil {
				return err
			}
			encoded, err := selected.Encode(o.ID, values)
			if err != nil {
				return err
			}
			text, err := json.Marshal(values)
			if err != nil {
				return err
			}
			fmt.Fprintf(&rows, "%s\t%s %s\t%x\n", profile, o.ID, text, encoded)
			break
		}
	}
	var vectors []struct{ CPU, Text, Hex string }
	if err := json.Unmarshal(independentVectors, &vectors); err != nil {
		return err
	}
	for _, vector := range vectors {
		coldfire := strings.Contains(vector.CPU, "isa") || vector.CPU == "coldfire-all"
		if (c.Architecture == "coldfire") == coldfire {
			fmt.Fprintf(&rows, "%s\t%s\t%s\n", vector.CPU, vector.Text, vector.Hex)
		}
	}
	directory := filepath.Join(output, "tests")
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "generated_corpus.tsv"), []byte(rows.String()), 0644); err != nil {
		return err
	}
	source := fmt.Sprintf(`use %s_codec::*;
#[test] fn source_forms_and_independent_vectors() {
    for line in include_str!("generated_corpus.tsv").lines() {
        let row: Vec<_> = line.split('\t').collect();
        let catalog = Catalog::new(row[0]).unwrap();
        let expected: Vec<_> = row[2].as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
        let encoded = catalog.assemble(row[1]).expect(row[1]);
        assert_eq!(encoded, expected, "{}", row[1]);
        // swbeg is a jump-table data marker with the illegal opcode prefix.
        if row[1].starts_with("swbeg_") { continue; }
        let instruction = catalog.decode(&encoded).expect(row[1]);
        assert_eq!(instruction.length, encoded.len());
        assert_eq!(catalog.assemble(&instruction.to_string()).unwrap(), encoded);
        let a=instruction.describe(0x1000);assert_eq!(a.text,instruction.to_string());for span in &a.operands{assert!(!a.text[span.start..span.end].is_empty());assert_eq!(span.value,instruction.operands[span.index]);}let mut output=vec![0xcc;encoded.len()];assert_eq!(instruction.relocate_into(&catalog,0x1000,0x1000,&mut output).unwrap(),encoded.len());assert_eq!(output,encoded);if let Ok(moved)=instruction.relocated(&catalog,0x1000,0x1004){assert_eq!(moved.branch_target(0x1004),instruction.branch_target(0x1000));for n in 0..instruction.operands.len(){assert_eq!(moved.pc_relative_target(n,0x1004),instruction.pc_relative_target(n,0x1000));}}
        let mut template = catalog.template(instruction.opcode.id).unwrap();assert!(template.could_match(&encoded));assert_eq!(template.holes().len(),instruction.operands.len());
        assert!(template.match_instruction(&encoded).is_some(), "{}", row[1]);
        for (n,value) in instruction.operands.iter().enumerate() { template.set(&format!("op{}",n),value.clone()).unwrap(); }
        assert_eq!(template.encode().unwrap(), encoded);assert!(template.holes().is_empty());
        assert!(template.match_instruction(&encoded).is_some(), "{}", row[1]);
    }
}
#[test] fn strict_domains() {
    if ARCHITECTURE == "m68k" {
        let catalog = Catalog::new("68000").unwrap();
        assert!(catalog.assemble("moveq [128,0]").is_err());
        assert!(catalog.assemble("bras [0]").is_err());
        assert!(catalog.decode(&[0x60]).is_err());
        let bytes = catalog.assemble("movel [[40,-8],[0]]").unwrap();
        let instruction = catalog.decode(&bytes).unwrap();
        let a=instruction.describe(0x1000);assert_eq!(a.text,instruction.to_string());for span in &a.operands{assert!(!a.text[span.start..span.end].is_empty());assert_eq!(span.value,instruction.operands[span.index]);}let mut output=vec![0xcc;bytes.len()];assert_eq!(instruction.relocate_into(&catalog,0x1000,0x1000,&mut output).unwrap(),bytes.len());assert_eq!(output,bytes);if let Ok(moved)=instruction.relocated(&catalog,0x1000,0x1004){assert_eq!(moved.branch_target(0x1004),instruction.branch_target(0x1000));for n in 0..instruction.operands.len(){assert_eq!(moved.pc_relative_target(n,0x1004),instruction.pc_relative_target(n,0x1000));}}
        let mut template = catalog.template(instruction.opcode.id).unwrap();assert!(template.could_match(&bytes));assert_eq!(template.holes().len(),instruction.operands.len());
        template.set("op0", Value::List(vec![Value::U(40), Value::I(-8)])).unwrap();
        assert!(template.match_instruction(&bytes).is_some());
        assert!(template.match_instruction(&catalog.assemble("movel [[40,-10],[0]]").unwrap()).is_none());
        assert!(template.encode().is_err());
    }
}
`, c.Architecture)
	return os.WriteFile(filepath.Join(directory, "generated_corpus.rs"), []byte(source), 0644)
}
