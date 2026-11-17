package mos6502

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed testdata/CC65-LICENSE
var cc65License string

//go:embed runtime.rs
var rustExtra string

//go:embed testdata/cc65-vectors.json
var referenceVectors []byte

//go:embed testdata/program.bin
var referenceRoutine []byte
var sourceNotice = "Opcode metadata from cc65 V2.19, Copyright Ullrich von Bassewitz and cc65 contributors. The four original source notices are retained in testdata/opcodes.c. License: Zlib. WDC reserved-NOP framing and BRK signature facts are derived from the W65C02S datasheet dated February 16,2024, tables 4-1 and 7-1; Copyright 1981-2024 Western Design Center, Inc. Datasheet is not redistributed.\n\n" + cc65License

func (c *Catalog) GenerateRust(output string) error {
	if err := c.Catalog.GenerateRust(output); err != nil {
		return err
	}
	lib := filepath.Join(output, "src/lib.rs")
	raw, err := os.ReadFile(lib)
	if err != nil {
		return err
	}
	text := string(raw)
	for _, signature := range []string{"pub fn assemble_with_features(text:&str,address:u64,active:Option<&[&str]>)->Result<Vec<Vec<u8>>,Error>{", "pub fn parse_with_features(text:&str,address:u64,active:Option<&[&str]>)->Result<Self,Error>{"} {
		if !strings.Contains(text, signature) {
			return fmt.Errorf("MOS6502 runtime hook changed")
		}
		text = strings.Replace(text, signature, signature+"\nlet normalized=mos_text(text);let text=normalized.as_str();", 1)
	}
	checks, err := c.rustChecks()
	if err != nil {
		return err
	}
	if err := os.WriteFile(lib, []byte("// cc65 V2.19 opcode metadata; Zlib notice in UPSTREAM-LICENSE.\n"+text+rustExtra+checks), 0644); err != nil {
		return err
	}
	f := filepath.Join(output, "README.md")
	raw, err = os.ReadFile(f)
	if err != nil {
		return err
	}
	return os.WriteFile(f, append(raw, []byte("\nSelect a named profile to disambiguate NMOS and CMOS opcode meanings: 6502,6502x,65sc02,65c02,w65c02,w65c02+nops. 6502x explicitly includes undocumented opcodes; +nops explicitly includes the WDC reserved NOP encodings. BRK consumes its signature byte and is represented as brk #signature (bare brk means signature zero). ca65 dollar hexadecimal and percent binary literals are accepted. resolve_operand models 16-bit wrapping, zero-page pointer wrapping, indexed page crossing and the NMOS JMP indirect page bug. 65816 bank and M/X state are outside this 6502-family codec. Metadata is from cc65 V2.19 with its Zlib notice preserved in UPSTREAM-LICENSE.\n")...), 0644)
}

func rustArray(b []byte) string {
	var parts []string
	for _, n := range b {
		parts = append(parts, fmt.Sprint(n))
	}
	return "[" + strings.Join(parts, ",") + "]"
}
func (c *Catalog) rustChecks() (string, error) {
	var rows []struct{ ID, Profile, Bytes string }
	if err := json.Unmarshal(referenceVectors, &rows); err != nil {
		return "", err
	}
	byID := make(map[string]struct{ ID, Profile, Bytes string }, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	var b strings.Builder
	b.WriteString("\n#[cfg(test)] mod mos_reference_checks{use super::*;\n#[test] fn full_pinned_reference_corpus(){\n")
	for j := range c.Encodings {
		e := &c.Encodings[j]
		row, exists := byID[e.ID]
		if !exists {
			return "", fmt.Errorf("reference corpus missing %s", e.ID)
		}
		raw, err := hex.DecodeString(row.Bytes)
		if err != nil {
			return "", err
		}
		var values []string
		for _, o := range e.Operands {
			n := int64(0x44)
			if o.Width() == 16 {
				n = 0x1234
			}
			if o.Relative {
				n = 8
			}
			if o.Name == "signature" {
				n = 0
			}
			values = append(values, fmt.Sprint(n))
		}
		fmt.Fprintf(&b, "{let expected=&%s;assert_eq!(encode(%q,&[%s]).unwrap(),expected);let d=decode_with_features(expected,Some(profile(%q).unwrap())).unwrap();assert_eq!(d.length,expected.len());assert!(assemble_with_features(&d.format(0x1000),0x1000,Some(profile(%q).unwrap())).unwrap().iter().any(|v|v==expected));}\n", rustArray(raw), row.ID, strings.Join(values, ","), row.Profile, row.Profile)
	}
	if len(c.Encodings) != len(rows) {
		// A CLI --cpu selection emits only that processor's instructions. Its
		// independent vectors stay executable without referring to removed forms.
		b.WriteString("}\n}\n")
		return b.String(), nil
	}
	fmt.Fprintf(&b, "}\n#[test] fn actual_assembled_routine(){let code=&%s;let mut offset=0;let mut count=0;let mut exits=0;while offset<code.len(){let d=decode_with_features(&code[offset..],Some(profile(\"65sc02\").unwrap())).unwrap();let e=d.encoding();assert_eq!(encode(e.id,&d.values[..e.operands.len()]).unwrap(),code[offset..offset+d.length]);assert!(assemble_with_features(&d.format((0x1000+offset)as u64),(0x1000+offset)as u64,Some(profile(\"65sc02\").unwrap())).unwrap().iter().any(|v|v==&code[offset..offset+d.length]));if let Some(target)=d.branch_target((0x1000+offset)as u64){if target==0xfff9&&e.mnemonic.eq_ignore_ascii_case(\"jmp\"){exits+=1;}else{assert!((0x1000..0x1000+code.len() as u64).contains(&target));}}offset+=d.length;count+=1;}assert_eq!(count,29);assert_eq!(exits,2);}\n", rustArray(referenceRoutine))
	b.WriteString(`#[test] fn profiles_templates_and_address_rules(){
 assert_eq!(Template::parse_with_features("nop",0,Some(profile("6502").unwrap())).unwrap().encode(&[]).unwrap(),vec![vec![0xea]]);
 assert_eq!(opcode_status("6502",2).unwrap(),"invalid");assert_eq!(opcode_status("6502x",2).unwrap(),"undocumented");assert_eq!(opcode_status("w65c02+nops",0x5c).unwrap(),"reserved-nop");
 assert!(decode_with_features(&[2],Some(profile("6502").unwrap())).is_err());assert_eq!(decode_with_features(&[2],Some(profile("6502x").unwrap())).unwrap().length,1);assert_eq!(decode_with_features(&[2],Some(profile("w65c02+nops").unwrap())).unwrap_err(),Error::Truncated);
 let t=Template::parse("lda #${constant}").unwrap();let bs=t.encode(&[("constant",255)]).unwrap();assert_eq!(bs,vec![vec![0xa9,255]]);assert_eq!(t.matches(&bs[0]).unwrap().1,vec![("constant".into(),255)]);
 assert_eq!(assemble("lda #$ff").unwrap(),bs);assert_eq!(assemble("lda #%11111111").unwrap(),bs);assert_eq!(assemble("brk").unwrap(),vec![vec![0,0]]);
 let b=assemble_with_features("bne $0002",0xfffe,Some(profile("6502").unwrap())).unwrap();let d=decode_with_features(&b[0],Some(profile("6502").unwrap())).unwrap();assert_eq!(d.branch_target(0xfffe),Some(2));
 let d=decode_with_features(&[0x6c,0xff,0x10],Some(profile("6502").unwrap())).unwrap();let mut read=|p|match p{0x10ff=>0x78,0x1000=>0x56,0x1100=>0x9a,_=>0};assert_eq!(resolve_operand(&d,"address",0,"6502",0,0,Some(&mut read)).unwrap().unwrap().address,0x5678);assert_eq!(resolve_operand(&d,"address",0,"65c02",0,0,Some(&mut read)).unwrap().unwrap().address,0x9a78);
 let d=decode_with_features(&[0xb5,0xff],Some(profile("6502").unwrap())).unwrap();assert_eq!(resolve_operand(&d,"address",0,"6502",2,0,None).unwrap().unwrap().address,1);
 for bad in ["lda #256","lda #-129","sta #1","jmp (65536)","brk #256"]{assert!(assemble(bad).is_err());}
}
}
`)
	return b.String(), nil
}
