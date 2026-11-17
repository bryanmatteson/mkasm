package mcs51

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed extra.rs
var extraRust string

//go:embed public.rs
var publicRust string

//go:embed data/oracle.json
var oracleJSON []byte

//go:embed data/sdcc.json
var sdccJSON []byte

//go:embed data/programs.json
var programJSON []byte

func (c *Catalog) GenerateRust(dir string) error {
	if e := c.Catalog.GenerateRust(dir); e != nil {
		return e
	}
	path := filepath.Join(dir, "src/lib.rs")
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	s := string(raw)
	for _, signature := range []string{"pub fn assemble_with_features(text:&str,address:u64,active:Option<&[&str]>)->Result<Vec<Vec<u8>>,Error>{", "pub fn parse_with_features(text:&str,address:u64,active:Option<&[&str]>)->Result<Self,Error>{"} {
		if !strings.Contains(s, signature) {
			return fmt.Errorf("MCS-51 shared runtime text hook changed")
		}
		s = strings.Replace(s, signature, signature+"let normalized=mcs51_text(text);let text=normalized.as_str();", 1)
	}
	checks, e := c.rustChecks()
	if e != nil {
		return e
	}
	if e = os.WriteFile(path, []byte(s+extraRust+checks), 0644); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Join(dir, "tests"), 0755); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "tests/public.rs"), []byte(strings.ReplaceAll(publicRust, "__CRATE__", c.Architecture)), 0644); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "MCS51-NOTICE"), []byte("Instruction constructors and SFR/bit symbols derived from Ghidra 12.1.2, revision "+Revision+" (Apache-2.0).\nhttps://github.com/NationalSecurityAgency/ghidra/blob/"+Revision+"/Ghidra/Processors/8051/data/languages/8051_main.sinc\n\n"+license+"\nCore MCS-51 opcodes and DS80C390 flat-mode forms are imported completely. A5 is reserved. 80251 and MX51 extension sources are separate and are not admitted by this codec.\nThe codec resolves encoded PC-relative/page targets. Logical register bank and external indirect helpers require caller-provided PSW/P2 state; it does not execute the processor.\n"), 0644)
}

type oracleVector struct {
	Architecture, Bytes, Assembly, OracleText, OracleEncoded, OracleError string
	Address                                                               uint64
	Length                                                                int
}

func (c *Catalog) rustChecks() (string, error) {
	var vectors []oracleVector
	if e := json.Unmarshal(oracleJSON, &vectors); e != nil {
		return "", e
	}
	var independent []oracleVector
	if e := json.Unmarshal(sdccJSON, &independent); e != nil {
		return "", e
	}
	vectors = append(vectors, independent...)
	var b strings.Builder
	b.WriteString("\n#[cfg(test)] mod mcs_oracle {use super::*;#[test]fn complete_real_opcode_oracle(){let cases:&[(&[u8],u64)]=&[\n")
	n := 0
	for _, v := range vectors {
		if v.Architecture != c.Architecture {
			continue
		}
		raw, e := hex.DecodeString(v.Bytes)
		if e != nil {
			return "", e
		}
		var x []string
		for _, v := range raw {
			x = append(x, strconv.Itoa(int(v)))
		}
		fmt.Fprintf(&b, "(&[%s],%d),\n", strings.Join(x, ","), v.Address)
		n++
	}
	fmt.Fprintf(&b, "];assert_eq!(cases.len(),%d);for &(raw,pc)in cases{let d=decode(raw).unwrap();assert_eq!(d.length,raw.len());assert_eq!(encode(ENCODINGS[d.encoding_index].id,&d.values[..ENCODINGS[d.encoding_index].operands.len()]).unwrap(),raw);let text=d.format(pc);assert!(assemble_at(&text,pc).unwrap().iter().any(|b|b==raw),\"{} at {:x}\",text,pc);let t=Template::parse_at(&text,pc).unwrap();assert!(t.matches(raw).is_some());assert!(t.encode(&[]).unwrap().iter().any(|b|b==raw));for n in 0..raw.len(){assert!(decode(&raw[..n]).is_err());}}assert!(decode(&[0xa5]).is_err());}}\n", n)
	var programs []oracleVector
	if e := json.Unmarshal(programJSON, &programs); e != nil {
		return "", e
	}
	b.WriteString("#[cfg(test)]mod mcs_compiled_program {use super::*;#[test]fn sdcc_compiled_program(){\n")
	for _, p := range programs {
		if p.Architecture != c.Architecture {
			continue
		}
		raw, e := hex.DecodeString(p.Bytes)
		if e != nil {
			return "", e
		}
		var values []string
		for _, v := range raw {
			values = append(values, strconv.Itoa(int(v)))
		}
		fmt.Fprintf(&b, "let raw:&[u8]=&[%s];let mut at=0;let mut out=Vec::new();while at<raw.len(){let d=decode(&raw[at..]).unwrap();let b=encode(d.encoding().id,&d.values[..d.encoding().operands.len()]).unwrap();assert!(assemble_at(&d.format(%d+at as u64),%d+at as u64).unwrap().iter().any(|x|*x==b));out.extend_from_slice(&b);at+=d.length;}assert_eq!(out,raw);\n", strings.Join(values, ","), p.Address, p.Address)
	}
	b.WriteString("}}\n")
	return b.String(), nil
}
