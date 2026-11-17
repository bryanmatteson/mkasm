package v850

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func retainedVectors(t *testing.T, name string) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var rows []vector
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestRetainedGhidra(t *testing.T) {
	c := load(t)
	rows := retainedVectors(t, "ghidra-vectors.json")
	if len(rows) != 308 {
		t.Fatal(len(rows))
	}
	for _, row := range rows {
		var e *codec.Encoding
		for j := range c.Encodings {
			if c.Encodings[j].ID == row.ID {
				e = &c.Encodings[j]
				break
			}
		}
		if e == nil {
			t.Fatal(row.ID)
		}
		got, err := c.Encode(row.ID, sample(e))
		want, _ := hex.DecodeString(row.Bytes)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal(row.ID, err)
		}
	}
}

func TestRealRoutine(t *testing.T) {
	c := load(t)
	code, err := os.ReadFile("testdata/program.bin")
	if err != nil {
		t.Fatal(err)
	}
	flow := map[string]int{}
	count := 0
	for offset := 0; offset < len(code); {
		d, err := c.DecodeWithFeatures(code[offset:], c.FeatureSets["v850e3v5+extension"])
		if err != nil {
			t.Fatalf("method offset %d: %v", offset, err)
		}
		encoded, err := c.Encode(d.Encoding.ID, d.Values)
		if err != nil || !bytes.Equal(encoded, code[offset:offset+d.Length]) {
			t.Fatalf("method offset %d: %v", offset, err)
		}
		text := d.Format(uint64(offset))
		forms, err := c.Assemble(text, uint64(offset))
		if err != nil {
			t.Fatal(text, err)
		}
		found := false
		for _, b := range forms {
			found = found || bytes.Equal(b, encoded)
		}
		if !found {
			t.Fatal("routine text lost bytes", text)
		}
		if target, ok := d.BranchTarget(uint64(offset)); ok && (target >= uint64(len(code)) || target%2 != 0) {
			t.Fatal("invalid routine target", target)
		}
		flow[d.Encoding.FlowControl]++
		t.Logf("%04x %-36s %x", offset, text, encoded)
		offset += d.Length
		count++
	}
	if count != 14 || flow["call"] != 1 || flow["conditional_branch"] != 2 || flow["return"] != 1 {
		t.Fatal(count, flow)
	}
	if as := os.Getenv("MKASM_V850_AS"); as != "" {
		dir := t.TempDir()
		object := filepath.Join(dir, "program.o")
		cmd := exec.Command(as, "-mv850e3v5", "-mextension", "-o", object, "testdata/program.s")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		f, err := elf.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		actual, err := f.Section(".text").Data()
		if err != nil || !bytes.Equal(actual, code) {
			t.Fatal("real GNU routine differs", err)
		}
	}
}

func TestBoundaryFields(t *testing.T) {
	c := load(t)
	for j := range c.Encodings {
		e := &c.Encodings[j]
		for _, o := range e.Operands {
			var candidates []int64
			switch o.Class {
			case "D9", "D9_RELAX":
				candidates = []int64{-256, -2, 0, 254}
			case "D16_15":
				candidates = []int64{-32768, -2, 0, 32766}
			case "D16", "D16_16", "I16", "IMM16LO":
				candidates = []int64{-32768, -1, 0, 32767}
			case "D16_LOOP":
				candidates = []int64{-65534, -2, 0}
			case "D17_16":
				candidates = []int64{-65536, -2, 0, 65534}
			case "D22":
				candidates = []int64{-2097152, -2, 0, 2097150}
			case "D23":
				candidates = []int64{-4194304, -1, 0, 4194303}
			case "D23_ALIGN1":
				candidates = []int64{-4194304, -2, 0, 4194302}
			case "D32_31", "D32_31_PCREL":
				candidates = []int64{-2147483648, -2, 0, 2147483646}
			case "IMM32":
				candidates = []int64{0, 0x80000000, 0xffffffff}
			case "IMM16HI":
				candidates = []int64{0, 0x80000000, 0xffff0000}
			case "I5DIV1":
				candidates = []int64{2, 30}
			case "I5DIV2":
				candidates = []int64{4, 30}
			case "I5DIV3":
				candidates = []int64{2, 32}
			}
			for _, n := range candidates {
				v := sample(e)
				v[o.Name] = n
				b, err := c.Encode(e.ID, v)
				if err != nil {
					t.Fatal(e.ID, o.Class, n, err)
				}
				// Decode the exact source form to check every split bit even when
				// another source alias is the preferred disassembly spelling.
				enc := *e
				enc.AssemblyOnly = false
				single := codec.Catalog{Encodings: []codec.Encoding{enc}}
				d, err := single.Decode(b)
				if err != nil || d.Values[o.Name] != n {
					t.Fatal(e.ID, o.Class, n, d, err)
				}
			}
		}
	}
	for mask := int64(0); mask < 4096; mask++ {
		var e *codec.Encoding
		for j := range c.Encodings {
			if c.Encodings[j].Mnemonic == "prepare" && len(c.Encodings[j].Operands) == 2 {
				e = &c.Encodings[j]
				break
			}
		}
		v := sample(e)
		v["op0"] = mask
		b, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(mask, err)
		}
		d, err := c.Decode(b)
		if err != nil || d.Values["op0"] != mask {
			t.Fatal(mask, d, err)
		}
	}
	for position := 0; position < 32; position++ {
		for width := 1; width <= 32-position; width++ {
			text := fmt.Sprintf("bins r1,%d,%d,r2", position, width)
			forms, err := c.Assemble(text, 0)
			if err != nil || len(forms) != 1 {
				t.Fatal(text, len(forms), err)
			}
			d, err := c.Decode(forms[0])
			if err != nil || d.Values["op1"] != int64(position) || d.Values["op2"] != int64(width) {
				t.Fatal(text, d, err)
			}
		}
	}
	for _, text := range []string{"bins r1,4,0,r2", "bins r1,31,2,r2", "divn 2,r1,r2,r3", "divhn 32,r1,r2,r3", "sdivn 0,r1,r2,r3"} {
		if _, err := c.Assemble(text, 0); err == nil {
			t.Fatal("invalid boundary accepted", text)
		}
	}
	for _, target := range []struct {
		address uint64
		text    string
		offset  int64
	}{{0xfffffffe, "br 0x2", 4}, {2, "br 0xfffffffe", -4}} {
		forms, err := c.Assemble(target.text, target.address)
		if err != nil {
			t.Fatal(err)
		}
		d, err := c.Decode(forms[0])
		if err != nil || d.Values["op0"] != target.offset || d.Format(target.address) != target.text {
			t.Fatal(target, d, err)
		}
	}
	for _, pair := range [][2]string{{"prepare {r20},4,sp", "prepare {r20},4,r3"}, {"dispose 4,{r20},[lp]", "dispose 4,{r20},lp"}, {"sld.w 4[ep],r2", "sld.w 4[r30],r2"}} {
		a, err := c.Assemble(pair[0], 0)
		if err != nil {
			t.Fatal(err)
		}
		b, err := c.Assemble(pair[1], 0)
		if err != nil || !bytes.Equal(a[0], b[0]) {
			t.Fatal(pair, err)
		}
	}
}

func TestGeneratedRust(t *testing.T) {
	if os.Getenv("MKASM_V850_RUST") == "" {
		t.Skip("set MKASM_V850_RUST=1 to compile and run the standalone consumer")
	}
	c := load(t)
	dir := t.TempDir()
	if artifact := os.Getenv("MKASM_V850_ARTIFACT_DIR"); artifact != "" {
		dir = filepath.Join(artifact, "rust")
	}
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	var test strings.Builder
	test.WriteString("use v850::*;\n#[test] fn independent_gnu_vectors(){\n")
	for j, row := range retainedVectors(t, "gnu-vectors.json") {
		e := &c.Encodings[j]
		v := sample(e)
		var values []string
		for _, o := range e.Operands {
			values = append(values, fmt.Sprint(v[o.Name]))
		}
		b, _ := hex.DecodeString(row.Bytes)
		fmt.Fprintf(&test, "{let b:Vec<u8>=vec!%v; assert_eq!(encode(%q,&[%s]).unwrap(),b);", b, e.ID, strings.Join(values, ","))
		if !e.AssemblyOnly {
			fmt.Fprintf(&test, "let d=decode_with_features(&b,Some(profile(%q).unwrap())).unwrap();assert_eq!(d.length,b.len());let e=d.encoding();assert_eq!(encode(e.id,&d.values[..e.operands.len()]).unwrap(),b);assert!(assemble_at(&d.format(0x1000),0x1000).unwrap().contains(&b));for n in 0..b.len(){assert_eq!(decode_with_features(&b[..n],Some(profile(%q).unwrap())).unwrap_err(),Error::Truncated);}", row.CPU+"+extension", row.CPU+"+extension")
		}
		test.WriteString("}\n")
	}
	test.WriteString("}\n")
	raw, err := os.ReadFile("testdata/gnu-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var boundaries []boundaryVector
	if err := json.Unmarshal(raw, &boundaries); err != nil {
		t.Fatal(err)
	}
	test.WriteString("#[test] fn independent_gnu_boundaries(){\n")
	for _, row := range boundaries {
		var e *codec.Encoding
		for j := range c.Encodings {
			if c.Encodings[j].ID == row.ID {
				e = &c.Encodings[j]
				break
			}
		}
		var values []string
		for _, o := range e.Operands {
			values = append(values, fmt.Sprint(row.Values[o.Name]))
		}
		b, _ := hex.DecodeString(row.Bytes)
		fmt.Fprintf(&test, "assert_eq!(encode(%q,&[%s]).unwrap(),%s);\n", row.ID, strings.Join(values, ","), rustBytes(b))
	}
	test.WriteString("}\n")
	code, _ := os.ReadFile("testdata/program.bin")
	fmt.Fprintf(&test, "#[test] fn actual_gnu_routine(){let code:Vec<u8>=vec!%v;let mut offset=0;let mut count=0;while offset<code.len(){let d=decode_with_features(&code[offset..],Some(profile(\"v850e3v5+extension\").unwrap())).unwrap();let e=d.encoding();let b=encode(e.id,&d.values[..e.operands.len()]).unwrap();assert_eq!(b,code[offset..offset+d.length]);assert!(assemble_at(&d.format(offset as u64),offset as u64).unwrap().contains(&b));if let Some(target)=d.branch_target(offset as u64){assert!(target<(code.len() as u64));}offset+=d.length;count+=1;}assert_eq!(count,14);}\n", code)
	test.WriteString(`#[test] fn syntax_templates_and_constraints(){
 let a=assemble("prepare {r22,r20,r21},4,r3").unwrap();
 assert_eq!(a,assemble("prepare {r20-r22},4,sp").unwrap());
 assert_eq!(assemble("dispose 4,{r20},lp").unwrap(),assemble("dispose 4,{r20},[lp]").unwrap());
 let template=Template::parse("prepare ${list},${adjust},sp").unwrap();
 let b=template.encode(&[("list",7),("adjust",4)]).unwrap();
 assert_eq!(b,a);let (_,holes)=template.matches(&b[0]).unwrap();assert!(holes.contains(&("list".into(),7)));
 for bad in ["prepare {r19},4,sp","prepare {r20,r20},4,sp","divn 2,r1,r2,r3","bins r1,4,0,r2","bins r1,31,2,r2","ld.dw 4[r4],r3"]{assert!(assemble(bad).is_err(),"{}",bad);}
 for position in 0..32 {for width in 1..=32-position{let b=assemble(&format!("bins r1,{},{},r2",position,width)).unwrap();assert_eq!(b.len(),1);let d=decode(&b[0]).unwrap();assert_eq!(d.operand("op1"),Some(position));assert_eq!(d.operand("op2"),Some(width));}}
 let b=assemble_at("br 0x2",0xfffffffe).unwrap();let d=decode(&b[0]).unwrap();assert_eq!(d.branch_target(0xfffffffe),Some(2));assert_eq!(d.operand("op0"),Some(4));
 assert_eq!(decode(&assemble("dbhvtrap").unwrap()[0]).unwrap().encoding().flow_control,"trap");
 assert!(assemble_with_features("prepare {r20},4,sp",0,Some(profile("v850").unwrap())).is_err());
 assert!(assemble_with_features("prepare {r20},4,sp",0,Some(profile("v850e").unwrap())).is_ok());
}
`)
	// Go's byte-slice formatting is whitespace separated; Rust requires commas.
	source := test.String()
	for _, row := range retainedVectors(t, "gnu-vectors.json") {
		b, _ := hex.DecodeString(row.Bytes)
		source = strings.ReplaceAll(source, fmt.Sprintf("vec!%v", b), rustBytes(b))
	}
	source = strings.ReplaceAll(source, fmt.Sprintf("vec!%v", code), rustBytes(code))
	if err := os.WriteFile(filepath.Join(dir, "tests/behavior.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--test", "behavior")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if artifact := os.Getenv("MKASM_V850_ARTIFACT_DIR"); artifact != "" {
		os.WriteFile(filepath.Join(artifact, "rust-validation.log"), out, 0644)
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Log(string(out))
}

func rustBytes(data []byte) string {
	parts := make([]string, len(data))
	for j, b := range data {
		parts[j] = fmt.Sprint(b)
	}
	return "vec![" + strings.Join(parts, ",") + "]"
}
