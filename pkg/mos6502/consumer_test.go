package mos6502

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetainedReferenceVectors(t *testing.T) {
	c := load(t)
	var rows []vector
	if err := json.Unmarshal(referenceVectors, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 361 {
		t.Fatal(len(rows))
	}
	exact, alternatives, reserved := 0, 0, 0
	for j, row := range rows {
		e := &c.Encodings[j]
		b, err := c.Encode(e.ID, sample(e))
		want, errHex := hex.DecodeString(row.Bytes)
		if row.ID != e.ID || err != nil || errHex != nil || !bytes.Equal(b, want) {
			t.Fatal(row.ID, err, errHex)
		}
		if row.Status == "reserved-nop" {
			reserved++
			continue
		}
		actual, err := hex.DecodeString(row.Actual)
		if err != nil {
			t.Fatal(row.ID, err)
		}
		if bytes.Equal(actual, want) {
			exact++
		} else {
			alternatives++
			if row.Status != "undocumented" {
				t.Fatal(row)
			}
		}
		forms, err := c.AssembleWithFeatures(row.DA65, 0x1000, c.FeatureSets[row.Profile])
		found := false
		for _, b := range forms {
			found = found || bytes.Equal(b, want)
		}
		if err != nil || !found {
			t.Fatal(row.ID, row.DA65, err)
		}
	}
	if exact != 282 || alternatives != 35 || reserved != 44 {
		t.Fatal(exact, alternatives, reserved)
	}
}

func TestRetainedGhidra(t *testing.T) {
	c := load(t)
	raw, err := os.ReadFile("testdata/ghidra-results.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		ID      string `json:"id"`
		Encoded string `json:"encoded"`
		Length  int    `json:"length"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 212 {
		t.Fatal(len(rows))
	}
	exact, mismatch, unsupported := 0, 0, 0
	for _, row := range rows {
		if row.Error != "" {
			unsupported++
			continue
		}
		var eIndex = -1
		for i, e := range c.Encodings {
			if e.ID == row.ID {
				eIndex = i
				break
			}
		}
		if eIndex < 0 {
			t.Fatal(row.ID)
		}
		e := &c.Encodings[eIndex]
		b, err := c.Encode(e.ID, sample(e))
		if err != nil {
			t.Fatal(err)
		}
		if row.ID == "brk_00_Signature" {
			if row.Encoded != "00" || row.Length != 1 {
				t.Fatal(row)
			}
			mismatch++
			continue
		}
		if row.Encoded != hex.EncodeToString(b) || row.Length != len(b) {
			t.Fatal(row.ID, "Ghidra mismatch", row)
		}
		exact++
	}
	if exact != 209 || mismatch != 1 || unsupported != 2 {
		t.Fatal(exact, mismatch, unsupported)
	}
}

func TestRealRoutine(t *testing.T) {
	c := load(t)
	code, err := os.ReadFile("testdata/program.bin")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	exits := 0
	flow := map[string]int{}
	for offset := 0; offset < len(code); {
		d, err := c.DecodeWithFeatures(code[offset:], c.FeatureSets["65sc02"])
		if err != nil {
			t.Fatal(offset, err)
		}
		b, err := c.Encode(d.Encoding.ID, d.Values)
		if err != nil || !bytes.Equal(b, code[offset:offset+d.Length]) {
			t.Fatal(offset, err)
		}
		text := d.Format(uint64(0x1000 + offset))
		forms, err := c.AssembleWithFeatures(text, uint64(0x1000+offset), c.FeatureSets["65sc02"])
		found := false
		for _, v := range forms {
			found = found || bytes.Equal(v, b)
		}
		if err != nil || !found {
			t.Fatal(text, err)
		}
		if target, ok := d.BranchTarget(uint64(0x1000 + offset)); ok {
			if target == 0xfff9 && strings.EqualFold(d.Encoding.Mnemonic, "jmp") {
				// sim65's exit service is an absolute jump outside this routine.
				exits++
			} else if target < 0x1000 || target >= 0x1000+uint64(len(code)) {
				t.Fatal("bad local target", target)
			}
		}
		t.Logf("%04x %-24s %x", 0x1000+offset, text, b)
		flow[d.Encoding.FlowControl]++
		offset += d.Length
		count++
	}
	if count != 29 || flow["call"] != 1 || flow["return"] != 1 {
		t.Fatal(count, flow)
	}
	if exits != 2 {
		t.Fatal("absolute sim65 exit targets", exits)
	}
	if bin := os.Getenv("MKASM_MOS6502_CC65"); bin != "" {
		dir := t.TempDir()
		obj := filepath.Join(dir, "program.o")
		binary := filepath.Join(dir, "program.bin")
		for _, cmd := range []*exec.Cmd{exec.Command(filepath.Join(bin, "ca65"), "-o", obj, "testdata/program.s"), exec.Command(filepath.Join(bin, "ld65"), "-C", "testdata/link.cfg", "-o", binary, obj)} {
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v %s", err, out)
			}
		}
		actual, err := os.ReadFile(binary)
		if err != nil || !bytes.Equal(actual, code) {
			t.Fatal("real routine bytes differ", err)
		}
		sim := filepath.Join(dir, "program.sim65")
		image := append([]byte{'s', 'i', 'm', '6', '5', 2, 1, 0, 0, 0x10, 0, 0x10}, actual...)
		if err := os.WriteFile(sim, image, 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(bin, "sim65"), "-v", sim)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "PVExit ($00)") {
			t.Fatalf("simulator %v %s", err, out)
		}
		t.Log(string(out))
	}
}

func TestGeneratedRust(t *testing.T) {
	if os.Getenv("MKASM_MOS6502_RUST") == "" {
		t.Skip("set MKASM_MOS6502_RUST=1 for standalone Cargo consumer")
	}
	c := load(t)
	dir := t.TempDir()
	if p := os.Getenv("MKASM_MOS6502_ARTIFACT_DIR"); p != "" {
		dir = filepath.Join(p, "rust")
	}
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "tests"), 0755)
	source := fmt.Sprintf(`use mos6502::*;
#[test] fn external_consumer(){
 assert_eq!(encoding_count(),361);
 let code=&%s;let mut offset=0;let mut count=0;
 while offset<code.len(){let d=decode_with_features(&code[offset..],Some(profile("65sc02").unwrap())).unwrap();let e=d.encoding();assert_eq!(encode(e.id,&d.values[..e.operands.len()]).unwrap(),code[offset..offset+d.length]);offset+=d.length;count+=1;}assert_eq!(count,29);
 let t=Template::parse("lda #${value}").unwrap();let b=t.encode(&[("value",42)]).unwrap();assert_eq!(b,vec![vec![0xa9,42]]);assert!(t.matches(&b[0]).is_some());
}`, rustArray(referenceRoutine))
	if err := os.WriteFile(filepath.Join(dir, "tests/consumer.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--test", "consumer")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if p := os.Getenv("MKASM_MOS6502_ARTIFACT_DIR"); p != "" {
		os.WriteFile(filepath.Join(p, "rust-validation.log"), out, 0644)
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Log(string(out))
}
