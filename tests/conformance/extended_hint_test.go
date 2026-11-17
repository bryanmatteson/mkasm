package conformance_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Check the entire HINTE operand domain using LLVM's independent generic
// system-register encoder. The native input is derived from the architectural
// immediate, without consulting mkasm's encoded word or imported bit layout.
func verifyExtendedHintSpace(t *testing.T, dir, language string) {
	t.Helper()
	mc := findLLVMMC(t)
	if mc == "" {
		t.Fatal("LLVM MC is required for HINTE reference coverage")
	}
	var source strings.Builder
	var immediates []int
	for imm := 0; imm < 65536; imm++ {
		text, valid := extendedHintSystemSyntax(fmt.Sprintf("HINTE #%d", imm))
		if valid {
			fmt.Fprintln(&source, text)
			immediates = append(immediates, imm)
		}
	}
	cmd := exec.Command(mc, "-triple=aarch64", "-show-encoding")
	cmd.Stdin = strings.NewReader(source.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native HINTE field-space reference: %v\n%.2000s", err, out)
	}
	matches := llvmMCEncodingRE.FindAllSubmatch(out, -1)
	if len(matches) != 65408 || len(immediates) != len(matches) {
		t.Fatalf("incomplete native HINTE domain: %d encodings, %d immediates", len(matches), len(immediates))
	}
	var vectors strings.Builder
	for n, match := range matches {
		var word uint64
		for b := 0; b < 4; b++ {
			value, err := strconv.ParseUint(string(match[b+1]), 0, 8)
			if err != nil {
				t.Fatal(err)
			}
			word |= value << uint(b*8)
		}
		fmt.Fprintf(&vectors, "%d %08x\n", immediates[n], word)
	}
	var testPath string
	var testSource string
	if language == "go" {
		module, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		testPath = filepath.Join(dir, "conformance", "extended_hint_reference_test.go")
		testSource = fmt.Sprintf(`package conformance
import("os";"strconv";"strings";"testing";encoders %q)
func TestExtendedHintReference(t *testing.T){
 data,err:=os.ReadFile("hinte-reference.tsv");if err!=nil{t.Fatal(err)}
 count:=0
 for _,line:=range strings.Split(strings.TrimSpace(string(data)),"\n"){
  parts:=strings.Fields(line);imm,_:=strconv.ParseUint(parts[0],10,16);want,_:=strconv.ParseUint(parts[1],16,32)
  got,err:=encoders.EncodeWithFields("HINTE_extendedhint",map[string]uint64{"L":imm>>15,"imm3":imm>>12&7,"imm7":imm>>5&127,"Rt":imm&31})
  if err!=nil||uint64(got)!=want{t.Fatalf("HINTE %%d: %%08x != %%08x: %%v",imm,got,want,err)};count++
 }
 if count!=65408{t.Fatal(count)}
 for imm:=uint64(12319);imm<=16383;imm+=32{
  if _,err:=encoders.EncodeWithFields("HINTE_extendedhint",map[string]uint64{"L":0,"imm3":3,"imm7":imm>>5&127,"Rt":31});err==nil{t.Fatalf("reserved HINTE %%d accepted",imm)}
 }
}
`, strings.Fields(string(module))[1]+"/encoders")
		cmd = exec.Command("go", "test", "./conformance", "-run", "^TestExtendedHintReference$", "-count=1")
	} else {
		testPath = filepath.Join(dir, "tests", "extended_hint_reference.rs")
		testSource = `use aarch64::encode_with_fields;
#[test]fn extended_hint_reference(){
 let mut count=0;
 for line in include_str!("hinte-reference.tsv").lines(){
  let p:Vec<_>=line.split_whitespace().collect();let imm:u64=p[0].parse().unwrap();let want=u32::from_str_radix(p[1],16).unwrap();
  let got=encode_with_fields("HINTE_extendedhint",&[("L",imm>>15),("imm3",imm>>12&7),("imm7",imm>>5&127),("Rt",imm&31)]).unwrap();
  assert_eq!(got,want,"HINTE {}",imm);count+=1;
 }
 assert_eq!(count,65408);
 for imm in (12319u64..=16383).step_by(32){assert!(encode_with_fields("HINTE_extendedhint",&[("L",0),("imm3",3),("imm7",imm>>5&127),("Rt",31)]).is_err(),"reserved HINTE {}",imm);}
}
`
		cmd = exec.Command("cargo", "test", "--quiet", "--test", "extended_hint_reference")
	}
	if err := os.WriteFile(testPath, []byte(testSource), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(testPath), "hinte-reference.tsv"), []byte(vectors.String()), 0644); err != nil {
		t.Fatal(err)
	}
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated %s HINTE reference consumer: %v\n%s", language, err, out)
	}
	t.Logf("%s HINTE: 65408 live LLVM generic-system encodings matched; all 128 reserved operands rejected", language)
}
