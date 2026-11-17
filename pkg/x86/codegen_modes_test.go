package x86

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRustExecutionModes(t *testing.T) {
	f, err := os.Open("testdata/opcodesdb-mode-fixture.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	catalog, err := ParseOpcodesDB(z)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "x86-modes")
	if err := GenerateRust(catalog, output); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip(err)
	}
	arguments := []string{"test", "--lib", "--examples", "--quiet"}
	if writeLLVMModeOracle(t, output) {
		arguments = append(arguments, "--test", "llvm_modes")
	}
	command := exec.Command("cargo", arguments...)
	command.Dir = output
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if b, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated mode-aware crate failed: %v\n%s", err, b)
	}
}

func TestGeneratedCrateDefaultExecutionModes(t *testing.T) {
	f, err := os.Open("testdata/opcodesdb-mode-fixture.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	catalog, err := ParseOpcodesDB(z)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, mode := range []Mode{Mode16, Mode32} {
		name := fmt.Sprintf("x86_%d", mode)
		output := filepath.Join(dir, name)
		if err := GenerateRustForMode(catalog, output, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
			t.Fatal(err)
		}
		register := "eax"
		if mode == Mode16 {
			register = "ax"
		}
		source := fmt.Sprintf(`use %s::*;
#[test] fn selected_defaults_are_public_behavior() {
assert_eq!(DEFAULT_MODE,Mode::Mode%d);
assert_eq!(EncodeFields::default().mode,DEFAULT_MODE);
let text="inc %s";let expected=&[0x40];
assert!(assemble(text).unwrap().iter().any(|e|e.bytes()==expected));
assert!(assemble_at(text,0x1000).unwrap().iter().any(|e|e.bytes()==expected));
let t=Template::parse(text).unwrap();assert_eq!(t.mode(),DEFAULT_MODE);assert_eq!(t.matches(expected,&mut Vec::new()),Some(1));
assert_eq!(Template::parse_at(text,0x1000).unwrap().matches(expected,&mut Vec::new()),Some(1));
assert_eq!(describe(expected).unwrap().text,text);
assert!(assemble("mov rax, rbx").is_err());
assert!(assemble_in_mode("mov rax, rbx",Mode::Mode64).is_ok());
}
`, name, mode, register) + rustIPWrapRegression
		if err := os.WriteFile(filepath.Join(output, "tests", "default_mode.rs"), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[workspace]\nresolver=\"2\"\nmembers=[\"x86_16\",\"x86_32\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip(err)
	}
	command := exec.Command("cargo", "test", "--workspace", "--lib", "--examples", "--tests", "--quiet")
	command.Dir = dir
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if b, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated default mode crates: %v\n%s", err, b)
	}
	if err := GenerateRustForMode(catalog, filepath.Join(dir, "invalid"), Mode(7)); err == nil {
		t.Fatal("accepted invalid default execution mode")
	}
}

// Intel SDM Vol. 2A, JMP/CALL: effective operand size controls non-long-mode
// target truncation, including operand-size overrides. These exact bytes also
// exercise stream formatting, absolute assembly, templates and relocation.
const rustIPWrapRegression = `
#[test] fn instruction_pointer_wrapping() {
let cases:&[(Mode,&[u8],u64,u64)]=&[
 (Mode::Mode32,&[0xeb,0],0xffff_fffe,0),
 (Mode::Mode16,&[0xeb,0],0xfffe,0),
 (Mode::Mode32,&[0x66,0xe9,0,0],0x1fffc,0),
 (Mode::Mode16,&[0x66,0xe9,0,0,0,0],0xffff_fffa,0),
 (Mode::Mode32,&[0xeb,0xfc],0,0xffff_fffe),
 (Mode::Mode16,&[0xeb,0xfc],0,0xfffe),
];
for &(mode,bytes,address,target) in cases {
 let d=decode(bytes,mode).unwrap();assert_eq!(d.branch_target(address),Some(target));
 let text=d.format_intel(address);assert_eq!(text,format!("jmp 0x{target:x}"));
 let all=assemble_at_in_mode(&text,address,mode).unwrap();assert!(all.iter().any(|v|v.bytes()==bytes),"{mode:?} {address:x}: {text}");
 let t=Template::parse_at_in_mode(&text,address,mode).unwrap();assert_eq!(t.matches(bytes,&mut Vec::new()),Some(bytes.len()));
 let mut relocated=[0u8;15];let new_address=if mode==Mode::Mode16{0xfff0}else{0xffff_fff0};
 let n=relocate(&d,bytes,address,new_address,&mut relocated).unwrap();assert_eq!(decode(&relocated[..n],mode).unwrap().branch_target(new_address),Some(target));
}
for (mode,bits,length) in [(Mode::Mode16,16,3usize),(Mode::Mode32,32,5usize)] {
 let mut out=[0u8;15];let mask=(1u64<<bits)-1;let address=mask-length as u64+1;
 let n=encode_relative_branch_in_mode(RelativeBranchKind::Call,address,0,mode,&mut out).unwrap();assert_eq!(n,length);assert_eq!(out[0],0xe8);assert!(out[1..n].iter().all(|&b|b==0));assert_eq!(decode(&out[..n],mode).unwrap().branch_target(address),Some(0));
 assert!(encode_relative_branch_in_mode(RelativeBranchKind::Jump,0,mask+1,mode,&mut out).is_err());
}
let mut out=[0u8;15];let n=encode_relative_branch(RelativeBranchKind::Call,0,3,&mut out).unwrap();
assert_eq!(n,if DEFAULT_MODE==Mode::Mode16{3}else{5});assert_eq!(decode(&out[..n],DEFAULT_MODE).unwrap().branch_target(0),Some(3));
assert!(assemble_at_in_mode("jmp 0x100000000",0,Mode::Mode32).is_err());
}
`

func TestEncodeRejectsUnavailableRegistersOutsideLongMode(t *testing.T) {
	for _, mode := range []Mode{Mode16, Mode32} {
		e := &codecCatalog().Encodings[4]
		for _, fields := range []EncodeFields{{Mode: mode, Mod: 3, Reg: 8}, {Mode: mode, Mod: 3, RM: 8}, {Mode: mode, Mod: 3, VVVV: 8}, {Mode: mode, Mod: 3, OpcodeReg: 8}} {
			if _, err := Encode(make([]byte, 15), e, fields); err != ErrInvalidEncodeField {
				t.Fatalf("mode %v accepted unavailable high register %+v: %v", mode, fields, err)
			}
		}
	}
}

// The independent assembler supplies these expected bytes at test time. The
// generated crate also checks every imported form through text, matching,
// describe spans, hole domains and relocation tests.
func writeLLVMModeOracle(t *testing.T, output string) bool {
	t.Helper()
	configured := os.Getenv("LLVM_MC")
	if configured == "" {
		configured = "llvm-mc"
	}
	llvm, err := exec.LookPath(configured)
	if err != nil && os.Getenv("LLVM_MC") == "" {
		llvm, err = exec.LookPath("/opt/homebrew/opt/llvm/bin/llvm-mc")
	}
	if err != nil {
		if os.Getenv("MKASM_REFERENCE_STRICT") == "1" {
			t.Skip("required LLVM execution-mode reference unavailable: ", err)
		}
		t.Log("llvm-mc unavailable: independent execution-mode oracle skipped")
		return false
	}
	cases := []struct {
		mode       int
		text, llvm string
	}{
		{16, "xchg ax, ax", ""}, {16, "xchg eax, eax", ""},
		{32, "xchg ax, ax", ""}, {32, "xchg eax, eax", ""},
		{64, "xchg ax, ax", ""}, {64, "xchg eax, eax", ""}, {64, "xchg rax, rax", ""},
		{32, "mov eax, dword ptr [ebx+ecx*4+0x10]", ""},
		{32, "mov ax, word ptr [eax]", ""},
		{32, "mov ecx, dword ptr [0xf0000000]", ""},
		{32, "mov eax, dword ptr [0xf0000000]", ""},
		{16, "mov cx, word ptr [0xf000]", ""},
		{32, "bound eax, qword ptr [eax]", "bound eax, [eax]"},
		{32, "mov eax, dword ptr [bx+si]", ""},
		{32, "mov eax, dword ptr [bp]", ""},
		{16, "mov ax, word ptr [bx+si]", ""},
		{16, "mov eax, dword ptr [ebx]", ""},
		{32, "inc eax", ""}, {32, "dec eax", ""},
		{32, "lds eax, fword ptr [eax]", ""}, {32, "les eax, fword ptr [eax]", ""},
		{32, "mov ah, bl", ""}, {32, "push eax", ""},
		{32, "vPaddd xmm1, xmm2, xmm3", ""},
		{32, "jmp .+16", "jmp .Ltarget\n.fill 14,1,0x90\n.Ltarget:"},
		{32, "call .+16", "call .Ltarget\n.fill 11,1,0x90\n.Ltarget:"},
	}
	var source strings.Builder
	source.WriteString("use x86_64::*;\n#[test] fn llvm_execution_mode_bytes(){\n")
	for _, c := range cases {
		asm := c.llvm
		if asm == "" {
			asm = c.text
		}
		triple := "i386"
		if c.mode == 64 {
			triple = "x86_64"
		}
		command := exec.Command(llvm, "-triple="+triple, "-filetype=obj")
		command.Stdin = strings.NewReader(fmt.Sprintf(".intel_syntax noprefix\n.code%d\n%s\n", c.mode, asm))
		var stderr bytes.Buffer
		command.Stderr = &stderr
		object, err := command.Output()
		if err != nil {
			t.Fatalf("LLVM %s: %v: %s", c.text, err, stderr.String())
		}
		file, err := elf.NewFile(bytes.NewReader(object))
		if err != nil {
			t.Fatal(err)
		}
		code, err := file.Section(".text").Data()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(c.text, "jmp .") {
			code = code[:2]
		}
		if strings.HasPrefix(c.text, "call .") {
			code = code[:5]
		}
		fmt.Fprintf(&source, "{let expected:&[u8]=&%s;let text=%q;let mode=Mode::Mode%d;let encoded=assemble_in_mode(text,mode).unwrap();assert!(encoded.iter().any(|e|e.bytes()==expected),\"{text}: {encoded:?} expected {expected:?}\");let template=Template::parse_in_mode(text,mode).unwrap();assert_eq!(template.matches(expected,&mut Vec::new()),Some(expected.len()));}\n", rustBytes(code), c.text, c.mode)
	}
	source.WriteString(rustSelfXchgRegression)
	source.WriteString("}\n")
	if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "tests", "llvm_modes.rs"), []byte(source.String()), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("LLVM MC independently emitted %d execution-mode vectors for the generated Rust consumer", len(cases))
	return true
}
func rustBytes(code []byte) string {
	parts := make([]string, len(code))
	for i, b := range code {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

const rustSelfXchgRegression = `
for (mode,width,original) in [
    (Mode::Mode16,16,vec![0x87,0xc0]),(Mode::Mode16,32,vec![0x66,0x87,0xc0]),
    (Mode::Mode32,16,vec![0x66,0x87,0xc0]),(Mode::Mode32,32,vec![0x87,0xc0]),
    (Mode::Mode64,16,vec![0x66,0x87,0xc0]),(Mode::Mode64,32,vec![0x87,0xc0]),(Mode::Mode64,64,vec![0x48,0x87,0xc0]),
] {
    let name=match width {16=>"ax",32=>"eax",_=>"rax"};
    let text=format!("xchg {name}, {name}");
    let encoded=assemble_in_mode(&text,mode).unwrap();
    assert!(encoded.iter().any(|e|e.bytes()==original),"{mode:?} {text}: original form lost: {encoded:?}");
    if mode==Mode::Mode64 && width==32 {assert!(encoded.iter().all(|e|e.bytes()!=[0x90]),"32-bit XCHG must clear upper bits in long mode");}
    let pattern=Template::parse_in_mode(&format!("xchg $r:gpr{width}, $r:gpr{width}"),mode).unwrap();
    for e in encoded {
        let mut values=Vec::new();
        assert_eq!(pattern.matches(e.bytes(),&mut values),Some(e.len()),"{text}: {e:?}");
        assert_eq!(values.len(),1);
        assert_eq!(values[0].value,0);
        assert!(pattern.encode(&values).unwrap().iter().any(|result|result.bytes()==e.bytes()));
    }
}
`
