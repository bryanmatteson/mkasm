package ptx

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompilerModules(t *testing.T) {
	for _, name := range []string{"clang-sm80.ptx", "clang-sm90-debug.ptx"} {
		b, e := os.ReadFile(filepath.Join("testdata", name))
		if e != nil {
			t.Fatal(e)
		}
		m, e := Decode(string(b))
		if e != nil {
			t.Fatal(name, e)
		}
		if m.Encode() != string(b) || len(m.Instructions) < 20 {
			t.Fatal("module roundtrip")
		}
		v := Default().Check(m, Profile{})
		if e = v.Error(); e != nil {
			t.Fatal(name, e)
		}
		var out bytes.Buffer
		m.Write(&out)
		if !bytes.Equal(b, out.Bytes()) {
			t.Fatal("lossless")
		}
	}
}
func TestFullSourceRegistry(t *testing.T) {
	c := Default()
	if len(c.Documents) != 295 || len(c.LLVM) != 6629 {
		t.Fatal("source corpus truncated")
	}
	nonempty := 0
	for _, r := range c.LLVM {
		if r.Syntax == "" {
			continue
		}
		nonempty++
		if _, e := c.Template(r.ID); e != nil {
			t.Fatal(r.ID, e)
		}
	}
	if nonempty != 6321 {
		t.Fatal("LLVM syntax count")
	}
	for _, d := range c.Documents {
		if len(d.Names) == 0 || len(d.Syntax) == 0 || d.ID == "" {
			t.Fatal("lost source document")
		}
	}
	var b bytes.Buffer
	if e := c.WriteJSON(&b); e != nil {
		t.Fatal(e)
	}
	back, e := Parse(&b, "nvptx")
	if e != nil || len(back.LLVM) != 6629 {
		t.Fatal(e)
	}
}
func TestOperandsAndTemplates(t *testing.T) {
	src := ".version 8.8\n.target sm_90\n.address_size 64\n.visible .entry k(){\n.reg .pred %p;\nL: @!%p cp.async.bulk.tensor.2d.shared::cluster.global.mbarrier::complete_tx::bytes [%r], [%rd, {%r1,%r2}], [%b];\nmov.b64 {%r1,%r2}, %rd;\ncall.uni (%r), fn, (%r1,%r2);\nret;\n}\n"
	m, e := Decode(src)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Instructions) != 4 || m.Instructions[0].Predicate != "%p" || !m.Instructions[0].Negated {
		t.Fatalf("structured %+v", m.Instructions)
	}
	if m.Instructions[0].Operands[0].Kind != "address" || m.Instructions[1].Operands[0].Kind != "vector" {
		t.Fatal("operands")
	}
	changed, e := m.ReplaceOperand(1, 1, "%new")
	if e != nil || !strings.Contains(changed.Source, "mov.b64 {%r1,%r2}, %new;") {
		t.Fatal(e)
	}
	tpl, e := CompileTemplate("add${mode}.u32 $dst, ${src:foo}, $$symbol;")
	if e != nil {
		t.Fatal(e)
	}
	filled, e := tpl.Fill(map[string]string{"mode": ".sat", "dst": "%r1", "src:foo": "%r2"})
	if e != nil || filled != "add.sat.u32 %r1, %r2, $symbol;" {
		t.Fatal(filled, e)
	}
}
func TestMalformed(t *testing.T) {
	for _, s := range []string{"mov.u32 %r, 1", "{ret;", ".version 9.5\n@!;", "ld.u32 %r, [%a);", ".file 1 \"unterminated", "/* open", "ret;}", "mov.b32 %r, ,;"} {
		if _, e := Decode(s); e == nil {
			t.Fatal("accepted", s)
		}
	}
	m, e := Decode(".version 9.9\n.target sm_999\n.address_size 16\n.entry k(){invented.op;}")
	if e != nil {
		t.Fatal(e)
	}
	if Default().Check(m, Profile{}).Error() == nil {
		t.Fatal("invalid profile")
	}
}

func TestGeneratedRust(t *testing.T) {
	out := t.TempDir()
	if e := Default().GenerateRust(out); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(out, "Cargo.toml"), "--test", "public")
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("generated Rust %v\n%s", e, b)
	}
}

func TestAllNVIDIASyntaxAndExamplesLexLosslessly(t *testing.T) {
	examples, syntax := 0, 0
	for _, d := range Default().Documents {
		for group, blocks := range map[string][]string{"syntax": d.Syntax, "example": d.Examples} {
			for _, text := range blocks {
				tokens, e := Lex(text)
				if e != nil {
					t.Fatalf("%s %s: %v", d.ID, group, e)
				}
				var b strings.Builder
				for _, token := range tokens {
					b.WriteString(token.Text)
				}
				if b.String() != text {
					t.Fatal("source tokenization lost bytes")
				}
				if group == "example" {
					examples++
				} else {
					syntax++
				}
			}
		}
	}
	if examples != 286 || syntax < 295 {
		t.Fatal(examples, syntax)
	}
}
func TestProfilesAndViews(t *testing.T) {
	m, e := Decode(".version 1.0\n.target sm_10\n.entry k(){ret;}")
	if e != nil || m.AddressSize != 32 {
		t.Fatal("default address size", e)
	}
	if e = Default().Check(m, Profile{}).Error(); e != nil {
		t.Fatal(e)
	}
	old, e := Decode(".version 1.0\n.target sm_90\n.entry k(){ret;}")
	if e != nil || Default().Check(old, Profile{}).Error() == nil {
		t.Fatal("target version unchecked")
	}
	for _, n := range []string{"clang-sm80.ptx", "clang-sm90-debug.ptx"} {
		b, _ := os.ReadFile(filepath.Join("testdata", n))
		m, e := Decode(string(b))
		if e != nil {
			t.Fatal(e)
		}
		if len(m.Functions()) != 3 || len(m.Declarations()) == 0 || len(m.ControlFlow()) == 0 {
			t.Fatal("module views")
		}
		if e = Default().Check(m, Profile{Target: "sm_70"}).Error(); e == nil {
			t.Fatal("target profile unchecked")
		}
	}
}
func FuzzDecode(f *testing.F) {
	for _, s := range []string{".version 8.8\n.target sm_80\n.entry k(){ret;}", "@!%p add.u32 %r, [%x], {%a,%b};"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if m, e := Decode(s); e == nil && m.Encode() != s {
			t.Fatal("lossless codec")
		}
	})
}

func TestPTX95(t *testing.T) {
	b, e := os.ReadFile("testdata/ptx95.ptx")
	if e != nil {
		t.Fatal(e)
	}
	m, e := Decode(string(b))
	if e != nil {
		t.Fatal(e)
	}
	if m.Version != "9.5" || len(m.Instructions) != 7 || len(m.Functions()) != 1 {
		t.Fatal("PTX9.5 module framing")
	}
	if e = Default().Check(m, Profile{}).Error(); e != nil {
		t.Fatal(e)
	}
	if m.Encode() != string(b) {
		t.Fatal("PTX9.5 roundtrip")
	}
}

func TestModuleTemplate(t *testing.T) {
	tpl, e := CompileModuleTemplate(".version 8.8\n.target sm_80\n.entry {{name}}(){ $L: mov.u32 %r, {{value}};ret;}")
	if e != nil {
		t.Fatal(e)
	}
	s, e := tpl.Fill(map[string]string{"name": "kernel", "value": "123"})
	if e != nil || !strings.Contains(s, "$L:") {
		t.Fatal(e)
	}
	if _, e = Default().Assemble(s, Profile{}); e != nil {
		t.Fatal(e)
	}
}
