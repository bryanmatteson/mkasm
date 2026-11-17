package z80

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Install this public consumer alongside the CLI-generated corpus so the root
// validation compiles it in the same Cargo batch, without duplicate builds.
func TestWriteVariantRustConsumers(t *testing.T) {
	root := os.Getenv("MKASM_Z80_VARIANT_RUST_DIR")
	if root == "" {
		t.Skip("set MKASM_Z80_VARIANT_RUST_DIR to generated target directories")
	}
	for _, arch := range []string{"ez80", "ez80-adl", "z80n", "r800"} {
		dir := filepath.Join(root, arch, "tests")
		if e := os.MkdirAll(dir, 0755); e != nil {
			t.Fatal(e)
		}
		source := `use CRATE::*;
#[test]fn conventional_negative_index_operands(){
 for (reg,prefix) in [("ix",0xdd),("iy",0xfd)]{
  let text=format!("ld a,({reg}-5)");let expected=vec![prefix,0x7e,0xfb];
  assert!(assemble_at(&text,0x1000).unwrap().contains(&expected));
  let mut assembler=Assembler::new();let mut output=[0u8;16];let n=assembler.assemble_into(&text,0x1000,&mut output).unwrap();
  assert!(assemble_at(&text,0x1000).unwrap().contains(&output[..n].to_vec()));
 }
}
`
		source = strings.ReplaceAll(source, "CRATE", strings.ReplaceAll(arch, "-", "_"))
		if e := os.WriteFile(filepath.Join(dir, "variant_inputs.rs"), []byte(source), 0644); e != nil {
			t.Fatal(e)
		}
	}
}
