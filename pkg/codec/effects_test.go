package codec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTableGenEffectFactsAndMissingMetadata(t *testing.T) {
	var record map[string]any
	if err := json.Unmarshal([]byte(`{"OutOperandList":{"args":[[{"def":"GPR"},"Rd"]]},"InOperandList":{"args":[[{"def":"GPR"},"Rn"],[{"def":"i32imm"},"imm"]]},"Defs":[{"def":"NZCV"}],"Uses":[{"def":"SP"}],"mayLoad":1,"mayStore":0,"hasSideEffects":0}`), &record); err != nil {
		t.Fatal(err)
	}
	facts := tableGenEffects(record)
	if len(facts.Registers) != 5 || facts.MayLoad == nil || !*facts.MayLoad || facts.MayStore == nil || *facts.MayStore || facts.MemoryKnowledge != EffectsPartial {
		t.Fatalf("lost source facts: %+v", facts)
	}
	unknown := tableGenEffects(map[string]any{})
	if unknown.MayLoad != nil || unknown.HasSideEffects != nil || unknown.MemoryKnowledge == EffectsComplete {
		t.Fatal("missing metadata claimed absence")
	}
}
func TestGeneratedRustEffects(t *testing.T) {
	c := exampleCatalog(t)
	c.Encodings[0].Effects = EffectSpec{Knowledge: EffectsPartial, RegistersKnowledge: EffectsComplete, Registers: []RegisterEffectSpec{{Operand: "Rd", Width: 32, Write: true, WriteBehavior: "zero_upper"}, {Name: "SP", Read: true, Implicit: true}}, Flags: []FlagEffectSpec{{Name: "C", Read: true, Action: "undefined", Conditional: true}}, Memory: []MemoryEffectSpec{{Read: true, Width: 64, Ordering: "acquire", Atomicity: "atomic", Writeback: "after"}}}
	d, err := c.Decode([]byte{0x82, 0})
	if err != nil {
		t.Fatal(err)
	}
	effects := d.Effects()
	if len(effects.Registers) != 2 || *effects.Registers[0].Number != 2 || effects.Registers[1].Number != nil {
		t.Fatalf("bad resolved effects: %+v", effects)
	}
	dir := t.TempDir()
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/effects.rs"), []byte(`use example::*;
#[test] fn retained_effects(){let d=decode(&[0x82,0]).unwrap();let e=d.effects();assert_eq!(e.knowledge,EffectKnowledge::Partial);assert_eq!(e.registers[0].register.number,Some(2));assert_eq!(e.registers[0].register.width,Some(32));assert_eq!(e.registers[0].write_behavior,WriteBehavior::ZeroUpper);assert!(e.registers[1].implicit);assert_eq!(e.flags[0].action,FlagAction::Undefined);assert!(e.flags[0].conditional);assert_eq!(e.memory[0].ordering,MemoryOrdering::Acquire);assert_eq!(e.memory[0].atomicity,Atomicity::Atomic);assert_eq!(e.memory[0].writeback,Writeback::After);let unknown=decode(&[0x90]).unwrap().effects();assert_eq!(unknown.knowledge,EffectKnowledge::Unknown);assert!(unknown.flags.is_empty());}
`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "effects", "--quiet")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated effects: %v\n%s", err, output)
	}
}
