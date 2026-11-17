package msp430

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedRustSymbolicTargets(t *testing.T) {
	if os.Getenv("MKASM_MSP430_RUST") == "" {
		t.Skip("set MKASM_MSP430_RUST=1")
	}
	artifact := os.Getenv("MKASM_MSP430_ARTIFACT")
	if artifact == "" {
		artifact = t.TempDir()
	}
	for _, arch := range []string{"msp430", "msp430x"} {
		t.Run(arch, func(t *testing.T) {
			c := load(t, arch)
			out := filepath.Join(artifact, arch)
			if err := c.GenerateRust(out); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
				t.Fatal(err)
			}
			consumer := strings.ReplaceAll(symbolicRustConsumer, "CRATE", arch)
			if arch == "msp430x" {
				consumer += extendedSymbolicRustConsumer
			}
			if err := os.WriteFile(filepath.Join(out, "tests", "symbolic_targets.rs"), []byte(consumer), 0644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(out, "Cargo.toml"), "--lib", "--test", "symbolic_targets")
			var log bytes.Buffer
			cmd.Stdout = &log
			cmd.Stderr = &log
			err := cmd.Run()
			if writeErr := os.WriteFile(filepath.Join(out, "symbolic-targets.log"), log.Bytes(), 0644); writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil {
				t.Fatalf("generated consumer: %v\n%s", err, log.Bytes())
			}
			t.Logf("%s", log.Bytes())
		})
	}
}

const symbolicRustConsumer = `use CRATE::*;
#[test]
fn control_flow_targets_exclude_data_and_indirect_calls(){
 for raw in [&[0x14,0x40,2,0][..],&[0x90,0x50,2,0,0,0],&[0x90,0x12,2,0],&[0x92,0x12,2,0],&[0x84,0x12]] {
  assert_eq!(decode(raw).unwrap().branch_target(0x1000),None);
 }
 assert_eq!(decode(&[0xb0,0x12,2,0]).unwrap().branch_target(0x1000),Some(2));
 assert_eq!(decode(&[0xb0,0x12,0xfe,0xff]).unwrap().branch_target(0x1000),Some(0xfffe));
 assert_eq!(decode(&[0xb0,0x12,0xff,0xff]).unwrap().branch_target(0x1000),Some(0xfffe));
 for(raw,target)in [([0x83,0x12],0),([0x93,0x12],0),([0xa3,0x12],2),([0xa2,0x12],4),([0xb2,0x12],8),([0xb3,0x12],0xfffe)] {assert_eq!(decode(&raw).unwrap().branch_target(0x1000),Some(target));}
 assert_eq!(decode(&[0,0x3c]).unwrap().branch_target(0x1000),Some(0x1002));
 let d=decode(&[0x14,0x40,2,0]).unwrap();let moved=d.relocated(0x1000,0x1002).unwrap();
 assert_eq!(moved.format(0x1002),d.format(0x1000));
}
#[test]
fn unsigned_symbolic_targets_are_addresses(){
 let raw=[0x90,0x50,0x00,0x80,0xfe,0x7f];
 for address in [0,0x1000,0x7ffe,0x8000,0xfffc,0xfffe]{
  let d=decode(&raw).unwrap();let text=d.format(address);
  if address==0x1000{assert_eq!(text,"add 0x9002, 0x9002");}
  let all=assemble_at(&text,address).unwrap_or_else(|e|panic!("{} at {:x}: {:?}",text,address,e));
  assert!(all.iter().any(|b|b.as_slice()==raw),"{} at {:x}: {:x?}",text,address,all);
  let template=Template::parse_at(&text,address).unwrap();assert!(template.matches(&raw).is_some());
  assert!(template.encode(&[]).unwrap().iter().any(|b|b.as_slice()==raw));
 }
 assert!(assemble_at("rla 0x9002",0x1000).unwrap().iter().any(|b|b.as_slice()==raw));
 // Signed-immediate lexical aliases still normalize independently of targets.
 assert!(assemble("mov #65535,r4").unwrap().iter().any(|b|b.as_slice()==[0x34,0x40,0xff,0xff]));
}
`
const extendedSymbolicRustConsumer = `
#[test]
fn calla_targets_distinguish_immediates_and_memory(){
 assert_eq!(decode(&[0xba,0x13,0xde,0xbc]).unwrap().branch_target(0x1000),Some(0xabcde));
 for raw in [&[0x8a,0x13,0xde,0xbc][..],&[0x90,0x13,2,0]] {assert_eq!(decode(raw).unwrap().branch_target(0x1000),None);}
}
#[test]
fn twenty_bit_symbolic_targets_keep_high_half(){
 for(text,raw)in [("movx.a 0xf0000,r4",&[0x00,0x18,0x54,0x40,0xfc,0xff][..]),("addx.a 0xf0000,0xf0002",&[0x00,0x18,0xd0,0x50,0xfc,0xff,0xfc,0xff])]{
  assert!(assemble_at(text,0xe0000).unwrap().iter().any(|b|b.as_slice()==raw));
  let d=decode(raw).unwrap();let formatted=d.format(0xe0000);
  assert!(assemble_at(&formatted,0xe0000).unwrap().iter().any(|b|b.as_slice()==raw));
  let template=Template::parse_at(&formatted,0xe0000).unwrap();assert!(template.matches(raw).is_some());
 }
}
`
