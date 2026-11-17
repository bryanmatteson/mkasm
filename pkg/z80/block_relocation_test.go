package z80

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedPrefixBlockRelocation(t *testing.T) {
	for _, arch := range []string{"z80", "z180"} {
		t.Run(arch, func(t *testing.T) {
			c, err := Parse(nil, arch)
			if err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			if err := c.GenerateRust(out); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
				t.Fatal(err)
			}
			consumer := "use " + arch + "::*;\n" + rustPrefixBlockConsumer
			if err := os.WriteFile(filepath.Join(out, "tests", "prefix_relocation.rs"), []byte(consumer), 0644); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("cargo", "test", "--lib", "--test", "prefix_relocation", "--quiet")
			command.Dir = out
			command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
			if b, err := command.CombinedOutput(); err != nil {
				t.Fatalf("generated prefix block relocation: %v\n%s", err, b)
			}
		})
	}
}

const rustPrefixBlockConsumer = `
#[test]fn canonical_body_api_is_explicit_and_callable(){
 let b=relocate_body_block(&[0x18,0],0x1000,0x1002).unwrap();assert_eq!(b.bytes,[0x18,0xfe]);
 let mut out=[0xcc;4];assert_eq!(relocate_body_block_into(&[0x18,0],0x1000,0x1002,&mut out).unwrap(),2);assert_eq!(out,[0x18,0xfe,0xcc,0xcc]);
}
#[test]fn plain_and_prefixed_internal_targets_remap(){
 let b=relocate_block(&[0xc3,3,0x10,0],0x1000,0x2000).unwrap();assert_eq!(b.bytes,[0xc3,3,0x20,0]);assert_eq!(b.offsets,[(0,0),(3,3)]);
 if ARCHITECTURE!="z80"{return;}
 let source=[0xdd,0xfd,0x18,1,0,0xdd,0x18,0xf8];let b=relocate_block(&source,0xffff,0x100).unwrap();assert_eq!(b.bytes,source);assert_eq!(b.offsets,[(0,0),(4,4),(5,5)]);
 assert_eq!(decode(&b.bytes).unwrap().branch_target(0x100),Some(0x105));assert_eq!(decode(&b.bytes[5..]).unwrap().branch_target(0x105),Some(0x100));
 let b=relocate_block(&[0xdd,0xc3,4,0x10,0],0x1000,0x2000).unwrap();assert_eq!(b.bytes,[0xdd,0xc3,4,0x20,0]);
}
#[test]fn prefixes_keep_external_destinations(){
 if ARCHITECTURE!="z80"{return;}
 let source=[0xdd,0xfd,0x18,0x10];let b=relocate_block(&source,0x1000,0x1002).unwrap();assert_eq!(b.bytes,[0xdd,0xfd,0x18,0x0e]);assert_eq!(decode(&b.bytes).unwrap().branch_target(0x1002),Some(0x1014));
 let source=[0xdd,0xfd,0xc3,0x34,0x12];let b=relocate_block(&source,0x1000,0x2000).unwrap();assert_eq!(b.bytes,source);
}
#[test]fn wrapped_addresses_and_call_next(){
 let b=relocate_block(&[0x18,0],0xffff,1).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(1),Some(1));
 assert_eq!(relocate_block(&[0xcd,3,0x10],0x1000,0x2000),Err(BlockRelocateError::PositionDiscovery));
 if ARCHITECTURE=="z80"{assert_eq!(relocate_block(&[0xdd,0xcd,4,0x10],0x1000,0x2000),Err(BlockRelocateError::PositionDiscovery));}
}
#[test]fn rejects_mid_instruction_and_prefix_interior_targets(){
 assert_eq!(relocate_block(&[0x18,1,1,0,0],0x1000,0x2000),Err(BlockRelocateError::MidInstructionTarget));
 if ARCHITECTURE=="z80"{assert_eq!(relocate_block(&[0x18,1,0xdd,0xfd,0],0x1000,0x2000),Err(BlockRelocateError::MidInstructionTarget));}
}
#[test]fn no_partial_output_and_profile_semantics(){
 let mut out=[0xcc;4];assert_eq!(relocate_block_into(&[0x18,0],0x1000,0x2000,&mut out),Err(BlockRelocateError::Encode(Error::Operand)));assert_eq!(out,[0xcc;4]);
 let mut short=[0xcc;1];assert_eq!(relocate_block_into(&[0x18,0],0x1000,0x1002,&mut short),Err(BlockRelocateError::Encode(Error::BufferTooSmall)));assert_eq!(short,[0xcc]);
 assert_eq!(relocate_block(&[0],u64::MAX,0),Err(BlockRelocateError::AddressOverflow));assert_eq!(relocate_block(&[0],0,u64::MAX),Err(BlockRelocateError::AddressOverflow));
 assert_eq!(relocate_block(&[0xdd,0xfd],0x1000,0x2000),Err(BlockRelocateError::Decode(Error::Truncated)));
 let mut train=vec![0xdd;65537];train.push(0);assert_eq!(relocate_block(&train,0x1000,0x2000),Err(BlockRelocateError::Unsupported));
 assert!(relocate_block_with_features(&[0],0x1000,0x2000,Some(&[])).is_err());
 if ARCHITECTURE=="z180"{assert_eq!(relocate_block(&[0xdd,0],0x1000,0x2000),Err(BlockRelocateError::Decode(Error::Unknown)));}
}
#[test]fn body_conditional_calls_and_absolute_wrap(){
 let b=relocate_body_block(&[0xc4,4,0x10,0,0],0x1000,0x2000).unwrap();assert_eq!(&b.bytes[..3],&[0xc4,4,0x20]);
 let b=relocate_body_block(&[0xc3,2,0,0],0xffff,0x1000).unwrap();assert_eq!(&b.bytes[..3],&[0xc3,3,0x10]);
 let b=relocate_body_block(&[0xc3,2,0,0],0xffff,0xfffe).unwrap();assert_eq!(&b.bytes[..3],&[0xc3,1,0]);
 for (old,target) in [(0x1000,0x1003),(0xffff,2)]{let mut out=[0xcc;8];assert_eq!(relocate_body_block_into(&[0xc4,target as u8,(target>>8) as u8],old,0x2000,&mut out),Err(BlockRelocateError::PositionDiscovery));assert_eq!(out,[0xcc;8]);}
}
`
