package tricore

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This compiles a dependency-free generated crate and exercises its public API
// from a separate Rust integration test, in addition to its all-form unit test.
func TestGeneratedRustConsumer(t *testing.T) {
	if os.Getenv("MKASM_TRICORE_RUST") == "" {
		t.Skip("set MKASM_TRICORE_RUST=1 to build generated Rust consumers")
	}
	artifact := os.Getenv("MKASM_TRICORE_ARTIFACT")
	if artifact == "" {
		artifact = t.TempDir()
	}
	for _, arch := range []string{"tricore", "tricore-pcp"} {
		t.Run(arch, func(t *testing.T) {
			c, err := Parse(nil, arch)
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(artifact, arch)
			if err = c.GenerateRust(out); err != nil {
				t.Fatal(err)
			}
			if err = os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
				t.Fatal(err)
			}
			consumer := cpuConsumer
			if arch == "tricore-pcp" {
				consumer = pcpConsumer
			}
			if err = os.WriteFile(filepath.Join(out, "tests", "public_consumer.rs"), []byte(consumer), 0644); err != nil {
				t.Fatal(err)
			}
			notice, err := os.ReadFile(filepath.Join(out, "UPSTREAM-LICENSE"))
			if err != nil || !strings.Contains(string(notice), SourceRevision) {
				t.Fatalf("upstream notice: %v", err)
			}
			cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(out, "Cargo.toml"), "--lib", "--test", "public_consumer")
			var log bytes.Buffer
			cmd.Stdout = &log
			cmd.Stderr = &log
			err = cmd.Run()
			os.WriteFile(filepath.Join(out, "consumer.log"), log.Bytes(), 0644)
			if err != nil {
				t.Fatalf("Rust public consumer: %v\n%s", err, log.Bytes())
			}
			t.Logf("%s", log.Bytes())
		})
	}
}

const cpuConsumer = `use tricore::*;
#[test]
fn instruction_sequence_and_public_apis() {
 let source=["mov d2,#5","mov d3,#7","add d2,d3","st.w [a10],d2","ld.w d4,[a10]","jeq d4,d2,0x1010","mov d4,#0","ret"];
 // These bytes came from Ghidra 12.1.2's independent assembler.
 let golden: &[u8]=&[0x82,0x52,0x82,0x73,0x42,0x32,0x74,0xa2,0x54,0xa4,0x5f,0x24,0x03,0x00,0x82,0x04,0x00,0x90];
 let mut offset=0;
 for (index,text) in source.iter().enumerate() {
  let address=0x1000+offset as u64;
  let assembled=assemble_with_features(text,address,profile("v2")).unwrap();
  let decoded=decode_with_features(&golden[offset..],profile("v2")).unwrap();
  assert!(assembled.contains(&golden[offset..offset+decoded.length].to_vec()));
  let values=decoded.operands().map(|(_,v)|v).collect::<Vec<_>>();
  assert_eq!(encode(decoded.encoding().id,&values).unwrap(),golden[offset..offset+decoded.length]);
  let (id,entry)=catalog_entry(decoded.encoding().id).unwrap();
  let mut buffer=[0;4];assert_eq!(encode_into(id,&values,&mut buffer).unwrap(),decoded.length);
  assert_eq!(&buffer[..decoded.length],&golden[offset..offset+decoded.length]);
  assert!(assemble_at(&decoded.format(address),address).unwrap().contains(&golden[offset..offset+decoded.length].to_vec()));
  if index==5 { assert_eq!(decoded.branch_target(address),Some(0x1010)); assert_eq!(entry.flow_control,"conditional_branch"); }
  if index==7 { assert_eq!(entry.flow_control,"return"); }
  offset+=decoded.length;
 }
 assert_eq!(offset,golden.len());
 assert_eq!(encoding_count(),3393);
 let template=Template::parse_at("add $dst,$src",0x1004).unwrap();
 let encoded=template.encode(&[("dst",2),("src",3)]).unwrap();
 assert!(encoded.contains(&vec![0x42,0x32]));
 let (length,holes)=template.matches(&golden[4..]).unwrap();
 assert_eq!(length,2);assert!(holes.contains(&("dst".into(),2)));assert!(holes.contains(&("src".into(),3)));
 assert!(Template::parse("add $same,$same").unwrap().matches(&[0x42,0x32]).is_none());
 assert!(Template::parse("add _,_").unwrap().matches(&[0x42,0x32]).is_some());
 assert!(Template::parse("add _,_").unwrap().encode(&[]).is_err());
 assert_eq!(decode(&[]).unwrap_err(),Error::Truncated);
 assert_eq!(decode(&[0x0b,0]).unwrap_err(),Error::Truncated);
 assert!(assemble_at("ld.d e3,[a0]0",0).is_err());
 assert!(assemble_at("j 0x1001",0x1000).is_err());
 assert!(assemble("mov d2,#-32768").is_ok());assert!(assemble("mov d2,#32767").is_ok());assert!(assemble("mov d2,#32768").is_err());
 assert!(assemble("jla 0xf01ffffe").is_ok());assert!(assemble("jla 0xf0200000").is_err());
 assert!(assemble("cop 0[0],d0,d0,d0,d0").is_err());assert_eq!(decode(&[0x6b,0,0,0]).unwrap().encoding().mnemonic,"pack");
 let branch=Template::parse_at("jeq $left,$right,$displacement",0x100a).unwrap();
 let branch_bytes=&golden[10..14];
 let (_,bindings)=branch.matches(branch_bytes).unwrap();assert!(bindings.contains(&("displacement".into(),6)));
 assert!(branch.encode(&[("left",4),("right",2),("displacement",6)]).unwrap().contains(&branch_bytes.to_vec()));
 assert!(assemble_with_features("wait",0,profile("rider-b")).is_err());
 assert!(assemble_with_features("wait",0,profile("v2")).is_ok());
}
`
const pcpConsumer = `use tricore_pcp::*;
#[test]
fn separate_pcp_stream_and_templates() {
 assert_eq!(ARCHITECTURE,"tricore-pcp");assert_eq!(encoding_count(),308);
 assert_eq!(assemble("nop").unwrap(),vec![vec![0,0]]);
 let b=assemble_at("add.i R4,#63",0x1000).unwrap().remove(0);
 let d=decode(&b).unwrap();assert_eq!(d.length,2);
 assert!(assemble_at(&d.format(0x1000),0x1000).unwrap().contains(&b));
 let t=Template::parse("add.i $dst,#$value").unwrap();
 assert!(t.matches(&b).is_some());assert!(t.encode(&[("dst",4),("value",63)]).unwrap().contains(&b));
 assert!(assemble("add.i R4,#64").is_err());
 assert!(assemble("add d2,d3").is_err());
}
`
