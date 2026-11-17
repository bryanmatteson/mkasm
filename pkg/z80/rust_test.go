package z80

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedRust(t *testing.T) {
	if os.Getenv("MKASM_Z80_RUST") == "" {
		t.Skip("set MKASM_Z80_RUST=1")
	}
	artifact := os.Getenv("MKASM_Z80_ARTIFACT")
	if artifact == "" {
		artifact = t.TempDir()
	}
	for _, arch := range []string{"z80", "z180"} {
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
			consumer := rustConsumer
			if arch == "z180" {
				consumer = z180Consumer
			}
			if err = os.WriteFile(filepath.Join(out, "tests", "public_consumer.rs"), []byte(consumer), 0644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(out, "Cargo.toml"), "--lib", "--test", "public_consumer")
			// Generated wrappers must remain warning-clean when their fixed-field
			// runtime is a private module, including library and public consumers.
			cmd.Env = append(os.Environ(), "RUSTFLAGS="+os.Getenv("RUSTFLAGS")+" -D warnings")
			var log bytes.Buffer
			cmd.Stdout = &log
			cmd.Stderr = &log
			err = cmd.Run()
			os.WriteFile(filepath.Join(out, "consumer.log"), log.Bytes(), 0644)
			if err != nil {
				t.Fatalf("%v\n%s", err, log.Bytes())
			}
			t.Logf("%s", log.Bytes())
		})
	}
}

const rustConsumer = `use z80::*;
#[test]fn public_workflow(){
 assert!(UNSUPPORTED.is_empty());
 let effects=decode(&[0]).unwrap().effects();assert_eq!(effects.knowledge,EffectKnowledge::Unknown);assert!(effects.flags.is_empty());
 let raw=[0xdd,0xfd,0xdd,0x21,0x34,0x12];let d=decode(&raw).unwrap();assert_eq!(d.length,6);assert_eq!(d.prefixes,vec![0xdd,0xfd]);assert_eq!(d.canonical_format(0x1000),"ld ix,4660");assert_eq!(d.reencode().unwrap(),raw);assert_eq!(assemble_at(&d.format(0x1000),0x1000).unwrap()[0],raw);
 assert_eq!(d.operand("pair"),Some(2));assert_eq!(d.operand("missing"),None);
 assert_eq!(decode_with_features(&raw,profile("z8401x")).unwrap().length,6);assert!(decode_with_features(&raw,Some(&[])).is_err());
 let mut buffer=[0;8];assert_eq!(d.reencode_into(&mut buffer).unwrap(),6);assert_eq!(&buffer[..6],&raw);
 for raw in [&[0xdd,0x76][..],&[0xfd,0xed,0x44],&[0xed,0x4c],&[0xdd,0xcb,0x80,0x40],&[0xdd,0xcb,0x7f,0x00],&[0xed,0x00]] {let d=decode(raw).unwrap();assert_eq!(d.reencode().unwrap(),raw);assert_eq!(assemble_at(&d.format(0x1000),0x1000).unwrap()[0],raw);}
 let d=decode(&[0xdd,0x18,0xfd]).unwrap();assert_eq!(d.branch_target(0xffff),Some(0xffff));assert_eq!(d.branch_target(u64::MAX),Some(0xffff));assert_eq!(d.format(u64::MAX),d.format(0xffff));
 let im=Template::parse("im $mode").unwrap();let(_,v)=im.matches(&[0xed,0x6e]).unwrap();assert!(v.contains(&("mode".into(),0)));assert_eq!(im.encode(&[("mode",2)]).unwrap().len(),2);
 let t=Template::parse_at("prefix[ddfd] ld $dst,$value",0x1000).unwrap();let encoded=t.encode(&[("dst",2),("value",0x1234)]).unwrap();assert!(encoded.contains(&vec![0xdd,0xfd,0xdd,0x21,0x34,0x12]));
 let (n,holes)=t.matches(&raw).unwrap();assert_eq!(n,6);assert!(holes.contains(&("value".into(),0x1234)));
 assert_eq!(decode(&[0xdd,0xfd]).unwrap_err(),Error::Truncated);assert_eq!(decode(&[0xdd,0xcb,0]).unwrap_err(),Error::Truncated);
 assert!(assemble("prefix[édd] nop").is_err());assert!(assemble("ld a,256").is_err());assert!(assemble("ld a,(ix-129)").is_err());assert!(assemble("prefix[dd] ld hl,1").is_err());
}
`
const z180Consumer = `use z180::*;
#[test]fn documented_z180(){assert!(UNSUPPORTED.is_empty());assert_eq!(decode(&[0xed,0x7c]).unwrap().operand("pair"),Some(3));let t=Template::parse("mlt $pair").unwrap();assert!(t.matches(&[0xed,0x7c]).is_some());for text in ["mlt sp","tst (hl)","in0 f,(17)","out0 (18),b","otimr","slp"]{let b=assemble(text).unwrap_or_else(|e|panic!("{}: {:?}",text,e)).remove(0);let d=decode(&b).unwrap();assert_eq!(d.reencode().unwrap(),b);assert_eq!(assemble(&d.format(0)).unwrap()[0],b);}assert!(assemble("sll b").is_err());assert!(assemble("ld ixh,1").is_err());assert_eq!(decode(&[0xdd,0]).unwrap_err(),Error::Unknown);for op in [0x31,0x82,0x8a,0x92,0x9a]{assert_eq!(decode(&[0xed,op]).unwrap_err(),Error::Unknown);}}
`
