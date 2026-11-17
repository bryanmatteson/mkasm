package m68k

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func corpus(t *testing.T) *Catalog {
	t.Helper()
	f, e := os.Open("testdata/m68k-opc.c")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	c, e := Parse(f, "m68k")
	if e != nil {
		t.Fatal(e)
	}
	c.CPU = "m68k-all"
	return c
}
func TestFullCorpus(t *testing.T) {
	for _, arch := range []string{"m68k", "coldfire"} {
		t.Run(arch, func(t *testing.T) {
			c := corpus(t)
			c.Architecture = arch
			if len(c.Opcodes) != 1887 {
				t.Fatalf("source records %d", len(c.Opcodes))
			}
			fail := 0
			for j := range c.Opcodes {
				o := &c.Opcodes[j]
				mask := uint32(1023)
				if arch == "coldfire" {
					mask = 0x7fc00
				}
				if o.Features&mask == 0 {
					continue
				}
				for _, profile := range []string{"68000", "68010", "68020", "68030", "68040", "68060", "68881", "68851", "cpu32", "fido", "coldfire-all"} {
					if Profiles[profile]&mask&o.Features != 0 {
						c.CPU = profile
						break
					}
				}
				v, e := sampleOpcode(c, o)
				if e != nil {
					t.Error(e)
					continue
				}
				b, e := c.Encode(o.ID, v)
				if e != nil {
					if fail < 25 {
						t.Errorf("%s %s: %v", o.ID, o.Args, e)
					}
					fail++
					continue
				}
				if o.Mnemonic == "swbeg" {
					continue
				}
				i, e := c.Decode(b)
				if e != nil {
					t.Errorf("%s %x: %v", o.ID, b, e)
					continue
				}
				b2, e := c.Assemble(i.Format())
				if e != nil || !bytes.Equal(b, b2) {
					t.Errorf("%s decoded %s %x: got%x %v", o.ID, i.Format(), b, b2, e)
				}
			}
			if fail > 0 {
				t.Fatalf("%d sample encoding failures", fail)
			}
		})
	}
}

func TestRustGeneration(t *testing.T) {
	output := os.Getenv("MKASM_M68K_RUST_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	for _, arch := range []string{"m68k", "coldfire"} {
		c := corpus(t)
		c.Architecture = arch
		if arch == "coldfire" {
			c.CPU = "isa-a"
		} else {
			c.CPU = "68000"
		}
		dir := filepath.Join(output, arch)
		if e := c.GenerateRust(dir); e != nil {
			t.Fatal(e)
		}
		var rows strings.Builder
		count := 0
		for j := range c.Opcodes {
			o := &c.Opcodes[j]
			cpu := ""
			profiles := []string{"68000", "68010", "68020", "68030", "68040", "68060", "68881", "68851", "cpu32", "fido"}
			if arch == "coldfire" {
				profiles = []string{"coldfire-all"}
			}
			for _, p := range profiles {
				if Profiles[p]&o.Features != 0 {
					cpu = p
					break
				}
			}
			if cpu == "" {
				continue
			}
			c.CPU = cpu
			values, e := sampleOpcode(c, o)
			if e != nil {
				t.Fatal(e)
			}
			b, e := c.Encode(o.ID, values)
			if e != nil {
				t.Fatal(o.ID, e)
			}
			a, _ := json.Marshal(values)
			fmt.Fprintf(&rows, "%s\t%s %s\t%x\n", cpu, o.ID, a, b)
			count++
		}

		aliasMap := map[string]string{}
		for _, alias := range c.Aliases {
			aliasMap[alias.Alias] = alias.Primary
		}
		for _, alias := range c.Aliases {
			name := alias.Primary
			for depth := 0; depth < len(c.Aliases); depth++ {
				next, ok := aliasMap[name]
				if !ok {
					break
				}
				name = next
			}
			mask := uint32(1023)
			cpu := "m68k-all"
			if arch == "coldfire" {
				mask = 0x7fc00
				cpu = "coldfire-all"
			}
			var selected *Opcode
			for j := range c.Opcodes {
				if c.Opcodes[j].Mnemonic == name && c.Opcodes[j].Features&mask != 0 {
					selected = &c.Opcodes[j]
					break
				}
			}
			if selected == nil {
				continue
			}
			c.CPU = cpu
			v, e := sampleOpcode(c, selected)
			if e != nil {
				t.Fatal(e)
			}
			b, e := c.Encode(alias.Alias, v)
			if e != nil {
				t.Fatal(e)
			}
			a, _ := json.Marshal(v)
			fmt.Fprintf(&rows, "%s\t%s %s\t%x\n", cpu, alias.Alias, a, b)
			count++
		}
		vectorData, e := os.ReadFile("testdata/gnu-vectors.json")
		if e != nil {
			t.Fatal(e)
		}
		var vectors []gnuVector
		if e = json.Unmarshal(vectorData, &vectors); e != nil {
			t.Fatal(e)
		}
		for _, v := range vectors {
			isCF := strings.Contains(v.CPU, "isa") || v.CPU == "coldfire-all"
			if (arch == "coldfire") != isCF {
				continue
			}
			fmt.Fprintf(&rows, "%s\t%s\t%s\n", v.CPU, v.Text, v.Hex)
			count++
		}
		if os.Getenv("MKASM_M68K_RUST_OUTPUT") != "" {
			richCases(t, c, func(cpu, id string, v []Value, b []byte) {
				a, _ := json.Marshal(v)
				fmt.Fprintf(&rows, "%s\t%s %s\t%x\n", cpu, id, a, b)
				count++
			})
		}
		if e := os.MkdirAll(filepath.Join(dir, "tests"), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(dir, "tests/corpus.tsv"), []byte(rows.String()), 0644); e != nil {
			t.Fatal(e)
		}
		source := fmt.Sprintf(`use %s_codec::*;
 #[test] fn borrowed_large_input() {let mut large=vec![0xff;1<<20];for line in include_str!("corpus.tsv").lines().take(1500){let a:Vec<_>=line.split('\t').collect();if a[1].starts_with("swbeg_"){continue};let c=Catalog::new(a[0]).unwrap();let expected:Vec<_>=a[2].as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();large[..expected.len()].copy_from_slice(&expected);let i=c.decode(&large).expect(a[1]);assert_eq!(i.length,expected.len(),"{}",a[1]);assert_eq!(c.assemble(&i.to_string()).unwrap(),expected);}}
 #[test] fn strict_branches_and_registers(){if ARCHITECTURE=="coldfire"{let c=Catalog::new("cfv4e").unwrap();assert_eq!(c.assemble("movec [\"d0\",\"asid\"]").unwrap(),vec![0x4e,0x7b,0,3]);assert_eq!(c.assemble("movec [\"a1\",\"pcr1u1\"]").unwrap(),vec![0x4e,0x7b,0x9d,0x0b]);}if ARCHITECTURE=="m68k"{let c=Catalog::new("68000").unwrap();assert_eq!(c.assemble("linkw [\"fp\",-32]").unwrap(),vec![0x4e,0x56,0xff,0xe0]);assert_eq!(c.assemble("moveq [-7,\"d3\"]").unwrap(),vec![0x76,0xf9]);assert!(c.assemble("moveq [128,0]").is_err());let b=c.assemble("bra [-20]").unwrap();let i=c.decode(&b).unwrap();assert_eq!(i.branch_target(0xfffffff0),Some(0xffffffde));assert!(c.assemble("bras [0]").is_err());assert!(c.assemble("braw [32768]").is_err());let c=Catalog::new("68020+68881").unwrap();let b=c.assemble("faddd [1,[58,-8],2]").unwrap();assert_eq!(c.decode(&b).unwrap().pc_relative_target(1,0x1000),Some(0xffc));}}
 #[test] fn corpus() {for line in include_str!("corpus.tsv").lines(){let a:Vec<_>=line.split('\t').collect();let c=Catalog::new(a[0]).unwrap();let expected:Vec<_>=a[2].as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();let b=c.assemble(a[1]).expect(a[1]);assert_eq!(b,expected,"{}",a[1]);if a[1].starts_with("swbeg_"){continue};let i=c.decode(&b).expect(a[1]);assert_eq!(i.length,b.len(),"{} decoded {}",a[1],i);assert_eq!(c.assemble(&i.to_string()).unwrap(),b,"{}",a[1]);let mut template=c.template(i.opcode.id).unwrap();for(n,v)in i.operands.iter().enumerate(){template.set(&format!("op{}",n),v.clone()).unwrap();};assert_eq!(template.encode().unwrap(),b);}}
 `, arch)
		if e := os.WriteFile(filepath.Join(dir, "tests/corpus.rs"), []byte(source), 0644); e != nil {
			t.Fatal(e)
		}
		t.Logf("generated %s and %d corpus cases: %s", arch, count, dir)
	}
}

func TestSourceAndAliasContract(t *testing.T) {
	c := corpus(t)
	if len(c.Aliases) < 150 {
		t.Fatalf("upstream aliases missing: %d", len(c.Aliases))
	}
	names := map[string]*Opcode{}
	for j := range c.Opcodes {
		if _, ok := names[c.Opcodes[j].Mnemonic]; !ok {
			names[c.Opcodes[j].Mnemonic] = &c.Opcodes[j]
		}
	}
	aliases := map[string]string{}
	for _, a := range c.Aliases {
		aliases[a.Alias] = a.Primary
	}
	checked := 0
	for _, a := range c.Aliases {
		name := a.Primary
		for depth := 0; depth < len(c.Aliases); depth++ {
			if p, ok := aliases[name]; ok {
				name = p
			} else {
				break
			}
		}
		o := names[name]
		if o == nil {
			t.Fatalf("alias %s has unknown primary %s", a.Alias, name)
		}
		c.CPU = "m68k-all"
		c.Architecture = "m68k"
		if o.Features&1023 == 0 {
			c.CPU = "coldfire-all"
			c.Architecture = "coldfire"
		}
		v, e := sampleOpcode(c, o)
		if e != nil {
			t.Fatal(e)
		}
		expected, e := c.Encode(o.ID, v)
		if e != nil {
			t.Fatal(o.ID, e)
		}
		actual, e := c.Encode(a.Alias, v)
		if e != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("alias %s primary%s got%x want%x err%v", a.Alias, o.ID, actual, expected, e)
		}
		checked++
	}
	t.Logf("upstream aliases %d", checked)
	raw, e := os.ReadFile("testdata/m68k-opc.c")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Parse(bytes.NewReader(append(raw, ' ')), "m68k"); e == nil {
		t.Fatal("unrecognized source revision accepted")
	}
}
