package hexagon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedRust(t *testing.T) {
	if os.Getenv("HEXAGON_RUST") == "" {
		t.Skip("set HEXAGON_RUST=1")
	}
	c := fixture(t)
	dir := os.Getenv("HEXAGON_RUST_OUTPUT")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	const boundaries = `use hexagon::*;
#[test] fn packet_address_boundaries() {
 for (text,pc,target) in [("{\njump 0xfffffffc\n}",0,0xfffffffcu64),("{\njump 0x0\n}",0xfffffffcu64,0)] {
  for bytes in assemble_at(text,pc).unwrap() {
   let p=decode(&bytes).unwrap();
   let description=p.describe(pc);
   let targets=description.operands.iter().filter_map(|o|o.position.target(pc,o.value)).collect::<Vec<_>>();
   assert!(!targets.is_empty()); assert!(targets.iter().all(|&t|t==target));
   assert!(assemble_at(&p.format(pc),pc).unwrap().contains(&bytes));
   let moved=p.relocated(pc,pc+4).unwrap();
   assert_eq!(moved.describe(pc+4).operands.iter().filter_map(|o|o.position.target(pc+4,o.value)).collect::<Vec<_>>(),targets);
  }
 }
}
`
	if err := os.WriteFile(filepath.Join(dir, "tests", "boundaries.rs"), []byte(boundaries), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"test", "--lib", "--test", "boundaries"}
	if path := os.Getenv("HEXAGON_CASES"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cases []struct{ ID, Actual string }
		if err = json.Unmarshal(data, &cases); err != nil {
			t.Fatal(err)
		}
		var source strings.Builder
		source.WriteString("use hexagon::*;\n#[test] fn independent_llvm_object_packets(){\nlet packets:&[(&str,&[u8])]=&[\n")
		count := 0
		for _, c := range cases {
			if c.Actual == "" {
				continue
			}
			b, err := hex.DecodeString(c.Actual)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&source, "(%q,&[", c.ID)
			for _, v := range b {
				fmt.Fprintf(&source, "%d,", v)
			}
			source.WriteString("]),\n")
			count++
		}
		source.WriteString("];\nlet mut seen=std::collections::HashSet::new();\nfor &(id,bytes) in packets {let p=decode(bytes).unwrap_or_else(|e|panic!(\"{id}: {e:?}\"));assert_eq!(p.length,bytes.len(),\"{id}\");assert_eq!(encode_packet(&p,None).unwrap(),bytes,\"{id}\");let analysis=p.describe(0x1000);assert_eq!(analysis.text,p.format(0x1000),\"{id}\");for s in &analysis.operands{assert!(s.domain.contains(s.value),\"{id} {} {:?}\",s.name,s.domain);assert!(!analysis.text[s.start..s.end].is_empty());}assert_eq!(encode_packet(&p.relocated(0x1000,0x1000).unwrap(),None).unwrap(),bytes,\"{id}\");if let Ok(moved)=p.relocated(0x1000,0x1004){let a=moved.describe(0x1004);let before=analysis.operands.iter().filter_map(|s|s.position.target(0x1000,s.value)).collect::<Vec<_>>();let after=a.operands.iter().filter_map(|s|s.position.target(0x1004,s.value)).collect::<Vec<_>>();assert_eq!(before,after,\"{id}\");}if seen.insert(id){let text=p.format(0x1000);assert!(assemble_at(&text,0x1000).unwrap_or_else(|e|panic!(\"{id} {text}: {e:?}\")).iter().any(|b|b==bytes),\"{id} {text}\");let template=Template::parse_at(&text,0x1000).unwrap_or_else(|e|panic!(\"{id} {text}: {e:?}\"));assert!(template.matches(bytes).is_some(),\"{id} {text}\");assert!(template.encode(&[]).unwrap().iter().any(|b|b==bytes),\"{id} {text}\");}}\nassert!(packets.len()>2900);\n}\n#[test] fn public_text_templates_and_profiles(){\nfor text in [\"{\\njump ##268435456\\n}\",\"{\\nr0 = #0xffffffff\\n}\",\"{\\nr0 = ##-1234567\\n}\",\"{\\nv1:0 = vcombine(v2,v3)\\nvmem(r0+#0) = v1.new\\n}\",\"{\\nr0 = #1\\nr1 = #2\\nr2 = #3\\n}:endloop0:endloop1\",\"{\\nr0 = add(r0,#1) ; r1 = add(r1,#2)\\n}\"]{for bytes in assemble(text).unwrap(){let p=decode(&bytes).unwrap();let text=p.format(0);assert!(assemble(&text).unwrap().contains(&bytes));let template=Template::parse(&text).unwrap();assert!(template.matches(&bytes).is_some());assert!(template.encode(&[]).unwrap().contains(&bytes));}}\nlet template=Template::parse(\"{\\nr0 = add($same,$same)\\n}\").unwrap();for bytes in template.encode(&[(\"same\",3)]).unwrap(){assert!(template.matches(&bytes).unwrap().1.contains(&(\"same\".into(),3)));}\nassert!(profile(\"hexagonv81+hvx-length128b+hvx-ieee-fp\").unwrap().contains(&\"UseHVXV81\"));\n}\n")
		if err = os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "tests/consumer.rs"), []byte(source.String()), 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("public consumer exercises %d independent object packets", count)
		args = append(args, "--test", "consumer")
	}
	cmd := exec.Command("cargo", args...)
	cmd.Dir = dir
	b, err := cmd.CombinedOutput()
	os.WriteFile(filepath.Join(dir, "test.log"), b, 0644)
	if err != nil {
		t.Fatalf("cargo: %v\n%s", err, b)
	}
}
