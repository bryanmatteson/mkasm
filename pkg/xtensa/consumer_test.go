package xtensa

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This is a separately compiled crate consumer: it uses only generated public
// APIs and independently assembled bytes, never the runtime's private helpers.
func TestWriteRustPublicConsumer(t *testing.T) {
	artifact, out := os.Getenv("XTENSA_ARTIFACTS"), os.Getenv("XTENSA_RUST_OUTPUT")
	if artifact == "" || out == "" {
		t.Skip("set XTENSA_ARTIFACTS and XTENSA_RUST_OUTPUT")
	}
	type external struct {
		ID, Architecture, Status, Bytes, Actual, Encoded string
		Seed                                             int
	}
	var rows []external
	for _, name := range []string{"gnu-results.json", "llvm-results.json", "ghidra-comparison.json"} {
		data, err := os.ReadFile(filepath.Join(artifact, name))
		if err != nil {
			t.Fatal(err)
		}
		var r []external
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r...)
	}
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		var src strings.Builder
		fmt.Fprintf(&src, "use %s::*;\n#[test]fn independent_instruction_consumer(){\nlet cases:&[(&str,&[u8])]=&[\n", arch)
		seen := map[string]bool{}
		forms := map[string]bool{}
		count := 0
		for _, r := range rows {
			if r.Architecture != arch || r.Status != "exact" {
				continue
			}
			key := fmt.Sprintf("%s/%d", r.ID, r.Seed)
			if seen[key] {
				continue
			}
			seen[key] = true
			forms[r.ID] = true
			data := r.Actual
			if data == "" {
				data = r.Encoded
			}
			b, err := hex.DecodeString(data)
			if err != nil || len(b) == 0 {
				t.Fatal("invalid external bytes", r.ID, data, err)
			}
			fmt.Fprintf(&src, "(%q,&%v),\n", r.ID, b)
			count++
		}
		src.WriteString("];\nlet mut seen=std::collections::HashSet::new();for &(id,b)in cases{let d=decode(b).unwrap_or_else(|e|panic!(\"{id} {b:x?} {e:?}\"));assert_eq!(d.length,b.len(),\"{id}\");assert_eq!(d.encode().unwrap(),b,\"{id}\");let analysis=d.describe(0x40000);assert_eq!(analysis.text,d.format(0x40000),\"{id}\");for s in &analysis.operands{assert!(s.domain.contains(s.value),\"{id} {} {:?}\",s.name,s.domain);assert!(!analysis.text[s.start..s.end].is_empty());}assert_eq!(d.relocated(0x40000,0x40000).unwrap().encode().unwrap(),b,\"{id}\");if let Ok(moved)=d.relocated(0x40000,0x40004){let a=moved.describe(0x40004);let before=analysis.operands.iter().filter_map(|s|s.position.target(0x40000,s.value)).collect::<Vec<_>>();let after=a.operands.iter().filter_map(|s|s.position.target(0x40004,s.value)).collect::<Vec<_>>();assert_eq!(before,after,\"{id}\");}if seen.insert(id){let text=d.format(0x40000);assert!(assemble_at(&text,0x40000).unwrap_or_else(|e|panic!(\"{id} {text}: {e:?}\")).iter().any(|x|x==b),\"{id} {text}\");let t=Template::parse_at(&text,0x40000).unwrap();assert!(t.matches(b).is_some(),\"{id} {text}\");assert!(t.encode(&[]).unwrap().iter().any(|x|x==b),\"{id} {text}\");}}\n}")
		fmt.Fprintf(&src, "\n#[test]fn public_operand_profiles_and_templates(){assert!(profile(\"esp32\").unwrap().contains(&\"HasWindowed\"));assert!(!profile(\"esp8266\").unwrap().contains(&\"HasWindowed\"));assert!(assemble_with_features(\"entry a1,32\",0,Some(profile(\"esp8266\").unwrap())).is_err());for address in 0x1000..0x1004{for b in assemble_at(\"l32r a2,0xffc\",address).unwrap(){let d=decode(&b).unwrap();assert_eq!(d.instructions[0].branch_target(address),None);let a=d.describe(address);let span=a.operands.iter().find(|s|s.position_dependent()).unwrap();assert_eq!(span.position.target(address,span.value),Some(0xffc));}}let template=Template::parse(\"add $dst,$same,$same\").unwrap();for b in template.encode(&[(\"dst\",2),(\"same\",3)]).unwrap(){let (_,v)=template.matches(&b).unwrap();assert!(v.contains(&(\"same\".into(),3)));assert!(Template::parse(\"add _,a3,a3\").unwrap().matches(&b).is_some());}assert!(assemble(\"all4 b0,b1\").is_err());assert!(assemble(\"extui a2,a3,31,2\").is_err());}\n")
		if arch == "xtensa" {
			src.WriteString("\n#[test]fn public_cross_slot_bindings(){let t=Template::parse(\"{ add a2,$same,a3; add a4,$same,a5; nop }\").unwrap();for b in t.encode(&[(\"same\",7)]).unwrap(){let (n,v)=t.matches(&b).unwrap();assert_eq!(n,8);assert_eq!(v,vec![(\"same\".into(),7)]);let mut d=decode(&b).unwrap();d.instructions[1].values[1]=6;let bad=d.encode().unwrap();assert!(t.matches(&bad).is_none());}assert!(assemble(\"{ add a2,a3,a4 }\").is_err());}\n")
		}
		text := src.String()
		text = normalizeRustArrays(text)
		dir := filepath.Join(out, arch, "tests")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "consumer.rs"), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s public consumer: %d independent byte cases, %d forms", arch, count, len(forms))
	}
}
func normalizeRustArrays(text string) string {
	return regexp.MustCompile(`&\[([0-9 ]+)\]`).ReplaceAllStringFunc(text, func(v string) string { return strings.ReplaceAll(v, " ", ",") })
}
