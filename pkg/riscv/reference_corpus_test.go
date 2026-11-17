package riscv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// Every upstream record, including imports, pseudo-ops and experimental
// extensions, goes through upstream's own Python parser. This checks physical
// allocation, not execution semantics for extensions LLVM does not implement.
func TestIndependentUpstreamCorpus(t *testing.T) {
	dir := os.Getenv("RISCV_OPCODES_DIR")
	if dir == "" {
		t.Skip("set RISCV_OPCODES_DIR for the live upstream Python reference")
	}
	cmd := exec.Command("python3", "-c", `import collections,json,pathlib,sys
from riscv_opcodes.shared_utils import process_enc_line
root=pathlib.Path(sys.argv[1]); files=sorted((root/'extensions').rglob('rv*')); bases={}; records=[]
for p in files:
 if not p.is_file(): continue
 for text in p.read_text().splitlines():
  text=text.split('#')[0].strip()
  if text and not text.startswith('$'): bases[p.name+'::'+text.split()[0]]=text
for p in files:
 if not p.is_file(): continue
 seen=collections.Counter()
 for text in p.read_text().splitlines():
  text=text.split('#')[0].strip()
  if not text: continue
  if text.startswith('$import '): text=bases[text.split()[1]]
  elif text.startswith('$pseudo_op '): text=' '.join(text.split()[2:])
  rawname=text.split()[0]; _,record=process_enc_line(text,str(p))
  ident=str(p.relative_to(root/'extensions'))+'::'+rawname;seen[ident]+=1
  if seen[ident]>1:ident+='#'+str(seen[ident])
  records.append(dict(id=ident,file=p.name,**record))
print(json.dumps(records))`, dir)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(dir, "src"), "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("upstream Python parser: %v", err)
	}
	var native []struct{ ID, File, Match, Mask string }
	if err := json.Unmarshal(out, &native); err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("MKASM_RISCV_REFERENCE_RUST")
	if root == "" {
		root = t.TempDir()
	}
	for _, architecture := range []string{"riscv32", "riscv64"} {
		c := upstream(t, architecture)
		if len(c.Unsupported) != 0 {
			t.Fatal("unsupported source records", c.Unsupported)
		}
		entries := map[string]*codec.Encoding{}
		for i := range c.Encodings {
			entries[c.Encodings[i].ID] = &c.Encodings[i]
		}
		var vectors strings.Builder
		forms, checked := 0, 0
		for _, row := range native {
			if strings.HasPrefix(row.File, "rv128_") || architecture == "riscv32" && strings.HasPrefix(row.File, "rv64_") || architecture == "riscv64" && strings.HasPrefix(row.File, "rv32_") {
				continue
			}
			e := entries[row.ID]
			if e == nil {
				t.Fatalf("%s: missing native source record %s", architecture, row.ID)
			}
			forms++
			match, err1 := strconv.ParseUint(row.Match, 0, 32)
			mask, err2 := strconv.ParseUint(row.Mask, 0, 32)
			if err1 != nil || err2 != nil {
				t.Fatal("invalid upstream mask", row)
			}
			size := len(e.Mask)
			var nativeValue, nativeMask [4]byte
			binary.LittleEndian.PutUint32(nativeValue[:], uint32(match))
			binary.LittleEndian.PutUint32(nativeMask[:], uint32(mask))
			if !bytes.Equal(e.Mask, nativeMask[:size]) || !bytes.Equal(e.Value, nativeValue[:size]) {
				t.Fatalf("%s: native match/mask %s/%s differ from Go %x/%x", row.ID, row.Match, row.Mask, e.Value, e.Mask)
			}
			// Native masks define all physical variable bits independently of
			// our operand layouts. Exercise full, alternating, and walking-bit
			// patterns; the source parser does not describe semantic exclusions.
			single := &codec.Catalog{Architecture: architecture, Encodings: []codec.Encoding{*e}}
			if e.AssemblyOnly {
				single.Encodings = nil
				for _, variant := range c.Encodings {
					if strings.HasPrefix(variant.ID, e.ID+"/") && !variant.AssemblyOnly {
						single.Encodings = append(single.Encodings, variant)
					}
				}
			}
			patterns := []uint32{0, ^uint32(0), 0x55555555, 0xaaaaaaaa}
			state := uint32(0x9e3779b9)
			for i := 0; i < 64; i++ {
				state ^= state << 13
				state ^= state >> 17
				state ^= state << 5
				patterns = append(patterns, state)
			}
			for bit := 0; bit < size*8; bit++ {
				if mask&(1<<uint(bit)) == 0 {
					patterns = append(patterns, ^uint32(0)^(1<<uint(bit)))
				}
			}
			valid := 0
			for _, pattern := range patterns {
				word := uint32(match) | pattern & ^uint32(mask)
				var raw [4]byte
				binary.LittleEndian.PutUint32(raw[:], word)
				data := raw[:size]
				d, err := single.Decode(data)
				if err != nil {
					continue // Semantic restrictions are checked by the LLVM suite.
				}
				actual, err := single.Encode(d.Encoding.ID, d.Values)
				if err != nil || !bytes.Equal(actual, data) {
					t.Fatalf("%s physical native pattern %x: %x %v", row.ID, data, actual, err)
				}
				valid++
				checked++
				fmt.Fprintf(&vectors, "%s\t%s\n", e.ID, hex.EncodeToString(data))
			}
			if valid == 0 {
				t.Fatalf("%s: no native physical pattern could be checked", row.ID)
			}
			for bit := 0; bit < size*8; bit++ {
				if mask&(1<<uint(bit)) == 0 {
					continue
				}
				bad := append([]byte(nil), nativeValue[:size]...)
				bad[bit/8] ^= 1 << uint(bit%8)
				if _, err := single.Decode(bad); err == nil {
					t.Fatalf("%s: accepted native fixed bit %d changed", row.ID, bit)
				}
			}
		}
		output := filepath.Join(root, architecture)
		if err := c.GenerateRust(output); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, "tests", "upstream.tsv"), []byte(vectors.String()), 0644); err != nil {
			t.Fatal(err)
		}
		source := fmt.Sprintf(`use %s::*;
#[test] fn native_physical_corpus() {
let mut count=0;
for line in include_str!("upstream.tsv").lines() {
 let (source,hex)=line.split_once('\t').unwrap();
 let b:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
 let d=decode(&b).unwrap_or_else(|e|panic!("{source} {hex}: {e:?}"));assert_eq!(d.length,b.len(),"{source}");
 let mut actual=[0u8;4];let n=d.encode_into(&mut actual).unwrap();assert_eq!(&actual[..n],b,"{source}");count+=1;
}assert_eq!(count,%d);
}
`, architecture, checked)
		if err := os.WriteFile(filepath.Join(output, "tests", "upstream_reference.rs"), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: all %d upstream records match native masks; %d native physical boundary patterns checked", architecture, forms, checked)
	}
	if err := os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte("[workspace]\nresolver=\"2\"\nmembers=[\"riscv32\",\"riscv64\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	consumer := exec.Command("cargo", "test", "--workspace", "--test", "upstream_reference", "--quiet")
	consumer.Dir = root
	if out, err := consumer.CombinedOutput(); err != nil {
		t.Fatalf("fresh Rust native corpus: %v\n%s", err, out)
	}
}
