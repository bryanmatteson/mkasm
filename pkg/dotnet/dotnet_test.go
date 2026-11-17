package dotnet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type oracleImage struct {
	Format  string
	Machine uint16
	Rows    []uint32
	Types   []struct {
		Token           Token
		Name, Ns        string
		Methods, Fields []Token
	}
	Methods []struct {
		Token            Token
		Name             string
		Rva, Flags, Impl uint32
		Signature        string
		Formatted        string
		IL               *string
		Raw              *string
		MaxStack         *uint16 `json:"max_stack"`
		Local            Token
		EH               []ExceptionClause
	}
	Strings []struct {
		Token Token
		Value string
	}
	Documents []struct {
		Token Token
		Name  string
	}
	DebugMethods []struct{}
	Resources    []struct {
		Token          Token
		Name           string
		Offset         uint32
		Implementation Token
	}
}

func fixture(t *testing.T, name string) ([]byte, oracleImage) {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata", name))
	if e != nil {
		t.Fatal(e)
	}
	j, e := os.ReadFile(filepath.Join("testdata", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var o oracleImage
	if e = json.Unmarshal(j, &o); e != nil {
		t.Fatal(e)
	}
	return b, o
}
func TestPEReaderOracle(t *testing.T) {
	for _, name := range []string{"anycpu.dll", "x86.exe", "x64.dll", "embedded.dll"} {
		t.Run(name, func(t *testing.T) {
			b, o := fixture(t, name)
			im, e := Open(b)
			if e != nil {
				t.Fatal(e)
			}
			if im.Format != strings.ReplaceAll(o.Format, "PE32Plus", "PE32+") {
				t.Fatal("PE format")
			}
			if im.Machine != o.Machine {
				t.Fatal("machine")
			}
			for i, n := range o.Rows {
				if im.Metadata.Tables[i].Count != n {
					t.Fatalf("table%d got%d want%d", i, im.Metadata.Tables[i].Count, n)
				}
			}
			types, e := im.Metadata.Types()
			if e != nil {
				t.Fatal(e)
			}
			if len(types) != len(o.Types) {
				t.Fatal("type count")
			}
			for i, typ := range types {
				v := o.Types[i]
				if typ.Token != v.Token || typ.Name != v.Name || typ.Namespace != v.Ns || !slices.Equal(typ.Methods, v.Methods) || !slices.Equal(typ.Fields, v.Fields) {
					t.Fatalf("type %s %+v %+v", typ.Token, typ, v)
				}
			}
			methods, e := im.Metadata.Methods()
			if e != nil {
				t.Fatal(e)
			}
			if len(methods) != len(o.Methods) {
				t.Fatal("method count")
			}
			for i, m := range methods {
				v := o.Methods[i]
				if m.Token != v.Token || m.RVA != v.Rva || m.Name != v.Name || m.Flags != v.Flags || m.ImplFlags != v.Impl {
					t.Fatalf("method %+v", m)
				}
				r, _ := im.Metadata.Row(6, m.Token.RID())
				sig, _ := im.Metadata.Blob(r[4])
				if hex.EncodeToString(sig) != v.Signature {
					t.Fatal("signature bytes")
				}
				if m.Signature.Format(im.Metadata) != v.Formatted {
					t.Fatalf("signature format got%q want%q", m.Signature.Format(im.Metadata), v.Formatted)
				}
				body, e := im.MethodBody(m.Token)
				if e != nil {
					t.Fatalf("%s %v", m.Token, e)
				}
				if v.IL == nil {
					if body.Kind == "cil" {
						t.Fatal("fabricated body")
					}
					continue
				}
				if hex.EncodeToString(body.IL) != *v.IL || hex.EncodeToString(body.Raw) != *v.Raw || body.MaxStack != *v.MaxStack || body.LocalSignature != v.Local {
					t.Fatalf("body %s %+v", m.Token, body)
				}
				if len(body.Exceptions) != len(v.EH) {
					t.Fatal("EH count")
				}
				for j, c := range body.Exceptions {
					want := v.EH[j]
					if want.Flags != 1 {
						want.FilterOffset = 0
					}
					if c != want {
						t.Fatalf("EH got%+v want%+v", c, want)
					}
				}
			}
			for _, s := range o.Strings {
				v, _, e := im.Metadata.UserString(s.Token.RID())
				if e != nil || v != s.Value {
					t.Fatalf("string %s %q %q %v", s.Token, v, s.Value, e)
				}
			}
			res, e := im.Resources()
			if e != nil || len(res) != 1 || !bytes.Equal(res[0].Data, []byte("managed resource ✓\n")) {
				t.Fatalf("resources %+v %v", res, e)
			}
			assemblies, e := im.Metadata.Assemblies()
			if e != nil || len(assemblies) != 1 || assemblies[0].Version != "1.2.3.4" {
				t.Fatalf("assemblies %+v %v", assemblies, e)
			}
			fields, e := im.Metadata.Fields()
			if e != nil || len(fields) == 0 {
				t.Fatal(e)
			}
			for table := 0; table < 45; table++ {
				for rid := uint32(1); rid <= im.Metadata.Tables[table].Count; rid++ {
					tok := Token(uint32(table)<<24 | rid)
					if _, e := im.Metadata.Resolve(tok); e != nil {
						t.Fatalf("resolve %s %v", tok, e)
					}
				}
			}
		})
	}
}
func TestPortablePDBOracle(t *testing.T) {
	for _, name := range []string{"anycpu.pdb", "x86.pdb", "x64.pdb"} {
		t.Run(name, func(t *testing.T) {
			b, o := fixture(t, name)
			im, e := Open(b)
			if e != nil {
				t.Fatal(e)
			}
			for i, n := range o.Rows {
				if im.Metadata.Tables[i].Count != n {
					t.Fatalf("rows %d", i)
				}
			}
			for _, v := range o.Documents {
				n, e := im.Metadata.DocumentName(v.Token.RID())
				if e != nil || n != v.Name {
					t.Fatalf("document %q %q %v", n, v.Name, e)
				}
			}
			var want struct {
				Methods []struct {
					Token  Token
					Points []SequencePoint
				}
			}
			j, _ := os.ReadFile(filepath.Join("testdata", name+".json"))
			json.Unmarshal(j, &want)
			for _, v := range want.Methods {
				_, points, e := im.Metadata.SequencePoints(v.Token)
				if e != nil {
					t.Fatal(e)
				}
				if !reflect.DeepEqual(points, v.Points) && !(len(points) == 0 && len(v.Points) == 0) {
					t.Fatalf("points %s got%+v want%+v", v.Token, points, v.Points)
				}
			}
		})
	}
}
func TestMalformedAndFraming(t *testing.T) {
	b, _ := fixture(t, "anycpu.dll")
	for n := 0; n < len(b); n++ {
		_, _ = Open(b[:n])
	}
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range im.Metadata.Streams {
		for _, v := range []uint32{0xffffffff, uint32(len(im.Metadata.Data)) + 1} {
			md := append([]byte(nil), im.Metadata.Data...)
			p := bytes.Index(md, []byte(d.Name+"\x00"))
			if p < 8 {
				t.Fatal("stream")
			}
			binary.LittleEndian.PutUint32(md[p-8:], v)
			if _, e := ParseMetadata(md); e == nil {
				t.Fatal("bad stream offset accepted")
			}
		}
	}
	for _, v := range [][]byte{{3}, {3, 0x30, 8, 0, 255, 255, 255, 255, 0, 0, 0, 0}, {0x0b, 0x30, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0, 0, 0}, {0xe0}, {0xff}} {
		if _, e := ParseMethodBody(v); e == nil {
			t.Fatalf("bad body %x", v)
		}
	}
	body, e := ParseMethodBody([]byte{6, 0x2a, 0xff, 0xff})
	if e != nil || len(body.Raw) != 2 || len(body.IL) != 1 {
		t.Fatal("tiny tail")
	}
	for _, v := range [][]byte{{0xe0}, {0x80}, {0xc0, 0, 0, 1}, {0x80, 0}} {
		if _, _, e := CompressedInteger(v); e == nil {
			t.Fatal("bad compressed")
		}
	}
	r := cursor{b: []byte{0x80, 1}}
	n, e := r.signedCompressed()
	if e != nil || n != -8192 {
		t.Fatalf("signed %d %v", n, e)
	}
	if _, e := im.Metadata.Resolve(0x020000ff); e == nil {
		t.Fatal("bad token")
	}
	for i := 0; i < 2000; i++ {
		md := append([]byte(nil), im.Metadata.Data...)
		p := (i * 7919) % len(md)
		md[p] ^= byte(i%255 + 1)
		_, _ = ParseMetadata(md)
	}
}

func TestGeneratedRust(t *testing.T) {
	out := t.TempDir()
	if e := GenerateRust(out); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(out, "Cargo.toml"), "--test", "metadata")
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("generated Rust: %v\n%s", e, b)
	}
}

func TestEmbeddedPDB(t *testing.T) {
	b, _ := fixture(t, "embedded.dll")
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	pdb, e := im.EmbeddedPDB(1024 * 1024)
	if e != nil || pdb == nil || pdb.PDB == nil {
		t.Fatalf("embedded PDB %v", e)
	}
	if _, e = im.EmbeddedPDB(1); e == nil {
		t.Fatal("unbounded embedded PDB")
	}
	for i := uint32(1); i <= pdb.Tables[49].Count; i++ {
		if _, _, e = pdb.SequencePoints(Token(6<<24 | i)); e != nil {
			t.Fatal(e)
		}
	}
}

func TestMemberResolutionAndAttributes(t *testing.T) {
	b, _ := fixture(t, "anycpu.dll")
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	m := im.Metadata
	genericMembers := 0
	for _, table := range []uint8{4, 6, 10, 43} {
		for rid := uint32(1); rid <= m.Tables[table].Count; rid++ {
			v, e := m.Member(Token(uint32(table)<<24 | rid))
			if e != nil {
				t.Fatal(e)
			}
			if v.Name == "" || v.DeclaringType == "" || v.ResolvedSignature.Format(m) == "" {
				t.Fatal("empty resolved member")
			}
			if len(v.TypeArguments) > 0 || len(v.MethodArguments) > 0 {
				genericMembers++
			}
		}
	}
	if genericMembers == 0 {
		t.Fatal("generic substitutions unexercised")
	}
	a, e := m.Attributes(0)
	if e != nil || len(a) == 0 {
		t.Fatalf("attributes %v", e)
	}
	for _, v := range a {
		if v.Constructor.Name != ".ctor" {
			t.Fatal("attribute constructor")
		}
	}
	for i := uint32(1); i <= m.Tables[6].Count; i++ {
		method, e := m.Method(Token(6<<24 | i))
		if e != nil {
			t.Fatal(e)
		}
		if method.Name == "NativeCall" {
			body, e := im.MethodBody(method.Token)
			if e != nil || body.Kind != "pinvoke" || len(body.IL) != 0 {
				t.Fatal("PInvoke fabricated CIL")
			}
		}
	}
	md := append([]byte(nil), m.Data...)
	td, _ := m.Stream("#~")
	off := bytes.Index(md, td) + int(m.Tables[6].Offset) + 4
	binary.LittleEndian.PutUint16(md[off:], 1)
	native, e := ParseMetadata(md)
	if e != nil {
		t.Fatal(e)
	}
	im.Metadata = native
	body, e := im.MethodBody(0x06000001)
	if e != nil || body.Kind != "native" || len(body.Raw) != 0 {
		t.Fatal("mixed native body fabricated")
	}
}

func TestSignatureBoundariesAndIndexGraphs(t *testing.T) {
	b, _ := fixture(t, "anycpu.dll")
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	m := im.Metadata
	for _, sig := range [][]byte{{0, 0xff}, {0x80, 0}, {0, 0, 0}, {6, 0x21}, {0, 1, 1, 0x41, 8}, {7, 0x80, 0}, {6, 15}, {6, 0x12, 3}} {
		if _, e := m.ParseSignature(sig); e == nil {
			t.Fatalf("malformed signature accepted %x", sig)
		}
	}
	array, e := m.TypeSignature([]byte{0x14, 8, 1, 1, 2, 1, 0x80, 1})
	if e != nil || array.LowerBounds[0] != -8192 || array.Sizes[0] != 2 {
		t.Fatalf("signed array bounds %+v %v", array, e)
	}
	for _, v := range [][]byte{{0x80, 0}, {0xbf, 0xff}, {0xc0, 0, 0, 0}} {
		r := cursor{b: v}
		if _, e := r.signedCompressed(); e == nil {
			t.Fatal("nonminimal signed accepted")
		}
	}
	for _, column := range []struct {
		kind  string
		table int
		count uint32
		want  int
	}{{"t2", 2, 65535, 2}, {"t2", 2, 65536, 4}, {"TypeDefOrRef", 1, 16383, 2}, {"TypeDefOrRef", 1, 16384, 4}, {"HasCustomAttribute", 6, 2047, 2}, {"HasCustomAttribute", 6, 2048, 4}} {
		copy := *m
		copy.Tables[column.table].Count = column.count
		width, e := copy.columnSize(column.kind)
		if e != nil || width != column.want {
			t.Fatalf("index boundary %+v width%d %v", column, width, e)
		}
	}
	for name, c := range CodedIndices {
		for tag, table := range c.Tables {
			tok, e := DecodeCoded(name, 1<<c.Bits|uint32(tag))
			if table < 0 {
				if e == nil {
					t.Fatal("reserved tag")
				}
			} else if e != nil || tok != Token(uint32(table)<<24|1) {
				t.Fatalf("coded %s tag%d %s %v", name, tag, tok, e)
			}
		}
	}
	md := append([]byte(nil), m.Data...)
	td, _ := m.Stream("#~")
	base := bytes.Index(md, td)
	off := base + int(m.Tables[41].Offset)
	binary.LittleEndian.PutUint16(md[off+2:], binary.LittleEndian.Uint16(md[off:]))
	if _, e = ParseMetadata(md); e == nil {
		t.Fatal("nested self-cycle accepted")
	}
	md = append([]byte(nil), m.Data...)
	off = base + int(m.Tables[9].Offset)
	if m.Tables[9].Count == 0 {
		t.Fatal("interface fixture")
	}
	binary.LittleEndian.PutUint16(md[off:], 0)
	if _, e = ParseMetadata(md); e == nil {
		t.Fatal("required nil index accepted")
	}
	props, e := m.Properties()
	if e != nil || len(props) == 0 {
		t.Fatal("properties", e)
	}
	events, e := m.Events()
	if e != nil || len(events) == 0 {
		t.Fatal("events", e)
	}
}

func FuzzOpen(f *testing.F) {
	for _, n := range []string{"anycpu.dll", "x64.dll", "anycpu.pdb", "embedded.dll"} {
		b, e := os.ReadFile(filepath.Join("testdata", n))
		if e != nil {
			f.Fatal(e)
		}
		f.Add(b)
	}
	f.Add([]byte("BSJB"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Open(b) })
}

func TestHostileMetadataSizes(t *testing.T) {
	b, _ := fixture(t, "anycpu.dll")
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	td, _ := im.Metadata.Stream("#~")
	base := bytes.Index(im.Metadata.Data, td)
	for _, value := range []uint32{0xffffff, 0x1000000, 0xffffffff} {
		md := append([]byte(nil), im.Metadata.Data...)
		binary.LittleEndian.PutUint32(md[base+24:], value)
		if _, e := ParseMetadata(md); e == nil {
			t.Fatal("hostile row count")
		}
	}
	md := append([]byte(nil), im.Metadata.Data...)
	binary.LittleEndian.PutUint64(md[base+8:], im.Metadata.Valid|1<<63)
	if _, e := ParseMetadata(md); e == nil {
		t.Fatal("unknown table accepted")
	}
	blob, _ := im.Metadata.Stream("#Blob")
	for _, v := range [][]byte{{0xdf, 255, 255, 255}, {0xff}, {0x80}} {
		md := append([]byte(nil), im.Metadata.Data...)
		off := bytes.Index(md, blob) + 1
		copy(md[off:], v)
		_, _ = ParseMetadata(md)
	}
	embedded, _ := fixture(t, "embedded.dll")
	for i := 0; i < 500; i++ {
		copy := append([]byte(nil), embedded...)
		copy[(i*7919)%len(copy)] ^= byte(i%255 + 1)
		if image, e := Open(copy); e == nil {
			_, _ = image.EmbeddedPDB(1024 * 1024)
		}
	}
}
