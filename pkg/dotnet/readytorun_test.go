package dotnet

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestNativeIntegerBoundaries(t *testing.T) {
	for _, b := range [][]byte{{}, {255}, {1}, {3, 0}, {7, 0, 0}, {15, 0, 0, 0}} {
		if _, _, e := nativeUnsigned(b, 0); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	for _, tc := range []struct {
		b []byte
		v uint32
	}{{[]byte{0xfe}, 127}, {[]byte{1, 2}, 128}, {[]byte{3, 0, 2}, 16384}, {[]byte{7, 0, 0, 2}, 2097152}, {[]byte{15, 0xff, 0xff, 0xff, 0xff}, 0xffffffff}} {
		v, n, e := nativeUnsigned(tc.b, 0)
		if e != nil || v != tc.v || int(n) != len(tc.b) {
			t.Fatalf("%x: %x %d %v", tc.b, v, n, e)
		}
	}
}

func TestReadyToRunRuntimeCorpus(t *testing.T) {
	path := os.Getenv("MKASM_DOTNET_CORPUS")
	if path == "" {
		t.Skip("set MKASM_DOTNET_CORPUS to a ReadyToRun image")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	h, e := im.ReadyToRunHeader()
	if e != nil || h == nil {
		t.Fatal(h, e)
	}
	functions, e := im.NativeFunctions()
	if e != nil {
		t.Fatal(e)
	}
	mapped := 0
	instances := 0
	total := 0
	for _, f := range functions {
		if len(f.Code) != int(f.EndRVA-f.BeginRVA) {
			t.Fatal("native range loss")
		}
		total += len(f.Code)
		mapped += len(f.Methods)
		instances += len(f.Instances)
		for _, instance := range f.Instances {
			if instance.FunctionIndex != f.Index || len(instance.Signature) == 0 {
				t.Fatal("generic entry identity lost")
			}
		}
		for _, m := range f.Methods {
			if _, e := im.Metadata.Method(m); e != nil {
				t.Fatal(e)
			}
		}
	}
	if len(functions) < 100 || mapped < 100 || instances == 0 {
		t.Fatalf("missing runtime coverage %d %d", len(functions), mapped)
	}
	t.Logf("%s R2R %d.%d: %d native functions, %d MethodDefs, %d generic instances, %d code bytes", h.Architecture, h.Major, h.Minor, len(functions), mapped, instances, total)
}

func TestReadyToRunGenericMappingAndUnwind(t *testing.T) {
	fixture, err := os.ReadFile("testdata/r2r-mapping.bin")
	if err != nil {
		t.Fatal(err)
	}
	for _, machine := range []uint16{0x6264, 0x5064} {
		im := &Image{Data: fixture, Machine: machine, SizeOfHeaders: uint32(len(fixture)), ReadyToRun: true, Metadata: &Metadata{}}
		im.CLI.ManagedNativeHeader = Directory{32, 40}
		fs, err := im.NativeFunctions()
		if err != nil || len(fs) != 2 {
			t.Fatalf("%x: %v %v", machine, fs, err)
		}
		if fs[0].EndRVA != 204 || fs[1].EndRVA != 216 || len(fs[1].Instances) != 1 || len(fs[0].Instances) != 0 {
			t.Fatal("incorrect native mapping", fs)
		}
		v := fs[1].Instances[0]
		if v.Hash != 0xaa || v.FunctionIndex != 1 || v.Token != 0x06000001 || len(v.TypeArguments) != 2 || v.TypeArguments[0].Kind != "int32" || v.TypeArguments[1].Kind != "canon" {
			t.Fatalf("%+v", v)
		}
		for _, edit := range []func([]byte){
			func(b []byte) { b[100] = 3 },                                // illegal hash index width
			func(b []byte) { b[101] = 0 },                                // index points into the hash header
			func(b []byte) { b[104] = 0xfe },                             // negative relative pointer outside data
			func(b []byte) { b[110] = 100 },                              // function index outside runtime table
			func(b []byte) { binary.LittleEndian.PutUint32(b[160:], 0) }, // empty extent
		} {
			b := append([]byte(nil), fixture...)
			edit(b)
			im.Data = b
			if _, err := im.NativeFunctions(); err == nil {
				t.Fatal("accepted malformed native data")
			}
		}
	}
}

func TestReadyToRunForeignSignatures(t *testing.T) {
	m := &Metadata{}
	// UpdateContext, OwnerType, MethodInstantiation and Constrained. The owner
	// explicitly refers to TypeDef 7 in module 2; no local token lookup is valid.
	b := []byte{0x80, 0xe4, 3, 0x3f, 2, 0x12, 28, 1, 2, 0x3e, 0x14, 8, 1, 0, 1, 3, 0x3f, 4, 8, 0}
	v, e := m.nativeMethodInstance(b, 0)
	if e != nil {
		t.Fatal(e)
	}
	if v.Module == nil || *v.Module != 3 || v.Owner.Kind != "module" || v.Owner.Index != 2 || v.Owner.Args[0].Token != 0x02000007 || v.Constrained.Index != 4 || v.TypeArguments[1].LowerBounds[0] != -1 {
		t.Fatalf("%+v", v)
	}
	// The same native-only type codes must remain invalid in ECMA metadata.
	for _, raw := range [][]byte{{0x3e}, {0x3f, 2, 8}} {
		if _, e := m.TypeSignature(raw); e == nil {
			t.Fatal("native type admitted in ECMA signature")
		}
	}
}

func TestReadyToRunCompositeCorpus(t *testing.T) {
	path := os.Getenv("MKASM_DOTNET_COMPOSITE")
	if path == "" {
		t.Skip("set MKASM_DOTNET_COMPOSITE to a published composite R2R image")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	if !im.Composite || !im.ReadyToRun {
		t.Fatal("composite not recognized")
	}
	cs, e := im.ReadyToRunComponents()
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) < 2 {
		t.Fatal("missing components", len(cs))
	}
	fs, e := im.NativeFunctions()
	if e != nil {
		t.Fatal(e)
	}
	mapped, instances := 0, 0
	for _, f := range fs {
		mapped += len(f.ComponentMethods)
		instances += len(f.Instances)
		for _, m := range f.ComponentMethods {
			if int(m.Component) >= len(cs) {
				t.Fatal(m)
			}
			if cs[m.Component].Metadata != nil {
				if _, e := cs[m.Component].Metadata.Method(m.Token); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	if len(fs) < 2 || mapped < 2 || instances == 0 {
		t.Fatal("missing composite native mappings", len(fs), mapped, instances)
	}
	if _, e := im.RewriteMethods(map[Token][]byte{0x06000001: {6, 0x2a}}, RewriteOptions{DropNative: true}); e == nil {
		t.Fatal("composite cannot be rewritten as global IL")
	}
	t.Logf("%d components, %d native functions, %d component methods, %d generic instances", len(cs), len(fs), mapped, instances)
}

func TestCompositePEExportsAndComponentIdentity(t *testing.T) {
	b, e := os.ReadFile("testdata/composite-pe.dll")
	if e != nil {
		t.Fatal(e)
	}
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	if !im.Composite || !im.ReadyToRun || im.HasMetadata {
		t.Fatal("incorrect native composite framing")
	}
	cs, e := im.ReadyToRunComponents()
	if e != nil || len(cs) != 1 || cs[0].Metadata == nil {
		t.Fatal(cs, e)
	}
	fs, e := im.NativeFunctions()
	if e != nil || len(fs) != 2 || len(fs[0].ComponentMethods) != 1 || len(fs[1].Instances) != 1 {
		t.Fatal(fs, e)
	}
	ref := fs[0].ComponentMethods[0]
	if ref.Component != 0 || ref.Token != 0x06000001 {
		t.Fatal(ref)
	}
	if _, e := cs[ref.Component].Metadata.Method(ref.Token); e != nil {
		t.Fatal(e)
	}
	for _, edit := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b[512+0x38:], 2) },             // export ordinal
		func(b []byte) { b[512+0x80] = 0 },                                            // exported signature
		func(b []byte) { binary.LittleEndian.PutUint32(b[512+0xe0+8:], 0xfffffff0) },  // component header RVA
		func(b []byte) { binary.LittleEndian.PutUint32(b[512+0x150+4:], 0xffffffff) }, // core header section count
	} {
		bad := append([]byte(nil), b...)
		edit(bad)
		im, e := Open(bad)
		if e == nil {
			_, e = im.NativeFunctions()
		}
		if e == nil {
			t.Fatal("accepted malformed composite data")
		}
	}
}
