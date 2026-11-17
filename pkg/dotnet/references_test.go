package dotnet

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type referenceFixture struct {
	rows           map[uint8][][]uint32
	strings, blobs []byte
	guids          []byte
}

func newReferenceFixture() *referenceFixture {
	return &referenceFixture{rows: map[uint8][][]uint32{}, strings: []byte{0}, blobs: []byte{0}}
}
func (f *referenceFixture) str(s string) uint32 {
	i := uint32(len(f.strings))
	f.strings = append(f.strings, []byte(s)...)
	f.strings = append(f.strings, 0)
	return i
}
func (f *referenceFixture) blob(b []byte) uint32 {
	i := uint32(len(f.blobs))
	if len(b) > 127 {
		panic("test blob too large")
	}
	f.blobs = append(f.blobs, byte(len(b)))
	f.blobs = append(f.blobs, b...)
	return i
}
func (f *referenceFixture) metadata(t *testing.T) *Metadata {
	t.Helper()
	td := make([]byte, 24)
	td[4] = 2
	td[7] = 1
	var valid uint64
	for table := uint8(0); table < 64; table++ {
		if len(f.rows[table]) > 0 {
			valid |= 1 << table
			td = binary.LittleEndian.AppendUint32(td, uint32(len(f.rows[table])))
		}
	}
	binary.LittleEndian.PutUint64(td[8:], valid)
	for table := uint8(0); table < 64; table++ {
		for _, row := range f.rows[table] {
			for i, v := range row {
				if Schemas[table].Columns[i].Kind == "u4" {
					td = binary.LittleEndian.AppendUint32(td, v)
				} else {
					td = binary.LittleEndian.AppendUint16(td, uint16(v))
				}
			}
		}
	}
	// BSJB root, version, flags/count, then three aligned stream headers.
	headerSize := 72
	streamCount := uint16(3)
	if len(f.guids) > 0 {
		headerSize += 16
		streamCount++
	}
	b := make([]byte, headerSize)
	copy(b, "BSJB")
	binary.LittleEndian.PutUint32(b[12:], 4)
	copy(b[16:], "v\x00")
	binary.LittleEndian.PutUint16(b[22:], streamCount)
	p := 24
	streams := []struct {
		name string
		data []byte
	}{{"#~", td}, {"#Strings", f.strings}, {"#Blob", f.blobs}}
	if len(f.guids) > 0 {
		streams = append(streams, struct {
			name string
			data []byte
		}{"#GUID", f.guids})
	}
	for _, stream := range streams {
		binary.LittleEndian.PutUint32(b[p:], uint32(len(b)))
		binary.LittleEndian.PutUint32(b[p+4:], uint32(len(stream.data)))
		copy(b[p+8:], stream.name)
		p = (p + 8 + len(stream.name) + 1 + 3) &^ 3
		b = append(b, stream.data...)
	}
	m, e := ParseMetadata(b)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func enumReference(t *testing.T, name string, version uint32, storage byte, forward string) *Metadata {
	t.Helper()
	f := newReferenceFixture()
	f.rows[0] = [][]uint32{{0, f.str(name + ".dll"), 0, 0, 0}}
	f.rows[32] = [][]uint32{{0, version, 0, 0, 0, 0, 0, f.str(name), 0}}
	f.rows[2] = [][]uint32{{0, f.str("<Module>"), 0, 0, 1, 1}}
	f.rows[35] = [][]uint32{{4, 0, 0, 0, 0, 0, f.str("System.Runtime"), 0, 0}}
	if forward != "" {
		f.rows[35] = append(f.rows[35], []uint32{1, 0, 0, 0, 0, 0, f.str(forward), 0, 0})
		f.rows[39] = [][]uint32{{0x200000, 0, f.str("Mode"), f.str("External"), 2<<2 | 1}}
	} else {
		f.rows[1] = [][]uint32{{1<<2 | 2, f.str("Enum"), f.str("System")}}
		f.rows[2] = append(f.rows[2], []uint32{0x101, f.str("Mode"), f.str("External"), 1<<2 | 1, 1, 1})
		f.rows[4] = [][]uint32{{0x606, f.str("value__"), f.blob([]byte{6, storage})}}
	}
	return f.metadata(t)
}
func TestExplicitEnumReferences(t *testing.T) {
	local := enumReference(t, "Local", 1, 8, "")
	one := enumReference(t, "One", 1, 7, "")
	two := enumReference(t, "Two", 1, 4, "")
	v2 := enumReference(t, "One", 2, 10, "")
	refs, e := NewReferenceSet(local, one, two, v2)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ name, want string }{{"External.Mode", "int32"}, {"External.Mode, Two", "int8"}, {"External.Mode, One, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", "uint16"}, {"External.Mode, One, Version=2.0.0.0", "int64"}} {
		got, e := refs.EnumUnderlying(tc.name)
		if e != nil || got != tc.want {
			t.Fatalf("%s: %s %v", tc.name, got, e)
		}
	}
	for _, name := range []string{"External.Mode, One", "External.Mode, Missing", "External.Mode, One, Version=3.0.0.0", "External.Mode, Two, PublicKeyToken=0011223344556677", "External.Mode, Two, Culture=fr", "External.Mode, Two, Version=1.0.0", "External.Mode, Two, Version=01.0.0.0", "External.Mode, Two, Culture=neutral, Culture=neutral", "External.Mode, Two, Unknown=x", "External.Mode[]", ", Two"} {
		if _, e := refs.EnumUnderlying(name); e == nil {
			t.Fatal("accepted", name)
		}
	}
	duplicate := enumReference(t, "One", 1, 4, "")
	if _, e := NewReferenceSet(local, one, duplicate); e == nil {
		t.Fatal("duplicate identity accepted")
	}
	if _, e := NewReferenceSet(local, one, one); e != nil {
		t.Fatal("same supplied metadata should deduplicate", e)
	}
	if _, e := NewReferenceSet(nil, one); e == nil {
		t.Fatal("nil local accepted")
	}
	if kind, e := local.LocalEnumUnderlying("External.Mode"); e != nil || kind != "int32" {
		t.Fatal("local resolver changed", kind, e)
	}

	for code, want := range map[byte]string{4: "int8", 5: "uint8", 6: "int16", 7: "uint16", 8: "int32", 9: "uint32", 10: "int64", 11: "uint64"} {
		m := enumReference(t, "Storage", 1, code, "")
		set, e := NewReferenceSet(m)
		if e != nil {
			t.Fatal(e)
		}
		if got, e := set.EnumUnderlying("External.Mode"); e != nil || got != want {
			t.Fatal(code, got, e)
		}
	}
	invalid := enumReference(t, "Invalid", 1, 12, "")
	invalidSet, _ := NewReferenceSet(invalid)
	if _, e := invalidSet.EnumUnderlying("External.Mode"); e == nil {
		t.Fatal("float enum storage accepted")
	}
}
func TestEnumReferenceForwarders(t *testing.T) {
	local := enumReference(t, "Local", 1, 8, "")
	facade := enumReference(t, "Facade", 1, 0, "One")
	one := enumReference(t, "One", 1, 7, "")
	refs, e := NewReferenceSet(local, facade, one)
	if e != nil {
		t.Fatal(e)
	}
	if kind, e := refs.EnumUnderlying("External.Mode, Facade"); e != nil || kind != "uint16" {
		t.Fatal(kind, e)
	}
	absent, _ := NewReferenceSet(local, facade)
	if _, e := absent.EnumUnderlying("External.Mode, Facade"); e == nil {
		t.Fatal("missing forwarded assembly accepted")
	}
	a := enumReference(t, "A", 1, 0, "B")
	b := enumReference(t, "B", 1, 0, "A")
	cycle, _ := NewReferenceSet(local, a, b)
	if _, e := cycle.EnumUnderlying("External.Mode, A"); e == nil || !strings.Contains(e.Error(), "cycle") {
		t.Fatal("cycle", e)
	}
}
func TestAssemblyTokenAndConstructorScope(t *testing.T) {
	if token, e := keyToken([]byte("abc"), true); e != nil || token != "9dd8d09c6cc25078" {
		t.Fatal(token, e)
	}
	f := newReferenceFixture()
	f.rows[0] = [][]uint32{{0, f.str("local.dll"), 0, 0, 0}}
	f.rows[32] = [][]uint32{{0, 1, 0, 0, 0, 0, 0, f.str("Local"), 0}}
	f.rows[35] = [][]uint32{{1, 2, 3, 4, 0, f.blob([]byte{1, 2, 3, 4, 5, 6, 7, 8}), f.str("Foreign"), 0, 0}}
	f.rows[1] = [][]uint32{{6, f.str("Outer"), f.str("External")}, {7, f.str("Mode"), 0}}
	f.rows[2] = [][]uint32{{0, f.str("<Module>"), 0, 0, 1, 1}}
	m := f.metadata(t)
	typ, e := m.attributeType(Type{Kind: "valuetype", Token: Token(1<<24 | 2)})
	if e != nil || typ.Enum != "External.Outer+Mode, Foreign, Version=1.2.3.4, Culture=neutral, PublicKeyToken=0102030405060708" {
		t.Fatal(typ, e)
	}
}

// A real compiler emits enum constructor signatures, named arguments and boxed
// enum values; resolution deliberately uses First's reference assembly.
func TestCompiledEnumReferences(t *testing.T) {
	if testing.Short() {
		t.Skip("real dotnet compiler")
	}
	dotnet, e := exec.LookPath("dotnet")
	if e != nil {
		dotnet = "/usr/local/share/dotnet/dotnet"
		if _, e := os.Stat(dotnet); e != nil {
			t.Skip("dotnet unavailable")
		}
	}
	dir := os.Getenv("MKASM_DOTNET_REFERENCE_ARTIFACTS")
	if dir == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			t.Fatal(e)
		}
		dir = filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/dotnet/references")
	}
	files := map[string]string{
		"Escapes/Escapes.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>`,
		"Escapes/Program.cs": `using System; using System.Reflection; using System.Reflection.Emit;
class Program { static void Main(string[] args) {
 var builder=new PersistedAssemblyBuilder(new AssemblyName("Escaped"){Version=new Version(1,0,0,0)},typeof(object).Assembly); var module=builder.DefineDynamicModule("Escaped.dll");
 foreach(var pair in new(string,Type)[]{("External.Outer+Mode",typeof(ushort)),("External.Mode, Other",typeof(uint)),(@"External.Back\Slash",typeof(byte)),("External.Br[ack]*&et",typeof(long)),("External.Tail,",typeof(ulong)),(@"Ns+Comma,\[].Leaf",typeof(short))}) {module.DefineEnum(pair.Item1,TypeAttributes.Public,pair.Item2).CreateType();}
 var outer=module.DefineType("External.Outer",TypeAttributes.Public);var nested=outer.DefineNestedType("Mode",TypeAttributes.NestedPublic|TypeAttributes.Sealed,typeof(Enum));nested.DefineField("value__",typeof(sbyte),FieldAttributes.Public|FieldAttributes.SpecialName|FieldAttributes.RTSpecialName);nested.CreateType();outer.CreateType();
 builder.Save(args[0]);var loaded=Assembly.LoadFile(System.IO.Path.GetFullPath(args[0]));
 foreach(var pair in new(string,Type)[]{(@"External.Outer\+Mode",typeof(ushort)),("External.Outer+Mode",typeof(sbyte)),(@"External.Mode\, Other",typeof(uint)),(@"External.Back\\Slash",typeof(byte)),(@"External.Br\[ack\]\*\&et",typeof(long)),(@"External.Tail\,",typeof(ulong)),(@"Ns\+Comma\,\\\[\].Leaf",typeof(short))}) {var t=loaded.GetType(pair.Item1,true);if(t.GetEnumUnderlyingType()!=pair.Item2||t.FullName!=pair.Item1)throw new Exception("escaping mismatch: "+t.FullName);Console.WriteLine(t.FullName+" "+t.GetEnumUnderlyingType().FullName);}
} }`,
		"First/First.csproj":   `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><AssemblyVersion>1.2.3.4</AssemblyVersion></PropertyGroup></Project>`,
		"First/Types.cs":       `namespace External { public enum Mode : ushort { Value=0x8123 } public class Outer { public enum Nested : byte { Value=0x81 } } public class GenericOuter<T> { public enum Mode : byte { Value=0x82 } } public sealed class GenericMarkAttribute : System.Attribute { public GenericMarkAttribute(GenericOuter<int>.Mode value, object boxed) {} } public sealed class MarkAttribute : System.Attribute { public MarkAttribute(Mode mode, object boxed, Mode[] array) {} public Mode Named { get; set; } } }`,
		"Second/Second.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>`,
		"Second/Types.cs":      `namespace External { public enum Mode : sbyte { Value=-7 } }`,
		"Facade/Facade.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include="../First/First.csproj" /></ItemGroup></Project>`,
		"Facade/Types.cs":      `[assembly:System.Runtime.CompilerServices.TypeForwardedTo(typeof(External.Mode))] [assembly:System.Runtime.CompilerServices.TypeForwardedTo(typeof(External.Outer))]`,
		"Client/Client.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include="../First/First.csproj" /></ItemGroup></Project>`,
		"Client/Types.cs":      `[External.Mark(External.Mode.Value, External.Mode.Value, new[]{External.Mode.Value}, Named=External.Mode.Value)] public class Subject { } [External.GenericMark(External.GenericOuter<int>.Mode.Value, External.GenericOuter<int>.Mode.Value)] public class GenericSubject { }`,
	}
	for path, s := range files {
		p := filepath.Join(dir, path)
		if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(s), 0644); e != nil {
			t.Fatal(e)
		}
	}
	for _, project := range []string{"Client", "Second", "Facade", "Escapes"} {
		cmd := exec.Command(dotnet, "build", filepath.Join(dir, project, project+".csproj"), "-c", "Release", "--nologo", "-v:q")
		cmd.Env = append(os.Environ(), "DOTNET_CLI_TELEMETRY_OPTOUT=1")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("real compiler %s: %v\n%s", project, e, b)
		}
	}
	emittedPath := filepath.Join(dir, "Escaped.dll")
	emit := exec.Command(dotnet, filepath.Join(dir, "Escapes/bin/Release/net10.0/Escapes.dll"), emittedPath)
	if b, e := emit.CombinedOutput(); e != nil {
		t.Fatalf("real escaped metadata emitter: %v\n%s", e, b)
	} else {
		t.Logf("reflection escaped-name oracle:\n%s", b)
	}
	emitted, e := os.ReadFile(emittedPath)
	if e != nil {
		t.Fatal(e)
	}
	emittedImage, e := Open(emitted)
	if e != nil {
		t.Fatal(e)
	}
	emittedRefs, e := NewReferenceSet(emittedImage.Metadata)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ name, want string }{{`External.Outer\+Mode`, "uint16"}, {`External.Outer+Mode`, "int8"}, {`External.Mode\, Other`, "uint32"}, {`External.Back\\Slash`, "uint8"}, {`External.Br\[ack\]\*\&et`, "int64"}, {`External.Tail\,`, "uint64"}, {`Ns\+Comma\,\\\[\].Leaf`, "int16"}} {
		kind, e := emittedRefs.EnumUnderlying(tc.name + ", Escaped")
		if e != nil || kind != tc.want {
			t.Fatal("actual emitted escaped enum", tc, kind, e)
		}
	}
	read := func(project string, reference bool) *Metadata {
		t.Helper()
		p := filepath.Join(dir, project, "bin/Release/net10.0", project+".dll")
		if reference {
			p = filepath.Join(dir, project, "obj/Release/net10.0/ref", project+".dll")
		}
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		im, e := Open(b)
		if e != nil {
			t.Fatal(e)
		}
		return im.Metadata
	}
	client, first, second, facade := read("Client", false), read("First", true), read("Second", true), read("Facade", true)
	genericRuntimeBytes, e := os.ReadFile("/usr/local/share/dotnet/packs/Microsoft.NETCore.App.Ref/10.0.12/ref/net10.0/System.Runtime.dll")
	if e != nil {
		t.Fatal(e)
	}
	genericRuntime, e := Open(genericRuntimeBytes)
	if e != nil {
		t.Fatal(e)
	}
	genericDir := filepath.Join(dir, "Generic")
	if e := os.MkdirAll(genericDir, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(genericDir, "System.Runtime.dll"), genericRuntimeBytes, 0644); e != nil {
		t.Fatal(e)
	}
	refs, e := NewReferenceSet(client, first, second, facade, genericRuntime.Metadata)
	if e != nil {
		t.Fatal(e)
	}
	attrs, e := client.Attributes(0)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, a := range attrs {
		if a.Constructor.DeclaringType == "External.GenericMarkAttribute" {
			value, e := refs.DecodeAttribute(client, a)
			if e != nil {
				t.Fatal("actual closed generic enum attribute", e)
			}
			if len(value.Fixed) != 2 || value.Fixed[0].Bits != 0x82 || value.Fixed[1].Elements[0].Bits != 0x82 || len(value.Fixed[0].Type.EnumArguments) != 1 || value.Fixed[0].Type.EnumArguments[0].Kind != "int32" || !strings.Contains(value.Fixed[0].Type.Enum, "GenericOuter`1+Mode[[System.Int32]]") {
				t.Fatalf("generic enum identity/value lost: %+v", value)
			}
			if _, e := client.DecodeAttribute(a, refs.EnumUnderlying); e != nil {
				t.Fatal("legacy assembly generic enum decoder", e)
			}
			withoutArgumentAssembly, _ := NewReferenceSet(client, first)
			if _, e := withoutArgumentAssembly.DecodeAttribute(client, a); e == nil {
				t.Fatal("qualified generic argument bound without supplied assembly")
			}
			t.Logf("real generic enum fixed=%s; boxed=%s", value.Fixed[0].Type.Enum, value.Fixed[1].Elements[0].Type.Enum)
		}
		if a.Constructor.DeclaringType != "External.MarkAttribute" {
			continue
		}
		count++
		if _, e := client.DecodeAttribute(a, client.LocalEnumUnderlying); e == nil {
			t.Fatal("foreign enum accepted without reference")
		}
		v, e := client.DecodeAttribute(a, refs.EnumUnderlying)
		if e != nil {
			t.Fatal(e)
		}
		if len(v.Fixed) != 3 || v.Fixed[0].Bits != 0x8123 || v.Fixed[1].Elements[0].Bits != 0x8123 || v.Fixed[2].Elements[0].Bits != 0x8123 || len(v.Named) != 1 || v.Named[0].Value.Bits != 0x8123 {
			t.Fatalf("actual compiled attribute: %+v", v)
		}
		if !strings.Contains(v.Fixed[0].Type.Enum, ", First, Version=1.2.3.4,") {
			t.Fatal("lost defining assembly", v.Fixed[0].Type)
		}
	}
	if count != 1 {
		t.Fatal("compiled attribute missing")
	}
	for _, name := range []string{"External.GenericOuter`1+Mode[System.Int32], First", "External.GenericOuter`1+Mode[[System.Int32]], First", "External.GenericOuter`1+Mode[System.Int32[]], First"} {
		if kind, e := refs.EnumUnderlying(name); e != nil || kind != "uint8" {
			t.Fatal("closed nested generic enum", name, kind, e)
		}
	}
	for _, name := range []string{"External.GenericOuter`1+Mode, First", "External.GenericOuter`1+Mode[], First", "External.GenericOuter`1+Mode[System.Int32,System.String], First", "External.GenericOuter`1+Mode[[System.Int32],], First", "External.GenericOuter`1+Mode[[System.Int32], First", "External.GenericOuter`1+Mode[Missing.Type], First", "External.GenericOuter`1+Mode[[System.Int32, Missing]], First", "External.GenericOuter`1+Mode[System.Int32*], First", "External.GenericOuter`1+Mode[!0], First", "External.GenericOuter`1[System.Int32], First"} {
		if _, e := refs.EnumUnderlying(name); e == nil {
			t.Fatal("malformed/open/non-enum generic input accepted", name)
		}
	}

	for _, tc := range []struct{ name, want string }{{"External.Mode, First", "uint16"}, {"External.Mode, Second", "int8"}, {"External.Mode, Facade", "uint16"}, {"External.Outer+Nested, Facade", "uint8"}} {
		kind, e := refs.EnumUnderlying(tc.name)
		if e != nil || kind != tc.want {
			t.Fatal(tc, kind, e)
		}
	}
	if _, e := refs.EnumUnderlying("External.Mode"); e == nil {
		t.Fatal("unqualified external enum guessed")
	}
	// Permission-set encoding carries assembly-qualified enum names explicitly.
	typ := "External.Mode, First, Version=1.2.3.4, Culture=neutral, PublicKeyToken=null"
	payload := []byte{1, 0x54, 0x55, byte(len(typ))}
	payload = append(payload, typ...)
	payload = append(payload, 1, 'E', 0x23, 0x81)
	security := []byte{'.', 1, 1, 'X', byte(len(payload))}
	security = append(security, payload...)
	value, e := DecodeSecurity(security, refs.EnumUnderlying)
	if e != nil || value.Attributes[0].Named[0].Value.Bits != 0x8123 {
		t.Fatal(value, e)
	}
	// Actual signed framework facade/core-library identities exercise full-key
	// hashing and AssemblyRef token matching through a real framework forwarder.
	runtimeDir := "/usr/local/share/dotnet/shared/Microsoft.NETCore.App/10.0.12"
	runtimeBytes, runtimeErr := os.ReadFile(filepath.Join(runtimeDir, "System.Runtime.dll"))
	coreBytes, coreErr := os.ReadFile(filepath.Join(runtimeDir, "System.Private.CoreLib.dll"))
	if runtimeErr == nil && coreErr == nil {
		runtimeImage, e := Open(runtimeBytes)
		if e != nil {
			t.Fatal(e)
		}
		coreImage, e := Open(coreBytes)
		if e != nil {
			t.Fatal(e)
		}
		id, e := coreImage.Metadata.AssemblyIdentity()
		if e != nil || id.PublicKeyToken != "7cec85d7bea7798e" {
			t.Fatal(id, e)
		}
		framework, e := NewReferenceSet(client, runtimeImage.Metadata, coreImage.Metadata)
		if e != nil {
			t.Fatal(e)
		}
		if kind, e := framework.EnumUnderlying("System.DayOfWeek, System.Runtime, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"); e != nil || kind != "int32" {
			t.Fatal(kind, e)
		}
		runtimeArtifacts := filepath.Join(dir, "Runtime")
		if e := os.MkdirAll(runtimeArtifacts, 0755); e != nil {
			t.Fatal(e)
		}
		for name, data := range map[string][]byte{"System.Runtime.dll": runtimeBytes, "System.Private.CoreLib.dll": coreBytes} {
			if e := os.WriteFile(filepath.Join(runtimeArtifacts, name), data, 0644); e != nil {
				t.Fatal(e)
			}
		}
	} else {
		t.Log("installed framework forwarding check unavailable:", runtimeErr, coreErr)
	}
	t.Logf("compiled client + three reference assemblies, attributes/security/nested forwarding verified; Rust consumer hook MKASM_DOTNET_REFERENCE_ARTIFACTS=%s", dir)
}

func escapedEnumFixture() *referenceFixture {
	f := newReferenceFixture()
	f.rows[0] = [][]uint32{{0, f.str("Escaped.dll"), 0, 0, 0}}
	f.rows[32] = [][]uint32{{0, 1, 0, 0, 0, 0, 0, f.str("Escaped"), 0}}
	f.rows[35] = [][]uint32{{4, 0, 0, 0, 0, 0, f.str("System.Runtime"), 0, 0}, {1, 0, 0, 0, 0, 0, f.str("Escaped"), 0, 0}}
	f.rows[1] = [][]uint32{{6, f.str("Enum"), f.str("System")}, {10, f.str("Outer+Mode"), f.str("External")}, {10, f.str("Outer"), f.str("External")}, {15, f.str("Mode"), 0}, {10, f.str("Mode, Other"), f.str("External")}, {10, f.str(`Back\Slash`), f.str("External")}}
	f.rows[2] = [][]uint32{{0, f.str("<Module>"), 0, 0, 1, 1}}
	add := func(name, ns string, code byte, parent uint32) {
		rid := uint32(len(f.rows[2]) + 1)
		start := uint32(len(f.rows[4]) + 1)
		flags := uint32(0x101)
		if parent != 0 {
			flags = 0x102
			f.rows[41] = append(f.rows[41], []uint32{rid, parent})
		}
		base := uint32(5)
		if code == 0 {
			base = 0
		}
		f.rows[2] = append(f.rows[2], []uint32{flags, f.str(name), f.str(ns), base, start, 1})
		if code != 0 {
			f.rows[4] = append(f.rows[4], []uint32{0x606, f.str("value__"), f.blob([]byte{6, code})})
		}
	}
	add("Outer+Mode", "External", 7, 0) // TypeDef2: literal plus.
	add("Outer", "External", 0, 0)      // TypeDef3: actual declaring type.
	add("Mode", "", 4, 3)               // TypeDef4: nested separator.
	add("Mode, Other", "External", 9, 0)
	add(`Back\Slash`, "External", 5, 0)
	add("Br[ack]*&et", "External", 10, 0)
	add("Tail,", "External", 11, 0)
	add("Leaf", "Ns+Comma,\\[]", 6, 0)
	return f
}
func TestEscapedEnumNames(t *testing.T) {
	m := escapedEnumFixture().metadata(t)
	other := enumReference(t, "Other", 1, 10, "")
	refs, e := NewReferenceSet(m, other)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ name, want string }{{`External.Outer\+Mode`, "uint16"}, {`External.Outer+Mode`, "int8"}, {`External.Mode\, Other`, "uint32"}, {`External.Back\\Slash`, "uint8"}, {`External.Br\[ack\]\*\&et`, "int64"}, {`External.Tail\,`, "uint64"}, {`Ns\+Comma\,\\\[\].Leaf`, "int16"}} {
		for _, qualified := range []bool{false, true} {
			name := tc.name
			if qualified {
				name += ", Escaped, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
			}
			kind, e := refs.EnumUnderlying(name)
			if e != nil || kind != tc.want {
				t.Fatal(name, kind, e)
			}
		}
		kind, e := m.LocalEnumUnderlying(tc.name)
		if e != nil || kind != tc.want {
			t.Fatal("local escaped enum", tc.name, kind, e)
		}
	}
	if kind, e := refs.EnumUnderlying("External.Mode, Other"); e != nil || kind != "int64" {
		t.Fatal("ordinary assembly separator", kind, e)
	}
	for rid, want := range map[uint32]string{2: `External.Outer\+Mode`, 4: `External.Outer+Mode`, 5: `External.Mode\, Other`, 6: `External.Back\\Slash`} {
		typ, e := m.attributeType(Type{Kind: "valuetype", Token: Token(1<<24 | rid)})
		if e != nil {
			t.Fatal(e)
		}
		if typ.Enum != want+", Escaped, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" {
			t.Fatal("constructor name scope lost", rid, typ.Enum)
		}
		if _, e := refs.EnumUnderlying(typ.Enum); e != nil {
			t.Fatal("constructor name not resolvable", e)
		}
	}
	for _, name := range []string{`External.Mode\`, `External.Mode\q`, `External.Outer++Mode`, `External.Outer+`, `External.Outer\+Mode[]`, `External.Mode\, Other,`, `External.Mode\, Other, Other`} {
		if _, e := refs.EnumUnderlying(name); e == nil {
			t.Fatal("accepted malformed or incorrectly bound name", name)
		}
	}
	// Forwarders use the same identifier grammar, including literal punctuation
	// in a nested name rather than a separator inside that identifier.
	f := newReferenceFixture()
	f.rows[0] = [][]uint32{{0, f.str("Facade.dll"), 0, 0, 0}}
	f.rows[32] = [][]uint32{{0, 1, 0, 0, 0, 0, 0, f.str("Facade"), 0}}
	f.rows[2] = [][]uint32{{0, f.str("<Module>"), 0, 0, 1, 1}}
	f.rows[35] = [][]uint32{{1, 0, 0, 0, 0, 0, f.str("Escaped"), 0, 0}}
	f.rows[39] = [][]uint32{{0x200000, 0, f.str("Outer+Mode"), f.str("External"), 5}, {0x200000, 0, f.str("Outer"), f.str("External"), 5}, {2, 0, f.str("Mode"), 0, 10}, {0x200000, 0, f.str("Mode, Other"), f.str("External"), 5}}
	facade := f.metadata(t)
	forward, _ := NewReferenceSet(facade, m, other)
	for _, tc := range []struct{ name, want string }{{`External.Outer\+Mode, Facade`, "uint16"}, {`External.Outer+Mode, Facade`, "int8"}, {`External.Mode\, Other, Facade`, "uint32"}} {
		kind, e := forward.EnumUnderlying(tc.name)
		if e != nil || kind != tc.want {
			t.Fatal(tc, kind, e)
		}
	}
}

type netmoduleOracle struct {
	Name     string `json:"name"`
	MVID     string `json:"mvid"`
	Assembly bool   `json:"assembly"`
	Files    []struct {
		Name     string `json:"name"`
		Metadata bool   `json:"metadata"`
		Hash     string `json:"hash"`
	} `json:"files"`
	Exports []struct {
		Name           string `json:"name"`
		Namespace      string `json:"namespace"`
		Implementation Token  `json:"implementation"`
		DefinitionID   uint32 `json:"definition_id"`
	} `json:"exports"`
	References []struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Scope     Token  `json:"scope"`
	} `json:"references"`
	Attributes []struct {
		Constructor Token  `json:"constructor"`
		Value       string `json:"value"`
	} `json:"attributes"`
}

func TestCompiledNetmoduleReferences(t *testing.T) {
	if testing.Short() {
		t.Skip("real Roslyn netmodule compiler")
	}
	dotnet, e := exec.LookPath("dotnet")
	if e != nil {
		dotnet = "/usr/local/share/dotnet/dotnet"
		if _, e := os.Stat(dotnet); e != nil {
			t.Skip("dotnet unavailable")
		}
	}
	dir := os.Getenv("MKASM_DOTNET_REFERENCE_ARTIFACTS")
	if dir == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			t.Fatal(e)
		}
		dir = filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/dotnet/references")
	}
	dir = filepath.Join(dir, "Modules")
	if e := os.MkdirAll(dir, 0755); e != nil {
		t.Fatal(e)
	}
	files := map[string]string{
		"Enums.cs":             `namespace Multi { public enum Mode : ushort { Value=0x8123 } public class Outer { public enum Nested : sbyte { Value=-7 } } public sealed class MarkAttribute:System.Attribute { public MarkAttribute(Mode a,Outer.Nested b){} public Mode Named {get;set;} } [Mark(Mode.Value,Outer.Nested.Value,Named=Mode.Value)] public class EnumSubject {} }`,
		"Consumer.cs":          `[Multi.Mark(Multi.Mode.Value,Multi.Outer.Nested.Value,Named=Multi.Mode.Value)] public class ModuleSubject {}`,
		"Manifest.cs":          `[Multi.Mark(Multi.Mode.Value,Multi.Outer.Nested.Value,Named=Multi.Mode.Value)] public class ManifestSubject {}`,
		"Oracle/Oracle.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>`,
		"Oracle/Program.cs": `using System;using System.IO;using System.Linq;using System.Reflection.Metadata;using System.Reflection.Metadata.Ecma335;using System.Reflection.PortableExecutable;using System.Text.Json;
class Program {static void Main(string[] paths){foreach(var path in paths){using var pe=new PEReader(File.OpenRead(path));var m=pe.GetMetadataReader();var module=m.GetModuleDefinition();var result=new {name=m.GetString(module.Name),mvid=m.GetGuid(module.Mvid).ToString(),assembly=m.IsAssembly,files=m.AssemblyFiles.Select(h=>{var f=m.GetAssemblyFile(h);return new{name=m.GetString(f.Name),metadata=f.ContainsMetadata,hash=Convert.ToHexString(m.GetBlobBytes(f.HashValue)).ToLowerInvariant()};}).ToArray(),exports=m.ExportedTypes.Select(h=>{var x=m.GetExportedType(h);return new{name=m.GetString(x.Name),@namespace=m.GetString(x.Namespace),implementation=MetadataTokens.GetToken(x.Implementation),definition_id=x.GetTypeDefinitionId()};}).ToArray(),references=m.TypeReferences.Select(h=>{var x=m.GetTypeReference(h);return new{name=m.GetString(x.Name),@namespace=m.GetString(x.Namespace),scope=MetadataTokens.GetToken(x.ResolutionScope)};}).ToArray(),attributes=m.CustomAttributes.Select(h=>{var x=m.GetCustomAttribute(h);return new{constructor=MetadataTokens.GetToken(x.Constructor),value=Convert.ToHexString(m.GetBlobBytes(x.Value)).ToLowerInvariant()};}).ToArray()};Console.WriteLine(JsonSerializer.Serialize(result));}}}`,
	}
	for path, value := range files {
		p := filepath.Join(dir, path)
		if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(value), 0644); e != nil {
			t.Fatal(e)
		}
	}
	csc := "/usr/local/share/dotnet/sdk/10.0.401/Roslyn/bincore/csc.dll"
	runtimeRef := "/usr/local/share/dotnet/packs/Microsoft.NETCore.App.Ref/10.0.12/ref/net10.0/System.Runtime.dll"
	for _, project := range []struct{ name, target, modules string }{{"Enums", "module", ""}, {"Consumer", "module", "Enums.netmodule"}, {"Manifest", "library", "Enums.netmodule,Consumer.netmodule"}} {
		extension := ".netmodule"
		if project.target == "library" {
			extension = ".dll"
		}
		args := []string{csc, "-nologo", "-noconfig", "-nostdlib+", "-target:" + project.target, "-out:" + project.name + extension, "-reference:" + runtimeRef}
		if project.modules != "" {
			args = append(args, "-addmodule:"+project.modules)
		}
		args = append(args, project.name+".cs")
		cmd := exec.Command(dotnet, args...)
		cmd.Dir = dir
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("real netmodule compiler: %v\n%s", e, b)
		}
	}
	build := exec.Command(dotnet, "build", filepath.Join(dir, "Oracle/Oracle.csproj"), "-c", "Release", "--nologo", "-v:q")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("PEReader oracle build: %v\n%s", e, b)
	}
	names := []string{"Manifest.dll", "Enums.netmodule", "Consumer.netmodule"}
	args := []string{filepath.Join(dir, "Oracle/bin/Release/net10.0/Oracle.dll")}
	for _, name := range names {
		args = append(args, filepath.Join(dir, name))
	}
	oracleBytes, e := exec.Command(dotnet, args...).CombinedOutput()
	if e != nil {
		t.Fatalf("independent PEReader oracle: %v\n%s", e, oracleBytes)
	}
	if e := os.WriteFile(filepath.Join(dir, "oracle.jsonl"), oracleBytes, 0644); e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(strings.TrimSpace(string(oracleBytes)), "\n")
	if len(lines) != 3 {
		t.Fatalf("oracle output %s", oracleBytes)
	}
	modules := make([]*Metadata, 3)
	for i, name := range names {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		image, e := Open(b)
		if e != nil {
			t.Fatal(e)
		}
		modules[i] = image.Metadata
		var oracle netmoduleOracle
		if e := json.Unmarshal([]byte(lines[i]), &oracle); e != nil {
			t.Fatal(e)
		}
		m := image.Metadata
		identity, e := m.ModuleIdentity()
		if e != nil || identity.Name != oracle.Name || identity.MVID != oracle.MVID || (m.Tables[32].Count == 1) != oracle.Assembly {
			t.Fatal("Module identity differs from PEReader", identity, oracle, e)
		}
		for j, file := range oracle.Files {
			row, e := m.Row(38, uint32(j+1))
			if e != nil {
				t.Fatal(e)
			}
			fileName, _ := m.String(row[1])
			hash, _ := m.Blob(row[2])
			if fileName != file.Name || (row[0]&1 == 0) != file.Metadata || hex.EncodeToString(hash) != file.Hash {
				t.Fatal("File differs from PEReader", file, row)
			}
		}
		for j, export := range oracle.Exports {
			row, e := m.Row(39, uint32(j+1))
			if e != nil {
				t.Fatal(e)
			}
			n, _ := m.String(row[2])
			ns, _ := m.String(row[3])
			implementation, _ := DecodeCoded("Implementation", row[4])
			if n != export.Name || ns != export.Namespace || implementation != export.Implementation || row[1] != export.DefinitionID {
				t.Fatal("ExportedType differs from PEReader", export, row)
			}
		}
		for j, reference := range oracle.References {
			row, e := m.Row(1, uint32(j+1))
			if e != nil {
				t.Fatal(e)
			}
			n, _ := m.String(row[1])
			ns, _ := m.String(row[2])
			scope, _ := DecodeCoded("ResolutionScope", row[0])
			if n != reference.Name || ns != reference.Namespace || scope != reference.Scope {
				t.Fatal("TypeRef differs from PEReader", reference, row)
			}
		}
		for j, attribute := range oracle.Attributes {
			row, e := m.Row(12, uint32(j+1))
			if e != nil {
				t.Fatal(e)
			}
			constructor, _ := DecodeCoded("CustomAttributeType", row[1])
			value, _ := m.Blob(row[2])
			if constructor != attribute.Constructor || hex.EncodeToString(value) != attribute.Value {
				t.Fatal("attribute differs from PEReader", attribute)
			}
		}
	}
	manifest, enums, consumer := modules[0], modules[1], modules[2]
	set, e := NewReferenceSet(manifest, enums, consumer)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"Multi.Mode", "Multi.Mode, Manifest"} {
		kind, e := set.EnumUnderlying(name)
		if e != nil || kind != "uint16" {
			t.Fatal(name, kind, e)
		}
	}
	if kind, e := set.EnumUnderlying("Multi.Outer+Nested, Manifest"); e != nil || kind != "int8" {
		t.Fatal(kind, e)
	}
	for _, origin := range modules {
		records, e := set.SerializedAttributes(origin, 0)
		if e != nil {
			t.Fatal(e)
		}
		count := 0
		for _, record := range records {
			if record.Constructor.DeclaringType != "Multi.MarkAttribute" {
				continue
			}
			count++
			v := record.Decoded
			if record.DecodeError != "" || v == nil {
				t.Fatalf("module-context attribute: %+v", record)
			}
			if len(v.Fixed) != 2 || v.Fixed[0].Bits != 0x8123 || v.Fixed[1].Bits != 0xf9 || len(v.Named) != 1 || v.Named[0].Value.Bits != 0x8123 {
				t.Fatalf("module-context enum values %+v", v)
			}
			if v.Fixed[0].Type.EnumModule == nil || v.Fixed[0].Type.EnumModule.Name != "Enums.netmodule" || !strings.Contains(v.Fixed[0].Type.Enum, ", Manifest,") {
				t.Fatal("lost assembly/module identity", v.Fixed[0].Type)
			}
		}
		if count != 1 {
			t.Fatal("module attribute missing", count)
		}
	}
	// The callback-only API deliberately cannot interpret a ModuleRef token.
	attrs, e := consumer.Attributes(0)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range attrs {
		if a.Constructor.DeclaringType == "Multi.MarkAttribute" {
			if _, e := consumer.DecodeAttribute(a, set.EnumUnderlying); e == nil {
				t.Fatal("legacy callback guessed ModuleRef scope")
			}
		}
	}
	localSet, e := NewReferenceSet(consumer, manifest, enums)
	if e != nil {
		t.Fatal(e)
	}
	if kind, e := localSet.EnumUnderlying("Multi.Mode"); e != nil || kind != "uint16" {
		t.Fatal("unqualified serialized name must use known owning assembly", kind, e)
	}
	if kind, e := localSet.EnumUnderlying("Multi.Mode, Manifest"); e != nil || kind != "uint16" {
		t.Fatal(kind, e)
	}
	securityType := "Multi.Mode"
	payload := []byte{1, 0x54, 0x55, byte(len(securityType))}
	payload = append(payload, securityType...)
	payload = append(payload, 1, 'E', 0x23, 0x81)
	security := []byte{'.', 1, 1, 'X', byte(len(payload))}
	security = append(security, payload...)
	decl, e := set.DecodeSecurity(consumer, security)
	if e != nil || decl.Attributes[0].Named[0].Value.Bits != 0x8123 {
		t.Fatal("module-context security enum", decl, e)
	}
	missing, _ := NewReferenceSet(manifest, consumer)
	if _, e := missing.EnumUnderlying("Multi.Mode, Manifest"); e == nil {
		t.Fatal("missing File module guessed")
	}
	t.Logf("Roslyn: two real netmodules + manifest; PEReader module/MVID/File/ExportedType/TypeRef/blob oracle matched; context-scoped attributes verified: %s", dir)
}

func netmoduleFixture(name string, storage byte) *referenceFixture {
	f := newReferenceFixture()
	f.guids = []byte{4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16}
	f.rows[0] = [][]uint32{{0, f.str(name), 1, 0, 0}}
	f.rows[35] = [][]uint32{{4, 0, 0, 0, 0, 0, f.str("System.Runtime"), 0, 0}}
	f.rows[1] = [][]uint32{{6, f.str("Enum"), f.str("System")}}
	f.rows[2] = [][]uint32{{0, f.str("<Module>"), 0, 0, 1, 1}, {0x101, f.str("Mode"), f.str("External"), 5, 1, 1}}
	f.rows[4] = [][]uint32{{0x606, f.str("value__"), f.blob([]byte{6, storage})}}
	return f
}
func moduleManifestFixture(name, fileName string, hint uint32, flags uint32) *referenceFixture {
	f := newReferenceFixture()
	f.rows[0] = [][]uint32{{0, f.str(name + ".dll"), 0, 0, 0}}
	f.rows[32] = [][]uint32{{0, 1, 0, 0, 0, 0, 0, f.str(name), 0}}
	f.rows[2] = [][]uint32{{0, f.str("<Module>"), 0, 0, 1, 1}}
	f.rows[38] = [][]uint32{{flags, f.str(fileName), f.blob([]byte{1, 2, 3})}}
	f.rows[39] = [][]uint32{{1, hint, f.str("Mode"), f.str("External"), 4}}
	return f
}
func TestNetmoduleBindingBoundaries(t *testing.T) {
	module := netmoduleFixture("Enums.netmodule", 7).metadata(t)
	manifest := moduleManifestFixture("Manifest", "Enums.netmodule", 0x02000002, 0).metadata(t)
	set, e := NewReferenceSet(manifest, module)
	if e != nil {
		t.Fatal(e)
	}
	id, e := module.ModuleIdentity()
	if e != nil || id.Name != "Enums.netmodule" || id.MVID != "01020304-0506-0708-090a-0b0c0d0e0f10" {
		t.Fatal(id, e)
	}
	if kind, e := set.EnumUnderlying("External.Mode, Manifest"); e != nil || kind != "uint16" {
		t.Fatal(kind, e)
	}
	// File hashes deliberately remain unverified for metadata-only explicit inputs.
	if owner, e := set.moduleOwner(module); e != nil || owner != manifest {
		t.Fatal("manifest identity lost", e)
	}
	duplicateFixture := netmoduleFixture("Enums.netmodule", 4)
	duplicateFixture.guids[0]++
	duplicate := duplicateFixture.metadata(t)
	ambiguous, _ := NewReferenceSet(manifest, module, duplicate)
	if _, e := ambiguous.EnumUnderlying("External.Mode, Manifest"); e == nil {
		t.Fatal("same-name netmodule ambiguity guessed")
	}
	if e := ambiguous.BindModule(manifest, Token(38<<24|1), module); e != nil {
		t.Fatal(e)
	}
	if kind, e := ambiguous.EnumUnderlying("External.Mode, Manifest"); e != nil || kind != "uint16" {
		t.Fatal(kind, e)
	}
	if e := ambiguous.BindModule(manifest, Token(38<<24|1), duplicate); e == nil {
		t.Fatal("conflicting explicit File binding accepted")
	}
	alias := moduleManifestFixture("Alias", "renamed.bin", 2, 0).metadata(t)
	explicit, _ := NewReferenceSet(alias, module)
	if _, e := explicit.EnumUnderlying("External.Mode, Alias"); e == nil {
		t.Fatal("guessed filename/module name mismatch")
	}
	if e := explicit.BindModule(alias, Token(38<<24|1), module); e != nil {
		t.Fatal(e)
	}
	if kind, e := explicit.EnumUnderlying("External.Mode, Alias"); e != nil || kind != "uint16" {
		t.Fatal(kind, e)
	}
	if target, e := explicit.scopeModule(alias, alias, "Enums.netmodule"); e != nil || target != module {
		t.Fatal("ModuleRef metadata name not retained", e)
	}
	if _, e := explicit.scopeModule(alias, alias, "renamed.bin"); e == nil {
		t.Fatal("File alias confused with Module.Name")
	}
	other := moduleManifestFixture("Other", "Enums.netmodule", 2, 0).metadata(t)
	twoOwners, _ := NewReferenceSet(manifest, module, other)
	if _, e := twoOwners.EnumUnderlyingIn(module, "External.Mode"); e == nil {
		t.Fatal("ambiguous owning assembly guessed")
	}
	stale := moduleManifestFixture("Stale", "Enums.netmodule", 1, 0).metadata(t)
	staleSet, _ := NewReferenceSet(stale, module)
	if _, e := staleSet.EnumUnderlying("External.Mode, Stale"); e == nil {
		t.Fatal("incorrect ExportedType TypeDefId accepted")
	}
	nonmetadata := moduleManifestFixture("Resource", "Enums.netmodule", 2, 1).metadata(t)
	resourceSet, _ := NewReferenceSet(nonmetadata, module)
	if _, e := resourceSet.EnumUnderlying("External.Mode, Resource"); e == nil {
		t.Fatal("nonmetadata File treated as module")
	}
	if e := resourceSet.BindModule(nonmetadata, Token(38<<24|1), module); e == nil {
		t.Fatal("nonmetadata binding accepted")
	}
	cycleFixture := moduleManifestFixture("Cycle", "Enums.netmodule", 2, 0)
	cycleFixture.rows[39][0][4] = 6
	cycle := cycleFixture.metadata(t)
	cycleSet, _ := NewReferenceSet(cycle, module)
	if _, e := cycleSet.EnumUnderlying("External.Mode, Cycle"); e == nil {
		t.Fatal("ExportedType cycle accepted")
	}
	standalone, _ := NewReferenceSet(module)
	if kind, e := standalone.EnumUnderlying("External.Mode"); e != nil || kind != "uint16" {
		t.Fatal("standalone local netmodule enum", kind, e)
	}
	if _, e := standalone.scopeModule(module, nil, "Other.netmodule"); e == nil {
		t.Fatal("ModuleRef ownership guessed")
	}
}

func TestClosedGenericEnumDefinitions(t *testing.T) {
	f := newReferenceFixture()
	f.rows[0] = [][]uint32{{0, f.str("Generic.dll"), 0, 0, 0}}
	f.rows[32] = [][]uint32{{0, 1, 0, 0, 0, 0, 0, f.str("Generic"), 0}}
	f.rows[35] = [][]uint32{{4, 0, 0, 0, 0, 0, f.str("System.Runtime"), 0, 0}}
	f.rows[1] = [][]uint32{{6, f.str("Enum"), f.str("System")}}
	f.rows[2] = [][]uint32{{0, f.str("<Module>"), 0, 0, 1, 1}, {1, f.str("Outer`1"), f.str("External"), 0, 1, 1}, {0x102, f.str("Mode"), 0, 5, 1, 1}}
	f.rows[4] = [][]uint32{{0x606, f.str("value__"), f.blob([]byte{6, 5})}}
	f.rows[41] = [][]uint32{{3, 2}}
	f.rows[42] = [][]uint32{{0, 0, 4, f.str("T")}, {0, 0, 6, f.str("T")}}
	m := f.metadata(t)
	refs, e := NewReferenceSet(m)
	if e != nil {
		t.Fatal(e)
	}
	if kind, e := m.LocalEnumUnderlying("External.Outer`1+Mode[System.Int32]"); e != nil || kind != "uint8" {
		t.Fatal("local closed enum", kind, e)
	}
	for _, name := range []string{"External.Outer`1+Mode[System.Int32]", "External.Outer`1+Mode[[System.Int32]]", "External.Outer`1+Mode[System.Int32[]]", "External.Outer`1+Mode[System.Int32[,]]", "External.Outer`1+Mode[System.Int32[*]]", "External.Outer`1+Mode[[External.Outer`1[System.String], Generic]], Generic"} {
		if kind, e := refs.EnumUnderlying(name); e != nil || kind != "uint8" {
			t.Fatal(name, kind, e)
		}
	}
	for _, name := range []string{"External.Outer`1+Mode", "External.Outer`1+Mode[System.Int32,System.String]", "External.Outer`1+Mode[[System.Int32],]", "External.Outer`1+Mode[System.Int32]x", "External.Outer`1+Mode[System.Void]", "External.Outer`1+Mode[[System.Int32, Missing]]", "External.Outer`1+Mode[T]", "External.Outer`1+Mode[!0]", "External.Outer`1+Mode[System.Int32&]", "External.Outer`1[System.Int32]"} {
		if _, e := refs.EnumUnderlying(name); e == nil {
			t.Fatal("invalid/open generic enum accepted", name)
		}
	}
	for _, argument := range []Type{{Kind: "int32"}, {Kind: "szarray", Args: []Type{{Kind: "int32"}}}, {Kind: "array", Rank: 2, Args: []Type{{Kind: "int32"}}}} {
		signature := Type{Kind: "genericinst", Args: []Type{{Kind: "valuetype", Token: Token(2<<24 | 3)}, argument}}
		typ, e := refs.referenceAttributeType(m, signature)
		if e != nil || len(typ.EnumArguments) != 1 {
			t.Fatal(typ, e)
		}
		if kind, e := refs.resolveSerializedEnum(m, typ); e != nil || kind != "uint8" {
			t.Fatal(typ, kind, e)
		}
		legacy, e := m.attributeType(signature)
		if e != nil {
			t.Fatal(e)
		}
		if kind, e := refs.EnumUnderlying(legacy.Enum); e != nil || kind != "uint8" {
			t.Fatal(legacy, kind, e)
		}
	}
}
