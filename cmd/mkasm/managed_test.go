package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedAssemblyInspection(t *testing.T) {
	for _, name := range []string{"anycpu.dll", "x86.exe", "x64.dll", "embedded.dll"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "pkg", "dotnet", "testdata", name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := run(context.Background(), []string{"--arch", ".NET", "--inspect", "--json", "-"}, bytes.NewReader(data), &out, io.Discard); err != nil {
				t.Fatal(err)
			}
			var report managedReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Schema != "mkasm.managed-report.v1" || len(report.Types) < 2 || len(report.Methods) < 10 {
				t.Fatal("missing managed metadata")
			}
			bodies, references := 0, 0
			for _, method := range report.Methods {
				if method.Kind != "cil" {
					if method.Body != nil {
						t.Fatal("non-CIL method was decoded as IL")
					}
					continue
				}
				if method.Body == nil || len(method.Body.Instructions) == 0 {
					t.Fatalf("missing body %s", method.FullName)
				}
				bodies++
				references += len(method.References)
			}
			if bodies < 5 || references < 5 {
				t.Fatal("inspection omitted methods or resolved token references")
			}
			if len(report.Resources) != 1 || string(report.Resources[0].Data) != "managed resource ✓\n" || len(report.Attributes) == 0 {
				t.Fatal("inspection omitted resources or custom attributes")
			}
			if len(report.Properties) == 0 || len(report.Events) == 0 {
				t.Fatal("inspection omitted properties or events")
			}
			decoded := 0
			for _, a := range report.Attributes {
				if a.Constructor.DeclaringType == "ManagedFixture.MarkAttribute" {
					if a.Decoded == nil || a.DecodeError != "" || a.Decoded.Named[0].Value.Bits != 17 {
						t.Fatal("missing structured attribute")
					}
					decoded++
				}
			}
			if decoded != 1 || len(report.Marshaling) == 0 || report.Marshaling[0].Decoded == nil {
				t.Fatal("missing structured serialized metadata")
			}
			if name == "embedded.dll" && (report.Symbols == nil || len(report.Symbols.Documents) == 0 || len(report.Symbols.Methods) == 0) {
				t.Fatal("inspection omitted embedded Portable PDB")
			}
		})
	}
	var out bytes.Buffer
	if err := inspectManaged(context.Background(), "-", bytes.NewReader([]byte("MZ")), &out); err == nil || out.Len() != 0 {
		t.Fatal("malformed managed input produced a report")
	}
	for _, args := range [][]string{
		{"--arch", "x86_64", "--inspect", "--json", "-"},
		{"--arch", "cil", "--inspect", "--codegen", "rust", "--output", t.TempDir(), "-"},
		{"--arch", "cil", "--inspect", "--cpu", "unknown", "--json", "-"},
		{"--list-architectures", "--inspect"},
	} {
		if err := run(context.Background(), args, bytes.NewReader(nil), io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted invalid inspection mode: %v", args)
		}
	}
}

func TestManagedCLIRewriteAndVerification(t *testing.T) {
	path := filepath.Join("..", "..", "pkg", "dotnet", "testdata", "anycpu.dll")
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	im, e := dotnet.Open(b)
	if e != nil {
		t.Fatal(e)
	}
	methods, e := im.Metadata.Methods()
	if e != nil {
		t.Fatal(e)
	}
	var token dotnet.Token
	for _, m := range methods {
		if m.Name == "Optional" {
			token = m.Token
		}
	}
	if token == 0 {
		t.Fatal("missing fixture method")
	}
	dir := t.TempDir()
	manifest, output := filepath.Join(dir, "edits.json"), filepath.Join(dir, "changed.dll")
	if e = os.WriteFile(manifest, []byte(fmt.Sprintf(`{"0x%08x":"0e1f2a2a"}`, uint32(token))), 0600); e != nil {
		t.Fatal(e)
	}
	if e = run(context.Background(), []string{"--arch", "cil", "--rewrite", manifest, "--output", output, path}, nil, io.Discard, io.Discard); e != nil {
		t.Fatal(e)
	}
	changed, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	next, e := dotnet.Open(changed)
	if e != nil {
		t.Fatal(e)
	}
	body, e := next.MethodBody(token)
	if e != nil || !bytes.Equal(body.IL, []byte{0x1f, 42, 0x2a}) {
		t.Fatal(body, e)
	}
	var out bytes.Buffer
	if e = run(context.Background(), []string{"--arch", "cil", "--inspect", "--verify", "--json", output}, nil, &out, io.Discard); e != nil {
		t.Fatal(e)
	}
	var report managedReport
	if e = json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	for _, m := range report.Methods {
		if m.Kind == "cil" && m.Stack == nil {
			t.Fatal("missing stack analysis", m.FullName)
		}
	}
	// A failed replacement must leave the already published output intact.
	if e = os.WriteFile(manifest, []byte(fmt.Sprintf(`{"0x%08x":"062a"}`, uint32(token))), 0600); e != nil {
		t.Fatal(e)
	}
	if e = run(context.Background(), []string{"--arch", "cil", "--rewrite", manifest, "--output", output, path}, nil, io.Discard, io.Discard); e == nil {
		t.Fatal("accepted invalid replacement stack")
	}
	after, e := os.ReadFile(output)
	if e != nil || !bytes.Equal(changed, after) {
		t.Fatal("failed rewrite changed output", e)
	}
	for _, manifestText := range []string{
		fmt.Sprintf(`{"0x%08x":"0e1f2a2a","0x%08x":"0e1f2b2a"}`, uint32(token), uint32(token)),
		fmt.Sprintf(`{"0x%08x":"0e1f2a2a","%d":"0e1f2b2a"}`, uint32(token), uint32(token)),
		fmt.Sprintf(`{"0x%08x":"0e1f2a2a"} {}`, uint32(token)),
	} {
		if e = os.WriteFile(manifest, []byte(manifestText), 0600); e != nil {
			t.Fatal(e)
		}
		if e = run(context.Background(), []string{"--arch", "cil", "--rewrite", manifest, "--output", output, path}, nil, io.Discard, io.Discard); e == nil {
			t.Fatal("accepted ambiguous rewrite manifest", manifestText)
		}
	}
}

func TestManagedCLICompositeNativeInspection(t *testing.T) {
	path := filepath.Join("..", "..", "pkg", "dotnet", "testdata", "composite-pe.dll")
	var out bytes.Buffer
	if e := run(context.Background(), []string{"--arch", "cil", "--inspect", "--native", "--json", path}, nil, &out, io.Discard); e != nil {
		t.Fatal(e)
	}
	var report managedReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	if !report.Image.Composite || report.Image.HasMetadata || len(report.Components) != 1 || len(report.NativeFunctions) != 2 || len(report.NativeFunctions[0].ComponentMethods) != 1 {
		t.Fatal("missing composite scopes")
	}
}

func TestManagedExplicitReferences(t *testing.T) {
	fixture := filepath.Join("..", "..", "pkg", "dotnet", "testdata", "anycpu.dll")
	var out bytes.Buffer
	if e := run(context.Background(), []string{"--arch", "cil", "--inspect", "--json", "--references", fixture, fixture}, nil, &out, io.Discard); e != nil {
		t.Fatal(e)
	}
	if _, e := loadManagedReferences([]string{filepath.Join(t.TempDir(), "missing*.dll")}, &dotnet.Metadata{}); e == nil {
		t.Fatal("missing references ignored")
	}
	dir := os.Getenv("MKASM_DOTNET_REFERENCE_ARTIFACTS")
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "Client/bin/Release/net10.0/Client.dll")
	refs := []string{}
	for _, name := range []string{"First", "Second", "Facade"} {
		refs = append(refs, filepath.Join(dir, name, "obj/Release/net10.0/ref", name+".dll"))
	}
	refs = append(refs, filepath.Join(dir, "Generic/System.Runtime.dll"))
	out.Reset()
	if e := run(context.Background(), []string{"--arch", "cil", "--inspect", "--json", "--references", strings.Join(refs, ","), path}, nil, &out, io.Discard); e != nil {
		t.Fatal(e)
	}
	var report managedReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	matched, generic := 0, 0
	for _, a := range report.Attributes {
		if a.Constructor.DeclaringType == "External.GenericMarkAttribute" {
			if a.Decoded == nil || a.DecodeError != "" || len(a.Decoded.Fixed) != 2 || a.Decoded.Fixed[0].Bits != 0x82 || len(a.Decoded.Fixed[1].Elements) != 1 || a.Decoded.Fixed[1].Elements[0].Bits != 0x82 || !strings.Contains(a.Decoded.Fixed[0].Type.Enum, "GenericOuter`1+Mode") || len(a.Decoded.Fixed[0].Type.EnumArguments) != 1 {
				t.Fatal("generic nested enum lost", a)
			}
			generic++
		}
		if a.Constructor.DeclaringType != "External.MarkAttribute" {
			continue
		}
		if a.Decoded == nil || a.DecodeError != "" || a.Decoded.Fixed[0].Bits != 0x8123 || a.Decoded.Named[0].Value.Bits != 0x8123 {
			t.Fatal("external enum lost", a)
		}
		matched++
	}
	if matched != 1 || generic != 1 {
		t.Fatal("reference-backed attribute omitted", matched, generic)
	}
}

func TestManagedCLIRealTypeVerification(t *testing.T) {
	verifier, refs, path := os.Getenv("MKASM_ILVERIFY"), os.Getenv("MKASM_DOTNET_REFERENCES"), os.Getenv("MKASM_DOTNET_TYPE_IMAGE")
	if verifier == "" || refs == "" || path == "" {
		t.Skip("set MKASM_ILVERIFY, MKASM_DOTNET_REFERENCES and MKASM_DOTNET_TYPE_IMAGE")
	}
	args := []string{"--arch", "cil", "--inspect", "--json", "--type-verifier", verifier, "--references", refs, path}
	var out bytes.Buffer
	if e := run(context.Background(), args, nil, &out, io.Discard); e != nil {
		t.Fatal(e)
	}
	var report managedReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	if report.TypeVerification == nil || !report.TypeVerification.Verified {
		t.Fatal("missing real verifier result")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	image, e := dotnet.Open(b)
	if e != nil {
		t.Fatal(e)
	}
	methods, e := image.Metadata.Methods()
	if e != nil {
		t.Fatal(e)
	}
	var token dotnet.Token
	for _, m := range methods {
		if m.Name == "Value" {
			token = m.Token
		}
	}
	if token == 0 {
		t.Fatal("missing type-check method")
	}
	bad, e := image.RewriteMethods(map[dotnet.Token][]byte{token: {10, 0x14, 0x2a}}, dotnet.RewriteOptions{})
	if e != nil {
		t.Fatal(e)
	}
	badPath := filepath.Join(t.TempDir(), "invalid.dll")
	if e = os.WriteFile(badPath, bad, 0600); e != nil {
		t.Fatal(e)
	}
	args[len(args)-1] = badPath
	out.Reset()
	if e = run(context.Background(), args, nil, &out, io.Discard); e == nil || out.Len() != 0 {
		t.Fatal("invalid return type accepted or report published", e)
	}
}

func TestManagedNetmoduleInspection(t *testing.T) {
	dir := os.Getenv("MKASM_DOTNET_REFERENCE_ARTIFACTS")
	if dir == "" {
		t.Skip("set MKASM_DOTNET_REFERENCE_ARTIFACTS to the compiled reference fixtures")
	}
	dir = filepath.Join(dir, "Modules")
	paths := []string{}
	for _, name := range []string{"Manifest.dll", "Enums.netmodule", "Consumer.netmodule"} {
		paths = append(paths, filepath.Join(dir, name))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			var out bytes.Buffer
			if e := run(context.Background(), []string{"--arch", "cil", "--inspect", "--verify", "--json", "--references", strings.Join(paths, ","), path}, nil, &out, io.Discard); e != nil {
				t.Fatal(e)
			}
			var report managedReport
			if e := json.Unmarshal(out.Bytes(), &report); e != nil {
				t.Fatal(e)
			}
			matched := 0
			for _, attribute := range report.Attributes {
				if attribute.Constructor.DeclaringType != "Multi.MarkAttribute" {
					continue
				}
				matched++
				value := attribute.Decoded
				if attribute.DecodeError != "" || value == nil || len(value.Fixed) != 2 || value.Fixed[0].Bits != 0x8123 || value.Fixed[1].Bits != 0xf9 || len(value.Named) != 1 || value.Named[0].Value.Bits != 0x8123 {
					t.Fatalf("lost module-scoped enum values: %+v", attribute)
				}
				if value.Fixed[0].Type.EnumModule == nil || value.Fixed[0].Type.EnumModule.Name != "Enums.netmodule" || !strings.Contains(value.Fixed[0].Type.Enum, ", Manifest,") {
					t.Fatal("lost module/assembly identity", value.Fixed[0].Type)
				}
			}
			if matched != 1 {
				t.Fatalf("got %d module attributes", matched)
			}
		})
	}
}

func TestManagedExplicitModuleFileBindings(t *testing.T) {
	dir := os.Getenv("MKASM_DOTNET_REFERENCE_ARTIFACTS")
	if dir == "" {
		t.Skip("set MKASM_DOTNET_REFERENCE_ARTIFACTS to the compiled reference fixtures")
	}
	dir = filepath.Join(dir, "Modules")
	dotnetPath, err := exec.LookPath("dotnet")
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	source, err := os.ReadFile(filepath.Join(dir, "Enums.cs"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte("0x8123")) {
		t.Fatal("missing enum value in compiler fixture")
	}
	if err = os.WriteFile(filepath.Join(other, "Enums.cs"), bytes.ReplaceAll(source, []byte("0x8123"), []byte("0x8234")), 0600); err != nil {
		t.Fatal(err)
	}
	csc := "/usr/local/share/dotnet/sdk/10.0.401/Roslyn/bincore/csc.dll"
	runtimeRef := "/usr/local/share/dotnet/packs/Microsoft.NETCore.App.Ref/10.0.12/ref/net10.0/System.Runtime.dll"
	for _, args := range [][]string{
		{"-target:module", "-out:Enums.netmodule", "Enums.cs"},
		{"-target:library", "-out:Other.dll", "-addmodule:Enums.netmodule", filepath.Join(dir, "Manifest.cs")},
	} {
		cmd := exec.Command(dotnetPath, append([]string{csc, "-nologo", "-noconfig", "-nostdlib+", "-reference:" + runtimeRef}, args...)...)
		cmd.Dir = other
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("real netmodule compiler: %v\n%s", err, out)
		}
	}
	manifest := filepath.Join(dir, "Manifest.dll")
	otherManifest := filepath.Join(other, "Other.dll")
	module := filepath.Join(dir, "Enums.netmodule")
	otherModule := filepath.Join(other, "Enums.netmodule")
	references := []string{manifest, module, otherManifest, otherModule}
	inspect := func(input string, refs []string) managedReport {
		t.Helper()
		var out bytes.Buffer
		if err := run(context.Background(), []string{"--arch", "cil", "--inspect", "--json", "--references", strings.Join(refs, ","), input}, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var report managedReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}
	attribute := func(report managedReport) dotnet.AttributeRecord {
		t.Helper()
		for _, a := range report.Attributes {
			if a.Constructor.DeclaringType == "Multi.MarkAttribute" {
				return a
			}
		}
		t.Fatal("missing module attribute")
		return dotnet.AttributeRecord{}
	}
	var mvids []string
	for _, tc := range []struct {
		input string
		value uint64
	}{{manifest, 0x8123}, {otherManifest, 0x8234}} {
		a := attribute(inspect(tc.input, references))
		if a.DecodeError != "" || a.Decoded == nil {
			t.Fatal("manifest-scoped module binding failed", a.DecodeError)
		}
		value := a.Decoded.Fixed[0]
		if value.Bits != tc.value || value.Type.EnumModule == nil || value.Type.EnumModule.Name != "Enums.netmodule" {
			t.Fatal("module identity or enum value lost", value)
		}
		mvids = append(mvids, value.Type.EnumModule.MVID)
	}
	if mvids[0] == mvids[1] {
		t.Fatal("independently compiled modules must retain distinct MVIDs")
	}
	// Filename-only guesses across directories remain errors when no supplied
	// path associates either module with this manifest's directory.
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	isolated := filepath.Join(t.TempDir(), "Manifest.dll")
	if err = os.WriteFile(isolated, data, 0600); err != nil {
		t.Fatal(err)
	}
	a := attribute(inspect(isolated, []string{module, otherModule}))
	if a.Decoded != nil || !strings.Contains(a.DecodeError, "ambiguous") {
		t.Fatal("unassociated same-name modules were guessed", a.DecodeError)
	}
	// Identical metadata supplied through another explicit path is one identity.
	data, err = os.ReadFile(module)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "Enums.netmodule")
	if err = os.WriteFile(alias, data, 0600); err != nil {
		t.Fatal(err)
	}
	a = attribute(inspect(manifest, append(references, alias)))
	if a.DecodeError != "" || a.Decoded == nil || a.Decoded.Fixed[0].Bits != 0x8123 {
		t.Fatal("duplicate input bytes created a false ambiguity", a.DecodeError)
	}
}

func TestPortablePDBCLIInspection(t *testing.T) {
	for _, name := range []string{"anycpu.pdb", "x86.pdb", "x64.pdb"} {
		var out bytes.Buffer
		path := filepath.Join("..", "..", "pkg", "dotnet", "testdata", name)
		if err := run(context.Background(), []string{"--arch", "cil", "--inspect", "--json", path}, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var report managedReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Image.Format != "portable-pdb" || report.Symbols == nil || len(report.Symbols.Documents) == 0 {
			t.Fatal("missing Portable PDB documents")
		}
		points := 0
		for _, method := range report.Symbols.Methods {
			points += len(method.SequencePoints)
		}
		if points == 0 {
			t.Fatal("missing Portable PDB sequence points")
		}
	}
}
