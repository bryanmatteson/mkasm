package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/cil"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
)

// Test the actual executable's public JSON and rewrite workflows against a live
// Microsoft PEReader/PortablePDB reader and a real CLR consumer.
func TestIndependentManagedCLIReference(t *testing.T) {
	cli := os.Getenv("MKASM_REFERENCE_CLI")
	if cli == "" {
		t.Skip("set MKASM_REFERENCE_CLI to the current built mkasm executable")
	}
	dotnetTool, err := exec.LookPath("dotnet")
	if err != nil {
		t.Skip(".NET SDK unavailable")
	}
	dir := t.TempDir()
	var rustReference strings.Builder
	rustReference.WriteString("use mkasm_cil::{dotnet::*,*};\nfn hex(b:&[u8])->String{b.iter().map(|v|format!(\"{v:02x}\")).collect()}\n#[test]fn live_microsoft_metadata_reference(){\n")
	fixtures, err := filepath.Abs("../../pkg/dotnet/testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Oracle.cs", "Oracle.csproj", "global.json"} {
		data, err := os.ReadFile(filepath.Join(fixtures, "source", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.Command(dotnetTool, "build", "Oracle.csproj", "-c", "Release", "-o", filepath.Join(dir, "oracle"), "--nologo", "-v:q")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Microsoft metadata reference: %v\n%s", err, out)
	}
	oracle := func(path string, result any) {
		t.Helper()
		out, err := exec.Command(dotnetTool, filepath.Join(dir, "oracle", "Oracle.dll"), path).Output()
		if err != nil {
			t.Fatal("Microsoft metadata reference: ", err)
		}
		if err := json.Unmarshal(out, result); err != nil {
			t.Fatal(err)
		}
	}
	inspect := func(path string) managedReport {
		t.Helper()
		out, err := exec.Command(cli, "--arch", "cil", "--inspect", "--json", path).Output()
		if err != nil {
			t.Fatal("CLI inspection: ", err)
		}
		var report managedReport
		if err := json.Unmarshal(out, &report); err != nil {
			t.Fatal(err)
		}
		if report.Schema != "mkasm.managed-report.v1" || report.Architecture != "cil" {
			t.Fatal("unexpected CLI report identity")
		}
		return report
	}
	type oracleMethod struct {
		Token            dotnet.Token
		Name             string
		RVA, Flags, Impl uint32
		Raw              *string
		MaxStack         *uint16 `json:"max_stack"`
		Local            dotnet.Token
	}
	type imageReference struct {
		Format  string
		Machine uint16
		Rows    []uint32
		Types   []struct {
			Token           dotnet.Token
			Name, Ns        string
			Methods, Fields []dotnet.Token
		}
		Methods []oracleMethod
	}
	var optional dotnet.Token
	methodCount := 0
	for _, name := range []string{"anycpu.dll", "x86.exe", "x64.dll", "embedded.dll"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(fixtures, name)
			var expected imageReference
			oracle(path, &expected)
			actual := inspect(path)
			fmt.Fprintf(&rustReference, "{let image=Image::open(include_bytes!(%q)).unwrap();assert_eq!(image.machine,%d);\n", "fixtures/"+name, expected.Machine)
			if actual.Image == nil || actual.Image.Metadata == nil || actual.Image.Format != strings.ReplaceAll(expected.Format, "PE32Plus", "PE32+") || actual.Image.Machine != expected.Machine {
				t.Fatal("CLI PE header differs from PEReader")
			}
			for n, rows := range expected.Rows {
				fmt.Fprintf(&rustReference, "assert_eq!(image.metadata.tables[%d].count,%d);\n", n, rows)
				if actual.Image.Metadata.Tables[n].Count != rows {
					t.Fatalf("table %d: CLI %d, PEReader %d", n, actual.Image.Metadata.Tables[n].Count, rows)
				}
			}
			if len(actual.Types) != len(expected.Types) || len(actual.Methods) != len(expected.Methods) {
				t.Fatal("CLI type/method count differs from PEReader")
			}
			fmt.Fprintf(&rustReference, "assert_eq!(image.metadata.types().unwrap().len(),%d);assert_eq!(image.metadata.methods().unwrap().len(),%d);\n", len(expected.Types), len(expected.Methods))
			for n, want := range expected.Types {
				got := actual.Types[n]
				if got.Token != want.Token || got.Name != want.Name || got.Namespace != want.Ns || !slices.Equal(got.Methods, want.Methods) || !slices.Equal(got.Fields, want.Fields) {
					t.Fatal("CLI type differs from PEReader: ", want.Token)
				}
			}
			for n, want := range expected.Methods {
				fmt.Fprintf(&rustReference, "{let method=image.metadata.method(Token(%d)).unwrap();assert_eq!(method.name,%q);assert_eq!(method.rva,%d);", want.Token, want.Name, want.RVA)
				got := actual.Methods[n]
				if got.Token != want.Token || got.Name != want.Name || got.RVA != want.RVA || got.Flags != want.Flags || got.ImplFlags != want.Impl {
					t.Fatal("CLI method differs from PEReader: ", want.Token)
				}
				if name == "anycpu.dll" && want.Name == "Optional" {
					optional = want.Token
				}
				if want.Raw == nil {
					rustReference.WriteString("assert_ne!(method.kind,\"cil\");}\n")
					if got.Body != nil {
						t.Fatal("CLI invented a CIL body: ", want.Token)
					}
					continue
				}
				if got.Body == nil || want.MaxStack == nil || got.Body.MaxStack != *want.MaxStack || got.Body.LocalSignatureToken != uint32(want.Local) {
					t.Fatal("CLI CIL body header differs from PEReader: ", want.Token)
				}
				body, err := cil.Default().EncodeMethodBody(got.Body)
				if err != nil || hex.EncodeToString(body) != *want.Raw {
					t.Fatalf("CLI instructions/EH differ from PEReader %s: %x != %s (%v)", want.Token, body, *want.Raw, err)
				}
				fmt.Fprintf(&rustReference, "let body=image.method_body(method.token).unwrap();assert_eq!(hex(body.raw),%q);assert_eq!(body.max_stack,%d);assert_eq!(body.local_signature,Token(%d));let decoded=inspect_managed_method(&image,method.token).unwrap().body.unwrap();assert_eq!(hex(&encode_method_body(&decoded).unwrap()),%q);verify_managed_method(&image,method.token).unwrap();}\n", *want.Raw, *want.MaxStack, want.Local, *want.Raw)
				methodCount++
			}
			rustReference.WriteString("}\n")
		})
	}
	for _, name := range []string{"anycpu.pdb", "x86.pdb", "x64.pdb"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(fixtures, name)
			var expected struct {
				Rows      []uint32
				Documents []managedDocument
				Methods   []struct {
					Token  dotnet.Token
					Points []dotnet.SequencePoint
				}
			}
			oracle(path, &expected)
			actual := inspect(path)
			fmt.Fprintf(&rustReference, "{let image=Image::open(include_bytes!(%q)).unwrap();\n", "fixtures/"+name)
			if actual.Symbols == nil || !reflect.DeepEqual(actual.Symbols.Documents, expected.Documents) || len(actual.Symbols.Methods) != len(expected.Methods) {
				t.Fatal("CLI Portable PDB identity differs from Microsoft reader")
			}
			for n, count := range expected.Rows {
				fmt.Fprintf(&rustReference, "assert_eq!(image.metadata.tables[%d].count,%d);\n", n, count)
				if actual.Image.Metadata.Tables[n].Count != count {
					t.Fatal("CLI Portable PDB row count differs: ", n)
				}
			}
			for _, document := range expected.Documents {
				fmt.Fprintf(&rustReference, "assert_eq!(image.metadata.document_name(%d).unwrap(),%q);\n", document.Token.RID(), document.Name)
			}
			for n, want := range expected.Methods {
				got := actual.Symbols.Methods[n]
				if got.Token != want.Token || !slices.Equal(got.SequencePoints, want.Points) {
					t.Fatal("CLI sequence points differ from Microsoft reader: ", want.Token)
				}
				fmt.Fprintf(&rustReference, "{let (_,points)=image.metadata.sequence_points(Token(%d)).unwrap();assert_eq!(points,vec![", want.Token)
				for _, point := range want.Points {
					fmt.Fprintf(&rustReference, "SequencePoint{document:Token(%d),offset:%d,start_line:%d,start_column:%d,end_line:%d,end_column:%d,hidden:%t},", point.Document, point.Offset, point.StartLine, point.StartColumn, point.EndLine, point.EndColumn, point.Hidden)
				}
				rustReference.WriteString("]);}\n")
			}
			rustReference.WriteString("}\n")
		})
	}
	if optional == 0 || methodCount == 0 {
		t.Fatal("reference did not identify the actual CIL methods")
	}
	manifest, changed := filepath.Join(dir, "edits.json"), filepath.Join(dir, "changed.dll")
	if err := os.WriteFile(manifest, []byte(fmt.Sprintf(`{"0x%08x":"0e1f2a2a"}`, uint32(optional))), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cli, "--arch", "cil", "--rewrite", manifest, "--output", changed, filepath.Join(fixtures, "anycpu.dll")).CombinedOutput(); err != nil {
		t.Fatalf("CLI method rewrite: %v\n%s", err, out)
	}
	for name, source := range map[string]string{
		"Harness.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include="Harness.cs" /></ItemGroup></Project>`,
		"Harness.cs":     `using System;using System.Reflection;using System.Runtime.Loader;var a=new AssemblyLoadContext("rewritten",true).LoadFromAssemblyPath(System.IO.Path.GetFullPath(args[0]));var value=a.GetType("ManagedFixture.Data")!.GetMethod("Optional")!.Invoke(null,new object[]{7});if(!Equals(value,42))throw new Exception("CLI rewrite returned "+value);Console.WriteLine("CLI rewrite executed: 42");`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	build = exec.Command(dotnetTool, "build", "Harness.csproj", "-c", "Release", "-o", filepath.Join(dir, "harness"), "--nologo", "-v:q")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLR consumer: %v\n%s", err, out)
	}
	if out, err := exec.Command(dotnetTool, filepath.Join(dir, "harness", "Harness.dll"), changed).CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "CLI rewrite executed: 42" {
		t.Fatalf("real CLR rejected CLI rewrite: %v\n%s", err, out)
	}
	fmt.Fprintf(&rustReference, "{let image=Image::open(include_bytes!(\"fixtures/anycpu.dll\")).unwrap();let edits=std::collections::BTreeMap::from([(Token(%d),vec![14,0x1f,42,0x2a])]);let changed=rewrite_verified_managed_methods(&image,&edits,RewriteOptions::default()).unwrap();std::fs::write(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"reference-changed.dll\"),changed).unwrap();}\n}\n", optional)
	rustOutput := os.Getenv("MKASM_DOTNET_REFERENCE_RUST")
	if rustOutput == "" {
		rustOutput = filepath.Join(dir, "managed-rust")
	}
	if out, err := exec.Command(cli, "--arch", "cil", "--codegen", "rust", "--output", rustOutput, filepath.Join(fixtures, "..", "..", "cil", "testdata", "opcode.def")).CombinedOutput(); err != nil {
		t.Fatalf("CLI managed Rust generation: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(rustOutput, "tests", "live_managed_reference.rs"), []byte(rustReference.String()), 0644); err != nil {
		t.Fatal(err)
	}
	consumer := exec.Command("cargo", "test", "--test", "live_managed_reference")
	consumer.Dir = rustOutput
	if out, err := consumer.CombinedOutput(); err != nil {
		t.Fatalf("CLI-generated managed Rust against live Microsoft reference: %v\n%s", err, out)
	}
	rustChanged := filepath.Join(rustOutput, "reference-changed.dll")
	if out, err := exec.Command(dotnetTool, filepath.Join(dir, "harness", "Harness.dll"), rustChanged).CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "CLI rewrite executed: 42" {
		t.Fatalf("real CLR rejected Rust rewrite: %v\n%s", err, out)
	}
	if err := os.Remove(rustChanged); err != nil {
		t.Fatal(err)
	}
	t.Logf("live Microsoft reference: four PE32/PE32+ images, %d CIL bodies with EH, three Portable PDBs, fresh CLI-generated managed Rust parity and real CLR execution of both CLI and Rust rewrites", methodCount)
}
