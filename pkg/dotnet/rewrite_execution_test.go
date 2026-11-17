package dotnet

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewrittenAssemblyExecutes(t *testing.T) {
	dotnet, err := exec.LookPath("dotnet")
	if err != nil {
		t.Skip("dotnet runtime unavailable")
	}
	raw, err := os.ReadFile("testdata/anycpu.dll")
	if err != nil {
		t.Fatal(err)
	}
	im, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	methods, err := im.Metadata.Methods()
	if err != nil {
		t.Fatal(err)
	}
	var token Token
	for _, m := range methods {
		if m.Name == "Optional" {
			token = m.Token
		}
	}
	changed, err := im.RewriteMethods(map[Token][]byte{token: {14, 0x1f, 42, 0x2a}}, RewriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"changed.dll":    changed,
		"Harness.csproj": []byte(`<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>`),
		"Program.cs":     []byte(`using System;using System.Reflection;using System.Runtime.Loader;var a=new AssemblyLoadContext("rewritten",true).LoadFromAssemblyPath(System.IO.Path.GetFullPath(args[0]));var v=a.GetType("ManagedFixture.Data")!.GetMethod("Optional")!.Invoke(null,new object[]{7});if(!Equals(v,42))throw new Exception("rewritten method returned "+v);Console.WriteLine("rewritten method returned 42");`),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.Command(dotnet, "build", filepath.Join(dir, "Harness.csproj"), "--nologo", "--output", filepath.Join(dir, "out"))
	build.Env = append(os.Environ(), "DOTNET_CLI_TELEMETRY_OPTOUT=1")
	if log, err := build.CombinedOutput(); err != nil {
		t.Fatalf("consumer build: %v\n%s", err, log)
	}
	run := exec.Command(dotnet, filepath.Join(dir, "out/Harness.dll"), filepath.Join(dir, "changed.dll"))
	log, err := run.CombinedOutput()
	if err != nil || !strings.Contains(string(log), "returned 42") {
		t.Fatalf("real CLR execution: %v\n%s", err, log)
	}
}
