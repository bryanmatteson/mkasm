package managed

import (
	"context"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRealTypeVerification(t *testing.T) {
	verifier := os.Getenv("MKASM_ILVERIFY")
	references := os.Getenv("MKASM_DOTNET_REFERENCES")
	if verifier == "" || references == "" {
		t.Skip("set MKASM_ILVERIFY and MKASM_DOTNET_REFERENCES")
	}
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "Check.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Library</OutputType></PropertyGroup></Project>`), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "Code.cs"), []byte(`public static class Check { public static int Value(int x) => x+1; }`), 0644); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("dotnet", "build", filepath.Join(dir, "Check.csproj"), "--nologo", "--verbosity", "quiet")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("%v %s", e, b)
	}
	path := filepath.Join(dir, "bin/Debug/net10.0/Check.dll")
	if result, e := VerifyTypes(context.Background(), verifier, path, []string{references}); e != nil || !result.Verified {
		t.Fatalf("%+v %v", result, e)
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
		t.Fatal("missing compiled method")
	}
	// ldnull; ret has a correct height and an incorrect return type. This
	// specifically verifies the distinction from local stack-height analysis.
	bad, e := RewriteVerifiedMethods(image, map[dotnet.Token][]byte{token: {10, 0x14, 0x2a}}, dotnet.RewriteOptions{})
	if e != nil {
		t.Fatal(e)
	}
	badPath := filepath.Join(dir, "Bad.dll")
	if e = os.WriteFile(badPath, bad, 0644); e != nil {
		t.Fatal(e)
	}
	if result, e := VerifyTypes(context.Background(), verifier, badPath, []string{references}); e == nil || result.Verified || result.Diagnostics == "" {
		t.Fatalf("type-invalid method accepted: %+v %v", result, e)
	}
}
