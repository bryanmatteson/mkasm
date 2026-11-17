package managed

import (
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
	"os"
	"testing"
)

func TestManagedStacksAndRewriting(t *testing.T) {
	for _, name := range []string{"anycpu.dll", "x86.exe", "x64.dll", "embedded.dll"} {
		raw, e := os.ReadFile("../dotnet/testdata/" + name)
		if e != nil {
			t.Fatal(e)
		}
		im, e := dotnet.Open(raw)
		if e != nil {
			t.Fatal(e)
		}
		methods, e := im.Metadata.Methods()
		if e != nil {
			t.Fatal(e)
		}
		count := 0
		for _, m := range methods {
			if m.Kind != "cil" {
				continue
			}
			if _, e := VerifyMethod(im, m.Token); e != nil {
				t.Fatalf("%s %s: %v", name, m.FullName, e)
			}
			count++
			if m.Name == "Optional" {
				if _, e := RewriteVerifiedMethods(im, map[dotnet.Token][]byte{m.Token: {14, 0x1f, 42, 0x2a}}, dotnet.RewriteOptions{}); e != nil {
					t.Fatal(e)
				}
				if _, e := RewriteVerifiedMethods(im, map[dotnet.Token][]byte{m.Token: {6, 0x2a}}, dotnet.RewriteOptions{}); e == nil {
					t.Fatal("accepted invalid return stack")
				}
			}
		}
		if count < 10 {
			t.Fatal("missing actual method coverage")
		}
	}
}

func TestRuntimeStackCorpus(t *testing.T) {
	path := os.Getenv("MKASM_DOTNET_CORPUS")
	if path == "" {
		t.Skip("set MKASM_DOTNET_CORPUS to a real assembly")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	im, e := dotnet.Open(raw)
	if e != nil {
		t.Fatal(e)
	}
	methods, e := im.Metadata.Methods()
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, m := range methods {
		if m.Kind != "cil" {
			continue
		}
		if _, e := VerifyMethod(im, m.Token); e != nil {
			t.Errorf("%s %s: %v", m.Token, m.FullName, e)
		}
		count++
	}
	t.Logf("verified %d CIL bodies", count)
}
