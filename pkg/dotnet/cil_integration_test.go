package dotnet_test

import (
	"bytes"
	"github.com/bryanmatteson/mkasm/pkg/cil"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
	"os"
	"path/filepath"
	"testing"
)

func TestCILConsumerUsesManagedMethodTokens(t *testing.T) {
	c := cil.Default()
	for _, name := range []string{"anycpu.dll", "x86.exe", "x64.dll", "embedded.dll"} {
		b, e := os.ReadFile(filepath.Join("testdata", name))
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
		for _, m := range methods {
			body, e := im.MethodBody(m.Token)
			if e != nil {
				t.Fatal(e)
			}
			if body.Kind != "cil" {
				continue
			}
			decoded, e := c.DecodeMethodBody(body.Raw)
			if e != nil {
				t.Fatalf("%s %s: %v", name, m.Token, e)
			}
			if !bytes.Equal(decoded.Code, body.IL) {
				t.Fatal("method boundary changed")
			}
			encoded, e := c.EncodeMethodBody(decoded)
			if e != nil || !bytes.Equal(encoded, body.Raw) {
				t.Fatalf("CIL re-encode %s: %v", m.Token, e)
			}
		}
	}
}
