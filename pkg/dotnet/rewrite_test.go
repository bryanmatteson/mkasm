package dotnet

import (
	"bytes"
	"os"
	"testing"
)

func TestRewriteMethods(t *testing.T) {
	for _, name := range []string{"anycpu.dll", "x86.exe", "x64.dll", "embedded.dll"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), raw...)
			im, err := Open(raw)
			if err != nil {
				t.Fatal(err)
			}
			methods, err := im.Metadata.Methods()
			if err != nil {
				t.Fatal(err)
			}
			edits := map[Token][]byte{}
			for _, m := range methods {
				if m.Name == "Optional" {
					edits[m.Token] = []byte{14, 0x1f, 42, 0x2a}
				}
			}
			if len(edits) != 1 {
				t.Fatal("missing real fixture method")
			}
			changed, err := im.RewriteMethods(edits, RewriteOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("input modified")
			}
			next, err := Open(changed)
			if err != nil {
				t.Fatal(err)
			}
			debug, err := next.DebugEntries()
			if err != nil || len(debug) != 0 {
				t.Fatalf("stale debug references after rewriting: %v %v", debug, err)
			}
			for _, m := range methods {
				before, err := im.MethodBody(m.Token)
				if err != nil {
					t.Fatal(err)
				}
				after, err := next.MethodBody(m.Token)
				if err != nil {
					t.Fatal(err)
				}
				want := before.Raw
				if b, ok := edits[m.Token]; ok {
					want = b
				}
				if !bytes.Equal(after.Raw, want) {
					t.Fatalf("method %s changed incorrectly", m.FullName)
				}
			}
			if _, err := im.RewriteMethods(map[Token][]byte{Token(0x06000001): {0xff}}, RewriteOptions{}); err == nil {
				t.Fatal("malformed replacement accepted")
			}
		})
	}
}

func TestRewriteMethodGrowth(t *testing.T) {
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
	body := make([]byte, 12+70001)
	body[0] = 3
	body[1] = 0x30
	body[2] = 8
	body[4] = 0x71
	body[5] = 0x11
	body[6] = 1
	body[len(body)-1] = 0x2a
	changed, err := im.RewriteMethods(map[Token][]byte{token: body}, RewriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	next, err := Open(changed)
	if err != nil {
		t.Fatal(err)
	}
	m, err := next.MethodBody(token)
	if err != nil || !bytes.Equal(m.Raw, body) {
		t.Fatalf("growing method: %v", err)
	}
}
