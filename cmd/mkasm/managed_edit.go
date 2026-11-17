package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
	"github.com/bryanmatteson/mkasm/pkg/managed"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// The manifest maps explicit MethodDef token strings to complete hex-encoded
// method bodies. Metadata tokens and signatures remain stable.
func rewriteManaged(ctx context.Context, input, manifest, output string, stdin io.Reader, options dotnet.RewriteOptions) error {
	r, closeInput, e := openSpecification(ctx, input, stdin)
	if e != nil {
		return e
	}
	defer closeInput()
	raw, e := io.ReadAll(r)
	if e != nil {
		return e
	}
	im, e := dotnet.Open(raw)
	if e != nil {
		return e
	}
	b, e := os.ReadFile(manifest)
	if e != nil {
		return e
	}
	edits := map[dotnet.Token][]byte{}
	decoder := json.NewDecoder(bytes.NewReader(b))
	start, e := decoder.Token()
	if e != nil {
		return e
	}
	if start != json.Delim('{') {
		return fmt.Errorf("rewrite manifest must be an object")
	}
	for decoder.More() {
		name, e := decoder.Token()
		if e != nil {
			return e
		}
		key, ok := name.(string)
		if !ok {
			return fmt.Errorf("invalid rewrite key")
		}
		var value string
		if e = decoder.Decode(&value); e != nil {
			return e
		}
		token, e := strconv.ParseUint(key, 0, 32)
		if e != nil {
			return fmt.Errorf("invalid token %q", key)
		}
		body, e := hex.DecodeString(value)
		if e != nil {
			return fmt.Errorf("%s: %w", key, e)
		}
		if _, exists := edits[dotnet.Token(token)]; exists {
			return fmt.Errorf("duplicate token %s", key)
		}
		edits[dotnet.Token(token)] = body
	}
	if _, e = decoder.Token(); e != nil {
		return e
	}
	if _, e = decoder.Token(); e != io.EOF {
		if e != nil {
			return e
		}
		return fmt.Errorf("trailing rewrite manifest data")
	}
	if len(edits) == 0 {
		return fmt.Errorf("rewrite manifest is empty")
	}
	changed, e := managed.RewriteVerifiedMethods(im, edits, options)
	if e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(output), ".mkasm-rewrite-*")
	if e != nil {
		return e
	}
	path := file.Name()
	defer os.Remove(path)
	if e = file.Chmod(0644); e != nil {
		file.Close()
		return e
	}
	if _, e = file.Write(changed); e != nil {
		file.Close()
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	return os.Rename(path, output)
}
