package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bryanmatteson/mkasm/pkg/x86"
)

func runX86(ctx context.Context, input string, stdin io.Reader, stdout, stderr io.Writer, output string, jsonIR bool) error {
	reader, closeInput, description, err := openX86Input(ctx, input, stdin)
	if err != nil {
		return err
	}
	if closeInput != nil {
		defer closeInput()
	}
	started := time.Now()
	catalog, err := x86.ParseOpcodesDB(reader)
	if err != nil {
		return fmt.Errorf("parse %s: %w", description, err)
	}
	fmt.Fprintf(stderr, "Input: %s\nArchitecture: x86_64\nForms: %d\nElapsed: %s\n",
		description, len(catalog.Encodings), time.Since(started).Round(time.Millisecond))
	if jsonIR {
		return json.NewEncoder(stdout).Encode(struct {
			Schema       string         `json:"schema"`
			Architecture string         `json:"architecture"`
			Encodings    []x86.Encoding `json:"encodings"`
		}{"mkasm.x86.v1", "x86_64", catalog.Encodings})
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := x86.GenerateRust(catalog, output); err != nil {
		return err
	}
	fmt.Fprintln(stderr, "Generated: rust")
	return nil
}

func openX86Input(ctx context.Context, input string, stdin io.Reader) (io.Reader, func() error, string, error) {
	if input == "-" {
		return stdin, nil, "stdin", nil
	}
	if strings.HasSuffix(strings.ToLower(input), ".xz") {
		return nil, nil, "", fmt.Errorf("x86 .xz input must be decompressed on stdin: xz -dc %q | mkasm --arch x86_64 ... -", input)
	}
	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, input, nil)
		if err != nil {
			return nil, nil, "", fmt.Errorf("create x86 input request: %w", err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, nil, "", fmt.Errorf("download x86 input: %w", err)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			response.Body.Close()
			return nil, nil, "", fmt.Errorf("download x86 input: HTTP %s", response.Status)
		}
		return response.Body, response.Body.Close, input, nil
	}
	file, err := os.Open(input)
	if err != nil {
		return nil, nil, "", fmt.Errorf("open x86 input %q: %w", input, err)
	}
	return file, file.Close, input, nil
}
