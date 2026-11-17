package main

import (
	"context"
	"encoding/json"
	"github.com/bryanmatteson/mkasm/pkg/object"
	"io"
	"os"
)

func assembleObject(ctx context.Context, input, output string, jsonOutput bool, stdin io.Reader, stdout io.Writer, options object.Options) error {
	r, closeInput, e := openSpecification(ctx, input, stdin)
	if e != nil {
		return e
	}
	defer closeInput()
	source, e := io.ReadAll(r)
	if e != nil {
		return e
	}
	result, e := object.Assemble(ctx, string(source), options)
	if e != nil {
		return e
	}
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(result)
	}
	return os.WriteFile(output, result.Data, 0644)
}
