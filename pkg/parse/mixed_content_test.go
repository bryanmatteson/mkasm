package parse_test

import (
	"context"
	"strings"
	"testing"

	"mkasm/pkg/parse"
)

func TestMixedContentTextAccumulatesDescendants(t *testing.T) {
	opts := parse.DefaultParseOptions()
	opts.EnableMetrics = false
	opts.StopOnError = true
	p := parse.NewParser(opts)
	defer p.Close(0)

	var got string
	p.RegisterHandler(parse.NewFuncHandler(
		parse.Select.Element("asmtemplate"),
		nil,
		func(ctx context.Context, hctx *parse.HandlerContext) error {
			got = hctx.Text
			return nil
		},
	))

	xml := `<?xml version="1.0"?>
<root>
  <asmtemplate><text>CLREX  {#</text><a>&lt;imm&gt;</a><text>}</text></asmtemplate>
</root>`

	if _, err := p.Parse(context.Background(), strings.NewReader(xml)); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := "CLREX {# <imm> }"
	// Normalize spaces for comparison of token join
	norm := strings.Join(strings.Fields(got), " ")
	wantNorm := strings.Join(strings.Fields(want), " ")
	if norm != wantNorm {
		t.Fatalf("asmtemplate text=%q want~=%q", got, want)
	}
}
