package arm

import "testing"

func TestParseLines_unbalancedBracketNoPanic(t *testing.T) {
	p := NewPseudocodeParser()
	// The bug was indexExpr := ident[idx+1 : len(ident)-1] when ] was missing
	// or when open bracket sat near the end.
	lines := []string{
		`bits(64) result = X[n`,
		`Mem[address, 8] = data`,
		`X[n] = bits(64) UNKNOWN`,
		`if (a + b) == c then`,
		`foo[`,
		`bar]`,
	}
	out := p.ParseLines(lines)
	if len(out) != len(lines) {
		t.Fatalf("got %d lines want %d", len(out), len(lines))
	}
	// Balanced index should produce an AST
	if out[2].AST == nil {
		t.Fatal("expected AST for X[n] assignment")
	}
}

func TestParseIdentifier_index(t *testing.T) {
	p := NewPseudocodeParser()
	n := p.parseIdentifier("X[n]")
	if n.Op != "index" || len(n.Args) != 2 {
		t.Fatalf("got %+v", n)
	}
	// Unbalanced: treat as bare variable, no panic
	n2 := p.parseIdentifier("X[n")
	if n2.Variable != "X[n" && n2.Op != "" {
		// either variable or non-index is fine
	}
}

func TestPseudocodeStatementScanner(t *testing.T) {
	p := NewPseudocodeParser()
	tests := []struct {
		line string
		op   string
	}{
		{`result = X[n] + 1`, "assign"},
		{`if result == 0 then`, "if"},
		{"if\tresult == 0\tthen", "if"},
		{`for i = 0 to 63 step 8`, "for"},
		{"for\ti = 0\tto\t63\tstep\t8", "for"},
		{`while IsZero(value) do`, "while"},
		{`return SignExtend(result, 64)`, "return"},
		{`BranchTo(target, BranchType_DIR)`, "call"},
	}
	for _, tt := range tests {
		node := p.parseLine(tt.line)
		if node == nil || node.Op != tt.op {
			t.Errorf("parseLine(%q) = %#v, want op %q", tt.line, node, tt.op)
		}
	}

	loop := p.parseLine(`for i = 0 to 63 step 8`)
	if loop.Variable != "i" || len(loop.Args) != 3 ||
		loop.Args[1].Literal != "63" || loop.Args[2].Literal != "8" {
		t.Fatalf("for statement parsed incorrectly: %#v", loop)
	}
	if node := p.parseLine(`// comment`); node != nil {
		t.Fatalf("comment produced AST: %#v", node)
	}
}

func TestPseudocodeScannerKeepsComparisonOutOfAssignment(t *testing.T) {
	p := NewPseudocodeParser()
	node := p.parseLine(`left == right`)
	if node == nil || node.Op != "==" {
		t.Fatalf("comparison parsed as %#v", node)
	}
}

func TestPseudocodeNestedCallArguments(t *testing.T) {
	p := NewPseudocodeParser()
	node := p.parseExpression(`Outer(Inner(a, b), X[n, m])`)
	if node.Op != "call" || node.Call == nil || node.Call.FuncName != "Outer" {
		t.Fatalf("outer call: %#v", node)
	}
	if len(node.Call.Args) != 2 {
		t.Fatalf("outer args = %d, want 2: %#v", len(node.Call.Args), node.Call.Args)
	}
	inner := node.Call.Args[0]
	if inner.Op != "call" || inner.Call == nil || inner.Call.FuncName != "Inner" ||
		len(inner.Call.Args) != 2 {
		t.Fatalf("inner call: %#v", inner)
	}
}
