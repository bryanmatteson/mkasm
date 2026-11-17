package cil

import (
	"errors"
	"testing"
)

func TestStackAnalysisUsesMethodBodyValidation(t *testing.T) {
	c := Default()
	for _, verify := range []func(*MethodBody, VerificationContext) (*StackAnalysis, error){c.AnalyzeStack, c.VerifyStack} {
		if _, err := verify(nil, VerificationContext{}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("nil method body: %v", err)
		}
	}
	code, err := c.AssembleMethod("ldnull\nthrow\ncatch: pop\nleave.s end\nend: ret")
	if err != nil {
		t.Fatal(err)
	}
	body := &MethodBody{
		Code: code, MaxStack: 1,
		Sections: []ExceptionSection{{Clauses: []ExceptionClause{{
			TryOffset: 0, TryLength: 2, HandlerOffset: 2, HandlerLength: 3,
			ClassTokenOrFilterOffset: 0x01000001,
		}}}},
	}
	result, err := c.VerifyStack(body, VerificationContext{})
	if err != nil || result.MaxStack != 1 || result.Heights[2] != 1 {
		t.Fatalf("catch handler analysis: %+v, %v", result, err)
	}
	// The end of this handler splits leave.s's operand. Stack analysis must
	// enforce the same exception boundaries as the method-body codec.
	body.Sections[0].Clauses[0].HandlerLength = 2
	if _, err := c.EncodeMethodBody(body); !errors.Is(err, ErrMalformed) {
		t.Fatalf("method-body validation: %v", err)
	}
	if _, err := c.AnalyzeStack(body, VerificationContext{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("stack analysis accepted split exception boundary: %v", err)
	}
}
