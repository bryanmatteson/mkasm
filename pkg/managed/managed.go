// Package managed composes the CIL codec with an owning PE/CLI image. Token
// resolution always uses the image being inspected or rewritten.
package managed

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/cil"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
)

func Context(metadata *dotnet.Metadata, method dotnet.Token, body *cil.MethodBody) (cil.VerificationContext, error) {
	c, e := metadata.EvaluationContext(method, dotnet.Token(body.LocalSignatureToken))
	if e != nil {
		return cil.VerificationContext{}, e
	}
	return cil.VerificationContext{Arguments: c.Arguments, Locals: c.Locals, ReturnsValue: c.ReturnsValue, ResolveCall: func(raw uint32) (cil.CallEffect, error) {
		s, e := metadata.CallSignature(dotnet.Token(raw))
		if e != nil {
			return cil.CallEffect{}, e
		}
		return cil.CallEffect{Parameters: len(s.Parameters), HasThis: s.CallingConvention&0x20 != 0 && s.CallingConvention&0x40 == 0, ReturnsValue: s.ReturnsValue()}, nil
	}}, nil
}

// VerifyMethod checks structural CIL and all reachable stack heights, variable
// bounds, EH entries, call effects and declared maxstack. Full ECMA type
// assignability requires referenced assemblies and VerifyTypes.
func VerifyMethod(image *dotnet.Image, token dotnet.Token) (*cil.StackAnalysis, error) {
	raw, e := image.MethodBody(token)
	if e != nil {
		return nil, e
	}
	if raw.Kind != "cil" {
		return nil, fmt.Errorf("managed: %s is %s", token, raw.Kind)
	}
	body, e := cil.Default().DecodeMethodBody(raw.Raw)
	if e != nil {
		return nil, e
	}
	ctx, e := Context(image.Metadata, token, body)
	if e != nil {
		return nil, e
	}
	return cil.Default().VerifyStack(body, ctx)
}

// RewriteVerifiedMethods checks each replacement in its owning metadata context
// before asking the PE writer to publish a new image. It never mutates image.
func RewriteVerifiedMethods(image *dotnet.Image, edits map[dotnet.Token][]byte, options dotnet.RewriteOptions) ([]byte, error) {
	for token, raw := range edits {
		body, e := cil.Default().DecodeMethodBody(raw)
		if e != nil {
			return nil, e
		}
		ctx, e := Context(image.Metadata, token, body)
		if e != nil {
			return nil, e
		}
		if _, e = cil.Default().VerifyStack(body, ctx); e != nil {
			return nil, fmt.Errorf("%s: %w", token, e)
		}
	}
	return image.RewriteMethods(edits, options)
}
