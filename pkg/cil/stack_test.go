package cil

import (
	"strings"
	"testing"
)

func TestEvaluationStack(t *testing.T) {
	c := Default()
	for _, tc := range []struct {
		name, text string
		ctx        VerificationContext
		max        uint16
		err        string
	}{
		{"arithmetic", "ldarg.0\nldc.i4.1\nadd\nret", VerificationContext{Arguments: 1, ReturnsValue: true}, 2, ""},
		{"loop", "ldc.i4.0\nstloc.0\nloop: ldloc.0\nldc.i4.1\nadd\nstloc.0\nldloc.0\nldc.i4.s 10\nblt.s loop\nret", VerificationContext{Locals: 1}, 2, ""},
		{"underflow", "pop\nret", VerificationContext{}, 0, "underflow"},
		{"merge", "ldc.i4.0\nbrtrue.s end\nldc.i4.1\nend: ret", VerificationContext{}, 0, "stack"},
		{"argument", "ldarg.1\npop\nret", VerificationContext{Arguments: 1}, 0, "variable index"},
		{"local", "ldloc.s 2\npop\nret", VerificationContext{Locals: 2}, 0, "variable index"},
		{"return", "ldc.i4.0\nret", VerificationContext{}, 0, "nonempty"},
		{"missing return", "nop", VerificationContext{}, 0, "outside"},
		{"throw discards", "ldc.i4.1\nldnull\nthrow", VerificationContext{}, 2, ""},
		{"call", "ldc.i4.1\ncall 0x06000001\nret", VerificationContext{ReturnsValue: true, ResolveCall: func(uint32) (CallEffect, error) { return CallEffect{Parameters: 1, ReturnsValue: true}, nil }}, 1, ""},
		{"calli", "ldc.i4.1\nldftn 0x06000001\ncalli 0x11000001\nret", VerificationContext{ReturnsValue: true, ResolveCall: func(uint32) (CallEffect, error) { return CallEffect{Parameters: 1, ReturnsValue: true}, nil }}, 2, ""},
		{"unresolved call", "call 0x06000001\nret", VerificationContext{}, 0, "resolver"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, e := c.AssembleMethod(tc.text)
			if e != nil {
				t.Fatal(e)
			}
			body := &MethodBody{Code: code, MaxStack: tc.max}
			x, e := c.VerifyStack(body, tc.ctx)
			if tc.err != "" {
				if e == nil || !strings.Contains(e.Error(), tc.err) {
					t.Fatalf("expected %q, got %+v %v", tc.err, x, e)
				}
				return
			}
			if e != nil || x.MaxStack != tc.max {
				t.Fatalf("%+v %v", x, e)
			}
			if tc.max > 0 {
				body.MaxStack--
				if _, e = c.VerifyStack(body, tc.ctx); e == nil {
					t.Fatal("accepted insufficient maxstack")
				}
			}
		})
	}
}
