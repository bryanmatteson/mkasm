package cil

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type CallEffect struct {
	Parameters   int
	HasThis      bool
	ReturnsValue bool
}
type VerificationContext struct {
	Arguments    int
	Locals       int
	ReturnsValue bool
	ResolveCall  func(uint32) (CallEffect, error)
}
type StackAnalysis struct {
	MaxStack              uint16         `json:"max_stack"`
	Heights               map[uint32]int `json:"stack_heights"`
	ReachableInstructions int            `json:"reachable_instructions"`
}

// AnalyzeStack performs control-flow stack analysis, resolving variable call
// effects through metadata supplied by the caller. It checks all reachable
// merges, variable bounds, returns and EH entry stacks and computes maxstack.
// This is evaluation-stack verification, not an assignability/type-system proof.
func (c *Catalog) AnalyzeStack(body *MethodBody, ctx VerificationContext) (*StackAnalysis, error) {
	if body == nil {
		return nil, malformed("nil method body")
	}
	if ctx.Arguments < 0 || ctx.Locals < 0 {
		return nil, malformed("negative variable count")
	}
	code := body.Code
	var err error
	if body.Instructions != nil {
		code, err = c.EncodeMethod(body.Instructions)
		if err != nil {
			return nil, err
		}
	}
	ins, err := c.DecodeMethod(code)
	if err != nil {
		return nil, err
	}
	if len(ins) == 0 {
		return nil, malformed("empty method")
	}
	if err := validateEH(body.Sections, ins, uint32(len(code))); err != nil {
		return nil, err
	}
	indexes := map[uint32]int{}
	for i, in := range ins {
		indexes[in.Offset] = i
	}
	out := &StackAnalysis{Heights: map[uint32]int{}}
	queue := []uint32{}
	add := func(offset uint32, height int) error {
		if _, ok := indexes[offset]; !ok {
			return malformed("control flow falls outside method")
		}
		if old, ok := out.Heights[offset]; ok {
			if old != height {
				return malformed(fmt.Sprintf("inconsistent stack height at IL_%04x: %d and %d", offset, old, height))
			}
			return nil
		}
		out.Heights[offset] = height
		queue = append(queue, offset)
		return nil
	}
	if err := add(0, 0); err != nil {
		return nil, err
	}
	for _, section := range body.Sections {
		for _, clause := range section.Clauses {
			height := 0
			if clause.Flags == 0 || clause.Flags == 1 {
				height = 1
			}
			if err := add(clause.HandlerOffset, height); err != nil {
				return nil, err
			}
			if clause.Flags == 1 {
				if err := add(clause.ClassTokenOrFilterOffset, 1); err != nil {
					return nil, err
				}
			}
		}
	}
	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]
		in := ins[indexes[at]]
		d := c.Definition(in.Opcode)
		height := out.Heights[at]
		name := d.Mnemonic
		if height > int(out.MaxStack) {
			out.MaxStack = uint16(height)
		}
		out.ReachableInstructions++
		// Short-form locals/arguments carry their index in the mnemonic.
		for _, variable := range []struct {
			prefix string
			count  int
		}{{"ldarg", ctx.Arguments}, {"ldarga", ctx.Arguments}, {"starg", ctx.Arguments}, {"ldloc", ctx.Locals}, {"ldloca", ctx.Locals}, {"stloc", ctx.Locals}} {
			if name == variable.prefix || strings.HasPrefix(name, variable.prefix+".") {
				index := -1
				suffix := strings.TrimPrefix(name, variable.prefix+".")
				if v, e := strconv.Atoi(suffix); e == nil {
					index = v
				} else if in.Operand != nil {
					index = int(in.Operand.Value)
				}
				if index < 0 || index >= variable.count {
					return nil, malformed(fmt.Sprintf("%s variable index out of range at IL_%04x", name, at))
				}
			}
		}
		pop, push := d.PopCount, d.PushCount
		if name == "ret" {
			pop = 0
			if ctx.ReturnsValue {
				pop = 1
			}
			push = 0
		} else if name == "call" || name == "callvirt" || name == "calli" || name == "newobj" || name == "jmp" {
			if in.Operand == nil || ctx.ResolveCall == nil {
				return nil, malformed("call requires a metadata signature resolver")
			}
			effect, e := ctx.ResolveCall(uint32(in.Operand.Value))
			if e != nil {
				return nil, e
			}
			if effect.Parameters < 0 || effect.Parameters > math.MaxUint16 {
				return nil, malformed("invalid resolved call signature")
			}
			pop = effect.Parameters
			push = 0
			if effect.HasThis && name != "newobj" {
				pop++
			}
			if effect.ReturnsValue || name == "newobj" {
				push = 1
			}
			if name == "calli" {
				pop++
			}
			if name == "jmp" {
				if height != 0 {
					return nil, malformed("jmp requires an empty stack")
				}
				pop = 0
				push = 0
			}
		}
		if pop < 0 || push < 0 {
			return nil, malformed("unresolved variable stack effect for " + name)
		}
		if height < pop {
			return nil, malformed(fmt.Sprintf("stack underflow at IL_%04x (%s)", at, name))
		}
		nextHeight := height - pop + push
		if nextHeight > math.MaxUint16 {
			return nil, malformed("maxstack exceeds uint16")
		}
		if nextHeight > int(out.MaxStack) {
			out.MaxStack = uint16(nextHeight)
		}
		// Exception transfers discard the evaluation stack after their operands
		// have been consumed (ECMA-335 III.3.35, III.4.24, III.4.25).
		if name == "throw" || name == "rethrow" || name == "endfinally" {
			continue
		}
		if name == "ret" || name == "endfilter" || name == "jmp" {
			if nextHeight != 0 {
				return nil, malformed(fmt.Sprintf("nonempty stack at %s IL_%04x", name, at))
			}
			continue
		}
		if name == "leave" || name == "leave.s" {
			nextHeight = 0
		}
		for _, target := range in.BranchTargets() {
			if target < 0 || target > math.MaxUint32 {
				return nil, malformed("branch target overflow")
			}
			if err := add(uint32(target), nextHeight); err != nil {
				return nil, err
			}
		}
		if d.Flow != "BRANCH" {
			next := in.Offset + uint32(in.Length)
			if err := add(next, nextHeight); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func (c *Catalog) VerifyStack(body *MethodBody, ctx VerificationContext) (*StackAnalysis, error) {
	result, err := c.AnalyzeStack(body, ctx)
	if err == nil && result.MaxStack > body.MaxStack {
		return nil, malformed(fmt.Sprintf("declared maxstack %d below required %d", body.MaxStack, result.MaxStack))
	}
	return result, err
}
