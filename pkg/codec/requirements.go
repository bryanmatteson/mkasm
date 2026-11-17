package codec

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

//go:embed requirements.rs.tmpl
var requirementRuntime string

// EmitRustRequirements emits a self-contained, allocation-free module. The
// sorted ID table supports exact source encoding/form IDs and alias inheritance.
func EmitRustRequirements(entries map[string]ir.Requirements) string {
	var b strings.Builder
	b.WriteString(requirementRuntime)
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteString("\nstatic TABLE: &[(&str,Requirements)] = &[\n")
	for _, k := range keys {
		r := entries[k]
		e := ir.UnknownRequirement("source metadata absent")
		if r.Expression != nil {
			e = *r.Expression
		}
		fallback := "None"
		if r.Fallback != nil {
			fallback = "Some(" + rustRequirement(*r.Fallback) + ")"
		}
		fmt.Fprintf(&b, "(%s,Requirements{expression:%s,fallback:%s,fallback_behavior:%s,source:%s}),\n", strconv.Quote(k), rustRequirement(e), fallback, strconv.Quote(r.FallbackBehavior), strconv.Quote(r.Source))
	}
	b.WriteString("];\npub fn for_encoding(id:&str)->&'static Requirements { TABLE.binary_search_by_key(&id, |(id,_)| *id).map(|i|&TABLE[i].1).unwrap_or(&UNKNOWN) }\n")
	return b.String()
}
func rustRequirement(e ir.RequirementExpr) string {
	switch e.Op {
	case "true":
		return "Expr::True"
	case "feature":
		return "Expr::Feature(" + strconv.Quote(e.Name) + ")"
	case "mode":
		return "Expr::Mode(" + strconv.Quote(e.Name) + ")"
	case "field_eq":
		return fmt.Sprintf("Expr::FieldEq{name:%s,mask:%d,value:%d}", strconv.Quote(e.Name), e.Mask, e.Value)
	case "all", "any":
		var args []string
		for _, a := range e.Args {
			args = append(args, rustRequirement(a))
		}
		kind := "All"
		if e.Op == "any" {
			kind = "Any"
		}
		return "Expr::" + kind + "(&[" + strings.Join(args, ",") + "])"
	case "not":
		if len(e.Args) == 1 {
			return "Expr::Not(&" + rustRequirement(e.Args[0]) + ")"
		}
	case "if":
		if len(e.Args) == 3 {
			return "Expr::If(&" + rustRequirement(e.Args[0]) + ",&" + rustRequirement(e.Args[1]) + ",&" + rustRequirement(e.Args[2]) + ")"
		}
	}
	return "Expr::Unknown(" + strconv.Quote(e.Name) + ")"
}

func encodingRequirements(e Encoding) ir.Requirements {
	if e.Requirements.Expression != nil {
		return e.Requirements
	}
	var args []ir.RequirementExpr
	for _, p := range e.SourcePredicates {
		args = append(args, ir.UnknownRequirement("TableGen predicate: "+p))
	}
	// Legacy Features select processor profiles. They are source names, not a
	// guaranteed complete architectural feature expression.
	if len(args) == 0 {
		args = append(args, ir.UnknownRequirement("architectural feature metadata absent; profile selectors are not requirements"))
	}
	expression := ir.RequirementAll(args...)
	return ir.Requirements{Expression: &expression, Source: "codec catalog"}
}
