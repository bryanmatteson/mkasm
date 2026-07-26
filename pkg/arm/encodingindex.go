package arm

import (
	"context"

	"mkasm/pkg/parse"
)

type InstructionTableContext struct {
	IClass string
}

// NewInstructionTableHandler makes an instruction table's class available to
// its row handlers through the parser's lexical scope stack.
func NewInstructionTableHandler() parse.Handler {
	builder := parse.NewTypedHandlerBuilder[*InstructionTableContext, *InstructionTableContext](
		"instruction_table",
		parse.Select.Element("instructiontable"),
	)

	return builder.
		WithContextCreator(func(hctx *parse.HandlerContext) *InstructionTableContext {
			return &InstructionTableContext{
				IClass: parse.GetAttr(hctx.Element, "iclass"),
			}
		}).
		WithStartProcessor(func(_ context.Context, table *InstructionTableContext, hctx *parse.HandlerContext) error {
			parse.StoreInScope(hctx, "instruction_table", table)
			return nil
		}).
		Build()
}
