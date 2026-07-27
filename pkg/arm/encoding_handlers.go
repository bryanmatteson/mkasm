package arm

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
	"github.com/bryanmatteson/mkasm/pkg/parse"
)

// InstructionRowHandler handles <tr> elements in encodingindex.xml
type InstructionRowHandler struct {
	*parse.TypedHandler[*InstructionRowContext, *ir.InstructionIR]
}

// InstructionRowContext holds state during instruction row parsing
type InstructionRowContext struct {
	EncodingID string
	Mnemonic   string
	IClass     string
	IFormFile  string
	Bitfields  []Bitfield
	Features   []string
}

// Bitfield represents a parsed bitfield
type Bitfield struct {
	Position int
	Width    int
	Value    string
	Name     string
}

// NewInstructionRowHandler creates a handler for instruction rows
func NewInstructionRowHandler() parse.Handler {
	builder := parse.NewTypedHandlerBuilder[*InstructionRowContext, *ir.InstructionIR](
		"instruction_row",
		parse.Select.Element("tr"),
	)

	return builder.
		WithStartMiddleware(
			parse.MetricsMiddleware("instruction_row.parse"),
			parse.When(func(hctx *parse.HandlerContext) bool {
				// Only real encoding rows; skip UNALLOCATED / undef
				if parse.GetAttr(hctx.Element, "undef") == "1" {
					return false
				}
				if parse.GetAttr(hctx.Element, "class") != "instructiontable" {
					return false
				}
				return parse.GetAttr(hctx.Element, "encname") != ""
			}),
		).
		WithContextCreator(func(hctx *parse.HandlerContext) *InstructionRowContext {
			ctx := &InstructionRowContext{
				EncodingID: parse.GetAttr(hctx.Element, "encname"),
				IFormFile:  parse.GetAttr(hctx.Element, "iformfile"),
				Bitfields:  make([]Bitfield, 0),
				Features:   make([]string, 0),
			}
			if tctx, ok := parse.LoadFromScope[*InstructionTableContext](hctx, "instruction_table"); ok {
				ctx.IClass = tctx.IClass
			}
			if av := parse.GetAttr(hctx.Element, "arch_version"); av != "" {
				for _, part := range strings.Split(av, "||") {
					part = strings.TrimSpace(part)
					if part != "" {
						ctx.Features = append(ctx.Features, part)
					}
				}
			}
			return ctx
		}).
		WithStartProcessor(processInstructionRowStart).
		WithEndProcessor(processInstructionRowEnd).
		WithResultHandler(handleInstructionResult).
		Build()
}

// processInstructionRowStart initializes instruction parsing
func processInstructionRowStart(ctx context.Context, irctx *InstructionRowContext, hctx *parse.HandlerContext) error {
	// Store context in scope for child handlers
	parse.StoreInScope(hctx, "instruction_row", irctx)

	// Track metrics
	hctx.IncrementCounter("instructions.started")

	return nil
}

// processInstructionRowEnd creates the instruction IR
func processInstructionRowEnd(ctx context.Context, irctx *InstructionRowContext, hctx *parse.HandlerContext) (*ir.InstructionIR, error) {
	// Create instruction IR
	instr := &ir.InstructionIR{
		EncodingID: irctx.EncodingID,
		Mnemonic:   irctx.Mnemonic,
		IClass:     irctx.IClass,
		IFormFile:  irctx.IFormFile,
		BitPattern: constructBitPattern(irctx.Bitfields),
		Encoding:   constructEncodingMask(irctx.Bitfields),
		Features: ir.FeatureSet{
			Tags: parseFeatureTags(irctx.Features),
		},
	}

	return instr, nil
}

// handleInstructionResult stores the parsed instruction
func handleInstructionResult(ctx context.Context, instr *ir.InstructionIR, hctx *parse.HandlerContext) error {
	hctx.StoreResult("instruction", instr)
	return nil
}

// MnemonicHandler handles <td class="iformname"> elements
type MnemonicHandler struct {
	*parse.FuncHandler
}

// NewMnemonicHandler creates a handler for mnemonic cells
func NewMnemonicHandler() parse.Handler {
	return parse.NewFuncHandler(
		parse.Select.Element("td"),
		handleMnemonicStart,
		handleMnemonicEnd,
	)
}

func handleMnemonicStart(ctx context.Context, hctx *parse.HandlerContext) error {
	if parse.GetAttr(hctx.Element, "class") != "iformname" {
		return nil
	}
	return nil
}

func handleMnemonicEnd(ctx context.Context, hctx *parse.HandlerContext) error {
	if parse.GetAttr(hctx.Element, "class") != "iformname" {
		return nil
	}
	if irctx, ok := parse.LoadFromScope[*InstructionRowContext](hctx, "instruction_row"); ok {
		cellText := strings.TrimSpace(hctx.Text)
		// Prefer iformid as the canonical mnemonic; keep cell list as variants
		if iformid := parse.GetAttr(hctx.Element, "iformid"); iformid != "" {
			irctx.Mnemonic = iformid
		} else if cellText != "" {
			// First token if comma-separated
			irctx.Mnemonic = strings.TrimSpace(strings.Split(cellText, ",")[0])
		} else {
			irctx.Mnemonic = cellText
		}

	}

	return nil
}

// BitfieldHandler handles <td class="bitfield"> elements
type BitfieldHandler struct {
	selector parse.Selector
	sessions *parse.SessionManager
}

// NewBitfieldHandler creates a handler for bitfield cells
func NewBitfieldHandler() parse.Handler {
	return &BitfieldHandler{
		selector: parse.Select.Element("td"),
		sessions: parse.NewSessionManager(),
	}
}

func (h *BitfieldHandler) Selector() parse.Selector { return h.selector }

func (h *BitfieldHandler) Start() parse.HandlerFunc {
	return func(ctx context.Context, hctx *parse.HandlerContext) error {
		if parse.GetAttr(hctx.Element, "class") != "bitfield" {
			return nil
		}
		// encodingindex <td class="bitfield"> only has bitwidth (+ cell text).
		// Absolute positions come from iform <regdiagram>/<box hibit> in Pass 2.
		width, _ := strconv.Atoi(parse.GetAttr(hctx.Element, "bitwidth"))
		parse.SessionStore(h.sessions, hctx.Path, Bitfield{
			Width: width,
		})
		return nil
	}
}

func (h *BitfieldHandler) End() parse.HandlerFunc {
	return func(ctx context.Context, hctx *parse.HandlerContext) error {
		if parse.GetAttr(hctx.Element, "class") != "bitfield" {
			return nil
		}
		bf, ok := parse.SessionLoad[Bitfield](h.sessions, hctx.Path)
		if !ok {
			return nil
		}
		h.sessions.Delete(hctx.Path)

		bf.Value = strings.TrimSpace(hctx.Text)
		if name := parse.GetAttr(hctx.Element, "name"); name != "" {
			bf.Name = name
		}

		if irctx, ok := parse.LoadFromScope[*InstructionRowContext](hctx, "instruction_row"); ok {
			irctx.Bitfields = append(irctx.Bitfields, bf)
		}
		return nil
	}
}

// FeatureHandler handles feature requirements
type FeatureHandler struct {
	*parse.FuncHandler
}

// NewFeatureHandler creates a handler for feature tags
func NewFeatureHandler() parse.Handler {
	return parse.NewFuncHandler(
		parse.Select.Element("feat"),
		nil,
		handleFeatureEnd,
	)
}

func handleFeatureEnd(ctx context.Context, hctx *parse.HandlerContext) error {
	feature := strings.TrimSpace(hctx.Text)

	// Add to parent instruction context if available
	if irctx, ok := parse.LoadFromScope[*InstructionRowContext](hctx, "instruction_row"); ok {
		irctx.Features = append(irctx.Features, feature)
	}

	return nil
}

// Helper functions

// constructBitPattern is provisional from encodingindex cells only.
// Pass 2 regdiagram overwrite is authoritative.
func constructBitPattern(bitfields []Bitfield) string {
	return strings.Repeat("x", 32)
}

// constructEncodingMask stores width-only provisional fields; Pass 2 replaces them.
func constructEncodingMask(bitfields []Bitfield) ir.EncodingMask {
	mask := ir.EncodingMask{
		Width:  32,
		Fields: make([]ir.BitField, 0, len(bitfields)),
	}
	for i, bf := range bitfields {
		name := bf.Name
		if name == "" {
			name = fmt.Sprintf("col%d", i)
		}
		field := ir.BitField{Name: name, Start: 0, End: 0}
		if bf.Width > 0 {
			field.End = bf.Width - 1 // provisional width marker only
		}
		mask.Fields = append(mask.Fields, field)
	}
	return mask
}

// parseFeatureTags converts feature strings to FeatureTags
func parseFeatureTags(features []string) []ir.FeatureTag {
	tags := make([]ir.FeatureTag, 0, len(features))

	for _, f := range features {
		tag := ir.FeatureTag{
			Name:     f,
			Required: true, // Assume required by default
		}

		// Add descriptions for known features
		switch f {
		case "FEAT_LSE":
			tag.Description = "Large System Extensions"
		case "FEAT_SVE":
			tag.Description = "Scalable Vector Extension"
		case "FEAT_SVE2":
			tag.Description = "Scalable Vector Extension version 2"
		}

		tags = append(tags, tag)
	}

	return tags
}
