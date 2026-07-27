package arm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// ValidationError records one consistency problem on an instruction.
// Cherry-picked from improved-parser-design utilities.InstructionValidator.
type ValidationError struct {
	InstructionID string
	Field         string
	Message       string
}

func (e ValidationError) String() string {
	return fmt.Sprintf("%s.%s: %s", e.InstructionID, e.Field, e.Message)
}

// InstructionValidator validates instruction IR consistency.
type InstructionValidator struct {
	errors []ValidationError
	mu     sync.Mutex
}

// NewInstructionValidator creates a validator.
func NewInstructionValidator() *InstructionValidator {
	return &InstructionValidator{errors: make([]ValidationError, 0)}
}

// Validate checks one instruction. Returns true if no new errors were found.
func (v *InstructionValidator) Validate(instr *ir.InstructionIR) bool {
	if instr == nil {
		v.addError("", "Instruction", "nil instruction")
		return false
	}
	ok := true
	id := instr.EncodingID
	if id == "" {
		id = instr.Mnemonic
	}

	if instr.Mnemonic == "" {
		v.addError(id, "Mnemonic", "missing mnemonic")
		ok = false
	}
	if instr.EncodingID == "" {
		v.addError(id, "EncodingID", "missing encoding ID")
		ok = false
	}
	if instr.BitPattern != "" && len(instr.BitPattern) != 32 {
		v.addError(id, "BitPattern", fmt.Sprintf("invalid length %d (want 32)", len(instr.BitPattern)))
		ok = false
	}

	// Pass-1 provisional encodings place every cell at Start=0 with width-only
	// End — skip structural field checks until Pass 2 resolves regdiagram boxes.
	resolved := hasPass2Encoding(instr)
	if resolved {
		if err := ir.ValidateBitFields(instr.Encoding.Fields); err != nil {
			v.addError(id, "Encoding", err.Error())
			ok = false
		}
		if instr.Encoding.Width > 0 && instr.Encoding.Width != 32 && instr.Encoding.Width != 16 {
			v.addError(id, "Encoding.Width", fmt.Sprintf("unusual width %d", instr.Encoding.Width))
		}
		for i, op := range instr.Operands {
			if op.Name == "" {
				v.addError(id, fmt.Sprintf("Operand[%d]", i), "missing name")
				ok = false
				continue
			}
			if op.BitRange.End > 0 || op.BitRange.Start > 0 {
				if op.BitRange.Start < 0 || op.BitRange.End > 31 || op.BitRange.Start > op.BitRange.End {
					v.addError(id, op.Name, fmt.Sprintf("bit range [%d:%d] out of bounds", op.BitRange.Start, op.BitRange.End))
					ok = false
				}
			}
			if op.Constraint.Max != 0 && op.Constraint.Min > op.Constraint.Max {
				v.addError(id, op.Name, "constraint Min > Max")
				ok = false
			}
		}
		// Pattern vs encoding fixed bits should agree when both exist
		if strings.ContainsAny(instr.BitPattern, "01") && len(instr.Encoding.Fields) > 0 {
			pm, pv := ir.FixedBitsFromPattern(instr.BitPattern)
			em, ev := ir.FixedBitsFromEncoding(instr.Encoding)
			both := pm & em
			if both != 0 && (pv&both) != (ev&both) {
				v.addError(id, "BitPattern", fmt.Sprintf("disagrees with encoding fixed bits (pat=0x%08x enc=0x%08x mask=0x%08x)", pv, ev, both))
				ok = false
			}
		}
	}
	return ok
}

// ValidateAll validates every instruction; returns error count.
func (v *InstructionValidator) ValidateAll(instructions []*ir.InstructionIR) int {
	n := 0
	for _, instr := range instructions {
		if !v.Validate(instr) {
			n++
		}
	}
	return n
}

// GetErrors returns a copy of collected errors.
func (v *InstructionValidator) GetErrors() []ValidationError {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]ValidationError, len(v.errors))
	copy(out, v.errors)
	return out
}

// ErrorCount returns the number of validation errors.
func (v *InstructionValidator) ErrorCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.errors)
}

func (v *InstructionValidator) addError(id, field, message string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.errors = append(v.errors, ValidationError{
		InstructionID: id,
		Field:         field,
		Message:       message,
	})
}
