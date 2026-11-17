// Package codec contains the byte-oriented instruction model shared by new
// specification importers. Instruction bits are numbered in physical byte order:
// bit zero is the low bit of the first byte, independently of target endianness.
package codec

import (
	"io"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

const Schema = "mkasm.codec.v1"

type Catalog struct {
	Schema          string              `json:"schema"`
	Architecture    string              `json:"architecture"`
	Source          string              `json:"source,omitempty"`
	SourceLicense   string              `json:"source_license,omitempty"`
	SourceLicenseID string              `json:"source_license_id,omitempty"`
	Encodings       []Encoding          `json:"encodings"`
	Unsupported     []Unsupported       `json:"unsupported,omitempty"`
	FeatureSets     map[string][]string `json:"feature_sets,omitempty"`
}

type Encoding struct {
	Effects  EffectSpec `json:"effects,omitempty"`
	ID       string     `json:"id"`
	Mnemonic string     `json:"mnemonic"`
	// Syntax uses {operand_name} placeholders; {{ and }} denote literal braces.
	Syntax           string          `json:"syntax"`
	Mask             []byte          `json:"mask"`
	Value            []byte          `json:"value"`
	Operands         []Operand       `json:"operands,omitempty"`
	Features         []string        `json:"features,omitempty"`
	Requirements     ir.Requirements `json:"requirements,omitempty"`
	SourcePredicates []string        `json:"source_predicates,omitempty"`
	FlowControl      string          `json:"flow_control,omitempty"`
	// FixedTarget describes a control-flow destination encoded entirely by
	// opcode bits, with no variable address operand. TargetMask defaults to all
	// bits and describes architectural truncation/alignment of destinations.
	FixedTarget  *uint64      `json:"fixed_target,omitempty"`
	TargetMask   uint64       `json:"target_mask,omitempty"`
	Constraints  []Constraint `json:"constraints,omitempty"`
	AssemblyOnly bool         `json:"assembly_only,omitempty"`
	DelaySlots   int          `json:"delay_slots,omitempty"`
}

type Operand struct {
	Name  string `json:"name"`
	Class string `json:"class,omitempty"` // source operand/register class
	Kind  string `json:"kind"`            // register, immediate, displacement, address
	// Bits assembles the encoded unsigned value before sign extension/scaling.
	Bits            []BitSlice `json:"bits"`
	Signed          bool       `json:"signed,omitempty"`
	InputSignedBits int        `json:"input_signed_bits,omitempty"`
	Implicit        bool       `json:"implicit,omitempty"` // omitted from syntax; its semantic value defaults to zero
	Optional        bool       `json:"optional,omitempty"` // omitted values default to zero; structured APIs preserve nonzero ignored/container bits
	Scale           int64      `json:"scale,omitempty"`    // zero means one
	Bias            int64      `json:"bias,omitempty"`
	BiasOperand     string     `json:"bias_operand,omitempty"`
	BiasScale       int64      `json:"bias_scale,omitempty"`
	Xor             uint64     `json:"xor,omitempty"`
	Lookup          []int64    `json:"lookup,omitempty"` // raw index to numeric value, before Scale/Bias; overrides sign extension
	RegisterPrefix  string     `json:"register_prefix,omitempty"`
	// Names maps encoded register/enumeration numbers to assembler spellings.
	Names           []string         `json:"names,omitempty"`
	RegisterAliases map[string]int64 `json:"register_aliases,omitempty"`
	Relative        bool             `json:"relative,omitempty"`
	PCBias          int64            `json:"pc_bias,omitempty"`
	PCPreAlignBias  int64            `json:"pc_pre_align_bias,omitempty"` // added before clearing PCAlignBits
	PCAlignBits     int              `json:"pc_align_bits,omitempty"`     // low address bits cleared before adding PCBias
	PCRegionBits    int              `json:"pc_region_bits,omitempty"`
	PCWrapBits      int              `json:"pc_wrap_bits,omitempty"`     // modular address space for relative targets
	PCLowWrapBits   int              `json:"pc_low_wrap_bits,omitempty"` // narrower wrapping when the PC base is in low memory
	PCBankBits      int              `json:"pc_bank_bits,omitempty"`     // wrap displacement within this many low bits, retaining the instruction's bank
}

type Constraint struct {
	Kind       string `json:"kind"` // ge, ne, eq, sum_le, diff_ge, masked_ne, encoded_targets_eq, tuple_in; an empty Right denotes zero
	Left       string `json:"left"`
	Right      string `json:"right"`
	UnlessZero string `json:"unless_zero,omitempty"`
	Limit      int64  `json:"limit,omitempty"`
	// Masked inequality can be restricted to selected register classes and
	// permit the same register while still rejecting different registers in a bank.
	LeftWhenMask  int64 `json:"left_when_mask,omitempty"`
	RightWhenMask int64 `json:"right_when_mask,omitempty"`
	EqualMask     int64 `json:"equal_mask,omitempty"`
	// Spans compare every consecutive register in each operand's bank set.
	// Zero has the same meaning as one register; explicit spans are bounded at 16.
	LeftSpan  int `json:"left_span,omitempty"`
	RightSpan int `json:"right_span,omitempty"`
	// Tuple membership uses semantic operand values, after lookup/scaling/bias.
	Operands []string  `json:"operands,omitempty"`
	Allowed  [][]int64 `json:"allowed,omitempty"`
}

type Unsupported struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type TableGenOptions struct {
	Architecture string
	LittleEndian bool
	// WordBytes reverses bytes within each word rather than the whole encoding.
	// AVR long instructions, for example, use two ordered little-endian words.
	WordBytes int
}

type BitSlice struct {
	InstructionBit int `json:"instruction_bit"`
	ValueBit       int `json:"value_bit"`
	Width          int `json:"width"`
}

// Backend also accommodates bytecodes and module-oriented instruction formats
// whose framing cannot be described by masks and fixed operand bit slices.
type Backend interface {
	WriteJSON(io.Writer) error
	GenerateRust(string) error
}

// InstructionCatalog exposes a fixed-field catalog through a backend wrapper.
// Wrappers can add source notices or generation behavior without losing CLI
// profile selection and unsupported-record diagnostics.
func (c *Catalog) InstructionCatalog() *Catalog { return c }

// NewCatalog normalizes schema and checks the complete imported catalog.
func NewCatalog(architecture, source string, encodings []Encoding) (*Catalog, error) {
	c := &Catalog{Schema: Schema, Architecture: architecture, Source: source, Encodings: encodings}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
