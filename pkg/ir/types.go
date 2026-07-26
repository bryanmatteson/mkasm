package ir

// ----------------------------
// Assembly/Disassembly Layer
// ----------------------------

// InstructionIR represents a single instruction variant parsed from ARM XML.
type InstructionIR struct {
	// Mnemonic is encodingindex.xml's iform group name, which is a grouping key
	// and not always spellable: CRC32CB/CRC32CH/CRC32CW all carry "CRC32C", and
	// the SIMD pages carry "ABS_advsimd". Callers that print use AsmMnemonic.
	Mnemonic string
	// AsmMnemonic is the assembler spelling, taken from the leading literal of
	// the encoding's asmtemplate. "B." for B.<cond>, where ARM makes the
	// condition part of the mnemonic.
	AsmMnemonic   string
	EncodingID    string
	IClass        string
	IFormFile     string // relative filename from encodingindex iformfile attr (e.g. "adc.xml")
	BitPattern    string
	Asm           AsmTemplate
	Operands      []OperandIR
	Encoding      EncodingMask
	Documentation *InstructionDoc
	Features      FeatureSet
	// BitDiffs is the raw encoding@bitdiffs expression from the iform XML.
	BitDiffs string
	// BitDiffsTree is the parsed/resolved constraint tree used at match time.
	// Equality pins are also applied into BitPattern / Encoding.Fixed.
	BitDiffsTree *BitDiffNode
	// AliasOf is set when this encoding is an architectural alias of another
	// (EncodingID of the canonical form), if detected from the iform.
	AliasOf string
}

// OperandIR describes a typed operand extracted from the encoding.
type OperandIR struct {
	Name        string
	DisplayName string
	Type        OperandType
	BitRange    BitRange
	Usage       OperandUsage
	Constraint  Constraint
	Enum        *EnumRef
	Register    *RegisterClass
}

// AsmTemplate captures the parsed asmtemplate field.
type AsmTemplate struct {
	Raw    string
	Tokens []AsmToken
}

type AsmTokenKind string

const (
	TokenLiteral AsmTokenKind = "literal"
	TokenOperand AsmTokenKind = "operand"
	TokenSymbol  AsmTokenKind = "symbol"
)

type AsmToken struct {
	Kind    AsmTokenKind
	Value   string
	Operand string
	Options []string
}

// BitRange describes a [lo, hi] bit range in the instruction word.
type BitRange struct {
	Start int
	End   int
}

type OperandType string

const (
	Reg     OperandType = "reg"
	Imm     OperandType = "imm"
	Cond    OperandType = "cond"
	Enum    OperandType = "enum"
	Flag    OperandType = "flag"
	SIMD    OperandType = "simd"
	SysReg  OperandType = "sysreg"
	PState  OperandType = "pstate"
	Special OperandType = "special"
)

type OperandUsage string

const (
	Read      OperandUsage = "read"
	Write     OperandUsage = "write"
	ReadWrite OperandUsage = "read/write"
)

type Constraint struct {
	MustBeZero     bool
	MustBeOne      bool
	Mask           uint64
	Min            uint64
	Max            uint64
	EnumOnly       bool
	AllowedVals    []uint64
	DisallowedVals []uint64
}

type EnumRef struct {
	Name   string
	Values map[string]uint64
}

type RegisterClass struct {
	Name      string
	WidthBits int
	Encoding  string
	Aliases   []string
	Features  []FeatureTag // e.g. only valid with FEAT_SVE
}

type EncodingMask struct {
	Width    int
	Fields   []BitField
	Features []FeatureTag // e.g. only valid with FEAT_SVE
}

type BitField struct {
	Name   string
	Start  int
	End    int
	Fixed  *uint64
	Source string
}

type BitMask struct {
	Mask uint32 // Bitmask to apply (e.g. 0xFF000000)
}

// InstructionDoc captures documentation and explanation.
type InstructionDoc struct {
	Pseudocode []PseudocodeLine
}

// ----------------------------
// Execution and Modeling Layer
// ----------------------------

type PseudocodeLine struct {
	Raw string
	AST *ExpressionNode
}

type ExpressionNode struct {
	Op       string
	Args     []*ExpressionNode
	Literal  string
	Variable string
	Call     *CallExpr
	Cond     *CondExpr
}

type CallExpr struct {
	FuncName string
	Args     []*ExpressionNode
}

type CondExpr struct {
	Cond      *ExpressionNode
	ThenBlock []*ExpressionNode
	ElseBlock []*ExpressionNode
}

// Explicit architectural effect modeling
// ----------------------------
// Architecture Feature Tags
// ----------------------------

// FeatureTag represents a required architecture feature.
type FeatureTag struct {
	Name        string // e.g. "FEAT_LSE"
	Description string // e.g. "Large System Extensions"
	Required    bool   // true if this must be checked before decoding
}

type FeatureSet struct {
	Tags []FeatureTag
}

// ----------------------------
// Decoder Tree Node
// ----------------------------

// DecoderNode is a node in a decision tree used to decode binary instruction words efficiently.
type DecoderNode struct {
	Mask        uint32           // bitmask
	Value       uint32           // expected value
	BitRange    BitRange         // bits [start:end] checked
	Children    []*DecoderNode   // further refinement
	Instruction *InstructionIR   // set if uniquely resolved, only leaf nodes
	Ambiguous   []*InstructionIR // set if multiple match (fallback case)
	Comment     string           // e.g. opcode meaning
}

// DecoderTree is the root node of a hierarchical bit-match tree.
type DecoderTree struct {
	Root *DecoderNode
}

// Symbol represents a named element extracted from documentation
type Symbol struct {
	Name     string // e.g., “Rd”, “imm5”, “CRm”
	Type     string // e.g., “register”, “immediate”, “field”
	Location string // Optional: e.g., “operand”, “regdiagram”, “encoding”
	Source   string // Optional: e.g., “explanation/symbol”, for provenance
	Doc      string // Optional: any associated text or explanation
}
