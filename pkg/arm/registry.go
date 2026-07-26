package arm

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"mkasm/pkg/ir"
)

// InstructionRegistry stores and indexes parsed instructions
type InstructionRegistry struct {
	mu sync.RWMutex

	// Primary storage
	instructions []*ir.InstructionIR

	// Indexes for fast lookup
	byEncodingID map[string]*ir.InstructionIR
	byMnemonic   map[string][]*ir.InstructionIR
	byClass      map[string][]*ir.InstructionIR
	byFeature    map[string][]*ir.InstructionIR
}

// NewInstructionRegistry creates a new instruction registry
func NewInstructionRegistry() *InstructionRegistry {
	return &InstructionRegistry{
		instructions: make([]*ir.InstructionIR, 0, 10000), // Pre-allocate for performance
		byEncodingID: make(map[string]*ir.InstructionIR),
		byMnemonic:   make(map[string][]*ir.InstructionIR),
		byClass:      make(map[string][]*ir.InstructionIR),
		byFeature:    make(map[string][]*ir.InstructionIR),
	}
}

// Add adds an instruction to the registry
func (r *InstructionRegistry) Add(instr *ir.InstructionIR) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate instruction
	if err := r.validateInstruction(instr); err != nil {
		return fmt.Errorf("invalid instruction: %w", err)
	}

	// Check for duplicates
	if existing, exists := r.byEncodingID[instr.EncodingID]; exists {
		return fmt.Errorf("duplicate encoding ID %s: existing=%s, new=%s",
			instr.EncodingID, existing.Mnemonic, instr.Mnemonic)
	}

	// Add to primary storage
	r.instructions = append(r.instructions, instr)

	// Update indexes
	r.byEncodingID[instr.EncodingID] = instr
	r.byMnemonic[instr.Mnemonic] = append(r.byMnemonic[instr.Mnemonic], instr)
	r.byClass[instr.IClass] = append(r.byClass[instr.IClass], instr)

	// Index by features
	for _, feature := range instr.Features.Tags {
		r.byFeature[feature.Name] = append(r.byFeature[feature.Name], instr)
	}

	return nil
}

// validateInstruction checks if an instruction is valid
func (r *InstructionRegistry) validateInstruction(instr *ir.InstructionIR) error {
	if instr.EncodingID == "" {
		return fmt.Errorf("missing encoding ID")
	}

	if instr.Mnemonic == "" {
		return fmt.Errorf("missing mnemonic")
	}

	if instr.Encoding.Width <= 0 {
		return fmt.Errorf("invalid encoding width: %d", instr.Encoding.Width)
	}

	return nil
}

// GetByEncodingID retrieves an instruction by its encoding ID
func (r *InstructionRegistry) GetByEncodingID(encodingID string) (*ir.InstructionIR, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	instr, exists := r.byEncodingID[encodingID]
	return instr, exists
}

// GetByMnemonic retrieves all instructions with a given mnemonic
func (r *InstructionRegistry) GetByMnemonic(mnemonic string) []*ir.InstructionIR {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Try exact match first
	if instrs, exists := r.byMnemonic[mnemonic]; exists {
		return copyInstructions(instrs)
	}

	// Try case-insensitive match
	upper := strings.ToUpper(mnemonic)
	for m, instrs := range r.byMnemonic {
		if strings.ToUpper(m) == upper {
			return copyInstructions(instrs)
		}
	}

	return nil
}

// GetByClass retrieves all instructions in a given class
func (r *InstructionRegistry) GetByClass(class string) []*ir.InstructionIR {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if instrs, exists := r.byClass[class]; exists {
		return copyInstructions(instrs)
	}

	return nil
}

// GetByFeature retrieves all instructions requiring a specific feature
func (r *InstructionRegistry) GetByFeature(feature string) []*ir.InstructionIR {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if instrs, exists := r.byFeature[feature]; exists {
		return copyInstructions(instrs)
	}

	return nil
}

// GetAll returns all instructions
func (r *InstructionRegistry) GetAll() []*ir.InstructionIR {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return copyInstructions(r.instructions)
}

// Size returns the number of instructions in the registry
func (r *InstructionRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.instructions)
}

// GroupByClass returns instructions grouped by class
func (r *InstructionRegistry) GroupByClass() map[string][]*ir.InstructionIR {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string][]*ir.InstructionIR)
	for class, instrs := range r.byClass {
		result[class] = copyInstructions(instrs)
	}

	return result
}

// GroupByFeature returns instructions grouped by required features
func (r *InstructionRegistry) GroupByFeature() map[string][]*ir.InstructionIR {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string][]*ir.InstructionIR)
	for feature, instrs := range r.byFeature {
		result[feature] = copyInstructions(instrs)
	}

	return result
}

// GetMnemonics returns all unique mnemonics
func (r *InstructionRegistry) GetMnemonics() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mnemonics := make([]string, 0, len(r.byMnemonic))
	for m := range r.byMnemonic {
		mnemonics = append(mnemonics, m)
	}

	sort.Strings(mnemonics)
	return mnemonics
}

// GetClasses returns all unique instruction classes
func (r *InstructionRegistry) GetClasses() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	classes := make([]string, 0, len(r.byClass))
	for c := range r.byClass {
		classes = append(classes, c)
	}

	sort.Strings(classes)
	return classes
}

// GetFeatures returns all unique features
func (r *InstructionRegistry) GetFeatures() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	features := make([]string, 0, len(r.byFeature))
	for f := range r.byFeature {
		features = append(features, f)
	}

	sort.Strings(features)
	return features
}

// Statistics returns registry statistics
func (r *InstructionRegistry) Statistics() RegistryStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RegistryStats{
		TotalInstructions: len(r.instructions),
		UniqueMnemonics:   len(r.byMnemonic),
		UniqueClasses:     len(r.byClass),
		UniqueFeatures:    len(r.byFeature),
		ClassDistribution: make(map[string]int),
		FeatureUsage:      make(map[string]int),
	}

	// Calculate distributions
	for class, instrs := range r.byClass {
		stats.ClassDistribution[class] = len(instrs)
	}

	for feature, instrs := range r.byFeature {
		stats.FeatureUsage[feature] = len(instrs)
	}

	// Find most common mnemonic
	maxCount := 0
	for mnemonic, instrs := range r.byMnemonic {
		if len(instrs) > maxCount {
			maxCount = len(instrs)
			stats.MostCommonMnemonic = mnemonic
		}
	}

	return stats
}

// RegistryStats holds statistics about the registry
type RegistryStats struct {
	TotalInstructions  int
	UniqueMnemonics    int
	UniqueClasses      int
	UniqueFeatures     int
	MostCommonMnemonic string
	ClassDistribution  map[string]int
	FeatureUsage       map[string]int
}

// MatchWord returns instructions whose BitPattern (or encoding fixed bits)
// match the given 32-bit instruction word. O(n) scan; use decoder.Match for tree walks.
// Results are sorted most-specific first (largest fixed-bit mask).
func (r *InstructionRegistry) MatchWord(word uint32) []*ir.InstructionIR {
	r.mu.RLock()
	defer r.mu.RUnlock()

	type hit struct {
		instr *ir.InstructionIR
		bits  int
	}
	var hits []hit
	for _, instr := range r.instructions {
		if !ir.MatchWord(instr, word) {
			continue
		}
		pat := instr.BitPattern
		if pat == "" || !strings.ContainsAny(pat, "01") {
			pat = ir.PatternFromEncoding(instr.Encoding)
		}
		mask, _ := ir.FixedBitsFromPattern(pat)
		if mask == 0 {
			mask, _ = ir.FixedBitsFromEncoding(instr.Encoding)
		}
		hits = append(hits, hit{instr: instr, bits: bitsSet32(mask)})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].bits != hits[j].bits {
			return hits[i].bits > hits[j].bits
		}
		// Prefer canonical encodings over aliases when specificity ties.
		ai, aj := hits[i].instr.AliasOf != "", hits[j].instr.AliasOf != ""
		if ai != aj {
			return !ai && aj
		}
		return hits[i].instr.EncodingID < hits[j].instr.EncodingID
	})
	out := make([]*ir.InstructionIR, len(hits))
	for i := range hits {
		out[i] = hits[i].instr
	}
	return out
}

func bitsSet32(m uint32) int {
	n := 0
	for m != 0 {
		n++
		m &= m - 1
	}
	return n
}

// BestMatch returns the most-specific MatchWord hit, if any.
func (r *InstructionRegistry) BestMatch(word uint32) (*ir.InstructionIR, bool) {
	hits := r.MatchWord(word)
	if len(hits) == 0 {
		return nil, false
	}
	return hits[0], true
}

// Disassemble is BestMatch plus field extraction for the winning encoding.
type Disassembly struct {
	Instruction *ir.InstructionIR
	Word        uint32
	Fields      []ir.FieldValue
	// Alternates are other MatchWord hits after the best (may be empty).
	Alternates []*ir.InstructionIR
}

// Disassemble matches word and extracts fields for the best encoding.
func (r *InstructionRegistry) Disassemble(word uint32) (*Disassembly, bool) {
	hits := r.MatchWord(word)
	if len(hits) == 0 {
		return nil, false
	}
	best := hits[0]
	var alts []*ir.InstructionIR
	if len(hits) > 1 {
		alts = hits[1:]
	}
	return &Disassembly{
		Instruction: best,
		Word:        word,
		Fields:      ir.ExtractFields(word, best.Encoding),
		Alternates:  alts,
	}, true
}

// ResolvedCount returns how many instructions look Pass-2-resolved.
func (r *InstructionRegistry) ResolvedCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, instr := range r.instructions {
		if hasPass2Encoding(instr) {
			n++
		}
	}
	return n
}

// copyInstructions creates a defensive copy of instruction slice
func copyInstructions(instructions []*ir.InstructionIR) []*ir.InstructionIR {
	result := make([]*ir.InstructionIR, len(instructions))
	copy(result, instructions)
	return result
}
