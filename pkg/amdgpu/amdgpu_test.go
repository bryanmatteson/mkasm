package amdgpu

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func representative(e *codec.Encoding) map[string]int64 {
	values := map[string]int64{}
	for _, o := range e.Operands {
		v := int64(0)
		if o.Name == "format" {
			v = 1
		} else if o.Name == "literal" {
			v = 0x12345678
			if o.Class == "AMDGPU_literal16" {
				v = 0x1234
			}
			if o.Class == "AMDGPU_literal64" {
				v = 0x123456789abcdef0
			}
		} else if o.Name == "imm" && strings.Contains(e.ID, "/literal") {
			v = 0x1234
		} else if o.Class == "smrd_literal_offset" {
			v = 0x12345
		} else if len(o.Names) > 0 {
			var mask uint64
			for _, b := range o.Bits {
				mask |= ((uint64(1) << uint(b.Width)) - 1) << uint(b.ValueBit)
			}
			for k, n := range o.Names {
				if n != "" && uint64(k)&^mask == 0 {
					v = int64(k)
					break
				}
			}
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		if len(o.Names) > 0 {
			// Vector sources avoid inventing additional scalar constant-bus uses.
			for k, n := range o.Names {
				if len(n) > 1 && (n[0] == 'v' || n[0] == 'a') && (n[1] >= '0' && n[1] <= '9' || n[1] == '[') && (strings.HasPrefix(o.Name, "src") || o.Name == "vdata") {
					var mask uint64
					for _, b := range o.Bits {
						mask |= ((uint64(1) << uint(b.Width)) - 1) << uint(b.ValueBit)
					}
					if uint64(k)&^mask == 0 {
						v = int64(k)
						break
					}
				}
			}
		}
		values[o.Name] = v*scale + o.Bias
	}
	if strings.HasPrefix(e.ID, "IMAGE_") && !strings.Contains(e.ID, "BVH") {
		words := 1
		for _, o := range e.Operands {
			if o.Name == "vdata" {
				k := (values[o.Name] - o.Bias)
				if k >= 0 && k < int64(len(o.Names)) {
					var a, b int
					if _, err := fmt.Sscanf(o.Names[k], "v[%d:%d]", &a, &b); err == nil {
						words = b - a + 1
					}
				}
			}
		}

		if strings.Contains(e.Mnemonic, "gather4") {
			values["dmask"] = 1
			if words == 2 || words == 3 {
				if _, ok := values["d16"]; ok {
					values["d16"] = 1
				}
			}
			if words == 3 || words == 5 {
				if _, ok := values["tfe"]; ok {
					values["tfe"] = 1
				}
			}
		} else {
			if words == 3 && strings.Contains(e.Mnemonic, "atomic") || words == 5 {
				if _, ok := values["tfe"]; ok {
					values["tfe"] = 1
					words--
				}
			}
			if words > 4 {
				words = 4
			}
			values["dmask"] = (1 << words) - 1
		}
	}
	if strings.HasPrefix(e.ID, "V_DUAL_") {
		for _, o := range e.Operands {
			target := ""
			switch o.Name {
			case "src0X":
				target = "v0"
			case "src1X", "vsrc1X":
				target = "v2"
			case "src2X", "vsrc2X":
				target = "v4"
			case "src0Y":
				target = "v1"
			case "src1Y", "vsrc1Y":
				target = "v3"
			case "src2Y", "vsrc2Y":
				target = "v5"
			case "vdstY":
				if o.Class != "VOPDDstYOperand" {
					target = "v2"
				}
			}
			if target != "" {
				for k, n := range o.Names {
					if n == target {
						values[o.Name] = int64(k) + o.Bias
						break
					}
				}

			}
		}
		// Tuple operands must use different source banks across the two
		// operations, just as scalar-width VGPR operands do.
		for _, pair := range [][2]string{{"src0X", "src0Y"}, {"vsrc1X", "vsrc1Y"}, {"vsrc2X", "vsrc2Y"}, {"src1X", "src1Y"}, {"src2X", "src2Y"}} {
			x, y := operandIndex(*e, pair[0]), operandIndex(*e, pair[1])
			if x < 0 || y < 0 {
				continue
			}
			ox, oy := e.Operands[x], e.Operands[y]
			kx := values[ox.Name] - ox.Bias
			if kx < 0 || kx >= int64(len(ox.Names)) {
				continue
			}
			var a, b int
			if _, err := fmt.Sscanf(ox.Names[kx], "v[%d:%d]", &a, &b); err != nil {
				continue
			}
			for k, n := range oy.Names {
				var c, d int
				if _, err := fmt.Sscanf(n, "v[%d:%d]", &c, &d); err == nil && c&3 != a&3 {
					values[oy.Name] = int64(k) + oy.Bias
					break
				}
			}
		}
	}
	for _, o := range e.Operands {
		if o.Name == "dpp_ctrl" && (strings.Contains(e.ID, "F64") || strings.Contains(e.ID, "U64")) {
			values[o.Name] = 0x150
		}
	}
	if _, ok := values["literal"]; ok {
		if strings.Contains(e.ID, "F16") || strings.Contains(e.ID, "I16") || strings.Contains(e.ID, "U16") || strings.Contains(e.ID, "B16") {
			values["literal"] = 0x1234
		}
	}
	return values
}
func enabled(e *codec.Encoding, features []string) bool {
	for _, r := range e.Features {
		found := false
		for _, f := range features {
			if f == r {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func oracleText(e codec.Encoding, values map[string]int64) string {
	e.Operands = append([]codec.Operand(nil), e.Operands...)
	vs := map[string]int64{}
	for k, v := range values {
		vs[k] = v
	}
	for i := range e.Operands {
		o := &e.Operands[i]
		if o.Relative {
			o.Relative = false
			o.Kind = "immediate"
			scale := o.Scale
			if scale == 0 {
				scale = 1
			}
			vs[o.Name] /= scale
			o.Scale = 1
		}
	}
	return (&codec.Decoded{Encoding: &e, Values: vs, Length: len(e.Mask)}).Format(0)
}

// This optional test traverses the entire real source corpus, never a synthetic
// opcode list. Ordinary forms use LLVM assembly/object emission; NonParsable
// physical forms use the compiled LLVM disassembler/code emitter on a compatible
// source-derived processor profile, with normalization reported separately.
func TestFullLLVMCorpus(t *testing.T) {
	path := os.Getenv("MKASM_AMDGPU_TABLEGEN")
	if path == "" {
		t.Skip("set MKASM_AMDGPU_TABLEGEN to LLVM's resolved AMDGPU dump")
	}
	llvm := "/opt/homebrew/opt/llvm/bin/llvm-mc"
	if _, err := os.Stat(llvm); err != nil {
		t.Skip(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	images := map[string]imageInfo{}
	c, err := parseWithInspector(file, "amdgpu", func(p *importer) {
		for id := range p.raw {
			if strings.HasPrefix(id, "IMAGE_") {
				r := p.rec(id)
				if r.BaseOpcode.Def != "" {
					images[id] = p.rec(r.BaseOpcode.Def).imageInfo
				}
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if output := os.Getenv("MKASM_AMDGPU_RUST"); output != "" {
		if err := c.GenerateRust(output); err != nil {
			t.Fatal(err)
		}
		consumer, err := os.ReadFile("testdata/consumer.rs")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, "tests", "consumer.rs"), consumer, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.Encodings) < 15000 {
		t.Fatalf("only %d forms", len(c.Encodings))
	}
	output := os.Getenv("MKASM_AMDGPU_ARTIFACTS")
	if output == "" {
		output = t.TempDir()
	}
	if err := os.MkdirAll(output, 0755); err != nil {
		t.Fatal(err)
	}
	cpus := []string{"gfx600", "gfx700", "gfx803", "gfx900", "gfx90a", "gfx942", "gfx950", "gfx1010", "gfx1030", "gfx1100", "gfx1200", "gfx1250"}
	for _, base := range append([]string(nil), cpus...) {
		cpus = append(cpus, base+"-wave32", base+"-wave64", base+"-true16", base+"-true16-wave32", base+"-true16-wave64")
	}
	var extra []string
	for cpu := range c.FeatureSets {
		found := false
		for _, x := range cpus {
			if x == cpu {
				found = true
			}
		}
		if !found {
			extra = append(extra, cpu)
		}
	}
	sort.Strings(extra)
	cpus = append(cpus, extra...)
	type sample struct {
		ID, Text, Hex, CPU string
		Reason             string `json:",omitempty"`
		Bytes              []byte `json:"-"`
	}
	groups := map[string][]sample{}
	alternateGroups := map[string][]alternateNativeSample{}
	var unavailable []string
	var encodeErrors []string
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if e.AssemblyOnly {
			continue
		}
		cpu := ""
		for _, candidate := range cpus {
			if fs, ok := c.FeatureSets[candidate]; ok && enabled(e, fs) {
				cpu = candidate
				break
			}
		}
		if cpu == "" {
			unavailable = append(unavailable, e.ID)
			continue
		}
		values := representative(e)
		if info, ok := images[strings.Split(e.ID, "/")[0]]; ok && len(e.Constraints) == 0 {
			imageRepresentative(e, values, info)
		}
		for _, constraint := range e.Constraints {
			if constraint.Kind == "tuple_in" {
				for k, name := range constraint.Operands {
					values[name] = constraint.Allowed[0][k]
				}
			}
			if constraint.Kind == "masked_ne" {
				l, r := values[constraint.Left], values[constraint.Right]
				if sampleBankMatch(constraint, l, r) {
					continue
				}
				j := operandIndex(*e, constraint.Right)
				if j < 0 {
					continue
				}
				o := e.Operands[j]
				for k, n := range o.Names {
					if len(n) < 2 || n[0] != 'v' || n[1] != '[' && (n[1] < '0' || n[1] > '9') {
						continue
					}
					v := int64(k) + o.Bias
					if sampleBankMatch(constraint, l, v) {
						values[o.Name] = v
						break
					}
				}

				if !sampleBankMatch(constraint, values[constraint.Left], values[constraint.Right]) {
					j = operandIndex(*e, constraint.Left)
					if j >= 0 {
						o = e.Operands[j]
						for k, n := range o.Names {
							if len(n) < 2 || n[0] != 'v' || n[1] != '[' && (n[1] < '0' || n[1] > '9') {
								continue
							}
							v := int64(k) + o.Bias
							if sampleBankMatch(constraint, v, values[constraint.Right]) {
								values[o.Name] = v
								break
							}
						}
					}
				}
			}
		}
		encoded, err := c.Encode(e.ID, values)
		if err != nil {
			encodeErrors = append(encodeErrors, e.ID+": "+err.Error())
			continue
		}
		if strings.HasPrefix(e.Syntax, "enc[") {
			// These source records have AsmVariantName=NonParsable. Keep their
			// exact private syntax out of the LLVM parser: it cannot express
			// otherwise unprinted physical fields such as the SGPR Offset.
			offsets := []int64{values["Offset"]}
			if _, ok := values["Offset"]; ok {
				offsets = []int64{0, 1, 127, 256, 511}
			}
			for _, offset := range offsets {
				v := map[string]int64{}
				for name, value := range values {
					v[name] = value
				}
				if _, ok := v["Offset"]; ok {
					v["Offset"] = offset
				}
				code, err := c.Encode(e.ID, v)
				if err != nil {
					encodeErrors = append(encodeErrors, e.ID+": "+err.Error())
					continue
				}
				text := (&codec.Decoded{Encoding: e, Values: v, Length: len(code)}).Format(0)
				parsed, ok := codec.ParseOperands(e, text, 0)
				if !ok {
					t.Fatalf("alternate raw syntax failed: %s %q", e.ID, text)
				}
				back, err := c.Encode(e.ID, parsed)
				if err != nil || !bytes.Equal(code, back) {
					t.Fatalf("alternate raw syntax lost fields: %s %x -> %x: %v", e.ID, code, back, err)
				}
				alternateGroups[cpu] = append(alternateGroups[cpu], alternateNativeSample{ID: e.ID, Text: text, Hex: hex.EncodeToString(code), CPU: cpu, Values: v, Mnemonic: e.Mnemonic})
			}
			continue
		}
		groups[cpu] = append(groups[cpu], sample{ID: e.ID, Text: oracleText(*e, values), Hex: hex.EncodeToString(encoded), CPU: cpu, Bytes: encoded})
	}
	encodingPattern := regexp.MustCompile(`encoding: \[([^]]+)\]`)
	labelPattern := regexp.MustCompile(`^case_([0-9]+):`)
	var accepted, rejected, mismatch []sample
	objectMatches := 0
	for _, cpu := range cpus {
		samples := groups[cpu]
		if len(samples) == 0 {
			continue
		}
		var input strings.Builder
		for i, s := range samples {
			fmt.Fprintf(&input, "case_%d:\n%s\n", i, s.Text)
		}
		source := filepath.Join(output, cpu+".s")
		_ = os.WriteFile(source, []byte(input.String()), 0644)
		target := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(cpu, "-wave32"), "-wave64"), "-true16")
		arguments := []string{"-triple=amdgcn", "-mcpu=" + target, "-show-encoding", source}
		var attrs []string
		if strings.Contains(cpu, "-wave32") {
			attrs = append(attrs, "+wavefrontsize32", "-wavefrontsize64")
		}
		if strings.Contains(cpu, "-wave64") {
			attrs = append(attrs, "-wavefrontsize32", "+wavefrontsize64")
		}
		if strings.Contains(cpu, "-true16") {
			attrs = append(attrs, "+real-true16")
		}
		if len(attrs) > 0 {
			arguments = append(arguments, "-mattr="+strings.Join(attrs, ","))
		}
		command := exec.Command(llvm, arguments...)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		stdout, _ := command.Output()
		_ = os.WriteFile(filepath.Join(output, cpu+".out"), stdout, 0644)
		_ = os.WriteFile(filepath.Join(output, cpu+".err"), stderr.Bytes(), 0644)
		actual := map[int][]byte{}
		index := -1
		scan := bufio.NewScanner(bytes.NewReader(stdout))
		for scan.Scan() {
			line := scan.Text()
			if m := labelPattern.FindStringSubmatch(line); m != nil {
				index, _ = strconv.Atoi(m[1])
				continue
			}
			if m := encodingPattern.FindStringSubmatch(line); m != nil && index >= 0 {
				var b []byte
				valid := true
				for _, s := range strings.Split(m[1], ",") {
					v, e := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
					if e != nil {
						valid = false
						break
					}
					b = append(b, byte(v))
				}
				if valid {
					actual[index] = b
				}
			}
		}
		if err := scan.Err(); err != nil {
			t.Fatal(err)
		}
		// Read the actual ELF .text section as well as LLVM's textual encoding
		// annotations. Labels identify instruction boundaries independently of
		// the imported bit descriptions and expose object-emission differences.
		objectArgs := append([]string(nil), arguments...)
		for i, arg := range objectArgs {
			if arg == "-show-encoding" {
				objectArgs[i] = "-filetype=obj"
			}
		}
		objectCommand := exec.Command(llvm, objectArgs...)
		var objectStderr bytes.Buffer
		objectCommand.Stderr = &objectStderr
		objectBytes, objectErr := objectCommand.Output()
		_ = os.WriteFile(filepath.Join(output, cpu+".object.err"), objectStderr.Bytes(), 0644)
		if objectErr != nil {
			t.Errorf("LLVM %s object emission: %v\n%s", cpu, objectErr, objectStderr.String())
		} else {
			_ = os.WriteFile(filepath.Join(output, cpu+".o"), objectBytes, 0644)
			object, err := elf.NewFile(bytes.NewReader(objectBytes))
			if err != nil {
				t.Fatal(err)
			}
			section := object.Section(".text")
			if section == nil {
				t.Fatal("LLVM object has no .text section")
			}
			code, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}
			symbols, err := object.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			positions := map[int]uint64{}
			for _, symbol := range symbols {
				if strings.HasPrefix(symbol.Name, "case_") {
					if index, err := strconv.Atoi(strings.TrimPrefix(symbol.Name, "case_")); err == nil {
						positions[index] = symbol.Value - section.Addr
					}
				}
			}
			for index, encoded := range actual {
				position, ok := positions[index]
				if !ok || position+uint64(len(encoded)) > uint64(len(code)) || !bytes.Equal(code[position:position+uint64(len(encoded))], encoded) {
					t.Errorf("LLVM object bytes differ for %s: offset %#x, present %v", samples[index].ID, position, ok)
					continue
				}
				objectMatches++
			}
			_ = object.Close()
		}
		diagnostics := map[int]string{}
		for _, m := range regexp.MustCompile(`(?m):([0-9]+):[0-9]+: error: ([^\n]+)`).FindAllStringSubmatch(stderr.String(), -1) {
			line, _ := strconv.Atoi(m[1])
			diagnostics[(line-2)/2] = m[2]
		}
		for i, s := range samples {
			b, ok := actual[i]
			if !ok {
				s.Reason = diagnostics[i]
				rejected = append(rejected, s)
			} else if !bytes.Equal(b, s.Bytes) {
				s.Hex += " != " + hex.EncodeToString(b)
				mismatch = append(mismatch, s)
			} else {
				accepted = append(accepted, s)
			}
		}
	}
	var alternateExact, alternateNormalized, alternateRejected []alternateNativeSample
	alternateRecords, alternateForms := map[string]bool{}, map[string]bool{}
	if len(alternateGroups) != 0 {
		executable := buildAlternateNativeOracle(t, output)
		for _, cpu := range cpus {
			samples := alternateGroups[cpu]
			if len(samples) == 0 {
				continue
			}
			for _, result := range runAlternateNativeOracle(t, executable, output, cpu, samples) {
				alternateRecords[strings.Split(result.ID, "/")[0]] = true
				alternateForms[result.ID] = true
				raw, err := hex.DecodeString(result.Hex)
				if err != nil {
					t.Fatal(err)
				}
				if result.Status != 3 || result.Length != len(raw) || result.LLVMText == "" || strings.Fields(result.LLVMText)[0] != result.Mnemonic {
					alternateRejected = append(alternateRejected, result)
				} else if result.LLVMHex == result.Hex {
					alternateExact = append(alternateExact, result)
				} else {
					alternateNormalized = append(alternateNormalized, result)
				}
			}
		}
	}
	// LLVM intentionally canonicalizes some valid VOPD forms to VOPD3.
	// Independently disassemble their original bytes and require both the exact
	// bytes and the same instruction text before treating them as source aliases.
	var canonicalized []sample
	var unresolved []sample
	for _, s := range mismatch {
		if !strings.HasPrefix(s.ID, "V_DUAL_") {
			unresolved = append(unresolved, s)
			continue
		}
		command := exec.Command(llvm, "-triple=amdgcn", "-mcpu="+s.CPU, "-disassemble", "-show-encoding")
		var input strings.Builder
		for _, b := range s.Bytes {
			fmt.Fprintf(&input, "0x%02x ", b)
		}
		input.WriteByte('\n')
		command.Stdin = strings.NewReader(input.String())
		out, err := command.Output()
		if err != nil {
			unresolved = append(unresolved, s)
			continue
		}
		m := encodingPattern.FindSubmatch(out)
		var actual []byte
		if m != nil {
			for _, part := range strings.Split(string(m[1]), ",") {
				v, _ := strconv.ParseUint(strings.TrimSpace(part), 0, 8)
				actual = append(actual, byte(v))
			}
		}
		printed := strings.Split(string(out), ";")[0]
		normalize := func(s string) string { return strings.Join(strings.Fields(s), "") }
		if bytes.Equal(actual, s.Bytes) && normalize(printed) == normalize(s.Text) {
			canonicalized = append(canonicalized, s)
		} else {
			unresolved = append(unresolved, s)
		}
	}
	mismatch = unresolved
	sort.Strings(unavailable)
	report := map[string]any{"encodings": len(c.Encodings), "unsupported": c.Unsupported, "matched": len(accepted), "object_matches": objectMatches, "canonicalized_by_llvm": canonicalized, "rejected": rejected, "mismatched": mismatch, "no_cpu_profile": unavailable, "encode_errors": encodeErrors, "alternate_source_records": len(alternateRecords), "alternate_forms": len(alternateForms), "alternate_native_exact_reemission": alternateExact, "alternate_native_normalized": alternateNormalized, "alternate_native_rejected": alternateRejected}
	b, _ := json.MarshalIndent(report, "", "  ")
	_ = os.WriteFile(filepath.Join(output, "parity.json"), b, 0644)
	t.Logf("%d forms; %d exact LLVM matches; %d rejected; %d mismatches; %d no CPU; %d encode errors; %d unsupported", len(c.Encodings), len(accepted), len(rejected), len(mismatch), len(unavailable), len(encodeErrors), len(c.Unsupported))
	t.Logf("%d additional source forms independently confirmed by LLVM disassembly after canonical assembly chose another framing", len(canonicalized))
	t.Logf("%d forms independently checked against emitted ELF .text bytes", objectMatches)
	t.Logf("%d alternate source records / %d forms: %d native decode+emit exact samples, %d native decode samples normalized on re-emission, %d native decode rejections", len(alternateRecords), len(alternateForms), len(alternateExact), len(alternateNormalized), len(alternateRejected))
	for _, result := range alternateRejected[:min(10, len(alternateRejected))] {
		t.Logf("ALTERNATE NATIVE REJECTION %+v", result)
	}
	for _, s := range mismatch[:min(10, len(mismatch))] {
		t.Logf("MISMATCH %s %s %s", s.ID, s.Text, s.Hex)
	}
	if len(mismatch) > 0 || len(encodeErrors) > 0 || len(rejected) > 0 || len(unavailable) > 0 || len(alternateRejected) > 0 {
		t.Fail()
	}
}

func sampleBankMatch(c codec.Constraint, l, r int64) bool {
	if c.LeftWhenMask != 0 && l&c.LeftWhenMask == 0 || c.RightWhenMask != 0 && r&c.RightWhenMask == 0 {
		return true
	}
	if c.EqualMask != 0 && l&c.EqualMask == r&c.EqualMask {
		return true
	}
	lspan, rspan := max(c.LeftSpan, 1), max(c.RightSpan, 1)
	for i := 0; i < lspan; i++ {
		for j := 0; j < rspan; j++ {
			if (l+int64(i))&c.Limit == (r+int64(j))&c.Limit {
				return false
			}
		}
	}
	return true
}

// Choose an address shape from the actual MIMG base-opcode properties, using
// the same documented coordinate/gradient packing independently of Inst bits.
func imageRepresentative(e *codec.Encoding, values map[string]int64, info imageInfo) {
	if info.BVH != 0 {
		return
	}
	if _, ok := values["dim"]; !ok {
		return
	}
	words := 0
	for _, o := range e.Operands {
		if strings.HasPrefix(o.Name, "vaddr") {
			v := values[o.Name] - o.Bias
			if v >= 0 && v < int64(len(o.Names)) {
				name := o.Names[v]
				var a, b int
				if _, err := fmt.Sscanf(name, "v[%d:%d]", &a, &b); err == nil {
					words += b - a + 1
				} else {
					words++
				}
			}
		}
	}
	coords := []int{1, 2, 3, 3, 2, 3, 3, 4}
	gradients := []int{2, 4, 6, 4, 2, 4, 4, 4}
	for a16 := 0; a16 <= 1; a16++ {
		if a16 != 0 {
			if _, ok := values["a16"]; !ok {
				continue
			}
		}
		for dim := 0; dim < 8; dim++ {
			if info.MSAA != 0 && dim < 6 {
				continue
			}
			size := int(info.NumExtraArgs)
			components := info.Coordinates*coords[dim] + info.LodOrClampOrMip
			if a16 != 0 {
				size += (components + 1) / 2
			} else {
				size += components
			}
			if info.Gradients != 0 {
				g := gradients[dim]
				if info.G16 != 0 {
					g = ((g / 2) + 1) &^ 1
				}
				size += g
			}
			if size == words || words == 8 && size >= 5 && size <= 7 {
				values["dim"] = int64(dim)
				if _, ok := values["a16"]; ok {
					values["a16"] = int64(a16)
				}
				return
			}
		}
	}
}
