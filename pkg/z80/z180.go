package z80

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"regexp"
	"strconv"
	"strings"
)

var cRow = regexp.MustCompile(`\{\s*(0x[0-9A-Fa-f]+),\s*(0x[0-9A-Fa-f]+),\s*(\w+),\s*("(?:[^"\\]|\\.)*"),\s*([^}]+)\}`)
var cNumber = regexp.MustCompile(`0x%0?[24]x`)

func z180Extensions(input []codec.Encoding) ([]codec.Encoding, error) {
	start := strings.Index(GNUDescription, "opc_ed[]")
	if start < 0 {
		return nil, fmt.Errorf("missing GNU ED opcode table")
	}
	end := strings.Index(GNUDescription[start:], "};")
	if end < 0 {
		return nil, fmt.Errorf("unterminated GNU ED table")
	}
	rows := cRow.FindAllStringSubmatch(GNUDescription[start:start+end], -1)
	out := make([]codec.Encoding, 0, len(input))
	for _, e := range input {
		if !strings.HasPrefix(e.ID, "ed") {
			out = append(out, e)
		}
	}
	regs := []string{"B", "C", "D", "E", "H", "L", "(HL)", "A"}
	pairs := []string{"BC", "DE", "HL", "SP"}
	for op := 0; op < 256; op++ {
		for _, r := range rows {
			val, _ := strconv.ParseInt(r[1], 0, 16)
			mask, _ := strconv.ParseInt(r[2], 0, 16)
			if int64(op)&mask != val {
				continue
			}
			features := strings.TrimSpace(r[5])
			if features != "INSS_ALL" && !strings.Contains(features, "INSS_Z180") {
				continue
			}
			if r[3] == "dump" {
				if op == 0x30 && strings.Contains(GhidraDescription, ":IN0 Flag,IOAddr8") {
					e, err := makeEncoding(record{"ed30", "IN0 F,(n)", ""}, "", "z180")
					if err != nil {
						return nil, err
					}
					out = append(out, e)
				}
				break
			}
			text, err := strconv.Unquote(r[4])
			if err != nil {
				return nil, err
			}
			switch r[3] {
			case "cis":
				prefix := []string{"LD", "CP", "IN", "OUT"}[op&3]
				if op&0x13 == 0x13 {
					prefix = "OT"
				}
				direction := "I"
				if op&8 != 0 {
					direction = "D"
				}
				repeat := ""
				if op&16 != 0 {
					repeat = "R"
				}
				text = prefix + direction + repeat
			case "cism":
				// GNU's broad mask also admits eZ80's INIM family. The actual
				// Z180 execution source marks these encodings illegal.
				if strings.Contains(Z180EDDescription, fmt.Sprintf("OP(ed,%02x) { illegal_2();", op)) {
					break
				}
				if op&1 == 0 {
					return nil, fmt.Errorf("unclassified Z180 block opcode %02x", op)
				}
				prefix := "IN"
				if op&1 != 0 {
					prefix = "OT"
				}
				direction := "I"
				if op&8 != 0 {
					direction = "D"
				}
				repeat := ""
				if op&16 != 0 {
					repeat = "R"
				}
				text = prefix + direction + "M" + repeat
			case "prt", "prt_n", "prt_nn":
			case "prt_rr", "prt_rr_nn":
				reg := pairs[(op>>4)&3]
				if strings.Contains(text, "%s") {
					text = strings.ReplaceAll(text, "%s", reg)
				} else {
					text += reg
				}
			case "prt_r", "prt_r_n":
				reg := regs[(op>>3)&7]
				if op == 0x30 {
					reg = "F"
				}
				if op == 0x31 {
					break
				}
				text = strings.ReplaceAll(text, "%s", reg)
			default:
				return nil, fmt.Errorf("unimplemented source Z180 handler %s", r[3])
			}
			if r[3] == "cism" && op&1 == 0 {
				break
			}
			if op == 0x31 {
				break
			}
			for strings.Contains(text, "%%") {
				text = strings.ReplaceAll(text, "%%", "%")
			}
			text = strings.ToUpper(text)
			text = cNumber.ReplaceAllStringFunc(strings.ToLower(text), func(v string) string {
				if strings.Contains(v, "4") {
					return "w"
				}
				return "n"
			})
			// Restore register names and mnemonics without uppercasing operand tokens.
			words := strings.Fields(text)
			for i, w := range words {
				words[i] = regexp.MustCompile(`[a-z][a-z0-9']*`).ReplaceAllStringFunc(w, func(v string) string {
					if v == "n" || v == "w" {
						return v
					}
					return strings.ToUpper(v)
				})
			}
			text = strings.Join(words, " ")
			e, err := makeEncoding(record{fmt.Sprintf("ed%02x", op), text, ""}, "", "z180")
			if err != nil {
				return nil, err
			}
			if e.ID == "" {
				return nil, fmt.Errorf("filtered documented Z180 source %02x", op)
			}
			out = append(out, e)
			break
		}
	}
	return out, nil
}
