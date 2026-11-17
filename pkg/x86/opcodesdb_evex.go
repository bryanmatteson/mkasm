package x86

import (
	"fmt"
	"strconv"
	"strings"
)

// normalizeOpcodesDBEVEX preserves opcodesDB's physical b-bit constraints and
// the distinction between raw LL control bits and the effective vector width.
// RVL is the source's logical width for ER/SAE register forms; an absent VL on
// an otherwise XMM-only form describes LLIG, including scalar memory forms.
func normalizeOpcodesDBEVEX(e *Encoding, fields map[string]string) error {
	if e.Kind != EncodingEVEX {
		return nil
	}
	if bp := fields["BP"]; bp != "" {
		if bp != "0" && bp != "1" {
			return fmt.Errorf("invalid EVEX BP %q", bp)
		}
		e.EVEXMask |= 16
		if bp == "1" {
			e.EVEXValue |= 16
		}
	}
	for _, o := range e.Operands {
		if o.EncodedIn != "VPREFIX" {
			continue
		}
		switch strings.ToUpper(o.Type) {
		case "RC":
			e.EmbeddedRounding = true
			e.SuppressExceptions = true
		case "SAE":
			e.SuppressExceptions = true
		}
	}
	if raw := fields["RVL"]; raw != "" {
		vl, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || vl != 128 && vl != 256 && vl != 512 {
			return fmt.Errorf("invalid EVEX RVL %q", raw)
		}
		e.VectorLength = uint16(vl)
	} else if fields["VL"] == "" {
		xmm, wider := false, false
		for _, o := range e.Operands {
			if o.Type != "VREG" {
				continue
			}
			switch o.Symbol {
			case "XMMREG":
				xmm = true
			case "YMMREG", "ZMMREG":
				wider = true
			}
		}
		if xmm && !wider {
			e.VectorLength = 128
			e.VectorLengthIgnored = true
		}
	}
	if e.SuppressExceptions && (e.Mod != ModRegister || fields["BP"] != "1" || fields["RVL"] == "") {
		return fmt.Errorf("EVEX ER/SAE requires source register/BP=1/RVL constraints")
	}
	return nil
}
