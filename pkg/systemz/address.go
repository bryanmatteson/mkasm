package systemz

import (
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// memoryVariants accepts the GNU assembler's omitted zero base/index forms.
// Canonical decode keeps explicit operands so it remains completely lossless.
func memoryVariants(original codec.Encoding, addresses []address) ([]codec.Encoding, error) {
	forms := []codec.Encoding{original}
	for _, a := range addresses {
		var next []codec.Encoding
		for _, e := range forms {
			next = append(next, e)
			if !strings.Contains(e.Syntax, addressSyntax(a)) {
				continue
			}
			base, disp := a.Children[0], a.Children[1]
			add := func(replacement string, zeros ...string) error {
				v := e
				v.Mask = append([]byte(nil), e.Mask...)
				v.Value = append([]byte(nil), e.Value...)
				v.Operands = append([]codec.Operand(nil), e.Operands...)
				v.Syntax = strings.ReplaceAll(v.Syntax, addressSyntax(a), replacement)
				for _, name := range zeros {
					at := -1
					for i, o := range v.Operands {
						if o.Name == name {
							at = i
							if err := fixOperand(&v, o, 0); err != nil {
								return err
							}
							break
						}
					}
					if at < 0 {
						return fmt.Errorf("missing zero-address field %s", name)
					}
					v.Operands = append(v.Operands[:at], v.Operands[at+1:]...)
				}
				next = append(next, v)
				return nil
			}
			if len(a.Children) == 2 {
				if err := add("{"+disp+"}", base); err != nil {
					return nil, err
				}
			} else if strings.HasPrefix(a.Types[2], "ADDR") {
				index := a.Children[2]
				if err := add("{"+disp+"}({"+base+"})", index); err != nil {
					return nil, err
				}
				if err := add("{"+disp+"}", index, base); err != nil {
					return nil, err
				}
			} else if !strings.HasPrefix(a.Types[2], "VR") {
				if err := add("{"+disp+"}({"+a.Children[2]+"})", base); err != nil {
					return nil, err
				}
			}
		}
		forms = next
	}
	var variants []codec.Encoding
	for i := 1; i < len(forms); i++ {
		v := forms[i]
		v.ID = fmt.Sprintf("%s_memory_%d", original.ID, i)
		v.AssemblyOnly = true
		variants = append(variants, v)
	}
	return variants, nil
}
