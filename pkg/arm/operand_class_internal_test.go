package arm

import "testing"

func TestStripNumericVariant(t *testing.T) {
	tests := map[string]string{
		"Wn":                 "Wn",
		"Wn__1":              "Wn",
		"Wn_option__42":      "Wn_option",
		"Wn__":               "Wn__",
		"Wn__not_a_number":   "Wn__not_a_number",
		"Wn__12_more_suffix": "Wn__12_more_suffix",
	}
	for input, want := range tests {
		if got := stripNumericVariant(input); got != want {
			t.Errorf("stripNumericVariant(%q) = %q, want %q", input, got, want)
		}
	}
}
