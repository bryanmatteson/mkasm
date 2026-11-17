package ptx

import "testing"

func TestCompleteRegistryRenderedTemplateMatching(t *testing.T) {
	count := 0
	for _, record := range Default().LLVM {
		if record.Syntax == "" {
			continue
		}
		template, err := CompileTemplate(record.Syntax)
		if err != nil {
			t.Fatal(record.ID, err)
		}
		bindings := map[string]string{}
		for _, hole := range template.Holes {
			key := hole.Name
			if hole.Format != "" {
				key += ":" + hole.Format
			}
			bindings[key] = "rendered_" + key
		}
		text, err := template.Fill(bindings)
		if err != nil {
			t.Fatal(record.ID, err)
		}
		captured, ok := template.Match(text)
		if !ok {
			t.Fatal(record.ID, "rendered template did not match")
		}
		actual, err := template.Fill(captured)
		if err != nil || actual != text {
			t.Fatal(record.ID, "captures did not retain text", err)
		}
		count++
	}
	if count != 6321 {
		t.Fatal("printed source corpus changed", count)
	}
}

func TestTemplateMatchConstraintsAndUTF8(t *testing.T) {
	template, err := CompileTemplate("add $same, $same; $$symbol ${value:format}")
	if err != nil {
		t.Fatal(err)
	}
	text := "add %r1, %r1; $symbol λ, {nested}"
	values, ok := template.Match(text)
	if !ok || values["same"] != "%r1" || values["value:format"] != "λ, {nested}" {
		t.Fatal(values, ok)
	}
	for _, invalid := range []string{"add %r1, %r2; $symbol λ", "sub %r1, %r1; $symbol λ"} {
		if _, ok := template.Match(invalid); ok {
			t.Fatal("accepted inconsistent template", invalid)
		}
	}
}
