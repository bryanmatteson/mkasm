package dotnet

type Property struct {
	Token         Token             `json:"token"`
	DeclaringType Token             `json:"declaring_type"`
	Name          string            `json:"name"`
	Flags         uint32            `json:"flags"`
	Signature     *Signature        `json:"signature"`
	Accessors     []MethodSemantics `json:"accessors"`
}
type Event struct {
	Token         Token             `json:"token"`
	DeclaringType Token             `json:"declaring_type"`
	Name          string            `json:"name"`
	Flags         uint32            `json:"flags"`
	Type          Token             `json:"type"`
	Accessors     []MethodSemantics `json:"accessors"`
}
type MethodSemantics struct {
	Flags  uint32 `json:"flags"`
	Method Token  `json:"method"`
}

func (m *Metadata) accessors(t Token) []MethodSemantics {
	var out []MethodSemantics
	for rid := uint32(1); rid <= m.Tables[24].Count; rid++ {
		r, _ := m.Row(24, rid)
		a, _ := DecodeCoded("HasSemantics", r[2])
		if a == t {
			out = append(out, MethodSemantics{r[0], Token(6<<24 | r[1])})
		}
	}
	return out
}
func (m *Metadata) listOwners(table uint8, target uint8) (map[Token]Token, error) {
	out := map[Token]Token{}
	for rid := uint32(1); rid <= m.Tables[table].Count; rid++ {
		r, _ := m.Row(table, rid)
		list, e := m.Range(table, rid, 1, target)
		if e != nil {
			return nil, e
		}
		for _, t := range list {
			if out[t] != 0 {
				return nil, bad("duplicate metadata member owner")
			}
			out[t] = Token(2<<24 | r[0])
		}
	}
	return out, nil
}
func (m *Metadata) Properties() ([]Property, error) {
	owners, e := m.listOwners(21, 23)
	if e != nil {
		return nil, e
	}
	var out []Property
	for rid := uint32(1); rid <= m.Tables[23].Count; rid++ {
		r, _ := m.Row(23, rid)
		t := Token(23<<24 | rid)
		if owners[t] == 0 {
			return nil, bad("orphan Property")
		}
		n, _ := m.String(r[1])
		b, _ := m.Blob(r[2])
		s, e := m.ParseSignature(b)
		if e != nil {
			return nil, e
		}
		if s.Kind != "property" {
			return nil, bad("Property has non-property signature")
		}
		out = append(out, Property{t, owners[t], n, r[0], s, m.accessors(t)})
	}
	return out, nil
}
func (m *Metadata) Events() ([]Event, error) {
	owners, e := m.listOwners(18, 20)
	if e != nil {
		return nil, e
	}
	var out []Event
	for rid := uint32(1); rid <= m.Tables[20].Count; rid++ {
		r, _ := m.Row(20, rid)
		t := Token(20<<24 | rid)
		if owners[t] == 0 {
			return nil, bad("orphan Event")
		}
		n, _ := m.String(r[1])
		typ, _ := DecodeCoded("TypeDefOrRef", r[2])
		out = append(out, Event{t, owners[t], n, r[0], typ, m.accessors(t)})
	}
	return out, nil
}
