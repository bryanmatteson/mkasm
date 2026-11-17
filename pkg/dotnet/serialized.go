package dotnet

// Serialized records retain their original bytes when a referenced enum cannot
// be resolved or a blob is malformed. DecodeError never means a decoded value.
type AttributeRecord struct {
	Attribute
	Decoded     *DecodedAttribute `json:"decoded,omitempty"`
	DecodeError string            `json:"decode_error,omitempty"`
}
type MarshalRecord struct {
	Token       Token              `json:"token"`
	Parent      Token              `json:"parent"`
	Value       []byte             `json:"value"`
	Decoded     *MarshalDescriptor `json:"decoded,omitempty"`
	DecodeError string             `json:"decode_error,omitempty"`
}
type SecurityRecord struct {
	Token       Token                `json:"token"`
	Parent      Token                `json:"parent"`
	Action      uint32               `json:"action"`
	Value       []byte               `json:"value"`
	Decoded     *SecurityDeclaration `json:"decoded,omitempty"`
	DecodeError string               `json:"decode_error,omitempty"`
}

func (m *Metadata) SerializedAttributes(parent Token, enums EnumResolver) ([]AttributeRecord, error) {
	attrs, e := m.Attributes(parent)
	if e != nil {
		return nil, e
	}
	out := make([]AttributeRecord, 0, len(attrs))
	for _, a := range attrs {
		r := AttributeRecord{Attribute: a}
		r.Decoded, e = m.DecodeAttribute(a, enums)
		if e != nil {
			r.Decoded = nil
			r.DecodeError = e.Error()
		}
		out = append(out, r)
	}
	return out, nil
}
func (m *Metadata) MarshalRecords() ([]MarshalRecord, error) {
	var out []MarshalRecord
	for rid := uint32(1); rid <= m.Tables[13].Count; rid++ {
		row, e := m.Row(13, rid)
		if e != nil {
			return nil, e
		}
		parent, e := DecodeCoded("HasFieldMarshal", row[0])
		if e != nil {
			return nil, e
		}
		value, e := m.Blob(row[1])
		if e != nil {
			return nil, e
		}
		r := MarshalRecord{Token: Token(13<<24 | rid), Parent: parent, Value: value}
		r.Decoded, e = DecodeMarshal(value)
		if e != nil {
			r.Decoded = nil
			r.DecodeError = e.Error()
		}
		out = append(out, r)
	}
	return out, nil
}
func (m *Metadata) SecurityRecords(enums EnumResolver) ([]SecurityRecord, error) {
	var out []SecurityRecord
	for rid := uint32(1); rid <= m.Tables[14].Count; rid++ {
		row, e := m.Row(14, rid)
		if e != nil {
			return nil, e
		}
		parent, e := DecodeCoded("HasDeclSecurity", row[1])
		if e != nil {
			return nil, e
		}
		value, e := m.Blob(row[2])
		if e != nil {
			return nil, e
		}
		r := SecurityRecord{Token: Token(14<<24 | rid), Parent: parent, Action: row[0], Value: value}
		r.Decoded, e = DecodeSecurity(value, enums)
		if e != nil {
			r.Decoded = nil
			r.DecodeError = e.Error()
		}
		out = append(out, r)
	}
	return out, nil
}
