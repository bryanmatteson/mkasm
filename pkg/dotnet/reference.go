package dotnet

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// AssemblyIdentity is the metadata binding identity, not a filesystem name.
// PublicKeyToken is lowercase hexadecimal, or "null" for unsigned assemblies.
type AssemblyIdentity struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Culture        string `json:"culture"`
	PublicKeyToken string `json:"public_key_token"`
}

func (a AssemblyIdentity) String() string {
	return fmt.Sprintf("%s, Version=%s, Culture=%s, PublicKeyToken=%s", a.Name, a.Version, a.Culture, a.PublicKeyToken)
}
func keyToken(key []byte, full bool) (string, error) {
	if len(key) == 0 {
		return "null", nil
	}
	if full {
		sum := sha1.Sum(key)
		b := make([]byte, 8)
		for i := range b {
			b[i] = sum[len(sum)-1-i]
		}
		return hex.EncodeToString(b), nil
	}
	if len(key) != 8 {
		return "", bad("assembly public key token must have eight bytes")
	}
	return hex.EncodeToString(key), nil
}
func (m *Metadata) assemblyIdentity(token Token) (AssemblyIdentity, error) {
	var a AssemblyIdentity
	if token.Table() != 32 && token.Table() != 35 {
		return a, bad("not an assembly identity token")
	}
	r, e := m.Row(token.Table(), token.RID())
	if e != nil {
		return a, e
	}
	v, k, n, c, f := 0, 5, 6, 7, 4
	if token.Table() == 32 {
		v, k, n, c, f = 1, 6, 7, 8, 5
	}
	a.Name, e = m.String(r[n])
	if e != nil {
		return a, e
	}
	if a.Name == "" || strings.ContainsAny(a.Name, ",=\r\n") {
		return a, bad("invalid assembly name")
	}
	a.Version = fmt.Sprintf("%d.%d.%d.%d", r[v], r[v+1], r[v+2], r[v+3])
	a.Culture, e = m.String(r[c])
	if e != nil {
		return a, e
	}
	if a.Culture == "" {
		a.Culture = "neutral"
	}
	key, e := m.Blob(r[k])
	if e != nil {
		return a, e
	}
	a.PublicKeyToken, e = keyToken(key, r[f]&1 != 0)
	return a, e
}

// AssemblyIdentity returns this manifest assembly's exact identity. Netmodules
// and portable PDBs have no assembly identity.
func (m *Metadata) AssemblyIdentity() (AssemblyIdentity, error) {
	if m.Tables[32].Count != 1 {
		return AssemblyIdentity{}, bad("metadata must contain one manifest Assembly row")
	}
	return m.assemblyIdentity(Token(32<<24 | 1))
}

// ReferenceSet resolves enums only through explicitly supplied metadata. It
// neither searches disk nor applies runtime/framework version unification.
// Assembly names and culture use ASCII case folding; other name bytes stay exact.
// Escaped identifier names preserve literal punctuation and nested-type scope.
// Modules bind only through manifest File records and their exact Module names.
// File hashes cannot be verified from metadata-only inputs. Keep all metadata
// unmodified; this API does not authenticate an assembly or its module images.
type ReferenceSet struct {
	local    *Metadata
	entries  []metadataReference
	modules  []*Metadata
	bindings []moduleBinding
}
type moduleBinding struct {
	manifest *Metadata
	file     Token
	module   *Metadata
}

// BindModule explicitly associates a supplied netmodule with a manifest File.
// Use it when File.Name differs from Module.Name or same-named supplied modules
// need disambiguation. This metadata-only binding does not verify File.HashValue.
func (s *ReferenceSet) BindModule(manifest *Metadata, file Token, module *Metadata) error {
	if !s.supplied(manifest) || !s.supplied(module) || manifest.Tables[32].Count != 1 || module.Tables[32].Count != 0 || file.Table() != 38 {
		return bad("invalid explicitly supplied module binding")
	}
	row, e := manifest.Row(38, file.RID())
	if e != nil {
		return e
	}
	if row[0] != 0 {
		return bad("manifest File does not contain metadata")
	}
	for _, binding := range s.bindings {
		if binding.manifest == manifest && binding.file == file {
			if binding.module != module {
				return bad("manifest File already has another module binding")
			}
			return nil
		}
	}
	s.bindings = append(s.bindings, moduleBinding{manifest, file, module})
	return nil
}
func (s *ReferenceSet) explicitModule(manifest *Metadata, file Token) *Metadata {
	for _, binding := range s.bindings {
		if binding.manifest == manifest && binding.file == file {
			return binding.module
		}
	}
	return nil
}

type metadataReference struct {
	identity AssemblyIdentity
	metadata *Metadata
}

func NewReferenceSet(local *Metadata, references ...*Metadata) (*ReferenceSet, error) {
	if local == nil {
		return nil, bad("local metadata is required")
	}
	out := &ReferenceSet{local: local}
	all := append([]*Metadata{local}, references...)
	for i, m := range all {
		if m == nil {
			return nil, bad("nil metadata reference")
		}
		if i == 0 && m.PDB != nil && m.Tables[0].Count == 0 {
			continue
		}
		if _, e := m.ModuleIdentity(); e != nil {
			return nil, e
		}
		known := false
		for _, existing := range out.modules {
			if existing == m {
				known = true
				break
			}
		}
		if !known {
			out.modules = append(out.modules, m)
		}
		if m.Tables[32].Count == 0 {
			continue
		}
		id, e := m.AssemblyIdentity()
		if e != nil {
			return nil, e
		}
		duplicate := false
		for _, entry := range out.entries {
			if identityMatches(entry.identity, id) && identityMatches(id, entry.identity) {
				if entry.metadata != m {
					return nil, bad("duplicate supplied assembly identity %s", id.String())
				}
				duplicate = true
			}
		}
		if !duplicate {
			out.entries = append(out.entries, metadataReference{id, m})
		}
	}
	return out, nil
}

// Binding uses ASCII case folding, preserving non-ASCII name bytes exactly.
// This intentionally does not emulate a runtime's Unicode/name unification.
func referenceEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
func identityMatches(actual, requested AssemblyIdentity) bool {
	return referenceEqualFold(actual.Name, requested.Name) && (requested.Version == "" || actual.Version == requested.Version) && (requested.Culture == "" || referenceEqualFold(actual.Culture, requested.Culture)) && (requested.PublicKeyToken == "" || referenceEqualFold(actual.PublicKeyToken, requested.PublicKeyToken))
}

// escapeEnumIdentifier follows the serialized reflection type-name escaping
// rules. Nested '+' separators are added from metadata scope, never inferred
// from punctuation inside a Name or Namespace heap string.
func escapeEnumIdentifier(name string) string {
	var out strings.Builder
	for _, c := range name {
		if strings.ContainsRune(`\,+[]&*`, c) {
			out.WriteByte('\\')
		}
		out.WriteRune(c)
	}
	return out.String()
}
func enumNamePrefix(name string) (string, *string, error) {
	escaped := false
	depth := 0
	for i, c := range name {
		if escaped {
			if !strings.ContainsRune(`\,+[]&*`, c) {
				return "", nil, bad("invalid serialized type name escape")
			}
			escaped = false
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case '[':
			depth++
			if depth > 64 {
				return "", nil, bad("type name nesting limit")
			}
		case ']':
			depth--
			if depth < 0 {
				return "", nil, bad("unmatched type name bracket")
			}
		case ',':
			if depth == 0 {
				assembly := name[i+1:]
				return strings.TrimSpace(name[:i]), &assembly, nil
			}
		}
	}
	if escaped || depth != 0 {
		return "", nil, bad("incomplete serialized type name")
	}
	return strings.TrimSpace(name), nil, nil
}

type referenceTypeShape struct {
	name      string
	arguments []string
	arrays    []int
}

func typeBracketEnd(name string, start int) (int, error) {
	depth := 0
	escaped := false
	for i := start; i < len(name); i++ {
		c := name[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '[' {
			depth++
		}
		if c == ']' {
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, bad("unmatched constructed type bracket")
}
func splitGenericArguments(content string) ([]string, error) {
	var args []string
	if strings.HasPrefix(content, "[") {
		for len(content) > 0 {
			if content[0] != '[' {
				return nil, bad("mixed generic argument qualification")
			}
			end, e := typeBracketEnd(content, 0)
			if e != nil {
				return nil, e
			}
			arg := strings.TrimSpace(content[1:end])
			if arg == "" {
				return nil, bad("empty generic argument")
			}
			args = append(args, arg)
			content = strings.TrimSpace(content[end+1:])
			if content == "" {
				break
			}
			if content[0] != ',' {
				return nil, bad("invalid generic argument separator")
			}
			content = strings.TrimSpace(content[1:])
			if content == "" {
				return nil, bad("empty generic argument")
			}
		}
	} else {
		start, depth := 0, 0
		escaped := false
		for i, c := range content {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			switch c {
			case '[':
				depth++
			case ']':
				depth--
			case ',':
				if depth == 0 {
					args = append(args, strings.TrimSpace(content[start:i]))
					start = i + 1
				}
			}
		}
		args = append(args, strings.TrimSpace(content[start:]))
		for _, arg := range args {
			if arg == "" {
				return nil, bad("empty generic argument")
			}
		}
	}
	return args, nil
}
func parseReferenceTypeShape(name string, depth int) (referenceTypeShape, error) {
	var shape referenceTypeShape
	if depth > 64 {
		return shape, bad("constructed type nesting limit")
	}
	escaped, segment := false, false
	start := len(name)
	for i, c := range name {
		if escaped {
			if !strings.ContainsRune(`\,+[]&*`, c) {
				return shape, bad("invalid serialized type name escape")
			}
			escaped = false
			segment = true
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case '+':
			if !segment {
				return shape, bad("empty nested type name")
			}
			segment = false
		case '[':
			start = i
			goto suffix
		case ']', '*', '&', ',':
			return shape, bad("invalid or indirect nominal type name")
		default:
			if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				segment = true
			}
		}
	}
suffix:
	if escaped || !segment {
		return shape, bad("incomplete nominal type name")
	}
	shape.name = strings.TrimSpace(name[:start])
	suffix := name[start:]
	for suffix != "" {
		if suffix[0] != '[' {
			return shape, bad("invalid constructed type suffix")
		}
		end, e := typeBracketEnd(suffix, 0)
		if e != nil {
			return shape, e
		}
		content := suffix[1:end]
		if strings.Trim(content, ",") == "" || content == "*" {
			rank := len(content) + 1
			if content == "*" {
				rank = 1
			}
			shape.arrays = append(shape.arrays, rank)
		} else {
			if shape.arguments != nil || len(shape.arrays) != 0 {
				return shape, bad("invalid generic construction")
			}
			shape.arguments, e = splitGenericArguments(content)
			if e != nil {
				return shape, e
			}
			for _, arg := range shape.arguments {
				typ, _, e := enumNamePrefix(arg)
				if e != nil {
					return shape, e
				}
				if _, e := parseReferenceTypeShape(typ, depth+1); e != nil {
					return shape, e
				}
			}
		}
		suffix = suffix[end+1:]
	}
	return shape, nil
}
func (m *Metadata) serializedEnumName(token Token, depth int) (string, error) {
	if depth > 64 {
		return "", bad("enum type name cycle/nesting limit")
	}
	if token.Table() != 1 && token.Table() != 2 {
		return "", bad("enum signature needs TypeDef/TypeRef")
	}
	r, e := m.Row(token.Table(), token.RID())
	if e != nil {
		return "", e
	}
	name, e := m.String(r[1])
	if e != nil {
		return "", e
	}
	ns, e := m.String(r[2])
	if e != nil {
		return "", e
	}
	parent := m.nested[token]
	if token.Table() == 1 {
		scope, e := DecodeCoded("ResolutionScope", r[0])
		if e != nil {
			return "", e
		}
		if scope.Table() == 1 && scope != 0 {
			parent = scope
		}
	}
	if parent != 0 {
		prefix, e := m.serializedEnumName(parent, depth+1)
		return prefix + "+" + escapeEnumIdentifier(name), e
	}
	return escapeEnumIdentifier(qualify(ns, name)), nil
}
func (m *Metadata) enumStorage(t TypeDefinition) (string, error) {
	base, e := m.Resolve(t.Extends)
	if e != nil || base != "System.Enum" {
		return "", bad("%s is not an enum", t.FullName)
	}
	for _, token := range t.Fields {
		member, e := m.Member(token)
		if e != nil {
			return "", e
		}
		if member.Name == "value__" && member.Signature.Return != nil {
			return member.Signature.Return.Kind, nil
		}
	}
	return "", bad("enum %s has no value__ storage field", t.FullName)
}
func parseEnumIdentity(name string) (string, *AssemblyIdentity, error) {
	return parseReferenceIdentity(name, false)
}
func parseReferenceIdentity(name string, allowArray bool) (string, *AssemblyIdentity, error) {
	typ, assembly, e := enumNamePrefix(name)
	if e != nil {
		return "", nil, e
	}
	shape, e := parseReferenceTypeShape(typ, 0)
	if e != nil {
		return "", nil, e
	}
	if !allowArray && len(shape.arrays) != 0 {
		return "", nil, bad("array is not an enum type")
	}
	if assembly == nil {
		return typ, nil, nil
	}
	parts := strings.Split(*assembly, ",")
	a := &AssemblyIdentity{Name: strings.TrimSpace(parts[0])}
	if a.Name == "" {
		return "", nil, bad("empty enum assembly identity")
	}
	seen := map[string]bool{}
	for _, part := range parts[1:] {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) != 2 {
			return "", nil, bad("invalid enum assembly identity")
		}
		k, v := strings.ToLower(strings.TrimSpace(pair[0])), strings.TrimSpace(pair[1])
		if seen[k] || v == "" {
			return "", nil, bad("duplicate/empty assembly identity component")
		}
		seen[k] = true
		switch k {
		case "version":
			nums := strings.Split(v, ".")
			if len(nums) != 4 {
				return "", nil, bad("assembly version must have four components")
			}
			for _, n := range nums {
				x, e := strconv.ParseUint(n, 10, 16)
				if e != nil || strconv.FormatUint(x, 10) != n {
					return "", nil, bad("invalid assembly version")
				}
			}
			a.Version = v
		case "culture":
			a.Culture = v
		case "publickeytoken":
			if !referenceEqualFold(v, "null") {
				b, e := hex.DecodeString(v)
				if e != nil || len(b) != 8 {
					return "", nil, bad("invalid assembly public key token")
				}
			}
			a.PublicKeyToken = strings.ToLower(v)
		default:
			return "", nil, bad("unsupported assembly identity component %s", k)
		}
	}
	return typ, a, nil
}
func (s *ReferenceSet) selectAssembly(id AssemblyIdentity) (*Metadata, error) {
	var selected *Metadata
	for _, entry := range s.entries {
		if identityMatches(entry.identity, id) {
			if selected != nil {
				return nil, bad("ambiguous supplied assembly %s", id.String())
			}
			selected = entry.metadata
		}
	}
	if selected == nil {
		return nil, bad("explicit metadata reference for %s is required", id.String())
	}
	return selected, nil
}

// ModuleIdentity retains a module's metadata name and canonical MVID. An empty
// MVID means the Module row has a nil Mvid index; it is never a wildcard match.
type ModuleIdentity struct {
	Name string `json:"name"`
	MVID string `json:"mvid"`
}

func (m *Metadata) ModuleIdentity() (ModuleIdentity, error) {
	if m.Tables[0].Count != 1 {
		return ModuleIdentity{}, bad("metadata must contain one Module row")
	}
	r, e := m.Row(0, 1)
	if e != nil {
		return ModuleIdentity{}, e
	}
	name, e := m.String(r[1])
	if e != nil {
		return ModuleIdentity{}, e
	}
	if name == "" {
		return ModuleIdentity{}, bad("empty module name")
	}
	id := ModuleIdentity{Name: name}
	if r[2] != 0 {
		g, e := m.GUID(r[2])
		if e != nil {
			return id, e
		}
		id.MVID = fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(g[:4]), binary.LittleEndian.Uint16(g[4:6]), binary.LittleEndian.Uint16(g[6:8]), g[8:10], g[10:])
	}
	return id, nil
}
func (s *ReferenceSet) supplied(m *Metadata) bool {
	for _, entry := range s.modules {
		if entry == m {
			return true
		}
	}
	return false
}
func (s *ReferenceSet) fileModule(manifest *Metadata, file Token) (*Metadata, error) {
	if file.Table() != 38 {
		return nil, bad("not a manifest File token")
	}
	if manifest.Tables[32].Count != 1 {
		return nil, bad("File binding requires manifest assembly context")
	}
	row, e := manifest.Row(38, file.RID())
	if e != nil {
		return nil, e
	}
	if row[0] != 0 {
		return nil, bad("manifest File does not contain metadata")
	}
	if module := s.explicitModule(manifest, file); module != nil {
		return module, nil
	}
	name, e := manifest.String(row[1])
	if e != nil {
		return nil, e
	}
	var found *Metadata
	for _, module := range s.modules {
		if module.Tables[32].Count != 0 {
			continue
		}
		id, e := module.ModuleIdentity()
		if e != nil {
			return nil, e
		}
		if id.Name == name {
			if found != nil {
				return nil, bad("ambiguous supplied netmodule %s", name)
			}
			found = module
		}
	}
	if found == nil {
		return nil, bad("explicit metadata for manifest File %s is required", name)
	}
	return found, nil
}
func (s *ReferenceSet) moduleOwner(module *Metadata) (*Metadata, error) {
	if !s.supplied(module) {
		return nil, bad("metadata context was not explicitly supplied")
	}
	if module.Tables[32].Count == 1 {
		return module, nil
	}
	id, e := module.ModuleIdentity()
	if e != nil {
		return nil, e
	}
	var owner *Metadata
	for _, assembly := range s.entries {
		for rid := uint32(1); rid <= assembly.metadata.Tables[38].Count; rid++ {
			r, e := assembly.metadata.Row(38, rid)
			if e != nil {
				return nil, e
			}
			name, e := assembly.metadata.String(r[1])
			if e != nil {
				return nil, e
			}
			if r[0]&1 == 0 && (name == id.Name || s.explicitModule(assembly.metadata, Token(38<<24|rid)) == module) {
				target, e := s.fileModule(assembly.metadata, Token(38<<24|rid))
				if e != nil {
					return nil, e
				}
				if target == module {
					if owner != nil {
						return nil, bad("ambiguous manifest ownership for netmodule %s", id.Name)
					}
					owner = assembly.metadata
				}
			}
		}
	}
	return owner, nil
}
func (s *ReferenceSet) scopeModule(origin, manifest *Metadata, name string) (*Metadata, error) {
	id, e := origin.ModuleIdentity()
	if e != nil {
		return nil, e
	}
	if id.Name == name {
		return origin, nil
	}
	if manifest == nil {
		return nil, bad("manifest assembly for ModuleRef %s is required", name)
	}
	id, e = manifest.ModuleIdentity()
	if e != nil {
		return nil, e
	}
	if id.Name == name {
		return manifest, nil
	}
	var found *Metadata
	for rid := uint32(1); rid <= manifest.Tables[38].Count; rid++ {
		r, e := manifest.Row(38, rid)
		if e != nil {
			return nil, e
		}
		fileName, e := manifest.String(r[1])
		if e != nil {
			return nil, e
		}
		explicit := s.explicitModule(manifest, Token(38<<24|rid))
		explicitName := ""
		if explicit != nil {
			identity, e := explicit.ModuleIdentity()
			if e != nil {
				return nil, e
			}
			explicitName = identity.Name
		}
		matches := fileName == name
		if explicit != nil {
			matches = explicitName == name
		}
		if r[0]&1 == 0 && matches {
			target, e := s.fileModule(manifest, Token(38<<24|rid))
			if e != nil {
				return nil, e
			}
			if found != nil {
				return nil, bad("ambiguous ModuleRef %s", name)
			}
			found = target
		}
	}
	if found == nil {
		return nil, bad("ModuleRef %s is absent from manifest File records", name)
	}
	return found, nil
}

// EnumUnderlying resolves assembly-scoped serialized names. Use EnumUnderlyingIn
// or the context-aware attribute methods when the originating module matters.
func (s *ReferenceSet) EnumUnderlying(name string) (string, error) {
	return s.EnumUnderlyingIn(s.local, name)
}

// EnumUnderlyingIn supplies the origin module for unqualified serialized names.
// Assembly-qualified names resolve through their manifest and ExportedType rows.
func (s *ReferenceSet) EnumUnderlyingIn(origin *Metadata, name string) (string, error) {
	typ, id, e := parseEnumIdentity(name)
	if e != nil {
		return "", e
	}
	manifest, e := s.moduleOwner(origin)
	if e != nil {
		return "", e
	}
	m := origin
	if id == nil && manifest != nil && manifest != origin {
		exported, e := manifest.referenceHasType(typ)
		if e != nil {
			return "", e
		}
		if exported {
			m = manifest
		}
	}
	if id != nil {
		m, e = s.selectAssembly(*id)
		if e != nil {
			return "", e
		}
		manifest = m
	}
	return s.resolveEnum(m, manifest, typ, map[string]bool{}, 0)
}
func (m *Metadata) referenceHasType(name string) (bool, error) {
	shape, e := parseReferenceTypeShape(name, 0)
	if e != nil {
		return false, e
	}
	name = shape.name
	for rid := uint32(1); rid <= m.Tables[2].Count; rid++ {
		n, e := m.serializedEnumName(Token(2<<24|rid), 0)
		if e != nil {
			return false, e
		}
		if n == name {
			return true, nil
		}
	}
	for rid := uint32(1); rid <= m.Tables[39].Count; rid++ {
		n, _, _, e := m.exportedBinding(rid, 0)
		if e != nil {
			return false, e
		}
		if n == name {
			return true, nil
		}
	}
	return false, nil
}
func (s *ReferenceSet) resolveEnum(m, manifest *Metadata, name string, seen map[string]bool, depth int) (string, error) {
	return s.resolveDefinition(m, manifest, name, seen, depth, true)
}
func (s *ReferenceSet) resolveDefinition(m, manifest *Metadata, name string, seen map[string]bool, depth int, requireEnum bool) (string, error) {
	shape, e := parseReferenceTypeShape(name, 0)
	if e != nil {
		return "", e
	}
	if requireEnum && len(shape.arrays) != 0 {
		return "", bad("array is not enum")
	}
	lookup := shape.name
	key := fmt.Sprintf("%p:%p:%s", m, manifest, name)
	if seen[key] || depth > 64 {
		return "", bad("enum forwarding cycle/nesting limit")
	}
	seen[key] = true
	types, e := m.Types()
	if e != nil {
		return "", e
	}
	matches := 0
	var definition *TypeDefinition
	for i := range types {
		canonical, e := m.serializedEnumName(types[i].Token, 0)
		if e != nil {
			return "", e
		}
		if canonical == lookup {
			matches++
			definition = &types[i]
		}
	}
	var destination Token
	var hint uint32
	for rid := uint32(1); rid <= m.Tables[39].Count; rid++ {
		n, target, id, e := m.exportedBinding(rid, 0)
		if e != nil {
			return "", e
		}
		if n == lookup {
			matches++
			destination = target
			hint = id
		}
	}
	if matches > 1 {
		return "", bad("ambiguous enum definition %s", name)
	}
	if matches == 0 {
		return "", bad("enum %s not found in selected module", name)
	}
	if definition != nil {
		if len(shape.arguments) != len(definition.GenericParameters) {
			return "", bad("open or wrong-arity generic enum/type name")
		}
		for _, arg := range shape.arguments {
			if e := s.validateTypeArgument(m, manifest, arg, depth+1); e != nil {
				return "", e
			}
		}
		if !requireEnum {
			return "", nil
		}
		kind, e := m.enumStorage(*definition)
		if e != nil {
			return "", e
		}
		switch kind {
		case "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64":
			return kind, nil
		}
		return "", bad("invalid enum storage type %s", kind)
	}
	switch destination.Table() {
	case 35:
		id, e := m.assemblyIdentity(destination)
		if e != nil {
			return "", e
		}
		next, e := s.selectAssembly(id)
		if e != nil {
			return "", e
		}
		return s.resolveDefinition(next, next, name, seen, depth+1, requireEnum)
	case 38:
		next, e := s.fileModule(m, destination)
		if e != nil {
			return "", e
		}
		if hint != 0 {
			rid := hint
			if hint>>24 != 0 {
				if hint>>24 != 2 {
					return "", bad("invalid exported TypeDefId")
				}
				rid = hint & 0xffffff
			}
			canonical, e := next.serializedEnumName(Token(2<<24|rid), 0)
			if e != nil {
				return "", e
			}
			if canonical != lookup {
				return "", bad("exported TypeDefId does not match enum name")
			}
		}
		return s.resolveDefinition(next, m, name, seen, depth+1, requireEnum)
	}
	return "", bad("unsupported exported enum implementation")
}
func (m *Metadata) exportedBinding(rid uint32, depth int) (string, Token, uint32, error) {
	if depth > 64 {
		return "", 0, 0, bad("exported type cycle/nesting limit")
	}
	r, e := m.Row(39, rid)
	if e != nil {
		return "", 0, 0, e
	}
	n, e := m.String(r[2])
	if e != nil {
		return "", 0, 0, e
	}
	ns, e := m.String(r[3])
	if e != nil {
		return "", 0, 0, e
	}
	name := escapeEnumIdentifier(qualify(ns, n))
	impl, e := DecodeCoded("Implementation", r[4])
	if e != nil {
		return "", 0, 0, e
	}
	if impl.Table() == 39 {
		parent, target, _, e := m.exportedBinding(impl.RID(), depth+1)
		return parent + "+" + escapeEnumIdentifier(n), target, r[1], e
	}
	if impl.Table() == 38 {
		return name, impl, r[1], nil
	}
	if impl.Table() == 35 && r[0]&0x200000 != 0 {
		return name, impl, r[1], nil
	}
	return name, 0, 0, nil
}

// enumTypeName retains AssemblyRef scope for constructor-derived foreign enums.
// Local TypeDef/TypeRef names keep the existing unqualified resolver contract.
func (m *Metadata) enumTypeName(token Token) (string, error) {
	name, e := m.serializedEnumName(token, 0)
	if e != nil {
		return "", e
	}
	scope := token
	for depth := 0; depth <= 64; depth++ {
		if scope.Table() == 2 {
			return name, nil
		}
		if scope.Table() != 1 {
			return "", bad("enum signature needs TypeDef/TypeRef")
		}
		row, e := m.Row(1, scope.RID())
		if e != nil {
			return "", e
		}
		scope, e = DecodeCoded("ResolutionScope", row[0])
		if e != nil {
			return "", e
		}
		if scope.Table() == 35 {
			id, e := m.assemblyIdentity(scope)
			if e != nil {
				return "", e
			}
			return name + ", " + id.String(), nil
		}
		if scope == 0 || scope.Table() == 0 {
			return name, nil
		}
		if scope.Table() == 26 {
			return "", bad("external enum netmodule scope requires explicit module resolution")
		}
	}
	return "", bad("enum type reference cycle/nesting limit")
}

func (s *ReferenceSet) enumTokenType(origin *Metadata, token Token) (SerializedType, error) {
	name, e := origin.serializedEnumName(token, 0)
	if e != nil {
		return SerializedType{}, e
	}
	manifest, e := s.moduleOwner(origin)
	if e != nil {
		return SerializedType{}, e
	}
	target := origin
	scope := token
	for depth := 0; depth <= 64; depth++ {
		if scope.Table() == 2 {
			break
		}
		if scope.Table() != 1 {
			return SerializedType{}, bad("invalid enum token scope")
		}
		r, e := origin.Row(1, scope.RID())
		if e != nil {
			return SerializedType{}, e
		}
		scope, e = DecodeCoded("ResolutionScope", r[0])
		if e != nil {
			return SerializedType{}, e
		}
		if scope.Table() == 1 {
			continue
		}
		switch scope.Table() {
		case 35:
			id, e := origin.assemblyIdentity(scope)
			if e != nil {
				return SerializedType{}, e
			}
			target, e = s.selectAssembly(id)
			if e != nil {
				return SerializedType{}, e
			}
			manifest = target
		case 26:
			r, e := origin.Row(26, scope.RID())
			if e != nil {
				return SerializedType{}, e
			}
			moduleName, e := origin.String(r[0])
			if e != nil {
				return SerializedType{}, e
			}
			target, e = s.scopeModule(origin, manifest, moduleName)
			if e != nil {
				return SerializedType{}, e
			}
		case 0:
		default:
			return SerializedType{}, bad("unsupported enum resolution scope")
		}
		break
	}
	id, e := target.ModuleIdentity()
	if e != nil {
		return SerializedType{}, e
	}
	if manifest != nil {
		assembly, e := manifest.AssemblyIdentity()
		if e != nil {
			return SerializedType{}, e
		}
		name += ", " + assembly.String()
	}
	return SerializedType{Kind: "enum", Enum: name, EnumModule: &id}, nil
}
func (s *ReferenceSet) referenceAttributeType(origin *Metadata, t Type) (SerializedType, error) {
	for (t.Kind == "modreq" || t.Kind == "modopt") && len(t.Args) == 1 {
		t = t.Args[0]
	}
	if t.Kind == "szarray" && len(t.Args) == 1 {
		child, e := s.referenceAttributeType(origin, t.Args[0])
		return SerializedType{Kind: "array", Element: &child}, e
	}
	if t.Kind == "genericinst" && len(t.Args) > 1 && t.Args[0].Kind == "valuetype" {
		typ, e := s.enumTokenType(origin, t.Args[0].Token)
		if e != nil {
			return typ, e
		}
		name, assembly, e := parseEnumIdentity(typ.Enum)
		if e != nil {
			return typ, e
		}
		var arguments []string
		for _, arg := range t.Args[1:] {
			n, e := s.signatureArgumentName(origin, arg, 0)
			if e != nil {
				return typ, e
			}
			arguments = append(arguments, "["+n+"]")
		}
		typ.Enum = name + "[" + strings.Join(arguments, ",") + "]"
		if assembly != nil {
			typ.Enum += ", " + assembly.String()
		}
		typ.EnumArguments = append([]Type(nil), t.Args[1:]...)
		return typ, nil
	}
	if t.Kind == "valuetype" {
		return s.enumTokenType(origin, t.Token)
	}
	return origin.attributeType(t)
}
func (s *ReferenceSet) resolveSerializedEnum(origin *Metadata, t SerializedType) (string, error) {
	if t.EnumModule == nil {
		return s.EnumUnderlyingIn(origin, t.Enum)
	}
	name, id, e := parseEnumIdentity(t.Enum)
	if e != nil {
		return "", e
	}
	manifest, e := s.moduleOwner(origin)
	if e != nil {
		return "", e
	}
	if id != nil {
		manifest, e = s.selectAssembly(*id)
		if e != nil {
			return "", e
		}
	}
	var target *Metadata
	for _, candidate := range s.modules {
		identity, e := candidate.ModuleIdentity()
		if e != nil {
			return "", e
		}
		if identity != *t.EnumModule {
			continue
		}
		owner, e := s.moduleOwner(candidate)
		if e != nil {
			return "", e
		}
		if owner != manifest || (manifest == nil && candidate != origin) {
			continue
		}
		if target != nil {
			return "", bad("ambiguous scoped enum module")
		}
		target = candidate
	}
	if target == nil {
		return "", bad("explicit enum module identity was not supplied in this assembly context")
	}
	return s.resolveEnum(target, manifest, name, map[string]bool{}, 0)
}

// DecodeAttribute retains constructor ModuleRef/TypeDef scope, which cannot be
// represented by the legacy EnumResolver(string) callback alone. origin must be
// one of the explicitly supplied metadata objects. EnumModule retains the exact
// lookup module identity independently of the defining assembly name.
func (s *ReferenceSet) DecodeAttribute(origin *Metadata, a Attribute) (*DecodedAttribute, error) {
	if !s.supplied(origin) {
		return nil, bad("attribute metadata context was not explicitly supplied")
	}
	if a.Constructor == nil || a.Constructor.ResolvedSignature == nil {
		return nil, bad("attribute constructor missing")
	}
	r := cursor{b: a.Value}
	prolog, e := r.uint(2)
	if e != nil || prolog != 1 {
		return nil, bad("invalid custom attribute prolog")
	}
	out := &DecodedAttribute{}
	resolver := func(t SerializedType) (string, error) { return s.resolveSerializedEnum(origin, t) }
	for _, p := range a.Constructor.ResolvedSignature.Parameters {
		typ, e := s.referenceAttributeType(origin, p)
		if e != nil {
			return nil, e
		}
		v, e := attributeValueScoped(&r, typ, resolver, 0)
		if e != nil {
			return nil, e
		}
		out.Fixed = append(out.Fixed, v)
	}
	count, e := r.uint(2)
	if e != nil {
		return nil, e
	}
	out.Named, e = namedArgumentsScoped(&r, count, resolver)
	if e != nil {
		return nil, e
	}
	if r.p != uint64(len(r.b)) {
		return nil, bad("trailing attribute bytes")
	}
	return out, nil
}
func (s *ReferenceSet) SerializedAttributes(origin *Metadata, parent Token) ([]AttributeRecord, error) {
	attrs, e := origin.Attributes(parent)
	if e != nil {
		return nil, e
	}
	out := make([]AttributeRecord, 0, len(attrs))
	for _, a := range attrs {
		record := AttributeRecord{Attribute: a}
		record.Decoded, e = s.DecodeAttribute(origin, a)
		if e != nil {
			record.DecodeError = e.Error()
		}
		out = append(out, record)
	}
	return out, nil
}
func (s *ReferenceSet) DecodeSecurity(origin *Metadata, b []byte) (*SecurityDeclaration, error) {
	return DecodeSecurity(b, func(name string) (string, error) { return s.EnumUnderlyingIn(origin, name) })
}
func (s *ReferenceSet) SecurityRecords(origin *Metadata) ([]SecurityRecord, error) {
	return origin.SecurityRecords(func(name string) (string, error) { return s.EnumUnderlyingIn(origin, name) })
}

var referencePrimitiveNames = map[string]string{"bool": "System.Boolean", "char": "System.Char", "int8": "System.SByte", "uint8": "System.Byte", "int16": "System.Int16", "uint16": "System.UInt16", "int32": "System.Int32", "uint32": "System.UInt32", "int64": "System.Int64", "uint64": "System.UInt64", "float32": "System.Single", "float64": "System.Double", "string": "System.String", "object": "System.Object", "native int": "System.IntPtr", "native uint": "System.UIntPtr"}

func (s *ReferenceSet) validateTypeArgument(origin, manifest *Metadata, name string, depth int) error {
	if depth > 64 {
		return bad("generic argument nesting limit")
	}
	typ, id, e := parseReferenceIdentity(name, true)
	if e != nil {
		return e
	}
	shape, e := parseReferenceTypeShape(typ, 0)
	if e != nil {
		return e
	}
	if shape.name == "System.Void" || shape.name == "System.TypedReference" || shape.name == "System.ArgIterator" || shape.name == "System.RuntimeArgumentHandle" {
		return bad("invalid generic argument type")
	}
	if id == nil && len(shape.arguments) == 0 {
		for _, primitive := range referencePrimitiveNames {
			if shape.name == primitive {
				return nil
			}
		}
	}
	target := origin
	if id != nil {
		target, e = s.selectAssembly(*id)
		if e != nil {
			return e
		}
		manifest = target
	} else if manifest != nil {
		found, e := manifest.referenceHasType(typ)
		if e != nil {
			return e
		}
		if found {
			target = manifest
		}
	}
	_, e = s.resolveDefinition(target, manifest, typ, map[string]bool{}, depth, false)
	return e
}
func (s *ReferenceSet) signatureArgumentName(origin *Metadata, t Type, depth int) (string, error) {
	if depth > 64 {
		return "", bad("generic signature nesting limit")
	}
	if name, ok := referencePrimitiveNames[t.Kind]; ok {
		return name, nil
	}
	if t.Kind == "class" || t.Kind == "valuetype" {
		typ, e := s.enumTokenType(origin, t.Token)
		return typ.Enum, e
	}
	if t.Kind == "genericinst" && len(t.Args) > 1 {
		base, e := s.signatureArgumentName(origin, t.Args[0], depth+1)
		if e != nil {
			return "", e
		}
		name, id, e := parseReferenceIdentity(base, false)
		if e != nil {
			return "", e
		}
		var args []string
		for _, arg := range t.Args[1:] {
			n, e := s.signatureArgumentName(origin, arg, depth+1)
			if e != nil {
				return "", e
			}
			args = append(args, "["+n+"]")
		}
		name += "[" + strings.Join(args, ",") + "]"
		if id != nil {
			name += ", " + id.String()
		}
		return name, nil
	}
	if t.Kind == "array" && len(t.Args) == 1 && t.Rank > 0 && t.Rank <= 32 {
		element, e := s.signatureArgumentName(origin, t.Args[0], depth+1)
		if e != nil {
			return "", e
		}
		name, id, e := parseReferenceIdentity(element, true)
		if e != nil {
			return "", e
		}
		suffix := "*"
		if t.Rank > 1 {
			suffix = strings.Repeat(",", int(t.Rank-1))
		}
		name += "[" + suffix + "]"
		if id != nil {
			name += ", " + id.String()
		}
		return name, nil
	}
	if t.Kind == "szarray" && len(t.Args) == 1 {
		element, e := s.signatureArgumentName(origin, t.Args[0], depth+1)
		if e != nil {
			return "", e
		}
		name, id, e := parseReferenceIdentity(element, true)
		if e != nil {
			return "", e
		}
		name += "[]"
		if id != nil {
			name += ", " + id.String()
		}
		return name, nil
	}
	return "", bad("open/indirect unsupported generic argument signature %s", t.Kind)
}

func (m *Metadata) serializedArgumentName(t Type, depth int) (string, error) {
	if depth > 64 {
		return "", bad("generic signature nesting limit")
	}
	if name, ok := referencePrimitiveNames[t.Kind]; ok {
		return name, nil
	}
	if t.Kind == "class" || t.Kind == "valuetype" {
		return m.enumTypeName(t.Token)
	}
	if t.Kind == "genericinst" && len(t.Args) > 1 {
		base, e := m.serializedArgumentName(t.Args[0], depth+1)
		if e != nil {
			return "", e
		}
		name, id, e := parseReferenceIdentity(base, false)
		if e != nil {
			return "", e
		}
		var args []string
		for _, arg := range t.Args[1:] {
			n, e := m.serializedArgumentName(arg, depth+1)
			if e != nil {
				return "", e
			}
			args = append(args, "["+n+"]")
		}
		name += "[" + strings.Join(args, ",") + "]"
		if id != nil {
			name += ", " + id.String()
		}
		return name, nil
	}
	if t.Kind == "array" && len(t.Args) == 1 && t.Rank > 0 && t.Rank <= 32 {
		element, e := m.serializedArgumentName(t.Args[0], depth+1)
		if e != nil {
			return "", e
		}
		name, id, e := parseReferenceIdentity(element, true)
		if e != nil {
			return "", e
		}
		suffix := "*"
		if t.Rank > 1 {
			suffix = strings.Repeat(",", int(t.Rank-1))
		}
		name += "[" + suffix + "]"
		if id != nil {
			name += ", " + id.String()
		}
		return name, nil
	}
	if t.Kind == "szarray" && len(t.Args) == 1 {
		base, e := m.serializedArgumentName(t.Args[0], depth+1)
		if e != nil {
			return "", e
		}
		name, id, e := parseReferenceIdentity(base, true)
		if e != nil {
			return "", e
		}
		name += "[]"
		if id != nil {
			name += ", " + id.String()
		}
		return name, nil
	}
	return "", bad("open/indirect generic argument signature %s", t.Kind)
}
