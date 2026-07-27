package arm

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// aliasIndexFiles are the per-instruction-set alphabetic indexes. Between them
// they list every iform file in the spec, alias pages included.
var aliasIndexFiles = []string{
	"index.xml",
	"fpsimdindex.xml",
	"sveindex.xml",
	"mortlachindex.xml",
}

// AliasEncoding is one <encoding> inside an alias iform page.
type AliasEncoding struct {
	EncodingID string
	Mnemonic   string // preferred disassembly (docvar alias_mnemonic)
	Canonical  string // docvar mnemonic: the instruction being aliased
	IFormFile  string
	RefIForm   string // <aliasto refiform>: iform file of the canonical encoding
}

// DiscoverAliasEncodings returns partial IR for every alias encoding in the spec.
//
// Pass 1 builds its registry from encodingindex.xml, which lists canonical
// encodings only. Without this step aliases — ASR_ASRV_32_dp_2src,
// BFC_BFM_32M_bitfield, AT_SYS_CR_systeminstrs and 285 others — never reach the
// catalog at all, even though ARM marks many of them as the preferred
// disassembly.
//
// canonicalFiles holds the iform files pass 1 already claimed. Alias pages are
// exactly the indexed files that are not among them, so the whole spec tree
// never has to be scanned to find them.
func DiscoverAliasEncodings(specDir string, canonicalFiles map[string]struct{}, classOf func(iformFile string) string) ([]*ir.InstructionIR, error) {
	return DiscoverAliasEncodingsCorpus(NewDirectoryXMLCorpus(specDir), canonicalFiles, classOf)
}

// DiscoverAliasEncodingsCorpus is the source-agnostic alias discovery path.
// It works identically for an extracted directory and an in-memory tar corpus.
func DiscoverAliasEncodingsCorpus(corpus XMLCorpus, canonicalFiles map[string]struct{}, classOf func(iformFile string) string) ([]*ir.InstructionIR, error) {
	if prepared, ok := corpus.(interface{ preparedAliases() []AliasEncoding }); ok {
		return buildAliasInstructions(prepared.preparedAliases(), canonicalFiles, classOf), nil
	}

	indexed, err := indexedIFormFiles(corpus)
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(indexed))
	for f := range indexed {
		if _, canonical := canonicalFiles[f]; !canonical {
			files = append(files, f)
		}
	}
	sort.Strings(files)

	encodings := make([]AliasEncoding, 0, 320)
	for _, f := range files {
		encs, err := listAliasEncodingsCorpus(corpus, f)
		if err != nil {
			return nil, err
		}
		encodings = append(encodings, encs...)
	}
	return buildAliasInstructions(encodings, canonicalFiles, classOf), nil
}

func buildAliasInstructions(encodings []AliasEncoding, canonicalFiles map[string]struct{}, classOf func(string) string) []*ir.InstructionIR {
	sort.Slice(encodings, func(i, j int) bool {
		if encodings[i].IFormFile != encodings[j].IFormFile {
			return encodings[i].IFormFile < encodings[j].IFormFile
		}
		return encodings[i].EncodingID < encodings[j].EncodingID
	})

	seen := make(map[string]struct{}, len(encodings))
	out := make([]*ir.InstructionIR, 0, len(encodings))
	for _, encoding := range encodings {
		if _, canonical := canonicalFiles[encoding.IFormFile]; canonical {
			continue
		}
		mnemonic := encoding.Mnemonic
		if mnemonic == "" {
			mnemonic = encoding.Canonical
		}
		if mnemonic == "" || encoding.EncodingID == "" {
			continue
		}
		key := encoding.IFormFile + "\x00" + encoding.EncodingID
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}

		class := ""
		if classOf != nil {
			class = classOf(encoding.RefIForm)
		}
		if class == "" {
			class = classFromEncodingID(encoding.EncodingID)
		}
		out = append(out, &ir.InstructionIR{
			EncodingID: encoding.EncodingID,
			Mnemonic:   mnemonic,
			IClass:     class,
			IFormFile:  encoding.IFormFile,
			Encoding:   ir.EncodingMask{Width: 32},
		})
	}
	return out
}

// indexedIFormFiles collects every iformfile named by the alphabetic indexes.
func indexedIFormFiles(corpus XMLCorpus) (map[string]struct{}, error) {
	out := make(map[string]struct{}, 2400)
	for _, name := range aliasIndexFiles {
		f, err := corpus.OpenXML(name)
		if err != nil {
			// Index files are per-instruction-set; a missing one is not fatal.
			continue
		}
		dec := xml.NewDecoder(f)
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return nil, err
			}
			if se, ok := tok.(xml.StartElement); ok {
				if v := attr(se, "iformfile"); v != "" {
					out[v] = struct{}{}
				}
			}
		}
		f.Close()
	}
	return out, nil
}

// listAliasEncodingsCorpus streams one alias page and returns its encodings.
func listAliasEncodingsCorpus(corpus XMLCorpus, name string) ([]AliasEncoding, error) {
	f, err := corpus.OpenXML(name)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	_, aliases, isIForm, err := inspectIFormMember(f, path.Base(name))
	if err != nil || !isIForm {
		return nil, err
	}
	return aliases, nil
}

// inspectIFormMember reads one bounded IForm member and applies the same
// structural scanner used by the compressed-corpus path.
func inspectIFormMember(r io.Reader, name string) (encodingIDs []string, aliases []AliasEncoding, isIForm bool, err error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, false, err
	}
	return inspectIFormMemberBytes(data, name)
}

// inspectIFormMemberBytes indexes an already-buffered tar member without
// constructing encoding/xml tokens for prose, diagrams, or pseudocode. It is a
// deliberately small XML scanner: it validates element nesting and only
// materializes the handful of attributes required by the corpus index.
func inspectIFormMemberBytes(data []byte, name string) (encodingIDs []string, aliases []AliasEncoding, isIForm bool, err error) {
	var (
		isAlias   bool
		refIForm  string
		pageAlias string
		pageCanon string
		cur       *AliasEncoding
		sawRoot   bool
		stack     [][]byte
	)

	for pos := 0; ; {
		rel := bytes.IndexByte(data[pos:], '<')
		if rel < 0 {
			break
		}
		start := pos + rel
		switch {
		case bytes.HasPrefix(data[start:], []byte("<!--")):
			end := bytes.Index(data[start+4:], []byte("-->"))
			if end < 0 {
				return nil, nil, false, fmt.Errorf("unterminated XML comment")
			}
			pos = start + 4 + end + 3
			continue
		case bytes.HasPrefix(data[start:], []byte("<![CDATA[")):
			end := bytes.Index(data[start+9:], []byte("]]>"))
			if end < 0 {
				return nil, nil, false, fmt.Errorf("unterminated XML CDATA")
			}
			pos = start + 9 + end + 3
			continue
		case bytes.HasPrefix(data[start:], []byte("<?")):
			end := bytes.Index(data[start+2:], []byte("?>"))
			if end < 0 {
				return nil, nil, false, fmt.Errorf("unterminated XML processing instruction")
			}
			pos = start + 2 + end + 2
			continue
		}

		end, ok := xmlTagEnd(data, start+1)
		if !ok {
			return nil, nil, false, fmt.Errorf("unterminated XML tag")
		}
		tag := bytes.TrimSpace(data[start+1 : end])
		pos = end + 1
		if len(tag) == 0 {
			return nil, nil, false, fmt.Errorf("empty XML tag")
		}
		if tag[0] == '!' {
			continue
		}

		if tag[0] == '/' {
			element := localXMLName(bytes.TrimSpace(tag[1:]))
			if len(stack) == 0 || !bytes.Equal(stack[len(stack)-1], element) {
				return nil, nil, false, fmt.Errorf("unbalanced XML end element %q", element)
			}
			stack = stack[:len(stack)-1]
			if bytes.Equal(element, []byte("encoding")) {
				cur = nil
			}
			continue
		}

		selfClosing := tag[len(tag)-1] == '/'
		if selfClosing {
			tag = bytes.TrimSpace(tag[:len(tag)-1])
		}
		elementEnd := bytes.IndexAny(tag, " \t\r\n")
		if elementEnd < 0 {
			elementEnd = len(tag)
		}
		element := localXMLName(tag[:elementEnd])
		if !sawRoot {
			sawRoot = true
			if !bytes.Equal(element, []byte("instructionsection")) {
				return nil, nil, false, nil
			}
			isIForm = true
		}

		switch string(element) {
		case "instructionsection":
			isAlias = xmlAttribute(tag[elementEnd:], "type") == "alias"
		case "aliasto":
			refIForm = xmlAttribute(tag[elementEnd:], "refiform")
		case "encoding":
			id := xmlAttribute(tag[elementEnd:], "name")
			if id != "" {
				encodingIDs = append(encodingIDs, id)
			}
			if isAlias {
				aliases = append(aliases, AliasEncoding{
					EncodingID: id,
					Mnemonic:   pageAlias,
					Canonical:  pageCanon,
					IFormFile:  name,
					RefIForm:   refIForm,
				})
				cur = &aliases[len(aliases)-1]
			}
		case "docvar":
			key := xmlAttribute(tag[elementEnd:], "key")
			value := xmlAttribute(tag[elementEnd:], "value")
			if value != "" {
				switch key {
				case "alias_mnemonic":
					if cur == nil {
						pageAlias = value
					} else {
						cur.Mnemonic = value
					}
				case "mnemonic":
					if cur == nil {
						pageCanon = value
					} else {
						cur.Canonical = value
					}
				}
			}
		}

		if !selfClosing {
			stack = append(stack, element)
		} else if bytes.Equal(element, []byte("encoding")) {
			cur = nil
		}
	}

	if len(stack) != 0 {
		return nil, nil, false, fmt.Errorf("unclosed XML element %q", stack[len(stack)-1])
	}
	if !isAlias {
		return encodingIDs, nil, isIForm, nil
	}
	for i := range aliases {
		aliases[i].RefIForm = refIForm
	}
	return encodingIDs, aliases, isIForm, nil
}

func xmlTagEnd(data []byte, start int) (int, bool) {
	var quote byte
	brackets := 0
	for i := start; i < len(data); i++ {
		switch c := data[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[':
			brackets++
		case c == ']' && brackets > 0:
			brackets--
		case c == '>' && brackets == 0:
			return i, true
		}
	}
	return 0, false
}

func localXMLName(name []byte) []byte {
	name = bytes.TrimSpace(name)
	if end := bytes.IndexAny(name, " \t\r\n"); end >= 0 {
		name = name[:end]
	}
	if colon := bytes.LastIndexByte(name, ':'); colon >= 0 {
		name = name[colon+1:]
	}
	return name
}

func xmlAttribute(attrs []byte, wanted string) string {
	for pos := 0; pos < len(attrs); {
		for pos < len(attrs) && isXMLSpace(attrs[pos]) {
			pos++
		}
		nameStart := pos
		for pos < len(attrs) && !isXMLSpace(attrs[pos]) && attrs[pos] != '=' {
			pos++
		}
		name := attrs[nameStart:pos]
		for pos < len(attrs) && isXMLSpace(attrs[pos]) {
			pos++
		}
		if pos >= len(attrs) || attrs[pos] != '=' {
			for pos < len(attrs) && !isXMLSpace(attrs[pos]) {
				pos++
			}
			continue
		}
		pos++
		for pos < len(attrs) && isXMLSpace(attrs[pos]) {
			pos++
		}
		if pos >= len(attrs) || (attrs[pos] != '"' && attrs[pos] != '\'') {
			continue
		}
		quote := attrs[pos]
		pos++
		valueStart := pos
		for pos < len(attrs) && attrs[pos] != quote {
			pos++
		}
		value := attrs[valueStart:pos]
		if pos < len(attrs) {
			pos++
		}
		if bytes.Equal(name, []byte(wanted)) {
			return html.UnescapeString(string(value))
		}
	}
	return ""
}

func isXMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// classFromEncodingID recovers the encoding class from an encoding ID when the
// canonical page's class is unavailable. IDs end with their class, which may
// itself contain underscores (ASR_ASRV_32_dp_2src -> dp_2src).
func classFromEncodingID(id string) string {
	parts := strings.Split(id, "_")
	if len(parts) < 2 {
		return "alias"
	}
	// Two trailing segments cover the compound classes (dp_2src, ldst_immpost,
	// addsub_carry); a single one covers the rest (bitfield, systeminstrs).
	if len(parts) >= 3 && isClassWord(parts[len(parts)-2]) {
		return parts[len(parts)-2] + "_" + parts[len(parts)-1]
	}
	return parts[len(parts)-1]
}

// isClassWord reports whether a segment is the leading half of a compound
// encoding-class name rather than a mnemonic or variant marker.
func isClassWord(s string) bool {
	switch s {
	case "dp", "ldst", "addsub", "log", "move", "cond", "float", "fp", "crypto", "perm", "comswap", "memop", "ldstexcl", "bitfield":
		return true
	}
	return false
}
