package arm

import (
	"encoding/xml"
	"io"
	"path"
	"sort"
	"strings"

	"mkasm/pkg/ir"
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

// inspectIFormMember reads the lightweight page structure needed by the
// streaming corpus loader. It returns after the root start tag for non-IForm
// XML, avoiding a scan of shared pseudocode and index documents.
func inspectIFormMember(r io.Reader, name string) (encodingIDs []string, aliases []AliasEncoding, isIForm bool, err error) {
	var (
		isAlias   bool
		refIForm  string
		pageAlias string // page-level alias_mnemonic
		pageCanon string // page-level mnemonic
		cur       *AliasEncoding
		sawRoot   bool
	)
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, false, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if !sawRoot {
				sawRoot = true
				if t.Name.Local != "instructionsection" {
					return nil, nil, false, nil
				}
				isIForm = true
			}
			switch t.Name.Local {
			case "instructionsection":
				isAlias = attr(t, "type") == "alias"
			case "aliasto":
				refIForm = attr(t, "refiform")
			case "encoding":
				id := attr(t, "name")
				if id != "" {
					encodingIDs = append(encodingIDs, id)
				}
				if !isAlias {
					break
				}
				aliases = append(aliases, AliasEncoding{
					EncodingID: attr(t, "name"),
					Mnemonic:   pageAlias,
					Canonical:  pageCanon,
					IFormFile:  name,
					RefIForm:   refIForm,
				})
				cur = &aliases[len(aliases)-1]
			case "docvar":
				k, v := attr(t, "key"), attr(t, "value")
				if v == "" {
					break
				}
				switch k {
				case "alias_mnemonic":
					if cur != nil {
						cur.Mnemonic = v
					} else {
						pageAlias = v
					}
				case "mnemonic":
					if cur != nil {
						cur.Canonical = v
					} else {
						pageCanon = v
					}
				}
			}
		case xml.EndElement:
			if t.Name.Local == "encoding" {
				cur = nil
			}
		}
	}
	if !isAlias {
		return encodingIDs, nil, isIForm, nil
	}
	for i := range aliases {
		aliases[i].RefIForm = refIForm
	}
	return encodingIDs, aliases, isIForm, nil
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
