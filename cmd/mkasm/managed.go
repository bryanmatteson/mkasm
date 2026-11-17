package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bryanmatteson/mkasm/pkg/cil"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
	"github.com/bryanmatteson/mkasm/pkg/managed"
)

type managedReference struct {
	Offset uint32       `json:"offset"`
	Token  dotnet.Token `json:"token"`
	Name   string       `json:"name"`
	Kind   string       `json:"kind"`
}

type managedMethod struct {
	dotnet.Method
	Body       *cil.MethodBody    `json:"body,omitempty"`
	References []managedReference `json:"references,omitempty"`
	Stack      *cil.StackAnalysis `json:"stack,omitempty"`
}

type managedReport struct {
	Schema           string                       `json:"schema"`
	Architecture     string                       `json:"architecture"`
	Image            *dotnet.Image                `json:"image"`
	Assemblies       []dotnet.Assembly            `json:"assemblies"`
	Types            []dotnet.TypeDefinition      `json:"types"`
	Fields           []dotnet.Field               `json:"fields"`
	Methods          []managedMethod              `json:"methods"`
	Properties       []dotnet.Property            `json:"properties"`
	Events           []dotnet.Event               `json:"events"`
	Attributes       []dotnet.AttributeRecord     `json:"attributes"`
	Marshaling       []dotnet.MarshalRecord       `json:"marshaling,omitempty"`
	Security         []dotnet.SecurityRecord      `json:"security,omitempty"`
	NativeHeader     *dotnet.ReadyToRunInfo       `json:"native_header,omitempty"`
	NativeFunctions  []dotnet.NativeFunction      `json:"native_functions,omitempty"`
	Components       []dotnet.ReadyToRunComponent `json:"components,omitempty"`
	Resources        []dotnet.Resource            `json:"resources,omitempty"`
	DebugEntries     []dotnet.DebugEntry          `json:"debug_entries,omitempty"`
	Symbols          *managedSymbols              `json:"symbols,omitempty"`
	TypeVerification *managed.TypeVerification    `json:"type_verification,omitempty"`
}

type managedDocument struct {
	Token dotnet.Token `json:"token"`
	Name  string       `json:"name"`
}

type managedDebugMethod struct {
	Token          dotnet.Token           `json:"token"`
	LocalSignature dotnet.Token           `json:"local_signature"`
	SequencePoints []dotnet.SequencePoint `json:"sequence_points"`
}

type managedSymbols struct {
	Metadata  *dotnet.Metadata     `json:"metadata"`
	Documents []managedDocument    `json:"documents"`
	Methods   []managedDebugMethod `json:"methods"`
}

func inspectManagedSymbols(metadata *dotnet.Metadata) (*managedSymbols, error) {
	if metadata == nil || metadata.PDB == nil {
		return nil, nil
	}
	symbols := &managedSymbols{Metadata: metadata}
	for rid := uint32(1); rid <= metadata.Tables[48].Count; rid++ {
		name, err := metadata.DocumentName(rid)
		if err != nil {
			return nil, err
		}
		symbols.Documents = append(symbols.Documents, managedDocument{dotnet.Token(48<<24 | rid), name})
	}
	for rid := uint32(1); rid <= metadata.Tables[49].Count; rid++ {
		token := dotnet.Token(6<<24 | rid)
		local, points, err := metadata.SequencePoints(token)
		if err != nil {
			return nil, err
		}
		symbols.Methods = append(symbols.Methods, managedDebugMethod{token, local, points})
	}
	return symbols, nil
}

func inspectManaged(ctx context.Context, input string, stdin io.Reader, stdout io.Writer) error {
	return inspectManagedWithVerification(ctx, input, stdin, stdout, false)
}
func inspectManagedWithVerification(ctx context.Context, input string, stdin io.Reader, stdout io.Writer, verify bool) error {
	return inspectManagedDetailed(ctx, input, stdin, stdout, verify, "", nil, "", false)
}
func inspectManagedDetailed(ctx context.Context, input string, stdin io.Reader, stdout io.Writer, verify bool, typeVerifier string, references []string, systemModule string, native bool) error {
	r, closeInput, err := openSpecification(ctx, input, stdin)
	if err != nil {
		return err
	}
	defer closeInput()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	image, err := dotnet.Open(data)
	if err != nil {
		return err
	}
	report := managedReport{Schema: "mkasm.managed-report.v1", Architecture: "cil", Image: image}
	enums := dotnet.EnumResolver(image.Metadata.LocalEnumUnderlying)
	var referenceSet *dotnet.ReferenceSet
	if len(references) > 0 {
		set, e := managedReferenceSet(references, image.Metadata, input)
		if e != nil {
			return e
		}
		referenceSet = set
	}
	if typeVerifier != "" {
		// Verify exactly the bytes inspected, including stdin and URL inputs.
		dir, e := os.MkdirTemp("", "mkasm-ilverify-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, "input.dll")
		if e = os.WriteFile(path, data, 0600); e != nil {
			return e
		}
		result, e := managed.VerifyTypesWith(ctx, typeVerifier, path, references, systemModule)
		if e != nil {
			return e
		}
		report.TypeVerification = &result
	}
	if report.Assemblies, err = image.Metadata.Assemblies(); err != nil {
		return err
	}
	if report.Types, err = image.Metadata.Types(); err != nil {
		return err
	}
	if report.Fields, err = image.Metadata.Fields(); err != nil {
		return err
	}
	if report.Properties, err = image.Metadata.Properties(); err != nil {
		return err
	}
	if report.Events, err = image.Metadata.Events(); err != nil {
		return err
	}
	if referenceSet != nil {
		report.Attributes, err = referenceSet.SerializedAttributes(image.Metadata, 0)
	} else {
		report.Attributes, err = image.Metadata.SerializedAttributes(0, enums)
	}
	if err != nil {
		return err
	}
	if report.Marshaling, err = image.Metadata.MarshalRecords(); err != nil {
		return err
	}
	if referenceSet != nil {
		report.Security, err = referenceSet.SecurityRecords(image.Metadata)
	} else {
		report.Security, err = image.Metadata.SecurityRecords(enums)
	}
	if err != nil {
		return err
	}
	if native {
		if report.NativeHeader, err = image.ReadyToRunHeader(); err != nil {
			return err
		}
		if report.NativeFunctions, err = image.NativeFunctions(); err != nil {
			return err
		}
		if report.Components, err = image.ReadyToRunComponents(); err != nil {
			return err
		}
	}
	if report.Resources, err = image.Resources(); err != nil {
		return err
	}
	if report.DebugEntries, err = image.DebugEntries(); err != nil {
		return err
	}
	symbolMetadata := image.Metadata
	if image.Metadata.PDB == nil {
		// The same input bound used for ordinary metadata also bounds embedded
		// Portable PDB decompression before parsing its tables and sequence data.
		symbolMetadata, err = image.EmbeddedPDB(512 << 20)
		if err != nil {
			return err
		}
	}
	if report.Symbols, err = inspectManagedSymbols(symbolMetadata); err != nil {
		return err
	}
	methods, err := image.Metadata.Methods()
	if err != nil {
		return err
	}
	codec := cil.Default()
	for _, method := range methods {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := managedMethod{Method: method}
		if method.Kind == "cil" {
			if verify {
				entry.Stack, err = managed.VerifyMethod(image, method.Token)
				if err != nil {
					return fmt.Errorf("%s (%s): %w", method.FullName, method.Token, err)
				}
			}
			body, err := image.MethodBody(method.Token)
			if err != nil {
				return err
			}
			entry.Body, err = codec.DecodeMethodBody(body.Raw)
			if err != nil {
				return fmt.Errorf("%s (%s): %w", method.FullName, method.Token, err)
			}
			resolve := func(offset uint32, token dotnet.Token, kind string) error {
				name, err := image.Metadata.Resolve(token)
				if err != nil {
					return fmt.Errorf("%s %s IL_%04x token %s: %w", method.FullName, kind, offset, token, err)
				}
				entry.References = append(entry.References, managedReference{offset, token, name, kind})
				return nil
			}
			if entry.Body.LocalSignatureToken != 0 {
				if err := resolve(0, dotnet.Token(entry.Body.LocalSignatureToken), "local-signature"); err != nil {
					return err
				}
			}
			for _, section := range entry.Body.Sections {
				for _, clause := range section.Clauses {
					if clause.Flags == 0 {
						if err := resolve(clause.HandlerOffset, dotnet.Token(clause.ClassTokenOrFilterOffset), "catch-type"); err != nil {
							return err
						}
					}
				}
			}
			for _, instruction := range entry.Body.Instructions {
				if instruction.Operand == nil || instruction.Operand.Kind != "token" {
					continue
				}
				token := dotnet.Token(instruction.Operand.Value)
				if err := resolve(instruction.Offset, token, "instruction"); err != nil {
					return err
				}
			}
		}
		report.Methods = append(report.Methods, entry)
	}
	return json.NewEncoder(stdout).Encode(report)
}
