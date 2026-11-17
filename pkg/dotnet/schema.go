// Package dotnet inspects managed PE images and ECMA-335 metadata without
// loading or executing the assemblies.
package dotnet

import (
	"fmt"
	"strconv"
	"strings"
)

type Column struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}
type TableSchema struct {
	ID      uint8    `json:"id"`
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
}
type CodedIndex struct {
	Bits   uint8
	Tables []int
}

var CodedIndices = map[string]CodedIndex{
	"TypeDefOrRef": {2, []int{2, 1, 27, -1}}, "HasConstant": {2, []int{4, 8, 23, -1}}, "HasCustomAttribute": {5, []int{6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43}}, "HasFieldMarshal": {1, []int{4, 8}}, "HasDeclSecurity": {2, []int{2, 6, 32, -1}}, "MemberRefParent": {3, []int{2, 1, 26, 6, 27}}, "HasSemantics": {1, []int{20, 23}}, "MethodDefOrRef": {1, []int{6, 10}}, "MemberForwarded": {1, []int{4, 6}}, "Implementation": {2, []int{38, 35, 39, -1}}, "CustomAttributeType": {3, []int{-1, -1, 6, 10, -1}}, "ResolutionScope": {2, []int{0, 26, 35, 1}}, "TypeOrMethodDef": {1, []int{2, 6}}, "HasCustomDebugInformation": {5, []int{6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43, 48, 50, 51, 52, 53}},
}

// Table schemas are factual layouts from ECMA-335 II.22/II.24 and Microsoft's
// Portable PDB v1.0 specification. Lists admit the end sentinel rowCount+1.
var schemaDefinitions = []string{
	"0 Module Generation:u2 Name:string Mvid:guid EncId:guid EncBaseId:guid",
	"1 TypeRef ResolutionScope:ResolutionScope Name:string Namespace:string",
	"2 TypeDef Flags:u4 Name:string Namespace:string Extends:TypeDefOrRef FieldList:l4 MethodList:l6",
	"3 FieldPtr Field:t4",
	"4 Field Flags:u2 Name:string Signature:blob",
	"5 MethodPtr Method:t6",
	"6 MethodDef RVA:u4 ImplFlags:u2 Flags:u2 Name:string Signature:blob ParamList:l8",
	"7 ParamPtr Param:t8",
	"8 Param Flags:u2 Sequence:u2 Name:string",
	"9 InterfaceImpl Class:t2 Interface:TypeDefOrRef",
	"10 MemberRef Class:MemberRefParent Name:string Signature:blob",
	"11 Constant Type:u2 Parent:HasConstant Value:blob",
	"12 CustomAttribute Parent:HasCustomAttribute Type:CustomAttributeType Value:blob",
	"13 FieldMarshal Parent:HasFieldMarshal NativeType:blob",
	"14 DeclSecurity Action:u2 Parent:HasDeclSecurity PermissionSet:blob",
	"15 ClassLayout PackingSize:u2 ClassSize:u4 Parent:t2",
	"16 FieldLayout Offset:u4 Field:t4",
	"17 StandAloneSig Signature:blob",
	"18 EventMap Parent:t2 EventList:l20",
	"19 EventPtr Event:t20",
	"20 Event EventFlags:u2 Name:string EventType:TypeDefOrRef",
	"21 PropertyMap Parent:t2 PropertyList:l23",
	"22 PropertyPtr Property:t23",
	"23 Property Flags:u2 Name:string Type:blob",
	"24 MethodSemantics Semantics:u2 Method:t6 Association:HasSemantics",
	"25 MethodImpl Class:t2 MethodBody:MethodDefOrRef MethodDeclaration:MethodDefOrRef",
	"26 ModuleRef Name:string",
	"27 TypeSpec Signature:blob",
	"28 ImplMap MappingFlags:u2 MemberForwarded:MemberForwarded ImportName:string ImportScope:t26",
	"29 FieldRVA RVA:u4 Field:t4",
	"30 EncLog Token:u4 FuncCode:u4",
	"31 EncMap Token:u4",
	"32 Assembly HashAlgId:u4 MajorVersion:u2 MinorVersion:u2 BuildNumber:u2 RevisionNumber:u2 Flags:u4 PublicKey:blob Name:string Culture:string",
	"33 AssemblyProcessor Processor:u4",
	"34 AssemblyOS OSPlatformId:u4 OSMajorVersion:u4 OSMinorVersion:u4",
	"35 AssemblyRef MajorVersion:u2 MinorVersion:u2 BuildNumber:u2 RevisionNumber:u2 Flags:u4 PublicKeyOrToken:blob Name:string Culture:string HashValue:blob",
	"36 AssemblyRefProcessor Processor:u4 AssemblyRef:t35",
	"37 AssemblyRefOS OSPlatformId:u4 OSMajorVersion:u4 OSMinorVersion:u4 AssemblyRef:t35",
	"38 File Flags:u4 Name:string HashValue:blob",
	"39 ExportedType Flags:u4 TypeDefId:u4 TypeName:string TypeNamespace:string Implementation:Implementation",
	"40 ManifestResource Offset:u4 Flags:u4 Name:string Implementation:Implementation",
	"41 NestedClass NestedClass:t2 EnclosingClass:t2",
	"42 GenericParam Number:u2 Flags:u2 Owner:TypeOrMethodDef Name:string",
	"43 MethodSpec Method:MethodDefOrRef Instantiation:blob",
	"44 GenericParamConstraint Owner:t42 Constraint:TypeDefOrRef",
	"48 Document Name:blob HashAlgorithm:guid Hash:blob Language:guid",
	"49 MethodDebugInformation Document:t48 SequencePoints:blob",
	"50 LocalScope Method:t6 ImportScope:t53 VariableList:l51 ConstantList:l52 StartOffset:u4 Length:u4",
	"51 LocalVariable Attributes:u2 Index:u2 Name:string",
	"52 LocalConstant Name:string Signature:blob",
	"53 ImportScope Parent:t53 Imports:blob",
	"54 StateMachineMethod MoveNextMethod:t6 KickoffMethod:t6",
	"55 CustomDebugInformation Parent:HasCustomDebugInformation Kind:guid Value:blob",
}
var Schemas = func() [64]*TableSchema {
	var a [64]*TableSchema
	for _, s := range schemaDefinitions {
		p := strings.Fields(s)
		n, _ := strconv.Atoi(p[0])
		t := &TableSchema{ID: uint8(n), Name: p[1]}
		for _, v := range p[2:] {
			name, kind, _ := strings.Cut(v, ":")
			t.Columns = append(t.Columns, Column{name, kind})
		}
		a[n] = t
	}
	return a
}()

type Token uint32

func (t Token) Table() uint8   { return uint8(t >> 24) }
func (t Token) RID() uint32    { return uint32(t) & 0xffffff }
func (t Token) String() string { return fmt.Sprintf("0x%08x", uint32(t)) }
func DecodeCoded(kind string, n uint32) (Token, error) {
	c, ok := CodedIndices[kind]
	if !ok {
		return 0, fmt.Errorf("unknown coded index %s", kind)
	}
	if n == 0 {
		return 0, nil
	}
	tag := int(n & ((1 << c.Bits) - 1))
	rid := n >> c.Bits
	if tag >= len(c.Tables) || c.Tables[tag] < 0 || rid == 0 || rid > 0xffffff {
		return 0, fmt.Errorf("invalid %s coded index 0x%x", kind, n)
	}
	return Token(uint32(c.Tables[tag])<<24 | rid), nil
}
