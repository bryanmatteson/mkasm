package codec

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestRustMatchProgram(t *testing.T) {
	operands := []Operand{{Name: "II"}, {Name: "Ii"}, {Name: "π"}}
	for _, tc := range []struct {
		pattern string
		want    []byte
	}{
		{"", nil},
		{"op", []byte("op")},
		{"op{Ii},{II}{π}", []byte{'o', 'p', 255, 1, ',', 255, 0, 255, 2}},
		{"{II}{II}", []byte{255, 0, 255, 0}},
		{"\x01{II}\x02", []byte{1, 255, 0, 2}},
		{"ä{π}", []byte{0xc3, 0xa4, 255, 2}},
		{"op{missing}", []byte{'o', 'p', 255, 255, 255, 255, 255, 255}},
		{"op{unclosed", []byte{'o', 'p', 255, 255, 255, 255, 255, 255}},
	} {
		if got := rustMatchProgram(tc.pattern, operands); !bytes.Equal(got, tc.want) {
			t.Fatalf("%q program = %v, want %v", tc.pattern, got, tc.want)
		}
		if got := rustMatchOperandCount(tc.want); got != strings.Count(tc.pattern, "{") {
			t.Fatalf("%q operand count = %d", tc.pattern, got)
		}
	}
	wide := make([]Operand, 257)
	wide[255].Name, wide[256].Name = "last_byte", "next_byte"
	if got := rustMatchProgram("{last_byte}{next_byte}", wide); !bytes.Equal(got, []byte{255, 255, 255, 0, 0, 0, 255, 255, 0, 1, 0, 0}) {
		t.Fatalf("wide operand indices = %v", got)
	}
	if got := rustMatchOperandCount(rustMatchProgram(strings.Repeat("{next_byte}", 300), wide)); got != 300 {
		t.Fatalf("repeated wide operand count = %d", got)
	}
	if got := rustByteString([]byte{'a', '"', '\\', 0, 0xc4, 0xb0, 255}); got != `b"a\x22\x5c\x00\xc4\xb0\xff"` {
		t.Fatalf("byte string = %q", got)
	}
}

func TestRustShortestCandidatesPreservePriority(t *testing.T) {
	es := []Encoding{{Value: make([]byte, 4)}, {Value: make([]byte, 2)}, {Value: make([]byte, 2)}, {Value: make([]byte, 1)}}
	indices := []int{0, 1, 2, 3}
	got := rustShortestCandidates(es, indices)
	if !reflect.DeepEqual(got, []int{3, 1, 2, 0}) || !reflect.DeepEqual(indices, []int{0, 1, 2, 3}) {
		t.Fatalf("stable shortest order %v; original %v", got, indices)
	}
	if rustShortestCandidates(es, got) != nil || rustShortestCandidates(es, nil) != nil {
		t.Fatal("already ordered candidates must reuse the original list")
	}
}

func TestRustOperandNamesPreservePrecedence(t *testing.T) {
	o := Operand{
		Names:           []string{"", " R1\t", "r1", "İ2", " \t", "π4"},
		RegisterAliases: map[string]int64{"R1": 9, "r1": 8, " İ2 ": 7, " Alias ": -1, "alias": 4, "": 12},
	}
	want := []rustOperandName{{"", 4}, {"alias", ^uint64(0)}, {"i\u03072", 3}, {"r1", 1}, {"π4", 5}}
	if got := prepareRustOperandNames(o); !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized names = %#v, want %#v", got, want)
	}
	if got := prepareRustOperandNames(Operand{}); len(got) != 0 {
		t.Fatalf("empty operand names = %#v", got)
	}
}

func TestRustOperandRunsPreserveCatalog(t *testing.T) {
	input := []Operand{{Name: "split", Bits: []BitSlice{{12, 4, 4}, {8, 0, 4}, {20, 1, 2}, {25, 7, 1}}}}
	original := append([]BitSlice(nil), input[0].Bits...)
	got := rustOperands(input)
	want := []BitSlice{{8, 0, 8}, {20, 1, 2}, {25, 7, 1}}
	if !reflect.DeepEqual(got[0].Bits, want) {
		t.Fatalf("coalesced bits = %v, want %v", got[0].Bits, want)
	}
	if !reflect.DeepEqual(input[0].Bits, original) {
		t.Fatal("generation mutated imported operands")
	}
}

func TestRustDispatchPreservesMaskPriority(t *testing.T) {
	c := exampleCatalog(t)
	// Include overlapping wildcards, equal-specificity alternatives and an
	// assembly-only wildcard that must never take part in decoding.
	c.Encodings = append(c.Encodings, Encoding{ID: "TIE", Mask: []byte{0xf0}, Value: []byte{0x80}}, Encoding{ID: "RAW", Mask: []byte{0}, Value: []byte{0}, AssemblyOnly: true})
	tree := buildRustDecodeTree(c.Encodings)
	if len(tree.nodes) <= 1 {
		t.Fatal("fixture did not exercise dispatch branches")
	}
	matches := func(ids []int, src []byte) []int {
		var result []int
		for _, id := range ids {
			e := c.Encodings[id]
			ok := true
			for i, b := range src {
				if i >= len(e.Mask) {
					break
				}
				if b&e.Mask[i] != e.Value[i] {
					ok = false
					break
				}
			}
			if ok {
				result = append(result, id)
			}
		}
		return result
	}
	for word := 0; word < 1<<16; word++ {
		src := []byte{byte(word), byte(word >> 8)}
		for _, n := range []int{0, 1, 2} {
			src := src[:n]
			node := 0
			var ids []int
			for {
				v := tree.nodes[node]
				if v.bit == ^uint32(0) {
					ids = tree.candidates[v.zero : v.zero+v.one]
					break
				}
				if int(v.bit/8) >= len(src) {
					ids = tree.order
					break
				}
				node = int(v.zero)
				if src[v.bit/8]&(1<<(v.bit%8)) != 0 {
					node = int(v.one)
				}
			}
			got, want := matches(ids, src), matches(tree.order, src)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%x candidates = %v, want %v", src, got, want)
			}
		}
	}
	empty := buildRustDecodeTree([]Encoding{{AssemblyOnly: true}})
	if len(empty.nodes) != 1 || empty.nodes[0].one != 0 {
		t.Fatal("assembly-only catalog must have an empty decode leaf")
	}
}

// Compare generated decoding with the independent Go consumer on malformed
// inputs and short prefixes, which catalog round trips alone cannot cover.
func rustDispatchConsumer(c *Catalog) string {
	var b strings.Builder
	b.WriteString("#[test]fn dispatch_matches_go(){let cases:&[(&[u8],&str,usize)]=&[\n")
	add := func(src []byte) {
		id, n := "Unknown", 0
		d, err := c.Decode(src)
		if err == nil {
			id, n = d.Encoding.ID, d.Length
		} else if err == ErrTruncated {
			id = "Truncated"
		}
		fmt.Fprintf(&b, "(&%s,%q,%d),\n", rustBytes(src), id, n)
	}
	for _, e := range c.Encodings {
		for n := 0; n <= len(e.Value); n++ {
			add(e.Value[:n])
		}
	}
	rng := rand.New(rand.NewSource(719))
	for i := 0; i < 512; i++ {
		src := make([]byte, i%10)
		rng.Read(src)
		add(src)
	}
	b.WriteString("];for &(bytes,id,length)in cases{match decode(bytes){Ok(d)=>{assert_eq!(d.encoding().id,id,\"{:x?}\",bytes);assert_eq!(d.length,length)},Err(e)=>assert_eq!(format!(\"{e:?}\"),id,\"{:x?}\",bytes)}}}\n")
	return b.String()
}

const rustZeroAllocationConsumer = `
use std::{alloc::{GlobalAlloc,Layout,System},cell::Cell};
struct CountAlloc;
thread_local!{static ALLOCS:Cell<Option<usize>>=const{Cell::new(None)};}
fn count_alloc(){let _=ALLOCS.try_with(|c|{if let Some(n)=c.get(){c.set(Some(n+1));}});}
unsafe impl GlobalAlloc for CountAlloc{
 unsafe fn alloc(&self,l:Layout)->*mut u8{count_alloc();unsafe{System.alloc(l)}}
 unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8{count_alloc();unsafe{System.realloc(p,l,n)}}
 unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:CountAlloc=CountAlloc;
fn without_allocations(f:impl FnOnce()) {ALLOCS.with(|c|c.set(Some(0)));f();let n=ALLOCS.with(|c|c.replace(None).unwrap());assert_eq!(n,0);}
#[test]fn fused_register_text_preserves_spans_and_numeric_fallback(){
 let mut d=decode(&[0x82,0xfc]).unwrap();
 let described=d.describe(0);assert_eq!(described.text,"mov r2, -8");
 assert_eq!(&described.text[described.operands[0].start..described.operands[0].end],"r2");
 for value in [-1,0,2,4,200] {d.values[0]=value;let expected=format!("mov r{value}, -8");let mut out=String::new();d.write_to(0,&mut out).unwrap();assert_eq!(out,expected);assert_eq!(d.describe(0).text,expected);}
}
#[test]fn reusable_hot_paths(){
 let mut asm=Assembler::with_capacity(4096);let mut out=[0xa5;64];let mut text=String::with_capacity(4096);
 for input in [" MOV\tR2, -8 ","rpt #3 { inc 5","gpu r1 clamp offset:4","gpu r1 offset:4","CASE 2, 7","mem (r2-3)","divide $zero,$v0,$v1","padding 3","long 256",".raw 256","unicode İÄ İ1","pick 7","pick 256","filter {π} 17 suffix64","17=literal64"]{
  let active=if input=="long 256"{Some(profile("long").unwrap())}else{None};
  let expected=assemble_with_features(input,0,active).unwrap();
  without_allocations(||{let n=asm.assemble_with_features_into(input,0,active,&mut out).unwrap();assert_eq!(&out[..n],expected[0]);});
 }
 for(index,e)in ENCODINGS.iter().enumerate(){
  let values=representative(index).unwrap();let bytes=encode(e.id,&values).unwrap();let active=FEATURE_SETS.iter().find(|(_,f)|e.features.iter().all(|r|f.contains(r))).map(|(_,f)|*f);
  if let Ok(d)=decode_with_features(&bytes,active){let expected=d.format(0x1000);text.clear();without_allocations(||d.write_to(0x1000,&mut text).unwrap());assert_eq!(text,expected);}
 }
 for bad in ["invalid", "mov r9,0", "mov r1,3"] {out.fill(0xa5);without_allocations(||assert_eq!(asm.assemble_into(bad,0,&mut out),Err(Error::Syntax)));assert_eq!(out,[0xa5;64]);}
 let n=asm.assemble_into("pick 7",0,&mut out).unwrap();assert_eq!(&out[..n],&[0xfa,7]);let n=asm.assemble_into("pick 256",0,&mut out).unwrap();assert_eq!(&out[..n],&[0xf9,0,1]);
 for input in ["order 1", "order 7", "backtrack ab,ab", "backtrack ab,a", "backtrack a,a", "backtrack b,b", "repeat_slots 1,1,1,1,1,1,1,1"]{
  let expected=assemble(input).unwrap();without_allocations(||{let n=asm.assemble_into(input,0,&mut out).unwrap();assert_eq!(&out[..n],expected[0]);});
 }
 let n=asm.assemble_into("order 1",0,&mut out).unwrap();assert_eq!(&out[..n],&[0xfe,1]);
 let n=asm.assemble_into("order 7",0,&mut out).unwrap();assert_eq!(&out[..n],&[0xfe,0x27]);
 for input in ["backtrack ab,b", "backtrack a,ab", "backtrack ab,abx", "repeat_slots 1,1,1,1,1,1,1,2"]{without_allocations(||assert_eq!(asm.assemble_into(input,0,&mut out),Err(Error::Syntax)));}
 let mut short=[0xa5;1];without_allocations(||assert_eq!(asm.assemble_into("mov r1,4",0,&mut short),Err(Error::BufferTooSmall)));assert_eq!(short,[0xa5]);
 struct Fail;impl std::fmt::Write for Fail{fn write_str(&mut self,_:&str)->std::fmt::Result{Err(std::fmt::Error)}}
 assert_eq!(decode(&[0x82,0xfc]).unwrap().write_to(0,&mut Fail),Err(std::fmt::Error));
 let t=Template::parse("mov $r,$n").unwrap();let mut captures=[("",0);16];
 without_allocations(||{assert!(t.is_match(&[0x82,0xfc]));assert!(!t.is_match(&[0x82]));assert_eq!(t.matches_into(&[0x82,0xfc],&mut captures),Ok(Some((2,2))));});
 assert_eq!(&captures[..2],&[("r",2),("n",-8)]);let mut small=[("sentinel",7)];without_allocations(||assert_eq!(t.matches_into(&[0x82,0xfc],&mut small),Err(Error::BufferTooSmall)));assert_eq!(small,[("sentinel",7)]);
 let repeated=Template::parse("mov $same,$same").unwrap();without_allocations(||{assert!(repeated.is_match(&[0x82,1]));assert!(!repeated.is_match(&[0x82,2]));});
 let long=format!("u64 {}1", "0".repeat(16384));assert_eq!(asm.assemble_into(&long,0,&mut out).unwrap(),9);without_allocations(||assert_eq!(asm.assemble_into(&long,0,&mut out).unwrap(),9));
}
`

func TestRustDisplayLiteralsResolveEscapesBeforeRendering(t *testing.T) {
	for _, syntax := range []string{"op {{r}} {x}", "é {{π}} [{x}]", "literal\x01x\x02 {x}", "nested {{{x}}}"} {
		encoding := Encoding{Syntax: syntax, Operands: []Operand{{Name: "x"}}}
		prepared := prepareRustSyntax(encoding)
		var got, want strings.Builder
		for _, part := range prepared.Parts {
			if part.Operand >= 0 {
				got.WriteString("7")
				want.WriteString("7")
				continue
			}
			got.WriteString(prepared.Display[part.Start:part.End])
			protected := strings.ReplaceAll(strings.ReplaceAll(syntax, "{{", "\x01"), "}}", "\x02")
			want.WriteString(strings.NewReplacer("\x01", "{", "\x02", "}").Replace(protected[part.Start:part.End]))
		}
		if got.String() != want.String() {
			t.Fatalf("%q: %q != %q", syntax, got.String(), want.String())
		}
	}
}

func TestRustCommaTokensPreserveSyntax(t *testing.T) {
	for _, tc := range []struct {
		name    string
		operand Operand
		fuse    bool
	}{
		{"identity", Operand{Names: []string{"", "r1", "π2"}}, true},
		{"explicit scale", Operand{Names: []string{"r0"}, Scale: 1}, true},
		{"transformed", Operand{Names: []string{"r0"}, Scale: 2}, false},
		{"bias", Operand{Names: []string{"r0"}, Bias: 1}, false},
		{"dependent bias", Operand{Names: []string{"r0"}, BiasOperand: "other"}, false},
		{"lookup", Operand{Names: []string{"r0"}, Lookup: []int64{7}}, false},
		{"large namespace", Operand{Names: make([]string, 65)}, false},
		{"numeric", Operand{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.operand.Name = "x"
			e := Encoding{Syntax: "op {{literal}} {x}, {y}, {x}", Operands: []Operand{tc.operand, {Name: "y"}}}
			syntax := prepareRustSyntax(e)
			var display strings.Builder
			fused := 0
			for _, part := range syntax.Parts {
				if part.Operand < 0 {
					display.WriteString(syntax.Display[part.Start:part.End])
				} else {
					display.WriteString(e.Operands[part.Operand].Name)
				}
				if part.Comma {
					fused++
					display.WriteString(", ")
				}
			}
			if display.String() != "op {literal} x, y, x" {
				t.Fatal(display.String())
			}
			want := 0
			if tc.fuse {
				want = 1
			}
			if fused != want {
				t.Fatalf("fused %d, want %d", fused, want)
			}
			if !bytes.Equal(syntax.Pattern, rustMatchProgram("op\x01literal\x02{x},{y},{x}", e.Operands)) {
				t.Fatalf("assembly program changed: %v", syntax.Pattern)
			}
		})
	}
}
