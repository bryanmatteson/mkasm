package x86

import (
	"strings"
	"testing"
)

// Compiled as its own integration binary so other tests cannot affect the
// process-wide allocation counter. The full-corpus CLI validation reuses it.
const rustIntelFormatReuseTest = `use x86_64::*;
use std::alloc::{GlobalAlloc,Layout,System};
use std::sync::atomic::{AtomicUsize,Ordering};
struct Alloc;
static CALLS:AtomicUsize=AtomicUsize::new(0);
unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self,l:Layout)->*mut u8{CALLS.fetch_add(1,Ordering::Relaxed);unsafe{System.alloc(l)}}
    unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
    unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8{CALLS.fetch_add(1,Ordering::Relaxed);unsafe{System.realloc(p,l,n)}}
}
#[global_allocator]static ALLOC:Alloc=Alloc;
#[test]
fn formatting_reuses_capacity_for_every_representable_form() {
    let mut checked=0;
    for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64] {
        for index in 0..encoding_count() {
            let mut bytes=[0;15];
            let Ok(n)=encode_representative(index,mode,&mut bytes) else{continue};
            let Ok(decoded)=decode(&bytes[..n],mode) else{continue};
            let expected=decoded.format_intel(0x1234);
            let mut output=String::with_capacity(expected.len()+32);
            output.push_str("stale output");
            CALLS.store(0,Ordering::Relaxed);
            for _ in 0..3 {decoded.format_intel_into(0x1234,&mut output);}
            let calls=CALLS.load(Ordering::Relaxed);
            assert_eq!(calls,0,"{} {mode:?}",decoded.encoding().form_id);
            assert_eq!(output,expected);
            format_intel_into(&decoded,0x1234,&mut output);
            assert_eq!(output,expected);
            let mut empty=String::new();
            decoded.format_intel_into(0x1234,&mut empty);
            assert_eq!(empty,expected);
            checked+=1;
        }
    }
    assert!(checked>0);
}
`

func TestRustMnemonicMetadataInternsRepeatedText(t *testing.T) {
	c := &Catalog{Encodings: []Encoding{{ID: "one", Mnemonic: "ADD"}, {ID: "two", Mnemonic: "ADD"}, {ID: "unicode", Mnemonic: "ÄDD"}}}
	data := buildRustCodegenData(c, &Decoder{})
	if data.TextMnemonics != "\"add\",\n\"Ädd\",\n" {
		t.Fatalf("mnemonic table: %q", data.TextMnemonics)
	}
	if strings.Count(data.Encodings, "text_mnemonic: 0,") != 2 || strings.Count(data.Encodings, "text_mnemonic: 1,") != 1 {
		t.Fatal(data.Encodings)
	}
}

func TestRustMnemonicIndexWidth(t *testing.T) {
	for _, tc := range []struct {
		count int
		want  string
	}{{0, "u16"}, {1 << 16, "u16"}, {1<<16 + 1, "u32"}} {
		if got := rustMnemonicIndexType(tc.count); got != tc.want {
			t.Fatalf("%d mnemonic slots use %s, want %s", tc.count, got, tc.want)
		}
	}
}
