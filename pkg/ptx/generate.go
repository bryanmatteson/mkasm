package ptx

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed runtime.rs UPSTREAM-NOTICE.md testdata/*.ptx
var runtimeAssets embed.FS

func rust(s string) string {
	hash := "###"
	for strings.Contains(s, "\""+hash) {
		hash += "#"
	}
	return "r" + hash + "\"" + s + "\"" + hash
}
func rustStrings(a []string) string {
	var b strings.Builder
	b.WriteString("&[")
	for _, s := range a {
		b.WriteString(rust(s))
		b.WriteByte(',')
	}
	b.WriteByte(']')
	return b.String()
}
func (c *Catalog) GenerateRust(out string) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(out)
		}
	}()

	if e := os.MkdirAll(filepath.Join(out, "src"), 0755); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Join(out, "tests/fixtures"), 0755); e != nil {
		return e
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "pub const ISA_VERSION:&str=%s;\npub const REGISTRY_JSON:&str=include_str!(\"registry.json\");\npub static DOCUMENTS:&[Document]=&[\n", rust(c.ISAVersion))
	for _, d := range c.Documents {
		fmt.Fprintf(&b, "Document{id:%s,kind:%s,section:%s,names:%s,syntax:%s,examples:%s,requirements:%s,min_version:%d,min_target:%d},\n", rust(d.ID), rust(d.Kind), rust(d.Section), rustStrings(d.Names), rustStrings(d.Syntax), rustStrings(d.Examples), rustStrings(d.Requirements), d.MinVersion, d.MinTarget)
	}
	b.WriteString("];\npub static LLVM:&[LLVMRecord]=&[\n")
	for _, r := range c.LLVM {
		fmt.Fprintf(&b, "LLVMRecord{id:%s,syntax:%s,pseudo:%t,namespace:%s,features:%s,constraints:%s,locations:%s,operands:&[", rust(r.ID), rust(r.Syntax), r.Pseudo, rust(r.Namespace), rustStrings(r.Features), rust(r.Constraints), rustStrings(r.Locations))
		for _, o := range r.Operands {
			fmt.Fprintf(&b, "OperandDefinition{name:%s,class_name:%s},", rust(o.Name), rust(o.Class))
		}
		b.WriteString("]},\n")
	}
	b.WriteString("];\n")
	targets := map[string]bool{}
	re := regexp.MustCompile(`sm_[0-9]+[af]?`)
	for _, d := range c.Documents {
		for _, s := range d.Syntax {
			for _, t := range re.FindAllString(s, -1) {
				targets[t] = true
			}
		}
	}
	ts := []string{}
	for t := range targets {
		ts = append(ts, t)
	}
	sort.Strings(ts)
	fmt.Fprintf(&b, "pub static TARGETS:&[&str]=%s;\n", rustStrings(ts))
	b.WriteString("pub static TARGET_VERSIONS:&[(&str,u32)]=&[")
	keys := []string{}
	for t := range c.TargetVersions {
		keys = append(keys, t)
	}
	sort.Strings(keys)
	for _, t := range keys {
		fmt.Fprintf(&b, "(%s,%d),", rust(t), c.TargetVersions[t])
	}
	b.WriteString("];\n")
	b.WriteString("pub static FEATURES:&[Feature]=&[")
	for _, f := range c.Features {
		fmt.Fprintf(&b, "Feature{id:%s,kind:%s,name:%s,field:%s,value:%s,description:%s,condition:%s,implies:%s},", rust(f.ID), rust(f.Kind), rust(f.Name), rust(f.Field), rust(f.Value), rust(f.Description), rust(f.Condition), rustStrings(f.Implies))
	}
	b.WriteString("];\n")
	runtime, _ := runtimeAssets.ReadFile("runtime.rs")
	b.Write(runtime)
	if e := os.WriteFile(filepath.Join(out, "src/lib.rs"), b.Bytes(), 0644); e != nil {
		return e
	}
	var j bytes.Buffer
	if e := c.WriteJSON(&j); e != nil {
		return e
	}
	if e := os.WriteFile(filepath.Join(out, "src/registry.json"), j.Bytes(), 0644); e != nil {
		return e
	}
	files := map[string]string{"Cargo.toml": "[package]\nname=\"mkasm-ptx\"\nversion=\"0.1.0\"\nedition=\"2021\"\nlicense=\"MIT\"\n[lib]\npath=\"src/lib.rs\"\n", "tests/public.rs": fmt.Sprintf(`use mkasm_ptx::*;
#[test]fn full_source(){assert_eq!(DOCUMENTS.len(),%d);assert_eq!(LLVM.len(),%d);let mut n=0;for r in LLVM{if r.syntax.is_empty(){continue}let t=template(r.id).unwrap();let bindings=t.holes.iter().map(|h|{let key=if h.format.is_empty(){h.name.clone()}else{h.name.clone()+":"+&h.format};(key.clone(),format!("capture_{}",key.replace(':',"_")))}).collect::<std::collections::BTreeMap<_,_>>();let text=t.fill(&bindings).unwrap();let captured=t.matches(&text).unwrap_or_else(||panic!("{} template does not match its rendering",r.id));assert_eq!(t.fill(&captured).unwrap(),text);n+=1;}assert_eq!(n,6321);assert!(REGISTRY_JSON.contains("NVIDIA PTX ISA 9.5"));assert_eq!(FEATURES.len(),157);let mut examples=0;for d in DOCUMENTS{for s in d.syntax.iter().chain(d.examples.iter()){let ts=lex(s).unwrap();assert_eq!(ts.iter().map(|t|t.text).collect::<String>(),*s);}examples+=d.examples.len();}assert_eq!(examples,286);}
#[test]fn clang_modules(){for s in [include_str!("fixtures/clang-sm80.ptx"),include_str!("fixtures/clang-sm90-debug.ptx")]{let m=decode(s).unwrap();assert_eq!(m.encode(),s);assert!(m.to_json().contains("\"source\""));assert!(m.instructions.len()>20);assert_eq!(m.functions().len(),3);assert!(!m.declarations().is_empty());assert!(!m.control_flow().is_empty());check(&m,&Profile::default()).result().unwrap();assert!(!check(&m,&Profile::default()).semantic_complete);}}
#[test]fn latest_isa(){let s=include_str!("fixtures/ptx95.ptx");let m=decode(s).unwrap();assert_eq!(m.version,"9.5");assert_eq!(m.functions().len(),1);assert_eq!(m.instructions.len(),7);assert!(m.instructions.iter().any(|i|i.opcode=="trace.mark.cond.b32"));check(&m,&Profile::default()).result().unwrap();assert_eq!(m.encode(),s);}
#[test]fn lookup_matches_original_registry_scan(){
fn original(opcode:&str)->Vec<&'static Document>{let mut out=vec![];let mut max=0;for d in DOCUMENTS{if d.kind!="instruction"{continue;}for n in d.names{if opcode==*n||opcode.starts_with(&format!("{}.",n))||opcode.starts_with(&format!("{}::",n))||(*n=="match.sync"&&(opcode.starts_with("match.any.sync.")||opcode.starts_with("match.all.sync."))){if n.len()>max{out.clear();max=n.len();}if n.len()==max{out.push(d);}break;}}}out}
for d in DOCUMENTS{for name in d.names{for suffix in ["",".u32","::cta","x",":cta",".π"]{let opcode=format!("{name}{suffix}");let got=lookup(&opcode);let want=original(&opcode);assert_eq!(got.iter().map(|d|d.id).collect::<Vec<_>>(),want.iter().map(|d|d.id).collect::<Vec<_>>(),"{opcode}");}}}
for opcode in ["match.any.sync.b32","match.all.sync.b32","","π","invented.op"]{assert_eq!(lookup(opcode).iter().map(|d|d.id).collect::<Vec<_>>(),original(opcode).iter().map(|d|d.id).collect::<Vec<_>>());}
}
#[test]fn scoped_families(){for op in ["tcgen05.fence::before_thread_sync","tcgen05.fence::after_thread_sync","tcgen05.wait::ld.sync.aligned","tcgen05.wait::st.sync.aligned"]{let d=lookup(op);assert_eq!(d.len(),1);assert_eq!(d[0].min_version,86);assert_eq!(d[0].min_target,100);}for op in ["tcgen05.waitx::ld.sync.aligned","tcgen05.fence:before_thread_sync"]{assert!(lookup(op).is_empty());}}
#[test]fn multiline_directive(){let s=".version 6.0\n.target sm_30\n.address_size 64\n.func f(){table: .branchtargets\n first,\n second;\n brx.idx %%r1,table;first: bra second;second: ret;}";let m=decode(s).unwrap();assert_eq!(m.encode(),s);assert_eq!(m.instructions.len(),3);assert_eq!(m.control_flow()[0].target,"table");assert!(decode(".branchtargets a,\nb").is_err());}
#[test]fn structured_edit(){let s=".version 8.8\n.target sm_90\n.address_size 64\n.entry k(){ @!%%p mov.b64 {%%r1,%%r2}, %%rd;ret;}";let m=decode(s).unwrap();assert_eq!(m.instructions[0].predicate,Some("%%p"));assert!(m.instructions[0].negated);assert_eq!(m.instructions[0].operands[0].kind,"vector");let edited=m.replace_operand(0,1,"%%new").unwrap();assert!(edited.contains("{%%r1,%%r2}, %%new;"));let t=Template::compile("add${mode}.u32 $dst, ${src:foo}, $$symbol;").unwrap();let v=std::collections::BTreeMap::from([("mode".into(),".sat".into()),("dst".into(),"%%r".into()),("src:foo".into(),"%%a".into())]);assert_eq!(t.fill(&v).unwrap(),"add.sat.u32 %%r, %%a, $symbol;");}
#[test]fn hostile(){for s in ["mov.u32 %%r,1","{ret;","ld.u32 %%r,[%%a);","/* open",".file 1 \"unterminated","ret;}","mov.u32 %%r,,;"]{assert!(decode(s).is_err(),"{}",s)}let s=include_str!("fixtures/clang-sm80.ptx");for n in 0..s.len(){if s.is_char_boundary(n){let _=decode(&s[..n]);}}let m=decode(".version 9.9\n.target sm_999\n.address_size 16\n.entry k(){ invented.op;}").unwrap();assert!(check(&m,&Profile::default()).result().is_err());}
`, len(c.Documents), len(c.LLVM))}
	for p, s := range files {
		if e := os.WriteFile(filepath.Join(out, p), []byte(s), 0644); e != nil {
			return e
		}
	}
	for _, n := range []string{"clang-sm80.ptx", "clang-sm90-debug.ptx", "ptx95.ptx"} {
		s, e := runtimeAssets.ReadFile("testdata/" + n)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(out, "tests/fixtures", n), s, 0644); e != nil {
			return e
		}
	}
	notice, _ := runtimeAssets.ReadFile("UPSTREAM-NOTICE.md")
	if e := os.WriteFile(filepath.Join(out, "UPSTREAM-NOTICE.md"), notice, 0644); e != nil {
		return e
	}
	return codec.WriteLicense(out)
}
