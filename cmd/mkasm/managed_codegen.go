package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/bryanmatteson/mkasm/pkg/cil"
	"github.com/bryanmatteson/mkasm/pkg/dotnet"
)

// Keep the instruction codec and metadata reader independently usable while
// presenting their complete composition through the public generator workflow.
type managedCILBackend struct{ *cil.Catalog }

func parseManagedCIL(r io.Reader, architecture string) (*managedCILBackend, error) {
	c, err := cil.Parse(r, architecture)
	if err != nil {
		return nil, err
	}
	return &managedCILBackend{c}, nil
}

func (c *managedCILBackend) GenerateRust(output string) error {
	if err := c.Catalog.GenerateRust(output); err != nil {
		return err
	}
	if err := dotnet.WriteRustModule(filepath.Join(output, "src/dotnet.rs")); err != nil {
		return err
	}
	if err := dotnet.WriteRustTests(output, "mkasm_cil::dotnet"); err != nil {
		return err
	}
	path := filepath.Join(output, "src/lib.rs")
	lib, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(lib, []byte(managedRustIntegration)...), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "tests/managed.rs"), []byte(managedRustConsumer), 0644); err != nil {
		return err
	}
	readme := filepath.Join(output, "README.md")
	text, err := os.ReadFile(readme)
	if err != nil {
		return err
	}
	if err := os.WriteFile(readme, append(text, []byte(managedRustReadme)...), 0644); err != nil {
		return err
	}
	return dotnet.WriteRustNotice(output)
}

const managedRustIntegration = `
/// Managed PE/CLI metadata, signatures, resources, and Portable PDB inspection.
pub mod dotnet;

/// Full ECMA type verification through an explicitly selected ILVerify tool and
/// complete dependency set. Unsafe code may be valid yet unverifiable.
pub fn verify_managed_types(verifier:&std::path::Path,image:&std::path::Path,references:&[&str],system_module:&str)
    -> std::result::Result<String,String>
{
    let mut command=std::process::Command::new(verifier);command.arg(image);
    for reference in references{command.arg("-r").arg(reference);}
    if !system_module.is_empty(){command.arg("-s").arg(system_module);}
    let out=command.output().map_err(|e|e.to_string())?;
    let text=format!("{}{}",String::from_utf8_lossy(&out.stdout),String::from_utf8_lossy(&out.stderr));
    if !out.status.success(){return Err(format!("type verification failed ({}): {}",out.status,text));}Ok(text)
}

/// Check stack heights using the method's actual signatures and local variables.
pub fn verify_managed_method(image:&dotnet::Image<'_>,token:dotnet::Token)
    -> std::result::Result<StackAnalysis,String>
{
    let raw=image.method_body(token).map_err(|e|e.to_string())?;
    if raw.kind!="cil"{return Err(format!("{} is {}",token,raw.kind));}
    let body=decode_method_body(raw.raw).map_err(|e|e.to_string())?;
    let c=image.metadata.evaluation_context(token,dotnet::Token(body.local_signature_token)).map_err(|e|e.to_string())?;
    let ctx=VerificationContext{arguments:c.arguments,locals:c.locals,returns_value:c.returns_value};
    verify_stack(&body,ctx,|raw|{
        let s=image.metadata.call_signature(dotnet::Token(raw)).map_err(|_|Error::Malformed("call signature resolution"))?;
        Ok(CallEffect{parameters:s.parameters.len(),has_this:s.calling_convention&0x20!=0&&s.calling_convention&0x40==0,returns_value:s.returns_value()})
    }).map_err(|e|e.to_string())
}

/// Validate replacement CIL in the owning metadata context before rewriting.
pub fn rewrite_verified_managed_methods(image:&dotnet::Image<'_>,edits:&std::collections::BTreeMap<dotnet::Token,Vec<u8>>,options:dotnet::RewriteOptions)
    -> std::result::Result<Vec<u8>,String>
{
    for (token,raw) in edits {
        let body=decode_method_body(raw).map_err(|e|e.to_string())?;
        let c=image.metadata.evaluation_context(*token,dotnet::Token(body.local_signature_token)).map_err(|e|e.to_string())?;
        let ctx=VerificationContext{arguments:c.arguments,locals:c.locals,returns_value:c.returns_value};
        verify_stack(&body,ctx,|raw|{
            let s=image.metadata.call_signature(dotnet::Token(raw)).map_err(|_|Error::Malformed("call signature resolution"))?;
            Ok(CallEffect{parameters:s.parameters.len(),has_this:s.calling_convention&0x20!=0&&s.calling_convention&0x40==0,returns_value:s.returns_value()})
        }).map_err(|e|e.to_string())?;
    }
    image.rewrite_methods(edits,options).map_err(|e|e.to_string())
}

#[derive(Debug, Clone)]
pub struct ManagedReference {
    pub offset: u32,
    pub token: dotnet::Token,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ManagedMethod {
    pub metadata: dotnet::Method,
    pub body: Option<MethodBody>,
    pub references: Vec<ManagedReference>,
}

/// Resolve a method definition and decode its CIL body in the owning image.
/// Native, abstract, runtime, and P/Invoke methods retain their explicit kind.
pub fn inspect_managed_method(image: &dotnet::Image<'_>, token: dotnet::Token)
    -> std::result::Result<ManagedMethod, String>
{
    let metadata = image.metadata.method(token).map_err(|e| e.to_string())?;
    let mut result = ManagedMethod { metadata, body: None, references: Vec::new() };
    if result.metadata.kind != "cil" { return Ok(result); }
    let raw = image.method_body(token).map_err(|e| e.to_string())?;
    let body = decode_method_body(raw.raw).map_err(|e| e.to_string())?;
    if body.local_signature_token != 0 {
        image.metadata.resolve(dotnet::Token(body.local_signature_token)).map_err(|e| e.to_string())?;
    }
    for section in &body.sections {
        for clause in &section.clauses {
            if clause.flags == 0 {
                image.metadata.resolve(dotnet::Token(clause.class_token_or_filter_offset)).map_err(|e| e.to_string())?;
            }
        }
    }
    for instruction in decode_method(&body.code).map_err(|e| e.to_string())? {
        if let Operand::Token(raw) = instruction.operand {
            let token = dotnet::Token(raw);
            let name = image.metadata.resolve(token).map_err(|e| e.to_string())?;
            result.references.push(ManagedReference { offset: instruction.offset, token, name });
        }
    }
    result.body = Some(body);
    Ok(result)
}
`

const managedRustConsumer = `use mkasm_cil::*;

#[test]
fn runtime_cil_corpus_verifies_and_round_trips(){
 let Ok(path)=std::env::var("MKASM_DOTNET_CORPUS")else{return;};
 let bytes=std::fs::read(path).unwrap();let image=dotnet::Image::open(&bytes).unwrap();
 let mut bodies=0;let mut instructions=0;
 for method in image.metadata.methods().unwrap(){
  if method.kind!="cil"{continue;}
  let raw=image.method_body(method.token).unwrap();
  let body=decode_method_body(raw.raw).unwrap_or_else(|e|panic!("{}: {e:?}",method.full_name));
  verify_managed_method(&image,method.token).unwrap_or_else(|e|panic!("{}: {e}",method.full_name));
  assert_eq!(encode_method_body(&body).unwrap(),raw.raw,"{}",method.full_name);
  let decoded=decode_method(&body.code).unwrap();instructions+=decoded.len();
  assert_eq!(encode_method(&decoded).unwrap(),raw.il,"{}",method.full_name);bodies+=1;
 }
 assert!(bodies>30_000&&instructions>100_000,"bodies={bodies} instructions={instructions}");
 eprintln!("runtime CIL corpus: {bodies} methods, {instructions} instructions");
}

#[test]
fn real_external_type_verifier_rejects_height_correct_bad_types(){
 let (Ok(verifier),Ok(references),Ok(path))=(std::env::var("MKASM_ILVERIFY"),std::env::var("MKASM_DOTNET_REFERENCES"),std::env::var("MKASM_DOTNET_TYPE_IMAGE"))else{return;};
 let verifier=std::path::Path::new(&verifier);let path=std::path::Path::new(&path);
 verify_managed_types(verifier,path,&[references.as_str()],"System.Private.CoreLib").unwrap();
 let bytes=std::fs::read(path).unwrap();let image=dotnet::Image::open(&bytes).unwrap();
 let method=image.metadata.methods().unwrap().into_iter().find(|m|m.name=="Value").unwrap();
 let edits=std::collections::BTreeMap::from([(method.token,vec![10,0x14,0x2a])]);
 let changed=rewrite_verified_managed_methods(&image,&edits,dotnet::RewriteOptions::default()).unwrap();
 let bad=path.with_file_name(format!("invalid-type-{}.dll",std::process::id()));std::fs::write(&bad,changed).unwrap();
 let result=verify_managed_types(verifier,&bad,&[references.as_str()],"System.Private.CoreLib");std::fs::remove_file(&bad).unwrap();assert!(result.is_err());
}

#[test]
fn verified_rewrite_preserves_metadata_and_rejects_stack_errors(){
 let bytes=include_bytes!("fixtures/anycpu.dll");let image=dotnet::Image::open(bytes).unwrap();
 let method=image.metadata.methods().unwrap().into_iter().find(|m|m.name=="Optional").unwrap();
 let edits=std::collections::BTreeMap::from([(method.token,vec![14,0x1f,42,0x2a])]);
 let rewritten=rewrite_verified_managed_methods(&image,&edits,dotnet::RewriteOptions::default()).unwrap();
 let next=dotnet::Image::open(&rewritten).unwrap();assert_eq!(next.method_body(method.token).unwrap().il,&[0x1f,42,0x2a]);
 assert_eq!(next.metadata.method(method.token).unwrap().full_name,method.full_name);verify_managed_method(&next,method.token).unwrap();
 let bad=std::collections::BTreeMap::from([(method.token,vec![6,0x2a])]);
 assert!(rewrite_verified_managed_methods(&image,&bad,dotnet::RewriteOptions::default()).is_err());
 assert_eq!(image.data,bytes);
}

#[test]
fn real_managed_assemblies_resolve_and_round_trip() {
    for bytes in [include_bytes!("fixtures/anycpu.dll").as_slice(),
                  include_bytes!("fixtures/x86.exe").as_slice(),
                  include_bytes!("fixtures/x64.dll").as_slice(),
                  include_bytes!("fixtures/embedded.dll").as_slice()] {
        let image = dotnet::Image::open(bytes).unwrap();
        let mut bodies = 0;
        let mut references = 0;
        let mut external = 0;
        for method in image.metadata.methods().unwrap() {
            let inspected = inspect_managed_method(&image, method.token).unwrap();
            assert_eq!(inspected.metadata.full_name, method.full_name);
            if let Some(body) = inspected.body {
                bodies += 1;
                let stack=verify_managed_method(&image,method.token).unwrap();
                assert!(stack.max_stack<=body.max_stack);
                let raw = image.method_body(method.token).unwrap();
                assert_eq!(encode_method_body(&body).unwrap(), raw.raw);
                assert_eq!(encode_method(&decode_method(&body.code).unwrap()).unwrap(), raw.il);
                for reference in inspected.references {
                    references += 1;
                    assert!(!reference.name.is_empty());
                    assert_eq!(reference.name, image.metadata.resolve(reference.token).unwrap());
                }
            } else {
                external += 1;
                assert_ne!(method.kind, "cil");
            }
        }
        assert!(bodies >= 10 && references >= 10 && external >= 1);
        assert!(inspect_managed_method(&image, dotnet::Token(0x06ffffff)).is_err());
    }
}
`

const managedRustReadme = `
## Managed image integration

The CLI-generated crate also exposes the dependency-free ` + "`dotnet`" + ` module:
PE32/PE32+ CLI headers, all metadata table layouts and heaps, coded indices,
signatures, generic substitution, members, properties/events, attributes,
resources, method framing, debug directories and Portable PDB sequence points.
` + "`inspect_managed_method(&image, token)`" + ` combines those APIs with CIL decoding
and token resolution. Its result retains non-CIL method kinds explicitly.

` + "```rust" + `
let image = mkasm_cil::dotnet::Image::open(assembly_bytes)?;
for method in image.metadata.methods()? {
    let inspected = mkasm_cil::inspect_managed_method(&image, method.token)?;
    // inspected.body contains decoded CIL; references contain resolved names.
}
` + "```" + `

Run ` + "`cargo test --lib --tests`" + ` for the combined opcode, managed-image,
compiled method, metadata, resource and Portable PDB consumer checks.
`
