use amdgpu::{assemble_with_features, decode_with_features, encode, profile, Template};
use std::{alloc::{GlobalAlloc,Layout,System},cell::Cell};

struct CountAlloc;
thread_local!{static ALLOCATIONS:Cell<Option<usize>>=const{Cell::new(None)};}
fn count_allocation(){let _=ALLOCATIONS.try_with(|c|{if let Some(n)=c.get(){c.set(Some(n+1));}});}
unsafe impl GlobalAlloc for CountAlloc{
    unsafe fn alloc(&self,l:Layout)->*mut u8{count_allocation();unsafe{System.alloc(l)}}
    unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8{count_allocation();unsafe{System.realloc(p,l,n)}}
    unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:CountAlloc=CountAlloc;

// Bytes independently assembled by LLVM 22.1.8 llvm-mc, not the generated codec.
#[test]
fn llvm_shader_forms_use_public_api() {
    let cases: &[(&str, &str, &[u8])] = &[
        ("gfx1100", "v_add_f32_e32 v3, v1, v2", &[0x01,0x05,0x06,0x06]),
        ("gfx1100", "v_add_f16_e64 v0.h, v1.l, v2.h op_sel:[0,1,1]", &[0x00,0x50,0x32,0xd5,0x01,0x05,0x02,0x00]),
        ("gfx1100", "image_load v0, [v0,v1,v2], s[0:7] dmask:1 dim:SQ_RSRC_IMG_2D_ARRAY", &[0x15,0x01,0x00,0xf0,0x00,0x00,0x00,0x00,0x01,0x02,0x00,0x00]),
        ("gfx1010", "image_gather4_b_cl_o v[0:1], v[0:2], s[0:7], s[0:3] dmask:1 dim:SQ_RSRC_IMG_1D a16 d16", &[0x00,0x01,0x58,0xf1,0x00,0x00,0x00,0xc0]),
        ("gfx900", "image_load v0, v0, s[0:7] dmask:1 a16", &[0x00,0x81,0x00,0xf0,0x00,0x00,0x00,0x00]),
        ("gfx1250", "s_mov_b64 s[0:1], 0x123456789abcdef0", &[0xfe,0x01,0x80,0xbe,0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12]),
    ];
    for &(cpu,text,bytes) in cases {
        let active=profile(cpu).unwrap();
        let candidates=assemble_with_features(text,0x1000,Some(active)).unwrap();
        assert!(candidates.iter().any(|b|b==bytes),"{cpu}: {text}");
        let decoded=decode_with_features(bytes,Some(active)).unwrap();
        assert_eq!(decoded.length,bytes.len(),"{text}");
        assert_eq!(encode(decoded.encoding().id,&decoded.values[..decoded.encoding().operands.len()]).unwrap(),bytes);
        let formatted=decoded.format(0x1000);
        assert!(assemble_with_features(&formatted,0x1000,Some(active)).unwrap().iter().any(|b|b==bytes),"{formatted}");
    }
}

#[test]
fn text_template_binds_and_matches_a_register() {
    let pattern=Template::parse("v_add_f32_e32 ${dst}, v1, v2").unwrap();
    let bytes=&[0x01,0x05,0x06,0x06];
    let (length,bindings)=pattern.matches(bytes).unwrap();
    assert_eq!(length,4);
    assert_eq!(bindings,vec![("dst".to_owned(),3)]);
    assert!(pattern.encode(&[("dst",3)]).unwrap().iter().any(|b|b==bytes));
}

#[test]
fn processor_profile_disambiguates_image_instruction_length() {
    // LLVM emits this 16-byte GFX10 image instruction and a 12-byte GFX11
    // instruction with the same prefix. Stream framing requires the CPU.
    let bytes=&[0x15,0x01,0xe8,0xf0,0,0,0,0,0,0,0,0,0,0,0,0];
    for (cpu,length,text) in [
        ("gfx1010",16,"image_sample_c_d_o_g16 v0, [v0,v0,v0,v0,v0,v0,v0,v0,v0], s[0:7], s[0:3] dmask:1 dim:SQ_RSRC_IMG_3D"),
        ("gfx1100",12,"image_sample_c_d_g16 v0, [v0,v0,v0,v0,v[0:1]], s[0:7], s[0:3] dmask:1 dim:SQ_RSRC_IMG_2D_ARRAY"),
    ] {
        let active=Some(profile(cpu).unwrap());
        let d=decode_with_features(bytes,active).unwrap();
        assert_eq!(d.length,length,"{cpu}");
        let expected=&bytes[..length];
        assert_eq!(encode(d.encoding().id,&d.values[..d.encoding().operands.len()]).unwrap(),expected);
        assert!(assemble_with_features(text,0x1000,active).unwrap().iter().any(|b|b==expected),"{cpu}");
        assert!(assemble_with_features(&d.format(0x1000),0x1000,active).unwrap().iter().any(|b|b==expected),"{cpu}");
    }
}

#[test]
fn source_operand_domains_and_relative_targets_use_public_api() {
    // LLVM rejects these source register-domain violations; the generated
    // consumer must apply the same image, bank, and alignment constraints.
    for (cpu,text) in [
        ("gfx1100", "image_load v[0:4], v[0:1], s[0:7] dmask:1 dim:SQ_RSRC_IMG_2D"),
        ("gfx1100", "v_dual_add_f32 v0, v0, v2 :: v_dual_add_f32 v1, v4, v3"),
        ("gfx950", "v_add_f64_e64 v[1:2], v[2:3], v[4:5]"),
    ] {
        assert!(assemble_with_features(text,0x1000,Some(profile(cpu).unwrap())).is_err(),"{cpu}: {text}");
    }
    // Independently assembled by LLVM from `s_branch 3`.
    let bytes=&[0x03,0x00,0xa0,0xbf];
    let active=Some(profile("gfx1100").unwrap());
    assert!(assemble_with_features("s_branch 0x1010",0x1000,active).unwrap().iter().any(|b|b==bytes));
    assert_eq!(decode_with_features(bytes,active).unwrap().branch_target(0x1000),Some(0x1010));
}

#[test]
fn reusable_shader_assembly_preserves_zero_allocations_and_errors(){
    let mut assembler=amdgpu::Assembler::with_capacity(4096);let mut output=[0xa5;64];
    for (cpu,text) in [
        ("gfx1100","v_add_f32_e32 v3, v1, v2"),
        ("gfx1100","v_add_f32_dpp v0, v1, v2 quad_perm:[3,2,1,0] row_mask:15 bank_mask:15"),
        ("gfx1100","v_add_f16_e64 v0.h, v1.l, v2.h op_sel:[0,1,1]"),
        ("gfx1100","image_load v0, [v0,v1,v2], s[0:7] dmask:1 dim:SQ_RSRC_IMG_2D_ARRAY"),
        ("gfx1010","image_gather4_b_cl_o v[0:1], v[0:2], s[0:7], s[0:3] dmask:1 dim:SQ_RSRC_IMG_1D a16 d16"),
        ("gfx1250","s_mov_b64 s[0:1], 0x123456789abcdef0"),
    ]{
        let active=Some(profile(cpu).unwrap());let expected=assemble_with_features(text,0x1000,active).unwrap();
        ALLOCATIONS.with(|c|c.set(Some(0)));
        let result=assembler.assemble_with_features_into(text,0x1000,active,&mut output);
        let allocations=ALLOCATIONS.with(|c|c.replace(None).unwrap());
        let n=result.unwrap();assert_eq!(&output[..n],expected[0]);assert_eq!(allocations,0,"{cpu}: {text}");
        let mut short=[0xa5;1];
        assert_eq!(assembler.assemble_with_features_into(text,0x1000,active,&mut short),Err(amdgpu::Error::BufferTooSmall));assert_eq!(short,[0xa5]);
    }
    for text in ["image_load v0, [v0,v1,v2], s[0:7] dmask:1 dim:unknown", "v_add_f32_e32 invalid,v1,v2", "s_mov_b64 s[0:1], 0xgarbage"]{
        output.fill(0xa5);ALLOCATIONS.with(|c|c.set(Some(0)));
        let result=assembler.assemble_with_features_into(text,0x1000,Some(profile("gfx1100").unwrap()),&mut output);
        let allocations=ALLOCATIONS.with(|c|c.replace(None).unwrap());
        assert_eq!(result,Err(amdgpu::Error::Syntax));assert_eq!(output,[0xa5;64]);assert_eq!(allocations,0,"{text}");
    }
}
