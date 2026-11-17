package x86

const x86IntegerMigrationRecipeTests = `
const INTEGER_NAMES: &[&str] = &["MPSADBW", "PABSB", "PABSD", "PABSW", "PACKSSDW", "PACKSSWB", "PACKUSDW", "PACKUSWB", "PADDB", "PADDD", "PADDQ", "PADDSB", "PADDSW", "PADDUSB", "PADDUSW", "PADDW", "PALIGNR", "PAND", "PANDN", "PAVGB", "PAVGW", "PBLENDD", "PBLENDVB", "PBLENDW", "PCMPEQB", "PCMPEQD", "PCMPEQQ", "PCMPEQW", "PCMPGTB", "PCMPGTD", "PCMPGTQ", "PCMPGTW", "PHADDD", "PHADDSW", "PHADDW", "PHMINPOSUW", "PHSUBD", "PHSUBSW", "PHSUBW", "PMADDUBSW", "PMADDWD", "PMAXSB", "PMAXSD", "PMAXSW", "PMAXUB", "PMAXUD", "PMAXUW", "PMINSB", "PMINSD", "PMINSW", "PMINUB", "PMINUD", "PMINUW", "PMOVSXBD", "PMOVSXBQ", "PMOVSXBW", "PMOVSXDQ", "PMOVSXWD", "PMOVSXWQ", "PMOVZXBD", "PMOVZXBQ", "PMOVZXBW", "PMOVZXDQ", "PMOVZXWD", "PMOVZXWQ", "PMULDQ", "PMULHRSW", "PMULHUW", "PMULHW", "PMULLD", "PMULLW", "PMULUDQ", "POR", "PSADBW", "PSHUFB", "PSHUFD", "PSHUFHW", "PSHUFLW", "PSHUFW", "PSIGNB", "PSIGND", "PSIGNW", "PSLLD", "PSLLDQ", "PSLLQ", "PSLLVD", "PSLLVQ", "PSLLW", "PSRAD", "PSRAVD", "PSRAW", "PSRLD", "PSRLDQ", "PSRLQ", "PSRLVD", "PSRLVQ", "PSRLW", "PSUBB", "PSUBD", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW", "PSUBW", "PTEST", "PUNPCKHBW", "PUNPCKHDQ", "PUNPCKHQDQ", "PUNPCKHWD", "PUNPCKLBW", "PUNPCKLDQ", "PUNPCKLQDQ", "PUNPCKLWD", "PXOR"];

#[test]
fn generated_integer_admits_every_supported_corpus_form() {
    for mode in [Mode::Mode16, Mode::Mode32, Mode::Mode64] {
        let mut covered = std::collections::HashSet::new();
        let mut count = 0;
        let mut declined = Vec::new();
        for index in 0..encoding_count() {
            let e = encoding(index).unwrap();
            let name = e.mnemonic.strip_prefix('V').unwrap_or(e.mnemonic);
            if !INTEGER_NAMES.contains(&name) || !SSE_AVX_FORMS.contains(&e.form_id) || !encoding_supports_mode(index, mode) {
                continue;
            }
            let mut bytes = [0; 15];
            let len = encode_representative(index, mode, &mut bytes)
                .unwrap_or_else(|error| panic!("{mode:?} {}: {error:?}", e.form_id));
            let decoded = decode(&bytes[..len], mode).unwrap();
            let recipe = decoded.semantic_recipe(0x1000);
            if recipe.support != Support::Full { declined.push(e.form_id); continue; }
            recipe.validate().unwrap();
            covered.insert(name);
            count += 1;
        }
        assert!(declined.is_empty(), "{mode:?} declined corpus forms: {declined:?}");
        assert_eq!(covered, INTEGER_NAMES.iter().copied().collect());
        println!("generated integer {mode:?}: {count} public corpus witnesses");
    }
}

#[test]
fn generated_mmx_uses_physical_payloads_for_every_incoming_top() {
    for top in 0..8u16 {
        let mut st=State::default();
        st.reg("x86.x87_control",0,0x37f);
        st.reg("x86.x87_status",0,u64::from(top)<<11|0x4000);
        st.reg("x86.x87_tags",0,0xffff);
        for logical in 0..8u16 {
            let physical=(logical+top)&7;
            st.reg("x86.x87",logical*2,0x0101010101010101*u64::from(physical+1));
            st.reg("x86.x87",logical*2+1,0x1000+u64::from(physical));
        }
        let t=run(&[0x0f,0xfc,0xc1],&st); // paddb mm0,mm1
        assert_eq!(reg(&t,"x86.x87",0),Value::known(64,0x0303030303030303));
        assert_eq!(reg(&t,"x86.x87",1),Value::known(16,0xffff));
        for n in 1..8u16 {
            assert_eq!(reg(&t,"x86.x87",n*2).bits,0x0101010101010101*u64::from(n+1));
            assert_eq!(reg(&t,"x86.x87",n*2+1).bits,0x1000+u64::from(n));
        }
        assert_eq!(reg(&t,"x86.x87_status",0).bits,0x4000);
        assert_eq!(reg(&t,"x86.x87_tags",0).bits,0);
        assert!(t.registers.iter().all(|v|v.register.bank!="x86.flags"));
    }
}
#[test]
fn generated_mmx_pending_exception_precedes_memory_and_publishes_nothing() {
    let mut state=State::default();state.reg("x86.x87_control",0,0x37e);state.reg("x86.x87_status",0,1);state.x(0,0xdeadbeef);
    let d=decode(&[0x0f,0xfc,0x00],Mode::Mode64).unwrap();
    let recipe=d.semantic_recipe(0x1000);assert_eq!(recipe.support,Support::Full);recipe.validate().unwrap();
    let t=s::evaluate(&recipe,&state).unwrap();
    assert_eq!(t.trap,Some(s::TrapKind::FloatingPoint));assert!(t.registers.is_empty());assert!(t.memory.is_empty());
}

#[test]
fn generated_integer_evex_align_covers_all_controls_and_masks() {
    for (vl,lbits) in [(128usize,0u8),(256,0x20),(512,0x40)] {
        for zero in [false,true] {
            for imm in 0..=255u8 {
                let mut st=State::default();
                let mask=0xa55a5aa55aa5a55au64;
                st.reg("x86.mask",1,mask);
                for chunk in 0..8u16 {
                    st.reg("x86.vector64",chunk,u64::MAX);
                    let bytes=|base:u8| (0..8).fold(0u64,|v,j|v|u64::from(base.wrapping_add((chunk*8+j)as u8))<<(j*8));
                    st.reg("x86.vector64",8+chunk,bytes(0x80));
                    st.reg("x86.vector64",16+chunk,bytes(1));
                }
                let bytes=[0x62,0xf3,0x75,0x09|lbits|if zero{0x80}else{0},0x0f,0xc2,imm];
                let t=run(&bytes,&st);
                for chunk in 0..8usize {
                    let mut expected=0u64;
                    for j in 0..8usize {
                        let i=chunk*8+j;
                        let value=if i>=vl/8 {0} else if mask>>i&1==0 {if zero{0}else{255}} else {
                            let index=i%16+usize::from(imm);let base=i/16*16;
                            if index<16 {(base+index+1)as u8} else if index<32 {(base+index-16+0x80)as u8} else {0}
                        };
                        expected|=u64::from(value)<<(j*8);
                    }
                    assert_eq!(vector_result(&t,0,chunk as u16),expected,"vl={vl} zero={zero} imm={imm} chunk={chunk}");
                }
            }
        }
    }
}
#[test]
fn generated_integer_low_mmx_unpack_reads_exactly_four_bytes() {
    let mut st=AccessState::new();
    st.state.reg("x86.x87_control",0,0x37f);st.state.reg("x86.x87_status",0,0);st.state.reg("x86.x87_tags",0,0xffff);
    for n in 0..8u16 {st.state.reg("x86.x87",n*2,0x0807060504030201);st.state.reg("x86.x87",n*2+1,0);}
    st.state.x(0,0x4000);st.state.mem.insert(0x4000,0x0c0b0a09);
    let d=decode(&[0x0f,0x60,0x00],Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);r.validate().unwrap();
    let t=s::evaluate(&r,&st).unwrap();assert_eq!(*st.reads.borrow(),[(0x4000,32)]);
    assert_eq!(reg(&t,"x86.x87",0).bits,0x0c040b030a020901);
}
`
