// Public generated-crate consumer. Installed for both MIPS16 byte orders.
use __CRATE__::{assemble_at, assemble_with_context, decode, ExecutionContext, ARCHITECTURE};

fn physical(words: &[u16]) -> Vec<u8> {
    words.iter().flat_map(|word| if ARCHITECTURE.ends_with("el") { word.to_le_bytes() } else { word.to_be_bytes() }).collect()
}

#[test]
fn explicit_delay_slot_pc_and_region_wrap() {
    let is64 = ARCHITECTURE.contains("64");
    let address_mask = if is64 { u64::MAX } else { 0xffff_ffff };
    let mut fixtures = vec![
        (0x1006, 0x1002, 0x1004), // Four-byte JAL/JALX, two-byte data slot.
        (0x1004, 0x1002, 0x1004), // Two-byte JR/JALR, two-byte data slot.
        (0, 0xffff_fffc, 0),      // 32-bit architectural wrap.
    ];
    if is64 {
        fixtures[2] = (0x1_0000_0000, 0xffff_fffc, 0x1_0000_0000);
        fixtures.extend([(0x1234_5678_1006, 0x1234_5678_1002, 0x1234_5678_1004), (0, u64::MAX - 3, 0)]);
    }
    for (instruction_address, pc_base, target) in fixtures {
        let context = ExecutionContext { instruction_address, pc_base };
        for word in [0x0801, 0xb201] {
            let bytes = physical(&[word]);
            let decoded = decode(&bytes).unwrap();
            let normal = decoded.format(instruction_address);
            let text = decoded.format_with_context(context);
            assert!(text.contains(&format!("0x{target:x}")), "{text}");
            assert_ne!(text, normal);
            assert!(assemble_with_context(&text, context, None).unwrap().contains(&bytes));
            assert!(assemble_at(&normal, instruction_address).unwrap().contains(&bytes));
            let description = decoded.describe_with_context(context);
            assert_eq!(description.text, text);
            for span in description.operands.iter().filter(|span| span.position.is_position_dependent()) {
                assert_eq!(span.position.target(instruction_address, span.value), Some(target));
            }
            let references = decoded.address_references_with_context(context);
            assert_eq!(references.len(), 1);
            let reference = &references[0];
            assert_eq!(reference.target, target);
            assert_eq!(reference.position.target(instruction_address, decoded.values[reference.operand_index]), Some(target));
            let mut output = [0; 4];
            let n = decoded.rewrite_reference_with_context(context, reference.operand_index, target.wrapping_add(4) & address_mask, &mut output).unwrap();
            assert_eq!(&output[..n], &physical(&[word + 1]));
            assert_eq!(decoded.format(instruction_address), normal);
        }
    }
    let bytes = physical(&[0x1800, 0]);
    let decoded = decode(&bytes).unwrap();
    let context = ExecutionContext { instruction_address: 0x0fff_fffc, pc_base: 0x0100_0000 };
    let text = decoded.format_with_context(context);
    assert_eq!(text, decoded.format(context.instruction_address));
    assert!(text.contains("0x10000000"));
}

#[test]
fn full_width_code_regions() {
    let is64 = ARCHITECTURE.contains("64");
    for (words, address, target32, target64) in [
        (vec![0x1001], 0xffff_fffc, 0, 0x1_0000_0000),
        (vec![0x1800, 0], 0x1234_5678_0fff_fffc, 0x1000_0000, 0x1234_5678_1000_0000),
        (vec![0x1800, 0], u64::MAX - 3, 0, 0),
    ] {
        let bytes = physical(&words);
        let decoded = decode(&bytes).unwrap();
        let target = if is64 { target64 } else { target32 };
        assert_eq!(decoded.branch_target(address), Some(target));
        assert!(assemble_at(&decoded.format(address), address).unwrap().contains(&bytes));
    }
}
