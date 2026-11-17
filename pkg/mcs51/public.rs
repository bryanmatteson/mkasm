use __CRATE__::*;
#[test]
fn public_instruction_workflow() {
    assert!(assemble("mov A,#0ffh").unwrap().contains(&vec![0x74, 0xff]));
    assert!(assemble("mov P1,#1")
        .unwrap()
        .contains(&vec![0x75, 0x90, 1]));
    assert!(assemble("setb P1.3").unwrap().contains(&vec![0xd2, 0x93]));
    assert!(assemble("mov 0x34,0x12")
        .unwrap()
        .contains(&vec![0x85, 0x12, 0x34]));
    let t = Template::parse("mov $dst,#$imm").unwrap();
    let raw = vec![0x7b, 0x55];
    assert!(t
        .encode(&[("dst", 3), ("imm", 0x55)])
        .unwrap()
        .contains(&raw));
    let (_, holes) = t.matches(&raw).unwrap();
    assert_eq!(holes, vec![("dst".into(), 3), ("imm".into(), 0x55)]);
    assert!(decode(&[0xa5]).is_err());
    assert!(assemble("mov @R2,A").is_err());
    assert!(assemble("mov R8,A").is_err());
    assert!(assemble("mov A,#256").is_err());
    assert_eq!(decode(&[0x22]).unwrap().encoding().flow_control, "return");
}
#[test]
fn public_page_wrap_and_state() {
    let flat = profile("mcs80390").is_some();
    let pc = if flat { 0xffffff } else { 0xffff };
    let raw = if flat { vec![1, 0, 1] } else { vec![1, 1] };
    let d = decode(&raw).unwrap();
    assert_eq!(d.branch_target(pc), Some(1));
    assert!(assemble_at(&d.format(pc), pc).unwrap().contains(&raw));
    let t = Template::parse_at(&d.format(pc), pc).unwrap();
    assert!(t.matches(&raw).is_some());
    assert!(t.encode(&[]).unwrap().contains(&raw));
    let b = vec![0x80, 0xfe];
    assert_eq!(decode(&b).unwrap().branch_target(pc), Some(pc));
    let target = if flat { 0x80000 } else { 0x800 };
    assert!(assemble_at(&format!("ajmp 0x{:x}", target), 0).is_err());
    for bank in 0..4 {
        for reg in 0..8 {
            assert_eq!(register_address(reg, bank << 3), Some(bank * 8 + reg));
        }
    }
    for b in 0..=255 {
        let (space, byte, bit) = resolve_bit(b);
        assert!(bit < 8);
        assert_eq!(space, if b < 128 { "INTMEM" } else { "SFR" });
        if b < 128 {
            assert_eq!(byte, 0x20 + b / 8)
        } else {
            assert_eq!(byte, b & 0xf8)
        }
    }
    assert_eq!(external_indirect_address(0x34, 0x12), 0x1234);
}
