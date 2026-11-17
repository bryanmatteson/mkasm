use aarch64::*;
fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}
fn word(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
fn target(b: &[u8], ip: u64) -> u64 {
    address_references(word(b), ip).unwrap()[0].target
}
#[test]
fn internal_and_external() {
    let source = bytes(&[0x14000002, 0xd503201f, 0x17fffffe]);
    let b = relocate_block(&source, 0x1000, 0x2000).unwrap();
    assert_eq!(source, b.bytes);
    assert_eq!(target(&b.bytes, 0x2000), 0x2008);
    assert_eq!(target(&b.bytes[8..], 0x2008), 0x2000);
    let source = bytes(&[0x14000001]);
    let b = relocate_block(&source, 0x1000, 0x2000).unwrap();
    assert_eq!(target(&b.bytes, 0x2000), 0x1004);
}
#[test]
fn conditional_compare_and_test_relax() {
    for w in [0x54000040, 0x34000040, 0x36000040] {
        let source = bytes(&[w]);
        let b = relocate_block(&source, 0x1000, 0x200000).unwrap();
        assert_eq!(b.bytes.len(), 8);
        assert_eq!(target(&b.bytes, 0x200000), 0x200008);
        assert_eq!(target(&b.bytes[4..], 0x200004), 0x1008);
    }
}
#[test]
fn cascade() {
    let mut words = vec![0xd503201f; 8192];
    words[0] = 0x3603ffe0;
    words[1] = 0x547fffe0;
    let b = relocate_block(&bytes(&words), 0x1000, 0x400000).unwrap();
    assert_eq!(b.bytes.len(), words.len() * 4 + 8);
    assert_eq!(b.offsets[1], (4, 8));
    assert_eq!(
        target(&b.bytes[4..], 0x400004),
        0x400000 + b.offsets[8191].1 as u64
    );
}
#[test]
fn data_and_pages_keep_targets() {
    for w in [0x10000000, 0x90000000, 0x58000000] {
        let r = address_references(w, 0x1000).unwrap();
        assert!(!r.is_empty());
        assert_ne!(r[0].kind, AddressReferenceKind::Branch);
        assert!(!r[0].bits.is_empty());
        let moved = relocate(w, 0x1000, 0x2000).unwrap();
        assert_eq!(
            address_references(moved, 0x2000).unwrap()[0].target,
            r[0].target
        );
    }
}
#[test]
fn errors_and_transactionality() {
    let mut out = [0xcc; 4];
    assert_eq!(
        relocate_into(0x14000000, 0x1000, 0x100000000, &mut out),
        Err(RelocateError::OutOfRange)
    );
    assert_eq!(out, [0xcc; 4]);
    assert_eq!(
        relocate_block(&bytes(&[0x94000001]), 0x1000, 0x2000),
        Err(RelocateError::PositionDiscovery)
    );
    assert_eq!(
        relocate_block(&[0], 0x1000, 0x2000),
        Err(RelocateError::Truncated)
    );
    assert_eq!(
        relocate_block(&bytes(&[0xd503201f]), u64::MAX - 3, 0x2000),
        Err(RelocateError::AddressOverflow)
    );
    assert_eq!(
        relocate_block(&bytes(&[0xd503201f]), 0x1000, u64::MAX - 3),
        Err(RelocateError::AddressOverflow)
    );
    assert_eq!(
        relocate_block(&bytes(&[0x54000040]), 0x1000, 0x20000000),
        Err(RelocateError::OutOfRange)
    );
    let mut out = [0xcc; 4];
    assert_eq!(
        relocate_block_into(&bytes(&[0x54000040]), 0x1000, 0x200000, &mut out),
        Err(RelocateError::BufferTooSmall)
    );
    assert_eq!(out, [0xcc; 4]);
}

#[test]
fn exact_instruction_address_overflow_is_transactional() {
    let mut out = [0xcc; 4];
    assert_eq!(
        relocate_into(0xd503201f, u64::MAX - 3, 0x2000, &mut out),
        Err(RelocateError::AddressOverflow)
    );
    assert_eq!(out, [0xcc; 4]);
}

#[test]
fn bc_conditional_internal_targets_are_code() {
    for words in [[0x54000030, 0xd503201f], [0xd503201f, 0x54fffff0]] {
        let source = bytes(&words);
        let index = if words[0] == 0xd503201f { 4 } else { 0 };
        assert_eq!(address_references(words[index / 4], 0x1000 + index as u64).unwrap()[0].kind, AddressReferenceKind::Branch);
        let b = relocate_block(&source, 0x1000, 0x2000).unwrap();
        assert_eq!(b.bytes, source);
        assert_eq!(target(&b.bytes[index..], 0x2000 + index as u64), if index == 0 { 0x2004 } else { 0x2000 });
    }
    let mut output = [0xcc; 16];
    assert_eq!(relocate_block_into(&bytes(&[0x54000050]), 0x1000, 0x200000, &mut output), Err(RelocateError::OutOfRange));
    assert_eq!(output, [0xcc; 16]);
}
