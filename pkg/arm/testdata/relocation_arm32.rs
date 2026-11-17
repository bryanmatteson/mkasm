use arm32::*;
fn target(b: &[u8], ip: u64, mode: Mode, endian: Endian) -> u32 {
    decode(b, mode, endian)
        .unwrap()
        .address_references(ip)
        .unwrap()[0]
        .target
}
#[test]
fn a32_internal_external_and_big_endian() {
    for endian in [Endian::Little, Endian::Big] {
        let words = [0xea000000u32, 0xe1a00000, 0xeafffffc];
        let source: Vec<u8> = words
            .into_iter()
            .flat_map(|w| match endian {
                Endian::Little => w.to_le_bytes(),
                Endian::Big => w.to_be_bytes(),
            })
            .collect();
        let b = relocate_block(&source, 0x1000, 0x2000, Mode::Arm, endian).unwrap();
        assert_eq!(source, b.bytes);
        assert_eq!(target(&b.bytes, 0x2000, Mode::Arm, endian), 0x2008);
        assert_eq!(target(&b.bytes[8..], 0x2008, Mode::Arm, endian), 0x2000);
    }
}
#[test]
fn thumb_short_external_relaxation() {
    for source in [&[0x3f, 0xe0][..], &[0x3f, 0xd1][..]] {
        let original = target(source, 0x1000, Mode::Thumb, Endian::Little);
        let b = relocate_block(source, 0x1000, 0x10000, Mode::Thumb, Endian::Little).unwrap();
        assert_eq!(b.bytes.len(), 4);
        assert_eq!(
            target(&b.bytes, 0x10000, Mode::Thumb, Endian::Little),
            original
        );
    }
}
#[test]
fn thumb_internal_and_split_call() {
    let source = [0, 0xe0, 0, 0xbf, 0xfc, 0xe7];
    let b = relocate_block(&source, 0x1000, 0x2000, Mode::Thumb, Endian::Little).unwrap();
    assert_eq!(source.as_slice(), b.bytes);
    assert_eq!(
        target(&b.bytes, 0x2000, Mode::Thumb, Endian::Little),
        0x2004
    );
    assert_eq!(
        target(&b.bytes[4..], 0x2004, Mode::Thumb, Endian::Little),
        0x2000
    );
    let source = [0, 0xf0, 1, 0xf8];
    let mut out = [0; 4];
    relocate(
        &source,
        0x1000,
        0x2000,
        Mode::Thumb,
        Endian::Little,
        &mut out,
    )
    .unwrap();
    assert_eq!(
        target(&source, 0x1000, Mode::Thumb, Endian::Little),
        target(&out, 0x2000, Mode::Thumb, Endian::Little)
    );
}
#[test]
fn adr_and_literal() {
    for source in [&[0, 0xa0][..], &[0, 0x48][..]] {
        let original = target(source, 0x1000, Mode::Thumb, Endian::Little);
        let mut out = [0; 2];
        relocate(source, 0x1000, 0xffc, Mode::Thumb, Endian::Little, &mut out).unwrap();
        assert_eq!(target(&out, 0xffc, Mode::Thumb, Endian::Little), original);
    }
}
#[test]
fn failures_do_not_write() {
    let mut out = [0xcc; 4];
    assert_eq!(
        relocate(
            &[0, 0xf0, 0, 0xf8],
            0x1000,
            0x2000,
            Mode::Thumb,
            Endian::Little,
            &mut out
        ),
        Err(RelocateError::PositionDiscovery)
    );
    assert_eq!(out, [0xcc; 4]);
    assert_eq!(
        relocate_block(&[0, 0xf0], 0x1000, 0x2000, Mode::Thumb, Endian::Little),
        Err(RelocateError::Truncated)
    );
    assert_eq!(
        relocate_block(&[0, 0xbf], 0xffff_fffe, 0x2000, Mode::Thumb, Endian::Little),
        Err(RelocateError::AddressOverflow)
    );
    assert_eq!(
        relocate_block(&[8, 0xbf], 0x1000, 0x2000, Mode::Thumb, Endian::Little),
        Err(RelocateError::Unsupported)
    );
    let mut out = [0xcc; 2];
    assert_eq!(
        relocate_block_into(
            &[0x3f, 0xe0],
            0x1000,
            0x10000,
            Mode::Thumb,
            Endian::Little,
            &mut out
        ),
        Err(RelocateError::BufferTooSmall)
    );
    assert_eq!(out, [0xcc; 2]);
}
#[test]
fn thumb_growth_cascade_and_mid_instruction() {
    let mut source = vec![0; 2052];
    for p in source.chunks_exact_mut(2) {
        p.copy_from_slice(&[0, 0xbf]);
    }
    source[..4].copy_from_slice(&[0xff, 0xe3, 0x80, 0xd1]);
    let b = relocate_block(&source, 0x1000, 0x10000, Mode::Thumb, Endian::Little).unwrap();
    assert_eq!(b.bytes.len(), source.len() + 4);
    assert_eq!(b.offsets[1], (2, 4));
    assert_eq!(
        target(&b.bytes, 0x10000, Mode::Thumb, Endian::Little),
        0x10000 + b.offsets[1025].1 as u32
    );
    assert_eq!(
        target(&b.bytes[4..], 0x10004, Mode::Thumb, Endian::Little),
        0xf06
    );
    assert_eq!(
        relocate_block(
            &[0, 0xe0, 0, 0xf0, 1, 0xf8],
            0x1000,
            0x2000,
            Mode::Thumb,
            Endian::Little
        ),
        Err(RelocateError::MidInstructionTarget)
    );
}
#[test]
fn physical_bit_positions_follow_endian_and_halfwords() {
    let d = decode(&[0, 0xf0, 1, 0xf8], Mode::Thumb, Endian::Little).unwrap();
    let r = d.address_references(0x1000).unwrap().remove(0);
    let little = r.encoded_bits(4, Mode::Thumb, Endian::Little);
    let big = r.encoded_bits(4, Mode::Thumb, Endian::Big);
    assert!(little
        .iter()
        .any(|b| b.value_bit == 24 && b.instruction_bit == 10));
    assert!(big
        .iter()
        .any(|b| b.value_bit == 24 && b.instruction_bit == 2));
}

#[test]
fn pc_value_stores_are_not_silently_copied() {
    assert_eq!(
        relocate_block(
            &0xe580f000u32.to_le_bytes(),
            0x1000,
            0x2000,
            Mode::Arm,
            Endian::Little
        ),
        Err(RelocateError::Unsupported)
    );
    assert_eq!(
        relocate_block(&[0x78, 0x46], 0x1000, 0x2000, Mode::Thumb, Endian::Little),
        Err(RelocateError::Unsupported)
    );
}
