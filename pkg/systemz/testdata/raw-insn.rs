use systemz::*;

#[test]
fn raw_directives_preserve_unknown_bytes() {
    let (index, entry) = catalog_entry("InsnE").expect("complete raw E format");
    assert!(entry.assembly_only);
    let values = representative(index).unwrap();
    let bytes = encode(entry.id, &values).unwrap();
    assert_eq!(bytes, [0x00, 0x00]);
    assert_eq!(decode(&bytes).unwrap_err(), Error::Unknown);
    assert!(assemble(".insn e,0").unwrap().contains(&bytes));
    let template = Template::parse(".insn e,$bits").unwrap();
    let (_, bindings) = template.matches(&bytes).unwrap();
    assert_eq!(bindings, [("bits".to_owned(), 0)]);
    for raw in [0i128, 1, 0x1812, 0xffff] {
        let expected = (raw as u16).to_be_bytes().to_vec();
        assert_eq!(encode("InsnE", &[raw]).unwrap(), expected);
        assert!(template
            .encode(&[("bits", raw)])
            .unwrap()
            .contains(&expected));
    }
}

#[test]
fn raw_rr_can_decode_as_a_real_instruction() {
    let expected = vec![0x18, 0x12];
    assert!(assemble(".insn rr,0x1800,%r1,%r2")
        .unwrap()
        .contains(&expected));
    let decoded = decode(&expected).unwrap();
    assert!(!decoded.encoding().assembly_only);
    assert_eq!(decoded.encoding().id, "LR");
    assert_eq!(decoded.format(0), "lr %r1, %r2");
    assert_eq!(
        encode(
            decoded.encoding().id,
            &decoded.values[..decoded.encoding().operands.len()]
        )
        .unwrap(),
        expected
    );
}

#[test]
fn all_raw_source_formats_and_address_variants_remain_available() {
    let mut count = 0;
    let mut source_formats = 0;
    for (index, entry) in ENCODINGS.iter().enumerate() {
        if !entry.id.starts_with("Insn") {
            continue;
        }
        if !entry.id.contains("_memory_") {
            source_formats += 1;
        }
        count += 1;
        assert!(entry.assembly_only, "{}", entry.id);
        let values = representative(index).unwrap();
        let bytes = encode(entry.id, &values).unwrap();
        let mut operands = [0; MAX_OPERANDS];
        operands[..values.len()].copy_from_slice(&values);
        let raw = Decoded {
            encoding_index: index,
            values: operands,
            length: bytes.len(),
        };
        let text = raw.format(0x1000);
        assert!(
            assemble_at(&text, 0x1000).unwrap().contains(&bytes),
            "{}: {}",
            entry.id,
            text
        );
        let template = Template::parse_at(&text, 0x1000).unwrap();
        assert!(template.matches(&bytes).is_some(), "{}", entry.id);
        assert!(
            template.encode(&[]).unwrap().contains(&bytes),
            "{}",
            entry.id
        );
    }
    assert_eq!(source_formats, 31);
    assert_eq!(count, 63);
}
