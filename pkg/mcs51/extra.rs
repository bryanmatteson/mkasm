/// PSW.RS1:RS0 select the physical internal-RAM bank for encoded R0..R7.
pub fn register_address(reg: u8, psw: u8) -> Option<u8> {
    (reg < 8).then_some(((psw >> 3) & 3) * 8 + reg)
}
pub fn resolve_direct(address: u8) -> (&'static str, u8) {
    (if address < 128 { "INTMEM" } else { "SFR" }, address)
}
pub fn resolve_bit(address: u8) -> (&'static str, u8, u8) {
    if address < 128 {
        ("INTMEM", 0x20 + address / 8, address & 7)
    } else {
        ("SFR", address & 0xf8, address & 7)
    }
}
pub fn external_indirect_address(ri_value: u8, p2: u8) -> u16 {
    u16::from(p2) << 8 | u16::from(ri_value)
}
pub fn computed_code_address(
    pc: u32,
    length: u8,
    acc: u8,
    dptr: u32,
    use_pc: bool,
    flat390: bool,
) -> u32 {
    let base = if use_pc {
        pc.wrapping_add(u32::from(length))
    } else {
        dptr
    };
    base.wrapping_add(u32::from(acc)) & if flat390 { 0xffffff } else { 0xffff }
}
fn mcs51_text(text: &str) -> String {
    let mut out = String::new();
    let mut token = String::new();
    let flush = |s: &mut String, out: &mut String| {
        let bytes = s.as_bytes();
        if bytes.first().is_some_and(u8::is_ascii_digit) && bytes.len() > 1 {
            let suffix = bytes[bytes.len() - 1].to_ascii_lowercase();
            let digits = &s[..s.len() - 1];
            if suffix == b'h' && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.push_str("0x");
                out.push_str(digits);
                s.clear();
                return;
            }
            if suffix == b'b' && digits.bytes().all(|b| b == b'0' || b == b'1') {
                out.push_str("0b");
                out.push_str(digits);
                s.clear();
                return;
            }
        }
        out.push_str(s);
        s.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            token.push(c)
        } else {
            flush(&mut token, &mut out);
            out.push(c)
        }
    }
    flush(&mut token, &mut out);
    out
}
#[cfg(test)]
mod mcs_helpers {
    use super::*;
    #[test]
    fn banks_bits_and_addresses() {
        for bank in 0..4 {
            for r in 0..8 {
                assert_eq!(register_address(r, bank << 3), Some(bank * 8 + r));
            }
        }
        assert_eq!(register_address(8, 0), None);
        assert_eq!(resolve_bit(0), ("INTMEM", 0x20, 0));
        assert_eq!(resolve_bit(0xff), ("SFR", 0xf8, 7));
        assert_eq!(external_indirect_address(0x34, 0x12), 0x1234);
        assert_eq!(computed_code_address(0xffff, 1, 1, 0, true, false), 1);
        assert_eq!(computed_code_address(0, 1, 1, 0xffffff, false, true), 0);
        assert!(assemble("mov a,#0ffh").unwrap().contains(&vec![0x74, 0xff]));
        assert!(assemble("mov a,#101b").unwrap().contains(&vec![0x74, 5]));
    }
}
