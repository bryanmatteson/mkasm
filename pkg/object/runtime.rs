//! Complete-program assembly through an explicit target toolchain. The target
//! assembler owns ABI relocations, pseudo expansion, pools and relaxation.
use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, path::PathBuf, process::Command};
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub executable: PathBuf,
    pub kind: String,
    pub triple: String,
    pub cpu: String,
    pub features: Vec<String>,
    pub arguments: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub flags: u64,
    pub size: u64,
    pub kind: u32,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub section: u32,
    pub info: u8,
    pub other: u8,
    pub table: u32,
    pub index: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub section: String,
    pub section_index: u32,
    pub offset: u64,
    pub kind: u32,
    pub symbol_index: u32,
    pub addend: i64,
    pub has_addend: bool,
    pub symbol_table: u32,
    pub original_symbol_index: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub format: String,
    pub machine: u16,
    pub class: u8,
    pub byte_order: String,
    pub elf_type: u16,
    pub flags: u32,
    pub data: Vec<u8>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub diagnostics: String,
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temporary() -> Result<Temporary, String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..100 {
        let p = std::env::temp_dir().join(format!(
            "mkasm-object-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&p) {
            Ok(()) => return Ok(Temporary(p)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("cannot create temporary assembly directory".into())
}
pub fn assemble(source: &str, options: &Options) -> Result<Object, String> {
    if options.executable.as_os_str().is_empty() {
        return Err("explicit assembler executable required".into());
    }
    let dir = temporary()?;
    let input = dir.0.join("input.s");
    let output = dir.0.join("output.o");
    fs::write(&input, source).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&options.executable);
    match options.kind.as_str() {
        "" | "llvm" => {
            if options.triple.is_empty() {
                return Err("LLVM target triple required".into());
            }
            cmd.arg("-filetype=obj")
                .arg(format!("-triple={}", options.triple));
            if !options.cpu.is_empty() {
                cmd.arg(format!("-mcpu={}", options.cpu));
            }
            if !options.features.is_empty() {
                cmd.arg(format!("-mattr={}", options.features.join(",")));
            }
            cmd.args(&options.arguments)
                .arg("-o")
                .arg(&output)
                .arg(&input);
        }
        "gnu" => {
            if !options.triple.is_empty() || !options.cpu.is_empty() || !options.features.is_empty()
            {
                return Err("GNU target options must be explicit arguments".into());
            }
            cmd.args(&options.arguments)
                .arg("-o")
                .arg(&output)
                .arg(&input);
        }
        "command" => {
            if !options.triple.is_empty() || !options.cpu.is_empty() || !options.features.is_empty()
            {
                return Err("command target options belong in arguments".into());
            }
            let (mut has_in, mut has_out) = (false, false);
            for arg in &options.arguments {
                has_in |= arg.contains("{input}");
                has_out |= arg.contains("{output}");
                cmd.arg(
                    arg.replace("{input}", &input.to_string_lossy())
                        .replace("{output}", &output.to_string_lossy()),
                );
            }
            if !has_in || !has_out {
                return Err("command requires {input} and {output}".into());
            }
        }
        _ => return Err("unknown assembler kind".into()),
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        return Err(format!(
            "assembler failed ({}): {}",
            out.status, diagnostics
        ));
    }
    let bytes =
        fs::read(output).map_err(|e| format!("assembler did not produce an object: {}", e))?;
    if bytes.is_empty() {
        return Err("empty object".into());
    }
    let mut object = parse(&bytes)?;
    object.diagnostics = diagnostics;
    Ok(object)
}
fn span(b: &[u8], p: u64, n: u64) -> Result<&[u8], String> {
    let end = p.checked_add(n).ok_or("object range overflow")?;
    let start = usize::try_from(p).map_err(|_| "object offset overflow")?;
    let end = usize::try_from(end).map_err(|_| "object size overflow")?;
    b.get(start..end).ok_or_else(|| "truncated object".into())
}
fn integer(b: &[u8], p: u64, n: u64, le: bool) -> Result<u64, String> {
    let a = span(b, p, n)?;
    let mut out = 0;
    for i in 0..a.len() {
        out |= (a[i] as u64) << ((if le { i } else { a.len() - i - 1 }) * 8);
    }
    Ok(out)
}
fn string(b: &[u8], p: u64) -> Result<String, String> {
    let a = b
        .get(usize::try_from(p).map_err(|_| "string offset overflow")?..)
        .ok_or("invalid string offset")?;
    let n = a
        .iter()
        .position(|x| *x == 0)
        .ok_or("unterminated object string")?;
    Ok(String::from_utf8_lossy(&a[..n]).into_owned())
}
/// Parse ELF identities and relocation records. Other vendor formats retain
/// their complete bytes without guessing their internal representation.
pub fn parse(data: &[u8]) -> Result<Object, String> {
    let mut out = Object {
        format: "vendor".into(),
        machine: 0,
        class: 0,
        byte_order: String::new(),
        elf_type: 0,
        flags: 0,
        data: data.to_vec(),
        sections: vec![],
        symbols: vec![],
        relocations: vec![],
        diagnostics: String::new(),
    };
    if !data.starts_with(b"\x7fELF") {
        return Ok(out);
    }
    span(data, 0, 16)?;
    let class = data[4];
    let le = match data[5] {
        1 => true,
        2 => false,
        _ => return Err("invalid ELF byte order".into()),
    };
    let word = match class {
        1 => 4,
        2 => 8,
        _ => return Err("invalid ELF class".into()),
    };
    span(data, 0, if word == 8 { 64 } else { 52 })?;
    let get = |p, n| integer(data, p, n, le);
    if data[6] != 1 || get(20, 4)? != 1 {
        return Err("invalid ELF version".into());
    }
    out.format = "ELF".into();
    out.machine = get(18, 2)? as u16;
    out.class = class;
    out.elf_type = get(16, 2)? as u16;
    out.flags = get(if word == 8 { 48 } else { 36 }, 4)? as u32;
    out.byte_order = if le { "little" } else { "big" }.into();
    let (shoff, entry, count, names) = if word == 8 {
        (get(40, 8)?, get(58, 2)?, get(60, 2)?, get(62, 2)?)
    } else {
        (get(32, 4)?, get(46, 2)?, get(48, 2)?, get(50, 2)?)
    };
    if shoff == 0 {
        if count != 0 || names != 0 {
            return Err("section references without a section table".into());
        }
        return Ok(out);
    }
    let need = if word == 8 { 64 } else { 40 };
    if entry < need {
        return Err("invalid ELF section width".into());
    }
    let header = |i: u64| -> Result<&[u8], String> {
        span(
            data,
            shoff
                .checked_add(i.checked_mul(entry).ok_or("ELF section overflow")?)
                .ok_or("ELF section overflow")?,
            entry,
        )
    };
    let zero = header(0)?;
    let count = if count == 0 {
        let extended = integer(zero, if word == 8 { 32 } else { 20 }, word, le)?;
        if extended < 0xff00 {
            return Err("invalid extended section count".into());
        }
        extended
    } else {
        count
    };
    let names = if names == 0xffff {
        integer(zero, if word == 8 { 40 } else { 24 }, 4, le)?
    } else {
        names
    };
    span(
        data,
        shoff,
        count.checked_mul(entry).ok_or("ELF section overflow")?,
    )?;
    if names >= count {
        return Err("invalid section-name table".into());
    }
    let section = |i: u64| -> Result<(u32, u64, u64, u64, u32, u32), String> {
        let h = header(i)?;
        let r = |p, n| integer(h, p, n, le);
        Ok((
            r(4, 4)? as u32,
            r(if word == 8 { 24 } else { 16 }, word)?,
            r(if word == 8 { 32 } else { 20 }, word)?,
            r(8, word)?,
            r(if word == 8 { 40 } else { 24 }, 4)? as u32,
            r(if word == 8 { 44 } else { 28 }, 4)? as u32,
        ))
    };
    let name_data = if names == 0 {
        &[][..]
    } else {
        let (kind, p, n, _, _, _) = section(names)?;
        if kind != 3 {
            return Err("invalid section-name table type".into());
        }
        span(data, p, n)?
    };
    for i in 0..count {
        let h = header(i)?;
        let (kind, p, n, flags, _, _) = section(i)?;
        let name_offset = integer(h, 0, 4, le)?;
        let name = if names == 0 {
            if name_offset != 0 {
                return Err("section name without string table".into());
            }
            String::new()
        } else {
            string(name_data, name_offset)?
        };
        let address = integer(h, if word == 8 { 16 } else { 12 }, word, le)?;
        let bytes = if kind == 8 || kind == 0 {
            vec![]
        } else {
            span(data, p, n)?.to_vec()
        };
        out.sections.push(Section {
            name,
            address,
            flags,
            size: n,
            kind,
            data: bytes,
        });
    }
    let mut tables = std::collections::BTreeMap::new();
    for i in 0..count {
        let (kind, p, n, _, link, _) = section(i)?;
        if kind != 2 && kind != 11 {
            continue;
        }
        if link as u64 >= count {
            return Err("invalid symbol string table".into());
        }
        let (st, sp, sn, _, _, _) = section(link as u64)?;
        if st != 3 {
            return Err("invalid symbol string table type".into());
        }
        let strings = span(data, sp, sn)?;
        let width = if word == 8 { 24 } else { 16 };
        let entsize = integer(header(i)?, if word == 8 { 56 } else { 36 }, word, le)?;
        if entsize != width || n % width != 0 {
            return Err("invalid symbol table width".into());
        }
        let base = u32::try_from(out.symbols.len()).map_err(|_| "too many symbols")?;
        let length = u32::try_from(n / width).map_err(|_| "too many symbols")?;
        base.checked_add(length).ok_or("too many symbols")?;
        tables.insert(i as u32, (base, length));
        let mut extended = None;
        for xi in 0..count {
            let (xk, xp, xn, _, xl, _) = section(xi)?;
            if xk == 18 && xl as u64 == i {
                if extended.is_some() || xn != n / width * 4 {
                    return Err("invalid extended symbol section indices".into());
                }
                extended = Some(span(data, xp, xn)?);
            }
        }
        for j in 0..n / width {
            let h = span(data, p + j * width, width)?;
            let r = |p, n| integer(h, p, n, le);
            let name = string(strings, r(0, 4)?)?;
            let (value, size, info, other, mut section) = if word == 8 {
                (
                    r(8, 8)?,
                    r(16, 8)?,
                    r(4, 1)? as u8,
                    r(5, 1)? as u8,
                    r(6, 2)? as u32,
                )
            } else {
                (
                    r(4, 4)?,
                    r(8, 4)?,
                    r(12, 1)? as u8,
                    r(13, 1)? as u8,
                    r(14, 2)? as u32,
                )
            };
            if section == 0xffff {
                section = integer(
                    extended.ok_or("missing extended symbol section indices")?,
                    j * 4,
                    4,
                    le,
                )? as u32;
                if section as u64 >= count {
                    return Err("invalid extended symbol section".into());
                }
            } else if section < 0xff00 && section as u64 >= count {
                return Err("invalid symbol section".into());
            }
            out.symbols.push(Symbol {
                name,
                value,
                size,
                info,
                other,
                section,
                table: i as u32,
                index: j as u32,
            });
        }
    }
    for i in 0..count {
        let (kind, p, n, _, link, info) = section(i)?;
        if kind != 4 && kind != 9 {
            continue;
        }
        let &(base, length) = tables.get(&link).ok_or("invalid relocation symbol table")?;
        if info as u64 >= count {
            return Err("invalid relocation target section".into());
        }
        let has_addend = kind == 4;
        let width = word * (if has_addend { 3 } else { 2 });
        if integer(header(i)?, if word == 8 { 56 } else { 36 }, word, le)? != width
            || n % width != 0
        {
            return Err("invalid relocation width".into());
        }
        for j in 0..n / width {
            let h = span(data, p + j * width, width)?;
            let r = |p, n| integer(h, p, n, le);
            let offset = r(0, word)?;
            let value = r(word, word)?;
            let (mut original_symbol_index, mut kind) = if word == 8 {
                ((value >> 32) as u32, value as u32)
            } else {
                ((value >> 8) as u32, (value & 255) as u32)
            };
            if word == 8 && out.machine == 8 && le {
                original_symbol_index = integer(h, 8, 4, true)? as u32;
                kind = integer(h, 12, 4, false)? as u32;
            }
            if original_symbol_index >= length {
                return Err("relocation symbol outside linked table".into());
            }
            let symbol_index = base + original_symbol_index;
            let addend = if has_addend {
                let v = r(2 * word, word)?;
                if word == 4 {
                    v as i32 as i64
                } else {
                    v as i64
                }
            } else {
                0
            };
            let section = out.sections[info as usize].name.clone();
            out.relocations.push(Relocation {
                section,
                section_index: info,
                offset,
                kind,
                symbol_index,
                addend,
                has_addend,
                symbol_table: link,
                original_symbol_index,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod program_tests {
    use super::*;
    #[test]
    fn symbol_table_identity_and_bounds() {
        let bytes = include_bytes!("object-fixture.elf");
        let object = parse(bytes).unwrap();
        assert_eq!(object.data, bytes);
        assert_eq!(object.symbols.len(), 4);
        assert_eq!(object.relocations.len(), 2);
        assert_eq!(object.class, 2);
        assert_eq!(object.byte_order, "little");
        assert_eq!(object.sections[2].size, 0x20000000);
        assert!(object.sections[2].data.is_empty());
        for (i, name) in ["static", "dynamic"].iter().enumerate() {
            let relocation = &object.relocations[i];
            let symbol = &object.symbols[relocation.symbol_index as usize];
            assert_eq!(symbol.name, *name);
            assert_eq!(symbol.table, (4 + i) as u32);
            assert_eq!(symbol.index, 1);
            assert_eq!(symbol.section, 1);
            assert_eq!(relocation.symbol_table, symbol.table);
            assert_eq!(relocation.original_symbol_index, 1);
            assert_eq!(relocation.section_index, 1);
        }
        assert_eq!(object.relocations[1].addend, -4);
        for (at, value) in [
            (64 + 6 * 64 + 40, 3u32),
            (64 + 6 * 64 + 44, 99),
            (64 + 4 * 64 + 40, 1),
            (64 + 4 * 64 + 56, 16),
        ] {
            let mut changed = bytes.to_vec();
            changed[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(parse(&changed).is_err());
        }
        let offset = u64::from_le_bytes(
            bytes[64 + 6 * 64 + 24..64 + 6 * 64 + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let mut changed = bytes.to_vec();
        changed[offset + 8..offset + 16].copy_from_slice(&((9u64 << 32) | 1).to_le_bytes());
        assert!(parse(&changed).is_err());
    }
    #[test]
    fn section_identity_and_header_validation() {
        let bytes = include_bytes!("object-fixture.elf");
        let mut changed = bytes.to_vec();
        let name = changed[64 + 64..64 + 64 + 4].to_vec();
        changed[64 + 2 * 64..64 + 2 * 64 + 4].copy_from_slice(&name);
        changed[64 + 7 * 64 + 44..64 + 7 * 64 + 48].copy_from_slice(&2u32.to_le_bytes());
        let object = parse(&changed).unwrap();
        assert_eq!(object.relocations[0].section, object.relocations[1].section);
        assert_eq!(object.relocations[0].section_index, 1);
        assert_eq!(object.relocations[1].section_index, 2);
        for (at, replacement) in [
            (6, vec![0]),
            (20, 2u32.to_le_bytes().to_vec()),
            (40, 0u64.to_le_bytes().to_vec()),
            (60, 0u16.to_le_bytes().to_vec()),
        ] {
            let mut changed = bytes.to_vec();
            changed[at..at + replacement.len()].copy_from_slice(&replacement);
            assert!(parse(&changed).is_err());
        }
        assert!(parse(&bytes[..63]).is_err());
    }
    #[test]
    fn native_hexagon_pools_and_relaxation() {
        let Ok(mc) = std::env::var("MKASM_LLVM_MC") else {
            return;
        };
        let object = assemble(
            include_str!("object-hexagon.s"),
            &Options {
                executable: mc.into(),
                triple: "hexagon".into(),
                cpu: "hexagonv60".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            (object.machine, object.class, object.byte_order.as_str()),
            (164, 1, "little")
        );
        assert_eq!(object.elf_type, 1);
        assert_eq!(object.flags, 0x60);
        let (text_index, text) = object
            .sections
            .iter()
            .enumerate()
            .find(|(_, s)| s.name == ".text")
            .unwrap();
        let pool32 = object
            .sections
            .iter()
            .find(|s| s.name == ".gnu.linkonce.l4.CONST_12345678")
            .unwrap();
        let pool64 = object
            .sections
            .iter()
            .find(|s| s.name == ".gnu.linkonce.l8.CONST_1122334455667788")
            .unwrap();
        assert_eq!(pool32.data, 0x12345678u32.to_le_bytes());
        assert_eq!(pool64.data, 0x1122334455667788u64.to_le_bytes());
        assert_eq!(text.data.len(), 28);
        assert_eq!(
            &text.data[12..],
            &[0, 0x40, 0, 0, 0, 0x41, 0, 0x5d, 0, 0x40, 0, 0, 0, 0xc1, 0x20, 0x5d]
        );
        assert_eq!(object.relocations.len(), 7);
        assert_eq!(
            object.relocations[0].symbol_index,
            object.relocations[1].symbol_index
        );
        for r in &object.relocations {
            assert_eq!(r.section_index, text_index as u32);
            assert!(r.has_addend);
            assert_eq!(
                r.symbol_table,
                object.symbols[r.symbol_index as usize].table
            );
        }
        for (i, name) in ["external_a", "external_a", "external_b", "external_b"]
            .iter()
            .enumerate()
        {
            let r = &object.relocations[i + 3];
            assert_eq!(object.symbols[r.symbol_index as usize].name, *name);
            assert_eq!(r.offset, 12 + 4 * i as u64);
            assert_eq!(r.addend, 4 * i as i64);
            assert_eq!(r.kind, if i % 2 == 0 { 16 } else { 19 });
        }
    }
    #[test]
    fn native_bpf_btf_and_byte_order() {
        let Ok(mc) = std::env::var("MKASM_LLVM_MC") else {
            return;
        };
        for (triple, order) in [
            ("bpfel-unknown-none", "little"),
            ("bpfeb-unknown-none", "big"),
        ] {
            let object = assemble(
                include_str!("object-bpf.s"),
                &Options {
                    executable: mc.clone().into(),
                    triple: triple.into(),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(
                (object.machine, object.class, object.byte_order.as_str()),
                (247, 2, order)
            );
            let (text_index, text) = object
                .sections
                .iter()
                .enumerate()
                .find(|(_, s)| s.name == ".text")
                .unwrap();
            let btf = object.sections.iter().find(|s| s.name == ".BTF").unwrap();
            let (ext_index, ext) = object
                .sections
                .iter()
                .enumerate()
                .find(|(_, s)| s.name == ".BTF.ext")
                .unwrap();
            assert_eq!(
                (text.data.len(), btf.data.len(), ext.data.len()),
                (16, 115, 80)
            );
            for (section, header_len) in [(btf, 24), (ext, 32)] {
                let magic = if order == "little" {
                    u16::from_le_bytes(section.data[..2].try_into().unwrap())
                } else {
                    u16::from_be_bytes(section.data[..2].try_into().unwrap())
                };
                let len = if order == "little" {
                    u32::from_le_bytes(section.data[4..8].try_into().unwrap())
                } else {
                    u32::from_be_bytes(section.data[4..8].try_into().unwrap())
                };
                assert_eq!(magic, 0xeb9f);
                assert_eq!(len, header_len);
            }
            assert!(btf.data.windows(12).any(|s| s == b"entry\0.text\0"));
            assert!(object.symbols.iter().any(|s| s.name == "entry"
                && s.other & 3 == 2
                && s.section == text_index as u32
                && s.size == 16));
            assert!(object
                .relocations
                .iter()
                .any(|r| r.section_index == text_index as u32
                    && r.kind == 10
                    && object.symbols[r.symbol_index as usize].name == "external"));
            let rels = object
                .relocations
                .iter()
                .filter(|r| r.section_index == ext_index as u32)
                .collect::<Vec<_>>();
            assert_eq!(rels.len(), 2);
            for r in rels {
                assert_eq!(r.kind, 4);
                assert!(!r.has_addend);
                assert_eq!(
                    object.symbols[r.symbol_index as usize].section,
                    text_index as u32
                );
            }
        }
    }
    #[test]
    fn native_compressed_sections_retain_stored_bytes() {
        let Ok(mc) = std::env::var("MKASM_LLVM_MC") else {
            return;
        };
        let object = assemble(
            ".text\nnop\n.section .debug_info,\"\",@progbits\n.rept 256\n.long 0x12345678\n.endr\n",
            &Options {
                executable: mc.into(),
                triple: "x86_64-unknown-linux-gnu".into(),
                arguments: vec!["--compress-debug-sections=zlib".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let (index, section) = object
            .sections
            .iter()
            .enumerate()
            .find(|(_, s)| s.name == ".debug_info")
            .unwrap();
        let shoff = u64::from_le_bytes(object.data[40..48].try_into().unwrap()) as usize;
        let header = &object.data[shoff + index * 64..shoff + (index + 1) * 64];
        let start = u64::from_le_bytes(header[24..32].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(header[32..40].try_into().unwrap()) as usize;
        assert_ne!(section.flags & 0x800, 0);
        assert_eq!(section.size, size as u64);
        assert_eq!(section.data, object.data[start..start + size]);
        assert!(size < 1024);
    }
    #[test]
    fn real_abi_objects() {
        let Ok(mc) = std::env::var("MKASM_LLVM_MC") else {
            return;
        };
        for (triple, text, machine, relocations) in [
            (
                "aarch64-unknown-linux-gnu",
                ".text\nadrp x0,external\nadd x0,x0,:lo12:external\nbl external\n",
                183,
                3,
            ),
            (
                "x86_64-unknown-linux-gnu",
                ".text\ncall external\nlea external(%rip),%rax\n",
                62,
                2,
            ),
            (
                "powerpc64le-unknown-linux-gnu",
                ".text\naddis 3,2,target@tprel@ha\naddi 3,3,target@tprel@l\n",
                21,
                2,
            ),
            (
                "sparcv9-unknown-linux-gnu",
                ".text\nsethi %hi(external),%g1\nor %g1,%lo(external),%g1\ncall external\nnop\n",
                43,
                3,
            ),
            (
                "riscv64-unknown-linux-gnu",
                ".text\nla a0,external\ncall external\n",
                243,
                2,
            ),
            (
                "bpfel-unknown-none",
                ".text\nr1 = external ll\nexit\n",
                247,
                1,
            ),
        ] {
            let object = assemble(
                text,
                &Options {
                    executable: mc.clone().into(),
                    triple: triple.into(),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(object.machine, machine);
            assert!(object.relocations.len() >= relocations);
            assert!(object
                .symbols
                .iter()
                .any(|s| s.name == "external" || s.name == "target"));
            assert_eq!(parse(&object.data).unwrap().relocations, object.relocations);
        }
    }
}
