// MIT licensed managed-image reader. Schema data comes from ECMA-335 II.22.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
fn err(s: &str) -> Error {
    Error(format!("dotnet: {s}"))
}
fn span(b: &[u8], p: usize, n: usize) -> Result<&[u8]> {
    b.get(p..p.checked_add(n).ok_or_else(|| err("range overflow"))?)
        .ok_or_else(|| err("truncated or out-of-bounds data"))
}
fn u16(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(span(b, p, 2)?.try_into().unwrap()))
}
fn u32(b: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(span(b, p, 4)?.try_into().unwrap()))
}
fn u64(b: &[u8], p: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(span(b, p, 8)?.try_into().unwrap()))
}
struct Cursor<'a> {
    native: bool,
    b: &'a [u8],
    p: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let a = span(self.b, self.p, n)?;
        self.p += n;
        Ok(a)
    }
    fn uint(&mut self, n: usize) -> Result<u32> {
        let b = self.take(n)?;
        Ok(match n {
            1 => b[0] as u32,
            2 => u16::from_le_bytes(b.try_into().unwrap()) as u32,
            4 => u32::from_le_bytes(b.try_into().unwrap()),
            _ => return Err(err("integer width")),
        })
    }
    fn raw_compressed(&mut self) -> Result<(u32, u32)> {
        let a = self.uint(1)?;
        if a & 128 == 0 {
            return Ok((a, 7));
        }
        if a & 192 == 128 {
            return Ok(((a & 63) << 8 | self.uint(1)?, 14));
        }
        if a & 224 == 192 {
            let b = self.take(3)?;
            return Ok((
                (a & 31) << 24 | (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32,
                29,
            ));
        }
        Err(err("reserved compressed integer prefix"))
    }
    fn compressed(&mut self) -> Result<u32> {
        let (n, b) = self.raw_compressed()?;
        if !self.native && (b == 14 && n < 128 || b == 29 && n < 16384) {
            return Err(err("nonminimal compressed integer"));
        }
        Ok(n)
    }
    fn signed(&mut self) -> Result<i32> {
        let (n, b) = self.raw_compressed()?;
        let mut v = (n >> 1) as i32;
        if n & 1 != 0 {
            v |= -1 << (b - 1)
        }
        if b == 14 && (-64..=63).contains(&v) || b == 29 && (-8192..=8191).contains(&v) {
            return Err(err("nonminimal signed compressed integer"));
        }
        Ok(v)
    }
}
pub fn compressed_integer(b: &[u8]) -> Result<(u32, usize)> {
    let mut r = Cursor { native: false, b, p: 0 };
    let v = r.compressed()?;
    Ok((v, r.p))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Token(pub u32);
impl Token {
    pub fn table(self) -> u8 {
        (self.0 >> 24) as u8
    }
    pub fn rid(self) -> u32 {
        self.0 & 0xffffff
    }
}
impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}
pub fn decode_coded(kind: &str, n: u32) -> Result<Token> {
    let (bits, tables) = coded(kind).ok_or_else(|| err("unknown coded index"))?;
    if n == 0 {
        return Ok(Token(0));
    }
    let tag = (n & ((1 << bits) - 1)) as usize;
    let rid = n >> bits;
    let t = *tables
        .get(tag)
        .ok_or_else(|| err("reserved coded index tag"))?;
    if t < 0 || rid == 0 || rid > 0xffffff {
        return Err(err("invalid coded index"));
    }
    Ok(Token((t as u32) << 24 | rid))
}
#[derive(Debug, Clone)]
pub struct Stream<'a> {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub data: &'a [u8],
}
#[derive(Debug, Clone, Default)]
pub struct Table {
    pub name: &'static str,
    pub count: u32,
    pub row_size: usize,
    pub offset: usize,
    widths: Vec<usize>,
}
#[derive(Debug, Clone)]
pub struct PdbHeader {
    pub id: [u8; 20],
    pub entry_point: Token,
    pub referenced_tables: u64,
    pub rows: [u32; 64],
}
#[derive(Debug)]
pub struct Metadata<'a> {
    pub data: &'a [u8],
    pub version: String,
    pub streams: Vec<Stream<'a>>,
    pub tables: [Table; 64],
    pub heap_sizes: u8,
    pub valid: u64,
    pub sorted: u64,
    pub pdb: Option<PdbHeader>,
    table_data: &'a [u8],
    external: [u32; 64],
    owners: BTreeMap<Token, Token>,
    generics: BTreeMap<Token, Vec<GenericParameter>>,
    nested: BTreeMap<Token, Token>,
}
impl<'a> Metadata<'a> {
    fn empty()->Self{Self{data:&[],version:String::new(),streams:vec![],tables:std::array::from_fn(|_|Table::default()),heap_sizes:0,valid:0,sorted:0,pdb:None,table_data:&[],external:[0;64],owners:BTreeMap::new(),generics:BTreeMap::new(),nested:BTreeMap::new()}}
    pub fn parse(b: &'a [u8]) -> Result<Self> {
        if span(b, 0, 4)? != b"BSJB" {
            return Err(err("invalid metadata signature"));
        }
        let vl = u32(b, 12)? as usize;
        if vl == 0 || vl % 4 != 0 {
            return Err(err("invalid metadata version length"));
        }
        let v = span(b, 16, vl)?;
        let zero = v
            .iter()
            .position(|&v| v == 0)
            .ok_or_else(|| err("unterminated metadata version"))?;
        let version = String::from_utf8(v[..zero].to_vec()).map_err(|_| err("version UTF-8"))?;
        let mut r = Cursor { native: false, b, p: 16 + vl };
        r.uint(2)?;
        let count = r.uint(2)?;
        let mut streams = Vec::new();
        let mut names = BTreeSet::new();
        for _ in 0..count {
            let offset = r.uint(4)?;
            let size = r.uint(4)?;
            let start = r.p;
            let mut found = false;
            for _ in 0..32 {
                if r.uint(1)? == 0 {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(err("unterminated stream name"));
            }
            let name = String::from_utf8(b[start..r.p - 1].to_vec())
                .map_err(|_| err("stream name UTF-8"))?;
            if name.is_empty() || !names.insert(name.clone()) {
                return Err(err("empty/duplicate stream"));
            }
            r.p = (r.p + 3) & !3;
            let data = span(b, offset as usize, size as usize)?;
            streams.push(Stream {
                name,
                offset,
                size,
                data,
            })
        }
        let mut ranges = Vec::new();
        for s in &streams {
            if (s.offset as usize) < r.p {
                return Err(err("stream overlaps headers"));
            }
            if s.size != 0 {
                ranges.push((s.offset as u64, s.offset as u64 + s.size as u64));
            }
        }
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(err("overlapping streams"));
            }
        }
        let mut m = Self {
            data: b,
            version,
            streams,
            tables: std::array::from_fn(|_| Table::default()),
            heap_sizes: 0,
            valid: 0,
            sorted: 0,
            pdb: None,
            table_data: &[],
            external: [0; 64],
            owners: BTreeMap::new(),
            generics: BTreeMap::new(),
            nested: BTreeMap::new(),
        };
        if let Some(b) = m.stream("#Pdb") {
            span(b, 0, 32)?;
            let mut h = PdbHeader {
                id: b[..20].try_into().unwrap(),
                entry_point: Token(u32(b, 20)?),
                referenced_tables: u64(b, 24)?,
                rows: [0; 64],
            };
            let mut r = Cursor { native: false, b, p: 32 };
            for t in 0..64 {
                if h.referenced_tables & (1 << t) != 0 {
                    if t > 44 || schema(t).is_none() {
                        return Err(err("invalid portable PDB external table"));
                    }
                    let n = r.uint(4)?;
                    if n > 0xffffff {
                        return Err(err("external row count exceeds token limit"));
                    }
                    h.rows[t] = n;
                    m.external[t] = n
                }
            }
            if r.p != b.len() {
                return Err(err("trailing #Pdb header bytes"));
            }
            m.pdb = Some(h)
        }
        let td = m
            .stream("#~")
            .or_else(|| m.stream("#-"))
            .ok_or_else(|| err("missing tables stream"))?;
        span(td, 0, 24)?;
        m.table_data = td;
        m.heap_sizes = td[6];
        if m.heap_sizes & !0xe7 != 0 {
            return Err(err("reserved heap flags"));
        }
        m.valid = u64(td, 8)?;
        m.sorted = u64(td, 16)?;
        let mut r = Cursor { native: false, b: td, p: 24 };
        for t in 0..64 {
            if m.valid & (1 << t) == 0 {
                continue;
            }
            let (name, _) = schema(t).ok_or_else(|| err("unknown metadata table"))?;
            if m.pdb.is_some() && t < 48 {
                return Err(err("PDB has type system table"));
            }
            let n = r.uint(4)?;
            if n > 0xffffff {
                return Err(err("row count exceeds token limit"));
            }
            m.tables[t].name = name;
            m.tables[t].count = n
        }
        if m.heap_sizes & 64 != 0 {
            r.uint(4)?;
        }
        for t in 0..64 {
            if m.valid & (1 << t) == 0 {
                continue;
            }
            let (_, cols) = schema(t).unwrap();
            let widths: Vec<usize> = cols
                .iter()
                .map(|c| m.column_size(c.1))
                .collect::<Result<_>>()?;
            let row_size = widths.iter().sum::<usize>();
            m.tables[t].widths = widths;
            m.tables[t].row_size = row_size;
            m.tables[t].offset = r.p;
            r.take(
                (m.tables[t].count as usize)
                    .checked_mul(row_size)
                    .ok_or_else(|| err("table size overflow"))?,
            )?;
        }
        m.validate()?;
        if m.pdb.is_none() {
            for rid in 1..=m.tables[2].count {
                for target in [4, 6] {
                    let col = if target == 4 { 4 } else { 5 };
                    for item in m.range(2, rid, col, target)? {
                        if m.owners.insert(item, Token(2 << 24 | rid)).is_some() {
                            return Err(err("multiply owned member"));
                        }
                    }
                }
            }
            if m.owners.len() as u64 != m.tables[4].count as u64 + m.tables[6].count as u64 {
                return Err(err("orphan member rows"));
            }
        }
        let mut constraints: BTreeMap<u32, Vec<Token>> = BTreeMap::new();
        for rid in 1..=m.tables[44].count {
            let r = m.row(44, rid)?;
            constraints
                .entry(r[0])
                .or_default()
                .push(decode_coded("TypeDefOrRef", r[1])?)
        }
        for rid in 1..=m.tables[42].count {
            let r = m.row(42, rid)?;
            let owner = decode_coded("TypeOrMethodDef", r[2])?;
            let g = GenericParameter {
                token: Token(42 << 24 | rid),
                number: r[0],
                flags: r[1],
                name: m.string(r[3])?.to_string(),
                constraints: constraints.remove(&rid).unwrap_or_default(),
            };
            m.generics.entry(owner).or_default().push(g)
        }
        for rid in 1..=m.tables[41].count {
            let r = m.row(41, rid)?;
            m.nested
                .insert(Token(2 << 24 | r[0]), Token(2 << 24 | r[1]));
        }
        Ok(m)
    }
    pub fn stream(&self, name: &str) -> Option<&'a [u8]> {
        self.streams.iter().find(|s| s.name == name).map(|s| s.data)
    }
    fn row_count(&self, t: usize) -> u32 {
        self.tables[t].count.max(self.external[t])
    }
    fn pointer_table(&self, t: usize) -> usize {
        let p = match t {
            4 => 3,
            6 => 5,
            8 => 7,
            20 => 19,
            23 => 22,
            _ => return t,
        };
        if self.tables[p].count > 0 {
            p
        } else {
            t
        }
    }
    fn column_size(&self, k: &str) -> Result<usize> {
        match k {
            "u2" => return Ok(2),
            "u4" => return Ok(4),
            "string" | "guid" | "blob" => {
                return Ok(
                    if self.heap_sizes
                        & match k {
                            "string" => 1,
                            "guid" => 2,
                            _ => 4,
                        }
                        != 0
                    {
                        4
                    } else {
                        2
                    },
                )
            }
            _ => {}
        }
        if k.starts_with('t') || k.starts_with('l') {
            let mut t: usize = k[1..].parse().map_err(|_| err("table kind"))?;
            if k.starts_with('l') {
                t = self.pointer_table(t)
            }
            return Ok(if self.row_count(t) >= 65536 { 4 } else { 2 });
        }
        let (bits, tables) = coded(k).ok_or_else(|| err("coded kind"))?;
        Ok(
            if tables
                .iter()
                .any(|&t| t >= 0 && self.row_count(t as usize) >= (1 << (16 - bits)))
            {
                4
            } else {
                2
            },
        )
    }
    pub fn row(&self, t: u8, rid: u32) -> Result<Vec<u32>> {
        let table = self
            .tables
            .get(t as usize)
            .ok_or_else(|| err("table index"))?;
        if rid == 0 || rid > table.count {
            return Err(err("row out of range"));
        }
        let mut r = Cursor { native: false,
            b: self.table_data,
            p: table.offset + (rid as usize - 1) * table.row_size,
        };
        table.widths.iter().map(|&w| r.uint(w)).collect()
    }
    pub fn validate_token(&self, t: Token) -> Result<()> {
        if t.rid() == 0 {
            return Err(err("nil token"));
        }
        if t.table() == 0x70 {
            self.user_string(t.rid())?;
            return Ok(());
        }
        if t.table() >= 64
            || schema(t.table() as usize).is_none()
            || t.rid() > self.row_count(t.table() as usize)
        {
            return Err(err("out-of-range token"));
        }
        Ok(())
    }
    pub fn string(&self, index: u32) -> Result<&'a str> {
        if index == 0 {
            return Ok("");
        }
        let b = self
            .stream("#Strings")
            .ok_or_else(|| err("missing string heap"))?;
        let b = b.get(index as usize..).ok_or_else(|| err("string index"))?;
        let n = b
            .iter()
            .position(|&v| v == 0)
            .ok_or_else(|| err("unterminated string"))?;
        std::str::from_utf8(&b[..n]).map_err(|_| err("heap string UTF-8"))
    }
    pub fn blob(&self, index: u32) -> Result<&'a [u8]> {
        if index == 0 {
            return Ok(&[]);
        }
        let b = self
            .stream("#Blob")
            .ok_or_else(|| err("missing blob heap"))?;
        let mut r = Cursor { native: false,
            b,
            p: index as usize,
        };
        let n = r.compressed()?;
        r.take(n as usize)
    }
    pub fn guid(&self, index: u32) -> Result<[u8; 16]> {
        if index == 0 {
            return Ok([0; 16]);
        }
        let b = self
            .stream("#GUID")
            .ok_or_else(|| err("missing GUID heap"))?;
        Ok(span(
            b,
            (index as usize - 1)
                .checked_mul(16)
                .ok_or_else(|| err("GUID offset overflow"))?,
            16,
        )?
        .try_into()
        .unwrap())
    }
    pub fn user_string(&self, index: u32) -> Result<Vec<u16>> {
        if index == 0 {
            return Ok(vec![]);
        }
        let b = self
            .stream("#US")
            .ok_or_else(|| err("missing user string heap"))?;
        let mut r = Cursor { native: false,
            b,
            p: index as usize,
        };
        let n = r.compressed()?;
        if n == 0 || n % 2 != 1 {
            return Err(err("invalid user string byte length"));
        }
        let b = r.take(n as usize)?;
        if *b.last().unwrap() > 1 {
            return Err(err("invalid user string flag"));
        }
        Ok(b[..b.len() - 1]
            .chunks_exact(2)
            .map(|a| u16::from_le_bytes(a.try_into().unwrap()))
            .collect())
    }
    pub fn validate(&self) -> Result<()> {
        for t in 0..64 {
            if self.tables[t].count == 0 {
                continue;
            }
            let (_, cols) = schema(t).unwrap();
            let mut previous = vec![0; cols.len()];
            for rid in 1..=self.tables[t].count {
                let row = self.row(t as u8, rid)?;
                for (j, c) in cols.iter().enumerate() {
                    let n = row[j];
                    let k = c.1;
                    if k.starts_with('t')
                        || k.starts_with('l')
                        || !["u2", "u4", "string", "blob", "guid"].contains(&k)
                    {
                        if n == 0 && !nullable_index(t, j) {
                            return Err(err("nil required index"));
                        }
                    }
                    if k.starts_with('l') {
                        if rid == 1 && n != 1 || rid > 1 && n < previous[j] {
                            return Err(err("invalid list ordering"));
                        }
                        previous[j] = n
                    }
                    match c.1 {
                        "u2" | "u4" => {}
                        "string" => {
                            self.string(n)?;
                        }
                        "blob" => {
                            self.blob(n)?;
                        }
                        "guid" => {
                            self.guid(n)?;
                        }
                        k => {
                            if k.starts_with('t') || k.starts_with('l') {
                                let mut target = k[1..].parse::<usize>().unwrap();
                                let mut limit = self.row_count(target);
                                if k.starts_with('l') {
                                    target = self.pointer_table(target);
                                    limit = self.row_count(target) + 1;
                                    if n == 0 {
                                        return Err(err("nil list start"));
                                    }
                                }
                                if n > limit {
                                    return Err(err("table index out of range"));
                                }
                            } else {
                                let tok = decode_coded(k, n)?;
                                if tok.0 != 0 {
                                    self.validate_token(tok)?
                                }
                            }
                        }
                    }
                }
            }
        }
        self.validate_graph()
    }
    pub fn range(&self, owner: u8, rid: u32, column: usize, target: u8) -> Result<Vec<Token>> {
        if target >= 64 || schema(target as usize).is_none() {
            return Err(err("invalid list target table"));
        }
        let row = self.row(owner, rid)?;
        if schema(owner as usize).unwrap().1.get(column).map(|c| c.1)
            != Some(format!("l{}", target).as_str())
        {
            return Err(err("invalid list column"));
        }
        let actual = self.pointer_table(target as usize);
        let start = *row.get(column).ok_or_else(|| err("list column"))?;
        let end = if rid < self.tables[owner as usize].count {
            self.row(owner, rid + 1)?[column]
        } else {
            self.tables[actual].count + 1
        };
        if start == 0 || start > end || end > self.tables[actual].count + 1 {
            return Err(err("invalid list range"));
        }
        let mut out = Vec::new();
        for n in start..end {
            let v = if actual == target as usize {
                n
            } else {
                self.row(actual as u8, n)?[0]
            };
            out.push(Token((target as u32) << 24 | v))
        }
        Ok(out)
    }
}
#[derive(Debug, Clone, Copy, Default)]
pub struct Directory {
    pub rva: u32,
    pub size: u32,
}
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}
#[derive(Debug, Clone, Default)]
pub struct CliHeader {
    pub size: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata: Directory,
    pub flags: u32,
    pub entry_point: u32,
    pub resources: Directory,
    pub strong_name_signature: Directory,
    pub code_manager_table: Directory,
    pub vtable_fixups: Directory,
    pub export_address_table_jumps: Directory,
    pub managed_native_header: Directory,
}
#[derive(Debug)]
pub struct Image<'a> {
    pub data: &'a [u8],
    pub format: &'static str,
    pub machine: u16,
    pub image_base: u64,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
    pub cli: CliHeader,
    pub metadata: Metadata<'a>,
    pub ready_to_run: bool,
    pub composite: bool,
    pub has_metadata: bool,
    pub native_header: Directory,
    pub debug_directory: Directory,
}
impl<'a> Image<'a> {
    pub fn open(b: &'a [u8]) -> Result<Self> {
        if b.starts_with(b"BSJB") {
            let md = Metadata::parse(b)?;
            let format = if md.pdb.is_some() {
                "portable-pdb"
            } else {
                "metadata"
            };
            return Ok(Self {
                data: b,
                format,
                machine: 0,
                image_base: 0,
                size_of_headers: 0,
                sections: vec![],
                cli: CliHeader::default(),
                metadata: md,
                ready_to_run: false, composite:false,has_metadata:true,native_header:Directory::default(),
                debug_directory: Directory::default(),
            });
        }
        if span(b, 0, 64)?[..2] != *b"MZ" {
            return Err(err("not a DOS/PE image"));
        }
        let pe = u32(b, 60)? as usize;
        let h = span(b, pe, 24)?;
        if h[..4] != *b"PE\0\0" {
            return Err(err("invalid PE header"));
        }
        let machine = u16(h, 4)?;
        let section_count = u16(h, 6)? as usize;
        let opt_size = u16(h, 20)? as usize;
        let opt = span(b, pe + 24, opt_size)?;
        let (format, dirs, image_base) = match u16(opt, 0)? {
            0x10b => ("PE32", 96, u32(opt, 28)? as u64),
            0x20b => ("PE32+", 112, u64(opt, 24)?),
            _ => return Err(err("optional header magic")),
        };
        let size_of_headers = u32(opt, 60)?;
        if size_of_headers as usize > b.len() {
            return Err(err("SizeOfHeaders out of range"));
        }
        let n = u32(opt, dirs - 4)? as usize;
        if n < 15 || n > opt.len().saturating_sub(dirs) / 8 {
            return Err(err("invalid data directory count"));
        }
        let dir = |i: usize| -> Result<Directory> {
            Ok(Directory {
                rva: u32(opt, dirs + i * 8)?,
                size: u32(opt, dirs + i * 8 + 4)?,
            })
        };
        let cli_dir = dir(14)?;
        let debug_directory = dir(6)?;
        let sections_data = span(b, pe + 24 + opt_size, section_count * 40)?;
        let mut sections = vec![];
        for a in sections_data.chunks_exact(40) {
            let name = String::from_utf8_lossy(&a[..8])
                .trim_end_matches('\0')
                .to_string();
            let s = Section {
                name,
                virtual_size: u32(a, 8)?,
                virtual_address: u32(a, 12)?,
                raw_size: u32(a, 16)?,
                raw_offset: u32(a, 20)?,
                characteristics: u32(a, 36)?,
            };
            span(b, s.raw_offset as usize, s.raw_size as usize)?;
            sections.push(s)
        }
        // Parse RVA mapping before the metadata object exists, without copying input.
        let at = |rva: u32, size: u32| -> Result<&'a [u8]> {
            let p = map_rva(b, size_of_headers, &sections, rva, size)?;
            span(b, p, size as usize)
        };
        let native_header=composite_directory(dir(0)?,&at)?;
        let composite=native_header.rva!=0;
        if cli_dir.rva == 0 || cli_dir.size == 0 {
            if native_header.rva==0{return Err(err("PE image has no CLI header"));}
            return Ok(Self{data:b,format,machine,image_base,size_of_headers,sections,cli:CliHeader::default(),metadata:Metadata::empty(),ready_to_run:true,composite:true,has_metadata:false,native_header,debug_directory});
        }
        if cli_dir.size < 72 {
            return Err(err("short CLI header"));
        }
        let c = at(cli_dir.rva, cli_dir.size)?;
        let cb = u32(c, 0)?;
        if cb < 72 || cb > cli_dir.size {
            return Err(err("invalid CLI header size"));
        }
        let d = |p: usize| -> Result<Directory> {
            Ok(Directory {
                rva: u32(c, p)?,
                size: u32(c, p + 4)?,
            })
        };
        let cli = CliHeader {
            size: cb,
            major_runtime_version: u16(c, 4)?,
            minor_runtime_version: u16(c, 6)?,
            metadata: d(8)?,
            flags: u32(c, 16)?,
            entry_point: u32(c, 20)?,
            resources: d(24)?,
            strong_name_signature: d(32)?,
            code_manager_table: d(40)?,
            vtable_fixups: d(48)?,
            export_address_table_jumps: d(56)?,
            managed_native_header: d(64)?,
        };
        let metadata = Metadata::parse(at(cli.metadata.rva, cli.metadata.size)?)?;
        for d in [
            cli.resources,
            cli.strong_name_signature,
            cli.code_manager_table,
            cli.vtable_fixups,
            cli.export_address_table_jumps,
            cli.managed_native_header,
        ] {
            if d.size != 0 {
                at(d.rva, d.size)?;
            }
        }
        let ready_to_run = composite || (cli.managed_native_header.size >= 4
            && u32(at(cli.managed_native_header.rva, 4)?, 0)? == 0x00525452);
        if cli.flags & 16 == 0 && cli.entry_point != 0 {
            let tok = Token(cli.entry_point);
            metadata.validate_token(tok)?;
            if tok.table() != 6 && tok.table() != 38 {
                return Err(err("entry point is not MethodDef/File"));
            }
        }
        Ok(Self {
            data: b,
            format,
            machine,
            image_base,
            size_of_headers,
            sections,
            cli,
            metadata,
            ready_to_run, composite,has_metadata:true,native_header,
            debug_directory,
        })
    }
    pub fn rva_offset(&self, rva: u32, size: u32) -> Result<usize> {
        map_rva(self.data, self.size_of_headers, &self.sections, rva, size)
    }
    pub fn bytes_at_rva(&self, rva: u32, size: u32) -> Result<&'a [u8]> {
        span(self.data, self.rva_offset(rva, size)?, size as usize)
    }
    fn rva_tail(&self, rva: u32) -> Result<&'a [u8]> {
        let p = self.rva_offset(rva, 1)?;
        let mut end = self.size_of_headers as usize;
        if rva >= self.size_of_headers {
            for s in &self.sections {
                if rva as u64 >= s.virtual_address as u64
                    && (rva as u64) < s.virtual_address as u64 + s.raw_size as u64
                {
                    end = s.raw_offset as usize + s.raw_size as usize;
                    break;
                }
            }
        }
        span(
            self.data,
            p,
            end.checked_sub(p).ok_or_else(|| err("RVA tail"))?,
        )
    }
}
fn map_rva(b: &[u8], headers: u32, sections: &[Section], rva: u32, size: u32) -> Result<usize> {
    if rva as u64 + size as u64 > 1u64 << 32 {
        return Err(err("RVA overflow"));
    }
    if rva < headers {
        if rva as u64 + size as u64 > headers as u64 {
            return Err(err("RVA crosses header boundary"));
        }
        span(b, rva as usize, size as usize)?;
        return Ok(rva as usize);
    }
    let mut offset = None;
    for s in sections {
        if (rva as u64) < s.virtual_address as u64
            || rva as u64 >= s.virtual_address as u64 + s.virtual_size.max(s.raw_size) as u64
        {
            continue;
        }
        if offset.is_some() {
            return Err(err("ambiguous overlapping RVA"));
        }
        let delta = rva as u64 - s.virtual_address as u64;
        if delta + size as u64 > s.raw_size as u64 {
            return Err(err("unbacked virtual section data"));
        }
        offset = Some(s.raw_offset as usize + delta as usize)
    }
    let p = offset.ok_or_else(|| err("unmapped RVA"))?;
    span(b, p, size as usize)?;
    Ok(p)
}
#[derive(Debug, Clone)]
pub struct Type {
    pub kind: String,
    pub token: Token,
    pub index: u32,
    pub args: Vec<Type>,
    pub rank: u32,
    pub sizes: Vec<u32>,
    pub lower_bounds: Vec<i32>,
    pub method: Option<Box<Signature>>,
}
impl Type {
    fn new(k: &str) -> Self {
        Self {
            kind: k.into(),
            token: Token(0),
            index: 0,
            args: vec![],
            rank: 0,
            sizes: vec![],
            lower_bounds: vec![],
            method: None,
        }
    }
    pub fn format(&self, m: &Metadata<'_>) -> String {
        self.format_depth(m, 0)
    }
    fn format_depth(&self, m: &Metadata<'_>, depth: usize) -> String {
        if depth > 64 {
            return "<cycle>".into();
        }
        let child = |i: usize| {
            self.args
                .get(i)
                .map(|t| t.format_depth(m, depth + 1))
                .unwrap_or_else(|| "<?>".into())
        };
        match self.kind.as_str() {
            "class" | "valuetype" => m
                .resolve_depth(self.token, depth + 1)
                .unwrap_or_else(|_| self.token.to_string()),
            "pointer" => child(0) + "*",
            "byref" => child(0) + "&",
            "szarray" => child(0) + "[]",
            "pinned" => child(0) + " pinned",
            "modreq" | "modopt" => format!(
                "{} {}({})",
                child(0),
                self.kind,
                m.resolve_depth(self.token, depth + 1)
                    .unwrap_or_else(|_| self.token.to_string())
            ),
            "var" => format!("!{}", self.index),
            "mvar" => format!("!!{}", self.index),
            "genericinst" => format!(
                "{}<{}>",
                child(0),
                (1..self.args.len())
                    .map(child)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "array" => {
                if self.rank > 256 {
                    return format!("{}[rank {}]", child(0), self.rank);
                }
                let a = (0..self.rank as usize)
                    .map(|i| {
                        let lo = *self.lower_bounds.get(i).unwrap_or(&0) as i64;
                        if let Some(&n) = self.sizes.get(i) {
                            format!("{}...{}", lo, lo + n as i64 - 1)
                        } else if i < self.lower_bounds.len() {
                            format!("{}...", lo)
                        } else {
                            String::new()
                        }
                    })
                    .collect::<Vec<_>>();
                format!("{}[{}]", child(0), a.join(","))
            }
            "fnptr" => self
                .method
                .as_ref()
                .map(|s| format!("method {}*", s.format_depth(m, depth + 1)))
                .unwrap_or_default(),
            _ => self.kind.clone(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct Signature {
    pub kind: String,
    pub calling_convention: u8,
    pub generic_arity: u32,
    pub return_type: Option<Type>,
    pub parameters: Vec<Type>,
    pub sentinel: Option<usize>,
}
impl Signature {
    pub fn format(&self, m: &Metadata<'_>) -> String {
        self.format_depth(m, 0)
    }
    fn format_depth(&self, m: &Metadata<'_>, depth: usize) -> String {
        if depth > 64 {
            return "<cycle>".into();
        }
        if self.kind == "field" {
            return self
                .return_type
                .as_ref()
                .map(|v| v.format_depth(m, depth + 1))
                .unwrap_or_default();
        }
        let mut a = Vec::new();
        for (i, t) in self.parameters.iter().enumerate() {
            if self.sentinel == Some(i) {
                a.push("...".into())
            }
            a.push(t.format_depth(m, depth + 1))
        }
        match self.kind.as_str() {
            "locals" => format!("locals ({})", a.join(", ")),
            "method-instantiation" => format!("<{}>", a.join(", ")),
            _ => {
                let mut ret = self
                    .return_type
                    .as_ref()
                    .map(|v| v.format_depth(m, depth + 1) + " ")
                    .unwrap_or_default();
                if self.calling_convention & 32 != 0 {
                    ret = "instance ".to_string() + &ret
                }
                if self.generic_arity != 0 {
                    ret += &format!("generic<{}> ", self.generic_arity)
                }
                format!("{}({})", ret, a.join(", "))
            }
        }
    }
}
impl<'a> Metadata<'a> {
    pub fn parse_signature(&self, b: &[u8]) -> Result<Signature> {
        let mut r = Cursor { native: false, b, p: 0 };
        let s = self.signature(&mut r, 0)?;
        if r.p != b.len() {
            return Err(err("trailing signature bytes"));
        }
        Ok(s)
    }
    pub fn type_signature(&self, b: &[u8]) -> Result<Type> {
        let mut r = Cursor { native: false, b, p: 0 };
        let t = self.signature_type(&mut r, 0)?;
        if r.p != b.len() {
            return Err(err("trailing type signature bytes"));
        }
        Ok(t)
    }
    fn signature(&self, r: &mut Cursor<'_>, depth: usize) -> Result<Signature> {
        if depth > 64 {
            return Err(err("signature nesting limit"));
        }
        let raw = r.uint(1)?;
        if raw & 128 != 0 {
            return Err(err("reserved calling convention"));
        }
        let cc = raw & 15;
        let kind = match cc {
            6 => "field",
            7 => "locals",
            10 => "method-instantiation",
            8 => "property",
            0 | 1 | 2 | 3 | 4 | 5 | 9 | 11 => "method",
            _ => return Err(err("unknown signature calling convention")),
        };
        let mut s = Signature {
            kind: kind.into(),
            calling_convention: raw as u8,
            generic_arity: 0,
            return_type: None,
            parameters: vec![],
            sentinel: None,
        };
        if cc == 6 {
            s.return_type = Some(self.signature_type(r, depth + 1)?);
            return Ok(s);
        }
        if raw & 16 != 0 {
            s.generic_arity = r.compressed()?
        }
        let count = r.compressed()?;
        if count as usize > r.b.len().saturating_sub(r.p) {
            return Err(err("signature parameter count"));
        }
        if cc != 7 && cc != 10 {
            s.return_type = Some(self.signature_type(r, depth + 1)?)
        }
        for i in 0..count {
            if r.b.get(r.p) == Some(&0x41) {
                if cc != 5 || s.sentinel.is_some() {
                    return Err(err("unexpected sentinel"));
                }
                s.sentinel = Some(i as usize);
                r.p += 1
            }
            s.parameters.push(self.signature_type(r, depth + 1)?)
        }
        Ok(s)
    }
    fn signature_type(&self, r: &mut Cursor<'_>, depth: usize) -> Result<Type> {
        if depth > 64 {
            return Err(err("signature nesting limit"));
        }
        let raw = r.uint(1)?;
        let k = if r.native { raw & 0x7f } else { raw };
        if r.native && k == 0x3e { return Ok(Type::new("canon")); }
        if r.native && k == 0x3f { let mut t=Type::new("module");t.index=r.compressed()?;t.args.push(self.signature_type(r,depth+1)?);return Ok(t); }
        let primitive = match k {
            1 => "void",
            2 => "bool",
            3 => "char",
            4 => "int8",
            5 => "uint8",
            6 => "int16",
            7 => "uint16",
            8 => "int32",
            9 => "uint32",
            10 => "int64",
            11 => "uint64",
            12 => "float32",
            13 => "float64",
            14 => "string",
            22 => "typedref",
            24 => "native int",
            25 => "native uint",
            28 => "object",
            _ => "",
        };
        if !primitive.is_empty() {
            return Ok(Type::new(primitive));
        }
        let mut t = Type::new(match k {
            15 => "pointer",
            16 => "byref",
            29 => "szarray",
            69 => "pinned",
            31 => "modreq",
            32 => "modopt",
            17 => "valuetype",
            18 => "class",
            19 => "var",
            30 => "mvar",
            20 => "array",
            21 => "genericinst",
            27 => "fnptr",
            _ => return Err(err("unknown/reserved signature element")),
        });
        match k {
            15 | 16 | 29 | 69 | 31 | 32 => {
                if k == 31 || k == 32 {
                    t.token = decode_coded("TypeDefOrRef", r.compressed()?)?;
                    if !r.native { self.validate_token(t.token)?; }
                }
                t.args.push(self.signature_type(r, depth + 1)?);
            }
            17 | 18 => {
                t.token = decode_coded("TypeDefOrRef", r.compressed()?)?;
                if !r.native { self.validate_token(t.token)?; }
            }
            19 | 30 => t.index = r.compressed()?,
            20 => {
                t.args.push(self.signature_type(r, depth + 1)?);
                t.rank = r.compressed()?;
                if r.native && t.rank==0 { t.kind="szarray".into();return Ok(t); }
                let n = r.compressed()?;
                if n > t.rank || n as usize > r.b.len().saturating_sub(r.p) {
                    return Err(err("invalid array sizes"));
                }
                for _ in 0..n {
                    t.sizes.push(r.compressed()?)
                }
                let n = r.compressed()?;
                if n > t.rank || n as usize > r.b.len().saturating_sub(r.p) {
                    return Err(err("invalid array bounds"));
                }
                for _ in 0..n {
                    t.lower_bounds.push(if r.native {let v=r.compressed()?;if v&1==0{(v>>1)as i32}else{-((v>>1)as i32)}} else {r.signed()?})
                }
            }
            21 => {
                let base = self.signature_type(r, depth + 1)?;
                let kind=if r.native && base.kind=="module" {base.args[0].kind.as_str()} else {base.kind.as_str()};
                if kind != "class" && kind != "valuetype" {
                    return Err(err("invalid generic base"));
                }
                t.args.push(base);
                let n = r.compressed()?;
                if n as usize > r.b.len().saturating_sub(r.p) {
                    return Err(err("generic argument count"));
                }
                for _ in 0..n {
                    t.args.push(self.signature_type(r, depth + 1)?)
                }
            }
            27 => t.method = Some(Box::new(self.signature(r, depth + 1)?)),
            _ => unreachable!(),
        }
        Ok(t)
    }
    pub fn resolve(&self, t: Token) -> Result<String> {
        self.resolve_depth(t, 0)
    }
    fn resolve_depth(&self, t: Token, depth: usize) -> Result<String> {
        if depth > 64 {
            return Err(err("resolution cycle/nesting limit"));
        }
        self.validate_token(t)?;
        if t.table() == 0x70 {
            return Ok(String::from_utf16_lossy(&self.user_string(t.rid())?));
        }
        let r = self.row(t.table(), t.rid())?;
        let s = |i: usize| self.string(r[i]).map(|s| s.to_string());
        match t.table() {
            0 => s(1),
            1 => {
                let scope = decode_coded("ResolutionScope", r[0])?;
                if scope.0 != 0 && scope.table() == 1 {
                    return Ok(self.resolve_depth(scope, depth + 1)? + "+" + &s(1)?);
                }
                Ok(qualify(&s(2)?, &s(1)?))
            }
            2 => {
                if let Some(&parent) = self.nested.get(&t) {
                    return Ok(self.resolve_depth(parent, depth + 1)? + "+" + &s(1)?);
                }
                Ok(qualify(&s(2)?, &s(1)?))
            }
            4 | 6 => {
                let o = self.owner(t)?;
                Ok(self.resolve_depth(o, depth + 1)?
                    + "::"
                    + &s(if t.table() == 4 { 1 } else { 3 })?)
            }
            8 => s(2),
            10 => Ok(
                self.resolve_depth(decode_coded("MemberRefParent", r[0])?, depth + 1)?
                    + "::"
                    + &s(1)?,
            ),
            17 => Ok(self
                .parse_signature(self.blob(r[0])?)?
                .format_depth(self, depth + 1)),
            20 | 23 => s(1),
            26 => s(0),
            27 => Ok(self
                .type_signature(self.blob(r[0])?)?
                .format_depth(self, depth + 1)),
            32 => s(7),
            35 => s(6),
            38 => s(1),
            39 => Ok(qualify(&s(3)?, &s(2)?)),
            40 => s(2),
            42 => s(3),
            43 => Ok(
                self.resolve_depth(decode_coded("MethodDefOrRef", r[0])?, depth + 1)?
                    + &self
                        .parse_signature(self.blob(r[1])?)?
                        .format_depth(self, depth + 1),
            ),
            48 => self.document_name(t.rid()),
            _ => Ok(format!("{}({})", schema(t.table() as usize).unwrap().0, t)),
        }
    }
    fn owner(&self, t: Token) -> Result<Token> {
        self.owners
            .get(&t)
            .copied()
            .ok_or_else(|| err("orphan member token"))
    }
    pub fn assemblies(&self) -> Result<Vec<Assembly>> {
        let mut out = vec![];
        for i in 1..=self.tables[32].count {
            let r = self.row(32, i)?;
            out.push(Assembly {
                token: Token(32 << 24 | i),
                name: self.string(r[7])?.into(),
                version: format!("{}.{}.{}.{}", r[1], r[2], r[3], r[4]),
                culture: self.string(r[8])?.into(),
                flags: r[5],
                public_key: self.blob(r[6])?.to_vec(),
            })
        }
        Ok(out)
    }
    pub fn generic_parameters(&self, owner: Token) -> Result<Vec<GenericParameter>> {
        Ok(self.generics.get(&owner).cloned().unwrap_or_default())
    }
    pub fn types(&self) -> Result<Vec<TypeDefinition>> {
        let mut out = vec![];
        for i in 1..=self.tables[2].count {
            let r = self.row(2, i)?;
            let token = Token(2 << 24 | i);
            out.push(TypeDefinition {
                token,
                name: self.string(r[1])?.into(),
                namespace: self.string(r[2])?.into(),
                full_name: self.resolve(token)?,
                flags: r[0],
                extends: decode_coded("TypeDefOrRef", r[3])?,
                fields: self.range(2, i, 4, 4)?,
                methods: self.range(2, i, 5, 6)?,
                generic_parameters: self.generic_parameters(token)?,
            })
        }
        Ok(out)
    }
    pub fn method(&self, t: Token) -> Result<Method> {
        if t.table() != 6 {
            return Err(err("not MethodDef token"));
        }
        let r = self.row(6, t.rid())?;
        let owner = self.owner(t)?;
        let name = self.string(r[3])?.to_string();
        let sig = self.parse_signature(self.blob(r[4])?)?;
        if sig.kind != "method" {
            return Err(err("MethodDef has non-method signature"));
        }
        let kind = if r[2] & 0x400 != 0 {
            "abstract"
        } else if r[2] & 0x2000 != 0 {
            "pinvoke"
        } else {
            match r[1] & 3 {
                1 => "native",
                2 => "optil",
                3 => "runtime",
                _ => {
                    if r[0] == 0 {
                        "no-body"
                    } else {
                        "cil"
                    }
                }
            }
        };
        Ok(Method {
            token: t,
            declaring_type: owner,
            full_name: self.resolve(owner)? + "::" + &name,
            name,
            rva: r[0],
            flags: r[2],
            impl_flags: r[1],
            kind,
            signature: sig,
            parameters: self.range(6, t.rid(), 5, 8)?,
            generic_parameters: self.generic_parameters(t)?,
        })
    }
    pub fn methods(&self) -> Result<Vec<Method>> {
        (1..=self.tables[6].count)
            .map(|i| self.method(Token(6 << 24 | i)))
            .collect()
    }
    pub fn fields(&self) -> Result<Vec<Field>> {
        let mut out = vec![];
        for i in 1..=self.tables[4].count {
            let r = self.row(4, i)?;
            let t = Token(4 << 24 | i);
            let sig = self.parse_signature(self.blob(r[2])?)?;
            if sig.kind != "field" {
                return Err(err("Field has non-field signature"));
            }
            out.push(Field {
                token: t,
                declaring_type: self.owner(t)?,
                name: self.string(r[1])?.into(),
                flags: r[0],
                signature: sig,
            })
        }
        Ok(out)
    }
    pub fn document_name(&self, rid: u32) -> Result<String> {
        let row = self.row(48, rid)?;
        let b = self.blob(row[0])?;
        if b.is_empty() {
            return Err(err("empty document name blob"));
        }
        let n = match b[0] {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(err("invalid document separator UTF-8")),
        };
        let s = std::str::from_utf8(span(b, 0, n)?)
            .map_err(|_| err("invalid document separator UTF-8"))?;
        let sep = if b[0] == 0 { "" } else { s };
        if n >= b.len() {
            return Err(err("document name has no parts"));
        }
        let mut r = Cursor { native: false, b, p: n };
        let mut parts = vec![];
        while r.p < b.len() {
            parts.push(
                std::str::from_utf8(self.blob(r.compressed()?)?)
                    .map_err(|_| err("document UTF-8"))?
                    .to_string(),
            )
        }
        Ok(parts.join(sep))
    }
}
fn qualify(ns: &str, name: &str) -> String {
    if ns.is_empty() {
        name.into()
    } else {
        ns.to_string() + "." + name
    }
}
#[derive(Debug, Clone)]
pub struct Assembly {
    pub token: Token,
    pub name: String,
    pub version: String,
    pub culture: String,
    pub flags: u32,
    pub public_key: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct GenericParameter {
    pub token: Token,
    pub number: u32,
    pub flags: u32,
    pub name: String,
    pub constraints: Vec<Token>,
}
#[derive(Debug, Clone)]
pub struct TypeDefinition {
    pub token: Token,
    pub name: String,
    pub namespace: String,
    pub full_name: String,
    pub flags: u32,
    pub extends: Token,
    pub fields: Vec<Token>,
    pub methods: Vec<Token>,
    pub generic_parameters: Vec<GenericParameter>,
}
#[derive(Debug, Clone)]
pub struct Method {
    pub token: Token,
    pub declaring_type: Token,
    pub name: String,
    pub full_name: String,
    pub rva: u32,
    pub flags: u32,
    pub impl_flags: u32,
    pub kind: &'static str,
    pub signature: Signature,
    pub parameters: Vec<Token>,
    pub generic_parameters: Vec<GenericParameter>,
}
#[derive(Debug, Clone)]
pub struct Field {
    pub token: Token,
    pub declaring_type: Token,
    pub name: String,
    pub flags: u32,
    pub signature: Signature,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionClause {
    pub flags: u32,
    pub try_offset: u32,
    pub try_length: u32,
    pub handler_offset: u32,
    pub handler_length: u32,
    pub class_token: Token,
    pub filter_offset: u32,
}
#[derive(Debug, Clone)]
pub struct MethodSection<'a> {
    pub kind: u8,
    pub fat: bool,
    pub data: &'a [u8],
}
#[derive(Debug, Clone)]
pub struct MethodBody<'a> {
    pub token: Token,
    pub rva: u32,
    pub kind: &'static str,
    pub flags: u16,
    pub max_stack: u16,
    pub local_signature: Token,
    pub init_locals: bool,
    pub header: &'a [u8],
    pub il: &'a [u8],
    pub exceptions: Vec<ExceptionClause>,
    pub sections: Vec<MethodSection<'a>>,
    pub raw: &'a [u8],
}
impl<'a> MethodBody<'a> {
    fn empty() -> Self {
        Self {
            token: Token(0),
            rva: 0,
            kind: "cil",
            flags: 0,
            max_stack: 0,
            local_signature: Token(0),
            init_locals: false,
            header: &[],
            il: &[],
            exceptions: vec![],
            sections: vec![],
            raw: &[],
        }
    }
    pub fn parse(b: &'a [u8]) -> Result<Self> {
        let first = *b.first().ok_or_else(|| err("empty method body"))?;
        let mut out = Self::empty();
        let (start, size, mut more) = match first & 3 {
            2 => {
                out.flags = 2;
                out.max_stack = 8;
                (1, (first >> 2) as usize, false)
            }
            3 => {
                span(b, 0, 12)?;
                let v = u16(b, 0)?;
                out.flags = v & 0xfff;
                let start = (v >> 12) as usize * 4;
                if start < 12 || out.flags & !0x1b != 0 {
                    return Err(err("invalid fat method header"));
                }
                out.max_stack = u16(b, 2)?;
                let size = u32(b, 4)? as usize;
                out.local_signature = Token(u32(b, 8)?);
                if out.local_signature.0 != 0
                    && (out.local_signature.table() != 17 || out.local_signature.rid() == 0)
                {
                    return Err(err("invalid locals token"));
                }
                out.init_locals = out.flags & 16 != 0;
                (start, size, out.flags & 8 != 0)
            }
            _ => return Err(err("invalid method header")),
        };
        out.header = span(b, 0, start)?;
        out.il = span(b, start, size)?;
        let mut end = start + size;
        while more {
            let p = (end + 3) & !3;
            let h = span(b, p, 4)?;
            let kind = h[0] & 63;
            let fat = h[0] & 64 != 0;
            more = h[0] & 128 != 0;
            let n = if fat {
                h[1] as usize | (h[2] as usize) << 8 | (h[3] as usize) << 16
            } else {
                if h[2] != 0 || h[3] != 0 {
                    return Err(err("reserved small section bytes"));
                }
                h[1] as usize
            };
            if n < 4 {
                return Err(err("invalid section size"));
            }
            let data = span(b, p, n)?;
            out.sections.push(MethodSection { kind, fat, data });
            if kind != 1 {
                return Err(err("unsupported method data section kind"));
            }
            let width = if fat { 24 } else { 12 };
            if (n - 4) % width != 0 {
                return Err(err("misaligned exception clauses"));
            }
            for a in data[4..].chunks_exact(width) {
                let (flags, to, tl, ho, hl, extra) = if fat {
                    (
                        u32(a, 0)?,
                        u32(a, 4)?,
                        u32(a, 8)?,
                        u32(a, 12)?,
                        u32(a, 16)?,
                        u32(a, 20)?,
                    )
                } else {
                    (
                        u16(a, 0)? as u32,
                        u16(a, 2)? as u32,
                        a[4] as u32,
                        u16(a, 5)? as u32,
                        a[7] as u32,
                        u32(a, 8)?,
                    )
                };
                if ![0, 1, 2, 4].contains(&flags)
                    || to as u64 + tl as u64 > size as u64
                    || ho as u64 + hl as u64 > size as u64
                    || tl == 0
                    || hl == 0
                {
                    return Err(err("invalid exception clause/range"));
                }
                let mut c = ExceptionClause {
                    flags,
                    try_offset: to,
                    try_length: tl,
                    handler_offset: ho,
                    handler_length: hl,
                    class_token: Token(0),
                    filter_offset: 0,
                };
                match flags {
                    0 => {
                        c.class_token = Token(extra);
                        if c.class_token.rid() == 0 || ![1, 2, 27].contains(&c.class_token.table())
                        {
                            return Err(err("catch type token"));
                        }
                    }
                    1 => {
                        c.filter_offset = extra;
                        if extra as usize >= size || extra >= ho {
                            return Err(err("filter offset"));
                        }
                    }
                    _ => {
                        if extra != 0 {
                            return Err(err("finally/fault union"));
                        }
                    }
                }
                out.exceptions.push(c)
            }
            end = p + n
        }
        out.raw = span(b, 0, end)?;
        Ok(out)
    }
}
impl<'a> Image<'a> {
    pub fn method_body(&self, t: Token) -> Result<MethodBody<'a>> {
        let m = self.metadata.method(t)?;
        if m.kind != "cil" {
            let mut out = MethodBody::empty();
            out.token = t;
            out.rva = m.rva;
            out.kind = m.kind;
            return Ok(out);
        }
        let mut out = MethodBody::parse(self.rva_tail(m.rva)?)?;
        out.token = t;
        out.rva = m.rva;
        if out.local_signature.0 != 0 {
            self.metadata.validate_token(out.local_signature)?;
            let r = self.metadata.row(17, out.local_signature.rid())?;
            if self
                .metadata
                .parse_signature(self.metadata.blob(r[0])?)?
                .kind
                != "locals"
            {
                return Err(err("local signature is not locals"));
            }
        }
        for c in &out.exceptions {
            if c.class_token.0 != 0 {
                self.metadata.validate_token(c.class_token)?
            }
        }
        Ok(out)
    }
    pub fn resources(&self) -> Result<Vec<Resource<'a>>> {
        let mut out = vec![];
        for i in 1..=self.metadata.tables[40].count {
            let r = self.metadata.row(40, i)?;
            let implementation = decode_coded("Implementation", r[3])?;
            let mut data = &[][..];
            if implementation.0 == 0 {
                let b = self.bytes_at_rva(self.cli.resources.rva, self.cli.resources.size)?;
                let n = u32(b, r[0] as usize)?;
                data = span(b, r[0] as usize + 4, n as usize)?
            }
            out.push(Resource {
                token: Token(40 << 24 | i),
                name: self.metadata.string(r[2])?.into(),
                flags: r[1],
                implementation,
                offset: r[0],
                data,
            })
        }
        Ok(out)
    }
    pub fn debug_entries(&self) -> Result<Vec<DebugEntry<'a>>> {
        let d = self.debug_directory;
        if d.size == 0 {
            return Ok(vec![]);
        }
        if d.size % 28 != 0 {
            return Err(err("debug directory size"));
        }
        let b = self.bytes_at_rva(d.rva, d.size)?;
        let mut out = vec![];
        for a in b.chunks_exact(28) {
            let n = u32(a, 16)?;
            let offset = u32(a, 24)?;
            out.push(DebugEntry {
                kind: u32(a, 12)?,
                timestamp: u32(a, 4)?,
                major: u16(a, 8)?,
                minor: u16(a, 10)?,
                rva: u32(a, 20)?,
                file_offset: offset,
                data: span(self.data, offset as usize, n as usize)?,
            })
        }
        Ok(out)
    }
}
#[derive(Debug, Clone)]
pub struct Resource<'a> {
    pub token: Token,
    pub name: String,
    pub flags: u32,
    pub implementation: Token,
    pub offset: u32,
    pub data: &'a [u8],
}
#[derive(Debug, Clone)]
pub struct DebugEntry<'a> {
    pub kind: u32,
    pub timestamp: u32,
    pub major: u16,
    pub minor: u16,
    pub rva: u32,
    pub file_offset: u32,
    pub data: &'a [u8],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencePoint {
    pub document: Token,
    pub offset: u32,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub hidden: bool,
}
impl<'a> Metadata<'a> {
    pub fn sequence_points(&self, method: Token) -> Result<(Token, Vec<SequencePoint>)> {
        if self.pdb.is_none() || method.table() != 6 {
            return Err(err("not a portable PDB method"));
        }
        let row = self.row(49, method.rid())?;
        let b = self.blob(row[1])?;
        if b.is_empty() {
            return Ok((Token(0), vec![]));
        }
        let mut r = Cursor { native: false, b, p: 0 };
        let local = r.compressed()?;
        let lt = if local == 0 {
            Token(0)
        } else {
            if local > 0xffffff {
                return Err(err("PDB local signature RID overflow"));
            }
            let t = Token(17 << 24 | local);
            self.validate_token(t)?;
            t
        };
        let mut doc = row[0];
        if doc == 0 {
            doc = r.compressed()?
        }
        if doc == 0 || doc > 0xffffff {
            return Err(err("invalid PDB document RID"));
        }
        self.validate_token(Token(48 << 24 | doc))?;
        let mut points: Vec<SequencePoint> = vec![];
        let mut off = 0u32;
        let (mut prev_line, mut prev_col) = (0i64, 0i64);
        let mut visible = false;
        while r.p < b.len() {
            let delta = r.compressed()?;
            if !points.is_empty() && delta == 0 {
                doc = r.compressed()?;
                if doc == 0 || doc > 0xffffff {
                    return Err(err("invalid PDB document RID"));
                }
                self.validate_token(Token(48 << 24 | doc))?;
                continue;
            }
            if off as u64 + delta as u64 >= 0x20000000 {
                return Err(err("PDB IL offset overflow"));
            }
            off += delta;
            let lines = r.compressed()?;
            let cols = if lines == 0 {
                r.compressed()? as i64
            } else {
                r.signed()? as i64
            };
            let mut p = SequencePoint {
                document: Token(48 << 24 | doc),
                offset: off,
                start_line: 0,
                start_column: 0,
                end_line: 0,
                end_column: 0,
                hidden: false,
            };
            if lines == 0 && cols == 0 {
                p.hidden = true;
                p.start_line = 0xfeefee;
                p.end_line = 0xfeefee
            } else {
                let (line, col) = if !visible {
                    (r.compressed()? as i64, r.compressed()? as i64)
                } else {
                    (
                        prev_line + r.signed()? as i64,
                        prev_col + r.signed()? as i64,
                    )
                };
                let end_line = line + lines as i64;
                let end_col = col + cols;
                if line < 0
                    || end_line >= 0x20000000
                    || line == 0xfeefee
                    || end_line == 0xfeefee
                    || col < 0
                    || col >= 65536
                    || end_col < 0
                    || end_col >= 65536
                    || lines == 0 && end_col <= col
                {
                    return Err(err("invalid sequence point"));
                }
                p.start_line = line as u32;
                p.start_column = col as u32;
                p.end_line = end_line as u32;
                p.end_column = end_col as u32;
                prev_line = line;
                prev_col = col;
                visible = true
            }
            points.push(p)
        }
        Ok((lt, points))
    }
}
#[derive(Debug, Clone)]
pub struct Member {
    pub token: Token,
    pub parent: Token,
    pub name: String,
    pub declaring_type: String,
    pub signature: Signature,
    pub resolved_signature: Signature,
    pub type_arguments: Vec<Type>,
    pub method_arguments: Vec<Type>,
}
fn substitute_signature(s: &Signature, types: &[Type], methods: &[Type]) -> Signature {
    let mut out = s.clone();
    out.return_type = s
        .return_type
        .as_ref()
        .map(|t| substitute_type(t, types, methods));
    out.parameters = s
        .parameters
        .iter()
        .map(|t| substitute_type(t, types, methods))
        .collect();
    out
}
fn substitute_type(t: &Type, types: &[Type], methods: &[Type]) -> Type {
    if t.kind == "var" {
        if let Some(t) = types.get(t.index as usize) {
            return t.clone();
        }
    }
    if t.kind == "mvar" {
        if let Some(t) = methods.get(t.index as usize) {
            return t.clone();
        }
    }
    let mut out = t.clone();
    out.args = t
        .args
        .iter()
        .map(|t| substitute_type(t, types, methods))
        .collect();
    out.method = t
        .method
        .as_ref()
        .map(|s| Box::new(substitute_signature(s, types, methods)));
    out
}
impl<'a> Metadata<'a> {
    pub fn member(&self, t: Token) -> Result<Member> {
        self.member_depth(t, 0)
    }
    fn member_depth(&self, t: Token, depth: usize) -> Result<Member> {
        if depth > 64 {
            return Err(err("member resolution nesting limit"));
        }
        self.validate_token(t)?;
        let r = self.row(t.table(), t.rid())?;
        if t.table() == 43 {
            let base = decode_coded("MethodDefOrRef", r[0])?;
            let mut out = self.member_depth(base, depth + 1)?;
            let s = self.parse_signature(self.blob(r[1])?)?;
            if s.kind != "method-instantiation"
                || out.signature.kind != "method"
                || s.parameters.len() as u32 != out.signature.generic_arity
            {
                return Err(err("MethodSpec generic arity mismatch"));
            }
            out.token = t;
            out.method_arguments = s.parameters;
            out.resolved_signature =
                substitute_signature(&out.signature, &out.type_arguments, &out.method_arguments);
            return Ok(out);
        }
        let (parent, name, signature) = match t.table() {
            4 | 6 => {
                let (col, scol) = if t.table() == 4 { (1, 2) } else { (3, 4) };
                (
                    self.owner(t)?,
                    self.string(r[col])?.to_string(),
                    self.parse_signature(self.blob(r[scol])?)?,
                )
            }
            10 => (
                decode_coded("MemberRefParent", r[0])?,
                self.string(r[1])?.to_string(),
                self.parse_signature(self.blob(r[2])?)?,
            ),
            _ => return Err(err("not a field/method member token")),
        };
        let mut type_arguments = vec![];
        if parent.table() == 27 {
            let r = self.row(27, parent.rid())?;
            let typ = self.type_signature(self.blob(r[0])?)?;
            if typ.kind == "genericinst" {
                type_arguments = typ.args[1..].to_vec()
            }
        }
        let resolved_signature = substitute_signature(&signature, &type_arguments, &[]);
        Ok(Member {
            token: t,
            parent,
            name,
            declaring_type: self.resolve(parent)?,
            signature,
            resolved_signature,
            type_arguments,
            method_arguments: vec![],
        })
    }
    pub fn attributes(&self, parent: Option<Token>) -> Result<Vec<Attribute<'a>>> {
        if let Some(t) = parent {
            self.validate_token(t)?
        }
        let mut out = vec![];
        for i in 1..=self.tables[12].count {
            let r = self.row(12, i)?;
            let p = decode_coded("HasCustomAttribute", r[0])?;
            if parent.is_some() && parent != Some(p) {
                continue;
            }
            let ctor = self.member(decode_coded("CustomAttributeType", r[1])?)?;
            let value = self.blob(r[2])?;
            if !value.starts_with(&[1, 0]) {
                return Err(err("custom attribute prolog"));
            }
            out.push(Attribute {
                token: Token(12 << 24 | i),
                parent: p,
                constructor: ctor,
                value,
            })
        }
        Ok(out)
    }
}
#[derive(Debug, Clone)]
pub struct Attribute<'a> {
    pub token: Token,
    pub parent: Token,
    pub constructor: Member,
    pub value: &'a [u8],
}
// Raw DEFLATE for MPDB payloads, implemented from RFC 1951. Output never exceeds
// the declared/caller-bounded size. PE/metadata reads themselves borrow input.
struct Bits<'a> {
    b: &'a [u8],
    p: usize,
}
impl Bits<'_> {
    fn read(&mut self, n: usize) -> Result<u32> {
        let mut v = 0;
        for i in 0..n {
            let a = *self
                .b
                .get(self.p / 8)
                .ok_or_else(|| err("truncated DEFLATE"))?;
            v |= (((a >> (self.p % 8)) & 1) as u32) << i;
            self.p += 1
        }
        Ok(v)
    }
}
struct Huffman {
    codes: BTreeMap<(usize, u32), u32>,
}
impl Huffman {
    fn new(lengths: &[u32]) -> Result<Self> {
        let mut counts = [0u32; 16];
        for &n in lengths {
            if n > 15 {
                return Err(err("DEFLATE code length"));
            }
            if n > 0 {
                counts[n as usize] += 1
            }
        }
        let mut left = 1i32;
        for &c in &counts[1..] {
            left = left * 2 - c as i32;
            if left < 0 {
                return Err(err("oversubscribed DEFLATE Huffman tree"));
            }
        }
        let mut next = [0u32; 16];
        let mut code = 0;
        for bits in 1..16 {
            code = (code + counts[bits - 1]) << 1;
            next[bits] = code
        }
        let mut codes = BTreeMap::new();
        for (sym, &n) in lengths.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let c = next[n as usize];
            next[n as usize] += 1;
            let reverse = c.reverse_bits() >> (32 - n);
            codes.insert((n as usize, reverse), sym as u32);
        }
        Ok(Self { codes })
    }
    fn decode(&self, r: &mut Bits<'_>) -> Result<u32> {
        let mut v = 0;
        for n in 1..=15 {
            v |= r.read(1)? << (n - 1);
            if let Some(&sym) = self.codes.get(&(n, v)) {
                return Ok(sym);
            }
        }
        Err(err("invalid DEFLATE Huffman code"))
    }
}
fn inflate(b: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut r = Bits { b, p: 0 };
    let mut out = Vec::new();
    loop {
        let last = r.read(1)? != 0;
        let kind = r.read(2)?;
        if kind == 0 {
            r.p = (r.p + 7) & !7;
            let n = r.read(16)?;
            if r.read(16)? != n ^ 65535 {
                return Err(err("DEFLATE stored block length"));
            }
            if n as usize > size.saturating_sub(out.len()) {
                return Err(err("DEFLATE exceeds declared size"));
            }
            for _ in 0..n {
                out.push(r.read(8)? as u8)
            }
        } else if kind == 1 || kind == 2 {
            let (lit, dist) = if kind == 1 {
                let lengths = (0..288)
                    .map(|i| match i {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    })
                    .collect::<Vec<_>>();
                (Huffman::new(&lengths)?, Huffman::new(&[5; 32])?)
            } else {
                let nl = r.read(5)? as usize + 257;
                let nd = r.read(5)? as usize + 1;
                let nc = r.read(4)? as usize + 4;
                if nl > 286 {
                    return Err(err("DEFLATE literal count"));
                }
                let order = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl = [0; 19];
                for i in 0..nc {
                    cl[order[i]] = r.read(3)?
                }
                let code = Huffman::new(&cl)?;
                let mut lengths = vec![];
                while lengths.len() < nl + nd {
                    let sym = code.decode(&mut r)?;
                    if sym <= 15 {
                        lengths.push(sym)
                    } else {
                        let (n, value) = match sym {
                            16 => (
                                r.read(2)? as usize + 3,
                                *lengths
                                    .last()
                                    .ok_or_else(|| err("DEFLATE repeat without prior code"))?,
                            ),
                            17 => (r.read(3)? as usize + 3, 0),
                            18 => (r.read(7)? as usize + 11, 0),
                            _ => return Err(err("DEFLATE code length symbol")),
                        };
                        if lengths.len() + n > nl + nd {
                            return Err(err("DEFLATE repeated lengths overflow"));
                        }
                        lengths.resize(lengths.len() + n, value)
                    }
                }
                if lengths[256] == 0 {
                    return Err(err("DEFLATE missing end-of-block"));
                }
                (Huffman::new(&lengths[..nl])?, Huffman::new(&lengths[nl..])?)
            };
            loop {
                let sym = lit.decode(&mut r)?;
                if sym < 256 {
                    if out.len() == size {
                        return Err(err("DEFLATE exceeds declared size"));
                    }
                    out.push(sym as u8)
                } else if sym == 256 {
                    break;
                } else {
                    let i = sym as usize - 257;
                    let bases = [
                        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
                        67, 83, 99, 115, 131, 163, 195, 227, 258,
                    ];
                    let extras = [
                        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5,
                        5, 5, 5, 0,
                    ];
                    if i >= bases.len() {
                        return Err(err("reserved DEFLATE length"));
                    }
                    let n = bases[i] + r.read(extras[i])? as usize;
                    let d = dist.decode(&mut r)? as usize;
                    let db = [
                        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
                        769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
                    ];
                    let de = [
                        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
                        11, 11, 12, 12, 13, 13,
                    ];
                    if d >= db.len() {
                        return Err(err("reserved DEFLATE distance"));
                    }
                    let distance = db[d] + r.read(de[d])? as usize;
                    if distance > out.len() || n > size.saturating_sub(out.len()) {
                        return Err(err("DEFLATE distance/output bounds"));
                    }
                    for _ in 0..n {
                        out.push(out[out.len() - distance])
                    }
                }
            }
        } else {
            return Err(err("reserved DEFLATE block kind"));
        }
        if last {
            break;
        }
    }
    if out.len() != size {
        return Err(err("embedded PDB size mismatch"));
    }
    Ok(out)
}
impl<'a> Image<'a> {
    /// Returns decompressed metadata bytes; parse with Metadata::parse(&bytes).
    pub fn embedded_pdb_bytes(&self, max_bytes: u32) -> Result<Option<Vec<u8>>> {
        for entry in self.debug_entries()? {
            if entry.kind != 17 {
                continue;
            }
            if !entry.data.starts_with(b"MPDB") {
                return Err(err("embedded PDB signature"));
            }
            let n = u32(entry.data, 4)?;
            if n > max_bytes {
                return Err(err("embedded PDB exceeds size limit"));
            }
            let b = inflate(
                span(entry.data, 8, entry.data.len().saturating_sub(8))?,
                n as usize,
            )?;
            if Metadata::parse(&b)?.pdb.is_none() {
                return Err(err("embedded data is not Portable PDB"));
            }
            return Ok(Some(b));
        }
        Ok(None)
    }
}
fn nullable_index(t: usize, c: usize) -> bool {
    matches!(
        (t, c),
        (1, 0) | (2, 3) | (40, 3) | (49, 0) | (50, 1) | (53, 0)
    )
}
impl<'a> Metadata<'a> {
    fn validate_graph(&self) -> Result<()> {
        let mut nested = BTreeMap::new();
        for rid in 1..=self.tables[41].count {
            let r = self.row(41, rid)?;
            if nested
                .insert(Token(2 << 24 | r[0]), Token(2 << 24 | r[1]))
                .is_some()
            {
                return Err(err("duplicate nested type owner"));
            }
        }
        let mut done = BTreeSet::new();
        let mut active = BTreeSet::new();
        for table in [1, 2, 27] {
            for rid in 1..=self.tables[table].count {
                self.visit_type(
                    Token((table as u32) << 24 | rid),
                    0,
                    &nested,
                    &mut done,
                    &mut active,
                )?
            }
        }
        Ok(())
    }
    fn visit_type(
        &self,
        t: Token,
        depth: usize,
        nested: &BTreeMap<Token, Token>,
        done: &mut BTreeSet<Token>,
        active: &mut BTreeSet<Token>,
    ) -> Result<()> {
        if depth > 64 {
            return Err(err("metadata graph nesting limit"));
        }
        if done.contains(&t) {
            return Ok(());
        }
        if !active.insert(t) {
            return Err(err("metadata type cycle"));
        }
        match t.table() {
            1 => {
                let r = self.row(1, t.rid())?;
                let parent = decode_coded("ResolutionScope", r[0])?;
                if parent.0 != 0 && parent.table() == 1 {
                    self.visit_type(parent, depth + 1, nested, done, active)?
                }
            }
            2 => {
                if let Some(&p) = nested.get(&t) {
                    self.visit_type(p, depth + 1, nested, done, active)?
                }
            }
            27 => {
                let r = self.row(27, t.rid())?;
                let v = self.type_signature(self.blob(r[0])?)?;
                self.visit_signature_type(&v, depth + 1, nested, done, active)?
            }
            _ => {}
        }
        active.remove(&t);
        done.insert(t);
        Ok(())
    }
    fn visit_signature_type(
        &self,
        t: &Type,
        depth: usize,
        nested: &BTreeMap<Token, Token>,
        done: &mut BTreeSet<Token>,
        active: &mut BTreeSet<Token>,
    ) -> Result<()> {
        if depth > 64 {
            return Err(err("signature graph nesting limit"));
        }
        if t.token.0 != 0 {
            self.visit_type(t.token, depth + 1, nested, done, active)?
        }
        for a in &t.args {
            self.visit_signature_type(a, depth + 1, nested, done, active)?
        }
        if let Some(s) = &t.method {
            if let Some(t) = &s.return_type {
                self.visit_signature_type(t, depth + 1, nested, done, active)?
            }
            for t in &s.parameters {
                self.visit_signature_type(t, depth + 1, nested, done, active)?
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct MethodSemantics {
    pub flags: u32,
    pub method: Token,
}
#[derive(Debug, Clone)]
pub struct Property {
    pub token: Token,
    pub declaring_type: Token,
    pub name: String,
    pub flags: u32,
    pub signature: Signature,
    pub accessors: Vec<MethodSemantics>,
}
#[derive(Debug, Clone)]
pub struct Event {
    pub token: Token,
    pub declaring_type: Token,
    pub name: String,
    pub flags: u32,
    pub event_type: Token,
    pub accessors: Vec<MethodSemantics>,
}
impl<'a> Metadata<'a> {
    fn accessors(&self, t: Token) -> Result<Vec<MethodSemantics>> {
        let mut out = vec![];
        for rid in 1..=self.tables[24].count {
            let r = self.row(24, rid)?;
            if decode_coded("HasSemantics", r[2])? == t {
                out.push(MethodSemantics {
                    flags: r[0],
                    method: Token(6 << 24 | r[1]),
                })
            }
        }
        Ok(out)
    }
    fn list_owners(&self, table: u8, target: u8) -> Result<BTreeMap<Token, Token>> {
        let mut out = BTreeMap::new();
        for rid in 1..=self.tables[table as usize].count {
            let r = self.row(table, rid)?;
            for t in self.range(table, rid, 1, target)? {
                if out.insert(t, Token(2 << 24 | r[0])).is_some() {
                    return Err(err("duplicate member owner"));
                }
            }
        }
        Ok(out)
    }
    pub fn properties(&self) -> Result<Vec<Property>> {
        let owners = self.list_owners(21, 23)?;
        let mut out = vec![];
        for rid in 1..=self.tables[23].count {
            let r = self.row(23, rid)?;
            let t = Token(23 << 24 | rid);
            let owner = *owners.get(&t).ok_or_else(|| err("orphan Property"))?;
            let signature = self.parse_signature(self.blob(r[2])?)?;
            if signature.kind != "property" {
                return Err(err("non-property signature"));
            }
            out.push(Property {
                token: t,
                declaring_type: owner,
                name: self.string(r[1])?.to_string(),
                flags: r[0],
                signature,
                accessors: self.accessors(t)?,
            })
        }
        Ok(out)
    }
    pub fn events(&self) -> Result<Vec<Event>> {
        let owners = self.list_owners(18, 20)?;
        let mut out = vec![];
        for rid in 1..=self.tables[20].count {
            let r = self.row(20, rid)?;
            let t = Token(20 << 24 | rid);
            out.push(Event {
                token: t,
                declaring_type: *owners.get(&t).ok_or_else(|| err("orphan Event"))?,
                name: self.string(r[1])?.to_string(),
                flags: r[0],
                event_type: decode_coded("TypeDefOrRef", r[2])?,
                accessors: self.accessors(t)?,
            })
        }
        Ok(out)
    }
}
