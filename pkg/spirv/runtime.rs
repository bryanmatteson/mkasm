//! Generated SPIR-V grammar codec. No external crates are required.
//! Binary grammar and ID framing are checked; use spirv-val for semantic module validation.
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy)]
pub struct Spec {
    pub kind: &'static str,
    /// 0: required, 1: optional, 2: variadic.
    pub quant: u8,
}
pub struct Requirement {
    pub version: u32,
    pub last: u32,
    pub capabilities: &'static [&'static str],
    pub extensions: &'static [&'static str],
}
pub struct Definition {
    pub name: &'static str,
    pub opcode: u16,
    pub aliases: &'static [&'static str],
    pub operands: &'static [Spec],
    pub requirements: Requirement,
}
struct Enumerant {
    name: &'static str,
    value: u32,
    aliases: &'static [&'static str],
    parameters: &'static [Spec],
    requirements: Requirement,
}
struct Kind {
    name: &'static str,
    category: u8,
    bases: &'static [&'static str],
    enumerants: &'static [Enumerant],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    pub kind: String,
    pub words: Vec<u32>,
    pub text: String,
    pub parameters: Vec<Operand>,
}
impl Operand {
    pub fn scalar(kind: &str, value: u32) -> Self {
        Self {
            kind: kind.into(),
            words: vec![value],
            text: String::new(),
            parameters: vec![],
        }
    }
    fn empty(kind: &str) -> Self {
        Self {
            kind: kind.into(),
            words: vec![],
            text: String::new(),
            parameters: vec![],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub opcode: u16,
    pub operands: Vec<Operand>,
}
#[derive(Default, Clone)]
pub struct Context {
    pub type_widths: HashMap<u32, u32>,
    pub id_types: HashMap<u32, u32>,
    pub float_types: HashSet<u32>,
    pub signed_types: HashSet<u32>,
    pub float_encodings: HashMap<u32, u32>,
}
impl Context {
    fn width(&self, id: u32) -> usize {
        self.type_widths
            .get(&id)
            .map_or(0, |w| (*w as usize + 31) / 32)
    }
    pub fn observe(&mut self, i: &Instruction) {
        let mut id = 0;
        let mut typ = 0;
        for o in &i.operands {
            if o.kind == "IdResult" {
                id = o.words[0]
            }
            if o.kind == "IdResultType" {
                typ = o.words[0]
            }
        }
        if id != 0 && typ != 0 {
            self.id_types.insert(id, typ);
        }
        if (i.opcode == 21 || i.opcode == 22) && i.operands.len() >= 2 {
            self.type_widths.insert(id, i.operands[1].words[0]);
            if i.opcode == 22 {
                self.float_types.insert(id);
                if i.operands.len() > 2 {
                    self.float_encodings.insert(id, i.operands[2].words[0]);
                }
            }
            if i.opcode == 21 && i.operands.len() > 2 && i.operands[2].words[0] != 0 {
                self.signed_types.insert(id);
            }
        }
    }
}
#[derive(Default)]
pub struct Environment {
    pub version: u32,
    pub capabilities: HashSet<String>,
    pub extensions: HashSet<String>,
}
fn allowed(r: &Requirement, env: Option<&Environment>) -> bool {
    let Some(e) = env else { return true };
    let core =
        (r.version != u32::MAX && r.version <= e.version && (r.last == 0 || e.version <= r.last))
            || (r.version == u32::MAX && r.extensions.is_empty() && !r.capabilities.is_empty());
    let ext = r.extensions.iter().any(|x| e.extensions.contains(*x));
    (core || ext)
        && (r.capabilities.is_empty() || r.capabilities.iter().any(|x| e.capabilities.contains(*x)))
}
pub fn definition(op: u16) -> Option<&'static Definition> {
    let index = OPCODE_INDEX.binary_search_by_key(&op, |&(opcode, _)| opcode).ok()?;
    Some(&DEFINITIONS[OPCODE_INDEX[index].1 as usize])
}
pub fn definition_by_name(name: &str) -> Option<&'static Definition> {
    DEFINITIONS
        .iter()
        .find(|d| d.name == name || d.aliases.contains(&name))
}
fn kind(name: &str) -> Result<&'static Kind, String> {
    KINDS
        .iter()
        .find(|k| k.name == name)
        .ok_or_else(|| format!("unknown operand kind {name}"))
}
fn enum_parameters(k: &Kind, n: u32, env: Option<&Environment>) -> Result<Vec<Spec>, String> {
    if k.category == 4 {
        let e = k
            .enumerants
            .iter()
            .find(|e| e.value == n)
            .ok_or("unknown enumerant")?;
        if !allowed(&e.requirements, env) {
            return Err("unavailable enumerant".into());
        }
        return Ok(e.parameters.to_vec());
    }
    let mut remaining = n;
    let mut seen = HashSet::new();
    let mut out = vec![];
    for e in k.enumerants {
        if !seen.insert(e.value) {
            continue;
        }
        if (e.value == 0 && n == 0) || (e.value != 0 && n & e.value == e.value) {
            remaining &= !e.value;
            if !allowed(&e.requirements, env) {
                return Err("unavailable mask bit".into());
            }
            out.extend_from_slice(e.parameters)
        }
    }
    if remaining != 0 {
        return Err("unknown mask bits".into());
    }
    Ok(out)
}
fn enum_text(k: &Kind, n: u32) -> String {
    if k.category != 3 || n == 0 {
        return k
            .enumerants
            .iter()
            .find(|e| e.value == n)
            .map_or_else(|| n.to_string(), |e| e.name.into());
    }
    let mut seen = HashSet::new();
    k.enumerants
        .iter()
        .filter(|e| e.value != 0 && n & e.value == e.value && seen.insert(e.value))
        .map(|e| e.name)
        .collect::<Vec<_>>()
        .join("|")
}
fn uint(s: &str) -> Result<u32, String> {
    let (s, radix) = if let Some(s) = s.strip_prefix("0x") {
        (s, 16)
    } else {
        (s, 10)
    };
    u32::from_str_radix(s, radix).map_err(|_| "invalid 32-bit integer".into())
}
fn enum_value(k: &Kind, s: &str) -> Result<u32, String> {
    if let Some(e) = k
        .enumerants
        .iter()
        .find(|e| e.name == s || e.aliases.contains(&s))
    {
        Ok(e.value)
    } else {
        uint(s)
    }
}
struct Decoder<'a> {
    env: Option<&'a Environment>,
    number_words: usize,
    switch_words: usize,
}
impl Decoder<'_> {
    fn sequence(
        &self,
        specs: &[Spec],
        words: &[u32],
        depth: usize,
    ) -> Result<(Vec<Operand>, usize), String> {
        if depth > 64 {
            return Err("operand nesting limit".into());
        }
        let mut out = vec![];
        let mut pos = 0;
        for s in specs {
            if s.quant != 0 && pos == words.len() {
                continue;
            }
            loop {
                let (o, n) = self.one(s.kind, &words[pos..], depth + 1)?;
                if n == 0 {
                    return Err("empty operand".into());
                }
                out.push(o);
                pos += n;
                if s.quant != 2 || pos == words.len() {
                    break;
                }
            }
        }
        Ok((out, pos))
    }
    fn one(&self, name: &str, words: &[u32], depth: usize) -> Result<(Operand, usize), String> {
        if depth > 64 {
            return Err("operand nesting limit".into());
        }
        let mut o = Operand::empty(name);
        let k = kind(name)?;
        if words.is_empty() {
            return Err(format!("missing {name}"));
        }
        if k.category == 2 {
            let mut pos = 0;
            for b in k.bases {
                if name == "PairLiteralIntegerIdRef"
                    && *b == "LiteralInteger"
                    && self.switch_words > 1
                {
                    let n = self.switch_words;
                    if n > words.len() - pos {
                        return Err("truncated wide switch literal".into());
                    }
                    let mut p = Operand::empty(b);
                    p.words = words[pos..pos + n].to_vec();
                    o.parameters.push(p);
                    pos += n;
                } else {
                    let (p, n) = self.one(b, &words[pos..], depth + 1)?;
                    o.parameters.push(p);
                    pos += n;
                }
            }
            return Ok((o, pos));
        }
        if name == "LiteralString" {
            let mut bytes = vec![];
            for (j, w) in words.iter().enumerate() {
                for n in 0..4 {
                    let ch = (w >> (n * 8)) as u8;
                    if ch == 0 {
                        if w >> (n * 8) != 0 {
                            return Err("nonzero string padding".into());
                        }
                        o.text = String::from_utf8(bytes).map_err(|_| "invalid UTF-8 string")?;
                        return Ok((o, j + 1));
                    }
                    bytes.push(ch)
                }
            }
            return Err("unterminated literal string".into());
        }
        let mut n = 1;
        if name == "LiteralContextDependentNumber" {
            n = if self.number_words == 0 {
                words.len()
            } else {
                self.number_words
            };
            if n > words.len() {
                return Err("truncated context-dependent number".into());
            }
        }
        o.words = words[..n].to_vec();
        if k.category == 0 && words[0] == 0 {
            return Err("zero ID".into());
        }
        let mut specs = vec![];
        if k.category == 3 || k.category == 4 {
            specs = enum_parameters(k, words[0], self.env)?
        }
        if name == "LiteralSpecConstantOpInteger" {
            let op = u16::try_from(words[0]).map_err(|_| "invalid embedded opcode")?;
            let d = definition(op).ok_or("unknown embedded opcode")?;
            if !allowed(&d.requirements, self.env) {
                return Err("embedded instruction unavailable".into());
            }
            specs.extend(
                d.operands
                    .iter()
                    .filter(|s| s.kind != "IdResult" && s.kind != "IdResultType")
                    .copied(),
            )
        }
        if !specs.is_empty() {
            let (p, used) = self.sequence(&specs, &words[n..], depth + 1)?;
            o.parameters = p;
            n += used;
        }
        Ok((o, n))
    }
}
fn decode_words(
    words: &[u32],
    ctx: Option<&Context>,
    env: Option<&Environment>,
) -> Result<Instruction, String> {
    if words.is_empty() || (words[0] >> 16) as usize != words.len() {
        return Err("inconsistent word count".into());
    }
    let op = words[0] as u16;
    let def = definition(op).ok_or("unknown opcode")?;
    if !allowed(&def.requirements, env) {
        return Err("instruction unavailable in environment".into());
    }
    let number_words = if words.len() > 1 && (op == 43 || op == 50) {
        ctx.map_or(0, |c| c.width(words[1]))
    } else {
        0
    };
    let switch_words = if words.len() > 1 && op == 251 {
        ctx.map_or(1, |c| {
            c.id_types.get(&words[1]).map_or(1, |t| c.width(*t).max(1))
        })
    } else {
        1
    };
    let d = Decoder {
        env,
        number_words,
        switch_words,
    };
    let (operands, n) = d.sequence(def.operands, &words[1..], 0)?;
    if n != words.len() - 1 {
        return Err("trailing operand words".into());
    }
    Ok(Instruction {
        opcode: op,
        operands,
    })
}
pub fn decode(
    data: &[u8],
    ctx: Option<&Context>,
    env: Option<&Environment>,
) -> Result<(Instruction, usize), String> {
    if data.len() < 4 {
        return Err("truncated header".into());
    }
    let count = (u32::from_le_bytes(data[..4].try_into().unwrap()) >> 16) as usize;
    if count == 0 || data.len() < count * 4 {
        return Err("invalid/truncated word count".into());
    }
    // Most instructions are short. Keep their byte-to-word conversion on the
    // stack; retain the unbounded path for strings and variadic instructions.
    let mut inline = [0u32; 16];
    let heap;
    let words = if count <= inline.len() {
        for (word, bytes) in inline.iter_mut().zip(data[..count * 4].chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().unwrap());
        }
        &inline[..count]
    } else {
        heap = data[..count * 4].chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap())).collect::<Vec<_>>();
        heap.as_slice()
    };
    Ok((decode_words(words, ctx, env)?, count * 4))
}
fn operand_words(o: &Operand) -> Result<Vec<u32>, String> {
    let k = kind(&o.kind)?;
    if o.kind == "LiteralString" {
        if !o.words.is_empty() || !o.parameters.is_empty() || o.text.as_bytes().contains(&0) {
            return Err("invalid literal string".into());
        }
        let mut bytes = o.text.as_bytes().to_vec();
        bytes.push(0);
        while bytes.len() % 4 != 0 {
            bytes.push(0)
        }
        return Ok(bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect());
    }
    if !o.text.is_empty()
        || (k.category == 2 && !o.words.is_empty())
        || (k.category != 2 && o.words.is_empty())
    {
        return Err("invalid structured operand".into());
    }
    let mut words = o.words.clone();
    for p in &o.parameters {
        words.extend(operand_words(p)?)
    }
    Ok(words)
}
pub fn encode(
    i: &Instruction,
    ctx: Option<&Context>,
    env: Option<&Environment>,
) -> Result<Vec<u8>, String> {
    let mut words = vec![0];
    for o in &i.operands {
        words.extend(operand_words(o)?)
    }
    if words.len() > 65535 {
        return Err("instruction exceeds 65535 words".into());
    }
    words[0] = (words.len() as u32) << 16 | i.opcode as u32;
    let d = decode_words(&words, ctx, env)?;
    if d != *i {
        return Err("structured operands do not match grammar".into());
    }
    Ok(words.iter().flat_map(|w| w.to_le_bytes()).collect())
}
fn quote(s: &str) -> String {
    let mut out = "\"".to_string();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn format_operand(o: &Operand) -> Result<Vec<String>, String> {
    let k = kind(&o.kind)?;
    if o.kind == "LiteralString" {
        return Ok(vec![quote(&o.text)]);
    }
    if k.category == 2 {
        let mut out = vec![];
        for p in &o.parameters {
            out.extend(format_operand(p)?)
        }
        return Ok(out);
    }
    let token = if k.category == 0 {
        format!("%{}", o.words[0])
    } else if k.category == 3 || k.category == 4 {
        enum_text(k, o.words[0])
    } else if o.kind == "LiteralSpecConstantOpInteger" {
        definition(o.words[0] as u16)
            .ok_or("unknown embedded opcode")?
            .name
            .trim_start_matches("Op")
            .into()
    } else if o.kind == "LiteralContextDependentNumber"
        || o.kind == "LiteralFloat"
        || o.words.len() > 1
    {
        return Ok(o.words.iter().map(|w| format!("!0x{w:08x}")).collect());
    } else if o.kind == "LiteralFloat" {
        f32::from_bits(o.words[0]).to_string()
    } else {
        o.words[0].to_string()
    };
    let mut out = vec![token];
    for p in &o.parameters {
        out.extend(format_operand(p)?)
    }
    Ok(out)
}
pub fn format_instruction(i: &Instruction) -> Result<String, String> {
    let d = definition(i.opcode).ok_or("unknown opcode")?;
    let mut result = String::new();
    let mut tokens = vec![d.name.to_string()];
    for o in &i.operands {
        if o.kind == "IdResult" {
            result = format!("%{} = ", o.words[0])
        } else {
            tokens.extend(format_operand(o)?)
        }
    }
    Ok(result + &tokens.join(" "))
}
fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let mut out = vec![];
    let b = s.as_bytes();
    let mut pos = 0;
    while pos < b.len() {
        while pos < b.len() && b[pos].is_ascii_whitespace() {
            pos += 1
        }
        if pos == b.len() || b[pos] == b';' {
            break;
        }
        let start = pos;
        if b[pos] == b'"' {
            pos += 1;
            while pos < b.len() && b[pos] != b'"' {
                if b[pos] == b'\\' {
                    pos += 1
                }
                pos += 1
            }
            if pos >= b.len() {
                return Err("unterminated quoted string".into());
            }
            pos += 1;
        } else {
            while pos < b.len() && !b[pos].is_ascii_whitespace() && b[pos] != b';' {
                pos += 1
            }
        }
        out.push(s[start..pos].to_string())
    }
    Ok(out)
}
fn unquote(s: &str) -> Result<String, String> {
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err("expected quoted literal string".into());
    }
    let mut out = String::new();
    let mut chars = s[1..s.len() - 1].chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next().ok_or("truncated escape")? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let mut n = 0;
                for _ in 0..4 {
                    n = n * 16
                        + chars
                            .next()
                            .and_then(|c| c.to_digit(16))
                            .ok_or("invalid unicode escape")?
                }
                out.push(char::from_u32(n).ok_or("invalid unicode scalar")?)
            }
            _ => return Err("invalid string escape".into()),
        }
    }
    Ok(out)
}
fn id(s: &str) -> Result<u32, String> {
    let n = s
        .strip_prefix('%')
        .ok_or("expected numeric ID")?
        .parse::<u32>()
        .map_err(|_| "invalid numeric ID")?;
    if n == 0 {
        Err("zero ID".into())
    } else {
        Ok(n)
    }
}
fn number(s: &str, n: usize, floating: bool) -> Result<Vec<u32>, String> {
    if n > 65535 {
        return Err("literal exceeds word-count limit".into());
    }
    if let Some(raw) = s.strip_prefix('!') {
        let out = raw
            .split(':')
            .map(|s| {
                u32::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map_err(|_| "invalid raw word".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if n != 0 && n != out.len() {
            return Err("literal width mismatch".into());
        }
        return Ok(out);
    }
    let n = n.max(1);
    if floating {
        let f = s.parse::<f64>().map_err(|_| "invalid floating literal")?;
        return match n {
            1 => Ok(vec![(f as f32).to_bits()]),
            2 => {
                let b = f.to_bits();
                Ok(vec![b as u32, (b >> 32) as u32])
            }
            _ => Err("use raw words for this floating width".into()),
        };
    }
    let negative = s.starts_with('-');
    let s = if negative { &s[1..] } else { s };
    let (s, radix) = if let Some(s) = s.strip_prefix("0x") {
        (s, 16u64)
    } else {
        (s, 10)
    };
    if s.is_empty() {
        return Err("invalid integer".into());
    }
    let mut out = vec![0u32; n];
    for c in s.chars() {
        let d = c.to_digit(radix as u32).ok_or("invalid integer digit")? as u64;
        let mut carry = d;
        for w in &mut out {
            let v = *w as u64 * radix + carry;
            *w = v as u32;
            carry = v >> 32
        }
        if carry != 0 {
            return Err("integer overflow".into());
        }
    }
    if negative {
        let mut carry = 1u64;
        for w in &mut out {
            let v = (!*w) as u64 + carry;
            *w = v as u32;
            carry = v >> 32
        }
    }
    Ok(out)
}
struct TextParser<'a> {
    tokens: Vec<String>,
    pos: usize,
    ctx: Option<&'a Context>,
    env: Option<&'a Environment>,
    type_id: u32,
    switch_words: usize,
}
impl TextParser<'_> {
    fn raw_tokens(&mut self, mut token: String, width: usize) -> String {
        if !token.starts_with('!') || token.contains(':') {
            return token;
        }
        let mut count = 1;
        while self.pos < self.tokens.len()
            && (width == 0 || count < width)
            && self.tokens[self.pos].starts_with('!')
        {
            token.push(':');
            token.push_str(self.tokens[self.pos].trim_start_matches('!'));
            self.pos += 1;
            count += 1;
        }
        token
    }
    fn one(&mut self, name: &str, depth: usize) -> Result<Operand, String> {
        if depth > 64 {
            return Err("operand nesting limit".into());
        }
        let k = kind(name)?;
        let mut o = Operand::empty(name);
        if k.category == 2 {
            for b in k.bases {
                let p = if name == "PairLiteralIntegerIdRef"
                    && *b == "LiteralInteger"
                    && self.switch_words > 1
                {
                    let token = self
                        .tokens
                        .get(self.pos)
                        .ok_or("missing switch literal")?
                        .clone();
                    self.pos += 1;
                    let token = self.raw_tokens(token, self.switch_words);
                    let mut p = Operand::empty(b);
                    p.words = number(&token, self.switch_words, false)?;
                    p
                } else {
                    self.one(b, depth + 1)?
                };
                o.parameters.push(p)
            }
            return Ok(o);
        }
        let token = self
            .tokens
            .get(self.pos)
            .ok_or_else(|| format!("missing {name}"))?
            .clone();
        self.pos += 1;
        if name == "LiteralString" {
            o.text = unquote(&token)?;
            return Ok(o);
        }
        let mut n = 0;
        let mut params = vec![];
        if k.category == 0 {
            n = id(&token)?
        } else if k.category == 3 || k.category == 4 {
            if k.category == 4 && token.contains('|') {
                return Err("value enum is not a bitmask".into());
            }
            for s in token.split('|') {
                n |= enum_value(k, s)?
            }
            params = enum_parameters(k, n, self.env)?
        } else if name == "LiteralSpecConstantOpInteger" {
            let full = if token.starts_with("Op") {
                token.clone()
            } else {
                format!("Op{token}")
            };
            let d = definition_by_name(&full)
                .or_else(|| {
                    uint(&token)
                        .ok()
                        .and_then(|v| u16::try_from(v).ok())
                        .and_then(definition)
                })
                .ok_or("unknown embedded opcode")?;
            n = d.opcode as u32;
            params.extend(
                d.operands
                    .iter()
                    .filter(|s| s.kind != "IdResult" && s.kind != "IdResultType")
                    .copied(),
            )
        } else if name == "LiteralContextDependentNumber" {
            let width = self.ctx.map_or(0, |c| c.width(self.type_id));
            let token = self.raw_tokens(token, width);
            let floating = self
                .ctx
                .is_some_and(|c| c.float_types.contains(&self.type_id));
            o.words = number(&token, width, floating)?;
            if floating && !token.starts_with('!') {
                let c = self.ctx.unwrap();
                let bits = c.type_widths[&self.type_id];
                if let Some(encoding) = c.float_encodings.get(&self.type_id) {
                    if *encoding == 0 && bits == 16 {
                        let w = token.parse::<f32>().map_err(|_| "invalid float")?.to_bits();
                        o.words = vec![w.wrapping_add(0x7fff + ((w >> 16) & 1)) >> 16]
                    } else {
                        return Err("use raw words for extension floating encoding".into());
                    }
                } else if bits == 16 {
                    o.words = vec![
                        float16_bits(token.parse::<f32>().map_err(|_| "invalid float")?) as u32,
                    ]
                } else if bits != 32 && bits != 64 {
                    return Err("use raw words for this floating width".into());
                }
            }
        } else if name == "LiteralFloat" {
            o.words = number(&token, 1, true)?
        } else if token.starts_with('!') {
            o.words = number(&token, 0, false)?
        } else {
            n = uint(&token)?
        }
        if o.words.is_empty() {
            o.words.push(n)
        }
        for s in params {
            if s.quant != 0 && self.pos == self.tokens.len() {
                continue;
            }
            loop {
                o.parameters.push(self.one(s.kind, depth + 1)?);
                if s.quant != 2 || self.pos == self.tokens.len() {
                    break;
                }
            }
        }
        Ok(o)
    }
}
pub fn assemble(
    text: &str,
    ctx: Option<&Context>,
    env: Option<&Environment>,
) -> Result<Instruction, String> {
    let mut tokens = tokenize(text)?;
    if tokens.is_empty() {
        return Err("empty instruction".into());
    }
    let mut result = None;
    if tokens.len() > 2 && tokens[1] == "=" {
        result = Some(id(&tokens[0])?);
        tokens.drain(..2);
    }
    let d = definition_by_name(&tokens[0]).ok_or("unknown instruction")?;
    tokens.remove(0);
    let mut p = TextParser {
        tokens,
        pos: 0,
        ctx,
        env,
        type_id: 0,
        switch_words: 1,
    };
    let mut operands = vec![];
    for s in d.operands {
        if s.kind == "IdResult" {
            operands.push(Operand::scalar(
                s.kind,
                result.take().ok_or("missing result assignment")?,
            ));
            continue;
        }
        if s.quant != 0 && p.pos == p.tokens.len() {
            continue;
        }
        loop {
            let o = p.one(s.kind, 0)?;
            if s.kind == "IdResultType" {
                p.type_id = o.words[0]
            }
            if d.opcode == 251 && operands.is_empty() {
                p.switch_words = ctx.map_or(1, |c| {
                    c.id_types
                        .get(&o.words[0])
                        .map_or(1, |t| c.width(*t).max(1))
                })
            }
            operands.push(o);
            if s.quant != 2 || p.pos == p.tokens.len() {
                break;
            }
        }
    }
    if result.is_some() || p.pos != p.tokens.len() {
        return Err("unexpected assembly operands".into());
    }
    let i = Instruction {
        opcode: d.opcode,
        operands,
    };
    encode(&i, ctx, env)?;
    Ok(i)
}
#[derive(Clone, Debug)]
pub struct Module {
    pub version: u32,
    pub generator: u32,
    pub bound: u32,
    pub instructions: Vec<Instruction>,
}
fn check_ids(operands: &[Operand], bound: u32, defined: &mut HashSet<u32>) -> Result<(), String> {
    for o in operands {
        if kind(&o.kind)?.category == 0 {
            let id = o.words[0];
            if id >= bound {
                return Err("ID exceeds module bound".into());
            }
            if o.kind == "IdResult" && !defined.insert(id) {
                return Err("duplicate result ID".into());
            }
        }
        check_ids(&o.parameters, bound, defined)?
    }
    Ok(())
}
pub fn decode_module(data: &[u8]) -> Result<Module, String> {
    if data.len() < 20 || data.len() % 4 != 0 {
        return Err("invalid module length".into());
    }
    let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
    let big = match magic {
        0x07230203 => false,
        0x03022307 => true,
        _ => return Err("invalid module magic".into()),
    };
    let words = data
        .chunks_exact(4)
        .map(|b| {
            if big {
                u32::from_be_bytes(b.try_into().unwrap())
            } else {
                u32::from_le_bytes(b.try_into().unwrap())
            }
        })
        .collect::<Vec<_>>();
    if words[1] & 0xff0000ff != 0
        || words[1] >> 16 != GRAMMAR_MAJOR
        || (words[1] >> 8) & 255 > GRAMMAR_MINOR
        || words[3] == 0
        || words[4] != 0
    {
        return Err("invalid module header".into());
    }
    let mut m = Module {
        version: words[1],
        generator: words[2],
        bound: words[3],
        instructions: vec![],
    };
    let mut pos = 5;
    let mut ctx = Context::default();
    let mut defined = HashSet::new();
    while pos < words.len() {
        let n = (words[pos] >> 16) as usize;
        if n == 0 || n > words.len() - pos {
            return Err("invalid module instruction length".into());
        }
        let i = decode_words(&words[pos..pos + n], Some(&ctx), None)?;
        check_ids(&i.operands, m.bound, &mut defined)?;
        ctx.observe(&i);
        m.instructions.push(i);
        pos += n;
    }
    validate_requirements(&m)?;
    Ok(m)
}
pub fn encode_module(m: &Module) -> Result<Vec<u8>, String> {
    let mut out = vec![];
    for n in [0x07230203, m.version, m.generator, m.bound, 0] {
        out.extend(n.to_le_bytes())
    }
    let mut ctx = Context::default();
    for i in &m.instructions {
        out.extend(encode(i, Some(&ctx), None)?);
        ctx.observe(i)
    }
    decode_module(&out)?;
    Ok(out)
}

/// Checks declared grammar requirements, including implied capabilities.
pub fn validate_requirements(m: &Module) -> Result<(), String> {
    let mut env = Environment {
        version: m.version,
        ..Environment::default()
    };
    let caps = kind("Capability")?;
    fn enable(name: &str, caps: &Kind, set: &mut HashSet<String>) {
        if !set.insert(name.into()) {
            return;
        }
        if let Some(e) = caps.enumerants.iter().find(|e| e.name == name) {
            for c in e.requirements.capabilities {
                enable(c, caps, set)
            }
        }
    }
    for i in &m.instructions {
        if i.opcode == 10 && !i.operands.is_empty() {
            env.extensions.insert(i.operands[0].text.clone());
        }
        if i.opcode == 17 && !i.operands.is_empty() {
            if let Some(e) = caps
                .enumerants
                .iter()
                .find(|e| e.value == i.operands[0].words[0])
            {
                enable(e.name, caps, &mut env.capabilities)
            }
        }
    }
    fn check(operands: &[Operand], env: &Environment) -> Result<(), String> {
        for o in operands {
            let k = kind(&o.kind)?;
            if k.category == 3 || k.category == 4 {
                enum_parameters(k, o.words[0], Some(env))?;
            }
            check(&o.parameters, env)?;
        }
        Ok(())
    }
    for i in &m.instructions {
        let d = definition(i.opcode).ok_or("unknown opcode")?;
        if !allowed(&d.requirements, Some(&env)) {
            return Err("instruction unavailable in declared module environment".into());
        }
        check(&i.operands, &env)?;
    }
    Ok(())
}

/// Resolves symbolic IDs across a full assembly module, preserving numeric IDs.
pub fn assemble_module(text: &str, version: u32, generator: u32) -> Result<Module, String> {
    let mut lines = vec![];
    let mut used = HashSet::new();
    for line in text.lines() {
        let tokens = tokenize(line)?;
        if tokens.is_empty() {
            continue;
        }
        for token in &tokens {
            if token.starts_with('%') {
                if let Ok(n) = id(token) {
                    used.insert(n);
                }
            }
        }
        lines.push(tokens)
    }
    let mut symbols = HashMap::<String, u32>::new();
    let mut next = 1u32;
    let mut bound = 1;
    let mut ctx = Context::default();
    let mut instructions = vec![];
    for mut tokens in lines {
        for token in &mut tokens {
            if !token.starts_with('%') {
                continue;
            }
            let n = if let Ok(n) = id(token) {
                n
            } else {
                let name = &token[1..];
                if name.is_empty()
                    || name.bytes().all(|c| c.is_ascii_digit())
                    || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                {
                    return Err("invalid symbolic ID".into());
                }
                if let Some(n) = symbols.get(token) {
                    *n
                } else {
                    while used.contains(&next) {
                        next = next.checked_add(1).ok_or("ID space exhausted")?
                    }
                    let n = next;
                    symbols.insert(token.clone(), n);
                    used.insert(n);
                    n
                }
            };
            bound = bound.max(n.checked_add(1).ok_or("ID bound overflow")?);
            *token = format!("%{n}");
        }
        let i = assemble(&tokens.join(" "), Some(&ctx), None)?;
        ctx.observe(&i);
        instructions.push(i)
    }
    let m = Module {
        version,
        generator,
        bound,
        instructions,
    };
    encode_module(&m)?;
    Ok(m)
}
pub fn format_module(m: &Module) -> Result<String, String> {
    let mut out = String::new();
    for i in &m.instructions {
        out.push_str(&format_instruction(i)?);
        out.push('\n')
    }
    Ok(out)
}

fn float16_bits(v: f32) -> u16 {
    let b = v.to_bits();
    let sign = ((b >> 16) as u16) & 0x8000;
    let mut exp = ((b >> 23) & 255) as i32 - 127 + 15;
    let mut mant = b & 0x7fffff;
    if (b >> 23) & 255 == 255 {
        if mant == 0 {
            return sign | 0x7c00;
        }
        return sign | 0x7c00 | ((mant >> 13) as u16) | 1;
    }
    if exp >= 31 {
        return sign | 0x7c00;
    }
    if exp <= 0 {
        if exp < -10 {
            return sign;
        }
        mant |= 0x800000;
        let shift = (14 - exp) as u32;
        let rounded = (mant + ((1u32 << (shift - 1)) - 1) + ((mant >> shift) & 1)) >> shift;
        return sign | rounded as u16;
    }
    mant += 0xfff + ((mant >> 13) & 1);
    if mant & 0x800000 != 0 {
        mant = 0;
        exp += 1;
        if exp >= 31 {
            return sign | 0x7c00;
        }
    }
    sign | ((exp << 10) as u16) | ((mant >> 13) as u16)
}

/// Structured operand templates preserve composite/enum parameters, strings and
/// wide values. A prototype determines optional/variadic shape; repeated names
/// bind equal operands. Encoding validates substitutions against module context.
#[derive(Clone, Debug)]
pub struct InstructionTemplate {
    prototype: Instruction,
    holes: HashMap<usize, String>,
}
impl InstructionTemplate {
    pub fn new(prototype: Instruction, holes: &[(usize, &str)]) -> Result<Self, String> {
        definition(prototype.opcode).ok_or("unknown template opcode")?;
        let mut bindings = HashMap::new();
        for &(index, name) in holes {
            if index >= prototype.operands.len()
                || name.is_empty()
                || bindings.insert(index, name.to_owned()).is_some()
            {
                return Err("invalid template hole".into());
            }
        }
        Ok(Self {
            prototype,
            holes: bindings,
        })
    }
    pub fn match_instruction(&self, instruction: &Instruction) -> Option<HashMap<String, Operand>> {
        if instruction.opcode != self.prototype.opcode
            || instruction.operands.len() != self.prototype.operands.len()
        {
            return None;
        }
        let mut captures = HashMap::<String, Operand>::new();
        for (index, value) in instruction.operands.iter().enumerate() {
            if let Some(name) = self.holes.get(&index) {
                if captures.get(name).is_some_and(|previous| previous != value) {
                    return None;
                }
                captures.insert(name.clone(), value.clone());
            } else if &self.prototype.operands[index] != value {
                return None;
            }
        }
        Some(captures)
    }
    pub fn match_bytes(
        &self,
        data: &[u8],
        ctx: Option<&Context>,
        env: Option<&Environment>,
    ) -> Result<(HashMap<String, Operand>, usize), String> {
        let (instruction, length) = decode(data, ctx, env)?;
        Ok((
            self.match_instruction(&instruction)
                .ok_or("instruction does not match template")?,
            length,
        ))
    }
    pub fn encode(
        &self,
        bindings: &HashMap<String, Operand>,
        ctx: Option<&Context>,
        env: Option<&Environment>,
    ) -> Result<Vec<u8>, String> {
        let mut instruction = self.prototype.clone();
        let mut used = HashSet::new();
        for (&index, name) in &self.holes {
            instruction.operands[index] = bindings
                .get(name)
                .ok_or("missing template binding")?
                .clone();
            used.insert(name);
        }
        if used.len() != bindings.len() {
            return Err("unknown template binding".into());
        }
        encode(&instruction, ctx, env)
    }
}
#[cfg(test)]
mod template_tests {
    use super::*;
    #[test]
    fn repeated_structured_operands() {
        let prototype = assemble("%3 = OpIAdd %1 %4 %4", None, None).unwrap();
        let template =
            InstructionTemplate::new(prototype.clone(), &[(2, "input"), (3, "input")]).unwrap();
        let bytes = encode(&prototype, None, None).unwrap();
        let (captures, length) = template.match_bytes(&bytes, None, None).unwrap();
        assert_eq!(length, bytes.len());
        assert_eq!(captures["input"], Operand::scalar("IdRef", 4));
        let bindings = HashMap::from([("input".into(), Operand::scalar("IdRef", 9))]);
        let expected = assemble("%3 = OpIAdd %1 %9 %9", None, None).unwrap();
        assert_eq!(
            template.encode(&bindings, None, None).unwrap(),
            encode(&expected, None, None).unwrap()
        );
        let mut different = expected.clone();
        different.operands[3].words[0] = 10;
        assert!(template.match_instruction(&different).is_none());
        let invalid = HashMap::from([("input".into(), Operand::scalar("IdRef", 0))]);
        assert!(template.encode(&invalid, None, None).is_err());
    }
}
