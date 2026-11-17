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
fn error(s: &str) -> Error {
    Error(format!("PTX: {s}"))
}
#[derive(Debug)]
pub struct Document {
    pub id: &'static str,
    pub kind: &'static str,
    pub section: &'static str,
    pub names: &'static [&'static str],
    pub syntax: &'static [&'static str],
    pub examples: &'static [&'static str],
    pub requirements: &'static [&'static str],
    pub min_version: u32,
    pub min_target: u32,
}
#[derive(Debug)]
pub struct OperandDefinition {
    pub name: &'static str,
    pub class_name: &'static str,
}
#[derive(Debug)]
pub struct LLVMRecord {
    pub id: &'static str,
    pub syntax: &'static str,
    pub pseudo: bool,
    pub namespace: &'static str,
    pub features: &'static [&'static str],
    pub operands: &'static [OperandDefinition],
    pub constraints: &'static str,
    pub locations: &'static [&'static str],
}
#[derive(Debug, Clone)]
pub struct Token<'a> {
    pub kind: &'static str,
    pub text: &'a str,
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}
#[derive(Debug, Clone)]
pub struct Node<'a> {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
    pub tokens: Vec<Token<'a>>,
    pub children: Vec<Node<'a>>,
}
#[derive(Debug, Clone)]
pub struct Operand<'a> {
    pub kind: &'static str,
    pub text: &'a str,
    pub tokens: Vec<Token<'a>>,
}
#[derive(Debug, Clone)]
pub struct Instruction<'a> {
    pub opcode: &'a str,
    pub mnemonic: &'a str,
    pub modifiers: Vec<&'a str>,
    pub predicate: Option<&'a str>,
    pub negated: bool,
    pub operands: Vec<Operand<'a>>,
    pub start: usize,
    pub end: usize,
}
#[derive(Debug)]
pub struct Module<'a> {
    pub source: &'a str,
    pub tokens: Vec<Token<'a>>,
    pub nodes: Vec<Node<'a>>,
    pub instructions: Vec<Instruction<'a>>,
    pub version: &'a str,
    pub targets: Vec<&'a str>,
    pub address_size: u32,
}
fn ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || b"_$%".contains(&c)
}
fn ident_part(c: u8) -> bool {
    ident_start(c) || c.is_ascii_digit() || c == b'.'
}
pub fn lex(source: &str) -> Result<Vec<Token<'_>>> {
    if source.contains('\0') {
        return Err(error("NUL in source"));
    }
    let b = source.as_bytes();
    let mut out = vec![];
    let (mut i, mut line, mut column) = (0, 1, 1);
    while i < b.len() {
        let (start, l, c) = (i, line, column);
        let ch = b[i];
        if ch == 0 {
            return Err(error("NUL in source"));
        }
        let kind;
        if b" \t\r\n".contains(&ch) {
            kind = "whitespace";
            i += 1;
            while i < b.len() && b" \t\r\n".contains(&b[i]) {
                i += 1
            }
        } else if b.get(i..i + 2) == Some(b"//") {
            kind = "comment";
            i += 2;
            while i < b.len() && b[i] != b'\n' {
                i += 1
            }
        } else if b.get(i..i + 2) == Some(b"/*") {
            kind = "comment";
            i += 2;
            loop {
                if i + 1 >= b.len() {
                    return Err(error("unterminated block comment"));
                }
                if &b[i..i + 2] == b"*/" {
                    i += 2;
                    break;
                }
                i += 1
            }
        } else if ch == b'"' {
            kind = "string";
            i += 1;
            loop {
                if i >= b.len() {
                    return Err(error("unterminated string"));
                }
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == b'"' {
                    i += 1;
                    break;
                }
                if b[i] == b'\n' || b[i] == b'\r' {
                    return Err(error("newline in string"));
                }
                i += 1
            }
        } else if ident_start(ch)
            || ch == b'.' && b.get(i + 1).copied().map(ident_start).unwrap_or(false)
        {
            kind = if ch == b'%' {
                "register"
            } else if ch == b'.' {
                "directive"
            } else {
                "identifier"
            };
            i += 1;
            while i < b.len() {
                if ident_part(b[i]) {
                    i += 1
                } else if b.get(i..i + 2) == Some(b"::") {
                    i += 2
                } else {
                    break;
                }
            }
        } else if ch.is_ascii_digit()
            || ch == b'.' && b.get(i + 1).map(|b| b.is_ascii_digit()).unwrap_or(false)
        {
            kind = "number";
            i += 1;
            while i < b.len() && (ident_part(b[i]) || b"+-".contains(&b[i])) {
                if b"+-".contains(&b[i]) && !b"eE".contains(&b[i - 1]) {
                    break;
                }
                i += 1
            }
        } else {
            kind = "punctuation";
            if ch >= 128 {
                return Err(error("non-ASCII unquoted token"));
            }
            i += 1;
            if let Some(a) = b.get(start..i + 1) {
                if [
                    b"::", b"<<", b">>", b"<=", b">=", b"==", b"!=", b"&&", b"||",
                ]
                .iter()
                .any(|s| *s == a)
                {
                    i += 1
                }
            }
        }
        let text = source
            .get(start..i)
            .ok_or_else(|| error("invalid string boundary"))?;
        for v in text.chars() {
            if v == '\n' {
                line += 1;
                column = 1
            } else {
                column += 1
            }
        }
        out.push(Token {
            kind,
            text,
            start,
            end: i,
            line: l,
            column: c,
        })
    }
    Ok(out)
}
fn semicolon_directive(s: &str) -> bool {
    [
        ".reg", ".sreg", ".param", ".local", ".shared", ".global", ".const", ".tex", ".surf",
        ".sampler", ".visible", ".extern", ".weak", ".common", ".align",
        ".alias", ".branchtargets", ".calltargets", ".callprototype", ".pragma", ".minperctamemory",
    ]
    .contains(&s)
}
fn matching(a: &str, b: &str) -> bool {
    matches!((a, b), ("(", ")") | ("[", "]") | ("{", "}"))
}
struct Parser<'a> {
    source: &'a str,
    tokens: Vec<Token<'a>>,
    at: usize,
    instructions: Vec<Instruction<'a>>,
    depth: usize,
}
impl<'a> Parser<'a> {
    fn fail(&self, s: &str) -> Error {
        if let Some(t) = self.tokens.get(self.at) {
            error(&format!("{}:{}: {}", t.line, t.column, s))
        } else {
            error(&format!("EOF: {s}"))
        }
    }
    fn nodes(&mut self, block: bool) -> Result<Vec<Node<'a>>> {
        self.depth += 1;
        if self.depth > 256 {
            return Err(self.fail("scope nesting limit"));
        }
        let result = self.nodes_inner(block);
        self.depth -= 1;
        result
    }
    fn nodes_inner(&mut self, block: bool) -> Result<Vec<Node<'a>>> {
        let mut out: Vec<Node<'a>> = vec![];
        while self.at < self.tokens.len() {
            if self.tokens[self.at].text == "}" {
                if !block {
                    return Err(self.fail("unmatched closing brace"));
                }
                self.at += 1;
                return Ok(out);
            }
            if self.tokens[self.at].text == "{" {
                let start = self.tokens[self.at].start;
                self.at += 1;
                let children = self.nodes(true)?;
                out.push(Node {
                    kind: "scope",
                    start,
                    end: self.tokens[self.at - 1].end,
                    tokens: vec![],
                    children,
                });
                continue;
            }
            let start = self.at;
            let mut depth = vec![];
            let kind = if self.tokens[start].kind == "directive" {
                "directive"
            } else {
                "instruction"
            };
            let (mut function, mut finished) = (false, false);
            while self.at < self.tokens.len() {
                let t = self.tokens[self.at].clone();
                if depth.is_empty()
                    && self.at > start
                    && kind == "directive"
                    && t.line > self.tokens[self.at - 1].line
                    && !function
                    && !semicolon_directive(self.tokens[start].text)
                {
                    finished = true;
                    break;
                }
                if t.text == ".entry" || t.text == ".func" {
                    function = true
                }
                if depth.is_empty() && t.text == "{" && function {
                    let header = self.tokens[start..self.at].to_vec();
                    self.at += 1;
                    let children = self.nodes(true)?;
                    out.push(Node {
                        kind: "function",
                        start: self.tokens[start].start,
                        end: self.tokens[self.at - 1].end,
                        tokens: header,
                        children,
                    });
                    finished = true;
                    break;
                }
                if depth.is_empty() && t.text == ":" {
                    self.at += 1;
                    out.push(Node {
                        kind: "label",
                        start: self.tokens[start].start,
                        end: t.end,
                        tokens: self.tokens[start..self.at].to_vec(),
                        children: vec![],
                    });
                    finished = true;
                    break;
                }
                if depth.is_empty() && t.text == ";" {
                    self.at += 1;
                    finished = true;
                    break;
                }
                if ["(", "[", "{"].contains(&t.text) {
                    depth.push(t.text);
                    if depth.len() > 256 {
                        return Err(self.fail("delimiter nesting limit"));
                    }
                } else if [")", "]", "}"].contains(&t.text) {
                    let a = depth
                        .pop()
                        .ok_or_else(|| self.fail("mismatched delimiter or missing semicolon"))?;
                    if !matching(a, t.text) {
                        return Err(self.fail("mismatched delimiter"));
                    }
                }
                self.at += 1
            }
            if out
                .last()
                .map(|n| {
                    (n.kind == "function" || n.kind == "label")
                        && n.start == self.tokens[start].start
                })
                .unwrap_or(false)
            {
                continue;
            }
            if !depth.is_empty() {
                return Err(self.fail("unclosed operand delimiter"));
            }
            if self.at == start {
                return Err(self.fail("empty statement"));
            }
            if !finished && (kind == "instruction" || (kind == "directive" && semicolon_directive(self.tokens[start].text))) {
                return Err(self.fail("statement missing semicolon"));
            }
            let tokens = self.tokens[start..self.at].to_vec();
            if kind == "instruction" {
                self.instructions.push(instruction(self.source, &tokens)?)
            }
            out.push(Node {
                kind,
                start: tokens[0].start,
                end: tokens.last().unwrap().end,
                tokens,
                children: vec![],
            })
        }
        if block {
            return Err(self.fail("unclosed scope"));
        }
        Ok(out)
    }
}
fn instruction<'a>(source: &'a str, t: &[Token<'a>]) -> Result<Instruction<'a>> {
    let mut i = 0;
    let (mut predicate, mut negated) = (None, false);
    if t[i].text == "@" {
        i += 1;
        if t.get(i).map(|t| t.text) == Some("!") {
            negated = true;
            i += 1
        }
        let p = t.get(i).ok_or_else(|| error("invalid predicate"))?;
        if p.kind != "register" && p.kind != "identifier" {
            return Err(error("invalid predicate"));
        }
        predicate = Some(p.text);
        i += 1
    }
    let opcode = t.get(i).ok_or_else(|| error("missing opcode"))?;
    if opcode.kind != "identifier" {
        return Err(error("invalid opcode"));
    }
    let parts = opcode.text.split('.').collect::<Vec<_>>();
    let mut out = Instruction {
        opcode: opcode.text,
        mnemonic: parts[0],
        modifiers: parts[1..].to_vec(),
        predicate,
        negated,
        operands: vec![],
        start: t[0].start,
        end: t.last().unwrap().end,
    };
    i += 1;
    let mut end = t.len();
    if t[end - 1].text == ";" {
        end -= 1
    }
    let (mut start, mut depth) = (i, 0);
    for j in i..=end {
        if j == end || t[j].text == "," && depth == 0 {
            if start < j {
                let a = &t[start..j];
                let kind = if a.len() == 1 {
                    a[0].kind
                } else {
                    match a[0].text {
                        "[" => "address",
                        "{" => "vector",
                        "(" => "tuple",
                        _ => "expression",
                    }
                };
                out.operands.push(Operand {
                    kind,
                    text: &source[a[0].start..a.last().unwrap().end],
                    tokens: a.to_vec(),
                })
            } else if j != end || j > i {
                return Err(error("empty operand"));
            }
            start = j + 1
        } else if ["(", "[", "{"].contains(&t[j].text) {
            depth += 1
        } else if [")", "]", "}"].contains(&t[j].text) {
            depth -= 1
        }
    }
    Ok(out)
}
pub fn decode(source: &str) -> Result<Module<'_>> {
    let tokens = lex(source)?;
    let mut has_address = false;
    let sig = tokens
        .iter()
        .filter(|t| t.kind != "whitespace" && t.kind != "comment")
        .cloned()
        .collect();
    let mut p = Parser {
        source,
        tokens: sig,
        at: 0,
        instructions: vec![],
        depth: 0,
    };
    let nodes = p.nodes(false)?;
    let (mut version, mut targets, mut address_size) = ("", vec![], 0);
    for n in &nodes {
        if n.kind != "directive" || n.tokens.len() < 2 {
            continue;
        }
        match n.tokens[0].text {
            ".version" => {
                if !version.is_empty() {
                    return Err(error("duplicate .version"));
                }
                version = n.tokens[1].text
            }
            ".target" => {
                if !targets.is_empty() {
                    return Err(error("duplicate .target"));
                }
                targets = n.tokens[1..]
                    .iter()
                    .filter(|t| t.text != "," && t.text != ";")
                    .map(|t| t.text)
                    .collect()
            }
            ".address_size" => {
                if has_address {
                    return Err(error("duplicate .address_size"));
                }
                has_address = true;
                address_size = n.tokens[1]
                    .text
                    .parse()
                    .map_err(|_| error("invalid .address_size integer"))?
            }
            _ => {}
        }
    }
    if !has_address {
        address_size = 32
    }
    Ok(Module {
        source,
        tokens,
        nodes,
        instructions: p.instructions,
        version,
        targets,
        address_size,
    })
}
impl Module<'_> {
    pub fn encode(&self) -> &str {
        self.source
    }
    pub fn replace(&self, start: usize, end: usize, text: &str) -> Result<String> {
        if start > end || !self.source.is_char_boundary(start) || !self.source.is_char_boundary(end)
        {
            return Err(error("replacement span out of bounds"));
        }
        let mut s = self.source[..start].to_string();
        s.push_str(text);
        s.push_str(&self.source[end..]);
        decode(&s)?;
        Ok(s)
    }
    pub fn replace_operand(&self, ins: usize, operand: usize, text: &str) -> Result<String> {
        let a = self
            .instructions
            .get(ins)
            .and_then(|i| i.operands.get(operand))
            .ok_or_else(|| error("operand index"))?;
        self.replace(a.tokens[0].start, a.tokens.last().unwrap().end, text)
    }
}
#[derive(Debug, Clone)]
pub struct Hole {
    pub name: String,
    pub format: String,
    pub start: usize,
    pub end: usize,
}
#[derive(Debug, Clone)]
pub struct Template {
    pub pattern: String,
    pub holes: Vec<Hole>,
}
impl Template {
    /// Captures rendered template text. This does not assert ISA legality.
    pub fn matches(&self,text:&str)->Option<BTreeMap<String,String>>{
        fn run(t:&Template,index:usize,at:usize,rest:&str,values:&mut BTreeMap<String,String>)->bool{
            if index==t.holes.len(){return rest==t.pattern[at..].replace("$$","$");}
            let h=&t.holes[index];let literal=t.pattern[at..h.start].replace("$$","$");let Some(rest)=rest.strip_prefix(&literal)else{return false;};let key=if h.format.is_empty(){h.name.clone()}else{format!("{}:{}",h.name,h.format)};
            if let Some(value)=values.get(&key){let Some(tail)=rest.strip_prefix(value.as_str())else{return false;};return run(t,index+1,h.end,tail,values);}
            let end=t.holes.get(index+1).map_or(t.pattern.len(),|next|next.start);let next=t.pattern[h.end..end].replace("$$","$");
            for n in rest.char_indices().map(|(n,_)|n).chain(std::iter::once(rest.len())){if !rest[n..].starts_with(&next){continue;}values.insert(key.clone(),rest[..n].to_owned());if run(t,index+1,h.end,&rest[n..],values){return true;}}
            values.remove(&key);false
        }
        let mut values=BTreeMap::new();run(self,0,0,text,&mut values).then_some(values)
    }
    pub fn compile(pattern: &str) -> Result<Self> {
        let b = pattern.as_bytes();
        let mut holes = vec![];
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'$' {
                i += 1;
                continue;
            }
            let start = i;
            i += 1;
            if i == b.len() {
                return Err(error("trailing template dollar"));
            }
            if b[i] == b'$' {
                i += 1;
                continue;
            }
            let (name, format);
            if b[i] == b'{' {
                let end = pattern[i + 1..]
                    .find('}')
                    .ok_or_else(|| error("unclosed template hole"))?
                    + i
                    + 1;
                let body = &pattern[i + 1..end];
                let (a, f) = body.split_once(':').unwrap_or((body, ""));
                name = a.to_string();
                format = f.to_string();
                i = end + 1
            } else {
                let a = i;
                while i < b.len()
                    && (ident_start(b[i]) && b[i] != b'$' && b[i] != b'%' || b[i].is_ascii_digit())
                {
                    i += 1
                }
                name = pattern[a..i].to_string();
                format = String::new()
            }
            if name.is_empty() {
                return Err(error("empty template hole"));
            }
            holes.push(Hole {
                name,
                format,
                start,
                end: i,
            })
        }
        Ok(Self {
            pattern: pattern.into(),
            holes,
        })
    }
    pub fn fill(&self, values: &BTreeMap<String, String>) -> Result<String> {
        let mut out = String::new();
        let mut at = 0;
        let mut used = BTreeSet::new();
        for h in &self.holes {
            out += &self.pattern[at..h.start].replace("$$", "$");
            let formatted = h.name.clone() + ":" + &h.format;
            let key = if !h.format.is_empty() && values.contains_key(&formatted) {
                &formatted
            } else {
                &h.name
            };
            out += values
                .get(key)
                .ok_or_else(|| error(&format!("missing template value {key}")))?;
            used.insert(key.clone());
            at = h.end
        }
        out += &self.pattern[at..].replace("$$", "$");
        if values.keys().any(|k| !used.contains(k)) {
            return Err(error("unused template value"));
        }
        Ok(out)
    }
}
pub fn template(id: &str) -> Result<Template> {
    let r = LLVM
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| error("unknown LLVM record"))?;
    if r.syntax.is_empty() {
        return Err(error("LLVM record has no printed syntax"));
    }
    Template::compile(r.syntax)
}
// Visit the same longest family matches as lookup, in document order. A
// longer family resets accumulated results; equal families retain all matches.
fn visit_documents(opcode: &str, mut found: impl FnMut(&'static Document, bool)) {
    let mut max = 0;
    for d in DOCUMENTS {
        if d.kind != "instruction" { continue; }
        for n in d.names {
            if opcode.strip_prefix(n).is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('.') || suffix.starts_with("::"))
                || (*n == "match.sync" && (opcode.starts_with("match.any.sync.") || opcode.starts_with("match.all.sync."))) {
                if n.len() >= max {
                    found(d, n.len() > max);
                    max = n.len();
                }
                break;
            }
        }
    }
}
pub fn lookup(opcode: &str) -> Vec<&'static Document> {
    let mut out = Vec::new();
    visit_documents(opcode, |d, reset| { if reset { out.clear(); } out.push(d); });
    out
}
#[derive(Debug, Default)]
pub struct Profile<'a> {
    pub max_version: &'a str,
    pub target: &'a str,
    pub address_size: u32,
}
#[derive(Debug)]
pub struct Issue {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
    pub offset: usize,
}
#[derive(Debug, Default)]
pub struct Validation {
    pub issues: Vec<Issue>,
    pub semantic_complete: bool,
}
impl Validation {
    pub fn result(&self) -> Result<()> {
        if let Some(i) = self.issues.iter().find(|i| i.severity == "error") {
            return Err(error(&i.message));
        }
        Ok(())
    }
}
fn version(s: &str) -> u32 {
    let Some((a, b)) = s.split_once('.') else {
        return 0;
    };
    let (a, b) = (
        a.parse::<u32>().unwrap_or(0),
        b.parse::<u32>().unwrap_or(99),
    );
    if a == 0 || a > 100000 || b > 9 {
        0
    } else {
        a * 10 + b
    }
}
fn target(s: &str) -> (u32, &str) {
    let Some(s) = s.strip_prefix("sm_") else {
        return (0, "");
    };
    let (n, suffix) = if s.ends_with('a') || s.ends_with('f') {
        (&s[..s.len() - 1], &s[s.len() - 1..])
    } else {
        (s, "")
    };
    (n.parse().unwrap_or(0), suffix)
}
fn family(n: u32) -> u32 {
    if n == 101 {
        11
    } else {
        n / 10
    }
}
pub fn check(m: &Module<'_>, p: &Profile<'_>) -> Validation {
    let mut v = Validation::default();
    let mut add = |code, msg: String, offset| {
        v.issues.push(Issue {
            severity: "error",
            code,
            message: msg,
            offset,
        })
    };
    let ver = version(m.version);
    if ver == 0 {
        add("version", "missing/invalid .version".into(), 0)
    } else if ver > version(ISA_VERSION) {
        add("version", "module exceeds pinned PTX ISA 9.5".into(), 0)
    }
    if !p.max_version.is_empty() && (version(p.max_version) == 0 || ver > version(p.max_version)) {
        add(
            "profile-version",
            "module exceeds maximum PTX version".into(),
            0,
        )
    }
    if m.address_size != 32 && m.address_size != 64 {
        add("address-size", ".address_size must be 32 or 64".into(), 0)
    }
    if p.address_size != 0 && p.address_size != m.address_size {
        add("profile-address-size", "address size mismatch".into(), 0)
    }
    let mut arch = "";
    for &t in &m.targets {
        if t.starts_with("sm_") {
            if !arch.is_empty() {
                add("target", "multiple SM targets".into(), 0)
            }
            arch = t;
            if !TARGETS.contains(&t) {
                add("target", format!("unknown target {t}"), 0)
            }
        } else if ![
            "texmode_unified",
            "texmode_independent",
            "debug",
            "map_f64_to_f32",
        ]
        .contains(&t)
        {
            add("target-option", format!("unknown target option {t}"), 0)
        }
    }
    let (sm, suffix) = target(arch);
    if TARGET_VERSIONS.iter().any(|(t, v)| *t == arch && *v > ver) {
        add(
            "target-version",
            "SM target requires newer PTX version".into(),
            0,
        )
    }
    if sm == 0 {
        add("target", "missing SM target".into(), 0)
    }
    if !p.target.is_empty() {
        let (device, _) = target(p.target);
        if device == 0 || !TARGETS.contains(&p.target) {
            add("profile-target", "invalid profile target".into(), 0)
        } else if sm > device
            || suffix == "a" && sm != device
            || suffix == "f" && family(sm) != family(device)
        {
            add("profile-target", "incompatible device target".into(), 0)
        }
    }
    for i in &m.instructions {
        let (mut known, mut version_ok, mut target_ok) = (false, false, false);
        visit_documents(i.opcode, |d, reset| {
            if reset { version_ok = false; target_ok = false; }
            known = true;
            version_ok |= d.min_version == 0 || ver >= d.min_version;
            target_ok |= d.min_target == 0 || sm >= d.min_target;
        });
        if !known {
            add(
                "unknown-opcode",
                format!("opcode absent from pinned source: {}", i.opcode),
                i.start,
            );
            continue;
        }
        if !version_ok {
            add(
                "instruction-version",
                format!("{} predates instruction family", i.opcode),
                i.start,
            )
        }
        if !target_ok {
            add(
                "instruction-target",
                format!("{} requires newer target", i.opcode),
                i.start,
            )
        }
    }
    v
}
#[derive(Debug)]
pub struct Function<'a> {
    pub name: &'a str,
    pub entry: bool,
    pub header: Vec<Token<'a>>,
    pub body: Vec<Node<'a>>,
    pub start: usize,
    pub end: usize,
}
#[derive(Debug)]
pub struct Declaration<'a> {
    pub names: Vec<&'a str>,
    pub space: &'a str,
    pub type_name: &'a str,
    pub tokens: Vec<Token<'a>>,
    pub start: usize,
    pub end: usize,
}
#[derive(Debug)]
pub struct Flow<'a> {
    pub kind: &'static str,
    pub target: &'a str,
    pub conditional: bool,
    pub offset: usize,
}
impl<'a> Module<'a> {
    pub fn functions(&self) -> Vec<Function<'a>> {
        fn walk<'a>(nodes: &[Node<'a>], out: &mut Vec<Function<'a>>) {
            for n in nodes {
                if n.kind == "function" {
                    let (mut name, mut entry, mut seen, mut depth) = ("", false, false, 0);
                    for t in &n.tokens {
                        if t.text == ".entry" || t.text == ".func" {
                            seen = true;
                            entry = t.text == ".entry";
                            continue;
                        }
                        if !seen {
                            continue;
                        }
                        if t.text == "(" {
                            depth += 1
                        } else if t.text == ")" {
                            depth -= 1
                        } else if depth == 0 && t.kind == "identifier" {
                            name = t.text;
                            break;
                        }
                    }
                    out.push(Function {
                        name,
                        entry,
                        header: n.tokens.clone(),
                        body: n.children.clone(),
                        start: n.start,
                        end: n.end,
                    })
                }
                walk(&n.children, out)
            }
        }
        let mut out = vec![];
        walk(&self.nodes, &mut out);
        out
    }
    pub fn declarations(&self) -> Vec<Declaration<'a>> {
        fn walk<'a>(nodes: &[Node<'a>], out: &mut Vec<Declaration<'a>>) {
            for n in nodes {
                if n.kind == "directive" {
                    let (mut space, mut typ) = ("", "");
                    let mut names = vec![];
                    for t in &n.tokens {
                        if t.text == "=" {
                            break;
                        }
                        if [
                            ".reg", ".sreg", ".param", ".local", ".shared", ".global", ".const",
                            ".tex", ".surf", ".sampler",
                        ]
                        .contains(&t.text)
                        {
                            if space.is_empty() {
                                space = t.text
                            }
                        }
                        if [".b", ".u", ".s", ".f"]
                            .iter()
                            .any(|p| t.text.starts_with(p))
                            || t.text == ".pred"
                        {
                            if ![".shared", ".surf", ".sampler", ".sreg"].contains(&t.text) {
                                typ = t.text
                            }
                        }
                        if t.kind == "register" || t.kind == "identifier" {
                            names.push(t.text)
                        }
                    }
                    if !space.is_empty() {
                        out.push(Declaration {
                            names,
                            space,
                            type_name: typ,
                            tokens: n.tokens.clone(),
                            start: n.start,
                            end: n.end,
                        })
                    }
                }
                walk(&n.children, out)
            }
        }
        let mut out = vec![];
        walk(&self.nodes, &mut out);
        out
    }
    pub fn control_flow(&self) -> Vec<Flow<'a>> {
        let mut out = vec![];
        for i in &self.instructions {
            let kind = match i.mnemonic {
                "bra" | "brx" => "branch",
                "call" => "call",
                "ret" => "return",
                "exit" => "exit",
                "trap" | "brkpt" => "trap",
                _ => continue,
            };
            let mut target = "";
            if kind == "branch" {
                let n=if i.mnemonic=="brx" {1} else {0};
                target = i.operands.get(n).map(|o| o.text).unwrap_or("")
            } else if kind == "call" {
                let n = if i.operands.first().map(|o| o.kind) == Some("tuple") {
                    1
                } else {
                    0
                };
                target = i.operands.get(n).map(|o| o.text).unwrap_or("")
            }
            out.push(Flow {
                kind,
                target,
                conditional: i.predicate.is_some(),
                offset: i.start,
            })
        }
        out
    }
}
/// Run an explicitly supplied primary validator with source on stdin. The
/// caller supplies validator arguments and owns process/resource policy.
pub fn validate_with(
    m: &Module<'_>,
    p: &Profile<'_>,
    command: &str,
    args: &[&str],
) -> Result<Validation> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut v = check(m, p);
    v.result()?;
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| error(&e.to_string()))?;
    let mut stdin = child.stdin.take().unwrap();
    let (output, write_result) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(m.source.as_bytes()));
        let output = child.wait_with_output();
        let written = writer
            .join()
            .map_err(|_| error("validator input writer panicked"))?;
        Ok::<_, Error>((output.map_err(|e| error(&e.to_string()))?, written))
    })?;
    if !output.status.success() {
        return Err(error(&format!(
            "primary validator: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    write_result.map_err(|e| error(&e.to_string()))?;
    v.semantic_complete = true;
    Ok(v)
}
#[derive(Debug)]
pub struct Feature {
    pub id: &'static str,
    pub kind: &'static str,
    pub name: &'static str,
    pub field: &'static str,
    pub value: &'static str,
    pub description: &'static str,
    pub condition: &'static str,
    pub implies: &'static [&'static str],
}
pub fn assemble<'a>(source: &'a str, p: &Profile<'_>) -> Result<Module<'a>> {
    let m = decode(source)?;
    check(&m, p).result()?;
    Ok(m)
}
pub fn compile_module_template(mut pattern: &str) -> Result<Template> {
    let mut out = String::new();
    while !pattern.is_empty() {
        let Some(start) = pattern.find("{{") else {
            out += &pattern.replace("$", "$$");
            break;
        };
        out += &pattern[..start].replace("$", "$$");
        let end = pattern[start + 2..]
            .find("}}")
            .ok_or_else(|| error("unclosed module template hole"))?
            + start
            + 2;
        let name = pattern[start + 2..end].trim();
        if name.is_empty() {
            return Err(error("empty module template hole"));
        }
        out += "${";
        out += name;
        out += "}";
        pattern = &pattern[end + 2..]
    }
    Template::compile(&out)
}
fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out += "\\\"",
            '\\' => out += "\\\\",
            '\n' => out += "\\n",
            '\r' => out += "\\r",
            '\t' => out += "\\t",
            c if c < ' ' => out += &format!("\\u{:04x}", c as u32),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
impl Token<'_> {
    fn json(&self) -> String {
        format!(
            "{{\"kind\":{},\"text\":{},\"start\":{},\"end\":{},\"line\":{},\"column\":{}}}",
            json_string(self.kind),
            json_string(self.text),
            self.start,
            self.end,
            self.line,
            self.column
        )
    }
}
impl Node<'_> {
    fn json(&self) -> String {
        format!(
            "{{\"kind\":{},\"start\":{},\"end\":{},\"tokens\":[{}],\"children\":[{}]}}",
            json_string(self.kind),
            self.start,
            self.end,
            self.tokens
                .iter()
                .map(|t| t.json())
                .collect::<Vec<_>>()
                .join(","),
            self.children
                .iter()
                .map(|n| n.json())
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}
impl Module<'_> {
    pub fn to_json(&self) -> String {
        let instructions=self.instructions.iter().map(|i|{let operands=i.operands.iter().map(|o|format!("{{\"kind\":{},\"text\":{},\"tokens\":[{}]}}",json_string(o.kind),json_string(o.text),o.tokens.iter().map(|t|t.json()).collect::<Vec<_>>().join(","))).collect::<Vec<_>>().join(",");format!("{{\"opcode\":{},\"mnemonic\":{},\"modifiers\":[{}],\"predicate\":{},\"negated\":{},\"operands\":[{}],\"start\":{},\"end\":{}}}",json_string(i.opcode),json_string(i.mnemonic),i.modifiers.iter().map(|s|json_string(s)).collect::<Vec<_>>().join(","),json_string(i.predicate.unwrap_or("")),i.negated,operands,i.start,i.end)}).collect::<Vec<_>>().join(",");
        format!("{{\"source\":{},\"version\":{},\"targets\":[{}],\"address_size\":{},\"tokens\":[{}],\"nodes\":[{}],\"instructions\":[{}]}}",json_string(self.source),json_string(self.version),self.targets.iter().map(|s|json_string(s)).collect::<Vec<_>>().join(","),self.address_size,self.tokens.iter().map(|t|t.json()).collect::<Vec<_>>().join(","),self.nodes.iter().map(|n|n.json()).collect::<Vec<_>>().join(","),instructions)
    }
}
