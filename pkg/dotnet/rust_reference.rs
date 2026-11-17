/// Exact metadata assembly identity. No disk lookup or runtime unification occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyIdentity {
    pub name: String,
    pub version: String,
    pub culture: String,
    pub public_key_token: String,
}
impl std::fmt::Display for AssemblyIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, Version={}, Culture={}, PublicKeyToken={}",
            self.name, self.version, self.culture, self.public_key_token
        )
    }
}
fn reference_sha1(bytes: &[u8]) -> [u8; 20] {
    let mut b = bytes.to_vec();
    let bits = (b.len() as u64).wrapping_mul(8);
    b.push(128);
    while b.len() % 64 != 56 {
        b.push(0);
    }
    b.extend_from_slice(&bits.to_be_bytes());
    let mut h = [
        0x67452301u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    for chunk in b.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, c) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(c.try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut bb, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((bb & c) | (!bb & d), 0x5a827999),
                20..=39 => (bb ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((bb & c) | (bb & d) | (c & d), 0x8f1bbcdc),
                _ => (bb ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = bb.rotate_left(30);
            bb = a;
            a = temp;
        }
        for (i, v) in [a, bb, c, d, e].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
fn reference_key_token(key: &[u8], full: bool) -> Result<String> {
    if key.is_empty() {
        return Ok("null".into());
    }
    let bytes = if full {
        reference_sha1(key)[12..]
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>()
    } else {
        if key.len() != 8 {
            return Err(err("assembly public key token must have eight bytes"));
        }
        key.to_vec()
    };
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
impl Metadata<'_> {
    fn reference_assembly_identity(&self, token: Token) -> Result<AssemblyIdentity> {
        if !matches!(token.table(), 32 | 35) {
            return Err(err("not an assembly identity token"));
        }
        let r = self.row(token.table(), token.rid())?;
        let (v, k, n, c, f) = if token.table() == 32 {
            (1, 6, 7, 8, 5)
        } else {
            (0, 5, 6, 7, 4)
        };
        let name = self.string(r[n])?.to_string();
        if name.is_empty() || name.contains([',', '=', '\r', '\n']) {
            return Err(err("invalid assembly name"));
        }
        let culture = self.string(r[c])?;
        Ok(AssemblyIdentity {
            name,
            version: format!("{}.{}.{}.{}", r[v], r[v + 1], r[v + 2], r[v + 3]),
            culture: if culture.is_empty() {
                "neutral".into()
            } else {
                culture.into()
            },
            public_key_token: reference_key_token(self.blob(r[k])?, r[f] & 1 != 0)?,
        })
    }
    pub fn assembly_identity(&self) -> Result<AssemblyIdentity> {
        if self.tables[32].count != 1 {
            return Err(err("metadata must contain one manifest Assembly row"));
        }
        self.reference_assembly_identity(Token(32 << 24 | 1))
    }
    fn reference_serialized_enum_name(&self, token: Token, depth: usize) -> Result<String> {
        if depth > 64 {
            return Err(err("enum type name cycle/nesting limit"));
        }
        if !matches!(token.table(), 1 | 2) {
            return Err(err("enum signature needs TypeDef/TypeRef"));
        }
        let r = self.row(token.table(), token.rid())?;
        let name = self.string(r[1])?;
        let ns = self.string(r[2])?;
        let mut parent = self.nested.get(&token).copied().unwrap_or(Token(0));
        if token.table() == 1 {
            let scope = decode_coded("ResolutionScope", r[0])?;
            if scope.table() == 1 && scope.0 != 0 {
                parent = scope;
            }
        }
        if parent.0 != 0 {
            return Ok(format!(
                "{}+{}",
                self.reference_serialized_enum_name(parent, depth + 1)?,
                reference_escape_enum_identifier(name)
            ));
        }
        Ok(reference_escape_enum_identifier(&if ns.is_empty() {
            name.into()
        } else {
            format!("{ns}.{name}")
        }))
    }
    fn reference_enum_storage(&self, t: &TypeDefinition) -> Result<String> {
        if self.resolve(t.extends)? != "System.Enum" {
            return Err(err("type is not enum"));
        }
        for &field in &t.fields {
            let m = self.member(field)?;
            if m.name == "value__" {
                if let Some(ret) = m.signature.return_type {
                    return Ok(ret.kind);
                }
            }
        }
        Err(err("enum has no value__ storage field"))
    }
    fn reference_enum_type_name(&self, token: Token) -> Result<String> {
        let name = self.reference_serialized_enum_name(token, 0)?;
        let mut scope = token;
        for _ in 0..=64 {
            if scope.table() == 2 {
                return Ok(name);
            }
            if scope.table() != 1 {
                return Err(err("enum signature needs TypeDef/TypeRef"));
            }
            let r = self.row(1, scope.rid())?;
            scope = decode_coded("ResolutionScope", r[0])?;
            if scope.table() == 35 {
                return Ok(format!(
                    "{}, {}",
                    name,
                    self.reference_assembly_identity(scope)?
                ));
            }
            if scope.0 == 0 || scope.table() == 0 {
                return Ok(name);
            }
            if scope.table() == 26 {
                return Err(err(
                    "external enum netmodule scope requires explicit module resolution",
                ));
            }
        }
        Err(err("enum type reference cycle/nesting limit"))
    }
    fn reference_has_type(&self, name: &str) -> Result<bool> {
        let shape = reference_type_shape(name, 0)?;
        let name = shape.name.as_str();
        for rid in 1..=self.tables[2].count {
            if self.reference_serialized_enum_name(Token(2 << 24 | rid), 0)? == name {
                return Ok(true);
            }
        }
        for rid in 1..=self.tables[39].count {
            if self.reference_exported_binding(rid, 0)?.0 == name {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn reference_exported_binding(&self, rid: u32, depth: usize) -> Result<(String, Token, u32)> {
        if depth > 64 {
            return Err(err("exported type cycle/nesting limit"));
        }
        let r = self.row(39, rid)?;
        let n = self.string(r[2])?;
        let ns = self.string(r[3])?;
        let name = reference_escape_enum_identifier(&if ns.is_empty() {
            n.into()
        } else {
            format!("{ns}.{n}")
        });
        let implementation = decode_coded("Implementation", r[4])?;
        if implementation.table() == 39 {
            let (parent, target, _) =
                self.reference_exported_binding(implementation.rid(), depth + 1)?;
            return Ok((
                format!("{parent}+{}", reference_escape_enum_identifier(n)),
                target,
                r[1],
            ));
        }
        if implementation.table() == 38 || (implementation.table() == 35 && r[0] & 0x200000 != 0) {
            return Ok((name, implementation, r[1]));
        }
        Ok((name, Token(0), 0))
    }
}

fn reference_identity_matches(actual: &AssemblyIdentity, requested: &AssemblyIdentity) -> bool {
    actual.name.eq_ignore_ascii_case(&requested.name)
        && (requested.version.is_empty() || actual.version == requested.version)
        && (requested.culture.is_empty() || actual.culture.eq_ignore_ascii_case(&requested.culture))
        && (requested.public_key_token.is_empty()
            || actual
                .public_key_token
                .eq_ignore_ascii_case(&requested.public_key_token))
}
fn reference_escape_enum_identifier(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if matches!(c, '\\' | ',' | '+' | '[' | ']' | '&' | '*') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
fn reference_enum_name_prefix(name: &str) -> Result<(&str, Option<&str>)> {
    let (mut escaped, mut depth) = (false, 0usize);
    for (i, c) in name.char_indices() {
        if escaped {
            if !matches!(c, '\\' | ',' | '+' | '[' | ']' | '&' | '*') {
                return Err(err("invalid serialized type name escape"));
            }
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '[' => {
                depth += 1;
                if depth > 64 {
                    return Err(err("type name nesting limit"));
                }
            }
            ']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| err("unmatched type name bracket"))?;
            }
            ',' if depth == 0 => return Ok((name[..i].trim(), Some(&name[i + 1..]))),
            _ => {}
        }
    }
    if escaped || depth != 0 {
        return Err(err("incomplete serialized type name"));
    }
    Ok((name.trim(), None))
}
struct ReferenceTypeShape {
    name: String,
    arguments: Vec<String>,
    arrays: Vec<usize>,
}
fn reference_bracket_end(name: &str, start: usize) -> Result<usize> {
    let (mut depth, mut escaped) = (0usize, false);
    for (i, c) in name.char_indices().filter(|(i, _)| *i >= start) {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '[' => depth += 1,
            ']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| err("unmatched type bracket"))?;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    Err(err("unmatched constructed type bracket"))
}
fn reference_generic_arguments(content: &str) -> Result<Vec<String>> {
    let mut args = vec![];
    if content.starts_with('[') {
        let mut rest = content;
        while !rest.is_empty() {
            if !rest.starts_with('[') {
                return Err(err("mixed generic argument qualification"));
            }
            let end = reference_bracket_end(rest, 0)?;
            let arg = rest[1..end].trim();
            if arg.is_empty() {
                return Err(err("empty generic argument"));
            }
            args.push(arg.into());
            rest = rest[end + 1..].trim();
            if rest.is_empty() {
                break;
            }
            rest = rest
                .strip_prefix(',')
                .ok_or_else(|| err("invalid generic argument separator"))?
                .trim();
            if rest.is_empty() {
                return Err(err("empty generic argument"));
            }
        }
    } else {
        let (mut start, mut depth, mut escaped) = (0, 0usize, false);
        for (i, c) in content.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match c {
                '\\' => escaped = true,
                '[' => depth += 1,
                ']' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| err("unmatched type bracket"))?
                }
                ',' if depth == 0 => {
                    args.push(content[start..i].trim().into());
                    start = i + 1;
                }
                _ => {}
            }
        }
        args.push(content[start..].trim().into());
        if args.iter().any(String::is_empty) {
            return Err(err("empty generic argument"));
        }
    }
    Ok(args)
}
fn reference_type_shape(name: &str, depth: usize) -> Result<ReferenceTypeShape> {
    if depth > 64 {
        return Err(err("constructed type nesting limit"));
    }
    let (mut escaped, mut segment, mut start) = (false, false, name.len());
    for (i, c) in name.char_indices() {
        if escaped {
            if !matches!(c, '\\' | ',' | '+' | '[' | ']' | '&' | '*') {
                return Err(err("invalid serialized type name escape"));
            }
            escaped = false;
            segment = true;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '+' => {
                if !segment {
                    return Err(err("empty nested type name"));
                }
                segment = false;
            }
            '[' => {
                start = i;
                break;
            }
            ']' | '*' | '&' | ',' => return Err(err("invalid or indirect nominal type name")),
            _ => {
                if !matches!(c, ' ' | '\t' | '\r' | '\n') {
                    segment = true;
                }
            }
        }
    }
    if escaped || !segment {
        return Err(err("incomplete nominal type name"));
    }
    let mut shape = ReferenceTypeShape {
        name: name[..start].trim().into(),
        arguments: vec![],
        arrays: vec![],
    };
    let mut suffix = &name[start..];
    let mut constructed = false;
    while !suffix.is_empty() {
        if !suffix.starts_with('[') {
            return Err(err("invalid constructed type suffix"));
        }
        let end = reference_bracket_end(suffix, 0)?;
        let content = &suffix[1..end];
        if content.chars().all(|c| c == ',') || content == "*" {
            shape
                .arrays
                .push(if content == "*" { 1 } else { content.len() + 1 });
        } else {
            if constructed || !shape.arrays.is_empty() {
                return Err(err("invalid generic construction"));
            }
            constructed = true;
            shape.arguments = reference_generic_arguments(content)?;
            for arg in &shape.arguments {
                let (typ, _) = reference_enum_name_prefix(arg)?;
                reference_type_shape(typ, depth + 1)?;
            }
        }
        suffix = &suffix[end + 1..];
    }
    Ok(shape)
}
fn reference_parse_enum_identity(name: &str) -> Result<(String, Option<AssemblyIdentity>)> {
    reference_parse_identity(name, false)
}
fn reference_parse_identity(
    name: &str,
    allow_array: bool,
) -> Result<(String, Option<AssemblyIdentity>)> {
    let (typ, assembly) = reference_enum_name_prefix(name)?;
    let shape = reference_type_shape(typ, 0)?;
    if !allow_array && !shape.arrays.is_empty() {
        return Err(err("array is not an enum type"));
    }
    let Some(assembly) = assembly else {
        return Ok((typ.into(), None));
    };
    let parts: Vec<_> = assembly.split(',').collect();
    let mut a = AssemblyIdentity {
        name: parts[0].trim().into(),
        version: String::new(),
        culture: String::new(),
        public_key_token: String::new(),
    };
    if a.name.is_empty() {
        return Err(err("empty enum assembly identity"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for part in &parts[1..] {
        let (k, v) = part
            .trim()
            .split_once('=')
            .ok_or_else(|| err("invalid enum assembly identity"))?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if !seen.insert(k.clone()) || v.is_empty() {
            return Err(err("duplicate/empty assembly identity component"));
        }
        match k.as_str() {
            "version" => {
                let nums: Vec<_> = v.split('.').collect();
                if nums.len() != 4
                    || nums.iter().any(|n| {
                        n.parse::<u16>()
                            .map(|v| v.to_string() != *n)
                            .unwrap_or(true)
                    })
                {
                    return Err(err("invalid assembly version"));
                }
                a.version = v.into();
            }
            "culture" => a.culture = v.into(),
            "publickeytoken" => {
                if !v.eq_ignore_ascii_case("null")
                    && (v.len() != 16 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(err("invalid assembly public key token"));
                }
                a.public_key_token = v.to_ascii_lowercase();
            }
            _ => return Err(err("unsupported assembly identity component")),
        }
    }
    Ok((typ.into(), Some(a)))
}
/// Explicit borrowed assembly references. Unqualified enum names stay local.
/// Assembly/culture names use ASCII folding; other name bytes remain exact.
/// Escaped identifier names preserve punctuation and nested scope.
/// Modules bind through manifest File rows and exact Module metadata names.
/// File hashes cannot be verified with metadata-only inputs.
/// Construct with `ReferenceSet::new(&image.metadata, &[&reference.metadata])`.
/// Pass `&mut |name| references.enum_underlying(name)` to blob decoding APIs.
pub struct ReferenceSet<'m, 'data> {
    local: &'m Metadata<'data>,
    entries: Vec<(AssemblyIdentity, &'m Metadata<'data>)>,
    modules: Vec<&'m Metadata<'data>>,
    bindings: Vec<(&'m Metadata<'data>, Token, &'m Metadata<'data>)>,
}
impl<'m, 'data> ReferenceSet<'m, 'data> {
    pub fn new(local: &'m Metadata<'data>, references: &[&'m Metadata<'data>]) -> Result<Self> {
        let mut out = Self {
            local,
            entries: vec![],
            modules: vec![],
            bindings: vec![],
        };
        for (i, m) in std::iter::once(local)
            .chain(references.iter().copied())
            .enumerate()
        {
            if i == 0 && m.pdb.is_some() && m.tables[0].count == 0 {
                continue;
            }
            m.module_identity()?;
            if !out.modules.iter().any(|x| std::ptr::eq(*x, m)) {
                out.modules.push(m);
            }
            if m.tables[32].count == 0 {
                continue;
            }
            let id = m.assembly_identity()?;
            let mut duplicate = false;
            for (existing, metadata) in &out.entries {
                if reference_identity_matches(existing, &id)
                    && reference_identity_matches(&id, existing)
                {
                    if !std::ptr::eq(*metadata, m) {
                        return Err(err(&format!("duplicate supplied assembly identity {id}")));
                    }
                    duplicate = true;
                }
            }
            if !duplicate {
                out.entries.push((id, m));
            }
        }
        Ok(out)
    }
    fn select_assembly(&self, id: &AssemblyIdentity) -> Result<&'m Metadata<'data>> {
        let mut selected = None;
        for (actual, m) in &self.entries {
            if reference_identity_matches(actual, id) {
                if selected.is_some() {
                    return Err(err(&format!("ambiguous supplied assembly {id}")));
                }
                selected = Some(*m);
            }
        }
        selected.ok_or_else(|| err(&format!("explicit metadata reference for {id} is required")))
    }
    /// Explicit metadata-only File binding; File.HashValue is not authenticated.
    pub fn bind_module(
        &mut self,
        manifest: &'m Metadata<'data>,
        file: Token,
        module: &'m Metadata<'data>,
    ) -> Result<()> {
        if !self.supplied(manifest)
            || !self.supplied(module)
            || manifest.tables[32].count != 1
            || module.tables[32].count != 0
            || file.table() != 38
        {
            return Err(err("invalid explicitly supplied module binding"));
        }
        if manifest.row(38, file.rid())?[0] != 0 {
            return Err(err("manifest File does not contain metadata"));
        }
        for &(m, f, target) in &self.bindings {
            if std::ptr::eq(m, manifest) && f == file {
                if !std::ptr::eq(target, module) {
                    return Err(err("manifest File already has another module binding"));
                }
                return Ok(());
            }
        }
        self.bindings.push((manifest, file, module));
        Ok(())
    }
    fn explicit_module(
        &self,
        manifest: &Metadata<'data>,
        file: Token,
    ) -> Option<&'m Metadata<'data>> {
        self.bindings
            .iter()
            .find(|&&(m, f, _)| std::ptr::eq(m, manifest) && f == file)
            .map(|&(_, _, target)| target)
    }
    fn supplied(&self, m: &Metadata<'data>) -> bool {
        self.modules.iter().any(|x| std::ptr::eq(*x, m))
    }
    fn file_module(
        &self,
        manifest: &'m Metadata<'data>,
        file: Token,
    ) -> Result<&'m Metadata<'data>> {
        if file.table() != 38 || manifest.tables[32].count != 1 {
            return Err(err("File binding requires manifest assembly context"));
        }
        let r = manifest.row(38, file.rid())?;
        if r[0] != 0 {
            return Err(err("manifest File does not contain metadata"));
        }
        if let Some(module) = self.explicit_module(manifest, file) {
            return Ok(module);
        }
        let name = manifest.string(r[1])?;
        let mut found = None;
        for &module in &self.modules {
            if module.tables[32].count != 0 {
                continue;
            }
            if module.module_identity()?.name == name {
                if found.is_some() {
                    return Err(err("ambiguous supplied netmodule"));
                }
                found = Some(module);
            }
        }
        found.ok_or_else(|| {
            err(&format!(
                "explicit metadata for manifest File {name} is required"
            ))
        })
    }
    fn module_owner(&self, module: &'m Metadata<'data>) -> Result<Option<&'m Metadata<'data>>> {
        if !self.supplied(module) {
            return Err(err("metadata context was not explicitly supplied"));
        }
        if module.tables[32].count == 1 {
            return Ok(Some(module));
        }
        let id = module.module_identity()?;
        let mut owner = None;
        for (_, assembly) in &self.entries {
            for rid in 1..=assembly.tables[38].count {
                let r = assembly.row(38, rid)?;
                if r[0] & 1 == 0
                    && (assembly.string(r[1])? == id.name
                        || self
                            .explicit_module(assembly, Token(38 << 24 | rid))
                            .map(|m| std::ptr::eq(m, module))
                            .unwrap_or(false))
                {
                    let target = self.file_module(assembly, Token(38 << 24 | rid))?;
                    if std::ptr::eq(target, module) {
                        if owner.is_some() {
                            return Err(err("ambiguous manifest ownership for netmodule"));
                        }
                        owner = Some(*assembly);
                    }
                }
            }
        }
        Ok(owner)
    }
    fn scope_module(
        &self,
        origin: &'m Metadata<'data>,
        manifest: Option<&'m Metadata<'data>>,
        name: &str,
    ) -> Result<&'m Metadata<'data>> {
        if origin.module_identity()?.name == name {
            return Ok(origin);
        }
        let manifest =
            manifest.ok_or_else(|| err("manifest assembly for ModuleRef is required"))?;
        if manifest.module_identity()?.name == name {
            return Ok(manifest);
        }
        let mut found = None;
        for rid in 1..=manifest.tables[38].count {
            let r = manifest.row(38, rid)?;
            let explicit_name = self
                .explicit_module(manifest, Token(38 << 24 | rid))
                .map(|m| m.module_identity())
                .transpose()?
                .map(|m| m.name);
            let matches = if let Some(explicit_name) = explicit_name {
                explicit_name == name
            } else {
                manifest.string(r[1])? == name
            };
            if r[0] & 1 == 0 && matches {
                let target = self.file_module(manifest, Token(38 << 24 | rid))?;
                if found.is_some() {
                    return Err(err("ambiguous ModuleRef"));
                }
                found = Some(target);
            }
        }
        found.ok_or_else(|| err("ModuleRef is absent from manifest File records"))
    }
    pub fn enum_underlying(&self, name: &str) -> Result<String> {
        self.enum_underlying_in(self.local, name)
    }
    pub fn enum_underlying_in(&self, origin: &'m Metadata<'data>, name: &str) -> Result<String> {
        let (typ, id) = reference_parse_enum_identity(name)?;
        let mut manifest = self.module_owner(origin)?;
        let mut m = origin;
        if id.is_none() {
            if let Some(owner) = manifest {
                if !std::ptr::eq(owner, origin) && owner.reference_has_type(&typ)? {
                    m = owner;
                }
            }
        }
        if let Some(id) = id {
            m = self.select_assembly(&id)?;
            manifest = Some(m);
        }
        self.resolve_enum(m, manifest, &typ, &mut Vec::new(), 0)
    }
    fn resolve_enum(
        &self,
        m: &'m Metadata<'data>,
        manifest: Option<&'m Metadata<'data>>,
        name: &str,
        seen: &mut Vec<(
            *const Metadata<'data>,
            Option<*const Metadata<'data>>,
            String,
        )>,
        depth: usize,
    ) -> Result<String> {
        self.resolve_definition(m, manifest, name, seen, depth, true)
    }
    fn resolve_definition(
        &self,
        m: &'m Metadata<'data>,
        manifest: Option<&'m Metadata<'data>>,
        name: &str,
        seen: &mut Vec<(
            *const Metadata<'data>,
            Option<*const Metadata<'data>>,
            String,
        )>,
        depth: usize,
        require_enum: bool,
    ) -> Result<String> {
        let shape = reference_type_shape(name, 0)?;
        if require_enum && !shape.arrays.is_empty() {
            return Err(err("array is not enum"));
        }
        let lookup = shape.name.as_str();
        let key = (
            m as *const _,
            manifest.map(|m| m as *const _),
            name.to_owned(),
        );
        if depth > 64 || seen.contains(&key) {
            return Err(err("enum forwarding cycle/nesting limit"));
        }
        seen.push(key);
        let types = m.types()?;
        let mut matches = 0;
        let mut definition = None;
        for t in &types {
            if m.reference_serialized_enum_name(t.token, 0)? == lookup {
                matches += 1;
                definition = Some(t);
            }
        }
        let mut destination = Token(0);
        let mut hint = 0;
        for rid in 1..=m.tables[39].count {
            let (n, target, id) = m.reference_exported_binding(rid, 0)?;
            if n == lookup {
                matches += 1;
                destination = target;
                hint = id;
            }
        }
        if matches > 1 {
            return Err(err("ambiguous enum definition"));
        }
        if matches == 0 {
            return Err(err("enum not found in selected module"));
        }
        if let Some(t) = definition {
            if shape.arguments.len() != t.generic_parameters.len() {
                return Err(err("open or wrong-arity generic enum/type name"));
            }
            for arg in &shape.arguments {
                self.validate_type_argument(m, manifest, arg, depth + 1)?;
            }
            if !require_enum {
                return Ok(String::new());
            }
            let kind = m.reference_enum_storage(t)?;
            if !matches!(
                kind.as_str(),
                "int8" | "uint8" | "int16" | "uint16" | "int32" | "uint32" | "int64" | "uint64"
            ) {
                return Err(err("invalid enum storage type"));
            }
            return Ok(kind);
        }
        match destination.table() {
            35 => {
                let id = m.reference_assembly_identity(destination)?;
                let next = self.select_assembly(&id)?;
                self.resolve_definition(next, Some(next), name, seen, depth + 1, require_enum)
            }
            38 => {
                let next = self.file_module(m, destination)?;
                if hint != 0 {
                    let rid = if hint >> 24 != 0 {
                        if hint >> 24 != 2 {
                            return Err(err("invalid exported TypeDefId"));
                        }
                        hint & 0xffffff
                    } else {
                        hint
                    };
                    if next.reference_serialized_enum_name(Token(2 << 24 | rid), 0)? != lookup {
                        return Err(err("exported TypeDefId does not match enum name"));
                    }
                }
                self.resolve_definition(next, Some(m), name, seen, depth + 1, require_enum)
            }
            _ => Err(err("unsupported exported enum implementation")),
        }
    }
    fn enum_token_type(&self, origin: &'m Metadata<'data>, token: Token) -> Result<SerializedType> {
        let mut name = origin.reference_serialized_enum_name(token, 0)?;
        let mut manifest = self.module_owner(origin)?;
        let mut target = origin;
        let mut scope = token;
        for _ in 0..=64 {
            if scope.table() == 2 {
                break;
            }
            if scope.table() != 1 {
                return Err(err("invalid enum token scope"));
            }
            let r = origin.row(1, scope.rid())?;
            scope = decode_coded("ResolutionScope", r[0])?;
            if scope.table() == 1 {
                continue;
            }
            match scope.table() {
                35 => {
                    let id = origin.reference_assembly_identity(scope)?;
                    target = self.select_assembly(&id)?;
                    manifest = Some(target);
                }
                26 => {
                    let r = origin.row(26, scope.rid())?;
                    target = self.scope_module(origin, manifest, origin.string(r[0])?)?;
                }
                0 => {}
                _ => return Err(err("unsupported enum resolution scope")),
            }
            break;
        }
        let identity = target.module_identity()?;
        if let Some(m) = manifest {
            name = format!("{}, {}", name, m.assembly_identity()?);
        }
        let mut out = SerializedType::scalar("enum");
        out.enum_name = name;
        out.enum_module = Some(identity);
        Ok(out)
    }
    fn reference_attribute_type(
        &self,
        origin: &'m Metadata<'data>,
        t: &Type,
    ) -> Result<SerializedType> {
        let mut t = t;
        while matches!(t.kind.as_str(), "modreq" | "modopt") && t.args.len() == 1 {
            t = &t.args[0];
        }
        if t.kind == "szarray" && t.args.len() == 1 {
            let mut out = SerializedType::scalar("array");
            out.element = Some(Box::new(self.reference_attribute_type(origin, &t.args[0])?));
            return Ok(out);
        }
        if t.kind == "genericinst" && t.args.len() > 1 && t.args[0].kind == "valuetype" {
            let mut typ = self.enum_token_type(origin, t.args[0].token)?;
            let (name, id) = reference_parse_enum_identity(&typ.enum_name)?;
            let mut args = vec![];
            for arg in &t.args[1..] {
                args.push(format!(
                    "[{}]",
                    self.signature_argument_name(origin, arg, 0)?
                ));
            }
            typ.enum_name = format!("{}[{}]", name, args.join(","));
            if let Some(id) = id {
                typ.enum_name = format!("{}, {}", typ.enum_name, id);
            }
            typ.enum_arguments = t.args[1..].to_vec();
            return Ok(typ);
        }
        if t.kind == "valuetype" {
            return self.enum_token_type(origin, t.token);
        }
        origin.attribute_type(t)
    }
    fn resolve_serialized_enum(
        &self,
        origin: &'m Metadata<'data>,
        t: &SerializedType,
    ) -> Result<String> {
        let Some(module) = &t.enum_module else {
            return self.enum_underlying_in(origin, &t.enum_name);
        };
        let (name, id) = reference_parse_enum_identity(&t.enum_name)?;
        let mut manifest = self.module_owner(origin)?;
        if let Some(id) = id {
            manifest = Some(self.select_assembly(&id)?);
        }
        let mut target = None;
        for &candidate in &self.modules {
            if candidate.module_identity()? != *module {
                continue;
            }
            let owner = self.module_owner(candidate)?;
            let same = match (owner, manifest) {
                (Some(a), Some(b)) => std::ptr::eq(a, b),
                (None, None) => std::ptr::eq(candidate, origin),
                _ => false,
            };
            if !same {
                continue;
            }
            if target.is_some() {
                return Err(err("ambiguous scoped enum module"));
            }
            target = Some(candidate);
        }
        let target = target.ok_or_else(|| {
            err("explicit enum module identity was not supplied in this assembly context")
        })?;
        self.resolve_enum(target, manifest, &name, &mut Vec::new(), 0)
    }
    fn validate_type_argument(
        &self,
        origin: &'m Metadata<'data>,
        mut manifest: Option<&'m Metadata<'data>>,
        name: &str,
        depth: usize,
    ) -> Result<()> {
        if depth > 64 {
            return Err(err("generic argument nesting limit"));
        }
        let (typ, id) = reference_parse_identity(name, true)?;
        let shape = reference_type_shape(&typ, 0)?;
        if matches!(
            shape.name.as_str(),
            "System.Void"
                | "System.TypedReference"
                | "System.ArgIterator"
                | "System.RuntimeArgumentHandle"
        ) {
            return Err(err("invalid generic argument type"));
        }
        if id.is_none()
            && shape.arguments.is_empty()
            && reference_primitive_kinds()
                .iter()
                .any(|(_, n)| *n == shape.name)
        {
            return Ok(());
        }
        let mut target = origin;
        if let Some(id) = id {
            target = self.select_assembly(&id)?;
            manifest = Some(target);
        } else if let Some(owner) = manifest {
            if owner.reference_has_type(&typ)? {
                target = owner;
            }
        }
        self.resolve_definition(target, manifest, &typ, &mut vec![], depth, false)?;
        Ok(())
    }
    fn signature_argument_name(
        &self,
        origin: &'m Metadata<'data>,
        t: &Type,
        depth: usize,
    ) -> Result<String> {
        if depth > 64 {
            return Err(err("generic signature nesting limit"));
        }
        if let Some((_, name)) = reference_primitive_kinds()
            .iter()
            .find(|(k, _)| *k == t.kind)
        {
            return Ok((*name).into());
        }
        if matches!(t.kind.as_str(), "class" | "valuetype") {
            return Ok(self.enum_token_type(origin, t.token)?.enum_name);
        }
        if t.kind == "genericinst" && t.args.len() > 1 {
            let base = self.signature_argument_name(origin, &t.args[0], depth + 1)?;
            let (mut name, id) = reference_parse_identity(&base, false)?;
            let mut args = vec![];
            for arg in &t.args[1..] {
                args.push(format!(
                    "[{}]",
                    self.signature_argument_name(origin, arg, depth + 1)?
                ));
            }
            name = format!("{}[{}]", name, args.join(","));
            if let Some(id) = id {
                name = format!("{name}, {id}");
            }
            return Ok(name);
        }
        if t.kind == "array" && t.args.len() == 1 && t.rank > 0 && t.rank <= 32 {
            let element = self.signature_argument_name(origin, &t.args[0], depth + 1)?;
            let (mut name, id) = reference_parse_identity(&element, true)?;
            let suffix = if t.rank == 1 {
                "*".into()
            } else {
                ",".repeat(t.rank as usize - 1)
            };
            name = format!("{name}[{suffix}]");
            if let Some(id) = id {
                name = format!("{name}, {id}");
            }
            return Ok(name);
        }
        if t.kind == "szarray" && t.args.len() == 1 {
            let element = self.signature_argument_name(origin, &t.args[0], depth + 1)?;
            let (mut name, id) = reference_parse_identity(&element, true)?;
            name.push_str("[]");
            if let Some(id) = id {
                name = format!("{name}, {id}");
            }
            return Ok(name);
        }
        Err(err("open/indirect unsupported generic argument signature"))
    }
    pub fn decode_attribute(
        &self,
        origin: &'m Metadata<'data>,
        a: &Attribute<'data>,
    ) -> Result<DecodedAttribute> {
        if !self.supplied(origin) {
            return Err(err(
                "attribute metadata context was not explicitly supplied",
            ));
        }
        let mut r = Cursor {
            native: false,
            b: a.value,
            p: 0,
        };
        if r.uint(2)? != 1 {
            return Err(err("invalid attribute prolog"));
        }
        let mut out = DecodedAttribute {
            fixed: vec![],
            named: vec![],
        };
        let mut resolver = |t: &SerializedType| self.resolve_serialized_enum(origin, t);
        for p in &a.constructor.resolved_signature.parameters {
            let t = self.reference_attribute_type(origin, p)?;
            out.fixed
                .push(attribute_value_scoped(&mut r, t, &mut resolver, 0)?);
        }
        let count = r.uint(2)?;
        out.named = named_arguments_scoped(&mut r, count, &mut resolver)?;
        if r.p != r.b.len() {
            return Err(err("trailing attribute bytes"));
        }
        Ok(out)
    }
    pub fn serialized_attributes(
        &self,
        origin: &'m Metadata<'data>,
        parent: Option<Token>,
    ) -> Result<Vec<AttributeRecord<'data>>> {
        origin
            .attributes(parent)?
            .into_iter()
            .map(|attribute| {
                let (decoded, decode_error) = match self.decode_attribute(origin, &attribute) {
                    Ok(v) => (Some(v), None),
                    Err(e) => (None, Some(e.to_string())),
                };
                Ok(AttributeRecord {
                    attribute,
                    decoded,
                    decode_error,
                })
            })
            .collect()
    }
    pub fn decode_security(
        &self,
        origin: &'m Metadata<'data>,
        b: &[u8],
    ) -> Result<SecurityDeclaration> {
        decode_security(b, &mut |name| self.enum_underlying_in(origin, name))
    }
    pub fn security_records(
        &self,
        origin: &'m Metadata<'data>,
    ) -> Result<Vec<SecurityRecord<'data>>> {
        origin.security_records(&mut |name| self.enum_underlying_in(origin, name))
    }
}
/// Metadata module identity. A nil Mvid heap index is represented by an empty MVID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleIdentity {
    pub name: String,
    pub mvid: String,
}
impl Metadata<'_> {
    pub fn module_identity(&self) -> Result<ModuleIdentity> {
        if self.tables[0].count != 1 {
            return Err(err("metadata must contain one Module row"));
        }
        let r = self.row(0, 1)?;
        let name = self.string(r[1])?.to_owned();
        if name.is_empty() {
            return Err(err("empty module name"));
        }
        let mvid = if r[2] == 0 {
            String::new()
        } else {
            let g = self.guid(r[2])?;
            format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
                u32::from_le_bytes(g[..4].try_into().unwrap()),
                u16::from_le_bytes(g[4..6].try_into().unwrap()),
                u16::from_le_bytes(g[6..8].try_into().unwrap()),
                g[8],
                g[9],
                g[10..]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        };
        Ok(ModuleIdentity { name, mvid })
    }
}
fn reference_primitive_kinds() -> &'static [(&'static str, &'static str)] {
    &[
        ("bool", "System.Boolean"),
        ("char", "System.Char"),
        ("int8", "System.SByte"),
        ("uint8", "System.Byte"),
        ("int16", "System.Int16"),
        ("uint16", "System.UInt16"),
        ("int32", "System.Int32"),
        ("uint32", "System.UInt32"),
        ("int64", "System.Int64"),
        ("uint64", "System.UInt64"),
        ("float32", "System.Single"),
        ("float64", "System.Double"),
        ("string", "System.String"),
        ("object", "System.Object"),
        ("native int", "System.IntPtr"),
        ("native uint", "System.UIntPtr"),
    ]
}
impl Metadata<'_> {
    fn reference_serialized_argument_name(&self, t: &Type, depth: usize) -> Result<String> {
        if depth > 64 {
            return Err(err("generic signature nesting limit"));
        }
        if let Some((_, name)) = reference_primitive_kinds()
            .iter()
            .find(|(k, _)| *k == t.kind)
        {
            return Ok((*name).into());
        }
        if matches!(t.kind.as_str(), "class" | "valuetype") {
            return self.reference_enum_type_name(t.token);
        }
        if t.kind == "genericinst" && t.args.len() > 1 {
            let base = self.reference_serialized_argument_name(&t.args[0], depth + 1)?;
            let (mut name, id) = reference_parse_identity(&base, false)?;
            let mut args = vec![];
            for arg in &t.args[1..] {
                args.push(format!(
                    "[{}]",
                    self.reference_serialized_argument_name(arg, depth + 1)?
                ));
            }
            name = format!("{}[{}]", name, args.join(","));
            if let Some(id) = id {
                name = format!("{name}, {id}");
            }
            return Ok(name);
        }
        if t.kind == "array" && t.args.len() == 1 && t.rank > 0 && t.rank <= 32 {
            let element = self.reference_serialized_argument_name(&t.args[0], depth + 1)?;
            let (mut name, id) = reference_parse_identity(&element, true)?;
            let suffix = if t.rank == 1 {
                "*".into()
            } else {
                ",".repeat(t.rank as usize - 1)
            };
            name = format!("{name}[{suffix}]");
            if let Some(id) = id {
                name = format!("{name}, {id}");
            }
            return Ok(name);
        }
        if t.kind == "szarray" && t.args.len() == 1 {
            let base = self.reference_serialized_argument_name(&t.args[0], depth + 1)?;
            let (mut name, id) = reference_parse_identity(&base, true)?;
            name.push_str("[]");
            if let Some(id) = id {
                name = format!("{name}, {id}");
            }
            return Ok(name);
        }
        Err(err("open/indirect generic argument signature"))
    }
}

#[cfg(test)]
mod reference_tests {
    use super::*;
    fn str_index(strings: &mut Vec<u8>, value: &str) -> u32 {
        let n = strings.len() as u32;
        strings.extend_from_slice(value.as_bytes());
        strings.push(0);
        n
    }
    fn enum_fixture(name: &str, version: u16, storage: u8, forward: Option<&str>) -> Vec<u8> {
        let mut strings = vec![0];
        let mut blob = vec![0];
        let mut rows = std::collections::BTreeMap::<usize, Vec<Vec<u32>>>::new();
        let module = str_index(&mut strings, &format!("{name}.dll"));
        let assembly = str_index(&mut strings, name);
        let module_type = str_index(&mut strings, "<Module>");
        let runtime = str_index(&mut strings, "System.Runtime");
        rows.insert(0, vec![vec![0, module, 0, 0, 0]]);
        rows.insert(
            32,
            vec![vec![0, version as u32, 0, 0, 0, 0, 0, assembly, 0]],
        );
        rows.insert(2, vec![vec![0, module_type, 0, 0, 1, 1]]);
        rows.insert(35, vec![vec![4, 0, 0, 0, 0, 0, runtime, 0, 0]]);
        if let Some(target) = forward {
            let target = str_index(&mut strings, target);
            rows.get_mut(&35)
                .unwrap()
                .push(vec![1, 0, 0, 0, 0, 0, target, 0, 0]);
            let mode = str_index(&mut strings, "Mode");
            let namespace = str_index(&mut strings, "External");
            rows.insert(39, vec![vec![0x200000, 0, mode, namespace, 9]]);
        } else {
            let base = str_index(&mut strings, "Enum");
            let system = str_index(&mut strings, "System");
            rows.insert(1, vec![vec![6, base, system]]);
            let mode = str_index(&mut strings, "Mode");
            let namespace = str_index(&mut strings, "External");
            rows.get_mut(&2)
                .unwrap()
                .push(vec![0x101, mode, namespace, 5, 1, 1]);
            let value = str_index(&mut strings, "value__");
            blob.extend_from_slice(&[2, 6, storage]);
            rows.insert(4, vec![vec![0x606, value, 1]]);
        }
        reference_fixture_bytes(rows, strings, blob)
    }
    fn reference_fixture_bytes(
        rows: std::collections::BTreeMap<usize, Vec<Vec<u32>>>,
        strings: Vec<u8>,
        blob: Vec<u8>,
    ) -> Vec<u8> {
        reference_fixture_bytes_with_guids(rows, strings, blob, vec![])
    }
    fn reference_fixture_bytes_with_guids(
        rows: std::collections::BTreeMap<usize, Vec<Vec<u32>>>,
        strings: Vec<u8>,
        blob: Vec<u8>,
        guids: Vec<u8>,
    ) -> Vec<u8> {
        let mut tables = vec![0u8; 24];
        tables[4] = 2;
        tables[7] = 1;
        let mut valid = 0u64;
        for (&table, r) in &rows {
            valid |= 1 << table;
            tables.extend_from_slice(&(r.len() as u32).to_le_bytes());
        }
        tables[8..16].copy_from_slice(&valid.to_le_bytes());
        for (&table, r) in &rows {
            for row in r {
                for (i, &value) in row.iter().enumerate() {
                    if matches!(
                        (table, i),
                        (2, 0) | (32, 0) | (32, 5) | (35, 4) | (38, 0) | (39, 0) | (39, 1)
                    ) {
                        tables.extend_from_slice(&value.to_le_bytes());
                    } else {
                        tables.extend_from_slice(&(value as u16).to_le_bytes());
                    }
                }
            }
        }
        let count = if guids.is_empty() { 3u16 } else { 4 };
        let mut b = vec![0u8; if count == 3 { 72 } else { 88 }];
        b[..4].copy_from_slice(b"BSJB");
        b[12..16].copy_from_slice(&4u32.to_le_bytes());
        b[16] = b'v';
        b[22..24].copy_from_slice(&count.to_le_bytes());
        let mut p = 24;
        let mut streams = vec![("#~", tables), ("#Strings", strings), ("#Blob", blob)];
        if !guids.is_empty() {
            streams.push(("#GUID", guids));
        }
        for (name, data) in streams {
            let offset = b.len() as u32;
            b[p..p + 4].copy_from_slice(&offset.to_le_bytes());
            b[p + 4..p + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            b[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
            p = (p + 8 + name.len() + 1 + 3) & !3;
            b.extend_from_slice(&data);
        }
        b
    }

    fn escaped_enum_fixture(forward: bool) -> Vec<u8> {
        let mut strings = vec![0];
        let mut blob = vec![0];
        let mut rows = std::collections::BTreeMap::<usize, Vec<Vec<u32>>>::new();
        let assembly = str_index(&mut strings, if forward { "Facade" } else { "Escaped" });
        let module = str_index(&mut strings, "Escaped.dll");
        let module_type = str_index(&mut strings, "<Module>");
        let runtime = str_index(&mut strings, "System.Runtime");
        let escaped = str_index(&mut strings, "Escaped");
        rows.insert(0, vec![vec![0, module, 0, 0, 0]]);
        rows.insert(32, vec![vec![0, 1, 0, 0, 0, 0, 0, assembly, 0]]);
        rows.insert(2, vec![vec![0, module_type, 0, 0, 1, 1]]);
        if forward {
            rows.insert(35, vec![vec![1, 0, 0, 0, 0, 0, escaped, 0, 0]]);
            let literal = str_index(&mut strings, "Outer+Mode");
            let outer = str_index(&mut strings, "Outer");
            let mode = str_index(&mut strings, "Mode");
            let comma = str_index(&mut strings, "Mode, Other");
            let ns = str_index(&mut strings, "External");
            rows.insert(
                39,
                vec![
                    vec![0x200000, 0, literal, ns, 5],
                    vec![0x200000, 0, outer, ns, 5],
                    vec![2, 0, mode, 0, 10],
                    vec![0x200000, 0, comma, ns, 5],
                ],
            );
        } else {
            rows.insert(
                35,
                vec![
                    vec![4, 0, 0, 0, 0, 0, runtime, 0, 0],
                    vec![1, 0, 0, 0, 0, 0, escaped, 0, 0],
                ],
            );
            let base = str_index(&mut strings, "Enum");
            let system = str_index(&mut strings, "System");
            let literal = str_index(&mut strings, "Outer+Mode");
            let outer = str_index(&mut strings, "Outer");
            let mode = str_index(&mut strings, "Mode");
            let comma = str_index(&mut strings, "Mode, Other");
            let slash = str_index(&mut strings, r"Back\Slash");
            let ns = str_index(&mut strings, "External");
            rows.insert(
                1,
                vec![
                    vec![6, base, system],
                    vec![10, literal, ns],
                    vec![10, outer, ns],
                    vec![15, mode, 0],
                    vec![10, comma, ns],
                    vec![10, slash, ns],
                ],
            );
            for (name, namespace, code, parent) in [
                ("Outer+Mode", "External", 7u8, 0),
                ("Outer", "External", 0, 0),
                ("Mode", "", 4, 3),
                ("Mode, Other", "External", 9, 0),
                (r"Back\Slash", "External", 5, 0),
                ("Br[ack]*&et", "External", 10, 0),
                ("Tail,", "External", 11, 0),
                ("Leaf", r"Ns+Comma,\[]", 6, 0),
            ] {
                let rid = rows[&2].len() as u32 + 1;
                let start = rows.get(&4).map(|r| r.len()).unwrap_or(0) as u32 + 1;
                let flags = if parent == 0 {
                    0x101
                } else {
                    rows.entry(41).or_default().push(vec![rid, parent]);
                    0x102
                };
                let name = str_index(&mut strings, name);
                let namespace = str_index(&mut strings, namespace);
                rows.get_mut(&2).unwrap().push(vec![
                    flags,
                    name,
                    namespace,
                    if code == 0 { 0 } else { 5 },
                    start,
                    1,
                ]);
                if code != 0 {
                    let value = str_index(&mut strings, "value__");
                    let index = blob.len() as u32;
                    blob.extend_from_slice(&[2, 6, code]);
                    rows.entry(4).or_default().push(vec![0x606, value, index]);
                }
            }
        }
        reference_fixture_bytes(rows, strings, blob)
    }
    #[test]
    fn escaped_enum_names_and_scope() {
        let bytes = escaped_enum_fixture(false);
        let other_bytes = enum_fixture("Other", 1, 10, None);
        let m = Metadata::parse(&bytes).unwrap();
        let other = Metadata::parse(&other_bytes).unwrap();
        let refs = ReferenceSet::new(&m, &[&other]).unwrap();
        for (name, want) in [
            (r"External.Outer\+Mode", "uint16"),
            (r"External.Outer+Mode", "int8"),
            (r"External.Mode\, Other", "uint32"),
            (r"External.Back\\Slash", "uint8"),
            (r"External.Br\[ack\]\*\&et", "int64"),
            (r"External.Tail\,", "uint64"),
            (r"Ns\+Comma\,\\\[\].Leaf", "int16"),
        ] {
            assert_eq!(refs.enum_underlying(name).unwrap(), want);
            assert_eq!(m.local_enum_underlying(name).unwrap(), want);
            assert_eq!(
                refs.enum_underlying(&format!(
                    "{name}, Escaped, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
                ))
                .unwrap(),
                want
            );
        }
        assert_eq!(
            refs.enum_underlying("External.Mode, Other").unwrap(),
            "int64"
        );
        for (rid, want) in [
            (2, r"External.Outer\+Mode"),
            (4, r"External.Outer+Mode"),
            (5, r"External.Mode\, Other"),
            (6, r"External.Back\\Slash"),
        ] {
            let mut typ = Type::new("valuetype");
            typ.token = Token(1 << 24 | rid);
            let name = m.attribute_type(&typ).unwrap().enum_name;
            assert_eq!(
                name,
                format!("{want}, Escaped, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null")
            );
            refs.enum_underlying(&name).unwrap();
        }
        for name in [
            r"External.Mode\",
            r"External.Mode\q",
            r"External.Outer++Mode",
            r"External.Outer+",
            r"External.Outer\+Mode[]",
            r"External.Mode\, Other,",
            r"External.Mode\, Other, Other",
        ] {
            assert!(refs.enum_underlying(name).is_err(), "{name}");
        }
        let facade_bytes = escaped_enum_fixture(true);
        let facade = Metadata::parse(&facade_bytes).unwrap();
        let forward = ReferenceSet::new(&facade, &[&m, &other]).unwrap();
        for (name, want) in [
            (r"External.Outer\+Mode, Facade", "uint16"),
            (r"External.Outer+Mode, Facade", "int8"),
            (r"External.Mode\, Other, Facade", "uint32"),
        ] {
            assert_eq!(forward.enum_underlying(name).unwrap(), want);
        }
    }
    #[test]
    fn explicit_enum_identity_and_conflicts() {
        let local_bytes = enum_fixture("Local", 1, 8, None);
        let one_bytes = enum_fixture("One", 1, 7, None);
        let two_bytes = enum_fixture("Two", 1, 4, None);
        let v2_bytes = enum_fixture("One", 2, 10, None);
        let duplicate_bytes = enum_fixture("One", 1, 4, None);
        let local = Metadata::parse(&local_bytes).unwrap();
        let one = Metadata::parse(&one_bytes).unwrap();
        let two = Metadata::parse(&two_bytes).unwrap();
        let v2 = Metadata::parse(&v2_bytes).unwrap();
        let duplicate = Metadata::parse(&duplicate_bytes).unwrap();
        let refs = ReferenceSet::new(&local, &[&one, &two, &v2]).unwrap();
        for (name, want) in [
            ("External.Mode", "int32"),
            ("External.Mode, Two", "int8"),
            (
                "External.Mode, One, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
                "uint16",
            ),
            ("External.Mode, One, Version=2.0.0.0", "int64"),
        ] {
            assert_eq!(refs.enum_underlying(name).unwrap(), want);
        }
        for name in [
            "External.Mode, One",
            "External.Mode, Missing",
            "External.Mode, One, Version=3.0.0.0",
            "External.Mode, Two, PublicKeyToken=0011223344556677",
            "External.Mode, Two, Culture=fr",
            "External.Mode, Two, Version=1.0.0",
            "External.Mode, Two, Version=01.0.0.0",
            "External.Mode, Two, Culture=neutral, Culture=neutral",
            "External.Mode, Two, Unknown=x",
            "External.Mode[]",
            ", Two",
        ] {
            assert!(refs.enum_underlying(name).is_err(), "{name}");
        }
        assert!(ReferenceSet::new(&local, &[&one, &duplicate]).is_err());
        assert!(ReferenceSet::new(&local, &[&one, &one]).is_ok());
        assert_eq!(
            local.local_enum_underlying("External.Mode").unwrap(),
            "int32"
        );
        for (code, want) in [
            (4, "int8"),
            (5, "uint8"),
            (6, "int16"),
            (7, "uint16"),
            (8, "int32"),
            (9, "uint32"),
            (10, "int64"),
            (11, "uint64"),
        ] {
            let data = enum_fixture("Storage", 1, code, None);
            let m = Metadata::parse(&data).unwrap();
            let refs = ReferenceSet::new(&m, &[]).unwrap();
            assert_eq!(refs.enum_underlying("External.Mode").unwrap(), want);
        }
        let invalid_bytes = enum_fixture("Invalid", 1, 12, None);
        let invalid = Metadata::parse(&invalid_bytes).unwrap();
        assert!(ReferenceSet::new(&invalid, &[])
            .unwrap()
            .enum_underlying("External.Mode")
            .is_err());
        let mut signature_type = Type::new("valuetype");
        signature_type.token = Token(1 << 24 | 1);
        assert_eq!(
            one.attribute_type(&signature_type).unwrap().enum_name,
            "System.Enum, System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=null"
        );
    }
    #[test]
    fn explicit_enum_forwarders() {
        let local_bytes = enum_fixture("Local", 1, 8, None);
        let one_bytes = enum_fixture("One", 1, 7, None);
        let facade_bytes = enum_fixture("Facade", 1, 0, Some("One"));
        let a_bytes = enum_fixture("A", 1, 0, Some("B"));
        let b_bytes = enum_fixture("B", 1, 0, Some("A"));
        let local = Metadata::parse(&local_bytes).unwrap();
        let one = Metadata::parse(&one_bytes).unwrap();
        let facade = Metadata::parse(&facade_bytes).unwrap();
        let a = Metadata::parse(&a_bytes).unwrap();
        let b = Metadata::parse(&b_bytes).unwrap();
        let refs = ReferenceSet::new(&local, &[&one, &facade]).unwrap();
        assert_eq!(
            refs.enum_underlying("External.Mode, Facade").unwrap(),
            "uint16"
        );
        assert!(ReferenceSet::new(&local, &[&facade])
            .unwrap()
            .enum_underlying("External.Mode, Facade")
            .is_err());
        assert!(ReferenceSet::new(&local, &[&a, &b])
            .unwrap()
            .enum_underlying("External.Mode, A")
            .unwrap_err()
            .to_string()
            .contains("cycle"));
    }
    #[test]
    fn assembly_token_sha1() {
        assert_eq!(
            reference_key_token(b"abc", true).unwrap(),
            "9dd8d09c6cc25078"
        );
        assert_eq!(reference_key_token(&[], false).unwrap(), "null");
        assert!(reference_key_token(&[1], false).is_err());
        assert_eq!(
            reference_key_token(&[1, 2, 3, 4, 5, 6, 7, 8], false).unwrap(),
            "0102030405060708"
        );
    }

    #[test]
    fn compiled_escaped_enum_identifiers() {
        let Ok(dir) = std::env::var("MKASM_DOTNET_REFERENCE_ARTIFACTS") else {
            return;
        };
        let data = std::fs::read(std::path::Path::new(&dir).join("Escaped.dll")).unwrap();
        let image = Image::open(&data).unwrap();
        let refs = ReferenceSet::new(&image.metadata, &[]).unwrap();
        for (name, want) in [
            (r"External.Outer\+Mode", "uint16"),
            (r"External.Outer+Mode", "int8"),
            (r"External.Mode\, Other", "uint32"),
            (r"External.Back\\Slash", "uint8"),
            (r"External.Br\[ack\]\*\&et", "int64"),
            (r"External.Tail\,", "uint64"),
            (r"Ns\+Comma\,\\\[\].Leaf", "int16"),
        ] {
            assert_eq!(
                refs.enum_underlying(&format!("{name}, Escaped")).unwrap(),
                want
            );
            assert_eq!(image.metadata.local_enum_underlying(name).unwrap(), want);
        }
    }

    fn netmodule_fixture(name: &str, storage: u8, manifest: Option<(&str, u32, u32)>) -> Vec<u8> {
        let mut strings = vec![0];
        let mut blob = vec![0];
        let mut rows = std::collections::BTreeMap::<usize, Vec<Vec<u32>>>::new();
        let module_name = str_index(
            &mut strings,
            if manifest.is_some() {
                "Manifest.dll"
            } else {
                name
            },
        );
        let module_type = str_index(&mut strings, "<Module>");
        rows.insert(
            0,
            vec![vec![
                0,
                module_name,
                if manifest.is_some() { 0 } else { 1 },
                0,
                0,
            ]],
        );
        rows.insert(2, vec![vec![0, module_type, 0, 0, 1, 1]]);
        if let Some((assembly, hint, flags)) = manifest {
            let assembly = str_index(&mut strings, assembly);
            rows.insert(32, vec![vec![0, 1, 0, 0, 0, 0, 0, assembly, 0]]);
            let filename = str_index(&mut strings, name);
            blob.extend_from_slice(&[3, 1, 2, 3]);
            rows.insert(38, vec![vec![flags, filename, 1]]);
            let mode = str_index(&mut strings, "Mode");
            let external = str_index(&mut strings, "External");
            rows.insert(39, vec![vec![1, hint, mode, external, 4]]);
            reference_fixture_bytes(rows, strings, blob)
        } else {
            let runtime = str_index(&mut strings, "System.Runtime");
            rows.insert(35, vec![vec![4, 0, 0, 0, 0, 0, runtime, 0, 0]]);
            let enum_name = str_index(&mut strings, "Enum");
            let system = str_index(&mut strings, "System");
            rows.insert(1, vec![vec![6, enum_name, system]]);
            let mode = str_index(&mut strings, "Mode");
            let external = str_index(&mut strings, "External");
            rows.get_mut(&2)
                .unwrap()
                .push(vec![0x101, mode, external, 5, 1, 1]);
            let value = str_index(&mut strings, "value__");
            blob.extend_from_slice(&[2, 6, storage]);
            rows.insert(4, vec![vec![0x606, value, 1]]);
            reference_fixture_bytes_with_guids(
                rows,
                strings,
                blob,
                vec![4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16],
            )
        }
    }
    #[test]
    fn netmodule_binding_boundaries() {
        let bytes = netmodule_fixture("Enums.netmodule", 7, None);
        let manifest_bytes =
            netmodule_fixture("Enums.netmodule", 0, Some(("Manifest", 0x02000002, 0)));
        let duplicate_bytes = netmodule_fixture("Enums.netmodule", 4, None);
        let module = Metadata::parse(&bytes).unwrap();
        let manifest = Metadata::parse(&manifest_bytes).unwrap();
        let duplicate = Metadata::parse(&duplicate_bytes).unwrap();
        let refs = ReferenceSet::new(&manifest, &[&module]).unwrap();
        assert_eq!(
            module.module_identity().unwrap().mvid,
            "01020304-0506-0708-090a-0b0c0d0e0f10"
        );
        assert_eq!(
            refs.enum_underlying("External.Mode, Manifest").unwrap(),
            "uint16"
        );
        assert!(std::ptr::eq(
            refs.module_owner(&module).unwrap().unwrap(),
            &manifest
        ));
        let mut ambiguous = ReferenceSet::new(&manifest, &[&module, &duplicate]).unwrap();
        assert!(ambiguous
            .enum_underlying("External.Mode, Manifest")
            .is_err());
        ambiguous
            .bind_module(&manifest, Token(38 << 24 | 1), &module)
            .unwrap();
        assert_eq!(
            ambiguous
                .enum_underlying("External.Mode, Manifest")
                .unwrap(),
            "uint16"
        );
        assert!(ambiguous
            .bind_module(&manifest, Token(38 << 24 | 1), &duplicate)
            .is_err());
        let alias_bytes = netmodule_fixture("renamed.bin", 0, Some(("Alias", 2, 0)));
        let alias = Metadata::parse(&alias_bytes).unwrap();
        let mut explicit = ReferenceSet::new(&alias, &[&module]).unwrap();
        assert!(explicit.enum_underlying("External.Mode, Alias").is_err());
        explicit
            .bind_module(&alias, Token(38 << 24 | 1), &module)
            .unwrap();
        assert_eq!(
            explicit.enum_underlying("External.Mode, Alias").unwrap(),
            "uint16"
        );
        assert!(std::ptr::eq(
            explicit
                .scope_module(&alias, Some(&alias), "Enums.netmodule")
                .unwrap(),
            &module
        ));
        assert!(explicit
            .scope_module(&alias, Some(&alias), "renamed.bin")
            .is_err());
        let other_bytes = netmodule_fixture("Enums.netmodule", 0, Some(("Other", 2, 0)));
        let other = Metadata::parse(&other_bytes).unwrap();
        let owners = ReferenceSet::new(&manifest, &[&module, &other]).unwrap();
        assert!(owners.enum_underlying_in(&module, "External.Mode").is_err());
        for (assembly, hint, flags) in [("Stale", 1, 0), ("Resource", 2, 1)] {
            let data = netmodule_fixture("Enums.netmodule", 0, Some((assembly, hint, flags)));
            let m = Metadata::parse(&data).unwrap();
            let mut set = ReferenceSet::new(&m, &[&module]).unwrap();
            assert!(set
                .enum_underlying(&format!("External.Mode, {assembly}"))
                .is_err());
            if flags == 1 {
                assert!(set.bind_module(&m, Token(38 << 24 | 1), &module).is_err());
            }
        }
        let standalone = ReferenceSet::new(&module, &[]).unwrap();
        assert_eq!(
            standalone.enum_underlying("External.Mode").unwrap(),
            "uint16"
        );
        assert!(standalone
            .scope_module(&module, None, "Other.netmodule")
            .is_err());
    }
    #[test]
    fn compiled_netmodule_references() {
        let Ok(dir) = std::env::var("MKASM_DOTNET_REFERENCE_ARTIFACTS") else {
            return;
        };
        let dir = std::path::Path::new(&dir).join("Modules");
        let manifest_bytes = std::fs::read(dir.join("Manifest.dll")).unwrap();
        let enums_bytes = std::fs::read(dir.join("Enums.netmodule")).unwrap();
        let consumer_bytes = std::fs::read(dir.join("Consumer.netmodule")).unwrap();
        let manifest = Image::open(&manifest_bytes).unwrap();
        let enums = Image::open(&enums_bytes).unwrap();
        let consumer = Image::open(&consumer_bytes).unwrap();
        let set =
            ReferenceSet::new(&manifest.metadata, &[&enums.metadata, &consumer.metadata]).unwrap();
        assert_eq!(
            set.enum_underlying("Multi.Mode, Manifest").unwrap(),
            "uint16"
        );
        assert_eq!(
            set.enum_underlying("Multi.Outer+Nested, Manifest").unwrap(),
            "int8"
        );
        let oracle = std::fs::read_to_string(dir.join("oracle.jsonl")).unwrap();
        for origin in [&manifest.metadata, &enums.metadata, &consumer.metadata] {
            let id = origin.module_identity().unwrap();
            assert!(oracle
                .lines()
                .any(|line| line.contains(&format!("\"name\":\"{}\"", id.name))
                    && line.contains(&format!("\"mvid\":\"{}\"", id.mvid))));
            let records = set.serialized_attributes(origin, None).unwrap();
            let mut count = 0;
            for record in records {
                if record.attribute.constructor.declaring_type != "Multi.MarkAttribute" {
                    continue;
                }
                count += 1;
                assert!(record.decode_error.is_none(), "{:?}", record.decode_error);
                let v = record.decoded.unwrap();
                assert_eq!(v.fixed[0].bits, 0x8123);
                assert_eq!(v.fixed[1].bits, 0xf9);
                assert_eq!(v.named[0].value.bits, 0x8123);
                assert_eq!(
                    v.fixed[0].typ.enum_module.as_ref().unwrap().name,
                    "Enums.netmodule"
                );
                assert!(v.fixed[0].typ.enum_name.contains(", Manifest,"));
            }
            assert_eq!(count, 1);
        }
        for a in consumer.metadata.attributes(None).unwrap() {
            if a.constructor.declaring_type == "Multi.MarkAttribute" {
                assert!(consumer
                    .metadata
                    .decode_attribute(&a, &mut |name| set.enum_underlying(name))
                    .is_err());
            }
        }
        let local =
            ReferenceSet::new(&consumer.metadata, &[&manifest.metadata, &enums.metadata]).unwrap();
        assert_eq!(local.enum_underlying("Multi.Mode").unwrap(), "uint16");
        let typ = "Multi.Mode";
        let mut payload = vec![1, 0x54, 0x55, typ.len() as u8];
        payload.extend_from_slice(typ.as_bytes());
        payload.extend_from_slice(&[1, b'E', 0x23, 0x81]);
        let mut security = vec![b'.', 1, 1, b'X', payload.len() as u8];
        security.extend_from_slice(&payload);
        assert_eq!(
            set.decode_security(&consumer.metadata, &security)
                .unwrap()
                .attributes[0]
                .named[0]
                .value
                .bits,
            0x8123
        );
        let missing = ReferenceSet::new(&manifest.metadata, &[&consumer.metadata]).unwrap();
        assert!(missing.enum_underlying("Multi.Mode, Manifest").is_err());
    }

    #[test]
    fn closed_generic_enum_definitions() {
        let mut strings = vec![0];
        let mut rows = std::collections::BTreeMap::<usize, Vec<Vec<u32>>>::new();
        let module = str_index(&mut strings, "Generic.dll");
        let assembly = str_index(&mut strings, "Generic");
        let module_type = str_index(&mut strings, "<Module>");
        let runtime = str_index(&mut strings, "System.Runtime");
        let enum_name = str_index(&mut strings, "Enum");
        let system = str_index(&mut strings, "System");
        let outer = str_index(&mut strings, "Outer`1");
        let external = str_index(&mut strings, "External");
        let mode = str_index(&mut strings, "Mode");
        let value = str_index(&mut strings, "value__");
        let t = str_index(&mut strings, "T");
        rows.insert(0, vec![vec![0, module, 0, 0, 0]]);
        rows.insert(32, vec![vec![0, 1, 0, 0, 0, 0, 0, assembly, 0]]);
        rows.insert(35, vec![vec![4, 0, 0, 0, 0, 0, runtime, 0, 0]]);
        rows.insert(1, vec![vec![6, enum_name, system]]);
        rows.insert(
            2,
            vec![
                vec![0, module_type, 0, 0, 1, 1],
                vec![1, outer, external, 0, 1, 1],
                vec![0x102, mode, 0, 5, 1, 1],
            ],
        );
        rows.insert(4, vec![vec![0x606, value, 1]]);
        rows.insert(41, vec![vec![3, 2]]);
        rows.insert(42, vec![vec![0, 0, 4, t], vec![0, 0, 6, t]]);
        let bytes = reference_fixture_bytes(rows, strings, vec![0, 2, 6, 5]);
        let m = Metadata::parse(&bytes).unwrap();
        let refs = ReferenceSet::new(&m, &[]).unwrap();
        assert_eq!(
            m.local_enum_underlying("External.Outer`1+Mode[System.Int32]")
                .unwrap(),
            "uint8"
        );
        for name in [
            "External.Outer`1+Mode[System.Int32]",
            "External.Outer`1+Mode[[System.Int32]]",
            "External.Outer`1+Mode[System.Int32[]]",
            "External.Outer`1+Mode[System.Int32[,]]",
            "External.Outer`1+Mode[System.Int32[*]]",
            "External.Outer`1+Mode[[External.Outer`1[System.String], Generic]], Generic",
        ] {
            assert_eq!(refs.enum_underlying(name).unwrap(), "uint8");
        }
        for name in [
            "External.Outer`1+Mode",
            "External.Outer`1+Mode[System.Int32,System.String]",
            "External.Outer`1+Mode[[System.Int32],]",
            "External.Outer`1+Mode[System.Int32]x",
            "External.Outer`1+Mode[System.Void]",
            "External.Outer`1+Mode[[System.Int32, Missing]]",
            "External.Outer`1+Mode[T]",
            "External.Outer`1+Mode[!0]",
            "External.Outer`1+Mode[System.Int32&]",
            "External.Outer`1[System.Int32]",
        ] {
            assert!(refs.enum_underlying(name).is_err(), "{name}");
        }
        let primitive = Type::new("int32");
        let mut vector = Type::new("szarray");
        vector.args.push(primitive.clone());
        let mut matrix = Type::new("array");
        matrix.rank = 2;
        matrix.args.push(primitive.clone());
        for argument in [primitive, vector, matrix] {
            let mut base = Type::new("valuetype");
            base.token = Token(2 << 24 | 3);
            let mut signature = Type::new("genericinst");
            signature.args = vec![base, argument];
            let typ = refs.reference_attribute_type(&m, &signature).unwrap();
            assert_eq!(typ.enum_arguments.len(), 1);
            assert_eq!(refs.resolve_serialized_enum(&m, &typ).unwrap(), "uint8");
            let legacy = m.attribute_type(&signature).unwrap();
            assert_eq!(refs.enum_underlying(&legacy.enum_name).unwrap(), "uint8");
        }
    }
    #[test]
    fn compiled_reference_assemblies() {
        let Ok(dir) = std::env::var("MKASM_DOTNET_REFERENCE_ARTIFACTS") else {
            return;
        };
        let read = |project: &str, reference: bool| {
            std::fs::read(
                std::path::Path::new(&dir)
                    .join(project)
                    .join(if reference {
                        "obj/Release/net10.0/ref"
                    } else {
                        "bin/Release/net10.0"
                    })
                    .join(format!("{project}.dll")),
            )
            .unwrap()
        };
        let client_bytes = read("Client", false);
        let first_bytes = read("First", true);
        let second_bytes = read("Second", true);
        let facade_bytes = read("Facade", true);
        let client = Image::open(&client_bytes).unwrap();
        let first = Image::open(&first_bytes).unwrap();
        let second = Image::open(&second_bytes).unwrap();
        let facade = Image::open(&facade_bytes).unwrap();
        let generic_runtime_bytes =
            std::fs::read(std::path::Path::new(&dir).join("Generic/System.Runtime.dll")).unwrap();
        let generic_runtime = Image::open(&generic_runtime_bytes).unwrap();
        let refs = ReferenceSet::new(
            &client.metadata,
            &[
                &first.metadata,
                &second.metadata,
                &facade.metadata,
                &generic_runtime.metadata,
            ],
        )
        .unwrap();
        let mut count = 0;
        let mut generic_count = 0;
        for a in client.metadata.attributes(None).unwrap() {
            if a.constructor.declaring_type == "External.GenericMarkAttribute" {
                generic_count += 1;
                let value = refs.decode_attribute(&client.metadata, &a).unwrap();
                assert_eq!(value.fixed[0].bits, 0x82);
                assert_eq!(value.fixed[1].elements[0].bits, 0x82);
                assert_eq!(value.fixed[0].typ.enum_arguments.len(), 1);
                assert_eq!(value.fixed[0].typ.enum_arguments[0].kind, "int32");
                assert!(value.fixed[0]
                    .typ
                    .enum_name
                    .contains("GenericOuter`1+Mode[[System.Int32]]"));
                client
                    .metadata
                    .decode_attribute(&a, &mut |n| refs.enum_underlying(n))
                    .unwrap();
                assert!(ReferenceSet::new(&client.metadata, &[&first.metadata])
                    .unwrap()
                    .decode_attribute(&client.metadata, &a)
                    .is_err());
            }
            if a.constructor.declaring_type != "External.MarkAttribute" {
                continue;
            }
            count += 1;
            assert!(client
                .metadata
                .decode_attribute(&a, &mut |n| client.metadata.local_enum_underlying(n))
                .is_err());
            let v = client
                .metadata
                .decode_attribute(&a, &mut |n| refs.enum_underlying(n))
                .unwrap();
            assert_eq!(v.fixed.len(), 3);
            assert_eq!(v.fixed[0].bits, 0x8123);
            assert_eq!(v.fixed[1].elements[0].bits, 0x8123);
            assert_eq!(v.fixed[2].elements[0].bits, 0x8123);
            assert_eq!(v.named[0].value.bits, 0x8123);
            assert!(v.fixed[0]
                .typ
                .enum_name
                .contains(", First, Version=1.2.3.4,"));
        }
        assert_eq!(count, 1);
        assert_eq!(generic_count, 1);
        for name in [
            "External.GenericOuter`1+Mode[System.Int32], First",
            "External.GenericOuter`1+Mode[[System.Int32]], First",
            "External.GenericOuter`1+Mode[System.Int32[]], First",
        ] {
            assert_eq!(refs.enum_underlying(name).unwrap(), "uint8");
        }
        for name in [
            "External.GenericOuter`1+Mode, First",
            "External.GenericOuter`1+Mode[], First",
            "External.GenericOuter`1+Mode[System.Int32,System.String], First",
            "External.GenericOuter`1+Mode[[System.Int32],], First",
            "External.GenericOuter`1+Mode[[System.Int32], First",
            "External.GenericOuter`1+Mode[Missing.Type], First",
            "External.GenericOuter`1+Mode[[System.Int32, Missing]], First",
            "External.GenericOuter`1+Mode[System.Int32*], First",
            "External.GenericOuter`1+Mode[!0], First",
            "External.GenericOuter`1[System.Int32], First",
        ] {
            assert!(refs.enum_underlying(name).is_err(), "{name}");
        }
        for (name, want) in [
            ("External.Mode, First", "uint16"),
            ("External.Mode, Second", "int8"),
            ("External.Mode, Facade", "uint16"),
            ("External.Outer+Nested, Facade", "uint8"),
        ] {
            assert_eq!(refs.enum_underlying(name).unwrap(), want);
        }
        assert!(refs.enum_underlying("External.Mode").is_err());

        let runtime_path = std::path::Path::new(&dir).join("Runtime");
        if let (Ok(runtime_bytes), Ok(core_bytes)) = (
            std::fs::read(runtime_path.join("System.Runtime.dll")),
            std::fs::read(runtime_path.join("System.Private.CoreLib.dll")),
        ) {
            let runtime = Image::open(&runtime_bytes).unwrap();
            let core = Image::open(&core_bytes).unwrap();
            assert_eq!(
                core.metadata.assembly_identity().unwrap().public_key_token,
                "7cec85d7bea7798e"
            );
            let framework =
                ReferenceSet::new(&client.metadata, &[&runtime.metadata, &core.metadata]).unwrap();
            assert_eq!(framework.enum_underlying("System.DayOfWeek, System.Runtime, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a").unwrap(),"int32");
        }
        let typ = "External.Mode, First, Version=1.2.3.4, Culture=neutral, PublicKeyToken=null";
        let mut payload = vec![1, 0x54, 0x55, typ.len() as u8];
        payload.extend_from_slice(typ.as_bytes());
        payload.extend_from_slice(&[1, b'E', 0x23, 0x81]);
        let mut security = vec![b'.', 1, 1, b'X', payload.len() as u8];
        security.extend_from_slice(&payload);
        let decoded = decode_security(&security, &mut |n| refs.enum_underlying(n)).unwrap();
        assert_eq!(decoded.attributes[0].named[0].value.bits, 0x8123);
    }
}
