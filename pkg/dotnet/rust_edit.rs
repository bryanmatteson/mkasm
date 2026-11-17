
#[derive(Clone, Copy, Debug, Default)]
pub struct RewriteOptions {
    pub drop_native: bool,
    pub strip_strong_name: bool,
    pub strip_authenticode: bool,
}
impl Image<'_> {
    /// Returns a new PE with replacement complete CIL method bodies. Tokens and
    /// all unrelated method bytes retain their identity. Signature/native-code
    /// invalidation requires explicit options, matching the Go API.
    pub fn rewrite_methods(&self, edits: &BTreeMap<Token, Vec<u8>>, options: RewriteOptions) -> Result<Vec<u8>> {
        if self.composite {return Err(err("rewrite the component IL image; composite images have no global CIL metadata"));}

        if !self.format.starts_with("PE") { return Err(err("rewriting requires a PE image")); }
        if edits.is_empty() { return Ok(self.data.to_vec()); }
        if self.ready_to_run && !options.drop_native { return Err(err("ReadyToRun rewriting requires drop_native")); }
        if options.drop_native {
            if !self.ready_to_run || self.cli.flags&0x10!=0{return Err(err("drop_native requires ReadyToRun with a managed entry point"));}
            for m in self.metadata.methods()? {
                if m.kind=="native" || (m.rva==0 && m.impl_flags&3==0 && m.flags&(0x400|0x2000)==0 && m.impl_flags&0x1000==0){return Err(err("cannot discard native code without retained IL bodies"));}
            }
        }
        if (self.cli.flags & 8 != 0 || self.cli.strong_name_signature.size != 0) && !options.strip_strong_name { return Err(err("signed image requires strip_strong_name")); }
        let pe = u32(self.data, 60)? as usize;
        let optional = pe + 24;
        let directory = if self.format == "PE32+" {112} else {96};
        let security = optional + directory + 32;
        if u32(self.data, security+4)? != 0 && !options.strip_authenticode { return Err(err("Authenticode image requires strip_authenticode")); }
        let file_align = u32(self.data, optional+36)? as u64;
        let section_align = u32(self.data, optional+32)? as u64;
        if !file_align.is_power_of_two() || !section_align.is_power_of_two() { return Err(err("invalid PE alignment")); }
        let align = |v:u64, a:u64| -> Result<u64> {v.checked_add(a-1).map(|n|n & !(a-1)).ok_or_else(||err("alignment overflow"))};
        for (token, body) in edits {
            if token.table() != 6 || self.method_body(*token)?.kind != "cil" { return Err(err("replacement requires a CIL MethodDef")); }
            if MethodBody::parse(body)?.raw.len() != body.len() { return Err(err("replacement has trailing bytes")); }
        }
        let table = optional + u16(self.data,pe+20)? as usize;
        let next_header = table + self.sections.len()*40;
        let first_raw = self.sections.iter().filter(|s|s.raw_size!=0).map(|s|s.raw_offset as usize).min().ok_or_else(||err("image has no sections"))?;
        let (last, max_va) = self.sections.iter().enumerate().map(|(i,s)|(i,s.virtual_address as u64+u64::from(s.virtual_size.max(s.raw_size)))).max_by_key(|(_,end)|*end).ok_or_else(||err("image has no sections"))?;
        let new_section = next_header+40 <= first_raw && next_header+40 <= self.size_of_headers as usize && self.sections.len()<u16::MAX as usize;
        let mut start = align(self.data.len() as u64,file_align)?;
        let mut base_va = align(max_va,section_align)?;
        let header = if new_section {next_header} else {
            let s=&self.sections[last];
            if self.sections.iter().any(|other|other.raw_offset as u64+other.raw_size as u64>s.raw_offset as u64+s.raw_size as u64) {return Err(err("no section header space and final section is not physically last"));}
            start=align(start.max(s.raw_offset as u64+s.virtual_size as u64),file_align)?;
            base_va=s.virtual_address as u64+start-s.raw_offset as u64;table+last*40
        };
        if start>u32::MAX as u64 || base_va>u32::MAX as u64 {return Err(err("PE address overflow"));}
        let mut out=self.data.to_vec();out.resize(start as usize,0);
        let mut rvas=BTreeMap::new();
        for (token,body) in edits {
            let p=align(out.len() as u64,4)?;out.resize(p as usize,0);
            let rva=base_va+p-start;
            if rva+body.len() as u64>u32::MAX as u64{return Err(err("PE address overflow"));}
            rvas.insert(*token,rva as u32);out.extend_from_slice(body);
        }
        let virtual_end=base_va+out.len() as u64-start;
        let raw_end=align(out.len() as u64,file_align)?;
        let image_size=align(virtual_end,section_align)?;
        if raw_end>u32::MAX as u64||image_size>u32::MAX as u64{return Err(err("PE address overflow"));}
        out.resize(raw_end as usize,0);
        let put=|b:&mut[u8],p:usize,v:u32|b[p..p+4].copy_from_slice(&v.to_le_bytes());
        if new_section {
            out[header..header+40].fill(0);out[header..header+5].copy_from_slice(b".mkil");
            put(&mut out,header+8,(virtual_end-base_va) as u32);put(&mut out,header+12,base_va as u32);put(&mut out,header+16,(raw_end-start) as u32);put(&mut out,header+20,start as u32);put(&mut out,header+36,0x40000040);
            out[pe+6..pe+8].copy_from_slice(&((self.sections.len()+1) as u16).to_le_bytes());
        } else {
            let s=&self.sections[last];put(&mut out,header+8,(virtual_end-s.virtual_address as u64) as u32);put(&mut out,header+16,(raw_end-s.raw_offset as u64) as u32);put(&mut out,header+36,(s.characteristics|0x40000040)&!0x02000000);
        }
        put(&mut out,optional+56,image_size as u32);put(&mut out,optional+64,0);
        // Source offsets in CodeView/Portable PDB data are invalid after edits.
        put(&mut out,optional+directory+6*8,0);put(&mut out,optional+directory+6*8+4,0);
        let mut initialized=u32(self.data,optional+8)? as u64;
        if new_section {initialized+=raw_end-start;}else{let s=&self.sections[last];initialized+=raw_end-s.raw_offset as u64-if s.characteristics&0x40!=0{s.raw_size as u64}else{0};}
        if initialized>u32::MAX as u64{return Err(err("PE initialized data overflow"));}
        put(&mut out,optional+8,initialized as u32);
        let metadata=self.rva_offset(self.cli.metadata.rva,self.cli.metadata.size)?;
        let tables_offset=self.metadata.streams.iter().find(|s|s.name=="#~"||s.name=="#-").ok_or_else(||err("missing tables stream"))?.offset as usize;
        let t=&self.metadata.tables[6];
        for (token,rva) in rvas {let p=metadata+tables_offset+t.offset+(token.rid() as usize-1)*t.row_size;span(&out,p,4)?;put(&mut out,p,rva);}
        let cli_rva=u32(&out,optional+directory+14*8)?;let cli=self.rva_offset(cli_rva,72)?;
        if options.drop_native {put(&mut out,cli+64,0);put(&mut out,cli+68,0);put(&mut out,cli+16,(self.cli.flags|1)&!4);}
        if options.strip_strong_name {
            let s=&self.cli.strong_name_signature;if s.size!=0{let p=self.rva_offset(s.rva,s.size)?;out[p..p+s.size as usize].fill(0);}
            put(&mut out,cli+32,0);put(&mut out,cli+36,0);let flags=u32(&out,cli+16)?;put(&mut out,cli+16,flags&!8);
        }
        if options.strip_authenticode {put(&mut out,security,0);put(&mut out,security+4,0);}
        let next=Image::open(&out)?;
        for (token,body) in edits {if next.method_body(*token)?.raw!=body.as_slice(){return Err(err("replacement validation failed"));}}
        Ok(out)
    }
}
