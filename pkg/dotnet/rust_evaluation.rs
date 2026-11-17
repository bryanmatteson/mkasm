#[derive(Debug,Clone,Copy)]
pub struct EvaluationContext {pub arguments:usize,pub locals:usize,pub returns_value:bool}
impl Signature {
    pub fn returns_value(&self)->bool{let Some(mut t)=self.return_type.as_ref() else{return false;};while matches!(t.kind.as_str(),"modreq"|"modopt")&&t.args.len()==1{t=&t.args[0];}t.kind!="void"}
}
impl Metadata<'_>{
    pub fn call_signature(&self,token:Token)->Result<Signature>{
        let s=if token.table()==17{
            let r=self.row(17,token.rid())?;self.parse_signature(self.blob(r[0])?)?
        }else{self.member(token)?.resolved_signature};
        if s.kind!="method"{return Err(err("call signature is not a method"));}Ok(s)
    }
    pub fn evaluation_context(&self,method:Token,locals:Token)->Result<EvaluationContext>{
        if method.table()!=6{return Err(err("method context requires MethodDef"));}
        let s=self.call_signature(method)?;
        let mut out=EvaluationContext{arguments:s.parameters.len()+usize::from(s.calling_convention&0x20!=0&&s.calling_convention&0x40==0),locals:0,returns_value:s.returns_value()};
        if locals.0!=0{
            if locals.table()!=17{return Err(err("locals require StandAloneSig"));}
            let r=self.row(17,locals.rid())?;let s=self.parse_signature(self.blob(r[0])?)?;
            if s.kind!="locals"{return Err(err("local token is not a local signature"));}out.locals=s.parameters.len();
        }Ok(out)
    }
}
