import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.app.plugin.processors.sleigh.expression.*;
import ghidra.app.plugin.processors.sleigh.pattern.*;
import java.io.*;
import java.util.*;
/** Exports original compiled SLEIGH constructors, not sampled instructions. */
public class ExportPIC {
 static Gson gson = new GsonBuilder().disableHtmlEscaping().create();
 static JsonObject obj(){return new JsonObject();}
 static JsonObject expr(PatternExpression p, Set<PatternExpression> seen) {
  if(p==null)return null;
  JsonObject r=obj(); r.addProperty("op",p.getClass().getSimpleName());
  if(!seen.add(p)){r.addProperty("cycle",true);return r;}
  if(p instanceof TokenField t){r.addProperty("start",t.getByteStart()*8+t.getShift());r.addProperty("width",t.getBitEnd()-t.getBitStart()+1);r.addProperty("signed",t.hasSignbit());}
  else if(p instanceof ConstantValue c)r.addProperty("value",c.getValue());
  else if(p instanceof BinaryExpression b){r.add("left",expr(b.getLeft(),new HashSet<>(seen)));r.add("right",expr(b.getRight(),new HashSet<>(seen)));}
  else if(p instanceof UnaryExpression u)r.add("left",expr(u.getUnary(),new HashSet<>(seen)));
  else if(p instanceof OperandValue v){var o=v.getConstructor().getOperand(v.getIndex());r.addProperty("operand",v.getIndex());r.addProperty("offset",o.getRelativeOffset());var e=o.getDefiningExpression();if(e==null && o.getDefiningSymbol()!=null)e=o.getDefiningSymbol().getPatternExpression();r.add("left",expr(e,new HashSet<>(seen)));}
  else if(p instanceof ContextField c){r.addProperty("start",c.getStartBit());r.addProperty("width",c.getEndBit()-c.getStartBit()+1);}
  return r;
 }
 static JsonObject expression(PatternExpression p){return expr(p,new HashSet<>());}
 static JsonArray patterns(DecisionNode node,int ctor){
  JsonArray out=new JsonArray(); if(node==null)return out;
  var pats=node.getPatterns();var cs=node.getConstructors();
  for(int i=0;i<cs.size();i++)if(cs.get(i).getId()==ctor){
   var p=pats.get(i);var q=obj(); var m=new JsonArray();var v=new JsonArray();
   for(int j=0;j<p.getLength(false);j++){m.add(p.getMask(j*8,8,false));v.add(p.getValue(j*8,8,false));}
   q.add("mask",m);q.add("value",v);q.addProperty("context",String.valueOf(p.getContextBlock()));out.add(q);
  }
  for(var ch:node.getChildren())for(var p:patterns(ch,ctor))out.add(p);return out;
 }
 public static void main(String[]args)throws Exception {
  PrintStream out=System.out; System.setOut(System.err);
  Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),new HeadlessGhidraApplicationConfiguration());
  var root=obj();root.addProperty("schema","mkasm.pic.sleigh.v1");var profiles=new JsonArray();root.add("profiles",profiles);
  String[] ids={"PIC-12:LE:16:PIC-12C5xx","PIC-16:LE:16:PIC-16C5x","PIC-16:LE:16:PIC-16","PIC-16:LE:16:PIC-16F","PIC-17:LE:16:PIC-17C7xx","PIC-18:LE:24:PIC-18","PIC-24E:LE:24:default","PIC-24F:LE:24:default","PIC-24H:LE:24:default","dsPIC30F:LE:24:default","dsPIC33F:LE:24:default","dsPIC33E:LE:24:default","dsPIC33C:LE:24:default"};
  for(String id:ids){
   var lang=(SleighLanguage)DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
   var profile=obj();profile.addProperty("language",id);profile.addProperty("word_size",lang.getDefaultSpace().getAddressableUnitSize());var tables=obj();profile.add("tables",tables);profiles.add(profile);
   for(Symbol s:lang.getSymbolTable().getSymbolList())if(s instanceof SubtableSymbol table){
    var ctors=new JsonArray();tables.add(s.getName(),ctors);
    for(int i=0;i<table.getNumConstructors();i++){
     var c=table.getConstructor(i);var j=obj();j.addProperty("id",i);j.addProperty("line",c.getLineno());j.addProperty("source",c.getSourceFile());j.addProperty("length",c.getMinimumLength());boolean indirect=false;if(c.getTempl()!=null)for(var op:c.getTempl().getOpVec())if(op.getOpcode()==ghidra.program.model.pcode.PcodeOp.BRANCHIND)indirect=true;j.addProperty("indirect",indirect);j.add("print",gson.toJsonTree(c.getPrintPieces()));j.add("patterns",patterns(table.getDecisionNode(),i));
     var ops=new JsonArray();j.add("operands",ops);
     for(int k=0;k<c.getNumOperands();k++){
      var o=c.getOperand(k);var q=obj();q.addProperty("name",o.getName());q.addProperty("offset",o.getRelativeOffset());q.addProperty("base",o.getOffsetBase());q.addProperty("length",o.getMinimumLength());q.addProperty("address",o.isCodeAddress());var sym=o.getDefiningSymbol();
      if(sym instanceof SubtableSymbol sub)q.addProperty("table",sub.getName());
      else if(sym instanceof VarnodeSymbol vn)q.addProperty("literal",vn.getName());
      else {var e=o.getDefiningExpression();if(e==null && sym!=null)e=sym.getPatternExpression();q.add("expression",expression(e));
       if(sym instanceof NameSymbol n)q.add("names",gson.toJsonTree(n.getNameTable()));
       if(sym instanceof VarnodeListSymbol n){var ns=new JsonArray();for(var vn:n.getVarnodeTable())ns.add(vn==null?"":vn.getName());q.add("names",ns);}
       if(sym instanceof ValueMapSymbol n)q.add("lookup",gson.toJsonTree(n.getMap()));
      }ops.add(q);
     }ctors.add(j);
    }
   }System.err.println("Exported "+id);
  }out.println(gson.toJson(root));
 }
}
