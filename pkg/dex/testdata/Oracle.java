// Independent encoder oracle using smali/dexlib2 3.0.9. No mkasm byte layout code.
package com.android.tools.smali.dexlib2.writer;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.iface.reference.*;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchElement;
public class Oracle {
 static Object proxy(Class<?> type, InvocationHandler h) {return Proxy.newProxyInstance(type.getClassLoader(),new Class<?>[]{type},h);}
 static Object pool(Class<?> type) {return proxy(type,(p,m,a)-> {if(m.getName().equals("getItemIndex"))return 5;throw new UnsupportedOperationException(m.getName());});}
 static String currentForm;
 public static void main(String[] args)throws Exception {
  BufferedReader r=new BufferedReader(new InputStreamReader(System.in));String line;
  while((line=r.readLine())!=null){String[] t=line.split("\t");int op=Integer.parseInt(t[0]);String form=t[1],name=t[2];Opcode opcode=Opcodes.forDexVersion(39).getOpcodeByValue(op);if(opcode==null)throw new Exception("no dexlib opcode "+op);
   ByteArrayOutputStream b=new ByteArrayOutputStream();DexDataWriter w=new DexDataWriter(b,0);
   InstructionWriter iw=new InstructionWriter(Opcodes.forDexVersion(39),w,(StringSection)pool(StringSection.class),(TypeSection)pool(TypeSection.class),(FieldSection)pool(FieldSection.class),(MethodSection)pool(MethodSection.class),(ProtoSection)pool(ProtoSection.class),(MethodHandleSection)pool(MethodHandleSection.class),(CallSiteSection)pool(CallSiteSection.class));
   String iface="Instruction"+form;if(form.equals("21h"))iface=op==0x19?"Instruction21lh":"Instruction21ih";
   int width=form.startsWith("array")?Integer.parseInt(form.substring(5)):0;
   if(form.equals("packed"))iface="PackedSwitchPayload";if(form.equals("sparse"))iface="SparseSwitchPayload";if(width>0)iface="ArrayPayload";
   Class<?> klass=Class.forName("com.android.tools.smali.dexlib2.iface.instruction.formats."+iface);
   Object ref=Proxy.newProxyInstance(Oracle.class.getClassLoader(),new Class<?>[]{StringReference.class,TypeReference.class,FieldReference.class,MethodReference.class,MethodProtoReference.class,MethodHandleReference.class,CallSiteReference.class},(p,m,a)->null);
   Object in=proxy(klass,(p,m,a)->{
    switch(m.getName()){
     case "getOpcode":return opcode;
     case "getRegisterA":return 3;case "getRegisterB":return 5;
     case "getRegisterC":return form.equals("35c")||form.equals("45cc")?1:7;
     case "getRegisterD":return 3;case "getRegisterE":return 5;case "getRegisterF":return 7;case "getRegisterG":return 9;
     case "getRegisterCount":return form.equals("3rc")||form.equals("4rcc")?6:5;
     case "getStartRegister":return 257;
     case "getNarrowLiteral":return op==0x15? -7<<16:-7;
     case "getWideLiteral":return op==0x19? -7L<<48:-7L;
     case "getHatLiteral":return (short)-7;
     case "getCodeOffset":return -3;
     case "getReference":case "getReference2":return ref;
     case "getReferenceType":return opcode.referenceType;case "getReferenceType2":return opcode.referenceType2;
     case "getElementWidth":return width;
     case "getArrayElements":return Arrays.asList(1L,2L,3L);
     case "getSwitchElements":List<SwitchElement> es=new ArrayList<>();for(int i=0;i<3;i++){final int j=i;es.add(new SwitchElement(){public int getKey(){return -5+j*(form.equals("sparse")?3:1);}public int getOffset(){return j*2-3;}});}return es;
    }
    throw new UnsupportedOperationException(m.getName());
   });
   InstructionWriter.class.getMethod("write",klass).invoke(iw,in);w.flush();StringBuilder hex=new StringBuilder();for(byte v:b.toByteArray())hex.append(String.format("%02x",v&255));System.out.println(op+"\t"+form+"\t"+hex);
  }
 }
}
