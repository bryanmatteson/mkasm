using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;
public static class Fixture {
 public static volatile int Global;
 public static int Tiny(int n)=>n+1;
 public static int Branch(int n){if(n<0)return -n;int s=0;for(int i=0;i<n;i++)s+=i;return s;}
 public static int Switch(int n)=>n switch {0=>17,1=>-3,2=>41,3=>9,4=>103,5=>7,6=>-17,7=>99,_=>-1};
 public static string Generic<T>(T value)where T:struct=>value.ToString()!;
 public static int Volatile(int n){Global=n;return Global;}
 public static int Catch(int n){try{return 100/n;}catch(DivideByZeroException){return -11;}}
 public static int FilterFinally(int n){try{if(n==0)throw new ArgumentException("zero");return 100/n;}catch(ArgumentException e)when(n==0&&e.Message.Length>0){return -31;}catch(Exception){return -32;}finally{Global++;}}
 public static int FatEH(int n){try{
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
Global += n;
return 100/n;}catch(DivideByZeroException){return -41;}finally{Global++;}}
}
public static class Program {
 public static void Main(){
 var ops=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static).Select(f=>(OpCode)f.GetValue(null)!).Where(o=>o.OpCodeType!=OpCodeType.Nternal).OrderBy(o=>(ushort)o.Value).ToArray();
 var ab=AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("OracleIL"),AssemblyBuilderAccess.Run);var tb=ab.DefineDynamicModule("M").DefineType("Emitted",TypeAttributes.Public);
 foreach(var op in ops){var mb=tb.DefineMethod("Op"+((ushort)op.Value).ToString("x4"),MethodAttributes.Public|MethodAttributes.Static,typeof(void),Type.EmptyTypes);var il=mb.GetILGenerator();var before=il.DefineLabel();var after=il.DefineLabel();il.MarkLabel(before);
 switch(op.OperandType){
 case OperandType.InlineNone:il.Emit(op);break;
 case OperandType.ShortInlineI:if(op==OpCodes.Unaligned)il.Emit(op,(byte)1);else il.Emit(op,(sbyte)-37);break;
 case OperandType.InlineI:il.Emit(op,-0x1234567);break;
 case OperandType.InlineI8:il.Emit(op,-0x123456789abcdL);break;
 case OperandType.ShortInlineR:il.Emit(op,BitConverter.UInt32BitsToSingle(0x7fc12345));break;
 case OperandType.InlineR:il.Emit(op,BitConverter.UInt64BitsToDouble(0xfff8000000004321));break;
 case OperandType.InlineVar:il.Emit(op,(short)300);break;
 case OperandType.ShortInlineVar:il.Emit(op,(byte)201);break;
 case OperandType.InlineString:il.Emit(op,"oracle");break;
 case OperandType.InlineType:case OperandType.InlineTok:il.Emit(op,typeof(int));break;
 case OperandType.InlineField:il.Emit(op,typeof(Fixture).GetField("Global")!);break;
 case OperandType.InlineMethod:il.Emit(op,typeof(Fixture).GetMethod("Tiny")!);break;
 case OperandType.InlineSig:il.Emit(op,SignatureHelper.GetMethodSigHelper(CallingConventions.Standard,typeof(void)));break;
 case OperandType.ShortInlineBrTarget:case OperandType.InlineBrTarget:il.Emit(op,before);break;
 case OperandType.InlineSwitch:il.Emit(op,new[]{before,after,after});break;
 default:throw new Exception(op.ToString());}
 il.MarkLabel(after);il.Emit(OpCodes.Ret);}
 var u=tb.DefineMethod("Unaligned",MethodAttributes.Public|MethodAttributes.Static,typeof(int),new[]{typeof(byte[])});{var il=u.GetILGenerator();il.Emit(OpCodes.Ldarg_0);il.Emit(OpCodes.Ldc_I4_0);il.Emit(OpCodes.Ldelema,typeof(byte));il.Emit(OpCodes.Unaligned,(byte)1);il.Emit(OpCodes.Ldind_I4);il.Emit(OpCodes.Ret);}
 var ro=tb.DefineMethod("ReadOnly",MethodAttributes.Public|MethodAttributes.Static,typeof(int),new[]{typeof(int[])});{var il=ro.GetILGenerator();il.Emit(OpCodes.Ldarg_0);il.Emit(OpCodes.Ldc_I4_0);il.Emit(OpCodes.Readonly);il.Emit(OpCodes.Ldelema,typeof(int));il.Emit(OpCodes.Ldind_I4);il.Emit(OpCodes.Ret);}
 var tail=tb.DefineMethod("Tail",MethodAttributes.Public|MethodAttributes.Static,typeof(int),new[]{typeof(int)});{var il=tail.GetILGenerator();il.Emit(OpCodes.Ldarg_0);il.Emit(OpCodes.Tailcall);il.Emit(OpCodes.Call,typeof(Fixture).GetMethod("Tiny")!);il.Emit(OpCodes.Ret);}
 var ty=tb.CreateType()!;
 var encodings=ops.Select(op=>new {code=(ushort)op.Value,bytes=Convert.ToHexString(ty.GetMethod("Op"+((ushort)op.Value).ToString("x4"))!.GetMethodBody()!.GetILAsByteArray()![..^1])}).ToArray();
 var dynamicMethods=new[]{"Unaligned","ReadOnly","Tail"}.Select(n=>new{name=n,il=Convert.ToHexString(ty.GetMethod(n)!.GetMethodBody()!.GetILAsByteArray()!)}).ToArray();
 using var pe=new PEReader(File.OpenRead(Assembly.GetExecutingAssembly().Location));var md=pe.GetMetadataReader();var methods=new List<object>();
 foreach(var h in md.MethodDefinitions){var m=md.GetMethodDefinition(h);if(md.GetString(md.GetTypeDefinition(m.GetDeclaringType()).Name)!="Fixture"||m.RelativeVirtualAddress==0)continue;var b=pe.GetMethodBody(m.RelativeVirtualAddress);methods.Add(new{name=md.GetString(m.Name),body=Convert.ToHexString(pe.GetSectionData(m.RelativeVirtualAddress).GetContent(0,b.Size).ToArray()),il=Convert.ToHexString(b.GetILBytes()!),maxStack=b.MaxStack,initLocals=b.LocalVariablesInitialized,localSignature=b.LocalSignature.IsNil?0:MetadataTokens.GetToken(b.LocalSignature),exceptions=b.ExceptionRegions.Select(e=>new{kind=e.Kind.ToString(),tryOffset=e.TryOffset,tryLength=e.TryLength,handlerOffset=e.HandlerOffset,handlerLength=e.HandlerLength,catchToken=e.Kind==ExceptionRegionKind.Catch?MetadataTokens.GetToken(e.CatchType):0,filterOffset=e.Kind==ExceptionRegionKind.Filter?e.FilterOffset:0})});}
 var execution=new{branch=Fixture.Branch(7),@switch=Fixture.Switch(4),@catch=Fixture.Catch(0),filter=Fixture.FilterFinally(0),fat=Fixture.FatEH(0),generic=Fixture.Generic(123),unaligned=ty.GetMethod("Unaligned")!.Invoke(null,new object[]{new byte[]{1,2,3,4}}),@readonly=ty.GetMethod("ReadOnly")!.Invoke(null,new object[]{new[]{42}}),tail=ty.GetMethod("Tail")!.Invoke(null,new object[]{9})};
 Console.WriteLine(JsonSerializer.Serialize(new{runtime=Environment.Version.ToString(),metadata=ops.Select(o=>new{name=o.Name,code=(ushort)o.Value,size=o.Size,operand=o.OperandType.ToString(),kind=o.OpCodeType.ToString(),flow=o.FlowControl.ToString(),pop=o.StackBehaviourPop.ToString(),push=o.StackBehaviourPush.ToString()}),encodings,dynamicMethods,methods,execution},new JsonSerializerOptions{WriteIndented=true}));
 }
}
