using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
[assembly: System.Reflection.AssemblyMetadata("fixture", "metadata ✓")]
namespace ManagedFixture;
[AttributeUsage(AttributeTargets.All)]
public sealed class MarkAttribute : Attribute { public string Name { get; } public int Number { get; set; } public MarkAttribute(string name) { Name=name; } }
public interface IFace<in T> { void Put(T value); }
[Mark("generic", Number=17)]
public class Outer<T> : IFace<T> where T : class, new() {
 public const string Text="hello\0🌍";
 public T Field=new T();
 public event Action<T>? Changed;
 public T Value { get => Field; set { Field=value; Changed?.Invoke(value); } }
 public void Put(T value) => Value=value;
 void IFace<T>.Put(T value) => Put(value);
 public U Map<U>(T input, U fallback) where U : struct => fallback;
 public class Nested<V> where V : IEnumerable<T> { public Dictionary<T,V[]>? Items; }
 public static unsafe int* Pointer(int* p) => p;
 public static unsafe delegate* unmanaged[Cdecl]<int,int> FunctionPointer(delegate* unmanaged[Cdecl]<int,int> p) => p;
 public static int[,] Array(int[,] values) => values;
 public static int Exceptions(int x) { try { if(x==0) throw new InvalidOperationException("zero"); return 100/x; } catch(InvalidOperationException e) when(e.Message.Length>0) { return -1; } catch(Exception) { return -2; } finally { System.GC.KeepAlive(x); } }
 public static async Task<int> Async(int x) { await Task.Yield(); return x+1; }
 public static IEnumerable<int> Iterate(int n) { for(int i=0;i<n;i++) yield return i; }

}
public static class Entry { [DllImport("libc",EntryPoint="getpid")] public static extern int NativeCall(); public static int Main(string[] args) => Outer<object>.Exceptions(args.Length); }

[StructLayout(LayoutKind.Explicit,Size=24,Pack=4)] public struct Layout { [FieldOffset(0)] public int Number; [FieldOffset(8)] public long Wide; }
[StructLayout(LayoutKind.Sequential)] public struct Marshaled { [MarshalAs(UnmanagedType.ByValArray,SizeConst=4)] public int[] Values; }
public static class Data { public static readonly byte[] Bytes = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12}; public static int Optional(int n=23)=>n; }
