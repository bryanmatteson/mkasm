package semantics

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Verify the physical dispatch masks against the actual June source diagrams,
// in addition to executing all Q/index variants and register aliases below.
func TestArm64EnhancedBFloatPrimaryDiagrams(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Skip("optional June architecture corpus unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zip, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zip.Close()
	wanted := map[string][2]uint32{"bfdot_advsimd_vec.xml": {0xbfe0fc00, 0x2e40fc00}, "bfdot_advsimd_elt.xml": {0xbfc0f400, 0x0f40f000}, "bfmmla_advsimd.xml": {0xffe0fc00, 0x6e40ec00}}
	reader := tar.NewReader(zip)
	seen := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		expected, ok := wanted[filepath.Base(header.Name)]
		if !ok || !strings.HasPrefix(header.Name, "ISA_A64_xml_A_profile-2026-06/") {
			continue
		}
		var doc struct {
			Classes []struct {
				Diagrams []struct {
					Boxes []struct {
						Hi    int      `xml:"hibit,attr"`
						Width int      `xml:"width,attr"`
						Cells []string `xml:"c"`
					} `xml:"box"`
				} `xml:"regdiagram"`
			} `xml:"classes>iclass"`
		}
		if err := xml.NewDecoder(reader).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		for _, class := range doc.Classes {
			for _, diagram := range class.Diagrams {
				var mask, bits uint32
				for _, box := range diagram.Boxes {
					width := box.Width
					if width == 0 {
						width = 1
					}
					if len(box.Cells) != width {
						continue
					}
					for i, cell := range box.Cells {
						if cell == "0" || cell == "1" {
							mask |= 1 << uint(box.Hi-i)
							if cell == "1" {
								bits |= 1 << uint(box.Hi-i)
							}
						}
					}
				}
				if [2]uint32{mask, bits} != expected {
					t.Fatalf("%s diagram got %#x/%#x, expected %#x/%#x", header.Name, mask, bits, expected[0], expected[1])
				}
				seen++
			}
		}
	}
	if seen != 3 {
		t.Fatalf("found %d primary diagrams, expected 3", seen)
	}
}

// The oracle uses exact rational arithmetic, independently of the native
// fixed-point limb accumulator. It follows June BFDotAdd: FPDot rounded to
// binary32 first, then FPAdd rounded to binary32; neither raises exceptions.
type bfReference struct {
	value    *big.Rat
	negative bool
	kind     int
}

func bfRead(bits uint32, half bool, control uint32) bfReference {
	if half {
		bits <<= 16
	}
	e, f := (bits>>23)&255, bits&0x7fffff
	v := bfReference{negative: bits>>31 != 0, value: new(big.Rat)}
	if e == 255 {
		v.kind = 1
		if f != 0 {
			v.kind = 2
		}
		return v
	}
	sig, exp := uint64(f), -149
	if e != 0 {
		sig |= 1 << 23
		exp = int(e) - 150
	} else if control&1 != 0 || control&((1<<24)|2) == 1<<24 {
		sig = 0
	}
	v.value.SetInt(new(big.Int).SetUint64(sig))
	if exp < 0 {
		v.value.Quo(v.value, new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(-exp))))
	} else {
		v.value.Mul(v.value, new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(exp))))
	}
	if v.negative {
		v.value.Neg(v.value)
	}
	return v
}
func bfMultiply(a, b bfReference) bfReference {
	z := bfReference{negative: a.negative != b.negative, value: new(big.Rat)}
	if a.kind == 2 || b.kind == 2 || a.kind == 1 && b.kind == 0 && b.value.Sign() == 0 || b.kind == 1 && a.kind == 0 && a.value.Sign() == 0 {
		z.kind = 2
		return z
	}
	if a.kind == 1 || b.kind == 1 {
		z.kind = 1
		return z
	}
	z.value.Mul(a.value, b.value)
	return z
}
func bfRound(v *big.Rat, control uint32) uint32 {
	negative := v.Sign() < 0
	sign := uint32(0)
	if negative {
		sign = 1 << 31
	}
	abs := new(big.Rat).Abs(v)
	e := abs.Num().BitLen() - abs.Denom().BitLen()
	power := new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(max(e, 0))))
	if e < 0 {
		power.Inv(new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(-e))))
	}
	if abs.Cmp(power) < 0 {
		e--
	}
	quotient := func(scale int) (uint64, bool) {
		scaled := new(big.Rat).Set(abs)
		power := new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(max(scale, -scale))))
		if scale < 0 {
			scaled.Quo(scaled, power)
		} else {
			scaled.Mul(scaled, power)
		}
		q, rem := new(big.Int), new(big.Int)
		q.QuoRem(scaled.Num(), scaled.Denom(), rem)
		exact := rem.Sign() == 0
		up := false
		switch control >> 22 & 3 {
		case 0:
			cmp := new(big.Int).Lsh(rem, 1).Cmp(scaled.Denom())
			up = cmp > 0 || cmp == 0 && q.Bit(0) != 0
		case 1:
			up = !exact && !negative
		case 2:
			up = !exact && negative
		}
		x := q.Uint64()
		if up {
			x++
		}
		return x, exact
	}
	unconstrained, _ := quotient(23 - e)
	tiny := e < -126
	if control&2 != 0 {
		tiny = e+map[bool]int{true: 1}[unconstrained == 1<<24] < -126
	}
	if tiny && control&(1<<24) != 0 {
		return sign
	}
	q, _ := quotient(23 - max(e, -126))
	if e < -126 {
		return sign | uint32(q)
	}
	if q == 1<<24 {
		q >>= 1
		e++
	}
	if e > 127 {
		mode := control >> 22 & 3
		if mode == 0 || mode == 1 && !negative || mode == 2 && negative {
			return sign | 0x7f800000
		}
		return sign | 0x7f7fffff
	}
	return sign | uint32(e+127)<<23 | uint32(q&0x7fffff)
}
func bfSum(a, b bfReference, control uint32) uint32 {
	if a.kind == 2 || b.kind == 2 || a.kind == 1 && b.kind == 1 && a.negative != b.negative {
		return 0x7fc00000 | (control&2)<<30
	}
	if a.kind == 1 || b.kind == 1 {
		if a.kind != 1 {
			a = b
		}
		if a.negative {
			return 0xff800000
		}
		return 0x7f800000
	}
	if a.value.Sign() == 0 && b.value.Sign() == 0 && a.negative == b.negative {
		if a.negative {
			return 1 << 31
		}
		return 0
	}
	sum := new(big.Rat).Add(a.value, b.value)
	if sum.Sign() == 0 {
		if control>>22&3 == 2 {
			return 1 << 31
		}
		return 0
	}
	return bfRound(sum, control)
}
func bfEnhanced(acc uint32, a0, a1, b0, b1 uint16, control uint32) uint32 {
	p := bfSum(bfMultiply(bfRead(uint32(a0), true, control), bfRead(uint32(b0), true, control)), bfMultiply(bfRead(uint32(a1), true, control), bfRead(uint32(b1), true, control)), control)
	return bfSum(bfRead(acc, false, control), bfRead(p, false, control), control)
}

func TestRustArm64EnhancedBFloat(t *testing.T) {
	// The arithmetic implementation is the real native kernel. The small type
	// shim only supplies its closed operation/rounding enums and exception bits.
	path := filepath.Join("..", "..", "..", "binary-toolkit", "crates", "isa", "core", "src", "floating_point", "bfloat16.rs")
	source, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("native BF16 consumer checkout unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	native := strings.ReplaceAll(string(source), "crate::", "crate::native_contract::")
	native = strings.ReplaceAll(native, "use crate::{", "use crate::native_contract::{")
	var fixtures strings.Builder
	fixtures.WriteString("const NUMERIC:&[(u32,[u16;4],u32,u32)]=&[\n")
	seed := uint64(0x2764ef16)
	next := func() uint32 { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return uint32(seed) }
	special := []uint16{0, 0x8000, 1, 0x7f, 0x80, 0x81, 0x8001, 0x3f80, 0xbf80, 0x3380, 0x7f7f, 0xff7f, 0x7f80, 0xff80, 0x7f81, 0x7fc1}
	for i := 0; i < 8192; i++ {
		acc := next()
		args := [4]uint16{uint16(next()), uint16(next()), uint16(next()), uint16(next())}
		if i < 2048 {
			for j := range args {
				args[j] = special[int(next())%len(special)]
			}
		}
		control := uint32(1<<13) | uint32(i&3)<<22 | uint32(i>>2&1)<<24 | uint32(i>>3&3) | 0x9f00
		expected := bfEnhanced(acc, args[0], args[1], args[2], args[3], control)
		fmt.Fprintf(&fixtures, "(0x%x,[0x%x,0x%x,0x%x,0x%x],0x%x,0x%x),\n", acc, args[0], args[1], args[2], args[3], control, expected)
	}
	fixtures.WriteString("];\nconst PHYSICAL:&[(u32,u32,[u64;6],[u64;2])]=&[\n")
	forms := []uint32{0x2e40fc00, 0x6e40fc00, 0x6e40ec00}
	for _, q := range []uint32{0, 1} {
		for index := uint32(0); index < 4; index++ {
			forms = append(forms, 0x0f40f000|q<<30|(index&1)<<21|(index>>1)<<11)
		}
	}
	for _, base := range forms {
		for _, regs := range [][3]uint16{{0, 1, 2}, {1, 1, 2}, {2, 1, 2}, {31, 31, 31}} {
			for _, control := range []uint32{0, 1 << 13, (1 << 13) | (1 << 24) | 2, (1 << 13) | (3 << 22) | 1} {
				d, n, m := regs[0], regs[1], regs[2]
				word := base | uint32(d) | uint32(n)<<5 | uint32(m)<<16
				values := map[uint16][2]uint64{}
				values[n] = [2]uint64{0x408040403f803f00, 0x410040e040c040a0}
				values[m] = [2]uint64{0x3f803f803f803f80, 0x4000400040004000}
				values[d] = [2]uint64{0x3f8000003f800000, 0x3f8000003f800000}
				lane := func(reg uint16, i, width int) uint32 {
					return uint32(values[reg][i*width/64]>>uint(i*width%64)) & uint32((uint64(1)<<width)-1)
				}
				matrix := base&0xffe0fc00 == 0x6e40ec00
				indexed := base&0xbfc0f400 == 0x0f40f000
				count := 2
				if matrix || base&(1<<30) != 0 {
					count = 4
				}
				var output [2]uint64
				for e := 0; e < count; e++ {
					sum := lane(d, e, 32)
					for k := 0; k < map[bool]int{false: 1, true: 2}[matrix]; k++ {
						left, right := 2*e, 2*e
						if matrix {
							left = 4*(e/2) + 2*k
							right = 4*(e%2) + 2*k
						} else if indexed {
							right = int(((word>>11&1)*2 + (word >> 21 & 1)) * 2)
						}
						sum = bfEnhanced(sum, uint16(lane(n, left, 16)), uint16(lane(n, left+1, 16)), uint16(lane(m, right, 16)), uint16(lane(m, right+1, 16)), control)
					}
					output[e/2] |= uint64(sum) << uint(e%2*32)
				}
				a, z, v := values[d], values[n], values[m]
				fmt.Fprintf(&fixtures, "(0x%x,0x%x,[0x%x,0x%x,0x%x,0x%x,0x%x,0x%x],[0x%x,0x%x]),\n", word, control, a[0], a[1], z[0], z[1], v[0], v[1], output[0], output[1])
			}
		}
	}
	fixtures.WriteString("];\n")
	runBFloatRust(t, enhancedBFloatTests+fixtures.String(), map[string]string{"native_bfloat.rs": native, "arm64_float_extra.rs": arm64FloatExtraSource})
}

func runBFloatRust(t *testing.T, source string, extra map[string]string) {
	t.Helper()
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	extra["runtime.rs"] = RustRuntime
	extra["tests.rs"] = source
	for name, body := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Dwarnings", "-o", "bfloat-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile enhanced BF16: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "bfloat-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute enhanced BF16: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

const enhancedBFloatTests = `
#[allow(dead_code)]mod runtime;
use runtime::*;
#[allow(dead_code)]mod arm64_float_extra;
#[allow(dead_code)]mod native_bfloat;
#[allow(dead_code)]mod native_contract{
 pub use super::runtime::BFloatOperation as AArch64BFloatBinaryOperation;
 #[derive(Clone,Copy)]pub enum FloatRounding{NearestEven,NearestAway,Zero,Down,Up}
 pub struct FloatExceptions;impl FloatExceptions{pub const INVALID:u8=1;pub const DENORMAL:u8=2;pub const DIVIDE_BY_ZERO:u8=4;pub const OVERFLOW:u8=8;pub const UNDERFLOW:u8=16;pub const INEXACT:u8=32;}
}
#[test]fn independent_rational_dot_corpus(){
 for &(acc,a,control,expected)in NUMERIC{
  assert_eq!(native_bfloat::aarch64_bfloat_dot_add_controlled(acc,a[0],a[1],a[2],a[3],control),expected,"{acc:08x} {a:04x?} FPCR={control:08x}");
 }
}
struct State{v:[[u64;2];32],control:u32,available:[[bool;2];32]}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{match r.bank{
  "a64.fpcr"=>Value::known(32,u64::from(self.control)),
  "a64.vector64"=>{let reg=r.index as usize/32;let chunk=r.index as usize%32;assert!(self.available[reg][chunk],"unavailable input {r:?}");Value::known(64,self.v[reg][chunk])},
  _=>panic!("BF dot must not read FPSR/NZCV or other state: {r:?}"),
 }}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("BF dot memory")}
 fn evaluate_float(&self,f:&FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  assert_eq!(f.operation,FloatOperation::BFloatDotAdd);assert_eq!(f.environment,FloatEnvironment::A64);assert_eq!(f.projection,FloatProjection::Value);assert_eq!(f.width,32);assert_eq!(status,Value::known(32,0));
  assert!(inputs.iter().all(|value|value.is_known()));assert!(control.is_known());
  Ok(Value::known(32,u64::from(native_bfloat::aarch64_bfloat_dot_add_controlled(inputs[0].bits as u32,inputs[1].bits as u16,inputs[2].bits as u16,inputs[3].bits as u16,inputs[4].bits as u16,control.bits as u32))))
 }
}
#[test]fn fixed_width_vector_indexed_matrix_and_alias_transitions(){
 for &(word,control,values,expected)in PHYSICAL{
  let (d,n,m)=((word&31)as usize,((word>>5)&31)as usize,((word>>16)&31)as usize);
  let mut state=State{v:[[0;2];32],control,available:[[false;2];32]};
  for (index,reg)in[d,n,m].into_iter().enumerate(){state.v[reg]=[values[index*2],values[index*2+1]];}
  let wide=word&(1<<30)!=0;let indexed=word&0xbfc0f400==0x0f40f000;
  for reg in[d,n]{state.available[reg][0]=true;if wide{state.available[reg][1]=true;}}
  if indexed{let index=((word>>11)&1)*2+((word>>21)&1);state.available[m][index as usize/2]=true;}else{state.available[m][0]=true;if wide{state.available[m][1]=true;}}
  let recipe=arm64_float_extra::fixed_bfloat(word,0x1000).unwrap();recipe.validate().unwrap();
  let transition=evaluate(&recipe,&state).unwrap();assert_eq!(transition.trap,None);assert!(transition.memory.is_empty());assert_eq!(transition.registers.len(),2);
  for (i,write)in transition.registers.iter().enumerate(){assert_eq!(write.register,register("a64.vector64",d as u16*32+i as u16,64,64).register);assert_eq!(write.value,Value::known(64,expected[i]),"{word:08x} FPCR={control:08x} chunk={i}");}
 }
}
#[test]fn fixed_bfloat_rejects_adjacent_unrelated_physical_classes(){
 for word in [0,0x2e40ec00,0x4e40fc00,0x1e634020,0x0f40e000]{assert!(arm64_float_extra::fixed_bfloat(word,0).is_none(),"{word:08x}");}
}
`
