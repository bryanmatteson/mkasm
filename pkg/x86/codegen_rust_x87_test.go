package x86

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture retains all 130 primary opcode records tagged X87, together with
// FISTTP, EMMS/FEMMS and FX environment images, from conformance/isa/x86_64.json.xz.
// Tests use explicit physical bytes and independent integer/stack state oracles.
func TestRustX86X87Recipes(t *testing.T) {
	f, err := os.Open("testdata/opcodesdb-x87-fixture.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	testX87Generated(t, z, false)
}
func TestRustX86X87CompleteCorpus(t *testing.T) {
	path := os.Getenv("MKASM_X86_OPCODESDB")
	if path == "" {
		t.Skip("set MKASM_X86_OPCODESDB to compile complete x86 corpus with x87 behavior checks")
	}
	var data []byte
	var err error
	if strings.HasSuffix(path, ".xz") {
		data, err = exec.Command("xz", "-dc", path).Output()
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		t.Fatal(err)
	}
	testX87Generated(t, bytes.NewReader(data), true)
}
func testX87Generated(t *testing.T, source io.Reader, supplement bool) {
	t.Helper()
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	catalog, err := ParseOpcodesDB(source)
	if err != nil {
		t.Fatal(err)
	}
	if supplement {
		report, err := SupplementXEDFP16(catalog)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("full corpus includes %d XED supplemental forms", report.Imported)
	}
	dir := t.TempDir()
	if err = GenerateRust(catalog, dir); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "tests", "x87.rs"), []byte(x87GeneratedTests), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "x87", "--quiet", "--", "--nocapture")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated x87 (%d imported forms): %v\n%s", len(catalog.Encodings), err, out)
	} else {
		t.Logf("%s", out)
	}
}

const x87GeneratedTests = `
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use x86_64::semantics::{self as s, *};
use x86_64::*;
fn ext(value: i128) -> u128 {
    if value == 0 {
        return 0;
    }
    let sign = u128::from(value < 0);
    let mag = value.unsigned_abs();
    let k = 127 - mag.leading_zeros();
    assert!(k <= 63);
    (sign << 79) | (u128::from(16383 + k) << 64) | (mag << (63 - k))
}
fn integer(value: u128) -> i128 {
    let exponent = ((value >> 64) & 0x7fff) as i32 - 16383;
    let fraction = value as u64;
    if fraction == 0 {
        return 0;
    }
    assert!((0..=63).contains(&exponent));
    let magnitude = i128::from(fraction >> (63 - exponent));
    if value >> 79 != 0 {
        -magnitude
    } else {
        magnitude
    }
}
fn ieee_to_ext(value: u128, width: u8) -> u128 {
    if width == 80 {
        return value;
    }
    let (f, e, bias) = if width == 32 {
        (23, 8, 127)
    } else {
        (52, 11, 1023)
    };
    let sign = value >> (width - 1);
    let exp = (value >> f) & ((1 << e) - 1);
    if exp == 0 {
        assert_eq!(value & ((1 << (width - 1)) - 1), 0);
        return sign << 79;
    }
    let fraction = (value & ((1 << f) - 1)) | (1 << f);
    (sign << 79) | ((exp + 16383 - bias) << 64) | (fraction << (63 - f))
}
fn ext_to_ieee(value: u128, width: u8) -> u128 {
    if width == 80 {
        return value;
    }
    let (f, bias) = if width == 32 { (23, 127) } else { (52, 1023) };
    let sign = value >> 79;
    if value & ((1 << 79) - 1) == 0 {
        return sign << (width - 1);
    }
    let exp = ((value >> 64) & 0x7fff) - 16383 + bias;
    (sign << (width - 1)) | (exp << f) | ((value as u64 as u128 >> (63 - f)) & ((1 << f) - 1))
}
#[derive(Default)]
struct Cpu {
    regs: HashMap<s::Register, u64>,
    memory: HashMap<u64, u8>,
    accesses: RefCell<Vec<(u64, u16)>>,
    calls: Cell<usize>,
    operations: RefCell<Vec<(X87Operation, Vec<u128>)>>,
    blocked: bool,
    c2: bool,
    unknown_address: bool,
    unknown_cpu: bool,
    unknown_mask: bool,
    unknown_osfxsr: bool,
    fail_at: Option<u64>,
}
impl Cpu {
    fn new() -> Self {
        let mut s = Self::default();
        s.set("x86.x87_control", 0, 0x37f);
        s.set("x86.x87_tags", 0, 0xfff0);
        for n in 0..8 {
            s.st(n, ext(i128::from(n) + 1));
        }
        s
    }
    fn set(&mut self, bank: &'static str, index: u16, value: u64) {
        self.regs.insert(s::Register { bank, index }, value);
    }
    fn st(&mut self, n: u16, value: u128) {
        self.set("x86.x87", n * 2, value as u64);
        self.set("x86.x87", n * 2 + 1, (value >> 64) as u64);
    }
    fn put(&mut self, address: u64, width: u16, value: u128) {
        for i in 0..width / 8 {
            self.memory
                .insert(address + u64::from(i), ((value >> (i * 8)) & 255) as u8);
        }
    }
    fn get(&self, bank: &'static str, index: u16) -> u64 {
        *self.regs.get(&s::Register { bank, index }).unwrap_or(&0)
    }
    fn bytes(&self, address: u64, width: u16) -> u128 {
        (0..width / 8)
            .map(|i| {
                u128::from(
                    *self
                        .memory
                        .get(&(address + u64::from(i)))
                        .unwrap_or_else(|| panic!("unmapped {address:x}/{width} byte {i}")),
                ) << (i * 8)
            })
            .fold(0, |a, b| a | b)
    }
}
impl Machine for Cpu {
    fn read_register(&self, r: s::Register) -> Value {
        if self.unknown_address && r.bank == "x86.gpr" {
            panic!("pending x87 exception evaluated address")
        };
        if self.unknown_cpu && r.bank == "x86.cpuid_7_ebx" {
            return Value::unknown(32);
        }
        if self.unknown_mask && r.bank == "x86.mxcsr_mask" {
            return Value::unknown(32);
        }
        if self.unknown_osfxsr && r.bank == "x86.control" && r.index == 4 {
            return Value::unknown(64);
        }
        Value::known(64, self.get(r.bank, r.index))
    }
    fn read_memory(&self, address: u64, width: u8, _: Endian) -> Result<Value, EvalError> {
        self.accesses.borrow_mut().push((address, u16::from(width)));
        if self.fail_at == Some(address) {
            return Err(EvalError::Memory);
        }
        Ok(Value::known(
            width,
            self.bytes(address, u16::from(width)) as u64,
        ))
    }
    fn read_wide_memory(
        &self,
        address: u64,
        width: u16,
        _: Endian,
    ) -> Result<Vec<Value>, EvalError> {
        self.accesses.borrow_mut().push((address, width));
        if self.fail_at == Some(address) {
            return Err(EvalError::Memory);
        }
        assert!(matches!(width, 80 | 128));
        let bits = self.bytes(address, width);
        Ok(vec![
            Value::known(64, bits as u64),
            Value::known((width - 64) as u8, (bits >> 64) as u64),
        ])
    }
    fn evaluate_x87(
        &self,
        e: &X87Expression,
        chunks: &[Value],
        control: Value,
        status: Value,
        tags: Value,
    ) -> Result<Value, EvalError> {
        self.calls.set(self.calls.get() + 1);
        assert!(chunks.iter().all(|v| v.is_known()));
        let mut cursor = 0;
        let mut input = vec![];
        for operand in &e.inputs {
            let mut value = 0;
            for n in 0..operand.chunks.len() {
                value |= u128::from(chunks[cursor].bits) << (64 * n);
                cursor += 1;
            }
            input.push(value);
        }
        assert_eq!(cursor, chunks.len());
        self.operations
            .borrow_mut()
            .push((e.operation, input.clone()));
        assert_eq!(control.width, 16);
        let (mut sw, mut tw) = (status.bits as u16, tags.bits as u16);
        let (mut results, mut stored, mut comparison) = ([None; 8], None, None);
        let (mut push, mut pops) = (false, 0u8);
        if self.blocked {
            sw |= 0x8081;
        } else {
            match e.operation {
                X87Operation::Binary {
                    operation,
                    source_width,
                    reverse,
                    destination_register,
                    pop,
                    ..
                } => {
                    let (mut a, mut b) = (
                        integer(input[0]),
                        integer(ieee_to_ext(input[1], source_width)),
                    );
                    if reverse {
                        std::mem::swap(&mut a, &mut b);
                    }
                    let v = match operation {
                        X87BinaryOperation::Add => a + b,
                        X87BinaryOperation::Subtract => a - b,
                        X87BinaryOperation::Multiply => a * b,
                        X87BinaryOperation::Divide => a / b,
                    };
                    results[usize::from(destination_register)] = Some(ext(v));
                    pops = u8::from(pop);
                }
                X87Operation::LoadFloat { source_width } => {
                    results[0] = Some(ieee_to_ext(input[0], source_width));
                    push = true;
                }
                X87Operation::LoadInteger { source_width } => {
                    let v = (input[0] << (128 - source_width)) as i128 >> (128 - source_width);
                    results[0] = Some(ext(v));
                    push = true;
                }
                X87Operation::LoadRegister { .. } | X87Operation::LoadBcd => {
                    results[0] = Some(input[0]);
                    push = true;
                }
                X87Operation::StoreFloat {
                    destination_width,
                    pop,
                } => {
                    stored = Some(ext_to_ieee(input[0], destination_width));
                    pops = u8::from(pop);
                }
                X87Operation::StoreInteger {
                    destination_width,
                    pop,
                } => {
                    stored = Some(integer(input[0]) as u128 & ((1u128 << destination_width) - 1));
                    pops = u8::from(pop);
                }
                X87Operation::StoreTruncatedInteger { destination_width } => {
                    stored = Some(integer(input[0]) as u128 & ((1u128 << destination_width) - 1));
                    pops = 1;
                }
                X87Operation::Unary { negate, register } => {
                    results[usize::from(register)] = Some(if negate {
                        input[0] ^ (1 << 79)
                    } else {
                        input[0] & !(1 << 79)
                    })
                }
                X87Operation::Exchange { register } => {
                    results[0] = Some(input[1]);
                    results[usize::from(register)] = Some(input[0]);
                }
                X87Operation::StoreRegister { register, pop } => {
                    results[usize::from(register)] = Some(input[0]);
                    pops = u8::from(pop);
                }
                X87Operation::Compare { pop, .. } => {
                    let (a, b) = (integer(input[0]), integer(input[1]));
                    comparison = Some((a == b, false, a < b));
                    pops = u8::from(pop);
                    sw &= !0x200;
                }
                X87Operation::CompareStatus {
                    source_width,
                    pops: p,
                    ..
                } => {
                    let (a, b) = (
                        integer(input[0]),
                        integer(ieee_to_ext(input[1], source_width)),
                    );
                    sw = (sw & !0x4700)
                        | if a == b {
                            0x4000
                        } else if a < b {
                            0x100
                        } else {
                            0
                        };
                    pops = p;
                }
                X87Operation::ConditionalMove { .. } => {
                    results[0] = Some(if input[2] != 0 { input[1] } else { input[0] });
                }
                X87Operation::Math { operation } => {
                    if operation == X87MathOperation::Examine {
                        sw = (sw & !0x4700) | 0x400;
                    } else if self.c2 {
                        sw |= 0x400;
                        results[0] = Some(input[0]);
                    } else {
                        sw &= !0x400;
                        if operation.pushes() {
                            push = true;
                            results[0] = Some(ext(1));
                            results[1] = Some(input[0]);
                        } else if operation.pops() {
                            pops = 1;
                            results[1] = Some(input[1]);
                        } else {
                            results[0] = Some(input[0]);
                        }
                    }
                }
                X87Operation::LoadConstant { .. } => {
                    results[0] = Some(ext(3));
                    push = true;
                }
                X87Operation::StoreBcd => {
                    let value = integer(input[0]);
                    let mut magnitude = value.unsigned_abs();
                    let mut bcd = 0;
                    for digit in 0..18 {
                        bcd |= (magnitude % 10) << (digit * 4);
                        magnitude /= 10;
                    }
                    assert_eq!(magnitude, 0);
                    stored = Some(bcd | (u128::from(value < 0) << 79));
                    pops = 1;
                }
            }
        }
        if !self.blocked {
            if push {
                tw = tw.rotate_left(2);
                sw = (sw & !0x3800) | ((((status.bits as u16 >> 11).wrapping_sub(1)) & 7) << 11);
            }
            for (n, value) in results.iter().enumerate() {
                if let Some(value) = value {
                    let tag = if value & ((1 << 79) - 1) == 0 { 1 } else { 0 };
                    tw = (tw & !(3 << (2 * n))) | (tag << (2 * n));
                }
            }
            for _ in 0..pops {
                tw = (tw >> 2) | 0xc000;
                sw = (sw & !0x3800) | ((((sw >> 11) + 1) & 7) << 11);
            }
        }
        let width = e.operation.projection_width(e.projection).unwrap();
        let value = match e.projection {
            X87Projection::Status => u128::from(sw),
            X87Projection::Tags => u128::from(tw),
            X87Projection::Commit => u128::from(!self.blocked),
            X87Projection::Result { register, chunk } => {
                if self.blocked {
                    return Err(EvalError::UnavailableX87Result);
                }
                results[usize::from(register)].ok_or(EvalError::UnavailableX87Result)?
                    >> (64 * chunk)
            }
            X87Projection::Store { chunk } => {
                if self.blocked {
                    return Err(EvalError::UnavailableX87Result);
                }
                stored.ok_or(EvalError::UnavailableX87Result)? >> (64 * chunk)
            }
            X87Projection::CompareFlag(flag) => {
                if self.blocked {
                    return Err(EvalError::UnavailableX87Result);
                }
                let (z, p, c) = comparison.ok_or(EvalError::UnavailableX87Result)?;
                u128::from(match flag {
                    X87CompareFlag::Zero => z,
                    X87CompareFlag::Parity => p,
                    X87CompareFlag::Carry => c,
                })
            }
        };
        Ok(Value::known(width, value as u64))
    }
}
fn recipe(bytes: &[u8], mode: Mode) -> Recipe {
    let d = decode(bytes, mode).unwrap_or_else(|e| panic!("{bytes:02x?}: {e:?}"));
    let r = d.semantic_recipe(0x12345678);
    assert_eq!(
        r.support,
        Support::Full,
        "{bytes:02x?} {}: {:?}",
        d.encoding().form_id,
        r.support
    );
    r.validate()
        .unwrap_or_else(|e| panic!("{bytes:02x?} {}: {e:?}", d.encoding().form_id));
    r
}
fn run(bytes: &[u8], cpu: &Cpu) -> Transition {
    s::evaluate(&recipe(bytes, Mode::Mode64), cpu).unwrap_or_else(|e| panic!("{bytes:02x?}: {e:?}"))
}
fn changed(t: &Transition, bank: &str, index: u16) -> Value {
    t.registers
        .iter()
        .rev()
        .find(|r| r.register.bank == bank && r.register.index == index)
        .unwrap_or_else(|| panic!("missing {bank}/{index}"))
        .value
}
fn output(t: &Transition, n: u16) -> u128 {
    u128::from(changed(t, "x86.x87", n * 2).bits)
        | (u128::from(changed(t, "x86.x87", n * 2 + 1).bits) << 64)
}
fn env(t: &Transition, bank: &str) -> Value {
    changed(t, bank, 0)
}
#[test]
fn arithmetic_register_aliases_reverse_pop_and_exact_integer_inputs() {
    let mut cpu = Cpu::new();
    cpu.set("x86.x87_tags", 0, 0);
    cpu.st(0, ext(12));
    cpu.st(1, ext(3));
    for (bytes, n, value) in [
        (&[0xd8, 0xc1][..], 0, 15),
        (&[0xdc, 0xc1][..], 1, 15),
        (&[0xd8, 0xe1][..], 0, 9),
        (&[0xd8, 0xe9][..], 0, -9),
        (&[0xde, 0xe9][..], 0, -9),
        (&[0xde, 0xf1][..], 0, 4),
    ] {
        let t = run(bytes, &cpu);
        assert_eq!(output(&t, n), ext(value), "{bytes:02x?}");
    }
    cpu.set("x86.gpr", 0, 0x4000);
    for value in [0i64, 1, -1, i64::MIN, i64::MAX] {
        cpu.put(0x4000, 32, (value as i32 as u32) as u128);
        let _ = run(&[0xda, 0x00], &cpu);
        let calls = cpu.operations.borrow();
        let (op, inputs) = calls
            .iter()
            .rev()
            .find(|(op, _)| matches!(op, X87Operation::Binary { .. }))
            .unwrap();
        assert!(matches!(
            op,
            X87Operation::Binary {
                source_width: 80,
                source_register: None,
                ..
            }
        ));
        assert_eq!(inputs[1], ext(i128::from(value as i32)));
    }
    cpu.set("x86.x87_tags", 0, 3 << 14);
    cpu.put(0x4000, 64, i64::MIN as u64 as u128);
    let t = run(&[0xdf, 0x28], &cpu);
    assert_eq!(output(&t, 0), ext(i128::from(i64::MIN)));
}
#[test]
fn push_pop_and_exchange_preserve_all_physical_payloads_and_incoming_aliases() {
    let mut cpu = Cpu::new();
    cpu.set("x86.x87_status", 0, 3 << 11);
    cpu.set("x86.x87_tags", 0, 3 << 14);
    cpu.st(7, ext(99));
    let t = run(&[0xd9, 0xc6], &cpu);
    assert_eq!(output(&t, 0), ext(7));
    for n in 1..8 {
        assert_eq!(output(&t, n), ext(i128::from(n)));
    }
    assert_eq!(env(&t, "x86.x87_status").bits & 0x3800, 2 << 11);
    cpu.set("x86.x87_tags", 0, 0);
    let t = run(&[0xdd, 0xd9], &cpu);
    assert_eq!(output(&t, 0), ext(1));
    assert_eq!(output(&t, 6), ext(99));
    assert_eq!(output(&t, 7), ext(1));
    assert_eq!(env(&t, "x86.x87_status").bits & 0x3800, 4 << 11);
    let t = run(&[0xd9, 0xcf], &cpu);
    assert_eq!(output(&t, 0), ext(99));
    assert_eq!(output(&t, 7), ext(1));
    let t = run(&[0xde, 0xd9], &cpu);
    assert_eq!(output(&t, 0), ext(3));
    assert_eq!(output(&t, 6), ext(1));
    assert_eq!(output(&t, 7), ext(2));
    assert_eq!(env(&t, "x86.x87_status").bits & 0x3800, 5 << 11);
}
#[test]
fn original_width_loads_and_commit_predicated_stores() {
    let mut cpu = Cpu::new();
    cpu.set("x86.gpr", 0, 0x4000);
    cpu.put(0x4000, 80, ext(-3));
    let t = run(&[0xdb, 0x28], &cpu);
    assert_eq!(output(&t, 0), ext(-3));
    assert_eq!(*cpu.accesses.borrow(), [(0x4000, 80)]);
    cpu.st(0, ext(3));
    let t = run(&[0xd9, 0x18], &cpu);
    assert_eq!(t.memory.len(), 1);
    assert_eq!(
        (
            t.memory[0].address,
            t.memory[0].value.width,
            t.memory[0].value.bits
        ),
        (0x4000, 32, 0x40400000)
    );
    assert_eq!(output(&t, 0), ext(2));
    cpu.blocked = true;
    cpu.set("x86.x87_control", 0, 0x37e);
    cpu.accesses.borrow_mut().clear();
    let t = run(&[0xd9, 0x18], &cpu);
    assert!(t.memory.is_empty() && t.wide_memory.is_empty());
    assert_eq!(output(&t, 0), ext(3));
    assert_eq!(env(&t, "x86.x87_status").bits & 0x8081, 0x8081);
    assert_eq!(env(&t, "x86.x87_ip").bits, 0x12345678);
    assert_eq!(env(&t, "x86.x87_opcode").bits, 0x118);
    assert!(t.trap.is_none());
}
#[test]
fn pending_exceptions_precede_memory_or_callback_and_nonwaiting_stores_still_run() {
    let mut cpu = Cpu::new();
    cpu.set("x86.x87_control", 0, 0x37e);
    cpu.set("x86.x87_status", 0, 1);
    cpu.unknown_address = true;
    for bytes in [
        &[0xd8, 0x00][..],
        &[0xdb, 0x28][..],
        &[0xd9, 0x20][..],
        &[0xdd, 0x20][..],
    ] {
        let t = run(bytes, &cpu);
        assert_eq!(t.trap, Some(TrapKind::FloatingPoint));
        assert!(t.registers.is_empty() && t.memory.is_empty());
        assert_eq!(cpu.calls.get(), 0);
        assert!(cpu.accesses.borrow().is_empty());
    }
    cpu.unknown_address = false;
    let t = run(&[0xdf, 0xe0], &cpu);
    assert!(t.trap.is_none());
    assert_eq!(changed(&t, "x86.gpr", 0).bits, 1);
}
#[test]
fn trig_push_availability_uses_resulting_c2_and_all_fcmov_conditions() {
    let mut cpu = Cpu::new();
    cpu.c2 = true;
    let t = run(&[0xd9, 0xfb], &cpu);
    for n in 0..8 {
        assert_eq!(output(&t, n), ext(i128::from(n) + 1));
    }
    assert_ne!(env(&t, "x86.x87_status").bits & 0x400, 0);
    cpu.c2 = false;
    let t = run(&[0xd9, 0xf2], &cpu);
    assert_eq!(output(&t, 0), ext(1));
    assert_eq!(output(&t, 1), ext(1));
    for (opcode, reg, cf, zf, pf, take) in [
        (0xda, 0, 1, 0, 0, true),
        (0xda, 1, 0, 1, 0, true),
        (0xda, 2, 0, 0, 0, false),
        (0xda, 3, 0, 0, 1, true),
        (0xdb, 0, 0, 0, 0, true),
        (0xdb, 1, 0, 1, 0, false),
        (0xdb, 2, 0, 0, 0, true),
        (0xdb, 3, 0, 0, 0, true),
    ] {
        cpu.set("x86.flags", 0, cf);
        cpu.set("x86.flags", 3, zf);
        cpu.set("x86.flags", 1, pf);
        let t = run(&[opcode, 0xc1 + reg * 8], &cpu);
        assert_eq!(output(&t, 0), ext(if take { 2 } else { 1 }));
    }
}
#[test]
fn compare_eflags_and_status_pops_are_coupled() {
    let mut cpu = Cpu::new();
    cpu.set("x86.x87_tags", 0, 0);
    cpu.st(0, ext(1));
    cpu.st(1, ext(2));
    for flag in 0..6 {
        cpu.set("x86.flags", flag, 1);
    }
    let t = run(&[0xdf, 0xe9], &cpu);
    for (i, value) in [(0, 1), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0)] {
        assert_eq!(changed(&t, "x86.flags", i).bits, value);
    }
    assert_eq!(output(&t, 0), ext(2));
    cpu.blocked = true;
    let t = run(&[0xdf, 0xe9], &cpu);
    for i in 0..6 {
        assert_eq!(changed(&t, "x86.flags", i).bits, 1);
    }
    assert_eq!(output(&t, 0), ext(1));
}
#[test]
fn stack_controls_and_initialize_retain_empty_physical_payloads() {
    let mut cpu = Cpu::new();
    cpu.set("x86.x87_status", 0, (3 << 11) | 0x4700);
    cpu.set("x86.x87_tags", 0, 0x1234);
    let t = run(&[0xd9, 0xf7], &cpu);
    assert_eq!(output(&t, 0), ext(2));
    assert_eq!(output(&t, 7), ext(1));
    assert_eq!(
        env(&t, "x86.x87_tags").bits,
        0x1234u16.rotate_right(2) as u64
    );
    assert_eq!(env(&t, "x86.x87_status").bits & 0x3800, 4 << 11);
    let t = run(&[0xdd, 0xc5], &cpu);
    assert_eq!(env(&t, "x86.x87_tags").bits, 0x1234 | (3 << 10));
    let t = run(&[0xdb, 0xe3], &cpu);
    for n in 0..8 {
        assert_eq!(output(&t, n), ext(i128::from((n + 5) & 7) + 1));
    }
    assert_eq!(env(&t, "x86.x87_control").bits, 0x37f);
    assert_eq!(env(&t, "x86.x87_status").bits, 0);
    assert_eq!(env(&t, "x86.x87_tags").bits, 0xffff);
}
#[test]
fn environment_images_rotate_physical_tags_preserve_offsets_and_reset_after_save() {
    let mut cpu = Cpu::new();
    cpu.set("x86.gpr", 0, 0x4000);
    cpu.set("x86.x87_status", 0, 3 << 11);
    cpu.set("x86.x87_tags", 0, 0x1234);
    cpu.set("x86.x87_ip", 0, 0x12345678);
    cpu.set("x86.x87_dp", 0, 0xabcd1234);
    cpu.set("x86.x87_cs", 0, 0x123);
    cpu.set("x86.x87_ds", 0, 0x456);
    cpu.set("x86.x87_opcode", 0, 0x321);
    let t = run(&[0xd9, 0x30], &cpu);
    assert_eq!(
        t.memory
            .iter()
            .find(|x| x.address == 0x4008)
            .unwrap()
            .value
            .bits,
        0x1234u16.rotate_left(6) as u64
    );
    assert_eq!(
        t.memory
            .iter()
            .find(|x| x.address == 0x400c)
            .unwrap()
            .value
            .bits,
        0x12345678
    );
    assert_eq!(
        t.memory
            .iter()
            .find(|x| x.address == 0x4010)
            .unwrap()
            .value
            .bits,
        0x3210123
    );
    assert_eq!(env(&t, "x86.x87_control").bits, 0x37f);
    let t = run(&[0xdd, 0x30], &cpu);
    assert_eq!(t.wide_memory.len(), 8);
    for (n, write) in t.wide_memory.iter().enumerate() {
        assert_eq!((write.address, write.width), (0x401c + n as u64 * 10, 80));
        assert_eq!(write.chunks[0].bits, ext(n as i128 + 1) as u64);
    }
    assert_eq!(env(&t, "x86.x87_status").bits, 0);
    assert_eq!(env(&t, "x86.x87_tags").bits, 0xffff);
    let t = s::evaluate(&recipe(&[0x66, 0xd9, 0x30], Mode::Mode64), &cpu).unwrap();
    assert_eq!(t.memory.len(), 7);
    assert_eq!(
        t.memory
            .iter()
            .find(|x| x.address == 0x4006)
            .unwrap()
            .value
            .bits,
        0x5678
    );
    assert_eq!(
        t.memory
            .iter()
            .find(|x| x.address == 0x4008)
            .unwrap()
            .value
            .bits,
        0x123
    );
    cpu.set("x86.control", 0, 0);
    let t = s::evaluate(&recipe(&[0x66, 0xd9, 0x30], Mode::Mode32), &cpu).unwrap();
    assert_eq!(
        t.memory
            .iter()
            .find(|x| x.address == 0x4008)
            .unwrap()
            .value
            .bits,
        0x4321
    );
}
#[test]
fn restored_environment_rebuilds_nonempty_tags_and_recomputes_pending() {
    let mut cpu = Cpu::new();
    cpu.set("x86.gpr", 0, 0x4000);
    for n in 0..7 {
        cpu.put(0x4000 + n * 4, 32, 0);
    }
    cpu.put(0x4000, 16, 0x37e);
    cpu.put(0x4004, 16, 1 | (2 << 11));
    cpu.put(0x4008, 16, 0);
    cpu.put(0x400c, 32, 0x12345678);
    cpu.put(0x4010, 32, 0x76540123);
    cpu.put(0x4014, 32, 0xabcdef01);
    cpu.put(0x4018, 32, 0x456);
    for n in 0..8 {
        let bits = if n == 0 {
            0
        } else if n == 1 {
            1
        } else {
            ext(n as i128)
        };
        cpu.put(0x401c + n * 10, 80, bits);
    }
    let t = run(&[0xdd, 0x20], &cpu);
    assert_eq!(env(&t, "x86.x87_status").bits, 0x8081 | (2 << 11));
    assert_eq!(env(&t, "x86.x87_tags").bits & 15, 1 | (2 << 2));
    assert_eq!(output(&t, 0), 0);
    assert_eq!(output(&t, 1), 1);
    assert_eq!(env(&t, "x86.x87_opcode").bits, 0x654);
    assert_eq!(env(&t, "x86.x87_ip").bits, 0x12345678);
    let t = run(&[0xd9, 0x20], &cpu);
    assert_eq!(output(&t, 0), ext(3));
    assert_eq!(output(&t, 7), ext(2));
}
#[test]
fn unavailable_target_context_is_explicit() {
    let mut cpu = Cpu::new();
    cpu.unknown_cpu = true;
    assert_eq!(
        s::evaluate(&recipe(&[0xd8, 0xc1], Mode::Mode64), &cpu),
        Err(EvalError::UnknownCondition)
    );
}
#[test]
fn every_primary_x87_form_compiles_a_valid_graph_or_a_precise_gap() {
    let mut checked = 0;
    for index in 0..encoding_count() {
        let e = encoding(index).unwrap();
        let x87 = e.mnemonic.starts_with('F') || e.mnemonic == "EMMS";
        if !x87 {
            continue;
        }
        for mode in [Mode::Mode16, Mode::Mode32, Mode::Mode64] {
            if !encoding_supports_mode(index, mode) {
                continue;
            }
            let mut bytes = [0; 15];
            let len = encode_representative(index, mode, &mut bytes).unwrap();
            let d = decode(&bytes[..len], mode).unwrap();
            let r = d.semantic_recipe(0);
            match r.support {
                Support::Full => r.validate().unwrap_or_else(|error| {
                    panic!("{} {mode:?} {:02x?}: {error:?}", e.form_id, &bytes[..len])
                }),
                Support::Unsupported(reason) => {
                    panic!("{} {mode:?} {:02x?}: {reason}", e.form_id, &bytes[..len])
                }
                Support::Partial(reason) => panic!("{}: {reason}", e.form_id),
            }
            checked += 1;
        }
    }
    assert!(checked > 350, "checked {checked}");
    println!("validated {checked} primary x87 form/mode graphs");
}

#[test]
fn rex_ignored_stack_extensions_and_control_transfers_are_exact() {
    let mut cpu = Cpu::new();
    cpu.st(0, ext(-3));
    cpu.st(1, ext(2));
    let a = run(&[0xd9, 0xc9], &cpu);
    let b = run(&[0x41, 0xd9, 0xc9], &cpu);
    assert_eq!(output(&a, 0), output(&b, 0));
    assert_eq!(output(&b, 1), ext(-3));
    cpu.set("x86.gpr", 0, 0x4000);
    cpu.put(0x4000, 16, 0x0b7e);
    let t = run(&[0xd9, 0x28], &cpu);
    assert_eq!(env(&t, "x86.x87_control").bits, 0x0b7e);
    assert_eq!(*cpu.accesses.borrow(), [(0x4000, 16)]);
    cpu.set("x86.x87_control", 0, 0x0b7f);
    let t = run(&[0xd9, 0x38], &cpu);
    assert_eq!(t.memory[0].value, Value::known(16, 0x0b7f));
    let t = run(&[0xdf, 0x08], &cpu);
    assert_eq!(t.memory[0].value, Value::known(16, 0xfffd));
    assert_eq!(output(&t, 0), ext(2));
}
#[test]
fn target_fopcode_and_data_pointer_controls_are_observed() {
    let mut cpu = Cpu::new();
    cpu.set("x86.cpuid_7_ebx", 0, 1 << 6);
    cpu.set("x86.x87_opcode", 0, 7);
    cpu.set("x86.x87_dp", 0, 0xdeadbeef);
    let t = run(&[0xd8, 0xc1], &cpu);
    assert_eq!(env(&t, "x86.x87_opcode").bits, 7);
    assert_eq!(env(&t, "x86.x87_dp").bits, 0xdeadbeef);
    cpu.set("x86.x87_fopcode_compat", 0, 1);
    let t = run(&[0xd8, 0xc1], &cpu);
    assert_eq!(env(&t, "x86.x87_opcode").bits, 0xc1);
    assert_eq!(env(&t, "x86.x87_dp").bits, 0xdeadbeef);
    cpu.set("x86.gpr", 0, 0x4000);
    cpu.set("x86.cpuid_7_ebx", 0, 1 << 13);
    let t = run(&[0xd9, 0x30], &cpu);
    assert_eq!(
        t.memory
            .iter()
            .find(|m| m.address == 0x4010)
            .unwrap()
            .value
            .bits
            & 0xffff,
        0
    );
}
#[test]
fn all_closed_math_operations_dispatch_and_missing_engine_rejects() {
    let cpu = Cpu::new();
    for (second, operation) in [
        (0xfa, X87MathOperation::SquareRoot),
        (0xfc, X87MathOperation::Round),
        (0xfd, X87MathOperation::Scale),
        (0xf8, X87MathOperation::Remainder),
        (0xf5, X87MathOperation::RemainderNearest),
        (0xf4, X87MathOperation::Extract),
        (0xfe, X87MathOperation::Sine),
        (0xff, X87MathOperation::Cosine),
        (0xfb, X87MathOperation::SineCosine),
        (0xf2, X87MathOperation::Tangent),
        (0xf3, X87MathOperation::Arctangent),
        (0xf0, X87MathOperation::Exp2MinusOne),
        (0xf1, X87MathOperation::YLog2X),
        (0xf9, X87MathOperation::YLog2XPlusOne),
        (0xe5, X87MathOperation::Examine),
    ] {
        let _ = run(&[0xd9, second], &cpu);
        assert!(cpu
            .operations
            .borrow()
            .iter()
            .any(|(op, _)| *op == X87Operation::Math { operation }));
    }
    struct Missing(Cpu);
    impl Machine for Missing {
        fn read_register(&self, r: s::Register) -> Value {
            self.0.read_register(r)
        }
        fn read_memory(&self, a: u64, w: u8, e: Endian) -> Result<Value, EvalError> {
            self.0.read_memory(a, w, e)
        }
    }
    assert_eq!(
        s::evaluate(&recipe(&[0xd9, 0xfa], Mode::Mode64), &Missing(cpu)),
        Err(EvalError::Unsupported)
    );
}

fn commit(cpu: &mut Cpu, t: &Transition) {
    for event in &t.events {
        match event {
            OrderedEvent::Store(i) => {
                let w = &t.memory[*i];
                cpu.put(
                    w.address,
                    u16::from(w.value.width),
                    u128::from(w.value.bits),
                );
            }
            OrderedEvent::WideStore(i) => {
                let w = &t.wide_memory[*i];
                assert_eq!(w.endian, Endian::Little);
                let bits = w
                    .chunks
                    .iter()
                    .enumerate()
                    .map(|(n, v)| u128::from(v.bits) << (n * 64))
                    .fold(0, |a, b| a | b);
                cpu.put(w.address, w.width, bits);
            }
            _ => panic!("unexpected FX event"),
        }
    }
    for w in &t.registers {
        cpu.set(w.register.bank, w.register.index, w.value.bits);
    }
}
fn fx_cpu() -> Cpu {
    let mut cpu = Cpu::new();
    cpu.set("x86.gpr", 0, 0x4000);
    cpu.set("x86.control", 4, 1 << 9);
    cpu.set("x86.mxcsr", 0, 0x1f80);
    cpu.set("x86.mxcsr_mask", 0, 0xffbf);
    cpu.set("x86.x87_status", 0, (3 << 11) | 0x45);
    cpu.set("x86.x87_tags", 0, 0x3fe4);
    cpu.st(1, 0);
    cpu.st(2, 1);
    cpu.set("x86.x87_ip", 0, 0x123456789abcdef0);
    cpu.set("x86.x87_dp", 0, 0xfedcba9876543210);
    cpu.set("x86.x87_cs", 0, 0x1234);
    cpu.set("x86.x87_ds", 0, 0x5678);
    cpu.set("x86.x87_opcode", 0, 0x321);
    for n in 0..16 {
        for chunk in 0..8 {
            cpu.set(
                "x86.vector64",
                n * 8 + chunk,
                0x1111000000000000 | u64::from(n) * 256 + u64::from(chunk),
            );
        }
    }
    for offset in 0..512 {
        cpu.memory.insert(0x4000 + offset, 0xcc);
    }
    cpu
}
#[test]
fn committed_80bit_float_and_bcd_stores_are_single_native_accesses() {
    let mut cpu = Cpu::new();
    cpu.set("x86.gpr", 0, 0x4000);
    cpu.st(0, ext(-123));
    let t = run(&[0xdb, 0x38], &cpu);
    assert!(t.memory.is_empty());
    assert_eq!(t.wide_memory.len(), 1);
    assert_eq!(t.wide_memory[0].width, 80);
    assert_eq!(
        t.wide_memory[0].chunks,
        [
            Value::known(64, ext(-123) as u64),
            Value::known(16, (ext(-123) >> 64) as u64)
        ]
    );
    assert_eq!(output(&t, 0), ext(2));
    cpu.st(0, ext(-123456789012345678));
    let t = run(&[0xdf, 0x30], &cpu);
    let w = &t.wide_memory[0];
    let bcd = u128::from(w.chunks[0].bits) | (u128::from(w.chunks[1].bits) << 64);
    assert_eq!(bcd, (1 << 79) | 0x123456789012345678);
    assert_eq!(w.width, 80);
    cpu.blocked = true;
    for bytes in [&[0xdb, 0x38][..], &[0xdf, 0x30][..]] {
        let t = run(bytes, &cpu);
        assert!(t.wide_memory.is_empty() && t.memory.is_empty());
        assert_eq!(output(&t, 0), ext(-123456789012345678));
    }
}
#[test]
fn fxsave_images_preserve_reserved_bytes_and_physical_tag_bitmap() {
    for wide in [false, true] {
        let mut cpu = fx_cpu();
        let before = cpu.memory.clone();
        let bytes = if wide {
            &[0x48, 0x0f, 0xae, 0x00][..]
        } else {
            &[0x0f, 0xae, 0x00][..]
        };
        let t = run(bytes, &cpu);
        assert!(t.trap.is_none());
        assert_eq!(t.wide_memory.iter().filter(|w| w.width == 80).count(), 8);
        assert_eq!(t.wide_memory.iter().filter(|w| w.width == 128).count(), 16);
        assert!(!t
            .registers
            .iter()
            .any(|w| w.register.bank.starts_with("x86.x87")));
        commit(&mut cpu, &t);
        assert_eq!(cpu.bytes(0x4000, 16), 0x37f);
        assert_eq!(cpu.bytes(0x4002, 16), (3 << 11) | 0x45);
        assert_eq!(cpu.bytes(0x4004, 8), 0x3c);
        assert_eq!(cpu.bytes(0x4006, 16), 0x321);
        assert_eq!(cpu.bytes(0x4018, 32), 0x1f80);
        assert_eq!(cpu.bytes(0x401c, 32), 0xffbf);
        if wide {
            assert_eq!(cpu.bytes(0x4008, 64), 0x123456789abcdef0);
            assert_eq!(cpu.bytes(0x4010, 64), 0xfedcba9876543210);
        } else {
            assert_eq!(cpu.bytes(0x4008, 32), 0x9abcdef0);
            assert_eq!(cpu.bytes(0x400c, 16), 0x1234);
            assert_eq!(cpu.bytes(0x4010, 32), 0x76543210);
            assert_eq!(cpu.bytes(0x4014, 16), 0x5678);
        }
        for offset in [5, 42, 43, 44, 45, 46, 47, 416, 511] {
            assert_eq!(cpu.memory[&(0x4000 + offset)], before[&(0x4000 + offset)]);
        }
        assert_eq!(cpu.bytes(0x4020, 80), ext(1));
        assert_eq!(cpu.bytes(0x40a0, 128), 0x11110000000000011111000000000000);
    }
}
#[test]
fn fxrstor_round_trip_restores_payloads_tags_selectors_and_low128_only() {
    for wide in [false, true] {
        let mut cpu = fx_cpu();
        let saved = cpu.regs.clone();
        let save = if wide {
            &[0x48, 0x0f, 0xae, 0x00][..]
        } else {
            &[0x0f, 0xae, 0x00][..]
        };
        let restore = if wide {
            &[0x48, 0x0f, 0xae, 0x08][..]
        } else {
            &[0x0f, 0xae, 0x08][..]
        };
        let t = run(save, &cpu);
        commit(&mut cpu, &t);
        for n in 0..16 {
            cpu.set("x86.x87", n, 0xdeadbeef);
        }
        for n in 0..16 {
            for chunk in 0..8 {
                cpu.set("x86.vector64", n * 8 + chunk, 0xdeadbeef);
            }
        }
        cpu.set("x86.x87_control", 0, 0x37e);
        cpu.set("x86.x87_status", 0, 1);
        let t = run(restore, &cpu);
        assert!(t.trap.is_none());
        assert_eq!(env(&t, "x86.x87_status").bits, (3 << 11) | 0x45);
        assert_eq!(env(&t, "x86.x87_tags").bits, 0x3fe4);
        assert_eq!(env(&t, "x86.x87_cs").bits, if wide { 0 } else { 0x1234 });
        assert_eq!(env(&t, "x86.x87_ds").bits, if wide { 0 } else { 0x5678 });
        assert_eq!(
            env(&t, "x86.x87_ip").bits,
            if wide { 0x123456789abcdef0 } else { 0x9abcdef0 }
        );
        for n in 0..8 {
            let expected = u128::from(
                saved[&s::Register {
                    bank: "x86.x87",
                    index: n * 2,
                }],
            ) | (u128::from(
                saved[&s::Register {
                    bank: "x86.x87",
                    index: n * 2 + 1,
                }],
            ) << 64);
            assert_eq!(output(&t, n), expected);
        }
        for n in 0..16 {
            for chunk in 0..2 {
                assert_eq!(
                    changed(&t, "x86.vector64", n * 8 + chunk).bits,
                    saved[&s::Register {
                        bank: "x86.vector64",
                        index: n * 8 + chunk
                    }]
                );
            }
        }
        assert!(!t
            .registers
            .iter()
            .any(|w| w.register.bank == "x86.vector64" && w.register.index % 8 >= 2));
        let accesses = cpu.accesses.borrow();
        assert_eq!(accesses.iter().filter(|(a, _)| *a == 0x4018).count(), 1);
        let mxcsr = accesses.iter().position(|x| *x == (0x4018, 32)).unwrap();
        assert!(accesses[..mxcsr].iter().filter(|(_, w)| *w == 80).count() == 8);
        assert_eq!(accesses[mxcsr + 1], (0x40a0, 128));
    }
}
#[test]
fn fx_alignment_and_invalid_mxcsr_trap_before_later_reads_or_state() {
    let mut cpu = fx_cpu();
    let t = run(&[0x0f, 0xae, 0x00], &cpu);
    commit(&mut cpu, &t);
    cpu.put(0x4018, 32, 0x1f80 | 0x10000);
    cpu.fail_at = Some(0x40a0);
    let t = run(&[0x0f, 0xae, 0x08], &cpu);
    assert_eq!(t.trap, Some(TrapKind::Protection));
    assert!(t.registers.is_empty());
    assert!(!cpu.accesses.borrow().iter().any(|(_, w)| *w == 128));
    assert_eq!(cpu.accesses.borrow().last(), Some(&(0x4018, 32)));
    cpu.put(0x4018, 32, 0x1f80);
    cpu.accesses.borrow_mut().clear();
    assert_eq!(
        s::evaluate(&recipe(&[0x0f, 0xae, 0x08], Mode::Mode64), &cpu),
        Err(EvalError::Memory)
    );
    assert_eq!(cpu.accesses.borrow().last(), Some(&(0x40a0, 128)));
    cpu.set("x86.gpr", 0, 0x4001);
    cpu.unknown_cpu = true;
    cpu.accesses.borrow_mut().clear();
    for bytes in [
        &[0x0f, 0xae, 0x00][..],
        &[0x0f, 0xae, 0x08][..],
        &[0x48, 0x0f, 0xae, 0x08][..],
    ] {
        let t = run(bytes, &cpu);
        assert_eq!(t.trap, Some(TrapKind::Protection));
        assert!(t.memory.is_empty() && t.wide_memory.is_empty() && t.registers.is_empty());
        assert!(cpu.accesses.borrow().is_empty());
    }
}
#[test]
fn osfxsr_false_skips_mxcsr_and_xmm_and_32bit_mode_has_eight_vectors() {
    let mut cpu = fx_cpu();
    cpu.set("x86.control", 4, 0);
    let t = run(&[0x0f, 0xae, 0x00], &cpu);
    assert_eq!(t.wide_memory.len(), 8);
    assert!(!t.memory.iter().any(|m| m.address == 0x4018));
    assert!(t.memory.iter().any(|m| m.address == 0x401c));
    commit(&mut cpu, &t);
    cpu.put(0x4018, 32, u32::MAX as u128);
    cpu.fail_at = Some(0x40a0);
    cpu.set("x86.mxcsr", 0, 0x1234);
    let t = run(&[0x0f, 0xae, 0x08], &cpu);
    assert!(t.trap.is_none());
    assert_eq!(env(&t, "x86.mxcsr").bits, 0x1234);
    assert!(!cpu
        .accesses
        .borrow()
        .iter()
        .any(|(a, w)| *a == 0x4018 || *w == 128));
    cpu.set("x86.control", 4, 1 << 9);
    cpu.fail_at = None;
    cpu.accesses.borrow_mut().clear();
    let t = s::evaluate(&recipe(&[0x0f, 0xae, 0x00], Mode::Mode32), &cpu).unwrap();
    assert_eq!(t.wide_memory.iter().filter(|m| m.width == 128).count(), 8);
    assert_eq!(
        t.wide_memory
            .iter()
            .filter(|m| m.width == 128)
            .map(|m| m.address)
            .max(),
        Some(0x4110)
    );
}

#[test]
fn fxrstor_rejects_unavailable_required_context_before_memory() {
    let mut cpu = fx_cpu();
    cpu.unknown_mask = true;
    assert_eq!(
        s::evaluate(&recipe(&[0x0f, 0xae, 0x08], Mode::Mode64), &cpu),
        Err(EvalError::UnknownCondition)
    );
    assert!(cpu.accesses.borrow().is_empty());
    cpu.unknown_mask = false;
    cpu.unknown_osfxsr = true;
    assert_eq!(
        s::evaluate(&recipe(&[0x0f, 0xae, 0x08], Mode::Mode64), &cpu),
        Err(EvalError::UnknownCondition)
    );
    assert!(cpu.accesses.borrow().is_empty());
    cpu.set("x86.gpr", 0, 0x4001);
    let t = run(&[0x0f, 0xae, 0x08], &cpu);
    assert_eq!(t.trap, Some(TrapKind::Protection));
    assert!(cpu.accesses.borrow().is_empty());
}
`
