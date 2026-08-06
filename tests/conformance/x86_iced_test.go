package conformance

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/x86"
)

func TestX86IcedConformance(t *testing.T) {
	if os.Getenv("MKASM_X86_ICED_CONFORMANCE") != "1" {
		t.Skip("set MKASM_X86_ICED_CONFORMANCE=1 to run the independent iced-x86 operand oracle")
	}
	path := os.Getenv("MKASM_X86_OPCODESDB")
	if path == "" {
		t.Fatal("set MKASM_X86_OPCODESDB to an opcodesDB v3 JSON or JSON.xz file")
	}
	catalog := loadX86Corpus(t, path)
	root := t.TempDir()
	generated := filepath.Join(root, "generated")
	if err := x86.GenerateRust(catalog, generated); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(root, "iced-oracle")
	if err := os.MkdirAll(filepath.Join(harness, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	cargo := fmt.Sprintf(`[package]
name = "mkasm-iced-oracle"
version = "0.0.0"
edition = "2021"

[dependencies]
mkasm = { package = "x86_64", path = %q }
iced-x86 = "=1.21.0"
`, generated)
	writeTestFile(t, filepath.Join(harness, "Cargo.toml"), cargo)
	writeTestFile(t, filepath.Join(harness, "src", "cases.rs"), representativeX86Cases(t, catalog))
	writeTestFile(t, filepath.Join(harness, "src", "main.rs"), icedOperandOracleSource)

	command := exec.Command("cargo", "run", "--quiet")
	command.Dir = harness
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	output, err := command.CombinedOutput()
	t.Log(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatalf("iced-x86 operand conformance: %v", err)
	}
}

func loadX86Corpus(t *testing.T, path string) *x86.Catalog {
	t.Helper()
	var reader io.Reader
	var command *exec.Cmd
	if strings.HasSuffix(path, ".xz") {
		command = exec.Command("xz", "-dc", path)
		pipe, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		reader = pipe
	} else {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		reader = file
	}
	catalog, err := x86.ParseOpcodesDB(reader)
	if err != nil {
		t.Fatal(err)
	}
	if command != nil {
		if err := command.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	return catalog
}

func representativeX86Cases(t *testing.T, catalog *x86.Catalog) string {
	t.Helper()
	seen := make(map[string]struct{})
	var output strings.Builder
	output.WriteString("static CASES: &[(&[u8], u32)] = &[\n")
	for index := range catalog.Encodings {
		encoding := &catalog.Encodings[index]
		fields := x86.EncodeFields{Reg: encoding.RegValue, RM: encoding.RMValue, Immediate: [4]uint64{0xa5, 0x1234, 0x89abcdef, 0x0123456789abcdef}}
		hasReg, hasRM, hasVVVV, hasOpcode, hasIS4, hasMemory := false, false, false, false, false, false
		for _, operand := range encoding.Operands {
			switch operand.EncodedIn {
			case "REG":
				hasReg = true
			case "RM":
				hasRM = true
			case "VVVV":
				hasVVVV = true
			case "OPCODE":
				hasOpcode = true
			case "IS4":
				hasIS4 = true
			case "AAA":
				fields.Mask = 1
			}
			if (operand.Type == "MEM" || operand.Type == "MIB" || operand.Type == "AGEN") && !operand.Suppressed {
				hasMemory = true
			}
		}
		if hasReg && encoding.RegMask == 0 {
			fields.Reg = 1
		}
		if hasVVVV {
			fields.VVVV = 3
		}
		if hasOpcode {
			fields.OpcodeReg = 1
		}
		if hasIS4 {
			fields.Immediate[0] = 0x4a
		}
		switch encoding.Mod {
		case x86.ModMemory:
			fields.Mod = 1
			fields.Displacement = -16
		case x86.ModRegister:
			fields.Mod = 3
		default:
			if encoding.HasModRM {
				fields.Mod = 3
			}
		}
		if hasRM && encoding.RMMask == 0 {
			if fields.Mod == 3 {
				fields.RM = 2
			} else {
				fields.RM = 4
			}
		}
		if encoding.HasModRM && fields.Mod != 3 && fields.RM&7 == 4 {
			fields.UseSIB, fields.Base, fields.Index = true, 0, 2
		}
		if hasMemory {
			fields.SegmentOverride = 0x64
		}
		for _, mode := range []x86.Mode{x86.Mode64, x86.Mode32, x86.Mode16} {
			fields.Mode = mode
			var bytes [15]byte
			length, err := x86.Encode(bytes[:], encoding, fields)
			if err != nil {
				continue
			}
			key := fmt.Sprintf("%d:%x", mode, bytes[:length])
			if _, duplicate := seen[key]; duplicate {
				break
			}
			seen[key] = struct{}{}
			output.WriteString("    (&[")
			for i, value := range bytes[:length] {
				if i != 0 {
					output.WriteByte(',')
				}
				fmt.Fprintf(&output, "0x%02x", value)
			}
			fmt.Fprintf(&output, "], %d),\n", mode)
			break
		}
	}
	output.WriteString("];\n")
	return output.String()
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

const icedOperandOracleSource = `use iced_x86::{CC_a, CC_ae, CC_e, CC_g, CC_ge, CC_ne, Decoder, DecoderOptions, Encoder, FlowControl as IcedFlowControl, Formatter, InstructionInfoFactory, IntelFormatter, MemorySizeOptions, NumberBase, OpAccess, OpKind};
use mkasm::{FlowControl, Mode, OperandKind, RegisterClass, RelocateError};

include!("cases.rs");

fn register_name(class: RegisterClass, number: u8, width: u16, high8: bool) -> String {
    if class == RegisterClass::Gpr {
        let table: &[&str] = match width {
            8 if high8 => &["ah", "ch", "dh", "bh"],
            8 => &["al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"],
            16 => &["ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"],
            32 => &["eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"],
            _ => &["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"],
        };
        let index = if high8 { number.saturating_sub(4) } else { number } as usize;
        return table.get(index).unwrap_or(&"?").to_string();
    }
    let prefix = match class {
        RegisterClass::Vector => match width { 128 => "xmm", 256 => "ymm", _ => "zmm" },
        RegisterClass::Mask => "k", RegisterClass::Mmx => "mm", RegisterClass::Bound => "bnd",
        RegisterClass::Control => "cr", RegisterClass::Debug => "dr", RegisterClass::X87 => "st",
        RegisterClass::Segment => return ["es", "cs", "ss", "ds", "fs", "gs"].get(number as usize).unwrap_or(&"?").to_string(),
        _ => "?",
    };
    format!("{prefix}{number}")
}

fn memory(kind: OpKind) -> bool {
    matches!(kind, OpKind::Memory | OpKind::MemorySegSI | OpKind::MemorySegESI | OpKind::MemorySegRSI |
        OpKind::MemorySegDI | OpKind::MemorySegEDI | OpKind::MemorySegRDI | OpKind::MemoryESDI |
        OpKind::MemoryESEDI | OpKind::MemoryESRDI)
}

fn format_iced(instruction: &iced_x86::Instruction) -> String {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_uppercase_prefixes(false);
    options.set_uppercase_mnemonics(false);
    options.set_uppercase_registers(false);
    options.set_uppercase_keywords(false);
    options.set_uppercase_decorators(false);
    options.set_uppercase_all(false);
    options.set_first_operand_char_index(0);
    options.set_tab_size(0);
    options.set_space_after_operand_separator(true);
    options.set_space_after_memory_bracket(false);
    options.set_space_between_memory_add_operators(false);
    options.set_space_between_memory_mul_operators(false);
    options.set_scale_before_index(false);
    options.set_always_show_scale(false);
    options.set_always_show_segment_register(false);
    options.set_show_zero_displacements(false);
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_hex_digit_group_size(0);
    options.set_decimal_prefix("");
    options.set_decimal_suffix("");
    options.set_decimal_digit_group_size(0);
    options.set_octal_prefix("");
    options.set_octal_suffix("");
    options.set_octal_digit_group_size(0);
    options.set_binary_prefix("");
    options.set_binary_suffix("");
    options.set_binary_digit_group_size(0);
    options.set_digit_separator("");
    options.set_leading_zeros(false);
    options.set_uppercase_hex(false);
    options.set_small_hex_numbers_in_decimal(false);
    options.set_add_leading_zero_to_hex_numbers(false);
    options.set_number_base(NumberBase::Hexadecimal);
    options.set_branch_leading_zeros(false);
    options.set_signed_immediate_operands(false);
    options.set_signed_memory_displacements(true);
    options.set_displacement_leading_zeros(false);
    options.set_memory_size_options(MemorySizeOptions::Always);
    options.set_rip_relative_addresses(true);
    options.set_show_branch_size(false);
    options.set_use_pseudo_ops(false);
    options.set_show_symbol_address(false);
    options.set_prefer_st0(false);
    options.set_show_useless_prefixes(false);
    options.set_cc_ae(CC_ae::nb);
    options.set_cc_e(CC_e::z);
    options.set_cc_ne(CC_ne::nz);
    options.set_cc_a(CC_a::nbe);
    options.set_cc_ge(CC_ge::nl);
    options.set_cc_g(CC_g::nle);
    let mut output = String::new();
    formatter.format(instruction, &mut output);
    output
}

fn iced_register_view_quirk(code: &str) -> bool {
    code.starts_with("Arpl_") || code.starts_with("Mov_r32m16_Sreg") ||
        code.starts_with("Lldt_r32m16") || code.starts_with("Lmsw_r32m16") || code.starts_with("Ltr_r32m16") ||
        code.starts_with("Verr_r32m16") || code.starts_with("Verw_r32m16")
}

fn flow_equal(ours: FlowControl, iced: IcedFlowControl) -> bool {
    matches!((ours, iced),
        (FlowControl::Next, IcedFlowControl::Next) |
        (FlowControl::Call, IcedFlowControl::Call) |
        (FlowControl::Return, IcedFlowControl::Return) |
        (FlowControl::UnconditionalBranch, IcedFlowControl::UnconditionalBranch) |
        (FlowControl::ConditionalBranch, IcedFlowControl::ConditionalBranch) |
        (FlowControl::IndirectCall, IcedFlowControl::IndirectCall) |
        (FlowControl::IndirectBranch, IcedFlowControl::IndirectBranch) |
        (FlowControl::Interrupt, IcedFlowControl::Interrupt) |
        (FlowControl::Exception, IcedFlowControl::Exception) |
        (FlowControl::Transactional, IcedFlowControl::XbeginXabortXend))
}

fn access_equal(ours: mkasm::Access, iced: OpAccess) -> bool {
    let read = matches!(iced, OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite);
    let write = matches!(iced, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite);
    (ours.read || ours.conditional_read) == read &&
        (ours.write || ours.conditional_write) == write
}

fn access_oracle_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "mov" | "movsx" | "movsxd" | "movzx" | "lea" | "add" | "sub" |
        "and" | "sal" | "sar" | "shl" | "shr" | "cmp" | "test" | "div" | "idiv" | "mul" | "imul")
}

fn implicit_oracle_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "div" | "idiv" | "mul" | "imul" | "cwd" | "cdq" | "cqo")
}

fn gpr_number(name: &str) -> Option<u8> {
    match name {
        "al" | "ah" | "ax" | "eax" | "rax" => Some(0),
        "cl" | "ch" | "cx" | "ecx" | "rcx" => Some(1),
        "dl" | "dh" | "dx" | "edx" | "rdx" => Some(2),
        "bl" | "bh" | "bx" | "ebx" | "rbx" => Some(3),
        _ => None,
    }
}

fn main() {
    let (mut checked, mut skipped, mut unsupported, mut bad) = (0usize, 0usize, 0usize, 0usize);
    let (mut formatted, mut format_bad) = (0usize, 0usize);
    let (mut flow_checked, mut flow_bad, mut access_checked, mut access_bad, mut access_incomparable) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let (mut target_checked, mut target_bad, mut implicit_checked, mut implicit_bad, mut implicit_incomparable) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut info_factory = InstructionInfoFactory::new();
    for (bytes, bits) in CASES {
        let mode = match bits { 16 => Mode::Mode16, 32 => Mode::Mode32, _ => Mode::Mode64 };
        let ours = match mkasm::decode(bytes, mode) { Ok(value) => value, Err(error) => {
            eprintln!("mkasm rejected {:02x?}: {error:?}", bytes); bad += 1; continue;
        }};
        let mut decoder = Decoder::with_ip(*bits, bytes, 0x1000, DecoderOptions::MPX | DecoderOptions::KNC);
        let iced = decoder.decode();
        if iced.is_invalid() || iced.len() != bytes.len() { unsupported += 1; continue; }
        if flow_equal(ours.flow_control(), iced.flow_control()) { flow_checked += 1; }
        else { eprintln!("flow mismatch {:02x?}: mkasm={:?} iced={:?}", bytes, ours.flow_control(), iced.flow_control()); flow_bad += 1; }
        let info = info_factory.info(&iced);
        let mkasm_text = ours.format_intel(0x1000);
        let iced_text = format_iced(&iced);
        if mkasm_text == iced_text { formatted += 1; }
        else {
            eprintln!("formatter mismatch {:02x?}: mkasm={mkasm_text:?} iced={iced_text:?}", bytes);
            format_bad += 1;
        }
        let explicit: Vec<_> = ours.operands().iter().filter(|operand| !operand.implicit && operand.kind != OperandKind::Mask).collect();
        for (index, operand) in explicit.iter().enumerate().take(iced.op_count() as usize) {
            let iced_access = info.op_access(index as u32);
            if !access_oracle_mnemonic(&ours.encoding().mnemonic.to_lowercase()) ||
                !matches!(operand.kind, OperandKind::Register | OperandKind::Memory) ||
                matches!(iced_access, OpAccess::None | OpAccess::NoMemAccess) ||
                operand.access.conditional_read || operand.access.conditional_write {
                access_incomparable += 1;
            } else if access_equal(operand.access, iced_access) { access_checked += 1; }
            else { eprintln!("access mismatch {:02x?} operand {index}: mkasm={:?} iced={:?}", bytes, operand.access, info.op_access(index as u32)); access_bad += 1; }
        }
        let implicit_registers: Vec<_> = ours.operands().iter().filter(|operand| operand.implicit && operand.kind == OperandKind::Register).collect();
        if !implicit_oracle_mnemonic(&ours.encoding().mnemonic.to_lowercase()) {
            implicit_incomparable += implicit_registers.len();
        } else {
            for number in 0u8..=3 {
                let ours_family: Vec<_> = implicit_registers.iter().filter(|operand| operand.register.is_some_and(|register| register.class == RegisterClass::Gpr && register.number == number)).collect();
                if ours_family.is_empty() { continue; }
                if explicit.iter().any(|operand| {
                    operand.register.is_some_and(|register| register.class == RegisterClass::Gpr && register.number == number) ||
                        operand.memory.base.is_some_and(|register| register.class == RegisterClass::Gpr && register.number == number) ||
                        operand.memory.index.is_some_and(|register| register.class == RegisterClass::Gpr && register.number == number)
                }) {
                    implicit_incomparable += ours_family.len();
                    continue;
                }
                let iced_family: Vec<_> = info.used_registers().iter().filter(|used| gpr_number(&format!("{:?}", used.register()).to_lowercase()) == Some(number)).collect();
                let ours_read = ours_family.iter().any(|operand| operand.access.read || operand.access.conditional_read);
                let ours_write = ours_family.iter().any(|operand| operand.access.write || operand.access.conditional_write);
                let iced_read = iced_family.iter().any(|used| matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite));
                let iced_write = iced_family.iter().any(|used| matches!(used.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite));
                if !iced_family.is_empty() && ours_read == iced_read && ours_write == iced_write {
                    implicit_checked += ours_family.len();
                } else {
                    eprintln!("implicit register family mismatch {:02x?}: gpr{number} mkasm=({ours_read},{ours_write}) iced=({iced_read},{iced_write})", bytes);
                    implicit_bad += ours_family.len();
                }
            }
        }
        if matches!(ours.flow_control(), FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch) &&
            iced.op_count() != 0 && matches!(iced.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
            if let Some(relative) = ours.operands().iter().find(|operand| operand.kind == OperandKind::Relative) {
                let ours_target = 0x1000u64.wrapping_add(ours.length as u64).wrapping_add_signed(relative.immediate.signed);
                if ours_target == iced.near_branch_target() { target_checked += 1; }
                else { eprintln!("branch target mismatch {:02x?}: mkasm=0x{ours_target:x} iced=0x{:x}", bytes, iced.near_branch_target()); target_bad += 1; }
            }
        }
        if let Some(memory) = ours.operands().iter().find(|operand| operand.kind == OperandKind::Memory && operand.memory.rip_relative) {
            let ours_target = 0x1000u64.wrapping_add(ours.length as u64).wrapping_add_signed(memory.memory.displacement);
            if ours_target == iced.ip_rel_memory_address() { target_checked += 1; }
            else { eprintln!("RIP target mismatch {:02x?}: mkasm=0x{ours_target:x} iced=0x{:x}", bytes, iced.ip_rel_memory_address()); target_bad += 1; }
        }
        if explicit.iter().any(|operand| matches!(operand.kind, OperandKind::Other | OperandKind::FarPointer | OperandKind::None)) || explicit.len() != iced.op_count() as usize {
            skipped += 1; continue;
        }
        let mut equal = true;
        for (index, operand) in explicit.iter().enumerate() {
            let kind = iced.op_kind(index as u32);
            match operand.kind {
                OperandKind::Register => if let Some(register) = operand.register {
                    let mkasm_register = register_name(register.class, register.number, register.width, register.high8);
                    let iced_register = format!("{:?}", iced.op_register(index as u32)).to_lowercase();
                    if mkasm_register != iced_register {
                        if !iced_register_view_quirk(&format!("{:?}", iced.code())) {
                            eprintln!("register mismatch {:02x?} operand {index}: mkasm={mkasm_register} iced={iced_register}", bytes);
                        }
                        equal = false;
                    }
                } else { equal = false; },
                OperandKind::Memory if memory(kind) => {
                    let base = operand.memory.base.map(|r| register_name(r.class, r.number, r.width, r.high8)).unwrap_or_else(|| "none".into());
                    let vector_index = operand.memory.index.map(|r| register_name(r.class, r.number, r.width, r.high8)).unwrap_or_else(|| "none".into());
                    equal &= base == format!("{:?}", iced.memory_base()).to_lowercase() &&
                        vector_index == format!("{:?}", iced.memory_index()).to_lowercase() &&
                        u32::from(operand.memory.scale) == iced.memory_index_scale();
                }
                OperandKind::Immediate if matches!(kind, OpKind::Immediate8 | OpKind::Immediate8_2nd | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32to64) => {
                    let iced_value = iced.immediate(index as u32);
                    if operand.immediate.value != iced_value {
                        eprintln!("immediate mismatch {:02x?} operand {index}: mkasm=0x{:x} iced=0x{iced_value:x} kind={kind:?}", bytes, operand.immediate.value);
                        equal = false;
                    }
                },
                OperandKind::Relative if matches!(kind, OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) => {}
                _ => equal = false,
            }
        }
        if equal { checked += 1; }
        else if iced_register_view_quirk(&format!("{:?}", iced.code())) { skipped += 1; }
        else { eprintln!("operand mismatch {:02x?}: {} vs {:?}", bytes, ours.format_intel(0x1000), iced.code()); bad += 1; }
    }
    let mut relocation_checks = 0usize;
    for (original, old_ip, new_ip) in [
        (&[0xe8, 0x00, 0x01, 0x00, 0x00][..], 0x1000u64, 0x2000u64),
        (&[0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00][..], 0x1000u64, 0x2000u64),
        (&[0x90][..], 0x1000u64, 0x2000u64),
    ] {
        let decoded = mkasm::decode(original, Mode::Mode64).unwrap();
        let mut ours_bytes = [0u8; 15];
        let ours_len = mkasm::relocate(&decoded, original, old_ip, new_ip, &mut ours_bytes).unwrap();
        let mut decoder = Decoder::with_ip(64, original, old_ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let mut encoder = Encoder::new(64);
        let iced_len = encoder.encode(&instruction, new_ip).unwrap();
        assert_eq!(&ours_bytes[..ours_len], &encoder.take_buffer()[..iced_len]);
        relocation_checks += 1;
    }
    let original = [0xe8, 0, 0, 0, 0];
    let decoded = mkasm::decode(&original, Mode::Mode64).unwrap();
    let mut relocated = [0u8; 15];
    assert_eq!(mkasm::relocate(&decoded, &original, 0, 0x1_0000_0000, &mut relocated), Err(RelocateError::OutOfRange));
    relocation_checks += 1;
    println!("iced oracle: cases={} operands_checked={} operands_skipped={} formatted={} flow_checked={} access_checked={} access_incomparable={} implicit_checked={} implicit_incomparable={} targets_checked={} relocation_checks={} iced_unsupported={} operand_mismatches={} formatter_mismatches={} flow_mismatches={} access_mismatches={} implicit_mismatches={} target_mismatches={}", CASES.len(), checked, skipped, formatted, flow_checked, access_checked, access_incomparable, implicit_checked, implicit_incomparable, target_checked, relocation_checks, unsupported, bad, format_bad, flow_bad, access_bad, implicit_bad, target_bad);
    if CASES.len() < 6_000 || checked < 6_000 || bad != 0 || format_bad != 0 || flow_bad != 0 || access_bad != 0 || implicit_bad != 0 || target_bad != 0 { std::process::exit(1); }
}
`
