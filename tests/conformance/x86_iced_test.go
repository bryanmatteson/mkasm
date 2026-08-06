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

const icedOperandOracleSource = `use iced_x86::{CC_a, CC_ae, CC_e, CC_g, CC_ge, CC_ne, Decoder, DecoderOptions, Formatter, IntelFormatter, MemorySizeOptions, NumberBase, OpKind};
use mkasm::{Mode, OperandKind, RegisterClass};

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

fn main() {
    let (mut checked, mut skipped, mut unsupported, mut bad) = (0usize, 0usize, 0usize, 0usize);
    let (mut formatted, mut format_bad) = (0usize, 0usize);
    for (bytes, bits) in CASES {
        let mode = match bits { 16 => Mode::Mode16, 32 => Mode::Mode32, _ => Mode::Mode64 };
        let ours = match mkasm::decode(bytes, mode) { Ok(value) => value, Err(error) => {
            eprintln!("mkasm rejected {:02x?}: {error:?}", bytes); bad += 1; continue;
        }};
        let mut decoder = Decoder::with_ip(*bits, bytes, 0x1000, DecoderOptions::MPX | DecoderOptions::KNC);
        let iced = decoder.decode();
        if iced.is_invalid() || iced.len() != bytes.len() { unsupported += 1; continue; }
        let mkasm_text = ours.format_intel(0x1000);
        let iced_text = format_iced(&iced);
        if mkasm_text == iced_text { formatted += 1; }
        else {
            eprintln!("formatter mismatch {:02x?}: mkasm={mkasm_text:?} iced={iced_text:?}", bytes);
            format_bad += 1;
        }
        let explicit: Vec<_> = ours.operands().iter().filter(|operand| !operand.implicit && operand.kind != OperandKind::Mask).collect();
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
    println!("iced oracle: cases={} operands_checked={} operands_skipped={} formatted={} iced_unsupported={} operand_mismatches={} formatter_mismatches={}", CASES.len(), checked, skipped, formatted, unsupported, bad, format_bad);
    if CASES.len() < 6_000 || checked < 6_000 || bad != 0 || format_bad != 0 { std::process::exit(1); }
}
`
