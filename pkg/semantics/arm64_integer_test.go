package semantics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed arm64_integer.rs
var a64IntegerModuleSource string

func TestRustA64IntegerSIMD(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_integer") {
		source += "\npub mod arm64_integer {\n" + a64IntegerModuleSource + "\n}\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "semantics.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	consumer := a64IntegerBehaviorTests + a64IntegerCorpusCases(t)
	if err := os.WriteFile(filepath.Join(dir, "integer.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "integer.rs", "-Dwarnings", "-o", filepath.Join(dir, "a64-integer-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A64 integer SIMD: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "a64-integer-tests"), "a64_integer_behavior::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute A64 integer SIMD: %v\n%s", err, out)
	}
}

// Derive physical words from upstream class diagrams, independently of the
// helper's masks. Ordinary tests retain portable, explicitly selected words.
func a64IntegerCorpusCases(t *testing.T) string {
	t.Helper()
	var result strings.Builder
	result.WriteString("\nconst INTEGER_CORPUS:&[(u32,bool,&str)]=&[\n")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		result.WriteString("];\n")
		return result.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	type cell struct {
		Text string `xml:",chardata"`
		Span int    `xml:"colspan,attr"`
	}
	type box struct {
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type cls struct {
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
	}
	type page struct {
		Classes []cls `xml:"classes>iclass"`
	}
	seen := map[string]bool{}
	count := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(header.Name)
		if seen[name] || !strings.HasPrefix(header.Name, "ISA_A64_xml_A_profile-2026-06/") {
			continue
		}
		stem := strings.TrimSuffix(name, ".xml")
		family := strings.Split(stem, "_")[0]
		supported := true
		selected := strings.HasSuffix(name, ".xml") && strings.Contains(name, "_advsimd")
		switch family {
		case "sqadd", "uqadd", "sqsub", "uqsub", "sqabs", "sqneg", "sshr", "ushr", "srshr", "urshr", "ssra", "usra", "srsra", "ursra", "shl", "sli", "sri", "sqshl", "uqshl", "sqshlu", "sshl", "ushl", "sqrshl", "uqrshl", "zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2", "xtn", "sqxtn", "uqxtn", "sqxtun", "shrn", "rshrn", "sqshrn", "uqshrn", "sqrshrn", "uqrshrn", "sqshrun", "sqrshrun", "saddl", "uaddl", "ssubl", "usubl", "saddw", "uaddw", "ssubw", "usubw", "smull", "umull", "smlal", "umlal", "smlsl", "umlsl", "addv", "saddlv", "uaddlv", "smaxv", "sminv", "umaxv", "uminv", "sdot", "udot", "tbl", "tbx", "rev16", "rev32", "rev64", "abs", "cnt", "rbit", "cls", "clz", "ext", "smax", "smin", "umax", "umin", "mul", "mla", "mls", "addp", "smaxp", "sminp", "umaxp", "uminp", "sshll", "ushll", "shll", "sabd", "uabd", "saba", "uaba", "suqadd", "usqadd", "shadd", "uhadd", "shsub", "uhsub", "srhadd", "urhadd", "addhn", "raddhn", "subhn", "rsubhn", "saddlp", "uaddlp", "sadalp", "uadalp", "sabdl", "uabdl", "sabal", "uabal", "sqdmulh", "sqrdmulh", "sqrdmlah", "sqrdmlsh", "sqdmull", "sqdmlal", "sqdmlsl", "dup", "ins", "umov", "smov":
		default:
			selected = false
		}
		if !selected {
			continue
		}
		seen[name] = true
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		var parsed page
		if err = xml.NewDecoder(bytes.NewReader(body)).Decode(&parsed); err != nil {
			t.Fatal(err)
		}
		for _, cl := range parsed.Classes {
			var fixed, value uint32
			for _, b := range cl.Diagram.Boxes {
				width := b.Width
				if width == 0 {
					width = 1
				}
				var bits strings.Builder
				for _, c := range b.Cells {
					span := c.Span
					if span == 0 {
						span = 1
					}
					text := strings.Trim(strings.TrimSpace(c.Text), "()")
					if len(text) != span {
						text = strings.Repeat("x", span)
					}
					bits.WriteString(text)
				}
				if bits.Len() != width {
					t.Fatalf("bad corpus diagram %s %s", name, b.Name)
				}
				for i, c := range bits.String() {
					if c == '0' || c == '1' {
						bit := uint32(1) << uint(b.Hi-i)
						fixed |= bit
						if c == '1' {
							value |= bit
						}
					}
				}
			}
			words := map[uint32]bool{}
			for flags := 0; flags < 4; flags++ {
				for variant := 0; variant < 2; variant++ {
					word := value
					for _, b := range cl.Diagram.Boxes {
						width := b.Width
						if width == 0 {
							width = 1
						}
						v := uint32(0)
						switch b.Name {
						case "size":
							v = 1
							if family == "sdot" || family == "udot" {
								v = 2
							}
							if family == "cnt" || family == "rev16" {
								v = 0
							}
						case "Q":
							v = 1
						case "Rn":
							v = 1
						case "Rm":
							v = 2
						case "Rd":
							v = uint32(variant)
						case "immh":
							v = 2
							if value&(1<<28) != 0 && (family == "sshr" || family == "ushr" || family == "srshr" || family == "urshr" || strings.HasSuffix(family, "sra") || family == "shl" || family == "sli" || family == "sri") {
								v = 8
							}
						case "imm5":
							v = 4 | (uint32(flags) << 3)
							if family == "umov" {
								v = 8 | (uint32(flags&1) << 4)
							}
						case "immb":
							v = uint32(flags)
						case "imm4", "len":
							v = uint32(flags)
						case "H", "L", "M":
							v = uint32(flags & 1)
						}
						low := b.Hi - width + 1
						mask := uint32((uint64(1)<<uint(width))-1) << uint(low)
						word |= (v << uint(low)) & mask &^ fixed
					}
					if words[word] {
						continue
					}
					words[word] = true
					fmt.Fprintf(&result, "(0x%08x,%t,%q),\n", word, supported, name)
					count++
				}
			}
		}
	}
	result.WriteString("];\n")
	t.Logf("derived %d A64 integer SIMD words from %d upstream pages", count, len(seen))
	return result.String()
}

const a64IntegerBehaviorTests = `
#[allow(dead_code)]
mod semantics;
mod a64_integer_behavior {
 #[test]fn ordinary_scalar_fp_major_groups_are_not_integer_simd(){
  for word in [0x1e209000,0x1e222820,0x1f020c20,0x9e620020,0x9e660020]{assert!(super::semantics::arm64_integer::a64(word,0x1000).is_none(),"{word:08x}");}
 }
    use super::semantics::arm64_integer::a64;
    use super::semantics::*;
    #[derive(Clone, Default)]
    struct State {
        v: [u128; 32],
        fpsr: u32,
        g: [u64; 31],
    }
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            match r.bank {
                "a64.gpr" => Value::known(64, self.g[r.index as usize]),
                "a64.vector64" => {
                    assert!(r.index % 32 < 2);
                    Value::known(
                        64,
                        (self.v[usize::from(r.index / 32)] >> (r.index % 32 * 64)) as u64,
                    )
                }
                "a64.fpsr" => {
                    assert_eq!(r.index, 0);
                    Value::known(32, u64::from(self.fpsr))
                }
                _ => panic!("unexpected bank {r:?}"),
            }
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("integer SIMD read memory")
        }
    }
    fn run(word: u32, s: &State) -> (State, Transition) {
        let r = a64(word, 0x1000).unwrap_or_else(|| panic!("unhandled {word:08x}"));
        assert_eq!(r.support, Support::Full, "{word:08x}");
        let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{word:08x}: {e:?}"));
        assert!(t.memory.is_empty());
        assert!(t.atomics.is_empty());
        assert!(t.events.is_empty());
        assert_eq!(t.next_pc, Value::known(64, 0x1004));
        let mut out = s.clone();
        for x in &t.registers {
            match x.register.bank {
                "a64.gpr" => out.g[x.register.index as usize] = x.value.bits,
                "a64.vector64" => {
                    let n = usize::from(x.register.index / 32);
                    let shift = (x.register.index % 32) * 64;
                    out.v[n] = (out.v[n] & !(u128::from(u64::MAX) << shift))
                        | (u128::from(x.value.bits) << shift);
                }
                "a64.fpsr" => out.fpsr = x.value.bits as u32,
                _ => panic!("unexpected output"),
            }
        }
        (out, t)
    }
    fn word(base: u32, size: u32, q: bool, d: u32, n: u32, m: u32) -> u32 {
        base | (size << 22) | ((q as u32) << 30) | (m << 16) | (n << 5) | d
    }
    fn elem(v: u128, i: u8, w: u8) -> u64 {
        ((v >> (u16::from(i) * u16::from(w))) as u64) & mask(w)
    }
    fn repeat(x: u64, w: u8, bits: u8) -> u128 {
        (0..bits / w).fold(0, |a, i| a | (u128::from(x & mask(w)) << (i * w)))
    }
    fn signed(x: u64, w: u8) -> i128 {
        let x = i128::from(x & mask(w));
        if x & (1i128 << (w - 1)) != 0 {
            x - (1i128 << w)
        } else {
            x
        }
    }
    fn sat(x: i128, w: u8, sign: bool) -> (u64, bool) {
        let lo = if sign { -(1i128 << (w - 1)) } else { 0 };
        let hi = if sign {
            (1i128 << (w - 1)) - 1
        } else {
            (1i128 << w) - 1
        };
        ((x.clamp(lo, hi) as u64) & mask(w), x < lo || x > hi)
    }
    #[test]
    fn saturation_all_lane_widths_scalar_vector_aliases_and_sticky_qc() {
        for size in 0..4 {
            let w = 8u8 << size;
            let vals = [0, 1, mask(w), 1u64 << (w - 1), (1u64 << (w - 1)) - 1];
            for scalar in [false, true] {
                for q in [false, true] {
                    if !scalar && w == 64 && !q {
                        continue;
                    }
                    for sign in [false, true] {
                        for sub in [false, true] {
                            for a in vals {
                                for z in vals {
                                    for oldqc in [0, 1 << 27] {
                                        let mut s = State::default();
                                        s.fpsr = 0x9f | oldqc;
                                        s.v[0] = repeat(a, w, 128);
                                        s.v[1] = repeat(z, w, 128);
                                        let x = if sign { signed(a, w) } else { i128::from(a) };
                                        let y = if sign { signed(z, w) } else { i128::from(z) };
                                        let (v, changed) =
                                            sat(if sub { x - y } else { x + y }, w, sign);
                                        let base = if scalar { 0x5e200c00 } else { 0x0e200c00 }
                                            | if sign { 0 } else { 1 << 29 }
                                            | if sub { 1 << 13 } else { 0 };
                                        let (out, _) = run(word(base, size, q, 0, 0, 1), &s);
                                        assert_eq!(out.v[0],repeat(v,w,if scalar{w}else if q{128}else{64}),"w={w} scalar={scalar} sign={sign} sub={sub} a={a:x} z={z:x}");
                                        assert_eq!(
                                            out.fpsr,
                                            0x9f | oldqc | if changed { 1 << 27 } else { 0 }
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn register_shifts_signed_low_byte_and_64_bit_rounding() {
        for size in 0..4 {
            let w = 8u8 << size;
            for sign in [false, true] {
                for rounded in [false, true] {
                    for saturated in [false, true] {
                        for amount in [
                            -128i16, -65, -64, -33, -32, -17, -16, -9, -8, -1, 0, 1, 7, 8, 15, 16,
                            31, 32, 63, 64, 65, 127,
                        ] {
                            for a in [0, 1, mask(w), (1u64 << (w - 1)), (1u64 << (w - 1)) - 1] {
                                let mut s = State::default();
                                s.v[0] = repeat(a, w, 128);
                                s.v[1] = repeat((amount as u8 as u64) | 0x1234567800000000, w, 128);
                                let x = if sign { signed(a, w) } else { i128::from(a) };
                                let (v, qc) = if amount >= 0 {
                                    if saturated {
                                        if amount >= i16::from(w) {
                                            if x == 0 {
                                                (0, false)
                                            } else {
                                                (
                                                    if sign && x < 0 {
                                                        1u64 << (w - 1)
                                                    } else if sign {
                                                        mask(w - 1)
                                                    } else {
                                                        mask(w)
                                                    },
                                                    true,
                                                )
                                            }
                                        } else {
                                            sat(x << amount, w, sign)
                                        }
                                    } else {
                                        (
                                            if amount >= i16::from(w) {
                                                0
                                            } else {
                                                ((x << amount) as u64) & mask(w)
                                            },
                                            false,
                                        )
                                    }
                                } else {
                                    let k = (-amount) as u32;
                                    let v = if k > 64 {
                                        if sign && x < 0 && !rounded {
                                            -1
                                        } else {
                                            0
                                        }
                                    } else {
                                        (x + if rounded { 1i128 << (k - 1) } else { 0 }) >> k
                                    };
                                    ((v as u64) & mask(w), false)
                                };
                                let base = 0x0e204400
                                    | if sign { 0 } else { 1 << 29 }
                                    | if rounded { 1 << 12 } else { 0 }
                                    | if saturated { 1 << 11 } else { 0 };
                                let (out, _) = run(word(base, size, true, 0, 0, 1), &s);
                                assert_eq!(out.v[0],repeat(v,w,128),"w={w} sign={sign} round={rounded} sat={saturated} shift={amount} a={a:x}");
                                assert_eq!(out.fpsr, if qc { 1 << 27 } else { 0 });
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn permutations_and_extract_capture_both_chunks_before_alias_writes() {
        let mut s = State::default();
        s.v[0] = u128::from_le_bytes(core::array::from_fn(|i| i as u8));
        s.v[1] = u128::from_le_bytes(core::array::from_fn(|i| 0x80 + i as u8));
        for size in 0..4 {
            let w = 8u8 << size;
            for q in [false, true] {
                if w == 64 && !q {
                    continue;
                }
                let count = if q { 128 / w } else { 64 / w };
                for (op, base) in [(0, 0x0e001800), (1, 0x0e002800), (2, 0x0e003800)] {
                    for part in 0..2 {
                        let mut expected = 0;
                        for i in 0..count {
                            let (reg, index) = match op {
                                0 => (
                                    if i < count / 2 { 0 } else { 1 },
                                    (i % (count / 2)) * 2 + part,
                                ),
                                1 => (i % 2, (i / 2) * 2 + part),
                                _ => (i % 2, i / 2 + part * (count / 2)),
                            };
                            expected |= u128::from(elem(s.v[reg as usize], index, w)) << (i * w);
                        }
                        let (out, _) =
                            run(word(base | ((part as u32) << 14), size, q, 0, 0, 1), &s);
                        assert_eq!(out.v[0], expected);
                    }
                }
            }
        }
        for q in [false, true] {
            let bytes = if q { 16 } else { 8 };
            for offset in 0..bytes {
                let mut expected = 0;
                for i in 0..bytes {
                    let k = i + offset;
                    expected |= u128::from(elem(s.v[if k < bytes { 0 } else { 1 }], k % bytes, 8))
                        << (i * 8);
                }
                let (out, _) = run(
                    word(0x2e000000 | ((offset as u32) << 11), 0, q, 0, 0, 1),
                    &s,
                );
                assert_eq!(out.v[0], expected);
            }
        }
    }
    #[test]
    fn table_lookup_wraps_registers_preserves_tbx_misses_and_zeros_q0_upper() {
        let mut s = State::default();
        for n in 0..32 {
            for i in 0..16 {
                s.v[n] |= u128::from((n * 16 + i) as u8) << (i * 8);
            }
        }
        for len in 1..5u8 {
            for q in [false, true] {
                for tbx in [false, true] {
                    let bytes = if q { 16 } else { 8 };
                    let indices = [
                        0, 15, 16, 31, 32, 47, 48, 63, 64, 127, 128, 255, 1, 17, 33, 49,
                    ];
                    s.v[30] = u128::from_le_bytes(indices);
                    let mut expected = 0;
                    for i in 0..bytes {
                        let index = indices[i as usize];
                        let val = if index < len * 16 {
                            elem(s.v[((31 + index / 16) % 32) as usize], index % 16, 8)
                        } else if tbx {
                            elem(s.v[30], i, 8)
                        } else {
                            0
                        };
                        expected |= u128::from(val) << (i * 8);
                    }
                    let (out, _) = run(
                        word(
                            0x0e000000 | (u32::from(len - 1) << 13) | if tbx { 1 << 12 } else { 0 },
                            0,
                            q,
                            30,
                            31,
                            30,
                        ),
                        &s,
                    );
                    assert_eq!(out.v[30], expected, "len={len} q={q} tbx={tbx}");
                }
            }
        }
    }
    #[test]
    fn widening_products_high_source_and_indexed_multiply_capture_accumulator() {
        let mut s = State::default();
        s.v[0] = u128::from_le_bytes([0xff, 0x80, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        s.v[1] = u128::from_le_bytes([3, 2, 1, 0xff, 0x80, 5, 4, 3, 2, 1, 0xff, 0x80, 4, 5, 6, 7]);
        for size in 0..3 {
            let w = 8u8 << size;
            for q in [false, true] {
                for unsigned in [false, true] {
                    for op in [0, 1, 2, 3, 8, 10, 12] {
                        let mut expected = 0;
                        for i in 0..64 / w {
                            let off = if q { 64 / w } else { 0 };
                            let av = if op == 1 || op == 3 {
                                elem(s.v[0], i, w * 2)
                            } else {
                                elem(s.v[0], i + off, w)
                            };
                            let zv = elem(s.v[1], i + off, w);
                            let a = if op == 1 || op == 3 || unsigned {
                                i128::from(av)
                            } else {
                                signed(av, w)
                            };
                            let z = if unsigned {
                                i128::from(zv)
                            } else {
                                signed(zv, w)
                            };
                            let value = match op {
                                0 | 1 => a + z,
                                2 | 3 => a - z,
                                8 => i128::from(elem(s.v[0], i, w * 2)) + a * z,
                                10 => i128::from(elem(s.v[0], i, w * 2)) - a * z,
                                12 => a * z,
                                _ => unreachable!(),
                            };
                            expected |= u128::from((value as u64) & mask(w * 2)) << (i * w * 2);
                        }
                        let (out, _) = run(
                            word(
                                0x0e200000 | (op << 12) | if unsigned { 1 << 29 } else { 0 },
                                size,
                                q,
                                0,
                                0,
                                1,
                            ),
                            &s,
                        );
                        assert_eq!(out.v[0], expected, "size={size} q={q} U={unsigned} op={op}");
                    }
                }
            }
        }
        for size in [1, 2] {
            let w = 8u8 << size;
            for h in 0..2 {
                for l in 0..2 {
                    for mb in 0..2 {
                        let rm = if size == 1 { 1 } else { 1 + mb * 16 };
                        s.v[rm as usize] = s.v[1];
                        let index = if size == 1 {
                            h * 4 + l * 2 + mb
                        } else {
                            h * 2 + l
                        };
                        let z = elem(s.v[rm as usize], index as u8, w);
                        let expected = (0..128 / w).fold(0, |acc, i| {
                            acc | (u128::from(elem(s.v[0], i, w).wrapping_mul(z) & mask(w))
                                << (i * w))
                        });
                        let encoding = 0x0f008000
                            | (size << 22)
                            | (1 << 30)
                            | (h << 11)
                            | (l << 21)
                            | (mb << 20)
                            | (1 << 16);
                        let (out, _) = run(encoding, &s);
                        assert_eq!(out.v[0], expected);
                    }
                }
            }
        }
    }
    #[test]
    fn narrowing_saturation_and_part_preservation() {
        for size in 0..3 {
            let w = 8u8 << size;
            let inputw = w * 2;
            for base in [0x0e212800, 0x0e214800, 0x2e214800, 0x2e212800] {
                for high in [false, true] {
                    let mut s = State::default();
                    s.v[0] = u128::MAX;
                    s.fpsr = 0x9f;
                    let values = [
                        0,
                        mask(inputw),
                        1u64 << (inputw - 1),
                        mask(w),
                        mask(w - 1),
                        1u64 << (w - 1),
                        mask(w) + 1,
                        1,
                    ];
                    for i in 0..128 / inputw {
                        s.v[1] |= u128::from(values[i as usize % values.len()] & mask(inputw))
                            << (i * inputw);
                    }
                    let mut expected = 0;
                    let mut qc = false;
                    for i in 0..64 / w {
                        let a = elem(s.v[1], i, inputw);
                        let (v, q) = if base == 0x0e212800 {
                            (a & mask(w), false)
                        } else {
                            sat(
                                if base == 0x2e214800 {
                                    i128::from(a)
                                } else {
                                    signed(a, inputw)
                                },
                                w,
                                base == 0x0e214800,
                            )
                        };
                        qc |= q;
                        expected |= u128::from(v) << (i * w);
                    }
                    if high {
                        expected = (expected << 64) | u128::from(u64::MAX);
                    }
                    let (out, _) = run(word(base, size, high, 0, 1, 0), &s);
                    assert_eq!(out.v[0], expected);
                    assert_eq!(out.fpsr, 0x9f | if qc { 1 << 27 } else { 0 });
                }
            }
        }
    }
    #[test]
    fn immediate_right_rounding_width_sized_and_narrow_ties() {
        for w in [8u8, 16, 32, 64] {
            for sign in [false, true] {
                for round in [false, true] {
                    for amount in [1, w / 2, w] {
                        for a in [0, 1, mask(w), 1u64 << (w - 1), mask(w - 1)] {
                            let mut s = State::default();
                            s.v[0] = repeat(a, w, 128);
                            let x = if sign { signed(a, w) } else { i128::from(a) };
                            let expected = (((x + if round { 1i128 << (amount - 1) } else { 0 })
                                >> amount) as u64)
                                & mask(w);
                            let imm = 2 * w - amount;
                            let base = 0x0f000400
                                | if sign { 0 } else { 1 << 29 }
                                | if round { 1 << 13 } else { 0 };
                            let (out, _) = run(base | (1 << 30) | (u32::from(imm) << 16), &s);
                            assert_eq!(
                                out.v[0],
                                repeat(expected, w, 128),
                                "w={w} amount={amount} round={round} signed={sign} a={a:x}"
                            );
                        }
                    }
                }
            }
        }
        for w in [8u8, 16, 32] {
            for sign in [false, true] {
                for round in [false, true] {
                    for high in [false, true] {
                        let mut s = State::default();
                        s.v[0] = u128::MAX;
                        let inputw = w * 2;
                        let value = mask(w - 1) * 2 + 1;
                        s.v[1] = repeat(value, inputw, 128);
                        let amount = 1;
                        let imm = 2 * w - amount;
                        let base = if sign { 0x0f009400 } else { 0x2f009400 }
                            | if round { 1 << 11 } else { 0 };
                        let (v, qc) = sat(
                            (i128::from(value) + if round { 1 } else { 0 }) >> 1,
                            w,
                            sign,
                        );
                        let expected = repeat(v, w, 64);
                        let expected = if high {
                            (expected << 64) | u128::from(u64::MAX)
                        } else {
                            expected
                        };
                        let (out, _) = run(
                            base | ((high as u32) << 30) | (u32::from(imm) << 16) | (1 << 5),
                            &s,
                        );
                        assert_eq!(out.v[0], expected);
                        assert_eq!(out.fpsr, if qc { 1 << 27 } else { 0 });
                    }
                }
            }
        }
    }
    #[test]
    fn dot_products_and_reductions_use_original_operands_and_scalar_zeroing() {
        let mut s = State::default();
        s.v[0] = u128::from_le_bytes([
            0x80, 0xff, 2, 3, 4, 5, 6, 7, 8, 9, 0xff, 0x80, 12, 13, 14, 15,
        ]);
        s.v[1] = u128::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0x80, 11, 12, 13, 14, 15, 16]);
        for q in [false, true] {
            for sign in [false, true] {
                for indexed in [false, true] {
                    for index in 0..4 {
                        let mut expected = 0;
                        for i in 0..if q { 4 } else { 2 } {
                            let mut value = i128::from(elem(s.v[0], i, 32));
                            for j in 0..4 {
                                let a = elem(s.v[0], i * 4 + j, 8);
                                let z = elem(
                                    s.v[1],
                                    if indexed { index * 4 + j } else { i * 4 + j },
                                    8,
                                );
                                value += if sign {
                                    signed(a, 8) * signed(z, 8)
                                } else {
                                    i128::from(a) * i128::from(z)
                                };
                            }
                            expected |= u128::from(value as u32) << (i * 32);
                        }
                        let base = if indexed {
                            0x0f80e000
                                | ((index as u32 & 1) << 21)
                                | ((u32::from(index) >> 1) << 11)
                        } else {
                            0x0e809400
                        } | if sign { 0 } else { 1 << 29 };
                        let (out, _) = run(word(base, 0, q, 0, 0, 1), &s);
                        assert_eq!(out.v[0], expected);
                    }
                }
            }
        }
        for size in 0..3 {
            let w = 8u8 << size;
            for unsigned in [false, true] {
                for op in [0x0e31b800, 0x0e303800, 0x0e30a800, 0x0e31a800] {
                    if unsigned && op == 0x0e31b800 {
                        continue;
                    }
                    let wide = op == 0x0e303800;
                    let width = if wide { w * 2 } else { w };
                    let vals: Vec<_> = (0..128 / w)
                        .map(|i| {
                            let a = elem(s.v[0], i, w);
                            if unsigned {
                                i128::from(a)
                            } else {
                                signed(a, w)
                            }
                        })
                        .collect();
                    let expected = if op == 0x0e30a800 {
                        *vals.iter().max().unwrap()
                    } else if op == 0x0e31a800 {
                        *vals.iter().min().unwrap()
                    } else {
                        vals.iter().sum()
                    };
                    let (out, _) = run(
                        word(op | if unsigned { 1 << 29 } else { 0 }, size, true, 0, 0, 0),
                        &s,
                    );
                    assert_eq!(out.v[0], u128::from((expected as u64) & mask(width)));
                }
            }
        }
    }

    #[test]
    fn mixed_signed_unsigned_accumulate_including_64_bit_extremes() {
        for size in 0..4 {
            let w = 8u8 << size;
            let vals = [0, 1, mask(w), 1u64 << (w - 1), mask(w - 1)];
            for unsigned in [false, true] {
                for scalar in [false, true] {
                    for a in vals {
                        for z in vals {
                            let mut s = State::default();
                            s.v[0] = repeat(a, w, 128);
                            s.v[1] = repeat(z, w, 128);
                            s.fpsr = 0x9f;
                            let x = if unsigned {
                                i128::from(a)
                            } else {
                                signed(a, w)
                            };
                            let y = if unsigned {
                                signed(z, w)
                            } else {
                                i128::from(z)
                            };
                            let (v, qc) = sat(x + y, w, !unsigned);
                            let base = if scalar { 0x5e203800 } else { 0x0e203800 }
                                | if unsigned { 1 << 29 } else { 0 };
                            let (out, _) = run(word(base, size, true, 0, 1, 0), &s);
                            assert_eq!(out.v[0], repeat(v, w, if scalar { w } else { 128 }));
                            assert_eq!(out.fpsr, 0x9f | if qc { 1 << 27 } else { 0 });
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn doubling_multiply_two_stage_saturation_and_rdm_final_saturation() {
        for size in [1, 2] {
            let w = 8u8 << size;
            let vals = [0, 1, mask(w), 1u64 << (w - 1), mask(w - 1)];
            for a in vals {
                for z in vals {
                    for acc in [0, mask(w), 1u64 << (w - 1), mask(w - 1)] {
                        for scalar in [false, true] {
                            let mut s = State::default();
                            s.v[0] = repeat(acc, w, 128);
                            s.v[1] = repeat(a, w, 128);
                            s.v[2] = repeat(z, w, 128);
                            for (base, rounded, accumulate, subtract) in [
                                (0x0e20b400, false, false, false),
                                (0x2e20b400, true, false, false),
                                (0x2e008400, true, true, false),
                                (0x2e008c00, true, true, true),
                            ] {
                                let product = signed(a, w) * signed(z, w) * 2;
                                let x = if accumulate {
                                    (signed(acc, w) << w)
                                        + if subtract { -product } else { product }
                                } else {
                                    product
                                };
                                let x = (x + if rounded { 1i128 << (w - 1) } else { 0 }) >> w;
                                let (v, qc) = sat(x, w, true);
                                let (out, _) = run(
                                    word(
                                        base | if scalar { 1 << 28 | 1 << 30 } else { 0 },
                                        size,
                                        true,
                                        0,
                                        1,
                                        2,
                                    ),
                                    &s,
                                );
                                assert_eq!(
                                    out.v[0],
                                    repeat(v, w, if scalar { w } else { 128 }),
                                    "base={base:x} a={a:x} z={z:x} acc={acc:x}"
                                );
                                assert_eq!(out.fpsr, if qc { 1 << 27 } else { 0 });
                            }
                        }
                    }
                }
            }
            for a in vals {
                for z in vals {
                    for acc in [0, mask(w * 2), 1u64 << (w * 2 - 1), mask(w * 2 - 1)] {
                        let mut s = State::default();
                        s.v[0] = repeat(acc, w * 2, 128);
                        s.v[1] = repeat(a, w, 128);
                        s.v[2] = repeat(z, w, 128);
                        let (product, q1) = sat(2 * signed(a, w) * signed(z, w), w * 2, true);
                        for (base, accumulate, subtract) in [
                            (0x0e20d000, false, false),
                            (0x0e209000, true, false),
                            (0x0e20b000, true, true),
                        ] {
                            let (v, q2) = if accumulate {
                                sat(
                                    signed(acc, w * 2)
                                        + if subtract {
                                            -signed(product, w * 2)
                                        } else {
                                            signed(product, w * 2)
                                        },
                                    w * 2,
                                    true,
                                )
                            } else {
                                (product, false)
                            };
                            let (out, _) = run(word(base, size, true, 0, 1, 2), &s);
                            assert_eq!(out.v[0], repeat(v, w * 2, 128));
                            assert_eq!(out.fpsr, if q1 || q2 { 1 << 27 } else { 0 });
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn modular_add_subtract_clears_upper_lanes_and_preserves_alias_inputs() {
        for size in 0..4 {
            let w = 8u8 << size;
            for q in [false, true] {
                if size == 3 && !q { continue; }
                for sub in [false, true] {
                    for alias in [false, true] {
                        let mut state = State::default();
                        state.v[0] = u128::MAX;
                        state.v[1] = repeat(mask(w), w, 128);
                        state.v[2] = repeat(2, w, 128);
                        let n = if alias { 0 } else { 1 };
                        let encoded = word(if sub { 0x2e208400 } else { 0x0e208400 }, size, q, 0, n, 2);
                        let (out, _) = run(encoded, &state);
                        let expected = if sub { mask(w).wrapping_sub(2) } else { mask(w).wrapping_add(2) } & mask(w);
                        assert_eq!(out.v[0], repeat(expected, w, if q { 128 } else { 64 }), "{encoded:08x}");
                    }
                }
            }
        }
        for (encoded, expected) in [(0x5ee28420, 1u128), (0x7ee28420, u128::from(u64::MAX - 2))] {
            let mut state = State::default(); state.v[0] = u128::MAX; state.v[1] = u128::MAX; state.v[2] = 2;
            assert_eq!(run(encoded, &state).0.v[0], expected);
        }
    }
    #[test]
    fn halving_high_narrow_and_pairwise_add_long() {
        for size in 0..3 {
            let w = 8u8 << size;
            for unsigned in [false, true] {
                for a in [0, 1, mask(w), 1u64 << (w - 1)] {
                    for z in [0, 1, mask(w), 1u64 << (w - 1)] {
                        let mut s = State::default();
                        s.v[0] = repeat(a, w, 128);
                        s.v[1] = repeat(z, w, 128);
                        let x = if unsigned {
                            i128::from(a)
                        } else {
                            signed(a, w)
                        };
                        let y = if unsigned {
                            i128::from(z)
                        } else {
                            signed(z, w)
                        };
                        for (base, sub, round) in [
                            (0x0e200400, false, false),
                            (0x0e201400, false, true),
                            (0x0e202400, true, false),
                        ] {
                            let value = if sub { x - y } else { x + y } + if round { 1 } else { 0 };
                            let expected = ((value >> 1) as u64) & mask(w);
                            let (out, _) = run(
                                word(
                                    base | if unsigned { 1 << 29 } else { 0 },
                                    size,
                                    true,
                                    0,
                                    0,
                                    1,
                                ),
                                &s,
                            );
                            assert_eq!(out.v[0], repeat(expected, w, 128));
                        }
                    }
                }
                let mut s = State::default();
                s.v[0] = u128::MAX;
                s.v[1] = repeat(1, w, 128);
                for acc in [false, true] {
                    let pair = if unsigned {
                        2i128 * i128::from(mask(w))
                    } else {
                        -2
                    };
                    let mut expected = 0;
                    for i in 0..128 / (w * 2) {
                        let value = pair
                            + if acc {
                                i128::from(elem(s.v[1], i, w * 2))
                            } else {
                                0
                            };
                        expected |= u128::from((value as u64) & mask(w * 2)) << (i * w * 2);
                    }
                    let (out, _) = run(
                        word(
                            0x0e202800
                                | if unsigned { 1 << 29 } else { 0 }
                                | if acc { 1 << 14 } else { 0 },
                            size,
                            true,
                            1,
                            0,
                            0,
                        ),
                        &s,
                    );
                    assert_eq!(out.v[1], expected);
                }
            }
            for high in [false, true] {
                for sub in [false, true] {
                    for round in [false, true] {
                        let mut s = State::default();
                        s.v[0] = u128::MAX;
                        s.v[1] = repeat(mask(w * 2), w * 2, 128);
                        s.v[2] = repeat(1, w * 2, 128);
                        let v = if sub {
                            mask(w * 2).wrapping_sub(1)
                        } else {
                            mask(w * 2).wrapping_add(1)
                        };
                        let v =
                            v.wrapping_add(if round { 1u64 << (w - 1) } else { 0 }) & mask(w * 2);
                        let expected = repeat(v >> w, w, 64);
                        let expected = if high {
                            expected << 64 | u128::from(u64::MAX)
                        } else {
                            expected
                        };
                        let (out, _) = run(
                            word(
                                0x0e204000
                                    | if sub { 1 << 13 } else { 0 }
                                    | if round { 1 << 29 } else { 0 },
                                size,
                                high,
                                0,
                                1,
                                2,
                            ),
                            &s,
                        );
                        assert_eq!(out.v[0], expected);
                    }
                }
            }
        }
    }

    #[test]
    fn saturation_unary_and_immediate_left_preserve_qc_other_bits() {
        for size in 0..4 {
            let w = 8u8 << size;
            for a in [0, 1, mask(w), 1u64 << (w - 1), mask(w - 1)] {
                for scalar in [false, true] {
                    let mut s = State::default();
                    s.v[0] = repeat(a, w, 128);
                    s.fpsr = 0x9f;
                    for neg in [false, true] {
                        let x = signed(a, w);
                        let (v, qc) = sat(if neg { -x } else { x.abs() }, w, true);
                        let base = if scalar { 0x5e207800 } else { 0x0e207800 }
                            | if neg { 1 << 29 } else { 0 };
                        let (out, _) = run(word(base, size, true, 0, 0, 0), &s);
                        assert_eq!(out.v[0], repeat(v, w, if scalar { w } else { 128 }));
                        assert_eq!(out.fpsr, 0x9f | if qc { 1 << 27 } else { 0 });
                    }
                    for (base, sign, unsignedout) in [
                        (0x0f007400, true, false),
                        (0x2f007400, false, true),
                        (0x2f006400, true, true),
                    ] {
                        for shift in [0, 1, w - 1] {
                            let x = if sign { signed(a, w) } else { i128::from(a) };
                            let (v, qc) = sat(x << shift, w, !unsignedout);
                            let encoding = base
                                | ((u32::from(w) + u32::from(shift)) << 16)
                                | (1 << 30)
                                | if scalar { 1 << 28 } else { 0 };
                            let (out, _) = run(encoding, &s);
                            assert_eq!(
                                out.v[0],
                                repeat(v, w, if scalar { w } else { 128 }),
                                "w={w} a={a:x} shift={shift} base={base:x}"
                            );
                            assert_eq!(out.fpsr, 0x9f | if qc { 1 << 27 } else { 0 });
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn scalar_and_vector_element_copies_gpr_zr_and_ignored_index_bits() {
        let mut s = State::default();
        s.v[0] = u128::MAX;
        s.v[1] = u128::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 0x87, 8, 9, 10, 11, 12, 13, 14, 0x8f]);
        s.g[1] = 0xfedcba9876543210;
        for size in 0..4 {
            let w = 8u8 << size;
            for index in 0..128 / w {
                let imm = (1u32 << size) | (u32::from(index) << (size + 1));
                let value = elem(s.v[1], index, w);
                let (out, _) = run(0x5e000400 | (imm << 16) | (1 << 5), &s);
                assert_eq!(out.v[0], u128::from(value));
                for q in [false, true] {
                    if w == 64 && !q {
                        continue;
                    }
                    let (out, _) =
                        run(0x0e000400 | ((q as u32) << 30) | (imm << 16) | (1 << 5), &s);
                    assert_eq!(out.v[0], repeat(value, w, if q { 128 } else { 64 }));
                    let (out, _) =
                        run(0x0e000c00 | ((q as u32) << 30) | (imm << 16) | (1 << 5), &s);
                    assert_eq!(out.v[0], repeat(s.g[1], w, if q { 128 } else { 64 }));
                    let (out, _) = run(
                        0x0e000c00 | ((q as u32) << 30) | (imm << 16) | (31 << 5),
                        &s,
                    );
                    assert_eq!(out.v[0], 0);
                }
                let source_index = (128 / w) - index - 1;
                let srcfield = (u32::from(source_index) << size) | ((1 << size) - 1);
                let (out, _) = run(0x6e000400 | (imm << 16) | (srcfield << 11) | (1 << 5), &s);
                let shift = index * w;
                let expected = (s.v[0] & !(u128::from(mask(w)) << shift))
                    | (u128::from(elem(s.v[1], source_index, w)) << shift);
                assert_eq!(out.v[0], expected);
                let (out, _) = run(0x4e001c00 | (imm << 16) | (1 << 5), &s);
                let expected = (s.v[0] & !(u128::from(mask(w)) << shift))
                    | (u128::from(s.g[1] & mask(w)) << shift);
                assert_eq!(out.v[0], expected);
                let (out, _) = run(
                    0x0e003c00 | if w == 64 { 1 << 30 } else { 0 } | (imm << 16) | (1 << 5),
                    &s,
                );
                assert_eq!(out.g[0], value);
                for q in [false, true] {
                    let dest = if q { 64 } else { 32 };
                    if w >= dest {
                        continue;
                    }
                    let (out, _) =
                        run(0x0e002c00 | ((q as u32) << 30) | (imm << 16) | (1 << 5), &s);
                    assert_eq!(out.g[0], (signed(value, w) as u64) & mask(dest));
                }
            }
        }
    }
    #[test]
    fn exact_boundaries_reject_and_nearby_unowned_opcodes_remain_unclaimed() {
        for word in [
            0x0ee00c00,
            0x0ee01800,
            0x4ee14800,
            0x0f408400,
            0x0f400400,
            0x2e204800 | (3 << 22),
        ] {
            let r = a64(word, 0).unwrap_or_else(|| panic!("reserved group {word:08x} unclaimed"));
            assert!(matches!(r.support, Support::Unsupported(_)), "{word:08x}");
        }
        for word in [0xd503201f, 0x2e209c00, 0x2e20bc00] {
            assert!(a64(word, 0).is_none(), "{word:08x}");
        }
        assert!(a64(0x0f000400, 0).is_none());
    }
    #[test]
    fn upstream_physical_diagrams_are_admitted_and_executable() {
        for &(word, _, page) in super::INTEGER_CORPUS {
            let r = a64(word, 0).unwrap_or_else(|| panic!("{page}: {word:08x} unhandled"));
            assert_eq!(r.support, Support::Full, "{page}: {word:08x}");
            r.validate().unwrap();
            let _ = run(word, &State::default());
        }
    }
}
`
