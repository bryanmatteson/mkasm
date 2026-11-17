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
	"strconv"
	"strings"
	"testing"
)

//go:embed arm32_crypto.rs
var arm32CryptoSource string

func TestRustArm32CryptoAndBytePermutations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"runtime.rs": RustRuntime, "arm32_crypto.rs": arm32CryptoSource,
		"crypto_tests.rs": arm32CryptoBehaviorTests + arm32CryptoHashTests + arm32CryptoCorpus(t),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "crypto_tests.rs", "-Dwarnings", "-o", "crypto-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A32 crypto/byte recipes: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "crypto-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute A32 crypto/byte recipes: %v\n%s", err, out)
	}
}

// Derive valid physical words from primary upstream diagrams, separately from
// the recipe's dispatch masks. Portable known-vector cases also run without XML.
func arm32CryptoCorpus(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(home, "Documents/Developer/go-mkasm/ISA_AArch32_xml_A_profile-2026-06.tar.gz"))
	if os.IsNotExist(err) {
		t.Log("optional Arm corpus absent; running portable crypto vectors")
		return "const CRYPTO_CORPUS:&[(bool,u32,&str)]=&[];\n"
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
	names := strings.Fields("aese aesd aesmc aesimc sha1c sha1p sha1m sha1h sha1su0 sha1su1 sha256h sha256h2 sha256su0 sha256su1 vmul_i vmull_i vext vtbl vcnt vclz vcls")
	wanted := map[string]bool{}
	seen := map[string]bool{}
	for _, name := range names {
		wanted[name+".xml"] = true
	}
	type cell struct {
		Text string `xml:",chardata"`
	}
	type box struct {
		Name  string `xml:"name,attr"`
		Hi    int    `xml:"hibit,attr"`
		Width int    `xml:"width,attr"`
		Cells []cell `xml:"c"`
	}
	type diagram struct {
		Form  string `xml:"form,attr"`
		Boxes []box  `xml:"box"`
	}
	var out strings.Builder
	out.WriteString("const CRYPTO_CORPUS:&[(bool,u32,&str)]=&[\n")
	reader := tar.NewReader(compressed)
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
		if !strings.HasPrefix(header.Name, "ISA_AArch32_xml_A_profile-2026-06/") || !wanted[name] {
			continue
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		decoder := xml.NewDecoder(bytes.NewReader(body))
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != "regdiagram" {
				continue
			}
			var d diagram
			if err := decoder.DecodeElement(&d, &start); err != nil {
				t.Fatal(err)
			}
			seen[name] = true
			for variant := 0; variant < 4; variant++ {
				var word uint32
				for _, b := range d.Boxes {
					width := b.Width
					if width == 0 {
						width = 1
					}
					var fixed strings.Builder
					for _, c := range b.Cells {
						text := strings.Trim(strings.TrimSpace(c.Text), "()")
						if text == "0" || text == "1" {
							fixed.WriteString(text)
						}
					}
					var value uint64
					if fixed.Len() == width {
						value, err = strconv.ParseUint(fixed.String(), 2, 32)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						switch b.Name {
						case "Vd":
							value = uint64([]int{0, 14, 0, 14}[variant])
						case "Vn":
							value = uint64([]int{2, 12, 0, 12}[variant])
						case "Vm":
							value = uint64([]int{4, 10, 0, 10}[variant])
						case "D", "N", "M":
							value = uint64(variant & 1)
						case "Q":
							value = 1
						case "size":
							if strings.HasPrefix(name, "sha") {
								value = 2
							} else if name == "vmull_i.xml" {
								value = uint64((variant & 1) * 2)
							} else if name == "vclz.xml" || name == "vcls.xml" {
								value = uint64(variant % 3)
							}
						case "op":
							if name == "vmul_i.xml" || name == "vmull_i.xml" {
								value = 1
							} else {
								value = uint64(variant & 1)
							}
						case "imm4":
							value = uint64(variant * 5)
						case "len":
							value = uint64(variant)
						}
					}
					word |= uint32(value) << uint(b.Hi-width+1)
				}
				fmt.Fprintf(&out, "(%t,0x%08x,%q),\n", d.Form == "16x2", word, name)
				count++
			}
		}
	}
	out.WriteString("];\n")
	if len(seen) != len(wanted) {
		t.Fatalf("crypto corpus represented %d/%d requested pages", len(seen), len(wanted))
	}
	t.Logf("derived %d A32/Thumb crypto/byte words from %d primary pages", count, len(seen))
	return out.String()
}

const arm32CryptoBehaviorTests = `
#[allow(dead_code)]
mod runtime;
use runtime::*;
mod arm32_crypto;
use std::cell::Cell;
#[derive(Clone, Default)]
struct State {
    v: [u128; 16],
    it: u8,
    pipeline: u8,
    reads: Cell<usize>,
}
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        self.reads.set(self.reads.get() + 1);
        match r.bank {
            "a32.vector64" => {
                assert!(r.index < 32);
                Value::known(
                    64,
                    (self.v[usize::from(r.index / 2)] >> ((r.index % 2) * 64)) as u64,
                )
            }
            "a32.itstate" => {
                assert_eq!(r.index, 0);
                Value::known(8, u64::from(self.it))
            }
            "pipeline" => Value::known(8, u64::from(self.pipeline)),
            _ => panic!("unexpected crypto state {r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!("crypto read memory")
    }
}
fn base(active: bool, thumb: bool) -> Recipe {
    let mut r = Recipe::new(0x1004, 32);
    r.guard = Expr::constant(1, u64::from(active));
    if thumb {
        r.write_always(
            register("pipeline", 0, 8, 8),
            WritePolicy::ZeroUpper,
            Expr::constant(8, 0x18),
        );
    }
    r
}
fn thumbword(w: u32) -> u32 {
    0xef000000 | (w & 0x00ffffff) | ((w & 0x01000000) << 4)
}
fn recipe_physical(word: u32, thumb: bool, active: bool) -> Recipe {
    let original = base(active, thumb);
    let r = if thumb {
        arm32_crypto::thumb(word, 4, original.clone())
    } else {
        arm32_crypto::a32(word, original.clone())
    }
    .unwrap_or_else(|| panic!("unhandled {word:08x}"));
    assert_eq!(r.always_writes, original.always_writes);
    assert_eq!(r.flow, original.flow);
    r
}
fn run_mode(word: u32, thumb: bool, s: &State) -> State {
    let physical = if thumb { thumbword(word) } else { word };
    let r = recipe_physical(physical, thumb, true);
    assert_eq!(r.support, Support::Full, "{physical:08x}");
    let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{physical:08x}: {e:?}"));
    assert!(t.memory.is_empty());
    assert!(t.wide_memory.is_empty());
    assert!(t.atomics.is_empty());
    assert!(t.events.is_empty());
    assert_eq!(t.next_pc, Value::known(32, 0x1004));
    assert_eq!(t.trap, None);
    let mut out = s.clone();
    for w in t.registers {
        assert!(w.value.is_known());
        match w.register.bank {
            "a32.vector64" => {
                let n = usize::from(w.register.index / 2);
                let shift = (w.register.index % 2) * 64;
                out.v[n] = (out.v[n] & !(u128::from(u64::MAX) << shift))
                    | (u128::from(w.value.bits) << shift);
            }
            "pipeline" => out.pipeline = w.value.bits as u8,
            _ => panic!("crypto wrote unrelated register"),
        }
    }
    out
}
fn words(v: [u32; 4]) -> u128 {
    v.into_iter()
        .enumerate()
        .fold(0, |a, (i, x)| a | (u128::from(x) << (i * 32)))
}
fn unpack(v: u128) -> [u32; 4] {
    core::array::from_fn(|i| (v >> (i * 32)) as u32)
}
fn hex(s: &str) -> u128 {
    u128::from_le_bytes(core::array::from_fn(|i| {
        u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()
    }))
}
fn encoding(base: u32, d: u32, n: u32, m: u32) -> u32 {
    vecword(base, 2 * d, 2 * n, 2 * m, false, 0)
}
fn vecword(base: u32, d: u32, n: u32, m: u32, q: bool, size: u32) -> u32 {
    base | ((d & 15) << 12)
        | ((d & 16) << 18)
        | ((n & 15) << 16)
        | ((n & 16) << 3)
        | (m & 15)
        | ((m & 16) << 1)
        | (u32::from(q) << 6)
        | (size << 20)
}
fn seeded(seed: u64) -> State {
    let mut s = State::default();
    let mut x = seed;
    for i in 0..32 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.v[i / 2] |= u128::from(x) << ((i % 2) * 64);
    }
    s
}
fn getd(s: &State, n: u32) -> u64 {
    (s.v[(n / 2) as usize] >> ((n % 2) * 64)) as u64
}
fn setd(s: &mut State, n: u32, v: u64) {
    let shift = (n % 2) * 64;
    s.v[(n / 2) as usize] =
        (s.v[(n / 2) as usize] & !(u128::from(u64::MAX) << shift)) | (u128::from(v) << shift);
}
fn poly(a: u64, z: u64, w: u8) -> u128 {
    (0..w).fold(0, |p, i| {
        if a & (1 << i) != 0 {
            p ^ (u128::from(z) << i)
        } else {
            p
        }
    })
}
#[test]
fn fips_aes_round_mix_and_all_sbox_values() {
    for thumb in [false, true] {
        let mut s = State::default();
        s.v[0] = hex("00102030405060708090a0b0c0d0e0f0");
        let a = run_mode(0xf3b00302, thumb, &s);
        assert_eq!(a.v[0], hex("6353e08c0960e104cd70b751bacad0e7"));
        let mut t = a.clone();
        t.v[1] = a.v[0];
        let mixed = run_mode(0xf3b00382, thumb, &t);
        assert_eq!(mixed.v[0], hex("5f72641557f5bc92f7be3b291db9f91a"));
        t.v[1] = mixed.v[0];
        assert_eq!(run_mode(0xf3b003c2, thumb, &t).v[0], a.v[0]);
        let mut inverse = a.clone();
        inverse.v[1] = 0;
        assert_eq!(run_mode(0xf3b00342, thumb, &inverse).v[0], s.v[0]);
        assert_eq!(
            run_mode(0xf3b00300, thumb, &s).v[0],
            u128::from_le_bytes([0x63; 16])
        );
        fn multiply(mut a: u8, mut b: u8) -> u8 {
            let mut result = 0;
            for _ in 0..8 {
                if b & 1 != 0 {
                    result ^= a
                }
                a = (a << 1) ^ if a & 128 != 0 { 0x1b } else { 0 };
                b >>= 1;
            }
            result
        }
        fn sub(x: u8) -> u8 {
            let mut p = 1u8;
            let mut a = x;
            let mut exp = 254;
            while exp != 0 {
                if exp & 1 != 0 {
                    p = multiply(p, a)
                }
                a = multiply(a, a);
                exp >>= 1;
            }
            p ^ p.rotate_left(1) ^ p.rotate_left(2) ^ p.rotate_left(3) ^ p.rotate_left(4) ^ 0x63
        }
        for value in 0..=255u8 {
            s.v[0] = u128::from_le_bytes([value; 16]);
            s.v[1] = 0;
            let out = run_mode(0xf3b00302, thumb, &s);
            assert_eq!(out.v[0], u128::from_le_bytes([sub(value); 16]));
            assert_eq!(run_mode(0xf3b00342, thumb, &out).v[0], s.v[0]);
        }
    }
}
#[test]
fn polynomial_products_lane_widths_aliases_and_high_registers() {
    for thumb in [false, true] {
        for sample in 0..5 {
            let s = seeded(0x123456789abcdef0 + sample);
            for (dd, dn, dm) in [(0, 1, 2), (2, 2, 2), (30, 31, 30)] {
                for width in [8u8, 64] {
                    let mut expected = 0u128;
                    for i in 0..64 / width {
                        let a = (getd(&s, dn) >> (i * width)) & mask(width);
                        let z = (getd(&s, dm) >> (i * width)) & mask(width);
                        expected |= poly(a, z, width) << (i * width * 2);
                    }
                    let word = vecword(
                        0xf2800e00,
                        dd,
                        dn,
                        dm,
                        false,
                        if width == 64 { 2 } else { 0 },
                    );
                    let out = run_mode(word, thumb, &s);
                    assert_eq!(out.v[(dd / 2) as usize], expected, "{word:08x}");
                    for i in 0..16 {
                        if i != (dd / 2) as usize {
                            assert_eq!(out.v[i], s.v[i]);
                        }
                    }
                }
            }
            for q in [false, true] {
                for (dd, dn, dm) in [(0, 2, 4), (2, 2, 2), (30, 28, 30), (31, 31, 29)] {
                    if q && (dd & 1 != 0 || dn & 1 != 0 || dm & 1 != 0) {
                        continue;
                    }
                    let count = if q { 2 } else { 1 };
                    let mut expected = s.clone();
                    for chunk in 0..count {
                        let mut v = 0;
                        for lane in 0..8 {
                            let a = (getd(&s, dn + chunk) >> (lane * 8)) & 255;
                            let z = (getd(&s, dm + chunk) >> (lane * 8)) & 255;
                            v |= (poly(a, z, 8) as u64 & 255) << (lane * 8);
                        }
                        setd(&mut expected, dd + chunk, v);
                    }
                    let word = vecword(0xf3000910, dd, dn, dm, q, 0);
                    assert_eq!(run_mode(word, thumb, &s).v, expected.v);
                }
            }
        }
    }
}
#[test]
fn byte_extract_and_lookup_preserve_original_aliases() {
    for thumb in [false, true] {
        let s = seeded(0x1111222233334444);
        for q in [false, true] {
            let count = if q { 16 } else { 8 };
            for offset in 0..count {
                for (dd, dn, dm) in [(0, 2, 4), (2, 2, 2), (30, 28, 30), (1, 0, 1)] {
                    if q && (dd & 1 != 0 || dn & 1 != 0 || dm & 1 != 0) {
                        continue;
                    }
                    let mut source = vec![];
                    for n in [dn, dm] {
                        for i in 0..count {
                            source.push((getd(&s, n + i / 8) >> ((i % 8) * 8)) as u8);
                        }
                    }
                    let mut expected = s.clone();
                    for chunk in 0..count / 8 {
                        let v = (0..8).fold(0, |a, i| {
                            a | (u64::from(source[(offset + chunk * 8 + i) as usize]) << (i * 8))
                        });
                        setd(&mut expected, dd + chunk, v);
                    }
                    let word = vecword(0xf2b00000, dd, dn, dm, q, 0) | (offset << 8);
                    assert_eq!(run_mode(word, thumb, &s).v, expected.v);
                }
            }
        }
        for length in 1..=4 {
            for extending in [false, true] {
                for (dd, dn, dm) in [(0, 1, 5), (3, 1, 3), (31, 28, 31)] {
                    let mut s = s.clone();
                    setd(
                        &mut s,
                        dm,
                        u64::from_le_bytes([0, 7, 8, 15, 23, 31, 32, 255]),
                    );
                    let indices = getd(&s, dm).to_le_bytes();
                    let old = getd(&s, dd).to_le_bytes();
                    let mut expected = [0; 8];
                    for i in 0..8 {
                        let idx = u32::from(indices[i]);
                        expected[i] = if idx < 8 * length {
                            (getd(&s, dn + idx / 8) >> ((idx % 8) * 8)) as u8
                        } else if extending {
                            old[i]
                        } else {
                            0
                        };
                    }
                    let word = vecword(0xf3b00800, dd, dn, dm, extending, 0) | ((length - 1) << 8);
                    let mut expected_state = s.clone();
                    setd(&mut expected_state, dd, u64::from_le_bytes(expected));
                    assert_eq!(run_mode(word, thumb, &s).v, expected_state.v);
                }
            }
        }
    }
}
#[test]
fn lane_counts_match_integer_oracle_and_preserve_other_d() {
    for thumb in [false, true] {
        for size in 0..3 {
            let width = 8u8 << size;
            for q in [false, true] {
                for sample in 0..6 {
                    let mut s = seeded(sample + 1);
                    if sample == 0 {
                        s.v[1] = 0
                    } else if sample == 1 {
                        s.v[1] = u128::MAX
                    }
                    for (base, op) in [(0xf3b00500, 0), (0xf3b00480, 1), (0xf3b00400, 2)] {
                        if op == 0 && size != 0 {
                            continue;
                        }
                        let mut expected = s.clone();
                        for chunk in 0..if q { 2 } else { 1 } {
                            let source = getd(&s, 2 + chunk);
                            let mut output = 0;
                            for i in 0..64 / width {
                                let x = (source >> (i * width)) & mask(width);
                                let value = match op {
                                    0 => x.count_ones() as u64,
                                    1 => u64::from(x.leading_zeros()) - u64::from(64 - width),
                                    _ => {
                                        let normalized = if x & (1 << (width - 1)) != 0 {
                                            (!x) & mask(width)
                                        } else {
                                            x
                                        };
                                        u64::from(normalized.leading_zeros())
                                            - u64::from(64 - width)
                                            - 1
                                    }
                                };
                                output |= value << (i * width);
                            }
                            setd(&mut expected, chunk, output);
                        }
                        let word = vecword(base, 0, 0, 2, q, 0) | ((size as u32) << 18);
                        assert_eq!(run_mode(word, thumb, &s).v, expected.v);
                    }
                }
            }
        }
    }
}
#[test]
fn every_crypto_family_uses_incoming_d_q_aliases() {
    for thumb in [false, true] {
        let s = seeded(0x0123456789abcdef);
        for (base, three) in [
            (0xf3b00300, false),
            (0xf3b00340, false),
            (0xf3b00380, false),
            (0xf3b003c0, false),
            (0xf2000c40, true),
            (0xf2100c40, true),
            (0xf2200c40, true),
            (0xf2300c40, true),
            (0xf3b902c0, false),
            (0xf3ba0380, false),
            (0xf3000c40, true),
            (0xf3100c40, true),
            (0xf3ba03c0, false),
            (0xf3200c40, true),
        ] {
            for (dd, dn, dm) in [(0, 0, 0), (0, 2, 0), (30, 30, 28), (28, 30, 28)] {
                let mut isolated = s.clone();
                isolated.v[12] = s.v[(dd / 2) as usize];
                isolated.v[13] = s.v[(dn / 2) as usize];
                isolated.v[14] = s.v[(dm / 2) as usize];
                let encode = |d, n, m| vecword(base, d, if three { n } else { 0 }, m, false, 0);
                let reference = run_mode(encode(24, 26, 28), thumb, &isolated);
                let word = encode(dd, dn, dm);
                let actual = run_mode(word, thumb, &s);
                assert_eq!(actual.v[(dd / 2) as usize], reference.v[12], "{word:08x}");
                for q in 0..16 {
                    if q != (dd / 2) as usize {
                        assert_eq!(actual.v[q], s.v[q]);
                    }
                }
            }
        }
    }
}
#[test]
fn predication_it_rejection_constraints_and_no_false_full() {
    let crypto = [
        0xf3b00302, 0xf3b00342, 0xf3b00382, 0xf3b003c2, 0xf2020c44, 0xf2120c44, 0xf2220c44,
        0xf2320c44, 0xf3b902c2, 0xf3ba0382, 0xf3020c44, 0xf3120c44, 0xf3ba03c2, 0xf3220c44,
        0xf2a10e02,
    ];
    let other = [
        0xf3020954, 0xf2810e02, 0xf2b20f44, 0xf3b10b05, 0xf3b10b45, 0xf3b00542, 0xf3b404c2,
        0xf3b80442,
    ];
    for word in crypto.into_iter().chain(other) {
        for thumb in [false, true] {
            let s = State::default();
            let physical = if thumb { thumbword(word) } else { word };
            let r = recipe_physical(physical, thumb, false);
            let t = evaluate(&r, &s).unwrap();
            assert_eq!(s.reads.get(), 0);
            assert!(t.registers.iter().all(|w| w.register.bank == "pipeline"));
            assert_eq!(t.registers.len(), usize::from(thumb));
        }
        let mut s = State::default();
        s.it = 8;
        let physical = thumbword(word);
        let r = recipe_physical(physical, true, true);
        if crypto.contains(&word) {
            assert_eq!(evaluate(&r, &s), Err(EvalError::UnsupportedContext));
        } else {
            assert_eq!(r.support, Support::Full);
            assert!(evaluate(&r, &s).is_ok());
        }
    }
    for word in [
        0xf3b01302, 0xf3b00303, 0xf3b40302, 0xf2020c04, 0xf2030c44, 0xf3120954, 0xf2910e02,
        0xf3810e02, 0xf2811e02, 0xf2b20804, 0xf3bf0b80, 0xf3bc0542,
    ] {
        for thumb in [false, true] {
            let physical = if thumb { thumbword(word) } else { word };
            let r = recipe_physical(physical, thumb, true);
            assert!(
                matches!(r.support, Support::Unsupported(_)),
                "{physical:08x}"
            );
            assert!(r.effects.is_empty());
            assert!(r.temporaries.is_empty());
        }
    }
    assert!(arm32_crypto::a32(0xe1a00000, base(true, false)).is_none());
    assert!(arm32_crypto::thumb(0xbf00, 2, base(true, true)).is_none());
}
#[test]
fn scalar_sha_inputs_do_not_require_unread_q_high_halves() {
    for thumb in [false, true] {
        for (word, reads) in [
            (0xf3b902c2, 1),
            (0xf2020c44, 5),
            (0xf2320c44, 5),
            (0xf3ba03c2, 3),
        ] {
            let s = State::default();
            let _ = run_mode(word, thumb, &s);
            assert_eq!(s.reads.get(), reads + usize::from(thumb), "{word:08x}");
        }
    }
}
#[test]
fn crypto_context_is_checked_not_undefined_and_inactive_context_is_lazy() {
    struct UnknownIt(State);
    impl Machine for UnknownIt {
        fn read_register(&self, r: Register) -> Value {
            if r.bank == "a32.itstate" {
                Value::unknown(8)
            } else {
                self.0.read_register(r)
            }
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("crypto read memory")
        }
    }
    let s = UnknownIt(State::default());
    let word = thumbword(0xf3b00302);
    assert_eq!(
        evaluate(&recipe_physical(word, true, true), &s),
        Err(EvalError::UnknownCondition)
    );
    assert!(evaluate(&recipe_physical(word, true, false), &s).is_ok());
    let mut known = State::default();
    known.it = 0xf0;
    assert_eq!(
        run_mode(0xf3b00302, true, &known).v[0],
        u128::from_le_bytes([0x63; 16])
    );
}
#[test]
fn primary_corpus_words_execute_and_preserve_base_pipeline() {
    for &(thumb, word, page) in CRYPTO_CORPUS {
        let r = recipe_physical(word, thumb, true);
        assert_eq!(r.support, Support::Full, "{page}: {word:08x}");
        r.validate().unwrap();
        let s = seeded(0x123456789abcdef0);
        let t = evaluate(&r, &s).unwrap_or_else(|e| panic!("{page}: {word:08x}: {e:?}"));
        assert_eq!(t.next_pc, Value::known(32, 0x1004));
        assert!(t.events.is_empty());
    }
}
`

const arm32CryptoHashTests = `
#[test]
fn sha1_abc_complete_schedule_and_compression() {
    for thumb in [false, true] {
        let run = |word, s: &State| run_mode(word, thumb, s);
        let mut w = [0u32; 80];
        w[0] = 0x61626380;
        w[15] = 24;
        for j in 16..80 {
            w[j] = (w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]).rotate_left(1);
        }
        let mut schedule = State::default();
        for j in (16..80).step_by(4) {
            schedule.v[0] = words(w[j - 16..j - 12].try_into().unwrap());
            schedule.v[1] = words(w[j - 12..j - 8].try_into().unwrap());
            schedule.v[2] = words(w[j - 8..j - 4].try_into().unwrap());
            schedule = run(encoding(0xf2300c40, 0, 1, 2), &schedule);
            schedule.v[1] = words(w[j - 4..j].try_into().unwrap());
            schedule = run(0xf3ba0382, &schedule);
            assert_eq!(unpack(schedule.v[0]), w[j..j + 4]);
        }
        let initial = [
            0x67452301u32,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0,
        ];
        let mut s = State::default();
        s.v[0] = words(initial[..4].try_into().unwrap());
        s.v[1] = u128::from(initial[4]);
        for j in (0..80).step_by(4) {
            let (k, op) = if j < 20 {
                (0x5a827999, 0xf2000c40)
            } else if j < 40 {
                (0x6ed9eba1, 0xf2100c40)
            } else if j < 60 {
                (0x8f1bbcdc, 0xf2200c40)
            } else {
                (0xca62c1d6, 0xf2100c40)
            };
            s.v[2] = words(core::array::from_fn(|i| w[j + i].wrapping_add(k)));
            s = run(0xf3b962c0, &s);
            s = run(encoding(op, 0, 1, 2), &s);
            s.v[1] = s.v[3];
        }
        let out = unpack(s.v[0]);
        let hash = [
            out[0].wrapping_add(initial[0]),
            out[1].wrapping_add(initial[1]),
            out[2].wrapping_add(initial[2]),
            out[3].wrapping_add(initial[3]),
            (s.v[1] as u32).wrapping_add(initial[4]),
        ];
        assert_eq!(
            hash,
            [0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d]
        );
    }
}
#[test]
fn sha256_abc_complete_schedule_and_compression() {
    for thumb in [false, true] {
        let run = |word, s: &State| run_mode(word, thumb, s);
        let mut w = [0u32; 64];
        w[0] = 0x61626380;
        w[15] = 24;
        for j in 16..64 {
            let s0 = w[j - 15].rotate_right(7) ^ w[j - 15].rotate_right(18) ^ (w[j - 15] >> 3);
            let s1 = w[j - 2].rotate_right(17) ^ w[j - 2].rotate_right(19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16]
                .wrapping_add(s0)
                .wrapping_add(w[j - 7])
                .wrapping_add(s1);
        }
        let mut schedule = State::default();
        for j in (16..64).step_by(4) {
            schedule.v[0] = words(w[j - 16..j - 12].try_into().unwrap());
            schedule.v[1] = words(w[j - 12..j - 8].try_into().unwrap());
            schedule = run(0xf3ba03c2, &schedule);
            schedule.v[1] = words(w[j - 8..j - 4].try_into().unwrap());
            schedule.v[2] = words(w[j - 4..j].try_into().unwrap());
            schedule = run(encoding(0xf3200c40, 0, 1, 2), &schedule);
            assert_eq!(unpack(schedule.v[0]), w[j..j + 4]);
        }
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let initial = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut s = State::default();
        s.v[0] = words(initial[..4].try_into().unwrap());
        s.v[1] = words(initial[4..].try_into().unwrap());
        for j in (0..64).step_by(4) {
            s.v[2] = words(core::array::from_fn(|i| w[j + i].wrapping_add(K[j + i])));
            s.v[3] = s.v[0];
            s = run(encoding(0xf3000c40, 0, 1, 2), &s);
            s = run(encoding(0xf3100c40, 1, 3, 2), &s);
        }
        let mut hash = [0; 8];
        for i in 0..8 {
            hash[i] = unpack(s.v[i / 4])[i % 4].wrapping_add(initial[i]);
        }
        assert_eq!(
            hash,
            [
                0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
                0xf20015ad
            ]
        );
    }
}
`
