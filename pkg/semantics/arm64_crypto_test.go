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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

//go:embed arm64_crypto.rs
var a64CryptoModuleSource string

func TestRustA64CryptoSIMD(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_crypto") {
		source += "\npub mod arm64_crypto {\n" + a64CryptoModuleSource + "\n}\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "semantics.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	corpus := a64CryptoCorpusCases(t)
	consumer := a64CryptoBehaviorTests + corpus + a64CryptoHardwareCases(t, corpus)
	if err := os.WriteFile(filepath.Join(dir, "crypto.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "crypto.rs", "-Dwarnings", "-o", filepath.Join(dir, "a64-crypto-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile A64 crypto SIMD: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "a64-crypto-tests"), "a64_crypto_behavior::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute A64 crypto SIMD: %v\n%s", err, out)
	}
}

// Derive physical words from upstream class diagrams, independently of the
// helper's masks. Ordinary tests retain portable, explicitly selected words.
func a64CryptoCorpusCases(t *testing.T) string {
	t.Helper()
	var result strings.Builder
	result.WriteString("\nconst CRYPTO_CORPUS:&[(u32,bool,&str)]=&[\n")
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
		case "aese", "aesd", "aesmc", "aesimc", "sha1c", "sha1m", "sha1p", "sha1h", "sha1su0", "sha1su1", "sha256h", "sha256h2", "sha256su0", "sha256su1", "sha512h", "sha512h2", "sha512su0", "sha512su1", "sm3ss1", "sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b", "sm3partw1", "sm3partw2", "sm4e", "sm4ekey", "pmul", "pmull", "eor3", "bcax", "rax1", "xar", "smmla", "ummla", "usmmla", "usdot", "sudot":
		case "bfdot", "bfmmla":
			supported = false
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
							v = 0
							if family == "pmull" && flags&1 != 0 {
								v = 3
							}
						case "Q":
							v = 1
						case "Rn":
							v = 1
						case "Ra":
							v = 3
						case "Rm":
							v = 2
						case "Rd":
							v = uint32(variant)
						case "imm2", "imm6":
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
	t.Logf("derived %d A64 crypto SIMD words from %d upstream pages", count, len(seen))
	return result.String()
}

// Compare generated recipes with real instruction executions when the host
// advertises the exact extension. Other hosts retain the portable vectors.
func a64CryptoHardwareCases(t *testing.T, corpus string) string {
	t.Helper()
	empty := "\nconst HARDWARE_CASES:&[(u32,u64,u128)]=&[];\n"
	if runtime.GOARCH != "arm64" || runtime.GOOS != "darwin" {
		return empty
	}
	if _, err := exec.LookPath("clang"); err != nil {
		return empty
	}
	supported := map[string]bool{}
	for _, f := range []string{"AES", "SHA1", "SHA256", "SHA512", "SHA3", "PMULL", "I8MM"} {
		out, _ := exec.Command("sysctl", "-n", "hw.optional.arm.FEAT_"+f).Output()
		supported[f] = strings.TrimSpace(string(out)) == "1"
	}
	type item struct {
		word uint32
		page string
	}
	var items []item
	for _, m := range regexp.MustCompile(`\(0x([0-9a-f]+),true,"([^"]+)"\)`).FindAllStringSubmatch(corpus, -1) {
		word, _ := strconv.ParseUint(m[1], 16, 32)
		items = append(items, item{uint32(word), m[2]})
	}
	if len(items) == 0 {
		for _, word := range []uint32{0x4e284820, 0x4e285820, 0x4e286820, 0x4e287820, 0x5e020020, 0x5e021020, 0x5e022020, 0x5e280820, 0x5e023020, 0x5e281820, 0x5e024020, 0x5e025020, 0x5e282820, 0x5e026020, 0xce628020, 0xce628420, 0xcec08020, 0xce628820, 0xce020c20, 0xce220c20, 0xce628c20, 0xce820c20, 0x4ee2e020, 0x6e229c20, 0x4e82a420, 0x6e82a420, 0x4e82ac20, 0x0e829c20} {
			items = append(items, item{word, "fallback"})
		}
	}
	var admitted []item
	for _, x := range items {
		page := x.page
		feature := ""
		switch {
		case strings.HasPrefix(page, "aes"):
			feature = "AES"
		case strings.HasPrefix(page, "sha1"):
			feature = "SHA1"
		case strings.HasPrefix(page, "sha256"):
			feature = "SHA256"
		case strings.HasPrefix(page, "sha512"):
			feature = "SHA512"
		case strings.HasPrefix(page, "pmul"):
			feature = "PMULL"
		case strings.HasPrefix(page, "smmla") || strings.HasPrefix(page, "ummla") || strings.HasPrefix(page, "usmmla") || strings.HasPrefix(page, "usdot") || strings.HasPrefix(page, "sudot"):
			feature = "I8MM"
		case strings.HasPrefix(page, "eor3") || strings.HasPrefix(page, "bcax") || strings.HasPrefix(page, "rax1") || strings.HasPrefix(page, "xar"):
			feature = "SHA3"
		case page == "fallback":
			if supported["AES"] && supported["SHA1"] && supported["SHA256"] && supported["SHA512"] && supported["SHA3"] && supported["PMULL"] && supported["I8MM"] {
				feature = "AES"
			}
		}
		if feature != "" && supported[feature] {
			admitted = append(admitted, x)
		}
	}
	if len(admitted) == 0 {
		return empty
	}
	dir := t.TempDir()
	var source strings.Builder
	source.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for i, x := range admitted {
		fmt.Fprintf(&source, "static void op%d(uint64_t*out,const uint64_t*in){__asm__ volatile(\"", i)
		for r := 0; r < 32; r += 2 {
			fmt.Fprintf(&source, "ldp q%d,q%d,[%%[in],#%d]\\n", r, r+1, r*16)
		}
		fmt.Fprintf(&source, ".inst 0x%08x\\nstr q%d,[%%[out]]\"::[in]\"r\"(in),[out]\"r\"(out):", x.word, x.word&31)
		for r := 0; r < 32; r++ {
			if r != 0 {
				source.WriteByte(',')
			}
			fmt.Fprintf(&source, "\"v%d\"", r)
		}
		source.WriteString(",\"memory\");}\n")
	}
	source.WriteString("int main(void){uint64_t in[64],out[2];\n")
	for i, x := range admitted {
		for sample := 0; sample < 4; sample++ {
			seed := uint64(0x123456789abcdef0) + uint64(sample)*0x102030405060708
			fmt.Fprintf(&source, "{uint64_t s=0x%016xULL;for(int j=0;j<64;j++){s^=s<<13;s^=s>>7;s^=s<<17;in[j]=s;}op%d(out,in);printf(\"%08x %016x %%016llx %%016llx\\n\",(unsigned long long)out[0],(unsigned long long)out[1]);}\n", seed, i, x.word, seed)
		}
	}
	source.WriteString("return 0;}\n")
	path := filepath.Join(dir, "hardware.c")
	if err := os.WriteFile(path, []byte(source.String()), 0644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "hardware")
	cmd := exec.Command("clang", "-O1", path, "-o", binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile native A64 instruction oracle: %v\n%s", err, out)
	}
	out, err := exec.Command(binary).CombinedOutput()
	if err != nil {
		t.Fatalf("execute admitted A64 instruction oracle: %v\n%s", err, out)
	}
	var result strings.Builder
	result.WriteString("\nconst HARDWARE_CASES:&[(u32,u64,u128)]=&[\n")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			t.Fatalf("bad hardware result: %q", line)
		}
		fmt.Fprintf(&result, "(0x%s,0x%s,0x%s%s),\n", fields[0], fields[1], fields[3], fields[2])
	}
	result.WriteString("];\n")
	t.Logf("compared %d native instruction/state pairs from %d encodings", len(lines), len(admitted))
	return result.String()
}

const a64CryptoBehaviorTests = `
#[allow(dead_code)]
mod semantics;
mod a64_crypto_behavior {
    use super::semantics::arm64_crypto::a64;
    use super::semantics::*;
    #[derive(Clone, Default)]
    struct State {
        v: [u128; 32],
    }
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            assert_eq!(r.bank, "a64.vector64");
            assert!(r.index % 32 < 2);
            Value::known(
                64,
                (self.v[usize::from(r.index / 32)] >> (r.index % 32 * 64)) as u64,
            )
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("crypto memory access")
        }
    }
    fn run(word: u32, s: &State) -> State {
        let r = a64(word, 0x1000).unwrap_or_else(|| panic!("unhandled {word:08x}"));
        assert_eq!(r.support, Support::Full, "{word:08x}");
        let t = evaluate(&r, s).unwrap_or_else(|e| panic!("{word:08x}: {e:?}"));
        assert!(t.memory.is_empty());
        assert!(t.atomics.is_empty());
        assert!(t.events.is_empty());
        assert_eq!(t.next_pc, Value::known(64, 0x1004));
        let chunks: std::collections::BTreeSet<_> = t.registers.iter().map(|w| w.register.index).collect();
        assert_eq!(chunks.len(), 2);
        let mut out = s.clone();
        for x in t.registers {
            assert_eq!(x.register.bank, "a64.vector64");
            let n = usize::from(x.register.index / 32);
            assert_eq!(n, (word & 31) as usize);
            let shift = (x.register.index % 32) * 64;
            out.v[n] =
                (out.v[n] & !(u128::from(u64::MAX) << shift)) | (u128::from(x.value.bits) << shift);
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
        let bytes: Vec<_> = (0..16)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        u128::from_le_bytes(bytes.try_into().unwrap())
    }
    fn encoding(base: u32, d: u32, n: u32, m: u32) -> u32 {
        base | (m << 16) | (n << 5) | d
    }
    fn seeded(seed: u64) -> State {
        let mut s = State::default();
        let mut x = seed;
        for i in 0..64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.v[i / 2] |= u128::from(x) << ((i % 2) * 64);
        }
        s
    }
    #[test]
    fn native_hardware_is_an_independent_bit_exact_oracle() {
        for &(word, seed, expected) in super::HARDWARE_CASES {
            let s = seeded(seed);
            let out = run(word, &s);
            assert_eq!(
                out.v[(word & 31) as usize],
                expected,
                "word={word:08x} seed={seed:x}"
            );
        }
    }
    #[test]
    fn fips_aes_round_and_mix_vectors_and_key_aliases() {
        let mut s = State::default();
        s.v[0] = hex("00102030405060708090a0b0c0d0e0f0");
        let a = run(0x4e284820, &s);
        assert_eq!(a.v[0], hex("6353e08c0960e104cd70b751bacad0e7"));
        let mut t = a.clone();
        t.v[1] = a.v[0];
        let mixed = run(0x4e286820, &t);
        assert_eq!(mixed.v[0], hex("5f72641557f5bc92f7be3b291db9f91a"));
        t.v[1] = mixed.v[0];
        assert_eq!(run(0x4e287820, &t).v[0], a.v[0]);
        assert_eq!(run(0x4e285820, &a).v[0], s.v[0]);
        assert_eq!(run(0x4e284800, &s).v[0], u128::from_le_bytes([0x63; 16]));
    }
    #[test]
    fn sm4_published_cipher_and_key_schedule() {
        let mut s = State::default();
        let key = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210];
        let fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
        s.v[0] = words(core::array::from_fn(|i| key[i] ^ fk[i]));
        let mut roundkeys = Vec::new();
        for group in 0..8 {
            let ck = core::array::from_fn(|i| {
                let r = group * 4 + i;
                (0..4).fold(0, |a, j| {
                    a | (((((r * 4 + j) * 7) & 255) as u32) << ((3 - j) * 8))
                })
            });
            s.v[1] = words(ck);
            s = run(encoding(0xce60c800, 0, 0, 1), &s);
            roundkeys.extend(unpack(s.v[0]));
        }
        assert_eq!(
            &roundkeys[..4],
            &[0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077]
        );
        assert_eq!(
            &roundkeys[28..],
            &[0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012]
        );
        s.v[0] = words(key);
        for group in 0..8 {
            s.v[1] = words(roundkeys[group * 4..group * 4 + 4].try_into().unwrap());
            s = run(0xcec08420, &s);
        }
        assert_eq!(
            unpack(s.v[0]),
            [0x536e4246, 0x86b3e94f, 0xd206965e, 0x681edf34]
        );
    }
    #[test]
    fn polynomial_widths_halves_and_mixed_matrix_signs() {
        fn poly(a: u64, z: u64, w: u8) -> u128 {
            (0..w).fold(0, |p, i| {
                if a & (1 << i) != 0 {
                    p ^ (u128::from(z) << i)
                } else {
                    p
                }
            })
        }
        for sample in 0..8 {
            let s = seeded(0x123456789abcdef0 + sample);
            for high in [false, true] {
                for w in [8u8, 64] {
                    let count = 64 / w;
                    let mut expected = 0;
                    for i in 0..count {
                        let offset = if high { 64 } else { 0 } + u32::from(i) * u32::from(w);
                        let a = ((s.v[1] >> offset) as u64) & mask(w);
                        let z = ((s.v[2] >> offset) as u64) & mask(w);
                        expected |= poly(a, z, w) << (u32::from(i) * u32::from(w) * 2);
                    }
                    let word = encoding(
                        0x0e20e000
                            | if high { 1 << 30 } else { 0 }
                            | if w == 64 { 3 << 22 } else { 0 },
                        1,
                        1,
                        2,
                    );
                    assert_eq!(run(word, &s).v[1], expected);
                }
            }
            for (base, sx, sy) in [
                (0x4e80a400, true, true),
                (0x6e80a400, false, false),
                (0x4e80ac00, false, true),
            ] {
                let mut expected = 0;
                for i in 0..2 {
                    for j in 0..2 {
                        let mut acc = (s.v[0] >> ((i * 2 + j) * 32)) as u32;
                        for k in 0..8 {
                            let a = (s.v[1] >> ((i * 8 + k) * 8)) as u8;
                            let z = (s.v[2] >> ((j * 8 + k) * 8)) as u8;
                            let a = if sx { i32::from(a as i8) } else { i32::from(a) };
                            let z = if sy { i32::from(z as i8) } else { i32::from(z) };
                            acc = acc.wrapping_add((a * z) as u32);
                        }
                        expected |= u128::from(acc) << ((i * 2 + j) * 32);
                    }
                }
                assert_eq!(run(encoding(base, 0, 1, 2), &s).v[0], expected);
            }
        }
    }

    #[test]
    fn sha1_abc_complete_schedule_and_compression() {
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
            schedule = run(encoding(0x5e003000, 0, 1, 2), &schedule);
            schedule.v[1] = words(w[j - 4..j].try_into().unwrap());
            schedule = run(0x5e281820, &schedule);
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
                (0x5a827999, 0x5e000000)
            } else if j < 40 {
                (0x6ed9eba1, 0x5e001000)
            } else if j < 60 {
                (0x8f1bbcdc, 0x5e002000)
            } else {
                (0xca62c1d6, 0x5e001000)
            };
            s.v[2] = words(core::array::from_fn(|i| w[j + i].wrapping_add(k)));
            s = run(0x5e280803, &s);
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
    #[test]
    fn sha256_abc_complete_schedule_and_compression() {
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
            schedule = run(0x5e282820, &schedule);
            schedule.v[1] = words(w[j - 8..j - 4].try_into().unwrap());
            schedule.v[2] = words(w[j - 4..j].try_into().unwrap());
            schedule = run(encoding(0x5e006000, 0, 1, 2), &schedule);
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
            s = run(encoding(0x5e004000, 0, 1, 2), &s);
            s = run(encoding(0x5e005000, 1, 3, 2), &s);
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
    #[test]
    fn sm3_abc_complete_schedule_and_compression() {
        fn p1(x: u32) -> u32 {
            x ^ x.rotate_left(15) ^ x.rotate_left(23)
        }
        let mut w = [0u32; 68];
        w[0] = 0x61626380;
        w[15] = 24;
        for j in 16..68 {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
                ^ w[j - 13].rotate_left(7)
                ^ w[j - 6];
        }
        let mut schedule = State::default();
        for j in (16..68).step_by(4) {
            schedule.v[0] = words(w[j - 16..j - 12].try_into().unwrap());
            schedule.v[1] = words(w[j - 9..j - 5].try_into().unwrap());
            schedule.v[2] = words(w[j - 4..j].try_into().unwrap());
            schedule = run(encoding(0xce60c000, 0, 1, 2), &schedule);
            schedule.v[1] = words(w[j - 6..j - 2].try_into().unwrap());
            schedule.v[2] = words(w[j - 13..j - 9].try_into().unwrap());
            schedule = run(encoding(0xce60c400, 0, 1, 2), &schedule);
            assert_eq!(unpack(schedule.v[0]), w[j..j + 4], "W{j}");
        }
        let initial = [
            0x7380166fu32,
            0x4914b2b9,
            0x172442d7,
            0xda8a0600,
            0xa96f30bc,
            0x163138aa,
            0xe38dee4d,
            0xb0fb0e4e,
        ];
        let mut s = State::default();
        s.v[0] = words([initial[3], initial[2], initial[1], initial[0]]);
        s.v[1] = words([initial[7], initial[6], initial[5], initial[4]]);
        for j in 0..64 {
            let tj = if j < 16 { 0x79cc4519u32 } else { 0x7a879d8a };
            s.v[3] = words([0, 0, 0, tj.rotate_left(j as u32)]);
            s = run(encoding(0xce400000 | (3 << 10), 2, 0, 1), &s);
            s.v[4] = u128::from(w[j] ^ w[j + 4]);
            s.v[5] = u128::from(w[j]);
            s = run(
                encoding(if j < 16 { 0xce408000 } else { 0xce408400 }, 0, 2, 4),
                &s,
            );
            s = run(
                encoding(if j < 16 { 0xce408800 } else { 0xce408c00 }, 1, 2, 5),
                &s,
            );
        }
        let mut hash = [0; 8];
        for i in 0..8 {
            hash[i] = unpack(s.v[i / 4])[3 - i % 4] ^ initial[i];
        }
        assert_eq!(
            hash,
            [
                0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b, 0xdc10e4e2, 0x4167c487, 0x5cf2f7a2, 0x297da02b,
                0x8f4ba8e0
            ]
        );
    }

    #[test]
    fn pmul_short_vectors_zero_upper_and_xar_all_rotations() {
        for seed in [1, 0x0123456789abcdef, u64::MAX] {
            let s = seeded(seed);
            for q in [false, true] {
                let bytes = if q { 16 } else { 8 };
                let mut expected = 0;
                for i in 0..bytes {
                    let a = (s.v[1] >> (i * 8)) as u8;
                    let z = (s.v[2] >> (i * 8)) as u8;
                    let value = (0..8).fold(0u8, |out, k| {
                        if a & (1 << k) != 0 {
                            out ^ (z << k)
                        } else {
                            out
                        }
                    });
                    expected |= u128::from(value) << (i * 8);
                }
                assert_eq!(
                    run(encoding(0x2e209c00 | ((q as u32) << 30), 1, 1, 2), &s).v[1],
                    expected
                );
            }
            for rotation in 0..64u32 {
                let mut expected = 0;
                for chunk in 0..2 {
                    let a = (s.v[1] >> (chunk * 64)) as u64;
                    let z = (s.v[2] >> (chunk * 64)) as u64;
                    expected |= u128::from((a ^ z).rotate_right(rotation)) << (chunk * 64);
                }
                assert_eq!(
                    run(encoding(0xce800000 | (rotation << 10), 1, 1, 2), &s).v[1],
                    expected
                );
            }
            for base in [0xce000000, 0xce200000] {
                let out = run(encoding(base | (31 << 10), 31, 31, 31), &s);
                assert_eq!(out.v[31], s.v[31]);
            }
        }
    }
    #[test]
    fn upstream_physical_groups_validate_and_execute_without_fabricating_bf16() {
        for &(word, supported, page) in super::CRYPTO_CORPUS {
            if !supported {
                assert!(
                    a64(word, 0).is_none(),
                    "FP-owned {page}: {word:08x} intercepted"
                );
                continue;
            }
            let r = a64(word, 0).unwrap_or_else(|| panic!("{page}: {word:08x} unhandled"));
            assert_eq!(r.support, Support::Full, "{page}: {word:08x}");
            r.validate().unwrap();
            let _ = run(word, &seeded(0x123456789abcdef0));
        }
        for word in [0x2e609c00, 0x0e60e000, 0x0ea0e000] {
            assert!(matches!(
                a64(word, 0).unwrap().support,
                Support::Unsupported(_)
            ));
        }
        assert!(a64(0xd503201f, 0).is_none());
    }
}
`
