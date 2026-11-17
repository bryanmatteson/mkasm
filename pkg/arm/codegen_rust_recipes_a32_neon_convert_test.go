package arm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Qualify physical vector encoding identities and ordered lane plumbing through
// a freshly generated decoder and the public portable evaluator.
func TestRustA32NeonRoundingAndIntegerFixedConversion(t *testing.T) {
	path := os.Getenv("MKASM_ARM32_CORPUS")
	if path == "" {
		t.Skip("set MKASM_ARM32_CORPUS to the June2026 AArch32 XML archive")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	primary := a32NeonConversionPrimary(t, path)
	corpus, err := OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(home, "Documents/Developer/go-mkasm")
	if err = os.MkdirAll(base, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "a32-neon-convert-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	parser := NewARMParser(ARMParserConfig{Corpus: corpus, EncodingIndexPath: ArchARM32.SpecIndexFile(), Arch: ArchARM32, Languages: []CodegenLang{LangRust}, OutputDirectory: dir})
	defer parser.Close(5 * time.Second)
	if err = parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "scalar.rs"), []byte(a32NeonConversionBehavior+primary), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--edition=2021", "--crate-name", "arm32", "--crate-type", "lib", "src/lib.rs", "-Dwarnings", "-o", "libarm32.rlib"},
		{"--edition=2021", "--test", "scalar.rs", "--extern", "arm32=libarm32.rlib", "-Dwarnings", "-Copt-level=1", "-o", "scalar-tests"},
		{"./scalar-tests", "--nocapture"},
	} {
		var cmd *exec.Cmd
		if strings.HasPrefix(args[0], "./") {
			cmd = exec.Command(filepath.Join(dir, args[0]), args[1:]...)
		} else {
			cmd = exec.Command("rustc", args...)
		}
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated A32 NEON floating %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

func a32NeonConversionPrimary(t *testing.T, path string) string {
	t.Helper()
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
	type encoding struct {
		Name  string `xml:"name,attr"`
		Boxes []box  `xml:"box"`
	}
	type class struct {
		ISA     string `xml:"isa,attr"`
		Diagram struct {
			Boxes []box `xml:"box"`
		} `xml:"regdiagram"`
		Encodings []encoding `xml:"encoding"`
	}
	type page struct {
		Classes []class `xml:"classes>iclass"`
	}
	apply := func(word uint32, boxes []box) uint32 {
		for _, b := range boxes {
			pos := b.Hi
			for _, c := range b.Cells {
				span := c.Span
				if span == 0 {
					span = 1
				}
				bits := strings.NewReplacer("(", "", ")", "").Replace(strings.TrimSpace(c.Text))
				if len(bits) != span {
					bits = strings.Repeat("x", span)
				}
				for _, bit := range bits {
					if bit == '0' || bit == '1' {
						word &^= 1 << uint(pos)
						word |= uint32(bit-'0') << uint(pos)
					}
					pos--
				}
			}
		}
		return word
	}
	wanted := map[string]bool{}
	for _, n := range strings.Fields("vcvta_asimd vcvtn_asimd vcvtm_asimd vcvtp_asimd vrinta_asimd vrintn_asimd vrintm_asimd vrintp_asimd vrintx_asimd vrintz_asimd vcvt_is vcvt_xs") {
		wanted[n+".xml"] = true
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out strings.Builder
	out.WriteString("#[test]fn primary_neon_floating_encoding_identities(){for(word,thumb,id)in[\n")
	classes, ids := 0, 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(h.Name, "ISA_AArch32_xml_A_profile-2026-06/")
		if !wanted[name] {
			continue
		}
		delete(wanted, name)
		var p page
		if err = xml.NewDecoder(tr).Decode(&p); err != nil {
			t.Fatal(err)
		}
		for _, cl := range p.Classes {
			vector := false
			for _, b := range cl.Diagram.Boxes {
				if b.Name == "Q" {
					vector = true
				}
			}
			if !vector {
				continue
			}
			classes++
			for _, e := range cl.Encodings {
				word := apply(0, cl.Diagram.Boxes)
				for _, b := range cl.Diagram.Boxes {
					if b.Name == "size" {
						word = (word &^ (3 << 18)) | (1 << 18)
					}
					if b.Name == "imm6" {
						word |= 63 << 16
					}
				}

				word = apply(word, e.Boxes)
				fmt.Fprintf(&out, "(0x%08x,%t,%q),\n", word, cl.ISA == "T32", e.Name)
				ids++
			}
		}
	}
	if len(wanted) != 0 || classes != 24 || ids != 48 {
		t.Fatalf("NEON floating primary coverage missing=%v classes=%d ids=%d", wanted, classes, ids)
	}
	out.WriteString("]{let d=physical_decoded(word,thumb,CodeEndian::Little);assert_eq!(d.encoding_id(),id,\"{word:08x}\");let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,\"{id} {word:08x}\");r.validate().unwrap();}}\n")
	t.Logf("qualified 12 primary pages, %d vector classes, %d encoding identities", classes, ids)
	return out.String()
}

const a32NeonConversionBehavior = a32NeonFloatingPrelude + `fn unary(base: u32, d: u32, m: u32, q: bool, width: u8) -> u32 {
    word(base, d, 0, m, q, 32) | if width == 16 { 1 << 18 } else { 2 << 18 }
}

fn check_unary(
    word: u32,
    thumb: bool,
    width: u8,
    q: bool,
    d: u32,
    m: u32,
    operation: FloatOperation,
) {
    for endian in [CodeEndian::Little, CodeEndian::Big] {
        let r = decoded(word, thumb, endian).semantic_recipe(0x1000);
        assert_eq!(r.support, Support::Full, "{word:08x}");
        r.validate().unwrap();
        let s = state(width);
        let t = evaluate(&r, &s).unwrap();
        let calls = s.calls.borrow();
        assert_eq!(calls.len(), usize::from(64 / width) * if q { 6 } else { 3 });
        for (chunk, values) in calls.chunks(usize::from(64 / width) * 3).enumerate() {
            for (lane, projections) in values.chunks(3).enumerate() {
                let mask = (1u64 << width) - 1;
                let expected = s.vectors[m as usize + chunk] >> (lane * usize::from(width)) & mask;
                for (o, w, v) in projections {
                    assert_eq!(*o, operation, "{word:08x}");
                    assert_eq!(*w, width);
                    assert_eq!(v, &vec![expected]);
                }
            }
            assert_eq!(
                out(&t, (d + chunk as u32) as u16),
                s.vectors[m as usize + chunk]
            );
        }
    }
}
#[test]
fn all_rounding_modes_formats_q_and_d_register_aliases() {
    for thumb in [false, true] {
        for width in [16u8, 32] {
            for q in [false, true] {
                for (d, m) in [(0, 0), (0, 2), (1, 31), (15, 16), (16, 16), (30, 30)] {
                    if q && (d | m) & 1 != 0 {
                        continue;
                    }
                    for (op, rounding, exact) in [
                        (0, FloatRounding::NearestEven, false),
                        (1, FloatRounding::Environment, true),
                        (2, FloatRounding::NearestAway, false),
                        (3, FloatRounding::Zero, false),
                        (5, FloatRounding::NegativeInfinity, false),
                        (7, FloatRounding::PositiveInfinity, false),
                    ] {
                        let w = unary(0xf3b20400 | (op << 7), d, m, q, width);
                        check_unary(
                            w,
                            thumb,
                            width,
                            q,
                            d,
                            m,
                            FloatOperation::RoundToIntegral { rounding, exact },
                        );
                    }
                    for (mode, rounding) in [
                        (0, FloatRounding::NearestAway),
                        (1, FloatRounding::NearestEven),
                        (2, FloatRounding::PositiveInfinity),
                        (3, FloatRounding::NegativeInfinity),
                    ] {
                        for signed in [false, true] {
                            let w = unary(
                                0xf3b30000 | (mode << 8) | if signed { 0 } else { 128 },
                                d,
                                m,
                                q,
                                width,
                            );
                            check_unary(
                                w,
                                thumb,
                                width,
                                q,
                                d,
                                m,
                                FloatOperation::ToInteger {
                                    source_width: width,
                                    signed,
                                    fractional_bits: 0,
                                    rounding,
                                },
                            );
                        }
                    }
                    for to_integer in [false, true] {
                        for signed in [false, true] {
                            let w = unary(
                                0xf3b30600
                                    | if to_integer { 256 } else { 0 }
                                    | if signed { 0 } else { 128 },
                                d,
                                m,
                                q,
                                width,
                            );
                            let operation = if to_integer {
                                FloatOperation::ToInteger {
                                    source_width: width,
                                    signed,
                                    fractional_bits: 0,
                                    rounding: FloatRounding::Zero,
                                }
                            } else {
                                FloatOperation::FromInteger {
                                    source_width: width,
                                    signed,
                                    fractional_bits: 0,
                                }
                            };
                            check_unary(w, thumb, width, q, d, m, operation);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn fixed_point_every_scale_direction_sign_and_vector_bank() {
    for thumb in [false, true] {
        for width in [16u8, 32] {
            for scale in 1..=width {
                for q in [false, true] {
                    for (d, m) in [(0, 0), (0, 2), (1, 31), (16, 16), (30, 30)] {
                        if q && (d | m) & 1 != 0 {
                            continue;
                        }
                        for to_integer in [false, true] {
                            for signed in [false, true] {
                                let w = 0xf2800c10
                                    | (u32::from(64 - scale) << 16)
                                    | ((d & 15) << 12)
                                    | ((d & 16) << 18)
                                    | (m & 15)
                                    | ((m & 16) << 1)
                                    | if width == 32 { 512 } else { 0 }
                                    | if to_integer { 256 } else { 0 }
                                    | if signed { 0 } else { 1 << 24 }
                                    | if q { 64 } else { 0 };
                                let operation = if to_integer {
                                    FloatOperation::ToInteger {
                                        source_width: width,
                                        signed,
                                        fractional_bits: scale,
                                        rounding: FloatRounding::Zero,
                                    }
                                } else {
                                    FloatOperation::FromInteger {
                                        source_width: width,
                                        signed,
                                        fractional_bits: scale,
                                    }
                                };
                                check_unary(w, thumb, width, q, d, m, operation);
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn conversion_half_metadata_and_thumb_it_are_explicit() {
    for w in [
        0xf3b70000, 0xf3b60400, 0xf3b60480, 0xf3b60580, 0xf3b70600, 0xf3bf0c10, 0xf3bf0d10,
    ] {
        let d = decoded(w, true, CodeEndian::Little);
        assert_eq!(
            d.requirements().expression.evaluate_with(
                &|name| if name == "FEAT_FP16" {
                    Some(false)
                } else {
                    None
                },
                "thumb",
                &|name| d.field(name).map(u64::from)
            ),
            arm32::requirements::Satisfaction::Unsatisfied,
            "{w:08x}"
        );
        for z in [0, 1] {
            let mut s = state(16);
            s.it = 8;
            s.z = z;
            assert_eq!(
                evaluate(&d.semantic_recipe(0x1000), &s),
                Err(EvalError::UnsupportedContext)
            );
            assert!(s.calls.borrow().is_empty());
        }
    }
}
`
