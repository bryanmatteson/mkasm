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

//go:embed arm64_atomics.rs
var a64AtomicModuleSource string

func TestRustA64NativeAtomics(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := RustRuntime
	if !strings.Contains(source, "pub mod arm64_atomics") {
		source += "\npub mod arm64_atomics {\n" + a64AtomicModuleSource + "\n}\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "semantics.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	consumer := a64AtomicBehaviorTests + a64AtomicCorpusCases(t)
	if err := os.WriteFile(filepath.Join(dir, "atomic.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "atomic.rs", "-Dwarnings", "-o", filepath.Join(dir, "a64-atomic-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile native A64 atomics: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "a64-atomic-tests"), "a64_atomic_behavior::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute native A64 atomics: %v\n%s", err, out)
	}
}

// Derive physical words from upstream class diagrams, independently of the
// helper's masks. Ordinary tests retain portable, explicitly selected words.
func a64AtomicCorpusCases(t *testing.T) string {
	t.Helper()
	var result strings.Builder
	result.WriteString("\nconst ATOMIC_CORPUS:&[(u32,bool,&str)]=&[\n")
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
		family = strings.TrimSuffix(strings.TrimSuffix(family, "b"), "h")
		supported := false
		selected := true
		switch family {
		case "ldxr", "ldaxr", "stxr", "stlxr", "ldxp", "ldaxp", "stxp", "stlxp", "ldar", "stlr", "cas", "casp", "swp", "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin", "stadd", "stclr", "steor", "stset", "stsmax", "stsmin", "stumax", "stumin", "swpp", "ldclrp", "ldsetp":
			supported = true
		case "ldlar", "stllr":
			supported = true
		case "ldapr", "cast", "caspt", "swpt":
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
			for size := 0; size < 4; size++ {
				for flags := 0; flags < 4; flags++ {
					word := value
					for _, b := range cl.Diagram.Boxes {
						width := b.Width
						if width == 0 {
							width = 1
						}
						v := uint32(0)
						switch b.Name {
						case "size":
							v = uint32(size)
						case "sz":
							v = uint32(size & 1)
						case "Rn":
							v = 10
						case "Rt":
							v = 0
						case "Rt2":
							v = 1
						case "Rs":
							v = 2
						case "A", "L":
							v = uint32(flags & 1)
						case "R", "o0":
							v = uint32(flags >> 1)
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
	t.Logf("derived %d A64 atomic words from %d upstream pages", count, len(seen))
	return result.String()
}

const a64AtomicBehaviorTests = `
#[allow(dead_code)]
mod semantics;
mod a64_atomic_behavior {
    use super::semantics::arm64_atomics::{a64, a64_with_context, AtomicContext};
    use super::semantics::*;
    use std::cell::Cell;
    #[derive(Clone)]
    struct State {
        x: [u64; 32],
        sp: u64,
        memory: [u8; 64],
        monitor: Option<ExclusiveReservation>,
        calls: Cell<usize>,
        fail_sc: bool,
    }
    impl State {
        fn new() -> Self {
            let mut x = [0; 32];
            x[10] = 16;
            Self {
                x,
                sp: 32,
                memory: [0; 64],
                monitor: None,
                calls: Cell::new(0),
                fail_sc: false,
            }
        }
        fn load(&self, address: u64, width: u8, endian: Endian) -> u128 {
            let count = usize::from(width / 8);
            let mut bits = 0u128;
            for i in 0..count {
                let shift = match endian {
                    Endian::Little => i,
                    Endian::Big => count - i - 1,
                };
                bits |= u128::from(self.memory[address as usize + i]) << (shift * 8);
            }
            bits
        }
        fn store(&mut self, address: u64, width: u8, endian: Endian, bits: u128) {
            let count = usize::from(width / 8);
            for i in 0..count {
                let shift = match endian {
                    Endian::Little => i,
                    Endian::Big => count - i - 1,
                };
                self.memory[address as usize + i] = (bits >> (shift * 8)) as u8;
            }
        }
        fn apply_atomic(&mut self, a: &AtomicTransition) {
            if let (Some(r), Some(low)) = (&a.request, a.stored) {
                let high = a.stored_high.map_or(0, |v| u128::from(v.bits) << 64);
                self.store(r.address, r.width, r.endian, u128::from(low.bits) | high);
            }
            match a.monitor {
                ExclusiveMonitorEffect::Set(r) => self.monitor = Some(r),
                ExclusiveMonitorEffect::Cleared => self.monitor = None,
                ExclusiveMonitorEffect::Preserved => {}
            }
        }
        fn commit(&mut self, t: &Transition) {
            for e in &t.events {
                if let OrderedEvent::Atomic(i) = e {
                    self.apply_atomic(&t.atomics[*i]);
                }
            }
            for w in &t.registers {
                match w.register.bank {
                    "a64.gpr" => self.x[w.register.index as usize] = w.value.bits,
                    "a64.sp" => self.sp = w.value.bits,
                    other => panic!("unexpected output {other}"),
                }
            }
        }
        fn observe(
            &self,
            r: &AtomicRequest,
            previous: &[AtomicTransition],
            pair: bool,
        ) -> AtomicPairObservation {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(r.width == 128, pair);
            let mut state = self.clone();
            for p in previous {
                state.apply_atomic(p)
            }
            let bits = state.load(r.address, r.width, r.endian);
            let read = matches!(
                r.kind,
                AtomicRequestKind::Load
                    | AtomicRequestKind::LoadLinked
                    | AtomicRequestKind::ReadModifyWrite { .. }
                    | AtomicRequestKind::CompareExchange { .. }
                    | AtomicRequestKind::LoadPair
                    | AtomicRequestKind::ReadModifyWritePair { .. }
                    | AtomicRequestKind::LoadLinkedPair
                    | AtomicRequestKind::CompareExchangePair { .. }
            );
            let conditional = matches!(
                r.kind,
                AtomicRequestKind::StoreConditional { .. }
                    | AtomicRequestKind::StoreConditionalPair { .. }
            );
            let linked = matches!(
                r.kind,
                AtomicRequestKind::LoadLinked | AtomicRequestKind::LoadLinkedPair
            );
            AtomicPairObservation {
                observation: AtomicObservation {
                    old: read.then(|| Value::known(if pair { 64 } else { r.width }, bits as u64)),
                    store_succeeded: conditional.then(|| {
                        !self.fail_sc
                            && r.reservation.is_some_and(|x| {
                                x.address == r.address
                                    && x.width == r.width
                                    && x.scope == r.scope
                                    && x.token == 9
                            })
                    }),
                    reservation_token: linked.then_some(9),
                    witness: previous.len() as u64 + 1,
                },
                old_high: (pair && read).then(|| Value::known(64, (bits >> 64) as u64)),
            }
        }
    }
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            Value::known(
                if r.bank=="a64.sp_alignment_enforced" {1} else {64},
                match r.bank {
                    "a64.gpr" => {
                        assert!(r.index < 31);
                        self.x[r.index as usize]
                    }
                    "a64.sp_alignment_enforced" => 1,
                    "a64.sp" => {
                        assert_eq!(r.index, 0);
                        self.sp
                    }
                    other => panic!("unexpected read {other}"),
                },
            )
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("atomic used plain memory")
        }
        fn read_exclusive_monitor(&self) -> Result<Option<ExclusiveReservation>, EvalError> {
            Ok(self.monitor)
        }
        fn evaluate_atomic(
            &self,
            r: &AtomicRequest,
            p: &[AtomicTransition],
        ) -> Result<AtomicObservation, EvalError> {
            Ok(self.observe(r, p, false).observation)
        }
        fn evaluate_atomic_pair(
            &self,
            r: &AtomicRequest,
            p: &[AtomicTransition],
        ) -> Result<AtomicPairObservation, EvalError> {
            Ok(self.observe(r, p, true))
        }
    }
    fn recipe(word: u32, endian: Endian) -> Recipe {
        a64_with_context(
            word,
            0x1000,
            endian,
            AtomicContext {
                exclusive_pair_atomic: true,
            },
        )
        .expect("recognized atomic")
    }
    fn execute(state: &mut State, word: u32, endian: Endian) -> Transition {
        let r = recipe(word, endian);
        assert_eq!(r.support, Support::Full);
        let t = evaluate(&r, state).unwrap();
        assert_eq!(t.atomics.len(), 1);
        assert_eq!(t.events, [OrderedEvent::Atomic(0)]);
        assert!(t.memory.is_empty());
        assert_eq!(t.next_pc, Value::known(64, 0x1004));
        state.commit(&t);
        t
    }
    fn ordering(a: bool, r: bool) -> MemoryOrdering {
        match (a, r) {
            (false, false) => MemoryOrdering::Monotonic,
            (true, false) => MemoryOrdering::Acquire,
            (false, true) => MemoryOrdering::Release,
            (true, true) => MemoryOrdering::AcquireRelease,
        }
    }
    #[test]
    fn scalar_exclusives_widths_order_status_and_monitor() {
        for endian in [Endian::Little, Endian::Big] {
            for size in 0..4 {
                for acquire in [false, true] {
                    let width = 8u8 << size;
                    let mask = mask(width);
                    let mut s = State::new();
                    s.x[0] = 0x1122334455667788;
                    s.x[2] = u64::MAX;
                    s.store(16, width, endian, u128::from(mask - 1));
                    let load = 0x085f7c00 | (size << 30) | ((acquire as u32) << 15) | (10 << 5) | 1;
                    let t = execute(&mut s, load, endian);
                    assert_eq!(s.x[1], mask - 1);
                    assert_eq!(
                        t.atomics[0].request.as_ref().unwrap().ordering,
                        ordering(acquire, false)
                    );
                    assert_eq!(s.monitor.unwrap().width, width);
                    for release in [false, true] {
                        let saved = s.clone();
                        let store = 0x08007c00
                            | (size << 30)
                            | ((release as u32) << 15)
                            | (2 << 16)
                            | (10 << 5);
                        let t = execute(&mut s, store, endian);
                        assert_eq!(s.x[2], 0);
                        assert!(s.monitor.is_none());
                        assert_eq!(s.load(16, width, endian), u128::from(s.x[0] & mask));
                        assert_eq!(
                            t.atomics[0].request.as_ref().unwrap().ordering,
                            ordering(false, release)
                        );
                        let _ = execute(&mut s, store, endian);
                        assert_eq!(s.x[2], 1);
                        s = saved;
                    }
                }
            }
        }
    }
    #[test]
    fn pair_exclusives_are_one_event_and_map_address_order_in_both_endians() {
        for endian in [Endian::Little, Endian::Big] {
            for element in [32u8, 64] {
                let mut s = State::new();
                let first = if element == 32 {
                    0x11223344
                } else {
                    0x1122334455667788
                };
                let second = if element == 32 {
                    0x99aabbcc
                } else {
                    0x99aabbccddeeff00
                };
                s.store(16, element, endian, first);
                s.store(16 + u64::from(element / 8), element, endian, second);
                let sz = if element == 64 { 1 << 30 } else { 0 };
                let load = 0x887f8000 | sz | (1 << 10) | (10 << 5);
                let t = execute(&mut s, load, endian);
                assert_eq!(s.x[0], first as u64);
                assert_eq!(s.x[1], second as u64);
                assert_eq!(t.atomics[0].request.as_ref().unwrap().width, element * 2);
                assert!(
                    matches!(t.atomics[0].monitor,ExclusiveMonitorEffect::Set(ExclusiveReservation{width,..})if width==element*2)
                );
                s.x[0] = 3;
                s.x[1] = 4;
                let store = 0x88208000 | sz | (2 << 16) | (1 << 10) | (10 << 5);
                let t = execute(&mut s, store, endian);
                assert_eq!(s.x[2], 0);
                assert_eq!(s.load(16, element, endian), 3);
                assert_eq!(s.load(16 + u64::from(element / 8), element, endian), 4);
                assert_eq!(t.atomics[0].stored_high.is_some(), element == 64);
                assert!(s.monitor.is_none());
            }
        }
    }
    #[test]
    fn pending_transition_alias_capture_and_backend_exclusive_failure() {
        let mut s = State::new();
        s.store(16, 64, Endian::Little, 7);
        // A linked load into its own base uses the incoming address. Evaluation
        // yields a pending transition; memory, registers and monitor commit together.
        let linked = recipe(0xc85f7c00 | (10 << 5) | 10, Endian::Little);
        let t = evaluate(&linked, &s).unwrap();
        assert_eq!(s.x[10], 16);
        assert!(s.monitor.is_none());
        assert_eq!(s.calls.get(), 1);
        assert_eq!(t.atomics[0].request.as_ref().unwrap().address, 16);
        s.commit(&t);
        assert_eq!(s.x[10], 7);
        assert_eq!(s.monitor.unwrap().address, 16);
        s.x[10] = 16;
        s.x[0] = 99;
        s.x[2] = u64::MAX;
        s.fail_sc = true;
        let conditional = recipe(0xc8027c00 | (10 << 5), Endian::Little);
        let t = evaluate(&conditional, &s).unwrap();
        assert_eq!(t.atomics[0].success, Some(false));
        assert!(t.atomics[0].stored.is_none());
        assert_eq!(s.x[2], u64::MAX);
        assert!(s.monitor.is_some());
        assert_eq!(s.load(16, 64, Endian::Little), 7);
        s.commit(&t);
        assert_eq!(s.x[2], 1);
        assert!(s.monitor.is_none());
        assert_eq!(s.load(16, 64, Endian::Little), 7);
        // XZR discards only data; the acquire and exclusive monitor still apply.
        let t = execute(&mut s, 0xc85ffc00 | (10 << 5) | 31, Endian::Little);
        assert!(t.registers.is_empty());
        assert!(s.monitor.is_some());
        assert_eq!(
            t.atomics[0].request.as_ref().unwrap().ordering,
            MemoryOrdering::Acquire
        );
        // LSE permits source, result and base to alias, capturing all incoming
        // inputs before the returned old value overwrites the register.
        s.x[10] = 16;
        let t = execute(&mut s, 0xf82a0000 | (10 << 5) | 10, Endian::Little);
        assert_eq!(s.x[10], 7);
        assert_eq!(s.load(16, 64, Endian::Little), 23);
        assert_eq!(t.atomics[0].request.as_ref().unwrap().address, 16);
    }
    #[test]
    fn acquire_release_load_store_zr_sp_and_writeback() {
        for endian in [Endian::Little, Endian::Big] {
            for size in 0..4 {
                let width = 8u8 << size;
                let mut s = State::new();
                s.x[0] = u64::MAX;
                s.store(16, width, endian, 5);
                let t = execute(&mut s, 0x08dffc00 | (size << 30) | (10 << 5), endian);
                assert_eq!(s.x[0], 5);
                assert_eq!(
                    t.atomics[0].request.as_ref().unwrap().ordering,
                    MemoryOrdering::Acquire
                );
                let t = execute(&mut s, 0x089ffc00 | (size << 30) | (10 << 5) | 31, endian);
                assert_eq!(s.load(16, width, endian), 0);
                assert!(t.registers.is_empty());
                assert_eq!(
                    t.atomics[0].request.as_ref().unwrap().ordering,
                    MemoryOrdering::Release
                );
            }
            let mut s = State::new();
            s.store(32, 64, endian, 42);
            let t = execute(&mut s, 0xc8dffc00 | (31 << 5), endian);
            assert_eq!(s.x[0], 42);
            assert_eq!(t.atomics[0].request.as_ref().unwrap().address, 32);
            s.x[0] = 0xabcdef;
            s.x[10] = 24;
            let t = execute(&mut s, 0xd9800800 | (10 << 5), endian);
            assert_eq!(s.x[10], 16);
            assert_eq!(s.load(16, 64, endian), 0xabcdef);
            assert_eq!(t.atomics[0].request.as_ref().unwrap().address, 16);
        }
    }
    #[test]
    fn cas_all_sizes_orders_aliases_and_zero_extension() {
        for endian in [Endian::Little, Endian::Big] {
            for size in 0..4 {
                for acquire in [false, true] {
                    for release in [false, true] {
                        let width = 8u8 << size;
                        let mut s = State::new();
                        s.x[0] = 0xffffffffffffffff;
                        s.x[1] = 7;
                        s.store(16, width, endian, u128::from(mask(width)));
                        let word = 0x08a07c00
                            | (size << 30)
                            | ((acquire as u32) << 22)
                            | ((release as u32) << 15)
                            | (10 << 5)
                            | 1;
                        let t = execute(&mut s, word, endian);
                        assert_eq!(t.atomics[0].success, Some(true));
                        assert_eq!(s.x[0], mask(width));
                        assert_eq!(s.load(16, width, endian), 7);
                        assert_eq!(
                            t.atomics[0].request.as_ref().unwrap().ordering,
                            ordering(acquire, release)
                        );
                        s.x[0] = 8;
                        let t = execute(&mut s, word, endian);
                        assert_eq!(t.atomics[0].success, Some(false));
                        assert_eq!(s.x[0], 7);
                        assert_eq!(s.load(16, width, endian), 7);
                    }
                }
            }
        }
        let mut s = State::new();
        s.x[1] = 9;
        let t = execute(
            &mut s,
            0xc8e0fc00 | (31 << 16) | (10 << 5) | 1,
            Endian::Little,
        );
        assert_eq!(
            t.atomics[0].request.as_ref().unwrap().ordering,
            MemoryOrdering::Release
        );
        assert!(t.registers.is_empty());
        assert_eq!(s.load(16, 64, Endian::Little), 9);
    }
    #[test]
    fn casp_pair_orders_registers_and_zero_register_pair() {
        for endian in [Endian::Little, Endian::Big] {
            for element in [32u8, 64] {
                let mut s = State::new();
                s.x[0] = 1;
                s.x[1] = 2;
                s.x[2] = 3;
                s.x[3] = 4;
                s.store(16, element, endian, 1);
                s.store(16 + u64::from(element / 8), element, endian, 2);
                let sz = if element == 64 { 1 << 30 } else { 0 };
                let word = 0x0860fc00 | sz | (10 << 5) | 2;
                let t = execute(&mut s, word, endian);
                assert_eq!(t.atomics[0].success, Some(true));
                assert_eq!(s.x[..4], [1, 2, 3, 4]);
                assert_eq!(s.load(16, element, endian), 3);
                assert_eq!(s.load(16 + u64::from(element / 8), element, endian), 4);
                assert_eq!(t.atomics[0].request.as_ref().unwrap().width, element * 2);
                assert_eq!(
                    t.atomics[0].request.as_ref().unwrap().ordering,
                    MemoryOrdering::AcquireRelease
                );
                let t = execute(&mut s, word, endian);
                assert_eq!(t.atomics[0].success, Some(false));
                assert_eq!(s.x[..2], [3, 4]);
                s.x[30] = 5;
                s.store(16, element, endian, 5);
                s.store(16 + u64::from(element / 8), element, endian, 0);
                let word = 0x08207c00 | sz | (30 << 16) | (10 << 5) | 2;
                let t = execute(&mut s, word, endian);
                assert_eq!(t.atomics[0].success, Some(true));
                assert!(t.registers.iter().all(|w| w.register.index != 31));
            }
        }
    }
    #[test]
    fn lse_all_rmw_operations_and_store_alias_order() {
        for endian in [Endian::Little, Endian::Big] {
            for size in 0..4 {
                let width = 8u8 << size;
                let m = mask(width);
                for opcode in 0..9 {
                    for acquire in [false, true] {
                        for release in [false, true] {
                            let mut s = State::new();
                            s.x[1] = 2;
                            s.x[2] = u64::MAX;
                            s.store(16, width, endian, u128::from(m - 1));
                            let word = 0x38200000
                                | (size << 30)
                                | ((acquire as u32) << 23)
                                | ((release as u32) << 22)
                                | (1 << 16)
                                | (opcode << 12)
                                | (10 << 5)
                                | 2;
                            let t = execute(&mut s, word, endian);
                            let expected = match opcode {
                                0 => 0,
                                1 | 2 => m - 3,
                                3 => m - 1,
                                4 => 2,
                                5 => m - 1,
                                6 => m - 1,
                                7 | 8 => 2,
                                _ => unreachable!(),
                            };
                            assert_eq!(s.x[2], m - 1);
                            assert_eq!(s.load(16, width, endian), u128::from(expected));
                            assert_eq!(
                                t.atomics[0].request.as_ref().unwrap().ordering,
                                ordering(acquire, release)
                            );
                        }
                    }
                }
            }
            let mut s = State::new();
            s.x[1] = 2;
            s.store(16, 64, endian, 5);
            let t = execute(&mut s, 0xf8e10000 | (10 << 5) | 31, endian);
            assert_eq!(s.load(16, 64, endian), 7);
            assert!(t.registers.is_empty());
            assert_eq!(
                t.atomics[0].request.as_ref().unwrap().ordering,
                MemoryOrdering::Release
            );
        }
    }
    #[test]
    fn context_reserved_and_constrained_encodings_reject_explicitly() {
        let split=a64(0xc87f0000 | (1 << 10) | (10 << 5),0,Endian::Little).unwrap();
        assert_eq!(split.support,Support::Full);
        assert!(matches!(&split.atomics[0],AtomicStep::Memory(AtomicOperation{kind:AtomicOperationKind::LoadLinkedPairSplit,..})));
        assert_eq!(
            recipe(0x887f0000 | (1 << 10) | (10 << 5), Endian::Little).support,
            Support::Full
        );
        for word in [
            0x08217c00 | (10 << 5),
            0x08207c01 | (10 << 5),
            0x085e7c00 | (10 << 5),
            0xb8bfc000 | (10 << 5),
            0x99c00800 | (10 << 5),
            0xc9807c00 | (10 << 5),
            0x49807c00 | (10 << 5),
            0x19208400 | (10 << 5),
        ] {
            let r = a64_with_context(
                word,
                0,
                Endian::Little,
                AtomicContext {
                    exclusive_pair_atomic: true,
                },
            )
            .expect("recognized rejected atomic class");
            assert!(
                matches!(r.support, Support::Unsupported(_)),
                "word {word:08x}"
            );
            assert!(r.atomics.is_empty());
        }
        let mut s = State::new();
        s.sp = 33;
        let r = recipe(0xc8dffc00 | (31 << 5), Endian::Little);
        assert_eq!(evaluate(&r, &s).unwrap().trap, Some(TrapKind::Protection));
        assert_eq!(s.calls.get(), 0);
        assert!(a64(0xd503201f, 0, Endian::Little).is_none());
    }
    #[test]
    fn upstream_physical_diagrams_dispatch_to_exact_support() {
        for &(word, supported, page) in super::ATOMIC_CORPUS {
            let r = recipe(word, Endian::Little);
            assert_eq!(
                r.support == Support::Full,
                supported,
                "{page}: {word:08x} => {:?}",
                r.support
            );
            if supported {
                r.validate().unwrap();
                assert_eq!(r.atomics.len(), 1);
            }
        }
    }
}
`
