#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
fn recipe(word: u32, vl: u16) -> Option<Recipe> {
    let _ = vl;
    system::a64(word, 0x1000).map(|r| arm64_bti::complete(word, r))
}
struct State(u64);
impl Machine for State {
    fn read_register(&self, r: Register) -> Value {
        match r.bank {
            "a64.bti_enabled" | "a64.bti_guarded_page" => Value::known(1, 1),
            "a64.debug_halted" => Value::known(1, 0),
            "a64.btype" => Value::known(2, self.0),
            _ => panic!("{r:?}"),
        }
    }
    fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        panic!()
    }
}
#[test]
fn decoded_landing_pads_keep_full_entry_and_completion_contract() {
    for hint in 0..4 {
        for btype in 0..4 {
            let word = 0xd503241f | hint << 6;
            let r = recipe(word, 128).unwrap();
            assert_eq!(r.support, Support::Full);
            assert_eq!(r.entry_traps.len(), 1);
            assert_eq!(r.completion_writes.len(), 1);
            let compatible = match hint {
                0 => btype == 0,
                1 => btype != 3,
                2 => btype != 2,
                _ => true,
            };
            let t = evaluate(&r, &State(btype)).unwrap();
            assert_eq!(t.trap.is_none(), btype == 0 || compatible);
            if t.trap.is_none() {
                assert_eq!(t.registers.len(), 1);
                assert_eq!(t.registers[0].value, Value::known(2, 0));
            }
        }
    }
}
