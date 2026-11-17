use std::io::{self, BufRead, Read};
use wasm_encoder::{
    reencode::{Reencode, RoundtripReencoder},
    Encode,
};
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--wat") {
        let mut source = String::new();
        io::stdin().read_to_string(&mut source).unwrap();
        let module = wat::parse_str(&source).unwrap();
        wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
            .validate_all(&module)
            .unwrap();
        for payload in wasmparser::Parser::new(0).parse_all(&module) {
            if let wasmparser::Payload::CodeSectionEntry(body) = payload.unwrap() {
                let range = body
                    .get_operators_reader()
                    .unwrap()
                    .get_binary_reader()
                    .remaining_range();
                let bytes = &module[range.start as usize..range.end as usize];
                println!(
                    "{}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
        }
        return;
    }
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (id, hex) = line.split_once(' ').unwrap();
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
            .collect();
        let prefix: &[u8] = match id {
            "Else" => &[0x04, 0x40],
            "Catch" | "Delegate" | "CatchAll" => &[0x06, 0x40],
            _ => &[],
        };
        let framed: Vec<u8> = prefix.iter().chain(&bytes).copied().collect();
        let mut r = wasmparser::OperatorsReader::new(wasmparser::BinaryReader::new(&framed, 0));
        if !prefix.is_empty() {
            r.read().unwrap();
        }
        let op = match r.read() {
            Ok(o) => o,
            Err(e) => {
                println!("ERR {id} {e}");
                continue;
            }
        };
        let desc = format!("{op:?}");
        let mut out = Vec::new();
        match RoundtripReencoder.instruction(op) {
            Ok(i) => i.encode(&mut out),
            Err(e) => {
                println!("ERR {id} {e}");
                continue;
            }
        };
        let actual: String = out.iter().map(|b| format!("{b:02x}")).collect();
        println!("{id} {actual} {desc}")
    }
}
