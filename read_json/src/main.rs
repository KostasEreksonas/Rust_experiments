use std::fs::File;
use std::path::Path;
use serde;

fn main() {
    let json_file_path = Path::new("../../read_json/src/scans/aes_sbox.json");
    let file = File::open(json_file_path)
    let json: serde_json::Value = serde_json::from_reader(file).expect("JSON was not well-formatted");
    println!("{:?}", json);
}
