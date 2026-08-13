# Taylor (SUIT Manifest Generator)

Taylor your SUIT Manifest!

Takes an input JSON file and converts it to a SUIT Manifest encoded in CBOR

## Usage

cargo run -- <path_to_json>

only cargo run for default path "examples/test1.json"

## How to add fields

 - Add the structure into the manifest.rs file
 - Implement parsing in parse.rs, 
   - start with adding to parse fn and if necessary add helper function
   - add to return value
 - Implement serde::Serialize Trait in encode.rs
