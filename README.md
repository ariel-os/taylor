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

## Copyright & License

Taylor is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

