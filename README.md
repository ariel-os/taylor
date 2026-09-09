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

## Testing

The `cddl` crate is not a reliable CDDL conformance oracle for this project (see
[docs/cddl-crate-map-groupname-bug.md](docs/cddl-crate-map-groupname-bug.md) for a confirmed
bug against real SUIT CDDL), so it is intentionally not a dependency. Instead:

- `cargo test --lib` runs unit tests colocated in `src/parse.rs`/`src/encode.rs`: parser edge
  cases (UUID/version-comparison parsing, shorthand expansion) and byte-exact known-answer
  tests for the trickier `Serialize` impls, independently cross-checked against Python's
  `cbor2`.
- `cargo test --test manifest_encoding` runs the integration suite in
  `tests/manifest_encoding.rs`:
  - `golden_*` tests freeze this crate's own CBOR output for every `examples/*.json` fixture
    (`tests/golden/*.hex`) and fail on any *unintentional* wire-format change. After a
    deliberate, manually-verified spec-conformant change, regenerate with
    `UPDATE_GOLDEN=1 cargo test`.
  - `structural_*` tests decode the output independently via `ciborium::Value` and assert the
    map-key/shape invariants the CDDL requires, without needing a schema engine.
  - `shorthand_and_standard_form_are_byte_identical` locks in that `parse.rs`'s
    `suit-condition-version` convenience expansion produces exactly the bytes a
    human-authored, spec-literal `suit-directive-try-each` would.

Run everything with `cargo test`. `cargo clippy --all-targets -- -D warnings` and
`cargo fmt --check` should also be run before committing (some pre-existing lint/format
debt remains outside the files touched by the test additions above).

## Copyright & License

Taylor is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
