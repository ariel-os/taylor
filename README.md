# Taylor (SUIT Manifest Generator)

Taylor your SUIT Manifest!

Takes an input JSON file and converts it to a SUIT Manifest encoded in CBOR

## Usage

```sh
cargo run -- <path_to_json>
```

`cargo run` with no path defaults to `examples/test.json`.

### Signing

Pass `-k`/`--key <PEM_FILE>` with a PEM-encoded EC private key (P-256/ES256 or
P-384/ES384; tried in that order) to append a `COSE_Sign1` authentication block over the
manifest digest, via the [`brody`](https://github.com/ariel-os/brody) crate:

```sh
cargo run -- <path_to_json> --key <path_to_pem>
```

### Output

Pass `-o`/`--output <dir>` to write the generated CBOR envelope to `<dir>/<stem>.cbor`
(`<stem>` is the input JSON file's stem). Without it, the CBOR is only printed as hex.

## How to add fields

 - Add the structure into the manifest.rs file
 - Implement parsing in parse.rs,
   - start with adding to parse fn and if necessary add helper function
   - add to return value
 - Implement serde::Serialize Trait in encode.rs

## Testing

```sh
cargo test
```

Runs unit tests, the signing integration tests in [`tests/signing.rs`](tests/signing.rs)
(which spawn the built binary and cryptographically verify the resulting `COSE_Sign1`
blocks), and all doc-tests.
## Documentation

```sh
cargo doc --no-deps --open
```

Builds and opens this crate's own API docs, excluding dependency documentation.

## Copyright & License

Taylor is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.
