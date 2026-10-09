# Taylor (SUIT Manifest Generator)

Taylor your SUIT Manifest!

Takes an input JSON file and converts it to a SUIT Manifest encoded in CBOR

## Usage

```sh
cargo run -- <path_to_json>
```

A `JSON_PATH` or `--template <PATH>` must be given explicitly; see `examples/input/manifests/test.json`
for a sample manifest.

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

### Templating

For build pipelines that need to inject values (vendor/class IDs, version numbers,
digests, ...) at build time instead of committing them into a static JSON file, pass a
[minijinja](https://docs.rs/minijinja) template with `--template` instead of a plain JSON
path, along with the variables it needs:

```sh
cargo run -- \
  --template examples/input/templates/manifest.jinja \
  --var sequence_number=1 \
  --var vendor_id=67e55044-10b1-426f-9247-bb680e5fe0c8 \
  --var class_id=69e55044-10b1-426f-2974-bb680e5fedc8 \
  --var image_size=1024 \
  --var digest=c12efb651dc800465d80264343852c304c4dcea2da82828d8824df7638628d17 \
  --var uri=https://example.com/firmware.bin \
  --output out/
```

- `--var KEY=VALUE` sets a single variable (repeatable); values are inferred as
  bool/int/float, falling back to a string.
- `--vars-file <PATH>` loads a JSON object as the base context; `--var` overrides take
  precedence on key collisions, so CI-provided values can override defaults from a
  checked-in file:

  ```sh
  cargo run -- --template examples/input/templates/manifest.jinja \
    --vars-file build/vars.json \
    --var sequence_number="$CI_PIPELINE_IID"
  ```
- `--render-only` prints the rendered JSON (or writes it to `--output` as `<stem>.json`)
  and exits, without parsing/encoding/signing it — useful for inspecting or unit-testing
  the rendered manifest in isolation.
- `--template` is mutually exclusive with a plain JSON path, and `--var`/`--vars-file`/
  `--render-only` all require `--template`.
- Rendering fails fast, before producing any output, if the template references a
  variable that wasn't supplied.

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
blocks), the templating integration tests in
[`tests/templating.rs`](tests/templating.rs), and all doc-tests.
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
