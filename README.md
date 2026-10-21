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

The manifest digest that the signature covers is SHA-256 by default. Pass
`--manifest-digest sha384` to use SHA-384 instead, for example to match the strength of a
P-384 key:

```sh
cargo run -- <path_to_json> --key <path_to_p384_pem> --manifest-digest sha384
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

### Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success, including `--help` and `--version` |
| 1 | Runtime failure, such as an unreadable file, invalid manifest, bad signing key, or a failed write to stdout |
| 2 | Usage error, such as a missing manifest source or conflicting arguments |

## Library usage

Add Taylor as a dependency with `cargo add taylor`, then parse a JSON manifest and build the
CBOR envelope:

```rust
use taylor::envelope::build_envelope;
use taylor::parse::parse;
use taylor::sign::load_signer;

fn generate(json: &str, key_pem: Option<&str>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let manifest = parse(&mut json.as_bytes())?;
    let signer = key_pem.map(load_signer).transpose()?;
    Ok(build_envelope(manifest, signer.as_ref())?)
}
```

- `taylor::parse::parse` reads the JSON manifest from any `std::io::Read` and returns an error,
  never panics, on malformed input.
- `taylor::envelope::build_envelope` encodes the manifest, adds its SHA-256 digest, and signs
  the envelope when a `Signer` is given. `build_envelope_with_digest` does the same with a
  chosen `DigestAlgorithm`, such as `DigestAlgorithm::Sha384`.
- `taylor::sign::sign_envelope_with_pem` and `sign_envelope_with_key` sign an already encoded
  envelope with a PEM key given as text or as a file path.
- `taylor::template::render` renders a `minijinja` template into manifest JSON.
- `taylor::cli::run` runs the command-line interface in-process and returns its exit code.

## Python package

The `taylor-suit` package on PyPI provides Python bindings to the same Rust code. It installs
as the `taylor` module plus a `taylor` command identical to the Rust CLI:

```sh
pip install taylor-suit
```

```python
import json
import taylor

manifest = json.load(open("manifest.json"))
unsigned = taylor.build_envelope(manifest)
signed = taylor.build_envelope(manifest, key_path="key.pem")
manifest_json = taylor.render_template("manifest.jinja", {"sequence_number": 7},
                                       vars_file="vars.json")
```

- `build_envelope` and `encode_manifest` accept the manifest as JSON text or as a mapping.
- Signing keys are given either as PEM text or bytes (`key_pem`) or as a file path
  (`key_path`), not both.
- `build_envelope(..., manifest_digest="sha384")` selects the manifest digest algorithm,
  like `--manifest-digest`.
- Errors are raised as `taylor.ManifestError`, `taylor.TemplateError`, or
  `taylor.SigningError`, all subclasses of `taylor.TaylorError`.
- If the Rust binary is also installed with `cargo install taylor`, whichever `taylor`
  comes first on `PATH` runs; both accept the same arguments, but their versions may differ.

The bindings live in [`python/`](python/), a Cargo workspace member built with
[maturin](https://www.maturin.rs/). To build and test them locally:

```sh
cd python
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest cbor2 cryptography
maturin develop
pytest tests
```

The `Wheels` workflow builds wheels for Linux, macOS, and Windows plus an sdist on every
`v*` tag, or when started manually. Publishing is manual: download the workflow artifacts
and upload them with `twine upload` (or `maturin upload`).

## Supported manifest members

Taylor supports these standard `SUIT_Manifest` members from `assets/suit-manifest.cddl`:

| JSON input | CDDL member | CBOR key | Taylor input |
| --- | --- | ---: | --- |
| `version` | `suit-manifest-version` | 1 | Integer; currently expected to be `1` |
| `sequence-number` | `suit-manifest-sequence-number` | 2 | Non-negative integer |
| `suit-common` | `suit-common` | 3 | Object containing the supported common members below |
| `image-validation` | `suit-validate` | 7 | Command-sequence array |
| `suit-load` | `suit-load` | 8 | Command-sequence array |
| `suit-invoke` | `suit-invoke` | 9 | Command-sequence array |
| `payload-fetch` | `suit-payload-fetch` | 16 | Command-sequence array |
| `payload-installation` | `suit-install` | 20 | Command-sequence array |

The `suit-common` object supports these standard members:

| JSON input | CDDL member | CBOR key | Taylor input |
| --- | --- | ---: | --- |
| `suit-components` | `suit-components` | 2 | Array of component identifiers, with each segment supplied as hex text |
| `suit-shared-sequence` | `suit-shared-sequence` | 4 | Command-sequence array |

Taylor also supports this extension manifest member from `assets/suit-manifest-extension.cddl`:

| JSON input | CDDL member | CBOR key | Taylor input |
| --- | --- | ---: | --- |
| `suit-set-version` | `suit-set-version` | 6 | Non-empty array of integers, encoded as `bstr .cbor SUIT_Condition_Version_Comparison_Value` |

## Supported directives

Taylor accepts directives as single-key JSON objects inside a command sequence. The following
directives from `assets/suit-manifest.cddl` are supported:

| JSON directive | CBOR code | Argument accepted by Taylor |
| --- | ---: | --- |
| `suit-directive-set-component-index` | 12 | Non-negative integer component index |
| `suit-directive-try-each` | 15 | Array of command-sequence arrays, optionally ending with `null` |
| `suit-directive-write` | 18 | Reporting-policy integer |
| `suit-directive-override-parameters` | 20 | JSON object of supported parameters |
| `suit-directive-fetch` | 21 | Reporting-policy integer |
| `suit-directive-copy` | 22 | Reporting-policy integer |
| `suit-directive-invoke` | 23 | Reporting-policy integer |
| `suit-directive-swap` | 31 | Reporting-policy integer |
| `suit-directive-run-sequence` | 32 | Nested command-sequence array |

Taylor currently supports no directives from the extension CDDL in
`assets/suit-manifest-extension.cddl`.

### Supported standard conditions

These conditions are defined by `assets/suit-manifest.cddl` and are supported by Taylor:

| JSON condition | CBOR code | Argument accepted by Taylor |
| --- | ---: | --- |
| `suit-condition-vendor-identifier` | 1 | Reporting-policy integer |
| `suit-condition-class-identifier` | 2 | Reporting-policy integer |
| `suit-condition-image-match` | 3 | Reporting-policy integer |
| `suit-condition-component-slot` | 5 | Reporting-policy integer |
| `suit-condition-check-content` | 6 | Reporting-policy integer |
| `suit-condition-abort` | 14 | Reporting-policy integer |
| `suit-condition-device-identifier` | 24 | Reporting-policy integer |

### Supported extension conditions

Taylor supports the following condition from `assets/suit-manifest-extension.cddl`:

| JSON condition | CBOR code | Argument accepted by Taylor |
| --- | ---: | --- |
| `suit-condition-version` | 28 | Reporting-policy integer; Taylor also accepts a convenience object described below |

In the extension CDDL, a version match is a two-element array containing one comparison type and
one non-empty integer vector (`[comparison-type, [+int]]`). In Taylor's JSON input, one version
parameter is written as an object with `comparison` and `value`; `value` is a single version
vector, not a list of alternatives. A single check uses the raw reporting-policy form of
`suit-condition-version`:

```json
[
  {"suit-directive-override-parameters": {
    "version": {"comparison": "equal", "value": [1, 3, 0]}
  }},
  {"suit-condition-version": 15}
]
```

Taylor also accepts a constrained dotted string in a single `value`, for example
`{"comparison": "equal", "value": "1.3.0"}`; integer vectors are the CDDL-shaped input.

To express alternatives, put each override and condition in its own command-sequence array under
`suit-directive-try-each`:

```json
{"suit-directive-try-each": [
  [
    {"suit-directive-override-parameters": {
      "version": {"comparison": "greater", "value": [1, 0, 0]}
    }},
    {"suit-condition-version": 15}
  ],
  [
    {"suit-directive-override-parameters": {
      "version": {"comparison": "equal", "value": [1, 3, 0]}
    }},
    {"suit-condition-version": 15}
  ],
  [
    {"suit-directive-override-parameters": {
      "version": {"comparison": "lesser", "value": [2, 0, 0]}
    }},
    {"suit-condition-version": 15}
  ]
]}
```

Each branch is attempted in order. A condition failure advances to the next branch; the first
branch that completes without condition failure ends `try-each`. Thus the branch count is the
maximum number of checks, not a count of checks that always run. The comparison names are
`greater`, `greater-equal`, `equal`, `lesser-equal`, and `lesser`.

Taylor also accepts a convenience shorthand on `suit-condition-version`: an object with
`comparison`, `versions`, and optional `policy` fields. Taylor expands each listed vector into its
own override/condition branch using the same comparison; this shorthand is not the CDDL form:

```json
{"suit-condition-version": {
  "comparison": "equal",
  "versions": [[1, 0, 0], [1, 3, 0]],
  "policy": 15
}}
```

The adjacent-parameter shorthand also accepts multiple candidates under `version.versions`
(or the legacy `version.value` alias), followed by a raw version condition:

```json
[
  {"suit-directive-override-parameters": {
    "version": {
      "comparison": "equal",
      "versions": [[1, 0, 0], [1, 3, 0]]
    }
  }},
  {"suit-condition-version": 15}
]
```

The condition shorthand likewise accepts the legacy `value` candidate-list spelling:

```json
{"suit-condition-version": {
  "comparison": "equal",
  "value": ["1.0.0", "1.3.0"]
}}
```

Taylor accepts constrained dotted strings in single values and candidate lists, converting them to
integer vectors. This is not unrestricted Semantic Versioning: the machine-readable version
constraints are defined by the update-management draft.

## How to add fields

 - Add the structure into the manifest.rs file
   - for a new `SuitManifest` or `SuitCommon` field, also set its default in the type's `new`
     constructor
 - Implement parsing in parse.rs,
   - start with adding to parse fn and if necessary add helper function
   - add to return value
 - Implement serde::Serialize Trait in encode.rs

## Testing

```sh
cargo test
```

Runs the unit tests, all doc-tests, and these integration tests:

- [`tests/manifest_encoding.rs`](tests/manifest_encoding.rs): compares the CBOR generated for
  each example manifest that has a fixture in `tests/golden/` with that fixture, and checks the
  decoded structure. After confirming that an output change is intended and spec-conformant,
  regenerate the fixtures with `UPDATE_GOLDEN=1 cargo test`.
- [`tests/library_api.rs`](tests/library_api.rs): exercises the public library API without
  running the binary.
- [`tests/signing.rs`](tests/signing.rs): runs the built binary and independently verifies the
  resulting `COSE_Sign1` signatures.
- [`tests/templating.rs`](tests/templating.rs): runs the built binary with `--template`,
  `--var`, `--vars-file`, and `--render-only`, including the trevm example.
- [`tests/cli_validation.rs`](tests/cli_validation.rs): checks that invalid invocations exit
  with code 2 and runtime failures exit with code 1.

The Python package has its own tests in [`python/tests/`](python/tests/), which compare its
output with the same golden fixtures and verify signatures with the `cryptography` package.
Each test's docstring describes what it verifies and is copied into JUnit XML reports as a
`description` property, so a test report can be generated with:

```sh
cd python
pytest tests --junitxml=test-report.xml
```

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
