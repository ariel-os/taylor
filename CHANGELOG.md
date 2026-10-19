# Changelog


## 0.2.2 - 2026-10-19

- Added `--manifest-digest sha256|sha384` to choose the hash algorithm of the manifest
  digest that the signature covers; the default stays `sha256`. The library gains
  `taylor::envelope::DigestAlgorithm` and `build_envelope_with_digest`, and the Python
  `build_envelope` gains a `manifest_digest` argument.
- Replaced the `sha256` dependency with `sha2`, which was already in the dependency tree.

## 0.2.1 - 2026-10-16

- Added the `taylor-suit` Python package (imported as `taylor`), built with PyO3 and
  maturin from the new `python/` workspace member. It provides `encode_manifest`,
  `build_envelope` (signing with `key_pem` or `key_path`), `render_template`, the
  `taylor` command, and the exceptions `TaylorError`, `ManifestError`, `TemplateError`,
  and `SigningError`.
- Fixed `taylor::cli::run` panicking when a write to stdout fails, for example on a
  closed pipe; it now returns exit code 1. Failed writes to stderr are ignored.
- CI now builds and tests the Python package on Python 3.9 and 3.13, and a new `wheels`
  workflow builds release wheels and an sdist, then installs and tests the wheels on
  Linux, macOS, and Windows.
- The `taylor` crate and the `taylor-suit` Python package now share one version, set in
  `[workspace.package]` in `Cargo.toml`. The `wheels` workflow fails if a release tag
  doesn't match it.

## 0.2.0 - 2026-10-14

- Added support for the optional SUIT extension manifest member
  `suit-set-version` (CBOR key `6`), including JSON parsing and CBOR encoding.
  **Breaking:** `SuitManifest` has a new public field, `suit_set_version`.
- Added `taylor::envelope::build_envelope`, which encodes a parsed manifest into a
  complete, optionally signed, `SUIT_Envelope`. It returns
  `Error::UnsupportedAlgorithm` instead of panicking when a hand-built manifest uses an
  unsupported digest algorithm; `encode_manifest` and `encode_envelope` document that
  they panic in that case.
- Added `taylor::sign::sign_envelope_with_pem` for signing with a PEM key held in memory,
  and re-exported `brody::Signer` as `taylor::sign::Signer`.
- Added `taylor::cli::run`, which runs the command-line interface in-process and returns
  its exit code.
- `taylor::parse::parse` now returns an error instead of panicking on malformed input,
  and rejects image digest algorithms other than `sha256`, `sha384`, and `sha512`.
  Parse errors now name the failing command, parameter, or algorithm and the sequence
  it appears in, instead of a generic "Invalid shared sequence" message.
- **Breaking:** `taylor::parse::parse` now rejects input it used to silently misread:
  a command object with more than one key (previously only one key was kept), and a
  `suit-condition-version` `policy` that isn't a non-negative integer (previously
  replaced by `15`).
- Added the `InvalidJson` and `Signing` variants to `taylor::error::Error`.
  **Breaking:** because they wrap `serde_json::Error` and `brody::Error`,
  `taylor::error::Error` is no longer `UnwindSafe` or `RefUnwindSafe`.
- **Breaking:** `taylor::error::Error` and `taylor::template::Error` are now
  `#[non_exhaustive]`.
- **Breaking:** `SuitManifest`, `SuitCommon`, `SuitCommandEnum`,
  `SuitCommandSequenceEnum`, and `SuitParametersEnum` are now `#[non_exhaustive]`, so
  future SUIT members, commands, phases, and parameters can be added in minor releases.
  Build `SuitManifest` and `SuitCommon` with the new `new` constructors, and add a
  wildcard arm when matching on these enums.
- Added a `cargo-semver-checks` CI job that checks the public API against the latest
  release on crates.io.
- **Breaking:** the CLI now exits with code 1 and an error message on runtime failures,
  instead of panicking with code 101. Usage errors still exit with code 2.

## 0.1.1 - 2026-10-09

- Added trevm example and tests
- Updated to brody 0.1.1 for the cose detached payload fix (see brody 0.1.1 changelog)
- Updated tests about signing

## 0.1.0 - 2026-09-21

- Initial implementation
- Fixed `SuitDigest` to encode/decode raw bytes instead of hex strings.
- Overhauled parameter types across `SuitParametersEnum` for CDDL correctness.
- Encoded component identifiers as raw bytes and unwrapped `suit-components`.
- Reworked command/sequence encoding to a flat-array architecture
  (`SuitCommandEnum`, `FlatSequence`, `MergedParams`, `TryEachArg`).
- Added a recursive command-sequence JSON parser, including `try-each` and
  `run-sequence` support.
- Migrated `examples/test.json` to the new array-based schema.
- Added `examples/prep-manifest.json` fixture (wrapped key / MAC / secure-boot
  manifest blocks).
- Added `-o`/`--output <dir>` CLI flag to write the generated CBOR envelope to
  a file.
- Verified full CDDL conformance of generated output against the official
  SUIT manifest CDDL (`suit-manifest.cddl`) using the `cddl` validator.
- Made the top-level `sequence` manifest key optional, defaulting to no phase
  sequences (`suit-validate`/`suit-load`/`suit-invoke`/`suit-payload-fetch`/
  `suit-install` are all `?`-optional per CDDL); fixed a copy-pasted error
  message on the `suit-common` lookup.
- Added `-k`/`--key <PEM_FILE>` CLI flag to sign the generated envelope with a
  `COSE_Sign1` authentication block, via the new `brody` dependency (ES256/ES384,
  PEM PKCS8/SEC1 keys). Removed the unimplemented `sign` module stub.
- Added integration tests (`tests/signing.rs`) that run the built binary and
  independently re-verify the ES256/ES384 `COSE_Sign1` signatures, the unsigned
  digest-only path, and that signing never alters the manifest/digest bytes.
- Added a GitHub Actions CI workflow (`.github/workflows/ci.yml`) running
  `cargo build`/`cargo test` on every push and pull request.
- Added runnable doc examples (doctests) to `parse::parse`, `encode::encode_manifest`,
  `encode::encode_envelope`, and the crate root; `cargo doc --no-deps` excludes
  dependency documentation.
- Added `templates/manifest.json.jinja`, a `minijinja` template for the manifest JSON,
  and a runnable example (`examples/render_template.rs`) rendering it end-to-end into
  an unsigned CBOR envelope.
- Generalized `parse::parse` to accept any `std::io::Read`, not just a `BufReader<File>`.
- Added a `taylor::template` module (`parse_var`, `build_context`, `render`) for
  rendering a `minijinja` template into manifest JSON from a variable context, failing
  fast with a clear error if the template references a variable that wasn't supplied.
- Added `--template <PATH>`, `--var KEY=VALUE`, `--vars-file <PATH>`, and
  `--render-only` CLI flags so a template path and its variables can be supplied on the
  command line (e.g. from CI), for build-pipeline integration.
- Added integration tests (`tests/templating.rs`) covering byte-identical output
  between the templated and direct-JSON paths, `--vars-file`/`--var` override
  precedence, missing-variable and malformed-`--var` failure modes, and rejection of
  `--var`/`--vars-file`/`--render-only` without `--template`.
