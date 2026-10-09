# Changelog


## 0.1.1 - 2026-10-09

- Added trevm example and tests
- Updated to brody 0.1.1 for the cose detached payload fix (see brody 0.1.1 changelog)
- Updated tests about signing

## 0.1.0 - 2026-09-21

- Initial implementation

## Unreleased

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
