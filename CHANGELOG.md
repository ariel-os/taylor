# Changelog

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
