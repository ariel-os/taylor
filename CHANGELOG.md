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
- Made the top-level `sequence` manifest key optional, defaulting to no phase
  sequences (`suit-validate`/`suit-load`/`suit-invoke`/`suit-payload-fetch`/
  `suit-install` are all `?`-optional per CDDL); fixed a copy-pasted error
  message on the `suit-common` lookup.
