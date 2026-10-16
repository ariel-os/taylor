# taylor-suit

Python bindings for [taylor](https://github.com/ariel-os/taylor), which generates
[IETF SUIT](https://www.rfc-editor.org/rfc/rfc9736) manifests, CBOR-encoded, from a JSON
description. The package is imported as `taylor` and also installs a `taylor` command that
behaves like the Rust CLI.

```sh
pip install taylor-suit
```

```python
import taylor

manifest = {
    "version": 1,
    "sequence-number": 1,
    "suit-common": {"suit-components": [["00"]], "suit-shared-sequence": []},
}
unsigned = taylor.build_envelope(manifest)
signed = taylor.build_envelope(manifest, key_path="key.pem")
```

- `build_envelope` and `encode_manifest` accept the manifest as JSON text or as a mapping.
- Signing keys are PEM-encoded ES256 or ES384 private keys, given either as text or bytes
  (`key_pem`) or as a file path (`key_path`).
- `manifest_digest="sha384"` makes the manifest digest that the signature covers SHA-384
  instead of the default SHA-256.
- `render_template` renders a minijinja template into manifest JSON.
- Errors are raised as `taylor.ManifestError`, `taylor.TemplateError`, or
  `taylor.SigningError`, all subclasses of `taylor.TaylorError`.

If the Rust binary is also installed with `cargo install taylor`, whichever `taylor` comes
first on `PATH` runs; both accept the same arguments, but their versions may differ.

See the [project README](https://github.com/ariel-os/taylor#readme) for the JSON manifest
format and the supported SUIT members, directives, and conditions.
