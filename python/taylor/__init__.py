"""Generate IETF SUIT manifests, CBOR-encoded, from a JSON description.

Python bindings for the `taylor` Rust crate.
"""

from __future__ import annotations

import json
import os
from typing import Any, Mapping, Optional, Union

from . import _taylor
from ._taylor import ManifestError, SigningError, TaylorError, TemplateError

__version__: str = _taylor.__version__

__all__ = [
    "ManifestError",
    "SigningError",
    "TaylorError",
    "TemplateError",
    "build_envelope",
    "encode_manifest",
    "render_template",
]

Manifest = Union[str, Mapping[str, Any]]
"""A JSON manifest description, as JSON text or as an already-decoded mapping."""

StrPath = Union[str, "os.PathLike[str]"]


def _manifest_json(manifest: Manifest) -> str:
    if isinstance(manifest, str):
        return manifest
    if isinstance(manifest, Mapping):
        try:
            return json.dumps(manifest, allow_nan=False)
        except (TypeError, ValueError) as e:
            raise ManifestError(f"manifest can't be encoded as JSON: {e}") from e
    raise TypeError(f"manifest must be a str or a mapping, not {type(manifest).__name__}")


def encode_manifest(manifest: Manifest) -> bytes:
    """Encode a manifest as a bstr-wrapped ``SUIT_Manifest``.

    Raises:
        ManifestError: if the manifest is malformed or unsupported.
    """
    return _taylor.encode_manifest(_manifest_json(manifest))


def build_envelope(
    manifest: Manifest,
    *,
    key_pem: Optional[Union[str, bytes]] = None,
    key_path: Optional[StrPath] = None,
) -> bytes:
    """Encode a manifest as a tag-107 ``SUIT_Envelope``.

    The envelope is signed with a ``COSE_Sign1`` block when a PEM-encoded ES256 or ES384
    private key is given, either as ``key_pem`` or as a file path in ``key_path``.

    Raises:
        ValueError: if both ``key_pem`` and ``key_path`` are given.
        ManifestError: if the manifest is malformed or unsupported.
        SigningError: if the key can't be read or loaded.
    """
    if isinstance(key_pem, bytes):
        try:
            key_pem = key_pem.decode("ascii")
        except UnicodeDecodeError as e:
            raise SigningError(f"invalid signing key: {e}") from e
    return _taylor.build_envelope(_manifest_json(manifest), key_pem, key_path)


def render_template(
    template_path: StrPath,
    variables: Optional[Mapping[str, Any]] = None,
    *,
    vars_file: Optional[StrPath] = None,
) -> str:
    """Render a minijinja template into manifest JSON.

    ``variables`` override keys of the same name from the JSON object in ``vars_file``.

    Raises:
        TemplateError: if the template or vars file can't be read or rendered, or the
            template references a variable that wasn't supplied.
    """
    if variables is None:
        variables_json = None
    else:
        try:
            variables_json = json.dumps(dict(variables), allow_nan=False)
        except (TypeError, ValueError) as e:
            raise TemplateError(f"template variables can't be encoded as JSON: {e}") from e
    return _taylor.render_template(template_path, variables_json, vars_file)
