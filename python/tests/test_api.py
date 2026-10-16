"""Tests for the taylor Python API, cross-checked against the Rust golden fixtures."""

import json
import math
import pathlib
import pickle

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import taylor

REPO = pathlib.Path(__file__).resolve().parents[2]
MANIFESTS = REPO / "examples" / "input" / "manifests"
GOLDEN = REPO / "tests" / "golden"
KEYS = REPO / "examples" / "input" / "keys"
PRIVATE_KEY = KEYS / "demo-private-key.pem"
PUBLIC_KEY = KEYS / "demo-public-key-p256.pem"
TEMPLATES = REPO / "examples" / "input" / "templates"

GOLDEN_CASES = sorted(p.stem for p in GOLDEN.glob("*.hex"))
assert GOLDEN_CASES, f"no golden fixtures found in {GOLDEN}"


def golden_bytes(name: str) -> bytes:
    return bytes.fromhex((GOLDEN / f"{name}.hex").read_text().strip())


def manifest_text(name: str) -> str:
    return (MANIFESTS / f"{name}.json").read_text()


def auth_elements(envelope: bytes) -> list:
    decoded = cbor2.loads(envelope)
    assert decoded.tag == 107
    return cbor2.loads(decoded.value[2])


def assert_valid_es256(envelope: bytes) -> None:
    public_key = serialization.load_pem_public_key(PUBLIC_KEY.read_bytes())
    assert_valid_signature(envelope, public_key, hashes.SHA256(), coordinate_size=32)


def assert_valid_signature(envelope: bytes, public_key, hash_algorithm, coordinate_size: int) -> None:
    elements = auth_elements(envelope)
    assert len(elements) == 2, "signed envelope must carry the digest plus one COSE_Sign1"
    digest_bstr = elements[0]
    cose = cbor2.loads(elements[1])
    assert cose.tag == 18
    protected, _unprotected, payload, signature = cose.value
    assert payload is None, "COSE_Sign1 payload must be detached"
    # Independently rebuild the COSE Sig_structure that brody signs over.
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", digest_bstr])
    r = int.from_bytes(signature[:coordinate_size], "big")
    s = int.from_bytes(signature[coordinate_size:], "big")
    public_key.verify(encode_dss_signature(r, s), to_be_signed, ec.ECDSA(hash_algorithm))


@pytest.mark.parametrize("name", GOLDEN_CASES)
def test_unsigned_envelope_matches_rust_golden_fixture(name):
    """The unsigned envelope for each example manifest is byte-identical to the Rust golden fixture."""
    assert taylor.build_envelope(manifest_text(name)) == golden_bytes(name)


def test_mapping_and_json_text_produce_identical_output():
    """A manifest given as a mapping encodes to the same bytes as the same manifest given as JSON text."""
    text = manifest_text("test")
    assert taylor.build_envelope(json.loads(text)) == taylor.build_envelope(text)
    assert taylor.encode_manifest(json.loads(text)) == taylor.encode_manifest(text)


def test_encode_manifest_is_the_envelope_manifest_member():
    """encode_manifest returns exactly the bstr-wrapped manifest stored in the envelope under key 3."""
    text = manifest_text("test")
    envelope = cbor2.loads(taylor.build_envelope(text))
    assert cbor2.dumps(envelope.value[3]) == taylor.encode_manifest(text)


@pytest.mark.parametrize("key_kind", ["pem_str", "pem_bytes", "path_str", "path"])
def test_signed_envelope_verifies_with_the_public_key(key_kind):
    """An envelope signed with the demo ES256 key verifies with its public key and keeps the manifest unchanged.

    The key is passed as PEM text, PEM bytes, a path string, or a ``pathlib.Path``. The
    COSE_Sign1 signature is checked independently with the ``cryptography`` package.
    """
    pem = PRIVATE_KEY.read_text()
    key_args = {
        "pem_str": {"key_pem": pem},
        "pem_bytes": {"key_pem": pem.encode()},
        "path_str": {"key_path": str(PRIVATE_KEY)},
        "path": {"key_path": PRIVATE_KEY},
    }[key_kind]
    envelope = taylor.build_envelope(manifest_text("test"), **key_args)
    assert_valid_es256(envelope)
    unsigned = cbor2.loads(golden_bytes("test"))
    assert cbor2.loads(envelope).value[3] == unsigned.value[3], "signing must not alter the manifest"


def test_passing_both_key_forms_is_rejected():
    """Passing both key_pem and key_path raises ValueError instead of picking one."""
    with pytest.raises(ValueError):
        taylor.build_envelope(manifest_text("test"), key_pem="x", key_path=PRIVATE_KEY)


def test_es384_key_produces_a_valid_signature():
    """A P-384 key produces an ES384 COSE_Sign1 signature that verifies with SHA-384."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    envelope = taylor.build_envelope(manifest_text("test"), key_pem=pem)
    assert_valid_signature(envelope, private_key.public_key(), hashes.SHA384(), coordinate_size=48)


def test_non_ascii_key_bytes_raise_signing_error():
    """Key bytes that aren't ASCII PEM raise SigningError rather than UnicodeDecodeError."""
    with pytest.raises(taylor.SigningError):
        taylor.build_envelope(manifest_text("test"), key_pem=b"\xff")


def test_trevm_template_matches_cli_render_only(capfd):
    """render_template output for the trevm example equals the CLI's --render-only output."""
    template = TEMPLATES / "trevm" / "manifest-trevm.jinja"
    vars_file = TEMPLATES / "trevm" / "vars-trevm.json"
    rendered = taylor.render_template(template, vars_file=vars_file)
    exit_code = taylor._taylor.run_cli(
        ["taylor", "--template", str(template), "--vars-file", str(vars_file), "--render-only"]
    )
    assert exit_code == 0
    assert capfd.readouterr().out == rendered + "\n"


def test_template_variables_override_the_vars_file():
    """Variables passed to render_template take precedence over the same keys in the vars file."""
    template = TEMPLATES / "trevm" / "manifest-trevm.jinja"
    vars_file = TEMPLATES / "trevm" / "vars-trevm.json"
    rendered = taylor.render_template(template, {"sequence_number": 42}, vars_file=vars_file)
    assert json.loads(rendered)["sequence-number"] == 42


@pytest.mark.parametrize(
    "call, error",
    [
        (lambda: taylor.build_envelope("{"), taylor.ManifestError),
        (lambda: taylor.build_envelope('{"version": 1}'), taylor.ManifestError),
        (lambda: taylor.build_envelope(manifest_text("test"), key_pem="not a key"), taylor.SigningError),
        (lambda: taylor.build_envelope(manifest_text("test"), key_path="missing.pem"), taylor.SigningError),
        (lambda: taylor.render_template(TEMPLATES / "manifest.jinja"), taylor.TemplateError),
        (lambda: taylor.render_template("missing.jinja"), taylor.TemplateError),
        (lambda: taylor.encode_manifest("{"), taylor.ManifestError),
        (lambda: taylor.build_envelope({"version": b"1"}), taylor.ManifestError),
        (lambda: taylor.build_envelope({"version": math.nan}), taylor.ManifestError),
        (lambda: taylor.render_template(TEMPLATES / "manifest.jinja", {"x": object()}), taylor.TemplateError),
    ],
    ids=[
        "invalid-json",
        "missing-member",
        "bad-pem",
        "missing-key-file",
        "missing-variables",
        "missing-template",
        "encode-invalid-json",
        "unserializable-manifest",
        "nan-in-manifest",
        "unserializable-variable",
    ],
)
def test_bad_input_raises_specific_taylor_errors(call, error):
    """Each kind of invalid input raises its specific exception, which is a subclass of TaylorError."""
    with pytest.raises(error) as excinfo:
        call()
    assert isinstance(excinfo.value, taylor.TaylorError)


def test_parse_error_names_the_failing_parameter_and_sequence():
    """A parse error names the unsupported value, the parameter, and the sequence it appears in."""
    manifest = json.loads(manifest_text("test"))
    manifest["suit-common"]["suit-shared-sequence"].insert(
        0,
        {"suit-directive-override-parameters": {"image-digest": {"algorithm": "md5", "digest": "00"}}},
    )
    with pytest.raises(taylor.ManifestError, match="md5 for image-digest in suit-shared-sequence"):
        taylor.build_envelope(manifest)


def test_non_manifest_type_is_rejected():
    """A manifest that is neither JSON text nor a mapping raises TypeError."""
    with pytest.raises(TypeError):
        taylor.build_envelope(42)


def test_vars_file_that_is_not_json_raises_template_error(tmp_path):
    """A vars file that isn't valid JSON raises TemplateError."""
    vars_file = tmp_path / "vars.json"
    vars_file.write_text("not json")
    with pytest.raises(taylor.TemplateError):
        taylor.render_template(TEMPLATES / "manifest.jinja", vars_file=vars_file)


@pytest.mark.parametrize("error", [taylor.TaylorError, taylor.ManifestError, taylor.SigningError])
def test_exceptions_survive_pickling(error):
    """taylor exceptions keep their type and message through pickling, e.g. across processes."""
    restored = pickle.loads(pickle.dumps(error("boom")))
    assert type(restored) is error
    assert str(restored) == "boom"
