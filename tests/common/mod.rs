//! Shared fixtures and helpers for `taylor`'s integration tests.
//!
//! This lives at `tests/common/mod.rs` (not `tests/common.rs`) so cargo treats it as a shared
//! module included by other test files via `mod common;`, rather than compiling it as its own
//! (empty) test binary.
//!
//! Not every consuming test file uses every helper below, so unused-item warnings are silenced
//! wholesale rather than per-item.
#![allow(dead_code)]

use ciborium::value::{Integer, Value as CborValue};
use p256::pkcs8::DecodePrivateKey as _;
use signature::Verifier as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Throwaway P-256 test key (PKCS8 PEM), generated solely for these tests via:
/// `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
pub const ES256_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIGiK10T2DJEwqIOE
8XkajPi9ZNGcgjaj8g/CBXJLEQ6hRANCAARf28DDbnSxAW/ojnCy9ilaBwuFqHEW
j3Mhq0ZdNGiyWrDruCZ5n5JfJsy9ae5zxsg4OmQa8e1w4IkL143PSLrx
-----END PRIVATE KEY-----";

/// Throwaway P-384 test key (PKCS8 PEM), generated solely for these tests via:
/// `openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
pub const ES384_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB06BrL2QfHEVxkG/oS
NoBUUH0RfYPvmOfXz66ZDBJEklNUsTzPAZlmsqQtdol/79yhZANiAASgxNuFj5Gw
IFukhPlStPwtisQ1qXo/2x5B3Pacxi4fKhp8D8lzBXJn274FrpcHdbduVoT0Pk+v
WVXSPaD4dVTzZl7m2QgcGhF/GpL66cZUbVeTD3KJyMv2l24DeRbuVPI=
-----END PRIVATE KEY-----";

/// The crate root, so tests work regardless of the working directory `cargo test` uses.
pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Path to the checked-in reference manifest (`examples/input/test.json`).
pub fn json_path() -> PathBuf {
    manifest_dir().join("examples/input/test.json")
}

/// Path to the checked-in Jinja template (`templates/manifest.jinja`).
pub fn template_path() -> PathBuf {
    manifest_dir().join("templates/manifest.jinja")
}

/// The full set of `--var KEY=VALUE` CLI args that render `templates/manifest.jinja` into
/// exactly `examples/input/test.json`'s content. Kept alongside [`matching_template_context`] so the
/// CLI-flag and library-context representations of the same values can't silently drift apart.
pub const MATCHING_VAR_ARGS: &[&str] = &[
    "--var",
    "sequence_number=1",
    "--var",
    "vendor_id=67e55044-10b1-426f-9247-bb680e5fe0c8",
    "--var",
    "class_id=69e55044-10b1-426f-2974-bb680e5fedc8",
    "--var",
    "image_size=1024",
    "--var",
    "digest=c12efb651dc800465d80264343852c304c4dcea2da82828d8824df7638628d17",
    "--var",
    "uri=https://example.com/firmware.bin",
];

/// The same values as [`MATCHING_VAR_ARGS`], as a `serde_json` context for rendering
/// `templates/manifest.jinja` directly through [`taylor::template::render`].
pub fn matching_template_context() -> serde_json::Value {
    serde_json::json!({
        "sequence_number": 1,
        "vendor_id": "67e55044-10b1-426f-9247-bb680e5fe0c8",
        "class_id": "69e55044-10b1-426f-2974-bb680e5fedc8",
        "image_size": 1024,
        "digest": "c12efb651dc800465d80264343852c304c4dcea2da82828d8824df7638628d17",
        "uri": "https://example.com/firmware.bin",
    })
}

/// A scratch directory dedicated to one test (by name), so parallel `cargo test` runs never
/// collide on the same output files.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("taylor-test-{name}"));
    fs::create_dir_all(&dir).expect("failed to create scratch dir");
    dir
}

/// Writes `pem` to `<dir>/key.pem` and returns its path.
pub fn write_key_file(dir: &Path, pem: &str) -> PathBuf {
    let path = dir.join("key.pem");
    fs::write(&path, pem).expect("failed to write test key file");
    path
}

/// Runs the compiled `taylor` binary with `args`, capturing its exit status and output.
pub fn run_taylor(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_taylor"))
        .args(args)
        .output()
        .expect("failed to spawn taylor binary")
}

pub fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Reads `out_dir/file_name`, panicking with a clear message if it's missing.
pub fn read_output_file(out_dir: &Path, file_name: &str) -> Vec<u8> {
    fs::read(out_dir.join(file_name))
        .unwrap_or_else(|e| panic!("failed to read {out_dir:?}/{file_name}: {e}"))
}

// --- SUIT_Envelope / COSE_Sign1 CBOR inspection, shared by every test that checks signing. ---

/// Unwraps the tag-107 `SUIT_Envelope` map.
pub fn envelope_map(bytes: &[u8]) -> Vec<(CborValue, CborValue)> {
    let value: CborValue = ciborium::de::from_reader(bytes).expect("output is not valid CBOR");
    match value {
        CborValue::Tag(107, inner) => match *inner {
            CborValue::Map(m) => m,
            other => panic!("expected a map inside tag 107, got {other:?}"),
        },
        other => panic!("expected tag-107 SUIT_Envelope, got {other:?}"),
    }
}

pub fn map_get_bytes(map: &[(CborValue, CborValue)], key: i64) -> Vec<u8> {
    map.iter()
        .find(|(k, _)| *k == CborValue::Integer(Integer::from(key)))
        .map(|(_, v)| match v {
            CborValue::Bytes(b) => b.clone(),
            other => panic!("key {key} is not a bstr, got {other:?}"),
        })
        .unwrap_or_else(|| panic!("missing key {key} in SUIT_Envelope map"))
}

/// Decodes the `suit-authentication-wrapper` (key 2) bstr into its array elements.
pub fn auth_wrapper_elements(envelope_bytes: &[u8]) -> Vec<CborValue> {
    let auth_bytes = map_get_bytes(&envelope_map(envelope_bytes), 2);
    match ciborium::de::from_reader::<CborValue, _>(auth_bytes.as_slice()).unwrap() {
        CborValue::Array(elements) => elements,
        other => panic!("SUIT_Authentication is not an array, got {other:?}"),
    }
}

pub fn as_bytes(value: &CborValue) -> &[u8] {
    match value {
        CborValue::Bytes(b) => b,
        other => panic!("expected a bstr, got {other:?}"),
    }
}

/// Decodes a `bstr`-wrapped, tag-18 `COSE_Sign1` block into (protected, unprotected map,
/// payload, signature).
pub fn decode_cose_sign1(
    block: &CborValue,
) -> (Vec<u8>, Vec<(CborValue, CborValue)>, Vec<u8>, Vec<u8>) {
    let inner: CborValue = ciborium::de::from_reader(as_bytes(block)).unwrap();
    let array = match inner {
        CborValue::Tag(18, boxed) => match *boxed {
            CborValue::Array(a) => a,
            other => panic!("expected array inside tag 18, got {other:?}"),
        },
        other => panic!("expected tag-18 COSE_Sign1_Tagged, got {other:?}"),
    };
    assert_eq!(array.len(), 4, "COSE_Sign1 must have exactly 4 elements");
    let protected = as_bytes(&array[0]).to_vec();
    let unprotected = match &array[1] {
        CborValue::Map(m) => m.clone(),
        other => panic!("expected a map for the unprotected header, got {other:?}"),
    };
    let payload = as_bytes(&array[2]).to_vec();
    let signature = as_bytes(&array[3]).to_vec();
    (protected, unprotected, payload, signature)
}

pub fn protected_alg(protected: &[u8]) -> i64 {
    match ciborium::de::from_reader::<CborValue, _>(protected).unwrap() {
        CborValue::Map(m) if m.len() == 1 => match (&m[0].0, &m[0].1) {
            (CborValue::Integer(k), CborValue::Integer(alg)) if i64::try_from(*k) == Ok(1) => {
                i64::try_from(*alg).expect("alg id must fit in i64")
            }
            other => panic!("unexpected protected header entry: {other:?}"),
        },
        other => panic!("expected a 1-entry protected header map, got {other:?}"),
    }
}

/// Rebuilds the COSE `Sig_structure` ("Signature1") that `brody` signs over.
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&structure, &mut out).unwrap();
    out
}

/// Independently verifies (via `p256`, not `brody`) that `signature` is a valid ES256 signature
/// by [`ES256_TEST_KEY_PEM`] over `Sig_structure(protected, payload)`.
pub fn assert_valid_es256_signature(protected: &[u8], payload: &[u8], signature: &[u8]) {
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(ES256_TEST_KEY_PEM).unwrap();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let sig = p256::ecdsa::Signature::from_slice(signature).expect("malformed ES256 signature");
    verifying_key
        .verify(&sig_structure(protected, payload), &sig)
        .expect("ES256 signature must verify against the recomputed Sig_structure");
}

/// Independently verifies (via `p384`, not `brody`) that `signature` is a valid ES384 signature
/// by [`ES384_TEST_KEY_PEM`] over `Sig_structure(protected, payload)`.
pub fn assert_valid_es384_signature(protected: &[u8], payload: &[u8], signature: &[u8]) {
    use p384::pkcs8::DecodePrivateKey as _;

    let signing_key = p384::ecdsa::SigningKey::from_pkcs8_pem(ES384_TEST_KEY_PEM).unwrap();
    let verifying_key = p384::ecdsa::VerifyingKey::from(&signing_key);
    let sig = p384::ecdsa::Signature::from_slice(signature).expect("malformed ES384 signature");
    verifying_key
        .verify(&sig_structure(protected, payload), &sig)
        .expect("ES384 signature must verify against the recomputed Sig_structure");
}
