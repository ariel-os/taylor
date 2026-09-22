//! Integration tests for the `taylor` CLI's `-k`/`--key` signing flag.
//!
//! These spawn the compiled `taylor` binary end-to-end against `examples/test.json` and
//! independently re-derive/verify the resulting `COSE_Sign1` block using `p256`/`p384`
//! directly (not via `brody`'s own API), so a regression in either `taylor`'s wiring or in
//! the `brody` dependency itself would be caught.

use ciborium::value::{Integer, Value};
use p256::pkcs8::DecodePrivateKey as _;
use signature::Verifier as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// Throwaway P-256 test key (PKCS8 PEM), generated solely for these tests via:
// `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
const ES256_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIGiK10T2DJEwqIOE
8XkajPi9ZNGcgjaj8g/CBXJLEQ6hRANCAARf28DDbnSxAW/ojnCy9ilaBwuFqHEW
j3Mhq0ZdNGiyWrDruCZ5n5JfJsy9ae5zxsg4OmQa8e1w4IkL143PSLrx
-----END PRIVATE KEY-----";

// Throwaway P-384 test key (PKCS8 PEM), generated solely for these tests via:
// `openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
const ES384_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB06BrL2QfHEVxkG/oS
NoBUUH0RfYPvmOfXz66ZDBJEklNUsTzPAZlmsqQtdol/79yhZANiAASgxNuFj5Gw
IFukhPlStPwtisQ1qXo/2x5B3Pacxi4fKhp8D8lzBXJn274FrpcHdbduVoT0Pk+v
WVXSPaD4dVTzZl7m2QgcGhF/GpL66cZUbVeTD3KJyMv2l24DeRbuVPI=
-----END PRIVATE KEY-----";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A scratch directory dedicated to one test, so parallel `cargo test` runs never collide.
fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("taylor-signing-test-{name}"));
    fs::create_dir_all(&dir).expect("failed to create scratch dir");
    dir
}

fn write_key_file(dir: &Path, pem: &str) -> PathBuf {
    let path = dir.join("key.pem");
    fs::write(&path, pem).expect("failed to write test key file");
    path
}

/// Runs the built `taylor` binary against `examples/test.json`, returning `(success, cbor)`.
/// `cbor` is empty when the process failed.
fn run_taylor(extra_args: &[&str], scratch: &Path) -> (bool, Vec<u8>) {
    let json_path = manifest_dir().join("examples/test.json");
    let out_dir = scratch.join("out");

    let status = Command::new(env!("CARGO_BIN_EXE_taylor"))
        .arg(&json_path)
        .args(extra_args)
        .arg("--output")
        .arg(&out_dir)
        .status()
        .expect("failed to spawn taylor binary");

    if !status.success() {
        return (false, Vec::new());
    }
    let cbor = fs::read(out_dir.join("test.cbor")).expect("taylor did not write output CBOR");
    (true, cbor)
}

/// Unwraps the tag-107 `SUIT_Envelope` map.
fn envelope_map(bytes: &[u8]) -> Vec<(Value, Value)> {
    let value: Value = ciborium::de::from_reader(bytes).expect("output is not valid CBOR");
    match value {
        Value::Tag(107, inner) => match *inner {
            Value::Map(m) => m,
            other => panic!("expected a map inside tag 107, got {other:?}"),
        },
        other => panic!("expected tag-107 SUIT_Envelope, got {other:?}"),
    }
}

fn map_get_bytes(map: &[(Value, Value)], key: i64) -> Vec<u8> {
    map.iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(key)))
        .map(|(_, v)| match v {
            Value::Bytes(b) => b.clone(),
            other => panic!("key {key} is not a bstr, got {other:?}"),
        })
        .unwrap_or_else(|| panic!("missing key {key} in SUIT_Envelope map"))
}

/// Decodes the `suit-authentication-wrapper` (key 2) bstr into its array elements.
fn auth_wrapper_elements(envelope_bytes: &[u8]) -> Vec<Value> {
    let auth_bytes = map_get_bytes(&envelope_map(envelope_bytes), 2);
    match ciborium::de::from_reader::<Value, _>(auth_bytes.as_slice()).unwrap() {
        Value::Array(elements) => elements,
        other => panic!("SUIT_Authentication is not an array, got {other:?}"),
    }
}

fn as_bytes(value: &Value) -> &[u8] {
    match value {
        Value::Bytes(b) => b,
        other => panic!("expected a bstr, got {other:?}"),
    }
}

/// Decodes a `bstr`-wrapped, tag-18 `COSE_Sign1` block into (protected, unprotected map,
/// payload, signature).
fn decode_cose_sign1(block: &Value) -> (Vec<u8>, Vec<(Value, Value)>, Vec<u8>, Vec<u8>) {
    let inner: Value = ciborium::de::from_reader(as_bytes(block)).unwrap();
    let array = match inner {
        Value::Tag(18, boxed) => match *boxed {
            Value::Array(a) => a,
            other => panic!("expected array inside tag 18, got {other:?}"),
        },
        other => panic!("expected tag-18 COSE_Sign1_Tagged, got {other:?}"),
    };
    assert_eq!(array.len(), 4, "COSE_Sign1 must have exactly 4 elements");
    let protected = as_bytes(&array[0]).to_vec();
    let unprotected = match &array[1] {
        Value::Map(m) => m.clone(),
        other => panic!("expected a map for the unprotected header, got {other:?}"),
    };
    let payload = as_bytes(&array[2]).to_vec();
    let signature = as_bytes(&array[3]).to_vec();
    (protected, unprotected, payload, signature)
}

fn protected_alg(protected: &[u8]) -> i64 {
    match ciborium::de::from_reader::<Value, _>(protected).unwrap() {
        Value::Map(m) if m.len() == 1 => match (&m[0].0, &m[0].1) {
            (Value::Integer(k), Value::Integer(alg)) if i64::try_from(*k) == Ok(1) => {
                i64::try_from(*alg).expect("alg id must fit in i64")
            }
            other => panic!("unexpected protected header entry: {other:?}"),
        },
        other => panic!("expected a 1-entry protected header map, got {other:?}"),
    }
}

/// Rebuilds the COSE `Sig_structure` ("Signature1") that `brody` signs over.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&structure, &mut out).unwrap();
    out
}

#[test]
fn unsigned_envelope_has_digest_only_authentication() {
    let scratch = scratch_dir("unsigned-only");
    let (ok, bytes) = run_taylor(&[], &scratch);
    assert!(ok, "taylor should succeed with no --key");

    let elements = auth_wrapper_elements(&bytes);
    assert_eq!(
        elements.len(),
        1,
        "unsigned SUIT_Authentication must contain only the digest"
    );
}

#[test]
fn signed_envelope_appends_a_valid_es256_cose_sign1_block() {
    let scratch = scratch_dir("es256-signed");
    let key_path = write_key_file(&scratch, ES256_TEST_KEY_PEM);
    let (ok, bytes) = run_taylor(&["--key", key_path.to_str().unwrap()], &scratch);
    assert!(ok, "taylor should succeed when signing with an ES256 key");

    let elements = auth_wrapper_elements(&bytes);
    assert_eq!(
        elements.len(),
        2,
        "signed SUIT_Authentication must contain the digest plus one auth block"
    );

    let digest_bstr = as_bytes(&elements[0]).to_vec();
    let (protected, unprotected, payload, signature) = decode_cose_sign1(&elements[1]);

    assert_eq!(protected_alg(&protected), -7, "ES256 must use COSE alg -7");
    assert!(
        unprotected.is_empty(),
        "unprotected header must be empty (no kid)"
    );
    assert_eq!(
        payload, digest_bstr,
        "COSE_Sign1 payload must be exactly the original SUIT_Digest bstr"
    );

    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(ES256_TEST_KEY_PEM).unwrap();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let sig = p256::ecdsa::Signature::from_slice(&signature).expect("malformed ES256 signature");
    verifying_key
        .verify(&sig_structure(&protected, &payload), &sig)
        .expect("ES256 signature must verify against the recomputed Sig_structure");
}

#[test]
fn signed_envelope_appends_a_valid_es384_cose_sign1_block() {
    let scratch = scratch_dir("es384-signed");
    let key_path = write_key_file(&scratch, ES384_TEST_KEY_PEM);
    let (ok, bytes) = run_taylor(&["--key", key_path.to_str().unwrap()], &scratch);
    assert!(
        ok,
        "taylor should succeed when signing with an ES384 key (fallback path)"
    );

    let elements = auth_wrapper_elements(&bytes);
    assert_eq!(elements.len(), 2);

    let digest_bstr = as_bytes(&elements[0]).to_vec();
    let (protected, unprotected, payload, signature) = decode_cose_sign1(&elements[1]);

    assert_eq!(protected_alg(&protected), -35, "ES384 must use COSE alg -35");
    assert!(unprotected.is_empty());
    assert_eq!(payload, digest_bstr);

    let signing_key = p384::ecdsa::SigningKey::from_pkcs8_pem(ES384_TEST_KEY_PEM).unwrap();
    let verifying_key = p384::ecdsa::VerifyingKey::from(&signing_key);
    let sig = p384::ecdsa::Signature::from_slice(&signature).expect("malformed ES384 signature");
    verifying_key
        .verify(&sig_structure(&protected, &payload), &sig)
        .expect("ES384 signature must verify against the recomputed Sig_structure");
}

#[test]
fn signing_does_not_alter_the_manifest_or_digest_bytes() {
    let unsigned_scratch = scratch_dir("manifest-unchanged-unsigned");
    let (ok, unsigned_bytes) = run_taylor(&[], &unsigned_scratch);
    assert!(ok);

    let signed_scratch = scratch_dir("manifest-unchanged-signed");
    let key_path = write_key_file(&signed_scratch, ES256_TEST_KEY_PEM);
    let (ok, signed_bytes) = run_taylor(&["--key", key_path.to_str().unwrap()], &signed_scratch);
    assert!(ok);

    let unsigned_map = envelope_map(&unsigned_bytes);
    let signed_map = envelope_map(&signed_bytes);
    assert_eq!(
        map_get_bytes(&unsigned_map, 3),
        map_get_bytes(&signed_map, 3),
        "suit-manifest (key 3) must be byte-identical whether or not the envelope is signed"
    );

    let unsigned_digest = as_bytes(&auth_wrapper_elements(&unsigned_bytes)[0]).to_vec();
    let signed_digest = as_bytes(&auth_wrapper_elements(&signed_bytes)[0]).to_vec();
    assert_eq!(
        unsigned_digest, signed_digest,
        "the SUIT_Digest bstr must be identical whether or not the envelope is signed"
    );
}

#[test]
fn signing_fails_cleanly_when_the_key_file_is_missing() {
    let scratch = scratch_dir("missing-key");
    let missing_path = scratch.join("does-not-exist.pem");
    let (ok, _) = run_taylor(&["--key", missing_path.to_str().unwrap()], &scratch);
    assert!(!ok, "taylor must not exit successfully with an unreadable key file");
}
