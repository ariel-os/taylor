//! Application-level integration tests for the `taylor` CLI's `-k`/`--key` signing flag, using
//! the **direct JSON path** (`examples/input/manifests/test.json`).
//!
//! See `tests/templating.rs` for the signed *and* templated combination,
//! `tests/library_api.rs` for equivalent coverage via the public library API (no subprocess),
//! and `tests/cli_validation.rs` for pure argument-shape/usage-error checks.
//!
//! These spawn the compiled `taylor` binary end-to-end and independently re-derive/verify the
//! resulting `COSE_Sign1` block using `p256`/`p384` directly (not via `brody`'s own API), so a
//! regression in either `taylor`'s wiring or in the `brody` dependency itself would be caught.

mod common;

use common::*;
use std::path::Path;

/// Runs `taylor` against `examples/input/manifests/test.json` with `extra_args`, returning `(success, cbor)`.
/// `cbor` is empty when the process failed.
fn run_on_test_json(extra_args: &[&str], scratch: &Path) -> (bool, Vec<u8>) {
    let json = json_path();
    let out_dir = scratch.join("out");
    let out_dir_str = out_dir.to_str().unwrap().to_string();

    let mut args = vec![json.to_str().unwrap()];
    args.extend_from_slice(extra_args);
    args.extend_from_slice(&["--output", &out_dir_str]);

    let output = run_taylor(&args);
    if !output.status.success() {
        return (false, Vec::new());
    }
    (true, read_output_file(&out_dir, "test.cbor"))
}

#[test]
fn unsigned_envelope_has_digest_only_authentication() {
    let scratch = scratch_dir("unsigned-only");
    let (ok, bytes) = run_on_test_json(&[], &scratch);
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
    let (ok, bytes) = run_on_test_json(&["--key", key_path.to_str().unwrap()], &scratch);
    assert!(ok, "taylor should succeed when signing with an ES256 key");

    let elements = auth_wrapper_elements(&bytes);
    assert_eq!(
        elements.len(),
        2,
        "signed SUIT_Authentication must contain the digest plus one auth block"
    );

    let digest_bstr = as_bytes(&elements[0]).to_vec();
    let (protected, unprotected, cose_payload, signature) = decode_cose_sign1(&elements[1]);

    assert_eq!(protected_alg(&protected), -7, "ES256 must use COSE alg -7");
    assert!(
        unprotected.is_empty(),
        "unprotected header must be empty (no kid)"
    );
    assert!(
        cose_payload.is_none(),
        "COSE_Sign1 payload must be null when using the detached SUIT_Digest"
    );

    assert_valid_es256_signature(&protected, &digest_bstr, &signature);
}

#[test]
fn signed_envelope_appends_a_valid_es384_cose_sign1_block() {
    let scratch = scratch_dir("es384-signed");
    let key_path = write_key_file(&scratch, ES384_TEST_KEY_PEM);
    let (ok, bytes) = run_on_test_json(&["--key", key_path.to_str().unwrap()], &scratch);
    assert!(
        ok,
        "taylor should succeed when signing with an ES384 key (fallback path)"
    );

    let elements = auth_wrapper_elements(&bytes);
    assert_eq!(elements.len(), 2);

    let digest_bstr = as_bytes(&elements[0]).to_vec();
    let (protected, unprotected, cose_payload, signature) = decode_cose_sign1(&elements[1]);

    assert_eq!(protected_alg(&protected), -35, "ES384 must use COSE alg -35");
    assert!(unprotected.is_empty());
    assert!(cose_payload.is_none());

    assert_valid_es384_signature(&protected, &digest_bstr, &signature);
}

#[test]
fn signing_does_not_alter_the_manifest_or_digest_bytes() {
    let unsigned_scratch = scratch_dir("manifest-unchanged-unsigned");
    let (ok, unsigned_bytes) = run_on_test_json(&[], &unsigned_scratch);
    assert!(ok);

    let signed_scratch = scratch_dir("manifest-unchanged-signed");
    let key_path = write_key_file(&signed_scratch, ES256_TEST_KEY_PEM);
    let (ok, signed_bytes) =
        run_on_test_json(&["--key", key_path.to_str().unwrap()], &signed_scratch);
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
    let (ok, _) = run_on_test_json(&["--key", missing_path.to_str().unwrap()], &scratch);
    assert!(
        !ok,
        "taylor must not exit successfully with an unreadable key file"
    );
}
