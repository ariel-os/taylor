//! Integration tests for using `taylor` as a **library** -- calling its public API directly,
//! with no `taylor` subprocess involved -- covering the same unsigned/signed x
//! direct-JSON/templated combinations that `tests/signing.rs` and `tests/templating.rs` cover
//! through the CLI. This catches a regression that only affects the public API surface (and not
//! `main.rs`'s own CLI wiring), and doubles as a working reference for library consumers who
//! embed `taylor` in their own tooling instead of shelling out to the binary.
//!
//! See `tests/cli_validation.rs` for the equivalent negative cases expressed as CLI exit codes
//! rather than `Result::Err` variants.

mod common;

use common::*;
use sha256::Sha256Digest as _;
use std::fs::File;
use std::io::{BufReader, Cursor};
use taylor::encode::{encode_envelope, encode_manifest};
use taylor::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope, SuitManifest};
use taylor::parse::parse;
use taylor::sign::sign_envelope_with_key;
use taylor::template::{build_context, render, Error};

/// Mirrors the manifest -> digest -> envelope assembly `main.rs` performs, so this test (and any
/// library consumer) can reuse the exact same sequence without depending on the CLI.
fn assemble_unsigned_envelope_cbor(manifest: SuitManifest) -> Vec<u8> {
    let manifest_cbor = encode_manifest(&manifest);
    let digest_hex = manifest_cbor.digest();
    let digest = hex::decode(&digest_hex).expect("sha256 digest hex must be valid");
    let envelope = SuitEnvelope {
        auth_block: SuitAuthentication {
            digest: SuitDigest {
                algorithm: "sha256".to_owned(),
                digest,
            },
            auth_blocks: Vec::new(),
        },
        manifest,
    };
    encode_envelope(&envelope)
}

fn parse_direct_json() -> SuitManifest {
    let mut reader = BufReader::new(
        File::open(json_path()).expect("examples/input/manifests/test.json must exist"),
    );
    parse(&mut reader).expect("examples/input/manifests/test.json must parse")
}

fn parse_rendered_template() -> SuitManifest {
    let rendered =
        render(&template_path(), &matching_template_context()).expect("template must render");
    parse(&mut Cursor::new(rendered.as_bytes())).expect("rendered JSON must parse")
}

#[test]
fn direct_json_and_rendered_template_produce_the_same_manifest() {
    // `matching_template_context` is set to `examples/input/manifests/test.json`'s exact values, so the two
    // sources must assemble into byte-identical envelopes -- the same guarantee
    // `tests/templating.rs::template_and_direct_json_produce_byte_identical_cbor` checks via
    // the CLI, proven here purely through the library API.
    let via_json = assemble_unsigned_envelope_cbor(parse_direct_json());
    let via_template = assemble_unsigned_envelope_cbor(parse_rendered_template());
    assert_eq!(via_json, via_template);
}

#[test]
fn unsigned_envelope_via_library_has_digest_only_authentication() {
    let cbor = assemble_unsigned_envelope_cbor(parse_direct_json());
    let elements = auth_wrapper_elements(&cbor);
    assert_eq!(
        elements.len(),
        1,
        "unsigned SUIT_Authentication must contain only the digest"
    );
}

#[test]
fn signed_envelope_via_library_from_direct_json_has_a_valid_es256_signature() {
    let scratch = scratch_dir("library-signed-direct");
    let key_path = write_key_file(&scratch, ES256_TEST_KEY_PEM);

    let unsigned = assemble_unsigned_envelope_cbor(parse_direct_json());
    let signed = sign_envelope_with_key(&unsigned, &key_path).expect("signing must succeed");

    let elements = auth_wrapper_elements(&signed);
    assert_eq!(elements.len(), 2);
    let digest_bstr = as_bytes(&elements[0]).to_vec();
    let (protected, _unprotected, cose_payload, signature) = decode_cose_sign1(&elements[1]);
    assert_eq!(protected_alg(&protected), -7, "ES256 must use COSE alg -7");
    assert!(cose_payload.is_none());
    assert_valid_es256_signature(&protected, &digest_bstr, &signature);
}

#[test]
fn signed_envelope_via_library_from_template_matches_signed_direct_json() {
    // Combination: templated source + signing, both driven purely through the public API.
    let scratch = scratch_dir("library-signed-template");
    let key_path = write_key_file(&scratch, ES256_TEST_KEY_PEM);

    let unsigned_from_template = assemble_unsigned_envelope_cbor(parse_rendered_template());
    let signed = sign_envelope_with_key(&unsigned_from_template, &key_path).expect("signing must succeed");

    let elements = auth_wrapper_elements(&signed);
    assert_eq!(elements.len(), 2);
    let digest_bstr = as_bytes(&elements[0]).to_vec();
    let (protected, _unprotected, cose_payload, signature) = decode_cose_sign1(&elements[1]);
    assert_eq!(protected_alg(&protected), -7);
    assert!(cose_payload.is_none());
    assert_valid_es256_signature(&protected, &digest_bstr, &signature);

    let unsigned_from_json = assemble_unsigned_envelope_cbor(parse_direct_json());
    assert_eq!(
        map_get_bytes(&envelope_map(&signed), 3),
        map_get_bytes(&envelope_map(&unsigned_from_json), 3),
        "suit-manifest bytes must match the direct-JSON path regardless of templating or signing"
    );
}

#[test]
fn render_fails_fast_when_a_required_variable_is_missing() {
    // Pins `template::Error::MissingVariables`'s exact contents (not just "is_err()"), so a
    // regression that silently renders `null` instead of erroring would be caught.
    let context = build_context(None, &[("sequence_number".to_string(), serde_json::json!(1))])
        .expect("build_context with only CLI vars must succeed");

    match render(&template_path(), &context) {
        Err(Error::MissingVariables(names)) => {
            assert!(names.contains(&"vendor_id".to_string()));
            assert!(names.contains(&"class_id".to_string()));
            assert!(names.contains(&"uri".to_string()));
        }
        other => panic!("expected Err(Error::MissingVariables(_)), got {other:?}"),
    }
}

#[test]
fn build_context_rejects_a_vars_file_that_is_not_a_json_object() {
    let scratch = scratch_dir("library-vars-file-not-object");
    let vars_file = scratch.join("vars.json");
    std::fs::write(&vars_file, "[1, 2, 3]").expect("failed to write vars file");

    match build_context(Some(&vars_file), &[]) {
        Err(Error::InvalidVarsFile(_)) => {}
        other => panic!("expected Err(Error::InvalidVarsFile(_)), got {other:?}"),
    }
}
