//! Integration tests for using `taylor` as a **library** -- calling its public API directly,
//! with no `taylor` subprocess involved -- covering the same unsigned/signed x
//! direct-JSON/templated combinations that `tests/signing.rs` and `tests/templating.rs` cover
//! through the CLI. This catches a regression that only affects the public API surface (and not
//! the CLI wiring in `src/cli.rs`), and doubles as a working reference for library consumers who
//! embed `taylor` in their own tooling instead of shelling out to the binary.
//!
//! See `tests/cli_validation.rs` for related negative cases expressed as CLI exit codes rather
//! than `Result::Err` variants.

mod common;

use common::*;
use std::fs::File;
use std::io::{BufReader, Cursor};
use taylor::envelope::build_envelope;
use taylor::manifest::{
    SuitCommand, SuitCommandEnum, SuitCommon, SuitDigest, SuitManifest, SuitParameter,
    SuitParametersEnum,
};
use taylor::parse::parse;
use taylor::sign::{load_signer, sign_envelope_with_key, sign_envelope_with_pem};
use taylor::template::{Error, build_context, render};

fn assemble_unsigned_envelope_cbor(manifest: SuitManifest) -> Vec<u8> {
    build_envelope(manifest, None).expect("unsigned envelope must build")
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
    let signed =
        sign_envelope_with_key(&unsigned_from_template, &key_path).expect("signing must succeed");

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
fn build_envelope_with_signer_matches_signing_the_unsigned_envelope() {
    let signer = load_signer(ES256_TEST_KEY_PEM).expect("test key must load");
    let signed = build_envelope(parse_direct_json(), Some(&signer)).expect("signing must succeed");

    let elements = auth_wrapper_elements(&signed);
    assert_eq!(elements.len(), 2);
    let digest_bstr = as_bytes(&elements[0]).to_vec();
    let (protected, _unprotected, _payload, signature) = decode_cose_sign1(&elements[1]);
    assert_valid_es256_signature(&protected, &digest_bstr, &signature);

    // ECDSA signatures differ per call, so only compare everything except the signature.
    let via_pem = sign_envelope_with_pem(
        &assemble_unsigned_envelope_cbor(parse_direct_json()),
        ES256_TEST_KEY_PEM,
    )
    .expect("signing must succeed");
    assert_eq!(
        map_get_bytes(&envelope_map(&signed), 3),
        map_get_bytes(&envelope_map(&via_pem), 3)
    );
    assert_eq!(auth_wrapper_elements(&via_pem)[0], elements[0]);
}

#[test]
fn build_envelope_rejects_unsupported_digest_algorithm_without_panicking() {
    let override_md5_digest = SuitCommand {
        ident: SuitCommandEnum::SuitDirectiveOverrideParameters(vec![SuitParameter {
            ident: SuitParametersEnum::SuitImageDigest(SuitDigest {
                algorithm: "md5".into(),
                digest: vec![0; 16],
            }),
        }]),
    };
    let components = vec![vec![serde_bytes::ByteBuf::from(vec![0x00])]];
    let manifest = SuitManifest::new(1, SuitCommon::new(components, vec![override_md5_digest]));

    match build_envelope(manifest, None) {
        Err(taylor::error::Error::UnsupportedAlgorithm(message)) => {
            assert_eq!(message, "md5 for image-digest");
        }
        other => panic!("expected Err(Error::UnsupportedAlgorithm(_)), got {other:?}"),
    }
}

#[test]
fn render_fails_fast_when_a_required_variable_is_missing() {
    // Pins `template::Error::MissingVariables`'s exact contents (not just "is_err()"), so a
    // regression that silently renders `null` instead of erroring would be caught.
    let context = build_context(
        None,
        &[("sequence_number".to_string(), serde_json::json!(1))],
    )
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
