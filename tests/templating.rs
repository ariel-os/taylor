//! Application-level integration tests for the `taylor` CLI's `--template`/`--var`/
//! `--vars-file`/`--render-only` flags, which render a `minijinja` template into the manifest
//! JSON before parsing/encoding it.
//!
//! See `tests/signing.rs` for the direct-JSON signing tests, `tests/library_api.rs` for
//! equivalent template-rendering coverage via the public library API (no subprocess), and
//! `tests/cli_validation.rs` for pure argument-shape/usage-error checks (including the
//! `--template`/`json_path` conflict and the "requires `--template`" flags).
//!
//! These spawn the compiled `taylor` binary end-to-end, matching the style of `tests/signing.rs`.

mod common;

use common::*;

#[test]
fn template_and_direct_json_produce_byte_identical_cbor() {
    let direct_out = scratch_dir("byte-identical-direct").join("out");
    let template_out = scratch_dir("byte-identical-template").join("out");

    let direct = run_taylor(&[
        json_path().to_str().unwrap(),
        "--output",
        direct_out.to_str().unwrap(),
    ]);
    assert!(direct.status.success(), "direct JSON path failed: {}", stderr_of(&direct));

    let template_path = template_path();
    let mut template_args = vec![
        "--template",
        template_path.to_str().unwrap(),
        "--output",
        template_out.to_str().unwrap(),
    ];
    template_args.extend_from_slice(MATCHING_VAR_ARGS);
    let templated = run_taylor(&template_args);
    assert!(
        templated.status.success(),
        "templated path failed: {}",
        stderr_of(&templated)
    );

    let direct_cbor = read_output_file(&direct_out, "test.cbor");
    let template_cbor = read_output_file(&template_out, "manifest.json.cbor");
    assert_eq!(
        direct_cbor, template_cbor,
        "rendering the template with matching --var values must produce identical CBOR to the direct JSON path"
    );
}

#[test]
fn signed_template_matches_signed_direct_json() {
    // Combination case: templating *and* signing together. The signature bytes themselves
    // can't be compared byte-for-byte (ECDSA is randomized per signing), so this instead
    // independently re-verifies the templated signature and checks that the suit-manifest bytes
    // (key 3) match the direct-JSON path exactly, mirroring
    // `tests/signing.rs::signing_does_not_alter_the_manifest_or_digest_bytes`.
    let direct_scratch = scratch_dir("signed-direct-for-template-comparison");
    let template_scratch = scratch_dir("signed-template");
    let key_path = write_key_file(&template_scratch, ES256_TEST_KEY_PEM);

    let direct_out = direct_scratch.join("out");
    let direct = run_taylor(&[
        json_path().to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
        "--output",
        direct_out.to_str().unwrap(),
    ]);
    assert!(
        direct.status.success(),
        "signed direct JSON path failed: {}",
        stderr_of(&direct)
    );

    let template_out = template_scratch.join("out");
    let template = template_path();
    let mut args = vec![
        "--template",
        template.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
        "--output",
        template_out.to_str().unwrap(),
    ];
    args.extend_from_slice(MATCHING_VAR_ARGS);
    let templated = run_taylor(&args);
    assert!(
        templated.status.success(),
        "signed templated path failed: {}",
        stderr_of(&templated)
    );

    let direct_cbor = read_output_file(&direct_out, "test.cbor");
    let template_cbor = read_output_file(&template_out, "manifest.json.cbor");

    let elements = auth_wrapper_elements(&template_cbor);
    assert_eq!(
        elements.len(),
        2,
        "signed SUIT_Authentication must contain the digest plus one auth block"
    );
    let (protected, _unprotected, payload, signature) = decode_cose_sign1(&elements[1]);
    assert_eq!(protected_alg(&protected), -7, "ES256 must use COSE alg -7");
    assert_valid_es256_signature(&protected, &payload, &signature);

    assert_eq!(
        map_get_bytes(&envelope_map(&direct_cbor), 3),
        map_get_bytes(&envelope_map(&template_cbor), 3),
        "suit-manifest bytes must match the direct-JSON path regardless of templating"
    );
}

#[test]
fn cli_vars_override_vars_file_on_key_collision() {
    let scratch = scratch_dir("vars-file-override");
    let vars_file = scratch.join("vars.json");
    std::fs::write(
        &vars_file,
        r#"{
            "sequence_number": 1,
            "vendor_id": "00000000-0000-0000-0000-000000000000",
            "class_id": "69e55044-10b1-426f-2974-bb680e5fedc8",
            "image_size": 1024,
            "digest": "c12efb651dc800465d80264343852c304c4dcea2da82828d8824df7638628d17",
            "uri": "https://example.com/firmware.bin"
        }"#,
    )
    .expect("failed to write vars file");

    // Override the (wrong) vendor_id from the vars file with the correct one via --var.
    let output = run_taylor(&[
        "--template",
        template_path().to_str().unwrap(),
        "--vars-file",
        vars_file.to_str().unwrap(),
        "--var",
        "vendor_id=67e55044-10b1-426f-9247-bb680e5fe0c8",
        "--render-only",
    ]);
    assert!(output.status.success(), "render failed: {}", stderr_of(&output));

    let rendered: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("--render-only must print valid JSON to stdout");
    let vendor_id = rendered["suit-common"]["suit-shared-sequence"][1]
        ["suit-directive-override-parameters"]["vendor-id"]
        .as_str()
        .expect("vendor-id must be a string");
    assert_eq!(
        vendor_id, "67e55044-10b1-426f-9247-bb680e5fe0c8",
        "--var must override the colliding key from --vars-file"
    );
}

#[test]
fn missing_template_variables_fail_fast_with_a_clear_error() {
    let output = run_taylor(&[
        "--template",
        template_path().to_str().unwrap(),
        "--var",
        "sequence_number=1",
        // vendor_id, class_id, image_size, digest, uri are all missing.
    ]);
    assert!(
        !output.status.success(),
        "rendering must fail when required template variables are missing"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("vendor_id") && stderr.contains("class_id") && stderr.contains("uri"),
        "error message must name the missing variables, got: {stderr}"
    );
}

#[test]
fn render_only_prints_json_and_skips_encoding() {
    let template_path = template_path();
    let mut args = vec!["--template", template_path.to_str().unwrap(), "--render-only"];
    args.extend_from_slice(MATCHING_VAR_ARGS);
    let output = run_taylor(&args);
    assert!(output.status.success(), "render-only failed: {}", stderr_of(&output));

    let rendered: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("--render-only must print valid JSON to stdout, with no CBOR encoding attempted");
    assert_eq!(rendered["sequence-number"], 1);
}
