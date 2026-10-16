//! Integration tests for the `taylor` CLI's exit codes: usage errors that must be rejected up
//! front with exit code 2, before any file I/O, rendering, or encoding happens, and runtime
//! failures (unreadable input, invalid manifest, bad signing key) that must exit with code 1
//! and an `error:` message instead of panicking.
//!
//! Kept separate from `tests/signing.rs`/`tests/templating.rs` so those files can focus on
//! "does the feature behave correctly", while this file focuses on "is a malformed invocation
//! rejected". See `tests/library_api.rs` for related negative cases at the library level
//! (`taylor::template::build_context`/`render` and `taylor::envelope::build_envelope` returning
//! `Err`, rather than a CLI exit code).

mod common;

use common::*;

#[test]
fn no_arguments_at_all_is_rejected() {
    // Previously defaulted silently to `examples/input/manifests/test.json`, which could sign/encode the wrong
    // manifest in a misconfigured build pipeline without any indication. A JSON path or
    // `--template` must now be given explicitly.
    let output = run_taylor(&[]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "running with no arguments must fail, not default silently to a manifest: {}",
        stderr_of(&output)
    );
}

#[test]
fn template_conflicts_with_a_positional_json_path() {
    let output = run_taylor(&[
        json_path().to_str().unwrap(),
        "--template",
        template_path().to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a JSON path and --template together must be rejected as mutually exclusive: {}",
        stderr_of(&output)
    );
}

#[test]
fn var_without_template_is_rejected() {
    let output = run_taylor(&[json_path().to_str().unwrap(), "--var", "foo=bar"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "--var without --template must be rejected: {}",
        stderr_of(&output)
    );
}

#[test]
fn vars_file_without_template_is_rejected() {
    let output = run_taylor(&["--vars-file", "does-not-matter.json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "--vars-file without --template must be rejected: {}",
        stderr_of(&output)
    );
}

#[test]
fn render_only_without_template_is_rejected() {
    let output = run_taylor(&[json_path().to_str().unwrap(), "--render-only"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "--render-only without --template must be rejected: {}",
        stderr_of(&output)
    );
}

#[test]
fn malformed_var_without_equals_sign_is_rejected() {
    let output = run_taylor(&[
        "--template",
        template_path().to_str().unwrap(),
        "--var",
        "no-equals-sign",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a --var without `=` must be rejected by clap's value_parser: {}",
        stderr_of(&output)
    );
}

#[test]
fn unsupported_manifest_digest_is_rejected() {
    let output = run_taylor(&[json_path().to_str().unwrap(), "--manifest-digest", "md5"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unsupported --manifest-digest must be rejected: {}",
        stderr_of(&output)
    );
}

#[test]
fn vars_file_with_json_path_but_no_template_exits_with_code_2() {
    let output = run_taylor(&[
        json_path().to_str().unwrap(),
        "--vars-file",
        "does-not-matter.json",
    ]);
    let stderr = stderr_of(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--vars-file requires --template"),
        "{stderr}"
    );
}

/// Runtime failures must report an error and exit with 1, never panic (exit 101).
fn assert_runtime_failure(args: &[&str]) {
    let output = run_taylor(args);
    let stderr = stderr_of(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("error:"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn missing_manifest_file_exits_with_code_1() {
    assert_runtime_failure(&["does-not-exist.json"]);
}

#[test]
fn malformed_manifest_json_exits_with_code_1() {
    let scratch = scratch_dir("cli-malformed-json");
    let manifest = scratch.join("manifest.json");
    std::fs::write(&manifest, "{ not json").unwrap();
    assert_runtime_failure(&[manifest.to_str().unwrap()]);
}

#[test]
fn closed_stdout_exits_with_code_1_instead_of_panicking() {
    let (reader, writer) = std::io::pipe().expect("failed to create pipe");
    // Closing the read end first makes the binary's first stdout write fail with EPIPE.
    drop(reader);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_taylor"))
        .arg(json_path())
        .stdout(writer)
        .output()
        .expect("failed to spawn taylor binary");
    let stderr = stderr_of(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("failed to write to stdout"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn invalid_signing_key_exits_with_code_1() {
    let scratch = scratch_dir("cli-invalid-key");
    let key_path = write_key_file(&scratch, "not a pem key");
    assert_runtime_failure(&[
        json_path().to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
    ]);
}
