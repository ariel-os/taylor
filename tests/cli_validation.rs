//! Integration tests for the `taylor` CLI's argument-shape validation -- usage errors that must
//! be rejected up front, before any file I/O, rendering, or encoding happens, regardless of
//! which feature (signing, templating) is otherwise in play.
//!
//! Kept separate from `tests/signing.rs`/`tests/templating.rs` so those files can focus on
//! "does the feature behave correctly", while this file focuses on "is a malformed invocation
//! rejected". See `tests/library_api.rs` for the equivalent negative cases at the library level
//! (`taylor::template::build_context`/`render` returning `Err`, rather than a CLI exit code).

mod common;

use common::*;

#[test]
fn no_arguments_at_all_is_rejected() {
    // Previously defaulted silently to `examples/input/manifests/test.json`, which could sign/encode the wrong
    // manifest in a misconfigured build pipeline without any indication. A JSON path or
    // `--template` must now be given explicitly.
    let output = run_taylor(&[]);
    assert!(
        !output.status.success(),
        "running with no arguments must fail, not default silently to a manifest"
    );
}

#[test]
fn template_conflicts_with_a_positional_json_path() {
    let output = run_taylor(&[
        json_path().to_str().unwrap(),
        "--template",
        template_path().to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "a JSON path and --template together must be rejected as mutually exclusive"
    );
}

#[test]
fn var_without_template_is_rejected() {
    let output = run_taylor(&[json_path().to_str().unwrap(), "--var", "foo=bar"]);
    assert!(!output.status.success(), "--var without --template must be rejected");
}

#[test]
fn vars_file_without_template_is_rejected() {
    let output = run_taylor(&["--vars-file", "does-not-matter.json"]);
    assert!(!output.status.success(), "--vars-file without --template must be rejected");
}

#[test]
fn render_only_without_template_is_rejected() {
    let output = run_taylor(&[json_path().to_str().unwrap(), "--render-only"]);
    assert!(!output.status.success(), "--render-only without --template must be rejected");
}

#[test]
fn malformed_var_without_equals_sign_is_rejected() {
    let output = run_taylor(&[
        "--template",
        template_path().to_str().unwrap(),
        "--var",
        "no-equals-sign",
    ]);
    assert!(
        !output.status.success(),
        "a --var without `=` must be rejected by clap's value_parser"
    );
}
