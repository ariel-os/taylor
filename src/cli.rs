//! The `taylor` command-line interface, exposed as a library function so other tools (for
//! example language bindings) can run it in-process.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! | ---: | --- |
//! | 0 | Success, including `--help` and `--version` |
//! | 1 | Runtime failure, such as an unreadable file, invalid manifest, bad signing key, or a failed write to stdout |
//! | 2 | Usage error, such as a missing manifest source or conflicting arguments |

use std::ffi::OsString;
use std::fmt::Arguments;
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};

use clap::{ArgAction, CommandFactory, Parser};
use sha256::Sha256Digest;

use crate::encode::try_encode_manifest;
use crate::envelope::build_envelope;
use crate::parse::parse;
use crate::sign::load_signer;
use crate::template::{build_context, parse_var, render};

#[derive(Parser)]
#[command(
    name = "taylor",
    version,
    about,
    long_about = "Generates IETF SUIT manifests, CBOR-encoded, from a JSON description.\n\n\
                  Provide the manifest source either as a positional JSON_PATH, or by rendering \
                  a minijinja template first via --template (together with --var / --vars-file \
                  / --render-only).",
    override_usage = "taylor <JSON_PATH> [OPTIONS]\n       taylor --template <PATH> [OPTIONS]"
)]
struct Cli {
    /// Path to the input JSON manifest. Ignored if `--template` is given.
    json_path: Option<PathBuf>,

    /// Path to a `minijinja` template rendered into the JSON manifest before parsing. Mutually
    /// exclusive with a plain JSON path.
    #[arg(long = "template", value_name = "PATH", conflicts_with = "json_path")]
    template_path: Option<PathBuf>,

    /// Sets a template variable as `KEY=VALUE`, overriding the same key from `--vars-file`.
    /// Values are inferred as bool/int/float, falling back to a string. Repeatable. Requires
    /// `--template`.
    #[arg(long = "var", value_name = "KEY=VALUE", value_parser = parse_var, action = ArgAction::Append)]
    vars: Vec<(String, serde_json::Value)>,

    /// Path to a JSON file of template variables, used as the base context before `--var`
    /// overrides are applied. Requires `--template`.
    #[arg(long = "vars-file", value_name = "PATH")]
    vars_file: Option<PathBuf>,

    /// Print the rendered JSON manifest and exit, without parsing/encoding/signing it. Requires
    /// `--template`.
    #[arg(long = "render-only")]
    render_only: bool,

    /// Path to a PEM-encoded EC private key (P-256/ES256 or P-384/ES384). Providing this
    /// signs the envelope with a COSE_Sign1 authentication block.
    #[arg(short = 'k', long = "key", value_name = "PEM_FILE")]
    key_path: Option<PathBuf>,

    /// Directory where the generated CBOR envelope (or, with `--render-only`, JSON) is written.
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,
}

/// Runs the `taylor` CLI with `args`, where the first item is the program name, and returns
/// the process exit code (see the [module documentation](crate::cli) for its meaning).
///
/// Errors are printed to stderr and the process is never exited. Neither bad input nor a failed
/// output write causes a panic: a failed write to stdout, such as a closed pipe, returns exit
/// code 1, and failed writes to stderr are ignored.
///
/// # Examples
///
/// ```
/// assert_eq!(taylor::cli::run(["taylor", "--version"]), 0);
/// assert_eq!(taylor::cli::run(["taylor", "--render-only"]), 2);
/// assert_eq!(taylor::cli::run(["taylor", "does-not-exist.json"]), 1);
/// ```
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            // Help and version also arrive here; clap routes them to stdout with code 0.
            let _ = err.print();
            return err.exit_code();
        }
    };

    if let Some(message) = usage_error(&cli) {
        let err = Cli::command().error(clap::error::ErrorKind::MissingRequiredArgument, message);
        let _ = err.print();
        return err.exit_code();
    }

    match execute(cli) {
        Ok(()) => 0,
        Err(message) => {
            diag(format_args!("error: {message}"));
            1
        }
    }
}

/// Writes a line of the CLI's result to stdout.
fn out(line: Arguments) -> Result<(), String> {
    writeln!(io::stdout().lock(), "{line}").map_err(|e| format!("failed to write to stdout: {e}"))
}

/// Writes a diagnostic line to stderr, ignoring failures since there is nowhere left to report them.
fn diag(line: Arguments) {
    let _ = writeln!(io::stderr().lock(), "{line}");
}

/// Argument combinations clap can't express: its `requires` doesn't fire on these flags once
/// `--template`'s `conflicts_with` is satisfied.
fn usage_error(cli: &Cli) -> Option<&'static str> {
    if cli.template_path.is_none() {
        if !cli.vars.is_empty() {
            return Some("--var requires --template");
        }
        if cli.vars_file.is_some() {
            return Some("--vars-file requires --template");
        }
        if cli.render_only {
            return Some("--render-only requires --template");
        }
        if cli.json_path.is_none() {
            return Some("no manifest source given: pass a JSON_PATH or --template <PATH>");
        }
    }
    None
}

fn execute(cli: Cli) -> Result<(), String> {
    let (source_path, json) = match (cli.template_path, cli.json_path) {
        (Some(template_path), _) => {
            diag(format_args!("Using template: {template_path:?}"));
            let context = build_context(cli.vars_file.as_deref(), &cli.vars)
                .map_err(|e| format!("failed to build template context: {e}"))?;
            let rendered = render(&template_path, &context)
                .map_err(|e| format!("failed to render template {template_path:?}: {e}"))?;
            (template_path, rendered)
        }
        (None, Some(json_path)) => {
            diag(format_args!("Using path: {json_path:?}"));
            let json = fs::read_to_string(&json_path)
                .map_err(|e| format!("failed to read {json_path:?}: {e}"))?;
            (json_path, json)
        }
        (None, None) => unreachable!("rejected by usage_error"),
    };

    if cli.render_only {
        match &cli.output {
            Some(out_dir) => write_output(out_dir, &source_path, "json", json.as_bytes())?,
            None => out(format_args!("{json}"))?,
        }
        return Ok(());
    }

    let signer = cli
        .key_path
        .as_deref()
        .map(|key_path| {
            fs::read_to_string(key_path)
                .map_err(|e| e.to_string())
                .and_then(|pem| load_signer(&pem).map_err(|e| e.to_string()))
                .map_err(|e| format!("failed to load signing key {key_path:?}: {e}"))
        })
        .transpose()?;

    let manifest = parse(&mut Cursor::new(json.as_bytes()))
        .map_err(|e| format!("failed to parse manifest {source_path:?}: {e}"))?;

    let manifest_cbor =
        try_encode_manifest(&manifest).map_err(|e| format!("failed to encode manifest: {e}"))?;
    out(format_args!(
        "digest string :: {:?}",
        manifest_cbor.digest()
    ))?;

    let envelope_cbor = build_envelope(manifest, signer.as_ref())
        .map_err(|e| format!("failed to build envelope: {e}"))?;

    out(format_args!(
        "CBOR Output of Envelope: {}",
        hex::encode(&envelope_cbor)
    ))?;

    if let Some(out_dir) = &cli.output {
        write_output(out_dir, &source_path, "cbor", &envelope_cbor)?;
    }
    Ok(())
}

/// Writes `contents` to `out_dir/<source_path file stem>.<extension>`, creating `out_dir` if
/// needed.
fn write_output(
    out_dir: &Path,
    source_path: &Path,
    extension: &str,
    contents: &[u8],
) -> Result<(), String> {
    fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create output directory {out_dir:?}: {e}"))?;
    let file_stem = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("manifest");
    let file_name = if file_stem.ends_with(&format!(".{extension}")) {
        file_stem.to_owned()
    } else {
        format!("{file_stem}.{extension}")
    };
    let out_path = out_dir.join(file_name);
    fs::write(&out_path, contents).map_err(|e| format!("failed to write {out_path:?}: {e}"))?;
    out(format_args!("Wrote output to: {out_path:?}"))
}
