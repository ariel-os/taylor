use clap::{ArgAction, CommandFactory, Parser};
use taylor::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope};
use taylor::sign::sign_envelope_with_key;
use taylor::template::{build_context, parse_var, render};
use taylor::{
    encode::{encode_envelope, encode_manifest},
    parse::parse,
};
use sha256::Sha256Digest;
use std::fs::{self, File};
use std::io::{BufReader, Cursor};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
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

fn main() {
    let Cli {
        json_path,
        template_path,
        vars,
        vars_file,
        render_only,
        key_path,
        output,
    } = Cli::parse();

    // `requires = "template_path"` on `vars`/`vars_file`/`render_only` isn't used here: clap's
    // derive macro fails to enforce `requires` on those args once `template_path`'s
    // `conflicts_with = "json_path"` is also satisfied (i.e. whenever a positional `json_path` is
    // given), so the check is done explicitly instead.
    if template_path.is_none() {
        let offending_flag = if !vars.is_empty() {
            Some("--var")
        } else if vars_file.is_some() {
            Some("--vars-file")
        } else if render_only {
            Some("--render-only")
        } else {
            None
        };
        if let Some(flag) = offending_flag {
            Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    format!("{flag} requires --template"),
                )
                .exit();
        }
    }

    // Either render a template into JSON, or use a plain JSON manifest path.
    let (source_path, rendered) = if let Some(template_path) = template_path {
        eprintln!("Using template: {template_path:?}");
        let context = build_context(vars_file.as_deref(), &vars)
            .unwrap_or_else(|e| panic!("failed to build template context: {e}"));
        let rendered = render(&template_path, &context)
            .unwrap_or_else(|e| panic!("failed to render template {template_path:?}: {e}"));
        (template_path, Some(rendered))
    } else {
        let json_path = json_path.unwrap_or_else(|| {
            Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "no manifest source given: pass a JSON_PATH or --template <PATH>",
                )
                .exit();
        });
        eprintln!("Using path: {json_path:?}");
        (json_path, None)
    };

    if render_only {
        let rendered = rendered.expect("--render-only requires --template");
        if let Some(out_dir) = &output {
            write_output(out_dir, &source_path, "json", rendered.as_bytes());
        } else {
            println!("{rendered}");
        }
        return;
    }

    // Parse inner manifest, either from the rendered template or directly from disk.
    let manifest = match &rendered {
        Some(json) => parse(&mut Cursor::new(json.as_bytes())).unwrap(),
        None => parse(&mut BufReader::new(File::open(&source_path).unwrap())).unwrap(),
    };

    let manifest_cbor = encode_manifest(&manifest);
    // Handle Envelope

    // Hash the raw manifest bytes, not their hex-text representation
    let digest_hex = manifest_cbor.digest();
    let digest = hex::decode(&digest_hex).expect("sha256 digest hex must be valid");
    println!("digest string :: {:?}", digest_hex);
    // SUIT_Authentication allows zero auth blocks; brody adds a real one when signing
    let suit_auth = SuitAuthentication {
        digest: SuitDigest {
            algorithm: "sha256".to_owned(),
            digest,
        },
        auth_blocks: Vec::new(),
    };

    let envelope = SuitEnvelope {
        auth_block: suit_auth,
        manifest,
    };

    let mut envelope_cbor = encode_envelope(&envelope);

    if let Some(key_path) = key_path.as_deref() {
        envelope_cbor = sign_envelope_with_key(&envelope_cbor, key_path)
            .unwrap_or_else(|e| panic!("failed to sign envelope with key {key_path:?}: {e}"));
    }

    println!("CBOR Output of Envelope: {}", hex::encode(&envelope_cbor));

    if let Some(out_dir) = output {
        write_output(&out_dir, &source_path, "cbor", &envelope_cbor);
    }
}

/// Writes `contents` to `out_dir/<source_path file stem>.<extension>`, creating `out_dir` if
/// needed.
fn write_output(out_dir: &std::path::Path, source_path: &std::path::Path, extension: &str, contents: &[u8]) {
    fs::create_dir_all(out_dir).expect("failed to create output directory");
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
    fs::write(&out_path, contents).expect("failed to write output file");
    println!("Wrote output to: {out_path:?}");
}
