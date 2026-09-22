use clap::Parser;
use taylor::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope};
use taylor::sign::sign_envelope_with_key;
use taylor::{
    encode::{encode_envelope, encode_manifest},
    parse::parse,
};
use sha256::Sha256Digest;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the input JSON manifest.
    json_path: Option<PathBuf>,

    /// Path to a PEM-encoded EC private key (P-256/ES256 or P-384/ES384). Providing this
    /// signs the envelope with a COSE_Sign1 authentication block.
    #[arg(short = 'k', long = "key", value_name = "PEM_FILE")]
    key_path: Option<PathBuf>,

    /// Directory where the generated CBOR envelope is written.
    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,
}

fn main() {
    let Cli {
        json_path,
        key_path,
        output,
    } = Cli::parse();
    let has_json_path = json_path.is_some();
    let should_sign = key_path.is_some();
    let json_path = json_path.unwrap_or_else(|| PathBuf::from("examples/test.json"));

    if should_sign || has_json_path {
        println!("Using path: {json_path:?}");
    } else {
        println!("Using default path: {json_path:?}");
    }

    let mut reader = BufReader::new(File::open(&json_path).unwrap());

    // Parse inner manifest

    let manifest = parse(&mut reader).unwrap();

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
        fs::create_dir_all(&out_dir).expect("failed to create output directory");
        let file_stem = json_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("manifest");
        let out_path = out_dir.join(format!("{file_stem}.cbor"));
        fs::write(&out_path, &envelope_cbor).expect("failed to write CBOR output file");
        println!("Wrote CBOR output to: {out_path:?}");
    }
}

