use taylor::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope};
use taylor::sign::sign;
use taylor::{
    encode::{encode_envelope, encode_manifest},
    parse::parse,
};
use sha256::Sha256Digest;
use std::env;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Provide default
    let mut json_path = Path::new("examples/test.json");

    let mut key_path = Path::new("key.pem");

    // Pull the --output/-o <dir> flag out first so it can appear in any position,
    // leaving the rest as positional (json path, key path) arguments.
    let mut output_dir: Option<&str> = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                output_dir = Some(
                    args.get(i)
                        .expect("--output requires a directory argument")
                        .as_str(),
                );
            }
            other => positional.push(other),
        }
        i += 1;
    }

    let should_sign = positional.len() == 2;

    // Path to program is first value of args
    if positional.len() > 2 {
        panic!(
            "Unexpected argument length, provide one or none for the example path (cargo run -- <path> <key> [--output <dir>])"
        )
    } else if positional.len() == 2 {

        json_path = Path::new(positional[0]);
        println!("Using path: {json_path:?}");

        key_path = Path::new(positional[1]);

    } else if positional.len() == 1 {

        json_path = Path::new(positional[0]);
        println!("Using path: {json_path:?}");

    } else {
        println!("Using default path: {json_path:?}");
    }

    let mut reader = BufReader::new(File::open(json_path).unwrap());

    // Parse inner manifest

    let manifest = parse(&mut reader).unwrap();

    let manifest_cbor = encode_manifest(&manifest);
    // Handle Envelope

    // Hash the raw manifest bytes, not their hex-text representation
    let digest_hex = manifest_cbor.digest();
    let digest = hex::decode(&digest_hex).expect("sha256 digest hex must be valid");
    println!("digest string :: {:?}", digest_hex);
    // SUIT_Authentication allows zero auth blocks; sign() adds a real one when signing
    let suit_auth = SuitAuthentication {
        digest: SuitDigest {
            algorithm: "sha256".to_owned(),
            digest,
        },
        auth_blocks: Vec::new(),
    };

    let mut envelope = SuitEnvelope {
        auth_block: suit_auth,
        manifest,
    };

    // Yet to be implemented
    if should_sign {
        envelope = sign(envelope, key_path);
    }

    let envelope_cbor = encode_envelope(&envelope);

    println!("CBOR Output of Envelope: {}", hex::encode(&envelope_cbor));

    if let Some(dir) = output_dir {
        let out_dir = Path::new(dir);
        fs::create_dir_all(out_dir).expect("failed to create output directory");
        let file_stem = json_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("manifest");
        let out_path = out_dir.join(format!("{file_stem}.cbor"));
        fs::write(&out_path, &envelope_cbor).expect("failed to write CBOR output file");
        println!("Wrote CBOR output to: {out_path:?}");
    }
}
