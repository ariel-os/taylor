//! Signs `manifest-handler-version.json` with the example ES384 keypair.
//!
//! Run with: `cargo run --example sign_manifest_handler_version`

use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;

use taylor::envelope::{DigestAlgorithm, build_envelope_with_digest};
use taylor::parse::parse;
use taylor::sign::load_signer;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let key_path = root.join("examples/input/keys/demo-private-key-p384.pem");
    let manifest_path = root.join("examples/input/manifests/manifest-handler-version.json");

    let private_key = fs::read_to_string(&key_path).expect("failed to read P-384 private key");
    let signer = load_signer(&private_key).expect("failed to load P-384 signing key");
    assert_eq!(signer.alg_id(), -35, "expected COSE ES384 signing key");

    let mut manifest_file = BufReader::new(
        File::open(&manifest_path).expect("failed to open manifest-handler-version.json"),
    );
    let manifest = parse(&mut manifest_file).expect("failed to parse SUIT manifest");
    let signed_envelope =
        build_envelope_with_digest(manifest, Some(&signer), DigestAlgorithm::Sha384)
            .expect("failed to build signed SUIT envelope");

    let output_dir = root.join("out");
    fs::create_dir_all(&output_dir).expect("failed to create out directory");
    let output_path = output_dir.join("manifest-handler-version-signed.cbor");
    fs::write(&output_path, signed_envelope).expect("failed to write signed SUIT envelope");
    println!("Wrote signed SUIT_Envelope to {}", output_path.display());
}
