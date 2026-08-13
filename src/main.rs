use manifest_generator::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope};
use manifest_generator::sign::sign;
use manifest_generator::{
    encode::{encode_envelope, encode_manifest},
    parse::parse,
};
use sha256::Sha256Digest;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Provide default
    let mut json_path = Path::new("examples/test.json");

    let mut key_path = Path::new("key.pem");

    // Path to program is first value of args
    if args.len() > 3 {
        panic!(
            "Unexpected argument length, provide one or none for the example path (cargo run -- <path> <key>)"
        )
    } else if args.len() == 3 {

        json_path = Path::new(args.get(1).expect("JSON Path argument couldn't be parsed"));
        println!("Using path: {json_path:?}");

        key_path = Path::new(args.get(2).expect("Path to key couldn't be parsed"));

    } else if args.len() == 2 {

        json_path = Path::new(args.get(1).expect("JSON Path argument couldn't be parsed"));
        println!("Using path: {json_path:?}");    

    } else {
        println!("Using default path: {json_path:?}");
    }

    let mut reader = BufReader::new(File::open(json_path).unwrap());

    // Parse inner manifest

    let manifest = parse(&mut reader).unwrap();

    let manifest_cbor = encode_manifest(&manifest);

    // Handle Envelope

    let digest = hex::encode(manifest_cbor).digest();

    let suit_auth = SuitAuthentication {
        digest: SuitDigest {
            algorithm: "sha256".to_owned(),
            digest: digest,
        },
        auth_blocks: Vec::new(),
    };

    let mut envelope = SuitEnvelope {
        auth_block: suit_auth,
        manifest: manifest,
    };

    // Yet to be implemented
    if args.len() == 3 {
        envelope = sign(envelope, &key_path);
    }

    let envelope_cbor = encode_envelope(&envelope);

    println!("CBOR Output of Envelope: {}", hex::encode(&envelope_cbor));
}
