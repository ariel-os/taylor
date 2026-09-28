//! Renders `templates/manifest.json.jinja` with sample values, then parses and encodes the
//! result into an unsigned (digest-only) `SUIT_Envelope` CBOR, same as `taylor` does by
//! default when no signing key is provided.
//!
//! Run with: `cargo run --example render_template`

use serde_json::json;
use sha256::Sha256Digest;
use std::io::Cursor;
use taylor::encode::{encode_envelope, encode_manifest};
use taylor::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope};
use taylor::parse::parse;
use taylor::template::render;

fn main() {
    let template_path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/manifest.json.jinja"));

    let context = json!({
        "sequence_number": 1,
        "vendor_id": "67e55044-10b1-426f-9247-bb680e5fe0c8",
        "class_id": "69e55044-10b1-426f-2974-bb680e5fedc8",
        "image_size": 1024,
        "digest": "c12efb651dc800465d80264343852c304c4dcea2da82828d8824df7638628d17",
        "uri": "https://example.com/firmware.bin",
    });

    let rendered = render(template_path, &context).expect("template must render to valid JSON");
    println!("{rendered}");

    let manifest = parse(&mut Cursor::new(rendered.as_bytes()))
        .expect("rendered JSON must parse as a SUIT manifest");

    let manifest_cbor = encode_manifest(&manifest);
    let digest_hex = manifest_cbor.digest();
    let digest = hex::decode(&digest_hex).expect("sha256 digest hex must be valid");

    // Unsigned envelope: zero auth blocks, digest-only authentication.
    let envelope = SuitEnvelope {
        auth_block: SuitAuthentication {
            digest: SuitDigest {
                algorithm: "sha256".to_owned(),
                digest,
            },
            auth_blocks: Vec::new(),
        },
        manifest,
    };

    let envelope_cbor = encode_envelope(&envelope);
    println!("CBOR Output of Envelope (unsigned): {}", hex::encode(&envelope_cbor));
}
