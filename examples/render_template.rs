//! Renders `examples/input/templates/manifest.jinja` with sample values, then parses and encodes the
//! result into an unsigned (digest-only) `SUIT_Envelope` CBOR, same as `taylor` does by
//! default when no signing key is provided.
//!
//! Run with: `cargo run --example render_template`

use serde_json::json;
use std::io::Cursor;
use taylor::envelope::build_envelope;
use taylor::parse::parse;
use taylor::template::render;

fn main() {
    let template_path = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/input/templates/manifest.jinja"
    ));

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

    let envelope_cbor = build_envelope(manifest, None).expect("unsigned envelope must build");
    println!(
        "CBOR Output of Envelope (unsigned): {}",
        hex::encode(&envelope_cbor)
    );
}
