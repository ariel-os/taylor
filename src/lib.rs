//! Generates [IETF SUIT](https://www.rfc-editor.org/rfc/rfc9736) manifests, CBOR-encoded,
//! from a JSON description.
//!
//! The pipeline is: [`parse::parse`] reads a JSON description into a [`manifest::SuitManifest`],
//! and [`envelope::build_envelope`] encodes it into a tag-107 `SUIT_Envelope`, optionally signed
//! with a key loaded by [`sign::load_signer`]. The lower-level [`encode`] and [`sign`] functions
//! remain available, and [`cli::run`] runs the `taylor` command-line interface in-process.
//!
//! # Examples
//!
//! ```
//! use taylor::envelope::build_envelope;
//! use taylor::parse::parse;
//!
//! let json = r#"{
//!     "version": 1,
//!     "sequence-number": 1,
//!     "suit-common": {
//!         "suit-components": [["00"]],
//!         "suit-shared-sequence": []
//!     },
//!     "sequence": {}
//! }"#;
//!
//! let manifest = parse(&mut json.as_bytes()).unwrap();
//! let envelope_cbor = build_envelope(manifest, None).unwrap();
//! assert_eq!(&envelope_cbor[..2], &[0xd8, 0x6b]); // tag 107, SUIT_Envelope
//! ```

#![deny(missing_docs)]

pub mod cli;
pub mod encode;
pub mod envelope;
pub mod error;
pub mod manifest;
pub mod parse;
pub mod sign;
pub mod template;
