//! Generates [IETF SUIT](https://www.rfc-editor.org/rfc/rfc9736) manifests, CBOR-encoded,
//! from a JSON description.
//!
//! The pipeline is: [`parse::parse`] reads a JSON file into a [`manifest::SuitManifest`],
//! [`encode::encode_manifest`] and [`encode::encode_envelope`] serialize it (and its
//! wrapping [`manifest::SuitEnvelope`]) to CBOR, and [`sign::sign_envelope_with_key`] adds a
//! COSE authentication block when signing is requested.
//!
//! # Examples
//!
//! ```
//! use std::fs::{self, File};
//! use std::io::BufReader;
//! use taylor::encode::{encode_envelope, encode_manifest};
//! use taylor::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope};
//! use taylor::parse::parse;
//!
//! let path = std::env::temp_dir().join("taylor_lib_doctest.json");
//! fs::write(&path, r#"{
//!     "version": 1,
//!     "sequence-number": 1,
//!     "suit-common": {
//!         "suit-components": [["00"]],
//!         "suit-shared-sequence": []
//!     },
//!     "sequence": {}
//! }"#).unwrap();
//!
//! let mut reader = BufReader::new(File::open(&path).unwrap());
//! let manifest = parse(&mut reader).unwrap();
//! let manifest_cbor = encode_manifest(&manifest);
//!
//! let envelope = SuitEnvelope {
//!     auth_block: SuitAuthentication {
//!         digest: SuitDigest { algorithm: "sha256".to_string(), digest: vec![0u8; 32] },
//!         auth_blocks: vec![],
//!     },
//!     manifest,
//! };
//! let envelope_cbor = encode_envelope(&envelope);
//! assert_eq!(&envelope_cbor[..2], &[0xd8, 0x6b]); // tag 107, SUIT_Envelope
//! assert!(!manifest_cbor.is_empty());
//!
//! fs::remove_file(&path).unwrap();
//! ```

#![deny(missing_docs)]

pub mod encode;
pub mod error;
pub mod manifest;
pub mod parse;
pub mod sign;
