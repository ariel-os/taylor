//! Generates [IETF SUIT](https://www.rfc-editor.org/rfc/rfc9736) manifests, CBOR-encoded,
//! from a JSON description.
//!
//! The pipeline is: [`parse::parse`] reads a JSON file into a [`manifest::SuitManifest`],
//! [`encode::encode_manifest`] and [`encode::encode_envelope`] serialize it (and its
//! wrapping [`manifest::SuitEnvelope`]) to CBOR, and [`sign::sign`] adds a COSE
//! authentication block (not yet implemented).

#![warn(missing_docs)]

pub mod encode;
pub mod error;
pub mod manifest;
pub mod parse;
pub mod sign;
