//! Assembles a complete, optionally signed, `SUIT_Envelope` from a parsed manifest.

use sha256::Sha256Digest;

use crate::encode::{try_encode_envelope, try_encode_manifest};
use crate::error::Error;
use crate::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope, SuitManifest};
use crate::sign::Signer;

/// Encodes `manifest`, wraps it with its SHA-256 digest in a tag-107 `SUIT_Envelope`, and
/// appends a `COSE_Sign1` authentication block when `signer` is given.
///
/// # Errors
///
/// Returns [`Error::UnsupportedAlgorithm`] if `manifest` contains a digest algorithm other than
/// `sha256`, `sha384`, or `sha512` (manifests returned by [`crate::parse::parse`] never do),
/// and [`Error::Signing`] if signing the envelope fails.
///
/// # Examples
///
/// ```
/// use taylor::envelope::build_envelope;
/// use taylor::parse::parse;
///
/// let json = r#"{
///     "version": 1,
///     "sequence-number": 1,
///     "suit-common": {
///         "suit-components": [["00"]],
///         "suit-shared-sequence": []
///     }
/// }"#;
/// let manifest = parse(&mut json.as_bytes()).unwrap();
///
/// let envelope_cbor = build_envelope(manifest, None).unwrap();
/// assert_eq!(&envelope_cbor[..2], &[0xd8, 0x6b]); // tag 107, SUIT_Envelope
/// ```
pub fn build_envelope(manifest: SuitManifest, signer: Option<&Signer>) -> Result<Vec<u8>, Error> {
    let digest = hex::decode(try_encode_manifest(&manifest)?.digest())
        .expect("sha256 digests are always valid hex");
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
    let envelope_cbor = try_encode_envelope(&envelope)?;

    match signer {
        Some(signer) => Ok(brody::sign_envelope(&envelope_cbor, signer)?),
        None => Ok(envelope_cbor),
    }
}
