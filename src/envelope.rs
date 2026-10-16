//! Assembles a complete, optionally signed, `SUIT_Envelope` from a parsed manifest.

use std::str::FromStr;

use sha2::{Digest, Sha256, Sha384};

use crate::encode::{try_encode_envelope, try_encode_manifest};
use crate::error::Error;
use crate::manifest::{SuitAuthentication, SuitDigest, SuitEnvelope, SuitManifest};
use crate::sign::Signer;

/// Hash algorithm for the manifest digest in an envelope's `SUIT_Authentication` wrapper, which
/// is what a signature covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256, COSE algorithm -16.
    #[default]
    Sha256,
    /// SHA-384, COSE algorithm -43.
    Sha384,
}

impl DigestAlgorithm {
    /// Returns the algorithm's name as used in manifest JSON, such as `"sha384"`.
    pub fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "sha256",
            DigestAlgorithm::Sha384 => "sha384",
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        }
    }
}

impl FromStr for DigestAlgorithm {
    type Err = Error;

    /// Parses an algorithm name as returned by [`DigestAlgorithm::name`].
    fn from_str(name: &str) -> Result<Self, Error> {
        match name {
            "sha256" => Ok(DigestAlgorithm::Sha256),
            "sha384" => Ok(DigestAlgorithm::Sha384),
            other => Err(Error::UnsupportedAlgorithm(format!(
                "{other} for manifest-digest"
            ))),
        }
    }
}

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
    build_envelope_with_digest(manifest, signer, DigestAlgorithm::Sha256)
}

/// Like [`build_envelope`], but computes the manifest digest with `digest_algorithm`.
///
/// # Errors
///
/// The same as [`build_envelope`].
///
/// # Examples
///
/// ```
/// use taylor::envelope::{DigestAlgorithm, build_envelope_with_digest};
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
/// let envelope_cbor = build_envelope_with_digest(manifest, None, DigestAlgorithm::Sha384).unwrap();
/// assert_eq!(&envelope_cbor[..2], &[0xd8, 0x6b]); // tag 107, SUIT_Envelope
/// ```
pub fn build_envelope_with_digest(
    manifest: SuitManifest,
    signer: Option<&Signer>,
    digest_algorithm: DigestAlgorithm,
) -> Result<Vec<u8>, Error> {
    let digest = digest_algorithm.digest(&try_encode_manifest(&manifest)?);
    let envelope = SuitEnvelope {
        auth_block: SuitAuthentication {
            digest: SuitDigest {
                algorithm: digest_algorithm.name().to_owned(),
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
