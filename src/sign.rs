//! Signs an encoded `SUIT_Envelope` with a PEM-encoded EC private key, via `brody`.
//!
//! Promoted out of the CLI so library consumers can reuse the ES256/ES384 key-loading and
//! signing convenience without re-implementing it.

use std::fs;
use std::path::Path;

use brody::{Algorithm, Error as BrodyError, Signer};

/// Loads a signing key from `pem`, trying ES256 then ES384 since the PEM itself doesn't name
/// its curve.
///
/// # Examples
///
/// ```
/// use taylor::sign::load_signer;
///
/// // Throwaway P-256 test key (PKCS8 PEM), generated solely for this example via:
/// // `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`
/// const ES256_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
/// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIGiK10T2DJEwqIOE
/// 8XkajPi9ZNGcgjaj8g/CBXJLEQ6hRANCAARf28DDbnSxAW/ojnCy9ilaBwuFqHEW
/// j3Mhq0ZdNGiyWrDruCZ5n5JfJsy9ae5zxsg4OmQa8e1w4IkL143PSLrx
/// -----END PRIVATE KEY-----";
///
/// let signer = load_signer(ES256_TEST_KEY_PEM).unwrap();
/// assert_eq!(signer.alg_id(), -7); // ES256
/// ```
pub fn load_signer(pem: &str) -> Result<Signer, BrodyError> {
    Signer::from_pem(pem, Algorithm::Es256).or_else(|_| Signer::from_pem(pem, Algorithm::Es384))
}

/// Reads the PEM key at `key_path` and returns `envelope_cbor` with a `COSE_Sign1`
/// authentication block appended over its digest.
///
/// # Errors
///
/// Returns [`BrodyError::Io`] if `key_path` can't be read, [`BrodyError::InvalidKey`] if the
/// PEM doesn't parse as ES256 or ES384, or [`BrodyError::InvalidEnvelope`] if `envelope_cbor`
/// isn't a well-formed `SUIT_Envelope`.
///
/// # Examples
///
/// ```
/// use serde_bytes::ByteBuf;
/// use taylor::encode::encode_envelope;
/// use taylor::manifest::{SuitAuthentication, SuitCommon, SuitDigest, SuitEnvelope, SuitManifest};
/// use taylor::sign::sign_envelope_with_key;
///
/// # const ES256_TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
/// # MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIGiK10T2DJEwqIOE
/// # 8XkajPi9ZNGcgjaj8g/CBXJLEQ6hRANCAARf28DDbnSxAW/ojnCy9ilaBwuFqHEW
/// # j3Mhq0ZdNGiyWrDruCZ5n5JfJsy9ae5zxsg4OmQa8e1w4IkL143PSLrx
/// # -----END PRIVATE KEY-----";
/// let key_path = std::env::temp_dir().join("taylor_sign_doctest_key.pem");
/// std::fs::write(&key_path, ES256_TEST_KEY_PEM).unwrap();
///
/// let envelope = SuitEnvelope {
///     auth_block: SuitAuthentication {
///         digest: SuitDigest { algorithm: "sha256".to_string(), digest: vec![0u8; 32] },
///         auth_blocks: vec![],
///     },
///     manifest: SuitManifest {
///         version: 1,
///         suit_set_version: None,
///         sequence_number: 1,
///         suit_common: SuitCommon {
///             components: vec![vec![ByteBuf::from(vec![0x00])]],
///             shared_sequence: vec![],
///         },
///         sequence: vec![],
///     },
/// };
/// let envelope_cbor = encode_envelope(&envelope);
///
/// let signed = sign_envelope_with_key(&envelope_cbor, &key_path).unwrap();
/// assert!(signed.len() > envelope_cbor.len());
///
/// std::fs::remove_file(&key_path).unwrap();
/// ```
pub fn sign_envelope_with_key(
    envelope_cbor: &[u8],
    key_path: &Path,
) -> Result<Vec<u8>, BrodyError> {
    let pem = fs::read_to_string(key_path)?;
    let signer = load_signer(&pem)?;
    brody::sign_envelope(envelope_cbor, &signer)
}
