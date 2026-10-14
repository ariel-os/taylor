//! CBOR encoding of a [`crate::manifest::SuitManifest`]/[`crate::manifest::SuitEnvelope`],
//! via hand-written [`Serialize`] impls that map each field to its CDDL-mandated integer key.

use crate::error::Error;
use crate::manifest::{
    SuitAuthentication, SuitCommand, SuitCommon, SuitDigest, SuitEnvelope, SuitManifest,
    SuitParameter,
};
use ciborium::ser::into_writer;
use serde::{
    Serialize,
    ser::{self, SerializeMap, SerializeSeq, SerializeTuple},
};
use serde_bytes::ByteBuf;

impl Serialize for SuitEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut m = serializer.serialize_map(Some(2))?;

        // integer keys 2 and 3 (not "2"/"3")
        m.serialize_entry(&2u8, &CborBstr(&self.auth_block))?;
        m.serialize_entry(&3u8, &CborBstr(&self.manifest))?;

        m.end()
    }
}

impl Serialize for SuitAuthentication {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if !self.auth_blocks.is_empty() {
            let mut s = serializer.serialize_tuple(2)?;
            s.serialize_element(&CborBstr(&self.digest))?;
            s.serialize_element(&CborBstr(&self.auth_blocks))?;
            s.end()
        } else {
            let mut s = serializer.serialize_tuple(1)?;
            s.serialize_element(&CborBstr(&self.digest))?;
            s.end()
        }
    }
}

impl Serialize for SuitManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let optional_members = usize::from(self.suit_set_version.is_some());
        let mut m = serializer.serialize_map(Some(3 + optional_members + self.sequence.len()))?;
        m.serialize_entry(&1u8, &self.version)?;
        m.serialize_entry(&2u8, &self.sequence_number)?;
        m.serialize_entry(&3u8, &CborBstr(&self.suit_common))?;
        if let Some(set_version) = &self.suit_set_version {
            m.serialize_entry(&6u8, &CborBstr(set_version))?;
        }
        for value in &self.sequence {
            match value.sequence {
                crate::manifest::SuitCommandSequenceEnum::SuitInstall => {
                    m.serialize_entry(&20u8, &CborBstr(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitPayloadFetch => {
                    m.serialize_entry(&16u8, &CborBstr(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitValidate => {
                    m.serialize_entry(&7u8, &CborBstr(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitLoad => {
                    m.serialize_entry(&8u8, &CborBstr(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitInvoke => {
                    m.serialize_entry(&9u8, &CborBstr(FlatSequence(&value.actions)))?;
                }
            }
        }
        m.end()
    }
}

impl Serialize for SuitCommon {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(2))?;
        // suit-components is a direct array (not bstr-wrapped); only shared-sequence is wrapped
        m.serialize_entry(&2u8, &self.components)?;
        m.serialize_entry(&4u8, &CborBstr(FlatSequence(&self.shared_sequence)))?;
        m.end()
    }
}

impl Serialize for SuitDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // suit-digest-algorithm-id is REQUIRED; per suit-manifest.cddl cose-alg-* values.
        let alg_id = digest_algorithm_id(&self.algorithm).ok_or_else(|| {
            <S::Error as ser::Error>::custom(format_args!("{} for SuitDigest", self.algorithm))
        })?;
        let mut s = serializer.serialize_tuple(2)?;
        s.serialize_element(&alg_id)?;
        s.serialize_element(&ByteBuf::from(self.digest.clone()))?;
        s.end()
    }
}

/// Maps a `SuitDigest` algorithm name to its COSE algorithm id, or `None` if unsupported.
pub(crate) fn digest_algorithm_id(name: &str) -> Option<i8> {
    match name {
        "sha256" => Some(-16),
        "sha384" => Some(-43),
        "sha512" => Some(-44),
        _ => None,
    }
}

impl SuitParameter {
    /// Writes this parameter's key+value as one entry into a caller-supplied map, so multiple
    /// parameters can be merged into a single `{+ $$SUIT_Parameters}` map.
    fn write_entry<M>(&self, map: &mut M) -> Result<(), M::Error>
    where
        M: SerializeMap,
    {
        match &self.ident {
            crate::manifest::SuitParametersEnum::SuitVendorID(bytes) => {
                map.serialize_entry(&1u8, &ByteBuf::from(bytes.clone()))?;
            }
            crate::manifest::SuitParametersEnum::SuitClassID(bytes) => {
                map.serialize_entry(&2u8, &ByteBuf::from(bytes.clone()))?;
            }
            crate::manifest::SuitParametersEnum::SuitImageDigest(digest) => {
                if digest_algorithm_id(&digest.algorithm).is_none() {
                    return Err(<M::Error as ser::Error>::custom(format_args!(
                        "{} for image-digest",
                        digest.algorithm
                    )));
                }
                map.serialize_entry(&3u8, &CborBstr(digest))?;
            }
            crate::manifest::SuitParametersEnum::SuitComponentSlot(v) => {
                map.serialize_entry(&5u8, v)?;
            }
            crate::manifest::SuitParametersEnum::SuitStrictOrder(v) => {
                map.serialize_entry(&12u8, v)?;
            }
            crate::manifest::SuitParametersEnum::SuitSoftFailure(v) => {
                map.serialize_entry(&13u8, v)?;
            }
            crate::manifest::SuitParametersEnum::SuitImageSize(v) => {
                map.serialize_entry(&14u8, v)?;
            }
            crate::manifest::SuitParametersEnum::SuitContent(bytes) => {
                map.serialize_entry(&18u8, &ByteBuf::from(bytes.clone()))?;
            }
            crate::manifest::SuitParametersEnum::SuitURI(v) => {
                map.serialize_entry(&21u8, v)?;
            }
            crate::manifest::SuitParametersEnum::SuitSourceComponent(v) => {
                map.serialize_entry(&22u8, v)?;
            }
            crate::manifest::SuitParametersEnum::SuitInvokeArgs(bytes) => {
                map.serialize_entry(&23u8, &ByteBuf::from(bytes.clone()))?;
            }
            crate::manifest::SuitParametersEnum::SuitDeviceID(bytes) => {
                map.serialize_entry(&24u8, &ByteBuf::from(bytes.clone()))?;
            }
            crate::manifest::SuitParametersEnum::SuitFetchArguments(bytes) => {
                map.serialize_entry(&25u8, &ByteBuf::from(bytes.clone()))?;
            }
            crate::manifest::SuitParametersEnum::SuitVersion(version_match) => {
                map.serialize_entry(&28u8, &CborBstr(version_match))?;
            }
        }
        Ok(())
    }
}

/// `SUIT_Parameter_Version_Match = [comparison-type, SUIT_Condition_Version_Comparison_Value]`.
impl Serialize for crate::manifest::SuitVersionMatch {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use crate::manifest::VersionComparisonType::*;
        let comparison_type: i8 = match self.comparison {
            Greater => 1,
            GreaterOrEqual => 2,
            Equal => 3,
            LesserOrEqual => 4,
            Lesser => 5,
        };
        let mut s = serializer.serialize_tuple(2)?;
        s.serialize_element(&comparison_type)?;
        s.serialize_element(&self.value)?;
        s.end()
    }
}

/// A whole `Vec<SuitParameter>` merged into ONE CBOR map, per `{+ $$SUIT_Parameters}`.
struct MergedParams<'a>(&'a [SuitParameter]);

impl<'a> Serialize for MergedParams<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(self.0.len()))?;
        for param in self.0 {
            param.write_entry(&mut m)?;
        }
        m.end()
    }
}

/// A command sequence as the flat array CDDL requires: alternating (code, argument) pairs,
/// instead of an array of per-command maps.
struct FlatSequence<'a>(&'a [SuitCommand]);

impl<'a> Serialize for FlatSequence<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len() * 2))?;
        for cmd in self.0 {
            cmd.serialize_pair(&mut seq)?;
        }
        seq.end()
    }
}

/// `[2* bstr .cbor SUIT_Command_Sequence, ?nil]` - try-each's branch list plus optional fallback.
struct TryEachArg<'a>(&'a [Vec<SuitCommand>], bool);

impl<'a> Serialize for TryEachArg<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let extra = if self.1 { 1 } else { 0 };
        let mut seq = serializer.serialize_seq(Some(self.0.len() + extra))?;
        for branch in self.0 {
            seq.serialize_element(&CborBstr(FlatSequence(branch)))?;
        }
        if self.1 {
            seq.serialize_element(&())?;
        }
        seq.end()
    }
}

impl SuitCommand {
    /// Serializes this command as a (code, argument) pair into a flat sequence array.
    fn serialize_pair<S>(&self, seq: &mut S) -> Result<(), S::Error>
    where
        S: SerializeSeq,
    {
        use crate::manifest::SuitCommandEnum::*;
        match &self.ident {
            SuitConditionVendorIdentifier(v) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(v)?;
            }
            SuitConditionClassIdentifier(v) => {
                seq.serialize_element(&2u8)?;
                seq.serialize_element(v)?;
            }
            SuitConditionDeviceIdentifier(v) => {
                seq.serialize_element(&24u8)?;
                seq.serialize_element(v)?;
            }
            SuitConditionImageMatch(v) => {
                seq.serialize_element(&3u8)?;
                seq.serialize_element(v)?;
            }
            SuitConditionCheckContent(v) => {
                seq.serialize_element(&6u8)?;
                seq.serialize_element(v)?;
            }
            SuitConditionComponentSlot(v) => {
                seq.serialize_element(&5u8)?;
                seq.serialize_element(v)?;
            }
            SuitConditionAbort(v) => {
                seq.serialize_element(&14u8)?;
                seq.serialize_element(v)?;
            }
            SuitDirectiveSetComponentIndex(v) => {
                seq.serialize_element(&12u8)?;
                seq.serialize_element(v)?;
            }
            SuitDirectiveTryEach(branches, else_nil) => {
                seq.serialize_element(&15u8)?;
                seq.serialize_element(&TryEachArg(branches, *else_nil))?;
            }
            SuitDirectiveOverrideParameters(params) => {
                seq.serialize_element(&20u8)?;
                seq.serialize_element(&MergedParams(params))?;
            }
            SuitDirectiveFetch(v) => {
                seq.serialize_element(&21u8)?;
                seq.serialize_element(v)?;
            }
            SuitDirectiveCopy(v) => {
                seq.serialize_element(&22u8)?;
                seq.serialize_element(v)?;
            }
            SuitDirectiveWrite(v) => {
                seq.serialize_element(&18u8)?;
                seq.serialize_element(v)?;
            }
            SuitDirectiveInvoke(v) => {
                seq.serialize_element(&23u8)?;
                seq.serialize_element(v)?;
            }
            SuitDirectiveRunSequence(nested) => {
                seq.serialize_element(&32u8)?;
                seq.serialize_element(&CborBstr(FlatSequence(nested)))?;
            }
            SuitDirectiveSwap(v) => {
                seq.serialize_element(&31u8)?;
                seq.serialize_element(v)?;
            }
            SuitConditionVersion(v) => {
                seq.serialize_element(&28u8)?;
                seq.serialize_element(v)?;
            }
            // Not spec-conformant (see manifest.rs) - kept minimal/out of scope.
            SuitCommandCustom(v) => {
                seq.serialize_element(&9u8)?;
                seq.serialize_element(v)?;
            }
        }
        Ok(())
    }
}

/// Writing into a `Vec` can't fail, so in practice this is a `SuitDigest` algorithm error.
fn cbor_error_message(error: ciborium::ser::Error<std::io::Error>) -> String {
    match error {
        ciborium::ser::Error::Value(message) => message,
        ciborium::ser::Error::Io(error) => error.to_string(),
    }
}

/// Encodes `value` into CBOR bytes.
fn encode_to_cbor<T: Serialize>(value: T) -> Result<ByteBuf, String> {
    let mut buf = Vec::new();
    into_writer(&value, &mut buf).map_err(cbor_error_message)?;
    Ok(ByteBuf::from(buf))
}

/// `bstr .cbor T`: serializes the wrapped value as a bstr holding its CBOR encoding.
struct CborBstr<T>(T);

impl<T: Serialize> Serialize for CborBstr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        encode_to_cbor(&self.0)
            .map_err(<S::Error as ser::Error>::custom)?
            .serialize(serializer)
    }
}

// Encode manifest first to calculate digest for envelope

fn encode_cbor_bstr_header(len: usize) -> Vec<u8> {
    match len {
        0..=23 => vec![0x40 | (len as u8)],
        24..=0xFF => vec![0x58, len as u8],
        0x100..=0xFFFF => {
            let mut header = vec![0x59];
            header.extend_from_slice(&(len as u16).to_be_bytes());
            header
        }
        0x1_0000..=0xFFFF_FFFF => {
            let mut header = vec![0x5A];
            header.extend_from_slice(&(len as u32).to_be_bytes());
            header
        }
        _ => {
            let mut header = vec![0x5B];
            header.extend_from_slice(&(len as u64).to_be_bytes());
            header
        }
    }
}

/// Encodes `manifest` as a `bstr .cbor SUIT_Manifest`: its CBOR map, prefixed with a bstr
/// length header. The digest embedded in the envelope's `SuitAuthentication` is computed
/// over these exact bytes.
///
/// # Panics
///
/// Panics if a [`SuitDigest`] in `manifest` uses an algorithm other than `sha256`, `sha384`,
/// or `sha512`. Manifests returned by [`crate::parse::parse`] never do; use
/// [`crate::envelope::build_envelope`] for a non-panicking path.
///
/// # Examples
///
/// ```
/// use serde_bytes::ByteBuf;
/// use taylor::encode::encode_manifest;
/// use taylor::manifest::{SuitCommon, SuitManifest};
///
/// let components = vec![vec![ByteBuf::from(vec![0x00])]];
/// let manifest = SuitManifest::new(1, SuitCommon::new(components, vec![]));
///
/// let cbor = encode_manifest(&manifest);
/// assert!(!cbor.is_empty());
/// ```
pub fn encode_manifest(manifest: &SuitManifest) -> Vec<u8> {
    try_encode_manifest(manifest).unwrap_or_else(|e| panic!("{e}"))
}

/// Fallible [`encode_manifest`].
pub(crate) fn try_encode_manifest(manifest: &SuitManifest) -> Result<Vec<u8>, Error> {
    let mut manifest_bytes = Vec::new();

    into_writer(manifest, &mut manifest_bytes)
        .map_err(|e| Error::UnsupportedAlgorithm(cbor_error_message(e)))?;
    let mut encoded = encode_cbor_bstr_header(manifest_bytes.len());
    encoded.extend_from_slice(&manifest_bytes);

    Ok(encoded)
}

/// Encodes `envelope` as a tag-107 `SUIT_Envelope` (per the IANA CBOR tag registry).
///
/// # Panics
///
/// Panics if a [`SuitDigest`] in `envelope` uses an algorithm other than `sha256`, `sha384`,
/// or `sha512`. Manifests returned by [`crate::parse::parse`] never do; use
/// [`crate::envelope::build_envelope`] for a non-panicking path.
///
/// # Examples
///
/// ```
/// use serde_bytes::ByteBuf;
/// use taylor::encode::encode_envelope;
/// use taylor::manifest::{
///     SuitAuthentication, SuitCommon, SuitDigest, SuitEnvelope, SuitManifest,
/// };
///
/// let components = vec![vec![ByteBuf::from(vec![0x00])]];
/// let manifest = SuitManifest::new(1, SuitCommon::new(components, vec![]));
///
/// let envelope = SuitEnvelope {
///     auth_block: SuitAuthentication {
///         digest: SuitDigest { algorithm: "sha256".to_string(), digest: vec![0u8; 32] },
///         auth_blocks: vec![],
///     },
///     manifest,
/// };
///
/// let cbor = encode_envelope(&envelope);
/// // `0xd8 0x6b` is the two-byte encoding of CBOR tag 107 (SUIT_Envelope).
/// assert_eq!(&cbor[..2], &[0xd8, 0x6b]);
/// ```
pub fn encode_envelope(envelope: &SuitEnvelope) -> Vec<u8> {
    try_encode_envelope(envelope).unwrap_or_else(|e| panic!("{e}"))
}

/// Fallible [`encode_envelope`].
pub(crate) fn try_encode_envelope(envelope: &SuitEnvelope) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();

    // Tag envelope with 107 according to IANA
    encoded.extend_from_slice(&[0xD8, 0x6B]);
    into_writer(envelope, &mut encoded)
        .map_err(|e| Error::UnsupportedAlgorithm(cbor_error_message(e)))?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        SuitCommandEnum, SuitParametersEnum, SuitVersionMatch, VersionComparisonType,
    };

    /// Known-answer test, independently cross-checked with Python's `cbor2`
    /// (`cbor2.dumps((-16, digest_bytes))`). Guards the COSE algorithm-id mapping
    /// (`sha256` -> -16) and the 2-tuple shape, byte-for-byte.
    #[test]
    fn suit_digest_sha256_encodes_cose_alg_id_and_raw_bytes() {
        let digest = SuitDigest {
            algorithm: "sha256".to_string(),
            digest: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let bytes = encode_to_cbor(&digest).unwrap();
        assert_eq!(hex::encode(bytes.as_slice()), "822f44aabbccdd");
    }

    /// `suit-digest-algorithm-id` is a REQUIRED CDDL field; an unrecognized algorithm must
    /// be a hard error, never a silently-truncated (and therefore invalid) CBOR tuple.
    #[test]
    fn suit_digest_unknown_algorithm_is_a_serialize_error() {
        let digest = SuitDigest {
            algorithm: "aes-ccm-mac".to_string(),
            digest: vec![0xAA],
        };
        let mut buf = Vec::new();
        assert!(into_writer(&digest, &mut buf).is_err());
    }

    /// Cross-checked with `cbor2.dumps((3, [1, 0, 0]))`.
    #[test]
    fn suit_version_match_encodes_as_comparison_and_value_tuple() {
        let version_match = SuitVersionMatch {
            comparison: VersionComparisonType::Equal,
            value: vec![1, 0, 0],
        };
        let bytes = encode_to_cbor(&version_match).unwrap();
        assert_eq!(hex::encode(bytes.as_slice()), "820383010000");
    }

    #[test]
    fn flat_sequence_alternates_code_and_argument() {
        let commands = vec![
            SuitCommand {
                ident: SuitCommandEnum::SuitDirectiveSetComponentIndex(1),
            },
            SuitCommand {
                ident: SuitCommandEnum::SuitConditionVersion(15),
            },
        ];
        let bytes = encode_to_cbor(FlatSequence(&commands)).unwrap();
        // array(4): [12, 1, 28, 15] - 28 needs a 1-byte-extra encoding (>23).
        assert_eq!(hex::encode(bytes.as_slice()), "840c01181c0f");
    }

    /// `SuitDirectiveOverrideParameters` merges every parameter into ONE CBOR map,
    /// per `{+ $$SUIT_Parameters}`, rather than one map per parameter.
    #[test]
    fn override_parameters_merges_multiple_params_into_one_map() {
        let params = vec![
            SuitParameter {
                ident: SuitParametersEnum::SuitImageSize(16),
            },
            SuitParameter {
                ident: SuitParametersEnum::SuitStrictOrder(true),
            },
        ];
        let bytes = encode_to_cbor(MergedParams(&params)).unwrap();
        // map(2), insertion order preserved: {14: 16, 12: true}
        assert_eq!(hex::encode(bytes.as_slice()), "a20e100cf5");
    }

    /// A `try-each` with `else_nil = false` must NOT append a CBOR `null` element;
    /// only `else_nil = true` may add the `?nil` fallback per `SUIT_Directive_Try_Each`.
    /// Each branch is `bstr .cbor SUIT_Command_Sequence`, i.e. bstr-wrapped, not inlined.
    #[test]
    fn try_each_arg_omits_nil_when_else_nil_is_false() {
        let branch = vec![SuitCommand {
            ident: SuitCommandEnum::SuitConditionVersion(15),
        }];
        let bytes = encode_to_cbor(TryEachArg(std::slice::from_ref(&branch), false)).unwrap();
        // array(1): [ bstr(len4)( array(2)[28, 15] ) ] = 81 44 82 18 1c 0f
        assert_eq!(hex::encode(bytes.as_slice()), "814482181c0f");
    }

    #[test]
    fn try_each_arg_appends_nil_when_else_nil_is_true() {
        let branches: Vec<Vec<SuitCommand>> = vec![];
        let bytes = encode_to_cbor(TryEachArg(&branches, true)).unwrap();
        // array(1): [ null ] = 0x81 0xF6
        assert_eq!(hex::encode(bytes.as_slice()), "81f6");
    }
}
