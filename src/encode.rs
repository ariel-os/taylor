//! CBOR encoding of a [`crate::manifest::SuitManifest`]/[`crate::manifest::SuitEnvelope`],
//! via hand-written [`Serialize`] impls that map each field to its CDDL-mandated integer key.

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
        m.serialize_entry(&2u8, &encode_to_cbor(&self.auth_block))?;
        m.serialize_entry(&3u8, &encode_to_cbor(&self.manifest))?;

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
            s.serialize_element(&encode_to_cbor(&self.digest))?;
            s.serialize_element(&encode_to_cbor(&self.auth_blocks))?;
            s.end()
        } else {
            let mut s = serializer.serialize_tuple(1)?;
            s.serialize_element(&encode_to_cbor(&self.digest))?;
            s.end()
        }
    }
}

impl Serialize for SuitManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(3 + self.sequence.len()))?; // 3 for version, sequence number and suit_common, rest is the command sequence
        m.serialize_entry(&1u8, &self.version)?;
        m.serialize_entry(&2u8, &self.sequence_number)?;
        m.serialize_entry(&3u8, &encode_to_cbor(&self.suit_common))?;
        for value in &self.sequence {
            match value.sequence {
                crate::manifest::SuitCommandSequenceEnum::SuitInstall => {
                    m.serialize_entry(&20u8, &encode_to_cbor(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitPayloadFetch => {
                    m.serialize_entry(&16u8, &encode_to_cbor(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitValidate => {
                    m.serialize_entry(&7u8, &encode_to_cbor(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitLoad => {
                    m.serialize_entry(&8u8, &encode_to_cbor(FlatSequence(&value.actions)))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitInvoke => {
                    m.serialize_entry(&9u8, &encode_to_cbor(FlatSequence(&value.actions)))?;
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
        m.serialize_entry(&4u8, &encode_to_cbor(FlatSequence(&self.shared_sequence)))?;
        m.end()
    }
}

impl Serialize for SuitDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // suit-digest-algorithm-id is REQUIRED; per suit-manifest.cddl cose-alg-* values.
        let alg_id: i8 = match self.algorithm.as_ref() {
            "sha256" => -16,
            "sha384" => -43,
            "sha512" => -44,
            _ => {
                return Err(ser::Error::custom("unsupported digest algorithm"));
            }
        };
        let mut s = serializer.serialize_tuple(2)?;
        s.serialize_element(&alg_id)?;
        s.serialize_element(&ByteBuf::from(self.digest.clone()))?;
        s.end()
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
                map.serialize_entry(&3u8, &encode_to_cbor(digest))?;
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
        }
        Ok(())
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
            seq.serialize_element(&encode_to_cbor(FlatSequence(branch)))?;
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
                seq.serialize_element(&encode_to_cbor(FlatSequence(nested)))?;
            }
            SuitDirectiveSwap(v) => {
                seq.serialize_element(&31u8)?;
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

/// Helper function for recursive CBOR encoding
/// Takes generic value that already implements the Serialize trait and encodes it into CBOR
fn encode_to_cbor<T>(str: T) -> ByteBuf
where
    T: Sized + ser::Serialize,
{
    let mut buf = Vec::new();
    into_writer(&str, &mut buf).unwrap();

    ByteBuf::from(buf)
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
pub fn encode_manifest(manifest: &SuitManifest) -> Vec<u8> {
    let mut manifest_bytes = Vec::new();

    into_writer(manifest, &mut manifest_bytes).unwrap();
    //let mut encoded = Vec::new();
    let mut encoded = encode_cbor_bstr_header(manifest_bytes.len());
    encoded.extend_from_slice(&manifest_bytes);

    encoded
}

/// Encodes `envelope` as a tag-107 `SUIT_Envelope` (per the IANA CBOR tag registry).
pub fn encode_envelope(envelope: &SuitEnvelope) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Tag envelope with 107 according to IANA
    encoded.extend_from_slice(&[0xD8, 0x6B]);
    into_writer(envelope, &mut encoded).unwrap();
    encoded
}
