use crate::manifest::{
    SuitAuthentication, SuitCommand, SuitCommon, SuitDigest, SuitEnvelope, SuitManifest,
    SuitParameter,
};
use ciborium::ser::into_writer;
use serde::{
    Serialize,
    ser::{self, SerializeMap, SerializeTuple},
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
        if self.auth_blocks.len() > 0 {
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
                    m.serialize_entry(&20u8, &encode_to_cbor(&value.actions))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitPayloadFetch => {
                    m.serialize_entry(&16u8, &encode_to_cbor(&value.actions))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitValidate => {
                    m.serialize_entry(&7u8, &encode_to_cbor(&value.actions))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitLoad => {
                    m.serialize_entry(&8u8, &encode_to_cbor(&value.actions))?;
                }
                crate::manifest::SuitCommandSequenceEnum::SuitInvoke => {
                    m.serialize_entry(&9u8, &encode_to_cbor(&value.actions))?;
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
        m.serialize_entry(&2u8, &encode_to_cbor(&self.components))?;
        m.serialize_entry(&4u8, &encode_to_cbor(&self.shared_sequence))?;
        m.end()
    }
}

impl Serialize for SuitDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_tuple(2)?;
        match self.algorithm.as_ref() {
            "sha256" => {
                s.serialize_element(&-16i8)?;
            }
            _ => {}
        }
        s.serialize_element(&encode_to_cbor(&self.digest))?;
        s.end()
    }
}

impl Serialize for SuitParameter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(1))?;
        match &self.ident {
            crate::manifest::SuitParametersEnum::SuitVendorID(str) => {
                m.serialize_entry(&1u8, &encode_to_cbor(str))?;
            }
            crate::manifest::SuitParametersEnum::SuitClassID(str) => {
                m.serialize_entry(&2u8, &encode_to_cbor(str))?;
            }
            crate::manifest::SuitParametersEnum::SuitImageDigest(str) => {
                m.serialize_entry(&3u8, &encode_to_cbor(str))?;
            }
            crate::manifest::SuitParametersEnum::SuitComponentSlot(str) => {
                m.serialize_entry(&5u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitStrictOrder(str) => {
                m.serialize_entry(&12u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitSoftFailure(str) => {
                m.serialize_entry(&13u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitImageSize(str) => {
                m.serialize_entry(&14u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitContent(str) => {
                m.serialize_entry(&18u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitURI(str) => {
                m.serialize_entry(&21u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitSourceComponent(str) => {
                m.serialize_entry(&22u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitInvokeArgs(str) => {
                m.serialize_entry(&23u8, str)?;
            }
            crate::manifest::SuitParametersEnum::SuitDeviceID(str) => {
                m.serialize_entry(&24u8, str)?;
            }
        }
        m.end()
    }
}

impl Serialize for SuitCommand {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut m = serializer.serialize_map(Some(1))?;
        match &self.ident {
            crate::manifest::SuitCommandEnum::SuitConditionVendorIdentifier => {
                m.serialize_entry(&1u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitConditionClassIdentifier => {
                m.serialize_entry(&2u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitConditionDeviceIdentifier => {
                m.serialize_entry(&24u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitConditionImageMatch => {
                m.serialize_entry(&3u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitConditionCheckContent => {
                m.serialize_entry(&6u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitConditionComponentSlot => {
                m.serialize_entry(&5u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitConditionAbort => {
                m.serialize_entry(&14u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveSetComponentIndex => {
                m.serialize_entry(&12u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveTryEach => {
                m.serialize_entry(&15u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveOverrideParameters(str) => {
                m.serialize_entry(&20u8, &encode_to_cbor(str))?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveFetch => {
                m.serialize_entry(&21u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveCopy => {
                m.serialize_entry(&22u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveWrite => {
                m.serialize_entry(&18u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveInvoke => {
                m.serialize_entry(&23u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveRunSequence => {
                m.serialize_entry(&32u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitDirectiveSwap => {
                m.serialize_entry(&31u8, &self.value)?;
            }
            crate::manifest::SuitCommandEnum::SuitCommandCustom => {
                m.serialize_entry(&9u8, &self.value)?;
            }
        }
        m.end()
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

pub fn encode_manifest(manifest: &SuitManifest) -> Vec<u8> {
    let mut encoded = Vec::new();

    into_writer(manifest, &mut encoded).unwrap();
    return encoded;
}

pub fn encode_envelope(envelope: &SuitEnvelope) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Tag envelope with 107 according to IANA
    encoded.extend_from_slice(&[0xD8, 0x6B]);
    into_writer(envelope, &mut encoded).unwrap();
    return encoded;
}
