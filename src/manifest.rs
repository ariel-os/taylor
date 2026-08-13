use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SuitEnvelope {
    pub auth_block: SuitAuthentication,
    pub manifest: SuitManifest,
}

#[derive(Debug, Deserialize)]
pub struct SuitAuthentication {
    pub digest: SuitDigest,
    pub auth_blocks: Vec<SuitAuthenticationBlock>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuitAuthenticationBlock {
    pub algorithm: COSEAuthBlockEnum,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum COSEAuthBlockEnum {
    COSESignTagged,
    COSESign1Tagged,
    COSEMacTagged,
    COSEMac0Tagged,
}

#[derive(Debug, Deserialize)]
pub struct SuitManifest {
    pub version: usize,
    pub sequence_number: usize,
    pub suit_common: SuitCommon,
    pub sequence: Vec<SuitCommandSequence>,
}

#[derive(Debug, Deserialize)]
pub struct SuitCommon {
    pub components: Vec<Vec<String>>,
    pub shared_sequence: Vec<SuitCommand>,
}

#[derive(Debug, Deserialize)]
pub struct SuitCommand {
    pub ident: SuitCommandEnum,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SuitCommandEnum {
    SuitConditionVendorIdentifier,
    SuitConditionClassIdentifier,
    SuitConditionDeviceIdentifier,
    SuitConditionImageMatch,
    SuitConditionCheckContent,
    SuitConditionComponentSlot,
    SuitConditionAbort,
    SuitDirectiveSetComponentIndex,
    SuitDirectiveTryEach,
    SuitDirectiveOverrideParameters(Vec<SuitParameter>),
    SuitDirectiveFetch,
    SuitDirectiveCopy,
    SuitDirectiveWrite,
    SuitDirectiveInvoke,
    SuitDirectiveRunSequence,
    SuitDirectiveSwap,
    SuitCommandCustom,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SuitCommandSequenceEnum {
    SuitPayloadFetch,
    SuitInstall,
    SuitValidate,
    SuitLoad,
    SuitInvoke,
}

#[derive(Debug, Deserialize)]
pub struct SuitCommandSequence {
    pub sequence: SuitCommandSequenceEnum,
    pub actions: Vec<SuitCommand>,
}

#[derive(Debug, Deserialize)]
pub struct SuitParameter {
    pub ident: SuitParametersEnum,
}

#[derive(Debug, Deserialize)]
pub struct SuitDigest {
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
pub enum SuitParametersEnum {
    SuitVendorID(String),
    SuitClassID(String),
    SuitImageDigest(SuitDigest),
    SuitComponentSlot(String),
    SuitStrictOrder(String),
    SuitSoftFailure(String),
    SuitImageSize(String),
    SuitContent(String),
    SuitURI(String),
    SuitSourceComponent(String),
    SuitInvokeArgs(String),
    SuitDeviceID(String),
}
