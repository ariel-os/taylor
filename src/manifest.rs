//! In-memory representation of a SUIT manifest, mirroring the CDDL `SUIT_Envelope` /
//! `SUIT_Manifest` structures. Built by [`crate::parse::parse`] and consumed by
//! [`crate::encode::encode_envelope`]/[`crate::encode::encode_manifest`].

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// The top-level `SUIT_Envelope`: an authentication wrapper plus the manifest it authenticates.
#[derive(Debug, Deserialize)]
pub struct SuitEnvelope {
    /// The digest (and, once implemented, COSE signatures) covering `manifest`.
    pub auth_block: SuitAuthentication,
    /// The manifest being authenticated and distributed.
    pub manifest: SuitManifest,
}

/// `SUIT_Authentication`: a mandatory digest plus zero or more COSE authentication blocks.
#[derive(Debug, Deserialize)]
pub struct SuitAuthentication {
    /// Digest of the encoded manifest bytes.
    pub digest: SuitDigest,
    /// COSE signature/MAC blocks over the digest. Empty means digest-only authentication.
    pub auth_blocks: Vec<SuitAuthenticationBlock>,
}

/// A single COSE authentication block wrapping `SuitAuthentication::digest`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuitAuthenticationBlock {
    /// Which COSE message type wraps this block.
    pub algorithm: COSEAuthBlockEnum,
}

/// The COSE message types usable for a SUIT authentication block.
#[derive(Debug, Serialize, Deserialize)]
pub enum COSEAuthBlockEnum {
    /// `COSE_Sign`, tagged.
    COSESignTagged,
    /// `COSE_Sign1`, tagged.
    COSESign1Tagged,
    /// `COSE_Mac`, tagged.
    COSEMacTagged,
    /// `COSE_Mac0`, tagged.
    COSEMac0Tagged,
}

/// `SUIT_Manifest`: manifest metadata, shared setup, and per-phase command sequences.
#[derive(Debug, Deserialize)]
pub struct SuitManifest {
    /// The `suit-manifest-version`; currently always `1`.
    pub version: usize,
    /// Monotonically increasing anti-rollback counter.
    pub sequence_number: usize,
    /// Component list and the shared command sequence run before every other sequence.
    pub suit_common: SuitCommon,
    /// The manifest's command sequences (payload-fetch, install, validate, load, invoke).
    pub sequence: Vec<SuitCommandSequence>,
}

/// `SUIT_Common`: the components under management and the sequence shared by every phase.
#[derive(Debug, Deserialize)]
pub struct SuitCommon {
    /// Component identifiers, each itself a list of hex-decoded path segments.
    pub components: Vec<Vec<ByteBuf>>,
    /// Commands run once before any command sequence that references a component.
    pub shared_sequence: Vec<SuitCommand>,
}

/// A single command within a command sequence.
#[derive(Debug, Deserialize)]
pub struct SuitCommand {
    /// The command and its argument.
    pub ident: SuitCommandEnum,
}

/// u64 payloads are a SUIT_Rep_Policy bitmask, except for set-component-index (IndexArg).
#[derive(Debug, Deserialize)]
pub enum SuitCommandEnum {
    /// Assert the current component's vendor ID parameter matches.
    SuitConditionVendorIdentifier(u64),
    /// Assert the current component's class ID parameter matches.
    SuitConditionClassIdentifier(u64),
    /// Assert the current component's device ID parameter matches.
    SuitConditionDeviceIdentifier(u64),
    /// Assert the current component's installed image matches its digest parameter.
    SuitConditionImageMatch(u64),
    /// Assert the current component's content matches its content parameter.
    SuitConditionCheckContent(u64),
    /// Assert the current component occupies the expected slot.
    SuitConditionComponentSlot(u64),
    /// Unconditionally abort processing.
    SuitConditionAbort(u64),
    /// Select which component(s) subsequent commands apply to.
    SuitDirectiveSetComponentIndex(u64),
    /// Run each branch in turn until one succeeds, falling back to `nil` if `bool` is set.
    SuitDirectiveTryEach(Vec<Vec<SuitCommand>>, bool),
    /// Set or override parameters for the current component(s).
    SuitDirectiveOverrideParameters(Vec<SuitParameter>),
    /// Fetch the current component's payload.
    SuitDirectiveFetch(u64),
    /// Copy the current component's payload from another component.
    SuitDirectiveCopy(u64),
    /// Write the current component's payload.
    SuitDirectiveWrite(u64),
    /// Invoke (execute/boot) the current component.
    SuitDirectiveInvoke(u64),
    /// Run a nested command sequence.
    SuitDirectiveRunSequence(Vec<SuitCommand>),
    /// Swap the current component with another.
    SuitDirectiveSwap(u64),
    /// Assert the current component's version compares as required against
    /// `suit-parameter-version` (`suit-condition-version`, code 28).
    SuitConditionVersion(u64),
    // Not spec-conformant: custom commands need a per-command vendor-defined nint code,
    // which conflicts with the no-vendor-lock-in requirement. Kept minimal, out of scope.
    /// Non-spec-conformant escape hatch for ad hoc commands; not portable.
    SuitCommandCustom(String),
}

/// Which phase a [`SuitCommandSequence`] belongs to; each maps to a fixed CDDL map key.
#[derive(Debug, Serialize, Deserialize)]
pub enum SuitCommandSequenceEnum {
    /// Fetch payloads (`suit-payload-fetch`).
    SuitPayloadFetch,
    /// Install fetched payloads (`suit-install`).
    SuitInstall,
    /// Validate installed payloads (`suit-validate`).
    SuitValidate,
    /// Prepare components for invocation (`suit-load`).
    SuitLoad,
    /// Invoke components (`suit-invoke`).
    SuitInvoke,
}

/// One command sequence: which phase it runs in, and its ordered commands.
#[derive(Debug, Deserialize)]
pub struct SuitCommandSequence {
    /// The phase this sequence runs in.
    pub sequence: SuitCommandSequenceEnum,
    /// The commands to run, in order.
    pub actions: Vec<SuitCommand>,
}

/// A single component parameter set via `SuitDirectiveOverrideParameters`.
#[derive(Debug, Deserialize)]
pub struct SuitParameter {
    /// The parameter key and its value.
    pub ident: SuitParametersEnum,
}

/// A digest algorithm identifier paired with the raw digest bytes.
#[derive(Debug, Deserialize)]
pub struct SuitDigest {
    /// Algorithm name, e.g. `"sha256"`.
    pub algorithm: String,
    /// The raw digest bytes.
    pub digest: Vec<u8>,
}

/// The component parameters `SuitParameter` can carry.
#[derive(Debug, Deserialize)]
pub enum SuitParametersEnum {
    /// Vendor UUID.
    SuitVendorID(Vec<u8>),
    /// Class UUID.
    SuitClassID(Vec<u8>),
    /// Expected digest of the component's image.
    SuitImageDigest(SuitDigest),
    /// Which slot of a multi-slot component to target.
    SuitComponentSlot(u64),
    /// Whether `try-each` branches must run in strict order.
    SuitStrictOrder(bool),
    /// Whether failures in this component are non-fatal.
    SuitSoftFailure(bool),
    /// Expected size, in bytes, of the component's image.
    SuitImageSize(u64),
    /// Inline content for the component, as raw bytes.
    SuitContent(Vec<u8>),
    /// URI to fetch the component's payload from.
    SuitURI(String),
    /// Index of the component to copy/fetch from.
    SuitSourceComponent(u64),
    /// Arguments passed when invoking the component.
    SuitInvokeArgs(Vec<u8>),
    /// Device UUID.
    SuitDeviceID(Vec<u8>),
    /// Arguments passed when fetching the component.
    SuitFetchArguments(Vec<u8>),
    /// Version comparison checked by `suit-condition-version` (`suit-parameter-version`, code 28).
    SuitVersion(SuitVersionMatch),
}

/// `SUIT_Parameter_Version_Match = [comparison-type, SUIT_Condition_Version_Comparison_Value]`.
#[derive(Debug, Deserialize)]
pub struct SuitVersionMatch {
    /// How `value` relates to the component's asserted version.
    pub comparison: VersionComparisonType,
    /// `SUIT_Condition_Version_Comparison_Value`: version as a sequence of integers,
    /// e.g. `[1, 2, 3]` for `1.2.3`; a negative entry (-1/-2/-3) marks a
    /// release-candidate/beta/alpha pre-release and must not appear as the first element.
    pub value: Vec<i64>,
}

/// `SUIT_Condition_Version_Comparison_Types`.
#[derive(Debug, Clone, Copy, Deserialize)]
pub enum VersionComparisonType {
    /// Component version must be greater than `value`.
    Greater,
    /// Component version must be greater than or equal to `value`.
    GreaterOrEqual,
    /// Component version must equal `value`.
    Equal,
    /// Component version must be less than or equal to `value`.
    LesserOrEqual,
    /// Component version must be less than `value`.
    Lesser,
}
