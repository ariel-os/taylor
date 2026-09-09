//! COSE authentication of a [`SuitEnvelope`]. **Not yet implemented.**

#![allow(unused)]

use crate::manifest::{COSEAuthBlockEnum, SuitAuthentication, SuitEnvelope, SuitManifest};
use std::path::Path;

struct COSESignTagged {}

struct COSESign1Tagged {}

struct COSEMacTagged {}

struct COSEMac0Tagged {}

/// Adds a COSE authentication block over `envelope`'s digest, signed with the key at `key`.
///
/// # Panics
///
/// Always panics: unimplemented.
pub fn sign(envelope: SuitEnvelope, key: &Path) -> SuitEnvelope {
    todo!()
}