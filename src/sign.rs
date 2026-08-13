#![allow(unused)]

use crate::manifest::{COSEAuthBlockEnum, SuitAuthentication, SuitEnvelope, SuitManifest};
use std::path::Path;

struct COSESignTagged {}

struct COSESign1Tagged {}

struct COSEMacTagged {}

struct COSEMac0Tagged {}

pub fn sign(envelope: SuitEnvelope, key: &Path) -> SuitEnvelope {
    todo!()
}