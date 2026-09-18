//! The error type shared by [`crate::parse`] and [`crate::encode`].

use std::fmt;

/// Failure parsing a JSON manifest description or encoding it to CBOR.
#[derive(Debug)]
pub enum Error {
    /// A `SuitCommand`/`SuitCommandSequence` key or argument was missing or malformed.
    UnsupportedCommand(String),
    /// A `SuitParameter` key or argument was missing or malformed.
    UnsupportedParameter(String),
    /// Top-level manifest input (e.g. version, sequence number) was missing or malformed.
    UnsupportedInput(String),
    /// A COSE algorithm identifier was missing or not recognized.
    UnsupportedAlgorithm(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedCommand(cmd) => write!(f, "Unsupported command: {}", cmd),
            Error::UnsupportedParameter(param) => write!(f, "Unsupported parameter: {}", param),
            Error::UnsupportedInput(input) => write!(f, "Unsupported input: {}", input),
            Error::UnsupportedAlgorithm(alg) => write!(f, "Unsupported COSE algorithm: {}", alg),
        }
    }
}
