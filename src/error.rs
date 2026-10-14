//! The error type shared by [`crate::parse`] and [`crate::envelope`].

use std::fmt;

/// Failure parsing a JSON manifest description, or building and signing its envelope.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A `SuitCommand`/`SuitCommandSequence` key or argument was missing or malformed.
    UnsupportedCommand(String),
    /// A `SuitParameter` key or argument was missing or malformed.
    UnsupportedParameter(String),
    /// Top-level manifest input (e.g. version, sequence number) was missing or malformed.
    UnsupportedInput(String),
    /// An algorithm, such as an image digest algorithm, isn't supported.
    UnsupportedAlgorithm(String),
    /// The input wasn't valid JSON.
    InvalidJson(serde_json::Error),
    /// Loading the signing key or signing the envelope failed.
    Signing(brody::Error),
}

impl Error {
    /// Appends where in the manifest the error occurred to its message.
    pub(crate) fn in_location(self, location: &str) -> Self {
        let locate = |message: String| format!("{message} in {location}");
        match self {
            Error::UnsupportedCommand(m) => Error::UnsupportedCommand(locate(m)),
            Error::UnsupportedParameter(m) => Error::UnsupportedParameter(locate(m)),
            Error::UnsupportedInput(m) => Error::UnsupportedInput(locate(m)),
            Error::UnsupportedAlgorithm(m) => Error::UnsupportedAlgorithm(locate(m)),
            other => other,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedCommand(cmd) => write!(f, "Unsupported command: {}", cmd),
            Error::UnsupportedParameter(param) => write!(f, "Unsupported parameter: {}", param),
            Error::UnsupportedInput(input) => write!(f, "Unsupported input: {}", input),
            Error::UnsupportedAlgorithm(alg) => write!(f, "Unsupported COSE algorithm: {}", alg),
            Error::InvalidJson(e) => write!(f, "Invalid JSON: {e}"),
            Error::Signing(e) => write!(f, "Signing failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::InvalidJson(e) => Some(e),
            Error::Signing(e) => Some(e),
            _ => None,
        }
    }
}

impl From<brody::Error> for Error {
    fn from(e: brody::Error) -> Self {
        Error::Signing(e)
    }
}
