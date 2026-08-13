use std::fmt;

#[derive(Debug)]
pub enum Error {
    UnsupportedCommand(String),
    UnsupportedParameter(String),
    UnsupportedInput(String),
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
