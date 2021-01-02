
/// Possible cryptographic submodule error conditions.
#[derive(Debug)]
pub enum CryptoError {
    /// Crypto primitive uses a version this library doesn't recognize (or one it no longer 
    /// accepts).
    UnsupportedVersion(u8),
    /// Crypto primitive uses a version that's too old, and deemed unsafe to use.
    OldVersion(u8),
    /// Crypto system was unable to decrypt the contents of a Lockbox.
    DecryptFailed,
    /// The provided data for wasn't the expected length.
    BadLength { step: &'static str, actual: usize, expected: usize },
    /// A provided cryptographic key (public or private) is weak or invalid.
    BadKey,
    /// The data format doesn't match spec. Can occur when decoding a lockbox or attempting to 
    /// decode from a String.
    BadFormat,
    /// An operation expected a specific object but didn't get it. Eg. Signature verification 
    /// expects a specific version of hash and fails if it doesn't get a hash with that version, or 
    /// a Lockbox should be unlocked with a specific key but we attempted to use the wrong one. 
    /// This almost always indicates a logic error.
    ObjectMismatch(&'static str),
    /// Verification of a signature failed.
    SignatureFailed,
}

use std::fmt;
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::UnsupportedVersion(version) =>
                write!(f, "Chosen crypto version ({}) not supported.", version),
            CryptoError::OldVersion(version) =>
                write!(f, "Crypto version ({}) is old and deemed unsafe.", version),
            CryptoError::DecryptFailed =>
                write!(f, "Could not decrypt with key"),
            CryptoError::BadLength{step, actual, expected} =>
                write!(f, "Expected data length {}, but got {} on step \"{}\"", expected, actual, step),
            CryptoError::BadKey =>
                write!(f, "Crypto key is weak or invalid"),
            CryptoError::BadFormat =>
                write!(f, "Format of data does not match specification"),
            CryptoError::ObjectMismatch(s) =>
                write!(f, "Object mismatch: {}", s),
            CryptoError::SignatureFailed =>
                write!(f, "Signature verification failed"),
        }
    }
}

impl std::error::Error for CryptoError {
}
