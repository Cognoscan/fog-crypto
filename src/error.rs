use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VersionType {
    Hash,
    Signing,
    SymmetricKey,
    PublicKey,
}

impl fmt::Display for VersionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionType::Hash => f.write_str("Hash"),
            VersionType::Signing => f.write_str("Signing"),
            VersionType::SymmetricKey => f.write_str("Symmetric Key"),
            VersionType::PublicKey => f.write_str("Public Key"),
        } 
    }
}

/// Possible cryptographic submodule error conditions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CryptoError {
    /// Crypto primitive uses a version this library doesn't recognize (or one it no longer
    /// accepts).
    UnsupportedVersion {
        ty: VersionType,
        version: u8,
        min: u8,
        max: u8,
    },
    /// Crypto system was unable to decrypt the contents of a Lockbox.
    DecryptFailed,
    /// The provided data for wasn't the expected length.
    BadLength {
        step: &'static str,
        actual: usize,
        expected: usize,
    },
    /// A provided cryptographic key (public or private) is weak or invalid.
    BadKey,
    /// The data format doesn't match spec. Can occur when decoding a lockbox or attempting to
    /// decode from a String.
    BadFormat(&'static str),
    /// An operation expected a specific object but didn't get it. Eg. Signature verification
    /// expects a specific version of hash and fails if it doesn't get a hash with that version, or
    /// a Lockbox should be unlocked with a specific key but we attempted to use the wrong one.
    /// This almost always indicates a logic error.
    ObjectMismatch(&'static str),
    /// Verification of a signature failed.
    SignatureFailed,
    /// The attempted operation isn't supported by the backing Vault.
    NotSupportedByVault,
}

impl CryptoError {
    pub fn serde_err(&self) -> String {
        match *self {
            CryptoError::UnsupportedVersion { ty, version, min, max } => {
                format!("crypto version ({version}) not supported for {ty} algorithm. Valid range is {min} to {max}")
            }
            CryptoError::DecryptFailed => "could not decrypt with key".to_string(),
            CryptoError::BadLength {
                step,
                actual,
                expected,
            } => format!(
                "expected data length {}, but got {} on step [{}]",
                expected, actual, step
            ),
            CryptoError::BadKey => "crypto key is weak or invalid".to_string(),
            CryptoError::BadFormat(s) => format!("format of data does not match spec: {}", s),
            CryptoError::ObjectMismatch(s) => format!("object mismatch: {}", s),
            CryptoError::SignatureFailed => "signature verification failed".to_string(),
            CryptoError::NotSupportedByVault => "vault doesn't support this operation".to_string(),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::UnsupportedVersion { ty, version, min, max } => {
                write!(f, "crypto version ({version}) not supported for {ty} algorithm. Valid range is {min} to {max}")
            }
            CryptoError::DecryptFailed => write!(f, "Could not decrypt with key"),
            CryptoError::BadLength {
                step,
                actual,
                expected,
            } => write!(
                f,
                "Expected data length {}, but got {} on step [{}]",
                expected, actual, step
            ),
            CryptoError::BadKey => write!(f, "Crypto key is weak or invalid"),
            CryptoError::BadFormat(s) => write!(f, "Format of data does not match spec: {}", s),
            CryptoError::ObjectMismatch(s) => write!(f, "Object mismatch: {}", s),
            CryptoError::SignatureFailed => write!(f, "Signature verification failed"),
            CryptoError::NotSupportedByVault => write!(f, "Vault doesn't support this operation"),
        }
    }
}

impl std::error::Error for CryptoError {}
