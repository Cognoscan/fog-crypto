use std::{fmt, io};
use std::error::Error;

/// Possible cryptographic submodule error conditions.
#[derive(Debug)]
pub enum CryptoError {
    /// Crypto primitive uses a version this library doesn't recognize (or one it no longer 
    /// accepts).
    UnsupportedVersion,
    /// Crypto system was unable to decrypt the contents of a Lockbox.
    DecryptFailed,
    /// The provided data for encode/decode wasn't the correct length.
    BadLength,
    /// A provided cryptographic key is weak or invalid.
    BadKey,
    /// The data format doesn't match spec. Only occurs when decoding a Lockbox and the internal 
    /// data marker isn't recognized.
    BadFormat,
    /// A requested private key or stream key was not in the Vault storage.
    NotInStorage,
    /// Decode/Encode error occurred.
    Io(io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::UnsupportedVersion   => write!(f, "Chosen crypto version not supported."),
            CryptoError::DecryptFailed        => write!(f, "Could not decrypt with key"),
            CryptoError::BadKey               => write!(f, "Crypto key is weak or invalid"),
            CryptoError::BadLength            => write!(f, "Provided data length is invalid"),
            CryptoError::BadFormat            => write!(f, "Format of data does not match specification"),
            CryptoError::NotInStorage         => write!(f, "Provided Key/Identity/StreamKey is not in storage"),
            CryptoError::Io(ref err)          => err.fmt(f),
        }
    }
}

impl Error for CryptoError {
}

impl From<io::Error> for CryptoError {
    fn from(err: io::Error) -> CryptoError {
        CryptoError::Io(err)
    }
}
