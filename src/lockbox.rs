//! Encrypted data.
//!
//! This submodule provides 4 different types of "lockboxes":
//! - [`IdentityLockbox`]: Stores an [`IdentityKey`]
//! - [`StreamLockbox`]: Stores a [`StreamKey`]
//! - [`LockLockbox`]: Stores a [`LockKey`]
//! - [`DataLockbox`]: Stores an arbitrary byte sequence
//!
//! Each lockbox is encoded the same way; the lockbox type must be known when decoding it.
//! 
//! A lockbox is created with a specific [`LockId`] or [`StreamKey`] as the intended recipient. 
//! A `DataLockbox` can be created by calling the encrypt function on a `StreamKey` or `LockId`, 
//! while the others can be created by calling the appropriate "export" function on the key to be 
//! exported.
//!
//! # Algorithms
//!
//! The current (and only) algorithm is XChaCha20 with a Poly1305 AEAD construction. For 
//! `StreamKey` recipients, the secret XChaCha20 key is used for encryption. For `LockId` 
//! recipients, an ephemeral X25519 keypair is generated and DH key agreement is used to generate 
//! the key.
//!
//! # Format
//!
//! The first lockbox format is for `LockId`-recipient lockboxes. It consists of the version 
//! byte, a byte set to 0x01, the encoded `LockId`, an ephemeral X25519 public key (without a 
//! version byte), a 24-byte nonce, the ciphertext, and the 16-byte Poly1305 authentication tag.
//!
//! The second lockbox format is for `StreamKey`-recipient lockboxes. It consists of the version 
//! byte, a byte set to 0x02, the encoded `StreamId`, a 24-byte nonce, the ciphertext, and the 
//! 16-byte Poly1305 authentication tag.
//!
//! ```text
//! +----------+----------+==========+==========+==========+==============+=====+
//! | Version  |   0x01   | SignKey  |  EphKey  |  Nonce   |  Ciphertext  | Tag |
//! +----------+----------+==========+==========+==========+==============+=====+
//! 
//! +----------+----------+==========+==========+==============+=====+
//! | Version  |   0x02   | StreamId |  Nonce   |  Ciphertext  | Tag |
//! +----------+----------+==========+==========+==============+=====+
//! 
//! - SignKey is a LockId. This is a version byte followed by a 32-byte X25519 public key
//! - EphKey is a 32-byte X25519 public key
//! - StreamId is a 32-byte hash of the encryption key (see StreamId documentation)
//! - Nonce is a 24-byte random nonce
//! - Ciphertext is the internal data, encrypted with XChaCha20
//! - Tag is the authentication tag produced using the XChaCha20-Poly1305 AEAD
//!     construction.
//! ```
//!
//! In the AEAD construction, the additional data consists of every byte prior to the nonce.
//!
//!

use crate::{
    lock::{LockId, LockKey, lock_id_size, lock_eph_size},
    identity::IdentityKey,
    stream::{stream_id_size, StreamId, StreamKey, MAX_STREAM_VERSION, MIN_STREAM_VERSION},
    CryptoError, Vault,
};

use std::{convert::TryFrom, fmt};

pub(crate) const V1_LOCKBOX_NONCE_SIZE: usize = 24;
pub(crate) const V1_LOCKBOX_TAG_SIZE: usize = 16;

pub const LOCKBOX_TYPE_LOCK: u8 = 1;
pub const LOCKBOX_TYPE_STREAM: u8 = 2;

/// Get expected size of a Lockbox's nonce for a given version. Version *must* be validated before
/// calling this.
pub(crate) fn lockbox_nonce_size(_version: u8) -> usize {
    V1_LOCKBOX_NONCE_SIZE
}

/// Get expected size of a Lockbox's AEAD tag for a given version. Version *must* be validated
/// before calling this.
pub(crate) fn lockbox_tag_size(_version: u8) -> usize {
    V1_LOCKBOX_TAG_SIZE
}

/// An encrypted `LockKey`.
pub struct LockLockbox(Lockbox);

impl LockLockbox {

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }
    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// Get the target recipient who can decrypt this.
    pub fn recipient(&self) -> &LockboxRecipient {
        self.0.recipient()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for LockLockbox {
    type Error = CryptoError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(Lockbox::try_from(value)?))
    }
}

/// An encrypted `IdentityKey`.
pub struct IdentityLockbox(Lockbox);

impl IdentityLockbox {

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }
    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// Get the target recipient who can decrypt this.
    pub fn recipient(&self) -> &LockboxRecipient {
        self.0.recipient()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for IdentityLockbox {
    type Error = CryptoError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(Lockbox::try_from(value)?))
    }
}

/// An encrypted `StreamKey`.
pub struct StreamLockbox(Lockbox);

impl StreamLockbox {

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }
    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// Get the target recipient who can decrypt this.
    pub fn recipient(&self) -> &LockboxRecipient {
        self.0.recipient()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for StreamLockbox {
    type Error = CryptoError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(Lockbox::try_from(value)?))
    }
}


/// General encrypted data.
pub struct DataLockbox(Lockbox);

impl DataLockbox {

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }

    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// Get the target recipient who can decrypt this.
    pub fn recipient(&self) -> &LockboxRecipient {
        self.0.recipient()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for DataLockbox {
    type Error = CryptoError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        //Ok(Self(Lockbox::try_from(value)?))
        let x = Self(Lockbox::try_from(value)?);
        Ok(x)
    }
}

pub struct LockboxParts<'a> {
    pub eph_pub: Option<&'a[u8]>,
    pub additional: &'a[u8],
    pub nonce: &'a[u8],
    pub ciphertext: &'a[u8],
}

#[derive(Clone,PartialEq,Eq)]
struct Lockbox {
    recipient: LockboxRecipient,
    inner: Vec<u8>,
}

impl Lockbox {
    fn as_parts(&self) -> LockboxParts {
        let version = self.version();
        let nonce_len = lockbox_nonce_size(version);
        match self.recipient {
            LockboxRecipient::LockId(ref id) => {
                let id_version = id.version(); // Can differ from lockbox version
                let id_len = lock_id_size(id_version);
                let eph_len = lock_eph_size(id_version);
                let additional_len = 2 + id_len + eph_len; // 1 for lockbox version, 1 for lockbox type
                let (additional, inner) = self.inner.split_at(additional_len);
                let eph_pub = additional.get((2+id_len)..).unwrap();
                let (nonce, ciphertext) = inner.split_at(nonce_len);
                LockboxParts {
                    eph_pub: Some(eph_pub),
                    additional,
                    nonce,
                    ciphertext,
                }
            }
            LockboxRecipient::StreamId(_) => {
                let id_len = stream_id_size(version);
                let additional_len = 2 + id_len; // 1 for lockbox version, 1 for lockbox type
                let (additional, inner) = self.inner.split_at(additional_len);
                let (nonce, ciphertext) = inner.split_at(nonce_len);
                LockboxParts {
                    eph_pub: None,
                    additional,
                    nonce,
                    ciphertext,
                }
            }
        }
    }

    /// Get the version of the Lockbox.
    fn version(&self) -> u8 {
        self.inner[0]
    }

    /// Get the target recipient who should be able to decrypt the lockbox.
    fn recipient(&self) -> &LockboxRecipient {
        &self.recipient
    }

    fn as_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl TryFrom<&[u8]> for Lockbox {
    type Error = CryptoError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let (&version, parse) = raw.split_first().ok_or(CryptoError::BadLength {
            step: "get lockbox version",
            expected: 1,
            actual: 0,
        })?;
        if version < MIN_STREAM_VERSION || version > MAX_STREAM_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        let (&boxtype, parse) = parse.as_ref().split_first().ok_or(CryptoError::BadLength {
            step: "get lockbox type",
            expected: 1,
            actual: 0,
        })?;
        match boxtype {
            LOCKBOX_TYPE_LOCK => {
                let id_version = *parse.first().ok_or(CryptoError::BadLength {
                    step: "get LockId version for lockbox",
                    expected: 1,
                    actual: 0,
                })?;
                let id_len = lock_id_size(id_version);
                let eph_len = lock_eph_size(id_version);
                let nonce_len = lockbox_nonce_size(version);
                let tag_len = lockbox_tag_size(version);
                if parse.len() < (id_len + eph_len + nonce_len + tag_len) {
                    return Err(CryptoError::BadLength {
                        step: "get lockbox component lengths",
                        expected: id_len + eph_len + nonce_len + tag_len,
                        actual: parse.len(),
                    })?;
                }
                // Extract the LockId
                let (raw_id, _) = parse.split_at(id_len);
                let id = LockId::try_from(raw_id)?;
                Ok(Self {
                    recipient: LockboxRecipient::LockId(id),
                    inner: Vec::from(raw),
                })
            }
            LOCKBOX_TYPE_STREAM => {
                // Check the length. Must be at least long enough to hold the StreamId, Nonce, and 
                // Tag. It is acceptable (if a bit silly) for the actual ciphertext to be of length 
                // 0.
                let id_len = stream_id_size(version);
                let nonce_len = lockbox_nonce_size(version);
                let tag_len = lockbox_tag_size(version);
                if parse.len() < (id_len + nonce_len + tag_len) {
                    return Err(CryptoError::BadLength {
                        step: "get lockbox component lengths",
                        expected: id_len + nonce_len + tag_len,
                        actual: parse.len(),
                    })?;
                }
                // Extract the StreamId
                let (raw_id, _) = parse.split_at(id_len);
                let id = StreamId::try_from(raw_id)?;
                // Compare the StreamId & version byte. We can't use stream keys that differ from
                // the lockbox version because they're supposed to literally be the same algorithm!
                if id.version() != version {
                    return Err(CryptoError::BadFormat);
                }
                Ok(Self {
                    recipient: LockboxRecipient::StreamId(id),
                    inner: Vec::from(raw),
                })
            }
            _ => return Err(CryptoError::BadFormat),
        }
    }
}

/// Directly take parts to construct a `LockLockbox`. Should only be used by implementors of the 
/// `encrypt` functions. This is *not* checked for correctness. Strongly consider having unit tests 
/// that check the round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn lock_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> LockLockbox {
    LockLockbox(Lockbox { recipient, inner })
}

/// Directly take parts to construct a `IdentityLockbox`. Should only be used by implementors of the 
/// `encrypt` functions. This is *not* checked for correctness. Strongly consider having unit tests 
/// that check the round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn identity_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> IdentityLockbox {
    IdentityLockbox(Lockbox { recipient, inner })
}

/// Directly take parts to construct a `StreamLockbox`. Should only be used by implementors of the 
/// `encrypt` functions. This is *not* checked for correctness. Strongly consider having unit tests 
/// that check the round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn stream_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> StreamLockbox {
    StreamLockbox(Lockbox { recipient, inner })
}

/// Directly take parts to construct a `DataLockbox`. Should only be used by implementors of the 
/// `encrypt` functions. This is *not* checked for correctness. Strongly consider having unit tests 
/// that check the round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn data_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> DataLockbox {
    DataLockbox(Lockbox { recipient, inner })
}

/// Lockboxes can be meant for one of two types of recipients: a LockId (public key), or a
/// StreamId (symmetric key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockboxRecipient {
    LockId(LockId),
    StreamId(StreamId),
}
