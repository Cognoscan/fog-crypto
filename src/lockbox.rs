//! Encrypted data.
//!
//! This submodule provides "lockboxes", which are byte sequences holding encrypted information.
//! There are 4 different types of lockboxes:
//! - [`IdentityLockbox`]: Stores an [`IdentityKey`](crate::identity::IdentityKey)
//! - [`StreamLockbox`]: Stores a [`StreamKey`](crate::stream::StreamKey)
//! - [`LockLockbox`]: Stores a [`LockKey`](crate::lock::LockKey)
//! - [`DataLockbox`]: Stores an arbitrary byte sequence
//!
//! Each lockbox is encoded in a similar way. The lockbox type should be known when attempting to
//! decode it, though if necessary it is also possible to determine the type through decoding (see
//! [`determine_lockbox_type`]).
//!
//! A lockbox is created with a specific [`LockId`] or [`StreamKey`](crate::stream::StreamKey) as
//! the intended recipient.  A `DataLockbox` can be created by calling the encrypt function on a
//! `StreamKey` or `LockId`, while the others can be created by calling the appropriate "export"
//! function on the key to be exported.
//!
//! For decoding, each lockbox has a corresponding reference type, which will parse a byte slice
//! and return a reference on success. These can be turned into their corresponding owned variants
//! if needed, or can be used directly for decryption. These reference types are:
//!
//! - [`IdentityLockboxRef`]
//! - [`StreamLockboxRef`]
//! - [`LockLockboxRef`]
//! - [`DataLockboxRef`]
//!
//! # Algorithms
//!
//! The current (and only) algorithm is XChaCha20 with a Poly1305 AEAD construction.
//!
//! For `StreamKey` recipients, the secret XChaCha20 key is used for encryption, and a randomized
//! nonce is used. The nonce is included in the lockbox header. For AEAD, the additional data is the
//! lockbox version and type.
//!
//! For `LockId` recipients, an ephemeral X25519 keypair is generated and DH key agreement
//! is used to generate the key. The nonce is calculated by concatenating the ephemeral public key
//! with the target public key, hashing them with Blake2b, and taking the first 24 bytes of the
//! hash. The ephemeral public key is included in the lockbox header. For AEAD, the additional data
//! is the lockbox version, lockbox type, and public ephemeral key.
//!
//! # Lockbox Types
//!
//! The different types of lockboxes each have 2 subtypes: one for `LockId`-recipient lockboxes,
//! and one for `StreamKey`-recipient lockboxes. The encoded type byte is thus:
//!
//! | Type              | Recipient  | Byte Value |
//! | --                | --         | --         |
//! | `IdentityLockbox` | `LockId`   | 0          |
//! | `IdentityLockbox` | `StreamId` | 1          |
//! | `StreamLockbox`   | `LockId`   | 2          |
//! | `StreamLockbox`   | `StreamId` | 3          |
//! | `LockLockbox`     | `LockId`   | 4          |
//! | `LockLockbox`     | `StreamId` | 5          |
//! | `DataLockbox`     | `LockId`   | 6          |
//! | `DataLockbox`     | `StreamId` | 7          |
//!
//! Alternately, the Type byte can be considered to have two bitfields: bit 0 encodes the
//! recipient type, and bits 2 & 1 encode the main lockbox type.
//!
//! # Format
//!
//! The first lockbox format is for `LockId`-recipient lockboxes. It consists of the version
//! byte, a byte set to the lockbox type, an ephemeral X25519 public key (with version byte), the
//! ciphertext, and the 16-byte Poly1305 authentication tag.
//!
//! The second lockbox format is for `StreamKey`-recipient lockboxes. It consists of the version
//! byte, a byte set to the lockbox type, a 24-byte nonce, the ciphertext,
//! and the 16-byte Poly1305 authentication tag.
//!
//! ```text
//! +----------+----------+==========+==============+=====+
//! | Version  |   Type   |  EphKey  |  Ciphertext  | Tag |
//! +----------+----------+==========+==============+=====+
//!
//! +----------+----------+==========+==============+=====+
//! | Version  |   Type   |  Nonce   |  Ciphertext  | Tag |
//! +----------+----------+==========+==============+=====+
//!
//! - Version indicates what version of symmetric-key encryption was used for this lockbox.
//! - Type indicates the lockbox type and recipient type. If bit 0 is cleared, the first format
//!   (with SignKey & EphKey) is used. If bit 1 is set, the second format (with StreamId) is used.
//! - EphKey is a raw public key, of the same version as SignKey.
//! - Nonce is a random byte sequence matching the nonce length specified by the symmetric
//!   encryption version used.
//! - Ciphertext is the internal data, encrypted with the chosen algorithm.
//! - Tag is the authentication tag produced using the chosen algorithm.
//!
//! For lockbox version 1 with version 1 public/private keys, the field sizes are:
//!
//! | Field      | Size (bytes) |
//! | ---------- | ------------ |
//! | Version    | 1            |
//! | Type       | 1            |
//! | EphKey     | 33           |
//! | Tag        | 16           |
//! | Ciphertext | Variable     |
//!
//! For lockbox version 1 with a version 1 stream key, the field sizes are:
//!
//! | Field      | Size (bytes) |
//! | ---------- | ------------ |
//! | Version    | 1            |
//! | Type       | 1            |
//! | Nonce      | 24           |
//! | Tag        | 16           |
//! | Ciphertext | Variable     |
//! ```
//!
//! In the AEAD construction, the additional data consists of every byte prior to the nonce.
//!

use crate::{
    lock::lock_id_size,
    stream::{MAX_STREAM_VERSION, MIN_STREAM_VERSION},
    CryptoError, VersionType, MAX_LOCK_VERSION, MIN_LOCK_VERSION,
};

use std::fmt;

pub(crate) const V1_LOCKBOX_NONCE_SIZE: usize = 24;
pub(crate) const V1_LOCKBOX_TAG_SIZE: usize = 16;

const LOCKBOX_OFFSET_VERSION: usize = 0;
const LOCKBOX_OFFSET_TYPE: usize = 1;
const LOCKBOX_OFFSET_HEADER: usize = 2;

/// Encodes the various types of lockboxes that may be decoded.
///
/// Each lockbox type can have a [`StreamKey`](crate::stream::StreamKey) recipient, in which case
/// the held boolean should be set to true.
pub enum LockboxType {
    Identity(bool),
    Stream(bool),
    Lock(bool),
    Data(bool),
}

impl LockboxType {
    /// Convert the lockbox type into its encoded byte value.
    pub fn as_u8(&self) -> u8 {
        use LockboxType::*;
        let (v, t) = match self {
            Identity(t) => (0, *t),
            Stream(t) => (2, *t),
            Lock(t) => (4, *t),
            Data(t) => (6, *t),
        };
        if t {
            v | 0x1
        } else {
            v
        }
    }

    /// Attempt to decode a lockbox type byte.
    pub fn from_u8(v: u8) -> Result<Self, CryptoError> {
        use LockboxType::*;
        let t = (v & 0x1) != 0;
        match v & 0xFE {
            0 => Ok(Identity(t)),
            2 => Ok(Stream(t)),
            4 => Ok(Lock(t)),
            6 => Ok(Data(t)),
            _ => Err(CryptoError::BadFormat("Lockbox type field wasn't valid")),
        }
    }

    /// Check if the lockbox type has a stream recipient.
    pub fn is_for_stream(&self) -> bool {
        use LockboxType::*;
        match self {
            Identity(t) => *t,
            Stream(t) => *t,
            Lock(t) => *t,
            Data(t) => *t,
        }
    }
}

/// Determine what type of lockbox is in the encoded sequence. This only checks the first two
/// bytes, and doesn't guarantee the whole `raw` byte slice contains a valid encoded lockbox.
pub fn determine_lockbox_type(raw: &[u8]) -> Result<LockboxType, CryptoError> {
    let &boxtype = raw.get(LOCKBOX_OFFSET_TYPE).ok_or(CryptoError::BadLength {
        step: "get lockbox type",
        expected: 2,
        actual: raw.len(),
    })?;
    LockboxType::from_u8(boxtype)
}

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

/// An encrypted [`LockKey`](crate::lock::LockKey).
///
/// This must be decrypted by the matching recipient, which will return the `LockKey` on success.
/// It can either be decrypted on its own, returning a temporary `LockKey`, or through a Vault,
/// which will store the `LockKey`. The recipient key is not encoded in the lockbox; it must be
/// determined through other means.
///
/// When decoding, a reference to the data is first created: [`LockLockboxRef`], which can then be
/// converted with `to_owned` to create this struct.
///
/// See: [`StreamKey::decrypt_lock_key`](crate::stream::StreamKey::decrypt_lock_key),
/// [`LockKey::decrypt_lock_key`](crate::lock::LockKey::decrypt_lock_key), and
/// [`Vault::decrypt_lock_key`](crate::Vault::decrypt_lock_key).
///
/// # Example
///
/// Using a `StreamKey` for decryption:
///
/// ```
/// # use fog_crypto::lock::*;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = LockKey::new();
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: LockLockbox = LockLockboxRef::from_bytes(&enc[..])?.to_owned();
/// // ...
/// // Retrieve the key by figuring out who the recipient is...
/// // ...
/// let dec_key: LockKey = key.decrypt_lock_key(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LockLockbox(Lockbox);

impl fmt::Debug for LockLockbox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("LockLockbox")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

impl std::ops::Deref for LockLockbox {
    type Target = LockLockboxRef;
    #[inline]
    fn deref(&self) -> &Self::Target {
        LockLockboxRef::new_ref(&self.0)
    }
}

impl std::borrow::Borrow<LockLockboxRef> for LockLockbox {
    fn borrow(&self) -> &LockLockboxRef {
        LockLockboxRef::new_ref(&self.0)
    }
}

/// An reference to an encrypted [`LockKey`](crate::lock::LockKey).
///
/// This must be decrypted by the matching recipient, which will return the `LockKey` on success.
/// It can either be decrypted on its own, returning a temporary `LockKey`, or through a Vault,
/// which will store the `LockKey`.
///
/// This is only a reference to an encrypted payload. The owned version is [`LockLockbox`].
///
/// See: [`StreamKey::decrypt_lock_key`](crate::stream::StreamKey::decrypt_lock_key),
/// [`LockKey::decrypt_lock_key`](crate::lock::LockKey::decrypt_lock_key), and
/// [`Vault::decrypt_lock_key`](crate::Vault::decrypt_lock_key).
///
/// # Example
///
/// Using a `StreamKey` for decryption:
///
/// ```
/// # use fog_crypto::lock::*;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = LockKey::new();
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: &LockLockboxRef = LockLockboxRef::from_bytes(&enc[..])?;
/// // ...
/// // Retrieve the key by determining the recipient...
/// // ...
/// let dec_key: LockKey = key.decrypt_lock_key(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(PartialEq, Eq, Hash)]
pub struct LockLockboxRef(LockboxRef);

impl LockLockboxRef {
    /// Create a new &LockboxRef from a byte slice. This should only be called by code that has
    /// already verified the byte slice.
    fn new_ref(lockbox_ref: &LockboxRef) -> &Self {
        // Justification:
        // LockLockboxRef is a newtype for a LockboxRef. See LockboxRef's `new_ref` for
        // more justification, as it does the same thing.
        unsafe { &*(lockbox_ref as *const LockboxRef as *const LockLockboxRef) }
    }

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }

    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(buf: &[u8]) -> Result<&Self, CryptoError> {
        let (lockbox, boxtype) = LockboxRef::decode(buf)?;
        if let LockboxType::Lock(_) = boxtype {
            Ok(Self::new_ref(lockbox))
        } else {
            Err(CryptoError::BadFormat("Didn't find a data lockbox"))
        }
    }
}

impl ToOwned for LockLockboxRef {
    type Owned = LockLockbox;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        LockLockbox(Lockbox {
            inner: Vec::from(&self.0.inner),
        })
    }
}

impl fmt::Debug for LockLockboxRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("LockLockboxRef")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

/// An encrypted [`IdentityKey`](crate::identity::IdentityKey).
///
/// This must be decrypted by the matching recipient, which will return the `IdentityKey` on
/// success.  It can either be decrypted on its own, returning a temporary `IdentityKey`, or
/// through a Vault, which will store the `IdentityKey`.
///
/// When decoding, a reference to the data is first created: [`IdentityLockboxRef`], which can then
/// be converted with `to_owned` to create this struct.
///
/// See: [`StreamKey::decrypt_identity_key`](crate::stream::StreamKey::decrypt_identity_key),
/// [`LockKey::decrypt_identity_key`](crate::lock::LockKey::decrypt_identity_key), and
/// [`Vault::decrypt_identity_key`](crate::Vault::decrypt_identity_key).
///
/// # Example
///
/// Using a `StreamKey` for decryption:
///
/// ```
/// # use fog_crypto::identity::*;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = IdentityKey::new();
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: IdentityLockbox = IdentityLockboxRef::from_bytes(&enc[..])?.to_owned();
/// // ...
/// // Retrieve the key by determining the recipient...
/// // ...
/// let dec_key: IdentityKey = key.decrypt_identity_key(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct IdentityLockbox(Lockbox);

impl fmt::Debug for IdentityLockbox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("IdentityLockbox")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

impl std::ops::Deref for IdentityLockbox {
    type Target = IdentityLockboxRef;
    #[inline]
    fn deref(&self) -> &Self::Target {
        IdentityLockboxRef::new_ref(&self.0)
    }
}

impl std::borrow::Borrow<IdentityLockboxRef> for IdentityLockbox {
    fn borrow(&self) -> &IdentityLockboxRef {
        IdentityLockboxRef::new_ref(&self.0)
    }
}

/// An encrypted [`IdentityKey`](crate::identity::IdentityKey).
///
/// This must be decrypted by the matching recipient, which will return the `IdentityKey` on
/// success.  It can either be decrypted on its own, returning a temporary `IdentityKey`, or
/// through a Vault, which will store the `IdentityKey`.
///
/// This is only a reference to an encrypted payload. The owned version is [`IdentityLockbox`].
///
/// See: [`StreamKey::decrypt_identity_key`](crate::stream::StreamKey::decrypt_identity_key),
/// [`LockKey::decrypt_identity_key`](crate::lock::LockKey::decrypt_identity_key), and
/// [`Vault::decrypt_identity_key`](crate::Vault::decrypt_identity_key).
///
/// # Example
///
/// Using a `StreamKey` for decryption:
///
/// ```
/// # use fog_crypto::identity::*;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = IdentityKey::new();
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: &IdentityLockboxRef = IdentityLockboxRef::from_bytes(&enc[..])?;
/// // ...
/// // Retrieve the key by determining the recipient...
/// // ...
/// let dec_key: IdentityKey = key.decrypt_identity_key(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(PartialEq, Eq, Hash)]
pub struct IdentityLockboxRef(LockboxRef);

impl IdentityLockboxRef {
    /// Create a new &LockboxRef from a byte slice. This should only be called by code that has
    /// already verified the byte slice.
    fn new_ref(lockbox_ref: &LockboxRef) -> &Self {
        // Justification:
        // IdentityLockboxRef is a newtype for a LockboxRef. See LockboxRef's `new_ref` for
        // more justification, as it does the same thing.
        unsafe { &*(lockbox_ref as *const LockboxRef as *const IdentityLockboxRef) }
    }

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }

    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(buf: &[u8]) -> Result<&Self, CryptoError> {
        let (lockbox, boxtype) = LockboxRef::decode(buf)?;
        if let LockboxType::Identity(_) = boxtype {
            Ok(Self::new_ref(lockbox))
        } else {
            Err(CryptoError::BadFormat("Didn't find a data lockbox"))
        }
    }
}

impl ToOwned for IdentityLockboxRef {
    type Owned = IdentityLockbox;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        IdentityLockbox(Lockbox {
            inner: Vec::from(&self.0.inner),
        })
    }
}

impl fmt::Debug for IdentityLockboxRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("IdentityLockboxRef")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

/// An encrypted [`StreamKey`](crate::stream::StreamKey).
///
/// This must be decrypted by the matching recipient, which will return the `StreamKey` on
/// success.  It can either be decrypted on its own, returning a temporary `StreamKey`, or
/// through a Vault, which will store the `StreamKey`.
///
/// When decoding, a reference to the data is first created: [`StreamLockboxRef`], which can then
/// be converted with `to_owned` to create this struct.
///
/// See: [`StreamKey::decrypt_stream_key`](crate::stream::StreamKey::decrypt_stream_key),
/// [`LockKey::decrypt_stream_key`](crate::lock::LockKey::decrypt_stream_key), and
/// [`Vault::decrypt_stream_key`](crate::Vault::decrypt_stream_key).
///
/// # Example
///
/// Using a `StreamKey` for decryption (different from the one contained in the lockbox!):
///
/// ```
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = StreamKey::new();
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: StreamLockbox = StreamLockboxRef::from_bytes(&enc[..])?.to_owned();
/// // ...
/// // Retrieve the key by determining the recipient...
/// // ...
/// let dec_key: StreamKey = key.decrypt_stream_key(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StreamLockbox(Lockbox);

impl fmt::Debug for StreamLockbox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("StreamLockbox")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

impl std::ops::Deref for StreamLockbox {
    type Target = StreamLockboxRef;
    #[inline]
    fn deref(&self) -> &Self::Target {
        StreamLockboxRef::new_ref(&self.0)
    }
}

impl std::borrow::Borrow<StreamLockboxRef> for StreamLockbox {
    fn borrow(&self) -> &StreamLockboxRef {
        StreamLockboxRef::new_ref(&self.0)
    }
}

/// An encrypted [`StreamKey`](crate::stream::StreamKey).
///
/// This must be decrypted by the matching recipient, which will return the `StreamKey` on
/// success.  It can either be decrypted on its own, returning a temporary `StreamKey`, or
/// through a Vault, which will store the `StreamKey`.
///
/// This is only a reference to an encrypted payload. The owned version is [`StreamLockbox`].
///
/// See: [`StreamKey::decrypt_stream_key`](crate::stream::StreamKey::decrypt_stream_key),
/// [`LockKey::decrypt_stream_key`](crate::lock::LockKey::decrypt_stream_key), and
/// [`Vault::decrypt_stream_key`](crate::Vault::decrypt_stream_key).
///
/// # Example
///
/// Using a `StreamKey` for decryption (different from the one contained in the lockbox!):
///
/// ```
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = StreamKey::new();
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: &StreamLockboxRef = StreamLockboxRef::from_bytes(&enc[..])?;
/// // ...
/// // Retrieve the key by determining the recipient...
/// // ...
/// let dec_key: StreamKey = key.decrypt_stream_key(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(PartialEq, Eq, Hash)]
pub struct StreamLockboxRef(LockboxRef);

impl StreamLockboxRef {
    /// Create a new &LockboxRef from a byte slice. This should only be called by code that has
    /// already verified the byte slice.
    fn new_ref(lockbox_ref: &LockboxRef) -> &Self {
        // Justification:
        // StreamLockboxRef is a newtype for a LockboxRef. See LockboxRef's `new_ref` for
        // more justification, as it does the same thing.
        unsafe { &*(lockbox_ref as *const LockboxRef as *const StreamLockboxRef) }
    }

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }

    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(buf: &[u8]) -> Result<&Self, CryptoError> {
        let (lockbox, boxtype) = LockboxRef::decode(buf)?;
        if let LockboxType::Stream(_) = boxtype {
            Ok(Self::new_ref(lockbox))
        } else {
            Err(CryptoError::BadFormat("Didn't find a data lockbox"))
        }
    }
}

impl ToOwned for StreamLockboxRef {
    type Owned = StreamLockbox;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        StreamLockbox(Lockbox {
            inner: Vec::from(&self.0.inner),
        })
    }
}

impl fmt::Debug for StreamLockboxRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("StreamLockboxRef")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

/// General encrypted data.
///
/// This must be decrypted by the matching recipient, which will return a `Vec<u8>` on success.
/// It can either be decrypted on its own or through a Vault. In both cases, the data is returned
/// without being stored anywhere.
///
/// When decoding, a reference to the data is first created: [`DataLockboxRef`], which can then be
/// converted with `to_owned` to create this struct.
///
/// See: [`StreamKey::decrypt_data`](crate::stream::StreamKey::decrypt_data),
/// [`LockKey::decrypt_data`](crate::lock::LockKey::decrypt_data), and
/// [`Vault::decrypt_data`](crate::Vault::decrypt_data).
///
/// # Example
///
/// Using a `StreamKey` for decryption:
///
/// ```
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = b"I am data to be encrypted, and you don't need to see me.";
/// #
/// # // Encrypt
/// # let lockbox = key.encrypt_data(&to_send[..]);
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: DataLockbox = DataLockboxRef::from_bytes(&enc[..])?.to_owned();
/// // ...
/// // Retrieve the key by determining the recipient...
/// // ...
/// let plaintext: Vec<u8> = key.decrypt_data(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DataLockbox(Lockbox);

impl fmt::Debug for DataLockbox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("DataLockbox")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

impl std::ops::Deref for DataLockbox {
    type Target = DataLockboxRef;
    #[inline]
    fn deref(&self) -> &Self::Target {
        DataLockboxRef::new_ref(&self.0)
    }
}

impl std::borrow::Borrow<DataLockboxRef> for DataLockbox {
    fn borrow(&self) -> &DataLockboxRef {
        DataLockboxRef::new_ref(&self.0)
    }
}

/// General encrypted data.
///
/// This must be decrypted by the matching recipient, which will return a `Vec<u8>` on success.
/// It can either be decrypted on its own or through a Vault. In both cases, the data is returned
/// without being stored anywhere.
///
/// This is only a reference to an encrypted payload. The owned version is [`DataLockbox`].
///
/// See: [`StreamKey::decrypt_data`](crate::stream::StreamKey::decrypt_data),
/// [`LockKey::decrypt_data`](crate::lock::LockKey::decrypt_data), and
/// [`Vault::decrypt_data`](crate::Vault::decrypt_data).
///
/// # Example
///
/// Using a `StreamKey` for decryption:
///
/// ```
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # // Setup
/// # let key = StreamKey::new();
/// # let to_send = b"I am data to be encrypted, and you don't need to see me.";
/// #
/// # // Encrypt
/// # let lockbox = key.encrypt_data(&to_send[..]);
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: &DataLockboxRef = DataLockboxRef::from_bytes(&enc[..])?;
/// // ...
/// // Retrieve the key by determining the recipient...
/// // ...
/// let plaintext: Vec<u8> = key.decrypt_data(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(PartialEq, Eq, Hash)]
pub struct DataLockboxRef(LockboxRef);

impl DataLockboxRef {
    /// Create a new &LockboxRef from a byte slice. This should only be called by code that has
    /// already verified the byte slice.
    fn new_ref(lockbox_ref: &LockboxRef) -> &Self {
        // Justification:
        // DataLockboxRef is a newtype for a LockboxRef. See LockboxRef's `new_ref` for
        // more justification, as it does the same thing.
        unsafe { &*(lockbox_ref as *const LockboxRef as *const DataLockboxRef) }
    }

    /// Decompose the lockbox into its component parts.
    pub fn as_parts(&self) -> LockboxParts {
        self.0.as_parts()
    }

    /// Get the stream encryption version.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// The raw bytestream, suitable for serialization.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_bytes(buf: &[u8]) -> Result<&Self, CryptoError> {
        let (lockbox, boxtype) = LockboxRef::decode(buf)?;
        if let LockboxType::Data(_) = boxtype {
            Ok(Self::new_ref(lockbox))
        } else {
            Err(CryptoError::BadFormat("Didn't find a data lockbox"))
        }
    }
}

impl ToOwned for DataLockboxRef {
    type Owned = DataLockbox;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        DataLockbox(Lockbox {
            inner: Vec::from(&self.0.inner),
        })
    }
}

impl fmt::Debug for DataLockboxRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("DataLockboxRef")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

/// A lockbox byte stream, sliced into its component parts
pub struct LockboxParts<'a> {
    /// The parsed lockbox type
    pub ty: LockboxType,
    /// The entire "additional data" portion - every byte prior to the tag
    pub additional: &'a [u8],
    /// The encrypted data + tag
    pub ciphertext: &'a [u8],
    /// The header portion that isn't additional or AEAD
    pub header: &'a [u8],
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Lockbox {
    inner: Vec<u8>,
}

impl fmt::Debug for Lockbox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("Lockbox")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

impl std::ops::Deref for Lockbox {
    type Target = LockboxRef;
    #[inline]
    fn deref(&self) -> &Self::Target {
        let inner: &[u8] = self.inner.as_ref();
        LockboxRef::new_ref(inner)
    }
}

impl std::borrow::Borrow<LockboxRef> for Lockbox {
    fn borrow(&self) -> &LockboxRef {
        let inner: &[u8] = self.inner.as_ref();
        LockboxRef::new_ref(inner)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct LockboxRef {
    inner: [u8],
}

impl LockboxRef {
    /// Create a new &LockboxRef from a byte slice. This should only be called by code that has
    /// already verified the byte slice.
    fn new_ref(buf: &[u8]) -> &Self {
        // Justification:
        // LockboxRef is literally a newtype for a [u8], so &[u8] and &LockboxRef refer to the
        // same thing. This is a hack to get the type system to let us turn one into the other, and
        // it's the same hack that `serde_bytes` uses for this functionality. Likewise, the
        // standard library does something similar for working with `OsStr`, `str`, and `[T]`. So
        // at least we're in good company.
        unsafe { &*(buf as *const [u8] as *const LockboxRef) }
    }

    fn as_parts(&self) -> LockboxParts {
        let version = self.version();
        let ty = LockboxType::from_u8(self.inner[LOCKBOX_OFFSET_TYPE]).unwrap();
        if ty.is_for_stream() {
            let header_len = LOCKBOX_OFFSET_HEADER + lockbox_nonce_size(version);
            let (header, ciphertext) = self.inner.split_at(header_len);
            let (additional, header) = header.split_at(LOCKBOX_OFFSET_HEADER);
            LockboxParts {
                ty,
                additional,
                header,
                ciphertext,
            }
        } else {
            let id_version = self.inner[LOCKBOX_OFFSET_HEADER]; // Can differ from lockbox version
            let header_len = LOCKBOX_OFFSET_HEADER + lock_id_size(id_version);
            let (additional, ciphertext) = self.inner.split_at(header_len);
            let header = &additional[LOCKBOX_OFFSET_HEADER..];
            LockboxParts {
                ty,
                additional,
                header,
                ciphertext,
            }
        }
    }

    /// Get the version of the Lockbox.
    fn version(&self) -> u8 {
        self.inner[LOCKBOX_OFFSET_VERSION]
    }

    /// Provide the encoded lockbox as a byte slice.
    fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Attempt to decode a lockbox & produce both the resulting lockbox and the lockbox type byte.
    fn decode(raw: &[u8]) -> Result<(&Self, LockboxType), CryptoError> {
        let (&version, parse) = raw.split_first().ok_or(CryptoError::BadLength {
            step: "get lockbox version",
            expected: 1,
            actual: 0,
        })?;
        if version < MIN_STREAM_VERSION || version > MAX_STREAM_VERSION {
            return Err(CryptoError::UnsupportedVersion {
                ty: VersionType::SymmetricKey,
                version,
                min: MIN_STREAM_VERSION,
                max: MAX_STREAM_VERSION,
            });
        }
        let (&boxtype, parse) = parse.split_first().ok_or(CryptoError::BadLength {
            step: "get lockbox type",
            expected: 1,
            actual: 0,
        })?;
        let boxtype = LockboxType::from_u8(boxtype)?;
        let header_len = if boxtype.is_for_stream() {
            lockbox_nonce_size(version)
        } else {
            let id_version = parse.first().copied().ok_or(CryptoError::BadLength {
                step: "get lockbox ephemeral LockId version",
                expected: 1,
                actual: 0,
            })?;
            if id_version < MIN_LOCK_VERSION || id_version > MAX_LOCK_VERSION {
                return Err(CryptoError::UnsupportedVersion {
                    ty: VersionType::PublicKey,
                    version: id_version,
                    min: MIN_LOCK_VERSION,
                    max: MAX_LOCK_VERSION,
                });
            }
            lock_id_size(id_version)
        };
        let tag_len = lockbox_tag_size(version);
        // Check the length. Must be at least long enough to hold the header and tag. It is
        // acceptable (if silly) for the actual ciphertext to be of length 0.
        if parse.len() < header_len + tag_len {
            return Err(CryptoError::BadLength {
                step: "get lockbox header data",
                expected: header_len + tag_len,
                actual: parse.len(),
            });
        }
        Ok((Self::new_ref(raw), boxtype))
    }
}

impl fmt::Debug for LockboxRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("Lockbox")
            .field("version", &self.version())
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

impl ToOwned for LockboxRef {
    type Owned = Lockbox;
    #[inline]
    fn to_owned(&self) -> Self::Owned {
        Lockbox {
            inner: Vec::from(&self.inner),
        }
    }
}

/// Directly take parts to construct a `LockLockbox`. Should only be used by implementors of the
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn lock_lockbox_from_parts(inner: Vec<u8>) -> LockLockbox {
    LockLockbox(Lockbox { inner })
}

/// Directly take parts to construct a `IdentityLockbox`. Should only be used by implementors of the
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn identity_lockbox_from_parts(inner: Vec<u8>) -> IdentityLockbox {
    IdentityLockbox(Lockbox { inner })
}

/// Directly take parts to construct a `StreamLockbox`. Should only be used by implementors of the
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn stream_lockbox_from_parts(inner: Vec<u8>) -> StreamLockbox {
    StreamLockbox(Lockbox { inner })
}

/// Directly take parts to construct a `DataLockbox`. Should only be used by implementors of the
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn data_lockbox_from_parts(inner: Vec<u8>) -> DataLockbox {
    DataLockbox(Lockbox { inner })
}
