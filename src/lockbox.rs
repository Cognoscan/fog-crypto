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
//! # Algorithms
//!
//! The current (and only) algorithm is XChaCha20 with a Poly1305 AEAD construction. For 
//! `StreamKey` recipients, the secret XChaCha20 key is used for encryption. For `LockId` 
//! recipients, an ephemeral X25519 keypair is generated and DH key agreement is used to generate 
//! the key.
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
//! recipient, and bits 2 & 1 encode the main lockbox type.
//!
//! # Format
//!
//! The first lockbox format is for `LockId`-recipient lockboxes. It consists of the version 
//! byte, a byte set to the lockbox type, the encoded `LockId`, an ephemeral X25519 public key 
//! (without a version byte), a 24-byte nonce, the ciphertext, and the 16-byte Poly1305 
//! authentication tag.
//!
//! The second lockbox format is for `StreamKey`-recipient lockboxes. It consists of the version 
//! byte, a byte set to the lockbox type, the encoded `StreamId`, a 24-byte nonce, the ciphertext, 
//! and the 16-byte Poly1305 authentication tag.
//!
//! ```text
//! +----------+----------+==========+==========+==========+==============+=====+
//! | Version  |   Type   | SignKey  |  EphKey  |  Nonce   |  Ciphertext  | Tag |
//! +----------+----------+==========+==========+==========+==============+=====+
//! 
//! +----------+----------+==========+==========+==============+=====+
//! | Version  |   Type   | StreamId |  Nonce   |  Ciphertext  | Tag |
//! +----------+----------+==========+==========+==============+=====+
//! 
//! - Version indicates what version of symmetric-key encryption was used for this lockbox.
//! - Type indicates the lockbox type and recipient type. If bit 0 is cleared, the first format 
//!   (with SignKey & EphKey) is used. If bit 1 is set, the second format (with StreamId) is used.
//! - SignKey is a LockId. This is a version byte followed by the encoded public key.
//! - EphKey is a raw public key, of the same version as SignKey.
//! - StreamId is an identifier for the StreamKey that created the lockbox.
//! - Nonce is a random byte sequence matching the nonce length specified by the symmetric 
//!   encryption version used.
//! - Ciphertext is the internal data, encrypted with the chosen algorithm.
//! - Tag is the authentication tag produced using the chosen algorithm.
//! ```
//!
//! In the AEAD construction, the additional data consists of every byte prior to the nonce.
//!

use crate::{
    lock::{LockId, lock_id_size, lock_eph_size},
    stream::{stream_id_size, StreamId, MAX_STREAM_VERSION, MIN_STREAM_VERSION},
    CryptoError
};

use std::{convert::TryFrom, fmt};

pub(crate) const V1_LOCKBOX_NONCE_SIZE: usize = 24;
pub(crate) const V1_LOCKBOX_TAG_SIZE: usize = 16;

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
            Stream(t)   => (2, *t),
            Lock(t)     => (4, *t),
            Data(t)     => (6, *t),
        };
        if t { v | 0x1 } else { v }
    }

    /// Attempt to decode a lockbox type byte.
    pub fn from_u8(v: u8) -> Result<Self,CryptoError> {
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
            Stream(t)   => *t,
            Lock(t)     => *t,
            Data(t)     => *t,
        }
    }
}

/// Determine what type of lockbox is in the encoded sequence. This only checks the first two 
/// bytes, and doesn't guarantee the whole `raw` byte slice contains a valid encoded lockbox.
pub fn determine_lockbox_type(raw: &[u8]) -> Result<LockboxType, CryptoError> {
    let &boxtype = raw.get(1).ok_or(CryptoError::BadLength {
        step: "get lockbox type",
        expected: 2,
        actual: raw.len()
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
/// which will store the `LockKey`.
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
/// # use std::convert::TryFrom;
/// # use fog_crypto::lock::*;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # // Setup
/// # let mut csprng = rand::rngs::OsRng;
/// # let key = StreamKey::new_temp(&mut csprng);
/// # let to_send = LockKey::new_temp(&mut csprng);
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: LockLockbox = LockLockbox::try_from(&enc[..]).unwrap();
/// let recipient: &LockboxRecipient = dec_lockbox.recipient();
/// // ...
/// // Retrieve the key by looking up recipient
/// // ...
/// let dec_key: LockKey = key.decrypt_lock_key(&dec_lockbox).unwrap();
///
/// ```
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
        let (x, boxtype) = Lockbox::decode(value)?;
        if let LockboxType::Lock(_) = boxtype {
            Ok(Self(x))
        }
        else {
            Err(CryptoError::BadFormat("Didn't find a lock lockbox"))
        }
    }
}

/// An encrypted [`IdentityKey`](crate::identity::IdentityKey).
///
/// This must be decrypted by the matching recipient, which will return the `IdentityKey` on 
/// success.  It can either be decrypted on its own, returning a temporary `IdentityKey`, or 
/// through a Vault, which will store the `IdentityKey`.
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
/// # use std::convert::TryFrom;
/// # use fog_crypto::identity::*;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # // Setup
/// # let mut csprng = rand::rngs::OsRng;
/// # let key = StreamKey::new_temp(&mut csprng);
/// # let to_send = IdentityKey::new_temp(&mut csprng);
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: IdentityLockbox = IdentityLockbox::try_from(&enc[..]).unwrap();
/// let recipient: &LockboxRecipient = dec_lockbox.recipient();
/// // ...
/// // Retrieve the key by looking up recipient
/// // ...
/// let dec_key: IdentityKey = key.decrypt_identity_key(&dec_lockbox).unwrap();
///
/// ```
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
        let (x, boxtype) = Lockbox::decode(value)?;
        if let LockboxType::Identity(_) = boxtype {
            Ok(Self(x))
        }
        else {
            Err(CryptoError::BadFormat("Didn't find a identity lockbox"))
        }
    }
}

/// An encrypted [`StreamKey`](crate::stream::StreamKey).
///
/// This must be decrypted by the matching recipient, which will return the `StreamKey` on 
/// success.  It can either be decrypted on its own, returning a temporary `StreamKey`, or 
/// through a Vault, which will store the `StreamKey`.
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
/// # use std::convert::TryFrom;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # // Setup
/// # let mut csprng = rand::rngs::OsRng;
/// # let key = StreamKey::new_temp(&mut csprng);
/// # let to_send = StreamKey::new_temp(&mut csprng);
/// #
/// # // Encrypt
/// # let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: StreamLockbox = StreamLockbox::try_from(&enc[..]).unwrap();
/// let recipient: &LockboxRecipient = dec_lockbox.recipient();
/// // ...
/// // Retrieve the key by looking up recipient
/// // ...
/// let dec_key: StreamKey = key.decrypt_stream_key(&dec_lockbox).unwrap();
///
/// ```
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
        let (x, boxtype) = Lockbox::decode(value)?;
        if let LockboxType::Stream(_) = boxtype {
            Ok(Self(x))
        }
        else {
            Err(CryptoError::BadFormat("Didn't find a stream lockbox"))
        }
    }
}


/// General encrypted data.
///
/// This must be decrypted by the matching recipient, which will return a `Vec<u8>` on success.
/// It can either be decrypted on its own or through a Vault. In both cases, the data is returned 
/// without being stored anywhere.
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
/// # use std::convert::TryFrom;
/// # use fog_crypto::lockbox::*;
/// # use fog_crypto::stream::*;
/// # // Setup
/// # let mut csprng = rand::rngs::OsRng;
/// # let key = StreamKey::new_temp(&mut csprng);
/// # let to_send = b"I am data to be encrypted, and you don't need to see me.";
/// #
/// # // Encrypt
/// # let lockbox = key.encrypt_data(&mut csprng, &to_send[..]);
/// # let enc = Vec::from(lockbox.as_bytes());
/// #
/// // We have `enc`, a byte vector containing a lockbox
/// let dec_lockbox: DataLockbox = DataLockbox::try_from(&enc[..]).unwrap();
/// let recipient: &LockboxRecipient = dec_lockbox.recipient();
/// // ...
/// // Retrieve the key by looking up recipient
/// // ...
/// let plaintext: Vec<u8> = key.decrypt_data(&dec_lockbox).unwrap();
///
/// ```
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
        let (x, boxtype) = Lockbox::decode(value)?;
        if let LockboxType::Data(_) = boxtype {
            Ok(Self(x))
        }
        else {
            Err(CryptoError::BadFormat("Didn't find a data lockbox"))
        }
    }
}

/// A lockbox byte stream, sliced into its component parts
pub struct LockboxParts<'a> {
    /// The ephemeral public key
    pub eph_pub: Option<&'a[u8]>,
    /// The entire "additional data" portion - every byte prior to the nonce.
    pub additional: &'a[u8],
    /// The random nonce.
    pub nonce: &'a[u8],
    /// The encrypted data, including the AEAD tag at the end.
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

    /// Provide the encoded lockbox as a byte slice.
    fn as_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Attempt to decode a lockbox & produce both the resulting lockbox and the lockbox type byte.
    fn decode(raw: &[u8]) -> Result<(Self, LockboxType), CryptoError> {
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
        let boxtype = LockboxType::from_u8(boxtype)?;
        if boxtype.is_for_stream() {
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
                return Err(CryptoError::BadFormat("Lockbox version didn't match Stream Id version"));
            }
            Ok((Self {
                recipient: LockboxRecipient::StreamId(id),
                inner: Vec::from(raw),
            }, boxtype))
        }
        else {
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
            Ok((Self {
                recipient: LockboxRecipient::LockId(id),
                inner: Vec::from(raw),
            }, boxtype))
        }
    }

}

impl fmt::Debug for Lockbox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let parts = self.as_parts();
        f.debug_struct("Lockbox")
            .field("version", &self.version())
            .field("recipient", &self.recipient)
            .field("cipertext_len", &parts.ciphertext.len())
            .finish()
    }
}

/// Directly take parts to construct a `LockLockbox`. Should only be used by implementors of the 
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the 
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn lock_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> LockLockbox {
    LockLockbox(Lockbox { recipient, inner })
}

/// Directly take parts to construct a `IdentityLockbox`. Should only be used by implementors of the 
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the 
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn identity_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> IdentityLockbox {
    IdentityLockbox(Lockbox { recipient, inner })
}

/// Directly take parts to construct a `StreamLockbox`. Should only be used by implementors of the 
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the 
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn stream_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> StreamLockbox {
    StreamLockbox(Lockbox { recipient, inner })
}

/// Directly take parts to construct a `DataLockbox`. Should only be used by implementors of the 
/// `encrypt` functions.
///
/// This is *not* checked for correctness. Strongly consider having unit tests that check the 
/// round-trip encrypt/decrypt for each lockbox type to catch misuse of this.
pub fn data_lockbox_from_parts(recipient: LockboxRecipient, inner: Vec<u8>) -> DataLockbox {
    DataLockbox(Lockbox { recipient, inner })
}

/// Lockboxes can be meant for one of two types of recipients: a [`LockId`] (public key), or a
/// [`StreamId`] (symmetric key). The corresponding [`LockKey`](crate::lock::LockKey) or 
/// [`StreamKey`](crate::stream::StreamKey) is needed for decryption of the lockbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockboxRecipient {
    LockId(LockId),
    StreamId(StreamId),
}
