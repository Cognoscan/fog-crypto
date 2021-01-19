//! Public-Key encryption.
//!
//! This module lets you create a [`LockKey`] (a private key), which comes with a corresponding 
//! [`LockId`] (the public key). The `LockId` can be used to encrypt data and export keys, while 
//! the `LockKey` can decrypt those keys and data.
//!
//! All `LockKey` structs are backed by some struct that implements the [`LockInterface`] trait; 
//! this can be an in-memory private key, an interface to an OS-managed keystore, an interface to a 
//! hardware security module, or something else.
//!
//! # Example
//!
//! ```
//! # use std::convert::TryFrom;
//! # use fog_crypto::lock::*;
//! # use fog_crypto::lockbox::*;
//!
//! // Make a new temporary key
//! let mut csprng = rand::rngs::OsRng {};
//! let key = LockKey::new_temp(&mut csprng);
//! let id = key.id().clone();
//!
//! println!("LockId(Base58): {}", key.id());
//!
//! // Encrypt some data with the public ID, then turn it into a byte vector
//! let data = b"I am sensitive information, about to be encrypted";
//! let lockbox = id.encrypt_data(&mut csprng, data.as_ref());
//! let mut encoded = Vec::new();
//! encoded.extend_from_slice(lockbox.as_bytes());
//!
//! // Decrypt that data with the private key
//! let dec_lockbox = DataLockbox::try_from(encoded.as_ref()).unwrap();
//! let dec_data = key.decrypt_data(&dec_lockbox).unwrap();
//! assert_eq!(&data[..], &dec_data[..]);
//! ```
//!
//! # Algorithms
//!
//! The current (and only) algorithm for public-key encryption is X25519 for calculation of the 
//! shared secret. The private key is handled by a [`LockKey`], while the public key is available 
//! as a [`LockId`].
//!
//! An ephemeral key pair is generated for each new lockbox, and the shared secret is calculated 
//! on encryption with the ephemeral private key and the `LockId` through Diffie-Hellman key 
//! exchange. On decryption, the ephemeral public key is recovered from the lockbox and is 
//! combined with the recipient's `LockKey`.
//!
//! In all cases, the 32-byte shared secret is directly used as the symmetric key in 
//! XChaCha20Poly1305.
//!
//! # Format
//!
//! A [`LockId`] is encoded as a version byte followed by the contained public key, whose length 
//! may be dependant on the version. For X25519, it is 32 bytes (plus the version byte).
//!
//! A [`LockKey`] is encoded as a version byte followed by the contained private key, whose length 
//! may be dependant on the version. For X25519, it is 32 bytes (plus the version byte).  This 
//! encoding is only ever used for the payload of a [`LockLockbox`].
//!
//! For details on the lockbox formatting, see the [submodule documentation](crate::lockbox).
//!

use crate::{
    identity::{IdentityKey, ContainedIdKey, new_identity_key},
    lockbox::*,
    stream::{StreamKey, ContainedStreamKey, new_stream_key, stream_key_encrypt},
    CryptoError,
    CryptoSrc,
};

use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroize;

use std::{
    fmt,
    sync::Arc,
    convert::TryFrom
};

/// Default public-key encryption algorithm version.
pub const DEFAULT_LOCK_VERSION: u8 = 1;

/// Minimum accepted public-key encryption algorithm version.
pub const MIN_LOCK_VERSION: u8 = 1;

/// Maximum accepted public-key encryption algorithm version.
pub const MAX_LOCK_VERSION: u8 = 1;

const V1_LOCK_ID_SIZE: usize = 32; // Size of public key
const V1_LOCK_KEY_SIZE: usize = 32; // Size of static secret key

pub(crate) fn lock_id_size(_version: u8) -> usize {
    1+V1_LOCK_ID_SIZE
}

pub(crate) fn lock_eph_size(_version: u8) -> usize {
    V1_LOCK_ID_SIZE
}

/// A key that allows decrypting data meant for a particular [`LockId`].
///
/// This acts as a wrapper for a specific cryptographic private decryption key,
///
/// # Example
/// ```
/// # use std::convert::TryFrom;
/// # use fog_crypto::lock::*;
/// # use fog_crypto::lockbox::*;
///
/// // Make a new temporary key
/// let mut csprng = rand::rngs::OsRng {};
/// let key = LockKey::new_temp(&mut csprng);
/// let id = key.id().clone();
/// println!("LockId(Base58): {}", key.id());
///
/// // ...
/// // Wait for encrypted data to show up
/// // ...
/// # let data = b"I am sensitive information, about to be encrypted";
/// # let lockbox = id.encrypt_data(&mut csprng, data.as_ref());
/// # let mut received = Vec::new();
/// # received.extend_from_slice(lockbox.as_bytes());
///
/// // Decrypt Some received data
/// let lockbox = DataLockbox::try_from(received.as_ref()).unwrap();
/// let data = key.decrypt_data(&lockbox).unwrap();
/// ```
#[derive(Clone)]
pub struct LockKey {
    interface: Arc<dyn LockInterface>,
}

impl LockKey {

    /// Generate a temporary `LockKey` that exists only in program memory.
    pub fn new_temp<R>(csprng: &mut R) -> LockKey
    where
        R: CryptoRng + RngCore,
    {
        let interface = Arc::new(ContainedLockKey::generate(csprng));
        new_lock_key(interface)
    }
    
    /// Generate a temporary `LockKey` that exists only in program memory. Uses the specified 
    /// version instead of the default, and fails if the version is unsupported.
    pub fn new_temp_with_version<R>(csprng: &mut R, version: u8) -> Result<LockKey, CryptoError>
    where
        R: CryptoRng + RngCore,
    {
        let interface = Arc::new(ContainedLockKey::with_version(csprng, version)?);
        Ok(new_lock_key(interface))
    }

    /// Version of Diffie-Hellman key exchange algorithm used by this key.
    pub fn version(&self) -> u8 {
        self.interface.id().version()
    }

    /// The public identifier for this key.
    pub fn id(&self) -> &LockId {
        self.interface.id()
    }
    
    /// Attempt to decrypt a `LockLockbox` with this key. On success, the returned `LockKey` is
    /// temporary and not associated with any Vault.
    pub fn decrypt_lock_key(&self, lockbox: &LockLockbox) -> Result<LockKey, CryptoError> {
        self.interface.decrypt_lock_key(lockbox)
    }

    /// Attempt to decrypt a `IdentityLockbox` with this key. On success, the returned
    /// `IdentityKey` is temporary and not associated with any Vault.
    pub fn decrypt_identity_key(
        &self,
        lockbox: &IdentityLockbox,
    ) -> Result<IdentityKey, CryptoError> {
        self.interface.decrypt_identity_key(lockbox)
    }

    /// Attempt to decrypt a `StreamLockbox` with this key. On success, the returned
    /// `StreamKey` is temporary and not associated with any Vault.
    pub fn decrypt_stream_key(&self, lockbox: &StreamLockbox) -> Result<StreamKey, CryptoError> {
        self.interface.decrypt_stream_key(lockbox)
    }

    /// Attempt to decrypt a `DataLockbox` with this key.
    pub fn decrypt_data(&self, lockbox: &DataLockbox) -> Result<Vec<u8>, CryptoError> {
        self.interface.decrypt_data(lockbox)
    }

    /// Export the signing key in an `LockLockbox`, with `receive_lock` as the recipient. If 
    /// the key cannot be exported, this should return None.
    pub fn export_for_lock<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        lock: &LockId
    ) -> Option<LockLockbox> {
        self.interface.self_export_lock(csprng, lock)
    }

    /// Export the private key in a `LockLockbox`, with `receive_stream` as the recipient. If 
    /// the key cannot be exported, this should return None. Additionally, if the underlying 
    /// implementation does not allow moving the raw key into memory (i.e. it cannot call
    /// [`StreamInterface::encrypt`](crate::stream::StreamInterface::encrypt) or 
    /// [`lock_id_encrypt`](lock_id_encrypt)) then None can also be returned.
    pub fn export_for_stream<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        stream: &StreamKey,
    ) -> Option<LockLockbox> {
        self.interface.self_export_stream(csprng, stream)
    }
}

impl fmt::Debug for LockKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockKey")
            .field("version", &self.version())
            .field("lock_id", &self.id().raw_public_key())
            .finish()
    }
}

impl fmt::Display for LockKey {
    /// Display just the LockId (never the underlying key).
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.id(), f)
    }
}

/// Create a new `LockKey` to hold a `LockInterface` implementation. Can be used by implementors of 
/// a vault when making new `LockKey` instances.
pub fn new_lock_key(interface: Arc<dyn LockInterface>) -> LockKey {
    LockKey {
        interface,
    }
}

/// A decryption interface, implemented by anything that can hold a private cryptographic 
/// decryption key.
///
/// An implementor must handle all supported Diffie-Hellman algorithms and symmetric-key encryption 
/// algorithms.
pub trait LockInterface {

    /// Get the corresponding `LockId` for the private key.
    fn id(&self) -> &LockId;

    /// Decrypt an exported `LockKey`.
    fn decrypt_lock_key(
        &self,
        lockbox: &LockLockbox,
    ) -> Result<LockKey, CryptoError>;

    /// Decrypt an exported `IdentityKey`.
    fn decrypt_identity_key(
        &self,
        lockbox: &IdentityLockbox,
    ) -> Result<IdentityKey, CryptoError>;

    /// Decrypt an exported `StreamKey`.
    fn decrypt_stream_key(
        &self,
        lockbox: &StreamLockbox,
    ) -> Result<StreamKey, CryptoError>;

    /// Decrypt encrypted data.
    fn decrypt_data(
        &self,
        lockbox: &DataLockbox
    ) -> Result<Vec<u8>, CryptoError>;

    /// Export the decryption key in a `LockLockbox`, with `receive_lock` as the recipient. If the 
    /// key cannot be exported, this should return None.
    fn self_export_lock(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_lock: &LockId
    ) -> Option<LockLockbox>;

    /// Export the decryption key in a `LockLockbox`, with `receive_stream` as the recipient. If the 
    /// key cannot be exported, this should return None.
    fn self_export_stream(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_stream: &StreamKey,
    ) -> Option<LockLockbox>;
}

/// An identifier for a corresponding [`LockKey`] that can be used to encrypt data for that key.
///
/// This contains a cryptographic public encryption key.
///
/// # Example
/// ```
/// # use fog_crypto::lock::*;
/// # use fog_crypto::lockbox::*;
/// # let mut csprng = rand::rngs::OsRng {};
/// # let key = LockKey::new_temp(&mut csprng);
/// # let id = key.id().clone();
///
/// // We've been given a LockId that we're sending encrypted data to.
/// println!("LockId(Base58): {}", key.id());
///
/// // Encrypt some data for that LockId
/// let data = b"I am sensitive information, about to be encrypted";
/// let lockbox = id.encrypt_data(&mut csprng, data.as_ref());
///
/// // The lockbox can be encoded onto a vec or used as raw bytes.
/// let mut to_send = Vec::new();
/// to_send.extend_from_slice(lockbox.as_bytes());
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LockId {
    inner: x25519_dalek::PublicKey
}

impl LockId {

    /// Encrypt a byte slice into a `DataLockbox`. Requires a cryptographic RNG to generate the 
    /// needed nonce.
    pub fn encrypt_data<R>(
        &self,
        csprng: &mut R,
        content: &[u8]
    ) -> DataLockbox
        where R: CryptoRng + RngCore
    {
        data_lockbox_from_parts(
            LockboxRecipient::LockId(self.clone()),
            lock_id_encrypt(&self, csprng, LockboxType::Data(false), content)
        )
    }

    /// Get the cryptographic algorithm version used for this ID.
    pub fn version(&self) -> u8 {
        1u8
    }

    /// Get the raw public encryption key contained within.
    pub fn raw_public_key(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Convert into a byte vector. For extending an existing byte vector, see 
    /// [`encode_vec`](Self::encode_vec).
    pub fn as_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode_vec(&mut v);
        v
    }

    /// Attempt to parse a base58-encoded `LockId`.
    pub fn from_base58(s: &str) -> Result<Self, CryptoError> {
        let raw = bs58::decode(s).into_vec().or(Err(CryptoError::BadFormat("Not valid Base58")))?;
        Self::try_from(&raw[..])
    }

    /// Convert into a base58-encoded `LockId`.
    pub fn to_base58(&self) -> String {
        bs58::encode(&(self.as_vec())).into_string()
    }

    /// Encode onto an existing byte vector. Writes out the version followed by the public signing 
    /// key. It does not include any length information in the encoding.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len());
        buf.push(self.version());
        buf.extend_from_slice(self.inner.as_bytes());
    }

    /// Get the length of this Identity once encoded as bytes.
    pub fn len(&self) -> usize {
        1 + V1_LOCK_ID_SIZE
    }
}

impl TryFrom<&[u8]> for LockId {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (&version, data) = value.split_first()
            .ok_or(CryptoError::BadLength{step: "get LockId version", expected: 1, actual: 0})?;
        if version != 1u8 {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        if data.len() != V1_LOCK_ID_SIZE {
            return Err(CryptoError::BadLength{
                step: "get LockId public key",
                expected: V1_LOCK_ID_SIZE,
                actual: data.len()
            });
        }
        let inner: [u8; V1_LOCK_ID_SIZE] = TryFrom::try_from(data)
            .or(Err(CryptoError::BadLength {
                step: "get LockId public key",
                expected: V1_LOCK_ID_SIZE,
                actual: data.len()
            }))?;
        Ok(Self {
            inner: x25519_dalek::PublicKey::from(inner)
        })
    }
}

impl fmt::Debug for LockId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Identity")
            .field("version", &self.version())
            .field("public_key", &self.raw_public_key())
            .finish()
    }
}

impl fmt::Display for LockId {
    /// Display as a base58-encoded string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::LowerHex for LockId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.as_vec().iter() {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for LockId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.as_vec().iter() {
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}

/// Encrypt data with a `LockId`, returning a raw byte vector. Implementors of 
/// [`SignInterface`][SignInterface], [`StreamInterface`][StreamInterface], [`LockInterface`] can 
/// use this when exporting keys.
///
/// It's not inside the regular `LockId` methods because those are meant for users, which should 
/// not use this function and instead rely on the various `export...` and `encrypt_data` functions.
///
/// [StreamInterface]: crate::stream::StreamInterface
/// [SignInterface]: crate::identity::SignInterface
pub fn lock_id_encrypt(
    id: &LockId,
    csprng: &mut dyn CryptoSrc,
    lock_type: LockboxType,
    content: &[u8],
) -> Vec<u8>
{
    assert!(!lock_type.is_for_stream(), "Tried to encrypt a non-lock-recipient lockbox with a LockId");
    use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
    use chacha20poly1305::aead::{NewAead, AeadInPlace};

    // Generate the ephemeral key and the nonce
    let mut nonce = [0u8; crate::lockbox::V1_LOCKBOX_NONCE_SIZE];
    csprng.fill_bytes(nonce.as_mut());
    let eph = x25519_dalek::EphemeralSecret::new(csprng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph);

    // Get the data lengths and allocate the vec
    let version = id.version();
    let tag_len = lockbox_tag_size(version);
    let nonce_len = lockbox_nonce_size(version);
    let header_len = 2 + id.len() + eph_pub.as_bytes().len();
    let len = header_len + nonce_len + content.len() + tag_len;
    let mut lockbox = Vec::with_capacity(len);

    // Lockbox header & data
    lockbox.push(version);
    lockbox.push(lock_type.as_u8());
    id.encode_vec(&mut lockbox);
    lockbox.extend_from_slice(eph_pub.as_bytes());
    lockbox.extend_from_slice(&nonce);
    lockbox.extend_from_slice(content);

    // Set up the symmetric-key cipher
    let (additional, nonce_and_content) = lockbox.split_at_mut(header_len);
    let (_, content) = nonce_and_content.split_at_mut(nonce_len);
    let secret = eph.diffie_hellman(&id.inner);
    let aead = XChaCha20Poly1305::new(
        Key::from_slice(secret.as_bytes()));
    let nonce = XNonce::from(nonce);

    // We unwrap here because the only failure condition on encryption is if the content is really 
    // big. Specifically, for XChaCha20Poly1305, 256 GiB big. This library cannot handle that for 
    // many other reasons, so it's a-ok if we panic here.
    let tag = aead.encrypt_in_place_detached(&nonce, additional, content)
        .expect("More data than the cipher can accept was put in");
    lockbox.extend_from_slice(&tag);
    lockbox
}

/// A self-contained implementor of `LockInterface`. It's expected this will be used unless the 
/// decryption key is being managed by the OS or a hardware module.
pub struct ContainedLockKey {
    id: LockId,
    key: x25519_dalek::StaticSecret
}

impl ContainedLockKey {

    /// Generate a new key given a cryptographic random number generator.
    pub fn generate<R>(csprng: &mut R) -> Self
        where R: CryptoRng + RngCore
    {
       Self::with_version(csprng, DEFAULT_LOCK_VERSION).unwrap()
    }

    /// Generate a new key with a specific version, given a cryptographic random number generator. 
    /// Fails if the version isn't supported.
    pub fn with_version<R>(csprng: &mut R, version: u8) -> Result<Self, CryptoError>
        where R: CryptoRng + RngCore
    {
        if (version < MIN_LOCK_VERSION) || (version > MAX_LOCK_VERSION) {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let key = x25519_dalek::StaticSecret::new(csprng);
        let id = LockId { inner: x25519_dalek::PublicKey::from(&key) };

        Ok(Self {
            key,
            id,
        })
    }

    /// Encode directly to a byte vector. The resulting vector should be zeroized or overwritten 
    /// before being dropped.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        buf.reserve(1+V1_LOCK_KEY_SIZE);
        buf.push(1u8);
        // We have to copy the key out and then extend it because x25519_dalek doesn't have a 
        // "as_bytes"-style function. Make sure to zeroize this after it's been used.
        let mut raw_key = self.key.to_bytes();
        buf.extend_from_slice(&raw_key);
        raw_key.zeroize();
    }

    /// Decrypt a lockbox's individual parts. This is only used by the `LockInterface` 
    /// implementation.
    fn decrypt_parts(&self, recipient: &LockboxRecipient, parts: LockboxParts) -> Result<Vec<u8>, CryptoError> {
        // Verify this is the right key for this lockbox. It costs us little to do this, and saves 
        // us from potential logic errors
        if let LockboxRecipient::LockId(id) = recipient {
            if id != &self.id {
                return Err(CryptoError::ObjectMismatch(
                    "StreamKey being used on a lockbox meant for a different LockId"
                ));
            }
        }
        else {
            return Err(CryptoError::ObjectMismatch(
                "Attempted to use a LockKey to decrypt a lockbox with a StreamId recipient"
            ));
        }

        // Attempt to read the ephemeral key and compute the secret
        let eph_pub = parts.eph_pub.unwrap();
        if eph_pub.len() != V1_LOCK_ID_SIZE {
            return Err(CryptoError::BadLength {
                step: "get Lockbox ephemeral public key",
                expected: V1_LOCK_ID_SIZE,
                actual: eph_pub.len()
            });
        }
        let eph_pub: [u8; 32] = TryFrom::try_from(eph_pub).
            map_err(|_| CryptoError::BadLength {
                step: "get Lockbox ephemeral public key",
                expected: V1_LOCK_ID_SIZE,
                actual: eph_pub.len()
            })?;
        let eph_pub = x25519_dalek::PublicKey::from(eph_pub);
        let secret = self.key.diffie_hellman(&eph_pub);

        // Feed the lockbox's parts into the decryption algorithm
        use chacha20poly1305::*;
        use chacha20poly1305::aead::{NewAead, Aead};
        let aead = XChaCha20Poly1305::new(
            Key::from_slice(secret.as_bytes()));
        let nonce = XNonce::from_slice(parts.nonce);
        let payload = aead::Payload {
            msg: parts.ciphertext,
            aad: parts.additional,
        };
        aead.decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptFailed)
    }


}

impl TryFrom<&[u8]> for ContainedLockKey {
    type Error = CryptoError;

    /// Try to decode a raw byte sequence into a private
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (version, raw_key) = value.split_first()
            .ok_or(CryptoError::BadLength{step: "get LockKey version", expected: 1, actual: 0})?;
        let version = *version;
        if version < MIN_LOCK_VERSION {
            return Err(CryptoError::OldVersion(version));
        }
        if version > MAX_LOCK_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        // Copy the private key, wrap in StaticSecret, and clear out the temporary value.
        // We have to do this because x25519_dalek doesn't support try_from and provides no other 
        // means to copy in from a byte slice.
        if raw_key.len() != V1_LOCK_KEY_SIZE {
            return Err(CryptoError::BadLength {
                step: "get LockKey key bytes",
                expected: V1_LOCK_KEY_SIZE,
                actual: raw_key.len()
            });
        }
        let mut raw_key: [u8; V1_LOCK_KEY_SIZE] = TryFrom::try_from(raw_key)
            .map_err(|_|
                CryptoError::BadLength {
                    step: "get LockKey key bytes",
                    expected: V1_LOCK_KEY_SIZE,
                    actual: raw_key.len()
                })?;
        let key = x25519_dalek::StaticSecret::from(raw_key);
        raw_key.zeroize();

        let public = x25519_dalek::PublicKey::from(&key);

        Ok(Self {
            key,
            id: LockId { inner: public },
        })
    }
}

impl LockInterface for ContainedLockKey {

    fn id(&self) -> &LockId {
        &self.id
    }

    fn decrypt_lock_key(
        &self,
        lockbox: &LockLockbox,
    ) -> Result<LockKey, CryptoError> {
        let recipient = lockbox.recipient();
        let parts = lockbox.as_parts();
        let mut key = self.decrypt_parts(recipient, parts)?;
        let result = ContainedLockKey::try_from(key.as_ref());
        key.zeroize();
        Ok(new_lock_key(Arc::new(result?)))
    }

    fn decrypt_identity_key(
        &self,
        lockbox: &IdentityLockbox,
    ) -> Result<IdentityKey, CryptoError> {
        let recipient = lockbox.recipient();
        let parts = lockbox.as_parts();
        let mut key = self.decrypt_parts(recipient, parts)?;
        let result = ContainedIdKey::try_from(key.as_ref());
        key.zeroize();
        Ok(new_identity_key(Arc::new(result?)))
    }

    fn decrypt_stream_key(
        &self,
        lockbox: &StreamLockbox,
    ) -> Result<StreamKey, CryptoError> {
        let recipient = lockbox.recipient();
        let parts = lockbox.as_parts();
        let mut key = self.decrypt_parts(recipient, parts)?;
        let result = ContainedStreamKey::try_from(key.as_ref());
        key.zeroize();
        Ok(new_stream_key(Arc::new(result?)))
    }

    fn decrypt_data(
        &self,
        lockbox: &DataLockbox
    ) -> Result<Vec<u8>, CryptoError> {
        let recipient = lockbox.recipient();
        let parts = lockbox.as_parts();
        self.decrypt_parts(recipient, parts)
    }

    fn self_export_lock(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_lock: &LockId
    ) -> Option<LockLockbox> {
        let mut raw_secret = Vec::new(); // Make 100% certain this is zeroized at the end!
        self.encode_vec(&mut raw_secret);
        let lockbox_vec = lock_id_encrypt(receive_lock, csprng, LockboxType::Lock(false), &raw_secret);
        raw_secret.zeroize();
        debug_assert!(raw_secret.iter().all(|&x| x == 0)); // You didn't remove the zeroize call, right?
        Some(lock_lockbox_from_parts(
            LockboxRecipient::LockId(receive_lock.clone()),
            lockbox_vec,
        ))
    }

    fn self_export_stream(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_stream: &StreamKey,
    ) -> Option<LockLockbox> {
        let mut raw_secret = Vec::new(); // Make 100% certain this is zeroized at the end!
        self.encode_vec(&mut raw_secret);
        let lockbox_vec = stream_key_encrypt(receive_stream, csprng, LockboxType::Lock(true), &raw_secret);
        raw_secret.zeroize();
        debug_assert!(raw_secret.iter().all(|&x| x == 0)); // You didn't remove the zeroize call, right?
        Some(lock_lockbox_from_parts(
            LockboxRecipient::StreamId(receive_stream.id().clone()),
            lockbox_vec,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_data() {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = LockKey::new_temp(&mut csprng);
        let message = b"I am a test message, going undercover";

        // Encrypt
        let lockbox = key.id().encrypt_data(&mut csprng, message);
        let expected_recipient = LockboxRecipient::LockId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        println!("Header = {:x?}", &enc[0..4]);
        let dec_lockbox = DataLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_message = key.decrypt_data(&dec_lockbox).unwrap();
        assert_eq!(message, &dec_message[..]);
    }

    #[test]
    fn lock_id_key() {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = LockKey::new_temp(&mut csprng);
        let to_send = IdentityKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_lock(&mut csprng, key.id()).unwrap();
        let expected_recipient = LockboxRecipient::LockId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        let dec_lockbox = IdentityLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_key = key.decrypt_identity_key(&dec_lockbox).unwrap();
        assert_eq!(to_send.id(), dec_key.id());
    }

    #[test]
    fn lock_stream_key() {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = LockKey::new_temp(&mut csprng);
        let to_send = StreamKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_lock(&mut csprng, key.id()).unwrap();
        let expected_recipient = LockboxRecipient::LockId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        let dec_lockbox = StreamLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_key = key.decrypt_stream_key(&dec_lockbox).unwrap();
        assert_eq!(to_send.id(), dec_key.id());
    }

    #[test]
    fn lock_lock_key() {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = LockKey::new_temp(&mut csprng);
        let to_send = LockKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_lock(&mut csprng, key.id()).unwrap();
        let expected_recipient = LockboxRecipient::LockId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        let dec_lockbox = LockLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_key = key.decrypt_lock_key(&dec_lockbox).unwrap();
        assert_eq!(to_send.id(), dec_key.id());
    }

}
