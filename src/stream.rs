//! Symmetric-Key encryption.
//!
//! This submodule provides a `StreamKey` for symmetric encryption & decryption of any lockbox 
//! type. Each `StreamKey` has a corresponding `StreamId` for easily identifying the key needed to 
//! decrypt a lockbox.
//!
//! # Example
//!
//! ```
//! # use std::convert::TryFrom;
//! # use fog_crypto::stream::*;
//! # use fog_crypto::lockbox::*;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! // Make a new temporary key
//! let mut csprng = rand::rngs::OsRng {};
//! let key = StreamKey::new_temp(&mut csprng);
//! let id = key.id().clone();
//!
//! println!("StreamId(Base58): {}", key.id());
//!
//! // Encrypt some data with the key, then turn it into a byte vector
//! let data = b"I am sensitive information, about to be encrypted";
//! let lockbox = key.encrypt_data(&mut csprng, data.as_ref());
//! let mut encoded = Vec::new();
//! encoded.extend_from_slice(lockbox.as_bytes());
//!
//! // Decrypt that data with the same key
//! let dec_lockbox = DataLockbox::try_from(encoded.as_ref())?;
//! let dec_data = key.decrypt_data(&dec_lockbox)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Algorithms
//!
//! The current (and only) algorithm for symmetric encryption is XChaCha20 with a Poly1305 AEAD 
//! construction (XChaCha20Poly1305).
//!
//! The `StreamId` is computed by taking the 32-byte secret key and hashing it with BLAKE2b, with 
//! the parameters: no key, no salt, and a persona set to "fog-crypto-sid". 32 bytes of the output 
//! hash are used to create the `StreamId`.
//!
//! # Format
//!
//! A `StreamId` is encoded as a version byte followed by the key itself, whose length is dependant 
//! on the version. For XChaCha20Poly1305, it is 32 bytes plus the version byte.
//!
//! A `StreamKey` is also encoded as a version byte followed by the key itself, whose length is 
//! dependant on the version. For XChaCha20Poly1305, it is 32 bytes plus the version byte. This 
//! encoding is only ever used for the payload of a [`StreamLockbox`].
//!
//! See the [`lockbox`](crate::lockbox) module for documentation on the encoding format for 
//! encrypted payloads.

use crate::{
    identity::{IdentityKey, ContainedIdKey, new_identity_key},
    lockbox::*,
    lock::{lock_id_encrypt, LockId, LockKey, ContainedLockKey, new_lock_key},
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

use blake2::{
    VarBlake2b,
    digest::{Update, VariableOutput},
};

/// Default symmetric-key encryption algorithm version.
pub const DEFAULT_STREAM_VERSION: u8 = 1;

/// Minimum accepted symmetric-key encryption algorithm version.
pub const MIN_STREAM_VERSION: u8 = 1;

/// Maximum accepted symmetric-key encryption algorithm version.
pub const MAX_STREAM_VERSION: u8 = 1;

const V1_STREAM_ID_SIZE: usize = 32;
const V1_STREAM_KEY_SIZE: usize = 32;

/// Get expected size of StreamId for a given version. Version *must* be validated before calling 
/// this.
pub(crate) fn stream_id_size(_version: u8) -> usize {
    1+V1_STREAM_ID_SIZE
}

/// Stream Key that allows encrypting data into a `Lockbox` and decrypting it later.
///
/// This acts as a wrapper for a specific cryptographic symmetric key, which can only be used with 
/// the corresponding symmetric encryption algorithm. The underlying key may be located in a 
/// hardware module or some other private keystore; in this case, it may be impossible to export 
/// the key.
///
/// ```
/// # use std::convert::TryFrom;
/// # use fog_crypto::stream::*;
/// # use fog_crypto::lockbox::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// // Make a new temporary key
/// let mut csprng = rand::rngs::OsRng {};
/// let key = StreamKey::new_temp(&mut csprng);
/// let id = key.id().clone();
///
/// // Encrypt some data with the key, then turn it into a byte vector
/// let data = b"I am sensitive information, about to be encrypted";
/// let lockbox = key.encrypt_data(&mut csprng, data.as_ref());
/// let mut encoded = Vec::new();
/// encoded.extend_from_slice(lockbox.as_bytes());
///
/// // Decrypt that data with the same key
/// let dec_lockbox = DataLockbox::try_from(encoded.as_ref())?;
/// let dec_data = key.decrypt_data(&dec_lockbox)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct StreamKey {
    interface: Arc<dyn StreamInterface>
}

impl StreamKey {

    /// Generate a temporary `StreamKey` that exists only in program memory.
    pub fn new_temp<R>(csprng: &mut R) -> StreamKey
        where R: CryptoRng + RngCore
    {
        let interface = Arc::new(ContainedStreamKey::generate(csprng));
        new_stream_key(interface)
    }
    
    /// Generate a temporary `StreamKey` that exists only in program memory. Uses the specified 
    /// version instead of the default, and fails if the version is unsupported.
    pub fn new_temp_with_version<R>(csprng: &mut R, version: u8) -> Result<StreamKey,CryptoError>
        where R: CryptoRng + RngCore
    {
        let interface = Arc::new(ContainedStreamKey::with_version(csprng, version)?);
        Ok(new_stream_key(interface))
    }

    /// Version of symmetric encryption algorithm used by this key.
    pub fn version(&self) -> u8 {
        self.interface.id().version()
    }

    /// The publically shareable identifier for this key.
    pub fn id(&self) -> &StreamId {
        self.interface.id()
    }

    /// Encrypt a byte slice into a `DataLockbox`. Requires a cryptographic RNG to generate the 
    /// needed nonce.
    pub fn encrypt_data<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        content: &[u8]
    ) -> DataLockbox {
        data_lockbox_from_parts(
            LockboxRecipient::StreamId(self.id().clone()),
            self.interface.encrypt(csprng, LockboxType::Data(true), content)
        )
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

    /// Pack this secret into a `StreamLockbox`, meant for the recipient specified by `id`. Returns 
    /// None if this key cannot be exported.
    pub fn export_for_lock<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        lock: &LockId
    ) -> Option<StreamLockbox> {
        self.interface.self_export_lock(csprng, lock)
    }

    /// Pack this key into a `StreamLockbox`, meant for the recipient specified by `stream`. Returns 
    /// None if this key cannot be exported for the given recipient. Generally, the recipient 
    /// should be in the same Vault as the key being exported, or the exported key should be a 
    /// temporary key.
    pub fn export_for_stream<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        stream: &StreamKey
    ) -> Option<StreamLockbox> {
        self.interface.self_export_stream(csprng, stream)
    }

}

/// Encrypt data with a `StreamKey`, returning a raw byte vector. Implementors of the 
/// StreamInterface can use this when building various lockboxes without it showing up in the 
/// regular StreamKey interface.
pub fn stream_key_encrypt(
    key: &StreamKey,
    csprng: &mut dyn CryptoSrc,
    lock_type: LockboxType,
    content: &[u8]
) -> Vec<u8> {
    key.interface.encrypt(csprng, lock_type, content)
}

impl fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("StreamKey")
            .field("version", &self.version())
            .field("stream_id", &self.id().raw_identifier())
            .finish()
    }
}

impl fmt::Display for StreamKey {
    /// Display just the StreamId (never the underlying key).
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.id(), f)
    }
}

/// Create a new `StreamKey` to hold a `StreamInterface` implementation. Can be used by 
/// implementors of a vault when making new `StreamKey` instances.
pub fn new_stream_key(interface: Arc<dyn StreamInterface>) -> StreamKey {
    StreamKey {
        interface,
    }
}

/// A symmetric encryption/decryption interface, implemented by anything that can hold a symmetric 
/// encryption key.
///
/// An implementor must handle all supported symmetric-key encryption algorithms.
pub trait StreamInterface: Sync + Send {

    /// Get the corresponding `StreamId` for the symmetric key.
    fn id(&self) -> &StreamId;

    /// Encrypt raw data into a lockbox, following the `StreamKey`-recipient lockbox format (see 
    /// [`lockbox`](crate::lockbox).
    fn encrypt(
        &self,
        csprng: &mut dyn CryptoSrc,
        lock_type: LockboxType,
        content: &[u8]
    ) -> Vec<u8>;

    /// Decrypt a `LockLockbox` and return a temporary (not stored in Vault) LockKey on success.
    fn decrypt_lock_key(
        &self,
        lockbox: &LockLockbox,
    ) -> Result<LockKey, CryptoError>;

    /// Decrypt a `IdentityLockbox` and return a temporary (not stored in Vault) `IdentityKey` on 
    /// success.
    fn decrypt_identity_key(
        &self,
        lockbox: &IdentityLockbox,
    ) -> Result<IdentityKey, CryptoError>;

    /// Decrypt a `StreamLockbox` and return a temporary (not stored in Vault) `StreamKey` on 
    /// success.
    fn decrypt_stream_key(
        &self,
        lockbox: &StreamLockbox,
    ) -> Result<StreamKey, CryptoError>;

    /// Decrypt a `DataLockbox` and return a the decoded raw data on success.
    fn decrypt_data(
        &self,
        lockbox: &DataLockbox
    ) -> Result<Vec<u8>, CryptoError>;

    /// Export the symmetric key in a `StreamLockbox`, with `receive_lock` as the recipient. If the 
    /// key cannot be exported, this should return None.
    fn self_export_lock(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_lock: &LockId
    ) -> Option<StreamLockbox>;

    /// Export the symmetric key in a `StreamLockbox`, with `receive_stream` as the recipient. If 
    /// the key cannot be exported, this should return None. Additionally, if the underlying 
    /// implementation does not allow moving the raw key into memory (i.e. it cannot call
    /// [`StreamInterface::encrypt`] or 
    /// [`lock_id_encrypt`](crate::lock::lock_id_encrypt)) then None can also be 
    /// returned.
    fn self_export_stream(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_stream: &StreamKey,
    ) -> Option<StreamLockbox>;
}

/// Compute the corresponding StreamId for a given raw key.
pub fn stream_id_from_key(version: u8, key: &[u8]) -> StreamId {
    assert_eq!(version, 1u8, "StreamKey must have version of 1");
    let mut hasher = VarBlake2b::with_params(&[], &[], b"fog-crypto", V1_STREAM_ID_SIZE);
    hasher.update(key);
    let mut id = StreamId { inner: Vec::with_capacity(1+V1_STREAM_ID_SIZE) };
    id.inner.push(1u8);
    hasher.finalize_variable(|hash| { id.inner.extend_from_slice(hash) });
    id
}

/// A self-contained implementor of `StreamInterface`. It's expected this will be used unless the 
/// symmetric key is being managed by the OS or a hardware module.
pub struct ContainedStreamKey {
    key: [u8; V1_STREAM_KEY_SIZE],
    id: StreamId,
}

impl ContainedStreamKey {

    /// Generate a new key, given a cryptographic RNG.
    pub fn generate<R>(csprng: &mut R) -> Self
        where R: CryptoRng + RngCore
    {
       Self::with_version(csprng, DEFAULT_STREAM_VERSION).unwrap()
    }

    /// Generate a new key with a specific version, given a cryptographic RNG. Fails if the version 
    /// isn't supported.
    pub fn with_version<R>(csprng: &mut R, version: u8) -> Result<Self, CryptoError>
        where R: CryptoRng + RngCore
    {
        if (version < MIN_STREAM_VERSION) || (version > MAX_STREAM_VERSION) {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let mut key = [0; V1_STREAM_KEY_SIZE];
        csprng.fill_bytes(&mut key);

        let new = Self {
            key,
            id: stream_id_from_key(version, &key)
        };
        // Wipe out the key after it's copied into the struct
        key.zeroize();
        // I'm real paranoid about things getting copied/not copied, so double check things here.
        debug_assert!(key.iter().all(|&x| x == 0));
        debug_assert!(new.key.iter().any(|&x| x != 0));

        Ok(new)
    }

    /// Encode directly to a byte vector. The resulting vector should be zeroized or overwritten 
    /// before being dropped.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        buf.reserve(1+V1_STREAM_KEY_SIZE);
        buf.push(1u8);
        buf.extend_from_slice(&self.key);
    }

    /// Decrypt a lockbox's individual parts. This is only used by the `StreamInterface` 
    /// implementation.
    fn decrypt_parts(&self, recipient: &LockboxRecipient, parts: LockboxParts) -> Result<Vec<u8>, CryptoError> {
        // Verify this is the right key for this lockbox. It costs us little to do this, and saves 
        // us from potential logic errors
        if let LockboxRecipient::StreamId(id) = recipient {
            if id != &self.id {
                return Err(CryptoError::ObjectMismatch(
                    "StreamKey being used on a lockbox meant for a different StreamId"
                ));
            }
        }
        else {
            return Err(CryptoError::ObjectMismatch(
                "Attempted to use a StreamKey to decrypt a lockbox with a LockId recipient"
            ));
        }
        // Feed the lockbox's parts into the decryption algorithm
        use chacha20poly1305::*;
        use chacha20poly1305::aead::{NewAead, Aead};
        let aead = XChaCha20Poly1305::new(
            Key::from_slice(&self.key));
        let nonce = XNonce::from_slice(parts.nonce);
        let payload = aead::Payload {
            msg: parts.ciphertext,
            aad: parts.additional,
        };
        aead.decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptFailed)
    }
}

impl TryFrom<&[u8]> for ContainedStreamKey {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (version, key) = value.split_first()
            .ok_or(CryptoError::BadLength{step: "get StreamKey version", expected: 1, actual: 0})?;
        let version = *version;
        if version < MIN_STREAM_VERSION {
            return Err(CryptoError::OldVersion(version));
        }
        if version > MAX_STREAM_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        if key.len() != V1_STREAM_KEY_SIZE {
            return Err(CryptoError::BadLength {
                step: "get StreamKey key bytes",
                expected: V1_STREAM_KEY_SIZE,
                actual: key.len()
            });
        }

        let mut new = Self {
            key: [0; V1_STREAM_KEY_SIZE],
            id: stream_id_from_key(version, key)
        };

        new.key.copy_from_slice(&key[..32]);
        Ok(new)
    }
}

impl Drop for ContainedStreamKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl StreamInterface for ContainedStreamKey {

    fn id(&self) -> &StreamId {
        &self.id
    }

    fn encrypt(
        &self,
        csprng: &mut dyn CryptoSrc,
        lock_type: LockboxType,
        content: &[u8],
    ) -> Vec<u8> {

        assert!(lock_type.is_for_stream(), "Tried to encrypt a non-stream-recipient lockbox with a StreamId");
        use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
        use chacha20poly1305::aead::{NewAead, AeadInPlace};

        // Get the data lengths and allocate the vec
        let id = self.id();
        let version = id.version();
        let tag_len = lockbox_tag_size(version);
        let nonce_len = lockbox_nonce_size(version);
        let header_len = 2 + id.len();
        let len = header_len + nonce_len + content.len() + tag_len;
        let mut lockbox: Vec<u8> = Vec::with_capacity(len);
        let mut nonce = [0u8; crate::lockbox::V1_LOCKBOX_NONCE_SIZE];
        csprng.fill_bytes(nonce.as_mut());

        // Lockbox header & data
        lockbox.push(version);
        lockbox.push(lock_type.as_u8());
        id.encode_vec(&mut lockbox);
        lockbox.extend_from_slice(nonce.as_ref());
        lockbox.extend_from_slice(content);

        // Setup & execute encryption
        let (additional, nonce_and_content) = lockbox.split_at_mut(header_len);
        let (_, content) = nonce_and_content.split_at_mut(nonce_len);
        let aead = XChaCha20Poly1305::new(
            Key::from_slice(&self.key));
        let nonce = XNonce::from(nonce);

        // Ok, this unwrap... the only failure condition on encryption is if the content is really 
        // big. For XChaCha20Poly1305, that's 256 GiB. This library is not going to be able to 
        // handle that for many other reasons, so it is a-ok if we panic instead.
        let tag = aead.encrypt_in_place_detached(&nonce, additional, content)
            .expect("More data than the cipher can accept was put in");
        lockbox.extend_from_slice(&tag);
        lockbox
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
    ) -> Option<StreamLockbox> {
        let mut raw_secret = Vec::new(); // Make 100% certain this is zeroized at the end!
        self.encode_vec(&mut raw_secret);
        let lockbox_vec = lock_id_encrypt(receive_lock, csprng, LockboxType::Stream(false), &raw_secret);
        raw_secret.zeroize();
        debug_assert!(raw_secret.iter().all(|&x| x == 0)); // You didn't remove the zeroize call, right?
        Some(stream_lockbox_from_parts(
            LockboxRecipient::LockId(receive_lock.clone()),
            lockbox_vec,
        ))
    }

    fn self_export_stream(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_stream: &StreamKey
    ) -> Option<StreamLockbox> {
        let mut raw_secret = Vec::new(); // Make 100% certain this is zeroized at the end!
        self.encode_vec(&mut raw_secret);
        let lockbox_vec = stream_key_encrypt(receive_stream, csprng, LockboxType::Stream(true), &raw_secret);
        raw_secret.zeroize();
        debug_assert!(raw_secret.iter().all(|&x| x == 0)); // You didn't remove the zeroize call, right?
        Some(stream_lockbox_from_parts(
            LockboxRecipient::StreamId(receive_stream.id().clone()),
            lockbox_vec,
        ))
    }
}

/// An identifier for a corresponding [`StreamKey`]. It is primarily used to indicate lockboxes are 
/// meant for that particular key.
///
/// This is derived through a hash of the key, given a set of specific hash parameters (see 
/// [`crate::stream`]).
///
/// # Examples
///
/// A `StreamId` can be made publically visible:
///
/// ```
/// # use fog_crypto::stream::*;
///
/// let mut csprng = rand::rngs::OsRng {};
/// let key = StreamKey::new_temp(&mut csprng);
/// let id = key.id();
///
/// println!("StreamId(Base58): {}", id);
/// ```
///
/// It can also be used to identify a recipient of a lockbox:
///
/// ```
/// # use std::convert::TryFrom;
/// # use fog_crypto::stream::*;
/// # use fog_crypto::lockbox::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let mut csprng = rand::rngs::OsRng {};
/// #
/// // We start with a known StreamKey
/// let key = StreamKey::new_temp(&mut csprng);
/// #
/// # // Encrypt some data with the key, then turn it into a byte vector
/// # let data = b"I am about to be enciphered, though you can't see me in here...";
/// # let lockbox = key.encrypt_data(&mut csprng, data.as_ref());
/// # let mut encoded = Vec::new();
/// # encoded.extend_from_slice(lockbox.as_bytes());
///
/// // ...
/// // We get the byte vector `encoded`, which might be a lockbox
/// // ...
///
/// let dec_lockbox = DataLockbox::try_from(encoded.as_ref())?;
/// let recipient = dec_lockbox.recipient();
/// if let LockboxRecipient::StreamId(ref id) = dec_lockbox.recipient() {
///     // Check to see if this matches the key's StreamId
///     if id == key.id() {
///         let dec_data: Vec<u8> = key.decrypt_data(&dec_lockbox)?;
///     }
///     else {
///         panic!("We were hoping this lockbox was for us!");
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StreamId {
    inner: Vec<u8>
}

impl StreamId {

    pub fn version(&self) -> u8 {
        self.inner[0]
    }

    pub fn raw_identifier(&self) -> &[u8] {
        &self.inner[1..]
    }

    /// Convert into a base58-encoded StreamId.
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.inner).into_string()
    }

    /// Attempt to parse a base58-encoded StreamId.
    pub fn from_base58(s: &str) -> Result<Self, CryptoError> {
        let raw = bs58::decode(s).into_vec().or(Err(CryptoError::BadFormat("Not valid Base58")))?;
        Self::try_from(&raw[..])
    }

    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len());
        buf.extend_from_slice(&self.inner);
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

}

impl TryFrom<&[u8]> for StreamId {
    type Error = CryptoError;
    /// Value must be the same length as the StreamId was when it was encoded (no trailing bytes 
    /// allowed).
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let _version = value.get(0)
            .ok_or(CryptoError::BadLength{step: "get stream version", actual: 0, expected: 1})?;
        let expected_len = 33;
        if value.len() != expected_len {
            return Err(CryptoError::BadLength{step: "get stream id", actual: value.len(), expected: expected_len});
        }
        Ok(Self {
            inner: Vec::from(value)
        })
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (version, id_bytes) = self.inner.split_first().unwrap();
        f.debug_struct("Identity")
            .field("version", version)
            .field("stream_id", &id_bytes)
            .finish()
    }
}

impl fmt::Display for StreamId {
    /// Display as a base58-encoded string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::LowerHex for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.inner.iter() {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.inner.iter() {
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockbox::LockboxRecipient;

    #[test]
    fn basics() {
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        assert_eq!(key.version(), DEFAULT_STREAM_VERSION);
        let key = StreamKey::new_temp_with_version(&mut csprng, DEFAULT_STREAM_VERSION).unwrap();
        assert_eq!(key.version(), DEFAULT_STREAM_VERSION);
        let result = StreamKey::new_temp_with_version(&mut csprng, 99u8);
        if let Err(CryptoError::UnsupportedVersion(99u8)) = result {} else {
            panic!("Didn't get expected error on new_temp_with_version");
        }
    }

    #[test]
    fn display() {
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let disp_key = format!("{}", &key);
        let disp_id = format!("{}", key.id());
        let base58 = key.id().to_base58();
        assert_eq!(disp_key, disp_id);
        assert_eq!(disp_key, base58);
        assert!(disp_key.len() > 1);
    }

    #[test]
    fn id_sanity_check() {
        // Just make sure the ID & Key aren't somehow the same
        // I cannot imagine screwing up the code enough for this to happen, but just in case...
        let mut csprng = rand::rngs::OsRng;
        let key = ContainedStreamKey::generate(&mut csprng);
        let id = key.id();
        let mut enc_key = Vec::new();
        let mut enc_id = Vec::new();
        key.encode_vec(&mut enc_key);
        id.encode_vec(&mut enc_id);
        assert_ne!(enc_id, enc_key);
    }

    #[test]
    fn base58() {
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let mut base58 = key.id().to_base58();
        assert!(base58.len() > 1);
        let id = StreamId::from_base58(&base58).unwrap();
        assert_eq!(&id, key.id());
        base58.push('a');
        base58.push('a');
        assert!(StreamId::from_base58(&base58).is_err());
        base58.pop();
        base58.pop();
        base58.pop();
        assert!(StreamId::from_base58(&base58).is_err());
    }

    #[test]
    fn encode() {
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let id = key.id();
        let mut id_vec = Vec::new();
        id.encode_vec(&mut id_vec);
        assert_eq!(id_vec.len(), id.len());
        let id = StreamId::try_from(&id_vec[..]).unwrap();
        assert_eq!(&id, key.id());
    }

    fn corrupt_version<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Version byte corruption
        let version = enc[0];
        enc[0] = 0;
        assert!(!check_decode(&enc[..]));
        enc[0] = 2;
        assert!(!check_decode(&enc[..]));
        enc[0] = version;
        assert!(check_decrypt(&enc[..]));
    }

    fn corrupt_type<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Type byte corruption
        enc[1] |= 0x80;
        assert!(!check_decode(&enc[..]));
        enc[1] &= 0x07;
        assert!(check_decrypt(&enc[..]));
        for _ in 0..6 {
            // First 6 increments should put it outside of expected lockbox type
            enc[1] = (enc[1] + 1) & 0x7;
            assert!(!check_decode(&enc[..]));
        }
        enc[1] = (enc[1] + 1) & 0x7; // 7th increment should still decode, but have bad recipient
        assert!(check_decode(&enc[..]));
        assert!(!check_decrypt(&enc[..]));
        // Last increment should take us back to the valid value
        enc[1] = (enc[1] + 1) & 0x7;
        assert!(check_decrypt(&enc[..]));
    }

    fn corrupt_id<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Identity corruption - 2 is ID version, 3 is first byte of ID
        enc[2] = 0;
        assert!(!check_decode(&enc[..]));
        enc[2] = 2;
        assert!(!check_decode(&enc[..]));
        enc[2] = DEFAULT_STREAM_VERSION;
        assert!(check_decrypt(&enc[..]));
        enc[3] ^= 0xFF;
        assert!(!check_decrypt(&enc[..]));
        enc[3] ^= 0xFF;
        assert!(check_decrypt(&enc[..]));
    }

    fn corrupt_nonce<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Nonce corruption - 35 is first byte of the nonce
        enc[35] ^= 0xFF;
        assert!(check_decode(&enc[..]));
        assert!(!check_decrypt(&enc[..]));
        enc[35] ^= 0xFF;
        assert!(check_decrypt(&enc[..]));
    }

    fn corrupt_ciphertext<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Ciphertext corruption - 59 is first byte of ciphertext
        enc[59] ^= 0xFF;
        assert!(check_decode(&enc[..]));
        assert!(!check_decrypt(&enc[..]));
        enc[59] ^= 0xFF;
        assert!(check_decrypt(&enc[..]));
    }

    fn corrupt_tag<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Tag corruption - corrupt the last byte
        let tag_end = enc.last_mut().unwrap();
        *tag_end ^= 0xFF;
        assert!(check_decode(&enc[..]));
        assert!(!check_decrypt(&enc[..]));
        let tag_end = enc.last_mut().unwrap();
        *tag_end ^= 0xFF;
        assert!(check_decrypt(&enc[..]));
    }

    fn corrupt_length_extend<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Length extension
        enc.push(0);
        assert!(check_decode(&enc[..]));
        assert!(!check_decrypt(&enc[..]));
        enc.pop();
        assert!(check_decrypt(&enc[..]));
    }

    fn corrupt_truncation<F1,F2>(
        mut enc: Vec<u8>,
        check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        // Early truncation
        enc.pop();
        assert!(check_decode(&enc[..]));
        assert!(!check_decrypt(&enc[..]));
    }

    fn corrupt_each_byte<F1,F2>(
        mut enc: Vec<u8>,
        _check_decode: F1,
        check_decrypt: F2,
    )
    where
        F1 : Fn(&[u8]) -> bool,
        F2 : Fn(&[u8]) -> bool,
    {
        for i in 0..enc.len() {
            enc[i] ^= 0xFF;
            assert!(!check_decrypt(&enc[..]));
            enc[i] ^= 0xFF;
        }
    }

    fn corrupt_inner_version<F: Fn(&[u8]) -> bool>(
        mut content: Vec<u8>,
        check_sequence: F
    )
    {
        // Corrupt the version byte
        content[0] = 0u8;
        assert!(!check_sequence(&content[..]));
        // Corrupt the version byte differently
        content[0] = 99u8;
        assert!(!check_sequence(&content[..]));
    }

    fn corrupt_inner_length_extend<F: Fn(&[u8]) -> bool>(
        mut content: Vec<u8>,
        check_sequence: F
    )
    {
        content.push(0u8);
        assert!(!check_sequence(&content[..]));
    }

    fn corrupt_inner_truncate<F: Fn(&[u8]) -> bool>(
        mut content: Vec<u8>,
        check_sequence: F
    )
    {
        content.pop();
        assert!(!check_sequence(&content[..]));
    }

    fn setup_data() -> (Vec<u8>, impl Fn(&[u8])->bool, impl Fn(&[u8])->bool)
    {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let message = b"I am a test message, going undercover";

        // Encrypt
        let lockbox = key.encrypt_data(&mut csprng, message);
        let recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());
        (
            enc,
            |enc| DataLockbox::try_from(enc).is_ok(),
            move |enc| {
                let dec_lockbox = if let Ok(d) = DataLockbox::try_from(enc) {
                    d
                }
                else {
                    return false;
                };
                if &LockboxRecipient::StreamId(key.id().clone()) != dec_lockbox.recipient() {
                    return false;
                }
                if let Ok(dec) = key.decrypt_data(&dec_lockbox) {
                    dec == message
                }
                else {
                    false
                }
            }
        )
    }

    #[test]
    fn data_clean_decrypt() {
        let (enc, _check_decode, check_decrypt) = setup_data();
        assert!(check_decrypt(&enc[..]));
    }

    #[test]
    fn data_corrupt_version() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_version(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_type() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_type(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_id() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_id(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_nonce() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_nonce(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_ciphertext() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_ciphertext(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_tag() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_tag(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_length_extend() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_length_extend(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_truncation() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_truncation(enc, check_decode, check_decrypt);
    }

    #[test]
    fn data_corrupt_each_byte() {
        let (enc, check_decode, check_decrypt) = setup_data();
        corrupt_each_byte(enc, check_decode, check_decrypt);
    }

    fn setup_id() -> (Vec<u8>, impl Fn(&[u8])->bool, impl Fn(&[u8])->bool)
    {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = IdentityKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        let recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());
        (
            enc,
            |enc| IdentityLockbox::try_from(enc).is_ok(),
            move |enc| {
                let dec_lockbox = if let Ok(d) = IdentityLockbox::try_from(enc) {
                    d
                }
                else {
                    return false;
                };
                if &LockboxRecipient::StreamId(key.id().clone()) != dec_lockbox.recipient() {
                    return false;
                }
                if let Ok(dec) = key.decrypt_identity_key(&dec_lockbox) {
                    dec.id() == to_send.id()
                }
                else {
                    false
                }
            }
        )
    }

    #[test]
    fn id_clean_decrypt() {
        let (enc, _check_decode, check_decrypt) = setup_id();
        assert!(check_decrypt(&enc[..]));
    }

    #[test]
    fn id_corrupt_version() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_version(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_type() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_type(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_id() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_id(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_nonce() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_nonce(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_ciphertext() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_ciphertext(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_tag() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_tag(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_length_extend() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_length_extend(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_truncation() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_truncation(enc, check_decode, check_decrypt);
    }

    #[test]
    fn id_corrupt_each_byte() {
        let (enc, check_decode, check_decrypt) = setup_id();
        corrupt_each_byte(enc, check_decode, check_decrypt);
    }

    fn setup_id_raw() -> (Vec<u8>, impl Fn(&[u8])->bool)
    {
        use crate::identity::SignInterface;
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = crate::ContainedIdKey::generate(&mut csprng);

        // Encrypt
        let mut content = Vec::new();
        to_send.encode_vec(&mut content);

        (
            content,
            move |content| {
                let mut csprng = rand::rngs::OsRng;
                let lockbox = identity_lockbox_from_parts(
                    LockboxRecipient::StreamId(key.id().clone()),
                    stream_key_encrypt(
                        &key,
                        &mut csprng,
                        crate::lockbox::LockboxType::Identity(true),
                        &content[..]
                    )
                );
                let enc = Vec::from(lockbox.as_bytes());
                let lockbox = if let Ok(l) = IdentityLockbox::try_from(&enc[..]) {
                    l
                }
                else {
                    return false;
                };
                if let Ok(dec) = key.decrypt_identity_key(&lockbox) {
                    dec.id() == to_send.id()
                }
                else {
                    false
                }
            }
        )
    }

    #[test]
    fn id_inner_ok() {
        let (content, check_sequence) = setup_id_raw();
        assert!(check_sequence(&content[..]));
    }

    #[test]
    fn id_corrupt_inner_version() {
        let (content, check_sequence) = setup_id_raw();
        corrupt_inner_version(content, check_sequence);
    }

    #[test]
    fn id_corrupt_inner_length_extend() {
        let (content, check_sequence) = setup_id_raw();
        corrupt_inner_length_extend(content, check_sequence);
    }

    #[test]
    fn id_corrupt_inner_truncate() {
        let (content, check_sequence) = setup_id_raw();
        corrupt_inner_truncate(content, check_sequence);
    }


    fn setup_stream() -> (Vec<u8>, impl Fn(&[u8])->bool, impl Fn(&[u8])->bool)
    {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = StreamKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        let recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());
        (
            enc,
            |enc| StreamLockbox::try_from(enc).is_ok(),
            move |enc| {
                let dec_lockbox = if let Ok(d) = StreamLockbox::try_from(enc) {
                    d
                }
                else {
                    return false;
                };
                if &LockboxRecipient::StreamId(key.id().clone()) != dec_lockbox.recipient() {
                    return false;
                }
                if let Ok(dec) = key.decrypt_stream_key(&dec_lockbox) {
                    dec.id() == to_send.id()
                }
                else {
                    false
                }
            }
        )
    }

    #[test]
    fn lock_stream_clean_decrypt() {
        let (enc, _check_decode, check_decrypt) = setup_stream();
        assert!(check_decrypt(&enc[..]));
    }

    #[test]
    fn lock_stream_corrupt_version() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_version(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_type() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_type(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_id() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_id(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_nonce() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_nonce(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_ciphertext() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_ciphertext(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_tag() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_tag(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_length_extend() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_length_extend(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_truncation() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_truncation(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_stream_corrupt_each_byte() {
        let (enc, check_decode, check_decrypt) = setup_stream();
        corrupt_each_byte(enc, check_decode, check_decrypt);
    }

    fn setup_stream_raw() -> (Vec<u8>, impl Fn(&[u8])->bool)
    {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = crate::ContainedStreamKey::generate(&mut csprng);

        // Encrypt
        let mut content = Vec::new();
        to_send.encode_vec(&mut content);

        (
            content,
            move |content| {
                let mut csprng = rand::rngs::OsRng;
                let lockbox = stream_lockbox_from_parts(
                    LockboxRecipient::StreamId(key.id().clone()),
                    stream_key_encrypt(
                        &key,
                        &mut csprng,
                        crate::lockbox::LockboxType::Stream(true),
                        &content[..]
                    )
                );
                let enc = Vec::from(lockbox.as_bytes());
                let lockbox = if let Ok(l) = StreamLockbox::try_from(&enc[..]) {
                    l
                }
                else {
                    return false;
                };
                if let Ok(dec) = key.decrypt_stream_key(&lockbox) {
                    dec.id() == to_send.id()
                }
                else {
                    false
                }
            }
        )
    }

    #[test]
    fn lock_stream_inner_ok() {
        let (content, check_sequence) = setup_stream_raw();
        assert!(check_sequence(&content[..]));
    }

    #[test]
    fn lock_stream_corrupt_inner_version() {
        let (content, check_sequence) = setup_stream_raw();
        corrupt_inner_version(content, check_sequence);
    }

    #[test]
    fn lock_stream_corrupt_inner_length_extend() {
        let (content, check_sequence) = setup_stream_raw();
        corrupt_inner_length_extend(content, check_sequence);
    }

    #[test]
    fn lock_stream_corrupt_inner_truncate() {
        let (content, check_sequence) = setup_stream_raw();
        corrupt_inner_truncate(content, check_sequence);
    }


    fn setup_lock() -> (Vec<u8>, impl Fn(&[u8])->bool, impl Fn(&[u8])->bool)
    {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = LockKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        let recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());
        (
            enc,
            |enc| LockLockbox::try_from(enc).is_ok(),
            move |enc| {
                let dec_lockbox = if let Ok(d) = LockLockbox::try_from(enc) {
                    d
                }
                else {
                    return false;
                };
                if &LockboxRecipient::StreamId(key.id().clone()) != dec_lockbox.recipient() {
                    return false;
                }
                if let Ok(dec) = key.decrypt_lock_key(&dec_lockbox) {
                    dec.id() == to_send.id()
                }
                else {
                    false
                }
            }
        )
    }

    #[test]
    fn lock_lock_clean_decrypt() {
        let (enc, _check_decode, check_decrypt) = setup_lock();
        assert!(check_decrypt(&enc[..]));
    }

    #[test]
    fn lock_lock_corrupt_version() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_version(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_type() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_type(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_id() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_id(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_nonce() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_nonce(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_ciphertext() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_ciphertext(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_tag() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_tag(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_length_extend() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_length_extend(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_truncation() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_truncation(enc, check_decode, check_decrypt);
    }

    #[test]
    fn lock_lock_corrupt_each_byte() {
        let (enc, check_decode, check_decrypt) = setup_lock();
        corrupt_each_byte(enc, check_decode, check_decrypt);
    }

    fn setup_lock_raw() -> (Vec<u8>, impl Fn(&[u8])->bool)
    {
        use crate::lock::LockInterface;
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = crate::ContainedLockKey::generate(&mut csprng);

        // Encrypt
        let mut content = Vec::new();
        to_send.encode_vec(&mut content);

        (
            content,
            move |content| {
                let mut csprng = rand::rngs::OsRng;
                let lockbox = lock_lockbox_from_parts(
                    LockboxRecipient::StreamId(key.id().clone()),
                    stream_key_encrypt(
                        &key,
                        &mut csprng,
                        crate::lockbox::LockboxType::Lock(true),
                        &content[..]
                    )
                );
                let enc = Vec::from(lockbox.as_bytes());
                let lockbox = if let Ok(l) = LockLockbox::try_from(&enc[..]) {
                    l
                }
                else {
                    return false;
                };
                if let Ok(dec) = key.decrypt_lock_key(&lockbox) {
                    dec.id() == to_send.id()
                }
                else {
                    false
                }
            }
        )
    }

    #[test]
    fn lock_lock_inner_ok() {
        let (content, check_sequence) = setup_lock_raw();
        assert!(check_sequence(&content[..]));
    }

    #[test]
    fn lock_lock_corrupt_inner_version() {
        let (content, check_sequence) = setup_lock_raw();
        corrupt_inner_version(content, check_sequence);
    }

    #[test]
    fn lock_lock_corrupt_inner_length_extend() {
        let (content, check_sequence) = setup_lock_raw();
        corrupt_inner_length_extend(content, check_sequence);
    }

    #[test]
    fn lock_lock_corrupt_inner_truncate() {
        let (content, check_sequence) = setup_lock_raw();
        corrupt_inner_truncate(content, check_sequence);
    }
}
