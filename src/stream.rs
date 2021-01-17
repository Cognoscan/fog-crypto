//! Symmetric-Key encryption.
//!
//! This submodule provides a `StreamKey` for symmetric encryption & decryption of any lockbox 
//! type. Each `StreamKey` has a corresponding `StreamId` for easily identifying the key needed to 
//! decrypt a lockbox.
//!
//! # Algorithms
//!
//! The current (and only) algorithm for symmetric encryption is XChaCha20 with a Poly1305 AEAD 
//! construction. See the [`lockbox`](crate::lockbox) module for documentation on the encoding 
//! format for encrypted data.
//!
//! The `StreamId` is computed by taking the 32-byte secret key and hashing it with BLAKE2b, with 
//! the parameters: no key, no salt, and a persona set to "fog-crypto-sid".
//!
//! # Encodings
//!
//! A `StreamId` is encoded as a version byte followed by the key itself, whose length is dependant 
//! on the version.
//!
//! A `StreamId` is also encoded as a version byte followed by the key itself, whose length is 
//! dependant on the version.
//!

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

pub const DEFAULT_STREAM_VERSION: u8 = 1;
pub const MIN_STREAM_VERSION: u8 = 1;
pub const MAX_STREAM_VERSION: u8 = 1;

const V1_STREAM_ID_SIZE: usize = 32;
const V1_STREAM_KEY_SIZE: usize = 32;

/// Get expected size of StreamId for a given version. Version *must* be validated before calling 
/// this.
pub(crate) fn stream_id_size(_version: u8) -> usize {
    1+V1_STREAM_ID_SIZE
}

/// Stream Key that allows encrypting data into a `Lockbox`. This acts as a wrapper for a specific 
/// cryptographic symmetric key, which can only be used with the corresponding symmetric encryption 
/// algorithm. The underlying key may be located in a hardware module or some other private 
/// keystore; in this case, it may be impossible to export the key.
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
            self.interface.encrypt(csprng, content)
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
    content: &[u8]
) -> Vec<u8> {
    key.interface.encrypt(csprng, content)
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

pub trait StreamInterface: Sync + Send {

    fn id(&self) -> &StreamId;

    /// Encrypt raw data into a lockbox, following the `StreamKey`-recipient lockbox format (see 
    /// [`lockbox`](crate::lockbox).
    fn encrypt(
        &self,
        csprng: &mut dyn CryptoSrc,
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
    /// [`LockInterface::encrypt`](crate::lock::LockInterface::encrypt)) then None can also be 
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

    /// Generate a new key with a specific version, given a cryptographic RNG.
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
        content: &[u8],
    ) -> Vec<u8> {

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
        lockbox.push(LOCKBOX_TYPE_STREAM);
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
        let lockbox_vec = lock_id_encrypt(receive_lock, &raw_secret, csprng);
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
        let lockbox_vec = stream_key_encrypt(receive_stream, csprng, &raw_secret);
        raw_secret.zeroize();
        debug_assert!(raw_secret.iter().all(|&x| x == 0)); // You didn't remove the zeroize call, right?
        Some(stream_lockbox_from_parts(
            LockboxRecipient::StreamId(receive_stream.id().clone()),
            lockbox_vec,
        ))
    }
}

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
        let raw = bs58::decode(s).into_vec().or(Err(CryptoError::BadFormat))?;
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

    #[test]
    fn stream_lock_data() {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let message = b"I am a test message, going undercover";

        // Encrypt
        let lockbox = key.encrypt_data(&mut csprng, message);
        let expected_recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        let dec_lockbox = DataLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_message = key.decrypt_data(&dec_lockbox).unwrap();
        assert_eq!(message, &dec_message[..]);
    }

    #[test]
    fn stream_lock_id_key() {
        //Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = IdentityKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        let expected_recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        let dec_lockbox = IdentityLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_key = key.decrypt_identity_key(&dec_lockbox).unwrap();
        assert_eq!(to_send.id(), dec_key.id());
    }

    #[test]
    fn stream_lock_stream_key() {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = StreamKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        let expected_recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        let dec_lockbox = StreamLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_key = key.decrypt_stream_key(&dec_lockbox).unwrap();
        assert_eq!(to_send.id(), dec_key.id());
    }

    #[test]
    fn stream_lock_lock_key() {
        // Setup
        let mut csprng = rand::rngs::OsRng;
        let key = StreamKey::new_temp(&mut csprng);
        let to_send = LockKey::new_temp(&mut csprng);

        // Encrypt
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        let expected_recipient = LockboxRecipient::StreamId(key.id().clone());
        assert_eq!(&expected_recipient, lockbox.recipient());
        let enc = Vec::from(lockbox.as_bytes());

        // Decrypt
        let dec_lockbox = LockLockbox::try_from(&enc[..]).unwrap();
        assert_eq!(&expected_recipient, dec_lockbox.recipient());
        let dec_key = key.decrypt_lock_key(&dec_lockbox).unwrap();
        assert_eq!(to_send.id(), dec_key.id());
    }
}
