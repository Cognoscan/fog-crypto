use crate::{
    lockbox::{Lockbox, LockboxTag, LockboxContent},
    lock::LockId,
    CryptoError,
};

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
pub(crate) fn stream_id_size(version: u8) -> usize {
    1+V1_STREAM_ID_SIZE
}

/// Get expected size of a StreamKey for a given version. Version *must* be validated before calling 
/// this.
pub(crate) fn stream_key_size(version: u8) -> usize {
    1+V1_STREAM_KEY_SIZE
}

/// Stream Key that allows encrypting data into a `Lockbox`. This acts as a wrapper for a specific 
/// cryptographic symmetric key, which can only be used with the corresponding symmetric encryption 
/// algorithm. The underlying key may be located in a hardware module or some other private 
/// keystore; in this case, it may be impossible to export the key.
#[derive(Clone)]
pub struct StreamKey {
    id: StreamId,
    interface: Arc<dyn StreamInterface>
}

impl StreamKey {

    pub fn version(&self) -> u8 {
        self.id.version()
    }

    pub fn id(&self) -> &StreamId {
        &self.id
    }

    pub fn encrypt(&self, content: &[u8]) -> Result<Lockbox, CryptoError> {
        self.encrypt_tagged(LockboxTag::Data, content)
    }

    /// Attempt to decrypt a `Lockbox` with this key. On success, any returned keys are temporary 
    /// and not associated with any Vault.
    pub fn decrypt(&self, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError> {
        self.interface.decrypt(&self.id, lockbox)
    }

    pub fn export_for_lock(&self, lock: &LockId) -> Option<Lockbox> {
        self.interface.self_export_lock(&self.id, lock)
    }

    pub fn export_for_stream(&self, stream: &StreamKey) -> Option<Lockbox> {
        self.interface.self_export_stream(&self.id, stream)
    }

    pub(crate) fn encrypt_tagged(&self, tag: LockboxTag, plaintext: &[u8]) -> Result<Lockbox, CryptoError> {
        self.interface.encrypt_tagged(&self.id, tag, plaintext)
    }
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

pub fn new_stream_key(id: StreamId, interface: Arc<dyn StreamInterface>) -> StreamKey {
    StreamKey {
        id,
        interface,
    }
}

/// Generate a temporary `IdentityKey` that exists only in program memory.
pub fn temp_stream_key<R>(csprng: &mut R) -> StreamKey
    where R: rand_core::CryptoRng + rand_core::RngCore
{
    let interface = Arc::new(ContainedStreamKey::generate(csprng));
    let id = interface.id();
    new_stream_key(id, interface)
}

/// Generate a temporary `IdentityKey` that exists only in program memory. Uses the specified 
/// version instead of the default, and fails if the version is unsupported.
pub fn temp_stream_key_with_version<R>(csprng: &mut R, version: u8) -> Result<StreamKey,CryptoError>
    where R: rand_core::CryptoRng + rand_core::RngCore
{
    let interface = Arc::new(ContainedStreamKey::with_version(csprng, version)?);
    let id = interface.id();
    Ok(new_stream_key(id, interface))
}


pub trait StreamInterface: Sync + Send {
    fn decrypt(&self, id: &StreamId, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError>;

    fn self_export_lock(&self, target: &StreamId, receive_lock: &LockId) -> Option<Lockbox>;

    fn self_export_stream(&self, target: &StreamId, receive_stream: &StreamKey) -> Option<Lockbox>;

    fn encrypt_tagged(&self, id: &StreamId, tag: LockboxTag, plaintext: &[u8]) -> Result<Lockbox, CryptoError>;
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct ContainedStreamKey {
    inner: [u8; V1_STREAM_KEY_SIZE]
}

impl ContainedStreamKey {
    pub fn generate<R>(csprng: &mut R) -> ContainedStreamKey
        where R: rand_core::CryptoRng + rand_core::RngCore
    {
       Self::with_version(csprng, DEFAULT_STREAM_VERSION).unwrap()
    }

    pub fn with_version<R>(csprng: &mut R, version: u8) -> Result<ContainedStreamKey, CryptoError>
        where R: rand_core::CryptoRng + rand_core::RngCore
    {
        if (version < MIN_STREAM_VERSION) || (version > MAX_STREAM_VERSION) {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let mut new = Self { inner: [0; V1_STREAM_KEY_SIZE] };
        csprng.fill_bytes(&mut new.inner);
        Ok(new)
    }

    pub fn id(&self) -> StreamId {
        let mut hasher = VarBlake2b::new_keyed(b"fogcrypt", V1_STREAM_ID_SIZE);
        hasher.update(&self.inner);
        let mut id = StreamId { inner: Vec::with_capacity(1+V1_STREAM_ID_SIZE) };
        id.inner.push(1u8);
        hasher.finalize_variable(|hash| { id.inner.extend_from_slice(hash) });
        id
    }
}

impl StreamInterface for ContainedStreamKey {
    fn encrypt_tagged(&self, id: &StreamId, tag: LockboxTag, plaintext: &[u8]) -> Result<Lockbox, CryptoError> {
        todo!()
    }

    fn decrypt(&self, id: &StreamId, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError> {
        todo!()
    }

    fn self_export_lock(&self, target: &StreamId, receive_lock: &LockId) -> Option<Lockbox> {
        todo!()
    }

    fn self_export_stream(&self, target: &StreamId, receive_stream: &StreamKey) -> Option<Lockbox> {
        todo!()
    }
}

#[derive(Clone, PartialEq, Eq)]
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

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Convert into a base58-encoded StreamId.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.as_bytes()).into_string()
    }

    /// Attempt to parse a base58-encoded StreamId.
    pub fn from_base58(s: &str) -> Result<Self, CryptoError> {
        let raw = bs58::decode(s).into_vec().or(Err(CryptoError::BadFormat))?;
        Self::try_from(&raw[..])
    }

}

impl TryFrom<&[u8]> for StreamId {
    type Error = CryptoError;
    /// Value must be the same length as the StreamId was when it was encoded (no trailing bytes 
    /// allowed).
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let version = value.get(0)
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
        for byte in self.as_bytes().iter() {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.as_bytes().iter() {
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}
