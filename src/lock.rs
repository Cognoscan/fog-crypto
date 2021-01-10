use crate::{
    CryptoError,
    lockbox::{Lockbox, LockboxContent},
    stream::StreamKey,
};

pub struct LockKey { id: LockId, interface: Box<dyn LockInterface> }

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct LockId {}

pub fn temp_lock_key<R>(csprng: &mut R) -> LockKey
    where R: rand_core::CryptoRng + rand_core::RngCore
{
    todo!()
}

pub fn temp_lock_key_with_version<R>(csprng: &mut R, version: u8) -> Result<LockKey,CryptoError>
    where R: rand_core::CryptoRng + rand_core::RngCore
{
    todo!()
}

impl LockKey {

    pub fn version(&self) -> u8 {
        self.id.version()
    }

    pub fn id(&self) -> &LockId {
        &self.id
    }

    /// Attempt to decrypt a `Lockbox` with this key. On success, any returned keys are temporary 
    /// and not associated with any Vault.
    pub fn decrypt(&self, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError> {
        self.interface.decrypt(&self.id, lockbox)
    }

    /// Pack this secret into a `Lockbox`, meant for the recipient specified by `id`. Returns None if 
    /// the cannot be exported.
    pub fn export_for_lock(&self, lock: &LockId) -> Option<Lockbox> {
        self.interface.self_export_lock(&self.id, lock)
    }

    /// Pack this key into a `Lockbox`, meant for the recipient specified by `stream`. Returns None 
    /// if this key cannot be exported.
    pub fn export_for_stream(&self, stream: &StreamKey) -> Option<Lockbox> {
        self.interface.self_export_stream(&self.id, stream)
    }

}

use std::fmt;
impl fmt::Debug for LockKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

pub trait LockInterface {

    fn decrypt(&self, id: &LockId, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError>;

    fn self_export_lock(&self, target: &LockId, receive_lock: &LockId) -> Option<Lockbox>;

    fn self_export_stream(&self, target: &LockId, receive_stream: &StreamKey) -> Option<Lockbox>;

}

impl LockId {

    pub fn version(&self) -> u8 {
        todo!()
    }

    pub fn raw_public_key(&self) -> &[u8] {
        todo!()
    }

    pub fn as_bytes(&self) -> &[u8] {
        todo!()
    }

    pub fn encrypt(&self, content: &[u8]) -> Result<Lockbox, CryptoError> {
        todo!()
    }

    pub fn from_bytes(raw: impl AsRef<[u8]>) -> Result<Self, CryptoError> {
        todo!()
    }

}
