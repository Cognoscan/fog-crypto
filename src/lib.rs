/*!
Provides basic cryptographic functionality. Key management, encryption, and signing are all 
done via a Vault.

A Vault is created using a password, or can be read in (either from a raw byte slice or from a 
file). It can then be used to create "permanent" keys and "temporary" keys. The only difference is 
that temporary keys are not saved when the Vault is saved off.
*/

mod error;
pub use self::error::CryptoError;

mod hash;
pub use self::hash::*;

mod signing;
pub use self::signing::*;

pub trait Vault {

    fn new_perm_id(&self, name: String) -> IdentitySecret;
    fn new_perm_lock(&self, name: String) -> LockKey;
    fn new_perm_stream(&self, name: String) -> StreamKey;

    fn new_temp_id(&self) -> IdentitySecret;
    fn new_temp_lock(&self) -> LockKey;
    fn new_temp_stream(&self) -> StreamKey;

    fn get_key(&self, name: &str) -> Option<IdentitySecret>;
    fn get_lock(&self, name: &str) -> Option<LockKey>;
    fn get_stream(&self, name: &str) -> Option<StreamKey>;

    fn find_id(&self, id: Identity) -> Option<IdentitySecret>;
    fn find_lock(&self, lock: LockId) -> Option<LockKey>;
    fn find_stream(&self, stream: StreamId) -> Option<StreamKey>;

    fn rename_id(&self, old_name: String, new_name: String) -> bool;
    fn rename_lock(&self, old_name: String, new_name: String) -> bool;
    fn rename_stream(&self, old_name: String, new_name: String) -> bool;

    fn remove_id(&self, name: &str) -> bool;
    fn remove_lock(&self, name: &str) -> bool;
    fn remove_stream(&self, name: &str) -> bool;
}

pub struct LockKey { id: LockId, interface: Box<dyn LockInterface> }
pub struct LockId {}
pub struct StreamKey { id: StreamId, interface: Box<dyn StreamInterface> }
pub struct StreamId {}
pub struct Lockbox { }

/// Lockboxes can be meant for one of two types of recipients: a LockId (public key), or a 
/// StreamId (symmetric key).
pub enum LockboxRecipient {
    LockId(LockId),
    StreamId(StreamId),
}


pub enum LockboxContent {
    IdentitySecret(IdentitySecret),
    LockKey(LockKey),
    StreamKey(StreamKey),
    Data(Vec<u8>),
}

impl LockKey {

    pub fn version(&self) -> u8 {
        self.id.version()
    }

    pub fn id(&self) -> &LockId {
        &self.id
    }

    /// Attempt to decrypt a `Lockbox` using this key, returning its content
    pub fn decrypt(&self, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError> {
        self.interface.decrypt(&self.id, lockbox)
    }

    /// Check if this lock key is in a permanent key store.
    pub fn is_perm(&self) -> bool {
        self.interface.is_perm(&self.id)
    }

    /// Move this to the permanent key store, if it isn't already. Returns true if the key was 
    /// already in the permanent key store.
    pub fn make_perm(&self) -> bool {
        self.interface.make_perm(&self.id)
    }

    /// Pack this secret into a `Lockbox`, meant for the recipient specified by `id`. Returns None if 
    /// the cannot be exported.
    pub fn export_for_lock(&self, lock: &LockId) -> Option<Lockbox> {
        self.interface.self_export_lock(&self.id, lock)
    }

    /// Pack this key into a `Lockbox`, meant for the recipient specified by `stream`. Returns None 
    /// if this key cannot be exported.
    pub fn export_for_stream(&self, stream: &StreamId) -> Option<Lockbox> {
        self.interface.self_export_stream(&self.id, stream)
    }

}

pub trait LockInterface {

    fn decrypt(&self, id: &LockId, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError>;

    fn is_perm(&self, id: &LockId) -> bool;

    fn make_perm(&self, id: &LockId) -> bool;

    fn self_export_lock(&self, target: &LockId, receive_lock: &LockId) -> Option<Lockbox>;

    fn self_export_stream(&self, target: &LockId, receive_stream: &StreamId) -> Option<Lockbox>;

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

    pub fn encrypt(&self, content: LockboxContent) -> Result<Lockbox, CryptoError> {
        todo!()
    }

    pub fn from_bytes(raw: impl AsRef<[u8]>) -> Result<Self, CryptoError> {
        todo!()
    }

}

impl StreamKey {

    pub fn version(&self) -> u8 {
        todo!()
    }

    pub fn id(&self) -> StreamId {
        todo!()
    }

    pub fn encrypt(&self, content: LockboxContent) -> Result<Lockbox, CryptoError> {
        todo!()
    }

    pub fn decrypt(&self, lockbox: &Lockbox) -> Result<LockboxContent, CryptoError> {
        todo!()
    }

    pub fn export_for_lock(&self, lock: &LockId) -> Option<Lockbox> {
        self.interface.self_export_lock(&self.id, lock)
    }

    pub fn export_for_stream(&self, stream: &StreamId) -> Option<Lockbox> {
        self.interface.self_export_stream(&self.id, stream)
    }
}

pub fn new_stream(id: StreamId, interface: Box<dyn StreamInterface>) -> StreamKey {
    StreamKey {
        id,
        interface,
    }
}

pub trait StreamInterface: Sync + Send {
    fn encrypt(&self, id: StreamId, content: LockboxContent) -> Result<Lockbox, CryptoError>;

    fn decrypt(&self, id: StreamId, lockbox: Lockbox) -> Result<LockboxContent, CryptoError>;

    fn self_export_lock(&self, target: &StreamId, receive_lock: &LockId) -> Option<Lockbox>;

    fn self_export_stream(&self, target: &StreamId, receive_stream: &StreamId) -> Option<Lockbox>;
}

impl StreamId {

    pub fn version(&self) -> u8 {
        todo!()
    }

    pub fn raw_identifier(&self) -> &[u8] {
        todo!()
    }

    pub fn as_bytes(&self) -> &[u8] {
        todo!()
    }

}

impl Lockbox {
    pub fn from_bytes(raw: impl AsRef<[u8]>) -> Result<Self, CryptoError> {
        todo!()
    }

    /// Get the target recipient who should be able to decrypt the lockbox.
    pub fn recipient(&self) -> LockboxRecipient {
        todo!()
    }

    pub fn as_bytes(&self) -> &[u8] {
        todo!()
    }

    /// Try to decrypt the lockbox using any keys known by a given vault
    pub fn try_decrypt(&self, vault: &dyn Vault) -> Result<LockboxContent, CryptoError> {
        todo!()
    }
}






























