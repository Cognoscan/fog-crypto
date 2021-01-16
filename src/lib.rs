/*!
Provides basic cryptographic functionality. Key management, encryption, and signing are all 
done via a Vault.

A Vault is created using a password, or can be read in (either from a raw byte slice or from a 
file). It can then be used to create "permanent" keys and "temporary" keys. The only difference is 
that temporary keys are not saved when the Vault is saved off.


# Cryptographic Algorithms Used

The currently used algorithms are:

- Hashing: Blake2B with a 32-byte digest
- Signing: Ed25519
- Symmetric Encryption: AEAD cipher using XChaCha20 and Poly1305.
- DH key exchange: X25519

# Cryptographic Versioning

This library has 4 core cryptographic algorithms that may be upgraded over time:

- The hash algorithm
- The signing algorithm
- The symmetric encryption algorithm (including bulk encryption, AEAD construction, and HMAC)
- The DH exchange algorithm (used for encrypting data with a public key)

Upgrades should be infrequent, and are done roughly when an existing recommended algorithm is 
regarded as weak but not yet broken. 

The ideal upgrade process is:

1. A new algorithm is selected to replace an existing one.
2. The new algorithm is implemented. The relevant MAX_VERSION constant is incremented.
3. After being deployed for 1 year, the relevant DEFAULT_VERSION constant is incremented. This 
   gives time for library users to support the new algorithm without breaking non-updated 
   deployments.
4. After 2 more years, the relevant MIN_VERSION constant is incremented. This gives time for 
   library users to increment the default version on all deployments, then upgrade all existing 
   stored data as required.

This is the best-case upgrade scenario. If an existing algorithm is considered broken, the 
DEFAULT_VERSION and MIN_VERSION will be incremented as soon as possible. "Broken" here means it is 
feasible for a well-funded attacker to compromise the algorithm. Breaking compatibility with 
deployed code is considered an acceptable choice when security is compromised.

We are almost certainly going to upgrade the signing and DH exchange algorithms in the future, 
as we will need to move to post-quantum algorithms.

*/

mod error;
pub use self::error::CryptoError;

pub mod hash;
use hash::*;

pub mod identity;
use identity::*;

pub mod lock;
use lock::*;

pub mod lockbox;
use lockbox::*;

pub mod stream;
use stream::*;

use rand_core::{CryptoRng, RngCore};

/// Holds a cryptographic random number generator (RNG). This trait is needed so that a RNG can be 
/// passed around as a trait object.
pub trait CryptoSrc: CryptoRng + RngCore {}
impl<T: CryptoRng + RngCore> CryptoSrc for T {}

/// A trait to interface with long-term storage of various cryptographic keys. Any implementor 
/// should store keys in three separate key-value stores: one for `IdentityKey` storage, one for 
/// `LockKey` storage, and one for `StreamKey` storage. Each provides a separate lookup by name, or 
/// the various keys may be retrieved by looking them up by their public identities.
pub trait Vault {

    /// Create & store a new `IdentityKey`.
    fn new_id(&self, name: String) -> IdentityKey;

    /// Create & store a new `LockKey`.
    fn new_lock(&self, name: String) -> LockKey;

    /// Create & store a new `StreamKey`.
    fn new_stream(&self, name: String) -> StreamKey;

    /// Fetch a stored `IdentityKey` by name. Returns none if no key by that name is stored.
    fn get_id(&self, name: &str) -> Option<IdentityKey>;

    /// Fetch a stored `LockKey` by name. Returns none if no key by that name is stored.
    fn get_lock(&self, name: &str) -> Option<LockKey>;

    /// Fetch a stored `StreamKey` by name. Returns none if no key by that name is stored.
    fn get_stream(&self, name: &str) -> Option<StreamKey>;

    /// Fetch a stored `IdentityKey` by its public `Identity`, also returning the name it is stored 
    /// under. Returns none if the key is not in the vault.
    fn find_id(&self, id: Identity) -> Option<(&str, IdentityKey)>;

    /// Fetch a stored `LockKey` by its public `LockId`, also returning the name it is stored 
    /// under. Returns none if the key is not in the vault.
    fn find_lock(&self, lock: LockId) -> Option<(&str, LockKey)>;

    /// Fetch a stored `StreamKey` by its public `StreamId`, also returning the name it is stored 
    /// under. Returns none if the key is not in the vault.
    fn find_stream(&self, stream: StreamId) -> Option<(&str, StreamKey)>;

    /// Change the lookup name for a `StreamKey`.
    fn rename_id(&self, old_name: &str, new_name: String) -> bool;

    /// Change the lookup name for a `StreamKey`.
    fn rename_lock(&self, old_name: &str, new_name: String) -> bool;

    /// Change the lookup name for a `StreamKey`.
    fn rename_stream(&self, old_name: &str, new_name: String) -> bool;

    /// Remove the 
    fn remove_id(&self, name: &str) -> bool;
    fn remove_lock(&self, name: &str) -> bool;
    fn remove_stream(&self, name: &str) -> bool;

    /// Attempt to decrypt a `LockLockbox` using any of the `LockKey` and `StreamKey` instances 
    /// stored. On success, the new `LockKey` is stored in the vault under the provided name.
    fn decrypt_lock_key(&self, name: String, lock: &LockLockbox) -> Result<LockKey,CryptoError>;

    /// Attempt to decrypt a `IdentityLockbox` using any of the `LockKey` and `StreamKey` instances 
    /// stored. On success, the new `IdentityKey` is stored in the vault under the provided name.
    fn decrypt_identity_key(&self, name: String, lock: &IdentityLockbox) -> Result<IdentityKey,CryptoError>;

    /// Attempt to decrypt a `StreamLockbox` using any of the `LockKey` and `StreamKey` instances 
    /// stored. On success, the new `StreamKey` is stored in the vault under the provided name.
    fn decrypt_stream_key(&self, name: String, lock: &StreamLockbox) -> Result<StreamKey,CryptoError>;

    /// Attempt to decrypt a `StreamLockbox` using any of the `LockKey` and `StreamKey` instances 
    /// stored.
    fn decrypt_data(&self, lock: &DataLockbox) -> Result<Vec<u8>,CryptoError>;
}

