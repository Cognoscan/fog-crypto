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

We are almost certainly going to upgrade the signing and DH exchange algorithms before 2030, as we 
will need to move to post-quantum algorithms.

*/

mod error;
pub use self::error::CryptoError;

pub mod hash;
use hash::*;

pub mod signing;
use signing::*;

pub mod lock;
use lock::*;

pub mod lockbox;
use lockbox::*;

pub mod stream;
use stream::*;

pub trait Vault {

    fn new_id(&self, name: String) -> IdentityKey;
    fn new_lock(&self, name: String) -> LockKey;
    fn new_stream(&self, name: String) -> StreamKey;

    fn get_id(&self, name: &str) -> Option<IdentityKey>;
    fn get_lock(&self, name: &str) -> Option<LockKey>;
    fn get_stream(&self, name: &str) -> Option<StreamKey>;

    fn find_id(&self, id: Identity) -> Option<IdentityKey>;
    fn find_lock(&self, lock: LockId) -> Option<LockKey>;
    fn find_stream(&self, stream: StreamId) -> Option<StreamKey>;

    fn rename_id(&self, old_name: &str, new_name: String) -> bool;
    fn rename_lock(&self, old_name: &str, new_name: String) -> bool;
    fn rename_stream(&self, old_name: &str, new_name: String) -> bool;

    fn remove_id(&self, name: &str) -> bool;
    fn remove_lock(&self, name: &str) -> bool;
    fn remove_stream(&self, name: &str) -> bool;

    /// Attempt to decrypt a lockbox using any of the locks & streams in the Vault. If the content 
    /// of the Lockbox is a `StreamKey`, `LockKey`, or `IdentityKey`, it will be stored in the 
    /// Vault under the provided name.
    fn decrypt(&self, name: String, lock: &Lockbox) -> Result<LockboxContent,CryptoError>;
}

