//! Cryptographic signatures.
//!
//! This module lets you create a signing [`IdentityKey`], which can be used to create a
//! [`Signature`] for a given [`HashState`](struct@crate::hash::HashState). Each `IdentityKey` has
//! an associated [`Identity`], which may be freely shared. A `Signature` may be provided separate
//! from the data or alongside it, and always includes the `Identity` of the signer.
//!
//! All `IdentityKey` structs are backed by some struct that implements the [`SignInterface`] trait;
//! this can be an in-memory private key, an interface to an OS-managed keystore, an interface to a
//! hardware security module, or something else.
//!
//! # Example
//!
//! ```
//! # use fog_crypto::identity::*;
//! # use fog_crypto::hash::HashState;
//! # use std::convert::TryFrom;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! // Make a new temporary key
//! let key = IdentityKey::new();
//!
//! println!("Identity(Base58): {}", key.id());
//!
//! // Sign some data
//! let mut hasher = HashState::new();
//! hasher.update(b"I am data, soon to be hashed");
//! let signature = key.sign(&hasher);
//!
//! // Encode the signature
//! let mut encoded = Vec::new();
//! signature.encode_vec(&mut encoded);
//!
//! // Decode the signature and verify it
//! let unverified = UnverifiedSignature::try_from(&encoded[..])?;
//! match unverified.verify(&hasher) {
//!     Ok(verified) => {
//!         println!("Got valid signature, signed by {}", verified.signer());
//!     },
//!     Err(_) => {
//!         println!("Signature failed validation");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Algorithms
//!
//! The current (and only) algorithm for public-key signatures is Ed25519, using Blake2b as the hash
//! algorithm, with [strict verification][StrictVerification]. The private key is handled by an
//! [`IdentityKey`], while the public key is available as an [`Identity`]. A context string of
//! `fog-crypto-sign-s1-h1` is used during signing, with `s1` identifying the signature version and
//! `h1` identifying the hash version.
//!
//! [StrictVerification]: https://docs.rs/ed25519-dalek/2.0.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict
//!
//! # Format
//!
//! An [`Identity`] is encoded as a version byte followed by the contained public key, whose length
//! may be dependant on the version. For Ed25519, it is 32 bytes (plus the version byte).
//!
//! An [`IdentityKey`] is encoded as a version byte followed by the contained private key, whose
//! length may be dependant on the version. For Ed25519, it is 32 bytes (plus the version byte).
//! This encoding is only ever used for the payload of an [`IdentityLockbox`].
//!
//! A [`Signature`] is encoded as the version of hash that was signed, the `Identity` of the
//! signer, and finally the actual signature bytes. The length of the signature is dependant on the
//! version of `IdentityKey` (and thus `Identity`) that was used to make the signature. For
//! Ed25519, it is 64 bytes.
//!
//! ```text
//! +--------------+==========+===========+
//! | Hash Version | Identity | Signature |
//! +--------------+==========+===========+
//!
//! - Hash Version (1 byte)
//! - Identity: Variable, depends on Identity version
//! - Signature: Variable, depends on Identity version
//! ```

use blake2::{Blake2b512, Digest};

use crate::{
    hash::{HashState, MAX_HASH_VERSION, MIN_HASH_VERSION},
    lock::LockId,
    lockbox::*,
    stream::StreamKey,
    CryptoError, CryptoSrc, VersionType,
};

use rand_core::{CryptoRng, RngCore};

use zeroize::{Zeroize, ZeroizeOnDrop};

use std::{convert::TryFrom, fmt, sync::Arc};

/// Default signature algorithm version.
pub const DEFAULT_SIGN_VERSION: u8 = 1;

/// Minimum accepted signature algorithm version.
pub const MIN_SIGN_VERSION: u8 = 1;

/// Maximum accepted signature algorithm version.
pub const MAX_SIGN_VERSION: u8 = 1;

const V1_IDENTITY_KEY_SIZE: usize = ed25519_dalek::SECRET_KEY_LENGTH;
const V1_IDENTITY_ID_SIZE: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
const V1_IDENTITY_SIGN_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

const V1_CONTEXT: &[u8] = b"fog-crypto-sign-s1-h1";

/// Identity Key that allows signing hashes as a given Identity.
///
/// This acts as a wrapper for a specific cryptographic private key, and it is only be used for a
/// specific corresponding signature algorithm. The underlying private key may be located in a
/// hardware module or some other private keystore; in this case, it may be impossible to export
/// the key.
///
/// # Example
///
/// ```
/// # use fog_crypto::identity::*;
/// # use fog_crypto::hash::HashState;
/// # use std::convert::TryFrom;
///
/// // Make a new temporary key
/// let key = IdentityKey::new();
///
/// // Sign some data with it
/// let hasher = HashState::new().chain_update(b"I am data, about to be signed");
/// let signature = key.sign(&hasher);
///
/// ```
#[derive(Clone)]
pub struct IdentityKey {
    /// The interface to the actual private key for signing. We wrap it in a Arc to avoid having it
    /// in more than one place in memory. Yes, that fact doesn't matter for keys located on hardware
    /// or in the OS, but it's a property that some crypto libraries (namely ed25519_dalek) want to
    /// encourage.
    interface: Arc<dyn SignInterface>,
}

#[cfg(feature = "getrandom")]
impl Default for IdentityKey {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityKey {
    /// Create a new `IdentityKey`, given a wrapped object that can implement a
    /// SignInterface.
    pub fn from_interface(interface: Arc<dyn SignInterface>) -> IdentityKey {
        IdentityKey { interface }
    }

    /// Generate a temporary `IdentityKey` that exists in program memory.
    #[cfg(feature = "getrandom")]
    pub fn new() -> IdentityKey {
        let interface = Arc::new(BareIdKey::new());
        Self::from_interface(interface)
    }

    /// Generate a temporary `IdentityKey` that exists in program memory, using
    /// the provided cryptographic RNG.
    pub fn with_rng<R>(csprng: &mut R) -> IdentityKey
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let interface = Arc::new(BareIdKey::with_rng(csprng));
        Self::from_interface(interface)
    }

    /// Generate a temporary `IdentityKey` that exists in program memory. Uses the specified
    /// version instead of the default, and fails if the version is unsupported.
    pub fn with_rng_and_version<R>(csprng: &mut R, version: u8) -> Result<IdentityKey, CryptoError>
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let interface = Arc::new(BareIdKey::with_rng_and_version(csprng, version)?);
        Ok(Self::from_interface(interface))
    }

    /// Get the signature algorithm version used by this key.
    pub fn version(&self) -> u8 {
        self.id().version()
    }

    /// Get the associated [`Identity`] for this key.
    pub fn id(&self) -> &Identity {
        self.interface.id()
    }

    /// Sign a hash state. Signing should be fast and always succeed.
    pub fn sign(&self, hash: &HashState) -> Signature {
        self.interface.sign(hash)
    }

    /// The maximum expected size of a signature from this key
    pub fn max_signature_size(&self) -> usize {
        // this comes straight from the Signature code
        1 + V1_IDENTITY_SIGN_SIZE + self.id().size()
    }

    #[cfg(feature = "getrandom")]
    /// Pack this key into a `Lockbox`, meant for the recipient specified by `lock`. Returns None if
    /// this key cannot be exported.
    pub fn export_for_lock(&self, lock: &LockId) -> Option<IdentityLockbox> {
        self.interface.self_export_lock(&mut rand_core::OsRng, lock)
    }

    /// Pack this key into a `Lockbox`, meant for the recipient specified by `lock`. Returns None if
    /// this key cannot be exported.
    pub fn export_for_lock_with_rng<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        lock: &LockId,
    ) -> Option<IdentityLockbox> {
        self.interface.self_export_lock(csprng, lock)
    }

    #[cfg(feature = "getrandom")]
    /// Pack this key into a `Lockbox`, meant for the recipient specified by `stream`. Returns None
    /// if this key cannot be exported.
    pub fn export_for_stream(&self, stream: &StreamKey) -> Option<IdentityLockbox> {
        self.interface
            .self_export_stream(&mut rand_core::OsRng, stream)
    }

    /// Pack this key into a `Lockbox`, meant for the recipient specified by `stream`. Returns None
    /// if this key cannot be exported.
    pub fn export_for_stream_with_rng<R: CryptoRng + RngCore>(
        &self,
        csprng: &mut R,
        stream: &StreamKey,
    ) -> Option<IdentityLockbox> {
        self.interface.self_export_stream(csprng, stream)
    }
}

impl fmt::Display for IdentityKey {
    /// Display just the Identity (never the underlying key).
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.id(), f)
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IdentityKey")
            .field("version", &self.version())
            .field("public_key", &self.id().raw_public_key())
            .finish()
    }
}

impl<T: SignInterface + 'static> From<T> for IdentityKey {
    fn from(value: T) -> Self {
        Self::from_interface(Arc::new(value))
    }
}

/// An Identity, wrapping a public signing key.
///
/// This is useful as an identifier of who has created a given signature.
#[derive(Clone)]
pub struct Identity {
    id: ed25519_dalek::VerifyingKey,
}

impl Identity {
    /// Get the cryptographic algorithm version used for this identity.
    pub fn version(&self) -> u8 {
        1u8
    }

    /// Get the raw public signing key contained within.
    pub fn raw_public_key(&self) -> &[u8] {
        self.id.as_ref()
    }

    /// Convert into a byte vector. For extending an existing byte vector, see
    /// [`encode_vec`](Self::encode_vec).
    pub fn as_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode_vec(&mut v);
        v
    }

    /// Attempt to parse a base58-encoded Identity.
    pub fn from_base58(s: &str) -> Result<Self, CryptoError> {
        let raw = bs58::decode(s)
            .into_vec()
            .or(Err(CryptoError::BadFormat("Not valid Base58")))?;
        Self::try_from(&raw[..])
    }

    /// Convert into a base58-encoded Identity.
    pub fn to_base58(&self) -> String {
        bs58::encode(&(self.as_vec())).into_string()
    }

    /// Encode onto an existing byte vector. Writes out the version followed by the public signing
    /// key. It does not include any length information in the encoding.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        let id = self.id.as_bytes();
        buf.reserve(self.size());
        buf.push(self.version());
        buf.extend_from_slice(id);
    }

    /// Get the length of this Identity once encoded as bytes.
    pub fn size(&self) -> usize {
        1 + self.id.as_ref().len()
    }
}

impl TryFrom<&[u8]> for Identity {
    type Error = CryptoError;

    /// Value must be the same length as the Identity was when it was encoded (no trailing bytes
    /// allowed).
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (&version, data) = value.split_first().ok_or(CryptoError::BadLength {
            step: "get Identity version",
            expected: 1,
            actual: 0,
        })?;
        if version != 1u8 {
            return Err(CryptoError::UnsupportedVersion {
                ty: VersionType::Signing,
                version,
                min: MIN_SIGN_VERSION,
                max: MAX_SIGN_VERSION,
            });
        }
        let Some(data) = data.try_into().ok() else {
            return Err(CryptoError::BadLength {
                step: "get Identity public key",
                expected: V1_IDENTITY_ID_SIZE,
                actual: data.len(),
            });
        };
        let id = ed25519_dalek::VerifyingKey::from_bytes(data).or(Err(CryptoError::BadKey))?;
        if id.is_weak() {
            return Err(CryptoError::BadKey);
        }
        Ok(Identity { id })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Identity")
            .field("version", &self.version())
            .field("public_key", &self.raw_public_key())
            .finish()
    }
}

impl fmt::Display for Identity {
    /// Display as a base58-encoded string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::LowerHex for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.as_vec().iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.as_vec().iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl std::cmp::PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl std::cmp::Eq for Identity {}

impl std::hash::Hash for Identity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.as_bytes().hash(state);
    }
}

/// A Signature interface, implemented by anything that can hold a private cryptographic signing
/// key.
///
/// An implementor must handle all supported cryptographic signing algorithms.
pub trait SignInterface {
    /// Get the corresponding `Identity` for the private key.
    fn id(&self) -> &Identity;

    /// Sign the hash produced by the provided [`HashState`].
    fn sign(&self, hash: &HashState) -> Signature;

    /// Export the signing key in an `IdentityLockbox`, with `receive_lock` as the recipient. If
    /// the key cannot be exported, this should return None.
    fn self_export_lock(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_lock: &LockId,
    ) -> Option<IdentityLockbox>;

    /// Export the signing key in an `IdentityLockbox`, with `receive_stream` as the recipient. If
    /// the key cannot be exported, this should return None. Additionally, if the underlying
    /// implementation does not allow moving the raw key into memory (i.e. it cannot call
    /// [`StreamInterface::encrypt`][StreamEncrypt] or [`lock_id_encrypt`][LockEncrypt]) then None
    /// can also be returned.
    ///
    /// [StreamEncrypt]: crate::stream::StreamInterface::encrypt
    /// [LockEncrypt]: crate::lock::lock_id_encrypt
    fn self_export_stream(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_stream: &StreamKey,
    ) -> Option<IdentityLockbox>;
}

/// A self-contained implementor of `SignInterface`. It's expected this will be used unless the key
/// is being managed by the OS or a hardware module.
///
/// In general, you *do not* want to use this directly - [`IdentityKey`] is
/// strongly preferred. This exists only so raw signing keys can be passed out
/// without having a target [`LockKey`][crate::lock::LockKey] or [`StreamKey`] -
/// a specialized requirement needed to implement things like invite tokens.
#[derive(Clone)]
pub struct BareIdKey {
    id: Identity,
    secret: ed25519_dalek::SecretKey,
}

impl Drop for BareIdKey {
    /// Zeroizes the raw secret key before dropping the value
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ZeroizeOnDrop for BareIdKey {}

impl std::fmt::Debug for BareIdKey {
    /// Only displays the identity, never the actual key
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BareIdKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for BareIdKey {
    /// Display as a base58-encoded string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

#[cfg(feature = "getrandom")]
impl Default for BareIdKey {
    fn default() -> Self {
        Self::new()
    }
}

impl BareIdKey {
    /// Generate a new self-contained Identity key.
    #[cfg(feature = "getrandom")]
    pub fn new() -> Self {
        Self::with_rng(&mut rand_core::OsRng)
    }

    /// Generate a new key given a cryptographic random number generator.
    pub fn with_rng<R>(csprng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        Self::with_rng_and_version(csprng, DEFAULT_SIGN_VERSION).unwrap()
    }

    /// Generate a new key with a specific version, given a cryptographic random number generator.
    /// Fails if the version isn't supported.
    pub fn with_rng_and_version<R>(csprng: &mut R, version: u8) -> Result<Self, CryptoError>
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        if (version < MIN_SIGN_VERSION) || (version > MAX_SIGN_VERSION) {
            return Err(CryptoError::UnsupportedVersion {
                ty: VersionType::Signing,
                version,
                min: MIN_SIGN_VERSION,
                max: MAX_SIGN_VERSION,
            });
        }

        // Construct the secret key and the public key
        let mut secret = ed25519_dalek::SecretKey::default();
        csprng.fill_bytes(&mut secret);
        let expanded_secret = Self::expand(&secret);
        let id = Identity {
            id: ed25519_dalek::VerifyingKey::from(&expanded_secret),
        };

        Ok(Self { id, secret })
    }

    /// Expand the secret key using Blake2b512 instead of SHA-512
    fn expand(key: &ed25519_dalek::SecretKey) -> ed25519_dalek::hazmat::ExpandedSecretKey {
        let expanded: [u8; 64] = Blake2b512::new().chain_update(key).finalize().into();
        ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&expanded)
    }

    /// Attempt to parse a base58-encoded BareIdKey.
    pub fn from_base58(s: &str) -> Result<Self, CryptoError> {
        let raw = bs58::decode(s)
            .into_vec()
            .or(Err(CryptoError::BadFormat("Not valid Base58")))?;
        Self::try_from(&raw[..])
    }

    /// Convert into a base58-encoded BareIdKey.
    pub fn to_base58(&self) -> String {
        let mut buf = Vec::new();
        self.encode_vec(&mut buf);
        bs58::encode(&buf).into_string()
    }

    pub fn size(&self) -> usize {
        1 + ed25519_dalek::SECRET_KEY_LENGTH
    }

    /// Encode the raw key, prepended with the version byte. The output vector must be either
    /// zeroized or encrypted before being dropped.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        buf.reserve(1 + ed25519_dalek::SECRET_KEY_LENGTH);
        buf.push(1u8);
        buf.extend_from_slice(&self.secret)
    }
}

impl TryFrom<&[u8]> for BareIdKey {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (version, key) = value.split_first().ok_or(CryptoError::BadLength {
            step: "get IdentityKey version",
            expected: 1,
            actual: 0,
        })?;
        let version = *version;
        if version < MIN_SIGN_VERSION || version > MAX_SIGN_VERSION {
            return Err(CryptoError::UnsupportedVersion {
                ty: VersionType::Signing,
                version,
                min: MIN_SIGN_VERSION,
                max: MAX_SIGN_VERSION,
            });
        }

        if key.len() != V1_IDENTITY_KEY_SIZE {
            return Err(CryptoError::BadLength {
                step: "get IdentityKey key bytes",
                expected: V1_IDENTITY_KEY_SIZE,
                actual: key.len(),
            });
        }

        let secret = ed25519_dalek::SecretKey::try_from(key).map_err(|_| CryptoError::BadKey)?;
        let id = ed25519_dalek::VerifyingKey::from(&Self::expand(&secret));
        if id.is_weak() {
            return Err(CryptoError::BadKey);
        }

        Ok(Self {
            secret,
            id: Identity { id },
        })
    }
}

impl fmt::LowerHex for BareIdKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = Vec::new();
        self.encode_vec(&mut buf);
        for byte in buf.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for BareIdKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = Vec::new();
        self.encode_vec(&mut buf);
        for byte in buf.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl std::cmp::PartialEq for BareIdKey {
    fn eq(&self, other: &Self) -> bool {
        self.secret == other.secret
    }
}

impl std::cmp::Eq for BareIdKey {}

impl std::hash::Hash for BareIdKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.secret.hash(state);
    }
}

impl SignInterface for BareIdKey {
    fn sign(&self, hasher: &HashState) -> Signature {
        let expanded = Self::expand(&self.secret);
        let inner = ed25519_dalek::hazmat::raw_sign_prehashed::<Blake2b512, Blake2b512>(
            &expanded,
            hasher.get_hasher(),
            &self.id.id,
            Some(V1_CONTEXT),
        )
        .unwrap();

        Signature {
            hash_version: hasher.version(),
            id: self.id.clone(),
            inner,
        }
    }

    fn id(&self) -> &Identity {
        &self.id
    }

    fn self_export_lock(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_lock: &LockId,
    ) -> Option<IdentityLockbox> {
        let mut raw_secret = Vec::new(); // Make 100% certain this is zeroized at the end!
        self.encode_vec(&mut raw_secret);
        let lockbox_vec = crate::lock::lock_id_encrypt(
            receive_lock,
            csprng,
            LockboxType::Identity(false),
            &raw_secret,
        );
        raw_secret.zeroize();
        debug_assert!(raw_secret.iter().all(|&x| x == 0)); // You didn't remove the zeroize call, right?
        Some(identity_lockbox_from_parts(lockbox_vec))
    }

    fn self_export_stream(
        &self,
        csprng: &mut dyn CryptoSrc,
        receive_stream: &StreamKey,
    ) -> Option<IdentityLockbox> {
        let mut raw_secret = Vec::new(); // Make 100% certain this is zeroized at the end!
        self.encode_vec(&mut raw_secret);
        let lockbox_vec = crate::stream::stream_key_encrypt(
            receive_stream,
            csprng,
            LockboxType::Identity(true),
            &raw_secret,
        );
        raw_secret.zeroize();
        debug_assert!(raw_secret.iter().all(|&x| x == 0)); // You didn't remove the zeroize call, right?
        Some(identity_lockbox_from_parts(lockbox_vec))
    }
}

/// An annotated cryptographic signature.
///
/// Includes the version of hash that was signed, the [`Identity`] of the signer, and the signature
/// itself. These are always encoded together to make it easier to verify signatures appended to a
/// chunk of data.
///
/// A signature can be constructed in one of two ways: calling `sign(...)` on an [`IdentityKey`],
/// or by verifying an [`UnverifiedSignature`].
///
/// The byte encoding is specifically:
/// 1. The Hash version byte
/// 2. The encoded signing `Identity`
/// 3. The cryptographic signature's raw bytes
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    hash_version: u8,
    id: Identity,
    inner: ed25519_dalek::Signature,
}

impl Signature {
    /// The version of the [`struct@Hash`] used in signature computation.
    pub fn hash_version(&self) -> u8 {
        self.hash_version
    }

    /// The public [`Identity`] of the [`IdentityKey`] that created this signature.
    pub fn signer(&self) -> &Identity {
        &self.id
    }

    /// Encode the signature onto a `Vec<u8>`. Adds the hash version, signing identity, and
    /// signature bytes.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        let signature = self.inner.to_bytes();
        buf.push(self.hash_version);
        self.id.encode_vec(buf);
        buf.extend_from_slice(&signature);
    }

    /// The length of the signature, in bytes, when encoded.
    pub fn size(&self) -> usize {
        1 + V1_IDENTITY_SIGN_SIZE + self.id.size()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Signature")
            .field("hash_version", &self.hash_version)
            .field("signer", &self.id)
            .field("signature", &self.inner)
            .finish()
    }
}

/// A signature that has been read from a byte slice but hasn't been verified yet.
///
/// Verification can be done by initializing a hasher with the appropriate version, feeding it the
/// message that was signed, and passing the hasher into the [`verify`][UnverifiedSignature::verify]
/// function.
///
/// # Example
/// ```
/// # use fog_crypto::identity::*;
/// # use fog_crypto::hash::HashState;
/// # use std::convert::TryFrom;
/// # use std::sync::Arc;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// #
/// # let key = IdentityKey::new();
/// # let mut encoded = Vec::new();
/// let data = b"I am some test data";
/// // ...
/// # let hasher = HashState::new().chain_update(&data[..]);
/// # let signature = key.sign(&hasher);
/// # signature.encode_vec(&mut encoded);
///
/// let unverified = UnverifiedSignature::try_from(&encoded[..])?;
/// let hash_version = unverified.hash_version();
/// let mut hasher = HashState::with_version(hash_version)?;
/// hasher.update(&data[..]);
/// match unverified.verify(&hasher) {
///     Ok(verified) => {
///         println!("Got valid signature, signed by {}", verified.signer());
///     },
///     Err(_) => {
///         println!("Signature failed validation");
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct UnverifiedSignature {
    hash_version: u8,
    signature: ed25519_dalek::Signature,
    id: Identity,
}

impl UnverifiedSignature {
    /// Get the version of hash needed to complete the signature.
    pub fn hash_version(&self) -> u8 {
        self.hash_version
    }

    /// The public [`Identity`] provided with this signature. Because this is an unverified
    /// signature, there can be no assurance that this identity has actually signed the data.
    pub fn signer(&self) -> &Identity {
        &self.id
    }

    /// Verify the Signature, producing a verified Signature or failing.
    pub fn verify(self, hasher: &HashState) -> Result<Signature, CryptoError> {
        if hasher.version() != self.hash_version {
            return Err(CryptoError::ObjectMismatch(
                "Verification step got wrong version of hash",
            ));
        }

        // Check for small torsion components in the R value of the signature. The original Ed25519
        // RFC considers this check optional, but we would like to avoid any point malleability.
        let compressed_r = self.signature.r_bytes();
        let expanded_r = curve25519_dalek::edwards::CompressedEdwardsY(*compressed_r)
            .decompress()
            .ok_or(CryptoError::SignatureFailed)?;
        if expanded_r.is_small_order() {
            return Err(CryptoError::SignatureFailed);
        }

        if ed25519_dalek::hazmat::raw_verify_prehashed::<Blake2b512, Blake2b512>(
            &self.id.id,
            hasher.get_hasher(),
            Some(V1_CONTEXT),
            &self.signature,
        )
        .is_err()
        {
            return Err(CryptoError::SignatureFailed);
        }

        Ok(Signature {
            hash_version: self.hash_version,
            id: self.id,
            inner: self.signature,
        })
    }
}

impl fmt::Debug for UnverifiedSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UnverifiedSignature")
            .field("hash_version", &self.hash_version)
            .field("signer", &self.id)
            .field("signature", &self.signature)
            .finish()
    }
}

impl TryFrom<&[u8]> for UnverifiedSignature {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (hash_version, value) = value.as_ref().split_first().ok_or(CryptoError::BadLength {
            step: "get signature hash version",
            expected: 1,
            actual: 0,
        })?;
        let hash_version = *hash_version;
        if hash_version < MIN_HASH_VERSION || hash_version > MAX_HASH_VERSION {
            return Err(CryptoError::UnsupportedVersion {
                ty: VersionType::Hash,
                version: hash_version,
                min: MIN_HASH_VERSION,
                max: MAX_HASH_VERSION,
            });
        }
        let (&id_version, data) = value.split_first().ok_or(CryptoError::BadLength {
            step: "get signature id version",
            expected: 1,
            actual: 0,
        })?;
        if id_version != 1 {
            return Err(CryptoError::UnsupportedVersion {
                ty: VersionType::Signing,
                version: id_version,
                min: MIN_SIGN_VERSION,
                max: MAX_SIGN_VERSION,
            });
        }

        let id_len = V1_IDENTITY_ID_SIZE;
        let raw_id = data.get(0..id_len).ok_or(CryptoError::BadLength {
            step: "get signature signer",
            expected: id_len,
            actual: data.len(),
        })?;
        let raw_signature = data.get(id_len..).ok_or(CryptoError::BadLength {
            step: "get signature data",
            expected: V1_IDENTITY_SIGN_SIZE,
            actual: data.len() - id_len,
        })?;
        let raw_id = raw_id.try_into().unwrap();
        let id = Identity {
            id: ed25519_dalek::VerifyingKey::from_bytes(raw_id).or(Err(CryptoError::BadKey))?,
        };
        if id.id.is_weak() {
            return Err(CryptoError::BadKey);
        }
        let signature = ed25519_dalek::Signature::try_from(raw_signature)
            .or(Err(CryptoError::SignatureFailed))?;
        Ok(UnverifiedSignature {
            hash_version,
            id,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);
        assert_eq!(key.version(), DEFAULT_SIGN_VERSION);
        let key = IdentityKey::with_rng_and_version(&mut csprng, DEFAULT_SIGN_VERSION).unwrap();
        assert_eq!(key.version(), DEFAULT_SIGN_VERSION);
        let result = IdentityKey::with_rng_and_version(&mut csprng, 99u8);
        let Err(CryptoError::UnsupportedVersion {
            ty: VersionType::Signing,
            version: 99u8,
            min: MIN_SIGN_VERSION,
            max: MAX_SIGN_VERSION,
        }) = result
        else {
            panic!("Didn't get expected error on with_rng_and_version");
        };

        let key = BareIdKey::with_rng(&mut csprng);
        assert_eq!(key.id().version(), DEFAULT_SIGN_VERSION);
        let key = BareIdKey::with_rng_and_version(&mut csprng, DEFAULT_SIGN_VERSION).unwrap();
        assert_eq!(key.id().version(), DEFAULT_SIGN_VERSION);
        let result = BareIdKey::with_rng_and_version(&mut csprng, 99u8);
        let Err(CryptoError::UnsupportedVersion {
            ty: VersionType::Signing,
            version: 99u8,
            min: MIN_SIGN_VERSION,
            max: MAX_SIGN_VERSION,
        }) = result
        else {
            panic!("Didn't get expected error on with_rng_and_version");
        };
    }

    #[test]
    fn display() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);
        let disp_key = format!("{}", &key);
        let disp_id = format!("{}", key.id());
        let base58 = key.id().to_base58();
        assert_eq!(disp_key, disp_id);
        assert_eq!(disp_key, base58);
        assert!(disp_key.len() > 1);
    }

    #[test]
    fn base58_id() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);
        let mut base58 = key.id().to_base58();
        assert!(base58.len() > 1);
        let id = Identity::from_base58(&base58).unwrap();
        assert_eq!(&id, key.id());
        base58.push('a');
        base58.push('a');
        assert!(Identity::from_base58(&base58).is_err());
        base58.pop();
        base58.pop();
        base58.pop();
        assert!(Identity::from_base58(&base58).is_err());
    }

    #[test]
    fn base58_bare_id_key() {
        let key = BareIdKey::new();
        let mut base58 = key.to_base58();
        assert!(base58.len() > 1);
        let key_dec = BareIdKey::from_base58(&base58).unwrap();
        assert_eq!(key.id(), key_dec.id());
        base58.push('a');
        base58.push('a');
        assert!(BareIdKey::from_base58(&base58).is_err());
        base58.pop();
        base58.pop();
        base58.pop();
        assert!(BareIdKey::from_base58(&base58).is_err());
    }

    #[test]
    fn encode() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);
        let id = key.id();
        let id_v0 = id.as_vec();
        let mut id_v1 = Vec::new();
        id.encode_vec(&mut id_v1);
        assert_eq!(id_v0.len(), id.size());
        assert_eq!(id_v0, id_v1);
        let id = Identity::try_from(&id_v0[..]).unwrap();
        assert_eq!(&id, key.id());
    }

    #[test]
    fn encode_bare() {
        let mut csprng = rand::rngs::OsRng;
        let key = BareIdKey::with_rng(&mut csprng);
        let id = key.id();
        let id_v0 = id.as_vec();
        let mut id_v1 = Vec::new();
        id.encode_vec(&mut id_v1);
        assert_eq!(id_v0.len(), id.size());
        assert_eq!(id_v0, id_v1);
        let id = Identity::try_from(&id_v0[..]).unwrap();
        assert_eq!(&id, key.id());
    }

    #[test]
    fn id_len() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);
        let id = key.id();
        let len = id.size();

        let mut enc = Vec::new();
        id.encode_vec(&mut enc);
        assert_eq!(len, enc.len());
        assert_eq!(len, id.as_vec().len());
    }

    #[test]
    fn signature_len() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);
        let hasher = HashState::new().chain_update(b"I am a test string");
        let sign = key.sign(&hasher);
        let len = sign.size();

        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        assert_eq!(len, enc.len());
    }

    #[test]
    fn sign() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);

        // Make new hash and check it
        let test_data = b"This is a test";
        let hasher = HashState::new().chain_update(test_data);
        let sign = key.sign(&hasher);
        assert_eq!(
            sign.hash_version(),
            hasher.version(),
            "Hash version in signature should match Hash's"
        );
        assert_eq!(
            sign.signer(),
            key.id(),
            "Identity in signature should match original Id"
        );

        // Encode/decode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        let dec_sign = UnverifiedSignature::try_from(&enc[..])
            .expect("Wasn't able to decode an unverified signature")
            .verify(&hasher)
            .expect("Wasn't able to verify the signature");
        assert_eq!(
            dec_sign.signer(),
            sign.signer(),
            "Signature Identities don't match"
        );
        assert_eq!(
            dec_sign.hash_version(),
            sign.hash_version(),
            "Signature hash versions don't match"
        );
    }

    #[test]
    fn wrong_hashes() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);

        // Make new hash and check it
        let test_data = b"This is a test";
        let hasher = HashState::new().chain_update(test_data);
        let bad_hasher = HashState::new().chain_update(b"Not the same data");
        let sign = key.sign(&hasher);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        // Decode: Fail the verification step
        let unverified = UnverifiedSignature::try_from(&enc[..])
            .expect("Wasn't able to decode an unverified signature");
        if let Err(CryptoError::SignatureFailed) = unverified.verify(&bad_hasher) {
        } else {
            panic!(
                "Signature verification should fail with SignatureFailed when given the wrong Hash"
            );
        }
    }

    #[test]
    fn wrong_hash_versions() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);

        // Make new hash and check it
        let test_data = b"This is a test";
        let hasher = HashState::new().chain_update(test_data);
        let sign = key.sign(&hasher);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);

        // Decode: Fail with an unsupported hash
        enc[0] = 0;
        let Err(CryptoError::UnsupportedVersion {
            ty: VersionType::Hash,
            version: 0,
            min: MIN_HASH_VERSION,
            max: MAX_HASH_VERSION,
        }) = UnverifiedSignature::try_from(&enc[..])
        else {
            panic!("Signature decoding shouldn't permit a hash with version 0");
        };
        enc[0] = 255;
        let Err(CryptoError::UnsupportedVersion {
            ty: VersionType::Hash,
            version: 255,
            min: MIN_HASH_VERSION,
            max: MAX_HASH_VERSION,
        }) = UnverifiedSignature::try_from(&enc[..])
        else {
            panic!("Signature decoding shouldn't permit a hash with version 255");
        };
    }

    #[test]
    fn wrong_id_versions() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);

        // Make new hash and check it
        let test_data = b"This is a test";
        let hasher = HashState::new().chain_update(test_data);
        let sign = key.sign(&hasher);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);

        // Decode: Fail with an unsupported identity
        enc[1] = 0;
        let Err(CryptoError::UnsupportedVersion {
            ty: VersionType::Signing,
            version: 0,
            min: MIN_SIGN_VERSION,
            max: MAX_SIGN_VERSION,
        }) = UnverifiedSignature::try_from(&enc[..])
        else {
            panic!("Signature decoding shouldn't permit an identity with version 0");
        };
        enc[1] = 255;
        let Err(CryptoError::UnsupportedVersion {
            ty: VersionType::Signing,
            version: 255,
            min: MIN_SIGN_VERSION,
            max: MAX_SIGN_VERSION,
        }) = UnverifiedSignature::try_from(&enc[..])
        else {
            panic!("Signature decoding shouldn't permit an identity with version 255");
        };
    }

    #[test]
    fn corrupted_signature() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);

        // Make new hash and check it
        let test_data = b"This is a test";
        let hasher = HashState::new().chain_update(test_data);
        let sign = key.sign(&hasher);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);

        // 1st Check: Change the length
        let unverified = UnverifiedSignature::try_from(&enc[..enc.len() - 1]);
        if unverified.is_ok() {
            panic!("Should fail with BadLength when the signature has been truncated");
        }
        enc.push(0);
        let unverified = UnverifiedSignature::try_from(&enc[..]);
        if unverified.is_ok() {
            panic!("Should fail with BadLength when the signature has been extended");
        }
        enc.pop();

        // 2nd Check: corrupt signature so uppermost 3 bits are inverted
        // This has a different failure condition than other corruptions, as ed25519_dalek checks the
        // uppermost bits during signature verification - a valid signature should have them all zeroed.
        let last = enc.last_mut().unwrap();
        *last = !*last;
        let unverified = UnverifiedSignature::try_from(&enc[..]).unwrap();
        if let Err(CryptoError::SignatureFailed) = unverified.verify(&hasher) {
        } else {
            panic!("Should fail with SignatureFailed when the last signature byte is wrong");
        }
        // 3rd Check: corrupt other signature bytes
        let last = enc.last_mut().unwrap();
        *last = !*last;
        let len = enc.len();
        let near_last = enc.get_mut(len - 2).unwrap();
        *near_last = !*near_last;
        let unverified = UnverifiedSignature::try_from(&enc[..]).unwrap();
        if let Err(CryptoError::SignatureFailed) = unverified.verify(&hasher) {
        } else {
            panic!("Should fail with SignatureFailed when the signature bytes are wrong");
        }
    }

    #[test]
    fn corrupted_id() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);

        // Make new hash and check it
        let test_data = b"This is a test";
        let hasher = HashState::new().chain_update(test_data);
        let sign = key.sign(&hasher);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        // Decode: Fail with a changed identity
        enc[4] = !enc[4];
        match UnverifiedSignature::try_from(&enc[..]) {
            Err(CryptoError::BadKey) => {}
            Ok(unverified) => {
                if let Err(CryptoError::SignatureFailed) = unverified.verify(&hasher) {
                } else {
                    panic!("Should fail with SignatureFailed when identity is wrong for signature");
                }
            }
            _ => {
                panic!("Should fail with BadKey when the identity is corrupted and ed25519_dalek can tell");
            }
        }
    }

    #[test]
    fn substitute_wrong_id() {
        let mut csprng = rand::rngs::OsRng;
        let key = IdentityKey::with_rng(&mut csprng);
        let other_id = IdentityKey::with_rng(&mut csprng);

        // Make new hash and check it
        let test_data = b"This is a test";
        let hasher = HashState::new().chain_update(test_data);
        let sign = key.sign(&hasher);

        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        for (dest, src) in enc.iter_mut().skip(1).zip(other_id.id().as_vec().iter()) {
            *dest = *src;
        }
        match UnverifiedSignature::try_from(&enc[..]) {
            Err(CryptoError::BadKey) => {
                panic!("Key should be valid, just wrong for the signature");
            }
            Ok(unverified) => {
                if let Err(CryptoError::SignatureFailed) = unverified.verify(&hasher) {
                } else {
                    panic!("Should fail with SignatureFailed when identity is wrong for signature");
                }
            }
            _ => {
                panic!("Shouldn't fail on the initial decoding to an UnverifiedSignature");
            }
        }
    }
}
