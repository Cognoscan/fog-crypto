/*!

Cryptographic signatures.

This module lets you create a signing [`IdentityKey`], which can be used to create a [`Signature`] 
for a given [`Hash`](crate::hash::Hash). Each `IdentityKey` has an associated [`Identity`], which may be freely 
shared. A `Signature` may be provided separate from the data or alongside it, and always includes 
the `Identity` of the signer.

All `IdentityKey` structs are backed by some struct that implements the `SignInterface` trait; this 
can be an in-memory private key, an interface to an OS-managed keystore, an interface to a hardware 
security module, or something else.

# Example

This uses a local Identity Key - a [`Vault`](crate::Vault) should normally be used to generate one instead.
```
# use fog_crypto::signing::*;
# use fog_crypto::hash::Hash;
# use std::convert::TryFrom;
# use std::sync::Arc;
# let mut csprng = rand::rngs::OsRng {};
# let key = Arc::new(ContainedIdKey::generate(&mut csprng));
# let key = new_identity_key(key.id(), key.clone());

println!("Identity(Base58): {}", key.id());

// Sign some data
let hash = Hash::new(b"I am data, soon to be hashed");
let signature = key.sign(&hash);

// Encode the signature
let mut encoded = Vec::new();
signature.encode_vec(&mut encoded);

// Decode the signature and verify it
let unverified = UnverifiedSignature::try_from(&encoded[..]).unwrap();
match unverified.verify(&hash) {
    Ok(verified) => {
        println!("Got valid signature, signed by {}", verified.signer());
    },
    Err(_) => {
        println!("Signature failed validation");
    }
}
```

*/
use ed25519_dalek::{Signer, Verifier};

use crate::{CryptoError, Hash, MIN_HASH_VERSION, MAX_HASH_VERSION, LockId, StreamId, Lockbox};

use std::{
    fmt,
    convert::TryFrom,
    sync::Arc,
};

pub const DEFAULT_SIGN_VERSION: u8 = 1;
pub const MIN_SIGN_VERSION: u8 = 1;
pub const MAX_SIGN_VERSION: u8 = 1;

/// Identity Key that allows signing hashes as a given Identity. This acts as a wrapper for a 
/// specific cryptographic private key, and it is only be used for a specific corresponding 
/// signature algorithm. The underlying private key may be located in a hardware module or some 
/// other private keystore; in this case, it may be impossible to export the key.
#[derive(Clone)]
pub struct IdentityKey {
    // The public identity, always available for use
    id: Identity,
    // The interface to the actual private key for signing. We wrap it in a Arc to avoid having it 
    // in more than one place in memory. Yes, that fact doesn't matter for keys located on hardware 
    // or in the OS, but it's a property that crypto libraries (namely ed25519_dalek) want to 
    // encourage.
    interface: Arc<dyn SignInterface>
}

impl IdentityKey {

    /// Get the signature algorithm version used by this key.
    pub fn version(&self) -> u8 {
        self.id.version()
    }

    /// Get the associated [`Identity`] for this key.
    pub fn id(&self) -> &Identity {
        &self.id
    }

    /// Sign a hash. Panics if an empty hash is provided. Signing should be fast and always 
    /// succeed.
    pub fn sign(&self, hash: &Hash) -> Signature {
        assert!(hash.version() != 0u8);
        self.interface.sign(&self.id, hash)
    }

    /// Pack this key into a `Lockbox`, meant for the recipient specified by `id`. Returns None if 
    /// this key cannot be exported.
    pub fn export_for_lock(&self, lock: &LockId) -> Option<Lockbox> {
        self.interface.self_export_lock(&self.id, lock)
    }

    /// Pack this key into a `Lockbox`, meant for the recipient specified by `stream`. Returns None 
    /// if this key cannot be exported.
    pub fn export_for_stream(&self, stream: &StreamId) -> Option<Lockbox> {
        self.interface.self_export_stream(&self.id, stream)
    }
}

/// An Identity, wrapping a public signing key.
///
/// The byte encoding is, in order:
/// 1. The version byte
/// 2. The raw public signing key bytes
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    inner: IdentityInner
}

#[derive(Clone, PartialEq, Eq)]
enum IdentityInner {
    V1(ed25519_dalek::PublicKey),
}

impl Identity {

    /// Get the cryptographic algorithm version used for this identity.
    pub fn version(&self) -> u8 {
        match self.inner {
            IdentityInner::V1(_) => 1,
        }
    }

    /// Get the raw public signing key contained within.
    pub fn raw_public_key(&self) -> &[u8] {
        match self.inner {
            IdentityInner::V1(ref id) => id.as_ref(),
        }
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
        let raw = bs58::decode(s).into_vec().or(Err(CryptoError::BadFormat))?;
        Self::try_from(&raw[..])
    }

    /// Convert into a base58-encoded Identity.
    pub fn to_base58(&self) -> String {
        bs58::encode(&(self.as_vec())).into_string()
    }

    /// Encode onto an existing byte vector. Writes out the version followed by the public signing 
    /// key. It does not include any length information in the encoding.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        match self.inner {
            IdentityInner::V1(id) => {
                let id = id.as_bytes();
                buf.reserve(self.len());
                buf.push(1u8);
                buf.extend_from_slice(id);
            }
        }
    }

    /// Get the length of this Identity once encoded as bytes.
    pub fn len(&self) -> usize {
        1 + match self.inner {
            IdentityInner::V1(_) => ed25519_dalek::PUBLIC_KEY_LENGTH,
        }
    }

}

impl TryFrom<&[u8]> for Identity {
    type Error = CryptoError;

    /// Value must be the same length as the Identity was when it was encoded (no trailing bytes 
    /// allowed).
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (version, data) = value.split_first()
            .ok_or(CryptoError::BadLength{step: "get identity version", expected: 1, actual: 0})?;
        let inner = match version {
            1 => {
                if data.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
                    return Err(CryptoError::BadLength{
                        step: "get identity public key",
                        expected: ed25519_dalek::PUBLIC_KEY_LENGTH,
                        actual: data.len()
                    });
                }
                IdentityInner::V1(ed25519_dalek::PublicKey::from_bytes(data).or(Err(CryptoError::BadKey))?)
            },
            _ => { return Err(CryptoError::UnsupportedVersion(*version)); }
        };
        Ok(Identity { inner })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (version, key_bytes) = match self.inner {
            IdentityInner::V1(ref id) => (1, id.as_bytes()),
        };
        write!(f, "{} {{ version: {:?}, public key: {:x?} }}",
            stringify!(Identity), version, key_bytes)
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
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.as_vec().iter() {
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}


/// Create a new `IdentityKey`, given an `Identity` and something implementing the signature 
/// interface. This should only be used by implementors of the `Vault` trait, not by any end users.
pub fn new_identity_key(id: Identity, interface: Arc<dyn SignInterface>) -> IdentityKey {
    IdentityKey {
        id,
        interface
    }
}

/// A Signature interface, implemented by anything that can hold a private cryptographic key. Must 
/// implement all supported cryptographic signing algorithms. Each function is given a reference to 
/// the `Identity` that will be used for signing, which may be optionally used for lookup if 
/// needed.
pub trait SignInterface {

    /// Sign a hash.
    fn sign(&self, id: &Identity, hash: &Hash) -> Signature;

    /// Export 
    fn self_export_lock(&self, target: &Identity, receive_lock: &LockId) -> Option<Lockbox>;

    fn self_export_stream(&self, target: &Identity, receive_stream: &StreamId) -> Option<Lockbox>;

}

/// A self-contained implementor of `SignInterface`. It's expected this will be used unless the key 
/// is being managed by the OS or a hardware module.
pub struct ContainedIdKey {
    inner: ContainedIdKeyInner,
}

enum ContainedIdKeyInner {
    V1(ed25519_dalek::Keypair),
}

impl ContainedIdKey {
    pub fn generate<R>(csprng: &mut R) -> ContainedIdKey
        where R: rand_core::CryptoRng + rand_core::RngCore
    {
       Self::with_version(csprng, DEFAULT_SIGN_VERSION).unwrap()
    }

    pub fn with_version<R>(csprng: &mut R, version: u8) -> Result<ContainedIdKey, CryptoError>
        where R: rand_core::CryptoRng + rand_core::RngCore
    {
        if (version < MIN_SIGN_VERSION) || (version > MAX_SIGN_VERSION) {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        Ok(Self {
            inner: ContainedIdKeyInner::V1(ed25519_dalek::Keypair::generate(csprng))
        })
    }

    pub fn id(&self) -> Identity {
        let inner = match self.inner {
            ContainedIdKeyInner::V1(ref key) => {
                IdentityInner::V1(key.public.clone())
            }
        };
        Identity { inner }
    }
}

impl SignInterface for ContainedIdKey {

    fn sign(&self, id: &Identity, hash: &Hash) -> Signature {
        let inner = match self.inner {
            ContainedIdKeyInner::V1(ref key) => {
                SignatureInner::V1(key.sign(hash.digest()))
            }
        };

        Signature {
            hash_version: hash.version(),
            id: id.clone(),
            inner,
        }
    }

    fn self_export_lock(&self, target: &Identity, receive_lock: &LockId) -> Option<Lockbox> {
        todo!()
    }

    fn self_export_stream(&self, target: &Identity, receive_stream: &StreamId) -> Option<Lockbox> {
        todo!()
    }
}

/// An annotated cryptographic signature. Includes the version of hash that was signed, the 
/// `Identity` of the signer, and the signature itself. These are always encoded together to make 
/// it easier to verify signatures appended to a chunk of data.
///
/// A signature can be constructed in one of two ways: calling `sign(...)` on an `IdentityKey`, 
/// or by verifying an `UnverifiedSignature`.
///
/// The byte encoding is specifically:
/// 1. Hash version byte
/// 2. The signing `Identity`, encoded
/// 3. The cryptographic signature bytes
pub struct Signature {
    hash_version: u8,
    id: Identity,
    inner: SignatureInner
}

enum SignatureInner {
    V1(ed25519_dalek::Signature),
}

impl Signature {

    /// The version of the `Hash` used in signature computation.
    pub fn hash_version(&self) -> u8 {
        self.hash_version
    }

    pub fn signer(&self) -> &Identity {
        &self.id
    }

    /// Encode the signature onto a `Vec<u8>`. Adds the hash version, signing identity, and 
    /// signature bytes.
    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        match self.inner {
            SignatureInner::V1(signature) => {
                let signature = signature.as_ref();
                buf.push(self.hash_version);
                self.id.encode_vec(buf);
                buf.extend_from_slice(signature);
            }
        }
    }

    /// The length of the signature, in bytes, when encoded.
    pub fn len(&self) -> usize {
        let raw_sig_len = match self.inner {
            SignatureInner::V1(_) => ed25519_dalek::SIGNATURE_LENGTH,
        };
        1 + raw_sig_len + self.id.len()
    }

}

/// A signature that has been read from a byte slice but hasn't been verified yet. Verification can 
/// be done by getting the appropriate version of hash into the `verify(...)` function.
///
/// # Example
/// ```
/// # use fog_crypto::signing::*;
/// # use fog_crypto::hash::Hash;
/// # use std::convert::TryFrom;
/// # use std::sync::Arc;
/// # let mut csprng = rand::rngs::OsRng {};
/// # let key = Arc::new(ContainedIdKey::generate(&mut csprng));
/// # let key = new_identity_key(key.id(), key.clone());
/// # let mut encoded = Vec::new();
/// let data = b"I am some test data";
/// // ...
/// # let hash = Hash::new(&data[..]);
/// # let signature = key.sign(&hash);
/// # signature.encode_vec(&mut encoded);
/// 
/// let unverified = UnverifiedSignature::try_from(&encoded[..]).unwrap();
/// let hash_version = unverified.hash_version();
/// let hash = Hash::with_version(&data[..], hash_version).unwrap();
/// match unverified.verify(&hash) {
///     Ok(verified) => {
///         println!("Got valid signature, signed by {}", verified.signer());
///     },
///     Err(_) => {
///         println!("Signature failed validation");
///     }
/// }
/// ```
pub struct UnverifiedSignature {
    hash_version: u8,
    inner: UnverifiedInner,
}

enum UnverifiedInner {
    V1 {
        signature: ed25519_dalek::Signature,
        id: ed25519_dalek::PublicKey,
    }
}

impl UnverifiedSignature {

    /// Get the version of hash needed to complete the signature.
    pub fn hash_version(&self) -> u8 {
        self.hash_version
    }

    /// Verify the Signature, producing a verified Signature or failing.
    pub fn verify(self, hash: &Hash) -> Result<Signature, CryptoError> {
        if hash.version() != self.hash_version {
            return Err(CryptoError::ObjectMismatch("Verification step got wrong version of hash"));
        }
        let (id, inner) = match self.inner {
            UnverifiedInner::V1 { id, signature } => {
                if id.verify(hash.digest(), &signature).is_err() {
                    return Err(CryptoError::SignatureFailed);
                }
                (
                    Identity { inner: IdentityInner::V1(id) },
                    SignatureInner::V1(signature),
                )
            }
        };

        Ok(Signature {
            hash_version: self.hash_version,
            id,
            inner,
        })
        
    }
}

impl TryFrom<&[u8]> for UnverifiedSignature {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (hash_version, value)  = value.as_ref().split_first()
            .ok_or(CryptoError::BadLength {
                step: "get signature hash version",
                expected: 1,
                actual: 0
            })?;
        let hash_version = *hash_version;
        if hash_version < MIN_HASH_VERSION || hash_version > MAX_HASH_VERSION {
            return Err(CryptoError::UnsupportedVersion(hash_version));
        }
        let (id_version, data) = value.split_first()
            .ok_or(CryptoError::BadLength {
                step: "get signature id version",
                expected: 1,
                actual: 0
            })?;
        let inner = match id_version {
            1 => {
                let id_len = ed25519_dalek::PUBLIC_KEY_LENGTH;
                let raw_id = data.get(0..id_len)
                    .ok_or(CryptoError::BadLength { step: "get signature signer", expected: id_len, actual: data.len() })?;
                let raw_signature = data.get(id_len..)
                    .ok_or(CryptoError::BadLength {
                        step: "get signature data",
                        expected: ed25519_dalek::SIGNATURE_LENGTH,
                        actual: data.len() - id_len
                    })?;
                let id = ed25519_dalek::PublicKey::from_bytes(raw_id)
                    .or(Err(CryptoError::BadKey))?;
                let signature = ed25519_dalek::Signature::try_from(raw_signature)
                    .or(Err(CryptoError::SignatureFailed))?;
                UnverifiedInner::V1 {
                    id,
                    signature,
                }
            },
            _ => { return Err(CryptoError::UnsupportedVersion(*id_version)); }
        };
        Ok(UnverifiedSignature {
            hash_version,
            inner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_key() -> IdentityKey {
        let mut csprng = rand::rngs::OsRng {};
        let key = Arc::new(ContainedIdKey::generate(&mut csprng));
        let key = new_identity_key(key.id(), key.clone());
        key
    }

    #[test]
    fn id_len() {
        let key = new_key();
        let id = key.id();
        let len = id.len();

        let mut enc = Vec::new();
        id.encode_vec(&mut enc);
        assert_eq!(len, enc.len());
        assert_eq!(len, id.as_vec().len());
    }

    #[test]
    fn signature_len() {
        let key = new_key();
        let hash = Hash::new(b"I am a test string");
        let sign = key.sign(&hash);
        let len = sign.len();

        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        assert_eq!(len, enc.len());
    }

    #[test]
    fn sign() {
        let key = new_key();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let sign = key.sign(&hash);
        assert_eq!(sign.hash_version(), hash.version(), "Hash version in signature should match Hash's");
        assert_eq!(sign.signer(), key.id(), "Identity in signature should match original Id");

        // Encode/decode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        let dec_sign = UnverifiedSignature::try_from(&enc[..])
            .expect("Wasn't able to decode an unverified signature")
            .verify(&hash)
            .expect("Wasn't able to verify the signature");
        assert_eq!(dec_sign.signer(), sign.signer(), "Signature Identities don't match");
        assert_eq!(dec_sign.hash_version(), sign.hash_version(), "Signature hash versions don't match");
    }

    #[test]
    #[should_panic]
    fn panic_on_empty_hash() {
        let key = new_key();
        let hash = Hash::new_empty();
        let _ = key.sign(&hash);
    }

    #[test]
    fn wrong_hashes() {
        let key = new_key();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let bad_hash = Hash::new(b"Not the same data");
        let sign = key.sign(&hash);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        // Decode: Fail the verification step
        let unverified = UnverifiedSignature::try_from(&enc[..])
            .expect("Wasn't able to decode an unverified signature");
        if let Err(CryptoError::ObjectMismatch(_)) = unverified.verify(&Hash::new_empty()) {} else {
            panic!("Signature verification should fail with ObjectMismatch when given an empty Hash");
        }
        let unverified = UnverifiedSignature::try_from(&enc[..]).unwrap();
        if let Err(CryptoError::SignatureFailed) = unverified.verify(&bad_hash) {} else {
            panic!("Signature verification should fail with SignatureFailed when given the wrong Hash");
        }
    }

    #[test]
    fn wrong_hash_versions() {
        let key = new_key();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let sign = key.sign(&hash);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);

        // Decode: Fail with an unsupported hash
        enc[0] = 0;
        if let Err(CryptoError::UnsupportedVersion(0)) = UnverifiedSignature::try_from(&enc[..]) {} else {
            panic!("Signature decoding shouldn't permit a hash with version 0");
        }
        enc[0] = 255;
        if let Err(CryptoError::UnsupportedVersion(255)) = UnverifiedSignature::try_from(&enc[..]) {} else {
            panic!("Signature decoding shouldn't permit a hash with version 255");
        }
    }

    #[test]
    fn wrong_id_versions() {
        let key = new_key();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let sign = key.sign(&hash);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);

        // Decode: Fail with an unsupported identity
        enc[1] = 0;
        if let Err(CryptoError::UnsupportedVersion(0)) = UnverifiedSignature::try_from(&enc[..]) {} else {
            panic!("Signature decoding shouldn't permit an identity with version 0");
        }
        enc[1] = 255;
        if let Err(CryptoError::UnsupportedVersion(255)) = UnverifiedSignature::try_from(&enc[..]) {} else {
            panic!("Signature decoding shouldn't permit an identity with version 255");
        }
    }

    #[test]
    fn corrupted_signature() {
        let key = new_key();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let sign = key.sign(&hash);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);

        // 1st Check: corrupt signature so uppermost 3 bits are inverted
        // This has a different failure path than other corruptions, as ed25519_dalek checks the 
        // uppermost bits during initial reading, as a valid signature should have them all zeroed.
        let last = enc.last_mut().unwrap();
        *last = !*last;
        let unverified = UnverifiedSignature::try_from(&enc[..]);
        if let Err(CryptoError::SignatureFailed) = unverified {} else {
            panic!("Should fail with SignatureFailed when the last signature byte is wrong");
        }
        // 2nd Check: corrupt other signature bytes
        let last = enc.last_mut().unwrap();
        *last = !*last;
        let len = enc.len();
        let near_last = enc.get_mut(len-2).unwrap();
        *near_last = !*near_last;
        let unverified = UnverifiedSignature::try_from(&enc[..]).unwrap();
        if let Err(CryptoError::SignatureFailed) = unverified.verify(&hash) {} else {
            panic!("Should fail with SignatureFailed when the signature bytes are wrong");
        }

    }

    #[test]
    fn corrupted_id() {
        let key = new_key();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let sign = key.sign(&hash);

        // Encode
        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        // Decode: Fail with a changed identity
        enc[4] = !enc[4];
        match UnverifiedSignature::try_from(&enc[..]) {
            Err(CryptoError::BadKey) => {
            },
            Ok(unverified) => {
                if let Err(CryptoError::SignatureFailed) = unverified.verify(&hash) {} else {
                    panic!("Should fail with SignatureFailed when identity is wrong for signature");
                }
            },
            _ => {
                panic!("Should fail with BadKey when the identity is corrupted and ed25519_dalek can tell");
            }
        }
    }

    #[test]
    fn substitute_wrong_id() {
        let key = new_key();
        let other_id = new_key();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let sign = key.sign(&hash);

        let mut enc = Vec::new();
        sign.encode_vec(&mut enc);
        for (dest, src) in enc.iter_mut().skip(1).zip(other_id.id().as_vec().iter()) {
            *dest = *src;
        }
        match UnverifiedSignature::try_from(&enc[..]) {
            Err(CryptoError::BadKey) => {
                panic!("Key should be valid, just wrong for the signature");
            },
            Ok(unverified) => {
                if let Err(CryptoError::SignatureFailed) = unverified.verify(&hash) {} else {
                    panic!("Should fail with SignatureFailed when identity is wrong for signature");
                }
            },
            _ => {
                panic!("Shouldn't fail on the initial decoding to an UnverifiedSignature");
            }
        }
    }
}

