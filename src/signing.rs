
use ed25519_dalek::{Signer, Verifier};

use crate::{CryptoError, Hash, MIN_HASH_VERSION, MAX_HASH_VERSION, LockId, StreamId, Lockbox};

use std::{
    fmt,
    convert::TryFrom,
    sync::Arc,
};

use subtle::{Choice, ConstantTimeEq};

pub const DEFAULT_SIGN_VERSION: u8 = 1;
pub const MIN_SIGN_VERSION: u8 = 1;
pub const MAX_SIGN_VERSION: u8 = 1;

#[derive(Clone)]
pub struct IdentitySecret {
    // The public identity, always available for use
    id: Identity,
    // The interface to the actual private key for signing. We wrap it in a Arc to avoid having it 
    // in more than one place in memory. Yes, that fact doesn't matter for keys located on hardware 
    // or in the OS, but it's a property that crypto libraries (namely ed25519_dalek) want to 
    // encourage.
    interface: Arc<dyn SignInterface>
}

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    inner: IdentityInner
}

#[derive(Clone, PartialEq, Eq)]
enum IdentityInner {
    V1(ed25519_dalek::PublicKey),
}

/// Create a new `IdentitySecret`, given an Identity and something implementing the signature 
/// interface. This should only be used by implementors of the `Vault` trait, not by any end users.
pub fn new_identity_secret(id: Identity, interface: Arc<dyn SignInterface>) -> IdentitySecret {
    IdentitySecret {
        id,
        interface
    }
}

pub trait SignInterface {

    fn sign(&self, id: &Identity, hash: &Hash) -> Signature;

    fn self_export_lock(&self, target: &Identity, receive_lock: &LockId) -> Option<Lockbox>;

    fn self_export_stream(&self, target: &Identity, receive_stream: &StreamId) -> Option<Lockbox>;

}

impl IdentitySecret {

    pub fn version(&self) -> u8 {
        self.id.version()
    }

    pub fn id(&self) -> &Identity {
        &self.id
    }

    /// Sign a hash. Panics if an empty hash is provided.
    pub fn sign(&self, hash: &Hash) -> Signature {
        assert!(hash.version() != 0u8);
        self.interface.sign(&self.id, hash)
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

/// A self-contained implementor of `SignInterface`. It's expected this will be used unless the key 
/// is being managed by the OS or a hardware module.
pub struct ContainedIdSecret {
    inner: ContainedIdSecretInner,
}

enum ContainedIdSecretInner {
    V1(ed25519_dalek::Keypair),
}

impl ContainedIdSecret {
    pub fn generate<R>(csprng: &mut R) -> ContainedIdSecret
        where R: rand_core::CryptoRng + rand_core::RngCore
    {
       Self::with_version(csprng, DEFAULT_SIGN_VERSION).unwrap()
    }

    pub fn with_version<R>(csprng: &mut R, version: u8) -> Result<ContainedIdSecret, CryptoError>
        where R: rand_core::CryptoRng + rand_core::RngCore
    {
        if (version < MIN_SIGN_VERSION) || (version > MAX_SIGN_VERSION) {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        Ok(Self {
            inner: ContainedIdSecretInner::V1(ed25519_dalek::Keypair::generate(csprng))
        })
    }

    pub fn id(&self) -> Identity {
        let inner = match self.inner {
            ContainedIdSecretInner::V1(ref key) => {
                IdentityInner::V1(key.public.clone())
            }
        };
        Identity { inner }
    }
}

impl SignInterface for ContainedIdSecret {

    fn sign(&self, id: &Identity, hash: &Hash) -> Signature {
        let inner = match self.inner {
            ContainedIdSecretInner::V1(ref key) => {
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

impl Identity {

    pub fn version(&self) -> u8 {
        match self.inner {
            IdentityInner::V1(_) => 1,
        }
    }

    pub fn raw_public_key(&self) -> &[u8] {
        match self.inner {
            IdentityInner::V1(ref id) => id.as_ref(),
        }
    }

    /// Convert into a `Vec<u8>`.
    pub fn as_vec(&self) -> Vec<u8> {
        match self.inner {
            IdentityInner::V1(id) => {
                let bytes = id.as_bytes();
                let mut out = Vec::with_capacity(bytes.len()+1);
                out.push(1u8);
                out.extend_from_slice(bytes);
                out
            },
        }
    }

    pub fn from_base58(s: &str) -> Result<Self, CryptoError> {
        let raw = bs58::decode(s).into_vec().or(Err(CryptoError::BadFormat))?;
        Self::try_from(&raw[..])
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&(self.as_vec())).into_string()
    }

    pub fn encode_vec(&self, buf: &mut Vec<u8>) {
        match self.inner {
            IdentityInner::V1(id) => {
                let id = id.as_bytes();
                buf.reserve(1+id.len());
                buf.push(1u8);
                buf.extend_from_slice(id);
            }
        }
    }

}

impl TryFrom<&[u8]> for Identity {
    type Error = CryptoError;

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

/// An annotated cryptographic signature. Includes the version of hash that was signed, the 
/// `Identity` of the signer, and the signature itself. These are always encoded together to make 
/// it easier to verify signatures appended to a chunk of data.
///
/// A signature can be constructed in one of two ways: calling `sign(...)` on an `IdentitySecret`, 
/// or by verifying an `UnverifiedSignature`.
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

}

/// The components of an unverified signature. Verification is done by providing the required 
/// version of hash into the `verify(...)` function.
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
                    .or(Err(CryptoError::BadLength {
                        step: "get signature data",
                        expected: ed25519_dalek::SIGNATURE_LENGTH,
                        actual: raw_signature.len()
                    }))?;
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

    fn new_secret() -> IdentitySecret {
        let mut csprng = rand::rngs::OsRng {};
        let secret = Arc::new(ContainedIdSecret::generate(&mut csprng));
        let secret_id = new_identity_secret(secret.id(), secret.clone());
        secret_id
    }

    #[test]
    fn sign() {
        let secret_id = new_secret();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let sign = secret_id.sign(&hash);
        assert_eq!(sign.hash_version(), hash.version(), "Hash version in signature should match Hash's");
        assert_eq!(sign.signer(), secret_id.id(), "Identity in signature should match original Id");

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
        let secret_id = new_secret();
        let hash = Hash::new_empty();
        let _ = secret_id.sign(&hash);
    }

    #[test]
    fn bad_sign() {
        let secret_id = new_secret();

        // Make new hash and check it
        let test_data = b"This is a test";
        let hash = Hash::new(test_data);
        let bad_hash = Hash::new(b"Not the same data");
        let sign = secret_id.sign(&hash);

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

        // Decode: Fail with an unsupported hash
        let mut bad_enc = enc.clone();
        bad_enc[0] = 0;
        if let Err(CryptoError::UnsupportedVersion(0)) = UnverifiedSignature::try_from(&bad_enc[..]) {} else {
            panic!("Signature decoding shouldn't permit a hash with version 0");
        }
        bad_enc[0] = 255;
        if let Err(CryptoError::UnsupportedVersion(255)) = UnverifiedSignature::try_from(&bad_enc[..]) {} else {
            panic!("Signature decoding shouldn't permit a hash with version 255");
        }

        // Decode: Fail with an unsupported identity
        let mut bad_enc = enc.clone();
        bad_enc[1] = 0;
        if let Err(CryptoError::UnsupportedVersion(0)) = UnverifiedSignature::try_from(&bad_enc[..]) {} else {
            panic!("Signature decoding shouldn't permit an identity with version 0");
        }
        bad_enc[1] = 255;
        if let Err(CryptoError::UnsupportedVersion(255)) = UnverifiedSignature::try_from(&bad_enc[..]) {} else {
            panic!("Signature decoding shouldn't permit an identity with version 255");
        }

        // Decode: Fail with a corrupted signature
        let mut bad_enc = enc.clone();
        println!("bad_enc = {:?}", &bad_enc[..]);
        let last = bad_enc.last_mut().unwrap();
        *last = !*last;
        println!("bad_enc = {:?}", &bad_enc[..]);
        let unverified = UnverifiedSignature::try_from(&enc[..]).unwrap();
        if let Err(CryptoError::SignatureFailed) = unverified.verify(&hash) {} else {
            let unverified = UnverifiedSignature::try_from(&enc[..]).unwrap();
            if let Err(t) = unverified.verify(&hash) {
                dbg!(t);
            }
            else {
                println!("Verification passed");
            }
            panic!("Signature verification should fail with SignatureFailed when the signature bytes are wrong");
        }

        // Decode: Fail with a changed identity
    }
}

