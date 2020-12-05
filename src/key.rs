use std::fmt;
use std::io::Read;
use byteorder::ReadBytesExt;

use crate::{
    sodium::*,
    error::CryptoError,
    hash::Hash,
};

/// A cryptographic private key, used to decrypt and sign as a particular 
/// Identity. Requires accessing a Vault in order to use it.
#[derive(Clone,PartialEq,Eq,Hash)]
pub struct Key {
    version: u8,
    id: PublicSignKey,
}

/// A fog-pack Identity, which may be used for signature verification and 
/// encryption of data. This is a key for Ed25519 signing and encryption with 
/// Curve25519.
#[derive(Clone,PartialEq,Eq,Hash)]
pub struct Identity {
    version: u8,
    id: PublicSignKey,
}

impl Key {
    /// Get the version of encryption used by this Key.
    pub fn get_version(&self) -> u8 {
        self.version
    }
    /// Get the Identity corresponding to this Key.
    pub fn get_identity(&self) -> Identity {
        Identity { version: self.version, id: self.id.clone() }
    }
}

impl Identity {
    /// Get the version of encryption used by this Identity.
    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn size(&self) -> usize {
        1 + self.id.0.len()
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.size());
        buf.push(self.version);
        buf.extend_from_slice(&self.id.0);
    }

    pub fn decode(buf: &mut &[u8]) -> Result<Identity, CryptoError> {
        let mut id = Identity { version: 0, id: Default::default() };
        id.version = buf.read_u8().map_err(CryptoError::Io)?;
        if id.version != 1 { return Err(CryptoError::UnsupportedVersion); }
        buf.read_exact(&mut id.id.0).map_err(CryptoError::Io)?;
        Ok(id)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ ver={}, {:x?} }}", stringify!(Key), &self.version, &self.id.0[..])
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ ver={}, {:x?} }}", stringify!(Identity), &self.version, &self.id.0[..])
    }
}

pub fn key_from_id(version: u8, id: PublicSignKey) -> Key {
    Key { version, id }
}

pub fn key_from_identity(id: &Identity) -> Key {
    Key { version: id.version, id: id.id.clone() }
}

pub fn identity_from_id(version: u8, id: PublicSignKey) -> Identity {
    Identity { version, id }
}

/// Signatures are used to authenticate a piece of data based on its hash.
///
/// One can be generated for a given [`Hash`] using a the [`sign`] function on a Vault. The 
/// versions of the underlying key and hash are stored, along with the identifying information of 
/// the key used.
///
/// It can be verified by providing the hash of the data. The signing identity can be determined 
/// from checking against the Identity returned by `signed_by`.
///
/// [`Hash`]: ./struct.Hash.html
/// [`sign`]: ./struct.Vault.html#method.sign
#[derive(Debug,PartialEq,Clone)]
pub struct Signature {
    id: Identity,
    hash_version: u8,
    sig: Sign,
}

impl Signature {
    /// Version of the `Hash` used in signature computation.
    pub fn get_hash_version(&self) -> u8 {
        self.hash_version
    }

    /// Retrieve the Identity of the signer.
    pub fn signed_by(&self) -> &Identity {
        &self.id
    }

    /// Verify the signature is authentic.
    pub fn verify(&self, hash: &Hash) -> bool {
        verify_detached(&self.id.id, hash.digest(), &self.sig)
    }

    pub fn size(&self) -> usize {
        2 + self.id.id.0.len() + self.sig.0.len()
    }

    /// Write the signature data out to a byte stream.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.size());
        buf.push(self.id.version);
        buf.push(self.hash_version);
        buf.extend_from_slice(&self.id.id.0);
        buf.extend_from_slice(&self.sig.0);
    }

    /// Read the signature data out of a byte stream.
    pub fn decode(buf: &mut &[u8]) -> Result<Signature, CryptoError> {
        let id_version = buf.read_u8().map_err(CryptoError::Io)?;
        let hash_version = buf.read_u8().map_err(CryptoError::Io)?;
        if id_version != 1 || hash_version != 1 { return Err(CryptoError::UnsupportedVersion); }
        let mut id: PublicSignKey = Default::default();
        let mut sig: Sign = Default::default();
        buf.read_exact(&mut id.0).map_err(CryptoError::Io)?;
        buf.read_exact(&mut sig.0).map_err(CryptoError::Io)?;
        Ok(Signature {
            id: Identity { version: id_version, id },
            hash_version,
            sig
        })
    }
}

/// FullKeys are the secret data needed to act as a particular FullIdentity.
/// - Consists of a Ed25519 private/public keypair, as well as the Curve25519 private key
/// - When encoded, it is just the "seed", from which the keypair and Curve25519 key can be derived
/// - The seed is actually the Ed25519 private key
#[derive(Debug,PartialEq,Clone)]
pub struct FullKey {
    version: u8,
    signing: SecretSignKey,
    decrypting: SecretCryptKey,
}

impl FullKey {

    fn blank() -> FullKey {
        FullKey {
            version: 0,
            signing: Default::default(),
            decrypting: Default::default(),
        }
    }

    fn complete(&mut self) {
        ed25519_sk_to_curve25519(&mut self.decrypting, &self.signing)
    }

    pub fn new_pair() -> Result<(FullKey, FullIdentity), CryptoError> {
        let mut key = FullKey::blank();
        let mut id = FullIdentity::blank();
        key.version = 1;
        id.version = 1;
        sign_keypair(&mut id.signing, &mut key.signing);
        key.complete();
        id.complete()?;
        Ok((key, id))
    }

    pub fn from_seed(seed: Seed) -> Result<(FullKey, FullIdentity), CryptoError> {
        let mut key = FullKey::blank();
        let mut id = FullIdentity::blank();
        key.version = 1;
        id.version = 1;
        sign_seed_keypair(&mut id.signing, &mut key.signing, &seed);
        key.complete();
        id.complete()?;
        Ok((key,id))
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_id(&self) -> PublicSignKey {
        let mut pk: PublicSignKey = Default::default();
        ed25519_sk_to_pk(&mut pk, &self.signing);
        pk
    }

    pub fn get_key_ref(&self) -> Key {
        Key {
            version: self.version,
            id: self.get_id(),
        }
    }

    pub fn get_identity(&self) -> Result<FullIdentity, CryptoError> {
        let mut id = FullIdentity::blank();
        id.version = 1;
        ed25519_sk_to_pk(&mut id.signing, &self.signing);
        id.complete()?;
        Ok(id)
    }

    pub fn calc_stream_key(&self, pk: &PublicCryptKey) -> Result<SecretKey, CryptoError> {
        calc_secret(pk, &self.decrypting)
    }

    pub fn sign(&self, hash: &Hash) -> Signature {
        Signature { 
            hash_version: hash.version(),
            id: Identity { version: self.version, id: self.get_id() },
            sig: sign_detached(&self.signing, hash.digest())
        }
    }

    pub fn len(&self) -> usize {
        1 + Seed::len()
    }

    pub fn max_len() -> usize {
        1 + Seed::len()
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len());
        buf.push(self.version);
        let mut seed = Default::default();
        ed25519_sk_to_seed(&mut seed, &self.signing);
        buf.extend_from_slice(&seed.0);
    }

    pub fn decode(buf: &mut &[u8]) -> Result<(FullKey, FullIdentity), CryptoError> {
        let mut seed: Seed = Default::default();
        let version = buf.read_u8().map_err(CryptoError::Io)?;
        match version {
            1 => {
                buf.read_exact(&mut seed.0).map_err(CryptoError::Io)?;
                FullKey::from_seed(seed)
            },
            _ => Err(CryptoError::UnsupportedVersion),
        }
    }
}

/// Public identity that can be shared with others. An identity can be used to create locks and 
/// verify signatures
///     - Consists of a Ed25519 public key and the Curve25519 public key.
///     - When encoded, it is just the Ed25519 public key
#[derive(Debug,Clone,PartialEq,Eq,Hash)]
pub struct FullIdentity {
    version: u8,                         // Crypto version
    signing: PublicSignKey,       // Version 1: Ed25519 public key
    encrypting: PublicCryptKey, // Version 1: Curve 25519 public key
}

/// Consists of a Ed25519 public key and corresponding Curve25519 public key.
/// When encoded, it is just the Ed25519 public key
impl FullIdentity {

    fn blank() -> FullIdentity {
        FullIdentity {
            version: 0,
            signing: Default::default(),
            encrypting: Default::default(),
        }
    }

    fn complete(&mut self) -> Result<(), CryptoError> {
        ed25519_pk_to_curve25519_pk(&mut self.encrypting, &self.signing)
    }

    pub fn from_identity(id: &Identity) -> Result<FullIdentity, CryptoError> {
        if id.version != 1 { return Err(CryptoError::UnsupportedVersion); }
        FullIdentity::from_public_key(id.id.clone())
    }


    pub fn from_public_key(pk: PublicSignKey) -> Result<FullIdentity,CryptoError> {
        let mut id = FullIdentity {
            version: 1,
            signing: pk,
            encrypting: Default::default(),
        };
        id.complete()?;
        Ok(id)
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_id(&self) -> PublicSignKey {
        self.signing.clone()
    }

    pub fn get_identity_ref(&self) -> Identity {
        Identity {
            version: self.version,
            id: self.get_id(),
        }
    }

    pub fn calc_stream_key(&self, sk: &SecretCryptKey) -> Result<SecretKey, CryptoError> {
        calc_secret(&self.encrypting, sk)
    }

    pub fn len(&self) -> usize {
        1 + self.signing.0.len()
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.signing.0);
    }

    pub fn decode(buf: &mut &[u8]) -> Result<FullIdentity, CryptoError> {
        let mut id = FullIdentity::blank();
        id.version = buf.read_u8().map_err(CryptoError::Io)?;
        match id.version {
            1 => {
                buf.read_exact(&mut id.signing.0).map_err(CryptoError::Io)?;
                id.complete()?;
                Ok(id)
            },
            _ => Err(CryptoError::UnsupportedVersion),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::init;


    fn key_enc_dec(k: FullKey) {
        let mut v = Vec::new();
        k.encode(&mut v);
        let id = k.get_identity().unwrap();
        let (kd,idd) = FullKey::decode(&mut &v[..]).unwrap();
        assert_eq!(k, kd);
        assert_eq!(id,idd);
    }

    fn identity_enc_dec(id: FullIdentity) {
        let mut v = Vec::new();
        id.encode(&mut v);
        let idd = FullIdentity::decode(&mut &v[..]).unwrap();
        assert_eq!(id,idd);
    }

    fn signature_enc_dec(sig: Signature) {
        let mut v = Vec::new();
        sig.encode(&mut v);
        let sigd = Signature::decode(&mut &v[..]).unwrap();
        assert_eq!(sig,sigd);
    }

    #[test]
    fn new() {
        init().unwrap();
        let (k, id) = FullKey::new_pair().unwrap();
        assert_eq!(k.get_version(),1);
        assert_eq!(k.get_id().0, id.get_id().0);
        assert_eq!(k.get_identity().unwrap(), id);
        // Keys shouldn't be 0 (the default)
        assert_ne!(k.get_id(), Default::default());
        assert_ne!(id.get_id(), Default::default());
        key_enc_dec(k);
        identity_enc_dec(id);
    }

    #[test]
    fn stream_key() {
        // We should always get the same shared secrets for all of the below calls
        init().unwrap();
        let (k1, id1) = FullKey::new_pair().unwrap();
        let (k2, id2) = FullKey::new_pair().unwrap();
        let s_k1_id2 = k1.calc_stream_key(&id2.encrypting).unwrap();
        let s_id1_k2 = id1.calc_stream_key(&k2.decrypting).unwrap();
        let s_k2_id1 = k2.calc_stream_key(&id1.encrypting).unwrap();
        let s_id2_k1 = id2.calc_stream_key(&k1.decrypting).unwrap();
        assert_eq!(s_k1_id2, s_id1_k2);
        assert_eq!(s_id1_k2, s_k2_id1);
        assert_eq!(s_k2_id1, s_id2_k1);
    }

    #[test]
    fn key_edge_cases() {
        let v = vec![0u8];
        let err = FullKey::decode(&mut &v[..]).unwrap_err();
        match err {
            CryptoError::UnsupportedVersion => (),
            _ => panic!("FullKey should never decode if version is 0"),
        };
    }

    /// Take raw data, sign it, and verify the signature. Verify it fails if provided with a 
    /// different hash.
    #[test]
    fn signing() {
        init().unwrap();
        let v: Vec<u8> = b"This is a test".to_vec();
        let h = Hash::new(&v[..]);
        let h2 = Hash::new(&v[1..]);
        let (k, id) = FullKey::new_pair().unwrap();
        let sig = k.sign(&h);
        assert_eq!(sig.get_hash_version(), 1);
        assert_eq!(*sig.signed_by(), Identity { version: k.get_version(), id: k.get_id() });
        assert_eq!(*sig.signed_by(), id.get_identity_ref());
        assert!(sig.verify(&h));
        assert!(!sig.verify(&h2));
        signature_enc_dec(sig);
    }

}
