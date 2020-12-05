use std::io::Read;
use byteorder::ReadBytesExt;

use crate::{
    error::CryptoError,
    sodium::*,
    key::{FullKey, FullIdentity, Key, Identity, identity_from_id, key_from_id},
    stream::{FullStreamKey, StreamKey, stream_from_id},
};


#[derive(Clone,PartialEq,Debug)]
enum LockType {
    /// Identity and ephemeral key used to make secret FullStreamKey
    Identity((PublicSignKey,PublicCryptKey)),
    /// ID of the Streamkey used
    Stream(StreamId),
}

impl LockType {

    fn to_u8(&self) -> u8 {
        match *self {
            LockType::Identity(_) => 1,
            LockType::Stream(_)   => 2,
        }
    }

    pub fn size(&self) -> usize {
        1 + match *self {
            LockType::Identity(ref v) => ((v.0).0.len() + (v.1).0.len()),
            LockType::Stream(ref v)    => v.0.len(),
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.to_u8());
        match *self {
            LockType::Identity(ref d) => {
                buf.extend_from_slice(&(d.0).0);
                buf.extend_from_slice(&(d.1).0);
            },
            LockType::Stream(ref d) => buf.extend_from_slice(&d.0),
        }
    }

    pub fn decode(buf: &mut &[u8]) -> Result<LockType, CryptoError> {
        let id = buf.read_u8().map_err(CryptoError::Io)?;
        match id {
            1 => {
                let mut pk: PublicSignKey = Default::default();
                let mut epk: PublicCryptKey = Default::default();
                buf.read_exact(&mut pk.0)?;
                buf.read_exact(&mut epk.0)?;
                Ok(LockType::Identity((pk,epk)))
            },
            2 => {
                let mut id: StreamId = Default::default();
                buf.read_exact(&mut id.0)?;
                Ok(LockType::Stream(id))
            },
            _ => Err(CryptoError::UnsupportedVersion),
        }
    }
}


/// A container for either a StreamKey, Key, or Value. Can be encrypted for a 
/// particular Identity, or for a particular StreamKey
#[derive(Clone, PartialEq, Debug)]
pub struct Lockbox {
    version: u8,
    type_id: LockType,
    nonce: Nonce,
    ciphertext: Vec<u8>,
}


impl Lockbox {
    /// Get what version of Key/StreamKey was used in encrypting the Lockbox
    pub fn get_version(&self) -> u8 {
        self.version
    }

    /// Returns true if the Lockbox was encrypted with a StreamKey
    pub fn uses_stream(&self) -> bool {
        if let LockType::Stream(_) = self.type_id {
            true
        } else {
            false
        }
    }

    /// Returns true if the Lockbox was encrypted with an Identity
    pub fn uses_identity(&self) -> bool {
        if let LockType::Identity(_) = self.type_id {
            true
        } else {
            false
        }
    }

    /// Get the StreamKey used for encrypting the Lockbox. Returns None if an 
    /// Identity was used instead.
    pub fn get_stream(&self) -> Option<StreamKey> {
        if let LockType::Stream(ref stream) = self.type_id {
            Some(stream_from_id(self.version, stream.clone()))
        } else {
            None
        }
    }

    /// Get the Identity used for encrypting the Lockbox. Returns None if a 
    /// StreamKey was used instead.
    pub fn get_id(&self) -> Option<Identity> {
        if let LockType::Identity(ref id) = self.type_id {
            Some(identity_from_id(self.version, id.0.clone()))
        } else {
            None
        }
    }

    /// Get the length of the Lockbox when it is binary-encoded
    pub fn size(&self) -> usize {
        1 + self.type_id.size() + Nonce::len() + self.ciphertext.len()
    }

    /// Encode a Lockbox into a byte stream. Does not encode length data itself
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.size());
        buf.push(self.version);
        self.type_id.encode(buf);
        buf.extend_from_slice(&self.nonce.0);
        buf.extend_from_slice(&self.ciphertext[..]);
    }

    /// Decode a Lockbox from a byte stream. Requires the complete length of the 
    /// Lockbox that was encoded.
    pub fn decode(len: usize, buf: &mut &[u8]) -> Result<Lockbox, CryptoError> {
        let version = buf.read_u8().map_err(CryptoError::Io)?;
        if version != 1 { return Err(CryptoError::UnsupportedVersion); }
        let type_id = LockType::decode(buf)?;
        let mut nonce: Nonce = Default::default();
        buf.read_exact(&mut nonce.0)?;
        if len < (1 + type_id.size() + nonce.0.len() + Tag::len()) { return Err(CryptoError::BadLength); }
        let cipher_len = len - 1 - type_id.size() - nonce.0.len();
        let mut ciphertext = Vec::with_capacity(cipher_len);
        let (a, b) = buf.split_at(cipher_len);
        ciphertext.extend_from_slice(a);
        *buf = b;
        Ok(Lockbox {
            version,
            type_id,
            nonce,
            ciphertext
        })
    }
}

pub fn get_key(lock: &Lockbox) -> Option<Key> {
    if let LockType::Identity(ref id) = lock.type_id {
        Some(key_from_id(lock.version, id.0.clone()))
    } else {
        None
    }
}


pub fn lockbox_from_stream(k: &FullStreamKey, mut message: Vec<u8>) -> Result<Lockbox, CryptoError> {
    let version = k.get_version();
    if version != 1 { 
        memzero(&mut message[..]); // Must assume data is sensitive and zero it out before failing
        return Err(CryptoError::UnsupportedVersion);
    }
    let nonce = Nonce::new();
    let raw_key = k.get_key();
    let type_id = LockType::Stream(k.get_id());

    message.reserve_exact(Tag::len()); // Need exactly enough to append the tag
    let tag = aead_encrypt(&mut message[..], &[], &nonce, &raw_key);
    message.extend_from_slice(&tag.0);
    Ok(Lockbox {
        version,
        type_id,
        nonce,
        ciphertext: message
    })
}

// Can fail due to bad public key
pub fn lockbox_from_identity(id: &FullIdentity, mut message: Vec<u8>) -> Result<(Lockbox, FullStreamKey),CryptoError> {
    let version = id.get_version();
    if version != 1 {
        memzero(&mut message[..]); // Must assume data is sensitive and zero it out before failing
        return Err(CryptoError::UnsupportedVersion);
    }
    let nonce = Nonce::new();
    let mut esk: SecretCryptKey = Default::default();
    let mut epk: PublicCryptKey = Default::default();
    crypt_keypair(&mut epk, &mut esk);
    let k = id.calc_stream_key(&esk)?;
    let k = FullStreamKey::from_secret(k);
    let type_id = LockType::Identity((id.get_id(),epk));

    message.reserve_exact(Tag::len()); // Need exactly enough to append the tag
    let tag = aead_encrypt(&mut message[..], &[], &nonce, &k.get_key());
    message.extend_from_slice(&tag.0);
    Ok((Lockbox {
        version,
        type_id,
        nonce,
        ciphertext: message
    }, k))
}

/// Computes the FullStreamKey for a lockbox given the needed FullKey. Does not 
/// verify that the correct FullKey was provided, but does check the versions
pub fn stream_key_from_lockbox(k: &FullKey, lock: &Lockbox) -> Result<FullStreamKey, CryptoError> {
    if k.get_version() != lock.get_version() { return Err(CryptoError::DecryptFailed); }
    if let LockType::Identity(ref id) = lock.type_id {
        let stream = k.calc_stream_key(&id.1)?;
        Ok(FullStreamKey::from_secret(stream))
    } else {
        Err(CryptoError::DecryptFailed)
    }
}

/// Consume the lockbox and spit out the decrypted data
pub fn decrypt_lockbox(k: &FullStreamKey, mut lock: Lockbox) -> Result<Vec<u8>, CryptoError> {
    let m_len = lock.ciphertext.len() - Tag::len();
    let success = {
        let (mut message, tag) = lock.ciphertext.split_at_mut(m_len);
        aead_decrypt(
            &mut message,
            &[],
            &tag,
            &lock.nonce,
            &k.get_key()
        )
    };
    if success {
        lock.ciphertext.truncate(m_len);
        Ok(lock.ciphertext) // Value is moved, so plaintext is only in the Result
    }
    else {
        Err(CryptoError::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::init;

    /// Encode & Decode a lockbox, and make sure the decoded one is equal, as 
    /// well as verifying the plaintext isn't in the encoded stream.
    fn enc_dec(lock: Lockbox, plain: Vec<u8>) -> Lockbox {
        let mut v = Vec::new();
        lock.encode(&mut v);
        // Walk through the stream looking for the plaintext
        for i in 0..(v.len()-plain.len()+1) {
            assert!(!v[i..].starts_with(&plain[..]), "Encrypted data included plaintext");
        }
        let lock_dec = Lockbox::decode(v.len(), &mut &v[..]).unwrap();
        assert_eq!(lock, lock_dec);
        lock_dec
    }

    /// Test the creation of a stream-based lockbox. Verify each function on it, 
    /// encode it, verify through decoding, then 
    /// Also 
    #[test]
    fn stream_lockbox() {
        init().unwrap();
        let stream = FullStreamKey::new();
        let stream_other = FullStreamKey::new();
        let stream_ref = stream.get_stream_ref();
        let plain: Vec<u8> = b"This is a test".to_vec();
        let lockbox = lockbox_from_stream(&stream, plain.clone()).unwrap();
        assert_eq!(lockbox.get_version(), 1u8);
        assert_eq!(lockbox.uses_stream(), true);
        assert_eq!(lockbox.uses_identity(), false);
        assert_eq!(lockbox.get_stream(), Some(stream_ref));
        assert_eq!(lockbox.get_id(), None);
        assert_eq!(get_key(&lockbox), None);
        // Lockbox is version byte, type byte, StreamId, Nonce, encrypted data, 
        // and encryption tag 
        assert_eq!(lockbox.size(), 2 + stream.get_id().0.len() + Nonce::len() + 
                   plain.len() + Tag::len());
        let lockbox = enc_dec(lockbox, plain.clone());
        let data = decrypt_lockbox(&stream, lockbox.clone()).unwrap();
        let data_other = decrypt_lockbox(&stream_other, lockbox.clone());
        assert_eq!(data, plain);
        assert!(data_other.is_err());
    }

    /// Test the creation of an identity-based lockbox. Verify each function on it.
    #[test]
    fn identity_lockbox() {
        init().unwrap();
        let (key, id) = FullKey::new_pair().unwrap();
        let id_ref = id.get_identity_ref();
        let plain: Vec<u8> = b"This is a test".to_vec();
        let (lockbox, stream) = lockbox_from_identity(&id, plain.clone()).unwrap();
        let stream_other = FullStreamKey::new();
        assert_eq!(lockbox.get_version(), 1u8);
        assert_eq!(lockbox.uses_stream(), false);
        assert_eq!(lockbox.uses_identity(), true);
        assert_eq!(lockbox.get_stream(), None);
        assert_eq!(lockbox.get_id(), Some(id_ref));
        assert_eq!(get_key(&lockbox), Some(key.get_key_ref()));
        // Lockbox is version byte, type byte, public key, ephemeral public key, 
        // Nonce, encrypted data, and encryption tag 
        //assert_eq!(lockbox.len(), 2 + id_ref.get_id().0.len() + Nonce::len() + 
                   //plain.len() + Tag::len());
        let lockbox = enc_dec(lockbox, plain.clone());
        let decrypt_key = stream_key_from_lockbox(&key, &lockbox).unwrap();
        assert_eq!(decrypt_key.get_stream_ref(), stream.get_stream_ref());
        let data = decrypt_lockbox(&stream, lockbox.clone()).unwrap();
        let data_other = decrypt_lockbox(&stream_other, lockbox.clone());
        assert_eq!(data, plain);
        assert!(data_other.is_err());
    }

}
