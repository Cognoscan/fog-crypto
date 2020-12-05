use std::io::Read;
use byteorder::ReadBytesExt;
use std::fmt;

use crate::{
    error::CryptoError,
    sodium::{StreamId, SecretKey, aead_keygen, derive_id},
};

/// A cryptographic symmetric key, used for creating a Lockbox. Requires accessing a Vault in order 
/// to use it.
#[derive(Clone,PartialEq,Eq,Hash)]
pub struct StreamKey {
    version: u8,
    id: StreamId,
}

pub fn stream_from_id(version: u8, id: StreamId) -> StreamKey {
    StreamKey { version, id }
}

impl fmt::Debug for StreamKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ ver={}, {:x?} }}", stringify!(StreamKey), &self.version, &self.id.0[..])
    }
}

/// FullStreamKey: A secret XChaCha20 key, identifiable by its ID
#[derive(Clone)]
pub struct FullStreamKey {
    version: u8,
    id: StreamId,
    key: SecretKey,
}

impl FullStreamKey {
    
    fn blank() -> FullStreamKey {
        FullStreamKey {
            version: 0,
            id: Default::default(),
            key: Default::default(),
        }
    }

    pub fn new() -> FullStreamKey {
        let mut k = FullStreamKey::blank();
        k.version = 1;
        aead_keygen(&mut k.key);
        k.complete();
        k
    }

    pub fn from_secret(k: SecretKey) -> FullStreamKey {
        let mut stream = FullStreamKey::blank();
        stream.version = 1;
        stream.key = k;
        stream.complete();
        stream
    }

    pub fn get_id(&self) -> StreamId {
        (&self.id).clone()
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_key(&self) -> &SecretKey {
        &self.key
    }

    pub fn get_stream_ref(&self) -> StreamKey {
        StreamKey {
            version: self.version,
            id: self.get_id()
        }
    }

    pub fn complete(&mut self) {
        derive_id(&self.key, &mut self.id)
    }

    pub fn len(&self) -> usize {
        1 + self.key.0.len()
    }

    pub fn max_len() -> usize {
        1 + SecretKey::len()
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.key.0);
    }

    pub fn decode(buf: &mut &[u8]) -> Result<FullStreamKey, CryptoError> {
        let mut k = FullStreamKey::blank();
        k.version = buf.read_u8().map_err(CryptoError::Io)?;
        if k.version != 1 { return Err(CryptoError::UnsupportedVersion); }
        buf.read_exact(&mut k.key.0).map_err(CryptoError::Io)?;
        k.complete();
        Ok(k)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_key() -> FullStreamKey {
        // Below test vectors come from using the C version of crypto_kdf_derive_from_key with 
        // subkey index of 1 and "fogpack" as the context.
        let key: [u8; 32] = [0x20, 0xa3, 0x02, 0x00, 0xe2, 0x5c, 0x38, 0x79,
                             0x3f, 0x74, 0x59, 0x21, 0x10, 0x49, 0xb7, 0x62,
                             0xb6, 0x6b, 0x15, 0xce, 0x02, 0xf2, 0x55, 0x79,
                             0x48, 0xbf, 0x17, 0xd9, 0xb5, 0xc1, 0x22, 0xb4];
        FullStreamKey::from_secret(SecretKey(key))
    }

    #[test]
    fn id_gen() {
        let key = example_key();
        let subkey: [u8; 32] = [0xe8, 0x23, 0x41, 0xd7, 0x6c, 0x68, 0x9f, 0x10,
                                0x0b, 0xc4, 0x53, 0x5f, 0xf6, 0x4c, 0xc7, 0x2a,
                                0xa8, 0xa5, 0x3a, 0x88, 0x53, 0x95, 0x09, 0x66,
                                0xf8, 0x87, 0xc7, 0x6d, 0x5e, 0xee, 0xf4, 0xea];
        assert_eq!(key.id.0, subkey);
    }

    fn enc_dec(k: FullStreamKey) {
        let mut v = Vec::new();
        k.encode(&mut v);
        let kd = FullStreamKey::decode(&mut &v[..]).unwrap();
        assert_eq!(k.version, kd.version);
        assert_eq!(k.key.0, kd.key.0);
        assert_eq!(k.id.0, kd.id.0);
    }
    
    #[test]
    fn stream_enc() {
        let k = example_key();
        enc_dec(k);
    }
}
