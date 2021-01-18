//! Cryptographic hashing.
//!
//! This module lets you create a cryptographic hash from a byte stream. Cryptographic hashes can 
//! be used to uniquely identify a data sequence. They can be passed to an 
//! [`IdentityKey`](crate::identity::IdentityKey) to be signed.
//!
//! Optionally, you can also create a special "empty" hash value. The empty hash can be used in a 
//! hash-based referencing scheme to refer to the containing document. It cannot be signed, and 
//! should
//!
//!
//! # Example
//!
//! ```
//! # use fog_crypto::hash::*;
//! // Create a new hash from raw bytes
//! let hash = Hash::new(b"I am the entire data sequence");
//! println!("Hash(Base58): {}", hash);
//!
//! // Create a hash by feeding in bytes repeatedly
//! let mut hash_state = HashState::new();
//! hash_state.update(b"I am the first part of a data sequence");
//! hash_state.update(b"And I am their sibling, the second part of a data sequence");
//! let hash = hash_state.finalize();
//! println!("Hash(Base58): {}", hash);
//! ```

use crate::error::CryptoError;

use std::{
    fmt,
    convert::TryFrom,
};

use blake2::{
    VarBlake2b,
    digest::{Update, VariableOutput},
};

use subtle::{Choice, ConstantTimeEq};

pub const DEFAULT_HASH_VERSION: u8 = 1;
pub const MIN_HASH_VERSION: u8 = 1;
pub const MAX_HASH_VERSION: u8 = 1;

const V1_DIGEST_SIZE: usize = 32;

/// Crytographically secure hash of data.
///
/// Offers constant time equality check (non-constant time ordinal checks). A version byte is used 
/// to indicate what hash algorithm should be used.  Uses base58 encoding when displayed, unless 
/// overridden with hex formatting or debug formatting.
///
/// # Supported Versions
/// - 1: Blake2B hash with 32 bytes of digest
///
/// # Example
/// ```
/// # use fog_crypto::hash::*;
/// // Create a new hash from raw bytes
/// let hash = Hash::new(b"I am the entire data sequence");
/// println!("Hash(Base58): {}", hash);
///
/// ```
#[derive(Clone)]
pub struct Hash {
    data: Vec<u8>,
}

impl Hash {

    /// Create a new hash from raw data, using the recommended algorithm.
    pub fn new(data: impl AsRef<[u8]>) -> Self {
        Self::with_version(data, DEFAULT_HASH_VERSION).unwrap()
    }

    /// Create a hash with a specific algorithm version. You should avoid this except when working 
    /// through a upgrade process, where you may briefly need to support more than one version. 
    /// Fails if the version isn't supported.
    pub fn with_version(data: impl AsRef<[u8]>, version: u8) -> Result<Self, CryptoError> {
        let mut state = HashState::with_version(version)?;
        state.update(data);
        Ok(state.finalize())
    }

    /// Algorithm version associated with this hash.
    pub fn version(&self) -> u8 {
        self.data[0]
    }

    /// The raw digest from the hash, without the version byte.
    pub fn digest(&self) -> &[u8] {
        &self.data[1..]
    }

    /// Attempt to parse a Base58-encoded hash type. Fails if the string isn't valid Base58 or the 
    /// hash itself isn't valid.
    pub fn from_base58(s: &str) -> Result<Self, CryptoError> {
        let raw = bs58::decode(s).into_vec().or(Err(CryptoError::BadFormat("Not valid Base58")))?;
        Self::try_from(&raw[..])
    }

    /// Encode the hash as a Base58 string.
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.data).into_string()
    }

}

impl TryFrom<&[u8]> for Hash {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw = value.as_ref();
        let &version = raw.get(0)
            .ok_or(CryptoError::BadLength{step: "get hash version", actual: 0, expected: 1})?;

        // Version check
        if version < MIN_HASH_VERSION || version > MAX_HASH_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        // Length check
        if raw.len() != 1+V1_DIGEST_SIZE {
            return Err(CryptoError::BadLength {
                step: "get hash digest (with version)",
                actual: raw.len(),
                expected: 1+V1_DIGEST_SIZE
            });
        }

        Ok(Self {
            data: Vec::from(raw),
        })
    }
}

impl std::convert::AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}

impl ConstantTimeEq for Hash {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.data[..].ct_eq(&other.data[..])
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Hash { }

// Not constant time, as no cryptographic operation requires Ord. This is solely for ordering in a 
// BTree
use std::cmp::Ordering;
impl std::cmp::Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        self.data.cmp(&other.data)
    }
}

impl std::cmp::PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (version, digest) = self.data.split_first().unwrap();
        f.debug_struct("Hash")
            .field("version", version)
            .field("digest", &digest)
            .finish()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::LowerHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.data.iter() {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.data.iter() {
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}

impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}


/// A hasher that can incrementally take in data and produce a hash at any time.
///
/// # Example
///
/// ```
/// // Create a hash by feeding in bytes repeatedly
/// # use fog_crypto::hash::*;
/// let mut hash_state = HashState::new();
/// hash_state.update(b"I am the first part of a data sequence");
/// let hash_first = hash_state.hash(); // Produce a hash of just the first part
/// hash_state.update(b"And I am their sibling, the second part of a data sequence");
/// let hash_full = hash_state.finalize(); // Consume the HashState
/// println!("hash_first(Base58): {}", hash_first);
/// println!("hash_full(Base58): {}", hash_full);
/// ```
#[derive(Clone)]
pub struct HashState {
    state: VarBlake2b
}

impl HashState {

    /// Initialize a new hasher.
    pub fn new() -> HashState {
        Self::with_version(DEFAULT_HASH_VERSION).unwrap()
    }

    /// Initialize a new hasher with a specific algorithm version. You should avoid this except 
    /// when working through an upgrade process, where you may briefly need to support more than 
    /// one version. Fails if the version isn't supported.
    pub fn with_version(version: u8) -> Result<HashState, CryptoError> {
        if version > MAX_HASH_VERSION || version < MIN_HASH_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        let state = VarBlake2b::new(V1_DIGEST_SIZE)
            .expect("Blake2B didn't support the chosen digest size");
        Ok(HashState { state })
    }

    /// Get the version of hash that this hasher will produce on completion.
    pub fn version(&self) -> u8 {
        1u8
    }

    /// Update the hasher with new input data.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.state.update(data);
    }

    /// Get the hash of the data fed into the algorithm so far.
    pub fn hash(&self) -> Hash {
        self.clone().finalize()
    }

    /// Finalize the hasher and produce a hash. Functions like `hash()` but consumes the state.
    pub fn finalize(self) -> Hash {
        let mut data = Vec::with_capacity(1+V1_DIGEST_SIZE);
        data.push(1u8);
        self.state.finalize_variable(|res| data.extend_from_slice(res));
        Hash { data }
    }
}

impl Default for HashState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HashState {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.debug_struct("HashState")
            .field("version", &self.version())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use serde_json::{self,Value};
    use hex;

    #[test]
    fn hash_vectors() {
        let file_ref = fs::File::open("test-resources/blake2b-test-vectors.json").unwrap();
        let json_ref : Value = serde_json::from_reader(file_ref).unwrap();

        for vector in json_ref.as_array().unwrap().iter() {
            let ref_hash = hex::decode(&vector["out"].as_str().unwrap()).unwrap();
            let ref_input = hex::decode(&vector["input"].as_str().unwrap()).unwrap();
            let h = Hash::new(&ref_input[..]);
            let mut state: HashState = HashState::new();
            state.update(&ref_input[..]);
            let h2 = state.hash();
            let h3 = state.finalize();
            assert_eq!(h.version(), 1u8);
            assert_eq!(h.digest(), &ref_hash[..]);
            assert_eq!(h2.version(), 1u8);
            assert_eq!(h2.digest(), &ref_hash[..]);
            assert_eq!(h3.version(), 1u8);
            assert_eq!(h3.digest(), &ref_hash[..]);
            let v = Vec::from(h.as_ref());
            let hd = Hash::try_from(&v[..]).unwrap();
            assert_eq!(h, hd);
        }
    }

    #[test]
    fn bad_version() {
        let hash = Hash::new(b"I am a message, being hashed.");
        let mut enc = Vec::from(hash.as_ref());
        enc[0] = 99u8;
        let result = Hash::try_from(&enc[..]);
        assert!(result.is_err());
        enc[0] = 0u8;
        let result = Hash::try_from(&enc[..]);
        assert!(result.is_err());
    }

    #[test]
    fn edge_cases() {
        match Hash::with_version(&[1,2], 0).unwrap_err() {
            CryptoError::UnsupportedVersion(v) => {
                assert_eq!(v, 0, "UnsupportedVersion should have been 0");
            },
            _ => panic!("New hash should always fail on version 0"),
        };
        match HashState::with_version(0).unwrap_err() {
            CryptoError::UnsupportedVersion(v) => {
                assert_eq!(v, 0, "UnsupportedVersion should have been 0");
            },
            _ => panic!("HashState should always fail on version 0"),
        };
        let digest = hex::decode(
            "8b57a796a5d07cb04cc1614dfc2acb3f73edc712d7f433619ca3bbe66bb15f49").unwrap();
        let h = Hash::new(&hex::decode("00010203040506070809").unwrap());
        assert_eq!(h.version(), 1);
        assert_eq!(h.digest(), &digest[..]);
    }

    #[test]
    fn base58() {
        use rand::prelude::*;
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let mut v: Vec<u8> = Vec::with_capacity(32);
            for _ in 0..32 {
                v.push(rng.gen());
            }
            let h = Hash::new(&v[..]);
            let b58 = h.to_base58();
            let h2 = Hash::from_base58(&b58).unwrap();
            let eq = h == h2;
            if !eq {
                println!("in:  {}", h);
                println!("out: {}", h2);
            }
            assert!(eq);
        }
    }
}
