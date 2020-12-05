use constant_time_eq::constant_time_eq;
use std::fmt;
use std::io::Read;
use byteorder::ReadBytesExt;
use std::hash;
use std::cmp;
use std::cmp::Ordering;

use crate::{
    error::CryptoError,
    sodium::{HASH_BYTES, blake2b, Blake2BState},
};

const DEFAULT_HASH_VERSION: u8 = 1;
const MIN_HASH_VERSION: u8 = 1;
const MAX_HASH_VERSION: u8 = 1;

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DIGIT_MAP: &[i8] = &[
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
];

/// Crytographically secure hash of data. Can be signed by a FullKey. It is impractical to generate an 
/// identical hash from different data.
///
/// # Supported Versions
/// - 0: Null hash. Used to refer to hash of parent document
/// - 1: Blake2B hash with 32 bytes of digest
#[derive(Clone)]
pub struct Hash {
    version: u8,
    digest: [u8; HASH_BYTES],
}

/// A hasher that can incrementally take in data and produce a hash at any time.
#[derive(Clone)]
pub struct HashState {
    version: u8,
    state: Blake2BState,
}

impl Eq for Hash { }

impl PartialEq for Hash {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version && constant_time_eq(&self.digest, &other.digest)
    }
}

// Not constant time, as no cryptographic operation requires Ord. This is solely for ordering in a 
// BTree
impl cmp::Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        match self.version.cmp(&other.version) {
            Ordering::Greater => { return Ordering::Greater; },
            Ordering::Less => { return Ordering::Less; }
            _ => {},
        }

        for i in 0..HASH_BYTES {
            match self.digest[i].cmp(&other.digest[i]) {
                Ordering::Greater => { return Ordering::Greater; },
                Ordering::Less => { return Ordering::Less; }
                _ => {},
            }
        }
        Ordering::Equal
    }
}

impl cmp::PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {{ version: {:?}, digest: {:x?} }}", stringify!(Hash), &self.version, &self.digest[..])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode_base58())
    }
}

impl fmt::LowerHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.version, f)?;
        for byte in self.digest.iter() {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.version, f)?;
        for byte in self.digest.iter() {
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}

impl hash::Hash for Hash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
        self.digest.hash(state);
    }
}

impl Hash {

    pub fn new(data: &[u8]) -> Hash {
        let mut hash = Hash {
            version: DEFAULT_HASH_VERSION,
            digest: [0;HASH_BYTES]
        };
        blake2b(&mut hash.digest, data);
        hash
    }

    pub fn with_version(version: u8, data: &[u8]) -> Result<Hash, CryptoError> {
        if version > MAX_HASH_VERSION || version < MIN_HASH_VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        let mut hash = Hash {version, digest: [0;HASH_BYTES]};
        blake2b(&mut hash.digest, data);
        Ok(hash)
    }

    pub fn new_empty() -> Hash {
        Hash { version: 0, digest: [0; HASH_BYTES] }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    pub fn size(&self) -> usize {
        if self.version == 0 {
            1
        }
        else {
            HASH_BYTES+1
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.size());
        buf.push(self.version);
        if self.version != 0 {
            buf.extend_from_slice(&self.digest);
        }
    }

    pub fn decode(buf: &mut &[u8]) -> Result<Hash, CryptoError> {
        let version = buf.read_u8().map_err(CryptoError::Io)?;
        if version == 0 { return Ok(Hash { version, digest:[0;HASH_BYTES] }); }
        if version != 1 { return Err(CryptoError::UnsupportedVersion); }
        let mut hash = Hash {version, digest:[0;HASH_BYTES]};
        buf.read_exact(&mut hash.digest).map_err(CryptoError::Io)?;
        Ok(hash)
    }

    pub fn encode_base58(&self) -> String {
        // Version 0 means just a leading zero and nothing else.
        if self.version == 0 {
            return String::from("1");
        }

        // We never have leading zeros because the version byte is 1 (or higher)
        // Run through base58 encoding loop, from the IETF Base58 Encoding Scheme 
        // (draft-msporny-base58-01)
        let mut input = Vec::with_capacity(self.size());
        self.encode(&mut input);

        let size = (input.len() * 89500 + 65535) >> 16; // ceil(size * log2(256)/log2(58)), scaled by 2^16.
        let mut buffer = vec![0u8; size];
        let mut high = size-1;

        // Repeated long division by 58, emitting the remainder of each division
        for byte in input {
            let mut carry = byte as u32;
            let mut j = size-1;
            while j > high || carry != 0 {
                carry |= 256 * buffer[j] as u32;
                let rem = carry % 58;
                let quot = carry / 58;
                buffer[j] = rem as u8;
                carry = quot;
                if j > 0 { j-=1; }
            }
            high = j;
        }

        let mut result = String::new();
        for j in (buffer.iter().take_while(|x| **x == 0).count())..size {
            result.push(char::from(ALPHABET[buffer[j] as usize]));
        }

        result
    }

    pub fn decode_base58(s: &str) -> Result<Hash, CryptoError> {
        if s.is_empty() { return Err(CryptoError::BadFormat); }
        // If we only have one character and it's '1', then it's the empty hash.
        if (s.len() == 1) && (s.as_bytes()[0] == b'1') {
            return Ok(Hash::new_empty());
        }
        // Prepare to perform mapping & multiplication to decode
        let mut buffer = [0u8; HASH_BYTES+1];
        for byte in s.bytes() {
            // Decode the character to 0-57, with -1 for invalid characters
            let carry  = *DIGIT_MAP
                .get(byte as usize)
                .ok_or(CryptoError::BadFormat)?;
            if carry == -1 { return Err(CryptoError::BadFormat); }
            let mut carry = carry as u32;

            // Big integer multiplication
            for byte in buffer.iter_mut().rev() {
                let t = (*byte as u32) * 58 + carry;
                carry = (t & 0xFF00) >> 8;
                *byte = (t & 0xFF) as u8;
            }

            // Shouldn't occur unless the hash is longer than expected
            if carry != 0 { return Err(CryptoError::BadFormat); }
        }
        // The below array initializer looks stupid, yes, but it's quite probably the fastest way 
        // to do this with safe rust. Slices complain about bounds, and everything else I know of 
        // requires unsafe. Feel free to replace this if there's something more compact.
        Ok(Hash {
            version: buffer[0],
            digest: [
                buffer[ 1], buffer[ 2], buffer[ 3], buffer[ 4], buffer[ 5], buffer[ 6], buffer[ 7], buffer[ 8], 
                buffer[ 9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], 
                buffer[17], buffer[18], buffer[19], buffer[20], buffer[21], buffer[22], buffer[23], buffer[24], 
                buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30], buffer[31], buffer[32], 
            ]
        })
    }
}

impl HashState {
    pub fn new() -> HashState {
        HashState {
            version: DEFAULT_HASH_VERSION,
            state: Blake2BState::new()
        }
    }

    pub fn with_version(version: u8) -> Result<HashState, CryptoError> {
        if version > MAX_HASH_VERSION || version < MIN_HASH_VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        Ok(HashState { version, state: Blake2BState::new() })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    pub fn get_hash(&self) -> Hash {
        let mut hash = Hash { version: self.version, digest: [0;HASH_BYTES] };
        self.state.get_hash(&mut hash.digest);
        hash
    }

    pub fn finalize(self) -> Hash {
        let mut hash = Hash { version: self.version, digest: [0;HASH_BYTES] };
        self.state.finalize(&mut hash.digest);
        hash
    }
}

impl Default for HashState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HashState {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ version: {:?} }}", stringify!(HashState), &self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use serde_json::{self,Value};
    use hex;

    fn enc_dec(h: Hash) {
        let mut v = Vec::new();
        h.encode(&mut v);
        let hd = Hash::decode(&mut &v[..]).unwrap();
        assert_eq!(h, hd);
    }

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
            let h2 = state.get_hash();
            let h3 = state.finalize();
            assert_eq!(h.version, 1u8);
            assert_eq!(h.digest[..], ref_hash[..]);
            assert_eq!(h2.version, 1u8);
            assert_eq!(h2.digest[..], ref_hash[..]);
            assert_eq!(h3.version, 1u8);
            assert_eq!(h3.digest[..], ref_hash[..]);
            enc_dec(h)
        }
    }

    #[test]
    fn edge_cases() {
        match Hash::with_version(0, &[1,2]).unwrap_err() {
            CryptoError::UnsupportedVersion => (),
            _ => panic!("New hash should always fail on version 0"),
        };
        match HashState::with_version(0).unwrap_err() {
            CryptoError::UnsupportedVersion => (),
            _ => panic!("HashState should always fail on version 0"),
        };
        let digest = hex::decode(
            "8b57a796a5d07cb04cc1614dfc2acb3f73edc712d7f433619ca3bbe66bb15f49").unwrap();
        let h = Hash::new(&hex::decode("00010203040506070809").unwrap());
        assert_eq!(h.version(), 1);
        assert_eq!(h.digest(), &digest[..]);
    }

    #[test]
    fn empty() {
        let h = Hash::new_empty();
        let digest = [0u8; HASH_BYTES];
        assert_eq!(h.version(), 0);
        assert_eq!(h.digest(), &digest[..]);
        enc_dec(h);
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
            let b58 = h.encode_base58();
            let h2 = Hash::decode_base58(&b58).unwrap();
            let eq = h == h2;
            if !eq {
                println!("in:  {}", h);
                println!("out: {}", h2);
            }
            assert!(eq);
        }
    }
}
