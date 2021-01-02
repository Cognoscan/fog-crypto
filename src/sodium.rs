//!
//! This contains all the internal structures and unsafe calls to libsodium. None of these should 
//! be used outside of the crypto module.
//!
//! Signing keys are all ed25519, encrypting keys are curve25519, secret keys are 32-byte shared 
//! secrets used for XChaCha20.

use std::fmt;
use std::ptr;
use std::ffi::CString;
use libc::c_ulonglong;
use libsodium_sys;
use constant_time_eq::constant_time_eq;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Read;

use crate::CryptoError;

use zeroize::Zeroize;

static LIB_INIT: std::sync::Once = std::sync::Once::new();

fn lib_init() {
    LIB_INIT.call_once(|| {
        let init_result = unsafe { libsodium_sys::sodium_init() };
        if init_result < 0 {
            panic!("libsodium could not initialize, error code {}", init_result);
        }
    });
}


pub const HASH_BYTES:         usize = 32;

const SECRET_KEY_BYTES:   usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
const NONCE_BYTES:        usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;
const TAG_BYTES:          usize = libsodium_sys::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
const SEED_KEY_BYTES:     usize = libsodium_sys::crypto_sign_SEEDBYTES as usize;
const SK_SIGN_KEY_BYTES:  usize = libsodium_sys::crypto_sign_ed25519_SECRETKEYBYTES as usize;
const SK_CRYPT_KEY_BYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_BYTES as usize;
const PK_SIGN_KEY_BYTES:  usize = libsodium_sys::crypto_sign_ed25519_PUBLICKEYBYTES as usize;
const PK_CRYPT_KEY_BYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_BYTES as usize;
const SIGN_BYTES:         usize = libsodium_sys::crypto_sign_ed25519_BYTES as usize;
const SALT_BYTES:         usize = libsodium_sys::crypto_pwhash_SALTBYTES as usize;

// Secret Structs
#[derive(Clone,Default,Zeroize)]
#[zeroize(drop)]
pub struct Seed(pub [u8; SEED_KEY_BYTES]);
#[derive(Clone,Zeroize)]
#[zeroize(drop)]
pub struct SecretSignKey([u8; SK_SIGN_KEY_BYTES]);
#[derive(Clone,Default,Zeroize)]
#[zeroize(drop)]
pub struct SecretCryptKey([u8; SK_CRYPT_KEY_BYTES]);
#[derive(Clone,Default,Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub [u8; SECRET_KEY_BYTES]);

#[derive(Clone,Default)]
pub struct PasswordConfig {
    ops_limit: u64,
    mem_limit: usize,
    alg: i32,
    salt: [u8; SALT_BYTES],
}

// Public Structs
#[derive(Clone,PartialEq,Eq,Hash,Default)]
pub struct PublicSignKey(pub [u8; PK_SIGN_KEY_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default)]
pub struct PublicCryptKey(pub [u8; PK_CRYPT_KEY_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default,Debug)]
pub struct Nonce(pub [u8; NONCE_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default,Debug)]
pub struct Tag(pub [u8; TAG_BYTES]);
#[derive(Clone,PartialEq,Eq,Hash,Default,Debug)]
pub struct StreamId(pub [u8; 32]);
#[derive(Clone)]
pub struct Sign(pub [u8; SIGN_BYTES]);
#[derive(Clone)]
pub struct Blake2BState(pub libsodium_sys::crypto_generichash_blake2b_state);

impl Nonce {
    pub fn new() -> Nonce {
        let mut nonce = Nonce([0;NONCE_BYTES]);
        randombytes(&mut nonce.0);
        nonce
    }
    pub fn len() -> usize {
        NONCE_BYTES
    }
}

impl Tag {
    pub fn len() -> usize {
        TAG_BYTES
    }
}

impl Default for Sign {
    fn default() -> Sign {
        Sign([0; SIGN_BYTES])
    }
}
impl fmt::Debug for Sign {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ {:?} }}", stringify!(Sign), &self.0[..])
    }
}
impl PartialEq for Sign {
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(other.0.iter()).all(|(a,b)| a == b)
    }
}

impl fmt::Debug for PublicSignKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ {:?} }}", stringify!(PublicSignKey), &self.0[..])
    }
}

impl fmt::Debug for PublicCryptKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {{ {:?} }}", stringify!(PublicCryptKey), &self.0[..])
    }
}

impl PasswordConfig {
    pub fn interactive() -> PasswordConfig {
        let mut pw = PasswordConfig {
            ops_limit: libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE as u64,
            mem_limit: libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
            alg: libsodium_sys::crypto_pwhash_ALG_DEFAULT as i32,
            salt: [0; SALT_BYTES],
        };
        randombytes(&mut pw.salt);
        pw
    }
    pub fn moderate() -> PasswordConfig {
        let mut pw = PasswordConfig {
            ops_limit: libsodium_sys::crypto_pwhash_OPSLIMIT_MODERATE as u64,
            mem_limit: libsodium_sys::crypto_pwhash_MEMLIMIT_MODERATE as usize,
            alg: libsodium_sys::crypto_pwhash_ALG_DEFAULT as i32,
            salt: [0; SALT_BYTES],
        };
        randombytes(&mut pw.salt);
        pw
    }
    pub fn sensitive() -> PasswordConfig {
        let mut pw = PasswordConfig {
            ops_limit: libsodium_sys::crypto_pwhash_OPSLIMIT_SENSITIVE as u64,
            mem_limit: libsodium_sys::crypto_pwhash_MEMLIMIT_SENSITIVE as usize,
            alg: libsodium_sys::crypto_pwhash_ALG_DEFAULT as i32,
            salt: [0; SALT_BYTES],
        };
        randombytes(&mut pw.salt);
        pw
    }

    pub fn len() -> usize {
        8+8+4+SALT_BYTES
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(PasswordConfig::len());
        buf.extend_from_slice(&self.ops_limit.to_be_bytes());
        buf.extend_from_slice(&(self.mem_limit as u64).to_be_bytes());
        buf.extend_from_slice(&self.alg.to_be_bytes());
        buf.extend_from_slice(&self.salt);
    }

    pub fn decode(buf: &mut &[u8]) -> Result<PasswordConfig, std::io::Error> {
        // No need to check for if these are valid. The pwhash function will do that and fail if 
        // they're invalid parameters.
        let mut pw = PasswordConfig { ops_limit: 0, mem_limit: 0, alg: 0, salt: [0;SALT_BYTES] };
        pw.ops_limit = buf.read_u64::<BigEndian>()?;
        pw.mem_limit = buf.read_u64::<BigEndian>()? as usize;
        pw.alg = buf.read_i32::<BigEndian>()?;
        buf.read_exact(&mut pw.salt)?;
        Ok(pw)
    }
}

// Seed
impl Seed {
    pub fn len() -> usize {
        SEED_KEY_BYTES
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(Seed))
    }
}
impl PartialEq for Seed {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// SecretSignKey
impl Default for SecretSignKey {
    fn default() -> SecretSignKey {
        SecretSignKey([0; SK_SIGN_KEY_BYTES])
    }
}
impl fmt::Debug for SecretSignKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(SecretSignKey))
    }
}
impl PartialEq for SecretSignKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// SecretCryptKey
impl fmt::Debug for SecretCryptKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(SecretCryptKey))
    }
}
impl PartialEq for SecretCryptKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// SecretKey
impl SecretKey {
    pub fn len() -> usize {
        SECRET_KEY_BYTES
    }
}
impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}(****)", stringify!(SecretKey))
    }
}
impl PartialEq for SecretKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

// Blake2BState
impl Blake2BState {
    pub fn new() -> Blake2BState {
        let mut state: libsodium_sys::crypto_generichash_blake2b_state;
        lib_init(); // Initialize here. Other libsodium calls inside Blake2BState require new() first.
        // Below will only fail or return -1 if we have more than 64 bytes in input or tell it to use a 
        // non-existant key
        unsafe {
            state = ::std::mem::MaybeUninit::uninit().assume_init();
            libsodium_sys::crypto_generichash_blake2b_init(&mut state, ::std::ptr::null(), 0, HASH_BYTES);
        }
        Blake2BState { 0: state }
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            libsodium_sys::crypto_generichash_blake2b_update(
                &mut self.0,
                data.as_ptr(),
                data.len() as c_ulonglong
            );
        }
    }

    pub fn get_hash(&self, hash: &mut [u8; HASH_BYTES]) {
        let mut temp_state = self.0;
        unsafe {
            libsodium_sys::crypto_generichash_blake2b_final(
                &mut temp_state,
                hash.as_mut_ptr(),
                HASH_BYTES
            );
        }
    }

    pub fn finalize(mut self, hash: &mut [u8; HASH_BYTES]) {
        unsafe {
            libsodium_sys::crypto_generichash_blake2b_final(
                &mut self.0,
                hash.as_mut_ptr(),
                HASH_BYTES
            );
        }
    }
}

/// Hashes a password according to a given PasswordConfig, returning a usable SecretKey.
/// The password string is zeroed out no matter what.
pub fn password_to_key(mut password: String, config: &PasswordConfig) -> Result<SecretKey, ()> {
    let mut key: SecretKey = Default::default();
    lib_init();
    let result = unsafe {
        libsodium_sys::crypto_pwhash(
            key.0.as_mut_ptr(),
            key.0.len() as c_ulonglong,
            password.as_ptr() as *const _,
            password.len() as c_ulonglong,
            config.salt.as_ptr(),
            config.ops_limit as c_ulonglong,
            config.mem_limit,
            config.alg
        )
    };
    unsafe { 
        let mut pw = password.as_bytes_mut();
        memzero(&mut pw);
    };
    if result >= 0 {
        Ok(key)
    } else {
        Err(())
    }
}

pub fn aead_keygen(key: &mut SecretKey) {
    lib_init();
    unsafe { libsodium_sys::crypto_aead_xchacha20poly1305_ietf_keygen(key.0.as_mut_ptr()) };
}

// Does in-place encryption of message and returns HMAC Tag
pub fn aead_encrypt(message: &mut [u8], ad: &[u8], n: &Nonce, k: &SecretKey) -> Tag {
    // tag will store the message authentication tag
    let mut tag = Tag([0; TAG_BYTES]);
    lib_init();
    unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            message.as_mut_ptr(),
            tag.0.as_mut_ptr(),
            ptr::null_mut(),
            message.as_ptr(),
            message.len() as c_ulonglong,
            ad.as_ptr(),
            ad.len() as c_ulonglong, 
            ptr::null_mut(),
            n.0.as_ptr(),
            k.0.as_ptr()
        );
    }
    tag
}

// Does in-place decryption of crypt and returns true if verification succeeds
pub fn aead_decrypt(crypt: &mut [u8], ad: &[u8], tag: &[u8],n: &Nonce, k: &SecretKey) -> bool {
    lib_init();
    0 <= unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            crypt.as_mut_ptr(),
            ptr::null_mut(),
            crypt.as_ptr(),
            crypt.len() as c_ulonglong,
            tag.as_ptr(),
            ad.as_ptr(),
            ad.len() as c_ulonglong,
            n.0.as_ptr(),
            k.0.as_ptr()
        )
    }
}

// Shouldn't fail as long as the input parameters are valid
pub fn derive_id(k: &SecretKey, id: &mut StreamId) {
    lib_init();
    unsafe {
        let ctx = CString::from_vec_unchecked(b"fogpack".to_vec());
        libsodium_sys::crypto_kdf_derive_from_key(id.0.as_mut_ptr(), id.0.len(), 1, ctx.as_ptr(), k.0.as_ptr());
    };
}

pub fn blake2b( hash: &mut [u8; HASH_BYTES], data: &[u8] ) {
    if data.len() > ::std::u64::MAX as usize {
        panic!("Data for hasher is somehow larger than maximum u64 value");
    }
    lib_init();
    // The below will only fail if we set up this function wrong.
    unsafe { 
        libsodium_sys::crypto_generichash_blake2b(
            hash.as_mut_ptr(), HASH_BYTES, 
            data.as_ptr(), data.len() as u64,
            ::std::ptr::null(), 0);
    }
}

pub fn calc_secret(pk: &PublicCryptKey, sk: &SecretCryptKey) -> Result<SecretKey,CryptoError> {
    lib_init();
    // This can fail with a bad key, so it must be checked
    let mut k: SecretKey = Default::default();
    if unsafe { 
        libsodium_sys::crypto_box_curve25519xchacha20poly1305_beforenm(
            k.0.as_mut_ptr(), pk.0.as_ptr(), sk.0.as_ptr())
    } >= 0 {
        Ok(k)
    }
    else {
        Err(CryptoError::BadKey)
    }
}

pub fn crypt_keypair(pk: &mut PublicCryptKey, sk: &mut SecretCryptKey) {
    lib_init();
    unsafe { libsodium_sys::crypto_box_keypair(pk.0.as_mut_ptr(), sk.0.as_mut_ptr()) };
}

pub fn sign_keypair(pk: &mut PublicSignKey, sk: &mut SecretSignKey) {
    lib_init();
    unsafe { libsodium_sys::crypto_sign_keypair(pk.0.as_mut_ptr(),sk.0.as_mut_ptr()) };
}

pub fn sign_seed_keypair(pk: &mut PublicSignKey, sk: &mut SecretSignKey, seed: &Seed) {
    lib_init();
    unsafe { libsodium_sys::crypto_sign_seed_keypair(pk.0.as_mut_ptr(),sk.0.as_mut_ptr(), seed.0.as_ptr()) };
}

pub fn ed25519_sk_to_pk(pk: &mut PublicSignKey, sk: &SecretSignKey) {
    lib_init();
    unsafe { libsodium_sys::crypto_sign_ed25519_sk_to_pk(pk.0.as_mut_ptr(),sk.0.as_ptr()) };
}

pub fn ed25519_sk_to_seed(seed: &mut Seed, ed: &SecretSignKey) {
    lib_init();
    unsafe { libsodium_sys::crypto_sign_ed25519_sk_to_seed(seed.0.as_mut_ptr(),ed.0.as_ptr()) };
}

pub fn ed25519_sk_to_curve25519(curve: &mut SecretCryptKey, ed: &SecretSignKey) {
    lib_init();
    unsafe { libsodium_sys::crypto_sign_ed25519_sk_to_curve25519(curve.0.as_mut_ptr(),ed.0.as_ptr()) };
}

pub fn ed25519_pk_to_curve25519_pk(
    curve: &mut PublicCryptKey,
    ed: &PublicSignKey,
) -> Result<(), CryptoError>
{
    lib_init();
    // Can actually fail with a bad key, so check it
    if unsafe {
        libsodium_sys::crypto_sign_ed25519_pk_to_curve25519(curve.0.as_mut_ptr(),ed.0.as_ptr())
    } >= 0 {
        Ok(())
    }
    else {
        Err(CryptoError::BadKey)
    }
}

pub fn sign_detached(k: &SecretSignKey, m: &[u8]) -> Sign {
    lib_init();
    let mut sig: Sign = Default::default();
    unsafe { libsodium_sys::crypto_sign_ed25519_detached(
            sig.0.as_mut_ptr(),
            ptr::null_mut(),
            m.as_ptr(),
            m.len() as c_ulonglong,
            k.0.as_ptr());
    };
    sig
}

pub fn verify_detached(k: &PublicSignKey, m: &[u8], sig: &Sign) -> bool {
    lib_init();
    // Verify was successful if non-negative
    0 <= unsafe {
        libsodium_sys::crypto_sign_ed25519_verify_detached(
            sig.0.as_ptr(),
            m.as_ptr(),
            m.len() as c_ulonglong,
            k.0.as_ptr())
    }
}


pub fn memzero(x: &mut [u8]) {
    lib_init();
    unsafe { libsodium_sys::sodium_memzero(x.as_mut_ptr() as *mut _, x.len()); }
}

pub fn randombytes(x: &mut [u8]) {
    lib_init();
    unsafe { libsodium_sys::randombytes_buf(x.as_mut_ptr() as *mut _, x.len()); }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BEFORE_NM_BYTES: usize = libsodium_sys::crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES as usize;

    #[test]
    fn correct_sizes() {
        assert_eq!(BEFORE_NM_BYTES, SECRET_KEY_BYTES);
    }
}
