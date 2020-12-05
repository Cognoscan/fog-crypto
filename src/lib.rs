/*!
Provides basic cryptographic functionality. Key management, encryption, and signing are all 
done via a Vault. Before using anything, `crypto::init()` must be called.

A Vault is created using a password, or can be read in (either from a raw byte slice or from a 
file). It can then be used to create "permanent" keys and "temporary" keys. The only difference is 
that temporary keys are not saved when the Vault is saved off.
*/

//use std::collections::HashMap;
//use std::fs::File;
//use std::io::{Write,BufReader, Read, ErrorKind};
//use byteorder::ReadBytesExt;
//use std::io;
//
//mod sodium;
//mod error;
//mod hash;
//mod key;
//mod stream;
//mod lockbox;
//
//use self::key::{FullIdentity};
//use self::stream::FullStreamKey;
//
//pub use self::error::CryptoError;
//pub use self::hash::{Hash, HashState};
//pub use self::key::{Signature, FullKey, Key, Identity};
//pub use self::stream::StreamKey;
//pub use self::lockbox::Lockbox;
//
//use self::sodium::{Tag, Nonce, PasswordConfig, SecretKey};

/// Initializes the underlying crypto library and makes all random number generation functions 
/// thread-safe. *Must* be called successfully before using the rest of this library.
pub fn init() -> Result<(), ()> {
    sodium::init()
}

/// Contains either the Key, StreamKey or data that was in the Lockbox
//#[derive(Debug)]
//pub enum LockboxContent {
//    Key(Key),
//    StreamKey(StreamKey),
//    Data(Vec<u8>),
//}
//
//#[derive(Clone, Copy, Debug)]
//enum LockboxType {
//    Key,
//    StreamKey,
//    Data,
//}
//
//impl LockboxType {
//    fn from_u8(i: u8) -> Option<LockboxType> {
//        match i {
//            1 => Some(LockboxType::Key),
//            2 => Some(LockboxType::StreamKey),
//            3 => Some(LockboxType::Data),
//            _ => None
//        }
//    }
//    fn into_u8(self) -> u8 {
//        match self {
//            LockboxType::Key       => 1,
//            LockboxType::StreamKey => 2,
//            LockboxType::Data      => 3,
//        }
//    }
//}
//
/// The level of security to be provided by a password hashing function.
#[derive(Clone, Copy, Debug)]
pub enum PasswordLevel {
    /// For online, reasonably fast password unlock. Requires 64 MiB of RAM.
    Interactive,
    /// Longer password unlock. Requires 256 MiB of RAM.
    Moderate,
    /// For sensitive, non-interactive operations. Requires 1024 MiB of RAM.
    Sensitive,
}

// Plan: We move all encrypt functions into the key itself. For decryption of lockboxes, we have a 
// conundrum: we don't know if we can decrypt it ahead of time, and also a decrypted lockbox may 
// contain a key - the type of lockbox is purposely obscured, remember. Should it be???

trait Key {
    fn encrypt(v:

// The Vault must be easy to clone, send, sync, etc. This would mean hiding your implementation 
// behind a Mutex, or putting it in a separate thread/task and having it process requests with 
// responses (my favorite!)
trait Vault {
    fn new_perm_key(&self) -> Key;
    fn new_perm_stream(&self) -> StreamKey;
    fn new_temp_key(&self) -> Key;
    fn new_temp_stream(&self) -> StreamKey;

    fn find_key(&self, id: Identity) -> Option<Key>;
    fn find_stream(&self, stream: StreamId) -> Option<Key>;

    fn drop_key(&self, key: Key) -> bool;
    fn drop_stream(&self, stream: StreamKey) -> bool;

    fn decrypt(&self, lock:


    fn find_key
}

trait Key {
    fn version(&self) -> u8;



New key/stream -> Return key/stream
Find key/stream -> Result<key/stream>
Drop key/stream -> bool, which is true if it was found and deleted
Decrypt Lockbox -> Result<LockboxContent, CryptoError>

































