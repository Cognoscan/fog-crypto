/**
Lockbox for holding encrypted data.
 */
use crate::{
    signing::IdentityKey,
    lock::{LockKey, LockId},
    stream::{
        StreamId,
        StreamKey,
        MIN_STREAM_VERSION,
        MAX_STREAM_VERSION,
        stream_id_size,
    },
    CryptoError,
    Vault,
};

use std::{
    fmt,
    convert::TryFrom
};

const V1_LOCKBOX_NONCE_SIZE: usize = 24;
const V1_LOCKBOX_TAG_SIZE: usize = 16;

/// Get expected size of a Lockbox's nonce for a given version. Version *must* be validated before 
/// calling this.
pub(crate) fn lockbox_nonce_size(_version: u8) -> usize {
    V1_LOCKBOX_NONCE_SIZE
}

/// Get expected size of a Lockbox's AEAD tag for a given version. Version *must* be validated 
/// before calling this.
pub(crate) fn lockbox_tag_size(_version: u8) -> usize {
    V1_LOCKBOX_TAG_SIZE
}


pub enum LockboxTag {
    IdentityKey,
    LockKey,
    StreamKey,
    Data,
}

impl TryFrom<u8> for LockboxTag {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(LockboxTag::IdentityKey),
            2 => Ok(LockboxTag::LockKey),
            3 => Ok(LockboxTag::StreamKey),
            4 => Ok(LockboxTag::Data),
            _ => Err(value),
        }
    }
}

impl From<LockboxTag> for u8 {
    fn from(value: LockboxTag) -> Self {
        match value {
            LockboxTag::IdentityKey => 1,
            LockboxTag::LockKey     => 2,
            LockboxTag::StreamKey   => 3,
            LockboxTag::Data        => 4,
        }
    }
}

pub struct Lockbox {
    recipient: LockboxRecipient,
    inner: Vec<u8>,
}

impl Lockbox {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, CryptoError> {
        let (version, parse) = raw.split_first()
            .ok_or(CryptoError::BadLength {
                step: "get lockbox version",
                expected: 1,
                actual: 0
            })?;
        let version = *version;
        if version < MIN_STREAM_VERSION || version > MAX_STREAM_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        let (boxtype, parse) = parse.as_ref().split_first()
            .ok_or(CryptoError::BadLength {
                step: "get lockbox type",
                expected: 1,
                actual: 0
            })?;
        match boxtype {
            1 => {
                todo!()
            },
            2 => {
                // Check the length
                let id_len = stream_id_size(version);
                let nonce_len = lockbox_nonce_size(version);
                let tag_len = lockbox_tag_size(version);
                if parse.len() < (1+id_len + nonce_len + tag_len) {
                    return Err(CryptoError::BadLength {
                        step: "get lockbox component lengths",
                        expected: id_len+nonce_len+tag_len+1,
                        actual: parse.len()
                    })?;
                }
                // Extract the StreamId
                let (raw_id, _) = parse.split_at(id_len);
                let id = StreamId::try_from(raw_id)?;
                // Compare the StreamId & version byte. We can't use stream keys that differ from 
                // the lockbox version because they're supposed to literally be the same algorithm!
                if id.version() != version {
                    return Err(CryptoError::BadFormat);
                }
                Ok(Self {
                    recipient: LockboxRecipient::StreamId(id),
                    inner: Vec::from(raw),
                })
            },
            _ => return Err(CryptoError::BadFormat),
        }
    }

    /// Get the version of the Lockbox.
    pub fn version(&self) -> u8 {
        self.inner[0]
    }

    /// Get the target recipient who should be able to decrypt the lockbox.
    pub fn recipient(&self) -> &LockboxRecipient {
        &self.recipient
    }

    pub fn as_bytes(&self) -> &[u8] {
        todo!()
    }

    /// Try to decrypt the lockbox using any keys known by a given vault
    pub fn try_decrypt(&self, vault: &dyn Vault) -> Result<LockboxContent, CryptoError> {
        todo!()
    }
}

impl TryFrom<&[u8]> for Lockbox {
    type Error = CryptoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Lockbox::from_bytes(value)
    }
}

/// Lockboxes can be meant for one of two types of recipients: a LockId (public key), or a 
/// StreamId (symmetric key).
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum LockboxRecipient {
    LockId(LockId),
    StreamId(StreamId),
}

/// Lockboxes hold one of 4 types of data: an `IdentityKey`, a `LockKey`, a `StreamKey`, or a 
/// generic byte vector.
#[derive(Debug)]
pub enum LockboxContent {
    IdentityKey(IdentityKey),
    LockKey(LockKey),
    StreamKey(StreamKey),
    Data(Vec<u8>),
}

