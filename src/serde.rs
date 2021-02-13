//! [`serde`](https://serde.rs/) support.
//!
//! This module is optionally compiled if the `with-serde` feature is enabled (which is the
//! default). Each type is serialized as though it were part of an enum, with each specific type
//! being an enum variant. The enum indexing and naming matches up with `fog-pack`'s encoding
//! scheme for these types. Supported types for serialization & deserialization are `Hash`,
//! `Identity`, `LockId`, `StreamId`, and all the lockbox types.
//!
//! The types will all serialize as bytes if the serializer is not marked as human-readable. If
//! human-readable, the `Hash`, `Identity`, `StreamId`, and `LockId` types will serialize as base58
//! strings (much like other public keys in a post-blockchain world), while the lockbox types will
//! serialize as base64 strings.
//!
//! Finally, since human-readable formats require base64 encode/decode for lockboxes, the `Ref`
//! variants used for zero-copy decoding are not supported in those instances.

/// Name marker used for the library's fictional Enum type
pub const FOG_TYPE_ENUM: &str = "_FogType";
/// Enum variant name for [`Hash`](crate::hash::Hash)
pub const FOG_TYPE_ENUM_HASH_NAME: &str = "Hash";
/// Enum variant name for [`Identity`](crate::identity::Identity)
pub const FOG_TYPE_ENUM_IDENTITY_NAME: &str = "Identity";
/// Enum variant name for [`LockId`](crate::lock::LockId)
pub const FOG_TYPE_ENUM_LOCK_ID_NAME: &str = "LockId";
/// Enum variant name for [`StreamId`](crate::stream::StreamId)
pub const FOG_TYPE_ENUM_STREAM_ID_NAME: &str = "StreamId";
/// Enum variant name for [`DataLockbox`](crate::lockbox::DataLockbox)
pub const FOG_TYPE_ENUM_DATA_LOCKBOX_NAME: &str = "DataLockbox";
/// Enum variant name for [`IdentityLockbox`](crate::lockbox::IdentityLockbox)
pub const FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME: &str = "IdentityLockbox";
/// Enum variant name for [`StreamLockbox`](crate::lockbox::StreamLockbox)
pub const FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME: &str = "StreamLockbox";
/// Enum variant name for [`LockLockbox`](crate::lockbox::LockLockbox)
pub const FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME: &str = "LockLockbox";

/// Enum variant index for [`Hash`](crate::hash::Hash)
pub const FOG_TYPE_ENUM_HASH_INDEX: u64 = 1;
/// Enum variant index for [`Identity`](crate::identity::Identity)
pub const FOG_TYPE_ENUM_IDENTITY_INDEX: u64 = 2;
/// Enum variant index for [`LockId`](crate::lock::LockId)
pub const FOG_TYPE_ENUM_LOCK_ID_INDEX: u64 = 3;
/// Enum variant index for [`StreamId`](crate::stream::StreamId)
pub const FOG_TYPE_ENUM_STREAM_ID_INDEX: u64 = 4;
/// Enum variant index for [`DataLockbox`](crate::lockbox::DataLockbox)
pub const FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX: u64 = 5;
/// Enum variant index for [`IdentityLockbox`](crate::lockbox::IdentityLockbox)
pub const FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX: u64 = 6;
/// Enum variant index for [`StreamLockbox`](crate::lockbox::StreamLockbox)
pub const FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX: u64 = 7;
/// Enum variant index for [`LockLockbox`](crate::lockbox::LockLockbox)
pub const FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX: u64 = 8;

const VARIANTS: &[&str] = &[
    FOG_TYPE_ENUM,
    FOG_TYPE_ENUM_HASH_NAME,
    FOG_TYPE_ENUM_IDENTITY_NAME,
    FOG_TYPE_ENUM_LOCK_ID_NAME,
    FOG_TYPE_ENUM_STREAM_ID_NAME,
    FOG_TYPE_ENUM_DATA_LOCKBOX_NAME,
    FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME,
    FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME,
    FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME,
];

use crate::{hash::Hash, identity::Identity, lock::LockId, lockbox::*, stream::StreamId};

use serde::{
    de::{Deserialize, Deserializer, EnumAccess, Error, Unexpected, VariantAccess, Visitor},
    ser::{Serialize, Serializer},
};
use serde_bytes::{ByteBuf, Bytes};
use std::{convert::TryFrom, fmt};

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = self.to_base58();
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_HASH_INDEX as u32,
                FOG_TYPE_ENUM_HASH_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_ref());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_HASH_INDEX as u32,
                FOG_TYPE_ENUM_HASH_NAME,
                value,
            )
        }
    }
}

impl Serialize for Identity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = self.to_base58();
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_IDENTITY_INDEX as u32,
                FOG_TYPE_ENUM_IDENTITY_NAME,
                &value,
            )
        } else {
            let value = ByteBuf::from(self.as_vec());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_IDENTITY_INDEX as u32,
                FOG_TYPE_ENUM_IDENTITY_NAME,
                &value,
            )
        }
    }
}

impl Serialize for StreamId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = self.to_base58();
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_STREAM_ID_INDEX as u32,
                FOG_TYPE_ENUM_STREAM_ID_NAME,
                &value,
            )
        } else {
            let value = ByteBuf::from(self.as_vec());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_STREAM_ID_INDEX as u32,
                FOG_TYPE_ENUM_STREAM_ID_NAME,
                &value,
            )
        }
    }
}

impl Serialize for LockId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = self.to_base58();
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_LOCK_ID_INDEX as u32,
                FOG_TYPE_ENUM_LOCK_ID_NAME,
                &value,
            )
        } else {
            let value = ByteBuf::from(self.as_vec());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_LOCK_ID_INDEX as u32,
                FOG_TYPE_ENUM_LOCK_ID_NAME,
                &value,
            )
        }
    }
}

impl Serialize for DataLockbox {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_DATA_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_DATA_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

impl Serialize for DataLockboxRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_DATA_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_DATA_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

impl Serialize for IdentityLockbox {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

impl Serialize for IdentityLockboxRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

impl Serialize for StreamLockbox {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

impl Serialize for StreamLockboxRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

impl Serialize for LockLockbox {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

impl Serialize for LockLockboxRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = base64::encode(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME,
                &value,
            )
        } else {
            let value = Bytes::new(self.as_bytes());
            serializer.serialize_newtype_variant(
                FOG_TYPE_ENUM,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX as u32,
                FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME,
                &value,
            )
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Deserialization
///////////////////////////////////////////////////////////////////////////////

enum CryptoEnum {
    Hash,
    Identity,
    LockId,
    StreamId,
    DataLockbox,
    IdentityLockbox,
    StreamLockbox,
    LockLockbox,
}

impl CryptoEnum {
    fn as_str(&self) -> &'static str {
        use CryptoEnum::*;
        match *self {
            Hash => "Hash",
            Identity => "Identity",
            LockId => "LockId",
            StreamId => "StreamId",
            DataLockbox => "DataLockbox",
            IdentityLockbox => "IdentityLockbox",
            StreamLockbox => "StreamLockbox",
            LockLockbox => "LockLockbox",
        }
    }
}

struct CryptoEnumVisitor;
impl<'de> Visitor<'de> for CryptoEnumVisitor {
    type Value = CryptoEnum;
    fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "variant identifier")
    }

    fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
        match v {
            FOG_TYPE_ENUM_HASH_INDEX => Ok(CryptoEnum::Hash),
            FOG_TYPE_ENUM_IDENTITY_INDEX => Ok(CryptoEnum::Identity),
            FOG_TYPE_ENUM_LOCK_ID_INDEX => Ok(CryptoEnum::LockId),
            FOG_TYPE_ENUM_STREAM_ID_INDEX => Ok(CryptoEnum::StreamId),
            FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX => Ok(CryptoEnum::DataLockbox),
            FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX => Ok(CryptoEnum::IdentityLockbox),
            FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX => Ok(CryptoEnum::StreamLockbox),
            FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX => Ok(CryptoEnum::LockLockbox),
            _ => Err(E::invalid_value(
                serde::de::Unexpected::Unsigned(v as u64),
                &"variant index 1 <= i <= 8",
            )),
        }
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
        match v {
            FOG_TYPE_ENUM_HASH_NAME => Ok(CryptoEnum::Hash),
            FOG_TYPE_ENUM_IDENTITY_NAME => Ok(CryptoEnum::Identity),
            FOG_TYPE_ENUM_LOCK_ID_NAME => Ok(CryptoEnum::LockId),
            FOG_TYPE_ENUM_STREAM_ID_NAME => Ok(CryptoEnum::StreamId),
            FOG_TYPE_ENUM_DATA_LOCKBOX_NAME => Ok(CryptoEnum::DataLockbox),
            FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME => Ok(CryptoEnum::IdentityLockbox),
            FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME => Ok(CryptoEnum::StreamLockbox),
            FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME => Ok(CryptoEnum::LockLockbox),
            _ => Err(E::unknown_variant(v, VARIANTS)),
        }
    }

    fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let v = std::str::from_utf8(v).map_err(|_| {
            let v = String::from_utf8_lossy(v);
            E::unknown_variant(v.as_ref(), VARIANTS)
        })?;
        match v {
            FOG_TYPE_ENUM_HASH_NAME => Ok(CryptoEnum::Hash),
            FOG_TYPE_ENUM_IDENTITY_NAME => Ok(CryptoEnum::Identity),
            FOG_TYPE_ENUM_LOCK_ID_NAME => Ok(CryptoEnum::LockId),
            FOG_TYPE_ENUM_STREAM_ID_NAME => Ok(CryptoEnum::StreamId),
            FOG_TYPE_ENUM_DATA_LOCKBOX_NAME => Ok(CryptoEnum::DataLockbox),
            FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME => Ok(CryptoEnum::IdentityLockbox),
            FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME => Ok(CryptoEnum::StreamLockbox),
            FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME => Ok(CryptoEnum::LockLockbox),
            _ => Err(E::unknown_variant(v, VARIANTS)),
        }
    }
}
impl<'de> Deserialize<'de> for CryptoEnum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(CryptoEnumVisitor)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for HashVisitor {
            type Value = Hash;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM, FOG_TYPE_ENUM_HASH_NAME, FOG_TYPE_ENUM_HASH_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::Hash, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"Hash",
                        ))
                    }
                };
                if self.is_human_readable {
                    let base58: String = variant.newtype_variant()?;
                    Hash::from_base58(&base58).map_err(|e| A::Error::custom(e.serde_err()))
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    Hash::try_from(bytes.as_ref()).map_err(|e| A::Error::custom(e.serde_err()))
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_HASH_NAME],
            HashVisitor { is_human_readable },
        )
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdentityVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for IdentityVisitor {
            type Value = Identity;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM, FOG_TYPE_ENUM_IDENTITY_NAME, FOG_TYPE_ENUM_IDENTITY_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::Identity, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"Identity",
                        ))
                    }
                };
                if self.is_human_readable {
                    let base58: String = variant.newtype_variant()?;
                    Identity::from_base58(&base58).map_err(|e| A::Error::custom(e.serde_err()))
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    Identity::try_from(bytes.as_ref()).map_err(|e| A::Error::custom(e.serde_err()))
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_IDENTITY_NAME],
            IdentityVisitor { is_human_readable },
        )
    }
}

impl<'de> Deserialize<'de> for StreamId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StreamIdVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for StreamIdVisitor {
            type Value = StreamId;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM, FOG_TYPE_ENUM_STREAM_ID_NAME, FOG_TYPE_ENUM_STREAM_ID_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::StreamId, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"StreamId",
                        ))
                    }
                };
                if self.is_human_readable {
                    let base58: String = variant.newtype_variant()?;
                    StreamId::from_base58(&base58).map_err(|e| A::Error::custom(e.serde_err()))
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    StreamId::try_from(bytes.as_ref()).map_err(|e| A::Error::custom(e.serde_err()))
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_STREAM_ID_NAME],
            StreamIdVisitor { is_human_readable },
        )
    }
}

impl<'de> Deserialize<'de> for LockId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockIdVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for LockIdVisitor {
            type Value = LockId;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM, FOG_TYPE_ENUM_LOCK_ID_NAME, FOG_TYPE_ENUM_LOCK_ID_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::LockId, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"LockId",
                        ))
                    }
                };
                if self.is_human_readable {
                    let base58: String = variant.newtype_variant()?;
                    LockId::from_base58(&base58).map_err(|e| A::Error::custom(e.serde_err()))
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    LockId::try_from(bytes.as_ref()).map_err(|e| A::Error::custom(e.serde_err()))
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_LOCK_ID_NAME],
            LockIdVisitor { is_human_readable },
        )
    }
}

impl<'de> Deserialize<'de> for DataLockbox {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = DataLockbox;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_DATA_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::DataLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"DataLockbox",
                        ))
                    }
                };
                if self.is_human_readable {
                    let v: String = variant.newtype_variant()?;
                    let bytes = base64::decode(v).map_err(|_| A::Error::custom(""))?;
                    Ok(DataLockboxRef::from_bytes(&bytes[..])
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    Ok(DataLockboxRef::from_bytes(&bytes)
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_DATA_LOCKBOX_NAME],
            LockboxVisitor { is_human_readable },
        )
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for &'a DataLockboxRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor;

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = &'de DataLockboxRef;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_DATA_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_DATA_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::DataLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"DataLockbox",
                        ))
                    }
                };
                let bytes: &Bytes = variant.newtype_variant()?;
                DataLockboxRef::from_bytes(&bytes).map_err(|e| A::Error::custom(e.serde_err()))
            }
        }
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_DATA_LOCKBOX_NAME],
            LockboxVisitor,
        )
    }
}

impl<'de> Deserialize<'de> for IdentityLockbox {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = IdentityLockbox;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::IdentityLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"IdentityLockbox",
                        ))
                    }
                };
                if self.is_human_readable {
                    let v: String = variant.newtype_variant()?;
                    let bytes = base64::decode(v).map_err(|_| A::Error::custom(""))?;
                    Ok(IdentityLockboxRef::from_bytes(&bytes[..])
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    Ok(IdentityLockboxRef::from_bytes(&bytes)
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME],
            LockboxVisitor { is_human_readable },
        )
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for &'a IdentityLockboxRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor;

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = &'de IdentityLockboxRef;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_IDENTITY_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::IdentityLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"IdentityLockbox",
                        ))
                    }
                };
                let bytes: &Bytes = variant.newtype_variant()?;
                IdentityLockboxRef::from_bytes(&bytes).map_err(|e| A::Error::custom(e.serde_err()))
            }
        }
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_IDENTITY_LOCKBOX_NAME],
            LockboxVisitor,
        )
    }
}

impl<'de> Deserialize<'de> for StreamLockbox {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = StreamLockbox;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::StreamLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"StreamLockbox",
                        ))
                    }
                };
                if self.is_human_readable {
                    let v: String = variant.newtype_variant()?;
                    let bytes = base64::decode(v).map_err(|_| A::Error::custom(""))?;
                    Ok(StreamLockboxRef::from_bytes(&bytes[..])
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    Ok(StreamLockboxRef::from_bytes(&bytes)
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME],
            LockboxVisitor { is_human_readable },
        )
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for &'a StreamLockboxRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor;

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = &'de StreamLockboxRef;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_STREAM_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::StreamLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"StreamLockbox",
                        ))
                    }
                };
                let bytes: &Bytes = variant.newtype_variant()?;
                StreamLockboxRef::from_bytes(&bytes).map_err(|e| A::Error::custom(e.serde_err()))
            }
        }
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_STREAM_LOCKBOX_NAME],
            LockboxVisitor,
        )
    }
}

impl<'de> Deserialize<'de> for LockLockbox {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor {
            is_human_readable: bool,
        }

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = LockLockbox;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::LockLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"LockLockbox",
                        ))
                    }
                };
                if self.is_human_readable {
                    let v: String = variant.newtype_variant()?;
                    let bytes = base64::decode(v).map_err(|_| A::Error::custom(""))?;
                    Ok(LockLockboxRef::from_bytes(&bytes[..])
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                } else {
                    let bytes: &Bytes = variant.newtype_variant()?;
                    Ok(LockLockboxRef::from_bytes(&bytes)
                        .map_err(|e| A::Error::custom(e.serde_err()))?
                        .to_owned())
                }
            }
        }
        let is_human_readable = deserializer.is_human_readable();
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME],
            LockboxVisitor { is_human_readable },
        )
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for &'a LockLockboxRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LockboxVisitor;

        impl<'de> serde::de::Visitor<'de> for LockboxVisitor {
            type Value = &'de LockLockboxRef;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(
                    fmt,
                    "{} enum with variant {} (id {})",
                    FOG_TYPE_ENUM,
                    FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME,
                    FOG_TYPE_ENUM_LOCK_LOCKBOX_INDEX
                )
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                let variant = match data.variant()? {
                    (CryptoEnum::LockLockbox, variant) => variant,
                    (e, _) => {
                        return Err(A::Error::invalid_type(
                            Unexpected::Other(e.as_str()),
                            &"LockLockbox",
                        ))
                    }
                };
                let bytes: &Bytes = variant.newtype_variant()?;
                LockLockboxRef::from_bytes(&bytes).map_err(|e| A::Error::custom(e.serde_err()))
            }
        }
        deserializer.deserialize_enum(
            FOG_TYPE_ENUM,
            &[FOG_TYPE_ENUM_LOCK_LOCKBOX_NAME],
            LockboxVisitor,
        )
    }
}

mod test {

    // I have no idea why this gets marked as "unused"... because the code will not compile without
    // it 🙃
    #[allow(unused_imports)]
    use crate::{hash::Hash, identity::Identity, lock::LockId, lockbox::*, stream::StreamId};

    #[test]
    fn serde_json_hash() {
        let hash = Hash::new(b"I'm going to be hashed and turned to JSON, yay!");
        let json = serde_json::to_string(&hash).unwrap();
        println!("{}", json);
        let dec_hash: Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(dec_hash, hash);
    }

    #[test]
    fn bincode_hash() {
        let hash = Hash::new(b"I'm going to be hashed and turned to bincode, yay!");
        let bin = bincode::serialize(&hash).unwrap();
        println!("Original Hash: {:x?}", hash);
        println!("Bincode: {:x?}", bin);
        let dec_hash: Hash = bincode::deserialize(&bin).unwrap();
        assert_eq!(dec_hash, hash);
    }

    #[test]
    fn serde_json_identity() {
        let mut csprng = rand::rngs::OsRng {};
        let id = crate::IdentityKey::new_temp(&mut csprng).id().clone();
        let json = serde_json::to_string(&id).unwrap();
        println!("{}", json);
        let dec: Identity = serde_json::from_str(&json).unwrap();
        assert_eq!(dec, id);
    }

    #[test]
    fn bincode_identity() {
        let mut csprng = rand::rngs::OsRng {};
        let id = crate::IdentityKey::new_temp(&mut csprng).id().clone();
        let bin = bincode::serialize(&id).unwrap();
        println!("Original Id: {:x?}", id);
        println!("Bincode: {:x?}", bin);
        let dec: Identity = bincode::deserialize(&bin).unwrap();
        assert_eq!(dec, id);
    }

    #[test]
    fn serde_json_stream_id() {
        let mut csprng = rand::rngs::OsRng {};
        let id = crate::StreamKey::new_temp(&mut csprng).id().clone();
        let json = serde_json::to_string(&id).unwrap();
        println!("{}", json);
        let dec: StreamId = serde_json::from_str(&json).unwrap();
        assert_eq!(dec, id);
    }

    #[test]
    fn bincode_stream_id() {
        let mut csprng = rand::rngs::OsRng {};
        let id = crate::StreamKey::new_temp(&mut csprng).id().clone();
        let bin = bincode::serialize(&id).unwrap();
        println!("Original Id: {:x?}", id);
        println!("Bincode: {:x?}", bin);
        let dec: StreamId = bincode::deserialize(&bin).unwrap();
        assert_eq!(dec, id);
    }

    #[test]
    fn serde_json_lock_id() {
        let mut csprng = rand::rngs::OsRng {};
        let id = crate::LockKey::new_temp(&mut csprng).id().clone();
        let json = serde_json::to_string(&id).unwrap();
        println!("{}", json);
        let dec: LockId = serde_json::from_str(&json).unwrap();
        assert_eq!(dec, id);
    }

    #[test]
    fn bincode_lock_id() {
        let mut csprng = rand::rngs::OsRng {};
        let id = crate::LockKey::new_temp(&mut csprng).id().clone();
        let bin = bincode::serialize(&id).unwrap();
        println!("Original Id: {:x?}", id);
        println!("Bincode: {:x?}", bin);
        let dec: LockId = bincode::deserialize(&bin).unwrap();
        assert_eq!(dec, id);
    }

    #[test]
    fn serde_json_data_lockbox() {
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = b"Crypto in JSON, eh?";
        let lockbox = key.encrypt_data(&mut csprng, to_send);

        let json = serde_json::to_string(&lockbox).unwrap();
        println!("{}", json);

        let dec: DataLockbox = serde_json::from_str(&json).unwrap();
        let dec = key.decrypt_data(&dec).unwrap();
        assert_eq!(dec, to_send);
    }

    #[test]
    fn serde_json_data_lockbox_ref() {
        // Verify only that LockboxRef encodes the same way as main Lockbox
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = b"Crypto in JSON, eh?";
        let lockbox = key.encrypt_data(&mut csprng, to_send);
        // Encode & check
        let json1 = serde_json::to_string(&lockbox).unwrap();
        let lockbox_ref: &DataLockboxRef = lockbox.deref();
        let json2 = serde_json::to_string(lockbox_ref).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn bincode_data_lockbox() {
        // Set up crypto
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = b"Crypto in bincode, eh?";
        let lockbox = key.encrypt_data(&mut csprng, to_send);
        // Encode
        let bin = bincode::serialize(&lockbox).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: DataLockbox = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_data(&dec).unwrap();
        assert_eq!(dec, to_send);
    }

    #[test]
    fn bincode_data_lockbox_ref() {
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = b"Crypto in bincode, eh?";
        let lockbox = key.encrypt_data(&mut csprng, to_send);
        // Encode
        let lockbox_ref: &DataLockboxRef = lockbox.deref();
        let bin = bincode::serialize(lockbox_ref).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: &DataLockboxRef = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_data(&dec).unwrap();
        assert_eq!(dec, to_send);
    }

    #[test]
    fn serde_json_identity_lockbox() {
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::IdentityKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();

        let json = serde_json::to_string(&lockbox).unwrap();
        println!("{}", json);

        let dec: IdentityLockbox = serde_json::from_str(&json).unwrap();
        let dec = key.decrypt_identity_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn serde_json_identity_lockbox_ref() {
        // Verify only that LockboxRef encodes the same way as main Lockbox
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::IdentityKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode & check
        let json1 = serde_json::to_string(&lockbox).unwrap();
        let lockbox_ref: &IdentityLockboxRef = lockbox.deref();
        let json2 = serde_json::to_string(lockbox_ref).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn bincode_identity_lockbox() {
        // Set up crypto
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::IdentityKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode
        let bin = bincode::serialize(&lockbox).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: IdentityLockbox = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_identity_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn bincode_identity_lockbox_ref() {
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::IdentityKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode
        let lockbox_ref: &IdentityLockboxRef = lockbox.deref();
        let bin = bincode::serialize(lockbox_ref).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: &IdentityLockboxRef = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_identity_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn serde_json_stream_lockbox() {
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::StreamKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();

        let json = serde_json::to_string(&lockbox).unwrap();
        println!("{}", json);

        let dec: StreamLockbox = serde_json::from_str(&json).unwrap();
        let dec = key.decrypt_stream_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn serde_json_stream_lockbox_ref() {
        // Verify only that LockboxRef encodes the same way as main Lockbox
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::StreamKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode & check
        let json1 = serde_json::to_string(&lockbox).unwrap();
        let lockbox_ref: &StreamLockboxRef = lockbox.deref();
        let json2 = serde_json::to_string(lockbox_ref).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn bincode_stream_lockbox() {
        // Set up crypto
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::StreamKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode
        let bin = bincode::serialize(&lockbox).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: StreamLockbox = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_stream_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn bincode_stream_lockbox_ref() {
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::StreamKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode
        let lockbox_ref: &StreamLockboxRef = lockbox.deref();
        let bin = bincode::serialize(lockbox_ref).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: &StreamLockboxRef = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_stream_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn serde_json_lock_lockbox() {
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::LockKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();

        let json = serde_json::to_string(&lockbox).unwrap();
        println!("{}", json);

        let dec: LockLockbox = serde_json::from_str(&json).unwrap();
        let dec = key.decrypt_lock_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn serde_json_lock_lockbox_ref() {
        // Verify only that LockboxRef encodes the same way as main Lockbox
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::LockKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode & check
        let json1 = serde_json::to_string(&lockbox).unwrap();
        let lockbox_ref: &LockLockboxRef = lockbox.deref();
        let json2 = serde_json::to_string(lockbox_ref).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn bincode_lock_lockbox() {
        // Set up crypto
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::LockKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode
        let bin = bincode::serialize(&lockbox).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: LockLockbox = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_lock_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }

    #[test]
    fn bincode_lock_lockbox_ref() {
        // Set up crypto
        use std::ops::Deref;
        let mut csprng = rand::rngs::OsRng {};
        let key = crate::StreamKey::new_temp(&mut csprng);
        let to_send = crate::LockKey::new_temp(&mut csprng);
        let lockbox = to_send.export_for_stream(&mut csprng, &key).unwrap();
        // Encode
        let lockbox_ref: &LockLockboxRef = lockbox.deref();
        let bin = bincode::serialize(lockbox_ref).unwrap();
        println!("Original Lockbox: {:x?}", lockbox);
        println!("Bincode: {:x?}", bin);
        // Decode & check
        let dec: &LockLockboxRef = bincode::deserialize(&bin).unwrap();
        let dec = key.decrypt_lock_key(&dec).unwrap();
        assert_eq!(dec.id(), to_send.id());
    }
}
