// Copyright © 2024 The Johns Hopkins Applied Physics Laboratory LLC.
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License,
// version 3, as published by the Free Software Foundation.  If you
// would like to purchase a commercial license for this software, please
// contact APL’s Tech Transfer at 240-592-0817 or
// techtransfer@jhuapl.edu.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

//! Wrapper types for cryptographic hashes and IDs generated from them.
use std::array::TryFromSliceError;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;

use blake2::Blake2b512;
use digest::Digest;
use ripemd::Ripemd160;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use sha2::Sha384;
use sha3::Sha3_512;
use skein::consts::U64;
use skein::Skein512;
use whirlpool::Whirlpool;

use crate::codec::DatagramCodec;

/// Trait for IDs generated from hashing a more complex type.
pub trait HashID: Sized {
    /// Get the name of the hash function used for this ID.
    fn name(&self) -> &str;

    /// Get the bytes of the hashed value.
    fn bytes(&self) -> &[u8];
}

/// Trait for specific cryptographic hash algorithms.
pub trait HashAlgo {
    type HashID: HashID;

    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError>;

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID;

    #[inline]
    fn null_hash(&self) -> Self::HashID {
        self.hash_bytes(&[])
    }

    fn hashid<T, Codec>(
        &self,
        codec: &mut Codec,
        val: &T
    ) -> Result<Self::HashID, Codec::EncodeError>
    where
        Codec: DatagramCodec<T> {
        let encoded = codec.encode_to_vec(val)?;

        Ok(self.hash_bytes(&encoded))
    }
}

/// [HashAlgo] using the Blake2b algorithm.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2bAlgo;

/// [HashID] using the Blake2b algorithm.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blake2bID {
    id: [u8; Self::HASH_LEN]
}

/// [HashAlgo] using the RipeMD-160 algorithm.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RipeMD160Algo;

/// [HashID] using the RipeMD-160 algorithm.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RipeMD160ID {
    id: [u8; Self::HASH_LEN]
}

/// [HashAlgo] using the SHA3-512 algorithm.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SHA3Algo;

/// [HashID] using the SHA3-512 algorithm.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SHA3ID {
    id: [u8; Self::HASH_LEN]
}

/// [HashAlgo] using the SHA384 (SHA2-384) algorithm.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SHA384Algo;

/// [HashID] using the SHA384 (SHA2-384) algorithm.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SHA384ID {
    id: [u8; Self::HASH_LEN]
}

/// [HashAlgo] using the Skein algorithm.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SkeinAlgo;

/// [HashID] using the Skein algorithm.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SkeinID {
    id: [u8; Self::HASH_LEN]
}

/// [HashAlgo] using the Whirlpool algorithm.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WhirlpoolAlgo;

/// [HashID] using the Whirlpool algorithm.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WhirlpoolID {
    id: [u8; Self::HASH_LEN]
}

/// [HashAlgo] instance capable of using a dynamically-configured hash
/// function.
///
/// This also can serve as a configuration object, and can be deserialized.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(try_from = "&'_ str")]
pub enum CompoundHashAlgo {
    /// The Blake2b hash algorithm.
    Blake2b { blake2b: Blake2bAlgo },
    /// The RipeMD-160 hash algorithm.
    RipeMD160 { ripemd160: RipeMD160Algo },
    /// The SHA3-512 hash algorithm.
    SHA3 { sha3: SHA3Algo },
    /// The SHA384 hash algorithm.
    SHA384 { sha384: SHA384Algo },
    /// The Skein-512 hash algorithm.
    Skein { skein: SkeinAlgo },
    /// The Whirlpool hash algorithm.
    Whirlpool { whirlpool: WhirlpoolAlgo }
}

/// [HashID] instance representing an ID generated from a
/// dynamically-configured hash algorithm.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CompoundHashID {
    /// ID generated from the Blake2b algorithm.
    Blake2b { blake2b: Blake2bID },
    /// ID generated from the RipeMD-160 algorithm.
    RipeMD160 { ripemd160: RipeMD160ID },
    /// ID generated from the SHA3-512 algorithm.
    SHA3 { sha3: SHA3ID },
    /// ID generated from the SHA384 algorithm.
    SHA384 { sha384: SHA384ID },
    /// ID generated from the Skein-512 algorithm.
    Skein { skein: SkeinID },
    /// ID generated from the Whirlpool algorithm.
    Whirlpool { whirlpool: WhirlpoolID }
}

impl HashAlgo for RipeMD160Algo {
    type HashID = RipeMD160ID;

    #[inline]
    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError> {
        let id = bytes.try_into()?;

        Ok(RipeMD160ID { id: id })
    }

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID {
        let mut hasher = Ripemd160::default();

        hasher.update(bytes);

        let hashed = hasher.finalize();
        let mut id = [0; RipeMD160ID::HASH_LEN];

        id.copy_from_slice(hashed.as_slice());

        RipeMD160ID { id: id }
    }
}

impl RipeMD160ID {
    const HASH_LEN: usize = 160 / 8;
}

impl HashID for RipeMD160ID {
    #[inline]
    fn name(&self) -> &str {
        "RipeMD-160"
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.id
    }
}

impl Display for RipeMD160ID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}:", self.name())?;

        for i in 0..Self::HASH_LEN {
            write!(f, "{:02x}", self.id[i])?;
        }

        Ok(())
    }
}

impl HashAlgo for Blake2bAlgo {
    type HashID = Blake2bID;

    #[inline]
    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError> {
        let id = bytes.try_into()?;

        Ok(Blake2bID { id: id })
    }

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID {
        let mut hasher = Blake2b512::default();

        hasher.update(bytes);

        let hashed = hasher.finalize();
        let mut id = [0; Blake2bID::HASH_LEN];

        id.copy_from_slice(hashed.as_slice());

        Blake2bID { id: id }
    }
}

impl Blake2bID {
    const HASH_LEN: usize = 512 / 8;
}

impl HashID for Blake2bID {
    #[inline]
    fn name(&self) -> &str {
        "Blake2b"
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.id
    }
}

impl Display for Blake2bID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}:", self.name())?;

        for i in 0..Self::HASH_LEN {
            write!(f, "{:02x}", self.id[i])?;
        }

        Ok(())
    }
}

impl HashAlgo for SHA3Algo {
    type HashID = SHA3ID;

    #[inline]
    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError> {
        let id = bytes.try_into()?;

        Ok(SHA3ID { id: id })
    }

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID {
        let mut hasher = Sha3_512::default();

        hasher.update(bytes);

        let hashed = hasher.finalize();
        let mut id = [0; SHA3ID::HASH_LEN];

        id.copy_from_slice(hashed.as_slice());

        SHA3ID { id: id }
    }
}

impl SHA3ID {
    const HASH_LEN: usize = 512 / 8;
}

impl HashID for SHA3ID {
    #[inline]
    fn name(&self) -> &str {
        "SHA3-512"
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.id
    }
}

impl Display for SHA3ID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}:", self.name())?;

        for i in 0..Self::HASH_LEN {
            write!(f, "{:02x}", self.id[i])?;
        }

        Ok(())
    }
}

impl HashAlgo for SHA384Algo {
    type HashID = SHA384ID;

    #[inline]
    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError> {
        let id = bytes.try_into()?;

        Ok(SHA384ID { id: id })
    }

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID {
        let mut hasher = Sha384::default();

        hasher.update(bytes);

        let hashed = hasher.finalize();
        let mut id = [0; SHA384ID::HASH_LEN];

        id.copy_from_slice(hashed.as_slice());

        SHA384ID { id: id }
    }
}

impl SHA384ID {
    const HASH_LEN: usize = 384 / 8;
}

impl HashID for SHA384ID {
    #[inline]
    fn name(&self) -> &str {
        "SHA384"
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.id
    }
}

impl Display for SHA384ID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}:", self.name())?;

        for i in 0..Self::HASH_LEN {
            write!(f, "{:02x}", self.id[i])?;
        }

        Ok(())
    }
}

impl HashAlgo for SkeinAlgo {
    type HashID = SkeinID;

    #[inline]
    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError> {
        let id = bytes.try_into()?;

        Ok(SkeinID { id: id })
    }

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID {
        let mut hasher = Skein512::<U64>::new();

        hasher.update(bytes);

        let hashed = hasher.finalize();
        let mut id = [0; SkeinID::HASH_LEN];

        id.copy_from_slice(hashed.as_slice());

        SkeinID { id: id }
    }
}

impl SkeinID {
    const HASH_LEN: usize = 512 / 8;
}

impl HashID for SkeinID {
    #[inline]
    fn name(&self) -> &str {
        "Skein-512"
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.id
    }
}

impl Display for SkeinID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}:", self.name())?;

        for i in 0..Self::HASH_LEN {
            write!(f, "{:02x}", self.id[i])?;
        }

        Ok(())
    }
}

impl HashAlgo for WhirlpoolAlgo {
    type HashID = WhirlpoolID;

    #[inline]
    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError> {
        let id = bytes.try_into()?;

        Ok(WhirlpoolID { id: id })
    }

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID {
        let mut hasher = Whirlpool::default();

        hasher.update(bytes);

        let hashed = hasher.finalize();
        let mut id = [0; WhirlpoolID::HASH_LEN];

        id.copy_from_slice(hashed.as_slice());

        WhirlpoolID { id: id }
    }
}

impl WhirlpoolID {
    const HASH_LEN: usize = 512 / 8;
}

impl HashID for WhirlpoolID {
    #[inline]
    fn name(&self) -> &str {
        "Whirlpool"
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        &self.id
    }
}

impl Display for WhirlpoolID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}:", self.name())?;

        for i in 0..Self::HASH_LEN {
            write!(f, "{:02x}", self.id[i])?;
        }

        Ok(())
    }
}

impl Default for CompoundHashAlgo {
    #[inline]
    fn default() -> Self {
        CompoundHashAlgo::SHA3 { sha3: SHA3Algo }
    }
}

impl<'a> TryFrom<&'a str> for CompoundHashAlgo {
    type Error = &'a str;

    fn try_from(name: &'a str) -> Result<CompoundHashAlgo, &'a str> {
        match name {
            "Blake2b" => Ok(CompoundHashAlgo::Blake2b {
                blake2b: Blake2bAlgo
            }),
            "RipeMD-160" => Ok(CompoundHashAlgo::RipeMD160 {
                ripemd160: RipeMD160Algo
            }),
            "SHA3-512" => Ok(CompoundHashAlgo::SHA3 { sha3: SHA3Algo }),
            "SHA384" => Ok(CompoundHashAlgo::SHA384 { sha384: SHA384Algo }),
            "Skein" => Ok(CompoundHashAlgo::Skein { skein: SkeinAlgo }),
            "Whirlpool" => Ok(CompoundHashAlgo::Whirlpool {
                whirlpool: WhirlpoolAlgo
            }),
            err => Err(err)
        }
    }
}

impl Serialize for CompoundHashAlgo {
    #[inline]
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            CompoundHashAlgo::Blake2b { .. } => {
                serializer.serialize_str("Blake2b")
            }
            CompoundHashAlgo::RipeMD160 { .. } => {
                serializer.serialize_str("RipeMD-160")
            }
            CompoundHashAlgo::SHA3 { .. } => {
                serializer.serialize_str("SHA3-512")
            }
            CompoundHashAlgo::SHA384 { .. } => {
                serializer.serialize_str("SHA384")
            }
            CompoundHashAlgo::Skein { .. } => serializer.serialize_str("Skein"),
            CompoundHashAlgo::Whirlpool { .. } => {
                serializer.serialize_str("Whirlpool")
            }
        }
    }
}

impl HashAlgo for CompoundHashAlgo {
    type HashID = CompoundHashID;

    #[inline]
    fn wrap_hashed_bytes(
        &self,
        bytes: &[u8]
    ) -> Result<Self::HashID, TryFromSliceError> {
        match self {
            CompoundHashAlgo::Blake2b { blake2b } => blake2b
                .wrap_hashed_bytes(bytes)
                .map(|out| CompoundHashID::Blake2b { blake2b: out }),
            CompoundHashAlgo::RipeMD160 { ripemd160 } => ripemd160
                .wrap_hashed_bytes(bytes)
                .map(|out| CompoundHashID::RipeMD160 { ripemd160: out }),
            CompoundHashAlgo::SHA3 { sha3 } => sha3
                .wrap_hashed_bytes(bytes)
                .map(|out| CompoundHashID::SHA3 { sha3: out }),
            CompoundHashAlgo::SHA384 { sha384 } => sha384
                .wrap_hashed_bytes(bytes)
                .map(|out| CompoundHashID::SHA384 { sha384: out }),
            CompoundHashAlgo::Skein { skein } => skein
                .wrap_hashed_bytes(bytes)
                .map(|out| CompoundHashID::Skein { skein: out }),
            CompoundHashAlgo::Whirlpool { whirlpool } => whirlpool
                .wrap_hashed_bytes(bytes)
                .map(|out| CompoundHashID::Whirlpool { whirlpool: out })
        }
    }

    fn hash_bytes(
        &self,
        bytes: &[u8]
    ) -> Self::HashID {
        match self {
            CompoundHashAlgo::Blake2b { blake2b } => CompoundHashID::Blake2b {
                blake2b: blake2b.hash_bytes(bytes)
            },
            CompoundHashAlgo::RipeMD160 { ripemd160 } => {
                CompoundHashID::RipeMD160 {
                    ripemd160: ripemd160.hash_bytes(bytes)
                }
            }
            CompoundHashAlgo::SHA3 { sha3 } => CompoundHashID::SHA3 {
                sha3: sha3.hash_bytes(bytes)
            },
            CompoundHashAlgo::SHA384 { sha384 } => CompoundHashID::SHA384 {
                sha384: sha384.hash_bytes(bytes)
            },
            CompoundHashAlgo::Skein { skein } => CompoundHashID::Skein {
                skein: skein.hash_bytes(bytes)
            },
            CompoundHashAlgo::Whirlpool { whirlpool } => {
                CompoundHashID::Whirlpool {
                    whirlpool: whirlpool.hash_bytes(bytes)
                }
            }
        }
    }
}

impl HashID for CompoundHashID {
    #[inline]
    fn name(&self) -> &str {
        match self {
            CompoundHashID::Blake2b { blake2b } => blake2b.name(),
            CompoundHashID::RipeMD160 { ripemd160 } => ripemd160.name(),
            CompoundHashID::SHA3 { sha3 } => sha3.name(),
            CompoundHashID::SHA384 { sha384 } => sha384.name(),
            CompoundHashID::Skein { skein } => skein.name(),
            CompoundHashID::Whirlpool { whirlpool } => whirlpool.name()
        }
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        match self {
            CompoundHashID::Blake2b { blake2b } => blake2b.bytes(),
            CompoundHashID::RipeMD160 { ripemd160 } => ripemd160.bytes(),
            CompoundHashID::SHA3 { sha3 } => sha3.bytes(),
            CompoundHashID::SHA384 { sha384 } => sha384.bytes(),
            CompoundHashID::Skein { skein } => skein.bytes(),
            CompoundHashID::Whirlpool { whirlpool } => whirlpool.bytes()
        }
    }
}

impl Display for CompoundHashID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            CompoundHashID::Blake2b { blake2b } => blake2b.fmt(f),
            CompoundHashID::RipeMD160 { ripemd160 } => ripemd160.fmt(f),
            CompoundHashID::SHA3 { sha3 } => sha3.fmt(f),
            CompoundHashID::SHA384 { sha384 } => sha384.fmt(f),
            CompoundHashID::Skein { skein } => skein.fmt(f),
            CompoundHashID::Whirlpool { whirlpool } => whirlpool.fmt(f)
        }
    }
}
