// Copyright © 2024-25 The Johns Hopkins Applied Physics Laboratory LLC.
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

//! Configuration objects.
//!
//! Types defined in this module are parseable from YAML using the
//! [serde] functionality.  They are intended to be used to parse
//! configuration files into objects representing the configuration
//! contained therein.

pub mod authn;
pub mod pki;
// pub mod signing;

use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;

use serde::Deserialize;
use serde::Serialize;

use crate::version::BadVersionRangeString;
use crate::version::BadVersionString;
use crate::version::Version;
use crate::version::VersionRange;

pub trait Create: Sized {
    type CreateError: Debug + Display;
    type Config;

    fn create(config: Self::Config) -> Result<Self, Self::CreateError>;
}

pub trait CreateArg: Sized {
    type CreateError: Debug + Display;
    type Config;
    type Arg;

    fn create(
        config: Self::Config,
        arg: Self::Arg
    ) -> Result<Self, Self::CreateError>;
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "version")]
#[serde(rename_all = "kebab-case")]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct VersionConfig(Version);

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename = "version-range")]
#[serde(rename_all = "kebab-case")]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct VersionRangeConfig(VersionRange);

/// Allowed verification flags.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(untagged)]
#[serde(try_from = "String")]
pub enum CompoundHashAlgoConfig {
    /// The Blake2b hash algorithm.
    Blake2b,
    /// The RipeMD-160 hash algorithm.
    RipeMD160,
    /// The SHA3-512 hash algorithm.
    SHA3,
    /// The SHA384 hash algorithm.
    SHA384,
    /// The Skein-512 hash algorithm.
    Skein,
    /// The Whirlpool hash algorithm.
    Whirlpool
}

pub struct BadHash(String);

impl Default for CompoundHashAlgoConfig {
    #[inline]
    fn default() -> Self {
        CompoundHashAlgoConfig::SHA3
    }
}

impl From<CompoundHashAlgoConfig> for String {
    #[inline]
    fn from(val: CompoundHashAlgoConfig) -> String {
        val.to_string()
    }
}

impl TryFrom<String> for CompoundHashAlgoConfig {
    type Error = BadHash;

    fn try_from(val: String) -> Result<Self, BadHash> {
        match val.to_lowercase().as_str() {
            "blake2b" => Ok(CompoundHashAlgoConfig::Blake2b),
            "ripemd160" | "ripemd-160" => Ok(CompoundHashAlgoConfig::RipeMD160),
            "sha3" | "sha3-512" => Ok(CompoundHashAlgoConfig::SHA3),
            "sha384" | "sha2-384" => Ok(CompoundHashAlgoConfig::SHA3),
            "skein" | "skein-512" => Ok(CompoundHashAlgoConfig::Skein),
            "whirlpool" => Ok(CompoundHashAlgoConfig::Whirlpool),
            _ => Err(BadHash(val))
        }
    }
}

impl Default for VersionRangeConfig {
    #[inline]
    fn default() -> Self {
        VersionRangeConfig(VersionRange {
            upper: None,
            lower: None
        })
    }
}

impl From<VersionConfig> for Version {
    #[inline]
    fn from(val: VersionConfig) -> Version {
        val.0
    }
}

impl From<Version> for VersionConfig {
    #[inline]
    fn from(val: Version) -> VersionConfig {
        VersionConfig(val)
    }
}

impl From<VersionRangeConfig> for VersionRange {
    #[inline]
    fn from(val: VersionRangeConfig) -> VersionRange {
        val.0
    }
}

impl From<VersionRange> for VersionRangeConfig {
    #[inline]
    fn from(val: VersionRange) -> VersionRangeConfig {
        VersionRangeConfig(val)
    }
}

impl TryFrom<String> for VersionConfig {
    type Error = BadVersionString;

    #[inline]
    fn try_from(val: String) -> Result<VersionConfig, BadVersionString> {
        VersionConfig::try_from(val.as_str())
    }
}

impl TryFrom<&'_ str> for VersionConfig {
    type Error = BadVersionString;

    #[inline]
    fn try_from(val: &str) -> Result<VersionConfig, BadVersionString> {
        let version = Version::try_from(val)?;

        Ok(VersionConfig(version))
    }
}

impl From<VersionConfig> for String {
    #[inline]
    fn from(val: VersionConfig) -> String {
        val.0.to_string()
    }
}

impl TryFrom<String> for VersionRangeConfig {
    type Error = BadVersionRangeString;

    #[inline]
    fn try_from(
        val: String
    ) -> Result<VersionRangeConfig, BadVersionRangeString> {
        VersionRangeConfig::try_from(val.as_str())
    }
}

impl TryFrom<&'_ str> for VersionRangeConfig {
    type Error = BadVersionRangeString;

    #[inline]
    fn try_from(
        val: &str
    ) -> Result<VersionRangeConfig, BadVersionRangeString> {
        let version = VersionRange::try_from(val)?;

        Ok(VersionRangeConfig(version))
    }
}

impl From<VersionRangeConfig> for String {
    #[inline]
    fn from(val: VersionRangeConfig) -> String {
        val.0.to_string()
    }
}

impl Display for CompoundHashAlgoConfig {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            CompoundHashAlgoConfig::Blake2b => write!(f, "blake2b"),
            CompoundHashAlgoConfig::RipeMD160 => write!(f, "ripemd160"),
            CompoundHashAlgoConfig::SHA3 => write!(f, "SHA3"),
            CompoundHashAlgoConfig::SHA384 => write!(f, "SHA384"),
            CompoundHashAlgoConfig::Skein => write!(f, "skein"),
            CompoundHashAlgoConfig::Whirlpool => write!(f, "whirlpool")
        }
    }
}

impl Display for BadHash {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "unknown hash algorithm {}", self.0)
    }
}
