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

use serde::Deserialize;
use serde::Serialize;

use crate::version::BadVersionRangeString;
use crate::version::BadVersionString;
use crate::version::Version;
use crate::version::VersionRange;

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "version")]
#[serde(rename_all = "kebab-case")]
#[serde(try_from = "&str")]
#[serde(into = "String")]
pub struct VersionConfig(Version);

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename = "version-range")]
#[serde(rename_all = "kebab-case")]
#[serde(try_from = "&str")]
#[serde(into = "String")]
pub struct VersionRangeConfig(VersionRange);

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
