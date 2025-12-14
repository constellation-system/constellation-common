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

//! Utilities for Unix Sockets.
//!
//! This module contains utilities for Unix sockets.  This primarily
//! consists of wrapper types to deal with the fact that [PathBuf] and
//! [SocketAddr] don't have [Display] instances.

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Error;
use std::io::ErrorKind;
use std::os::unix::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use crate::net::PassthruDatagramXfrmParam;

/// A wrapper around [SocketAddr]s for Unix sockets.
///
/// This is primarily to deal with the fact that `SocketAddr` does not
/// have a [Display] instance.
#[derive(Clone, Debug)]
pub struct UnixSocketAddr(SocketAddr);

/// A wrapper around [PathBuf]s for Unix socket addresses.
///
/// This is primarily to deal with the fact that `PathBuf` does not
/// have a [Display] instance.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixSocketPath(PathBuf);

impl Display for UnixSocketAddr {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self.0.as_pathname() {
            Some(name) => name.to_string_lossy().fmt(f),
            None => write!(f, "<unnamed unix socket>")
        }
    }
}

impl<'a> From<&'a UnixSocketAddr> for &'a SocketAddr {
    #[inline]
    fn from(val: &'a UnixSocketAddr) -> &'a SocketAddr {
        &val.0
    }
}

impl From<UnixSocketAddr> for PassthruDatagramXfrmParam {
    #[inline]
    fn from(_val: UnixSocketAddr) -> Self {
        PassthruDatagramXfrmParam
    }
}

impl From<UnixSocketAddr> for SocketAddr {
    #[inline]
    fn from(val: UnixSocketAddr) -> SocketAddr {
        val.0
    }
}

impl From<SocketAddr> for UnixSocketAddr {
    #[inline]
    fn from(val: SocketAddr) -> UnixSocketAddr {
        UnixSocketAddr(val)
    }
}

impl TryFrom<&'_ str> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &str) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<String> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: String) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<&'_ Path> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &Path) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<&'_ PathBuf> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &PathBuf) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<PathBuf> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: PathBuf) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<&'_ UnixSocketPath> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &UnixSocketPath) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(&val.0)?))
    }
}

impl TryFrom<UnixSocketPath> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: UnixSocketPath) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val.0)?))
    }
}

impl TryFrom<&'_ UnixSocketAddr> for UnixSocketPath {
    type Error = Error;

    #[inline]
    fn try_from(val: &UnixSocketAddr) -> Result<UnixSocketPath, Error> {
        let path = val.0.as_pathname()
            .ok_or(Error::new(ErrorKind::Other, "anonymous socket"))?;

        Ok(UnixSocketPath(path.to_owned()))
    }
}

impl TryFrom<UnixSocketAddr> for UnixSocketPath {
    type Error = Error;

    #[inline]
    fn try_from(val: UnixSocketAddr) -> Result<UnixSocketPath, Error> {
        UnixSocketPath::try_from(&val)
    }
}

impl From<&'_ str> for UnixSocketPath {
    #[inline]
    fn from(val: &str) -> UnixSocketPath {
        UnixSocketPath(PathBuf::from(val))
    }
}

impl From<String> for UnixSocketPath {
    #[inline]
    fn from(val: String) -> UnixSocketPath {
        UnixSocketPath(PathBuf::from(val))
    }
}

impl From<&'_ Path> for UnixSocketPath {
    #[inline]
    fn from(val: &Path) -> UnixSocketPath {
        UnixSocketPath(PathBuf::from(val))
    }
}

impl From<&'_ PathBuf> for UnixSocketPath {
    #[inline]
    fn from(val: &PathBuf) -> UnixSocketPath {
        UnixSocketPath(val.clone())
    }
}

impl From<PathBuf> for UnixSocketPath {
    #[inline]
    fn from(val: PathBuf) -> UnixSocketPath {
        UnixSocketPath(val)
    }
}

impl From<UnixSocketPath> for PathBuf {
    #[inline]
    fn from(val: UnixSocketPath) -> PathBuf {
        val.0
    }
}

impl TryFrom<&'_ UnixSocketPath> for SocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &UnixSocketPath) -> Result<SocketAddr, Error> {
        SocketAddr::from_pathname(&val.0)
    }
}

impl TryFrom<UnixSocketPath> for SocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: UnixSocketPath) -> Result<SocketAddr, Error> {
        SocketAddr::from_pathname(&val.0)
    }
}


impl TryFrom<&'_ SocketAddr> for UnixSocketPath {
    type Error = Error;

    #[inline]
    fn try_from(val: &SocketAddr) -> Result<UnixSocketPath, Error> {
        let path = val.as_pathname()
            .ok_or(Error::new(ErrorKind::Other, "anonymous socket address"))?;

        Ok(UnixSocketPath(path.to_owned()))
    }
}

impl TryFrom<SocketAddr> for UnixSocketPath {
    type Error = Error;

    #[inline]
    fn try_from(val: SocketAddr) -> Result<UnixSocketPath, Error> {
        let path = val.as_pathname()
            .ok_or(Error::new(ErrorKind::Other, "anonymous socket address"))?;

        Ok(UnixSocketPath(path.to_owned()))
    }
}

impl Hash for UnixSocketAddr {
    #[inline]
    fn hash<H>(
        &self,
        h: &mut H
    ) where
        H: Hasher {
        if let Some(name) = self.0.as_pathname() {
            name.hash(h)
        }
    }
}

impl Eq for UnixSocketAddr {}

impl PartialEq for UnixSocketAddr {
    #[inline]
    fn eq(
        &self,
        other: &Self
    ) -> bool {
        match (self.0.as_pathname(), other.0.as_pathname()) {
            (Some(a), Some(b)) => a.eq(b),
            (None, None) => true,
            _ => false
        }
    }
}

impl Ord for UnixSocketAddr {
    #[inline]
    fn cmp(
        &self,
        other: &Self
    ) -> Ordering {
        match (self.0.as_pathname(), other.0.as_pathname()) {
            (Some(a), Some(b)) => a.cmp(b),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal
        }
    }
}

impl PartialOrd for UnixSocketAddr {
    #[inline]
    fn partial_cmp(
        &self,
        other: &Self
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<SocketAddr> for UnixSocketAddr {
    #[inline]
    fn as_ref(&self) -> &SocketAddr {
        &self.0
    }
}

impl AsRef<Path> for UnixSocketPath {
    #[inline]
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Display for UnixSocketPath {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        self.0.to_string_lossy().fmt(f)
    }
}
