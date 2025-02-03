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

use std::cmp::Ordering;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;

use crate::codec::per::PERCodec;
pub use crate::generated::version::Version;
pub use crate::generated::version::VersionRange;
pub use crate::generated::version::VersionRangeElem;
pub use crate::generated::version::VersionRangeElemMajor;
pub use crate::generated::version::VersionRangeElemMinor;
pub use crate::generated::version::VersionRangeElemSub;

pub type VersionPERCodec = PERCodec<Version, 32>;

impl Version {
    /// Create a new `Version` from the version components.
    #[inline]
    pub fn new(
        major: u16,
        minor: u16,
        sub: u16
    ) -> Self {
        Version {
            major: major,
            minor: minor,
            sub: sub
        }
    }

    /// Get the major version number.
    #[inline]
    pub fn major(&self) -> u16 {
        self.major
    }

    /// Get the minor version number.
    #[inline]
    pub fn minor(&self) -> u16 {
        self.minor
    }

    /// Get the sub-minor version number.
    #[inline]
    pub fn sub(&self) -> u16 {
        self.sub
    }
}

impl VersionRangeElemMajor {
    /// Create a new `VersionRangeElemMajor` from the version components.
    #[inline]
    pub fn new(major: u16) -> Self {
        VersionRangeElemMajor { major: major }
    }

    /// Get the major version number.
    #[inline]
    pub fn major(&self) -> u16 {
        self.major
    }
}

impl VersionRangeElemMinor {
    /// Create a new `VersionRangeElemMinor` from the version components.
    #[inline]
    pub fn new(
        major: u16,
        minor: u16
    ) -> Self {
        VersionRangeElemMinor {
            major: major,
            minor: minor
        }
    }

    /// Get the major version number.
    #[inline]
    pub fn major(&self) -> u16 {
        self.major
    }

    /// Get the minor version number.
    #[inline]
    pub fn minor(&self) -> u16 {
        self.minor
    }
}

impl VersionRangeElemSub {
    /// Create a new `VersionRangeElemSub` from the version components.
    #[inline]
    pub fn new(
        major: u16,
        minor: u16,
        sub: u16
    ) -> Self {
        VersionRangeElemSub {
            major: major,
            minor: minor,
            sub: sub
        }
    }

    /// Get the major version number.
    #[inline]
    pub fn major(&self) -> u16 {
        self.major
    }

    /// Get the minor version number.
    #[inline]
    pub fn minor(&self) -> u16 {
        self.minor
    }

    /// Get the sub-minor version number.
    #[inline]
    pub fn sub(&self) -> u16 {
        self.sub
    }
}

impl VersionRangeElem {
    /// Create a new `VersionRangeElem` from a major version.
    #[inline]
    pub fn major(major: u16) -> Self {
        VersionRangeElem::Major(VersionRangeElemMajor::new(major))
    }

    /// Create a new `VersionRangeElem` from a minor version.
    #[inline]
    pub fn minor(
        major: u16,
        minor: u16
    ) -> Self {
        VersionRangeElem::Minor(VersionRangeElemMinor::new(major, minor))
    }

    /// Create a new `VersionRangeElem` from a subminor version.
    #[inline]
    pub fn sub(
        major: u16,
        minor: u16,
        sub: u16
    ) -> Self {
        VersionRangeElem::Sub(VersionRangeElemSub::new(major, minor, sub))
    }
}

impl Display for Version {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        write!(f, "{}.{}.{}", self.major(), self.minor(), self.sub())
    }
}

impl Display for VersionRangeElem {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        match self {
            VersionRangeElem::Major(elem) => elem.fmt(f),
            VersionRangeElem::Minor(elem) => elem.fmt(f),
            VersionRangeElem::Sub(elem) => elem.fmt(f)
        }
    }
}

impl Display for VersionRangeElemMajor {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        write!(f, "{}.*", self.major())
    }
}

impl Display for VersionRangeElemMinor {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        write!(f, "{}.{}.*", self.major(), self.minor())
    }
}

impl Display for VersionRangeElemSub {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        write!(f, "{}.{}.{}", self.major(), self.minor(), self.sub())
    }
}

impl Eq for Version {}
impl Eq for VersionRangeElem {}
impl Eq for VersionRangeElemMajor {}
impl Eq for VersionRangeElemMinor {}
impl Eq for VersionRangeElemSub {}

impl PartialEq<VersionRangeElem> for Version {
    fn eq(
        &self,
        other: &VersionRangeElem
    ) -> bool {
        match other {
            VersionRangeElem::Major(elem) => self.eq(elem),
            VersionRangeElem::Minor(elem) => self.eq(elem),
            VersionRangeElem::Sub(elem) => self.eq(elem)
        }
    }
}

impl PartialEq<VersionRangeElemMajor> for Version {
    fn eq(
        &self,
        other: &VersionRangeElemMajor
    ) -> bool {
        self.major().eq(&other.major())
    }
}

impl PartialEq<VersionRangeElemMinor> for Version {
    fn eq(
        &self,
        other: &VersionRangeElemMinor
    ) -> bool {
        self.major().eq(&other.major()) && self.minor().eq(&other.minor())
    }
}

impl PartialEq<VersionRangeElemSub> for Version {
    fn eq(
        &self,
        other: &VersionRangeElemSub
    ) -> bool {
        self.major().eq(&other.major()) &&
            self.minor().eq(&other.minor()) &&
            self.sub().eq(&other.sub())
    }
}

impl PartialEq<Version> for VersionRangeElem {
    fn eq(
        &self,
        other: &Version
    ) -> bool {
        match self {
            VersionRangeElem::Major(elem) => elem.eq(other),
            VersionRangeElem::Minor(elem) => elem.eq(other),
            VersionRangeElem::Sub(elem) => elem.eq(other)
        }
    }
}

impl PartialEq<VersionRangeElemMajor> for VersionRangeElem {
    fn eq(
        &self,
        other: &VersionRangeElemMajor
    ) -> bool {
        match self {
            VersionRangeElem::Major(elem) => elem.eq(other),
            VersionRangeElem::Minor(elem) => elem.eq(other),
            VersionRangeElem::Sub(elem) => elem.eq(other)
        }
    }
}

impl PartialEq<VersionRangeElemMinor> for VersionRangeElem {
    fn eq(
        &self,
        other: &VersionRangeElemMinor
    ) -> bool {
        match self {
            VersionRangeElem::Major(elem) => elem.eq(other),
            VersionRangeElem::Minor(elem) => elem.eq(other),
            VersionRangeElem::Sub(elem) => elem.eq(other)
        }
    }
}

impl PartialEq<VersionRangeElemSub> for VersionRangeElem {
    fn eq(
        &self,
        other: &VersionRangeElemSub
    ) -> bool {
        match self {
            VersionRangeElem::Major(elem) => elem.eq(other),
            VersionRangeElem::Minor(elem) => elem.eq(other),
            VersionRangeElem::Sub(elem) => elem.eq(other)
        }
    }
}

impl PartialEq<Version> for VersionRangeElemMajor {
    fn eq(
        &self,
        other: &Version
    ) -> bool {
        self.major().eq(&other.major())
    }
}

impl PartialEq<VersionRangeElem> for VersionRangeElemMajor {
    fn eq(
        &self,
        other: &VersionRangeElem
    ) -> bool {
        match other {
            VersionRangeElem::Major(elem) => self.eq(elem),
            VersionRangeElem::Minor(elem) => self.eq(elem),
            VersionRangeElem::Sub(elem) => self.eq(elem)
        }
    }
}

impl PartialEq<VersionRangeElemMinor> for VersionRangeElemMajor {
    fn eq(
        &self,
        other: &VersionRangeElemMinor
    ) -> bool {
        self.major().eq(&other.major())
    }
}

impl PartialEq<VersionRangeElemSub> for VersionRangeElemMajor {
    fn eq(
        &self,
        other: &VersionRangeElemSub
    ) -> bool {
        self.major().eq(&other.major())
    }
}

impl PartialEq<Version> for VersionRangeElemMinor {
    fn eq(
        &self,
        other: &Version
    ) -> bool {
        self.major().eq(&other.major()) && self.minor().eq(&other.minor())
    }
}

impl PartialEq<VersionRangeElem> for VersionRangeElemMinor {
    fn eq(
        &self,
        other: &VersionRangeElem
    ) -> bool {
        match other {
            VersionRangeElem::Major(elem) => self.eq(elem),
            VersionRangeElem::Minor(elem) => self.eq(elem),
            VersionRangeElem::Sub(elem) => self.eq(elem)
        }
    }
}

impl PartialEq<VersionRangeElemMajor> for VersionRangeElemMinor {
    fn eq(
        &self,
        other: &VersionRangeElemMajor
    ) -> bool {
        self.major().eq(&other.major())
    }
}

impl PartialEq<VersionRangeElemSub> for VersionRangeElemMinor {
    fn eq(
        &self,
        other: &VersionRangeElemSub
    ) -> bool {
        self.major().eq(&other.major()) && self.minor().eq(&other.minor())
    }
}

impl PartialEq<Version> for VersionRangeElemSub {
    fn eq(
        &self,
        other: &Version
    ) -> bool {
        self.major().eq(&other.major()) &&
            self.minor().eq(&other.minor()) &&
            self.sub().eq(&other.sub())
    }
}

impl PartialEq<VersionRangeElem> for VersionRangeElemSub {
    fn eq(
        &self,
        other: &VersionRangeElem
    ) -> bool {
        match other {
            VersionRangeElem::Major(elem) => self.eq(elem),
            VersionRangeElem::Minor(elem) => self.eq(elem),
            VersionRangeElem::Sub(elem) => self.eq(elem)
        }
    }
}

impl PartialEq<VersionRangeElemMajor> for VersionRangeElemSub {
    fn eq(
        &self,
        other: &VersionRangeElemMajor
    ) -> bool {
        self.major().eq(&other.major())
    }
}

impl PartialEq<VersionRangeElemMinor> for VersionRangeElemSub {
    fn eq(
        &self,
        other: &VersionRangeElemMinor
    ) -> bool {
        self.major().eq(&other.major()) && self.minor().eq(&other.minor())
    }
}

impl PartialOrd for Version {
    #[inline]
    fn partial_cmp(
        &self,
        other: &Version
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<VersionRangeElem> for Version {
    fn partial_cmp(
        &self,
        other: &VersionRangeElem
    ) -> Option<Ordering> {
        match other {
            VersionRangeElem::Major(elem) => self.partial_cmp(elem),
            VersionRangeElem::Minor(elem) => self.partial_cmp(elem),
            VersionRangeElem::Sub(elem) => self.partial_cmp(elem)
        }
    }
}

impl PartialOrd<VersionRangeElemMajor> for Version {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMajor
    ) -> Option<Ordering> {
        self.major().partial_cmp(&other.major())
    }
}

impl PartialOrd<VersionRangeElemMinor> for Version {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMinor
    ) -> Option<Ordering> {
        match self.major().partial_cmp(&other.major()) {
            Some(Ordering::Equal) => self.minor().partial_cmp(&other.minor()),
            out => out
        }
    }
}

impl PartialOrd<VersionRangeElemSub> for Version {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemSub
    ) -> Option<Ordering> {
        match self.major().partial_cmp(&other.major()) {
            Some(Ordering::Equal) => match self
                .minor()
                .partial_cmp(&other.minor())
            {
                Some(Ordering::Equal) => self.sub().partial_cmp(&other.sub()),
                out => out
            },
            out => out
        }
    }
}

impl PartialOrd for VersionRangeElem {
    #[inline]
    fn partial_cmp(
        &self,
        other: &VersionRangeElem
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Version> for VersionRangeElem {
    fn partial_cmp(
        &self,
        other: &Version
    ) -> Option<Ordering> {
        match self {
            VersionRangeElem::Major(elem) => elem.partial_cmp(other),
            VersionRangeElem::Minor(elem) => elem.partial_cmp(other),
            VersionRangeElem::Sub(elem) => elem.partial_cmp(other)
        }
    }
}

impl PartialOrd<VersionRangeElemMajor> for VersionRangeElem {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMajor
    ) -> Option<Ordering> {
        match self {
            VersionRangeElem::Major(elem) => elem.partial_cmp(other),
            VersionRangeElem::Minor(elem) => elem.partial_cmp(other),
            VersionRangeElem::Sub(elem) => elem.partial_cmp(other)
        }
    }
}

impl PartialOrd<VersionRangeElemMinor> for VersionRangeElem {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMinor
    ) -> Option<Ordering> {
        match self {
            VersionRangeElem::Major(elem) => elem.partial_cmp(other),
            VersionRangeElem::Minor(elem) => elem.partial_cmp(other),
            VersionRangeElem::Sub(elem) => elem.partial_cmp(other)
        }
    }
}

impl PartialOrd<VersionRangeElemSub> for VersionRangeElem {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemSub
    ) -> Option<Ordering> {
        match self {
            VersionRangeElem::Major(elem) => elem.partial_cmp(other),
            VersionRangeElem::Minor(elem) => elem.partial_cmp(other),
            VersionRangeElem::Sub(elem) => elem.partial_cmp(other)
        }
    }
}

impl PartialOrd for VersionRangeElemMajor {
    #[inline]
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMajor
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Version> for VersionRangeElemMajor {
    fn partial_cmp(
        &self,
        other: &Version
    ) -> Option<Ordering> {
        self.major().partial_cmp(&other.major())
    }
}

impl PartialOrd<VersionRangeElem> for VersionRangeElemMajor {
    fn partial_cmp(
        &self,
        other: &VersionRangeElem
    ) -> Option<Ordering> {
        match other {
            VersionRangeElem::Major(elem) => self.partial_cmp(elem),
            VersionRangeElem::Minor(elem) => self.partial_cmp(elem),
            VersionRangeElem::Sub(elem) => self.partial_cmp(elem)
        }
    }
}

impl PartialOrd<VersionRangeElemMinor> for VersionRangeElemMajor {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMinor
    ) -> Option<Ordering> {
        self.major().partial_cmp(&other.major())
    }
}

impl PartialOrd<VersionRangeElemSub> for VersionRangeElemMajor {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemSub
    ) -> Option<Ordering> {
        self.major().partial_cmp(&other.major())
    }
}

impl PartialOrd for VersionRangeElemMinor {
    #[inline]
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMinor
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Version> for VersionRangeElemMinor {
    fn partial_cmp(
        &self,
        other: &Version
    ) -> Option<Ordering> {
        match self.major().partial_cmp(&other.major()) {
            Some(Ordering::Equal) => self.minor().partial_cmp(&other.minor()),
            out => out
        }
    }
}

impl PartialOrd<VersionRangeElem> for VersionRangeElemMinor {
    fn partial_cmp(
        &self,
        other: &VersionRangeElem
    ) -> Option<Ordering> {
        match other {
            VersionRangeElem::Major(elem) => self.partial_cmp(elem),
            VersionRangeElem::Minor(elem) => self.partial_cmp(elem),
            VersionRangeElem::Sub(elem) => self.partial_cmp(elem)
        }
    }
}

impl PartialOrd<VersionRangeElemMajor> for VersionRangeElemMinor {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMajor
    ) -> Option<Ordering> {
        self.major().partial_cmp(&other.major())
    }
}

impl PartialOrd<VersionRangeElemSub> for VersionRangeElemMinor {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemSub
    ) -> Option<Ordering> {
        match self.major().partial_cmp(&other.major()) {
            Some(Ordering::Equal) => self.minor().partial_cmp(&other.minor()),
            out => out
        }
    }
}

impl PartialOrd for VersionRangeElemSub {
    #[inline]
    fn partial_cmp(
        &self,
        other: &VersionRangeElemSub
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Version> for VersionRangeElemSub {
    fn partial_cmp(
        &self,
        other: &Version
    ) -> Option<Ordering> {
        match self.major().partial_cmp(&other.major()) {
            Some(Ordering::Equal) => match self
                .minor()
                .partial_cmp(&other.minor())
            {
                Some(Ordering::Equal) => self.sub().partial_cmp(&other.sub()),
                out => out
            },
            out => out
        }
    }
}

impl PartialOrd<VersionRangeElem> for VersionRangeElemSub {
    fn partial_cmp(
        &self,
        other: &VersionRangeElem
    ) -> Option<Ordering> {
        match other {
            VersionRangeElem::Major(elem) => self.partial_cmp(elem),
            VersionRangeElem::Minor(elem) => self.partial_cmp(elem),
            VersionRangeElem::Sub(elem) => self.partial_cmp(elem)
        }
    }
}

impl PartialOrd<VersionRangeElemMajor> for VersionRangeElemSub {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMajor
    ) -> Option<Ordering> {
        self.major().partial_cmp(&other.major())
    }
}

impl PartialOrd<VersionRangeElemMinor> for VersionRangeElemSub {
    fn partial_cmp(
        &self,
        other: &VersionRangeElemMinor
    ) -> Option<Ordering> {
        match self.major().partial_cmp(&other.major()) {
            Some(Ordering::Equal) => self.minor().partial_cmp(&other.minor()),
            out => out
        }
    }
}

impl Ord for Version {
    fn cmp(
        &self,
        other: &Version
    ) -> Ordering {
        match self.major().cmp(&other.major()) {
            Ordering::Equal => match self.minor().cmp(&other.minor()) {
                Ordering::Equal => self.sub().cmp(&other.sub()),
                out => out
            },
            out => out
        }
    }
}

impl Ord for VersionRangeElem {
    fn cmp(
        &self,
        other: &VersionRangeElem
    ) -> Ordering {
        match (self, other) {
            (VersionRangeElem::Major(a), VersionRangeElem::Major(b)) => {
                a.cmp(b)
            }
            (VersionRangeElem::Major(a), VersionRangeElem::Minor(b)) => {
                a.major().cmp(&b.major())
            }
            (VersionRangeElem::Major(a), VersionRangeElem::Sub(b)) => {
                a.major().cmp(&b.major())
            }
            (VersionRangeElem::Minor(a), VersionRangeElem::Major(b)) => {
                a.major().cmp(&b.major())
            }
            (VersionRangeElem::Minor(a), VersionRangeElem::Minor(b)) => {
                a.cmp(b)
            }
            (VersionRangeElem::Minor(a), VersionRangeElem::Sub(b)) => {
                match a.major().cmp(&b.major()) {
                    Ordering::Equal => a.minor().cmp(&b.minor()),
                    out => out
                }
            }
            (VersionRangeElem::Sub(a), VersionRangeElem::Major(b)) => {
                a.major().cmp(&b.major())
            }
            (VersionRangeElem::Sub(a), VersionRangeElem::Minor(b)) => {
                match a.major().cmp(&b.major()) {
                    Ordering::Equal => a.minor().cmp(&b.minor()),
                    out => out
                }
            }
            (VersionRangeElem::Sub(a), VersionRangeElem::Sub(b)) => a.cmp(b)
        }
    }
}

impl Ord for VersionRangeElemMajor {
    fn cmp(
        &self,
        other: &VersionRangeElemMajor
    ) -> Ordering {
        self.major().cmp(&other.major())
    }
}

impl Ord for VersionRangeElemMinor {
    fn cmp(
        &self,
        other: &VersionRangeElemMinor
    ) -> Ordering {
        match self.major().cmp(&other.major()) {
            Ordering::Equal => self.minor().cmp(&other.minor()),
            out => out
        }
    }
}

impl Ord for VersionRangeElemSub {
    fn cmp(
        &self,
        other: &VersionRangeElemSub
    ) -> Ordering {
        match self.major().cmp(&other.major()) {
            Ordering::Equal => match self.minor().cmp(&other.minor()) {
                Ordering::Equal => self.sub().cmp(&other.sub()),
                out => out
            },
            out => out
        }
    }
}

#[cfg(test)]
use asn1rs::syn::io::UperWriter;
#[cfg(test)]
use asn1rs::syn::Readable;
#[cfg(test)]
use asn1rs::syn::Writable;

#[cfg(test)]
use crate::codec::DatagramCodec;

#[test]
fn test_version_codec() {
    let version = Version::new(1, 2, 10);
    let mut codec = VersionPERCodec::create(()).unwrap();
    let mut buf = [0; VersionPERCodec::MAX_BYTES];
    let nencoded = codec.encode(&version, &mut buf[..]).unwrap();
    let (actual, nbytes) = codec.decode(&buf[..]).unwrap();

    assert_eq!(version, actual);
    assert_eq!(nencoded, nbytes);
}

#[test]
fn test_version_read_write() {
    let expected = Version::new(1, 2, 3);
    let mut writer = UperWriter::with_capacity(4);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = Version::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_range_elem_major_read_write() {
    let expected = VersionRangeElem::major(1);
    let mut writer = UperWriter::with_capacity(2);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = VersionRangeElem::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_range_elem_minor_read_write() {
    let expected = VersionRangeElem::minor(1, 2);
    let mut writer = UperWriter::with_capacity(3);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = VersionRangeElem::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_range_elem_sub_read_write() {
    let expected = VersionRangeElem::sub(1, 2, 3);
    let mut writer = UperWriter::with_capacity(5);

    expected.write(&mut writer).expect("Expected success");

    let mut reader = writer.as_reader();
    let actual = VersionRangeElem::read(&mut reader).expect("Expected success");

    assert_eq!(expected, actual);
}

#[test]
fn test_version_eq() {
    let tests = [
        ((1, 0, 0), (1, 0, 0), true),
        ((1, 1, 0), (1, 0, 0), false),
        ((1, 0, 0), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 0), true),
        ((1, 1, 1), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_version_range_elem_major() {
    let tests = [
        ((1, 0, 0), 2, false),
        ((2, 0, 0), 2, true),
        ((3, 0, 0), 2, false),
        ((1, 1, 0), 2, false),
        ((2, 1, 0), 2, true),
        ((3, 1, 0), 2, false),
        ((1, 0, 1), 2, false),
        ((2, 0, 1), 2, true),
        ((3, 0, 1), 2, false),
        ((1, 1, 1), 2, false),
        ((2, 1, 1), 2, true),
        ((3, 1, 1), 2, false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::major(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_major_eq_version() {
    let tests = [
        (2, (1, 0, 0), false),
        (2, (2, 0, 0), true),
        (2, (3, 0, 0), false),
        (2, (1, 1, 0), false),
        (2, (2, 1, 0), true),
        (2, (3, 1, 0), false),
        (2, (1, 0, 1), false),
        (2, (2, 0, 1), true),
        (2, (3, 0, 1), false),
        (2, (1, 1, 1), false),
        (2, (2, 1, 1), true),
        (2, (3, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::major(*lhs);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_version_range_elem_minor() {
    let tests = [
        ((1, 0, 0), (2, 1), false),
        ((2, 0, 0), (2, 1), false),
        ((3, 0, 0), (2, 1), false),
        ((1, 1, 0), (2, 1), false),
        ((2, 1, 0), (2, 1), true),
        ((3, 1, 0), (2, 1), false),
        ((1, 1, 1), (2, 1), false),
        ((2, 1, 1), (2, 1), true),
        ((3, 1, 1), (2, 1), false),
        ((1, 2, 0), (2, 1), false),
        ((2, 2, 0), (2, 1), false),
        ((3, 2, 0), (2, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::minor(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_minor_eq_version() {
    let tests = [
        ((2, 1), (1, 0, 0), false),
        ((2, 1), (2, 0, 0), false),
        ((2, 1), (3, 0, 0), false),
        ((2, 1), (1, 1, 0), false),
        ((2, 1), (2, 1, 0), true),
        ((2, 1), (3, 1, 0), false),
        ((2, 1), (1, 1, 1), false),
        ((2, 1), (2, 1, 1), true),
        ((2, 1), (3, 1, 1), false),
        ((2, 1), (1, 2, 0), false),
        ((2, 1), (2, 2, 0), false),
        ((2, 1), (3, 2, 0), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::minor(lhs.0, lhs.1);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_version_range_elem_sub() {
    let tests = [
        ((1, 0, 0), (2, 1, 1), false),
        ((2, 0, 0), (2, 1, 1), false),
        ((3, 0, 0), (2, 1, 1), false),
        ((1, 1, 1), (2, 1, 1), false),
        ((2, 1, 1), (2, 1, 1), true),
        ((3, 1, 1), (2, 1, 1), false),
        ((1, 1, 2), (2, 1, 1), false),
        ((2, 1, 2), (2, 1, 1), false),
        ((3, 1, 2), (2, 1, 1), false),
        ((1, 2, 0), (2, 1, 1), false),
        ((2, 2, 0), (2, 1, 1), false),
        ((3, 2, 0), (2, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = Version::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::sub(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_sub_eq_version() {
    let tests = [
        ((2, 1, 1), (1, 0, 0), false),
        ((2, 1, 1), (2, 0, 0), false),
        ((2, 1, 1), (3, 0, 0), false),
        ((2, 1, 1), (1, 1, 1), false),
        ((2, 1, 1), (2, 1, 1), true),
        ((2, 1, 1), (3, 1, 1), false),
        ((2, 1, 1), (1, 1, 2), false),
        ((2, 1, 1), (2, 1, 2), false),
        ((2, 1, 1), (3, 1, 2), false),
        ((2, 1, 1), (1, 2, 0), false),
        ((2, 1, 1), (2, 2, 0), false),
        ((2, 1, 1), (3, 2, 0), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::sub(lhs.0, lhs.1, lhs.2);
        let rhs = Version::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_major_eq() {
    let tests = [(0, 1, false), (1, 0, false), (1, 1, true)];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_major_eq_version_range_elem_minor() {
    let tests = [
        (2, (1, 0), false),
        (2, (2, 0), true),
        (2, (3, 0), false),
        (2, (1, 1), false),
        (2, (2, 1), true),
        (2, (3, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::major(*lhs);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMajor::new(*lhs);
        let rhs = VersionRangeElem::minor(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_minor_eq_version_range_elem_major() {
    let tests = [
        ((1, 0), 2, false),
        ((2, 0), 2, true),
        ((3, 0), 2, false),
        ((1, 1), 2, false),
        ((2, 1), 2, true),
        ((3, 1), 2, false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElem::major(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::minor(lhs.0, lhs.1);
        let rhs = VersionRangeElemMajor::new(*rhs);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_eq_range_elem_minor() {
    let tests = [
        ((1, 0), (1, 0), true),
        ((1, 1), (1, 0), false),
        ((1, 0), (1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_minor_eq_version_range_elem_sub() {
    let tests = [
        ((2, 1), (1, 0, 0), false),
        ((2, 1), (2, 0, 0), false),
        ((2, 1), (3, 0, 0), false),
        ((2, 1), (1, 1, 0), false),
        ((2, 1), (2, 1, 0), true),
        ((2, 1), (3, 1, 0), false),
        ((2, 1), (1, 1, 1), false),
        ((2, 1), (2, 1, 1), true),
        ((2, 1), (3, 1, 1), false),
        ((2, 1), (1, 2, 0), false),
        ((2, 1), (2, 2, 0), false),
        ((2, 1), (3, 2, 0), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::minor(lhs.0, lhs.1);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemMinor::new(lhs.0, lhs.1);
        let rhs = VersionRangeElem::sub(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_sub_eq_version_range_elem_minor() {
    let tests = [
        ((1, 0, 0), (2, 1), false),
        ((2, 0, 0), (2, 1), false),
        ((3, 0, 0), (2, 1), false),
        ((1, 1, 0), (2, 1), false),
        ((2, 1, 0), (2, 1), true),
        ((3, 1, 0), (2, 1), false),
        ((1, 1, 1), (2, 1), false),
        ((2, 1, 1), (2, 1), true),
        ((3, 1, 1), (2, 1), false),
        ((1, 2, 0), (2, 1), false),
        ((2, 2, 0), (2, 1), false),
        ((3, 2, 0), (2, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElem::sub(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemMinor::new(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElem::minor(rhs.0, rhs.1);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}

#[test]
fn test_version_range_elem_sub_eq() {
    let tests = [
        ((1, 0, 0), (1, 0, 0), true),
        ((1, 1, 0), (1, 0, 0), false),
        ((1, 0, 0), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 0), true),
        ((1, 1, 1), (1, 1, 0), false),
        ((1, 1, 0), (1, 1, 1), false)
    ];

    for (lhs, rhs, expected) in &tests {
        let lhs = VersionRangeElemSub::new(lhs.0, lhs.1, lhs.2);
        let rhs = VersionRangeElemSub::new(rhs.0, rhs.1, rhs.2);

        assert_eq!(&lhs.eq(&rhs), expected)
    }
}
