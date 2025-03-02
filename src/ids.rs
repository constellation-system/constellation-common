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

//! ID generator streams.
//!
//! This module contains various implementation of [Iterator] that can
//! be used to generate streams of IDs.  [AscendingCount] represents
//! the simplest of these, and is a simple ascending counter.  Other
//! provide a cryptographically-secure random number stream.

use std::sync::Arc;
use std::sync::Mutex;

/// Trait for ID generators.
pub trait IDGen: Iterator
where
    Self::Item: Default {
    /// Configuration type for this `IDGen`.
    type Config: Default;

    /// Create an instance of the `IDGen` from a configuration and a
    /// current ID.
    fn create(config: Self::Config) -> Self;
}

/// Ascending count ID stream.
///
/// This generates a
pub struct AscendingCount {
    curr: u128
}

pub struct SharedIDGen<Inner>
where
    Inner: IDGen,
    Inner::Item: Default {
    inner: Arc<Mutex<Inner>>
}

impl IDGen for AscendingCount {
    type Config = ();

    #[inline]
    fn create(_config: Self::Config) -> Self {
        AscendingCount {
            curr: Self::Item::default()
        }
    }
}

impl<Inner> IDGen for SharedIDGen<Inner>
where
    Inner: IDGen,
    Inner::Item: Default
{
    type Config = Inner::Config;

    #[inline]
    fn create(config: Self::Config) -> Self {
        SharedIDGen {
            inner: Arc::new(Mutex::new(Inner::create(config)))
        }
    }
}

impl Default for AscendingCount {
    #[inline]
    fn default() -> Self {
        AscendingCount { curr: 0 }
    }
}

impl Iterator for AscendingCount {
    type Item = u128;

    #[inline]
    fn next(&mut self) -> Option<u128> {
        let out = self.curr;

        self.curr += 1;

        Some(out)
    }
}

impl<Inner> Iterator for SharedIDGen<Inner>
where
    Inner: IDGen,
    Inner::Item: Default
{
    type Item = Inner::Item;

    #[inline]
    fn next(&mut self) -> Option<Inner::Item> {
        self.inner
            .lock()
            .map(|mut guard| guard.next())
            .unwrap_or(None)
    }
}
