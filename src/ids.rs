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

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;

/// Trait for ID generators.
pub trait IDGen: Iterator {
    /// Configuration type for this `IDGen`.
    type Config: Default;

    /// Create an instance of the `IDGen` from a configuration and a
    /// current ID.
    fn create(config: Self::Config) -> Self;
}

/// Ascending count ID stream.
///
/// This generates a stream of objects obtained from the [From]
/// instance of a monotonically-ascending count of `u128`s.
#[derive(Clone)]
pub struct AscendingCount<T>
where
    T: From<u128> {
    t: PhantomData<T>,
    curr: u128
}

pub struct SharedIDGen<Inner>
where
    Inner: IDGen,
    Inner::Item: Default {
    inner: Arc<Mutex<Inner>>
}

impl<T> IDGen for AscendingCount<T>
where
    T: From<u128>
{
    type Config = ();

    #[inline]
    fn create(_config: Self::Config) -> Self {
        AscendingCount::default()
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

impl<T> Default for AscendingCount<T>
where
    T: From<u128>
{
    #[inline]
    fn default() -> Self {
        AscendingCount {
            t: PhantomData,
            curr: 0
        }
    }
}

impl<T> Iterator for AscendingCount<T>
where
    T: From<u128>
{
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<T> {
        let out = T::from(self.curr);

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
