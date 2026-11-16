// Copyright © 2024-26 The Johns Hopkins Applied Physics Laboratory LLC.
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

// XXX rename this module to lazy.

//! Lazy-initialized data structures.
//!
//! This module provides several lazy-initialized data structures.
//! These are useful for cases where elements need to be accumulated
//! as part of traversing some structure or iterator, but there is a
//! high probability of zero elements at the end.  An example use case
//! is processing batches, and accumulating errors or retries.

use std::collections::BinaryHeap;
use std::collections::HashSet;
use std::hash::Hash;

/// Lazy-initialized [`Vec`].
///
/// This is a [`Vec`] that will be initialized only when the first
/// element is added.
///
/// # Type Parameters
///
/// - `T`: Type of elements.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum LazyInitVec<T> {
    Full(Vec<T>),
    Empty(usize)
}

/// Lazy-initialized [`HashSet`].
///
/// This is a [`HashSet`] that will be initialized only when the first
/// element is added.
///
/// # Type Parameters
///
/// - `T`: Type of elements.
#[derive(Clone, Debug)]
pub enum LazyInitHashSet<T>
where
    T: Eq + Hash {
    Full(HashSet<T>),
    Empty(usize)
}

/// Lazy-initialized [`BinaryHeap`].
///
/// This is a [`BinaryHeap`] that will be initialized only when the
/// first element is added.
///
/// # Type Parameters
///
/// - `T`: Type of elements.
#[derive(Clone, Debug)]
pub enum LazyInitBinaryHeap<T>
where
    T: Eq + Ord {
    Full(BinaryHeap<T>),
    Empty(usize)
}

impl<T> LazyInitVec<T> {
    /// Create a new `LazyInitVec`.
    ///
    /// # Parameters
    ///
    /// - `size_hint`: Size hint that will be used if the `LazyInitVec` is
    ///   initialized.
    #[inline]
    pub fn new(size_hint: usize) -> Self {
        LazyInitVec::Empty(size_hint)
    }

    /// Push an element to the `LazyInitVec`.
    ///
    /// This is analogous to [`Vec::push`].  If the `LazyInitVec` has
    /// not yet been initialized, this call will initialize it.
    ///
    /// # Parameters
    ///
    /// - `val`: Element to push.
    pub fn push(
        &mut self,
        val: T
    ) {
        match self {
            LazyInitVec::Full(vec) => {
                vec.push(val);
            }
            LazyInitVec::Empty(size) => {
                let mut vec = Vec::with_capacity(*size);

                vec.push(val);
                *self = LazyInitVec::Full(vec);
            }
        }
    }

    /// Append a [`Vec`] to the `LazyInitVec`.
    ///
    /// This is analogous to [`Vec::append`].  If the `LazyInitVec` has
    /// not yet been initialized, this call will initialize it.
    ///
    /// # Parameters
    ///
    /// - `val`: [`Vec`] to append.
    pub fn append(
        &mut self,
        val: &mut Vec<T>
    ) {
        match self {
            LazyInitVec::Full(vec) => {
                vec.append(val);
            }
            LazyInitVec::Empty(size) => {
                let mut vec = Vec::with_capacity(*size);

                vec.append(val);
                *self = LazyInitVec::Full(vec);
            }
        }
    }

    /// Obtain the underlying [`Vec`], if this has been initialized.
    ///
    /// This will consume the `LazyInitVec` and produce the [`Vec`],
    /// if any elements were added.
    #[inline]
    pub fn take(self) -> Option<Vec<T>> {
        match self {
            LazyInitVec::Full(out) => Some(out),
            LazyInitVec::Empty(_) => None
        }
    }
}

impl<T> LazyInitHashSet<T>
where
    T: Eq + Hash
{
    /// Create a new `LazyInitHashSet`.
    ///
    /// # Parameters
    ///
    /// - `size_hint`: Size hint that will be used if the `LazyInitHashSet` is
    ///   initialized.
    #[inline]
    pub fn new(size_hint: usize) -> Self {
        LazyInitHashSet::Empty(size_hint)
    }

    /// Insert an element into the `LazyInitVec`.
    ///
    /// This is analogous to [`HashSet::insert`].  If the
    /// `LazyInitHashSet` has not yet been initialized, this call will
    /// initialize it.
    ///
    /// # Parameters
    ///
    /// - `val`: Element to insert.
    pub fn insert(
        &mut self,
        val: T
    ) {
        match self {
            LazyInitHashSet::Full(set) => {
                set.insert(val);
            }
            LazyInitHashSet::Empty(size) => {
                let mut set = HashSet::with_capacity(*size);

                set.insert(val);
                *self = LazyInitHashSet::Full(set);
            }
        }
    }

    /// Extend a `LazyInitHashSet` with a [`Vec`].
    ///
    /// This is analogous to [`HashSet::extend`].  If the
    /// `LazyInitHashSet` has not yet been initialized, this call will
    /// initialize it.
    ///
    /// # Parameters
    ///
    /// - `val`: [`Vec`] with which to extend..
    pub fn extend(
        &mut self,
        val: Vec<T>
    ) {
        match self {
            LazyInitHashSet::Full(set) => {
                set.extend(val);
            }
            LazyInitHashSet::Empty(size) => {
                let mut set = HashSet::with_capacity(*size);

                set.extend(val);
                *self = LazyInitHashSet::Full(set);
            }
        }
    }

    /// Obtain the underlying [`HashSet`], if this has been initialized.
    ///
    /// This will consume the `LazyInitHashSet` and produce the
    /// [`HashSet`], if any elements were added.
    #[inline]
    pub fn take(self) -> Option<HashSet<T>> {
        match self {
            LazyInitHashSet::Full(out) => Some(out),
            LazyInitHashSet::Empty(_) => None
        }
    }
}

impl<T> LazyInitBinaryHeap<T>
where
    T: Eq + Ord
{
    /// Create a new `LazyInitBinaryHeap`.
    ///
    /// # Parameters
    ///
    /// - `size_hint`: Size hint that will be used if the `LazyInitBinaryHeap`
    ///   is initialized.
    #[inline]
    pub fn new(size_hint: usize) -> Self {
        LazyInitBinaryHeap::Empty(size_hint)
    }

    /// Push an element to the `LazyInitBinaryHeap`.
    ///
    /// This is analogous to [`BinaryHeap::push`].  If the
    /// `LazyInitBinaryHeap` has not yet been initialized, this call
    /// will initialize it.
    ///
    /// # Parameters
    ///
    /// - `val`: Element to push.
    pub fn push(
        &mut self,
        val: T
    ) {
        match self {
            LazyInitBinaryHeap::Full(heap) => {
                heap.push(val);
            }
            LazyInitBinaryHeap::Empty(size) => {
                let mut heap = BinaryHeap::with_capacity(*size);

                heap.push(val);
                *self = LazyInitBinaryHeap::Full(heap);
            }
        }
    }

    /// Extend a `LazyInitBinaryHeap` with a [`Vec`].
    ///
    /// This is analogous to [`BinaryHeap::extend`].  If the
    /// `LazyInitBinaryHeap` has not yet been initialized, this call
    /// will initialize it.
    ///
    /// # Parameters
    ///
    /// - `val`: [`Vec`] with which to extend..
    pub fn extend(
        &mut self,
        val: Vec<T>
    ) {
        match self {
            LazyInitBinaryHeap::Full(heap) => {
                heap.extend(val);
            }
            LazyInitBinaryHeap::Empty(size) => {
                let mut heap = BinaryHeap::with_capacity(*size);

                heap.extend(val);
                *self = LazyInitBinaryHeap::Full(heap);
            }
        }
    }

    /// Obtain the underlying [`BinaryHeap`], if this has been initialized.
    ///
    /// This will consume the `LazyInitBinaryHeap` and produce the
    /// [`BinaryHeap`], if any elements were added.
    #[inline]
    pub fn take(self) -> Option<BinaryHeap<T>> {
        match self {
            LazyInitBinaryHeap::Full(out) => Some(out),
            LazyInitBinaryHeap::Empty(_) => None
        }
    }
}
