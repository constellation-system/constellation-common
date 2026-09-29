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

use std::collections::BinaryHeap;
use std::collections::HashSet;
use std::hash::Hash;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum LazyInitVec<T> {
    Full(Vec<T>),
    Empty(usize)
}

#[derive(Clone, Debug)]
pub enum LazyInitHashSet<T>
where
    T: Eq + Hash {
    Full(HashSet<T>),
    Empty(usize)
}

#[derive(Clone, Debug)]
pub enum LazyInitBinaryHeap<T>
where
    T: Eq + Ord {
    Full(BinaryHeap<T>),
    Empty(usize)
}

impl<T> LazyInitVec<T> {
    #[inline]
    pub fn new(size_hint: usize) -> Self {
        LazyInitVec::Empty(size_hint)
    }

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
    #[inline]
    pub fn new(size_hint: usize) -> Self {
        LazyInitHashSet::Empty(size_hint)
    }

    pub fn push(
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
    #[inline]
    pub fn new(size_hint: usize) -> Self {
        LazyInitBinaryHeap::Empty(size_hint)
    }

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

    #[inline]
    pub fn take(self) -> Option<BinaryHeap<T>> {
        match self {
            LazyInitBinaryHeap::Full(out) => Some(out),
            LazyInitBinaryHeap::Empty(_) => None
        }
    }
}
