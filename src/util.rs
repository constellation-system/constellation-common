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
            LazyInitHashSet::Full(vec) => {
                vec.insert(val);
            }
            LazyInitHashSet::Empty(size) => {
                let mut vec = HashSet::with_capacity(*size);

                vec.insert(val);
                *self = LazyInitHashSet::Full(vec);
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
