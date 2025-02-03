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

//! Shutdown flags for multithreaded operation.
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Shutdown flag that can be triggered manually, or by a signal.
#[derive(Clone)]
pub struct ShutdownFlag {
    /// Atomic boolean flag.
    flag: Arc<AtomicBool>
}

impl Default for ShutdownFlag {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownFlag {
    /// Create a new shutdown flag.
    #[inline]
    pub fn new() -> ShutdownFlag {
        ShutdownFlag {
            flag: Arc::new(AtomicBool::new(false))
        }
    }

    /// Check if the flag is not in shutdown mode.
    #[inline]
    pub fn is_live(&self) -> bool {
        !self.is_shutdown()
    }

    /// Check if the flag is in shutdown mode.
    #[inline]
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Set the shutdown status on this flag.
    ///
    /// Once set, it cannot be unset.
    #[inline]
    pub fn set(&mut self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Get the underlying `Arc<AtomicBool>`.
    ///
    /// This should only be used for purposes like registering a
    /// signal flag.
    pub fn underlying(&self) -> Arc<AtomicBool> {
        self.flag.clone()
    }
}
