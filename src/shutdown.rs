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

//! Shutdown flags for multithreaded operation.
use std::io::Error;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use mio::Waker;

use crate::error::MutexPoison;
use crate::error::WithMutexPoison;

/// Shutdown flag that can be triggered manually, or by a signal.
#[derive(Clone)]
pub struct ShutdownFlag {
    wakers: Arc<RwLock<Vec<Arc<Waker>>>>,
    /// Atomic boolean flag.
    flag: Arc<AtomicBool>
}

impl Default for ShutdownFlag {
    #[inline]
    fn default() -> Self {
        ShutdownFlag {
            flag: Arc::new(AtomicBool::new(false)),
            wakers: Arc::new(RwLock::new(Vec::new()))
        }
    }
}

impl ShutdownFlag {
    /// Create a new shutdown flag.
    #[inline]
    pub fn new() -> ShutdownFlag {
        Self::default()
    }

    /// Create a new shutdown flag.
    #[inline]
    pub fn with_capacity(size: usize) -> ShutdownFlag {
        ShutdownFlag {
            flag: Arc::new(AtomicBool::new(false)),
            wakers: Arc::new(RwLock::new(Vec::with_capacity(size)))
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

    /// Register a new [Waker].
    #[inline]
    pub fn add_waker(
        &mut self,
        waker: Arc<Waker>
    ) -> Result<(), MutexPoison> {
        self.wakers.write().map_err(|_| MutexPoison)?.push(waker);

        Ok(())
    }

    /// Set the shutdown status on this flag.
    ///
    /// Once set, it cannot be unset.
    #[inline]
    pub fn set(&mut self) -> Result<(), WithMutexPoison<Error>> {
        self.flag.store(true, Ordering::Release);
        self.wakers
            .read()
            .map_err(|_| WithMutexPoison::MutexPoison)?
            .iter()
            .try_for_each(|waker| {
                waker
                    .wake()
                    .map_err(|err| WithMutexPoison::Inner { err: err })
            })
    }
}
