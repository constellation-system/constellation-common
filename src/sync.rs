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

// XXX rename this to notify.

//! Notification functionality for [`mio`].
//!
//! This module defines two types that act as wrappers for the
//! [`Waker`] type found in [`mio`].  These allow threads to be
//! noified of non-I/O events, such as available messages in a queue.

use std::io::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use mio::Waker;

/// Notifier for an [`mio`] thread.
///
/// This acts as a wrapper for the [`Waker`] type, allowing threads to
/// be notified of non-I/O events.
#[derive(Clone)]
pub struct Notify {
    waker: Arc<Waker>
}

/// Notifier for an [`mio`] thread, with a flag.
///
/// This acts as a wrapper for the [`Waker`] type, allowing threads to
/// be notified of non-I/O events.  This also has an atomic boolean
/// flag that can be checked and cleared.
///
/// # Usage
///
/// A `NotifyFlag` can be obtained from a [`Notify`] using its
/// [`From`] instances.
#[derive(Clone)]
pub struct NotifyFlag {
    waker: Arc<Waker>,
    flag: Arc<AtomicBool>
}

impl From<NotifyFlag> for Notify {
    #[inline]
    fn from(val: NotifyFlag) -> Self {
        Notify::from(&val)
    }
}

impl From<&'_ NotifyFlag> for Notify {
    #[inline]
    fn from(val: &NotifyFlag) -> Self {
        Notify {
            waker: val.waker.clone()
        }
    }
}

impl From<Notify> for NotifyFlag {
    #[inline]
    fn from(val: Notify) -> Self {
        NotifyFlag::from(&val)
    }
}

impl From<&'_ Notify> for NotifyFlag {
    #[inline]
    fn from(val: &Notify) -> Self {
        NotifyFlag {
            flag: Arc::new(AtomicBool::new(false)),
            waker: val.waker.clone()
        }
    }
}

// XXX Take a non-Arc waker in the new function.  Or just use a From
// instance.

impl Notify {
    /// Create a new `Notify`.
    ///
    /// # Parameters
    ///
    /// - `Waker`: The [`Waker`] from which to create this `Notify`.
    #[inline]
    pub fn new(waker: Arc<Waker>) -> Self {
        Notify { waker: waker }
    }

    /// Send a notification.
    ///
    /// This will cause any [`mio`] polling in the corresponding
    /// thread to return.
    #[inline]
    pub fn notify(&self) -> Result<(), Error> {
        self.waker.wake()
    }
}

impl NotifyFlag {
    /// Send a notification.
    ///
    /// This will cause any [`mio`] polling in the corresponding
    /// thread to return.
    #[inline]
    pub fn notify(&self) -> Result<(), Error> {
        self.flag.store(true, Ordering::Release);
        self.waker.wake()
    }

    /// Clear the notification, and return whether it was set.
    ///
    /// # Return Value
    ///
    /// Whether the flag had been set by another thread's
    /// [`notify`](NotifyFlag::notify)
    #[inline]
    pub fn collect(&self) -> bool {
        self.flag.swap(false, Ordering::AcqRel)
    }
}
