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

use std::io::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use mio::Waker;

#[derive(Clone)]
pub struct Notify {
    waker: Arc<Waker>
}

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

impl Notify {
    /// Create a new `Notify`.
    #[inline]
    pub fn new(waker: Arc<Waker>) -> Self {
        Notify { waker: waker }
    }

    /// Send the notification.
    #[inline]
    pub fn notify(&self) -> Result<(), Error> {
        self.waker.wake()
    }
}

impl NotifyFlag {
    /// Send the notification.
    #[inline]
    pub fn notify(&self) -> Result<(), Error> {
        self.flag.store(true, Ordering::Release);
        self.waker.wake()
    }

    /// Clear the notification, and return whether it was set.
    #[inline]
    pub fn collect(&self) -> bool {
        self.flag.swap(false, Ordering::AcqRel)
    }
}
