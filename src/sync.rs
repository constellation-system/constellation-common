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
    waker: Arc<Waker>,
    flag: Arc<AtomicBool>
}

#[derive(Clone)]
pub struct NotifyRecv {
    flag: Arc<AtomicBool>
}

impl From<Notify> for NotifyRecv {
    #[inline]
    fn from(val: Notify) -> Self {
        NotifyRecv { flag: val.flag }
    }
}

impl Notify {
    /// Create a new `Notify`.
    #[inline]
    pub fn new(waker: Arc<Waker>) -> Self {
        Notify {
            flag: Arc::new(AtomicBool::new(false)),
            waker: waker
        }
    }

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

impl NotifyRecv {
    /// Check if the notification is set, and clear the notification.
    #[inline]
    pub fn collect(&self) -> bool {
        self.flag.swap(false, Ordering::AcqRel)
    }
}
