// Copyright © 2024 The Johns Hopkins Applied Physics Laboratory LLC.
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

use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Instant;
use std::time::Duration;

use crate::error::MutexPoison;

struct NotifyContent {
    cond: Condvar,
    flag: Mutex<bool>
}

/// One-shot notification that supports a wait operation.
#[derive(Clone)]
pub struct Notify(Arc<NotifyContent>);

impl Notify {
    /// Create a new `Notify`.
    #[inline]
    pub fn new() -> Self {
        Notify(Arc::new(NotifyContent {
            cond: Condvar::new(),
            flag: Mutex::new(false)
        }))
    }

    /// Send the notification.
    pub fn notify(&self) -> Result<(), MutexPoison> {
        let mut guard = self.0.flag.lock().map_err(|_| MutexPoison)?;

        *guard = true;
        self.0.cond.notify_all();

        Ok(())
    }

    /// Wait on the notification for a fixed amount of time.
    ///
    /// This will filter spurious wakeups.
    pub fn wait_timeout(
        &self,
        timeout: Duration
    ) -> Result<bool, MutexPoison> {
        let mut guard = self.0.flag.lock().map_err(|_| MutexPoison)?;
        let when = Instant::now() + timeout;

        while when < Instant::now() && !*guard {
            guard = self
                .0
                .cond
                .wait_timeout(guard, timeout)
                .map_err(|_| MutexPoison)?
                .0;
        }

        let out = *guard;

        Ok(out)
    }

    /// Wait on the notification.
    ///
    /// This will filter spurious wakeups.
    pub fn wait(&self) -> Result<(), MutexPoison> {
        let mut guard = self.0.flag.lock().map_err(|_| MutexPoison)?;

        while !*guard {
            guard = self.0.cond.wait(guard).map_err(|_| MutexPoison)?;
        }

        Ok(())
    }
}

#[cfg(test)]
use std::thread::sleep;
#[cfg(test)]
use std::thread::spawn;

#[test]
fn test_notify() {
    let notify = Notify::new();

    let listen_notify = notify.clone();
    let listen = spawn(move || {
        listen_notify.wait().expect("Expected success");
    });
    let send_notify = notify.clone();
    let send = spawn(move || {
        sleep(Duration::from_secs(1));
        send_notify.notify().expect("Expected success");
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_notify_before() {
    let notify = Notify::new();

    let send_notify = notify.clone();
    let send = spawn(move || {
        send_notify.notify().expect("Expected success");
    });
    let listen_notify = notify.clone();
    let listen = spawn(move || {
        sleep(Duration::from_secs(1));
        listen_notify.wait().expect("Expected success");
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_notify_wait_timeout() {
    let notify = Notify::new();

    let listen_notify = notify.clone();
    let listen = spawn(move || {
        let res = listen_notify
            .wait_timeout(Duration::from_millis(100))
            .expect("Expected success");

        assert!(!res)
    });
    let send_notify = notify.clone();
    let send = spawn(move || {
        sleep(Duration::from_secs(1));
        send_notify.notify().expect("Expected success");
    });

    listen.join().unwrap();
    send.join().unwrap();
}
