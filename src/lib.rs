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

//! Common definitions and functionality for the Constellation
//! distributed systems platform.
//!
//! This package contains a collection of common definitions and
//! functionality for use in other packages in the Constellation
//! distributed systems platform.  In general, a particular
//! functionality should be added to this package only if one or more
//! of the following is true:
//!
//! * The functionality does not clearly belong in another package.
//!
//! * Placing the functionality in another package results in a dependency
//!   cycle, or otherwise pointless dependency relationships.
#![feature(peer_credentials_unix_socket)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

#[allow(clippy::all)]
#[rustfmt::skip]

mod generated;

pub mod codec;
pub mod config;
pub mod error;
pub mod hashid;
pub mod net;
pub mod nonblock;
pub mod retry;
pub mod sched;
pub mod shutdown;
pub mod sync;
pub mod version;

#[cfg(test)]
use std::sync::Once;

#[cfg(test)]
use log::LevelFilter;

#[cfg(test)]
static INIT: Once = Once::new();

#[cfg(test)]
fn init() {
    INIT.call_once(|| {
        env_logger::builder()
            .is_test(true)
            .filter_level(LevelFilter::Trace)
            .init()
    })
}
