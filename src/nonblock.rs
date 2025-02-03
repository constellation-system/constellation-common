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

//! Nonblocking result type.
//!
//! This module provides the [NonblockResult] type.

//! [NonblockResult] is a type similar to [Result], but intended for
//! operations where an attempt is made at a non-blocking variant,
//! which might fail due to the need to block.

/// Results that can be returned from an attempt at a non-blocking
/// operation.
pub enum NonblockResult<S, F> {
    /// The operation was successful.
    Success(S),
    /// The operation failed because it needed to block.
    Fail(F)
}
