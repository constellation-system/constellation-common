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

/// Trait for dynamic-typed schemas.
///
/// These are schema elements that do not have a statically-known
/// native type.  This is intended to be used as a multiplexer to
/// convert into [SchemaElem] using [TryFrom](std::convert::TryFrom).
pub trait Schema {
    /// Type of tags, indicating what kind of schema element this
    /// represents.
    type Kind;

    /// Get the kind of schema element this represents.
    fn kind(&self) -> Self::Kind;
}

/// Type of static-typed schemas.
///
/// This is a master trait for schema elements that have a known
/// native type.
pub trait SchemaElem {
    /// Native type of this schema element.
    type Native;
    /// Errors that can occur validating a value of type
    /// [Native](Self::Native).
    type ValidateError;

    /// Validate a value of type [Native](Self::Native).
    fn validate(
        &self,
        val: &Self::Native
    ) -> Result<(), Self::ValidateError>;
}
