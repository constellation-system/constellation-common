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

//! Codec traits for encoding/decoding objects.
//!
//! This module defines traits for codecs used by other Constellation
//! APIs.  Constellation relies on explicit codec objects for encoding
//! and decoding objects for transmission over the network, as opposed
//! to the [serde] framework.  This is done for several reasons:
//!
//! * It allows the exact formats of messages to vary for different channels.
//!
//! * It allows more precise control over the exact message formats.
//!
//! * It facilitates the use of encoding formats such as ASN.1 PER.
use std::fmt::Display;
use std::io::Read;
use std::io::Write;

pub mod per;

use crate::error::ScopedError;

pub trait Codec<T>: Sized {
    /// Parameter for the [create](DatagramCodec::create) function.
    type Param;
    /// Errors that can occur when creating an instance.
    type CreateError: Display + ScopedError;
    /// Errors that can occur when encoding.
    type EncodeError: Display + ScopedError;
    /// Errors that can occur when decoding.
    type DecodeError: Display + ScopedError;

    /// Create a new instance of this codec.
    fn create(param: Self::Param) -> Result<Self, Self::CreateError>;

    /// Encode a message into `buf` and return the number of bytes produced.
    ///
    /// The slice `buf` must contain at least
    /// [MAX_BYTES](DatagramCodec::MAX_BYTES) bytes.
    fn encode(
        &mut self,
        val: &T,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError>;

    /// Encode `val` to a newly-allocated [Vec].
    fn encode_to_vec(
        &mut self,
        val: &T
    ) -> Result<Vec<u8>, Self::EncodeError>;

    /// Decode a message into `buf` and return the number of bytes consumed.
    ///
    /// The slice `buf` must contain at least
    /// [MAX_BYTES](DatagramCodec::MAX_BYTES) bytes.
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(T, usize), Self::DecodeError>;
}

pub trait BytestreamCodec<T> {
    type StreamDecodeError: Display + ScopedError;
    type StreamEncodeError: Display + ScopedError;

    fn encode_to_stream<W>(
        &mut self,
        stream: &mut W,
        val: &T
    ) -> Result<usize, Self::StreamEncodeError>
    where
        W: Write;

    fn decode_from_stream<R>(
        &mut self,
        stream: &mut R
    ) -> Result<(T, usize), Self::StreamDecodeError>
    where
        R: Read;
}

/// Trait for encoding/decoding logic on types to datagrams.
pub trait DatagramCodec<T>: Codec<T> + Sized {
    /// Maximum message size.
    const MAX_BYTES: usize;
}
