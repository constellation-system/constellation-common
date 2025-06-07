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

/// Trait for encoding/decoding logic from types to datagrams of
/// constant size.
///
/// This only provides the [MAX_BYTES](DatagramCodec::MAX_BYTES)
/// constant; actual encoding/decoding logic is provided by [Encoder]
/// and [Decoder].
///
/// # Type Parameters
///
/// * `T`: The type represented in messages.
pub trait DatagramCodec<T> {
    /// Maximum message size.
    const MAX_BYTES: usize;
}

/// Trait for encoding logic from `T` to a datagram message format.
///
/// # Type Parameters
///
/// * `T`: The type represented in messages.
pub trait Encoder<T> {
    /// Errors that can occur when encoding.
    type EncodeError: Display + ScopedError;

    /// Get a safe size for buffers for [encode](Encoder::encode)ing
    /// `val`.
    ///
    /// This can return a size larger than needed.
    ///
    /// # Parameters
    ///
    /// * `val`: Value to be encoded.
    fn buf_size(
        &self,
        val: &T
    ) -> usize;

    /// Encode a message into `buf` and return the number of bytes produced.
    ///
    /// The slice `buf` must contain at least
    /// [MAX_BYTES](DatagramCodec::MAX_BYTES) bytes.
    ///
    /// # Parameters
    ///
    /// * `val`: Value to be encoded.
    /// * `buf`: Buffer into which to encode.
    fn encode(
        &mut self,
        val: &T,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError>;

    /// Encode `val` to a newly-allocated [Vec].
    ///
    /// # Parameters
    ///
    /// * `val`: Value to be encoded.
    fn encode_to_vec(
        &mut self,
        val: &T
    ) -> Result<Vec<u8>, Self::EncodeError> {
        let mut buf = vec![0; self.buf_size(val)];

        self.encode(val, &mut buf)?;

        Ok(buf)
    }
}

/// Trait for decoding logic from a datagram message format to a
/// `T`.
///
/// # Type Parameters
///
/// * `T`: The type represented in messages.
pub trait Decoder<T> {
    /// Errors that can occur when decoding.
    type DecodeError: Display + ScopedError;

    /// Decode a message into `buf` and return the number of bytes consumed.
    ///
    /// The slice `buf` must contain at least
    /// [MAX_BYTES](DatagramCodec::MAX_BYTES) bytes.
    ///
    /// # Parameters
    ///
    /// * `buf`: Buffer from which to decode.
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(T, usize), Self::DecodeError>;
}

pub trait BytestreamEncoder<T> {
    type StreamEncodeError: Display + ScopedError;

    fn encode_to_stream<W>(
        &mut self,
        stream: &mut W,
        val: &T
    ) -> Result<usize, Self::StreamEncodeError>
    where
        W: Write;
}

pub trait BytestreamDecoder<T> {
    type StreamDecodeError: Display + ScopedError;

    fn decode_from_stream<R>(
        &mut self,
        stream: &mut R
    ) -> Result<(T, usize), Self::StreamDecodeError>
    where
        R: Read;
}
