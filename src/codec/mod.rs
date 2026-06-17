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

//! Codec traits for encoding/decoding objects.
//!
//! This module defines traits for codecs used by other Constellation
//! APIs.  Constellation relies on explicit codec objects for encoding
//! and decoding objects for transmission over the network, as opposed
//! to the [serde] framework.  This is done for several reasons:
//!
//! - It allows the exact formats of messages to vary for different channels.
//!
//! - It allows more precise control over the exact message formats.
//!
//! - It facilitates the use of encoding formats such as ASN.1 PER.
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Read;
use std::io::Write;

pub mod per;
pub mod test;

use crate::error::ErrorScope;
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
/// - `T`: The type represented in messages.
pub trait DatagramCodec<T> {
    /// Maximum message size.
    const MAX_BYTES: usize;
}

/// Trait for encoding logic from `T` to a datagram message format.
///
/// # Type Parameters
///
/// - `T`: The type represented in messages.
pub trait Encoder<T: ?Sized> {
    /// Errors that can occur when encoding.
    type EncodeError: Debug + Display + ScopedError;

    /// Get a safe size for buffers for [encode](Encoder::encode)ing
    /// `val`.
    ///
    /// This can return a size larger than needed.
    ///
    /// # Parameters
    ///
    /// - `val`: Value to be encoded.
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
    /// - `val`: Value to be encoded.
    ///
    /// - `buf`: Buffer into which to encode.
    fn encode(
        &mut self,
        val: &T,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError>;

    /// Encode `val` to a newly-allocated [Vec].
    ///
    /// # Parameters
    ///
    /// - `val`: Value to be encoded.
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
/// - `T`: The type represented in messages.
pub trait Decoder<T> {
    /// Errors that can occur when decoding.
    type DecodeError: Debug + Display + ScopedError;

    /// Decode a message from `buf` and return the number of bytes consumed.
    ///
    /// The slice `buf` must contain at least
    /// [MAX_BYTES](DatagramCodec::MAX_BYTES) bytes.
    ///
    /// # Parameters
    ///
    /// - `buf`: Buffer from which to decode.
    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(T, usize), Self::DecodeError>;
}

/// Trait for encoding logic from `T` to a [Write]r.
///
/// # Type Parameters
///
/// - `T`: The type represented in messages.
pub trait BytestreamEncoder<T: ?Sized> {
    type StreamEncodeError: Debug + Display + ScopedError;

    /// Encode a message into `stream` and return the number of bytes
    /// produced.
    ///
    /// # Type Parameters
    ///
    /// - `W`: The type of bytestream [Write]rs used.
    ///
    /// # Parameters
    ///
    /// - `stream`: Stream to which to write `val`.
    ///
    /// - `val`: Value to be encoded.
    fn encode_to_stream<W>(
        &mut self,
        stream: &mut W,
        val: &T
    ) -> Result<usize, Self::StreamEncodeError>
    where
        W: Write;
}

/// Trait for decoding logic from a bytestream [Read]er to a `T`.
///
/// # Type Parameters
///
/// - `T`: The type represented in messages.
pub trait BytestreamDecoder<T> {
    type StreamDecodeError: Debug + Display + ScopedError;

    /// Decode a message from `stream` and return the number of bytes
    /// consumed.
    ///
    /// The slice `buf` must contain at least
    /// [MAX_BYTES](DatagramCodec::MAX_BYTES) bytes.
    ///
    /// # Type Parameters
    ///
    /// - `R`: Type of bytestream [Read]ers used.
    ///
    /// # Parameters
    ///
    /// - `stream`: Bytestream [Read]er from which to read the message.
    fn decode_from_stream<R>(
        &mut self,
        stream: &mut R
    ) -> Result<(T, usize), Self::StreamDecodeError>
    where
        R: Read;
}

/// Simple [Encoder]/[Decoder] instance for a `usize`.
///
/// This is intended primarily for testing.
pub struct USizeCodec;

/// Simple [Encoder]/[Decoder] instance for a `isize`.
///
/// This is intended primarily for testing.
pub struct ISizeCodec;

/// Error indicating the buffer was too short.
#[derive(Debug)]
pub struct TooShort;

impl Decoder<usize> for USizeCodec {
    type DecodeError = TooShort;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(usize, usize), Self::DecodeError> {
        let size = (usize::BITS / 8) as usize;

        if size <= buf.len() {
            let mut data = [0; (usize::BITS / 8) as usize];

            data.copy_from_slice(&buf[..size]);

            Ok((usize::from_le_bytes(data), size))
        } else {
            Err(TooShort)
        }
    }
}

impl Decoder<isize> for ISizeCodec {
    type DecodeError = TooShort;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(isize, usize), Self::DecodeError> {
        let size = (isize::BITS / 8) as usize;

        if size <= buf.len() {
            let mut data = [0; (isize::BITS / 8) as usize];

            data.copy_from_slice(&buf[..size]);

            Ok((isize::from_le_bytes(data), size))
        } else {
            Err(TooShort)
        }
    }
}

impl Encoder<usize> for USizeCodec {
    type EncodeError = TooShort;

    #[inline]
    fn buf_size(
        &self,
        _val: &usize
    ) -> usize {
        (usize::BITS / 8) as usize
    }

    #[inline]
    fn encode(
        &mut self,
        val: &usize,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let size = self.buf_size(val);

        if size <= buf.len() {
            buf.copy_from_slice(&val.to_le_bytes());

            Ok(size)
        } else {
            Err(TooShort)
        }
    }
}

impl Encoder<isize> for ISizeCodec {
    type EncodeError = TooShort;

    #[inline]
    fn buf_size(
        &self,
        _val: &isize
    ) -> usize {
        (isize::BITS / 8) as usize
    }

    #[inline]
    fn encode(
        &mut self,
        val: &isize,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let size = self.buf_size(val);

        if size <= buf.len() {
            buf.copy_from_slice(&val.to_le_bytes());

            Ok(size)
        } else {
            Err(TooShort)
        }
    }
}

impl ScopedError for TooShort {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Unrecoverable
    }
}

impl Display for TooShort {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "buffer is too small")
    }
}
