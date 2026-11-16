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

//! Codec implementations using ASN.1 packed encoding rules (PER).
//!
//! This module provides a [`DatagramCodec`] implementation for any type
//! implementhing the [`Readable`] and [`Writable`] traits from the
//! [`asn1rs`] package.  This codec encodes and decodes the type using
//! the ASN.1 packed encoding rules.
//!
//! This codec is the preferred method for encoding data for
//! transmission over far-link channels, and in general provides a
//! very dense encoding format.
//!
//! # Rationale for ASN.1 PER
//!
//! ASN.1 may seem at first to be a somewhat archaic design choice,
//! and PER may also seem unusual.  The following are factors that
//! lead to this choice:
//!
//! - ASN.1 PER remains one of the densest encoding formats available, and
//!   indeed it would be difficult to exceed its density without considerably
//!   more effort per datatype (e.g. arithmetic enconding)
//!
//!   - Constellation's protocols *should* be designed to be dense, as some of
//!     its operating environments involve significant bandwidth constraints.
//!
//!   - Constellation's protocols should also be highly entropic (meaning they
//!     look similar to random noise), as this offers a degree of censorship and
//!     cryptanalysis resistance.
//!
//! - Many message and data format standards (particularly those dealing with
//!   cryptography) are defined using ASN.1.
//!
//!   - These data formats can be directly incorporated into Constellation's
//!     protocols.  Technically the use of PER for these would be
//!     standard-nonconforming, but that will not affect anything other than
//!     Constellation.
//!
//! - Historically, ASN.1 developed a bad reputation for reasons that are no
//!   longer valid:
//!
//!   - The standards were originally closed, and required expensive
//!     subscriptions to obtain.  This has not been the case for some time.
//!
//!   - Development tools also were not available except at considerable cost,
//!     and tended to be of low quality.  This is also no longer the case (the
//!     [asn1rs] package, for example).
//!
//!   - Legacy parser implementations were prone to buffer overflow
//!     vulnerabilities.
//!
//!   - Its datatype schema is somewhat archaic.  This comes down to the
//!     presence of alternative string datatypes, and the lack of type
//!     parameters.  The second is more significant, but can be worked around at
//!     the application level.
//!
//!   - BER and its derivatives are fairly wasteful in terms of space (however,
//!     web-based encodings are far worse).  However, Costellation uses PER.
use std::convert::Infallible;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;

use asn1rs::io::per::err::Error;
use asn1rs::io::per::unaligned::ScopedBitRead;
use asn1rs::prelude::Reader;
use asn1rs::prelude::Writer;
use asn1rs::syn::Readable;
use asn1rs::syn::Writable;
use asn1rs::syn::io::UperReader;
use asn1rs::syn::io::UperWriter;

use crate::codec::BytestreamDecoder;
use crate::codec::BytestreamEncoder;
use crate::codec::DatagramCodec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::config::Create;
use crate::error::CodecStreamError;

/// Sub-trait of [`DatagramCodec`] for things that can be encoded using
/// the ASN.1 packed encoding rules (PER).
///
/// # Type Parameters
///
/// - `T`: The type represented in messages.
pub trait DatagramPEREncoder<T>: DatagramCodec<T>
where
    T: Readable + Writable {
    /// Encode `val` into the [`UperWriter`].
    ///
    /// # Parameters
    ///
    /// - `val`: Value to be encoded.
    ///
    /// - `writer`: [`UperWriter`] to use to encode.
    #[inline]
    fn encode_to_writer(
        &mut self,
        val: &T,
        writer: &mut UperWriter
    ) -> Result<(), Error> {
        writer.write(val)
    }
}

/// Sub-trait of [`DatagramCodec`] for things that can be decoded using
/// the ASN.1 packed encoding rules (PER).
///
/// # Type Parameters
///
/// - `T`: The type represented in messages.
pub trait DatagramPERDecoder<T>: DatagramCodec<T>
where
    T: Readable + Writable {
    /// Decode a value of type `T` from the [`UperReader`].
    ///
    /// # Parameters
    ///
    /// - `reader`: [`UperReader`] to use to decode.
    #[inline]
    fn decode_from_reader<B>(
        &mut self,
        reader: &mut UperReader<B>
    ) -> Result<T, Error>
    where
        B: ScopedBitRead {
        reader.read::<T>()
    }
}

/// Codec for encoding/decoding using ASN.1 packed encoding rules (PER).
///
/// This type provides a [`DatagramCodec`] implementation for any type
/// implementing the [`Readable`] and [Writable] traits from the
/// [asn1rs] packages.  This implementation encodes and decodes the
/// type using the ASN.1 packed encoding rules, providing a very dense
/// encoding format.
///
/// # Limitations
///
/// At present, it is required to specify the maximum size of the
/// encoded message.  This is a limitation inherited from the [asn1rs]
/// package, and should be removed from the Constellation APIs
/// whenever it is eliminated in `asn1rs`.
///
/// # Type Parameters
///
/// - `T`: The type represented in messages.
///
/// - `MAX_BITS`: Maximum size of the encoded message in bits.
pub struct PERCodec<T: Readable + Writable, const MAX_BITS: usize>(
    PhantomData<T>
);

impl<T, const MAX_BITS: usize> Clone for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    #[inline]
    fn clone(&self) -> Self {
        PERCodec(self.0)
    }
}

impl<T, const MAX_BITS: usize> Create for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Infallible> {
        Ok(PERCodec(PhantomData))
    }
}

impl<T, const MAX_BITS: usize> Decoder<T> for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    type DecodeError = Error;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(T, usize), Self::DecodeError> {
        let (mut reader, max_bits) = if buf.len() > Self::MAX_BYTES {
            let max_bits = Self::MAX_BYTES * 8;

            (
                UperReader::from((&buf[..Self::MAX_BYTES], max_bits)),
                max_bits
            )
        } else {
            let max_bits = buf.len() * 8;

            (UperReader::from((buf, max_bits)), max_bits)
        };
        let out = self.decode_from_reader(&mut reader)?;
        let nbits = max_bits - reader.bits_remaining();

        let nbytes = if nbits != 0 {
            ((nbits - 1) >> 3) + 1
        } else {
            0
        };

        Ok((out, nbytes))
    }
}

impl<T, const MAX_BITS: usize> Encoder<T> for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    type EncodeError = Error;

    #[inline]
    fn buf_size(
        &self,
        _val: &T
    ) -> usize {
        if MAX_BITS > 0 {
            ((MAX_BITS - 1) / 8) + 1
        } else {
            0
        }
    }

    #[inline]
    fn encode_to_vec(
        &mut self,
        val: &T
    ) -> Result<Vec<u8>, Self::EncodeError> {
        let mut writer = UperWriter::with_capacity(Self::MAX_BYTES);

        self.encode_to_writer(val, &mut writer)?;

        Ok(writer.into_bytes_vec())
    }

    #[inline]
    fn encode(
        &mut self,
        val: &T,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let vec = self.encode_to_vec(val)?;
        let len = vec.len();

        buf[..len].copy_from_slice(&vec);

        Ok(len)
    }
}

impl<T, const MAX_BITS: usize> BytestreamDecoder<T> for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    type StreamDecodeError = CodecStreamError<Error, std::io::Error>;

    fn decode_from_stream<R>(
        &mut self,
        stream: &mut R
    ) -> Result<(T, usize), Self::StreamDecodeError>
    where
        R: Read {
        // XXX eventually, this should just directly decode from the stream.
        let mut lenbuf = [0; 2];

        stream
            .read_exact(&mut lenbuf[..])
            .map_err(|err| CodecStreamError::IO { err: err })?;

        let len = (lenbuf[0] as usize) | (lenbuf[1] as usize) << 1;
        let mut buf = vec![0; len];

        stream
            .read_exact(&mut buf[..])
            .map_err(|err| CodecStreamError::IO { err: err })?;

        let (val, _) = self
            .decode(&buf)
            .map_err(|err| CodecStreamError::Codec { err: err })?;

        Ok((val, len + 2))
    }
}

impl<T, const MAX_BITS: usize> BytestreamEncoder<T> for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    type StreamEncodeError = CodecStreamError<Error, std::io::Error>;

    fn encode_to_stream<W>(
        &mut self,
        stream: &mut W,
        val: &T
    ) -> Result<usize, Self::StreamEncodeError>
    where
        W: Write {
        // XXX eventually, this should just directly encode to the stream.
        let mut buf = vec![0; Self::MAX_BYTES + 2];
        let nbytes = self
            .encode(val, &mut buf[2..Self::MAX_BYTES + 2])
            .map_err(|err| CodecStreamError::Codec { err: err })?;

        buf[0] = (nbytes & 0xff) as u8;
        buf[1] = ((nbytes >> 1) & 0xff) as u8;
        buf.truncate(nbytes + 2);

        stream
            .write_all(&buf)
            .map_err(|err| CodecStreamError::IO { err: err })?;

        Ok(nbytes + 2)
    }
}

impl<T, const MAX_BITS: usize> DatagramCodec<T> for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    const MAX_BYTES: usize = ((MAX_BITS - 1) >> 3) + 1;
}

impl<T, const MAX_BITS: usize> DatagramPERDecoder<T> for PERCodec<T, MAX_BITS> where
    T: Readable + Writable
{
}

impl<T, const MAX_BITS: usize> DatagramPEREncoder<T> for PERCodec<T, MAX_BITS> where
    T: Readable + Writable
{
}

impl<T, const MAX_BITS: usize> Default for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    #[inline]
    fn default() -> Self {
        PERCodec(PhantomData)
    }
}
