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

//! Codec implementations using ASN.1 packed encoding rules (PER).
//!
//! This module provides a [DatagramCodec] implementation for any type
//! implementhing the [Readable] and [Writable] traits from the
//! [asn1rs] package.  This codec encodes and decodes the type using
//! the ASN.1 packed encoding rules.
//!
//! This codec is the preferred method for encoding data for
//! transmission over far-link channels, and in general provides a
//! very dense encoding format.
use std::convert::Infallible;
use std::marker::PhantomData;

use asn1rs::io::per::err::Error;
use asn1rs::io::per::unaligned::ScopedBitRead;
use asn1rs::prelude::Reader;
use asn1rs::prelude::Writer;
use asn1rs::syn::io::UperReader;
use asn1rs::syn::io::UperWriter;
use asn1rs::syn::Readable;
use asn1rs::syn::Writable;

use crate::codec::DatagramCodec;

/// Sub-trait of [DatagramCodec] for things that can be encoded using
/// the ASN.1 packed encoding rules (PER).
pub trait DatagramPERCodec<T>: DatagramCodec<T>
where
    T: Readable + Writable {
    /// Encode `val` into the [UperWriter].
    #[inline]
    fn encode_to_writer(
        &mut self,
        val: &T,
        writer: &mut UperWriter
    ) -> Result<(), Error> {
        writer.write(val)
    }

    /// Decode a value of type `T` from the [UperReader].
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
/// This type provides a [DatagramCodec] implementation for any type
/// implementing the [Readable] and [Writable] traits from the
/// [asn1rs] packages.  This implementation encodes and decodes the
/// type using the ASN.1 packed encoding rules, providing a very dense
/// encoding format.
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

impl<T, const MAX_BITS: usize> DatagramCodec<T> for PERCodec<T, MAX_BITS>
where
    T: Readable + Writable
{
    type CreateError = Infallible;
    type DecodeError = Error;
    type EncodeError = Error;
    type Param = ();

    const MAX_BYTES: usize = ((MAX_BITS - 1) >> 3) + 1;

    #[inline]
    fn create(_param: ()) -> Result<Self, Infallible> {
        Ok(PERCodec(PhantomData))
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

    #[inline]
    fn encode_to_vec(
        &mut self,
        val: &T
    ) -> Result<Vec<u8>, Self::EncodeError> {
        let mut writer = UperWriter::with_capacity(Self::MAX_BYTES);

        self.encode_to_writer(val, &mut writer)?;

        Ok(writer.into_bytes_vec())
    }

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

impl<T, const MAX_BITS: usize> DatagramPERCodec<T> for PERCodec<T, MAX_BITS> where
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
