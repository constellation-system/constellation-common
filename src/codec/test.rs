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

//! Testing codec implementation.
//!
//! This module provides a [Decoder] and [Encoder] implementation
//! suitable for testing purposes.

use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::string::FromUtf8Error;

use crate::codec::BytestreamDecoder;
use crate::codec::BytestreamEncoder;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::config::Create;
use crate::error::ErrorScope;
use crate::error::ScopedError;

/// A simple codec implementation that implements [Encoder] and
/// [Decoder] for `String`s up to 1024 characters.
///
/// This is intended primarily for testing.
#[derive(Clone, Default)]
pub struct TestStringCodec;

/// A simple codec implementation that implements [Encoder] and
/// [Decoder] for `Vec<u8>`.
///
/// This is intended primarily for testing.
#[derive(Clone, Default)]
pub struct TestBytesCodec;

#[derive(Debug)]
pub struct TooShort {
    expected: usize,
    actual: usize
}

#[derive(Debug)]
pub enum TestDecodeError {
    FromUTF8 { err: FromUtf8Error },
    TooShort { expected: usize, actual: usize }
}

#[derive(Debug)]
pub enum TestReadError {
    IO { err: Error },
    FromUTF8 { err: FromUtf8Error }
}

impl Create for TestStringCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Self::CreateError> {
        Ok(Self::default())
    }
}

impl Create for TestBytesCodec {
    type Config = ();
    type CreateError = Infallible;

    #[inline]
    fn create(_config: ()) -> Result<Self, Self::CreateError> {
        Ok(Self::default())
    }
}

impl Decoder<String> for TestStringCodec {
    type DecodeError = TestDecodeError;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(String, usize), Self::DecodeError> {
        if buf.len() >= 4 {
            let mut len = [0; 4];

            len.copy_from_slice(&buf[..4]);

            let len = u32::from_le_bytes(len) as usize;
            let mut vec = vec![0; len];
            let buf = &buf[4..];

            if buf.len() >= len {
                vec.copy_from_slice(&buf[0..len]);

                let str = String::from_utf8(vec)
                    .map_err(|err| TestDecodeError::FromUTF8 { err: err })?;

                Ok((str, len + 4))
            } else {
                Err(TestDecodeError::TooShort {
                    actual: buf.len() + 4,
                    expected: len + 4
                })
            }
        } else {
            Err(TestDecodeError::TooShort {
                actual: buf.len(),
                expected: 4
            })
        }
    }
}

impl Decoder<Vec<u8>> for TestBytesCodec {
    type DecodeError = TestDecodeError;

    fn decode(
        &mut self,
        buf: &[u8]
    ) -> Result<(Vec<u8>, usize), Self::DecodeError> {
        if buf.len() >= 4 {
            let mut len = [0; 4];

            len.copy_from_slice(&buf[..4]);

            let len = u32::from_le_bytes(len) as usize;
            let buf = &buf[4..];

            if buf.len() >= len {
                let mut vec = vec![0; len];

                vec.copy_from_slice(&buf[0..len]);

                Ok((vec, len + 4))
            } else {
                Err(TestDecodeError::TooShort {
                    actual: buf.len() + 4,
                    expected: len + 4
                })
            }
        } else {
            Err(TestDecodeError::TooShort {
                actual: buf.len(),
                expected: 4
            })
        }
    }
}

impl Encoder<str> for TestStringCodec {
    type EncodeError = TooShort;

    #[inline]
    fn buf_size(
        &self,
        val: &str
    ) -> usize {
        val.as_bytes().len() + 4
    }

    fn encode(
        &mut self,
        val: &str,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let len = val.as_bytes().len();

        if buf.len() >= len + 4 {
            buf[..4].copy_from_slice(&(len as u32).to_le_bytes());

            let buf = &mut buf[4..];

            buf[..len].copy_from_slice(val.as_bytes());

            Ok(len as usize + 4)
        } else {
            Err(TooShort {
                expected: len + 4,
                actual: buf.len()
            })
        }
    }
}

impl Encoder<[u8]> for TestBytesCodec {
    type EncodeError = TooShort;

    #[inline]
    fn buf_size(
        &self,
        val: &[u8]
    ) -> usize {
        val.len() + 4
    }

    fn encode(
        &mut self,
        val: &[u8],
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        let len = val.len();

        if buf.len() >= len + 4 {
            buf[..4].copy_from_slice(&(len as u32).to_le_bytes());

            let buf = &mut buf[4..];

            buf[..len].copy_from_slice(val);

            Ok(len as usize + 4)
        } else {
            Err(TooShort {
                expected: len + 4,
                actual: buf.len()
            })
        }
    }
}

impl Encoder<String> for TestStringCodec {
    type EncodeError = TooShort;

    #[inline]
    fn buf_size(
        &self,
        val: &String
    ) -> usize {
        self.buf_size(val.as_str())
    }

    fn encode(
        &mut self,
        val: &String,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        self.encode(val.as_str(), buf)
    }
}

impl Encoder<Vec<u8>> for TestBytesCodec {
    type EncodeError = TooShort;

    #[inline]
    fn buf_size(
        &self,
        val: &Vec<u8>
    ) -> usize {
        self.buf_size(val.as_slice())
    }

    fn encode(
        &mut self,
        val: &Vec<u8>,
        buf: &mut [u8]
    ) -> Result<usize, Self::EncodeError> {
        self.encode(val.as_slice(), buf)
    }
}

impl BytestreamDecoder<Vec<u8>> for TestStringCodec {
    type StreamDecodeError = TestReadError;

    fn decode_from_stream<R>(
        &mut self,
        stream: &mut R
    ) -> Result<(Vec<u8>, usize), Self::StreamDecodeError>
    where
        R: Read {
        let mut len = [0; 4];

        stream
            .read_exact(&mut len)
            .map_err(|err| TestReadError::IO { err: err })?;

        let len = u32::from_le_bytes(len) as usize;
        let mut buf = vec![0; len];

        stream
            .read_exact(&mut buf)
            .map_err(|err| TestReadError::IO { err: err })?;

        Ok((buf, len + 4))
    }
}

impl BytestreamEncoder<str> for TestStringCodec {
    type StreamEncodeError = Error;

    fn encode_to_stream<W>(
        &mut self,
        stream: &mut W,
        val: &str
    ) -> Result<usize, Self::StreamEncodeError>
    where
        W: Write {
        let bytes = val.as_bytes();
        let len = bytes.len();

        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(bytes)?;

        Ok(len + 4)
    }
}

impl BytestreamEncoder<String> for TestBytesCodec {
    type StreamEncodeError = Error;

    fn encode_to_stream<W>(
        &mut self,
        stream: &mut W,
        val: &String
    ) -> Result<usize, Self::StreamEncodeError>
    where
        W: Write {
        let bytes = val.as_bytes();
        let len = bytes.len();

        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(bytes)?;

        Ok(len + 4)
    }
}

impl ScopedError for TooShort {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Msg
    }
}

impl ScopedError for TestDecodeError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Msg
    }
}

impl ScopedError for TestReadError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            TestReadError::IO { err } => err.scope(),
            TestReadError::FromUTF8 { .. } => ErrorScope::Msg
        }
    }
}

impl Display for TooShort {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "buffer length {}, required {}",
            self.actual, self.expected
        )
    }
}

impl Display for TestDecodeError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            TestDecodeError::FromUTF8 { err } => err.fmt(f),
            TestDecodeError::TooShort { actual, expected } => {
                write!(f, "buffer length {}, required {}", actual, expected)
            }
        }
    }
}

impl Display for TestReadError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            TestReadError::IO { err } => err.fmt(f),
            TestReadError::FromUTF8 { err } => err.fmt(f)
        }
    }
}

#[test]
fn test_string_codec() {
    let mut buf = [0 as u8; 15];
    let mut codec = TestStringCodec;
    let expected = "hello world";

    codec.encode(expected, &mut buf).expect("Expected success");

    let (actual, size) = codec.decode(&buf).expect("Expected success");

    assert_eq!(size, expected.len() + 4);
    assert_eq!(expected, actual);
}
