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

//! Common traits for network communications.
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::str::FromStr;
use std::time::Instant;

use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

use crate::error::ScopedError;

/// Trait for sources of messages to be sent over a shared channel.
pub trait SharedMsgs<Party, Msg> {
    /// Type of errors that can occur when collecting messages.
    type MsgsError: Display + ScopedError;

    /// Collect and report outbound messages.
    ///
    /// This will provide the outbound messages, if there are any, as
    /// well as the time at which to check again for new messages.
    fn msgs(
        &mut self
    ) -> Result<
        (Option<Vec<(Vec<Party>, Vec<Msg>)>>, Option<Instant>),
        Self::MsgsError
    >;
}

/// Common supertrait for socket-like objects.
///
/// This trait is intended to be implemented by things that behave
/// like low-level sockets, which will typically be thin wrappers
/// around Unix datagram or UDP sockets.
pub trait Socket: Send + Sync {
    type Addr: Clone + Display + Eq;

    /// Get the local socket address.
    ///
    /// This is our address.
    fn local_addr(&self) -> Result<Self::Addr, Error>;

    /// Whether to allow counterparty addresses to be used as a
    /// credential.
    ///
    /// This is generally unsafe, and is definitely unsafe for UDP
    /// socket, as addresses can be spoofed.  It is safer on Unix
    /// datagram sockets, but still does not conclusively establish
    /// identity.
    #[inline]
    fn allow_session_addr_creds(&self) -> bool {
        false
    }
}

/// Subtrait of [Socket] for sockets capable of sending.
///
/// This is separate from [Receiver], to allow implementations to
/// spilt into a send and receive half.
pub trait Sender: Socket {
    /// Get maximum transmission unit (MTU) for the socket, if it exists.
    ///
    /// This is the maximum size of a packet that can be sent without
    /// fragmentation occurring.
    #[inline]
    fn mtu(&self) -> Option<usize> {
        None
    }

    /// Send the data in `buf` to the counterparty at `Addr`.
    ///
    /// This returns the number of bytes sent, which should be equal
    /// to `buf.len()` unless the maximum size is exceeded, or an
    /// error if one occurs.
    fn send_to(
        &self,
        addr: &Self::Addr,
        buf: &[u8]
    ) -> Result<usize, Error>;

    /// Ensure all pending packets are sent.
    fn flush(&self) -> Result<(), Error>;
}

/// Subtrait of [Socket] for sockets capable of receiving.
///
/// This is separate from [Sender], to allow implementations to
/// spilt into a send and receive half.
pub trait Receiver: Socket {
    /// Receive a message into `buf`, returning the number of bytes
    /// received and the address of the counterparty that sent the
    /// message.
    ///
    /// If the size of the message exceeds the space available in
    /// `buf`, the remaining bytes will be dropped.
    ///
    /// The counterparty address is generally able to be spoofed and
    /// cannot establish identity, unless the underlying socket
    /// implementation guarantees it.  See
    /// [allow_session_addr_creds](Socket::allow_session_addr_creds).
    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error>;

    /// Examine a pending message without consuming it.
    ///
    /// This reads the next pending message into `buf`, returning the
    /// number of bytes received and the address of the counterparty
    /// that sent the message.
    ///
    /// If the size of the message exceeds the space available in
    /// `buf`, the remaining bytes will be dropped.
    ///
    /// The counterparty address is generally able to be spoofed and
    /// cannot establish identity, unless the underlying socket
    /// implementation guarantees it.  See
    /// [allow_session_addr_creds](Socket::allow_session_addr_creds).
    fn peek_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error>;
}

/// Transformations based on a mutable context that can be done on messages.
///
/// This is used as a transformer to wrap messages in a protocol that
/// requires a mutable context.  This provides a way to apply
/// transformations to messages at the level of the entire channel, as
/// opposed to a single traffic flow.
///
/// The primary use of this is to implement the SOCKS5 UDP
/// encapsulation protocol.
pub trait DatagramXfrm {
    /// Errors that can occur wrapping or unwrapping mesages.
    type Error: Display;
    /// Errors that can occur getting the header size;
    type SizeError: Display;
    /// Type of peer addresses.
    type PeerAddr: Clone + Display + Eq + Send;
    type LocalAddr: Clone + Display + Eq + Send;

    /// Get the header size for sending a message to `addr`.
    fn header_size(
        &self,
        addr: &Self::PeerAddr
    ) -> Result<usize, Self::SizeError>;

    /// Allocate a buffer for the wrapped message, if one is needed.
    ///
    /// If the wrapped message size is larger than the text, this will
    /// return a `Vec` with enough space to contain the wrapped
    /// message.  Otherwise, `None` will be returned.
    ///
    /// This is intended to allocate buffers for reading in results
    /// from the socket, prior to unwrapping the message.
    #[inline]
    fn msg_buf(
        &self,
        buf: &[u8],
        addr: &Self::PeerAddr,
        mtu: Option<usize>
    ) -> Result<Option<Vec<u8>>, Self::SizeError> {
        let headers = self.header_size(addr)?;

        match mtu {
            // If the buffer size is already as large as the MTU, we're good.
            Some(mtu) if buf.len() >= mtu => Ok(None),
            // If we know the MTU, allocate a buffer big enough for it.
            Some(mtu) => Ok(Some(vec![0; mtu])),
            // If the header length is zero, we're good.
            None if headers == 0 => Ok(None),
            // Otherwise, allocate a buffer with enough space for the headers.
            None => Ok(Some(vec![0; buf.len() + headers]))
        }
    }

    /// Wrap the message in `buf`.
    ///
    /// This will wrap the message in `buf`, returning `None` if no
    /// change is made to the message, and `Some` if a new message has
    /// been generated.  In either case, the
    fn wrap(
        &mut self,
        msg: &[u8],
        addr: Self::PeerAddr
    ) -> Result<(Option<Vec<u8>>, Self::LocalAddr), Self::Error>;

    /// Unwrap the message in `buf` in-place.
    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: Self::LocalAddr
    ) -> Result<(usize, Self::PeerAddr), Self::Error>;
}

/// Trait for [DatagramXfrm] instances that can be created from
/// whole cloth, from a configuration object.
pub trait DatagramXfrmCreate: DatagramXfrm {
    /// Type of parameters used to create this type of context.
    type CreateParam;
    /// Type of peer addresses to use.
    type Addr;

    /// Create a context from `param`.
    fn create(
        addr: &Self::Addr,
        param: &Self::CreateParam
    ) -> Self;
}

/// Trait for recovering parameters from a [DatagramXfrm] and a socket.
pub trait DatagramXfrmCreateParam: DatagramXfrm {
    /// Type of sockets from which to obtain parameters.
    type Socket;
    /// Type of parameters that are obtained.
    type Param;
    /// Errors that can occur recovering parameters.
    type ParamError: Display + ScopedError;

    /// Recover the [DatagramXfrm] creation parameters from this
    /// instance together with a socket.
    fn param(
        &self,
        socket: &Self::Socket
    ) -> Result<Self::Param, Self::ParamError>;
}

/// This is a [DatagramXfrm] that does no transformation on the
/// messages.
///
/// This is typically used as the "bottom level" in a nested
/// construction of [DatagramXfrm]s.
pub struct PassthruDatagramXfrm<Addr>(PhantomData<Addr>);

/// An endpoint for an IP connection.
///
/// This can be either a DNS name, an IPv4 address, or an IPv6
/// address.  This is a configuration object, and can be parsed from YAML.
///
/// # YAML Format
///
/// The YAML format is always a string.  If it is parseable as an IP
/// address, then the result will be converted to an [IpAddr] and
/// interpreted as such.  Otherwise, the result will be interpreted as
/// a name, which will ultimately be resolved.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(untagged)]
#[serde(from = "String")]
pub enum IPEndpointAddr {
    /// A fixed IP address.
    ///
    /// The YAML representation for this value is a string describing
    /// an IPv4 or IPv6 address.
    Addr(IpAddr),
    /// A DNS name that must be resolved.
    ///
    /// The YAML representation for this value is a string.  Note that
    /// strings that represent an IPv4 or IPv6 address will always be
    /// converted to `Addr` instead.
    Name(String)
}

/// IP socket configuration.
///
/// This consists of an [IPEndpointAddr] together with a port number.
/// This is used to incorporate resolvable names into a
/// [SocketAddr]-like type, thus allowing name resolution to be
/// handled in a more robust manner.  This is a configuration object,
/// and can be parsed from YAML.
///
/// # YAML Format
///
/// The YAML format has two fields, both of which are mandatory:
///
/// - `addr`: An [IPEndpointAddr], represented as a string.
/// - `port`: A number, representing the port number.
///
/// ## Examples
///
/// The following is an example YAML coniguration:
/// ```yaml
/// addr: en.wikipedia.org
/// port: 443
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "ip")]
#[serde(rename_all = "kebab-case")]
pub struct IPEndpoint {
    /// IP endpoint to which to connect.
    addr: IPEndpointAddr,
    /// Port to which to connect.
    port: u16
}

/// Creation parameter for [PassthruDatagramXfrm].
///
/// This contains no information.
#[derive(Clone, Eq, Debug, Hash, Ord, PartialEq, PartialOrd)]
pub struct PassthruDatagramXfrmParam;

impl Default for PassthruDatagramXfrmParam {
    #[inline]
    fn default() -> Self {
        PassthruDatagramXfrmParam
    }
}

impl From<SocketAddr> for PassthruDatagramXfrmParam {
    #[inline]
    fn from(_val: SocketAddr) -> Self {
        PassthruDatagramXfrmParam
    }
}

impl<Addr> PassthruDatagramXfrm<Addr> {
    #[inline]
    pub fn new() -> Self {
        PassthruDatagramXfrm(PhantomData)
    }
}

impl<Addr> Default for PassthruDatagramXfrm<Addr> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Addr> DatagramXfrm for PassthruDatagramXfrm<Addr>
where
    Addr: Clone + Display + Eq + Send
{
    type Error = Infallible;
    type LocalAddr = Addr;
    type PeerAddr = Addr;
    type SizeError = Infallible;

    #[inline]
    fn header_size(
        &self,
        _addr: &Self::PeerAddr
    ) -> Result<usize, Infallible> {
        Ok(0)
    }

    #[inline]
    fn msg_buf(
        &self,
        _buf: &[u8],
        _addr: &Addr,
        _mtu: Option<usize>
    ) -> Result<Option<Vec<u8>>, Infallible> {
        Ok(None)
    }

    #[inline]
    fn wrap(
        &mut self,
        _msg: &[u8],
        addr: Addr
    ) -> Result<(Option<Vec<u8>>, Addr), Self::Error> {
        Ok((None, addr))
    }

    #[inline]
    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: Addr
    ) -> Result<(usize, Addr), Self::Error> {
        Ok((buf.len(), addr))
    }
}

impl<Addr> DatagramXfrmCreate for PassthruDatagramXfrm<Addr>
where
    Addr: Clone + Display + Eq + Send
{
    type Addr = Addr;
    type CreateParam = PassthruDatagramXfrmParam;

    #[inline]
    fn create(
        _addr: &Addr,
        _param: &PassthruDatagramXfrmParam
    ) -> Self {
        PassthruDatagramXfrm::default()
    }
}

impl IPEndpointAddr {
    /// Null IPv4 address, consisting of all zeroes.
    pub const NULL_IPV4: IPEndpointAddr =
        IPEndpointAddr::Addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    /// Null IPv6 address, consisting of all zeroes.
    pub const NULL_IPV6: IPEndpointAddr =
        IPEndpointAddr::Addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED));

    /// Create an `IPEndpointAddr` specifying an IP address.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use std::net::IpAddr;
    /// # use std::net::Ipv4Addr;
    /// #
    /// let yaml = "10.10.10.10";
    ///
    /// assert_eq!(
    ///     IPEndpointAddr::ip(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn ip(ip: IpAddr) -> Self {
        IPEndpointAddr::from(ip)
    }

    /// Create an `IPEndpointAddr` specifying a resolvable name.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::net::IPEndpointAddr;
    /// #
    /// let yaml = "en.wikipedia.org";
    ///
    /// assert_eq!(
    ///     IPEndpointAddr::name(String::from("en.wikipedia.org")),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn name(name: String) -> Self {
        IPEndpointAddr::Name(name)
    }
}

impl IPEndpoint {
    /// Null IPv4 address, consisting of all zeroes, with the port set
    /// to zero.
    pub const NULL_IPV4: IPEndpoint = IPEndpoint {
        addr: IPEndpointAddr::NULL_IPV4,
        port: 0
    };
    /// Null IPv6 address, consisting of all zeroes, with the port set
    /// to zero.
    pub const NULL_IPV6: IPEndpoint = IPEndpoint {
        addr: IPEndpointAddr::NULL_IPV6,
        port: 0
    };

    /// Create a new `IPEndpoint` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_common::net::IPEndpoint;
    /// #
    /// let yaml = concat!("addr: en.wikipedia.org\n",
    ///                    "port: 443\n");
    /// let ip = IPEndpointAddr::name(String::from("en.wikipedia.org"));
    ///
    /// assert_eq!(
    ///     IPEndpoint::new(ip, 443),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        endpoint: IPEndpointAddr,
        port: u16
    ) -> Self {
        IPEndpoint {
            addr: endpoint,
            port: port
        }
    }

    /// Decompose an `IPEndpoint` into its components.
    #[inline]
    pub fn take(self) -> (IPEndpointAddr, u16) {
        (self.addr, self.port)
    }

    /// Get the [IPEndpointAddr] component.
    #[inline]
    pub fn ip_endpoint(&self) -> &IPEndpointAddr {
        &self.addr
    }

    /// Get the port number.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Display for IPEndpoint {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        write!(f, "{}:{}", self.ip_endpoint(), self.port())
    }
}

impl Display for IPEndpointAddr {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            IPEndpointAddr::Addr(addr) => addr.fmt(f),
            IPEndpointAddr::Name(name) => name.fmt(f)
        }
    }
}

impl From<Ipv4Addr> for IPEndpointAddr {
    #[inline]
    fn from(val: Ipv4Addr) -> IPEndpointAddr {
        IPEndpointAddr::Addr(IpAddr::V4(val))
    }
}

impl From<&'_ Ipv4Addr> for IPEndpointAddr {
    #[inline]
    fn from(val: &'_ Ipv4Addr) -> IPEndpointAddr {
        IPEndpointAddr::Addr(IpAddr::V4(*val))
    }
}

impl From<&'_ mut Ipv4Addr> for IPEndpointAddr {
    #[inline]
    fn from(val: &'_ mut Ipv4Addr) -> IPEndpointAddr {
        IPEndpointAddr::Addr(IpAddr::V4(*val))
    }
}

impl From<Ipv6Addr> for IPEndpointAddr {
    #[inline]
    fn from(val: Ipv6Addr) -> IPEndpointAddr {
        IPEndpointAddr::Addr(IpAddr::V6(val))
    }
}

impl From<&'_ Ipv6Addr> for IPEndpointAddr {
    #[inline]
    fn from(val: &'_ Ipv6Addr) -> IPEndpointAddr {
        IPEndpointAddr::Addr(IpAddr::V6(*val))
    }
}

impl From<&'_ mut Ipv6Addr> for IPEndpointAddr {
    #[inline]
    fn from(val: &'_ mut Ipv6Addr) -> IPEndpointAddr {
        IPEndpointAddr::Addr(IpAddr::V6(*val))
    }
}

impl From<IpAddr> for IPEndpointAddr {
    #[inline]
    fn from(val: IpAddr) -> IPEndpointAddr {
        IPEndpointAddr::Addr(val)
    }
}

impl From<String> for IPEndpointAddr {
    #[inline]
    fn from(val: String) -> IPEndpointAddr {
        match IpAddr::from_str(&val) {
            Ok(addr) => IPEndpointAddr::Addr(addr),
            Err(_) => IPEndpointAddr::Name(val)
        }
    }
}

impl From<SocketAddr> for IPEndpoint {
    #[inline]
    fn from(val: SocketAddr) -> IPEndpoint {
        match val {
            SocketAddr::V4(addr) => IPEndpoint::from(addr),
            SocketAddr::V6(addr) => IPEndpoint::from(addr)
        }
    }
}

impl From<SocketAddrV4> for IPEndpoint {
    #[inline]
    fn from(val: SocketAddrV4) -> IPEndpoint {
        IPEndpoint {
            addr: IPEndpointAddr::from(val.ip()),
            port: val.port()
        }
    }
}

impl From<SocketAddrV6> for IPEndpoint {
    #[inline]
    fn from(val: SocketAddrV6) -> IPEndpoint {
        IPEndpoint {
            addr: IPEndpointAddr::from(val.ip()),
            port: val.port()
        }
    }
}

impl Serialize for IPEndpointAddr {
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            IPEndpointAddr::Addr(addr) => {
                serializer.serialize_str(&addr.to_string())
            }
            IPEndpointAddr::Name(name) => serializer.serialize_str(name)
        }
    }
}

#[test]
fn test_deserialize_tcp_cfg_ipv4_addr() {
    let yaml = concat!("addr: 10.10.10.10\n", "port: 1024");
    let addr = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));
    let expected = IPEndpoint {
        addr: IPEndpointAddr::Addr(addr),
        port: 1024
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_tcp_cfg_ipv6_addr() {
    let yaml = concat!("addr: 1:29:3a:4b:5c:6d:7e:8f\n", "port: 1024");
    let addr = Ipv6Addr::new(0x1, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f);
    let expected = IPEndpoint {
        addr: IPEndpointAddr::Addr(IpAddr::V6(addr)),
        port: 1024
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_tcp_cfg_domain() {
    let yaml = concat!("addr: example.com\n", "port: 1024");
    let expected = IPEndpoint {
        addr: IPEndpointAddr::Name(String::from("example.com")),
        port: 1024
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_ip_endpoint_domain() {
    let yaml = "example.com";
    let expected = IPEndpointAddr::Name(String::from(yaml));
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_ip_endpoint_ipv4() {
    let yaml = "10.10.10.10";
    let expected =
        IPEndpointAddr::Addr(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)));
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_ip_endpoint_ipv6() {
    let yaml = "1:29:3a:4b:5c:6d:7e:8f";
    let addr = Ipv6Addr::new(0x1, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f);
    let expected = IPEndpointAddr::Addr(IpAddr::V6(addr));
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_ip_endpoint_ipv6_localhost() {
    let yaml = "::1";
    let addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let expected = IPEndpointAddr::Addr(IpAddr::V6(addr));
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}
