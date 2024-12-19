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

//! Configuration objects for GSSAPI.
//!
//! This module contains configuration objects useful for setting up
//! GSSAPI contexts.
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

/// GSSAPI security level specification.
///
/// This specifies the security level in bits, as well as whether this
/// security level is optional or required.
///
/// # YAML Format
///
/// The YAML format consists of a single field, which holds the
/// security level.  The name of the field is either `optional` or
/// `required`.
///
/// ## Examples
///
/// The following shows a specification for a 128-bit optional
/// security level:
///
/// ```yaml
/// optional: 128
/// ```
///
/// The following shows a specification for a 56-bit required security
/// level (note that this is the highest security level that Kerberos
/// is capable of supporting):
///
/// ```yaml
/// required: 56
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "gssapi-security")]
#[serde(untagged)]
pub enum GSSAPISecurity {
    /// Optional security level.
    ///
    /// This security level will be requested, but the client will not
    /// terminate the connection if it is not met.
    Optional {
        /// The security level in bits.
        #[serde(rename = "optional")]
        seclvl: u8
    },
    /// Required security level.
    ///
    /// This security level will be requested, and the client will
    /// terminate the connection if it is not met.  (Note that
    /// Kerberos notably uses out-of-date encryption, which provides
    /// only 56 bits of security.)
    Required {
        /// The security level in bits.
        #[serde(rename = "required")]
        seclvl: u8
    }
}

/// Configuration for client-side GSSAPI authentication.
///
/// This provides configurations for clients that use GSSAPI
/// authentication.  This is usable for both direct GSSAPI
/// authentication as well as for protocols like SOCKS5.
///
/// # YAML Format
///
/// The YAML format has four fields, all of which are optional, or
/// have defaults:
///
/// - `name`: The name of the principal that will be used for authentication.
///   This will be used by the analogue of `gss_acquire_cred` to find the
///   credential.  If this is not provided, a credential will be acquired using
///   default behavior.
///
/// - `service`: The expected name of the service prinicpal.  If this is not
///   provided, no check will be made.
///
/// - `time_req`: The duration for which to request credentials.  If this is not
///   provided, credentials will be requested for as long as possible.
///
/// - `security`: A [GSSAPISecurity] specification, giving the security level
///   and whether or not it is required.
///
/// ## Examples
///
/// The following is an example of a YAML configuration with all
/// fields represented:
///
/// ```yaml
/// name: test
/// service: socks5
/// security:
///   optional: 128
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "gssapi")]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub struct ClientGSSAPIConfig {
    /// Name of the principal to acquire and use in authentication.
    #[serde(default)]
    name: Option<String>,
    /// Name of the service principal to expect.
    #[serde(default)]
    service: Option<String>,
    /// Duration for which to request credentials.
    #[serde(default)]
    time_req: Option<Duration>,
    /// GSSAPI security level (see [GSSAPISecurity]).
    #[serde(default)]
    security: GSSAPISecurity
}

/// Configuration for server-side GSSAPI authentication.
///
/// This provides configurations for servers that offer GSSAPI
/// authentication.
///
/// # YAML Format
///
/// The YAML format has two fields, all of which are optional, or
/// have defaults:
///
/// - `name`: The name of the principal that will be used for authentication.
///   This will be used by the analogue of `gss_acquire_cred` to find the
///   credential.  If this is not provided, a credential will be acquired using
///   default behavior.
///
/// - `time_req`: The duration for which to request credentials.  If this is not
///   provided, credentials will be requested for as long as possible.
///
/// ## Examples
///
/// The following is an example of a YAML configuration with all
/// fields represented:
///
/// ```yaml
/// name: test
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "gssapi")]
#[serde(rename_all = "kebab-case")]
pub struct ServerGSSAPIConfig {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    time_req: Option<Duration>
}

impl ClientGSSAPIConfig {
    /// Create a new `ClientGSSAPIConfig` from its components.
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
    /// # use constellation_common::config::authn::ClientGSSAPIConfig;
    /// # use constellation_common::config::authn::GSSAPISecurity;
    /// #
    /// let yaml = concat!(
    ///     "name: test\n",
    ///     "service: socks5\n",
    ///     "security:\n",
    ///     "  optional: 128\n",
    /// );
    /// assert_eq!(
    ///     ClientGSSAPIConfig::new(
    ///         Some(String::from("test")),
    ///         Some(String::from("socks5")),
    ///         None,
    ///         GSSAPISecurity::Optional { seclvl: 128 }
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        name: Option<String>,
        service: Option<String>,
        time_req: Option<Duration>,
        security: GSSAPISecurity
    ) -> Self {
        ClientGSSAPIConfig {
            name: name,
            service: service,
            time_req: time_req,
            security: security
        }
    }

    /// Decompose this `ClientGSSAPIConfig` into its components.
    ///
    /// The components returned, in order are:
    ///
    /// - The client principal name ([name](ClientGSSAPIConfig::name))
    /// - The expected service principal name
    ///   ([service](ClientGSSAPIConfig::service))
    /// - The duration for which to request credentials
    ///   ([time_req](ClientGSSAPIConfig::time_req))
    /// - The security level specification
    ///   ([security](ClientGSSAPIConfig::security))
    #[inline]
    pub fn take(
        self
    ) -> (
        Option<String>,
        Option<String>,
        Option<Duration>,
        GSSAPISecurity
    ) {
        (self.name, self.service, self.time_req, self.security)
    }

    /// Get the client principal name, if one is specified.
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the expected service principal name, if one is specified.
    #[inline]
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }

    /// The time for which to request credentials.
    #[inline]
    pub fn time_req(&self) -> Option<Duration> {
        self.time_req
    }

    /// Get the security level.
    #[inline]
    pub fn security(&self) -> &GSSAPISecurity {
        &self.security
    }
}

impl GSSAPISecurity {
    /// Create a `GSSAPISecurity` object specifying an optional
    /// security level of `seclvl`.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::config::authn::GSSAPISecurity;
    /// #
    /// let yaml = "optional: 128";
    ///
    /// assert_eq!(
    ///     GSSAPISecurity::optional(128),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn optional(seclvl: u8) -> Self {
        GSSAPISecurity::Optional { seclvl: seclvl }
    }

    /// Create a `GSSAPISecurity` object specifying a required
    /// security level of `seclvl`.  (Note that Kerberos notably uses
    /// out-of-date encryption, which provides only 56 bits of
    /// security.)
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::config::authn::GSSAPISecurity;
    /// #
    /// let yaml = "required: 56";
    ///
    /// assert_eq!(
    ///     GSSAPISecurity::required(56),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn required(seclvl: u8) -> Self {
        GSSAPISecurity::Required { seclvl: seclvl }
    }

    /// Get the security level in bits.
    #[inline]
    pub fn seclvl(&self) -> u8 {
        match self {
            GSSAPISecurity::Optional { seclvl } => *seclvl,
            GSSAPISecurity::Required { seclvl } => *seclvl
        }
    }

    /// Indicate whether or not this security level is required.
    #[inline]
    pub fn is_required(&self) -> bool {
        match self {
            GSSAPISecurity::Optional { .. } => false,
            GSSAPISecurity::Required { .. } => true
        }
    }
}

impl ServerGSSAPIConfig {
    /// Create a new `ServerGSSAPIConfig` from its components.
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
    /// # use constellation_common::config::authn::ServerGSSAPIConfig;
    /// # use constellation_common::config::authn::GSSAPISecurity;
    /// #
    /// let yaml = concat!(
    ///     "name: test\n",
    /// );
    /// assert_eq!(
    ///     ServerGSSAPIConfig::new(
    ///         Some(String::from("test")),
    ///         None,
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        name: Option<String>,
        time_req: Option<Duration>
    ) -> Self {
        ServerGSSAPIConfig {
            name: name,
            time_req: time_req
        }
    }

    /// Decompose this `ServerGSSAPIConfig` into its components.
    ///
    /// The components returned, in order are:
    ///
    /// - The service principal name ([name](ServerGSSAPIConfig::name))
    /// - The duration for which to request credentials
    ///   ([time_req](ServerGSSAPIConfig::time_req))
    #[inline]
    pub fn take(self) -> (Option<String>, Option<Duration>) {
        (self.name, self.time_req)
    }

    /// Get the service principal name, if one is specified.
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The time for which to request credentials.
    #[inline]
    pub fn time_req(&self) -> Option<Duration> {
        self.time_req
    }
}

impl Default for GSSAPISecurity {
    #[inline]
    fn default() -> Self {
        GSSAPISecurity::Optional { seclvl: 0 }
    }
}

// #[test]
// fn test_deserialize_client_gssapi_time_req() {
// let yaml = concat!("gssapi:\n",
// "  time-req: 1");
// let expected = SOCKS5AuthNConfig::GSSAPI {
// gssapi: ClientGSSAPIConfig {
// name: None, service: None,
// time_req: Some(Duration::from_secs(1)),
// security: GSSAPISecurity::default()
// }
// };
// let actual = serde_yaml::from_str(yaml).unwrap();
//
// assert_eq!(expected, actual)
// }

#[test]
fn test_deserialize_server_gssapi_name() {
    let yaml = concat!("name: cred\n");
    let expected = ServerGSSAPIConfig {
        name: Some(String::from("cred")),
        time_req: None
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}
