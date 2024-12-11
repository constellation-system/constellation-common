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

//! Configuration objects for Public Key Infrastructure (PKI) trust roots.
//!
//! This module contains configuration objects PKI trust roots.  This
//! functionality is used for setting up DTLS/TLS sessions, as well as
//! for signing and signature verification purposes.
#[cfg(feature = "openssl")]
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Formatter;
use std::path::PathBuf;
#[cfg(feature = "openssl")]
use std::time::SystemTime;

#[cfg(feature = "openssl")]
use log::debug;
#[cfg(feature = "openssl")]
use log::info;
#[cfg(feature = "openssl")]
use log::trace;
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack;
#[cfg(feature = "openssl")]
use openssl::ssl::SslFiletype;
#[cfg(feature = "openssl")]
use openssl::x509::store::X509Lookup;
#[cfg(feature = "openssl")]
use openssl::x509::store::X509Store;
#[cfg(feature = "openssl")]
use openssl::x509::store::X509StoreBuilder;
#[cfg(feature = "openssl")]
use openssl::x509::verify::X509CheckFlags;
#[cfg(feature = "openssl")]
use openssl::x509::verify::X509VerifyFlags;
#[cfg(feature = "openssl")]
use openssl::x509::verify::X509VerifyParam;
#[cfg(feature = "openssl")]
use openssl::x509::X509PurposeId;
use serde::Deserialize;
use serde::Serialize;
#[cfg(feature = "openssl")]
use serde::Serializer;
#[cfg(feature = "openssl")]
use time::OffsetDateTime;

use crate::error::ErrorScope;
use crate::error::ScopedError;
#[cfg(feature = "openssl")]
use crate::net::IPEndpointAddr;

/// Allowed flags for X509 hosts.
#[cfg(feature = "openssl")]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(untagged)]
#[serde(try_from = "&'_ str")]
pub enum X509HostFlag {
    AlwaysCheckSubject,
    NoWildcards,
    NoPartialWildcards,
    MultiLabelWildcards,
    SingleLabelSubdomains,
    NeverCheckSubject
}

/// Allowed verification flags.
#[cfg(feature = "openssl")]
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(untagged)]
#[serde(try_from = "&'_ str")]
pub enum X509VerifyFlag {
    /// Check CRLs on leaf certificates.
    CRLCheck,
    /// Check CRLs for all certificates.
    CRLCheckAll,
    AllowProxyCerts,
    /// Enable policy checking.
    PolicyCheck,
    ExplicitPolicy,
    InhibitAny,
    InhibitMap,
    /// Check signatures on root (self-signed) certificates.
    CheckSSSignature,
    /// Do not check time.
    NoCheckTime
}

/// Errors that can occur while loading a [PKITrustRoot].
#[derive(Debug)]
pub enum PKITrustRootLoadError {
    #[cfg(feature = "openssl")]
    /// An error occurred in the OpenSSL library.
    OpenSSL {
        /// The OpenSSL error stack.
        error: ErrorStack
    },
    #[cfg(feature = "openssl")]
    /// A bad [SystemTime] value was specified.
    BadTime {
        /// The bad [SystemTime].
        time: SystemTime
    },
    /// No root certificates were found.
    NoRootCerts
}

/// Configurations for a PKI-based root-of-trust.
///
/// This provides the configuration options for verifying signatures
/// based on X.509 certificates and certificate chains.
///
/// # YAML Format
///
/// The YAML format has seven fields, some of which are present only
/// when the `openssl` feature is enabled:
///
/// - `dirs`: A list of paths to CA directories, containing root certificates
///   and CRLs.
///
/// - `root-certs`: A list of paths to files containing PEM-encoded root
///   certificates.
///
/// - `crls`: A list of paths to files containing PEM-encoded CRLs.
///
/// - `verify-flags`: OpenSSL verification flags.  Not all verification flags
///   are allowed by this library; only the following are supported:
///
///   - `CRL_CHECK`
///   - `CRL_CHECK_ALL`
///   - `ALLOW_PROXY_CERTS`
///   - `POLICY_CHECK`
///   - `EXPLICIT_POLICY`
///   - `INHIBIT_ANY`
///   - `INHIBIT_MAP`
///   - `CHECK_SS_SIGNATURE`
///   - `NO_CHECK_TIME`
///
/// - `host-flags`: OpenSSL host flags.  Not all verification flags are allowed
///   by this library; only the following are supported:
///
///   - `ALWAYS_CHECK_SUBJECT`
///   - `NO_WILDCARDS`
///   - `NO_PARTIAL_WILDCARDS`
///   - `MULTI_LABEL_WILDCARDS`
///   - `SINGLE_LABEL_SUBDOMAINS`
///   - `NEVER_CHECK_SUBJECT`
///
/// - `auth-level`: OpenSSL authentication level.  This can be used as a blanket
///   method for setting a minimum security level.  The following descriptions
///   are taken from the OpenSSL documentation (note that this library
///   deliberately does not allow some of these configuration options):
///
///   - **Level 0**: Everything is permitted. This retains compatibility with
///     previous versions of OpenSSL.
///
///   - **Level 1**: The security level corresponds to a minimum of 80 bits of
///     security. Any parameters offering below 80 bits of security are
///     excluded. As a result RSA, DSA and DH keys shorter than 1024 bits and
///     ECC keys shorter than 160 bits are prohibited. All export cipher suites
///     are prohibited since they all offer less than 80 bits of security. SSL
///     version 2 is prohibited. Any cipher suite using MD5 for the MAC is also
///     prohibited.
///
///   - **Level 2**: Security level set to 112 bits of security. As a result
///     RSA, DSA and DH keys shorter than 2048 bits and ECC keys shorter than
///     224 bits are prohibited. In addition to the level 1 exclusions any
///     cipher suite using RC4 is also prohibited. SSL version 3 is also not
///     allowed. Compression is disabled.
///
///   - **Level 3**: Security level set to 128 bits of security. As a result
///     RSA, DSA and DH keys shorter than 3072 bits and ECC keys shorter than
///     256 bits are prohibited. In addition to the level 2 exclusions cipher
///     suites not offering forward secrecy are prohibited. TLS versions below
///     1.1 are not permitted. Session tickets are disabled.
///
///   - **Level 4**: Security level set to 192 bits of security. As a result
///     RSA, DSA and DH keys shorter than 7680 bits and ECC keys shorter than
///     384 bits are prohibited. Cipher suites using SHA1 for the MAC are
///     prohibited. TLS versions below 1.2 are not permitted.
///
///   - **Level 5**: Security level set to 256 bits of security. As a result
///     RSA, DSA and DH keys shorter than 15360 bits and ECC keys shorter than
///     512 bits are prohibited.
///
/// - `verify-depth`: Depth to which to verify certificate chains. This is only
///   available on OpenSSL.
///
/// ## Examples
///
/// The following is an example of a YAML configuration with all
/// fields represented:
/// ```yaml
/// dirs:
///   - /etc/ssl/CA
/// root-certs:
///   - /etc/ssl/certs/server-ca-cert.pem
/// crls:
///   - /etc/ssl/crls/server-ca-crl.pem
/// verify-flags:
///   - EXPLICIT_POLICY
///   - ALLOW_PROXY_CERTS
/// host-flags:
///   - ALWAYS_CHECK_SUBJECT
///   - NO_WILDCARDS
/// auth-level: 4
/// verify-depth: 16
/// ```
#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[serde(rename = "pki-trust-root")]
pub struct PKITrustRoot {
    /// Paths to CA directories, containing root CA certs and CRLs.
    #[serde(default)]
    dirs: Vec<PathBuf>,
    /// A list of paths to files containing PEM-encoded CA certs.
    #[serde(default)]
    root_certs: Vec<PathBuf>,
    /// A list of paths to files containing PEM-encoded CRLs.
    #[serde(default)]
    crls: Vec<PathBuf>,
    #[cfg(feature = "openssl")]
    /// OpenSSL verification flags.
    #[serde(default)]
    verify_flags: Vec<X509VerifyFlag>,
    #[cfg(feature = "openssl")]
    /// OpenSSL host flags.
    #[serde(default)]
    host_flags: Vec<X509HostFlag>,
    #[cfg(feature = "openssl")]
    /// OpenSSL authentication level.
    ///
    /// This can be used as a blanket method for setting a minimum
    /// security level.  The following descriptions are taken from the
    /// OpenSSL documentation (note that this library deliberately
    /// does not allow some of these configuration options):
    ///
    /// - 0: Everything is permitted. This retains compatibility with previous
    ///   versions of OpenSSL.
    ///
    /// - 1: The security level corresponds to a minimum of 80 bits of
    ///   security. Any parameters offering below 80 bits of security are
    ///   excluded. As a result RSA, DSA and DH keys shorter than 1024 bits and
    ///   ECC keys shorter than 160 bits are prohibited. All export cipher
    ///   suites are prohibited since they all offer less than 80 bits of
    ///   security. SSL version 2 is prohibited. Any cipher suite using MD5 for
    ///   the MAC is also prohibited.
    ///
    /// - 2: Security level set to 112 bits of security. As a result RSA, DSA
    ///   and DH keys shorter than 2048 bits and ECC keys shorter than 224 bits
    ///   are prohibited. In addition to the level 1 exclusions any cipher
    ///   suite using RC4 is also prohibited. SSL version 3 is also not
    ///   allowed. Compression is disabled.
    ///
    /// - 3: Security level set to 128 bits of security. As a result RSA, DSA
    ///   and DH keys shorter than 3072 bits and ECC keys shorter than 256 bits
    ///   are prohibited. In addition to the level 2 exclusions cipher suites
    ///   not offering forward secrecy are prohibited. TLS versions below 1.1
    ///   are not permitted. Session tickets are disabled.
    ///
    /// - 4: Security level set to 192 bits of security. As a result RSA, DSA
    ///   and DH keys shorter than 7680 bits and ECC keys shorter than 384 bits
    ///   are prohibited. Cipher suites using SHA1 for the MAC are prohibited.
    ///   TLS versions below 1.2 are not permitted.
    ///
    /// - 5: Security level set to 256 bits of security. As a result RSA, DSA
    ///   and DH keys shorter than 15360 bits and ECC keys shorter than 512
    ///   bits are prohibited.
    #[serde(default)]
    auth_level: Option<u8>,
    #[cfg(feature = "openssl")]
    /// Depth to which to verify certificate chains.
    #[serde(default)]
    verify_depth: Option<u8>
}

impl PKITrustRoot {
    /// Create a new `PKITrustRoot` from its components.
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
    /// # use constellation_common::config::pki::PKITrustRoot;
    /// # #[cfg(feature = "openssl")]
    /// # use constellation_common::config::pki::X509HostFlag;
    /// # #[cfg(feature = "openssl")]
    /// # use constellation_common::config::pki::X509VerifyFlag;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!(
    ///     "dirs:\n",
    ///     "  - /etc/ssl/CA\n",
    ///     "root-certs:\n",
    ///     "  - /etc/ssl/certs/server-ca-cert.pem\n",
    ///     "crls:\n",
    ///     "  - /etc/ssl/crls/server-ca-crl.pem\n",
    ///     "verify-flags:\n",
    ///     "  - EXPLICIT_POLICY\n",
    ///     "  - ALLOW_PROXY_CERTS\n",
    ///     "host-flags:\n",
    ///     "  - ALWAYS_CHECK_SUBJECT\n",
    ///     "  - NO_WILDCARDS\n",
    ///     "auth-level: 4\n",
    ///     "verify-depth: 16\n"
    /// );
    /// assert_eq!(
    ///     PKITrustRoot::new(
    ///         vec![PathBuf::from("/etc/ssl/CA")],
    ///         vec![PathBuf::from("/etc/ssl/certs/server-ca-cert.pem")],
    ///         vec![PathBuf::from("/etc/ssl/crls/server-ca-crl.pem")],
    ///         #[cfg(feature = "openssl")]
    ///         vec![X509VerifyFlag::ExplicitPolicy,
    ///              X509VerifyFlag::AllowProxyCerts],
    ///         #[cfg(feature = "openssl")]
    ///         vec![X509HostFlag::AlwaysCheckSubject,
    ///              X509HostFlag::NoWildcards],
    ///         #[cfg(feature = "openssl")]
    ///         Some(4),
    ///         #[cfg(feature = "openssl")]
    ///         Some(16)
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        dirs: Vec<PathBuf>,
        certs: Vec<PathBuf>,
        crls: Vec<PathBuf>,
        #[cfg(feature = "openssl")] verify_flags: Vec<X509VerifyFlag>,
        #[cfg(feature = "openssl")] host_flags: Vec<X509HostFlag>,
        #[cfg(feature = "openssl")] auth_level: Option<u8>,
        #[cfg(feature = "openssl")] verify_depth: Option<u8>
    ) -> PKITrustRoot {
        PKITrustRoot {
            dirs: dirs,
            root_certs: certs,
            crls: crls,
            #[cfg(feature = "openssl")]
            verify_flags: verify_flags,
            #[cfg(feature = "openssl")]
            host_flags: host_flags,
            #[cfg(feature = "openssl")]
            auth_level: auth_level,
            #[cfg(feature = "openssl")]
            verify_depth: verify_depth
        }
    }

    /// Get the CA directories.
    #[inline]
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// Get the paths to the PEM-encoded CA certificates.
    #[inline]
    pub fn root_certs(&self) -> &[PathBuf] {
        &self.root_certs
    }

    /// Get the paths to the PEM-encoded CA certificates.
    #[inline]
    pub fn crls(&self) -> &[PathBuf] {
        &self.crls
    }

    #[cfg(feature = "openssl")]
    /// Get the verification flags.
    #[inline]
    pub fn verify_flags(&self) -> &[X509VerifyFlag] {
        &self.verify_flags
    }

    #[cfg(feature = "openssl")]
    /// Get the host flags.
    #[inline]
    pub fn host_flags(&self) -> &[X509HostFlag] {
        &self.host_flags
    }

    #[cfg(feature = "openssl")]
    /// Get the OpenSSL authentication level.
    #[inline]
    pub fn auth_level(&self) -> Option<u8> {
        self.auth_level
    }

    #[cfg(feature = "openssl")]
    /// Get the maximum verification depth.
    #[inline]
    pub fn verify_depth(&self) -> Option<u8> {
        self.verify_depth
    }

    #[cfg(feature = "openssl")]
    /// Get the OpenSSL host flags.
    fn load_host_flags(&self) -> X509CheckFlags {
        let mut flags = X509CheckFlags::empty();

        for flag in &self.host_flags {
            match flag {
                X509HostFlag::AlwaysCheckSubject => {
                    trace!(target: "pki-trust-root",
                           "setting ALWAYS_CHECK_SUBJECT flag");

                    flags.insert(X509CheckFlags::ALWAYS_CHECK_SUBJECT);
                }
                X509HostFlag::NoWildcards => {
                    trace!(target: "pki-trust-root",
                           "setting NO_WILDCARDS flag");

                    flags.insert(X509CheckFlags::NO_WILDCARDS);
                }
                X509HostFlag::NoPartialWildcards => {
                    trace!(target: "pki-trust-root",
                           "setting NO_PARTIAL_WILDCARDS flag");

                    flags.insert(X509CheckFlags::NO_PARTIAL_WILDCARDS);
                }
                X509HostFlag::MultiLabelWildcards => {
                    trace!(target: "pki-trust-root",
                           "setting MULTI_LABEL_WILDCARDS flag");

                    flags.insert(X509CheckFlags::MULTI_LABEL_WILDCARDS);
                }
                X509HostFlag::SingleLabelSubdomains => {
                    trace!(target: "pki-trust-root",
                           "setting SINGLE_LABEL_SUBDOMAINS flag");

                    flags.insert(X509CheckFlags::SINGLE_LABEL_SUBDOMAINS);
                }
                X509HostFlag::NeverCheckSubject => {
                    trace!(target: "pki-trust-root",
                           "setting NEVER_CHECK_SUBJECT flag");

                    flags.insert(X509CheckFlags::NEVER_CHECK_SUBJECT);
                }
            }
        }

        flags
    }

    #[cfg(feature = "openssl")]
    /// Get the OpenSSL verify flags.
    fn load_verify_flags(
        &self,
        use_time: bool
    ) -> X509VerifyFlags {
        let mut flags = X509VerifyFlags::empty();

        // Extra debugging for issuer checks: hardwired off
        flags.remove(X509VerifyFlags::CB_ISSUER_CHECK);
        // Use a preset timestamp: set by params
        flags.remove(X509VerifyFlags::USE_CHECK_TIME);
        // Check CRL on leaf certificate: default off
        flags.remove(X509VerifyFlags::CRL_CHECK);
        // Check CRL on all certificates: default off
        flags.remove(X509VerifyFlags::CRL_CHECK_ALL);
        // Ignore critical errors: hardwired off
        flags.remove(X509VerifyFlags::IGNORE_CRITICAL);
        // Strict validation: hardwired on
        flags.insert(X509VerifyFlags::X509_STRICT);
        // Proxy certs: default off
        flags.remove(X509VerifyFlags::ALLOW_PROXY_CERTS);
        // Policy checks: default off
        flags.remove(X509VerifyFlags::POLICY_CHECK);
        // Explicit policy checks: default off
        flags.remove(X509VerifyFlags::EXPLICIT_POLICY);
        // Inhibit any policy: default off
        flags.remove(X509VerifyFlags::INHIBIT_ANY);
        // Inhibit mapping: default off
        flags.remove(X509VerifyFlags::INHIBIT_MAP);
        // Polity notification: default off, automatically activated
        flags.remove(X509VerifyFlags::NOTIFY_POLICY);
        // Extended CRL support: default off, automatically activated
        flags.remove(X509VerifyFlags::EXTENDED_CRL_SUPPORT);
        // CRL delta support: default off, automatically activated
        flags.remove(X509VerifyFlags::USE_DELTAS);
        // Check root cert signatures: default off
        flags.remove(X509VerifyFlags::CHECK_SS_SIGNATURE);
        // Trust store certs first: hardwired on
        flags.insert(X509VerifyFlags::TRUSTED_FIRST);
        // Suite B 128-bit security: default off
        flags.remove(X509VerifyFlags::SUITEB_128_LOS);
        // Suite B 128-bit security only: default off
        flags.remove(X509VerifyFlags::SUITEB_128_LOS_ONLY);
        // Suite B 192-bit security: default off
        flags.remove(X509VerifyFlags::SUITEB_192_LOS);
        // Partial chains: hardwired off
        flags.remove(X509VerifyFlags::PARTIAL_CHAIN);
        // No alternate chains: hardwired off
        flags.remove(X509VerifyFlags::NO_ALT_CHAINS);
        // No expiration check: default off
        flags.remove(X509VerifyFlags::NO_CHECK_TIME);

        let mut no_check_time = false;

        for flag in &self.verify_flags {
            match flag {
                X509VerifyFlag::CRLCheck => {
                    trace!(target: "pki-trust-root",
                           "setting CRL_CHECK flag");

                    flags.insert(X509VerifyFlags::CRL_CHECK);
                    flags.insert(X509VerifyFlags::EXTENDED_CRL_SUPPORT);
                    flags.insert(X509VerifyFlags::USE_DELTAS);
                }
                X509VerifyFlag::CRLCheckAll => {
                    trace!(target: "pki-trust-root",
                           "setting CRL_CHECK_ALL flag");

                    flags.insert(X509VerifyFlags::CRL_CHECK_ALL);
                    flags.insert(X509VerifyFlags::EXTENDED_CRL_SUPPORT);
                    flags.insert(X509VerifyFlags::USE_DELTAS);
                }
                X509VerifyFlag::AllowProxyCerts => {
                    trace!(target: "pki-trust-root",
                           "setting ALLOW_PROXY_CERTS flag");

                    flags.insert(X509VerifyFlags::ALLOW_PROXY_CERTS);
                }
                X509VerifyFlag::PolicyCheck => {
                    trace!(target: "pki-trust-root",
                           "setting POLICY_CHECK flag");

                    flags.insert(X509VerifyFlags::POLICY_CHECK);
                    flags.insert(X509VerifyFlags::NOTIFY_POLICY);
                }
                X509VerifyFlag::ExplicitPolicy => {
                    trace!(target: "pki-trust-root",
                           "setting EXPLICIT_POLICY flag");

                    flags.insert(X509VerifyFlags::EXPLICIT_POLICY);
                    flags.insert(X509VerifyFlags::POLICY_CHECK);
                    flags.insert(X509VerifyFlags::NOTIFY_POLICY);
                }
                X509VerifyFlag::InhibitAny => {
                    trace!(target: "pki-trust-root",
                           "setting INHIBIT_ANY flag");

                    flags.insert(X509VerifyFlags::INHIBIT_ANY);
                    flags.insert(X509VerifyFlags::POLICY_CHECK);
                    flags.insert(X509VerifyFlags::NOTIFY_POLICY);
                }
                X509VerifyFlag::InhibitMap => {
                    trace!(target: "pki-trust-root",
                           "setting INHIBIT_MAP flag");

                    flags.insert(X509VerifyFlags::INHIBIT_ANY);
                    flags.insert(X509VerifyFlags::POLICY_CHECK);
                    flags.insert(X509VerifyFlags::NOTIFY_POLICY);
                }
                X509VerifyFlag::CheckSSSignature => {
                    trace!(target: "pki-trust-root",
                           "setting CHECK_SS_SIGNATURE flag");

                    flags.insert(X509VerifyFlags::CHECK_SS_SIGNATURE);
                }
                X509VerifyFlag::NoCheckTime => {
                    trace!(target: "pki-trust-root",
                           "setting NO_CHECK_TIME flag");

                    flags.insert(X509VerifyFlags::NO_CHECK_TIME);
                    no_check_time = true;
                }
            }
        }

        if use_time && !no_check_time {
            debug!(target: "pki-trust-root",
                  "NO_CHECK_TIME flag overrides USE_TIME");

            flags.insert(X509VerifyFlags::USE_CHECK_TIME);
        } else {
            trace!(target: "pki-trust-root",
                  "not setting USE_TIME flag");

            flags.remove(X509VerifyFlags::USE_CHECK_TIME);
        }

        if !self.crls.is_empty() {
            trace!(target: "pki-trust-root",
                   "setting CRL_CHECK flag");

            flags.insert(X509VerifyFlags::CRL_CHECK);
            flags.insert(X509VerifyFlags::EXTENDED_CRL_SUPPORT);
            flags.insert(X509VerifyFlags::USE_DELTAS);
        }

        flags
    }

    #[cfg(feature = "openssl")]
    fn verify_params(
        &self,
        verify_time: Option<SystemTime>,
        endpoint: Option<&IPEndpointAddr>,
        purpose: X509PurposeId
    ) -> Result<X509VerifyParam, PKITrustRootLoadError> {
        let mut params = X509VerifyParam::new()
            .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;

        params
            .set_purpose(purpose)
            .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;
        params.set_hostflags(self.load_host_flags());
        params
            .set_flags(self.load_verify_flags(verify_time.is_some()))
            .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;

        if let Some(time) = verify_time {
            info!(target: "pki-trust-root",
                  "setting PKI verification time to {}",
                  OffsetDateTime::from(time));

            let duration = time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| PKITrustRootLoadError::BadTime { time: time })?;

            params.set_time(duration.as_secs() as i64)
        }

        match endpoint {
            Some(IPEndpointAddr::Addr(addr)) => {
                info!(target: "pki-trust-root",
                      "setting PKI verification target to {}",
                      addr);

                params
                    .set_ip(*addr)
                    .map_err(|e| PKITrustRootLoadError::OpenSSL { error: e })?
            }
            Some(IPEndpointAddr::Name(name)) => {
                info!(target: "pki-trust-root",
                      "setting PKI verification target to {}",
                      name);

                params
                    .set_host(name)
                    .map_err(|e| PKITrustRootLoadError::OpenSSL { error: e })?
            }
            None => {}
        }

        if let Some(lvl) = self.auth_level {
            debug!(target: "pki-trust-root",
                   "setting PKI authentication level to {}",
                   lvl);

            params.set_auth_level(lvl.into())
        }

        Ok(params)
    }

    #[cfg(feature = "openssl")]
    /// Generate an OpenSSL [X509Store] from this configuration.
    ///
    /// This create a new [X509Store] and then use the configuration
    /// information in this object as arguments to its corresponding
    /// configuration functions.  The resulting object is then usable
    /// as a trust store.
    ///
    /// The `verify_time` parameter optionally sets the time that will
    /// be checked against certificate validity and expiry times.  The
    /// `endpoint` parameter supplied an [IPEndpointAddr] used to check
    /// certificates, if one exists.  The `purpose` parameter is a
    /// [X509PurposeId] giving the trust store's role.
    ///
    /// Additionally, the [X509Store] will be configured in the
    /// following ways:
    ///
    /// - The minimum protocol version will be set to TLS 1.3
    ///
    /// # Examples
    ///
    /// The following example demonstrates loading a YAML
    /// configuration, then using it to configure an [X509Store]:
    ///
    /// ```
    /// # use constellation_common::config::pki::PKITrustRoot;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use openssl::x509::X509PurposeId;
    /// #
    /// let yaml = concat!(
    ///     "root-certs:\n",
    ///     "  - test/data/certs/server/ca_cert.pem\n",
    ///     "crls: []\n",
    ///     "verify-flags:\n",
    ///     "  - EXPLICIT_POLICY\n",
    ///     "  - ALLOW_PROXY_CERTS\n",
    ///     "host-flags:\n",
    ///     "  - ALWAYS_CHECK_SUBJECT\n",
    ///     "  - NO_WILDCARDS\n",
    ///     "auth-level: 4\n",
    ///     "verify-depth: 16\n"
    /// );
    /// let conf: PKITrustRoot = serde_yaml::from_str(yaml).unwrap();
    ///
    /// conf.load(None, Some(&IPEndpointAddr::name(String::from("test"))),
    ///           X509PurposeId::SSL_CLIENT)
    ///     .expect("Expected success");
    /// ```
    pub fn load(
        &self,
        verify_time: Option<SystemTime>,
        endpoint: Option<&IPEndpointAddr>,
        purpose: X509PurposeId
    ) -> Result<X509Store, PKITrustRootLoadError> {
        debug!(target: "pki-trust-root",
               "initializing PKI trust root from configuration");

        let mut builder = X509StoreBuilder::new()
            .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;
        let params = self.verify_params(verify_time, endpoint, purpose)?;

        builder
            .set_param(&params)
            .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;

        if self.root_certs.is_empty() && self.dirs.is_empty() {
            return Err(PKITrustRootLoadError::NoRootCerts);
        }

        // Add individual CA cert files.
        let files = builder
            .add_lookup(X509Lookup::file())
            .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;

        for cert in &self.root_certs {
            trace!(target: "pki-trust-root",
                   "loading trusted cert file {}",
                   cert.to_string_lossy());

            files
                .load_cert_file(cert, SslFiletype::PEM)
                .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;
        }

        // Add CRLs
        for crl in &self.crls {
            trace!(target: "pki-trust-root",
                   "loading CRL file {}",
                   crl.to_string_lossy());

            files
                .load_crl_file(crl, SslFiletype::PEM)
                .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;
        }

        // Add CA directories.
        let dirs = builder
            .add_lookup(X509Lookup::hash_dir())
            .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;

        for dir in &self.dirs {
            trace!(target: "pki-trust-root",
                   "adding trust root directory {}",
                   dir.to_string_lossy());

            dirs.add_dir(dir.to_string_lossy().as_ref(), SslFiletype::PEM)
                .map_err(|err| PKITrustRootLoadError::OpenSSL { error: err })?;
        }

        Ok(builder.build())
    }

    #[cfg(feature = "openssl")]
    /// Generate an OpenSSL [X509Store] for SSL clients from this
    /// configuration.
    ///
    /// This create a new [X509Store] and then use the configuration
    /// information in this object as arguments to its corresponding
    /// configuration functions.  The resulting object is then usable
    /// as a trust store.
    ///
    /// The `verify_time` parameter optionally sets the time that will
    /// be checked against certificate validity and expiry times.
    ///
    /// Additionally, the [X509Store] will be configured in the
    /// following ways:
    ///
    /// - The minimum protocol version will be set to TLS 1.3
    #[inline]
    pub fn load_server(
        &self,
        verify_time: Option<SystemTime>
    ) -> Result<X509Store, PKITrustRootLoadError> {
        self.load(verify_time, None, X509PurposeId::SSL_SERVER)
    }

    #[cfg(feature = "openssl")]
    /// Generate an OpenSSL [X509Store] for SSL servers from this
    /// configuration.
    ///
    /// This create a new [X509Store] and then use the configuration
    /// information in this object as arguments to its corresponding
    /// configuration functions.  The resulting object is then usable
    /// as a trust store.
    ///
    /// The `verify_time` parameter optionally sets the time that will
    /// be checked against certificate validity and expiry times.  The
    /// `endpoint` parameter supplied an [IPEndpointAddr] used to check
    /// certificates.
    ///
    /// Additionally, the [X509Store] will be configured in the
    /// following ways:
    ///
    /// - The minimum protocol version will be set to TLS 1.3
    #[inline]
    pub fn load_client(
        &self,
        verify_time: Option<SystemTime>,
        endpoint: &IPEndpointAddr
    ) -> Result<X509Store, PKITrustRootLoadError> {
        self.load(verify_time, Some(endpoint), X509PurposeId::SSL_CLIENT)
    }

    #[cfg(feature = "openssl")]
    /// Generate an OpenSSL [X509Store] for SSL peers from this
    /// configuration.
    ///
    /// This create a new [X509Store] and then use the configuration
    /// information in this object as arguments to its corresponding
    /// configuration functions.  The resulting object is then usable
    /// as a trust store.
    ///
    /// The `verify_time` parameter optionally sets the time that will
    /// be checked against certificate validity and expiry times.  The
    /// `endpoint` parameter supplied an [IPEndpointAddr] used to check
    /// certificates.
    ///
    /// Additionally, the [X509Store] will be configured in the
    /// following ways:
    ///
    /// - The minimum protocol version will be set to TLS 1.3
    #[inline]
    pub fn load_peer(
        &self,
        verify_time: Option<SystemTime>,
        endpoint: &IPEndpointAddr
    ) -> Result<X509Store, PKITrustRootLoadError> {
        self.load(verify_time, Some(endpoint), X509PurposeId::ANY)
    }
}

impl ScopedError for PKITrustRootLoadError {
    fn scope(&self) -> ErrorScope {
        match self {
            PKITrustRootLoadError::OpenSSL { .. } => ErrorScope::Unrecoverable,
            PKITrustRootLoadError::BadTime { .. } => ErrorScope::Unrecoverable,
            PKITrustRootLoadError::NoRootCerts => ErrorScope::System
        }
    }
}

impl Display for PKITrustRootLoadError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "openssl")]
            PKITrustRootLoadError::OpenSSL { error } => error.fmt(f),
            #[cfg(feature = "openssl")]
            PKITrustRootLoadError::BadTime { time } => {
                write!(
                    f,
                    "time {} is before epoch",
                    OffsetDateTime::from(*time)
                )
            }
            PKITrustRootLoadError::NoRootCerts => {
                write!(f, "no CA dirs and no root certs in configuration")
            }
        }
    }
}

#[cfg(feature = "openssl")]
impl Serialize for X509HostFlag {
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            X509HostFlag::AlwaysCheckSubject => {
                serializer.serialize_str("ALWAYS_CHECK_SUBJECT")
            }
            X509HostFlag::NoWildcards => {
                serializer.serialize_str("NO_WILDCARDS")
            }
            X509HostFlag::NoPartialWildcards => {
                serializer.serialize_str("NO_PARTIAL_WILDCARDS")
            }
            X509HostFlag::MultiLabelWildcards => {
                serializer.serialize_str("MULTI_LABEL_WILDCARDS")
            }
            X509HostFlag::SingleLabelSubdomains => {
                serializer.serialize_str("SINGLE_LABEL_SUBDOMAINS")
            }
            X509HostFlag::NeverCheckSubject => {
                serializer.serialize_str("NEVER_CHECK_SUBJECT")
            }
        }
    }
}

#[cfg(feature = "openssl")]
impl Serialize for X509VerifyFlag {
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            X509VerifyFlag::CRLCheck => serializer.serialize_str("CRL_CHECK"),
            X509VerifyFlag::CRLCheckAll => {
                serializer.serialize_str("CRL_CHECK_ALL")
            }
            X509VerifyFlag::AllowProxyCerts => {
                serializer.serialize_str("ALLOW_PROXY_CERTS")
            }
            X509VerifyFlag::PolicyCheck => {
                serializer.serialize_str("POLICY_CHECK")
            }
            X509VerifyFlag::ExplicitPolicy => {
                serializer.serialize_str("EXPLICIT_POLICY")
            }
            X509VerifyFlag::InhibitAny => {
                serializer.serialize_str("INHIBIT_ANY")
            }
            X509VerifyFlag::InhibitMap => {
                serializer.serialize_str("INHIBIT_MAP")
            }
            X509VerifyFlag::CheckSSSignature => {
                serializer.serialize_str("CHECK_SS_SIGNATURE")
            }
            X509VerifyFlag::NoCheckTime => {
                serializer.serialize_str("NO_CHECK_TIME")
            }
        }
    }
}

#[cfg(feature = "openssl")]
impl<'a> TryFrom<&'a str> for X509HostFlag {
    type Error = &'a str;

    #[inline]
    fn try_from(val: &'a str) -> Result<X509HostFlag, &'a str> {
        match val {
            "ALWAYS_CHECK_SUBJECT" => Ok(X509HostFlag::AlwaysCheckSubject),
            "NO_WILDCARDS" => Ok(X509HostFlag::NoWildcards),
            "NO_PARTIAL_WILDCARDS" => Ok(X509HostFlag::NoPartialWildcards),
            "MULTI_LABEL_WILDCARDS" => Ok(X509HostFlag::MultiLabelWildcards),
            "SINGLE_LABEL_SUBDOMAINS" => {
                Ok(X509HostFlag::SingleLabelSubdomains)
            }
            "NEVER_CHECK_SUBJECT" => Ok(X509HostFlag::NeverCheckSubject),
            _ => Err(val)
        }
    }
}

#[cfg(feature = "openssl")]
impl<'a> TryFrom<&'a str> for X509VerifyFlag {
    type Error = &'a str;

    #[inline]
    fn try_from(val: &'a str) -> Result<X509VerifyFlag, &'a str> {
        match val {
            "CRL_CHECK" => Ok(X509VerifyFlag::CRLCheck),
            "CRL_CHECK_ALL" => Ok(X509VerifyFlag::CRLCheckAll),
            "ALLOW_PROXY_CERTS" => Ok(X509VerifyFlag::AllowProxyCerts),
            "POLICY_CHECK" => Ok(X509VerifyFlag::PolicyCheck),
            "EXPLICIT_POLICY" => Ok(X509VerifyFlag::ExplicitPolicy),
            "INHIBIT_ANY" => Ok(X509VerifyFlag::InhibitAny),
            "INHIBIT_MAP" => Ok(X509VerifyFlag::InhibitMap),
            "CHECK_SS_SIGNATURE" => Ok(X509VerifyFlag::CheckSSSignature),
            "NO_CHECK_TIME" => Ok(X509VerifyFlag::NoCheckTime),
            _ => Err(val)
        }
    }
}

#[cfg(test)]
use crate::init;

#[test]
fn test_deserialize_cfg_dir() {
    init();

    let yaml = concat!("dirs:\n", "  - \"/usr/local/etc/test/certs/\"\n");
    let expected = PKITrustRoot {
        dirs: vec![PathBuf::from("/usr/local/etc/test/certs/")],
        root_certs: Vec::default(),
        crls: Vec::default(),
        #[cfg(feature = "openssl")]
        verify_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        host_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        auth_level: None,
        #[cfg(feature = "openssl")]
        verify_depth: None
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_cfg_dir_certs() {
    init();

    let yaml = concat!(
        "root-certs:\n",
        "  - /usr/local/etc/test/test.cert\n",
        "dirs:\n",
        "  - \"/usr/local/etc/test/certs/\"\n"
    );
    let expected = PKITrustRoot {
        dirs: vec![PathBuf::from("/usr/local/etc/test/certs/")],
        root_certs: vec![PathBuf::from("/usr/local/etc/test/test.cert")],
        crls: Vec::default(),
        #[cfg(feature = "openssl")]
        verify_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        host_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        auth_level: None,
        #[cfg(feature = "openssl")]
        verify_depth: None
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_cfg_dir_crls() {
    init();

    let yaml = concat!(
        "dirs:\n",
        "  - \"/usr/local/etc/test/certs/\"\n",
        "crls:\n",
        "  - /usr/local/etc/test/test.crl\n"
    );
    let expected = PKITrustRoot {
        dirs: vec![PathBuf::from("/usr/local/etc/test/certs/")],
        root_certs: Vec::default(),
        crls: vec![PathBuf::from("/usr/local/etc/test/test.crl")],
        #[cfg(feature = "openssl")]
        verify_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        host_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        auth_level: None,
        #[cfg(feature = "openssl")]
        verify_depth: None
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_cfg_certs_dir_empty_crls() {
    init();

    let yaml = concat!(
        "dirs:\n",
        "  - \"/usr/local/etc/test/certs/\"\n",
        "crls: []\n"
    );
    let expected = PKITrustRoot {
        dirs: vec![PathBuf::from("/usr/local/etc/test/certs/")],
        root_certs: Vec::default(),
        crls: Vec::default(),
        #[cfg(feature = "openssl")]
        verify_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        host_flags: Vec::default(),
        #[cfg(feature = "openssl")]
        auth_level: None,
        #[cfg(feature = "openssl")]
        verify_depth: None
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "openssl")]
#[test]
fn test_deserialize_cfg_dir_certs_auth_level() {
    init();

    let yaml = concat!(
        "root-certs:\n",
        "  - /usr/local/etc/test/test.cert\n",
        "dirs:\n",
        "  - \"/usr/local/etc/test/certs/\"\n",
        "auth-level: 3\n"
    );
    let expected = PKITrustRoot {
        dirs: vec![PathBuf::from("/usr/local/etc/test/certs/")],
        root_certs: vec![PathBuf::from("/usr/local/etc/test/test.cert")],
        crls: Vec::default(),
        verify_flags: Vec::default(),
        host_flags: Vec::default(),
        auth_level: Some(3),
        verify_depth: None
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "openssl")]
#[test]
fn test_deserialize_cfg_dir_certs_verify_flags() {
    init();

    let yaml = concat!(
        "root-certs:\n",
        "  - /usr/local/etc/test/test.cert\n",
        "dirs:\n",
        "  - \"/usr/local/etc/test/certs/\"\n",
        "verify-flags:\n",
        "  - CRL_CHECK_ALL\n",
        "  - EXPLICIT_POLICY\n"
    );
    let expected = PKITrustRoot {
        dirs: vec![PathBuf::from("/usr/local/etc/test/certs/")],
        root_certs: vec![PathBuf::from("/usr/local/etc/test/test.cert")],
        crls: Vec::default(),
        verify_flags: vec![
            X509VerifyFlag::CRLCheckAll,
            X509VerifyFlag::ExplicitPolicy,
        ],
        host_flags: Vec::default(),
        auth_level: None,
        verify_depth: None
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_trust_root_single_no_crl() {
    init();

    let yaml = concat!(
        "root-certs:\n",
        "  - test/data/certs/client/ca_cert.pem\n",
        "crls: []\n"
    );
    let root: PKITrustRoot = serde_yaml::from_str(yaml).unwrap();
    let name = String::from("test-client.nowhere.com");
    let endpoint = IPEndpointAddr::name(name);

    root.load_client(None, &endpoint).expect("Expected success");
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_trust_root_two_no_crl() {
    init();

    let yaml = concat!(
        "root-certs:\n",
        "  - test/data/certs/client/ca_cert.pem\n",
        "  - test/data/certs/server/ca_cert.pem\n",
        "crls: []\n"
    );
    let root: PKITrustRoot = serde_yaml::from_str(yaml).unwrap();
    let name = String::from("test-client.nowhere.com");
    let endpoint = IPEndpointAddr::name(name);

    root.load_client(None, &endpoint).expect("Expected success");
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_trust_root_dir_no_crl() {
    init();

    let yaml =
        concat!("dirs:\n", "  - test/data/certs/client/\n", "crls: []\n");
    let root: PKITrustRoot = serde_yaml::from_str(yaml).unwrap();
    let name = String::from("test-client.nowhere.com");
    let endpoint = IPEndpointAddr::name(name);

    root.load_client(None, &endpoint).expect("Expected success");
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_trust_root_dir_certs_auth_level() {
    init();

    let yaml = concat!(
        "root-certs:\n",
        "  - test/data/certs/server/ca_cert.pem\n",
        "dirs:\n",
        "  - test/data/certs/client/\n",
        "auth-level: 3\n"
    );
    let root: PKITrustRoot = serde_yaml::from_str(yaml).unwrap();
    let name = String::from("test-server.nowhere.com");
    let endpoint = IPEndpointAddr::name(name);

    root.load_client(None, &endpoint).expect("Expected success");
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_trust_root_dir_certs_verify_flags() {
    init();

    let yaml = concat!(
        "root-certs:\n",
        "  - test/data/certs/server/ca_cert.pem\n",
        "dirs:\n",
        "  - test/data/certs/client/\n",
        "verify-flags:\n",
        "  - CRL_CHECK_ALL\n",
        "  - EXPLICIT_POLICY\n"
    );
    let root: PKITrustRoot = serde_yaml::from_str(yaml).unwrap();
    let name = String::from("test-server.nowhere.com");
    let endpoint = IPEndpointAddr::name(name);

    root.load_client(None, &endpoint).expect("Expected success");
}
