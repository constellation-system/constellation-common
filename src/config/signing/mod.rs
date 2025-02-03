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

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[serde(rename = "pgp-trust-root")]
pub struct PGPTrustRoot {
    /// Path to the PGP key wallet.
    pub(crate) path: PathBuf,
    pub(crate) trust_keys: Vec<String>,
    pub(crate) signing_key: String,
    pub(crate) min_trust: String
}

#[test]
fn test_deserialize_tls_cfg_certs_dir() {
    let yaml = concat!(
        "path: /usr/local/etc/test/keystore.pgp\n",
        "trust-keys:\n",
        "  - ABCDEF1234567890\n",
        "  - 0987654321FEDCBA\n",
        "signing-key: ABCDEF1234567890\n",
        "min-trust: ultimate\n"
    );
    let expected = PGPTrustRoot {
        path: PathBuf::from("/usr/local/etc/test/keystore.pgp"),
        trust_keys: vec![
            String::from("ABCDEF1234567890"),
            String::from("0987654321FEDCBA"),
        ],
        signing_key: String::from("ABCDEF1234567890"),
        min_trust: String::from("ultimate")
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}
