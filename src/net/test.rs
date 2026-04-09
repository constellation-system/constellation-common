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

use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::time::Instant;

use crate::error::ErrorScope;
use crate::error::ScopedError;
use crate::net::PrivateMsgs;
use crate::net::SharedMsgs;

/// Scriptable [PrivateMsgs] instance for testing.
pub struct TestPrivateMsgs<Msg> {
    script: Vec<Result<(Option<Vec<Msg>>, Option<Instant>), TestMsgsError>>
}

/// Scriptable [SharedMsgs] instance for testing.
pub struct TestSharedMsgs<Party, Msg>
where
    Party: Clone + Eq + Hash {
    script: Vec<
        Result<
            (Option<Vec<(Vec<Party>, Vec<Msg>)>>, Option<Instant>),
            TestMsgsError
        >
    >
}

/// Test error for use with [TestPrivateMsgs] and [TestSharedMsgs].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TestMsgsError {
    pub scope: ErrorScope
}

impl<Msg> TestPrivateMsgs<Msg> {
    /// Create a `TestPrivateMsgs` from a script.
    ///
    /// Each entry in `script` determines the outcome of one call of
    /// [msgs](PrivateMsgs::msgs).  This will panic if `msgs` is
    /// called when the script is exhausted.
    ///
    /// # Parameters
    ///
    /// - `script`: The action script for calls to [msgs](PrivateMsgs::msgs).
    pub fn new(
        mut script: Vec<
            Result<(Option<Vec<Msg>>, Option<Instant>), TestMsgsError>
        >
    ) -> Self {
        script.reverse();

        TestPrivateMsgs { script: script }
    }
}

impl<Party, Msg> TestSharedMsgs<Party, Msg>
where
    Party: Clone + Eq + Hash
{
    /// Create a `TestSharedMsgs` from a script.
    ///
    /// Each entry in `script` determines the outcome of one call of
    /// [msgs](SharedMsgs::msgs).  This will panic if `msgs` is
    /// called when the script is exhausted.
    ///
    /// # Parameters
    ///
    /// - `script`: The action script for calls to [msgs](SharedMsgs::msgs).
    pub fn new(
        mut script: Vec<
            Result<
                (Option<Vec<(Vec<Party>, Vec<Msg>)>>, Option<Instant>),
                TestMsgsError
            >
        >
    ) -> Self {
        script.reverse();

        TestSharedMsgs { script: script }
    }
}

impl<Msg> PrivateMsgs<Msg> for TestPrivateMsgs<Msg> {
    type MsgsError = TestMsgsError;

    #[inline]
    fn msgs(
        &mut self
    ) -> Result<(Option<Vec<Msg>>, Option<Instant>), Self::MsgsError> {
        self.script.pop().expect("expected script action")
    }
}

impl<Party, Msg> SharedMsgs<Party, Msg> for TestSharedMsgs<Party, Msg>
where
    Party: Clone + Eq + Hash
{
    type MsgsError = TestMsgsError;

    #[inline]
    fn msgs(
        &mut self,
        live: &HashSet<Party>
    ) -> Result<
        (Option<Vec<(Vec<Party>, Vec<Msg>)>>, Option<Instant>),
        Self::MsgsError
    > {
        self.script.pop().expect("expected script action").map(
            |(msgs, when)| {
                let msgs = msgs.map(|msgs| {
                    msgs.into_iter()
                        .map(|(parties, msgs)| {
                            let parties = parties
                                .into_iter()
                                .filter(|party| live.contains(party))
                                .collect();

                            (parties, msgs)
                        })
                        .collect()
                });

                (msgs, when)
            }
        )
    }
}

impl ScopedError for TestMsgsError {
    fn scope(&self) -> ErrorScope {
        self.scope
    }
}

impl Display for TestMsgsError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "test error")
    }
}

#[test]
fn test_test_private_msgs() {
    let now = Instant::now();
    let script = vec![
        Ok((Some(vec!["hello", "goodbye"]), None)),
        Ok((None, Some(now))),
        Err(TestMsgsError {
            scope: ErrorScope::Msg
        }),
    ];
    let mut msgs = TestPrivateMsgs::new(script.clone());

    for act in script {
        assert_eq!(msgs.msgs(), act)
    }
}

#[test]
fn test_test_shared_msgs() {
    let now = Instant::now();
    let script = vec![
        Ok((
            Some(vec![
                (vec![1, 2], vec!["hello", "goodbye"]),
                (vec![1, 2, 3], vec!["test"]),
            ]),
            None
        )),
        Ok((
            Some(vec![
                (vec![1, 2], vec!["hello", "goodbye"]),
                (vec![1, 2, 3], vec!["test"]),
            ]),
            None
        )),
        Ok((
            Some(vec![
                (vec![1, 2], vec!["hello", "goodbye"]),
                (vec![1, 2, 3], vec!["test"]),
            ]),
            None
        )),
        Ok((None, Some(now))),
        Err(TestMsgsError {
            scope: ErrorScope::Msg
        }),
    ];
    let mut msgs: TestSharedMsgs<usize, &str> =
        TestSharedMsgs::new(script.clone());
    let all = vec![1, 2, 3].into_iter().collect();
    let one_three = vec![1, 3].into_iter().collect();
    let one_two = vec![1, 2].into_iter().collect();

    assert_eq!(
        msgs.msgs(&all),
        Ok((
            Some(vec![
                (vec![1, 2], vec!["hello", "goodbye"]),
                (vec![1, 2, 3], vec!["test"])
            ]),
            None
        ))
    );
    assert_eq!(
        msgs.msgs(&one_three),
        Ok((
            Some(vec![
                (vec![1], vec!["hello", "goodbye"]),
                (vec![1, 3], vec!["test"])
            ]),
            None
        ))
    );
    assert_eq!(
        msgs.msgs(&one_two),
        Ok((
            Some(vec![
                (vec![1, 2], vec!["hello", "goodbye"]),
                (vec![1, 2], vec!["test"])
            ]),
            None
        ))
    );
    assert_eq!(msgs.msgs(&all), Ok((None, Some(now))));
    assert_eq!(
        msgs.msgs(&all),
        Err(TestMsgsError {
            scope: ErrorScope::Msg
        })
    );
}
