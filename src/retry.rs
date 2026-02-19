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

//! Retry backoff delay configuration and functionality.
//!
//! This module provides the [Retry] and [RetryResult] types.  [Retry]
//! is a general, configurable implementation of a delay mechanism to
//! be used for backoff delays with increasing intervals.
//!
//! [RetryResult] is a type similar to [Result], but intended to
//! indicate the need to retry an operation later, as opposed to an
//! error.

use std::cmp::min;
use std::convert::Infallible;
use std::fmt::Error;
use std::fmt::Formatter;
use std::time::Duration;
use std::time::Instant;

use rand::thread_rng;
use rand::Rng;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

/// Trait for retrieving a time from retry values.
pub trait RetryWhen {
    /// Get the time at which to retry.
    fn when(&self) -> Instant;
}

/// Retry delay configuration.
///
/// This provides a configurable mathematical formula for computing
/// retry delays for situations like failed connection attempts and
/// contention management.  This is a configuration object, and can be
/// parsed from YAML.
///
/// # Delay Formula
///
/// Retry delays are calculated using a combined exponential, linear,
/// and random addend.  The exponential component is calculated as
/// follows, for the `n`th round:
///
/// `factor * exp_base ^ (exp_factor * min(n, exp_rounds_cap))`
///
/// This is then added to the linear scaling component is calculated
/// as follows:
///
/// `factor * linear_factor * min(n, linear_rounds_cap)`
///
/// (Note that both of these are multiplied by `factor`)
///
/// A random addend is then computed between `0` and `max_random`
/// using a uniform distribution and added to this sum.  Finally, the
/// constant walue `addend` is added.
///
/// # YAML Format
///
/// The YAML format has eight fields, all of which have default values:
///
/// - `factor`: A scaling factor, by which both the exponential and linear
///   components are multiplied.
///
/// - `exp_base`: The base of the exponent in the exponential component.
///
/// - `exp_factor`: The factor by which the capped number of rounds is
///   multiplied in the exponent.  (Note that the same effect can be achieved by
///   raising `exp_base` to this power.)
///
/// - `exp_rounds_cap`: The maximum number of rounds that will be used in
///   computing the exponent.
///
/// - `linear_factor`: A value by which the capped number of rounds is
///   multiplied to compute the linear component.  (Note that the linear
///   component is also multiplied by `factor`.)
///
/// - `linear_rounds_cap`: The maximum number of rounds that will be used in
///   computing the linear component.  Unlike the exponential component, this
///   value is unbounded by default.
///
/// - `max_random`: The maximum value for a randomly-distributed addend.  The
///   minimum is always `0`.
///
/// - `addend`: A constant addend.
///
/// # Examples
///
/// The following is an example of a YAML configuration with all
/// fields represented:
/// ```yaml
/// factor: 100s
/// exp-base: 2.0
/// exp-factor: 1.0
/// exp-rounds-cap: 20
/// linear-factor: 1.0
/// linear-rounds-cap: 50
/// max-random: 100s
/// addend: 50s
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Retry {
    /// Scaling factor multiplied by both exponential and linear components.
    #[serde(deserialize_with = "Retry::deserialize_time")]
    #[serde(serialize_with = "Retry::serialize_time")]
    factor: Duration,
    /// Base of the exponent.
    exp_base: f32,
    /// Factor by which to multiply the exponent.
    exp_factor: f32,
    /// Maximum value of the number of rounds used in the exponent.
    exp_rounds_cap: usize,
    /// Additional factor by which to multiply the linear scaling component.
    linear_factor: f32,
    /// Maximum value of the number of rounds used in the linear
    /// component.
    linear_rounds_cap: Option<usize>,
    /// Maximum random value to which to add to the result of
    /// exponentiation.
    #[serde(deserialize_with = "Retry::deserialize_time")]
    #[serde(serialize_with = "Retry::serialize_time")]
    max_random: Duration,
    /// Constant base addend.
    #[serde(deserialize_with = "Retry::deserialize_time")]
    #[serde(serialize_with = "Retry::serialize_time")]
    addend: Duration
}

/// A return type for non-blocking functions that can indicate a delay.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RetryResult<T, R: RetryWhen = Instant> {
    /// An immediate result.
    Success(T),
    /// Indication that the call should be retried at a point in the
    /// future.
    Retry(R)
}

/// A return type for non-blocking functions that can indicate a
/// possibly indefinite delay.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RetryIndefResult<T, R: RetryWhen = Instant, I = ()> {
    /// An immediate result.
    Success(T),
    /// Indication that the call should be retried at a point in the
    /// future.
    Retry(R),
    /// Indication that the call should be retried after some
    /// condition has been met.
    Indef(I)
}

/// A retry time paired with an arbitrary value.
pub struct WithRetryWhen<T> {
    /// The retry time.
    when: Instant,
    /// The wrapped value.
    val: T
}

struct RetryVisitor;

/// Given an unbounded wait and a definite wait, combine the two and
/// get the wait time.
///
/// # Parameters
///
/// - `unbound`: The unbounded time, `None` representing an indefinite wait.
///
/// - `next`: The definite time.
///
/// # Return Value
///
/// If `unbound` is `Some(time)`, then the sooner of `time` and
/// `next`; otherwise, `next`.
#[inline]
pub fn next_retry_definite(
    unbound: Option<Instant>,
    next: Instant
) -> Instant {
    unbound.map_or(next, |when| when.min(next))
}

/// Given two unbounded waits, combine the two and get the wait time.
///
/// # Parameters
///
/// - `curr`: An unbounded time, `None` representing an indefinite wait.
///
/// - `other`: The other unbounded time, `None` representing an indefinite wait.
///
/// # Return Value
///
/// If both times are `None`, then `None`; if one wait time is
/// `Some(time)`, then `Some(time)`; if both wait times are
/// `Some(time)` then the sooner of the two times.
#[inline]
pub fn next_retry(
    curr: Option<Instant>,
    other: Option<Instant>
) -> Option<Instant> {
    other.map_or(curr, |when| Some(next_retry_definite(curr, when)))
}

impl Default for Retry {
    #[inline]
    fn default() -> Retry {
        Retry {
            factor: Duration::from_micros(100),
            exp_base: 2.0,
            exp_factor: 1.0,
            exp_rounds_cap: 20,
            linear_factor: 0.0,
            linear_rounds_cap: None,
            addend: Duration::ZERO,
            max_random: Duration::from_micros(100)
        }
    }
}

impl Retry {
    /// Default `Retry` parameters for normal terrestrial networks.
    pub const TERRESTRIAL_NETWORK_DEFAULT: Retry = Retry {
        factor: Duration::from_millis(500),
        exp_base: 2.0,
        exp_factor: 1.0,
        exp_rounds_cap: 20,
        linear_factor: 0.0,
        linear_rounds_cap: None,
        addend: Duration::ZERO,
        max_random: Duration::from_millis(500)
    };
    /// Default `Retry` parameters for resubmitting large object
    /// transfers on normal terrestrial networks.
    pub const TERRESTRIAL_NETWORK_RESUBMIT_DEFAULT: Retry = Retry {
        factor: Duration::from_secs(30),
        exp_base: 2.0,
        exp_factor: 1.0,
        exp_rounds_cap: 20,
        linear_factor: 0.0,
        linear_rounds_cap: None,
        addend: Duration::ZERO,
        max_random: Duration::from_secs(30)
    };

    /// Create a new `Retry` from its components.
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
    /// # use std::time::Duration;
    /// # use constellation_common::retry::Retry;
    /// #
    /// let yaml = concat!("factor: 10s\n",
    ///                    "exp-base: 2.0\n",
    ///                    "exp-factor: 1.0\n",
    ///                    "exp-rounds-cap: 20\n",
    ///                    "linear-factor: 1.0\n",
    ///                    "linear-rounds-cap: 50\n",
    ///                    "max-random: 10s\n",
    ///                    "addend: 50ms\n");
    ///
    /// assert_eq!(
    ///     Retry::new(Duration::from_secs(10), 2.0, 1.0, 20,
    ///                1.0, Some(50), Duration::from_secs(10),
    ///                Duration::from_millis(50)),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        factor: Duration,
        exp_base: f32,
        exp_factor: f32,
        exp_rounds_cap: usize,
        linear_factor: f32,
        linear_rounds_cap: Option<usize>,
        max_random: Duration,
        addend: Duration
    ) -> Self {
        Retry {
            factor: factor,
            exp_base: exp_base,
            exp_factor: exp_factor,
            exp_rounds_cap: exp_rounds_cap,
            linear_factor: linear_factor,
            linear_rounds_cap: linear_rounds_cap,
            max_random: max_random,
            addend: addend
        }
    }

    /// Calculate the retry delay for the `n`th round.
    pub fn retry_delay(
        &self,
        n: usize
    ) -> Duration {
        let exp_round = min(n, self.exp_rounds_cap);
        let exponent = self.exp_factor * exp_round as f32;
        let linear_round = match self.linear_rounds_cap {
            Some(cap) => min(n, cap) as f32,
            None => n as f32
        };
        let random = thread_rng().gen_range(0..self.max_random.as_micros());
        let random = Duration::from_micros(random as u64);

        self.factor.mul_f32(self.exp_base.powf(exponent)) +
            self.factor.mul_f32(linear_round * self.linear_factor) +
            random +
            self.addend
    }

    pub fn serialize_time<S>(
        time: &Duration,
        ser: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        let mut out = String::new();

        if time.as_secs() != 0 {
            let mut secs = time.as_secs();
            let years = secs / (60 * 60 * 24 * 365);

            if years != 0 {
                out.push_str(&format!("{}y", years));

                secs -= years * 60 * 60 * 24 * 365;
            }

            let weeks = secs / (60 * 60 * 24 * 7);

            if weeks != 0 {
                if out.is_empty() {
                    out.push_str(&format!("{}w", weeks))
                } else {
                    out.push_str(&format!(" {}w", weeks))
                }

                secs -= weeks * 60 * 60 * 24 * 7;
            }

            let days = secs / (60 * 60 * 24);

            if days != 0 {
                if out.is_empty() {
                    out.push_str(&format!("{}d", days))
                } else {
                    out.push_str(&format!(" {}d", days))
                }

                secs -= days * 60 * 60 * 24;
            }

            let hours = secs / (60 * 60);

            if hours != 0 {
                if out.is_empty() {
                    out.push_str(&format!("{}h", hours))
                } else {
                    out.push_str(&format!(" {}h", hours))
                }

                secs -= days * 60 * 60;
            }

            let mins = secs / 60;

            if mins != 0 {
                if out.is_empty() {
                    out.push_str(&format!("{}m", mins))
                } else {
                    out.push_str(&format!(" {}m", mins))
                }

                secs -= mins * 60;
            }

            if secs != 0 {
                if out.is_empty() {
                    out.push_str(&format!("{}m", mins))
                } else {
                    out.push_str(&format!(" {}m", mins))
                }
            }
        }

        let mut nanos = time.subsec_nanos();
        let millis = nanos / (1000 * 1000);

        if millis != 0 {
            if out.is_empty() {
                out.push_str(&format!("{}ms", millis))
            } else {
                out.push_str(&format!(" {}ms", millis))
            }

            nanos -= millis * 1000 * 1000;
        }

        let micros = nanos / 1000;

        if micros != 0 {
            if out.is_empty() {
                out.push_str(&format!("{}us", micros))
            } else {
                out.push_str(&format!(" {}us", micros))
            }

            nanos -= millis * 1000;
        }

        if nanos != 0 {
            if out.is_empty() {
                out.push_str(&format!("{}ns", nanos))
            } else {
                out.push_str(&format!(" {}ns", nanos))
            }
        }

        ser.serialize_str(&out)
    }

    #[inline]
    pub fn deserialize_time<'de, D>(de: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de> {
        de.deserialize_str(RetryVisitor)
    }
}

impl Visitor<'_> for RetryVisitor {
    type Value = Duration;

    #[inline]
    fn expecting(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        f.write_str("a string containing times")
    }

    fn visit_str<E>(
        self,
        s: &str
    ) -> Result<Self::Value, E>
    where
        E: serde::de::Error {
        let mut out = Duration::ZERO;

        for s in s.split(' ') {
            let time = if let Some(idx) =
                s.find(|c| char::is_ascii_alphabetic(&c))
            {
                let (num, suffix) = s.split_at(idx);

                match (num.parse(), suffix) {
                    (Ok(num), "ns") => Ok(Duration::from_nanos(num)),
                    (Ok(num), "us") => Ok(Duration::from_micros(num)),
                    (Ok(num), "ms") => Ok(Duration::from_millis(num)),
                    (Ok(num), "s" | "sec") => Ok(Duration::from_secs(num)),
                    (Ok(num), "m" | "min") => {
                        let secs = num * 60;

                        Ok(Duration::from_secs(secs))
                    }
                    (Ok(num), "h" | "hr") => {
                        let secs = num * 60 * 60;

                        Ok(Duration::from_secs(secs))
                    }
                    (Ok(num), "d") => {
                        let secs = num * 60 * 60 * 24;

                        Ok(Duration::from_secs(secs))
                    }
                    (Ok(num), "w" | "wk") => {
                        let secs = num * 60 * 60 * 24 * 7;

                        Ok(Duration::from_secs(secs))
                    }
                    (Ok(num), "y" | "yr") => {
                        let secs = num * 60 * 60 * 24 * 365;

                        Ok(Duration::from_secs(secs))
                    }
                    (Ok(_), unit) => {
                        Err(E::custom(format!("invalid time unit {}", unit)))
                    }
                    (Err(err), _) => Err(E::custom(err.to_string()))
                }
            } else {
                Err(E::custom(format!("invalid time specifier {}", s)))
            }?;

            out += time
        }

        if out != Duration::ZERO {
            Ok(out)
        } else {
            Err(E::custom("no time amounts specified"))
        }
    }
}

impl<T, R, I> From<RetryResult<T, R>> for RetryIndefResult<T, R, I>
where
    R: RetryWhen
{
    #[inline]
    fn from(val: RetryResult<T, R>) -> Self {
        match val {
            RetryResult::Success(val) => RetryIndefResult::Success(val),
            RetryResult::Retry(when) => RetryIndefResult::Retry(when)
        }
    }
}

impl<T, R> RetryResult<T, R>
where
    R: RetryWhen
{
    /// Apply a mapping function to the success result.
    #[inline]
    pub fn map<F, S>(
        self,
        f: F
    ) -> RetryResult<S, R>
    where
        F: FnOnce(T) -> S {
        match self {
            RetryResult::Success(val) => RetryResult::Success(f(val)),
            RetryResult::Retry(retry) => RetryResult::Retry(retry)
        }
    }

    /// Apply a mapping function to the retry result.
    #[inline]
    pub fn map_retry<F, Q>(
        self,
        f: F
    ) -> RetryResult<T, Q>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> Q {
        match self {
            RetryResult::Success(val) => RetryResult::Success(val),
            RetryResult::Retry(retry) => RetryResult::Retry(f(retry))
        }
    }

    /// Apply an error-producing mapping function to the success result.
    #[inline]
    pub fn map_ok<F, S, E>(
        self,
        f: F
    ) -> Result<RetryResult<S, R>, E>
    where
        F: FnOnce(T) -> Result<S, E> {
        match self {
            RetryResult::Success(val) => Ok(RetryResult::Success(f(val)?)),
            RetryResult::Retry(retry) => Ok(RetryResult::Retry(retry))
        }
    }

    /// Apply an error-producing mapping function to the retry result.
    #[inline]
    pub fn map_retry_ok<F, Q, E>(
        self,
        f: F
    ) -> Result<RetryResult<T, Q>, E>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> Result<Q, E> {
        match self {
            RetryResult::Success(val) => Ok(RetryResult::Success(val)),
            RetryResult::Retry(retry) => Ok(RetryResult::Retry(f(retry)?))
        }
    }

    /// Apply a mapping function to the success result.
    #[inline]
    pub fn flat_map<F, S>(
        self,
        f: F
    ) -> RetryResult<S, R>
    where
        F: FnOnce(T) -> RetryResult<S, R> {
        match self {
            RetryResult::Success(val) => f(val),
            RetryResult::Retry(retry) => RetryResult::Retry(retry)
        }
    }

    /// Apply a mapping function to the retry result.
    #[inline]
    pub fn flat_map_retry<F, Q>(
        self,
        f: F
    ) -> RetryResult<T, Q>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> RetryResult<T, Q> {
        match self {
            RetryResult::Success(val) => RetryResult::Success(val),
            RetryResult::Retry(retry) => f(retry)
        }
    }

    /// Apply an error-producing mapping function to the success result.
    #[inline]
    pub fn flat_map_ok<F, S, E>(
        self,
        f: F
    ) -> Result<RetryResult<S, R>, E>
    where
        F: FnOnce(T) -> Result<RetryResult<S, R>, E> {
        match self {
            RetryResult::Success(val) => f(val),
            RetryResult::Retry(retry) => Ok(RetryResult::Retry(retry))
        }
    }

    /// Apply an error-producing mapping function to the retry result.
    #[inline]
    pub fn flat_map_retry_ok<F, Q, E>(
        self,
        f: F
    ) -> Result<RetryResult<T, Q>, E>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> Result<RetryResult<T, Q>, E> {
        match self {
            RetryResult::Success(val) => Ok(RetryResult::Success(val)),
            RetryResult::Retry(retry) => f(retry)
        }
    }

    /// Apply a function to the success result.
    #[inline]
    pub fn app<F>(
        self,
        f: F
    ) where
        F: FnOnce(T) {
        if let RetryResult::Success(val) = self {
            f(val)
        }
    }

    /// Apply a function to the retry result.
    #[inline]
    pub fn app_retry<F>(
        self,
        f: F
    ) where
        F: FnOnce(R) {
        if let RetryResult::Retry(retry) = self {
            f(retry)
        }
    }

    /// Apply a function to the success result.
    #[inline]
    pub fn inspect<F>(
        &self,
        f: F
    ) where
        F: FnOnce(&T) {
        if let RetryResult::Success(val) = self {
            f(val)
        }
    }

    /// Apply a function to the retry result.
    #[inline]
    pub fn inspect_retry<F>(
        &self,
        f: F
    ) where
        F: FnOnce(&R) {
        if let RetryResult::Retry(retry) = self {
            f(retry)
        }
    }
}

impl<T, R, I> RetryIndefResult<T, R, I>
where
    R: RetryWhen
{
    /// Apply a mapping function to the success result.
    #[inline]
    pub fn map<F, S>(
        self,
        f: F
    ) -> RetryIndefResult<S, R, I>
    where
        F: FnOnce(T) -> S {
        match self {
            RetryIndefResult::Success(val) => RetryIndefResult::Success(f(val)),
            RetryIndefResult::Retry(retry) => RetryIndefResult::Retry(retry),
            RetryIndefResult::Indef(indef) => RetryIndefResult::Indef(indef)
        }
    }

    /// Apply a mapping function to the retry result.
    #[inline]
    pub fn map_retry<F, Q>(
        self,
        f: F
    ) -> RetryIndefResult<T, Q, I>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> Q {
        match self {
            RetryIndefResult::Success(val) => RetryIndefResult::Success(val),
            RetryIndefResult::Retry(retry) => RetryIndefResult::Retry(f(retry)),
            RetryIndefResult::Indef(indef) => RetryIndefResult::Indef(indef)
        }
    }

    /// Apply a mapping function to the retry result.
    #[inline]
    pub fn map_indef<F, J>(
        self,
        f: F
    ) -> RetryIndefResult<T, R, J>
    where
        F: FnOnce(I) -> J {
        match self {
            RetryIndefResult::Success(val) => RetryIndefResult::Success(val),
            RetryIndefResult::Retry(retry) => RetryIndefResult::Retry(retry),
            RetryIndefResult::Indef(indef) => RetryIndefResult::Indef(f(indef))
        }
    }

    /// Apply an error-producing mapping function to the success result.
    #[inline]
    pub fn map_ok<F, S, E>(
        self,
        f: F
    ) -> Result<RetryIndefResult<S, R, I>, E>
    where
        F: FnOnce(T) -> Result<S, E> {
        match self {
            RetryIndefResult::Success(val) => {
                Ok(RetryIndefResult::Success(f(val)?))
            }
            RetryIndefResult::Retry(retry) => {
                Ok(RetryIndefResult::Retry(retry))
            }
            RetryIndefResult::Indef(indef) => Ok(RetryIndefResult::Indef(indef))
        }
    }

    /// Apply an error-producing mapping function to the retry result.
    #[inline]
    pub fn map_retry_ok<F, Q, E>(
        self,
        f: F
    ) -> Result<RetryIndefResult<T, Q, I>, E>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> Result<Q, E> {
        match self {
            RetryIndefResult::Success(val) => {
                Ok(RetryIndefResult::Success(val))
            }
            RetryIndefResult::Retry(retry) => {
                Ok(RetryIndefResult::Retry(f(retry)?))
            }
            RetryIndefResult::Indef(indef) => Ok(RetryIndefResult::Indef(indef))
        }
    }

    /// Apply a mapping function to the success result.
    #[inline]
    pub fn flat_map<F, S>(
        self,
        f: F
    ) -> RetryIndefResult<S, R, I>
    where
        F: FnOnce(T) -> RetryIndefResult<S, R, I> {
        match self {
            RetryIndefResult::Success(val) => f(val),
            RetryIndefResult::Retry(retry) => RetryIndefResult::Retry(retry),
            RetryIndefResult::Indef(indef) => RetryIndefResult::Indef(indef)
        }
    }

    /// Apply a mapping function to the retry result.
    #[inline]
    pub fn flat_map_retry<F, Q>(
        self,
        f: F
    ) -> RetryIndefResult<T, Q, I>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> RetryIndefResult<T, Q, I> {
        match self {
            RetryIndefResult::Success(val) => RetryIndefResult::Success(val),
            RetryIndefResult::Retry(retry) => f(retry),
            RetryIndefResult::Indef(indef) => RetryIndefResult::Indef(indef)
        }
    }

    /// Apply an error-producing mapping function to the success result.
    #[inline]
    pub fn flat_map_ok<F, S, E>(
        self,
        f: F
    ) -> Result<RetryIndefResult<S, R, I>, E>
    where
        F: FnOnce(T) -> Result<RetryIndefResult<S, R, I>, E> {
        match self {
            RetryIndefResult::Success(val) => f(val),
            RetryIndefResult::Retry(retry) => {
                Ok(RetryIndefResult::Retry(retry))
            }
            RetryIndefResult::Indef(indef) => Ok(RetryIndefResult::Indef(indef))
        }
    }

    /// Apply an error-producing mapping function to the retry result.
    #[inline]
    pub fn flat_map_retry_ok<F, Q, E>(
        self,
        f: F
    ) -> Result<RetryIndefResult<T, Q, I>, E>
    where
        Q: RetryWhen,
        F: FnOnce(R) -> Result<RetryIndefResult<T, Q, I>, E> {
        match self {
            RetryIndefResult::Success(val) => {
                Ok(RetryIndefResult::Success(val))
            }
            RetryIndefResult::Retry(retry) => f(retry),
            RetryIndefResult::Indef(indef) => Ok(RetryIndefResult::Indef(indef))
        }
    }

    /// Apply a function to the success result.
    #[inline]
    pub fn app<F>(
        self,
        f: F
    ) where
        F: FnOnce(T) {
        if let RetryIndefResult::Success(val) = self {
            f(val)
        }
    }

    /// Apply a function to the retry result.
    #[inline]
    pub fn app_retry<F>(
        self,
        f: F
    ) where
        F: FnOnce(R) {
        if let RetryIndefResult::Retry(retry) = self {
            f(retry)
        }
    }

    /// Apply a function to the success result.
    #[inline]
    pub fn inspect<F>(
        &self,
        f: F
    ) where
        F: FnOnce(&T) {
        if let RetryIndefResult::Success(val) = self {
            f(val)
        }
    }

    /// Apply a function to the retry result.
    #[inline]
    pub fn inspect_retry<F>(
        &self,
        f: F
    ) where
        F: FnOnce(&R) {
        if let RetryIndefResult::Retry(retry) = self {
            f(retry)
        }
    }
}

impl<R> RetryWhen for Vec<R>
where
    R: RetryWhen
{
    #[inline]
    fn when(&self) -> Instant {
        self.iter()
            .map(|val| val.when())
            .min()
            .unwrap_or(Instant::now())
    }
}

impl<T, R> RetryWhen for RetryResult<T, R>
where
    R: RetryWhen
{
    #[inline]
    fn when(&self) -> Instant {
        match self {
            RetryResult::Success(_) => Instant::now(),
            RetryResult::Retry(retry) => retry.when()
        }
    }
}

impl<T> WithRetryWhen<T> {
    /// Create a `WithRetryWhen` from its components.
    #[inline]
    pub fn new(
        val: T,
        when: Instant
    ) -> Self {
        WithRetryWhen {
            when: when,
            val: val
        }
    }

    /// Deconstruct a `WithRetryWhen` into its components.
    #[inline]
    pub fn take(self) -> (T, Instant) {
        (self.val, self.when)
    }
}

impl<T> RetryWhen for WithRetryWhen<T> {
    #[inline]
    fn when(&self) -> Instant {
        self.when
    }
}

impl RetryWhen for Instant {
    #[inline]
    fn when(&self) -> Instant {
        *self
    }
}

impl RetryWhen for Infallible {
    #[inline]
    fn when(&self) -> Instant {
        Instant::now()
    }
}

#[test]
fn test_next_retry_definite_none() {
    let now = Instant::now();
    let time = next_retry_definite(None, now);

    assert_eq!(time, now);
}

#[test]
fn test_next_retry_definite_some_less() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry_definite(Some(now), next);

    assert_eq!(time, now);
}

#[test]
fn test_next_retry_definite_some_greater() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry_definite(Some(next), now);

    assert_eq!(time, now);
}

#[test]
fn test_next_retry_none() {
    let time = next_retry(None, None);

    assert_eq!(time, None);
}

#[test]
fn test_next_retry_none_some() {
    let now = Instant::now();
    let time = next_retry(None, Some(now));

    assert_eq!(time, Some(now));
}

#[test]
fn test_next_retry_some_none() {
    let now = Instant::now();
    let time = next_retry(Some(now), None);

    assert_eq!(time, Some(now));
}

#[test]
fn test_next_retry_some_some_less() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry(Some(now), Some(next));

    assert_eq!(time, Some(now));
}

#[test]
fn test_next_retry_some_some_greater() {
    let now = Instant::now();
    let next = now + Duration::from_secs(1);
    let time = next_retry(Some(next), Some(now));

    assert_eq!(time, Some(now));
}
