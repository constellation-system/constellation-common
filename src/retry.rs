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
use std::time::Duration;
use std::time::Instant;

use rand::thread_rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

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
/// factor: 100
/// exp-base: 2.0
/// exp-factor: 1.0
/// exp-rounds-cap: 20
/// linear-factor: 1.0
/// linear-rounds-cap: 50
/// max-random: 100
/// addend: 50
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Retry {
    /// Scaling factor multiplied by both exponential and linear components.
    factor: usize,
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
    max_random: usize,
    /// Constant base addend.
    addend: usize
}

/// A return type for non-blocking functions that can indicate a delay.
#[derive(Clone)]
pub enum RetryResult<T, R: RetryWhen = Instant> {
    /// An immediate result.
    Success(T),
    /// Indication that the call should be retried at a point in the
    /// future.
    Retry(R)
}

impl Default for Retry {
    #[inline]
    fn default() -> Retry {
        Retry {
            factor: 100,
            exp_base: 2.0,
            exp_factor: 1.0,
            exp_rounds_cap: 20,
            linear_factor: 0.0,
            linear_rounds_cap: None,
            addend: 0,
            max_random: 100
        }
    }
}

impl Retry {
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
    /// # use constellation_common::retry::Retry;
    /// #
    /// let yaml = concat!("factor: 100\n",
    ///                    "exp-base: 2.0\n",
    ///                    "exp-factor: 1.0\n",
    ///                    "exp-rounds-cap: 20\n",
    ///                    "linear-factor: 1.0\n",
    ///                    "linear-rounds-cap: 50\n",
    ///                    "max-random: 100\n",
    ///                    "addend: 50\n");
    ///
    /// assert_eq!(
    ///     Retry::new(100, 2.0, 1.0, 20, 1.0, Some(50), 100, 50),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        factor: usize,
        exp_base: f32,
        exp_factor: f32,
        exp_rounds_cap: usize,
        linear_factor: f32,
        linear_rounds_cap: Option<usize>,
        max_random: usize,
        addend: usize
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
        let random = thread_rng().gen_range(0..self.max_random);
        let duration = (self.exp_base.powf(exponent) * (self.factor as f32)) +
            (linear_round * self.linear_factor * (self.factor as f32)) +
            (random as f32) +
            (self.addend as f32);

        Duration::from_micros(duration.max(0.0) as u64)
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
