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

//! Common functionality for errors and error-handling.
use std::cmp::Ordering;
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::io::ErrorKind;

use log::error;
#[cfg(feature = "openssl")]
use openssl::ssl::HandshakeError;

/// Errors that have a known scope.
///
/// This is used to decide on the exact action to take in response to
/// an error.
pub trait ScopedError {
    /// Get the error's scope.
    fn scope(&self) -> ErrorScope;

    /// Whether or not the error has the
    /// [Shutdown](ErrorScope::Shutdown) scope.
    #[inline]
    fn is_shutdown(&self) -> bool {
        self.scope() == ErrorScope::Shutdown
    }

    /// Whether or not the error has the
    /// [Unrecoverable](ErrorScope::Unrecoverable) scope.
    #[inline]
    fn is_unrecoverable(&self) -> bool {
        self.scope() == ErrorScope::Unrecoverable
    }

    /// Whether or not the error has the
    /// [System](ErrorScope::System) scope.
    #[inline]
    fn is_system(&self) -> bool {
        self.scope() == ErrorScope::System
    }

    /// Whether or not the error has the
    /// [Session](ErrorScope::Session) scope.
    #[inline]
    fn is_session(&self) -> bool {
        self.scope() == ErrorScope::Session
    }

    /// Whether or not the error has the
    /// [Batch](ErrorScope::Batch) scope.
    #[inline]
    fn is_batch(&self) -> bool {
        self.scope() == ErrorScope::Batch
    }

    /// Whether or not the error has the
    /// [Msg](ErrorScope::Msg) scope.
    #[inline]
    fn is_msg(&self) -> bool {
        self.scope() == ErrorScope::Msg
    }

    /// Whether or not the error has the
    /// [External](ErrorScope::External) scope.
    #[inline]
    fn is_external(&self) -> bool {
        self.scope() == ErrorScope::External
    }

    /// Whether or not the error has the
    /// [Retryable](ErrorScope::Retryable) scope.
    #[inline]
    fn is_retryable(&self) -> bool {
        self.scope() == ErrorScope::Retryable
    }
}

/// Indicator of the nature and scope of an error.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum ErrorScope {
    /// The error is not recoverable.
    ///
    /// This is usually indicative of programming errors.  These
    /// should usually be reported at `error`.
    Unrecoverable,
    /// The error results from the state of the local system.
    ///
    /// This means the application is not viable given the current
    /// state of the system.  These should be reported at `warn` or
    /// lower severity.
    System,
    /// The error indicates a shutdown condition.
    ///
    /// This means the system is shutting down.  These should
    /// generally be reported at `info` or lower severity.
    Shutdown,
    /// The error indicates the current session is no longer viable.
    ///
    /// This means that something is wrong with the current session,
    /// and it should be terminated.  These should generally be
    /// reported at `info` or lower severity.
    Session,
    /// The error is limited to the current batch.
    ///
    /// This means the batch is no longer viable and should be aborted.
    Batch,
    /// The error is limited to the current message.
    ///
    /// This means the current message is corrupted in some way.
    /// These should generally be reported at `warn` or lower
    /// severity.
    Msg,
    /// The error is caused by external factors, such as network
    /// accessibility and other machines.
    ///
    /// This generally means the current operation cannot succeed at
    /// present, but may be able to succeed in the future.  These
    /// should be reported at `info` or lower severity.
    External,
    /// The error is temporary in nature, and the operation can be retried.
    ///
    /// This is associated with errors such as
    /// [WouldBlock](ErrorKind::WouldBlock),
    /// [TimedOut](ErrorKind::TimedOut), and
    /// [Interrupted](ErrorKind::Interrupted).  These should generally
    /// not be reported, except as debug messages.
    Retryable
}

#[derive(Debug)]
pub struct MutexPoison;

#[derive(Debug)]
pub enum WithMutexPoison<Error> {
    Inner { error: Error },
    MutexPoison
}

impl Ord for ErrorScope {
    fn cmp(
        &self,
        other: &Self
    ) -> Ordering {
        match (self, other) {
            (ErrorScope::Unrecoverable, ErrorScope::Unrecoverable) => {
                Ordering::Equal
            }
            (ErrorScope::Unrecoverable, _) => Ordering::Greater,
            (_, ErrorScope::Unrecoverable) => Ordering::Less,
            (ErrorScope::System, ErrorScope::System) => Ordering::Equal,
            (ErrorScope::System, _) => Ordering::Greater,
            (_, ErrorScope::System) => Ordering::Less,
            (ErrorScope::Shutdown, ErrorScope::Shutdown) => Ordering::Equal,
            (ErrorScope::Shutdown, _) => Ordering::Greater,
            (_, ErrorScope::Shutdown) => Ordering::Less,
            (ErrorScope::Session, ErrorScope::Session) => Ordering::Equal,
            (ErrorScope::Session, _) => Ordering::Greater,
            (_, ErrorScope::Session) => Ordering::Less,
            (ErrorScope::Batch, ErrorScope::Batch) => Ordering::Equal,
            (ErrorScope::Batch, _) => Ordering::Greater,
            (_, ErrorScope::Batch) => Ordering::Less,
            (ErrorScope::Msg, ErrorScope::Msg) => Ordering::Equal,
            (ErrorScope::Msg, _) => Ordering::Greater,
            (_, ErrorScope::Msg) => Ordering::Less,
            (ErrorScope::External, ErrorScope::External) => Ordering::Equal,
            (ErrorScope::External, _) => Ordering::Greater,
            (_, ErrorScope::External) => Ordering::Less,
            (ErrorScope::Retryable, ErrorScope::Retryable) => Ordering::Equal
        }
    }
}

impl PartialOrd for ErrorScope {
    #[inline]
    fn partial_cmp(
        &self,
        other: &Self
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ScopedError for std::io::Error {
    fn scope(&self) -> ErrorScope {
        match self.kind() {
            ErrorKind::InvalidInput |
            ErrorKind::OutOfMemory |
            ErrorKind::Unsupported |
            ErrorKind::Other => ErrorScope::Unrecoverable,
            ErrorKind::AlreadyExists |
            ErrorKind::AddrNotAvailable |
            ErrorKind::AddrInUse |
            ErrorKind::PermissionDenied |
            ErrorKind::NotFound => ErrorScope::System,
            ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => {
                ErrorScope::Session
            }
            ErrorKind::InvalidData |
            ErrorKind::UnexpectedEof |
            ErrorKind::WriteZero => ErrorScope::Msg,
            ErrorKind::ConnectionRefused | ErrorKind::ConnectionAborted => {
                ErrorScope::External
            }
            ErrorKind::Interrupted |
            ErrorKind::WouldBlock |
            ErrorKind::TimedOut => ErrorScope::Retryable,
            _ => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for Infallible {
    #[inline]
    fn scope(&self) -> ErrorScope {
        error!(target: "scoped-error",
               "this function should never be called!");

        ErrorScope::Unrecoverable
    }
}

impl ScopedError for MutexPoison {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Unrecoverable
    }
}

impl<Error> ScopedError for WithMutexPoison<Error>
where
    Error: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            WithMutexPoison::Inner { error } => error.scope(),
            WithMutexPoison::MutexPoison => ErrorScope::Unrecoverable
        }
    }
}

#[cfg(feature = "openssl")]
impl<S> ScopedError for HandshakeError<S> {
    fn scope(&self) -> ErrorScope {
        match self {
            HandshakeError::SetupFailure(_) => ErrorScope::System,
            HandshakeError::Failure(_) => ErrorScope::External,
            HandshakeError::WouldBlock(_) => ErrorScope::Retryable
        }
    }
}

impl Display for MutexPoison {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "mutex poisoned")
    }
}

impl<Err> Display for WithMutexPoison<Err>
where
    Err: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            WithMutexPoison::Inner { error } => error.fmt(f),
            WithMutexPoison::MutexPoison => write!(f, "mutex poisoned")
        }
    }
}
