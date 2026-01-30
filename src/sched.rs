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

//! Generalized scheduling implementation.
//!
//! This module provides [Scheduler], which generalizes and abstracts
//! much of the implementation of an OS-type scheduler that maintains
//! a history of successes and failures for multiple different items,
//! and selects from among them at various points.
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::marker::PhantomData;
use std::time::Instant;

use log::error;
use log::trace;
use log::warn;

use crate::error::ErrorScope;
use crate::error::ScopedError;
use crate::retry::Retry;
use crate::retry::RetryIndefResult;

/// Trait for histories that are used to determine scores for scheduling.
pub trait History {
    /// Type of configuration information.
    type Config;

    /// Create a fresh history.
    fn new(config: &Self::Config) -> Self;

    /// Check whether this item is active.
    fn is_active(&self) -> bool {
        true
    }

    /// Set whether or not this item is active.
    fn set_active(
        &mut self,
        _active: bool
    ) {
    }

    /// Record a success.
    fn success(
        &mut self,
        config: &Self::Config
    );

    /// Record a failure.
    fn failure(
        &mut self,
        config: &Self::Config
    );

    /// Record a retry.
    fn retry(
        &mut self,
        config: &Self::Config
    );

    /// Get the number of retries.
    fn nretries(&self) -> usize;

    /// Get the score for this history.
    fn score(
        &self,
        config: &Self::Config,
        now: Instant
    ) -> f32;
}

/// Trait for scheduling policies that are used to filter and prefer
/// items.
pub trait Policy {
    /// Type of items.
    type Item: Clone + Display + Eq + Hash;

    /// Compare two item's
    fn cmp_items(
        &self,
        a: &Self::Item,
        b: &Self::Item
    ) -> Ordering;

    /// Filter the item's in `items` according to the policy.
    fn filter<I, Origin>(
        &self,
        items: I
    ) -> Vec<(Self::Item, Origin)>
    where
        I: Iterator<Item = (Self::Item, Origin)> {
        items.filter(|(x, _)| self.check(x)).collect()
    }

    /// Check if `item` is acceptable.
    fn check(
        &self,
        item: &Self::Item
    ) -> bool;
}

/// Epoch-specfic dense integer index for a given item.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DenseItemID<Epoch> {
    epoch: Epoch,
    id: usize
}

/// A simple [Policy] that does not filter inputs.
pub struct PassthruPolicy<Item>(PhantomData<Item>);

/// Record of a single item.
#[derive(Clone, Debug)]
struct Record<H: History> {
    /// Success and failure history.
    history: H,
    /// Time at which the address was last used.
    last_use: Instant,
    /// Time at which the address will next be usable.
    delay_until: Option<Instant>
}

/// Scheduler for multiple possible addresses.
#[derive(Clone, Debug)]
struct MultiSched<Item, Origin, H: History> {
    /// Mapping of items to dense indexes.
    ids: HashMap<Item, usize>,
    /// Mapping from dense indexes to records.
    items: Vec<(Item, Origin, Record<H>)>,
    // ISSUE #9: at present, this is implemented as a lazily-sorted array.
    // We can do better with a binary heap, but the default Rust one
    // doesn't provide an easy way to update scores.
    /// Order of preference for addresses.
    ordering: Vec<usize>
}

enum SchedState<Item, Origin, H: History> {
    /// Multiple possible addresses.
    Multi {
        sched: MultiSched<Item, Origin, H>,
        /// Time of the last refresh.
        latest: Instant
    },
    Single {
        /// History configuration.
        record: Record<H>,
        single: Item,
        origin: Origin,
        /// Time of the last refresh.
        latest: Instant
    },
    /// Uninitialized state.
    Uninit
}

/// Information about an epoch change.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EpochChange<Epoch, Item, Origin> {
    /// The epoch ID.
    id: Epoch,
    /// Mapping of all `Item`s to a dense range of integers.
    dense_ids: Vec<(Item, Origin)>,
    /// New addresses added in this epoch.
    added: Option<Vec<(Item, Origin)>>,
    /// Existing addrcesses removed in this epoch.
    removed: Option<Vec<(Item, Origin)>>
}

/// Scheduler for selecting among several different items and
/// maintaining history about their successes and failures.
///
/// `Scheduler` can be refreshed with a new set of items.  If this
/// generates a change in the set of available items, `Scheduler` will
/// generate a new "epoch" with a unique ID, and will create a new
/// mapping of items to a dense range of IDs.  This allows scheduler
/// selections to be serialized as a pair of numbers.
///
/// `Scheduler` is generally used to choose from among several different
/// options for communicating with a given counterparty.
pub struct Scheduler<Epochs: Iterator, H: History, P: Policy, Origin> {
    /// History configuration.
    config: H::Config,
    /// Policy for item's.
    policy: P,
    /// Retry configuration.
    retry: Retry,
    /// Current state.
    state: SchedState<P::Item, Origin, H>,
    /// Current epoch.
    epoch: Epochs::Item,
    /// Iterator to generate new epochs.
    epochs: Epochs
}

/// Errors that can occur while reporting successes or failures.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum ReportError<Item> {
    /// The item was not found.
    BadItem { item: Item },
    /// The scheduler was not initialized.
    Uninit
}

/// Errors that can occur when providing a refresh to the scheduler.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RefreshError {
    /// Epoch iterator was exhausted.
    OutOfEpochs,
    /// No valid addresses were supplied.
    NoValidItems
}

/// Errors that can occur when selecting an item from the scheduler.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SelectError {
    /// Scheduler was uninitialized.
    Uninit
}

impl ScopedError for RefreshError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            RefreshError::OutOfEpochs => ErrorScope::Unrecoverable,
            RefreshError::NoValidItems => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for SelectError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            SelectError::Uninit => ErrorScope::Unrecoverable
        }
    }
}

impl<Item> ScopedError for ReportError<Item> {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            ReportError::BadItem { .. } => ErrorScope::Unrecoverable,
            ReportError::Uninit => ErrorScope::Unrecoverable
        }
    }
}

impl<Epoch, Item, Origin> EpochChange<Epoch, Item, Origin> {
    /// Get the new epoch ID.
    #[inline]
    pub fn id(&self) -> &Epoch {
        &self.id
    }

    /// Get a mapping of dense IDs to item/origin pairs.
    #[inline]
    pub fn dense_ids(&self) -> &[(Item, Origin)] {
        &self.dense_ids
    }

    /// Get the item/origin pairs that were added in this epoch.
    #[inline]
    pub fn added(&self) -> Option<&Vec<(Item, Origin)>> {
        self.added.as_ref()
    }

    /// Get the item/origin pairs that were removed in this epoch.
    #[inline]
    pub fn removed(&self) -> Option<&Vec<(Item, Origin)>> {
        self.removed.as_ref()
    }

    /// Deconstruct this into the new id, the new dense ID mappings,
    /// the added addresses, and the removed addresses.
    #[inline]
    pub fn take(
        self
    ) -> (
        Epoch,
        Vec<(Item, Origin)>,
        Option<Vec<(Item, Origin)>>,
        Option<Vec<(Item, Origin)>>
    ) {
        (self.id, self.dense_ids, self.added, self.removed)
    }
}

impl<Epoch> DenseItemID<Epoch> {
    /// Create a new `DenseItemID`
    #[inline]
    pub fn new(
        epoch: Epoch,
        id: usize
    ) -> Self {
        DenseItemID {
            epoch: epoch,
            id: id
        }
    }

    /// Get the epoch identitfier.
    #[inline]
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }

    /// Get the epoch-specific index.
    #[inline]
    pub fn idx(&self) -> usize {
        self.id
    }
}

impl<H> Record<H>
where
    H: History
{
    #[inline]
    fn new(
        config: &H::Config,
        time: Instant
    ) -> Self {
        Record {
            history: H::new(config),
            last_use: time,
            delay_until: None
        }
    }

    #[inline]
    fn is_active(&self) -> bool {
        self.history.is_active()
    }

    fn cmp_actives(
        &self,
        other: &Self
    ) -> Ordering {
        match (self.history.is_active(), other.history.is_active()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => Ordering::Equal
        }
    }

    fn cmp_last_use(
        &self,
        other: &Self
    ) -> Ordering {
        // Deliberately reverse order; we want later uses to be preferable.
        other.last_use.cmp(&self.last_use)
    }

    fn cmp_delays(
        &self,
        other: &Self
    ) -> Ordering {
        match (self.delay_until, other.delay_until) {
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            // If both are None or both are equal, go to the last use.
            (None, None) => self.cmp_last_use(other),
            (Some(a), Some(b)) => match a.cmp(&b) {
                Ordering::Equal => self.cmp_last_use(other),
                out => out
            }
        }
    }
}

impl<Item, Origin, H> MultiSched<Item, Origin, H>
where
    H: Clone + History,
    Item: Clone + Display + Eq + Hash,
    Origin: Clone + Eq + Hash
{
    /// Create a new `MultiSched` from its components.
    #[inline]
    fn new<I>(
        config: &H::Config,
        now: Instant,
        items: I
    ) -> Self
    where
        I: Iterator<Item = (Item, Origin)> {
        let items: Vec<(Item, Origin, Record<H>)> = items
            .map(|(item, origin)| (item, origin, Record::new(config, now)))
            .collect();
        let mut ids = HashMap::with_capacity(items.len());
        let mut ordering = Vec::with_capacity(items.len());

        for i in 0..items.len() {
            // De-duplicate the inputs.
            if !ids.contains_key(&items[i].0) {
                ids.insert(items[i].0.clone(), i);
                ordering.push(i);
            } else {
                warn!(target: "multi-sched",
                      "duplicate item {} in scheduler inputs",
                      items[i].0.clone())
            }
        }

        MultiSched {
            items: items,
            ids: ids,
            ordering: ordering
        }
    }

    /// Record a success for `item`.
    fn success(
        &mut self,
        config: &H::Config,
        item: &Item,
        origin: &Origin
    ) -> Result<(), ReportError<Item>> {
        match self.ids.get_mut(item) {
            Some(idx) if origin == &self.items[*idx].1 => {
                trace!(target: "multi-sched",
                       "recording success for {}",
                       item);
                let (_, _, record) = &mut self.items[*idx];

                record.history.success(config);
                record.delay_until = None;

                Ok(())
            }
            _ => Err(ReportError::BadItem { item: item.clone() })
        }
    }

    #[inline]
    fn success_id(
        &mut self,
        config: &H::Config,
        idx: usize
    ) {
        let (_, _, record) = &mut self.items[idx];

        record.history.success(config);
        record.delay_until = None;
    }

    fn set_active(
        &mut self,
        item: &Item,
        origin: &Origin,
        active: bool
    ) -> Result<(), ReportError<Item>> {
        match self.ids.get_mut(item) {
            Some(idx) if origin == &self.items[*idx].1 => {
                trace!(target: "multi-sched",
                       "setting {} to active = {}",
                       item, active);
                let (_, _, record) = &mut self.items[*idx];

                record.history.set_active(active);

                Ok(())
            }
            _ => Err(ReportError::BadItem { item: item.clone() })
        }
    }

    #[inline]
    fn set_active_id(
        &mut self,
        idx: usize,
        active: bool
    ) {
        let (_, _, record) = &mut self.items[idx];

        record.history.set_active(active);
    }

    /// Record a failure for `addr`.
    fn failure(
        &mut self,
        config: &H::Config,
        retry: &Retry,
        item: &Item,
        origin: &Origin
    ) -> Result<(), ReportError<Item>> {
        match self.ids.get_mut(item) {
            Some(idx) if origin == &self.items[*idx].1 => {
                trace!(target: "multi-sched",
                       "recording failure for {}",
                       item);
                let (_, _, record) = &mut self.items[*idx];
                let delay = retry.retry_delay(record.history.nretries());

                record.delay_until = Some(record.last_use + delay);
                record.history.failure(config);

                Ok(())
            }
            _ => Err(ReportError::BadItem { item: item.clone() })
        }
    }

    #[inline]
    fn failure_id(
        &mut self,
        config: &H::Config,
        retry: &Retry,
        idx: usize
    ) -> Result<(), ReportError<Item>> {
        let (_, _, record) = &mut self.items[idx];
        let delay = retry.retry_delay(record.history.nretries() + 1);

        record.delay_until = Some(record.last_use + delay);
        record.history.failure(config);

        Ok(())
    }

    fn cmp_scores(
        a: f32,
        b: f32
    ) -> Ordering {
        match a.partial_cmp(&b) {
            // Note incomparable items.
            None => {
                error!(target: "multi-sched",
                       "failed to compare scores {} and {}",
                       a, b);

                Ordering::Equal
            }
            Some(out) => out
        }
    }

    fn fixup_ordering<P>(
        items: &mut [(Item, Origin, Record<H>)],
        ordering: &mut [usize],
        config: &H::Config,
        policy: &P
    ) where
        P: Policy<Item = Item> {
        let mut scores = vec![None; items.len()];
        let now = Instant::now();

        ordering.sort_unstable_by(|idx_a, idx_b| {
            let (item_a, _, a) = &items[*idx_a];
            let (item_b, _, b) = &items[*idx_b];
            let a_score = match scores[*idx_a] {
                Some(score) => score,
                None => {
                    let score = a.history.score(config, now);

                    scores[*idx_a] = Some(score);

                    score
                }
            };
            let b_score = match scores[*idx_b] {
                Some(score) => score,
                None => {
                    let score = b.history.score(config, now);

                    scores[*idx_b] = Some(score);

                    score
                }
            };

            match a.cmp_actives(b) {
                Ordering::Equal => match Self::cmp_scores(a_score, b_score) {
                    // If scores are equal, look at the address preference.
                    Ordering::Equal => match policy.cmp_items(item_a, item_b) {
                        Ordering::Equal => a.cmp_delays(b),
                        out => out
                    },
                    Ordering::Less => Ordering::Greater,
                    Ordering::Greater => Ordering::Less
                },
                out => out
            }
        });
    }

    fn item<P>(
        &mut self,
        config: &H::Config,
        policy: &P
    ) -> RetryIndefResult<(Item, Origin, usize)>
    where
        P: Policy<Item = Item> {
        // The ordering array should always be nonzero, but check anyway.
        if !self.ordering.is_empty() {
            // Sort the active array
            Self::fixup_ordering(
                &mut self.items,
                &mut self.ordering,
                config,
                policy
            );

            let idx = self.ordering[0];
            let (item, origin, record) = &mut self.items[idx];
            let (out, until) = match record.delay_until {
                // There's a delay recorded.
                Some(until) => {
                    // Check to see if it's expired.
                    let new_until = if until < Instant::now() {
                        None
                    } else {
                        Some(until)
                    };

                    (RetryIndefResult::Retry(until), new_until)
                }
                // No delay record; the address is good to go.
                None => {
                    if record.is_active() {
                        record.last_use = Instant::now();

                        (
                            RetryIndefResult::Success((
                                item.clone(),
                                origin.clone(),
                                idx
                            )),
                            None
                        )
                    } else {
                        (RetryIndefResult::Indef(()), None)
                    }
                }
            };

            record.delay_until = until;

            out
        } else {
            RetryIndefResult::Indef(())
        }
    }

    /// Convert this into a possible single record, producing the
    /// array of removed items as well.
    fn convert_to_single(
        &mut self,
        target: &Item,
        target_origin: &Origin
    ) -> (Option<Record<H>>, Vec<(Item, Origin)>) {
        let mut out = None;
        let mut removed = Vec::with_capacity(self.items.len());

        for (item, origin, record) in self.items.drain(..) {
            if &item == target && &origin == target_origin {
                match out {
                    None => {
                        out = Some(record);
                    }
                    // This shouldn't happen.
                    _ => {
                        warn!(target: "multi-sched",
                              "duplicate entry for {}",
                              item);
                    }
                }
            } else {
                removed.push((item, origin))
            }
        }

        (out, removed)
    }

    fn from_single<I>(
        config: &H::Config,
        now: Instant,
        target: &Item,
        existing: &Record<H>,
        items: I
    ) -> (Self, Vec<(Item, Origin)>, bool)
    where
        I: Iterator<Item = (Item, Origin)> {
        let mut removed = true;
        let items: Vec<(Item, Origin, Record<H>)> = items
            .map(|(item, origin)| {
                if &item != target {
                    (item, origin, Record::new(config, now))
                } else {
                    (item, origin, existing.clone())
                }
            })
            .collect();
        let mut ids = HashMap::with_capacity(items.len());
        let mut ordering = Vec::with_capacity(items.len());
        let mut added = Vec::with_capacity(items.len());

        for i in 0..items.len() {
            // De-duplicate the inputs.
            if !ids.contains_key(&items[i].0) {
                ids.insert(items[i].0.clone(), i);
                ordering.push(i);
            } else {
                warn!(target: "multi-sched",
                      "duplicate item {} in scheduler inputs",
                      items[i].0.clone())
            }

            let (item, origin, _) = &items[i];

            if item == target {
                removed = false;
            } else {
                added.push((item.clone(), origin.clone()))
            }
        }

        (
            MultiSched {
                items: items,
                ids: ids,
                ordering: ordering
            },
            added,
            removed
        )
    }

    fn update<I>(
        &mut self,
        config: &H::Config,
        now: Instant,
        items: I
    ) -> (Option<Vec<(Item, Origin)>>, Option<Vec<(Item, Origin)>>)
    where
        I: Iterator<Item = (Item, Origin)> {
        // Check if the address set is changing.
        let mut items: HashSet<(Item, Origin)> = items.collect();
        let mut existing: HashSet<(Item, Origin)> = self
            .items
            .iter()
            .map(|(item, origin, _)| (item.clone(), origin.clone()))
            .collect();

        if items != existing {
            let mut added = Vec::with_capacity(items.len());
            // Build the new items array by trying to look up the old
            // records.
            let items: Vec<(Item, Origin, Record<H>)> = items
                .drain()
                .map(|(item, origin)| match self.ids.get(&item) {
                    // Make sure that the origins match too.
                    Some(idx) if origin == self.items[*idx].1 => {
                        (item, origin, self.items[*idx].2.clone())
                    }
                    _ => {
                        added.push((item.clone(), origin.clone()));

                        (item, origin, Record::new(config, now))
                    }
                })
                .collect();

            let mut ids = HashMap::with_capacity(items.len());
            let mut ordering = Vec::with_capacity(items.len());

            for i in 0..items.len() {
                // De-duplicate the inputs.
                if !ids.contains_key(&items[i].0) {
                    ids.insert(items[i].0.clone(), i);
                    ordering.push(i);
                } else {
                    warn!(target: "multi-sched",
                          "duplicate item {} in scheduler inputs",
                          items[i].0.clone())
                }
            }

            let removed: Vec<(Item, Origin)> = existing
                .drain()
                .filter(|(item, _)| !ids.contains_key(item))
                .collect();
            let added = if !added.is_empty() { Some(added) } else { None };
            let removed = if !removed.is_empty() {
                Some(removed)
            } else {
                None
            };

            self.items = items;
            self.ids = ids;
            self.ordering = ordering;

            (added, removed)
        } else {
            // No change in the address set.
            trace!(target: "multi-sched",
               "got same set of multiple addresses");

            (None, None)
        }
    }
}

impl<Epochs, H, P, Origin> Scheduler<Epochs, H, P, Origin>
where
    Origin: Clone + Eq + Hash,
    Epochs: Iterator,
    Epochs::Item: Clone + Eq,
    H: Clone + History,
    P: Policy
{
    /// Create a new `Scheduler` from its components.
    #[inline]
    pub fn new(
        config: H::Config,
        retry: Retry,
        policy: P,
        mut epochs: Epochs
    ) -> Result<Self, RefreshError> {
        match epochs.next() {
            Some(epoch) => Ok(Scheduler {
                state: SchedState::Uninit,
                config: config,
                policy: policy,
                retry: retry,
                epochs: epochs,
                epoch: epoch
            }),
            None => Err(RefreshError::OutOfEpochs)
        }
    }

    /// Get the epoch identitfier.
    #[inline]
    pub fn epoch(&self) -> &Epochs::Item {
        &self.epoch
    }

    /// Record a success for `item`.
    pub fn success(
        &mut self,
        item: &P::Item,
        origin: &Origin
    ) -> Result<(), ReportError<P::Item>> {
        match &mut self.state {
            SchedState::Multi { sched, .. } => {
                sched.success(&self.config, item, origin)
            }
            SchedState::Single { record, .. } => {
                record.history.success(&self.config);

                Ok(())
            }
            SchedState::Uninit => Err(ReportError::Uninit)
        }
    }

    pub fn success_id(
        &mut self,
        id: &DenseItemID<Epochs::Item>
    ) -> Result<(), ReportError<P::Item>> {
        if id.epoch == self.epoch {
            match &mut self.state {
                SchedState::Multi { sched, .. } => {
                    sched.success_id(&self.config, id.id);

                    Ok(())
                }
                SchedState::Single { record, .. } => {
                    record.history.success(&self.config);

                    Ok(())
                }
                SchedState::Uninit => Err(ReportError::Uninit)
            }
        } else {
            Ok(())
        }
    }

    pub fn set_active(
        &mut self,
        item: &P::Item,
        origin: &Origin,
        active: bool
    ) -> Result<(), ReportError<P::Item>> {
        match &mut self.state {
            SchedState::Multi { sched, .. } => {
                sched.set_active(item, origin, active)
            }
            SchedState::Single { record, .. } => {
                record.history.set_active(active);

                Ok(())
            }
            SchedState::Uninit => Err(ReportError::Uninit)
        }
    }

    pub fn set_active_id(
        &mut self,
        id: &DenseItemID<Epochs::Item>,
        active: bool
    ) -> Result<(), ReportError<P::Item>> {
        if id.epoch == self.epoch {
            match &mut self.state {
                SchedState::Multi { sched, .. } => {
                    sched.set_active_id(id.id, active);

                    Ok(())
                }
                SchedState::Single { record, .. } => {
                    record.history.set_active(active);

                    Ok(())
                }
                SchedState::Uninit => Err(ReportError::Uninit)
            }
        } else {
            Ok(())
        }
    }

    /// Record a failure for `item`.
    #[inline]
    pub fn failure(
        &mut self,
        item: &P::Item,
        origin: &Origin
    ) -> Result<(), ReportError<P::Item>> {
        match &mut self.state {
            SchedState::Multi { sched, .. } => {
                sched.failure(&self.config, &self.retry, item, origin)
            }
            SchedState::Single { record, .. } => {
                trace!(target: "scheduler",
                       "recording failure for {}",
                       item);

                let delay = self.retry.retry_delay(record.history.nretries());

                record.delay_until = Some(record.last_use + delay);
                record.history.failure(&self.config);

                Ok(())
            }
            SchedState::Uninit => Err(ReportError::Uninit)
        }
    }

    #[inline]
    pub fn failure_id(
        &mut self,
        id: &DenseItemID<Epochs::Item>
    ) -> Result<(), ReportError<P::Item>> {
        if id.epoch == self.epoch {
            match &mut self.state {
                SchedState::Multi { sched, .. } => {
                    sched.failure_id(&self.config, &self.retry, id.id)
                }
                SchedState::Single { record, .. } => {
                    record.history.success(&self.config);

                    Ok(())
                }
                SchedState::Uninit => Err(ReportError::Uninit)
            }
        } else {
            Ok(())
        }
    }

    /// Refresh this `AddrMultiplex` with new addresses.
    pub fn refresh<I>(
        &mut self,
        now: Instant,
        iter: I
    ) -> Result<Option<EpochChange<Epochs::Item, P::Item, Origin>>, RefreshError>
    where
        I: Iterator<Item = (P::Item, Origin)> {
        // See if we need a refresh.
        let need_refresh = match &self.state {
            SchedState::Single { latest, .. } |
            SchedState::Multi { latest, .. } => now > *latest,
            SchedState::Uninit => true
        };

        if need_refresh {
            let mut filtered = self.policy.filter(iter);

            let changes = match filtered.pop() {
                Some((item, origin)) => {
                    if filtered.is_empty() {
                        // There is only one item.

                        // Check if we've got the same item.
                        match &mut self.state {
                            // We're not changing the single item.
                            SchedState::Single {
                                origin: old_origin,
                                single,
                                ..
                            } => {
                                // The item is the same as the one we
                                // have, so no change.
                                if single == &item {
                                    trace!(target: "scheduler",
                                           "got the same singular item {}",
                                           item);

                                    Ok((None, None))
                                } else {
                                    let removed = vec![(
                                        single.clone(),
                                        old_origin.clone()
                                    )];
                                    let added =
                                        vec![(item.clone(), origin.clone())];

                                    self.state = SchedState::Single {
                                        record: Record::new(&self.config, now),
                                        origin: origin,
                                        latest: now,
                                        single: item
                                    };

                                    Ok((Some(added), Some(removed)))
                                }
                            }
                            // We're going from multiple items to one, but
                            // we need to make sure we don't have that item
                            // in the multiple previous item's
                            SchedState::Multi { sched, .. } => {
                                let (record, removed) =
                                    sched.convert_to_single(&item, &origin);

                                match record {
                                    // The old item is among the new ones.
                                    Some(record) => {
                                        trace!(target: "scheduler",
                                               concat!("got a previously known",
                                                       " singular item {}"),
                                               item);

                                        self.state = SchedState::Single {
                                            record: record,
                                            latest: now,
                                            single: item,
                                            origin: origin
                                        };

                                        Ok((None, Some(removed)))
                                    }
                                    // Create a new record.
                                    None => {
                                        trace!(target: "scheduler",
                                           "got a new singular item {}",
                                               item);
                                        let added = vec![(
                                            item.clone(),
                                            origin.clone()
                                        )];
                                        let record =
                                            Record::new(&self.config, now);

                                        self.state = SchedState::Single {
                                            record: record,
                                            latest: now,
                                            single: item,
                                            origin: origin
                                        };

                                        Ok((Some(added), Some(removed)))
                                    }
                                }
                            }
                            // We always build a set of addresses.
                            SchedState::Uninit => {
                                let added =
                                    vec![(item.clone(), origin.clone())];

                                self.state = SchedState::Single {
                                    record: Record::new(&self.config, now),
                                    latest: now,
                                    single: item,
                                    origin: origin
                                };

                                Ok((Some(added), None))
                            }
                        }
                    } else {
                        // There were multiple items.
                        filtered.push((item, origin));

                        // Build the hash map of records.
                        let (newsched, added, removed) = match &mut self.state {
                            // We're going from one item to many, but
                            // we might need to keep the old record.
                            SchedState::Single {
                                single,
                                record,
                                origin,
                                ..
                            } => {
                                let (sched, added, removed) =
                                    MultiSched::from_single(
                                        &self.config,
                                        now,
                                        single,
                                        record,
                                        filtered.drain(..)
                                    );
                                let removed = if removed {
                                    Some(vec![(single.clone(), origin.clone())])
                                } else {
                                    None
                                };

                                (Some(sched), Some(added), removed)
                            }
                            SchedState::Multi { sched, .. } => {
                                // Update in place.
                                let (added, removed) = sched.update(
                                    &self.config,
                                    now,
                                    filtered.drain(..)
                                );

                                (None, added, removed)
                            }
                            // We always build a set of addresses.
                            SchedState::Uninit => {
                                let sched = MultiSched::new(
                                    &self.config,
                                    now,
                                    filtered.iter().cloned()
                                );

                                // All records were added.
                                (Some(sched), Some(filtered.clone()), None)
                            }
                        };

                        // Update the state, if we need to.
                        match newsched {
                            Some(sched) => {
                                trace!(target: "scheduler",
                                   "setting scheduler to multiple addresses");

                                self.state = SchedState::Multi {
                                    sched: sched,
                                    latest: now
                                };
                            }
                            None => {
                                trace!(target: "scheduler",
                                   "no change in the item set");
                            }
                        }

                        Ok((added, removed))
                    }
                }
                // No valid addresses.
                None => Err(RefreshError::NoValidItems)
            }?;

            // Generate a new epoch, if we need to.
            match changes {
                (None, None) => {
                    // Nothing changed.
                    trace!(target: "scheduler",
                           "no change in the item set");
                    Ok(None)
                }
                (added, removed) => {
                    // Something changed; generate a new epoch.
                    self.epoch = match self.epochs.next() {
                        Some(epoch) => Ok(epoch),
                        None => Err(RefreshError::OutOfEpochs)
                    }?;

                    trace!(target: "scheduler",
                           "setting scheduler to multiple addresses");

                    // Collect dense ID range.
                    let dense = match &self.state {
                        SchedState::Single { single, origin, .. } => {
                            vec![(single.clone(), origin.clone())]
                        }
                        SchedState::Multi { sched, .. } => sched
                            .items
                            .iter()
                            .map(|(item, origin, _)| {
                                (item.clone(), origin.clone())
                            })
                            .collect(),
                        _ => {
                            trace!(target: "scheduler",
                                   "scheduler uninitialized at end of refresh");

                            vec![]
                        }
                    };

                    Ok(Some(EpochChange {
                        id: self.epoch.clone(),
                        dense_ids: dense,
                        added: added,
                        removed: removed
                    }))
                }
            }
        } else {
            trace!(target: "scheduler",
                   "skipping stale refresh");

            Ok(None)
        }
    }

    /// Get the best available item, or when we should retry.
    pub fn select(
        &mut self
    ) -> Result<
        RetryIndefResult<(P::Item, Origin, DenseItemID<Epochs::Item>)>,
        SelectError
    > {
        match &mut self.state {
            SchedState::Multi { sched, .. } => {
                Ok(sched.item(&self.config, &self.policy)
                   .map(|(item, origin, idx)| {
                       let dense = DenseItemID {
                           epoch: self.epoch.clone(),
                           id: idx
                       };

                       (item, origin, dense)
                   }))
            }
            SchedState::Single {
                record,
                single,
                origin,
                ..
            } => {
                if record.history.is_active() {
                    let (out, until) = match record.delay_until {
                        // There's a delay recorded.
                        Some(until) => {
                            // Check to see if it's expired.
                            let new_until = if until < Instant::now() {
                                None
                            } else {
                                Some(until)
                            };

                            (Ok(RetryIndefResult::Retry(until)), new_until)
                        }
                        // No delay record; the address is good to go.
                        None => {
                            let dense = DenseItemID {
                                epoch: self.epoch.clone(),
                                id: 0
                            };
                            record.last_use = Instant::now();

                            (
                                Ok(RetryIndefResult::Success((
                                    single.clone(),
                                    origin.clone(),
                                    dense
                                ))),
                                None
                            )
                        }
                    };

                    record.delay_until = until;

                    out
                } else {
                    Ok(RetryIndefResult::Indef(()))
                }
            }
            // This shouldn't happen.
            SchedState::Uninit => {
                error!(target: "scheduler",
                       concat!("attempting to get item from ",
                               "uninitialized scheduler"));

                Err(SelectError::Uninit)
            }
        }
    }
}

impl<Item> PassthruPolicy<Item> {
    #[inline]
    pub fn new() -> Self {
        PassthruPolicy(PhantomData)
    }
}

impl<Item> Default for PassthruPolicy<Item> {
    #[inline]
    fn default() -> Self {
        PassthruPolicy(PhantomData)
    }
}

impl<Item> Policy for PassthruPolicy<Item>
where
    Item: Clone + Display + Eq + Hash
{
    type Item = Item;

    #[inline]
    fn cmp_items(
        &self,
        _a: &Self::Item,
        _b: &Self::Item
    ) -> Ordering {
        Ordering::Equal
    }

    #[inline]
    fn filter<I, Origin>(
        &self,
        items: I
    ) -> Vec<(Self::Item, Origin)>
    where
        I: Iterator<Item = (Self::Item, Origin)> {
        items.collect()
    }

    #[inline]
    fn check(
        &self,
        _item: &Self::Item
    ) -> bool {
        true
    }
}

impl<Epoch> Display for DenseItemID<Epoch>
where
    Epoch: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        write!(f, "{} (epoch {})", self.id, self.epoch)
    }
}

impl<Item> Display for ReportError<Item>
where
    Item: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        match self {
            ReportError::BadItem { item } => {
                write!(f, "unrecognized Item {}", item)
            }
            ReportError::Uninit => write!(f, "state is uninitialized")
        }
    }
}

impl Display for RefreshError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        match self {
            RefreshError::OutOfEpochs => {
                write!(f, "could not generate next epoch ID")
            }
            RefreshError::NoValidItems => {
                write!(f, "no valid items supplied")
            }
        }
    }
}

impl Display for SelectError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        match self {
            SelectError::Uninit => {
                write!(f, "no valid items exist")
            }
        }
    }
}

#[cfg(test)]
pub struct TestPolicy;

#[cfg(test)]
#[derive(Clone)]
pub struct TestHistory {
    active: bool,
    nretries: usize,
    score: f32
}

#[cfg(test)]
impl Policy for TestPolicy {
    type Item = usize;

    fn cmp_items(
        &self,
        _a: &Self::Item,
        _b: &Self::Item
    ) -> Ordering {
        Ordering::Equal
    }

    fn check(
        &self,
        _item: &Self::Item
    ) -> bool {
        false
    }
}

#[cfg(test)]
impl History for TestHistory {
    type Config = f32;

    fn new(config: &Self::Config) -> Self {
        TestHistory {
            active: true,
            nretries: 0,
            score: *config
        }
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn set_active(
        &mut self,
        active: bool
    ) {
        self.active = active;
    }

    fn success(
        &mut self,
        _config: &Self::Config
    ) {
        self.nretries = 0;
        self.score += 1.0;
    }

    fn failure(
        &mut self,
        _config: &Self::Config
    ) {
        self.score -= 1.0;
    }

    fn retry(
        &mut self,
        _config: &Self::Config
    ) {
        self.nretries += 1;
    }

    fn nretries(&self) -> usize {
        self.nretries
    }

    fn score(
        &self,
        _config: &Self::Config,
        _now: Instant
    ) -> f32 {
        self.score
    }
}

#[test]
fn test_multi_sched_prefer_success() {
    let now = Instant::now();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched.success(&config, &1, &()).expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Success((1, (), _))));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![1, 0])
}

#[test]
fn test_multi_sched_prefer_more_success() {
    let now = Instant::now();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched.success(&config, &1, &()).expect("Expected success");
    sched.success(&config, &1, &()).expect("Expected success");
    sched.success(&config, &0, &()).expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Success((1, (), _))));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![1, 0])
}

#[test]
fn test_multi_sched_prefer_no_fail() {
    let now = Instant::now();
    let retry = Retry::default();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched
        .failure(&config, &retry, &0, &())
        .expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Success((1, (), _))));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![1, 0])
}

#[test]
fn test_multi_sched_prefer_fewer_fail() {
    let now = Instant::now();
    let retry = Retry::default();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched
        .failure(&config, &retry, &0, &())
        .expect("Expected success");
    sched
        .failure(&config, &retry, &0, &())
        .expect("Expected success");
    sched
        .failure(&config, &retry, &1, &())
        .expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Retry(_)));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![1, 0])
}

#[test]
fn test_multi_sched_prefer_active_over_success() {
    let now = Instant::now();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched.success(&config, &1, &()).expect("Expected success");
    sched.set_active(&1, &(), false).expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Success((0, (), _))));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![0, 1])
}

#[test]
fn test_multi_sched_prefer_active_over_more_success() {
    let now = Instant::now();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched.success(&config, &1, &()).expect("Expected success");
    sched.success(&config, &1, &()).expect("Expected success");
    sched.success(&config, &0, &()).expect("Expected success");
    sched.set_active(&1, &(), false).expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Success((0, (), _))));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![0, 1])
}

#[test]
fn test_multi_sched_prefer_active_over_no_fail() {
    let now = Instant::now();
    let retry = Retry::default();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched
        .failure(&config, &retry, &0, &())
        .expect("Expected success");
    sched.set_active(&1, &(), false).expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Retry(_)));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![0, 1])
}

#[test]
fn test_multi_sched_prefer_active_over_fewer_fail() {
    let now = Instant::now();
    let retry = Retry::default();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched
        .failure(&config, &retry, &0, &())
        .expect("Expected success");
    sched
        .failure(&config, &retry, &0, &())
        .expect("Expected success");
    sched
        .failure(&config, &retry, &1, &())
        .expect("Expected success");
    sched.set_active(&1, &(), false).expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Retry(_)));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![0, 1])
}

#[test]
fn test_multi_sched_no_actives() {
    let now = Instant::now();
    let config = 5.0;
    let items: Vec<(usize, ())> = vec![(0, ()), (1, ())];
    let mut sched = MultiSched::<usize, (), TestHistory>::new(
        &config,
        now,
        items.into_iter()
    );

    sched.set_active(&0, &(), false).expect("Expected success");
    sched.set_active(&1, &(), false).expect("Expected success");

    let res = sched.item(&config, &TestPolicy);

    assert!(matches!(res, RetryIndefResult::Indef(())));

    let mut vec = Vec::with_capacity(sched.ordering.len());

    for idx in sched.ordering.iter() {
        vec.push(sched.items[*idx].0)
    }

    assert_eq!(vec, vec![0, 1])
}
