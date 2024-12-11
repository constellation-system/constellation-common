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
use crate::retry::RetryResult;

/// Trait for histories that are used to determine scores for scheduling.
pub trait History {
    /// Type of configuration information.
    type Config;

    /// Create a fresh history.
    fn new(config: &Self::Config) -> Self;

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

    /// Compute and cache the score, if applicable.
    fn cache_score(
        &mut self,
        config: &Self::Config
    );

    // XXX technical debt item.  The need for this should be
    // eliminated eventually.
    fn clear_score_cache(&mut self);

    /// Get the score for this history.
    fn score(
        &self,
        config: &Self::Config
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
    // XXX at present, this is implemented as a lazily-sorted array.
    // We can do etter with a binary heap, but the default Rust one
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
    /// No addresses are available.
    ///
    /// This is a fatal error, and should not occur in normal
    /// operations.
    Empty
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
            SelectError::Empty => ErrorScope::Unrecoverable
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

    fn cmp_scores(
        &self,
        config: &H::Config,
        other: &Self
    ) -> Ordering {
        let self_score = self.history.score(config);
        let other_score = other.history.score(config);

        match self_score.partial_cmp(&other_score) {
            // Note incomparable items.
            None => {
                error!(target: "addr-multiplex",
                       concat!("failed to compare scores ",
                               "{} and {}"),
                       self_score, other_score);

                Ordering::Equal
            }
            Some(out) => out
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
                warn!(target: "scheduler",
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
                trace!(target: "scheduler",
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
    ) -> Result<(), ReportError<Item>> {
        let (_, _, record) = &mut self.items[idx];

        record.history.success(config);
        record.delay_until = None;

        Ok(())
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
                trace!(target: "scheduler",
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

    fn fixup_ordering<P>(
        &mut self,
        config: &H::Config,
        policy: &P
    ) where
        P: Policy<Item = Item> {
        for (_, _, record) in &mut self.items {
            record.history.cache_score(config)
        }

        // XXX this is bad, but the ordering array is a bad solution anyway.
        let mut ordering = self.ordering.clone();

        ordering.sort_unstable_by(|idx_a, idx_b| {
            let (item_a, _, a) = &self.items[*idx_a];
            let (item_b, _, b) = &self.items[*idx_b];

            match a.cmp_scores(config, b) {
                // If scores are equal, look at the address preference.
                Ordering::Equal => match policy.cmp_items(item_a, item_b) {
                    Ordering::Equal => a.cmp_delays(b),
                    out => out
                },
                Ordering::Less => Ordering::Greater,
                Ordering::Greater => Ordering::Less
            }
        });

        for (_, _, record) in &mut self.items {
            record.history.clear_score_cache()
        }

        self.ordering = ordering;
    }

    fn item<P>(
        &mut self,
        config: &H::Config,
        policy: &P
    ) -> Result<RetryResult<(Item, Origin, usize)>, SelectError>
    where
        P: Policy<Item = Item> {
        // The ordering array should always be nonzero, but check anyway.
        if !self.ordering.is_empty() {
            // Sort the active array
            self.fixup_ordering(config, policy);

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

                    (Ok(RetryResult::Retry(until)), new_until)
                }
                // No delay record; the address is good to go.
                None => {
                    record.last_use = Instant::now();

                    (
                        Ok(RetryResult::Success((
                            item.clone(),
                            origin.clone(),
                            idx
                        ))),
                        None
                    )
                }
            };

            record.delay_until = until;

            out
        } else {
            Err(SelectError::Empty)
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
                        warn!(target: "scheduler",
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
                warn!(target: "scheduler",
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
                    warn!(target: "scheduler",
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
            trace!(target: "scheduler",
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
    #[inline]
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

    #[inline]
    pub fn success_id(
        &mut self,
        id: &DenseItemID<Epochs::Item>
    ) -> Result<(), ReportError<P::Item>> {
        if id.epoch == self.epoch {
            match &mut self.state {
                SchedState::Multi { sched, .. } => {
                    sched.success_id(&self.config, id.id)
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
        RetryResult<(P::Item, Origin, DenseItemID<Epochs::Item>)>,
        SelectError
    > {
        match &mut self.state {
            SchedState::Multi { sched, .. } => {
                match sched.item(&self.config, &self.policy)? {
                    RetryResult::Retry(when) => Ok(RetryResult::Retry(when)),
                    RetryResult::Success((item, origin, idx)) => {
                        let dense = DenseItemID {
                            epoch: self.epoch.clone(),
                            id: idx
                        };

                        Ok(RetryResult::Success((item, origin, dense)))
                    }
                }
            }
            SchedState::Single {
                record,
                single,
                origin,
                ..
            } => {
                let (out, until) = match record.delay_until {
                    // There's a delay recorded.
                    Some(until) => {
                        // Check to see if it's expired.
                        let new_until = if until < Instant::now() {
                            None
                        } else {
                            Some(until)
                        };

                        (Ok(RetryResult::Retry(until)), new_until)
                    }
                    // No delay record; the address is good to go.
                    None => {
                        let dense = DenseItemID {
                            epoch: self.epoch.clone(),
                            id: 0
                        };
                        record.last_use = Instant::now();

                        (
                            Ok(RetryResult::Success((
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
            }
            // This shouldn't happen.
            SchedState::Uninit => {
                error!(target: "scheduler",
                       concat!("attempting to get item from ",
                               "uninitialized scheduler"));

                Err(SelectError::Empty)
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
            SelectError::Empty => {
                write!(f, "no valid items exist")
            }
        }
    }
}
