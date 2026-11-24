/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The connection slab: chunks of slots whose indices never move, so a connection keeps its
//! [`ConnKey`] for life and a reused slot gets a new generation.
//!
//! Each slot has its own `RefCell` and chunks are reference counted, so the driver can lend one
//! connection to its session while the session opens another connection, which reserves and
//! fills a different slot, possibly in a new chunk.

use std::cell::RefCell;
use std::cell::RefMut;
use std::rc::Rc;

use mvfstr_proto::ConnKey;

/// Slots per chunk.
pub(crate) const CHUNK: usize = 64;

/// One slot: its generation and its value, if occupied.
pub(crate) struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

impl<T> Slot<T> {
    /// Returns the value stored under `key`, if `key` is current.
    pub(crate) fn get(&mut self, key: ConnKey) -> Option<&mut T> {
        if self.generation != key.generation {
            return None;
        }
        self.value.as_mut()
    }
}

/// A slot of the slab, held apart from the slab's own borrow.
pub(crate) struct SlotRef<T> {
    chunk: Rc<[RefCell<Slot<T>>]>,
    offset: usize,
}

impl<T> SlotRef<T> {
    /// Borrows the slot.
    pub(crate) fn borrow_mut(&self) -> RefMut<'_, Slot<T>> {
        self.chunk[self.offset].borrow_mut()
    }
}

/// The slab.
pub(crate) struct Slab<T> {
    chunks: Vec<Rc<[RefCell<Slot<T>>]>>,
    free: Vec<u32>,
    /// The next index never handed out.
    next: u32,
    live: usize,
}

impl<T> Slab<T> {
    pub(crate) fn new() -> Self {
        Self {
            chunks: Vec::new(),
            free: Vec::new(),
            next: 0,
            live: 0,
        }
    }

    /// Returns the number of occupied slots.
    pub(crate) fn len(&self) -> usize {
        self.live
    }

    /// Returns one past the highest index ever handed out.
    pub(crate) fn end(&self) -> u32 {
        self.next
    }

    /// Reserves a vacant slot and returns its key; [`insert`](Self::insert) fills it and
    /// [`cancel`](Self::cancel) gives it back.
    pub(crate) fn reserve(&mut self) -> ConnKey {
        let index = self.free.pop().unwrap_or_else(|| {
            let index = self.next;
            self.next += 1;
            if index as usize == self.chunks.len() * CHUNK {
                self.chunks.push(
                    (0..CHUNK)
                        .map(|_| {
                            RefCell::new(Slot {
                                generation: 0,
                                value: None,
                            })
                        })
                        .collect(),
                );
            }
            index
        });
        let generation = self.cell(index).borrow().generation;
        ConnKey { index, generation }
    }

    /// Fills the slot reserved as `key`.
    pub(crate) fn insert(&mut self, key: ConnKey, value: T) {
        let mut slot = self.cell(key.index).borrow_mut();
        debug_assert!(
            slot.value.is_none() && slot.generation == key.generation,
            "inserting into a slot that was not reserved"
        );
        slot.value = Some(value);
        drop(slot);
        self.live += 1;
    }

    /// Gives back a slot reserved as `key` and never filled.
    pub(crate) fn cancel(&mut self, key: ConnKey) {
        self.free.push(key.index);
    }

    /// Empties the slot holding `key`, which must not be borrowed, and returns its value; the
    /// slot's next key has a new generation.
    pub(crate) fn remove(&mut self, key: ConnKey) -> Option<T> {
        let mut slot =
            self.chunks.get(key.index as usize / CHUNK)?[key.index as usize % CHUNK].borrow_mut();
        if slot.generation != key.generation {
            return None;
        }
        let value = slot.value.take()?;
        slot.generation = slot.generation.wrapping_add(1);
        drop(slot);
        self.free.push(key.index);
        self.live -= 1;
        Some(value)
    }

    /// Returns the slot at `index`, if the slab has grown that far.
    pub(crate) fn slot(&self, index: u32) -> Option<SlotRef<T>> {
        let chunk = self.chunks.get(index as usize / CHUNK)?;
        Some(SlotRef {
            chunk: Rc::clone(chunk),
            offset: index as usize % CHUNK,
        })
    }

    /// Returns the key of the value in slot `index`, if the slot is occupied.
    pub(crate) fn key_at(&self, index: u32) -> Option<ConnKey> {
        let chunk = self.chunks.get(index as usize / CHUNK)?;
        let slot = chunk[index as usize % CHUNK].borrow();
        slot.value.as_ref().map(|_| ConnKey {
            index,
            generation: slot.generation,
        })
    }

    /// Returns the cell of a slot handed out before.
    fn cell(&self, index: u32) -> &RefCell<Slot<T>> {
        &self.chunks[index as usize / CHUNK][index as usize % CHUNK]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(slab: &Slab<usize>, key: ConnKey) -> Option<usize> {
        slab.slot(key.index)?.borrow_mut().get(key).copied()
    }

    #[test]
    fn indices_never_move_and_a_reused_slot_gets_a_new_generation() {
        let mut slab = Slab::new();
        let keys: Vec<ConnKey> = (0..CHUNK + 3)
            .map(|i| {
                let key = slab.reserve();
                slab.insert(key, i);
                key
            })
            .collect();
        assert_eq!(slab.len(), CHUNK + 3);
        assert_eq!(slab.end() as usize, CHUNK + 3);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key.index as usize, i, "slots are handed out in order");
            assert_eq!(value(&slab, *key), Some(i));
        }

        // A slot lent out stays valid while the slab grows by another chunk.
        let first = slab.slot(0).unwrap();
        for i in 0..CHUNK {
            let key = slab.reserve();
            slab.insert(key, 1000 + i);
        }
        assert_eq!(first.borrow_mut().get(keys[0]).copied(), Some(0));

        assert_eq!(slab.remove(keys[5]), Some(5));
        assert_eq!(slab.remove(keys[5]), None, "a stale key removes nothing");
        let reused = slab.reserve();
        assert_eq!(reused.index, 5, "the freed index is reused");
        assert_ne!(reused.generation, keys[5].generation);
        slab.insert(reused, 55);
        assert_eq!(
            value(&slab, keys[5]),
            None,
            "the old key no longer reaches the slot"
        );
        assert_eq!(value(&slab, reused), Some(55));

        let reserved = slab.reserve();
        assert_eq!(
            value(&slab, reserved),
            None,
            "a reserved slot holds nothing"
        );
        slab.cancel(reserved);
        assert_eq!(
            slab.reserve().index,
            reserved.index,
            "a cancelled reservation is reused"
        );
        assert_eq!(slab.len(), 2 * CHUNK + 3);
    }
}
