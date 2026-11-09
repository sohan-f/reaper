//! Deadline queue with per-key coalescing.

use std::collections::{BTreeMap, HashSet};

#[derive(Default)]
pub struct Pending {
    by_deadline: BTreeMap<u64, Vec<(u32, u32)>>,
    keys: HashSet<(u32, u32)>,
}

impl Pending {
    /// Insert (user, appid) with a deadline. Returns true only when the key
    /// was not already pending; an existing key keeps its original deadline.
    pub fn insert(&mut self, user: u32, appid: u32, deadline_ns: u64) -> bool {
        if !self.keys.insert((user, appid)) {
            return false;
        }
        self.by_deadline
            .entry(deadline_ns)
            .or_default()
            .push((user, appid));
        true
    }

    pub fn pop_due(&mut self, now_ns: u64) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        while let Some((&deadline, _)) = self.by_deadline.iter().next() {
            if deadline > now_ns {
                break;
            }
            let entries = self.by_deadline.remove(&deadline).unwrap_or_default();
            for key in entries {
                self.keys.remove(&key);
                out.push(key);
            }
        }
        out
    }

    pub fn earliest(&self) -> Option<u64> {
        self.by_deadline.keys().next().copied()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_duplicate_keys() {
        let mut pending = Pending::default();
        assert!(pending.insert(0, 10293, 1000));
        assert!(!pending.insert(0, 10293, 5000));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.earliest(), Some(1000));
    }

    #[test]
    fn pops_only_due_keys() {
        let mut pending = Pending::default();
        pending.insert(0, 1, 1000);
        pending.insert(0, 2, 2000);
        pending.insert(0, 3, 3000);
        assert_eq!(pending.pop_due(2000), vec![(0, 1), (0, 2)]);
        assert_eq!(pending.pop_due(2000), Vec::new());
        assert_eq!(pending.pop_due(3000), vec![(0, 3)]);
        assert_eq!(pending.len(), 0);
    }
}
