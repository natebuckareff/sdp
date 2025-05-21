use std::collections::BTreeMap;

const MAX_REMOVED_LEN: usize = 4000; // ~32 kB

pub struct RangeWindow {
    base: usize,
    ranges: BTreeMap<usize, usize>,
    removed: Vec<usize>,
}

impl RangeWindow {
    pub fn new(base: usize) -> Self {
        Self {
            base,
            ranges: BTreeMap::new(),
            removed: vec![],
        }
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn insert(&mut self, start: usize, end: usize) {
        self.ranges.insert(start, end);
    }

    pub fn advance(&mut self) -> Option<usize> {
        let mut i = 0;
        let mut current = self.base;

        while let Some((start, end)) = self.ranges.first_key_value() {
            if i >= MAX_REMOVED_LEN {
                // TODO: telemetry and allow caller to tune this
                break;
            }

            if *start == current {
                current = *end;
                self.removed.push(*start);
                i += 1;
            } else {
                break;
            }
        }

        for start in self.removed.drain(..) {
            self.ranges.remove(&start);
        }

        if current == self.base {
            None
        } else {
            Some(current)
        }
    }
}
