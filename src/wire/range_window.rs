use anyhow::{Result, anyhow};
use std::collections::BTreeMap;

pub struct RangeWindow {
    base: usize,
    ranges: BTreeMap<usize, usize>,
}

impl RangeWindow {
    pub fn new(base: usize) -> Self {
        Self {
            base,
            ranges: BTreeMap::new(),
        }
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn insert(&mut self, start: usize, end: usize) -> Result<()> {
        if start < self.base {
            return Err(anyhow!("range start is below base"));
        }

        if start >= end {
            return Err(anyhow!("invalid range"));
        }

        if let Some((_prev_start, prev_end_val)) = self.ranges.range(..=start).next_back() {
            if *prev_end_val > start {
                return Err(anyhow!("range overlaps with an existing range"));
            }
        }

        if let Some((next_start_key, _)) = self.ranges.range(start..).next() {
            if *next_start_key < end {
                return Err(anyhow!("range overlaps with an existing range"));
            }
        }

        self.ranges.insert(start, end);

        Ok(())
    }

    pub fn advance(&mut self) -> Option<usize> {
        let mut current = self.base;

        while let Some((start, end)) = self.ranges.pop_first() {
            if start == current {
                current = end;
            } else {
                self.ranges.insert(start, end);
                break;
            }
        }

        if current == self.base {
            None
        } else {
            self.base = current;
            Some(current)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contiguous_ranges() {
        let mut window = RangeWindow::new(0);
        window.insert(0, 10).unwrap();
        window.insert(10, 20).unwrap();
        window.insert(20, 30).unwrap();

        let new_base = window.advance();
        assert_eq!(new_base, Some(30));
        assert_eq!(window.base(), 30);
    }

    #[test]
    fn test_non_contiguous_ranges() {
        let mut window = RangeWindow::new(0);
        window.insert(0, 10).unwrap();
        window.insert(20, 30).unwrap(); // Gap between 10 and 20
        window.insert(30, 40).unwrap();

        let new_base = window.advance();
        assert_eq!(new_base, Some(10));
        assert_eq!(window.base(), 10);

        let new_base_2 = window.advance();
        assert_eq!(new_base_2, None);
        assert_eq!(window.base(), 10);

        window.insert(10, 20).unwrap();

        let new_base_3 = window.advance();
        assert_eq!(new_base_3, Some(40));
        assert_eq!(window.base(), 40);
    }

    #[test]
    fn test_empty_window() {
        let mut window = RangeWindow::new(0);
        let new_base = window.advance();
        assert_eq!(new_base, None);
        assert_eq!(window.base(), 0);
    }

    #[test]
    fn test_insert_overlapping_ranges() {
        let mut window = RangeWindow::new(0);
        window.insert(10, 20).unwrap();

        // Case 1: New range is completely within an existing range
        assert!(
            window.insert(12, 18).is_err(),
            "Should err: (12,18) within (10,20)"
        );

        // Case 2: New range overlaps at the start of an existing range
        assert!(
            window.insert(5, 15).is_err(),
            "Should err: (5,15) overlaps start of (10,20)"
        );

        // Case 3: New range overlaps at the end of an existing range
        assert!(
            window.insert(15, 25).is_err(),
            "Should err: (15,25) overlaps end of (10,20)"
        );

        // Case 4: New range engulfs an existing range
        assert!(
            window.insert(5, 25).is_err(),
            "Should err: (5,25) engulfs (10,20)"
        );

        // Case 5: Insert a range that is adjacent (touching) but not overlapping - should be OK
        window.insert(20, 30).unwrap(); // (10,20) exists, (20,30) is fine
        assert_eq!(window.ranges.get(&10), Some(&20));
        assert_eq!(window.ranges.get(&20), Some(&30));

        window.insert(0, 10).unwrap(); // (0,10) is fine before (10,20)
        assert_eq!(window.ranges.get(&0), Some(&10));

        // Case 6: Try to insert an identical range
        assert!(
            window.insert(0, 10).is_err(),
            "Should err: (0,10) is identical to existing"
        );
    }

    #[test]
    fn test_insert_invalid_ranges() {
        let mut window = RangeWindow::new(0);

        // Case 1: start == end
        let res1 = window.insert(5, 5);
        assert!(res1.is_err());
        assert_eq!(res1.unwrap_err().to_string(), "invalid range");

        // Case 2: start > end
        let res2 = window.insert(10, 5);
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err().to_string(), "invalid range");

        // Ensure no ranges were actually added
        assert!(
            window.ranges.is_empty(),
            "Ranges map should be empty after invalid inserts"
        );
    }

    #[test]
    fn test_larger_variable_ranges() {
        let mut window = RangeWindow::new(0);

        // Insert contiguous larger ranges
        window.insert(0, 100).unwrap();
        window.insert(100, 250).unwrap();
        window.insert(250, 300).unwrap();

        let new_base1 = window.advance();
        assert_eq!(new_base1, Some(300));
        assert_eq!(window.base(), 300);
        assert!(window.ranges.is_empty());

        // Reset window and test non-contiguous larger ranges
        let mut window2 = RangeWindow::new(0);
        window2.insert(0, 50).unwrap();
        window2.insert(100, 120).unwrap(); // Gap: 50 to 100
        window2.insert(120, 180).unwrap();

        let new_base2_first = window2.advance();
        assert_eq!(new_base2_first, Some(50));
        assert_eq!(window2.base(), 50);
        assert_eq!(window2.ranges.len(), 2); // (100,120) and (120,180) should remain

        let new_base2_second = window2.advance();
        assert_eq!(
            new_base2_second, None,
            "Advance should return None due to gap"
        );
        assert_eq!(window2.base(), 50, "Base should not change due to gap");

        // Bridge the gap
        window2.insert(50, 100).unwrap();
        let new_base2_third = window2.advance();
        assert_eq!(new_base2_third, Some(180));
        assert_eq!(window2.base(), 180);
        assert!(window2.ranges.is_empty());
    }

    #[test]
    fn test_insert_order_and_advance_at_base() {
        // Scenario 1: base is 50. Attempting to insert (40,50) should now fail.
        let mut window1 = RangeWindow::new(50);
        window1.insert(50, 60).unwrap(); // This is fine

        let res_below_base = window1.insert(40, 50);
        assert!(
            res_below_base.is_err(),
            "Scenario 1: Should err when inserting range start below base"
        );
        assert_eq!(
            res_below_base.unwrap_err().to_string(),
            "range start is below base",
            "Scenario 1: Error message mismatch"
        );

        // Check that (50,60) is still there and base is unchanged before any advance attempt
        assert_eq!(
            window1.ranges.len(),
            1,
            "Scenario 1: Range (50,60) should still be present"
        );
        assert_eq!(
            window1.ranges.get(&50),
            Some(&60),
            "Scenario 1: Range (50,60) should be (50,60)"
        );
        assert_eq!(window1.base(), 50, "Scenario 1: Base should remain 50");

        // Advancing window1 now should consume (50,60)
        let new_base1_advanced = window1.advance();
        assert_eq!(
            new_base1_advanced,
            Some(60),
            "Scenario 1: Advance should now consume (50,60)"
        );
        assert_eq!(
            window1.base(),
            60,
            "Scenario 1: Base should be 60 after advance"
        );
        assert!(
            window1.ranges.is_empty(),
            "Scenario 1: Ranges should be empty after advance"
        );

        // Scenario 2: base is 0, insert (50,60), then (0,10), then (10,20) - This remains valid
        let mut window2 = RangeWindow::new(0);
        window2.insert(50, 60).unwrap(); // Out of order insert for later
        window2.insert(0, 10).unwrap();
        window2.insert(10, 20).unwrap();

        let new_base2_a = window2.advance(); // Consumes (0,10) and (10,20)
        assert_eq!(
            new_base2_a,
            Some(20),
            "Scenario 2: First advance should consume up to 20"
        );
        assert_eq!(
            window2.base(),
            20,
            "Scenario 2: Base should be 20 after first advance"
        );

        let new_base2_b = window2.advance(); // Gap: base is 20, next is (50,60)
        assert_eq!(
            new_base2_b, None,
            "Scenario 2: Second advance should find a gap"
        );
        assert_eq!(
            window2.base(),
            20,
            "Scenario 2: Base should remain 20 due to gap"
        );
        assert_eq!(
            window2.ranges.len(),
            1,
            "Scenario 2: One range (50,60) should remain"
        );
        assert_eq!(
            window2.ranges.get(&50),
            Some(&60),
            "Scenario 2: Range (50,60) should be present"
        );
    }
}
