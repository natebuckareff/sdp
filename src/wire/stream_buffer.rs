use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};

use super::range_window::RangeWindow;

pub struct StreamBuffer {
    chunk_size: usize,
    chunk_list: Vec<Option<Box<[u8]>>>,
    recycle_list: Vec<Box<[u8]>>,
    range_window: RangeWindow,
}

impl StreamBuffer {
    pub fn new(chunk_size: usize, base_offset: usize) -> Result<Self> {
        if chunk_size == 0 {
            return Err(anyhow!("chunk size must be positive"));
        }

        Ok(Self {
            chunk_size,
            chunk_list: vec![],
            recycle_list: vec![],
            range_window: RangeWindow::new(base_offset),
        })
    }

    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        if offset < self.range_window.base() {
            return Err(anyhow!("offset is below base"));
        }

        if data.is_empty() {
            return Ok(());
        }

        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| anyhow!("offset + len overflows usize"))?;

        self.range_window.insert(offset, end)?;

        let relative_start = offset - self.range_window.base();
        let relative_end = relative_start + data.len();

        let chunk_start = relative_start / self.chunk_size;
        let chunk_end = (relative_end - 1) / self.chunk_size + 1;

        while self.chunk_list.len() < chunk_end {
            self.chunk_list.push(None);
        }

        for chunk_index in chunk_start..chunk_end {
            let chunk_start = chunk_index * self.chunk_size;
            let chunk_end = (chunk_index + 1) * self.chunk_size;

            let i = chunk_start.max(relative_start);
            let j = relative_end.min(chunk_end);

            if j == i {
                continue;
            }

            let a = i - relative_start;
            let b = j - relative_start;

        let chunk = match &mut self.chunk_list[chunk_index] {
            Some(chunk) => chunk,
            None => {
                    let chunk = match self.recycle_list.pop() {
                        Some(recycled_chunk) => recycled_chunk,
                        None => {
                            let chunk = Box::new_zeroed_slice(self.chunk_size);
                            // SAFETY: all-zero bit pattern is valid for u8
                            unsafe { chunk.assume_init() }
                        }
                    };
                self.chunk_list[chunk_index] = Some(chunk);
                self.chunk_list[chunk_index].as_mut().unwrap()
            }
        };

            let src = &data[a..b];
            let dst_off = i - chunk_start;
            chunk[dst_off..dst_off + src.len()].copy_from_slice(src);
        }

        Ok(())
    }

    pub fn consume(&mut self, output: &mut BytesMut) -> Result<bool> {
        let old_base = self.range_window.base();

        let Some(new_base) = self.range_window.advance() else {
            return Ok(false);
        };

        let relative_start = 0;
        let relative_end = new_base - old_base;

        let chunk_start = relative_start / self.chunk_size;
        let chunk_end = (relative_end - 1) / self.chunk_size + 1;

        let mut drain_count = 0;

        for chunk_index in chunk_start..chunk_end {
            let chunk = match &self.chunk_list[chunk_index] {
                Some(chunk) => chunk,
                None => {
                    return Err(anyhow!("uninitialized chunk"));
                }
            };

            let chunk_start = chunk_index * self.chunk_size;
            let chunk_end = (chunk_index + 1) * self.chunk_size;

            let i = chunk_start.max(relative_start);
            let j = relative_end.min(chunk_end);

            let a = i - chunk_start;
            let b = j - chunk_start;

            let src = &chunk[a..b];
            output.put_slice(src);

            if src.len() == self.chunk_size {
                drain_count += 1;
            }
        }

        for chunk in self.chunk_list.drain(0..drain_count) {
            if let Some(chunk) = chunk {
                self.recycle_list.push(chunk);
            }
        }

        Ok(true)
    }
}

    }
}
