use anyhow::Result;
use bytes::BytesMut;

use super::range_window::RangeWindow;

pub struct StreamBuffer {
    chunk_size: usize,
    chunk_list: Vec<Option<Box<[u8]>>>,
    range_window: RangeWindow,
}

impl StreamBuffer {
    pub fn new(chunk_size: usize, base_offset: usize) -> Self {
        Self {
            chunk_size,
            chunk_list: vec![],
            range_window: RangeWindow::new(base_offset),
        }
    }

    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        let chunk_index = offset / self.chunk_size;
        let chunk_offset = offset % self.chunk_size;

        // Truncate so all ranges lie fully within the same chunk
        if chunk_offset + data.len() > self.chunk_size {
            let left = &data[..self.chunk_size];
            let right = &data[self.chunk_size..];

            self.write(offset, left)?;
            self.write(offset + self.chunk_size, right)?;
            return Ok(());
        }

        while self.chunk_list.len() <= chunk_index {
            self.chunk_list.push(None);
        }

        let chunk = match &mut self.chunk_list[chunk_index] {
            Some(chunk) => chunk,
            None => {
                let chunk = Box::new_uninit_slice(self.chunk_size);
                let chunk = unsafe { chunk.assume_init() };
                self.chunk_list[chunk_index] = Some(chunk);
                self.chunk_list[chunk_index].as_mut().unwrap()
            }
        };

        chunk[chunk_offset..chunk_offset + data.len()].copy_from_slice(data);

        self.range_window.insert(offset, offset + data.len())?;

        Ok(())
    }

    pub fn consume(&mut self, output: &mut BytesMut) -> bool {
        let virtual_start = self.range_window.base();
        let Some(virtual_end) = self.range_window.advance() else {
            return false;
        };

        let mut consumed = 0;
        let chunk_count = (virtual_end - virtual_start) / self.chunk_size;

        for chunk_index in 0..chunk_count {
            let chunk_virtual_start = virtual_start + chunk_index * self.chunk_size;
            let chunk_virtual_end = virtual_end.min(chunk_virtual_start + self.chunk_size);

            let chunk_start = chunk_virtual_start % self.chunk_size;
            let chunk_end = chunk_virtual_end % self.chunk_size;

            let chunk = self.chunk_list[chunk_index]
                .as_ref()
                .expect("consuming uninitialized chunk");

            output.copy_from_slice(&chunk[chunk_start..chunk_end]);

            if chunk_end == self.chunk_size {
                consumed += 1;
            }
        }

        self.chunk_list.drain(..consumed);

        true
    }
}
