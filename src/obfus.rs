use memmap::{Mmap, MmapMut};
use std::{fs::OpenOptions, io::prelude::*};

const HEADER_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

pub struct Obfuscator {
    input: Mmap,
    output: MmapMut,
}

impl Obfuscator {
    pub fn open(input_path: &str, output_path: &str) -> std::io::Result<Obfuscator> {
        let file = match OpenOptions::new().read(true).write(true).open(input_path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("failed to open file: {}", e);
                return Err(e);
            }
        };

        let mut output_file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(output_path)
        {
            Ok(file) => file,
            Err(e) => {
                eprintln!("failed to create file: {}", e);
                return Err(e);
            }
        };

        let mut input_contents = Vec::new();
        file.try_clone()?
            .take(usize::MAX as u64)
            .read_to_end(&mut input_contents)?;
        output_file.write_all(&input_contents)?;

        let input = unsafe { Mmap::map(&file)? };
        let output = unsafe { MmapMut::map_mut(&output_file)? };

        Ok(Obfuscator { input, output })
    }

    pub fn is_elf(&self) -> bool {
        self.input[0..4] == HEADER_MAGIC
    }

    pub fn change_class(&mut self) {
        if self.output[4] == 1 {
            self.output[4] = 2;
        } else {
            self.output[4] = 1;
        }
    }

    pub fn change_endian(&mut self) {
        if self.output[5] == 1 {
            self.output[5] = 2;
        } else {
            self.output[5] = 1;
        }
    }
}
