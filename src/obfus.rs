use memmap::{Mmap, MmapMut};
use std::{fs::OpenOptions, io::prelude::*, mem};

const HEADER_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

const ELF64_ADDR_SIZE: usize = mem::size_of::<u64>();
const ELF64_OFF_SIZE: usize = mem::size_of::<u64>();
const ELF64_WORD_SIZE: usize = mem::size_of::<u32>();
const ELF64_HALF_SIZE: usize = mem::size_of::<u16>();

const E_TYPE_START_BYTE: usize = 16;
const E_TYPE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_MACHINE_START_BYTE: usize = E_TYPE_START_BYTE + E_TYPE_SIZE_BYTE;
const E_MACHINE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_VERSION_START_BYTE: usize = E_MACHINE_START_BYTE + E_MACHINE_SIZE_BYTE;
const E_VERSION_SIZE_BYTE: usize = ELF64_WORD_SIZE;
const E_ENTRY_START_BYTE: usize = E_VERSION_START_BYTE + E_VERSION_SIZE_BYTE;
const E_ENTRY_SIZE_BYTE: usize = ELF64_ADDR_SIZE;
const E_PHOFF_START_BYTE: usize = E_ENTRY_START_BYTE + E_ENTRY_SIZE_BYTE;
const E_PHOFF_SIZE_BYTE: usize = ELF64_OFF_SIZE;
const E_SHOFF_START_BYTE: usize = E_PHOFF_START_BYTE + E_PHOFF_SIZE_BYTE;
const E_SHOFF_SIZE_BYTE: usize = ELF64_OFF_SIZE;
const E_FLAGS_START_BYTE: usize = E_SHOFF_START_BYTE + E_SHOFF_SIZE_BYTE;
const E_FLAGS_SIZE_BYTE: usize = ELF64_WORD_SIZE;
const E_EHSIZE_START_BYTE: usize = E_FLAGS_START_BYTE + E_FLAGS_SIZE_BYTE;
const E_EHSIZE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_PHENTSIZE_START_BYTE: usize = E_EHSIZE_START_BYTE + E_EHSIZE_SIZE_BYTE;
const E_PHENTSIZE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_PHNUM_START_BYTE: usize = E_PHENTSIZE_START_BYTE + E_PHENTSIZE_SIZE_BYTE;
const E_PHNUM_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_SHENTSIZE_START_BYTE: usize = E_PHNUM_START_BYTE + E_PHNUM_SIZE_BYTE;
const E_SHENTSIZE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_SHNUM_START_BYTE: usize = E_SHENTSIZE_START_BYTE + E_SHENTSIZE_SIZE_BYTE;

pub struct Obfuscator {
    input: Mmap,
    output: MmapMut,
    sec_hdr_num: u64,
    sec_hdr_size: u64,
    sec_hdr_offset: u64,
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

        let sec_hdr_offset = (input[E_SHOFF_START_BYTE + 3] as u64) << 24
            | (input[E_SHOFF_START_BYTE + 2] as u64) << 16
            | (input[E_SHOFF_START_BYTE + 1] as u64) << 8
            | (input[E_SHOFF_START_BYTE] as u64);
        let sec_hdr_num = (input[E_SHENTSIZE_START_BYTE + 1] as u64) << 8
            | (input[E_SHENTSIZE_START_BYTE] as u64);
        let sec_hdr_size =
            (input[E_SHNUM_START_BYTE + 1] as u64) << 8 | (input[E_SHNUM_START_BYTE] as u64);

        Ok(Obfuscator {
            input,
            output,
            sec_hdr_num,
            sec_hdr_size,
            sec_hdr_offset,
        })
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

    pub fn null_sec_hdr(&mut self) {
        for i in 0..self.sec_hdr_num {
            let offset = self.sec_hdr_offset + i * self.sec_hdr_size;
            println!("offset: {:x}", offset);
            for j in offset..offset + self.sec_hdr_size {
                self.output[j as usize] = 0;
            }
        }
    }
}
