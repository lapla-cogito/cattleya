use memmap::{Mmap, MmapMut};
use std::{fs::OpenOptions, io::prelude::*, mem};

pub const HEADER_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

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
    pub output: MmapMut,
    sec_hdr: String,
    sec_hdr_num: u64,
    sec_hdr_size: u64,
    sec_hdr_offset: u64,
    sec_table: u64,
}

impl Obfuscator {
    pub fn open(input_path: &str, output_path: &str) -> std::io::Result<Obfuscator> {
        let file = match OpenOptions::new().read(true).write(true).open(input_path) {
            Ok(file) => file,
            Err(e) => {
                panic!("failed to open file: {}", e);
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
                panic!("failed to create file: {}", e);
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
        let sec_hdr_num =
            (input[E_SHNUM_START_BYTE + 1] as u64) << 8 | (input[E_SHNUM_START_BYTE] as u64);
        let sec_hdr_size = (input[E_SHENTSIZE_START_BYTE + 1] as u64) << 8
            | (input[E_SHENTSIZE_START_BYTE] as u64);

        let bit64 = input[4] == 2;

        let sec_table = match bit64 {
            true => u64::from_le_bytes(input[40..48].try_into().unwrap()),
            false => u32::from_le_bytes(input[32..36].try_into().unwrap()) as u64,
        };

        let sh_table_header_addr = (u16::from_le_bytes(input[62..64].try_into().unwrap()) as u64
            * sec_hdr_size
            + sec_table) as usize;

        let sh_table_header =
            &input[sh_table_header_addr..sh_table_header_addr + sec_hdr_size as usize];

        let sh_table_addr =
            u64::from_le_bytes(sh_table_header[24..32].try_into().unwrap()) as usize;

        let mut curr_strings = -1;
        let mut index = sh_table_addr;
        let mut curr_byte;

        while curr_strings < sec_hdr_num as isize {
            curr_byte = input[index] as isize;
            if curr_byte == 0 {
                curr_strings += 1;
            }
            index += 1;
        }

        let mut data_copy: Vec<u8> = vec![0; index - sh_table_addr];
        data_copy.copy_from_slice(&input[sh_table_addr..index]);

        for byte in &mut data_copy {
            if *byte == 0 {
                *byte = b' ';
            }
        }

        let sec_hdr = String::from_utf8_lossy(&data_copy).to_string();

        Ok(Obfuscator {
            input,
            output,
            sec_hdr,
            sec_hdr_num,
            sec_hdr_size,
            sec_hdr_offset,
            sec_table,
        })
    }

    pub fn is_elf(&self) -> bool {
        self.input[0..4] == HEADER_MAGIC
    }

    pub fn is_64bit(&self) -> bool {
        self.input[4] == 2
    }

    fn get_section(&self, section: &str) -> (usize, usize) {
        let searched_idx = self.sec_hdr.find(section).unwrap_or(usize::MAX);
        if searched_idx == usize::MAX {
            panic!("section not found");
        }

        for i in 0..self.sec_hdr_num {
            let sec_hdr = self.input[(self.sec_table + i * self.sec_hdr_size) as usize
                ..(self.sec_table + (i + 1) * self.sec_hdr_size) as usize]
                .to_vec();
            let string_offset = u32::from_le_bytes(sec_hdr[0..4].try_into().unwrap());
            if string_offset == searched_idx as u32 {
                return (
                    u64::from_le_bytes(sec_hdr[24..32].try_into().unwrap()) as usize,
                    u64::from_le_bytes(sec_hdr[32..40].try_into().unwrap()) as usize,
                );
            }
        }

        (usize::MAX, usize::MAX)
    }

    pub fn change_class(&mut self) {
        self.output[4] = 3 - self.output[4];
    }

    pub fn change_endian(&mut self) {
        self.output[5] = 3 - self.output[5];
    }

    pub fn nullify_sec_hdr(&mut self) {
        for i in 0..self.sec_hdr_num {
            let offset = self.sec_hdr_offset + i * self.sec_hdr_size;
            for j in offset..offset + self.sec_hdr_size {
                self.output[j as usize] = 0;
            }
        }
    }

    pub fn nullify_section(&mut self, section: &str) {
        let (section_addr, section_size) = self.get_section(section);
        if section_addr == usize::MAX {
            panic!("section not found");
        }
        for i in section_addr..section_addr + section_size {
            self.output[i] = 0;
        }
    }
}
