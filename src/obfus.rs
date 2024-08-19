use std::io::prelude::*;

pub const HEADER_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

#[repr(C, packed)]
#[derive(Debug)]
pub struct ElfHeader {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

pub struct Obfuscator {
    input: memmap2::Mmap,
    pub output: memmap2::MmapMut,
    sec_hdr: String,
    sec_hdr_num: u64,
    sec_hdr_size: u64,
    sec_hdr_offset: u64,
    sec_table: u64,
}

impl Obfuscator {
    pub fn open(input_path: &str, output_path: &str) -> crate::error::Result<Obfuscator> {
        let file = match std::fs::OpenOptions::new().read(true).open(input_path) {
            Ok(file) => file,
            Err(e) => {
                return Err(crate::error::Error::OpenFile(e));
            }
        };

        let mut output_file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_path)
        {
            Ok(file) => file,
            Err(e) => {
                return Err(crate::error::Error::CreateFile(e));
            }
        };

        let mut input_contents = Vec::new();
        file.try_clone()
            .map_err(crate::error::Error::Io)?
            .take(usize::MAX as u64)
            .read_to_end(&mut input_contents)
            .map_err(crate::error::Error::Io)?;
        output_file
            .write_all(&input_contents)
            .map_err(crate::error::Error::Io)?;

        let input = unsafe { memmap2::Mmap::map(&file).map_err(crate::error::Error::Mmap)? };
        let output =
            unsafe { memmap2::MmapMut::map_mut(&output_file).map_err(crate::error::Error::Mmap)? };

        let elf_hdr: ElfHeader = unsafe { std::ptr::read(input.as_ptr() as *const ElfHeader) };

        let sec_hdr_offset = elf_hdr.e_shoff as u64;
        let sec_hdr_num = elf_hdr.e_shnum as u64;
        let sec_hdr_size = elf_hdr.e_shentsize as u64;

        let sec_table = match input[4] == 2 {
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

    fn is_enable_pie(&self) -> bool {
        self.input[16] == 2
    }

    fn is_stripped(&self) -> bool {
        self.get_section(".symtab").unwrap().0 == 0
    }

    // (section_addr, section_size, entry_size, vaddr)
    fn get_section(&self, section: &str) -> crate::error::Result<(usize, usize, usize, usize)> {
        let searched_idx = self.sec_hdr.find(section).unwrap_or(usize::MAX);
        if searched_idx == usize::MAX {
            return Err(crate::error::Error::InvalidOption("section not found"));
        }

        for i in 0..self.sec_hdr_num {
            let sec_hdr = self.input[(self.sec_table + i * self.sec_hdr_size) as usize
                ..(self.sec_table + (i + 1) * self.sec_hdr_size) as usize]
                .to_vec();
            let string_offset = u32::from_le_bytes(sec_hdr[0..4].try_into().unwrap());
            if string_offset == searched_idx as u32 {
                if self.is_64bit() {
                    return Ok((
                        u64::from_le_bytes(sec_hdr[24..32].try_into().unwrap()) as usize,
                        u64::from_le_bytes(sec_hdr[32..40].try_into().unwrap()) as usize,
                        u64::from_le_bytes(sec_hdr[56..64].try_into().unwrap()) as usize,
                        u64::from_le_bytes(sec_hdr[16..24].try_into().unwrap()) as usize,
                    ));
                } else {
                    return Ok((
                        u32::from_le_bytes(sec_hdr[16..20].try_into().unwrap()) as usize,
                        u32::from_le_bytes(sec_hdr[20..24].try_into().unwrap()) as usize,
                        u32::from_le_bytes(sec_hdr[36..40].try_into().unwrap()) as usize,
                        u32::from_le_bytes(sec_hdr[12..16].try_into().unwrap()) as usize,
                    ));
                }
            }
        }

        // section not found
        Err(crate::error::Error::InvalidOption("section not found"))
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

    pub fn nullify_section(&mut self, section: &str) -> crate::error::Result<()> {
        let (section_addr, section_size, _, _) = self.get_section(section).unwrap();
        if section_addr == usize::MAX {
            return Err(crate::error::Error::InvalidOption("section not found"));
        }

        for i in section_addr..section_addr + section_size {
            self.output[i] = 0;
        }

        Ok(())
    }

    pub fn got_overwrite(&self, function: &str, new_func_addr: &str) {
        if self.is_enable_pie() {
            println!("replacing GOT get will no effect with PIE enabled")
        } else if self.is_stripped() {
            println!("cannot overwrite GOT with stripped binary")
        }

        if self.is_64bit() {
            let (section_addr, section_size, entry_size, vaddr) =
                self.get_section(".rela.plt").unwrap();
            for i in 0..section_size / entry_size {
                let entry = &self.input[section_addr..section_addr + section_size]
                    [i * entry_size..(i + 1) * entry_size];
            }
        } else {
            let (section_addr, section_size, entry_size, vaddr) =
                self.get_section(".rel.plt").unwrap();
        }
    }
}
