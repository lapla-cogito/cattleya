use std::io::Read as _;
use std::io::Write as _;

const HEADER_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

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
    dyn_strings: String,
    string_table: String,
}

impl Obfuscator {
    pub fn open(input_path: &str, output_path: &str) -> crate::error::Result<Obfuscator> {
        let file = match std::fs::OpenOptions::new().read(true).open(input_path) {
            Ok(file) => file,
            Err(e) => {
                return Err(crate::error::Error::OpenFile(e));
            }
        };

        let input = unsafe { memmap2::Mmap::map(&file).map_err(crate::error::Error::Mmap)? };
        if !Self::is_elf(&input) {
            return Err(crate::error::Error::InvalidMagic);
        }

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

        let mut obfus = Obfuscator {
            input,
            output,
            sec_hdr,
            sec_hdr_num,
            sec_hdr_size,
            sec_hdr_offset,
            sec_table,
            dyn_strings: String::new(),
            string_table: String::new(),
        };

        let (section_addr, section_size, _, _) = obfus.get_section(".dynstr").unwrap();
        obfus.dyn_strings =
            String::from_utf8_lossy(&obfus.input[section_addr..section_addr + section_size])
                .to_string();

        let (section_addr, section_size, _, _) = obfus.get_section(".strtab").unwrap();
        obfus.string_table =
            String::from_utf8_lossy(&obfus.input[section_addr..section_addr + section_size])
                .to_string();

        Ok(obfus)
    }

    fn is_elf(mmap: &memmap2::Mmap) -> bool {
        mmap[0..4] == HEADER_MAGIC
    }

    fn is_64bit(&self) -> bool {
        self.input[4] == 2
    }

    fn is_enable_pie(&self) -> bool {
        self.input[16] != 2
    }

    fn is_stripped(&self) -> bool {
        self.get_section(".symtab").is_err()
    }

    fn v2p(&self, virtual_addr: usize, section: &str) -> usize {
        let (section_addr, _, _, vaddr) = self.get_section(section).unwrap();

        section_addr + virtual_addr - vaddr
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
        Err(crate::error::Error::NotFound(
            "section not found".to_owned() + section,
        ))
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
        let (section_addr, section_size, _, _) = self.get_section(section)?;

        for i in section_addr..section_addr + section_size {
            self.output[i] = 0;
        }

        Ok(())
    }

    fn get_dyn_func_idx(&self, function: &str) -> crate::error::Result<u64> {
        let idx = self.dyn_strings.find(function).unwrap();
        let (section_addr, section_size, entry_size, _) = self.get_section(".dynsym").unwrap();

        let dynsym_section = &self.input[section_addr..section_addr + section_size];

        for i in 0..section_size / entry_size {
            let entry = &dynsym_section[i * entry_size..(i + 1) * entry_size];
            let name_offset = u32::from_le_bytes(entry[0..4].try_into().unwrap());
            if name_offset == idx as u32 {
                return Ok(i as u64);
            }
        }

        Err(crate::error::Error::NotFound(
            "function not found".to_owned() + function,
        ))
    }

    fn get_func_addr_by_name(&self, function: &str) -> crate::error::Result<u64> {
        let idx = self.string_table.find(function).unwrap();
        let (section_addr, section_size, entry_size, _) = self.get_section(".symtab").unwrap();

        let dynsym_section = &self.input[section_addr..section_addr + section_size];

        for i in 0..section_size / entry_size {
            let entry = &dynsym_section[i * entry_size..(i + 1) * entry_size];
            if self.is_64bit() {
                if u32::from_le_bytes(entry[0..4].try_into().unwrap()) == idx as u32 {
                    return Ok(u64::from_le_bytes(entry[8..16].try_into().unwrap()));
                }
            } else if u32::from_le_bytes(entry[0..4].try_into().unwrap()) == idx as u32 {
                return Ok(u32::from_le_bytes(entry[4..8].try_into().unwrap()) as u64);
            }
        }

        Err(crate::error::Error::NotFound(
            "function not found".to_owned() + function,
        ))
    }

    pub fn got_overwrite(
        &mut self,
        target_function_name: &str,
        new_func_name: &str,
    ) -> crate::error::Result<()> {
        if self.is_enable_pie() {
            return Err(crate::error::Error::InvalidOption(
                "replacing GOT get will no effect with PIE enabled",
            ));
        } else if self.is_stripped() {
            return Err(crate::error::Error::InvalidOption(
                "cannot overwrite GOT with stripped binary",
            ));
        }

        let dyn_func = self.get_dyn_func_idx(target_function_name)?;

        if self.is_64bit() {
            let (section_addr, section_size, entry_size, _) =
                self.get_section(".rela.plt").unwrap();

            for i in 0..section_size / entry_size {
                let entry = &self.input[section_addr..section_addr + section_size]
                    [i * entry_size..(i + 1) * entry_size];

                if u64::from_le_bytes(entry[8..16].try_into().unwrap()) >> 32 == dyn_func {
                    let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
                    let addr = self.v2p(offset as usize, ".got.plt");
                    let new_func_addr = self.get_func_addr_by_name(new_func_name);
                    self.output[addr..addr + 8]
                        .copy_from_slice(&new_func_addr.unwrap().to_le_bytes());

                    return Ok(());
                }
            }
        } else {
            let (section_addr, section_size, entry_size, _) = self.get_section(".rel.plt").unwrap();
            for i in 0..section_size / entry_size {
                let entry = &self.input[section_addr..section_addr + section_size]
                    [i * entry_size..(i + 1) * entry_size];

                if (u32::from_le_bytes(entry[8..16].try_into().unwrap()) >> 8) as u64 == dyn_func {
                    let offset = u32::from_le_bytes(entry[0..4].try_into().unwrap());
                    let addr = self.v2p(offset as usize, ".got.plt");
                    let new_func_addr = self.get_func_addr_by_name(new_func_name);
                    self.output[addr..addr + 4]
                        .copy_from_slice(&new_func_addr.unwrap().to_le_bytes());

                    return Ok(());
                }
            }
        }

        Err(crate::error::Error::Obfuscation("failed to overwrite GOT"))
    }

    pub fn encrypt_function_name(&mut self, function: &str, key: &str) -> crate::error::Result<()> {
        use sha2::digest::Digest as _;

        let hash = sha2::Sha256::digest(key.as_bytes());
        let encryptor = crypto::aessafe::AesSafe256Encryptor::new(&hash);

        let tmp_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open("/tmp/cattleya_encrypted_function_name")
            .map_err(crate::error::Error::CreateFile)?;
        aesstream::AesWriter::new(tmp_file, encryptor)
            .map_err(crate::error::Error::OpenFile)?
            .write_all(function.as_bytes())
            .map_err(crate::error::Error::Io)?;

        let mut encrypted_function_name = Vec::new();
        std::fs::File::open("/tmp/cattleya_encrypted_function_name")
            .map_err(crate::error::Error::OpenFile)?
            .read_to_end(&mut encrypted_function_name)
            .map_err(crate::error::Error::Io)?;

        let idx = self.string_table.find(function).unwrap();
        let (section_addr, _, _, _) = self.get_section(".strtab").unwrap();
        if function.len() >= 16 {
            self.output[section_addr + idx..section_addr + idx + function.len()]
                .copy_from_slice(&encrypted_function_name);
        } else {
            encrypted_function_name.resize(function.len(), 0);
            self.output[section_addr + idx..section_addr + idx + function.len()]
                .copy_from_slice(&encrypted_function_name);
        }

        std::fs::remove_file("/tmp/cattleya_encrypted_function_name")
            .map_err(crate::error::Error::RemoveFile)?;

        Ok(())
    }
}
