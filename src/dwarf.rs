#[derive(Debug, Clone)]
pub struct ByteEdit {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

/// Section locations supplied by the caller. Missing sections should map to `(0, &[])`.
pub struct SectionMap<'a, F>
where
    F: Fn(gimli::SectionId) -> (usize, &'a [u8]),
{
    pub get: F,
}

#[derive(Debug, Clone)]
struct SubprogramInfo {
    /// Section-relative offset in `.debug_info` where the DIE begins.
    die_offset: usize,
    /// Section-relative offset of the next DIE (or end of unit).
    die_end: usize,
    address_size: u8,
    low_pc: Option<u64>,
    /// Raw value of `DW_AT_high_pc`. May be a length (`Udata`/`Data*`) or an
    /// address (`Addr`); we only need the bytes for in-place swap, not its
    /// semantic interpretation.
    high_pc_value: Option<u64>,
    /// Encoding width of `high_pc` in bytes when stored as a fixed-width data
    /// form. `None` means the form is `DW_FORM_addr` (use `address_size`).
    high_pc_data_width: Option<u8>,
}

fn locate_unique(haystack: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > haystack.len() {
        return None;
    }
    let mut found: Option<usize> = None;
    for i in 0..=haystack.len() - pattern.len() {
        if &haystack[i..i + pattern.len()] == pattern {
            if found.is_some() {
                return None; // ambiguous
            }
            found = Some(i);
        }
    }
    found
}

fn encode_le(value: u64, width: u8) -> Vec<u8> {
    let mut bytes = value.to_le_bytes().to_vec();
    bytes.truncate(width as usize);
    bytes
}

pub fn plan_subprogram_swap<'a, F>(
    section_map: &SectionMap<'a, F>,
    name_a: &str,
    name_b: &str,
) -> Result<Vec<ByteEdit>, gimli::Error>
where
    F: Fn(gimli::SectionId) -> (usize, &'a [u8]),
{
    let endian = gimli::LittleEndian;

    // Capture file offsets for the sections we may need to write into.
    let (debug_info_off, debug_info_bytes) = (section_map.get)(gimli::SectionId::DebugInfo);
    if debug_info_bytes.is_empty() {
        return Ok(Vec::new());
    }
    let (debug_aranges_off, debug_aranges_bytes) =
        (section_map.get)(gimli::SectionId::DebugAranges);
    let dwarf_sections = gimli::DwarfSections::load(|id| -> Result<&'a [u8], gimli::Error> {
        Ok((section_map.get)(id).1)
    })?;
    let dwarf = dwarf_sections.borrow(|section| gimli::EndianSlice::new(section, endian));

    let mut matches: Vec<(String, SubprogramInfo)> = Vec::new();

    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;

        let mut die_offsets: Vec<usize> = Vec::new();
        {
            let mut cursor = unit.entries();
            while cursor.next_entry()? {
                if let Some(entry) = cursor.current() {
                    die_offsets.push(entry.offset().to_unit_section_offset(&unit.header).0);
                }
            }
        }
        die_offsets.sort_unstable();
        let unit_section_off = unit.header.offset().0;
        let unit_end = unit_section_off + unit.header.length_including_self();

        let mut cursor = unit.entries();
        while cursor.next_entry()? {
            let entry = match cursor.current() {
                Some(e) => e,
                None => continue,
            };
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }

            let name_attr = match entry.attr(gimli::DW_AT_name) {
                Some(a) => a,
                None => continue,
            };
            let name = match dwarf.attr_string(&unit, name_attr.value()) {
                Ok(r) => String::from_utf8_lossy(r.slice()).into_owned(),
                Err(_) => continue,
            };
            if name != name_a && name != name_b {
                continue;
            }

            let die_off_section = entry.offset().to_unit_section_offset(&unit.header).0;
            let die_end = match die_offsets.binary_search(&die_off_section) {
                Ok(idx) if idx + 1 < die_offsets.len() => die_offsets[idx + 1],
                _ => unit_end,
            };

            let low_pc = match entry.attr(gimli::DW_AT_low_pc) {
                Some(a) => match a.value() {
                    gimli::AttributeValue::Addr(v) => Some(v),
                    gimli::AttributeValue::DebugAddrIndex(idx) => dwarf.address(&unit, idx).ok(),
                    _ => None,
                },
                None => None,
            };

            let (high_pc_value, high_pc_data_width) = match entry.attr(gimli::DW_AT_high_pc) {
                Some(a) => match a.value() {
                    gimli::AttributeValue::Addr(v) => (Some(v), None),
                    gimli::AttributeValue::Udata(v) => (Some(v), None),
                    gimli::AttributeValue::Data1(v) => (Some(v as u64), Some(1)),
                    gimli::AttributeValue::Data2(v) => (Some(v as u64), Some(2)),
                    gimli::AttributeValue::Data4(v) => (Some(v as u64), Some(4)),
                    gimli::AttributeValue::Data8(v) => (Some(v), Some(8)),
                    _ => (None, None),
                },
                None => (None, None),
            };

            if low_pc.is_none() && high_pc_value.is_none() {
                continue;
            }

            matches.push((
                name,
                SubprogramInfo {
                    die_offset: die_off_section,
                    die_end,
                    address_size: unit.header.address_size(),
                    low_pc,
                    high_pc_value,
                    high_pc_data_width,
                },
            ));
        }
    }

    let a = matches
        .iter()
        .find(|(n, _)| n == name_a)
        .map(|(_, i)| i.clone());
    let b = matches
        .iter()
        .find(|(n, _)| n == name_b)
        .map(|(_, i)| i.clone());

    let (a, b) = match (a, b) {
        (Some(a), Some(b)) => (a, b),
        _ => return Ok(Vec::new()),
    };

    let mut edits: Vec<ByteEdit> = Vec::new();

    let mut plan_one = |src: &SubprogramInfo, dst: &SubprogramInfo| {
        let span = &debug_info_bytes[src.die_offset..src.die_end];

        if let (Some(src_lo), Some(dst_lo)) = (src.low_pc, dst.low_pc) {
            let pat = encode_le(src_lo, src.address_size);
            let new = encode_le(dst_lo, src.address_size);
            if pat != new
                && let Some(rel) = locate_unique(span, &pat)
            {
                edits.push(ByteEdit {
                    offset: debug_info_off + src.die_offset + rel,
                    bytes: new,
                });
            }
        }

        if let (Some(src_hi), Some(dst_hi)) = (src.high_pc_value, dst.high_pc_value) {
            let width = src.high_pc_data_width.unwrap_or(src.address_size);
            let dst_width = dst.high_pc_data_width.unwrap_or(dst.address_size);
            if width == dst_width {
                let pat = encode_le(src_hi, width);
                let new = encode_le(dst_hi, width);
                if pat != new
                    && let Some(rel) = locate_unique(span, &pat)
                {
                    edits.push(ByteEdit {
                        offset: debug_info_off + src.die_offset + rel,
                        bytes: new,
                    });
                }
            }
        }
    };

    plan_one(&a, &b);
    plan_one(&b, &a);

    if !debug_aranges_bytes.is_empty()
        && let (Some(a_low), Some(b_low)) = (a.low_pc, b.low_pc)
    {
        let asz = a.address_size.max(b.address_size);
        let pat_a = encode_le(a_low, asz);
        let pat_b = encode_le(b_low, asz);
        if pat_a.len() == pat_b.len() && pat_a != pat_b {
            for i in 0..debug_aranges_bytes.len().saturating_sub(pat_a.len()) {
                let slice = &debug_aranges_bytes[i..i + pat_a.len()];
                if slice == pat_a.as_slice() {
                    edits.push(ByteEdit {
                        offset: debug_aranges_off + i,
                        bytes: pat_b.clone(),
                    });
                } else if slice == pat_b.as_slice() {
                    edits.push(ByteEdit {
                        offset: debug_aranges_off + i,
                        bytes: pat_a.clone(),
                    });
                }
            }
        }
    }

    Ok(edits)
}
